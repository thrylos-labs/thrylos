package chain

import (
	"bytes"
	"database/sql"
	"encoding/gob"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"math/big"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/cloudflare/circl/sign/mldsa/mldsa44"
	thrylos "github.com/thrylos-labs/thrylos"
	"github.com/thrylos-labs/thrylos/balance"
	"github.com/thrylos-labs/thrylos/config"
	"github.com/thrylos-labs/thrylos/consensus/processor"
	"github.com/thrylos-labs/thrylos/consensus/staking"
	"github.com/thrylos-labs/thrylos/crypto"
	"github.com/thrylos-labs/thrylos/crypto/hash"
	"github.com/thrylos-labs/thrylos/network"
	"github.com/thrylos-labs/thrylos/store"
	"github.com/thrylos-labs/thrylos/types"
	"github.com/thrylos-labs/thrylos/utils"
)

type BlockchainImpl struct {
	Blockchain            *types.Blockchain
	TransactionPropagator *types.TransactionPropagator
	modernProcessor       *processor.ModernProcessor
	txPool                types.TxPool
	dagManager            *processor.DAGManager
	MessageBus            types.MessageBusInterface
	AppConfig             *config.Config
	Libp2pManager         *network.Libp2pManager
}

// Now you can simplify the Close method to use the interface methods
func (bc *BlockchainImpl) Close() error {
	log.Println("Closing blockchain resources...")

	if bc.Blockchain != nil && bc.Blockchain.Database != nil {
		// Get lock file path
		lockFile := bc.Blockchain.Database.GetLockFilePath()
		if lockFile != "" {
			log.Printf("Lock file path: %s", lockFile)
		}

		// Close the database
		if err := bc.Blockchain.Database.Close(); err != nil {
			return fmt.Errorf("error closing database: %v", err)
		}
		log.Println("Database closed successfully")
	}

	log.Println("Blockchain resources closed successfully")
	return nil
}

// In blockchain.go (or similar)

// AddBlockToChain handles validation, state updates, and persistence for a new signed block.
func (bc *BlockchainImpl) AddBlockToChain(block *types.Block) error {
	// --- Initial Checks ---
	if block == nil {
		return errors.New("cannot add nil block")
	}
	if block.Validator == "" {
		log.Printf("ERROR: [AddBlock] Block %d is missing validator information.", block.Index)
		return errors.New("block verification failed: missing validator")
	}
	if block.Signature == nil || len(block.Signature.Bytes()) == 0 {
		log.Printf("ERROR: [AddBlock] Block %d (Validator: %s) signature is missing or empty.", block.Index, block.Validator)
		return errors.New("block verification failed: missing or empty block signature")
	}
	log.Printf("Attempting to add Block %d (Validator: %s) to chain...", block.Index, block.Validator)

	// --- 1. Verify Signature (No Lock Needed Yet) ---
	// This implicitly verifies the block hash *including* the TransactionsRoot,
	// assuming SerializeForSigning and block.Marshal are correct.
	log.Printf("Verifying signature for block %d from validator %s...", block.Index, block.Validator)

	validatorPubKey, err := bc.GetValidatorPublicKey(block.Validator)
	if err != nil {
		log.Printf("ERROR: [AddBlock] Block %d verification failed - Could not get public key for validator %s: %v", block.Index, block.Validator, err)
		return fmt.Errorf("block verification failed: cannot get validator public key: %w", err)
	}

	hashBytesToVerify, err := SerializeForSigning(block) // Calls helper from block.go
	if err != nil {
		log.Printf("ERROR: [AddBlock] Block %d verification failed - Could not serialize block for hash recomputation: %v", block.Index, err)
		return fmt.Errorf("block verification failed: serialization error: %w", err)
	}
	if len(hashBytesToVerify) == 0 {
		log.Printf("ERROR: [AddBlock] Block %d verification failed - Serialization for hash recomputation resulted in empty bytes.", block.Index)
		return fmt.Errorf("block verification failed: empty serialization result")
	}

	recomputedHash := hash.NewHash(hashBytesToVerify)
	if recomputedHash.Equal(hash.NullHash()) {
		log.Printf("ERROR: [AddBlock] Block %d verification failed - Hash recomputation resulted in zero hash.", block.Index)
		return fmt.Errorf("block verification failed: zero hash recomputation")
	}

	signatureBytes := block.Signature.Bytes()
	retrievedRawBytes := validatorPubKey.Bytes() // Assuming GetValidatorPublicKey returns mldsa44.PublicKey

	// Verify the signature against the recomputed hash
	isValid := mldsa44.Verify(validatorPubKey, recomputedHash.Bytes(), nil, signatureBytes)
	if !isValid {
		log.Printf("ERROR: [AddBlock] Block %d verification failed - Invalid signature from validator %s.", block.Index, block.Validator)
		// Log details for debugging
		log.Printf("DEBUG: [AddBlock Verify Failed] PubKey (mldsa44 bytes): %x", retrievedRawBytes)
		log.Printf("DEBUG: [AddBlock Verify Failed] Hash: %x", recomputedHash.Bytes())
		log.Printf("DEBUG: [AddBlock Verify Failed] Sig: %x", signatureBytes)
		return fmt.Errorf("block verification failed: invalid signature")
	}
	log.Printf("Block %d signature verified successfully against recomputed hash.", block.Index)
	// --- End Signature Verification ---

	// --- MERKLE ROOT & FULL BLOCK VERIFICATION (ADDED) ---
	// Call the updated Verify function from block.go which checks Merkle Root and recomputes hash
	if err := Verify(block); err != nil {
		log.Printf("ERROR: [AddBlock] Block %d failed full verification (Merkle/Hash): %v", block.Index, err)
		// Note: Signature was valid, but content (e.g., Merkle root) might be inconsistent
		// or the stored Hash field doesn't match recomputation.
		return fmt.Errorf("block verification failed (Merkle/Hash): %w", err)
	}
	log.Printf("Block %d Merkle root and hash verified successfully.", block.Index)
	// --- END MERKLE ROOT & FULL BLOCK VERIFICATION ---

	// --- Acquire Lock for state update and chain modification ---
	bc.Blockchain.Mu.Lock()
	defer bc.Blockchain.Mu.Unlock()

	// --- 2. Final Validation Under Lock (Index, PrevHash against actual last block) ---
	// Re-check length in case chain changed between lock acquisition and previous checks
	if len(bc.Blockchain.Blocks) == 0 {
		// This should only be possible if adding the genesis block, which usually follows a different path
		if block.Index != 0 {
			return fmt.Errorf("cannot add non-genesis block %d to empty chain", block.Index)
		}
		// Add genesis-specific checks if needed
	} else {
		// Check against the actual last block under lock
		prevBlock := bc.Blockchain.Blocks[len(bc.Blockchain.Blocks)-1]
		if block.Index != prevBlock.Index+1 {
			return fmt.Errorf("invalid block index under lock: expected %d, got %d", prevBlock.Index+1, block.Index)
		}
		if !block.PrevHash.Equal(prevBlock.Hash) {
			log.Printf("PrevHash mismatch under lock! Expected: %s, Got: %s", prevBlock.Hash.String(), block.PrevHash.String())
			return fmt.Errorf("invalid PrevHash under lock: expected %s, got %s", prevBlock.Hash.String(), block.PrevHash.String())
		}
	}
	// --- End Final Validation ---

	// --- ATOMIC DATABASE PERSISTENCE ---
	dbTxContext, err := bc.Blockchain.Database.BeginTransaction()
	if err != nil {
		log.Printf("ERROR: Failed to begin DB transaction for block %d: %v", block.Index, err)
		return fmt.Errorf("failed start DB tx for block %d: %w", block.Index, err)
	}
	var finalErr error
	defer func() {
		if finalErr != nil && dbTxContext != nil {
			log.Printf("WARN: Rolling back DB transaction for block %d due to error: %v", block.Index, finalErr)
			_ = bc.Blockchain.Database.RollbackTransaction(dbTxContext)
		}
	}()

	// 3. Persist State Changes
	finalErr = bc.persistStateChangesToDB(dbTxContext, block)
	if finalErr != nil {
		log.Printf("ERROR: Failed to persist state changes to DB for block %d: %v", block.Index, finalErr)
		return finalErr // Defer will rollback
	}
	log.Printf("DEBUG: Successfully persisted state changes to DB for Block %d (within transaction).", block.Index)

	// 4. Persist Block Data
	finalErr = bc.Blockchain.Database.SaveBlockWithContext(dbTxContext, block)
	if finalErr != nil {
		log.Printf("ERROR: Failed to save block %d data to DB: %v", block.Index, finalErr)
		return finalErr // Defer will rollback
	}
	log.Printf("DEBUG: Successfully saved block %d data to DB (within transaction).", block.Index)

	// 5. Commit DB Transaction
	commitErr := bc.Blockchain.Database.CommitTransaction(dbTxContext)
	if commitErr != nil {
		finalErr = fmt.Errorf("failed to commit DB transaction for block %d: %w", block.Index, commitErr)
		log.Printf("CRITICAL ERROR: %v. DB state may be inconsistent.", finalErr)
		// dbTxContext is effectively invalid now, defer might try rollback but likely fail
		dbTxContext = nil
		return finalErr
	}
	dbTxContext = nil // Prevent defer rollback on success
	log.Printf("DEBUG: Successfully committed DB transaction for Block %d.", block.Index)
	// --- END ATOMIC DATABASE PERSISTENCE ---

	// --- UPDATE IN-MEMORY STATE (Only after successful commit) ---
	// 6. Append block
	bc.Blockchain.Blocks = append(bc.Blockchain.Blocks, block)
	log.Printf("INFO: Appended block %d to in-memory chain (Hash: %s)", block.Index, block.Hash.String())

	// 7. Update UTXOs and Balances
	if err := bc.updateStateForBlock(block); err != nil {
		// This is critical - the block is committed but in-memory state failed.
		// Needs careful handling - maybe halt, or attempt recovery?
		log.Printf("CRITICAL ERROR: In-memory state update failed for committed block %d: %v. State inconsistent!", block.Index, err)
		// Depending on recovery strategy, might need to panic or enter a safe mode.
		return fmt.Errorf("CRITICAL: in-memory state update failed post-commit for block %d: %w", block.Index, err)
	}
	log.Printf("DEBUG: Successfully updated in-memory state (Stakeholders, UTXOs) for Block %d.", block.Index)

	// 8. Update timestamp
	bc.Blockchain.LastTimestamp = block.Timestamp
	// --- END UPDATE IN-MEMORY STATE ---

	// --- Trigger Notifications & Status Updates ---
	if bc.Blockchain.OnNewBlock != nil {
		go bc.Blockchain.OnNewBlock(block)
	}
	// Use the already computed block hash bytes if needed, or recompute if necessary
	blockHashBytes := block.Hash.Bytes()
	go func(b *types.Block, bhBytes []byte) { // Pass block hash bytes
		for _, tx := range b.Transactions {
			txID := tx.ID // Assuming types.Transaction has ID field
			// Call the corrected UpdateTransactionStatus
			if err := bc.UpdateTransactionStatus(txID, "included", bhBytes); err != nil {
				log.Printf("WARN: [Block Adder] Failed to update status for tx %s after block inclusion: %v", txID, err)
			} else {
				// Status update function now logs success
				// log.Printf("DEBUG: [Block Adder] Updated status for tx %s to 'included' in block %s...", txID, b.Hash.String()[:10])
			}
		}
	}(block, blockHashBytes) // Pass block and hash bytes to goroutine

	if bc.Libp2pManager != nil {
		if err := bc.Libp2pManager.BroadcastBlock(block); err != nil {
			log.Printf("WARN: [AddBlock] Failed to broadcast block %d via Libp2p: %v", block.Index, err)
			// Decide if broadcast failure should halt. Usually, it's a best-effort.
		} else {
			log.Printf("INFO: [AddBlock] Successfully broadcast block %d (Hash: %s) via Libp2p.", block.Index, block.Hash.String())
		}
	} else {
		log.Printf("WARN: [AddBlock] Libp2pManager is nil, cannot broadcast block %d.", block.Index)
	}

	// --- Final Success ---
	log.Printf("INFO: Successfully added and persisted Block %d proposed by %s.", block.Index, block.Validator)
	return nil
}

func (bc *BlockchainImpl) persistStateChangesToDB(dbTxContext types.TransactionContext, block *types.Block) error {
	log.Printf("DEBUG: [DB Persist] Persisting state changes for Block %d", block.Index)
	// Access config directly from the BlockchainImpl struct
	appConfig := bc.AppConfig

	for _, tx := range block.Transactions {
		// Use appConfig.MinGasFee for validation
		if !tx.IsGenesis() && !tx.IsFunding() {
			if tx.GasFee < appConfig.MinGasFee { // <-- Use bc.AppConfig.MinGasFee
				err := fmt.Errorf("transaction fee %d is below minimum required %d for tx %s", tx.GasFee, appConfig.MinGasFee, tx.ID)
				log.Printf("ERROR: [DB Persist] %v", err)
				return err
			}
		}

		// Determine Sender Address
		senderAddress := ""
		if tx.SenderPublicKey != nil {
			addr, err := tx.SenderPublicKey.Address()
			if err == nil {
				senderAddress = addr.String()
			} else {
				log.Printf("WARN: [DB Persist] Failed to get sender address for Tx %s: %v", tx.ID, err)
			}
		} else if !tx.IsGenesis() && !tx.IsFunding() { // Use methods from types.Transaction
			log.Printf("WARN: [DB Persist] Tx %s is missing SenderPublicKey (and is not Genesis/Funding).", tx.ID)
		}

		// Initialize sums for this transaction
		var totalInputAmount int64 = 0
		var totalOutputAmount int64 = 0

		// --- 1. Persist Input spending & Calculate totalInputAmount ---
		for _, input := range tx.Inputs { // input is types.UTXO
			utxoKey := input.Key() // Assuming types.UTXO has Key() method

			// Verify input UTXO exists and is not spent before attempting to spend
			// This might require a GetUTXO function in your store that uses dbTxContext
			// existingUtxo, errGet := bc.Blockchain.Database.GetUTXO(dbTxContext, utxoKey)
			// if errGet != nil {
			//     log.Printf("ERROR: [DB Persist] Failed to get input UTXO %s for validation in DB tx %s: %v", utxoKey, tx.ID, errGet)
			//     return fmt.Errorf("failed to validate input UTXO %s in DB for tx %s: %w", utxoKey, tx.ID, errGet)
			// }
			// if existingUtxo.IsSpent {
			//     log.Printf("ERROR: [DB Persist] Input UTXO %s already spent in DB for tx %s.", utxoKey, tx.ID)
			//     return fmt.Errorf("double spend detected in DB for UTXO %s in tx %s", utxoKey, tx.ID)
			// }

			// Now spend it
			amount, err := bc.Blockchain.Database.SpendUTXO(dbTxContext, utxoKey) // Requires store implementation
			if err != nil {
				log.Printf("ERROR: [DB Persist] Failed to spend input UTXO %s in DB for tx %s: %v", utxoKey, tx.ID, err)
				return fmt.Errorf("failed to spend input UTXO %s in DB for tx %s: %w", utxoKey, tx.ID, err)
			}
			totalInputAmount += amount
			log.Printf("DEBUG: [DB Persist] Spent UTXO %s (Amount: %d) for Tx %s", utxoKey, amount, tx.ID)
		}

		// --- 2. Persist Output creation, calculate totalOutputAmount & update recipient balances ---
		for i, output := range tx.Outputs { // output is types.UTXO value; 'i' is used
			err := bc.Blockchain.Database.AddNewUTXO(dbTxContext, output) // Requires store implementation
			if err != nil {
				log.Printf("ERROR: [DB Persist] Failed to add output UTXO %s to DB for tx %s: %v", output.Key(), tx.ID, err)
				return fmt.Errorf("failed to add output UTXO %s to DB for tx %s: %w", output.Key(), tx.ID, err)
			}
			log.Printf("DEBUG: [DB Persist] Added Output UTXO %s for Tx %s", output.Key(), tx.ID)

			outputAmount := int64(output.Amount) // Assuming output.Amount is amount.Amount (int64 alias)
			totalOutputAmount += outputAmount

			// Apply balance change using AddToBalance which handles existing/new keys
			err = bc.Blockchain.Database.AddToBalance(dbTxContext, output.OwnerAddress, outputAmount) // Requires store implementation
			if err != nil {
				log.Printf("ERROR: [DB Persist] Failed to update recipient %s balance in DB for tx %s output %d: %v", output.OwnerAddress, tx.ID, i, err)
				return fmt.Errorf("failed to update recipient %s balance in DB for tx %s output %d: %w", output.OwnerAddress, tx.ID, i, err)
			}
			// Log message from AddToBalance should confirm the update
			log.Printf("DEBUG: [DB Persist] Balance update initiated for %s (+%d) (Tx %s Output %d)", output.OwnerAddress, outputAmount, tx.ID, i)
		}

		// --- *** BEGIN MODIFIED SECTION 3: UPDATE SENDER BALANCE IN DB (Net Debit) *** ---
		if senderAddress != "" {
			// Calculate the fee (still useful for logging/validation)
			fee := totalInputAmount - totalOutputAmount
			if fee < 0 {
				// This should ideally be caught by earlier validation, but check again
				log.Printf("CRITICAL ERROR: [DB Persist] Negative fee calculated for Tx %s! Input: %d, Output: %d", tx.ID, totalInputAmount, totalOutputAmount)
				return fmt.Errorf("transaction %s results in negative fee during DB persistence", tx.ID)
			}
			// Log the fee calculation
			log.Printf("DEBUG: [DB Persist] Calculated fee for Tx %s: %d (Input: %d, Output: %d)", tx.ID, fee, totalInputAmount, totalOutputAmount)

			// Calculate change amount sent back to sender
			var changeAmount int64 = 0
			for _, output := range tx.Outputs {
				if output.OwnerAddress == senderAddress {
					changeAmount += int64(output.Amount) // Sum up all outputs returning to sender
				}
			}
			log.Printf("DEBUG: [DB Persist] Calculated change amount for sender %s: %d", senderAddress, changeAmount)

			// Calculate the NET amount to debit from the sender
			// netDebit = totalInputAmount - changeAmount
			// This equals amountSentToOthers + fee
			netDebit := totalInputAmount - changeAmount
			log.Printf("DEBUG: [DB Persist] Calculated Net Debit for sender %s: %d (Input: %d, Change: %d)", senderAddress, netDebit, totalInputAmount, changeAmount)

			// Ensure netDebit is not negative (shouldn't happen if fee >= 0)
			if netDebit < 0 {
				log.Printf("CRITICAL ERROR: [DB Persist] Calculated negative net debit (%d) for Tx %s!", netDebit, tx.ID)
				return fmt.Errorf("internal error: negative net debit calculated for tx %s", tx.ID)
			}

			// *** Apply Net Debit using AddToBalance with negative amount ***
			// Check if netDebit is zero - no balance change needed if sender only received change back exactly equal to input
			if netDebit > 0 {
				err := bc.Blockchain.Database.AddToBalance(dbTxContext, senderAddress, -netDebit) // Apply NEGATIVE netDebit
				if err != nil {
					// Check specifically for insufficient balance error
					// Note: This check might need adjustment based on the exact error message from your AddToBalance
					if strings.Contains(err.Error(), "insufficient balance") {
						// This indicates a potential double-spend or validation failure earlier
						log.Printf("ERROR: [DB Persist] Insufficient balance reported by DB for sender %s during Tx %s NET debit attempt (Debit: %d). Validation failed?", senderAddress, tx.ID, netDebit)
					} else {
						log.Printf("ERROR: [DB Persist] Failed to apply net debit for sender %s in DB for tx %s: %v", senderAddress, tx.ID, err)
					}
					// Propagate the error to trigger rollback
					return fmt.Errorf("failed to apply net debit for sender %s balance in DB for tx %s: %w", senderAddress, tx.ID, err)
				}
				// Log successful application of net debit
				log.Printf("DEBUG: [DB Persist] Balance update initiated for sender %s (-%d) (Tx %s Net Debit)", senderAddress, netDebit, tx.ID)
			} else {
				log.Printf("DEBUG: [DB Persist] Skipping zero net debit for sender %s (Tx %s)", senderAddress, tx.ID)
			}
			// *** End Net Debit Application ***

		} else if !tx.IsGenesis() && !tx.IsFunding() {
			if totalInputAmount < totalOutputAmount+int64(tx.GasFee) { // Check against tx.GasFee
				err := fmt.Errorf("insufficient input value (%d) to cover outputs (%d) + stated fee (%d) for tx %s", totalInputAmount, totalOutputAmount, tx.GasFee, tx.ID)
				log.Printf("ERROR: [DB Persist] %v", err)
				return err
			}
		}
		// --- End Input Coverage Validation ---

	} // End loop through transactions

	log.Printf("DEBUG: [DB Persist] Finished persisting state changes for Block %d", block.Index)
	return nil
}

func (bc *BlockchainImpl) updateStateForBlock(block *types.Block) error {
	if block == nil {
		return errors.New("cannot update state for nil block")
	}
	log.Printf("DEBUG: [State Update] Starting state update for Block %d", block.Index)

	if bc.Blockchain.UTXOs == nil {
		return fmt.Errorf("UTXO map is nil during state update for block %d", block.Index)
	}
	if bc.Blockchain.Stakeholders == nil {
		return fmt.Errorf("stakeholders map is nil during state update for block %d", block.Index)
	}

	for _, tx := range block.Transactions {
		log.Printf("DEBUG: [State Update] Processing Tx %s in Block %d", tx.ID, block.Index)

		var totalInputAmount int64 = 0
		var totalOutputAmount int64 = 0
		senderAddress := "" // String representation of sender address

		// Determine sender address string if public key exists
		if tx.SenderPublicKey != nil {
			addr, err := tx.SenderPublicKey.Address() // Assuming this returns address.Address type
			if err != nil {
				log.Printf("WARN: [State Update] Failed get sender addr for Tx %s: %v. Sender balance update might be skipped.", tx.ID, err)
			} else {
				senderAddress = addr.String() // Store the string representation
			}
		} else if !tx.IsGenesis() && !tx.IsFunding() { // Use methods from types.Transaction
			log.Printf("WARN: [State Update] Tx %s has nil SenderPublicKey and is not Genesis/Funding.", tx.ID)
			// senderAddress remains ""
		}

		// 1. Process Inputs (Remove spent UTXOs from map, Calculate Input Total from map state)
		// (Keep Section 1 exactly as it was in the previous correct version)
		for _, input := range tx.Inputs {
			utxoKey := input.Key()
			mapKey := utxoKey

			log.Printf("DEBUG: [State Update] Processing Input UTXO Map Key: %s for Tx %s", mapKey, tx.ID)

			utxoSlice, sliceExists := bc.Blockchain.UTXOs[mapKey]
			if !sliceExists || len(utxoSlice) == 0 {
				log.Printf("ERROR: [State Update] Input UTXO key %s not found in in-memory map for Tx %s.", mapKey, tx.ID)
				return fmt.Errorf("input UTXO %s not found in cache for tx %s during state update", mapKey, tx.ID)
			}
			if utxoSlice[0].IsSpent {
				log.Printf("ERROR: [State Update] Input UTXO key %s is already marked as spent in-memory map for Tx %s.", mapKey, tx.ID)
				return fmt.Errorf("double spend detected in-memory for UTXO %s in tx %s", mapKey, tx.ID)
			}
			if len(utxoSlice) > 1 {
				log.Printf("ERROR: [State Update] Ambiguous state for input key %s (slice len %d) for Tx %s.", mapKey, len(utxoSlice), tx.ID)
				return fmt.Errorf("ambiguous state for input UTXO %s (slice length %d) for tx %s", mapKey, len(utxoSlice), tx.ID)
			}
			spentProtoUTXO := utxoSlice[0]
			totalInputAmount += spentProtoUTXO.Amount
			delete(bc.Blockchain.UTXOs, mapKey)
			log.Printf("DEBUG: [State Update] Removed/Marked spent UTXO key %s (Amount: %d).", mapKey, spentProtoUTXO.Amount)
		}

		// --- *** BEGIN REVERTED/REFINED SECTION 2 *** ---
		// 2. Process Outputs (Add to UTXO map, Unconditionally credit recipient balances)
		// NOTE: This will temporarily inflate the sender's balance if change exists,
		// but Section 3 will correct it IF senderAddress is known.
		for i, output := range tx.Outputs { // output is types.UTXO value
			newUtxoKey := output.Key()
			mapKey := newUtxoKey

			protoUtxo := convertTypesUTXOToProtoUTXO(output) // Use helper function
			if protoUtxo == nil {
				log.Printf("ERROR: [State Update] Failed convert output %d for Tx %s to proto UTXO.", i, tx.ID)
				continue
			}

			// Add the new UTXO to the map
			bc.Blockchain.UTXOs[mapKey] = append(bc.Blockchain.UTXOs[mapKey], protoUtxo)
			log.Printf("DEBUG: [State Update] Appended new proto UTXO key %s (Owner: %s, Amount: %d) to map slice.", mapKey, protoUtxo.OwnerAddress, protoUtxo.Amount)

			// --- ** REVERTED LOGIC ** ---
			// Unconditionally update the balance for the output owner address.
			recipientAddr := output.OwnerAddress // This is a string
			currentBalance, _ := bc.Blockchain.Stakeholders[recipientAddr]
			outputAmount := int64(output.Amount)
			bc.Blockchain.Stakeholders[recipientAddr] = currentBalance + outputAmount
			// Log this update, indicating it might be temporary for the sender
			logString := "DEBUG: [State Update] Updated Stakeholders balance for output %d owner %s: %d -> %d (+%d)"
			if recipientAddr == senderAddress {
				logString += " (Change Output - Balance will be corrected in Section 3)"
			}
			log.Printf(logString, i, recipientAddr, currentBalance, bc.Blockchain.Stakeholders[recipientAddr], outputAmount)
			// --- ** END REVERTED LOGIC ** ---

			// Still add all output amounts to totalOutputAmount for fee calculation
			totalOutputAmount += int64(output.Amount)
		}
		// --- *** END REVERTED/REFINED SECTION 2 *** ---

		// --- *** SECTION 3: UPDATE SENDER BALANCE *** ---
		// This section remains unchanged and correctly calculates the final sender balance
		// if the senderAddress could be determined.
		if senderAddress != "" {
			fee := totalInputAmount - totalOutputAmount
			if fee < 0 {
				log.Printf("ERROR: [State Update] Negative fee calculated for Tx %s (Input: %d, Output: %d)! Halting block processing.", tx.ID, totalInputAmount, totalOutputAmount)
				return fmt.Errorf("negative fee calculated for tx %s in block %d", tx.ID, block.Index)
			}
			if fee != 0 {
				log.Printf("DEBUG: [State Update] Calculated fee for Tx %s: %d (Input: %d, Output: %d)", tx.ID, fee, totalInputAmount, totalOutputAmount)
			}

			senderBalanceBeforeTx, senderExists := bc.Blockchain.Stakeholders[senderAddress]
			// Note: senderBalanceBeforeTx here INCLUDES the change amount added back in section 2

			if !senderExists {
				// This check might be less reliable now if sender didn't exist before but received change in sec 2
				// It's better to rely on input validation ensuring sender has funds initially.
				log.Printf("ERROR: [State Update] Sender %s not found in Stakeholders map for Tx %s final balance update check (should exist if inputs were valid).", senderAddress, tx.ID)
				// Continue cautiously, the calculation might still work if change was added
				// return fmt.Errorf("sender %s not found for tx %s in block %d", senderAddress, tx.ID, block.Index)
			}

			// Calculate change amount explicitly (needed for the final balance calculation)
			changeAmount := int64(0)
			for _, output := range tx.Outputs {
				if output.OwnerAddress == senderAddress {
					changeAmount += int64(output.Amount)
				}
			}

			// Calculate final balance: Start with initial balance recorded *before* section 2 ran its course for this TX
			// To get the true initial balance, we subtract the change that section 2 just added:
			trueInitialSenderBalance := senderBalanceBeforeTx - changeAmount

			// Calculate final balance based on the true initial balance:
			finalSenderBalance := trueInitialSenderBalance - totalInputAmount + changeAmount

			if finalSenderBalance < 0 {
				log.Printf("ERROR: [State Update] Calculated negative final balance (%d) for sender %s for Tx %s. TrueInitial: %d, InputTotal: %d, Change: %d.", finalSenderBalance, senderAddress, tx.ID, trueInitialSenderBalance, totalInputAmount, changeAmount)
				return fmt.Errorf("calculated negative final balance for sender %s in tx %s", senderAddress, tx.ID)
			}

			// Update the sender's balance in the map directly to the calculated final balance
			bc.Blockchain.Stakeholders[senderAddress] = finalSenderBalance
			// Log the transition from the balance *after* section 2 ran to the final correct balance
			log.Printf("DEBUG: [State Update] Corrected Stakeholders balance for SENDER %s: %d (Post-Sec2) -> %d (Final) (Inputs: %d, Change: %d, Fee: %d)", senderAddress, senderBalanceBeforeTx, finalSenderBalance, totalInputAmount, changeAmount, fee)

		} else {
			// Log if sender update is skipped due to unknown sender
			log.Printf("DEBUG: [State Update] Skipping Section 3 sender balance correction for Tx %s because sender address is unknown (SenderPublicKey was nil).", tx.ID)
		}
		// --- *** END SECTION 3 *** ---

	} // End loop through transactions

	log.Printf("DEBUG: [State Update] Finished state update for Block %d.", block.Index)
	return nil
}

func NewBlockchain(setupConfig *types.BlockchainConfig, appConfig *config.Config, libp2pManager *network.Libp2pManager) (*BlockchainImpl, types.Store, error) { // <--- ADD libp2pManager argument
	if setupConfig == nil || appConfig == nil {
		log.Panic("FATAL: NewBlockchain called with nil config")
	}
	if setupConfig.GenesisAccount == nil {
		log.Panic("FATAL: NewBlockchain called but setupConfig.GenesisAccount is nil")
	}
	if libp2pManager == nil { // Validate this crucial dependency
		log.Panic("FATAL: NewBlockchain called with nil Libp2pManager")
	}

	database, err := store.NewDatabase(setupConfig.DataDir)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to initialize the blockchain database: %v", err)
	}

	storeInstance, err := store.NewStore(database, setupConfig.AESKey)
	if err != nil {
		database.Close()
		return nil, nil, fmt.Errorf("failed to create store: %v", err)
	}

	database.Blockchain = storeInstance
	log.Println("BlockchainDB created")

	genesis := NewGenesisBlock()
	log.Println("Genesis block created")
	publicKeyMap := make(map[string]*crypto.PublicKey)
	totalSupplyNano := int64(120000000 * 1e9)
	log.Printf("Initializing genesis account with total supply: %.2f THR", float64(totalSupplyNano)/1e9)

	stakeholdersMap := make(map[string]int64)
	privKey := setupConfig.GenesisAccount

	var pubKey crypto.PublicKey = privKey.PublicKey()
	if pubKey == nil { /* handle error */
	}

	addr, err := pubKey.Address()
	if err != nil { /* handle error */
	}

	genesisAddressString := addr.String()
	stakeholdersMap[genesisAddressString] = totalSupplyNano

	log.Printf("Genesis account address: %s", genesisAddressString)

	log.Printf("DEBUG: Attempting to save Public Key for address %s", genesisAddressString)
	err = storeInstance.SavePublicKey(pubKey)
	if err != nil {
		log.Printf("WARN: Could not save genesis public key (may already exist): %v", err)
	} else {
		log.Printf("DEBUG: Successfully saved/updated Public Key for genesis address %s", genesisAddressString)
	}

	dummySignatureBytes := make([]byte, crypto.MLDSASignatureSize)

	genesisTx := &thrylos.Transaction{
		Id:        "genesis_tx_" + addr.String(),
		Timestamp: time.Now().Unix(),
		Sender:    "",
		Outputs: []*thrylos.UTXO{{
			OwnerAddress: addr.String(),
			Amount:       totalSupplyNano,
		}},
		Signature:       dummySignatureBytes,
		SenderPublicKey: nil,
		Inputs:          nil,
		Gasfee:          0,
	}
	utxoMap := make(map[string][]*thrylos.UTXO)
	utxoKey := fmt.Sprintf("%s:%d", genesisTx.Id, 0)
	utxoMap[utxoKey] = []*thrylos.UTXO{genesisTx.Outputs[0]}

	sharedGenesisTx := utils.ConvertToSharedTransaction(genesisTx)
	if sharedGenesisTx == nil {
		log.Println("CRITICAL ERROR: Failed to convert genesis protobuf transaction.")
		storeInstance.Close()
		return nil, nil, fmt.Errorf("failed to convert genesis transaction")
	}
	genesis.Transactions = []*types.Transaction{sharedGenesisTx}

	// REMOVE THIS: stateNetwork := network.NewDefaultNetwork() // No longer used for P2P
	messageBus := types.GetGlobalMessageBus()

	temp := &BlockchainImpl{
		Blockchain: &types.Blockchain{
			Blocks:               []*types.Block{genesis},
			Genesis:              genesis,
			Stakeholders:         stakeholdersMap,
			Database:             storeInstance,
			PublicKeyMap:         publicKeyMap,
			UTXOs:                utxoMap,
			Forks:                make([]*types.Fork, 0),
			GenesisAccount:       privKey,
			PendingTransactions:  make([]*thrylos.Transaction, 0),
			ActiveValidators:     make([]string, 0),
			TestMode:             setupConfig.TestMode,
			ValidatorKeys:        store.NewValidatorKeyStore(database, addr.Bytes()),
			MinStakeForValidator: big.NewInt(appConfig.MinimumStakeAmount()),
		},
		MessageBus:    messageBus,
		AppConfig:     appConfig,
		Libp2pManager: libp2pManager, // <--- NEW: Store the Libp2pManager here
	}

	temp.TransactionPropagator = &types.TransactionPropagator{
		Blockchain: temp,
		Mu:         sync.RWMutex{},
	}
	temp.txPool = NewTxPool(database, temp)

	log.Println("Initializing BalanceUpdateQueue...")
	balanceQueue := balance.NewBalanceUpdateQueue()
	if balanceQueue == nil {
		database.Close()
		return nil, nil, fmt.Errorf("failed to initialize BalanceUpdateQueue")
	}
	log.Println("BalanceUpdateQueue initialized successfully.")

	log.Println("Initializing StakingService...")
	stakingSvc := staking.NewStakingService(temp.Blockchain)
	if stakingSvc == nil {
		database.Close()
		return nil, nil, fmt.Errorf("failed to initialize StakingService")
	}
	log.Println("StakingService initialized successfully.")

	log.Println("Initializing TransactionProcessorImpl...")
	txProcessor := processor.NewTransactionProcessorImpl(
		temp.TransactionPropagator,
		balanceQueue,
		temp.Blockchain,
		storeInstance,
		stakingSvc,
	)
	if txProcessor == nil {
		database.Close()
		return nil, nil, fmt.Errorf("failed to initialize TransactionProcessorImpl")
	}
	log.Println("TransactionProcessorImpl initialized successfully.")

	log.Println("Initializing DAGManager...")
	dagMan := processor.NewDAGManager()
	if dagMan == nil {
		database.Close()
		return nil, nil, fmt.Errorf("failed to initialize DAGManager")
	}
	temp.dagManager = dagMan
	log.Println("DAGManager initialized successfully.")

	log.Println("Initializing ModernProcessor...")
	temp.modernProcessor = processor.NewModernProcessor(txProcessor, libp2pManager, temp.txPool, temp.dagManager) // <--- CORRECTED ORDER
	if temp.modernProcessor == nil {
		database.Close()
		return nil, nil, fmt.Errorf("failed to initialize modern processor")
	}
	log.Println("ModernProcessor initialized successfully.")

	ch := make(chan types.Message, 100)
	temp.MessageBus.Subscribe(types.FundNewAddress, ch)
	go func() {
		log.Println("Started FundNewAddress message listener")
		for msg := range ch {
			log.Printf("Received message: %s", msg.Type)
			if msg.Type == types.FundNewAddress {
				temp.HandleFundNewAddress(msg)
			}
		}
	}()

	balanceCh := make(chan types.Message, 100)
	temp.MessageBus.Subscribe(types.GetStakeholderBalance, balanceCh)
	go func() {
		log.Println("Started GetStakeholderBalance message listener")
		for msg := range balanceCh {
			log.Printf("Received balance message: %s", msg.Type)
			if msg.Type == types.GetStakeholderBalance {
				temp.HandleGetBalance(msg)
			}
		}
	}()

	publicKeyMap[addr.String()] = &pubKey
	log.Println("Genesis account public key added to publicKeyMap")
	log.Printf("Inserting block %d into database", genesis.Index)
	if err := database.Blockchain.SaveBlock(genesis); err != nil {
		log.Printf("CRITICAL ERROR: Failed to save genesis block to the database: %v", err)
		storeInstance.Close()
		return nil, nil, fmt.Errorf("failed to save genesis block: %w", err)
	}
	log.Printf("Block %d inserted successfully", genesis.Index)

	log.Printf("Genesis account %s initialized with total supply: %d nanoTHRYLOS", addr.String(), totalSupplyNano)

	go func() {
		c := make(chan os.Signal, 1)
		signal.Notify(c, os.Interrupt, syscall.SIGTERM)
		<-c
		log.Println("Stopping blockchain...")
		// Consider calling temp.Close() here for graceful shutdown
	}()

	if !setupConfig.DisableBackground {
		log.Println("Starting background processes...") // Existing log

		// --- ADDED: Start Periodic Validator Update ---
		// Determine interval and count (using defaults or config)
		validatorUpdateInterval := 1 * time.Minute          // Example: Update every minute
		maxActiveValidators := 5                            // Example: Max 5 active validators
		if appConfig != nil && appConfig.Consensus != nil { // Safely access nested config
			if appConfig.Consensus.ValidatorUpdateInterval > 0 {
				validatorUpdateInterval = time.Duration(appConfig.Consensus.ValidatorUpdateInterval) * time.Second
			}
			if appConfig.Consensus.MaxActiveValidators > 0 {
				maxActiveValidators = appConfig.Consensus.MaxActiveValidators
			}
		}
		log.Printf("Starting periodic validator update: Interval=%v, MaxValidators=%d", validatorUpdateInterval, maxActiveValidators)
		// This line starts the goroutine that periodically calls UpdateActiveValidators
		// Ensure StartPeriodicValidatorUpdate method exists on *BlockchainImpl
		go temp.StartPeriodicValidatorUpdate(validatorUpdateInterval, maxActiveValidators)
		// --- END ADDED SECTION ---

		// Start Block Creation Loop (Existing Code - assumes it follows)
		go func(bci *BlockchainImpl) { // <--- Pass *BlockchainImpl as 'bci'
			syncTicker := time.NewTicker(5 * time.Minute)
			defer syncTicker.Stop()
			for range syncTicker.C {
				// Now use 'bci' instead of 'bc'
				if bci.Libp2pManager != nil { // <--- Use bci.Libp2pManager
					log.Println("INFO: Initiating periodic blockchain sync...")
					bci.Libp2pManager.SyncBlockchain() // <--- Use bci.Libp2pManager
				} else {
					log.Println("WARN: Libp2pManager is nil, cannot perform periodic sync.")
				}
			}
		}(temp) // <--- Pass 'temp' here when launching the goroutine
	} else {
		log.Println("Background processes disabled for testing")
	}

	log.Println("NewBlockchain initialization completed successfully")
	return temp, storeInstance, nil
}

// // // ensuring that no blocks have been altered or inserted maliciously.
func (bc *BlockchainImpl) CheckChainIntegrity() bool {
	for i := 1; i < len(bc.Blockchain.Blocks); i++ {
		prevBlock := bc.Blockchain.Blocks[i-1]
		currentBlock := bc.Blockchain.Blocks[i]

		if !currentBlock.PrevHash.Equal(prevBlock.Hash) {
			fmt.Printf("Invalid previous hash in block %d\n", currentBlock.Index)
			return false
		}

		blockBytes, err := SerializeForSigning(currentBlock)
		if err != nil {
			fmt.Printf("Failed to serialize block %d: %v\n", currentBlock.Index, err)
			return false
		}
		computedHash := hash.NewHash(blockBytes)

		if !currentBlock.Hash.Equal(computedHash) {
			fmt.Printf("Invalid hash in block %d\n", currentBlock.Index)
			return false
		}
	}
	return true
}

// helper methods
func (bc *BlockchainImpl) GetGenesis() *types.Block {
	return bc.Blockchain.Genesis
}

func (bc *BlockchainImpl) GetBlocks() []*types.Block {
	return bc.Blockchain.Blocks
}

func (bc *BlockchainImpl) Status() string {
	return fmt.Sprintf("Height: %d, Blocks: %d",
		len(bc.Blockchain.Blocks)-1,
		len(bc.Blockchain.Blocks))
}

func (bc *BlockchainImpl) HandleGetBalance(msg types.Message) {
	address, ok := msg.Data.(string)
	if !ok {
		msg.ResponseCh <- types.Response{Error: fmt.Errorf("invalid address format")}
		return
	}

	log.Printf("DEBUG-BALANCE: HandleGetBalance called for address: %s", address)

	// Access the stakeholders map
	bc.Blockchain.Mu.RLock()

	// Direct map access check
	mapSize := len(bc.Blockchain.Stakeholders)
	log.Printf("DEBUG-BALANCE: Stakeholders map has %d entries", mapSize)

	// Check for specific addresses
	genesis, _ := bc.Blockchain.GenesisAccount.PublicKey().Address()
	genesisAddr := genesis.String()
	genesisBalance, genesisExists := bc.Blockchain.Stakeholders[genesisAddr]
	log.Printf("DEBUG-BALANCE: Genesis address %s exists: %v, balance: %d",
		genesisAddr, genesisExists, genesisBalance)

	testBalance, testExists := bc.Blockchain.Stakeholders["test_address_123"]
	log.Printf("DEBUG-BALANCE: Test address exists: %v, balance: %d", testExists, testBalance)

	// Check the target address
	targetBalance, targetExists := bc.Blockchain.Stakeholders[address]
	log.Printf("DEBUG-BALANCE: Target address %s exists: %v, balance: %d",
		address, targetExists, targetBalance)

	// Print all entries in the map
	log.Printf("DEBUG-BALANCE: All addresses in map:")
	for addr, bal := range bc.Blockchain.Stakeholders {
		log.Printf("  %s: %d", addr, bal)
	}

	// Get the final balance
	balance := int64(0)
	if targetExists {
		balance = targetBalance
		log.Printf("DEBUG-BALANCE: Using balance %d from map", balance)
	} else {
		log.Printf("DEBUG-BALANCE: No balance found, using 0")
	}

	bc.Blockchain.Mu.RUnlock()

	// Send the response
	log.Printf("DEBUG-BALANCE: Sending final balance: %d", balance)
	msg.ResponseCh <- types.Response{Data: balance}
}

func (bc *BlockchainImpl) TestStakeholdersMap() {
	testAddress := "test_address_123"

	// Print initial state
	bc.Blockchain.Mu.RLock()
	log.Printf("TEST: Initial stakeholders map:")
	for addr, bal := range bc.Blockchain.Stakeholders {
		log.Printf("  %s: %d", addr, bal)
	}
	initialBalance, exists := bc.Blockchain.Stakeholders[testAddress]
	bc.Blockchain.Mu.RUnlock()

	log.Printf("TEST: Initial balance for %s: %d (exists: %v)", testAddress, initialBalance, exists)

	// Modify the map
	bc.Blockchain.Mu.Lock()
	bc.Blockchain.Stakeholders[testAddress] = 12345
	bc.Blockchain.Mu.Unlock()

	// Check if the modification worked
	bc.Blockchain.Mu.RLock()
	newBalance, exists := bc.Blockchain.Stakeholders[testAddress]
	bc.Blockchain.Mu.RUnlock()

	log.Printf("TEST: After modification, balance for %s: %d (exists: %v)", testAddress, newBalance, exists)

	// Print final state
	bc.Blockchain.Mu.RLock()
	log.Printf("TEST: Final stakeholders map:")
	for addr, bal := range bc.Blockchain.Stakeholders {
		log.Printf("  %s: %d", addr, bal)
	}
	bc.Blockchain.Mu.RUnlock()
}

// Block functions
func (bc *BlockchainImpl) GetLastBlock() (*types.Block, int, error) {
	// Query the last block data and index
	blockData, err := bc.Blockchain.Database.GetLastBlockData()
	if err != nil {
		if err == sql.ErrNoRows {
			// Handle no rows returned, which means the blockchain is empty
			return nil, 0, nil
		}
		return nil, 0, err
	}

	// Get the last block index
	lastIndex, err := bc.Blockchain.Database.GetLastBlockIndex()
	if err != nil {
		return nil, 0, err
	}

	// Deserialize the block
	var lastBlock types.Block
	buffer := bytes.NewBuffer(blockData)
	decoder := gob.NewDecoder(buffer)
	err = decoder.Decode(&lastBlock)
	if err != nil {
		return nil, 0, err
	}

	// Return the block along with its index
	return &lastBlock, lastIndex, nil
}

func (bc *BlockchainImpl) GetBlockCount() int {
	bc.Blockchain.Mu.RLock()
	defer bc.Blockchain.Mu.RUnlock()
	return len(bc.Blockchain.Blocks)
}

func (bc *BlockchainImpl) GetBlock(blockNumber int) (*types.Block, error) {
	blockData, err := bc.Blockchain.Database.RetrieveBlock(blockNumber)
	if err != nil {
		return nil, fmt.Errorf("failed to retrieve block data: %v", err)
	}

	var block types.Block
	if err := json.Unmarshal(blockData, &block); err != nil { // Deserialize here
		return nil, fmt.Errorf("failed to deserialize block: %v", err)
	}
	return &block, nil
}

func (bc *BlockchainImpl) GetBlockByID(id string) (*types.Block, error) { // Changed return type to pointer
	// First, try to parse id as a block index
	if index, err := strconv.Atoi(id); err == nil {
		// id is a valid integer, so we treat it as a block index
		if index >= 0 && index < len(bc.Blockchain.Blocks) {
			block := bc.Blockchain.Blocks[index]
			log.Printf("Block found by index: Index=%d, Transactions=%v", block.Index, block.Transactions)
			return block, nil
		}
	}

	// If id is not a valid index, try to match it as a hash
	idBytes, err := hex.DecodeString(id)
	if err != nil {
		log.Printf("Invalid block ID format: %s", id)
		return nil, errors.New("invalid block ID format")
	}

	// Create a Hash from the bytes
	idHash, err := hash.FromBytes(idBytes)
	if err != nil {
		return nil, fmt.Errorf("invalid hash bytes: %v", err)
	}

	// Iterate over blocks and find by hash
	for _, block := range bc.Blockchain.Blocks {
		if block.Hash.Equal(idHash) { // Use the Equal method from Hash type
			log.Printf("Block found by hash: Index=%d, Transactions=%v", block.Index, block.Transactions)
			return block, nil
		}
	}

	log.Println("Block not found with ID:", id)
	return nil, errors.New("block not found")
}
