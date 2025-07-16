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
	ShardState            *types.ChainState // This is the core, shard-specific state
	TransactionPropagator *types.TransactionPropagator
	modernProcessor       *processor.ModernProcessor
	txPool                types.TxPool
	dagManager            *processor.DAGManager
	MessageBus            types.MessageBusInterface
	AppConfig             *config.Config
	Libp2pManager         *network.Libp2pManager
}

// GetChainState provides access to the underlying types.ChainState.
// This is the method main.go will call to pass the state to node.NewNode etc.
func (bc *BlockchainImpl) GetChainState() *types.ChainState {
	return bc.ShardState
}

// Close closes the underlying database
func (bc *BlockchainImpl) Close() error {
	log.Println("Closing blockchain resources...")

	if bc.ShardState != nil && bc.ShardState.Database != nil { // Access ShardState.Database
		// Get lock file path
		lockFile := bc.ShardState.Database.GetLockFilePath()
		if lockFile != "" {
			log.Printf("Lock file path: %s", lockFile)
		}

		// Close the database
		if err := bc.ShardState.Database.Close(); err != nil {
			return fmt.Errorf("error closing database for shard %d: %v", bc.ShardState.ShardID, err)
		}
		log.Printf("Database closed successfully for shard %d", bc.ShardState.ShardID)
	}

	log.Println("Blockchain resources closed successfully")
	return nil
}

// AddBlockToChain handles validation, state updates, and persistence for a new signed block.
// This method now operates on the ShardState of this BlockchainImpl instance.
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
	log.Printf("Attempting to add Block %d (Validator: %s) to chain (Shard: %d)...", block.Index, block.Validator, bc.ShardState.ShardID)

	// --- 1. Verify Signature (No Lock Needed Yet) ---
	log.Printf("Verifying signature for block %d from validator %s...", block.Index, block.Validator)

	// You need to ensure GetValidatorPublicKey is shard-aware or global.
	// For now, assuming it gets it from the ShardState's ValidatorKeys.
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

	isValid := mldsa44.Verify(validatorPubKey, recomputedHash.Bytes(), nil, signatureBytes)
	if !isValid {
		log.Printf("ERROR: [AddBlock] Block %d verification failed - Invalid signature from validator %s.", block.Index, block.Validator)
		log.Printf("DEBUG: [AddBlock Verify Failed] PubKey (mldsa44 bytes): %x", retrievedRawBytes)
		log.Printf("DEBUG: [AddBlock Verify Failed] Hash: %x", recomputedHash.Bytes())
		log.Printf("DEBUG: [AddBlock Verify Failed] Sig: %x", signatureBytes)
		return fmt.Errorf("block verification failed: invalid signature")
	}
	log.Printf("Block %d signature verified successfully against recomputed hash.", block.Index)

	if err := Verify(block); err != nil { // Calls Verify from block.go
		log.Printf("ERROR: [AddBlock] Block %d failed full verification (Merkle/Hash): %v", block.Index, err)
		return fmt.Errorf("block verification failed (Merkle/Hash): %w", err)
	}
	log.Printf("Block %d Merkle root and hash verified successfully.", block.Index)

	// --- Acquire Lock for state update and chain modification (for THIS shard) ---
	bc.ShardState.Mu.Lock()
	defer bc.ShardState.Mu.Unlock()

	// --- 2. Final Validation Under Lock (Index, PrevHash against actual last block for THIS shard) ---
	// All these checks must be against the ShardState's Blocks slice.
	if len(bc.ShardState.Blocks) == 0 {
		if block.Index != 0 {
			return fmt.Errorf("cannot add non-genesis block %d to empty chain (Shard: %d)", block.Index, bc.ShardState.ShardID)
		}
	} else {
		prevBlock := bc.ShardState.Blocks[len(bc.ShardState.Blocks)-1]
		if block.Index != prevBlock.Index+1 {
			return fmt.Errorf("invalid block index under lock for shard %d: expected %d, got %d", bc.ShardState.ShardID, prevBlock.Index+1, block.Index)
		}
		if !block.PrevHash.Equal(prevBlock.Hash) {
			log.Printf("PrevHash mismatch under lock for shard %d! Expected: %s, Got: %s", bc.ShardState.ShardID, prevBlock.Hash.String(), block.PrevHash.String())
			return fmt.Errorf("invalid PrevHash under lock for shard %d: expected %s, got %s", bc.ShardState.ShardID, prevBlock.Hash.String(), block.PrevHash.String())
		}
	}

	// --- ATOMIC DATABASE PERSISTENCE (for THIS shard's database) ---
	dbTxContext, err := bc.ShardState.Database.BeginTransaction()
	if err != nil {
		log.Printf("ERROR: Failed to begin DB transaction for block %d on shard %d: %v", block.Index, bc.ShardState.ShardID, err)
		return fmt.Errorf("failed start DB tx for block %d on shard %d: %w", block.Index, bc.ShardState.ShardID, err)
	}
	var finalErr error
	defer func() {
		if finalErr != nil && dbTxContext != nil {
			log.Printf("WARN: Rolling back DB transaction for block %d on shard %d due to error: %v", block.Index, bc.ShardState.ShardID, finalErr)
			_ = bc.ShardState.Database.RollbackTransaction(dbTxContext)
		}
	}()

	// 3. Persist State Changes (using the shard-specific database)
	// This function (persistStateChangesToDB) needs to be updated internally to pass ShardID to store methods.
	finalErr = bc.persistStateChangesToDB(dbTxContext, block)
	if finalErr != nil {
		log.Printf("ERROR: Failed to persist state changes to DB for block %d on shard %d: %v", block.Index, bc.ShardState.ShardID, finalErr)
		return finalErr
	}
	log.Printf("DEBUG: Successfully persisted state changes to DB for Block %d (within transaction) on shard %d.", block.Index, bc.ShardState.ShardID)

	// 4. Persist Block Data (using the shard-specific database)
	// SaveBlockWithContext needs to be updated internally to pass ShardID to store methods.
	finalErr = bc.ShardState.Database.SaveBlockWithContext(dbTxContext, block)
	if finalErr != nil {
		log.Printf("ERROR: Failed to save block %d data to DB for shard %d: %v", block.Index, bc.ShardState.ShardID, finalErr)
		return finalErr
	}
	log.Printf("DEBUG: Successfully saved block %d data to DB (within transaction) on shard %d.", block.Index, bc.ShardState.ShardID)

	// 5. Commit DB Transaction
	commitErr := bc.ShardState.Database.CommitTransaction(dbTxContext)
	if commitErr != nil {
		finalErr = fmt.Errorf("failed to commit DB transaction for block %d on shard %d: %w", block.Index, bc.ShardState.ShardID, commitErr)
		log.Printf("CRITICAL ERROR: %v. DB state may be inconsistent.", finalErr)
		dbTxContext = nil
		return finalErr
	}
	dbTxContext = nil
	log.Printf("DEBUG: Successfully committed DB transaction for Block %d on shard %d.", block.Index, bc.ShardState.ShardID)

	// --- UPDATE IN-MEMORY STATE (Only after successful commit, for THIS shard) ---
	// 6. Append block
	bc.ShardState.Blocks = append(bc.ShardState.Blocks, block)
	log.Printf("INFO: Appended block %d to in-memory chain (Hash: %s) for shard %d", block.Index, block.Hash.String(), bc.ShardState.ShardID)

	// 7. Update UTXOs and Balances (for THIS shard's in-memory maps)
	// This function (updateStateForBlock) needs to be updated internally to use ShardState.
	if err := bc.updateStateForBlock(block); err != nil {
		log.Printf("CRITICAL ERROR: In-memory state update failed for committed block %d on shard %d: %v. State inconsistent!", block.Index, bc.ShardState.ShardID, err)
		return fmt.Errorf("CRITICAL: in-memory state update failed post-commit for block %d on shard %d: %w", block.Index, bc.ShardState.ShardID, err)
	}
	log.Printf("DEBUG: Successfully updated in-memory state (Stakeholders, UTXOs) for Block %d on shard %d.", block.Index, bc.ShardState.ShardID)

	// 8. Update timestamp
	bc.ShardState.LastTimestamp = block.Timestamp

	// --- Trigger Notifications & Status Updates ---
	if bc.ShardState.OnNewBlock != nil {
		go bc.ShardState.OnNewBlock(block)
	}
	blockHashBytes := block.Hash.Bytes()
	go func(b *types.Block, bhBytes []byte) {
		for _, tx := range b.Transactions {
			txID := tx.ID
			// UpdateTransactionStatus needs to be shard-aware if status is per-shard
			if err := bc.UpdateTransactionStatus(txID, "included", bhBytes); err != nil {
				log.Printf("WARN: [Block Adder] Failed to update status for tx %s after block inclusion on shard %d: %v", txID, bc.ShardState.ShardID, err)
			}
		}
	}(block, blockHashBytes)

	// Broadcast the block only to relevant peers (those interested in this shard).
	// Libp2pManager will need logic to filter/route based on shard.
	if bc.Libp2pManager != nil {
		// You'll need to modify BroadcastBlock to accept the ShardID
		if err := bc.Libp2pManager.BroadcastBlock(block); err != nil { // Needs `shardID` parameter
			log.Printf("WARN: [AddBlock] Failed to broadcast block %d for shard %d via Libp2p: %v", block.Index, bc.ShardState.ShardID, err)
		} else {
			log.Printf("INFO: [AddBlock] Successfully broadcast block %d (Hash: %s) for shard %d via Libp2p.", block.Index, block.Hash.String(), bc.ShardState.ShardID)
		}
	} else {
		log.Printf("WARN: [AddBlock] Libp2pManager is nil, cannot broadcast block %d for shard %d.", block.Index, bc.ShardState.ShardID)
	}

	log.Printf("INFO: Successfully added and persisted Block %d proposed by %s for shard %d.", block.Index, block.Validator, bc.ShardState.ShardID)
	return nil
}

func (bc *BlockchainImpl) persistStateChangesToDB(dbTxContext types.TransactionContext, block *types.Block) error {
	log.Printf("DEBUG: [DB Persist] Persisting state changes for Block %d on Shard %d", block.Index, bc.ShardState.ShardID)
	appConfig := bc.AppConfig

	for _, tx := range block.Transactions {
		// For simplicity, this assumes transactions within a block belong to THIS shard.
		// Cross-shard transactions would complicate this with explicit messaging/proofs.
		txShardID := store.CalculateShardID(tx.SenderAddress.String(), bc.AppConfig.NumShards) // Use config.NumShards

		if txShardID != bc.ShardState.ShardID && bc.ShardState.ShardID != types.ShardID(-1) { // If it's not for this shard, and not beacon
			log.Printf("WARN: [DB Persist] Skipping transaction %s (sender shard %d) as it's not for this shard %d. This implies a cross-shard transaction that needs special handling or a protocol error.",
				tx.ID, txShardID, bc.ShardState.ShardID)
			continue // Skip, or error out if strict single-shard validation is desired
		}
		// If it's a beacon node, it might process all transactions and route them.
		// For simplicity, beacon node also filters for its own (non-existent) shard, so it might process nothing here
		// unless beacon chain transactions exist.

		if !tx.IsGenesis() && !tx.IsFunding() {
			if tx.GasFee < appConfig.MinGasFee {
				err := fmt.Errorf("transaction fee %d is below minimum required %d for tx %s", tx.GasFee, appConfig.MinGasFee, tx.ID)
				log.Printf("ERROR: [DB Persist] %v", err)
				return err
			}
		}

		senderAddress := ""
		if tx.SenderPublicKey != nil {
			addr, err := tx.SenderPublicKey.Address()
			if err == nil {
				senderAddress = addr.String()
			} else {
				log.Printf("WARN: [DB Persist] Failed to get sender address for Tx %s: %v", tx.ID, err)
			}
		} else if !tx.IsGenesis() && !tx.IsFunding() {
			log.Printf("WARN: [DB Persist] Tx %s is missing SenderPublicKey (and is not Genesis/Funding).", tx.ID)
		}

		var totalInputAmount int64 = 0
		var totalOutputAmount int64 = 0

		// --- 1. Persist Input spending & Calculate totalInputAmount ---
		for _, input := range tx.Inputs {
			utxoKey := input.Key() // Assuming types.UTXO has Key() method "txid-index"

			// Get the shard ID for the owner of this UTXO
			// This is critical: the UTXO's owner's address determines its shard
			// REPLACE the problematic validation with this:
			if bc.ShardState.ShardID == types.ShardID(-1) {
				// Beacon chain can process UTXOs from any shard
				log.Printf("DEBUG: [DB Persist] Beacon chain processing UTXO %s from any shard", utxoKey)
			} else {
				// For regular shards, validate same-shard ownership
				inputOwnerShardID := store.CalculateShardID(input.OwnerAddress, bc.AppConfig.NumShards)
				if inputOwnerShardID != bc.ShardState.ShardID {
					return fmt.Errorf("attempt to spend UTXO %s from shard %d on current shard %d for tx %s (cross-shard tx not fully supported here)",
						utxoKey, inputOwnerShardID, bc.ShardState.ShardID, tx.ID)
				}
			}

			// SpendUTXO needs to be updated to pass ShardID, or its internal implementation will use it
			// Assuming SpendUTXO uses the UTXO's owner address internally to get the shard key.
			amount, err := bc.ShardState.Database.SpendUTXO(dbTxContext, utxoKey, input.OwnerAddress, int(bc.ShardState.ShardID))
			if err != nil {
				log.Printf("ERROR: [DB Persist] Failed to spend input UTXO %s in DB for tx %s on shard %d: %v", utxoKey, tx.ID, bc.ShardState.ShardID, err)
				return fmt.Errorf("failed to spend input UTXO %s in DB for tx %s on shard %d: %w", utxoKey, tx.ID, bc.ShardState.ShardID, err)
			}
			totalInputAmount += amount
			log.Printf("DEBUG: [DB Persist] Spent UTXO %s (Amount: %d) for Tx %s on shard %d", utxoKey, amount, tx.ID, bc.ShardState.ShardID)
		}

		// --- 2. Persist Output creation, calculate totalOutputAmount & update recipient balances ---
		for i, output := range tx.Outputs {
			// Get the shard ID for the owner of this new UTXO
			outputOwnerShardID := store.CalculateShardID(output.OwnerAddress, bc.AppConfig.NumShards)

			// Only process outputs for this shard's database
			if outputOwnerShardID == bc.ShardState.ShardID {
				// AddNewUTXO needs to be updated to pass ShardID, or its internal implementation will use it
				err := bc.ShardState.Database.AddNewUTXO(dbTxContext, output, int(bc.ShardState.ShardID))

				if err != nil {
					log.Printf("ERROR: [DB Persist] Failed to add output UTXO %s to DB for tx %s on shard %d: %v", output.Key(), tx.ID, bc.ShardState.ShardID, err)
					return fmt.Errorf("failed to add output UTXO %s to DB for tx %s on shard %d: %w", output.Key(), tx.ID, bc.ShardState.ShardID, err)
				}
				log.Printf("DEBUG: [DB Persist] Added Output UTXO %s for Tx %s on shard %d", output.Key(), tx.ID, bc.ShardState.ShardID)

				outputAmount := int64(output.Amount)
				totalOutputAmount += outputAmount

				// AddToBalance needs to be updated to pass ShardID
				err = bc.ShardState.Database.AddToBalance(dbTxContext, output.OwnerAddress, outputAmount, int(bc.ShardState.ShardID))
				if err != nil {
					log.Printf("ERROR: [DB Persist] Failed to update recipient %s balance in DB for tx %s output %d on shard %d: %v", output.OwnerAddress, tx.ID, i, bc.ShardState.ShardID, err)
					return fmt.Errorf("failed to update recipient %s balance in DB for tx %s output %d on shard %d: %w", output.OwnerAddress, tx.ID, i, bc.ShardState.ShardID, err)
				}
				log.Printf("DEBUG: [DB Persist] Balance update initiated for %s (+%d) (Tx %s Output %d) on shard %d", output.OwnerAddress, outputAmount, tx.ID, i, bc.ShardState.ShardID)
			} else {
				log.Printf("WARN: [DB Persist] Skipping DB persistence for output to %s (shard %d) as it's not for current shard %d.",
					output.OwnerAddress, outputOwnerShardID, bc.ShardState.ShardID)
				// This is where cross-shard transaction outputs would be recorded as "receipts"
				// on the beacon chain or as messages for the target shard.
			}
		}

		// --- *** BEGIN MODIFIED SECTION 3: UPDATE SENDER BALANCE IN DB (Net Debit) *** ---
		if senderAddress != "" {
			// Check if senderAddress belongs to this shard.
			senderShardID := store.CalculateShardID(senderAddress, bc.AppConfig.NumShards)
			if senderShardID != bc.ShardState.ShardID {
				log.Printf("WARN: [DB Persist] Skipping sender balance update for %s (shard %d) as it's not for current shard %d. This implies a cross-shard transaction.",
					senderAddress, senderShardID, bc.ShardState.ShardID)
				// This is where cross-shard transaction logic would handle debits on source shard
				// and credits on destination shard. For now, only single-shard txs fully processed.
			} else {
				fee := totalInputAmount - totalOutputAmount
				if fee < 0 {
					log.Printf("CRITICAL ERROR: [DB Persist] Negative fee calculated for Tx %s! Input: %d, Output: %d", tx.ID, totalInputAmount, totalOutputAmount)
					return fmt.Errorf("transaction %s results in negative fee during DB persistence", tx.ID)
				}
				log.Printf("DEBUG: [DB Persist] Calculated fee for Tx %s: %d (Input: %d, Output: %d)", tx.ID, fee, totalInputAmount, totalOutputAmount)

				var changeAmount int64 = 0
				for _, output := range tx.Outputs {
					if output.OwnerAddress == senderAddress {
						changeAmount += int64(output.Amount)
					}
				}
				log.Printf("DEBUG: [DB Persist] Calculated change amount for sender %s: %d", senderAddress, changeAmount)

				netDebit := totalInputAmount - changeAmount
				log.Printf("DEBUG: [DB Persist] Calculated Net Debit for sender %s: %d (Input: %d, Change: %d)", senderAddress, netDebit, totalInputAmount, changeAmount)

				if netDebit < 0 {
					log.Printf("CRITICAL ERROR: [DB Persist] Calculated negative net debit (%d) for Tx %s!", netDebit, tx.ID)
					return fmt.Errorf("internal error: negative net debit calculated for tx %s", tx.ID)
				}

				if netDebit > 0 {
					// AddToBalance needs to be updated to pass ShardID
					err := bc.ShardState.Database.AddToBalance(dbTxContext, senderAddress, -netDebit, int(bc.ShardState.ShardID))
					if err != nil {
						if strings.Contains(err.Error(), "insufficient balance") {
							log.Printf("ERROR: [DB Persist] Insufficient balance reported by DB for sender %s during Tx %s NET debit attempt (Debit: %d). Validation failed?", senderAddress, tx.ID, netDebit)
						} else {
							log.Printf("ERROR: [DB Persist] Failed to apply net debit for sender %s in DB for tx %s on shard %d: %v", senderAddress, tx.ID, bc.ShardState.ShardID, err)
						}
						return fmt.Errorf("failed to apply net debit for sender %s balance in DB for tx %s on shard %d: %w", senderAddress, tx.ID, bc.ShardState.ShardID, err)
					}
					log.Printf("DEBUG: [DB Persist] Balance update initiated for sender %s (-%d) (Tx %s Net Debit) on shard %d", senderAddress, netDebit, tx.ID, bc.ShardState.ShardID)
				} else {
					log.Printf("DEBUG: [DB Persist] Skipping zero net debit for sender %s (Tx %s) on shard %d", senderAddress, tx.ID, bc.ShardState.ShardID)
				}
			}
		} else if !tx.IsGenesis() && !tx.IsFunding() {
			if totalInputAmount < totalOutputAmount+int64(tx.GasFee) {
				err := fmt.Errorf("insufficient input value (%d) to cover outputs (%d) + stated fee (%d) for tx %s", totalInputAmount, totalOutputAmount, tx.GasFee, tx.ID)
				log.Printf("ERROR: [DB Persist] %v", err)
				return err
			}
		}
	}

	log.Printf("DEBUG: [DB Persist] Finished persisting state changes for Block %d on Shard %d", block.Index, bc.ShardState.ShardID)
	return nil
}

func (bc *BlockchainImpl) updateStateForBlock(block *types.Block) error {
	if block == nil {
		return errors.New("cannot update state for nil block")
	}
	log.Printf("DEBUG: [State Update] Starting state update for Block %d on Shard %d", block.Index, bc.ShardState.ShardID)

	if bc.ShardState.UTXOs == nil {
		return fmt.Errorf("UTXO map is nil during state update for block %d on shard %d", block.Index, bc.ShardState.ShardID)
	}
	if bc.ShardState.Stakeholders == nil {
		return fmt.Errorf("stakeholders map is nil during state update for block %d on shard %d", block.Index, bc.ShardState.ShardID)
	}

	for _, tx := range block.Transactions {
		log.Printf("DEBUG: [State Update] Processing Tx %s in Block %d for Shard %d", tx.ID, block.Index, bc.ShardState.ShardID)

		txShardID := store.CalculateShardID(tx.SenderAddress.String(), bc.AppConfig.NumShards)
		if txShardID != bc.ShardState.ShardID && bc.ShardState.ShardID != types.ShardID(-1) { // If not for this shard, and not beacon node
			log.Printf("WARN: [State Update] Skipping transaction %s (sender shard %d) as it's not for this shard %d's in-memory state.",
				tx.ID, txShardID, bc.ShardState.ShardID)
			continue // Skip in-memory update for transactions not belonging to this shard
		}

		var totalInputAmount int64 = 0
		var totalOutputAmount int64 = 0
		senderAddress := ""

		if tx.SenderPublicKey != nil {
			addr, err := tx.SenderPublicKey.Address()
			if err != nil {
				log.Printf("WARN: [State Update] Failed get sender addr for Tx %s: %v. Sender balance update might be skipped.", tx.ID, err)
			} else {
				senderAddress = addr.String()
			}
		} else if !tx.IsGenesis() && !tx.IsFunding() {
			log.Printf("WARN: [State Update] Tx %s has nil SenderPublicKey and is not Genesis/Funding.", tx.ID)
		}

		// 1. Process Inputs (Remove spent UTXOs from map, Calculate Input Total from map state)
		for _, input := range tx.Inputs {
			utxoKey := input.Key()
			mapKey := fmt.Sprintf("ux-%d-%s", bc.ShardState.ShardID, utxoKey)

			log.Printf("DEBUG: [State Update] Processing Input UTXO Map Key: %s for Tx %s on Shard %d", mapKey, tx.ID, bc.ShardState.ShardID)

			// Check if this UTXO belongs to this shard before modifying local state
			// REPLACE with:
			if bc.ShardState.ShardID == types.ShardID(-1) {
				// Beacon chain can process UTXOs from any shard
				log.Printf("DEBUG: [State Update] Beacon chain processing UTXO %s from any shard", mapKey)
			} else {
				// For regular shards, validate same-shard ownership
				inputOwnerShardID := store.CalculateShardID(input.OwnerAddress, bc.AppConfig.NumShards)
				if inputOwnerShardID != bc.ShardState.ShardID {
					log.Printf("WARN: [State Update] Skipping in-memory update for input UTXO %s (owner shard %d) as it's not for current shard %d.",
						mapKey, inputOwnerShardID, bc.ShardState.ShardID)
					continue // Skip, it's not for our shard's in-memory state
				}
			}

			utxoSlice, sliceExists := bc.ShardState.UTXOs[mapKey] // Access ShardState's UTXOs
			if !sliceExists || len(utxoSlice) == 0 {
				log.Printf("ERROR: [State Update] Input UTXO key %s not found in in-memory map for Tx %s on Shard %d.", mapKey, tx.ID, bc.ShardState.ShardID)
				return fmt.Errorf("input UTXO %s not found in cache for tx %s during state update on shard %d", mapKey, tx.ID, bc.ShardState.ShardID)
			}
			if utxoSlice[0].IsSpent {
				log.Printf("ERROR: [State Update] Input UTXO key %s is already marked as spent in-memory map for Tx %s on Shard %d.", mapKey, tx.ID, bc.ShardState.ShardID)
				return fmt.Errorf("double spend detected in-memory for UTXO %s in tx %s on shard %d", mapKey, tx.ID, bc.ShardState.ShardID)
			}
			if len(utxoSlice) > 1 {
				log.Printf("ERROR: [State Update] Ambiguous state for input key %s (slice len %d) for Tx %s on Shard %d.", mapKey, len(utxoSlice), tx.ID, bc.ShardState.ShardID)
				return fmt.Errorf("ambiguous state for input UTXO %s (slice length %d) for tx %s on shard %d", mapKey, len(utxoSlice), tx.ID, bc.ShardState.ShardID)
			}
			spentProtoUTXO := utxoSlice[0]
			totalInputAmount += spentProtoUTXO.Amount
			delete(bc.ShardState.UTXOs, mapKey) // Modify ShardState's UTXOs
			log.Printf("DEBUG: [State Update] Removed/Marked spent UTXO key %s (Amount: %d) on Shard %d.", mapKey, spentProtoUTXO.Amount, bc.ShardState.ShardID)
		}

		// 2. Process Outputs (Add to UTXO map, Unconditionally credit recipient balances)
		for i, output := range tx.Outputs {
			newUtxoKey := output.Key()
			mapKey := newUtxoKey

			// Check if this new UTXO belongs to this shard
			outputOwnerShardID := store.CalculateShardID(output.OwnerAddress, bc.AppConfig.NumShards)
			if outputOwnerShardID == bc.ShardState.ShardID {
				protoUtxo := convertTypesUTXOToProtoUTXO(output) // Helper func needed (defined below)
				if protoUtxo == nil {
					log.Printf("ERROR: [State Update] Failed convert output %d for Tx %s to proto UTXO.", i, tx.ID)
					continue
				}

				bc.ShardState.UTXOs[mapKey] = append(bc.ShardState.UTXOs[mapKey], protoUtxo) // Modify ShardState's UTXOs
				log.Printf("DEBUG: [State Update] Appended new proto UTXO key %s (Owner: %s, Amount: %d) to map slice on Shard %d.", mapKey, protoUtxo.OwnerAddress, protoUtxo.Amount, bc.ShardState.ShardID)

				recipientAddr := output.OwnerAddress
				currentBalance, _ := bc.ShardState.Stakeholders[recipientAddr] // Access ShardState's Stakeholders
				outputAmount := int64(output.Amount)
				bc.ShardState.Stakeholders[recipientAddr] = currentBalance + outputAmount // Modify ShardState's Stakeholders
				logString := "DEBUG: [State Update] Updated Stakeholders balance for output %d owner %s: %d -> %d (+%d)"
				if recipientAddr == senderAddress {
					logString += " (Change Output - Balance will be corrected in Section 3)"
				}
				log.Printf(logString, i, recipientAddr, currentBalance, bc.ShardState.Stakeholders[recipientAddr], outputAmount)
			} else {
				log.Printf("WARN: [State Update] Skipping in-memory UTXO and balance update for output to %s (shard %d) as it's not for current shard %d.",
					output.OwnerAddress, outputOwnerShardID, bc.ShardState.ShardID)
				// Cross-shard output logic would go here.
			}
			totalOutputAmount += int64(output.Amount) // Still sum for fee calculation regardless of shard
		}

		// 3. Update SENDER BALANCE
		if senderAddress != "" {
			senderShardID := store.CalculateShardID(senderAddress, bc.AppConfig.NumShards)
			if senderShardID != bc.ShardState.ShardID {
				log.Printf("WARN: [State Update] Skipping sender balance correction for %s (shard %d) as it's not for current shard %d.",
					senderAddress, senderShardID, bc.ShardState.ShardID)
			} else {
				fee := totalInputAmount - totalOutputAmount
				if fee < 0 {
					log.Printf("ERROR: [State Update] Negative fee calculated for Tx %s (Input: %d, Output: %d)! Halting block processing.", tx.ID, totalInputAmount, totalOutputAmount)
					return fmt.Errorf("negative fee calculated for tx %s in block %d", tx.ID, block.Index)
				}
				if fee != 0 {
					log.Printf("DEBUG: [State Update] Calculated fee for Tx %s: %d (Input: %d, Output: %d)", tx.ID, fee, totalInputAmount, totalOutputAmount)
				}

				senderBalanceBeforeTx, _ := bc.ShardState.Stakeholders[senderAddress] // Access ShardState's Stakeholders

				changeAmount := int64(0)
				for _, output := range tx.Outputs {
					if output.OwnerAddress == senderAddress {
						changeAmount += int64(output.Amount)
					}
				}

				trueInitialSenderBalance := senderBalanceBeforeTx - changeAmount
				finalSenderBalance := trueInitialSenderBalance - totalInputAmount + changeAmount

				if finalSenderBalance < 0 {
					log.Printf("ERROR: [State Update] Calculated negative final balance (%d) for sender %s for Tx %s. TrueInitial: %d, InputTotal: %d, Change: %d.", finalSenderBalance, senderAddress, tx.ID, trueInitialSenderBalance, totalInputAmount, changeAmount)
					return fmt.Errorf("calculated negative final balance for sender %s in tx %s", senderAddress, tx.ID)
				}

				bc.ShardState.Stakeholders[senderAddress] = finalSenderBalance // Modify ShardState's Stakeholders
				log.Printf("DEBUG: [State Update] Corrected Stakeholders balance for SENDER %s on Shard %d: %d (Post-Sec2) -> %d (Final) (Inputs: %d, Change: %d, Fee: %d)", senderAddress, bc.ShardState.ShardID, senderBalanceBeforeTx, finalSenderBalance, totalInputAmount, changeAmount, fee)
			}
		} else {
			log.Printf("DEBUG: [State Update] Skipping Section 3 sender balance correction for Tx %s because sender address is unknown.", tx.ID)
		}
	}

	log.Printf("DEBUG: [State Update] Finished state update for Block %d on Shard %d.", block.Index, bc.ShardState.ShardID)
	return nil
}

func NewBlockchain(setupConfig *types.BlockchainConfig, appConfig *config.Config, libp2pManager *network.Libp2pManager, shardID types.ShardID, totalNumShards int) (*BlockchainImpl, types.Store, error) {
	if setupConfig == nil || appConfig == nil {
		log.Panic("FATAL: NewBlockchain called with nil config")
	}
	if setupConfig.GenesisAccount == nil {
		log.Panic("FATAL: NewBlockchain called but setupConfig.GenesisAccount is nil")
	}
	if libp2pManager == nil {
		log.Panic("FATAL: NewBlockchain called with nil Libp2pManager")
	}

	// Pass shardID to NewDatabase (if you intend to have separate DB files per shard)
	// Or, NewDatabase might return a global DB instance that the `store` package
	// then shims with shard-prefixed keys. For now, assume separate DB files.
	database, err := store.NewDatabase(setupConfig.DataDir) // setupConfig.DataDir is now shard-specific
	if err != nil {
		return nil, nil, fmt.Errorf("failed to initialize the blockchain database for shard %d: %v", shardID, err)
	}

	// NewStore also needs the shardID to create shard-aware key generation helpers
	// within the store or to select the correct database instance.
	// For now, assume it's set up to implicitly use the dataDir.
	storeInstance, err := store.NewStore(database, setupConfig.AESKey, totalNumShards) // FIXED: Added totalNumShards
	if err != nil {
		// Corrected error message to include shardID for context
		database.Close()
		return nil, nil, fmt.Errorf("failed to create store for shard %d: %v", shardID, err)
	}

	// database.Blockchain = storeInstance // This line seems to create a circular dependency
	// The Database struct should probably just *use* the Store interface, not contain it directly.
	// Assuming `database` is of type `*store.Database` and it doesn't need to hold `types.Store`.
	// If your `store.Database` *does* need to access `types.Store`, then this part of the design
	// needs to be re-evaluated to avoid circular dependency. Let's comment it out for now.
	// log.Println("BlockchainDB created")

	genesis := NewGenesisBlock() // This should probably be shard-specific genesis
	log.Printf("Genesis block created for shard %d", shardID)
	publicKeyMap := make(map[string]*crypto.PublicKey)
	totalSupplyNano := int64(120000000 * 1e9) // This supply might be per-shard
	log.Printf("Initializing genesis account with total supply: %.2f THR for shard %d", float64(totalSupplyNano)/1e9, shardID)

	stakeholdersMap := make(map[string]int64)
	privKey := setupConfig.GenesisAccount // This genesis account should be for the specific shard

	var pubKey crypto.PublicKey = privKey.PublicKey()
	if pubKey == nil {
		return nil, nil, fmt.Errorf("genesis public key is nil")
	}

	addr, err := pubKey.Address()
	if err != nil {
		return nil, nil, fmt.Errorf("failed to get genesis address: %w", err)
	}

	genesisAddressString := addr.String()
	// The genesis account should belong to THIS shard. If not, this is a misconfiguration
	// or implies a cross-shard genesis transaction (complex).
	if store.CalculateShardID(genesisAddressString, totalNumShards) != shardID && shardID != types.ShardID(-1) {
		return nil, nil, fmt.Errorf("genesis account %s (shard %d) does not belong to configured shard %d",
			genesisAddressString, store.CalculateShardID(genesisAddressString, totalNumShards), shardID)
	}

	stakeholdersMap[genesisAddressString] = totalSupplyNano

	log.Printf("Genesis account address: %s for shard %d", genesisAddressString, shardID)

	log.Printf("DEBUG: Attempting to save Public Key for address %s for shard %d", genesisAddressString, shardID)
	// SavePublicKey is a method on types.Store, it needs to be shard-aware in its implementation
	err = storeInstance.SavePublicKey(pubKey)
	if err != nil {
		log.Printf("WARN: Could not save genesis public key for shard %d (may already exist): %v", shardID, err)
	} else {
		log.Printf("DEBUG: Successfully saved/updated Public Key for genesis address %s for shard %d", genesisAddressString, shardID)
	}

	dummySignatureBytes := make([]byte, crypto.MLDSASignatureSize)

	genesisTx := &thrylos.Transaction{
		Id:        "genesis_tx_" + addr.String(),
		Timestamp: time.Now().Unix(),
		Sender:    "",
		Outputs: []*thrylos.UTXO{{
			OwnerAddress: addr.String(), // This output should be for the genesis address of THIS shard
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

	messageBus := types.GetGlobalMessageBus() // Global message bus

	temp := &BlockchainImpl{
		ShardState: &types.ChainState{ // This is the actual ChainState for THIS shard/beacon
			ShardID:              shardID,        // Assign the shard ID
			TotalNumShards:       totalNumShards, // Store total number of shards
			Blocks:               []*types.Block{genesis},
			Genesis:              genesis,
			Stakeholders:         stakeholdersMap, // Only stakeholders for THIS shard
			Database:             storeInstance,   // Store instance for THIS shard
			PublicKeyMap:         publicKeyMap,
			UTXOs:                utxoMap, // Only UTXOs for THIS shard
			Forks:                make([]*types.Fork, 0),
			GenesisAccount:       privKey,                         // Genesis account for THIS shard
			PendingTransactions:  make([]*thrylos.Transaction, 0), // Pending TXs for THIS shard
			ActiveValidators:     make([]string, 0),               // Active validators for THIS shard
			TestMode:             setupConfig.TestMode,
			ValidatorKeys:        store.NewValidatorKeyStore(database, addr.Bytes()), // For this shard
			MinStakeForValidator: big.NewInt(appConfig.MinimumStakeAmount()),
		},
		MessageBus:    messageBus,    // Global message bus
		AppConfig:     appConfig,     // Global app config
		Libp2pManager: libp2pManager, // Global Libp2pManager (needs shard awareness)
	}

	// NOTE: txPool and other components must now operate on temp.ShardState
	temp.TransactionPropagator = &types.TransactionPropagator{
		Blockchain: temp, // This needs to be adjusted. TransactionPropagator should probably act on a specific ShardState.
		Mu:         sync.RWMutex{},
	}

	// NewTxPool needs to be updated to be shard-aware (e.g., use temp.ShardState.Database)
	temp.txPool = NewTxPool(temp.ShardState.Database, temp) // Pass shard-specific database to TxPool

	log.Println("Initializing BalanceUpdateQueue...")
	// BalanceUpdateQueue likely operates on shard-specific balances
	balanceQueue := balance.NewBalanceUpdateQueue()
	if balanceQueue == nil {
		database.Close()
		return nil, nil, fmt.Errorf("failed to initialize BalanceUpdateQueue for shard %d", shardID)
	}
	log.Printf("BalanceUpdateQueue initialized successfully for shard %d.", shardID)

	log.Println("Initializing StakingService...")
	// StakingService needs to operate on temp.ShardState
	stakingSvc := staking.NewStakingService(temp.GetChainState()) // Pass the ChainState
	if stakingSvc == nil {
		database.Close()
		return nil, nil, fmt.Errorf("failed to initialize StakingService for shard %d", shardID)
	}
	log.Printf("StakingService initialized successfully for shard %d.", shardID)

	log.Println("Initializing TransactionProcessorImpl...")
	// TransactionProcessorImpl needs to operate on temp.ShardState
	txProcessor := processor.NewTransactionProcessorImpl(
		temp.TransactionPropagator, // Propagator needs to be shard-aware
		balanceQueue,
		temp.GetChainState(), // Pass the ChainState
		storeInstance,        // Store instance for this shard
		stakingSvc,
	)
	if txProcessor == nil {
		database.Close()
		return nil, nil, fmt.Errorf("failed to initialize TransactionProcessorImpl for shard %d", shardID)
	}
	log.Printf("TransactionProcessorImpl initialized successfully for shard %d.", shardID)

	log.Println("Initializing DAGManager...")
	// DAGManager likely operates on a shard-specific DAG
	dagMan := processor.NewDAGManager()
	if dagMan == nil {
		database.Close()
		return nil, nil, fmt.Errorf("failed to initialize DAGManager for shard %d", shardID)
	}
	temp.dagManager = dagMan
	log.Printf("DAGManager initialized successfully for shard %d.", shardID)

	log.Println("Initializing ModernProcessor...")
	// ModernProcessor needs to operate on shard-specific components
	temp.modernProcessor = processor.NewModernProcessor(txProcessor, libp2pManager, temp.txPool, temp.dagManager) // Libp2pManager is global
	if temp.modernProcessor == nil {
		database.Close()
		return nil, nil, fmt.Errorf("failed to initialize modern processor for shard %d", shardID)
	}
	log.Printf("ModernProcessor initialized successfully for shard %d.", shardID)

	ch := make(chan types.Message, 100)
	temp.MessageBus.Subscribe(types.FundNewAddress, ch)
	go func() {
		log.Printf("Started FundNewAddress message listener for shard %d", shardID)
		for msg := range ch {
			log.Printf("Received message: %s for shard %d", msg.Type, shardID)
			if msg.Type == types.FundNewAddress {
				temp.HandleFundNewAddress(msg) // This needs to be shard-aware
			}
		}
	}()

	balanceCh := make(chan types.Message, 100)
	temp.MessageBus.Subscribe(types.GetStakeholderBalance, balanceCh)
	go func() {
		log.Printf("Started GetStakeholderBalance message listener for shard %d", shardID)
		for msg := range balanceCh {
			log.Printf("Received balance message: %s for shard %d", msg.Type, shardID)
			if msg.Type == types.GetStakeholderBalance {
				temp.HandleGetBalance(msg) // This needs to be shard-aware
			}
		}
	}()

	publicKeyMap[addr.String()] = &pubKey
	log.Printf("Genesis account public key added to publicKeyMap for shard %d", shardID)
	log.Printf("Inserting genesis block %d into database for shard %d", genesis.Index, shardID)
	// SaveBlock needs to be shard-aware in its implementation
	if err := storeInstance.SaveBlock(genesis); err != nil { // Save genesis using storeInstance
		log.Printf("CRITICAL ERROR: Failed to save genesis block to the database for shard %d: %v", shardID, err)
		storeInstance.Close()
		return nil, nil, fmt.Errorf("failed to save genesis block for shard %d: %w", shardID, err)
	}
	log.Printf("Genesis block %d inserted successfully for shard %d", genesis.Index, shardID)

	log.Printf("Genesis account %s initialized with total supply: %d nanoTHRYLOS for shard %d", addr.String(), totalSupplyNano, shardID)

	go func() {
		c := make(chan os.Signal, 1)
		signal.Notify(c, os.Interrupt, syscall.SIGTERM)
		<-c
		log.Printf("Stopping blockchain for shard %d...", shardID)
	}()

	if !setupConfig.DisableBackground {
		log.Println("Starting background processes...")

		validatorUpdateInterval := 1 * time.Minute
		maxActiveValidators := 5
		if appConfig != nil && appConfig.Consensus != nil {
			if appConfig.Consensus.ValidatorUpdateInterval > 0 {
				validatorUpdateInterval = time.Duration(appConfig.Consensus.ValidatorUpdateInterval) * time.Second
			}
			if appConfig.Consensus.MaxActiveValidators > 0 {
				maxActiveValidators = appConfig.Consensus.MaxActiveValidators
			}
		}

		initialValidatorUpdateDone := make(chan struct{})

		log.Printf("Starting periodic validator update for shard %d: Interval=%v, MaxValidators=%d", shardID, validatorUpdateInterval, maxActiveValidators)
		// StartPeriodicValidatorUpdate needs to operate on bc.ShardState
		go temp.StartPeriodicValidatorUpdate(validatorUpdateInterval, maxActiveValidators, initialValidatorUpdateDone)

		select {
		case <-initialValidatorUpdateDone:
			log.Printf("INFO: Initial active validator set populated for shard %d.", shardID)
		case <-time.After(30 * time.Second):
			log.Printf("WARN: Timeout waiting for initial active validator set to be populated for shard %d.", shardID)
		}

		go func() {
			log.Printf("Starting block creation process for shard %d", shardID)
			if temp.modernProcessor == nil {
				log.Printf("ERROR: Block creation loop cannot start for shard %d, ModernProcessor is nil.", shardID)
				return
			}
			ticker := time.NewTicker(time.Duration(appConfig.Consensus.BlockInterval) * time.Second) // Use config's block interval
			defer ticker.Stop()

			for range ticker.C {
				txs, err := temp.txPool.GetAllTransactions() // TxPool needs to be shard-aware
				if err != nil {
					log.Printf("ERROR: [Block Creator] Error getting transactions from pool for shard %d: %v", shardID, err)
					continue
				}

				if len(txs) > 0 {
					log.Printf("INFO: [Block Creator] Processing %d transactions from pool for shard %d", len(txs), shardID)
					var processedSuccessfully []*types.Transaction

					for _, tx := range txs {
						// Crucial check: only process transactions meant for THIS shard
						txShardID := store.CalculateShardID(tx.SenderAddress.String(), totalNumShards)
						if txShardID != shardID && shardID != types.ShardID(-1) { // If not for this shard, and not beacon
							log.Printf("WARN: [Block Creator] Skipping tx %s (sender shard %d) for shard %d's block creation, as it doesn't belong here.",
								tx.ID, txShardID, shardID)
							continue // Skip this transaction
						}
						// If it's the beacon node, it might process all transactions and route them.
						// For simplicity, beacon node also filters for its own (non-existent) shard.

						log.Printf("DEBUG: [Block Creator] Processing TxID: %s from pool for shard %d", tx.ID, shardID)
						processErr := temp.ProcessIncomingTransaction(tx) // This needs to be shard-aware
						log.Printf("DEBUG: [Block Creator] Result of ProcessIncomingTransaction for %s (shard %d): %v", tx.ID, shardID, processErr)

						if processErr != nil {
							log.Printf("ERROR: [Block Creator] Error processing transaction %s for shard %d: %v. Skipping removal.", tx.ID, shardID, processErr)
						} else {
							log.Printf("INFO: [Block Creator] Successfully processed transaction %s by ModernProcessor for shard %d.", tx.ID, shardID)
							processedSuccessfully = append(processedSuccessfully, tx)

							log.Printf("DEBUG: [Block Creator] Attempting to remove %s from pool for shard %d...", tx.ID, shardID)
							if errRem := temp.txPool.RemoveTransaction(tx); errRem != nil { // TxPool needs to be shard-aware
								log.Printf("ERROR: [Block Creator] Failed to remove processed transaction %s from pool for shard %d: %v", tx.ID, shardID, errRem)
								if len(processedSuccessfully) > 0 {
									processedSuccessfully = processedSuccessfully[:len(processedSuccessfully)-1]
								}
							} else {
								log.Printf("INFO: [Block Creator] Removed processed transaction %s from pool for shard %d.", tx.ID, shardID)
							}
						}
					}

					if len(processedSuccessfully) > 0 {
						log.Printf("INFO: [Block Creator] Ready to create block with %d transactions for shard %d.", len(processedSuccessfully), shardID)

						selectedValidatorID, errSelect := temp.SelectNextValidator() // Needs to be shard-aware
						if errSelect != nil {
							log.Printf("ERROR: [Block Creator] Failed to select validator for shard %d: %v. Skipping block creation.", shardID, errSelect)
							continue
						}
						log.Printf("INFO: [Block Creator] Selected validator for new block on shard %d: %s", shardID, selectedValidatorID)

						protoTxs, errConv := utils.ConvertMultipleToProto(processedSuccessfully)
						if errConv != nil {
							log.Printf("ERROR: [Block Creator] Failed to convert transactions to proto for block on shard %d: %v. Skipping block.", shardID, errConv)
							continue
						}

						log.Printf("DEBUG: [Block Creator] Calling CreateUnsignedBlock with validator %s for shard %d...", selectedValidatorID, shardID)
						unsignedBlock, errCreate := temp.CreateUnsignedBlock(protoTxs, selectedValidatorID) // Needs to be shard-aware
						if errCreate != nil {
							log.Printf("ERROR: [Block Creator] Failed to create unsigned block for shard %d: %v. Skipping block creation.", shardID, errCreate)
							continue
						}
						if unsignedBlock.Validator == "" {
							log.Printf("ERROR: [Block Creator] CreateUnsignedBlock did not set validator field for shard %d. Skipping.", shardID)
							continue
						}
						log.Printf("DEBUG: [Block Creator] Created unsigned block Index: %d, Validator: %s for shard %d", unsignedBlock.Index, unsignedBlock.Validator, shardID)

						log.Printf("DEBUG: [Block Creator] Signing block %d using key for validator %s on shard %d...", unsignedBlock.Index, unsignedBlock.Validator, shardID)

						validatorPrivKey, retrievedAddr, errKey := temp.GetValidatorPrivateKey(unsignedBlock.Validator) // Needs to be shard-aware
						if errKey != nil {
							log.Printf("ERROR: [Block Creator] Failed to get private key for validator %s on shard %d: %v. Skipping block signing.", unsignedBlock.Validator, shardID, errKey)
							continue
						}
						log.Printf("DEBUG: [Block Creator] Retrieved private key for address %s (matches block validator: %v) for shard %d", retrievedAddr, retrievedAddr == unsignedBlock.Validator, shardID)

						log.Printf("DEBUG: [Block Creator] Computing block hash for signing block %d on shard %d...", unsignedBlock.Index, shardID)
						errHash := ComputeBlockHash(unsignedBlock) // Assuming global function in block.go
						if errHash != nil {
							log.Printf("ERROR: [Block Creator] Failed to compute block hash for signing block %d on shard %d: %v", unsignedBlock.Index, shardID, errHash)
							continue
						}
						log.Printf("DEBUG: [Block Creator] Computed block hash for signing: %s for shard %d", unsignedBlock.Hash.String(), shardID)

						signature := validatorPrivKey.Sign(unsignedBlock.Hash.Bytes())
						unsignedBlock.Signature = signature

						if unsignedBlock.Signature == nil || len(unsignedBlock.Signature.Bytes()) == 0 {
							log.Printf("ERROR: [Block Creator] Failed to generate signature for block %d on shard %d", unsignedBlock.Index, shardID)
							continue
						}

						log.Printf("DEBUG: [Block Creator] Block %d signed successfully by %s for shard %d.", unsignedBlock.Index, unsignedBlock.Validator, shardID)

						log.Printf("DEBUG: [Block Creator] Adding signed block %d to chain for shard %d...", unsignedBlock.Index, shardID)
						errAdd := temp.AddBlockToChain(unsignedBlock) // This method is already being refactored
						if errAdd != nil {
							log.Printf("ERROR: [Block Creator] Failed to add signed block %d to chain for shard %d: %v", unsignedBlock.Index, shardID, errAdd)
							continue
						}
					}
				}
			}
		}()

		go func(bci *BlockchainImpl) {
			syncTicker := time.NewTicker(5 * time.Minute)
			defer syncTicker.Stop()
			for range syncTicker.C {
				if bci.Libp2pManager != nil {
					log.Printf("INFO: Initiating periodic blockchain sync for shard %d...", bci.ShardState.ShardID)
					// SyncBlockchain needs to be shard-aware
					bci.Libp2pManager.SyncBlockchain()
				} else {
					log.Printf("WARN: Libp2pManager is nil, cannot perform periodic sync for shard %d.", bci.ShardState.ShardID)
				}
			}
		}(temp)
	} else {
		log.Println("Background processes disabled for testing")
	}

	log.Printf("NewBlockchain initialization completed successfully for shard %d.", shardID)
	return temp, storeInstance, nil
}

// helper methods
func (bc *BlockchainImpl) GetGenesis() *types.Block {
	return bc.ShardState.Genesis
}

func (bc *BlockchainImpl) GetBlocks() []*types.Block {
	return bc.ShardState.Blocks
}

func (bc *BlockchainImpl) HandleGetBalance(msg types.Message) {
	address, ok := msg.Data.(string)
	if !ok {
		msg.ResponseCh <- types.Response{Error: fmt.Errorf("invalid address format")}
		return
	}

	log.Printf("DEBUG-BALANCE: HandleGetBalance called for address: %s", address)

	// Access the stakeholders map
	bc.ShardState.Mu.RLock()

	// Direct map access check
	mapSize := len(bc.ShardState.Stakeholders)
	log.Printf("DEBUG-BALANCE: Stakeholders map has %d entries", mapSize)

	// Check for specific addresses
	genesis, _ := bc.ShardState.GenesisAccount.PublicKey().Address()
	genesisAddr := genesis.String()
	genesisBalance, genesisExists := bc.ShardState.Stakeholders[genesisAddr]
	log.Printf("DEBUG-BALANCE: Genesis address %s exists: %v, balance: %d",
		genesisAddr, genesisExists, genesisBalance)

	testBalance, testExists := bc.ShardState.Stakeholders["test_address_123"]
	log.Printf("DEBUG-BALANCE: Test address exists: %v, balance: %d", testExists, testBalance)

	// Check the target address
	targetBalance, targetExists := bc.ShardState.Stakeholders[address]
	log.Printf("DEBUG-BALANCE: Target address %s exists: %v, balance: %d",
		address, targetExists, targetBalance)

	// Print all entries in the map
	log.Printf("DEBUG-BALANCE: All addresses in map:")
	for addr, bal := range bc.ShardState.Stakeholders {
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

	bc.ShardState.Mu.RUnlock()

	// Send the response
	log.Printf("DEBUG-BALANCE: Sending final balance: %d", balance)
	msg.ResponseCh <- types.Response{Data: balance}
}

// Status now reflects the specific shard/beacon chain.
func (bc *BlockchainImpl) Status() string {
	bc.ShardState.Mu.RLock()
	defer bc.ShardState.Mu.RUnlock()
	return fmt.Sprintf("Shard: %d, Height: %d, Blocks: %d",
		bc.ShardState.ShardID,
		len(bc.ShardState.Blocks)-1,
		len(bc.ShardState.Blocks))
}

// CheckChainIntegrity now checks the integrity of THIS shard's chain.
func (bc *BlockchainImpl) CheckChainIntegrity() bool {
	bc.ShardState.Mu.RLock()
	defer bc.ShardState.Mu.RUnlock()
	for i := 1; i < len(bc.ShardState.Blocks); i++ {
		prevBlock := bc.ShardState.Blocks[i-1]
		currentBlock := bc.ShardState.Blocks[i]

		if !currentBlock.PrevHash.Equal(prevBlock.Hash) {
			fmt.Printf("Invalid previous hash in block %d for shard %d\n", currentBlock.Index, bc.ShardState.ShardID)
			return false
		}

		blockBytes, err := SerializeForSigning(currentBlock)
		if err != nil {
			fmt.Printf("Failed to serialize block %d for shard %d: %v\n", currentBlock.Index, bc.ShardState.ShardID, err)
			return false
		}
		computedHash := hash.NewHash(blockBytes)

		if !currentBlock.Hash.Equal(computedHash) {
			fmt.Printf("Invalid hash in block %d for shard %d\n", currentBlock.Index, bc.ShardState.ShardID)
			return false
		}
	}
	fmt.Printf("Blockchain integrity check passed for shard %d.\n", bc.ShardState.ShardID)
	return true
}

func (bc *BlockchainImpl) TestStakeholdersMap() {
	testAddress := "test_address_123" // This test address might not belong to this shard!
	// For a sharded test, you should use an address guaranteed to be on this shard,
	// or skip this test if the address doesn't belong to the current shard.
	testAddrShardID := store.CalculateShardID(testAddress, bc.AppConfig.NumShards)

	if testAddrShardID != bc.ShardState.ShardID && bc.ShardState.ShardID != types.ShardID(-1) {
		log.Printf("WARN: [TestStakeholdersMap] Skipping test for address %s (shard %d) as it's not for current shard %d.",
			testAddress, testAddrShardID, bc.ShardState.ShardID)
		return
	}

	bc.ShardState.Mu.RLock()
	log.Printf("TEST: Initial stakeholders map for shard %d:", bc.ShardState.ShardID)
	for addr, bal := range bc.ShardState.Stakeholders {
		log.Printf("  %s: %d", addr, bal)
	}
	initialBalance, exists := bc.ShardState.Stakeholders[testAddress]
	bc.ShardState.Mu.RUnlock()

	log.Printf("TEST: Initial balance for %s on shard %d: %d (exists: %v)", testAddress, bc.ShardState.ShardID, initialBalance, exists)

	bc.ShardState.Mu.Lock()
	bc.ShardState.Stakeholders[testAddress] = 12345
	bc.ShardState.Mu.Unlock()

	bc.ShardState.Mu.RLock()
	newBalance, exists := bc.ShardState.Stakeholders[testAddress]
	bc.ShardState.Mu.RUnlock()

	log.Printf("TEST: After modification, balance for %s on shard %d: %d (exists: %v)", testAddress, bc.ShardState.ShardID, newBalance, exists)

	bc.ShardState.Mu.RLock()
	log.Printf("TEST: Final stakeholders map for shard %d:", bc.ShardState.ShardID)
	for addr, bal := range bc.ShardState.Stakeholders {
		log.Printf("  %s: %d", addr, bal)
	}
	bc.ShardState.Mu.RUnlock()
}

// Block functions
func (bc *BlockchainImpl) GetLastBlock(shardID types.ShardID) (*types.Block, int, error) { // MODIFIED signature
	// Query the last block data and index for THIS shard's database
	// bc.ShardState.Database.GetLastBlockData() MUST be updated to accept shardID
	blockData, err := bc.ShardState.Database.GetLastBlockData(shardID) // Pass shardID
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, 0, nil
		}
		return nil, 0, err
	}

	// bc.ShardState.Database.GetLastBlockIndex() MUST be updated to accept shardID
	lastIndex, err := bc.ShardState.Database.GetLastBlockIndex(shardID) // Pass shardID
	if err != nil {
		return nil, 0, err
	}

	var lastBlock types.Block
	buffer := bytes.NewBuffer(blockData)
	decoder := gob.NewDecoder(buffer)
	err = decoder.Decode(&lastBlock)
	if err != nil {
		return nil, 0, err
	}

	return &lastBlock, lastIndex, nil
}

func (bc *BlockchainImpl) GetBlockCount(shardID types.ShardID) int { // MODIFIED signature
	// The in-memory `Blocks` slice of `ShardState` corresponds to the current shard.
	bc.ShardState.Mu.RLock()
	defer bc.ShardState.Mu.RUnlock()
	return len(bc.ShardState.Blocks) // This implicitly counts blocks for the current shard
}

func (bc *BlockchainImpl) GetBlock(shardID types.ShardID, blockNumber int) (*types.Block, error) { // MODIFIED signature
	// Retrieve from THIS shard's database
	// bc.ShardState.Database.RetrieveBlock() MUST be updated to accept shardID
	blockData, err := bc.ShardState.Database.RetrieveBlock(shardID, blockNumber) // Pass shardID
	if err != nil {
		return nil, fmt.Errorf("failed to retrieve block data for shard %d: %v", shardID, err)
	}

	var block types.Block
	if err := json.Unmarshal(blockData, &block); err != nil { // Deserialize here
		return nil, fmt.Errorf("failed to deserialize block for shard %d: %v", shardID, err)
	}
	return &block, nil
}

func (bc *BlockchainImpl) GetBlockByID(shardID types.ShardID, id string) (*types.Block, error) { // MODIFIED signature
	// First, try to parse id as a block index
	if index, err := strconv.Atoi(id); err == nil {
		// id is a valid integer, so we treat it as a block index
		// Check the in-memory `Blocks` slice of `ShardState`
		bc.ShardState.Mu.RLock()
		defer bc.ShardState.Mu.RUnlock()
		if index >= 0 && index < len(bc.ShardState.Blocks) {
			block := bc.ShardState.Blocks[index]
			log.Printf("Block found by index: Index=%d, Transactions=%v for shard %d", block.Index, block.Transactions, shardID)
			return block, nil
		}
	}

	idBytes, err := hex.DecodeString(id)
	if err != nil {
		log.Printf("Invalid block ID format: %s", id)
		return nil, errors.New("invalid block ID format")
	}

	idHash, err := hash.FromBytes(idBytes)
	if err != nil {
		return nil, fmt.Errorf("invalid hash bytes: %v", err)
	}

	// Iterate over in-memory blocks and find by hash
	bc.ShardState.Mu.RLock()
	defer bc.ShardState.Mu.RUnlock()
	for _, block := range bc.ShardState.Blocks {
		if block.Hash.Equal(idHash) {
			log.Printf("Block found by hash: Index=%d, Transactions=%v for shard %d", block.Index, block.Transactions, shardID)
			return block, nil
		}
	}

	log.Printf("Block not found with ID: %s for shard %d", id, shardID)
	return nil, errors.New("block not found")
}
