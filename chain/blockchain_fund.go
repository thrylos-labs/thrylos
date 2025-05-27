package chain

import (
	"fmt"
	"log"
	"time" // Keep time import - will be needed for UTXO ID later

	// Ensure necessary imports are present
	"github.com/thrylos-labs/thrylos"                // For protobuf UTXO if needed by helpers
	"github.com/thrylos-labs/thrylos/crypto/address" // For address.Address type
	"github.com/thrylos-labs/thrylos/types"          // Assuming types path for UTXO, Message etc.
)

// Conversion function will be needed when UTXO logic is added below
func convertTypesUTXOToProtoUTXO(typeUtxo types.UTXO) *thrylos.UTXO {
	// Create default proto UTXO
	protoUTXO := &thrylos.UTXO{
		// Map fields:
		TransactionId: typeUtxo.TransactionID, // Assuming TransactionID exists
		Index:         int32(typeUtxo.Index),
		OwnerAddress:  typeUtxo.OwnerAddress,
		Amount:        int64(typeUtxo.Amount), // Ensure amount.Amount converts safely to int64
		IsSpent:       typeUtxo.IsSpent,       // Assuming IsSpent exists
		// Map other fields if necessary
	}

	// Check for nil or empty required fields after mapping if necessary
	if protoUTXO.TransactionId == "" || protoUTXO.OwnerAddress == "" {
		log.Printf("WARN: Conversion resulted in proto UTXO with missing TxID or OwnerAddress: %+v", protoUTXO)
		// Decide how to handle this - return nil or the potentially invalid proto?
		// Returning nil might be safer if TxID/Owner are absolutely required downstream.
		// return nil
	}
	return protoUTXO
}

func (bc *BlockchainImpl) HandleFundNewAddress(msg types.Message) {
	mapAddress := fmt.Sprintf("%p", &bc.ShardState.Stakeholders)
	log.Printf("DEBUG: HandleFundNewAddress using stakeholders map at address %s", mapAddress)
	log.Println("Handling FundNewAddress message")

	req, ok := msg.Data.(types.FundAddressRequest)
	if !ok {
		log.Println("Invalid fund request format")
		msg.ResponseCh <- types.Response{Error: fmt.Errorf("invalid fund request format")}
		return
	}

	totalNumShards := bc.AppConfig.NumShards

	// --- FIX for AddressString undefined ---
	var genesisAddr *address.Address // Variable for the address object
	var genesisAddrStr string        // Variable for the address string
	var err error                    // Variable for error checking

	genesisPubKey := bc.ShardState.GenesisAccount.PublicKey() // Get PublicKey interface value
	if genesisPubKey == nil {                                 // It's good practice to check if the key could be nil
		finalErr := fmt.Errorf("genesis account public key is nil")
		log.Printf("ERROR: %v", finalErr)
		msg.ResponseCh <- types.Response{Error: finalErr}
		return
	}

	genesisAddr, err = genesisPubKey.Address() // Step 1: Call Address() method
	if err != nil {
		finalErr := fmt.Errorf("failed to get address object from genesis public key: %v", err)
		log.Printf("ERROR: %v", finalErr)
		msg.ResponseCh <- types.Response{Error: finalErr}
		return
	}
	if genesisAddr == nil { // Also check if the returned address object itself is nil
		finalErr := fmt.Errorf("genesis public key returned nil address object")
		log.Printf("ERROR: %v", finalErr)
		msg.ResponseCh <- types.Response{Error: finalErr}
		return
	}

	genesisAddrStr = genesisAddr.String() // Step 2: Call String() on the address object
	// --- END FIX ---

	// --- Use Database Transaction for Atomicity ---
	// NOTE: Adding DB transaction logic here as it's essential for the *next* step (UTXO creation)
	var dbTxContext types.TransactionContext
	dbTxContext, err = bc.ShardState.Database.BeginTransaction()
	if err != nil {
		log.Printf("ERROR: HandleFundNewAddress failed to begin database transaction: %v", err)
		msg.ResponseCh <- types.Response{Error: fmt.Errorf("failed to start DB transaction: %v", err)}
		return
	}
	var finalErr error // Use named error variable for deferred rollback logic
	defer func() {
		if finalErr != nil && dbTxContext != nil {
			log.Printf("WARN: Rolling back DB transaction in HandleFundNewAddress due to error: %v", finalErr)
			_ = bc.ShardState.Database.RollbackTransaction(dbTxContext) // Ignore rollback error
		}
	}()

	// --- Lock In-Memory State (Single Scope for consistency) ---
	bc.ShardState.Mu.Lock()
	defer bc.ShardState.Mu.Unlock()

	// --- Check Genesis Balance & Update In-Memory Stakeholders ---
	log.Printf("All addresses in stakeholders map before funding:")
	for addr, bal := range bc.ShardState.Stakeholders {
		log.Printf("  %s: %d", addr, bal)
	}

	genesisBalance, genesisExists := bc.ShardState.Stakeholders[genesisAddrStr] // Use corrected genesisAddrStr
	if !genesisExists {
		finalErr = fmt.Errorf("genesis address %s not found in stakeholders map", genesisAddrStr)
		log.Printf("ERROR: %v", finalErr)
		// Unlock happens via defer, just send response and return
		msg.ResponseCh <- types.Response{Error: finalErr}
		return
	}
	log.Printf("Genesis address: %s, Balance: %d", genesisAddrStr, genesisBalance)

	amountValue := int64(req.Amount)

	if genesisBalance < amountValue {
		finalErr = fmt.Errorf("insufficient genesis funds: %d needed, %d available", amountValue, genesisBalance)
		log.Printf("ERROR: %v", finalErr)
		msg.ResponseCh <- types.Response{Error: finalErr}
		return
	}

	// Update Stakeholders map (In-Memory)
	bc.ShardState.Stakeholders[genesisAddrStr] -= amountValue
	recipientBalance := bc.ShardState.Stakeholders[req.Address]
	bc.ShardState.Stakeholders[req.Address] = recipientBalance + amountValue
	log.Printf("Credited %d tokens (in-memory) to address %s, new balance: %d",
		amountValue, req.Address, bc.ShardState.Stakeholders[req.Address])

	// --- Create Funding UTXO --- <<< ADDED LOGIC >>>
	fundingTxID := fmt.Sprintf("funding-%s-%d", req.Address, time.Now().UnixNano())
	fundingUtxo := types.UTXO{
		TransactionID: fundingTxID,
		Index:         0,
		OwnerAddress:  req.Address,
		Amount:        req.Amount, // Use original amount.Amount type
		IsSpent:       false,
	}
	fundingUtxoKey := fundingUtxo.Key() // Or fmt.Sprintf("%s-%d", fundingTxID, 0)

	// --- Add Funding UTXO to In-Memory Map --- <<< ADDED LOGIC >>>
	protoUtxo := convertTypesUTXOToProtoUTXO(fundingUtxo) // Convert to map value type (*thrylos.UTXO)
	bc.ShardState.UTXOs[fundingUtxoKey] = append(bc.ShardState.UTXOs[fundingUtxoKey], protoUtxo)
	log.Printf("DEBUG: Added funding UTXO %s to in-memory map", fundingUtxoKey)

	// --- Persist State Changes to Database (within DB Transaction) ---
	log.Printf("DEBUG: Persisting balance/UTXO updates to DB...")

	// 1. Update Genesis Balance in DB
	err = bc.ShardState.Database.UpdateBalance(genesisAddrStr, bc.ShardState.Stakeholders[genesisAddrStr]) // Use dbTxContext if required?
	if err != nil {
		finalErr = fmt.Errorf("failed to update genesis balance in DB: %v", err)
		log.Printf("ERROR: %v", finalErr)
		msg.ResponseCh <- types.Response{Error: finalErr}
		return
	}
	log.Printf("SUCCESS: Updated genesis balance for %s in DB", genesisAddrStr)

	// 2. Update Recipient Balance in DB
	err = bc.ShardState.Database.UpdateBalance(req.Address, bc.ShardState.Stakeholders[req.Address]) // Use dbTxContext if required?
	if err != nil {
		finalErr = fmt.Errorf("failed to update recipient %s balance in DB: %v", req.Address, err)
		log.Printf("ERROR: %v", finalErr)
		msg.ResponseCh <- types.Response{Error: finalErr}
		return
	}
	log.Printf("SUCCESS: Updated recipient balance for %s in DB", req.Address)

	// 3. Add New Funding UTXO to DB --- <<< ADDED LOGIC >>>
	err = bc.ShardState.Database.AddNewUTXO(dbTxContext, fundingUtxo, totalNumShards) // FIXED: Added totalNumShards
	if err != nil {
		finalErr = fmt.Errorf("failed to persist funding UTXO %s to DB: %v", fundingUtxoKey, err)
		log.Printf("ERROR: %v", finalErr)
		// Assuming msg.ResponseCh and return are part of this function's signature
		// msg.ResponseCh <- types.Response{Error: finalErr}
		return // Ensure the function correctly handles returning after error
	}
	log.Printf("SUCCESS: Persisted funding UTXO %s to DB", fundingUtxoKey)

	// --- Commit DB Transaction ---
	// If we got here, all DB ops conceptually succeeded. Commit now.
	commitErr := bc.ShardState.Database.CommitTransaction(dbTxContext)
	if commitErr != nil {
		finalErr = fmt.Errorf("failed to commit funding DB transaction for %s: %v", req.Address, commitErr)
		log.Printf("ERROR: %v", finalErr)
		// Rollback is handled by defer using finalErr
		msg.ResponseCh <- types.Response{Error: finalErr}
		return
	}
	dbTxContext = nil // Prevent rollback by defer if commit was successful

	// --- Success ---
	log.Printf("Successfully funded address %s and created UTXO %s", req.Address, fundingUtxoKey)
	msg.ResponseCh <- types.Response{Data: true} // Send success AFTER commit
}
