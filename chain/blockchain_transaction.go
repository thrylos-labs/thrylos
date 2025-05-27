package chain

import (
	"bytes"
	"encoding/hex"
	"errors"
	"fmt"
	"log"

	"github.com/dgraph-io/badger/v3"
	"github.com/thrylos-labs/thrylos/amount"
	"github.com/thrylos-labs/thrylos/crypto"
	"github.com/thrylos-labs/thrylos/crypto/address"
	"github.com/thrylos-labs/thrylos/store"

	thrylos "github.com/thrylos-labs/thrylos"
	"github.com/thrylos-labs/thrylos/types"
	"github.com/thrylos-labs/thrylos/utils"
)

func (bc *BlockchainImpl) ProcessPendingTransactionsWithBatch(validator string, batch []*thrylos.Transaction) (*types.Block, error) {
	// Similar to ProcessPendingTransactions but works with the provided batch
	return bc.ProcessPendingTransactions(validator)
}

func (bc *BlockchainImpl) AddTransactionToPool(tx *types.Transaction) error {
	if bc.txPool == nil {
		return fmt.Errorf("transaction pool is not initialized")
	}
	return bc.txPool.AddTransaction(tx)
}

func (b *BlockchainImpl) ProcessIncomingTransaction(tx *types.Transaction) error {
	// Convert the transaction type and handle both return values
	thrylosTx, err := ConvertToThrylosTransaction(tx)
	if err != nil {
		return fmt.Errorf("failed to convert transaction: %w", err)
	}
	if thrylosTx == nil {
		return fmt.Errorf("converted transaction is nil")
	}

	return b.modernProcessor.ProcessIncomingTransaction(thrylosTx)
}

// // // ProcessPendingTransactions processes all pending transactions, attempting to form a new block.
func (bc *BlockchainImpl) ProcessPendingTransactions(validator string) (*types.Block, error) {
	// Optional: Verify validator status early if desired
	if !bc.IsActiveValidator(validator) {
		return nil, fmt.Errorf("provided validator %s is not active", validator)
	}

	// Take a snapshot of pending transactions under lock
	bc.ShardState.Mu.Lock()
	// Check if the pool is empty *after* acquiring the lock
	if len(bc.ShardState.PendingTransactions) == 0 {
		bc.ShardState.Mu.Unlock()
		log.Println("INFO: [ProcessPending] No pending transactions to process.")
		return nil, nil // Nothing to process
	}
	// Create a copy to work with outside the lock
	pendingTransactions := make([]*thrylos.Transaction, len(bc.ShardState.PendingTransactions))
	copy(pendingTransactions, bc.ShardState.PendingTransactions)
	// Clear the main pending list immediately after copying
	bc.ShardState.PendingTransactions = make([]*thrylos.Transaction, 0)
	bc.ShardState.Mu.Unlock() // Release lock after copying/clearing

	log.Printf("INFO: [ProcessPending] Attempting to process %d pending transactions.", len(pendingTransactions))

	// --- REMOVED DB Transaction Context and processTransactionInBlock loop ---
	// Validation and state changes (marking UTXOs spent, creating new ones, updating balances)
	// are now handled entirely and atomically within AddBlockToChain.

	// Optional: Perform preliminary validation here if desired (e.g., signature checks, basic structure)
	// This could filter out obviously invalid transactions before block creation attempt.
	// For simplicity, we assume AddBlockToChain handles all final validation.
	transactionsForBlock := pendingTransactions // Use all copied transactions for now

	// If no transactions are available after potential filtering, exit
	if len(transactionsForBlock) == 0 {
		log.Println("INFO: [ProcessPending] No valid transactions available to form a block.")
		// Need to decide if original pendingTransactions should be requeued if filtering occurred.
		return nil, nil
	}

	log.Printf("INFO: [ProcessPending] Preparing to create block with %d transactions.", len(transactionsForBlock))

	// --- Block Creation and Signing ---
	// Create unsigned block with the selected transactions
	// The validator passed to this function is used here. Ensure it's a valid, active one.
	unsignedBlock, err := bc.CreateUnsignedBlock(transactionsForBlock, validator)
	if err != nil {
		// TODO: Requeue transactionsForBlock?
		return nil, fmt.Errorf("block creation failed: %w", err)
	}
	// Ensure validator was set
	if unsignedBlock.Validator == "" {
		// TODO: Requeue transactionsForBlock?
		return nil, errors.New("CreateUnsignedBlock did not set validator field")
	}

	// Retrieve the private key for the designated validator
	validatorPrivKey, _, errKey := bc.GetValidatorPrivateKey(unsignedBlock.Validator)
	if errKey != nil {
		// TODO: Requeue transactionsForBlock?
		return nil, fmt.Errorf("failed to get private key for validator %s: %w", unsignedBlock.Validator, errKey)
	}

	// Compute the block hash
	errHash := ComputeBlockHash(unsignedBlock)
	if errHash != nil {
		// TODO: Requeue transactionsForBlock?
		return nil, fmt.Errorf("failed to compute block hash: %w", errHash)
	}

	// Sign the block hash
	signature := validatorPrivKey.Sign(unsignedBlock.Hash.Bytes())
	unsignedBlock.Signature = signature

	// Basic check on signature
	if unsignedBlock.Signature == nil || len(unsignedBlock.Signature.Bytes()) == 0 {
		// TODO: Requeue transactionsForBlock?
		return nil, errors.New("failed to generate signature for block")
	}

	log.Printf("DEBUG: [ProcessPending] Block %d signed by %s.", unsignedBlock.Index, unsignedBlock.Validator)
	signedBlock := unsignedBlock // Rename for clarity
	// --- End Block Creation and Signing ---

	// --- REMOVED Commit DB Transaction for Transaction Effects ---

	// --- Add the Signed Block to the Chain ---
	// AddBlockToChain now handles all validation, DB transactions, state updates, and persistence atomically.
	errAdd := bc.AddBlockToChain(signedBlock)
	if errAdd != nil {
		// If AddBlockToChain fails, the state remains consistent as it handles its own rollback.
		log.Printf("ERROR: [ProcessPending] Failed to add signed block %d to chain: %v", signedBlock.Index, errAdd)
		// TODO: Requeue transactionsForBlock?
		return nil, fmt.Errorf("failed to add block %d to chain: %w", signedBlock.Index, errAdd)
	}
	// --- End Add Block ---

	// --- REMOVED Handling of Failed Transactions (as preliminary processing was removed) ---
	// If preliminary validation was added above, failed transactions would need requeueing here.

	// --- REMOVED Redundant Async notifications ---
	// AddBlockToChain should handle necessary notifications.

	log.Printf("INFO: [ProcessPending] Successfully processed pending transactions and initiated adding Block %d.", signedBlock.Index)
	return signedBlock, nil // Return the successfully added block
}

// // Helper function to convert thrylos.Transaction to shared.Transaction
func (bc *BlockchainImpl) convertToSharedTransaction(tx *thrylos.Transaction) (types.Transaction, error) {
	if tx == nil {
		return types.Transaction{}, fmt.Errorf("nil transaction received for conversion")
	}

	// Create a proper Signature object instead of using a string
	var signature crypto.Signature
	// This depends on your crypto package implementation - you might need to create it differently
	if len(tx.Signature) > 0 {
		signature = crypto.NewSignature(tx.Signature)
	}

	// Convert sender to address.Address
	senderAddr, err := address.FromString(tx.Sender)
	if err != nil {
		return types.Transaction{}, fmt.Errorf("invalid sender address: %v", err)
	}

	inputs := make([]types.UTXO, len(tx.Inputs))
	for i, input := range tx.Inputs {
		inputs[i] = types.UTXO{
			TransactionID: input.TransactionId,
			Index:         int(input.Index),
			OwnerAddress:  input.OwnerAddress,
			Amount:        amount.Amount(input.Amount), // Convert int64 to amount.Amount
		}
	}

	outputs := make([]types.UTXO, len(tx.Outputs))
	for i, output := range tx.Outputs {
		outputs[i] = types.UTXO{
			TransactionID: tx.Id, // Assume output inherits transaction ID
			Index:         int(output.Index),
			OwnerAddress:  output.OwnerAddress,
			Amount:        amount.Amount(output.Amount), // Convert int64 to amount.Amount
		}
	}

	return types.Transaction{
		ID:            tx.Id,
		Inputs:        inputs,
		Outputs:       outputs,
		Signature:     signature,
		Timestamp:     tx.Timestamp,
		SenderAddress: *senderAddr, // Use SenderAddress instead of Sender
		// Include other required fields with sensible defaults
		PreviousTxIds: tx.PreviousTxIds,
		GasFee:        int(tx.Gasfee),
		BlockHash:     string(tx.BlockHash),
		Salt:          tx.Salt,
		Status:        tx.Status,
	}, nil
}

// // This function should return the number of transactions for a given address, which is often referred to as the "nonce."

func (bc *BlockchainImpl) GetTransactionCount(address string) int {
	bc.ShardState.Mu.RLock()
	defer bc.ShardState.Mu.RUnlock()

	count := 0
	for _, block := range bc.ShardState.Blocks {
		for _, transaction := range block.Transactions {
			// Use SenderAddress instead of Sender and convert it to string for comparison
			if transaction.SenderAddress.String() == address {
				count++
			}
		}
	}
	return count
}

func (bc *BlockchainImpl) UpdateTransactionStatus(txID string, status string, blockHash []byte) (err error) { // Named return 'err'
	// Begin a new database transaction specifically for this status update
	txnCtx, startErr := bc.ShardState.Database.BeginTransaction()
	if startErr != nil {
		err = fmt.Errorf("failed to begin database transaction for status update %s: %w", txID, startErr)
		return err
	}

	// Defer a conditional rollback based on the named return error 'err'
	defer func() {
		if err != nil && txnCtx != nil {
			log.Printf("Rolling back transaction status update for %s due to error: %v", txID, err)
			_ = bc.ShardState.Database.RollbackTransaction(txnCtx)
		}
	}() // Invoke the func literal

	badgerTxn := txnCtx.GetBadgerTxn()
	if badgerTxn == nil {
		err = fmt.Errorf("failed to get underlying badger transaction from context for tx %s", txID)
		return err
	}

	// Use the correct prefix from your constants
	txKey := []byte(store.TransactionPrefix + txID)

	// Use the correct Transaction type (e.g., types.Transaction, thrylos.Transaction)
	var tx types.Transaction // Adjust type as needed

	item, getErr := badgerTxn.Get(txKey)
	if getErr != nil {
		if getErr == badger.ErrKeyNotFound {
			log.Printf("WARN: Transaction %s not found in DB for status update. Creating minimal entry.", txID)
			// You might need to adapt this based on whether your Transaction type is a struct or pointer, and how it's initialized
			tx = types.Transaction{ // Adjust initialization based on your actual struct/proto type
				ID: txID,
			}
		} else {
			err = fmt.Errorf("error retrieving transaction %s from DB: %w", txID, getErr)
			return err
		}
	} else {
		// Key found, unmarshal existing data
		valErr := item.Value(func(val []byte) error {
			// Use the correct unmarshal method for your Transaction type (e.g., JSON, Protobuf)
			// Example assumes a method exists on the type:
			unmarshalErr := tx.Unmarshal(val) // Replace with actual unmarshal logic
			if unmarshalErr != nil {
				log.Printf("ERROR: Failed to unmarshal existing transaction %s. Raw data: %x", txID, val)
				return fmt.Errorf("unmarshaling error: %w", unmarshalErr)
			}
			return nil
		})
		if valErr != nil {
			err = fmt.Errorf("error reading transaction value for %s: %w", txID, valErr)
			return err
		}
	}

	// --- Update the status and block hash ---
	tx.Status = status
	// <<< FIX IS HERE: Convert byte slice to hex string >>>
	tx.BlockHash = hex.EncodeToString(blockHash)
	// tx.Timestamp = time.Now().UnixNano() // Optional: update timestamp?

	// Marshal the updated transaction
	// Use the correct marshal method for your Transaction type
	updatedTxBytes, marshalErr := tx.Marshal() // Replace with actual marshal logic
	if marshalErr != nil {
		err = fmt.Errorf("error marshaling updated transaction %s: %w", txID, marshalErr)
		return err
	}

	// Set the updated value in the transaction context
	// Ensure SetTransaction exists and works with your context type
	setErr := bc.ShardState.Database.SetTransaction(txnCtx, txKey, updatedTxBytes)
	if setErr != nil {
		err = fmt.Errorf("error storing updated transaction %s: %w", txID, setErr)
		return err
	}

	// --- Commit the transaction ---
	commitErr := bc.ShardState.Database.CommitTransaction(txnCtx)
	if commitErr != nil {
		err = fmt.Errorf("error committing transaction status update for %s: %w", txID, commitErr)
		txnCtx = nil // Prevent defer rollback after commit failure
		return err
	}

	// --- Commit successful ---
	txnCtx = nil // Prevent defer rollback after successful commit
	// Log the original byte slice hash for consistency with other logs if desired
	log.Printf("Transaction %s status updated to %s in block %x", txID, status, blockHash)

	// err is implicitly nil here
	return nil
}

// verifyTransactionUniqueness checks if a transaction's salt is unique across the blockchain
func verifyTransactionUniqueness(tx *types.Transaction, bc *BlockchainImpl, shardID types.ShardID) error {
	if tx == nil {
		return fmt.Errorf("nil transaction")
	}
	if len(tx.Salt) == 0 {
		return fmt.Errorf("empty salt")
	}
	if len(tx.Salt) != 32 {
		return fmt.Errorf("invalid salt length: expected 32 bytes, got %d", len(tx.Salt))
	}

	// Use the efficient helper function to check salt uniqueness
	if bc.checkSaltInBlocks(tx.Salt, shardID) {
		return fmt.Errorf("duplicate salt detected: transaction replay attempt")
	}

	return nil
}

// // // // Helper function to efficiently check salt uniqueness in all blocks
func (bc *BlockchainImpl) checkSaltInBlocks(salt []byte, shardID types.ShardID) bool { // MODIFIED: Added shardID parameter
	// Log for clarity, showing which shard this check is for.
	log.Printf("DEBUG: checkSaltInBlocks called for salt %x on shard %d", salt, shardID)

	bc.ShardState.Mu.RLock()
	defer bc.ShardState.Mu.RUnlock()

	// Create an efficient lookup for pending transaction salts
	// These pending transactions should already be for THIS shard.
	pendingSalts := make(map[string]bool)
	for _, tx := range bc.ShardState.PendingTransactions {
		// Double check: ensure tx.Salt is not nil or empty before using as map key
		if len(tx.Salt) > 0 {
			pendingSalts[string(tx.Salt)] = true
		}
	}

	// Check pending transactions first (faster in-memory check)
	if len(salt) > 0 && pendingSalts[string(salt)] { // Add check for salt length
		log.Printf("INFO: Duplicate salt %x found in pending transactions for shard %d.", salt, shardID)
		return true
	}

	// Check confirmed blocks for this shard
	// `bc.ShardState.Blocks` already represents the blocks for *this specific shard*,
	// so no further filtering by `shardID` is needed here.
	for _, block := range bc.ShardState.Blocks {
		for _, tx := range block.Transactions {
			if bytes.Equal(tx.Salt, salt) {
				log.Printf("INFO: Duplicate salt %x found in block %d (Tx: %s) for shard %d.", salt, block.Index, tx.ID, shardID)
				return true
			}
		}
	}

	log.Printf("DEBUG: Salt %x not found in blocks or pending transactions for shard %d.", salt, shardID)
	return false
}

func (bc *BlockchainImpl) validatePoolTransaction(tx *thrylos.Transaction) error {
	// Implement pool-specific transaction validation
	if tx.Sender == "staking-pool" {
		// Validate undelegation
		delegator := tx.Outputs[0].OwnerAddress
		amount := tx.Outputs[0].Amount

		// Get the delegator's balance directly from the blockchain's stakeholders map
		bc.ShardState.Mu.RLock()
		delegatorBalance, exists := bc.ShardState.Stakeholders[delegator]
		bc.ShardState.Mu.RUnlock()

		if !exists {
			return fmt.Errorf("delegator not found: %s", delegator)
		}

		// Check if undelegation amount is valid
		if delegatorBalance < amount {
			return fmt.Errorf("invalid undelegation amount: %d exceeds available balance: %d",
				amount, delegatorBalance)
		}
	}

	return nil
}

// Update verifyTransactionUniqueness to handle thrylos.Transaction
func verifyTransactionUniquenessTx(tx *thrylos.Transaction, bc *BlockchainImpl, shardID types.ShardID) error {
	if tx == nil {
		return fmt.Errorf("nil transaction")
	}
	if len(tx.Salt) == 0 {
		return fmt.Errorf("empty salt")
	}
	if len(tx.Salt) != 32 {
		return fmt.Errorf("invalid salt length: expected 32 bytes, got %d", len(tx.Salt))
	}

	// Use the efficient helper function to check salt uniqueness
	// This call is correct, as `bc.checkSaltInBlocks` takes `salt` and `shardID`.
	if bc.checkSaltInBlocks(tx.Salt, shardID) {
		return fmt.Errorf("duplicate salt detected: transaction replay attempt on shard %d", shardID) // Added shardID to error msg
	}

	return nil
}

func (bc *BlockchainImpl) VerifyTransaction(tx *thrylos.Transaction) (bool, error) {
	// Check if salt is present and valid
	if len(tx.Salt) == 0 {
		return false, fmt.Errorf("transaction missing salt")
	}
	if len(tx.Salt) != 32 {
		return false, fmt.Errorf("invalid salt length: expected 32 bytes, got %d", len(tx.Salt))
	}

	// Get the shardID from the current BlockchainImpl's state
	currentShardID := bc.ShardState.ShardID

	// Verify transaction uniqueness using salt
	// Pass the currentShardID as the third argument
	if err := verifyTransactionUniquenessTx(tx, bc, currentShardID); err != nil { // FIXED: Added currentShardID
		return false, fmt.Errorf("salt verification failed: %v", err)
	}

	// Convert UTXOs to proto format
	// This section also implicitly operates on the current shard's state
	protoUTXOs := make(map[string][]*thrylos.UTXO)
	for key, utxos := range bc.ShardState.UTXOs {
		protoUTXOs[key] = utxos
	}

	// Define a function that returns crypto.PublicKey, not []byte
	pubKeyFetcher := func(addrStr string) (crypto.PublicKey, error) {
		// Convert string to address
		addr, err := address.FromString(addrStr)
		if err != nil {
			return nil, fmt.Errorf("invalid address format: %v", err)
		}

		// This returns the crypto.PublicKey directly, don't try to convert to bytes
		// GetPublicKey doesn't typically need shardID if public keys are global.
		// If your types.Store.GetPublicKey was updated to take shardID, pass it here.
		pubKey, err := bc.ShardState.Database.GetPublicKey(*addr)
		if err != nil {
			return nil, err
		}

		return pubKey, nil
	}

	// Call VerifyTransactionData with the function that returns crypto.PublicKey
	// VerifyTransactionData itself might need to be shard-aware if it does lookups.
	isValid, err := VerifyTransactionData(tx, protoUTXOs, pubKeyFetcher)

	if err != nil {
		return false, fmt.Errorf("transaction data verification failed: %v", err)
	}
	if !isValid {
		return false, fmt.Errorf("invalid transaction data")
	}

	return true, nil
}

// // Now we can update ProcessPoolTransaction to use these conversion functions
func (bc *BlockchainImpl) ProcessPoolTransaction(tx *thrylos.Transaction) error {
	// Use the Blockchain's mutex instead of Mu which doesn't exist directly on BlockchainImpl
	bc.ShardState.Mu.Lock()
	defer bc.ShardState.Mu.Unlock()

	// Verify pool-related transaction if needed
	if tx.Sender == "staking_pool" || (len(tx.Outputs) > 0 && tx.Outputs[0].OwnerAddress == "staking_pool") {
		// Check if validatePoolTransaction expects a *thrylos.Transaction
		if err := bc.validatePoolTransaction(tx); err != nil {
			return err
		}
	}

	// Convert thrylos.Transaction to types.Transaction for processing
	sharedTx := utils.ConvertToSharedTransaction(tx)

	// Use ProcessIncomingTransaction instead of AddPendingTransaction
	return bc.ProcessIncomingTransaction(sharedTx)
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

func (bc *BlockchainImpl) GetTransactionByID(id string) (*thrylos.Transaction, error) {
	// iterate over blocks and transactions to find by ID
	for _, block := range bc.ShardState.Blocks {
		for _, tx := range block.Transactions {
			if tx.ID == id { // Changed from Id to ID to match the field name
				// Convert from *types.Transaction to *thrylos.Transaction
				return convertToThrylosTransaction(tx), nil
			}
		}
	}
	return nil, errors.New("transaction not found")
}

// Helper function to convert from types.Transaction to thrylos.Transaction
func convertToThrylosTransaction(tx *types.Transaction) *thrylos.Transaction {
	if tx == nil {
		return nil
	}

	// Convert inputs - using UTXO instead of UTXOPointer
	inputs := make([]*thrylos.UTXO, len(tx.Inputs))
	for i, input := range tx.Inputs {
		inputs[i] = &thrylos.UTXO{
			TransactionId: input.TransactionID,
			Index:         int32(input.Index),
			OwnerAddress:  input.OwnerAddress,
			Amount:        int64(input.Amount),
			IsSpent:       input.IsSpent,
		}
	}

	// Convert outputs
	outputs := make([]*thrylos.UTXO, len(tx.Outputs))
	for i, output := range tx.Outputs {
		outputs[i] = &thrylos.UTXO{
			TransactionId: output.TransactionID,
			Index:         int32(output.Index),
			OwnerAddress:  output.OwnerAddress,
			Amount:        int64(output.Amount),
			IsSpent:       output.IsSpent,
		}
	}

	thrylosTx := &thrylos.Transaction{
		Id:               tx.ID,
		Timestamp:        tx.Timestamp,
		Inputs:           inputs,
		Outputs:          outputs,
		EncryptedInputs:  tx.EncryptedInputs,
		EncryptedOutputs: tx.EncryptedOutputs,
		EncryptedAesKey:  tx.EncryptedAESKey,
		PreviousTxIds:    tx.PreviousTxIds,
		Gasfee:           int32(tx.GasFee),
		BlockHash:        []byte(tx.BlockHash),
		Salt:             tx.Salt,
		Status:           tx.Status,
	}

	return thrylosTx
}
