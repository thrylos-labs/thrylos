package chain

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"sync"

	"github.com/thrylos-labs/thrylos/amount"
	"github.com/thrylos-labs/thrylos/crypto"
	"github.com/thrylos-labs/thrylos/crypto/address"
	"github.com/thrylos-labs/thrylos/shared"

	thrylos "github.com/thrylos-labs/thrylos"
	"github.com/thrylos-labs/thrylos/types"
	"github.com/thrylos-labs/thrylos/utils"
)

func (bc *BlockchainImpl) ProcessPendingTransactionsWithBatch(validator string, batch []*thrylos.Transaction) (*types.Block, error) {
	// Similar to ProcessPendingTransactions but works with the provided batch
	return bc.ProcessPendingTransactions(validator)
}

func (bc *BlockchainImpl) notifyBalanceUpdates(tx *thrylos.Transaction) {
	if bc.Blockchain.OnBalanceUpdate == nil {
		return
	}

	addresses := make(map[string]bool)
	addresses[tx.Sender] = true
	for _, output := range tx.Outputs {
		addresses[output.OwnerAddress] = true
	}

	for address := range addresses {
		balance, err := bc.GetBalance(address)
		if err != nil {
			log.Printf("Failed to get balance for %s: %v", address, err)
			continue
		}
		// Convert amount.Amount to int64 for the callback
		bc.Blockchain.OnBalanceUpdate(address, int64(balance))
	}
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
	// First, verify validator status before acquiring locks
	// if !bc.IsActiveValidator(validator) {
	// 	return nil, fmt.Errorf("invalid validator: %s", validator)
	// }

	// Take a snapshot of pending transactions under lock
	bc.Blockchain.Mu.Lock()
	if len(bc.Blockchain.PendingTransactions) == 0 {
		bc.Blockchain.Mu.Unlock()
		return nil, nil // Nothing to process
	}
	pendingTransactions := make([]*thrylos.Transaction, len(bc.Blockchain.PendingTransactions))
	copy(pendingTransactions, bc.Blockchain.PendingTransactions)
	bc.Blockchain.Mu.Unlock()

	// Start database transaction
	txContext, err := bc.Blockchain.Database.BeginTransaction()
	if err != nil {
		return nil, fmt.Errorf("database transaction error: %v", err)
	}
	defer bc.Blockchain.Database.RollbackTransaction(txContext)

	// Process transactions in batches
	successfulTransactions := make([]*thrylos.Transaction, 0, len(pendingTransactions))
	for _, tx := range pendingTransactions {
		// Convert to pointer if processTransactionInBlock expects a pointer
		// or change processTransactionInBlock to accept an interface
		if err := bc.processTransactionInBlock(&txContext, tx); err != nil {
			log.Printf("Transaction %s failed: %v", tx.Id, err) // Changed ID to Id
			continue
		}
		successfulTransactions = append(successfulTransactions, tx)
	}

	// Create and sign block
	unsignedBlock, err := bc.CreateUnsignedBlock(successfulTransactions, validator)
	if err != nil {
		return nil, fmt.Errorf("block creation failed: %v", err)
	}

	signedBlock, err := bc.SimulateValidatorSigning(unsignedBlock)
	if err != nil {
		return nil, fmt.Errorf("block signing failed: %v", err)
	}

	// Commit database changes
	if err := bc.Blockchain.Database.CommitTransaction(txContext); err != nil {
		return nil, fmt.Errorf("commit failed: %v", err)
	}

	// Only after successful commit do we update blockchain state
	bc.Blockchain.Mu.Lock()
	bc.Blockchain.Blocks = append(bc.Blockchain.Blocks, signedBlock)
	// Remove processed transactions from pending pool
	bc.Blockchain.PendingTransactions = bc.Blockchain.PendingTransactions[len(successfulTransactions):]
	bc.Blockchain.Mu.Unlock()

	// Async notifications
	go func() {
		for _, tx := range signedBlock.Transactions {
			// Convert the hash string to []byte
			blockHashBytes := []byte(signedBlock.Hash.String())

			bc.UpdateTransactionStatus(tx.ID, "included", blockHashBytes)

			// Convert to thrylos.Transaction before calling the callback
			thrylosTx := convertToThrylosTransaction(tx)

			if bc.Blockchain.OnTransactionProcessed != nil {
				bc.Blockchain.OnTransactionProcessed(thrylosTx)
			}

			// Now we can use the same converted transaction for notifying balance updates
			bc.notifyBalanceUpdates(thrylosTx)
		}
	}()

	return signedBlock, nil
}

// // First, ensure when creating transaction inputs we set the original transaction ID
func (bc *BlockchainImpl) processTransactionInBlock(txContext *types.TransactionContext, tx *thrylos.Transaction) error {
	// Mark input UTXOs as spent
	for _, input := range tx.Inputs {
		// Validate input fields
		if input.TransactionId == "" {
			return fmt.Errorf("input UTXO has no transaction_id field set")
		}

		utxo := types.UTXO{
			TransactionID: input.TransactionId, // This must be the genesis or previous transaction ID
			Index:         int(input.Index),
			OwnerAddress:  input.OwnerAddress,
			Amount:        amount.Amount(input.Amount), // Convert int64 to amount.Amount
			IsSpent:       false,
		}

		// Debug logging
		log.Printf("Processing input UTXO: TransactionID=%s, Index=%d, Owner=%s, Amount=%d",
			utxo.TransactionID, utxo.Index, utxo.OwnerAddress, utxo.Amount)

		// Dereference txContext since the function expects an interface, not a pointer to an interface
		if err := bc.Blockchain.Database.MarkUTXOAsSpent(*txContext, utxo); err != nil {
			return fmt.Errorf("failed to mark UTXO as spent: %v", err)
		}
	}

	// Create new UTXOs for outputs with the current transaction ID
	for i, output := range tx.Outputs {
		newUTXO := types.UTXO{
			TransactionID: tx.Id, // Use current transaction's ID for new UTXOs
			Index:         i,
			OwnerAddress:  output.OwnerAddress,
			Amount:        amount.Amount(output.Amount), // Convert int64 to amount.Amount
			IsSpent:       false,
		}

		// Debug logging
		log.Printf("Creating new UTXO: TransactionID=%s, Index=%d, Owner=%s, Amount=%d",
			newUTXO.TransactionID, newUTXO.Index, newUTXO.OwnerAddress, newUTXO.Amount)

		// Dereference txContext since the function expects an interface, not a pointer to an interface
		if err := bc.Blockchain.Database.AddNewUTXO(*txContext, newUTXO); err != nil {
			return fmt.Errorf("failed to create new UTXO: %v", err)
		}
	}

	return nil
}

// // // validateTransactionsConcurrently runs transaction validations in parallel and collects errors.
// // Validate transactions with available UTXOs
func (bc *BlockchainImpl) validateTransactionsConcurrently(transactions []*thrylos.Transaction) []error {
	var wg sync.WaitGroup
	errChan := make(chan error, len(transactions))

	// Convert UTXOs outside the goroutines to avoid concurrent map read/write issues
	availableUTXOs := bc.convertUTXOsToRequiredFormat()

	for _, tx := range transactions {
		wg.Add(1)
		go func(tx *thrylos.Transaction) {
			defer wg.Done()

			// Check if the transaction ID is empty
			if tx.Id == "" {
				errChan <- fmt.Errorf("transaction ID is empty")
				return
			}

			// Convert each thrylos.Transaction to a shared.Transaction
			sharedTx, err := bc.convertToSharedTransaction(tx)
			if err != nil {
				errChan <- fmt.Errorf("conversion error for transaction ID %s: %v", tx.Id, err)
				return
			}

			// Validate the converted transaction using the shared transaction validation logic
			// ValidateTransaction returns an error, not a boolean
			if err := shared.ValidateTransaction(&sharedTx, availableUTXOs); err != nil {
				errChan <- fmt.Errorf("validation failed for transaction ID %s: %v", sharedTx.ID, err)
			}
		}(tx)
	}

	wg.Wait()
	close(errChan)

	var errs []error
	for err := range errChan {
		if err != nil {
			errs = append(errs, err)
		}
	}
	return errs
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
	bc.Blockchain.Mu.RLock()
	defer bc.Blockchain.Mu.RUnlock()

	count := 0
	for _, block := range bc.Blockchain.Blocks {
		for _, transaction := range block.Transactions {
			// Use SenderAddress instead of Sender and convert it to string for comparison
			if transaction.SenderAddress.String() == address {
				count++
			}
		}
	}
	return count
}

func (bc *BlockchainImpl) UpdateTransactionStatus(txID string, status string, blockHash []byte) error {
	// Begin a new database transaction
	txn, err := bc.Blockchain.Database.BeginTransaction()
	if err != nil {
		return fmt.Errorf("failed to begin database transaction: %v", err)
	}
	defer bc.Blockchain.Database.RollbackTransaction(txn)

	// Retrieve the existing transaction
	// Use GetBadgerTxn() to get the underlying Badger transaction
	badgerTxn := txn.GetBadgerTxn()
	txKey := []byte("transaction-" + txID)

	item, err := badgerTxn.Get(txKey)
	if err != nil {
		// If transaction doesn't exist, create a new one
		tx := &thrylos.Transaction{
			Id:        txID,
			Status:    status,
			BlockHash: blockHash,
			// Set other required fields that you have available
		}
		txJSON, err := json.Marshal(tx)
		if err != nil {
			return fmt.Errorf("error marshaling new transaction: %v", err)
		}
		if err := bc.Blockchain.Database.SetTransaction(txn, txKey, txJSON); err != nil {
			return fmt.Errorf("error storing new transaction: %v", err)
		}
	} else {
		// Update existing transaction
		var tx thrylos.Transaction
		err = item.Value(func(val []byte) error {
			return json.Unmarshal(val, &tx)
		})
		if err != nil {
			return fmt.Errorf("error unmarshaling transaction: %v", err)
		}

		// Update the transaction status
		tx.Status = status
		tx.BlockHash = blockHash

		// Serialize and store the updated transaction
		updatedTxJSON, err := json.Marshal(tx)
		if err != nil {
			return fmt.Errorf("error marshaling updated transaction: %v", err)
		}
		if err := bc.Blockchain.Database.SetTransaction(txn, txKey, updatedTxJSON); err != nil {
			return fmt.Errorf("error updating transaction: %v", err)
		}
	}

	// Commit the transaction
	if err := bc.Blockchain.Database.CommitTransaction(txn); err != nil {
		return fmt.Errorf("error committing transaction update: %v", err)
	}

	log.Printf("Transaction %s status updated to %s in block %x", txID, status, blockHash)
	return nil
}

// verifyTransactionUniqueness checks if a transaction's salt is unique across the blockchain
func verifyTransactionUniqueness(tx *types.Transaction, bc *BlockchainImpl) error {
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
	if bc.checkSaltInBlocks(tx.Salt) {
		return fmt.Errorf("duplicate salt detected: transaction replay attempt")
	}

	return nil
}

// Update validateBlockTransactionSalts to use the new function
func (bc *BlockchainImpl) validateBlockTransactionSalts(block *types.Block) error {
	seenSalts := make(map[string]bool)

	for _, tx := range block.Transactions {
		saltStr := string(tx.Salt)
		if seenSalts[saltStr] {
			return fmt.Errorf("duplicate salt found in block transactions")
		}
		seenSalts[saltStr] = true

		// Verify each transaction's salt
		if err := verifyTransactionUniqueness(tx, bc); err != nil {
			return fmt.Errorf("invalid transaction salt: %v", err)
		}
	}
	return nil
}

// // // // Helper function to efficiently check salt uniqueness in all blocks
func (bc *BlockchainImpl) checkSaltInBlocks(salt []byte) bool {
	bc.Blockchain.Mu.RLock()
	defer bc.Blockchain.Mu.RUnlock()

	// Create an efficient lookup for pending transaction salts
	pendingSalts := make(map[string]bool)
	for _, tx := range bc.Blockchain.PendingTransactions {
		pendingSalts[string(tx.Salt)] = true
	}

	// Check pending transactions first (faster in-memory check)
	if pendingSalts[string(salt)] {
		return true
	}

	// Check confirmed blocks
	for _, block := range bc.Blockchain.Blocks {
		for _, tx := range block.Transactions {
			if bytes.Equal(tx.Salt, salt) {
				return true
			}
		}
	}

	return false
}

// func SharedToThrylos(tx *types.Transaction) *thrylos.Transaction {
// 	if tx == nil {
// 		return nil
// 	}

// 	signatureBytes, _ := base64.StdEncoding.DecodeString(tx.Signature)

// 	// Generate salt for new transaction if not present
// 	salt := tx.Salt
// 	if len(salt) == 0 {
// 		var err error
// 		salt, err = generateSalt()
// 		if err != nil {
// 			log.Printf("Failed to generate salt: %v", err)
// 			return nil
// 		}
// 	}

// 	return &thrylos.Transaction{
// 		Id:            tx.ID,
// 		Timestamp:     tx.Timestamp,
// 		Inputs:        ConvertSharedInputs(tx.Inputs),
// 		Outputs:       ConvertSharedOutputs(tx.Outputs),
// 		Signature:     signatureBytes,
// 		Salt:          salt,
// 		PreviousTxIds: tx.PreviousTxIds,
// 		Sender:        tx.Sender,
// 		Status:        tx.Status,
// 		Gasfee:        int32(tx.GasFee),
// 	}
// }

// func ConvertSharedOutputs(outputs []types.UTXO) []*thrylos.UTXO {
// 	result := make([]*thrylos.UTXO, len(outputs))
// 	for i, output := range outputs {
// 		result[i] = &thrylos.UTXO{
// 			TransactionId: output.TransactionID,
// 			Index:         int32(output.Index),
// 			OwnerAddress:  output.OwnerAddress,
// 			Amount:        output.Amount,
// 			IsSpent:       output.IsSpent,
// 		}
// 	}
// 	return result
// }

// func ConvertSharedInputs(inputs []types.UTXO) []*thrylos.UTXO {
// 	return ConvertSharedOutputs(inputs) // Same conversion process
// }

// // Helper function to get delegation pool stats
// func (bc *BlockchainImpl) GetPoolStats() map[string]interface{} {
// 	bc.Mu.RLock()
// 	defer bc.Mu.RUnlock()

// 	return bc.StakingService.GetPoolStats()
// }

func (bc *BlockchainImpl) validatePoolTransaction(tx *thrylos.Transaction) error {
	// Implement pool-specific transaction validation
	if tx.Sender == "staking-pool" {
		// Validate undelegation
		delegator := tx.Outputs[0].OwnerAddress
		amount := tx.Outputs[0].Amount

		// Get the delegator's balance directly from the blockchain's stakeholders map
		bc.Blockchain.Mu.RLock()
		delegatorBalance, exists := bc.Blockchain.Stakeholders[delegator]
		bc.Blockchain.Mu.RUnlock()

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
func verifyTransactionUniquenessTx(tx *thrylos.Transaction, bc *BlockchainImpl) error {
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
	if bc.checkSaltInBlocks(tx.Salt) {
		return fmt.Errorf("duplicate salt detected: transaction replay attempt")
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

	// Verify transaction uniqueness using salt
	if err := verifyTransactionUniquenessTx(tx, bc); err != nil {
		return false, fmt.Errorf("salt verification failed: %v", err)
	}

	// Convert UTXOs to proto format
	protoUTXOs := make(map[string][]*thrylos.UTXO)
	for key, utxos := range bc.Blockchain.UTXOs {
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
		pubKey, err := bc.Blockchain.Database.GetPublicKey(*addr)
		if err != nil {
			return nil, err
		}

		return pubKey, nil
	}

	// Call VerifyTransactionData with the function that returns crypto.PublicKey
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
	bc.Blockchain.Mu.Lock()
	defer bc.Blockchain.Mu.Unlock()

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
	for _, block := range bc.Blockchain.Blocks {
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

func (bc *BlockchainImpl) updateBalancesForBlock(block *types.Block) {
	for _, tx := range block.Transactions {
		// Update sender's balance
		senderBalance, err := bc.GetBalance(tx.SenderAddress.String())
		if err != nil {
			log.Printf("Error getting sender balance for %s: %v", tx.SenderAddress.String(), err)
			continue
		}

		// Convert amount.Amount to int64
		bc.Blockchain.Stakeholders[tx.SenderAddress.String()] = int64(senderBalance)

		// Update recipients' balances from outputs
		for _, output := range tx.Outputs {
			recipientBalance, err := bc.GetBalance(output.OwnerAddress)
			if err != nil {
				log.Printf("Error getting recipient balance for %s: %v", output.OwnerAddress, err)
				continue
			}
			// Convert amount.Amount to int64
			bc.Blockchain.Stakeholders[output.OwnerAddress] = int64(recipientBalance)
		}
	}

	// Log the updated balances for debugging
	for address, balance := range bc.Blockchain.Stakeholders {
		log.Printf("Updated balance for %s: %d", address, balance)
	}
}
