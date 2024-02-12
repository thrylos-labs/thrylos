package core

import (
	"Thrylos/shared"
	"crypto/rand"
	"crypto/rsa"
	"testing"
)

// This test checks if the blockchain initializes correctly with a genesis block.
func TestBlockchainInitialization(t *testing.T) {
	bc, err := NewBlockchain()
	if err != nil {
		t.Fatalf("Failed to initialize blockchain: %v", err)
	}
	if len(bc.Blocks) != 1 {
		t.Errorf("Blockchain should start with the genesis block. Found %d blocks", len(bc.Blocks))
	}
}

// Generatees the test keys
func generateTestKeyPairs() (*rsa.PrivateKey, *rsa.PublicKey, error) {
	privKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, nil, err
	}
	return privKey, &privKey.PublicKey, nil
}

func CreateMockTransactions() []shared.Transaction {
	privKey, _, _ := generateTestKeyPairs()

	// Create UTXO with valid data
	inputUTXO := shared.UTXO{
		ID:            "utxo1", // Ensure this ID matches an entry in availableUTXOs
		TransactionID: "tx0",
		Index:         0,
		OwnerAddress:  "Alice",
		Amount:        100,
	}

	outputUTXO := shared.UTXO{
		ID:            "utxo2",
		TransactionID: "tx1",
		Index:         0,
		OwnerAddress:  "Bob",
		Amount:        100,
	}

	tx, _ := shared.CreateAndSignTransaction("tx1", []shared.UTXO{inputUTXO}, []shared.UTXO{outputUTXO}, privKey)

	// Return a slice of transactions
	return []shared.Transaction{tx}
}

// Test the transaction verification mechanism to ensure only valid transactions are processed.

func TestTransactionVerification(t *testing.T) {
	// Setup: Create a blockchain and a valid transaction
	bc, _ := NewBlockchain()
	txs := CreateMockTransactions() // Assume this function creates valid transactions

	// Add the transactions to a block
	err := bc.AddBlock(txs, "validator1", bc.Blocks[len(bc.Blocks)-1].Hash)
	if err != nil {
		t.Fatalf("Failed to add block with transactions: %v", err)
	}

	// Check if the transactions were verified and added successfully
	if len(bc.Blocks) != 2 {
		t.Errorf("Transactions were not added to the blockchain")
	}
}

// This test ensures that blocks with invalid transactions are rejected.

func TestBlockAdditionWithInvalidTransactions(t *testing.T) {
	bc, _ := NewBlockchain()
	validTxs := CreateMockTransactions()   // Valid transactions
	invalidTxs := CreateMockTransactions() // Manipulate to make them invalid, e.g., by altering the signature

	// Attempt to add a block with invalid transactions
	err := bc.AddBlock(append(validTxs, invalidTxs...), "validator1", bc.Blocks[len(bc.Blocks)-1].Hash)
	if err == nil {
		t.Errorf("Expected error when adding a block with invalid transactions")
	}
}

// This test validates the consensus mechanism, ensuring that only the longest valid chain is accepted.

func TestBlockchainConsensus(t *testing.T) {
	// Initialize two blockchain instances to simulate a fork
	bc1, _ := NewBlockchain()
	bc2, _ := NewBlockchain()

	// Add blocks to both chains
	bc1.AddBlock(CreateMockTransactions(), "validator1", bc1.Blocks[len(bc1.Blocks)-1].Hash)
	bc2.AddBlock(CreateMockTransactions(), "validator2", bc2.Blocks[len(bc2.Blocks)-1].Hash)
	bc2.AddBlock(CreateMockTransactions(), "validator3", bc2.Blocks[len(bc2.Blocks)-1].Hash)

	// Simulate resolving the fork by choosing the longest chain (bc2 in this case)
	bc1.ResolveForks() // Call ResolveForks method on bc1
	if len(bc1.Blocks) != len(bc2.Blocks) {
		t.Errorf("Blockchain consensus failed to choose the correct chain")
	}
}

// Ensure that UTXOs are correctly updated after transactions.

func TestUTXOHandling(t *testing.T) {
	bc, _ := NewBlockchain()
	txs := CreateMockTransactions() // Assume this creates valid transactions and updates UTXOs

	bc.AddBlock(txs, "validator1", bc.Blocks[len(bc.Blocks)-1].Hash)

	// Verify UTXOs are correctly updated
	for _, tx := range txs {
		for _, output := range tx.Outputs {
			utxoKey := output.ID
			_, exists := bc.UTXOs[utxoKey]
			if !exists {
				t.Errorf("UTXO for output ID %s not found", output.ID)
			}
		}
	}
}
