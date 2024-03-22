package core

import (
	"Thrylos/shared"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"testing"
)

// setupTestBlockchain initializes a blockchain instance for testing, including the creation of a genesis block if necessary.
func setupTestBlockchain(t *testing.T) *Blockchain {
	// Initialize the blockchain. This might involve creating a genesis block,
	// setting up a test database, or other initial setup required for your blockchain.
	bc, err := NewBlockchain()
	if err != nil {
		t.Fatalf("Failed to initialize blockchain for testing: %v", err)
	}

	// Example: Adding a genesis block explicitly if your NewBlockchain
	// function does not automatically do this. Adjust as needed.
	if len(bc.Blocks) == 0 {
		genesis := NewGenesisBlock()
		bc.Blocks = append(bc.Blocks, genesis)
		// If your blockchain implementation directly interacts with a database,
		// you might also need to insert the genesis block into the database here.
	}

	return bc
}

func TestGenesisBlockCreation(t *testing.T) {
	bc, err := NewBlockchain()
	if err != nil {
		t.Fatalf("Failed to initialize blockchain: %v", err)
	}
	if bc.Blocks[0] != bc.Genesis {
		t.Errorf("Genesis block is not the first block in the blockchain")
	}
	// Additional checks can include validating genesis block's specific properties.
}

func TestTransactionSigningAndVerification(t *testing.T) {
	// Step 1: Generate RSA keys
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("Failed to generate RSA keys: %v", err)
	}

	// Step 2: Create a new transaction
	tx := shared.Transaction{
		ID:        "txTest123",
		Timestamp: 1630000000,
		Inputs:    []shared.UTXO{{TransactionID: "tx0", Index: 0, OwnerAddress: "Alice", Amount: 100}},
		Outputs:   []shared.UTXO{{TransactionID: "txTest123", Index: 0, OwnerAddress: "Bob", Amount: 100}},
	}

	// Step 3: Serialize the transaction (excluding the signature for now, as we're focusing on signing)
	serializedTx, err := json.Marshal(tx)
	if err != nil {
		t.Fatalf("Failed to serialize transaction: %v", err)
	}

	// Step 4: Sign the serialized transaction data directly (Ed25519 does not require hashing before signing)
	signature := ed25519.Sign(privateKey, serializedTx)
	if signature == nil {
		t.Fatalf("Failed to sign transaction")
	}

	// Step 5: Verify the signature
	if !ed25519.Verify(publicKey, serializedTx, signature) {
		t.Fatalf("Signature verification failed")
	}

	t.Log("Transaction signing and verification successful with Ed25519")
}
