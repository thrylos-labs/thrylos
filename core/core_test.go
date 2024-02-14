package core

import (
	"Thrylos/shared"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
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
	privateKey, publicKey, err := shared.GenerateRSAKeys(2048)
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

	// Step 3: Serialize the transaction, excluding the signature
	serializedTx, err := json.Marshal(tx)
	if err != nil {
		t.Fatalf("Failed to serialize transaction: %v", err)
	}

	// Step 4: Hash the serialized transaction data
	hashed := sha256.Sum256(serializedTx)

	// Step 5: Sign the hash
	signature, err := rsa.SignPKCS1v15(rand.Reader, privateKey, crypto.SHA256, hashed[:])
	if err != nil {
		t.Fatalf("Failed to sign transaction: %v", err)
	}

	// Step 6: Verify the signature
	err = rsa.VerifyPKCS1v15(publicKey, crypto.SHA256, hashed[:], signature)
	if err != nil {
		t.Fatalf("Signature verification failed: %v", err)
	}

	t.Log("Transaction signing and verification successful")
}
