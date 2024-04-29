package core

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"io/ioutil"
	"os"
	"testing"

	"github.com/thrylos-labs/thrylos/shared"
)

// go test -v -timeout 30s -run ^TestGenesisBlockCreation$ github.com/thrylos-labs/thrylos/core

func TestGenesisBlockCreation(t *testing.T) {
	// Set up the blockchain with a genesis block
	bc := setupTestBlockchain(t)

	// Check if the first block is the genesis block
	if len(bc.Blocks) == 0 || bc.Blocks[0] != bc.Genesis {
		t.Errorf("Genesis block is not the first block in the blockchain")
	}
}

func setupTestBlockchain(t *testing.T) *Blockchain {
	tempDir, err := ioutil.TempDir("", "blockchain_test")
	if err != nil {
		t.Fatalf("Failed to create temporary directory: %v", err)
	}
	defer os.RemoveAll(tempDir)

	aesKey, err := shared.GenerateAESKey() // Adjust the function call according to your package and method
	if err != nil {
		t.Fatalf("Failed to generate AES key: %v", err)
	}

	bc, err := NewBlockchain(tempDir, aesKey)
	if err != nil {
		t.Fatalf("Failed to initialize blockchain: %v", err)
	}

	if len(bc.Blocks) == 0 {
		genesis := NewGenesisBlock(nil) // Assuming no transactions in genesis for simplicity
		bc.Blocks = append(bc.Blocks, genesis)
	}

	return bc
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
