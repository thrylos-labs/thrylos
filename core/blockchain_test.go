package core

import (
	"crypto/ed25519"
	"crypto/rand"
	"io/ioutil"
	"os"
	"testing"

	"github.com/thrylos-labs/thrylos/shared"
)

func TestNewBlockchain(t *testing.T) {
	// Create a temporary directory for blockchain data
	tempDir, err := ioutil.TempDir("", "blockchain_test")
	if err != nil {
		t.Fatalf("Failed to create temporary directory: %v", err)
	}
	// Clean up the temporary directory after the test
	defer os.RemoveAll(tempDir)

	// Generate a dummy AES key for testing
	aesKey, err := shared.GenerateAESKey() // Adjust the function call according to your package and method
	if err != nil {
		t.Fatalf("Failed to generate AES key: %v", err)
	}

	// Create a new blockchain using the temporary directory and generated AES key
	bc, err := NewBlockchain(tempDir, aesKey)
	if err != nil {
		t.Fatalf("Failed to create blockchain: %v", err)
	}

	if bc.Genesis == nil {
		t.Errorf("Genesis block is nil")
	}
	// Further checks can include validating the initial state of the blockchain, such as the number of blocks, initial UTXOs, etc.
}

func TestEd25519Signature(t *testing.T) {
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("Ed25519 key generation failed: %v", err)
	}

	// Create a mock transaction (simplified representation)
	tx := "mock transaction"
	txBytes := []byte(tx)

	// Sign the transaction
	signature := ed25519.Sign(privateKey, txBytes)

	// Verify the signature
	if !ed25519.Verify(publicKey, txBytes, signature) {
		t.Fatal("Ed25519 signature verification failed")
	}

	t.Log("Ed25519 signature verification succeeded")
}
