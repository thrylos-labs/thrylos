package chaintests

import (
	"crypto"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/cloudflare/circl/sign/mldsa/mldsa44"
	"github.com/thrylos-labs/thrylos/chain"
	encryption "github.com/thrylos-labs/thrylos/crypto/encrypt"
	"github.com/thrylos-labs/thrylos/shared"
)

func TestGenesisBlockCreation(t *testing.T) {
	// Set the environment variable needed for the test
	os.Setenv("GENESIS_ACCOUNT", "dummy_genesis_account_value")
	defer os.Unsetenv("GENESIS_ACCOUNT")

	// Create a temporary directory for blockchain data with a unique suffix
	tempDir, err := ioutil.TempDir("", fmt.Sprintf("blockchain_test_%d", time.Now().UnixNano()))
	if err != nil {
		t.Fatalf("Failed to create temporary directory: %v", err)
	}

	// Enhanced cleanup function that handles BadgerDB lock files
	cleanup := func() {
		// Give some time for any pending operations to complete
		time.Sleep(100 * time.Millisecond)

		// Remove lock file first
		lockFile := filepath.Join(tempDir, "LOCK")
		if err := os.Remove(lockFile); err != nil && !os.IsNotExist(err) {
			t.Logf("Warning: Failed to remove lock file: %v", err)
		}

		// Remove manifest files
		manifestFiles, err := filepath.Glob(filepath.Join(tempDir, "MANIFEST*"))
		if err == nil {
			for _, f := range manifestFiles {
				if err := os.Remove(f); err != nil {
					t.Logf("Warning: Failed to remove manifest file %s: %v", f, err)
				}
			}
		}

		// Give some time for file handles to be released
		time.Sleep(100 * time.Millisecond)

		// Finally remove the directory
		if err := os.RemoveAll(tempDir); err != nil {
			t.Logf("Warning: Failed to remove temp directory: %v", err)
		}
	}

	// Ensure cleanup runs at the end
	defer cleanup()

	// Generate a dummy AES key for testing
	aesKey, err := encryption.GenerateAESKey()
	if err != nil {
		t.Fatalf("Failed to generate AES key: %v", err)
	}

	genesisAccount := os.Getenv("GENESIS_ACCOUNT")
	if genesisAccount == "" {
		t.Fatal("Genesis account is not set in environment variables. This should not happen.")
	}

	// Initialize the blockchain with the temporary directory
	blockchain, store, err := chain.NewBlockchainWithConfig(&chain.BlockchainConfig{
		DataDir:           tempDir,
		AESKey:            aesKey,
		GenesisAccount:    genesisAccount,
		TestMode:          true,
		DisableBackground: true,
	})

	// If initialization fails, run cleanup and return
	if err != nil {
		cleanup()
		t.Fatalf("Failed to initialize blockchain: %v", err)
	}

	// Ensure store is closed before cleanup
	if closer, ok := store.(interface{ Close() }); ok {
		defer func() {
			closer.Close()
			time.Sleep(100 * time.Millisecond) // Give time for close operation to complete
		}()
	}

	// Check if the first block is the genesis block
	if len(blockchain.Blocks) == 0 || blockchain.Blocks[0] != blockchain.Genesis {
		t.Errorf("Genesis block is not the first block in the blockchain")
	}
}

func TestTransactionSigningAndVerification(t *testing.T) {
	// Step 1: Generate ML-DSA-44 keys
	seed := new([mldsa44.SeedSize]byte)
	_, err := rand.Read(seed[:])
	if err != nil {
		t.Fatalf("Failed to generate seed: %v", err)
	}

	publicKey, privateKey := mldsa44.NewKeyFromSeed(seed)

	// Step 2: Create a new transaction
	tx := shared.Transaction{
		ID:        "txTest123",
		Timestamp: 1630000000,
		Inputs:    []shared.UTXO{{TransactionID: "tx0", Index: 0, OwnerAddress: "Alice", Amount: 100}},
		Outputs:   []shared.UTXO{{TransactionID: "txTest123", Index: 0, OwnerAddress: "Bob", Amount: 100}},
	}

	// Step 3: Serialize the transaction
	serializedTx, err := json.Marshal(tx)
	if err != nil {
		t.Fatalf("Failed to serialize transaction: %v", err)
	}

	// Step 4: Sign the serialized transaction
	context := []byte{} // Use an empty context as required by ML-DSA-44
	// Sign the serialized transaction
	signature, err := privateKey.Sign(rand.Reader, serializedTx, crypto.Hash(0))
	if err != nil {
		t.Fatalf("Failed to sign transaction: %v", err)
	}

	// Step 5: Verify the signature
	if !mldsa44.Verify(publicKey, serializedTx, context, signature) {
		t.Fatalf("Signature verification failed")
	}

	t.Log("Transaction signing and verification successful with ML-DSA44")
}
