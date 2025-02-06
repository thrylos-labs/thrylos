package chaintests

import (
	"crypto"
	"io/ioutil"
	"log"
	"os"
	"testing"

	"github.com/cloudflare/circl/sign/mldsa/mldsa44"
	"github.com/joho/godotenv"
	"github.com/thrylos-labs/thrylos/chain"
	encryption "github.com/thrylos-labs/thrylos/crypto/encrypt"
)

func TestNewBlockchain(t *testing.T) {
	// Try to load env but don't fail if it doesn't exist
	err := godotenv.Load(".env.dev")
	if err != nil {
		log.Printf("Note: .env.dev file not found, using default test values")
	}

	// Use a valid tl1 prefix address for testing
	os.Setenv("GENESIS_ACCOUNT", "tl11test0genesis0account0value00000000000000")
	defer os.Unsetenv("GENESIS_ACCOUNT")

	tempDir, err := ioutil.TempDir("", "blockchain_test")
	if err != nil {
		t.Fatalf("Failed to create temporary directory: %v", err)
	}
	defer os.RemoveAll(tempDir)

	aesKey, err := encryption.GenerateAESKey()
	if err != nil {
		t.Fatalf("Failed to generate AES key: %v", err)
	}

	genesisAccount := os.Getenv("GENESIS_ACCOUNT")

	// Correctly handle all three return values
	blockchain, store, err := chain.NewBlockchainWithConfig(&chain.BlockchainConfig{
		DataDir:           tempDir,
		AESKey:            aesKey,
		GenesisAccount:    genesisAccount,
		TestMode:          true,
		DisableBackground: true,
	})
	if err != nil {
		t.Fatalf("Failed to create blockchain: %v", err)
	}

	// Ensure cleanup
	if closer, ok := store.(interface{ Close() }); ok {
		defer closer.Close()
	}

	if blockchain.Genesis == nil {
		t.Errorf("Genesis block is nil")
	}
}

func TestMLDSA44Signature(t *testing.T) {
	// Generate a new key pair
	publicKey, privateKey, err := mldsa44.GenerateKey(nil)
	if err != nil {
		t.Fatalf("MLDSA44 key generation failed: %v", err)
	}

	// Create a mock transaction (simplified representation)
	tx := "mock transaction"
	txBytes := []byte(tx)

	// Sign the transaction
	// Note: MLDSA44 requires passing nil for the random source and crypto.Hash(0) for options
	signature, err := privateKey.Sign(nil, txBytes, crypto.Hash(0))
	if err != nil {
		t.Fatalf("MLDSA44 signing failed: %v", err)
	}

	// Verify the signature using the scheme's Verify function
	if !mldsa44.Verify(publicKey, txBytes, nil, signature) {
		t.Fatal("MLDSA44 signature verification failed")
	}

	t.Log("MLDSA44 signature verification succeeded")
}
