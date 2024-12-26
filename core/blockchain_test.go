package core

import (
	"crypto/rand"
	"io/ioutil"
	"log"
	"os"
	"testing"

	"golang.org/x/crypto/ed25519"

	"github.com/joho/godotenv"
	"github.com/thrylos-labs/thrylos/shared"
)

func loadEnvTest() {
	if err := godotenv.Load("../.env.dev"); err != nil {
		log.Fatalf("Error loading .env file: %v", err)
	}
}

func TestNewBlockchain(t *testing.T) {
	loadEnvTest() // Ensure environment variables are loaded before any Supabase operations

	os.Setenv("GENESIS_ACCOUNT", "dummy_genesis_account_value") // Load this from .env for consistency
	defer os.Unsetenv("GENESIS_ACCOUNT")

	tempDir, err := ioutil.TempDir("", "blockchain_test")
	if err != nil {
		t.Fatalf("Failed to create temporary directory: %v", err)
	}
	defer os.RemoveAll(tempDir)

	aesKey, err := shared.GenerateAESKey()
	if err != nil {
		t.Fatalf("Failed to generate AES key: %v", err)
	}

	genesisAccount := os.Getenv("GENESIS_ACCOUNT")

	// Correctly handle all three return values
	blockchain, db, err := NewBlockchainWithConfig(&BlockchainConfig{
		DataDir:           tempDir,
		AESKey:            aesKey,
		GenesisAccount:    genesisAccount,
		TestMode:          true,
		DisableBackground: true,
	})
	if err != nil {
		t.Fatalf("Failed to create blockchain: %v", err)
	}

	// Optionally, you can use `db` here if needed
	_ = db // Suppress "declared but not used" warning if you do not use `db`

	if blockchain.Genesis == nil {
		t.Errorf("Genesis block is nil")
	}
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
