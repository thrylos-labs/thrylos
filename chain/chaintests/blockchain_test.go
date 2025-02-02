package chaintests

// import (
// 	"crypto"
// 	"io/ioutil"
// 	"log"
// 	"os"
// 	"testing"

// 	"github.com/cloudflare/circl/sign/mldsa/mldsa44"
// 	"github.com/joho/godotenv"
// 	"github.com/thrylos-labs/thrylos/core/chain"
// 	"github.com/thrylos-labs/thrylos/shared"
// )

// func loadEnvTest() {
// 	if err := godotenv.Load("../.env.dev"); err != nil {
// 		log.Fatalf("Error loading .env file: %v", err)
// 	}
// }

// func TestNewBlockchain(t *testing.T) {
// 	loadEnvTest() // Ensure environment variables are loaded before any Supabase operations

// 	// Use a valid tl1 prefix address for testing
// 	os.Setenv("GENESIS_ACCOUNT", "tl11test0genesis0account0value00000000000000")
// 	defer os.Unsetenv("GENESIS_ACCOUNT")

// 	tempDir, err := ioutil.TempDir("", "blockchain_test")
// 	if err != nil {
// 		t.Fatalf("Failed to create temporary directory: %v", err)
// 	}
// 	defer os.RemoveAll(tempDir)

// 	aesKey, err := shared.GenerateAESKey()
// 	if err != nil {
// 		t.Fatalf("Failed to generate AES key: %v", err)
// 	}

// 	genesisAccount := os.Getenv("GENESIS_ACCOUNT")

// 	// Correctly handle all three return values
// 	blockchain, db, err := chain.NewBlockchainWithConfig(&chain.BlockchainConfig{
// 		DataDir:           tempDir,
// 		AESKey:            aesKey,
// 		GenesisAccount:    genesisAccount,
// 		TestMode:          true,
// 		DisableBackground: true,
// 	})
// 	if err != nil {
// 		t.Fatalf("Failed to create blockchain: %v", err)
// 	}

// 	// Optionally, you can use `db` here if needed
// 	_ = db // Suppress "declared but not used" warning if you do not use `db`

// 	if blockchain.Genesis == nil {
// 		t.Errorf("Genesis block is nil")
// 	}
// }

// func TestMLDSA44Signature(t *testing.T) {
// 	// Generate a new key pair
// 	publicKey, privateKey, err := mldsa44.GenerateKey(nil)
// 	if err != nil {
// 		t.Fatalf("MLDSA44 key generation failed: %v", err)
// 	}

// 	// Create a mock transaction (simplified representation)
// 	tx := "mock transaction"
// 	txBytes := []byte(tx)

// 	// Sign the transaction
// 	// Note: MLDSA44 requires passing nil for the random source and crypto.Hash(0) for options
// 	signature, err := privateKey.Sign(nil, txBytes, crypto.Hash(0))
// 	if err != nil {
// 		t.Fatalf("MLDSA44 signing failed: %v", err)
// 	}

// 	// Verify the signature using the scheme's Verify function
// 	if !mldsa44.Verify(publicKey, txBytes, nil, signature) {
// 		t.Fatal("MLDSA44 signature verification failed")
// 	}

// 	t.Log("MLDSA44 signature verification succeeded")
// }
