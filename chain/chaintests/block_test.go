package chaintests

import (
	"crypto"
	"crypto/rand"
	"encoding/json"
	"testing"

	"github.com/cloudflare/circl/sign/mldsa/mldsa44"
	"github.com/thrylos-labs/thrylos/chain"
)

// func TestGenesisBlockCreation(t *testing.T) {
// 	// Set the environment variable needed for the test
// 	os.Setenv("GENESIS_ACCOUNT", "dummy_genesis_account_value")
// 	defer os.Unsetenv("GENESIS_ACCOUNT") // Ensure clean-up after the test

// 	// Create a temporary directory for blockchain data
// 	tempDir, err := ioutil.TempDir("", "blockchain_test")
// 	if err != nil {
// 		t.Fatalf("Failed to create temporary directory: %v", err)
// 	}
// 	defer os.RemoveAll(tempDir) // Clean up the temporary directory after the test

// 	// Generate a dummy AES key for testing
// 	aesKey, err := shared.GenerateAESKey() // Adjust the function call according to your package and method
// 	if err != nil {
// 		t.Fatalf("Failed to generate AES key: %v", err)
// 	}

// 	genesisAccount := os.Getenv("GENESIS_ACCOUNT")
// 	if genesisAccount == "" {
// 		t.Fatal("Genesis account is not set in environment variables. This should not happen.")
// 	}

// 	// Initialize the blockchain with the temporary directory
// 	blockchain, _, err := chain.NewBlockchainWithConfig(&chain.BlockchainConfig{
// 		DataDir:           tempDir,
// 		AESKey:            aesKey,
// 		GenesisAccount:    genesisAccount,
// 		TestMode:          true,
// 		DisableBackground: true,
// 	})
// 	if err != nil {
// 		t.Fatalf("Failed to initialize blockchain: %v", err)
// 	}

// 	// Check if the first block is the genesis block
// 	if len(blockchain.Blocks) == 0 || blockchain.Blocks[0] != blockchain.Genesis {
// 		t.Errorf("Genesis block is not the first block in the blockchain")
// 	}
// }

func TestTransactionSigningAndVerification(t *testing.T) {
	// Step 1: Generate ML-DSA-44 keys
	seed := new([mldsa44.SeedSize]byte)
	_, err := rand.Read(seed[:])
	if err != nil {
		t.Fatalf("Failed to generate seed: %v", err)
	}

	publicKey, privateKey := mldsa44.NewKeyFromSeed(seed)

	// Step 2: Create a new transaction
	tx := chain.Transaction{
		ID:        "txTest123",
		Timestamp: 1630000000,
		Inputs:    []chain.UTXO{{TransactionID: "tx0", Index: 0, OwnerAddress: "Alice", Amount: 100}},
		Outputs:   []chain.UTXO{{TransactionID: "txTest123", Index: 0, OwnerAddress: "Bob", Amount: 100}},
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
