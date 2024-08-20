package core

import (
	"crypto/rand"
	"encoding/json"
	"io/ioutil"
	"os"
	"testing"

	"golang.org/x/crypto/ed25519"

	"github.com/supabase-community/supabase-go"
	"github.com/thrylos-labs/thrylos/shared"
)

func TestGenesisBlockCreation(t *testing.T) {
	// Set the environment variable needed for the test
	os.Setenv("GENESIS_ACCOUNT", "dummy_genesis_account_value")
	defer os.Unsetenv("GENESIS_ACCOUNT") // Ensure clean-up after the test

	// Create a temporary directory for blockchain data
	tempDir, err := ioutil.TempDir("", "blockchain_test")
	if err != nil {
		t.Fatalf("Failed to create temporary directory: %v", err)
	}
	defer os.RemoveAll(tempDir) // Clean up the temporary directory after the test

	// Generate a dummy AES key for testing
	aesKey, err := shared.GenerateAESKey() // Adjust the function call according to your package and method
	if err != nil {
		t.Fatalf("Failed to generate AES key: %v", err)
	}

	genesisAccount := os.Getenv("GENESIS_ACCOUNT") // Now this should always be set
	if genesisAccount == "" {
		t.Fatal("Genesis account is not set in environment variables. This should not happen.")
	}

	// Initialize Supabase app
	supabaseURL := os.Getenv("SUPABASE_URL")
	supabasePublicKey := os.Getenv("SUPABASE_PUBLIC_KEY")
	supabaseClient, err := supabase.NewClient(supabaseURL, supabasePublicKey, nil)
	if err != nil {
		t.Fatalf("error initializing app: %v\n", err)
	}

	// Initialize the blockchain with the temporary directory
	blockchain, _, err := NewBlockchain(tempDir, aesKey, genesisAccount, true, supabaseClient)
	if err != nil {
		t.Fatalf("Failed to initialize blockchain: %v", err)
	}

	// Check if the first block is the genesis block
	if len(blockchain.Blocks) == 0 || blockchain.Blocks[0] != blockchain.Genesis {
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
