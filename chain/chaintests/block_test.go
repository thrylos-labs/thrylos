package chaintests

import (
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/thrylos-labs/thrylos/chain"
	"github.com/thrylos-labs/thrylos/crypto"
	"github.com/thrylos-labs/thrylos/crypto/encryption"
	"github.com/thrylos-labs/thrylos/crypto/hash"
)

func TestGenesisBlockCreation(t *testing.T) {
	// Set a properly formatted genesis account address
	genesisAccount := "tl1dummy_genesis_account_value" // Changed to start with tl1
	os.Setenv("GENESIS_ACCOUNT", genesisAccount)
	defer os.Unsetenv("GENESIS_ACCOUNT")

	// Create a temporary directory for blockchain data with a unique suffix
	tempDir, err := ioutil.TempDir("", fmt.Sprintf("blockchain_test_%d", time.Now().UnixNano()))
	if err != nil {
		t.Fatalf("Failed to create temporary directory: %v", err)
	}

	// Rest of cleanup function remains the same
	cleanup := func() {
		time.Sleep(100 * time.Millisecond)
		lockFile := filepath.Join(tempDir, "LOCK")
		if err := os.Remove(lockFile); err != nil && !os.IsNotExist(err) {
			t.Logf("Warning: Failed to remove lock file: %v", err)
		}
		manifestFiles, err := filepath.Glob(filepath.Join(tempDir, "MANIFEST*"))
		if err == nil {
			for _, f := range manifestFiles {
				if err := os.Remove(f); err != nil {
					t.Logf("Warning: Failed to remove manifest file %s: %v", f, err)
				}
			}
		}
		time.Sleep(100 * time.Millisecond)
		if err := os.RemoveAll(tempDir); err != nil {
			t.Logf("Warning: Failed to remove temp directory: %v", err)
		}
	}
	defer cleanup()

	// Generate a dummy AES key for testing
	aesKey, err := encryption.GenerateAESKey()
	if err != nil {
		t.Fatalf("Failed to generate AES key: %v", err)
	}

	genesisAccount = os.Getenv("GENESIS_ACCOUNT") //I assume the genesis account is the private key
	if genesisAccount == "" {
		t.Fatal("Genesis account is not set in environment variables. This should not happen.")
	}
	priv, err := crypto.NewPrivateKeyFromBytes([]byte(genesisAccount))
	if err != nil {
		t.Fatal("Error converting the genesis account into a private key.")
	}

	// Initialize the blockchain with the temporary directory
	blockchain, store, err := chain.NewBlockchainWithConfig(&chain.BlockchainConfig{
		DataDir:           tempDir,
		AESKey:            aesKey,
		GenesisAccount:    priv,
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
			time.Sleep(100 * time.Millisecond)
		}()
	}

	// Check if the first block is the genesis block
	if len(blockchain.Blocks) == 0 || blockchain.Blocks[0] != blockchain.Genesis {
		t.Errorf("Genesis block is not the first block in the blockchain")
	}
}

func TestBlockCreation(t *testing.T) {
	privateKey, err := crypto.NewPrivateKey()
	if err != nil {
		t.Fatalf("Failed to generate private key: %v", err)
	}
	//stakeAmount := amount.Amount(100)
	index := int64(1)
	prevHash := hash.NewHash([]byte("previous-hash"))
	pubKey := privateKey.PublicKey()
	//val := validator.NewValidator(privateKey, index, stakeAmount)
	//tx:= shared.NewTransaction()
	b, err := chain.NewBlock(index, prevHash, nil, pubKey)
	if err != nil {
		t.Logf("error creating a block: %v", err)
	}
	err = chain.Verify(b)
	if err != nil {
		t.Logf("error verifing the block... this should fail because the block has no transaction: %v", err)
	}
}
