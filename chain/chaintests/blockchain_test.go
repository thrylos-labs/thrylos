package chaintests

import (
	"crypto"
	"io/ioutil"
	"log"
	"os"
	"testing"

	"github.com/cloudflare/circl/sign/mldsa/mldsa44"
	"github.com/joho/godotenv"
	"github.com/stretchr/testify/require"
	"github.com/thrylos-labs/thrylos/chain"
	encryption "github.com/thrylos-labs/thrylos/crypto/encrypt"
)

func TestNewBlockchain(t *testing.T) {
	// Try to load env but don't fail if it doesn't exist
	err := godotenv.Load(".env.dev")
	if err != nil {
		log.Printf("Note: .env.dev file not found, using default test values")
	}

	// Use a predefined valid Bech32 address for genesis
	genesisAddress := "tl11d26lhajjmg2xw95u66xathy7sge36t83zyfvwq"

	tempDir, err := ioutil.TempDir("", "blockchain_test")
	require.NoError(t, err, "Failed to create temporary directory")
	defer os.RemoveAll(tempDir)

	aesKey, err := encryption.GenerateAESKey()
	require.NoError(t, err, "Failed to generate AES key")

	blockchain, store, err := chain.NewBlockchainWithConfig(&chain.BlockchainConfig{
		DataDir:           tempDir,
		AESKey:            aesKey,
		GenesisAccount:    genesisAddress,
		TestMode:          true,
		DisableBackground: true,
	})
	require.NoError(t, err, "Failed to create blockchain")

	// Ensure cleanup
	if closer, ok := store.(interface{ Close() }); ok {
		defer closer.Close()
	}

	// Additional assertions
	require.NotNil(t, blockchain, "Blockchain should not be nil")
	require.NotNil(t, blockchain.Genesis, "Genesis block should not be nil")
	require.Equal(t, genesisAddress, blockchain.GenesisAccount, "Genesis account should match")
	// require.Greater(t, len(blockchain.ActiveValidators), 0, "Should have active validators")

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
