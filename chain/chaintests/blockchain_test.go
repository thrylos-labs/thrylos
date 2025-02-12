package chaintests

import (
	"io/ioutil"
	"log"
	"os"
	"testing"

	"github.com/joho/godotenv"
	"github.com/stretchr/testify/require"
	"github.com/thrylos-labs/thrylos/chain"
	"github.com/thrylos-labs/thrylos/crypto"
	"github.com/thrylos-labs/thrylos/crypto/encryption"
)

func TestNewBlockchain(t *testing.T) {
	// Try to load env but don't fail if it doesn't exist
	err := godotenv.Load(".env.dev")
	if err != nil {
		log.Printf("Note: .env.dev file not found, using default test values")
	}

	// Use a predefined valid Bech32 address for genesis
	//genesisAddress := "tl11d26lhajjmg2xw95u66xathy7sge36t83zyfvwq"
	priv, err := crypto.NewPrivateKey()
	if err != nil {
		t.Log("Error generating the private key for the genesis account")
	}
	tempDir, err := ioutil.TempDir("", "blockchain_test")
	require.NoError(t, err, "Failed to create temporary directory")
	defer os.RemoveAll(tempDir)

	aesKey, err := encryption.GenerateAESKey()
	require.NoError(t, err, "Failed to generate AES key")

	blockchain, store, err := chain.NewBlockchainWithConfig(&chain.BlockchainConfig{
		DataDir:           tempDir,
		AESKey:            aesKey,
		GenesisAccount:    priv,
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
	// require.Greater(t, len(blockchain.ActiveValidators), 0, "Should have active validators")

}

func TestSignature(t *testing.T) {
	// Generate a new key pair
	privateKey, err := crypto.NewPrivateKey()
	if err != nil {
		t.Fatalf(" key generation failed: %v", err)
	}

	// Create a mock transaction (simplified representation)
	tx := "mock transaction"
	txBytes := []byte(tx)

	// Sign the transaction
	signature := privateKey.Sign(txBytes)
	if err != nil {
		t.Fatalf(" signing failed: %v", err)
	}

	// Verify the signature using the scheme's Verify function
	pubKey := privateKey.PublicKey()
	err = signature.Verify(&pubKey, txBytes)
	if err != nil {
		t.Fatal(" signature verification failed")
	}

	t.Log("MLDSA44 signature verification succeeded")
}
