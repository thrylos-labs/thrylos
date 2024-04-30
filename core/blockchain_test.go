package core

import (
	"crypto/ed25519"
	"crypto/rand"
	"testing"

	"github.com/dgraph-io/badger"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/thrylos-labs/thrylos/database"
)

// MockBadgerDB extends the BadgerDB with mocking capabilities
type MockBadgerDB struct {
	mock.Mock
}

func (m *MockBadgerDB) Open(opts badger.Options) (*badger.DB, error) {
	args := m.Called(opts)
	return args.Get(0).(*badger.DB), args.Error(1)
}

// Setup the mock and its expectations for Open
func setupMockDB() *MockBadgerDB {
	mockDB := new(MockBadgerDB)
	mockDB.On("Open", mock.AnythingOfType("badger.Options")).Return(new(badger.DB), nil)
	return mockDB
}

func TestNewBlockchain(t *testing.T) {
	// Mock setup
	mockDB := setupMockDB()
	// badger.Open = mockDB.Open // Assuming you can override the Open function like this

	// Create a temporary directory for the database
	dataDir := t.TempDir()

	// Initialize the database
	db, err := database.InitializeDatabase(dataDir)
	assert.NoError(t, err, "Database should be initialized without error")
	assert.NotNil(t, db, "Database instance should not be nil")

	// Test creating a new blockchain
	aesKey := []byte("testkey123")
	blockchain, err := NewBlockchain(dataDir, aesKey)
	assert.NoError(t, err, "Blockchain should be created without error")
	assert.NotNil(t, blockchain, "Blockchain instance should not be nil")

	// Ensure all expectations are met
	mockDB.AssertExpectations(t)
}

// go test -v -timeout 30s -run ^TestNewBlockchain$ github.com/thrylos-labs/thrylos/core

// func TestNewBlockchain(t *testing.T) {
// 	// Create a temporary directory for the blockchain data
// 	tempDir, err := ioutil.TempDir("", "blockchain_test")
// 	if err != nil {
// 		t.Fatalf("Failed to create temporary directory: %v", err)
// 	}
// 	defer os.RemoveAll(tempDir) // Clean up after the test

// 	// Set the DATA_DIR to the temporary directory
// 	os.Setenv("DATA_DIR", tempDir)

// 	aesKey := []byte("0123456789abcdef0123456789abcdef")

// 	// Call NewBlockchain which is supposed to setup the blockchain with a genesis block
// 	bc, err := NewBlockchain(tempDir, aesKey)
// 	if err != nil {
// 		t.Fatalf("Failed to initialize blockchain: %v", err)
// 	}
// 	assert.NotNil(t, bc, "Blockchain instance should not be nil")
// 	assert.NotNil(t, bc.Genesis, "Genesis block should not be nil")
// 	assert.Len(t, bc.Blocks, 1, "Blockchain should have exactly one block after initialization - the genesis block")
// 	assert.Equal(t, bc.Blocks[0], bc.Genesis, "The first block should be the genesis block")

// 	// Verify the setup of transactions in the genesis block
// 	assert.NotEmpty(t, bc.Genesis.Transactions, "Genesis block should contain transactions")
// 	for _, tx := range bc.Genesis.Transactions {
// 		numOutputs := tx.OutputsLength() // Assuming OutputsLength() exists to provide the number of outputs
// 		assert.True(t, numOutputs > 0, "Genesis transactions should have outputs")
// 		var utxo thrylos.UTXO
// 		for j := 0; j < numOutputs; j++ {
// 			ok := tx.Outputs(&utxo, j)
// 			assert.True(t, ok, "Should successfully retrieve UTXO")
// 			assert.NotEmpty(t, utxo.OwnerAddress(), "UTXO should have an owner address")
// 			assert.True(t, utxo.Amount() > 0, "UTXO should have a positive amount")
// 		}
// 	}
// }

// func TestNewBlockchain(t *testing.T) {
// 	// Create a temporary directory for blockchain data
// 	tempDir, err := ioutil.TempDir("", "blockchain_test")
// 	if err != nil {
// 		t.Fatalf("Failed to create temporary directory: %v", err)
// 	}
// 	// Clean up the temporary directory after the test
// 	defer os.RemoveAll(tempDir)

// 	// Generate a dummy AES key for testing
// 	aesKey, err := shared.GenerateAESKey() // Adjust the function call according to your package and method
// 	if err != nil {
// 		t.Fatalf("Failed to generate AES key: %v", err)
// 	}

// 	// Create a new blockchain using the temporary directory and generated AES key
// 	bc, err := NewBlockchain(tempDir, aesKey)
// 	if err != nil {
// 		t.Fatalf("Failed to create blockchain: %v", err)
// 	}

// 	if bc.Genesis == nil {
// 		t.Errorf("Genesis block is nil")
// 	}
// 	// Further checks can include validating the initial state of the blockchain, such as the number of blocks, initial UTXOs, etc.
// }

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
