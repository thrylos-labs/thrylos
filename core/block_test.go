/*

Passed unit test

estGenesisBlockCreation:
This test checks if the genesis block (the first block in the blockchain) is correctly created with an index of 0, no previous hash, and an empty Merkle root.
If your NewGenesisBlock function correctly sets up these properties, this test will pass.
TestNewBlockCreation:
This test verifies the creation of a new block using a mock transaction.
It checks whether NewBlock correctly creates a non-nil block with the given transactions, index, previous hash, and validator.
If the NewBlock function correctly initializes a new block with these parameters and the mock transactions are valid, this test will pass.
TestBlockSerializationDeserialization:
This test checks if a block can be serialized to a byte array and then deserialized back to a block object without losing any data (particularly the block hash).
If your block's Serialize and Deserialize methods work correctly, ensuring that the hash of the deserialized block matches the original, this test will pass.
TestComputeHash:
This test is designed to ensure that the ComputeHash function of a block correctly computes its hash.
If the hash calculation is correct and matches the hash stored in the block, this test will pass.
TestNewBlockWithTimestamp:
Similar to TestNewBlockCreation, this test checks the creation of a new block, but with a specified timestamp.
It ensures that NewBlockWithTimestamp successfully creates a block with the provided timestamp.
If the function correctly sets the timestamp and other properties of the block, and the block is not nil, the test will pass.

Validity: These tests ensure that the core functionalities of your blockchain related to block handling (creation, serialization, hashing) are working as expected.
Reliability: By passing these tests, you have a level of confidence that your blockchain's block management logic is reliable.
Regression Testing: In the future, if you make changes to the blockchain code, these tests will help ensure that the fundamental block functionalities still work as intended.
*/

package core

import (
	"Thrylos/shared"
	"crypto/rand"
	"crypto/rsa"
	"testing"
)

// Assuming we have a function to generate keys
func generateTestKeyPairsForBlock() (*rsa.PrivateKey, *rsa.PublicKey, error) {
	privKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, nil, err
	}
	return privKey, &privKey.PublicKey, nil
}

func CreateMockTransactionsForBlock() []shared.Transaction {
	privKey, _, _ := generateTestKeyPairs()

	// Create UTXO with valid data
	inputUTXO := shared.UTXO{
		ID:            "utxo1", // Ensure this ID matches an entry in availableUTXOs
		TransactionID: "tx0",
		Index:         0,
		OwnerAddress:  "Alice",
		Amount:        100,
	}

	outputUTXO := shared.UTXO{
		ID:            "utxo2",
		TransactionID: "tx1",
		Index:         0,
		OwnerAddress:  "Bob",
		Amount:        100,
	}

	tx, _ := shared.CreateAndSignTransaction("tx1", []shared.UTXO{inputUTXO}, []shared.UTXO{outputUTXO}, privKey)

	// Return a slice of transactions
	return []shared.Transaction{tx}
}

// TestGenesisBlockCreation tests the creation of the genesis block
func TestGenesisBlockCreation(t *testing.T) {
	genesisBlock := NewGenesisBlock()

	if genesisBlock.Index != 0 || genesisBlock.PrevHash != "" || len(genesisBlock.MerkleRoot) != 0 {
		t.Errorf("Genesis block properties are incorrect")
	}
}

// TestNewBlockCreation tests the creation of a new block
func TestNewBlockCreation(t *testing.T) {
	transactions := CreateMockTransactionsForBlock() // Use/Create this function
	if len(transactions) == 0 {
		t.Fatal("No transactions provided for block creation test")
	}

	genesisBlock := NewGenesisBlock()
	newBlock := NewBlock(1, transactions, genesisBlock.Hash, "Validator", genesisBlock.Timestamp)

	if newBlock == nil {
		t.Fatal("New block creation failed")
	}
}

// TestBlockSerializationDeserialization tests serialization and deserialization
func TestBlockSerializationDeserialization(t *testing.T) {
	block := NewGenesisBlock()
	serialized, err := block.Serialize()
	if err != nil {
		t.Fatal(err)
	}

	deserialized, err := Deserialize(serialized)
	if err != nil {
		t.Fatal(err)
	}

	if deserialized.Hash != block.Hash {
		t.Errorf("Deserialized block hash does not match original")
	}
}

// TestComputeHash tests the hash computation of a block
func TestComputeHash(t *testing.T) {
	block := NewGenesisBlock()
	computedHash := block.ComputeHash()

	if computedHash != block.Hash {
		t.Errorf("Computed hash does not match block's hash")
	}
}

// TestNewBlockWithTimestamp tests creating a new block with a specific timestamp
func TestNewBlockWithTimestamp(t *testing.T) {
	transactions := CreateMockTransactionsForBlock() // Use/Create this function
	if len(transactions) == 0 {
		t.Fatal("No transactions provided for block creation test")
	}

	genesisBlock := NewGenesisBlock()
	newBlock := NewBlockWithTimestamp(1, transactions, genesisBlock.Hash, "Validator", 1234567890)

	if newBlock == nil {
		t.Fatal("Failed to create new block with timestamp")
	}

}
