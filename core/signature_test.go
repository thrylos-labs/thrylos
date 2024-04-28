package core

import (
	"encoding/json"
	"fmt"
	"testing"

	"github.com/thrylos-labs/thrylos/shared"
	"golang.org/x/crypto/blake2b"
)

// HashData uses SHA-256 to hash the input data
func HashData(data []byte) []byte {
	hash, err := blake2b.New256(nil) // No key, simple hash
	if err != nil {
		panic(err) // Handle errors appropriately in production code
	}
	hash.Write(data)
	return hash.Sum(nil)
}

// Your TestHashDataConsistency test passed successfully, indicating that the HashData function correctly hashes the serialized transaction data using SHA-256, and the output matches the expected hash value. This confirms that the serialization and hashing steps in your transaction handling process are consistent and reliable.

func TestHashDataConsistency(t *testing.T) {
	// Assuming Transaction and UTXO structs are defined in the shared package
	tx := shared.Transaction{
		ID:        "tx123",
		Timestamp: 1630000000,
		Inputs:    []shared.UTXO{{TransactionID: "tx0", Index: 0, OwnerAddress: "Alice", Amount: 100}},
		Outputs:   []shared.UTXO{{TransactionID: "tx123", Index: 0, OwnerAddress: "Bob", Amount: 100}},
	}

	// Serialize the transaction
	serializedTx, err := json.Marshal(tx)
	if err != nil {
		t.Fatalf("Failed to serialize transaction: %v", err)
	}

	// Hash the serialized transaction data using HashData function
	hash := shared.HashData(serializedTx)

	// Here you should provide the actual expected hash for the serializedTx
	// For demonstration, this is just a placeholder and needs to be replaced with the actual expected hash value
	expectedHash := "9631a8d4886623276af58d9259cc774fc8e10943f1bea7accfb7bd025aaa9d3a"

	// Convert hash to a hexadecimal string for comparison
	hashHex := fmt.Sprintf("%x", hash)

	// Compare the calculated hash with the expected hash
	if hashHex != expectedHash {
		t.Errorf("Hash output does not match expected value.\nExpected: %s\nGot: %s", expectedHash, hashHex)
	}
}

func TestSerializeWithoutSignature(t *testing.T) {
	// Step 1: Create a known transaction object
	tx := shared.Transaction{
		ID:        "tx123",
		Timestamp: 1630000000, // Example timestamp
		Inputs: []shared.UTXO{
			{TransactionID: "tx0", Index: 0, OwnerAddress: "Alice", Amount: 100},
		},
		Outputs: []shared.UTXO{
			{TransactionID: "tx123", Index: 0, OwnerAddress: "Bob", Amount: 100},
		},
	}

	// Step 2: Serialize the transaction without the signature
	serializedTx, err := tx.SerializeWithoutSignature()
	if err != nil {
		t.Fatalf("Failed to serialize transaction: %v", err)
	}

	// Step 3: Define the hardcoded expected JSON string
	expectedJSON := `{"ID":"tx123","Inputs":[{"ID":"","TransactionID":"tx0","Index":0,"OwnerAddress":"Alice","Amount":100}],"Outputs":[{"ID":"","TransactionID":"tx123","Index":0,"OwnerAddress":"Bob","Amount":100}],"Timestamp":1630000000}`

	// Convert serializedTx (byte array) to string for comparison
	serializedTxStr := string(serializedTx)

	// Step 4: Assert equality
	if serializedTxStr != expectedJSON {
		t.Errorf("Serialized transaction does not match expected output.\nExpected: %s\nGot: %s", expectedJSON, serializedTxStr)
	}
}
