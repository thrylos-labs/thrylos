package chaintests

import (
	"bytes"
	"testing"

	"github.com/thrylos-labs/thrylos/core/chain"
)

// TestNewVerkleTree tests the NewVerkleTree function to ensure it creates a tree correctly with valid data.

func TestNewVerkleTree(t *testing.T) {
	// Example keys and values for testing
	key1 := bytes.Repeat([]byte{1}, chain.KeySize)
	value1 := bytes.Repeat([]byte{2}, chain.LeafValueSize)
	key2 := bytes.Repeat([]byte{3}, chain.KeySize)
	value2 := bytes.Repeat([]byte{4}, chain.LeafValueSize)

	// Ensure test data items are at least KeySize + LeafValueSize in length
	testData := [][]byte{
		append(key1, value1...),
		append(key2, value2...),
	}

	tree, err := chain.NewVerkleTree(testData)
	if err != nil {
		t.Fatalf("Failed to create Verkle tree: %v", err)
	}

	if tree == nil {
		t.Fatalf("Expected non-nil Verkle tree, got nil")
	}

	// Create a dummy resolver function or use an appropriate one for your context
	// If your tree logic requires actual node resolution, provide the necessary logic here
	dummyResolver := func(key []byte) ([]byte, error) {
		return nil, nil // Placeholder implementation
	}

	// Attempt to retrieve the values for each key inserted into the tree
	retrievedValue1, err := tree.Get(key1, dummyResolver)
	if err != nil {
		t.Fatalf("Failed to retrieve value for key1: %v", err)
	}
	if !bytes.Equal(retrievedValue1, value1) {
		t.Errorf("Retrieved value for key1 does not match expected value. Got: %v, want: %v", retrievedValue1, value1)
	}

	retrievedValue2, err := tree.Get(key2, dummyResolver)
	if err != nil {
		t.Fatalf("Failed to retrieve value for key2: %v", err)
	}
	if !bytes.Equal(retrievedValue2, value2) {
		t.Errorf("Retrieved value for key2 does not match expected value. Got: %v, want: %v", retrievedValue2, value2)
	}
}
