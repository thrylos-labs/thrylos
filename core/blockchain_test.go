package core

import (
	"testing"

	_ "github.com/mattn/go-sqlite3" // SQLite driver
)

func TestNewBlockchain(t *testing.T) {
	bc, err := NewBlockchain()
	if err != nil {
		t.Fatalf("Failed to create blockchain: %v", err)
	}

	if bc.Genesis == nil {
		t.Errorf("Genesis block is nil")
	}
	// Further checks can include validating the initial state of the blockchain, such as the number of blocks, initial UTXOs, etc.
}
