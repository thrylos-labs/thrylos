package database

import (
	"encoding/json"
	"fmt"
	"log"
	"testing"

	"github.com/dgraph-io/badger"
	"github.com/thrylos-labs/thrylos/shared"
)

// inserting and retrieving UTXOs in your database setup is working as expected

func TestUTXOInsertionAndRetrieval(t *testing.T) {
	// Setup database
	db, err := InitializeDatabase("./testdata") // Use a temporary directory or test-specific directory
	if err != nil {
		t.Fatalf("Failed to initialize database: %v", err)
	}
	defer db.Close() // Ensure the database is closed after the test runs

	bdb := &BlockchainDB{DB: db} // Wrap the *badger.DB

	// Test data
	address := "tl11rn2agc9tqwg6eemqefj5uvtns2glepu2uaztj0v8pz3d4zg87k8szawc22"
	utxo := shared.UTXO{OwnerAddress: address, Amount: 1000}

	// Insert UTXO
	if err := testInsertUTXO(bdb, address, utxo); err != nil {
		t.Errorf("Failed to insert test UTXO: %v", err)
	}

	// Fetch to verify
	retrievedUTXOs, err := bdb.GetUTXOsForAddress(address)
	if err != nil {
		t.Errorf("Failed to fetch UTXOs: %v", err)
	}

	if len(retrievedUTXOs) == 0 {
		t.Error("No UTXOs found after insertion")
	} else {
		t.Logf("Retrieved UTXOs: %v", retrievedUTXOs)
	}
}

func testInsertUTXO(bdb *BlockchainDB, address string, utxo shared.UTXO) error {
	key := fmt.Sprintf("utxo-%s-%s", address, "unique_identifier")
	log.Printf("Inserting UTXO with key: %s", key)
	val, err := json.Marshal(utxo)
	if err != nil {
		return err
	}
	return bdb.DB.Update(func(txn *badger.Txn) error {
		return txn.Set([]byte(key), val)
	})
}

// testInsertUTXO function as before...
