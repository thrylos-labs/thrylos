package store

import (
	"fmt"
	"log"
	"os"
	"path/filepath"
	"sync"
	"time"

	badger "github.com/dgraph-io/badger/v3"
	"github.com/thrylos-labs/thrylos/types"
)

// BadgerDB wraps the Badger database
type Database struct {
	db            *badger.DB
	utxos         map[string]types.UTXO
	once          sync.Once
	dataDir       string
	Blockchain    types.Store // Use the interface here
	encryptionKey []byte      // The AES-256 key used for encryption and decryption
}

// NewDatabase initializes and returns a new instance of BadgerDB
func NewDatabase(path string) (*Database, error) {
	// Add a small delay to ensure proper cleanup
	time.Sleep(100 * time.Millisecond)

	// Remove any existing lock file before opening
	lockFile := filepath.Join(path, "LOCK")
	log.Printf("Attempting to remove lock file: %s", lockFile)
	if err := os.Remove(lockFile); err != nil && !os.IsNotExist(err) {
		return nil, fmt.Errorf("failed to remove existing lock file: %v", err)
	}

	d := &Database{
		dataDir: path,
	}
	var err error
	d.once.Do(func() {
		opts := badger.DefaultOptions(path).
			WithLogger(nil).
			WithSyncWrites(false).     // Disable sync for testing
			WithDetectConflicts(false) // Disable conflict detection for testing

		// Remove the WithInMemory option and ensure the directory exists
		if err := os.MkdirAll(path, 0755); err != nil {
			err = fmt.Errorf("failed to create database directory: %v", err)
			return
		}

		// Try to open the database
		d.db, err = badger.Open(opts)
		if err != nil {
			err = fmt.Errorf("failed to open Badger database: %v", err)
			return
		}
	})

	if err != nil {
		return nil, err
	}

	return d, nil
}

func (d *Database) GetDataDir() string {
	return d.dataDir
}

func (d *Database) GetLockFilePath() string {
	return filepath.Join(d.dataDir, "LOCK")
}

// GetDB returns the underlying BadgerDB instance
func (d *Database) GetDB() *badger.DB {
	return d.db
}

// Set sets a key-value pair in the Badger database
func (d *Database) Set(key, value []byte) error {
	return d.db.Update(func(txn *badger.Txn) error {
		return txn.Set(key, value)
	})
}

// Get retrieves a value for a given key from the Badger database
func (d *Database) Get(key []byte) ([]byte, error) {
	var valCopy []byte
	err := d.db.View(func(txn *badger.Txn) error {
		item, err := txn.Get(key)
		if err != nil {
			return err
		}
		valCopy, err = item.ValueCopy(nil)
		return err
	})
	return valCopy, err
}

// Update updates a key-value pair in the Badger database
func (d *Database) Update(key, value []byte) error {
	return d.db.Update(func(txn *badger.Txn) error {
		_, err := txn.Get(key)
		if err != nil {
			return err
		}
		return txn.Set(key, value)
	})
}

// Delete deletes a key-value pair from the Badger database
func (d *Database) Delete(key []byte) error {
	return d.db.Update(func(txn *badger.Txn) error {
		return txn.Delete(key)
	})
}

// Close closes the Badger database
func (d *Database) Close() error {
	if d.db != nil {
		err := d.db.Close()
		if err != nil {
			return fmt.Errorf("failed to close Badger database: %v", err)
		}
	}
	return nil
}
