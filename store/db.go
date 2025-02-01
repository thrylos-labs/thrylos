package store

import (
	"log"
	"sync"

	"github.com/dgraph-io/badger/v3"
)

// BadgerDB wraps the Badger database
type BadgerDB struct {
	db   *badger.DB
	once sync.Once
}

// NewBadgerDB initializes and returns a new instance of BadgerDB
func NewBadgerDB(path string) *BadgerDB {
	b := &BadgerDB{}
	b.once.Do(func() {
		opts := badger.DefaultOptions(path).WithLogger(nil)
		var err error
		b.db, err = badger.Open(opts)
		if err != nil {
			log.Fatalf("Failed to open Badger database: %v", err)
		}
	})
	return b
}

// Close closes the Badger database
func (b *BadgerDB) Close() {
	if b.db != nil {
		err := b.db.Close()
		if err != nil {
			log.Fatalf("Failed to close Badger database: %v", err)
		}
	}
}

// Set sets a key-value pair in the Badger database
func (b *BadgerDB) Set(key, value []byte) error {
	return b.db.Update(func(txn *badger.Txn) error {
		return txn.Set(key, value)
	})
}

// Get retrieves a value for a given key from the Badger database
func (b *BadgerDB) Get(key []byte) ([]byte, error) {
	var valCopy []byte
	err := b.db.View(func(txn *badger.Txn) error {
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
func (b *BadgerDB) Update(key, value []byte) error {
	return b.db.Update(func(txn *badger.Txn) error {
		_, err := txn.Get(key)
		if err != nil {
			return err
		}
		return txn.Set(key, value)
	})
}

// Delete deletes a key-value pair from the Badger database
func (b *BadgerDB) Delete(key []byte) error {
	return b.db.Update(func(txn *badger.Txn) error {
		return txn.Delete(key)
	})
}
