package store

import (
	"encoding/json"
	"fmt"
	"log"
	"strconv"
	"strings"
	"sync"

	"github.com/dgraph-io/badger/v3"
	"github.com/fxamacker/cbor/v2"
	"github.com/thrylos-labs/thrylos"
	"github.com/thrylos-labs/thrylos/consensus/validator"
	"github.com/thrylos-labs/thrylos/crypto"
	"github.com/thrylos-labs/thrylos/crypto/address"
	"github.com/thrylos-labs/thrylos/shared"
)

var (
	db   *badger.DB
	once sync.Once
)

type store struct {
	db            *Database
	cache         *UTXOCache
	encryptionKey []byte // The AES-256 key used for encryption and decryption
}

// NewStore creates a new store instance with the provided BadgerDB instance and encryption key.
func NewStore(dbPath string, encryptionKey []byte) (shared.Store, error) { // Changed return type to include error
	db, err := NewDatabase(dbPath)
	if err != nil {
		return nil, fmt.Errorf("failed to open BadgerDB: %v", err) // Return error instead of fatal
	}

	c, err := NewUTXOCache(1024, 10000, 0.01)
	if err != nil {
		return nil, fmt.Errorf("failed to create UTXO cache: %v", err) // Return error instead of fatal
	}

	s := &store{
		db:            db,
		cache:         c,
		encryptionKey: encryptionKey,
	}

	// Verify interface implementation at compile time
	var _ shared.Store = (*store)(nil)

	return s, nil
}

func (s *store) GetUTXO(addr address.Address) ([]*shared.UTXO, error) {
	userUTXOs := []*shared.UTXO{}
	db := s.db.GetDB()
	err := db.View(func(txn *badger.Txn) error {
		it := txn.NewIterator(badger.DefaultIteratorOptions)
		defer it.Close()

		prefix := []byte(UTXOPrefix + addr.String() + "-") //FIXME: this key is not how we store UTXOs in the database. We need to fix this.
		for it.Seek(prefix); it.ValidForPrefix(prefix); it.Next() {
			item := it.Item()
			err := item.Value(func(val []byte) error {
				var utxo shared.UTXO
				if err := cbor.Unmarshal(val, &utxo); err != nil {
					return err
				}
				if !utxo.IsSpent {
					userUTXOs = append(userUTXOs, &utxo)
				}
				return nil
			})
			if err != nil {
				return err
			}
		}
		return nil
	})
	return userUTXOs, err
}

func (s *store) GetTransaction(id string) (*shared.Transaction, error) {
	var tx shared.Transaction
	key := []byte(TransactionPrefix + id)
	data, err := s.db.Get(key)
	if err != nil {
		log.Printf("Failed to retrieve transaction: %v", err)
		return nil, fmt.Errorf("error retrieving transaction: %v", err)
	}
	err = tx.Unmarshal(data)
	if err != nil {
		log.Printf("Failed to unmarshal transaction: %v", err)
		return nil, err
	}
	return &tx, nil
}

func (s *store) GetLastBlock() (*shared.Block, error) {
	var blockData []byte
	var lastIndex int = -1
	db := s.db.GetDB()
	err := db.View(func(txn *badger.Txn) error {
		opts := badger.DefaultIteratorOptions
		opts.Reverse = true
		it := txn.NewIterator(opts)
		defer it.Close()

		for it.Rewind(); it.Valid(); it.Next() {
			item := it.Item()
			key := item.Key()
			if strings.HasPrefix(string(key), BlockPrefix) {
				blockNumberStr := strings.TrimPrefix(string(key), BlockPrefix)
				var parseErr error
				lastIndex, parseErr = strconv.Atoi(blockNumberStr)
				if parseErr != nil {
					log.Printf("Failed to parse block number: %v", parseErr)
					return fmt.Errorf("error parsing block number: %v", parseErr)
				}
				blockData, parseErr = item.ValueCopy(nil)
				if parseErr != nil {
					log.Printf("Failed to retrieve block data: %v", parseErr)
					return fmt.Errorf("error retrieving block data: %v", parseErr)
				}
				return nil
			}
		}
		return fmt.Errorf("no blocks found in the database")
	})

	if err != nil {
		log.Printf("Failed to retrieve last block: %v", err)
		return nil, err
	}

	if lastIndex == -1 {
		log.Printf("No blocks found in the database")
		return nil, fmt.Errorf("no blocks found in the database")
	}

	var b shared.Block
	err = b.Unmarshal(blockData)
	if err != nil {
		log.Printf("Failed to unmarshal block: %v", err)
		return nil, fmt.Errorf("error unmarshaling block: %v", err)
	}

	return &b, nil
}

func (s *store) GetLastBlockNumber() (int, error) {
	var lastIndex int = -1 // Default to -1 to indicate no blocks if none found
	db := s.db.GetDB()
	err := db.View(func(txn *badger.Txn) error {
		opts := badger.DefaultIteratorOptions
		opts.Reverse = true // Iterate in reverse order to get the latest block first
		it := txn.NewIterator(opts)
		defer it.Close()

		if it.Rewind(); it.Valid() {
			item := it.Item()
			key := item.Key()
			if strings.HasPrefix(string(key), BlockPrefix) {
				blockNumberStr := strings.TrimPrefix(string(key), BlockPrefix)
				var parseErr error
				lastIndex, parseErr = strconv.Atoi(blockNumberStr)
				if parseErr != nil {
					log.Printf("Error parsing block number from key %s: %v", key, parseErr)
					return parseErr
				}
				return nil // Stop after the first (latest) block
			}
		}
		return fmt.Errorf("no blocks found in the database")
	})

	if err != nil {
		log.Printf("Failed to retrieve the last block index: %v", err)
		return -1, err // Return -1 when no block is found
	}

	return lastIndex, nil

}

func (s *store) GetBlock(blockNumber uint32) (*shared.Block, error) {
	key := fmt.Sprintf("%s%d", BlockPrefix, blockNumber)
	log.Printf("Retrieving block %d from the database", blockNumber)
	var blockData []byte

	blockData, err := s.db.Get([]byte(key))
	if err != nil {
		log.Printf("Failed to retrieve block %d: %v", blockNumber, err)
		return nil, fmt.Errorf("failed to retrieve block data: %v", err)
	}
	log.Printf("Block %d retrieved successfully", blockNumber)

	var block shared.Block
	err = block.Unmarshal(blockData)
	if err != nil {
		log.Printf("Failed to unmarshal block %d: %v", blockNumber, err)
		return nil, fmt.Errorf("failed to unmarshal block data: %v", err)
	}
	return &block, nil
}

func (s *store) GetPublicKey(addr address.Address) (crypto.PublicKey, error) {
	key := []byte(PublicKeyPrefix + addr.String())
	data, err := s.db.Get(key)
	if err != nil {
		log.Printf("Failed to retrieve public key: %v", err)
		return nil, fmt.Errorf("error retrieving public key: %v", err)
	}
	var pub crypto.PublicKey
	err = pub.Unmarshal(data)
	if err != nil {
		log.Printf("Failed to unmarshal public key: %v", err)
		return nil, fmt.Errorf("error unmarshaling public key: %v", err)
	}
	return pub, nil
}

func (s *store) GetValidator(addr address.Address) (*validator.Validator, error) {
	key := []byte(ValidatorPrefix + addr.String())
	data, err := s.db.Get(key)
	if err != nil {
		log.Printf("Failed to retrieve validator: %v", err)
		return nil, fmt.Errorf("error retrieving validator: %v", err)
	}
	var vl validator.Validator
	err = vl.Unmarshal(data)
	if err != nil {
		log.Printf("Failed to unmarshal validator: %v", err)
		return nil, fmt.Errorf("error unmarshaling validator: %v", err)
	}
	return &vl, nil
}

func (s *store) UpdateUTXO(utxo *shared.UTXO) error {
	// Implement the logic to update a UTXO in the database and in the cache
	return nil
}

// SaveTransaction stores a transaction in the BadgerDB without processing utxos
func (s *store) SaveTransaction(tx *shared.Transaction) error {
	db := s.db.GetDB()
	txn := db.NewTransaction(true)
	defer txn.Discard()

	txData, err := tx.Marshal()
	if err != nil {
		log.Printf("Failed to marshal transaction: %v", err)
		return fmt.Errorf("error marshaling transaction: %v", err)
	}

	key := []byte(TransactionPrefix + tx.ID)
	if err := txn.Set(key, txData); err != nil {
		return fmt.Errorf("error storing transaction in BadgerDB: %v", err)
	}

	if err := txn.Commit(); err != nil {
		return fmt.Errorf("transaction commit failed: %v", err)
	}
	return nil
}

// ProcessTransaction processes a transaction by updating the UTXOs in the database and caching the UTXOs
func (s *store) ProcessTransaction(tx *shared.Transaction) error {
	db := s.db.GetDB()
	return db.Update(func(txn *badger.Txn) error {
		if err := s.updateUTXOsInTxn(txn, tx.Inputs, tx.Outputs); err != nil {
			return err
		}
		if err := s.addTransactionInTxn(txn, tx); err != nil {
			return err
		}
		return nil
	})
}

func (s *store) addTransactionInTxn(txn *badger.Txn, tx *shared.Transaction) error {
	key := []byte(TransactionPrefix + tx.ID)
	value, err := cbor.Marshal(tx)
	if err != nil {
		log.Fatalf("Failed to marshal transaction: %v", err)
		return err
	}
	return txn.Set(key, value)
}

func (s *store) updateUTXOsInTxn(txn *badger.Txn, inputs []shared.UTXO, outputs []shared.UTXO) error {
	for _, input := range inputs {
		key := []byte(fmt.Sprintf("%s%s-%d", UTXOPrefix, input.TransactionID, input.Index))
		input.IsSpent = true
		utxoData, err := cbor.Marshal(input)
		if err != nil {
			log.Fatalf("Failed to marshal UTXO: %v", err)
			return err
		}
		if err := txn.Set(key, utxoData); err != nil {
			log.Fatalf("Failed to set UTXO: %v", err)
			return err
		}
		s.cache.Remove(fmt.Sprintf("%s%s-%d", utxoData, input.TransactionID, input.Index))
	}

	for _, output := range outputs {
		key := []byte(fmt.Sprintf("%s%s-%d", UTXOPrefix, output.TransactionID, output.Index))
		utxoData, err := cbor.Marshal(output)
		if err != nil {
			log.Fatalf("Failed to marshal UTXO: %v", err)
			return err
		}
		if err := txn.Set(key, utxoData); err != nil {
			log.Fatalf("Failed to set UTXO: %v", err)
			return err
		}
		s.cache.Add(fmt.Sprintf("%s%s-%d", UTXOPrefix, output.TransactionID, output.Index), &output)
	}

	return nil
}

func (s *store) SaveBlock(b *shared.Block) error {
	key := fmt.Sprintf("%s%d", BlockPrefix, b.Index)
	log.Printf("Inserting block %d into database", b.Index)

	blockData, err := b.Marshal()
	if err != nil {
		log.Printf("Failed to marshal block %d: %v", b.Index, err)
		return fmt.Errorf("error marshaling block %d: %v", b.Index, err)
	}
	db := s.db.GetDB()
	err = db.Update(func(txn *badger.Txn) error {
		log.Printf("Storing data at key: %s", key)
		return txn.Set([]byte(key), blockData)
	})
	if err != nil {
		log.Printf("Error inserting block %d: %v", b.Index, err)
		return fmt.Errorf("error inserting block into BadgerDB: %v", err)
	}
	log.Printf("Block %d inserted successfully", b.Index)
	return nil
}

func (s *store) UpdateValidator(v *validator.Validator) error {
	addr, err := v.PublicKey.Address()
	if err != nil {
		log.Printf("Failed to get address from public key: %v", err)
		return fmt.Errorf("error getting address from public key: %v", err)
	}
	key := []byte(ValidatorPrefix + addr.String())
	data, err := v.Marshal()
	if err != nil {
		log.Printf("Failed to marshal validator: %v", err)
		return fmt.Errorf("error marshaling validator: %v", err)
	}
	err = s.db.Update(key, data)
	if err != nil {
		log.Printf("Failed to update validator: %v", err)
		return fmt.Errorf("error updating validator: %v", err)
	}
	return nil
}

func (s *store) RetrieveValidatorPublicKey(validatorAddress string) ([]byte, error) {
	var publicKey []byte
	db := s.db.GetDB()

	err := db.View(func(txn *badger.Txn) error {
		key := []byte("validatorPubKey-" + validatorAddress)
		log.Printf("Retrieving public key for validator: %s, key: %s", validatorAddress, key)
		item, err := txn.Get(key)
		if err != nil {
			log.Printf("Error retrieving public key for validator %s: %v", validatorAddress, err)
			return err
		}
		publicKey, err = item.ValueCopy(nil)
		return err
	})

	if err != nil {
		if err == badger.ErrKeyNotFound {
			log.Printf("Public key not found for validator %s", validatorAddress)
			return nil, fmt.Errorf("public key not found for validator %s", validatorAddress)
		}
		log.Printf("Error retrieving public key for validator %s: %v", validatorAddress, err)
		return nil, fmt.Errorf("error retrieving public key for validator %s: %v", validatorAddress, err)
	}

	log.Printf("Retrieved public key for validator %s: %x", validatorAddress, publicKey)
	return publicKey, nil
}

func (s *store) BeginTransaction() (*shared.TransactionContext, error) {
	db := s.db.GetDB()
	txn := db.NewTransaction(true)
	return shared.NewTransactionContext(txn), nil
}

func (s *store) RollbackTransaction(txn *shared.TransactionContext) error {
	txn.Txn.Discard()
	return nil
}

func (s *store) CommitTransaction(ctx *shared.TransactionContext) error {
	if ctx == nil {
		return fmt.Errorf("nil transaction context")
	}
	return ctx.Txn.Commit()
}

func (s *store) AddNewUTXO(txContext *shared.TransactionContext, utxo shared.UTXO) error {
	// Ensure TransactionID is set
	if utxo.TransactionID == "" {
		return fmt.Errorf("cannot add UTXO without TransactionID")
	}

	key := fmt.Sprintf("utxo-%s-%s-%d", utxo.OwnerAddress, utxo.TransactionID, utxo.Index)
	val, err := json.Marshal(utxo)
	if err != nil {
		return fmt.Errorf("failed to marshal UTXO: %v", err)
	}

	return txContext.Txn.Set([]byte(key), val)
}

func (s *store) MarkUTXOAsSpent(txContext *shared.TransactionContext, utxo shared.UTXO) error {
	// Ensure we have all required fields
	if utxo.OwnerAddress == "" {
		return fmt.Errorf("owner address is required")
	}
	if utxo.TransactionID == "" {
		return fmt.Errorf("transaction ID is required")
	}

	// Construct the key using the transaction ID from the input
	key := fmt.Sprintf("utxo-%s-%s-%d", utxo.OwnerAddress, utxo.TransactionID, utxo.Index)
	log.Printf("Marking UTXO as spent - Key: %s, TransactionID: %s, Amount: %d, Owner: %s",
		key, utxo.TransactionID, utxo.Amount, utxo.OwnerAddress)

	// Get the existing UTXO
	item, err := txContext.Txn.Get([]byte(key))
	if err != nil {
		if err == badger.ErrKeyNotFound {
			return fmt.Errorf("UTXO not found: %s", key)
		}
		return fmt.Errorf("error retrieving UTXO: %v", err)
	}

	var existingUTXO shared.UTXO
	err = item.Value(func(val []byte) error {
		return json.Unmarshal(val, &existingUTXO)
	})
	if err != nil {
		return fmt.Errorf("error unmarshaling UTXO: %v", err)
	}

	// Verify this UTXO isn't already spent
	if existingUTXO.IsSpent {
		return fmt.Errorf("UTXO is already spent: %s", key)
	}

	// Mark as spent
	existingUTXO.IsSpent = true

	// Save back
	updatedValue, err := json.Marshal(existingUTXO)
	if err != nil {
		return fmt.Errorf("error marshaling updated UTXO: %v", err)
	}

	err = txContext.Txn.Set([]byte(key), updatedValue)
	if err != nil {
		return fmt.Errorf("error saving updated UTXO: %v", err)
	}

	log.Printf("Successfully marked UTXO as spent - Key: %s", key)
	return nil
}

func (s *store) GetUTXOsForAddress(address string) ([]shared.UTXO, error) {
	var utxos []shared.UTXO
	db := s.db.GetDB()
	err := db.View(func(txn *badger.Txn) error {
		it := txn.NewIterator(badger.DefaultIteratorOptions)
		defer it.Close()

		prefix := []byte(fmt.Sprintf("utxo-%s-", address))
		log.Printf("Searching for UTXOs with prefix: %s", string(prefix))

		for it.Seek(prefix); it.ValidForPrefix(prefix); it.Next() {
			item := it.Item()
			err := item.Value(func(val []byte) error {
				var utxo shared.UTXO
				if err := json.Unmarshal(val, &utxo); err != nil {
					return err
				}
				log.Printf("Found UTXO: %+v", utxo)
				if !utxo.IsSpent {
					utxos = append(utxos, utxo)
					log.Printf("Added unspent UTXO: %+v", utxo)
				} else {
					log.Printf("Skipped spent UTXO: %+v", utxo)
				}
				return nil
			})
			if err != nil {
				return err
			}
		}
		return nil
	})

	log.Printf("Retrieved %d UTXOs for address %s", len(utxos), address)
	return utxos, err
}

func (s *store) SetTransaction(txn *shared.TransactionContext, key []byte, value []byte) error {
	if txn == nil || txn.Txn == nil {
		return fmt.Errorf("invalid transaction context")
	}
	if len(key) == 0 {
		return fmt.Errorf("key cannot be empty")
	}
	return txn.Txn.Set(key, value)
}

// AddTransaction stores a new transaction in the database. It serializes transaction inputs,
// outputs, and the signature for persistent storage.
func (s *store) AddTransaction(tx *thrylos.Transaction) error {
	db := s.db.GetDB()
	txn := db.NewTransaction(true)
	defer txn.Discard()

	txJSON, err := json.Marshal(tx)
	if err != nil {
		return fmt.Errorf("error marshaling transaction: %v", err)
	}

	key := []byte("transaction-" + tx.Id)

	if err := txn.Set(key, txJSON); err != nil {
		return fmt.Errorf("error storing transaction in BadgerDB: %v", err)
	}

	if err := txn.Commit(); err != nil {
		return fmt.Errorf("transaction commit failed: %v", err)
	}

	return nil
}
