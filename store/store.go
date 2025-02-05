package store

import (
	stdcrypto "crypto" // Alias for standard crypto
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/rsa"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"regexp"
	"strconv"
	"strings"
	"sync"

	"github.com/dgraph-io/badger/v3"
	"github.com/fxamacker/cbor/v2"
	"github.com/thrylos-labs/thrylos"

	"github.com/thrylos-labs/thrylos/crypto"
	"github.com/thrylos-labs/thrylos/crypto/address"
	"github.com/thrylos-labs/thrylos/crypto/mldsa44"
	"github.com/thrylos-labs/thrylos/shared"
	"golang.org/x/crypto/blake2b"
)

type store struct {
	db            *Database
	cache         *UTXOCache
	utxos         map[string]shared.UTXO // Add this line
	encryptionKey []byte                 // The AES-256 key used for encryption and decryption
}

var globalUTXOCache *UTXOCache

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
		utxos:         make(map[string]shared.UTXO),
		encryptionKey: encryptionKey,
	}

	// Verify interface implementation at compile time
	var _ shared.Store = (*store)(nil)

	return s, nil
}

// GetUTXO retrieves a UTXO by its key.
func GetUTXO(txID string, index int) (*shared.UTXO, error) {
	key := fmt.Sprintf("%s-%d", txID, index)
	utxo, exists := globalUTXOCache.Get(key)
	if !exists {
		return nil, fmt.Errorf("UTXO not found")
	}
	return utxo, nil
}

// ENCRYPT AND DECRYPT

// encryptData encrypts data using AES-256 GCM.
func (s *store) encryptData(data []byte) ([]byte, error) {
	block, err := aes.NewCipher(s.encryptionKey)
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err = io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}

	return gcm.Seal(nonce, nonce, data, nil), nil
}

// decryptData decrypts data using AES-256 GCM.
func (s *store) decryptData(encryptedData []byte) ([]byte, error) {
	block, err := aes.NewCipher(s.encryptionKey)
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	if len(encryptedData) < gcm.NonceSize() {
		return nil, fmt.Errorf("invalid encrypted data")
	}

	nonce, ciphertext := encryptedData[:gcm.NonceSize()], encryptedData[gcm.NonceSize():]
	return gcm.Open(nil, nonce, ciphertext, nil)
}

func (s *store) hashData(data []byte) []byte {
	hasher, _ := blake2b.New256(nil)
	hasher.Write(data)
	return hasher.Sum(nil)
}

// UTXO

func (s *store) CreateAndStoreUTXO(id, txID string, index int, owner string, amount int64) error {
	utxo := shared.CreateUTXO(id, index, txID, owner, amount, false)
	db := s.db.GetDB()

	// Marshal the UTXO object into JSON for storage.
	utxoJSON, err := json.Marshal(utxo)
	if err != nil {
		return fmt.Errorf("error marshalling UTXO: %v", err)
	}

	// Prepare the key for this UTXO entry in the database.
	key := []byte("utxo-" + id)

	// Use BadgerDB transaction to put the UTXO data into the database.
	err = db.Update(func(txn *badger.Txn) error {
		return txn.Set(key, utxoJSON)
	})
	if err != nil {
		return fmt.Errorf("error inserting UTXO into BadgerDB: %v", err)
	}

	return nil
}

// MarkUTXOAsSpent marks a UTXO as spent in the database.
func generateUTXOKey(address string, transactionID string, index int) string {
	if transactionID == "" {
		// For genesis or initial UTXOs, use a special format
		return fmt.Sprintf("utxo-%s-%d", address, index)
	}
	return fmt.Sprintf("utxo-%s-%s-%d", address, transactionID, index)
}

func GenerateUTXOKey(ownerAddress string, transactionID string, index int) string {
	return fmt.Sprintf("utxo-%s-%s-%d", ownerAddress, transactionID, index)
}

func (s *store) CreateUTXO(id, txID string, index int, address string, amount int64) (shared.UTXO, error) {
	utxo := shared.CreateUTXO(id, index, txID, address, amount, false)

	// Marshal UTXO to JSON
	utxoJSON, err := json.Marshal(utxo)
	if err != nil {
		return shared.UTXO{}, fmt.Errorf("error marshalling UTXO: %v", err)
	}

	// Store in BadgerDB
	key := []byte("utxo-" + id)
	err = s.db.GetDB().Update(func(txn *badger.Txn) error {
		return txn.Set(key, utxoJSON)
	})
	if err != nil {
		return shared.UTXO{}, fmt.Errorf("error storing UTXO: %v", err)
	}

	return *utxo, nil
}

func (s *store) GetUTXOsForUser(address string) ([]shared.UTXO, error) {
	db := s.db.GetDB()
	userUTXOs := []shared.UTXO{}
	err := db.View(func(txn *badger.Txn) error {
		it := txn.NewIterator(badger.DefaultIteratorOptions)
		defer it.Close()

		prefix := []byte("utxo-" + address + "-")
		for it.Seek(prefix); it.ValidForPrefix(prefix); it.Next() {
			item := it.Item()
			err := item.Value(func(val []byte) error {
				var utxo shared.UTXO
				if err := json.Unmarshal(val, &utxo); err != nil {
					return err
				}
				if !utxo.IsSpent {
					userUTXOs = append(userUTXOs, utxo)
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

// UpdateUTXOs updates the UTXOs in the database, marking the inputs as spent and adding new outputs.
func (s *store) UpdateUTXOs(inputs []shared.UTXO, outputs []shared.UTXO) error {
	db := s.db.GetDB()

	badgerTxn := db.NewTransaction(true)
	defer badgerTxn.Discard()

	// Create a TransactionContext wrapper
	txn := &shared.TransactionContext{Txn: badgerTxn}

	for _, input := range inputs {
		err := s.MarkUTXOAsSpent(txn, input)
		if err != nil {
			return fmt.Errorf("error marking UTXO as spent: %w", err)
		}
	}

	for _, output := range outputs {
		err := s.AddNewUTXO(txn, output)
		if err != nil {
			return fmt.Errorf("error adding new UTXO: %w", err)
		}
	}

	return badgerTxn.Commit()
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

func (s *store) AddUTXO(utxo shared.UTXO) error {
	db := s.db.GetDB()

	return db.Update(func(txn *badger.Txn) error {
		// Ensure we have a TransactionID
		if utxo.TransactionID == "" {
			utxo.TransactionID = fmt.Sprintf("genesis-%s", utxo.OwnerAddress)
		}

		// Retrieve the current index for the address
		idxKey := fmt.Sprintf("index-%s", utxo.OwnerAddress)
		item, err := txn.Get([]byte(idxKey))
		if err != nil && err != badger.ErrKeyNotFound {
			return err
		}
		var index int64 = 0
		if err != badger.ErrKeyNotFound {
			err = item.Value(func(val []byte) error {
				index = int64(binary.BigEndian.Uint64(val))
				return nil
			})
			if err != nil {
				return err
			}
		}

		// Increment the index for the next UTXO
		index++
		utxo.Index = int(index)
		indexBytes := make([]byte, 8)
		binary.BigEndian.PutUint64(indexBytes, uint64(index))
		if err := txn.Set([]byte(idxKey), indexBytes); err != nil {
			return err
		}

		// Create UTXO with the new index using the same format as AddNewUTXO
		key := fmt.Sprintf("utxo-%s-%s-%d", utxo.OwnerAddress, utxo.TransactionID, utxo.Index)
		val, err := json.Marshal(utxo)
		if err != nil {
			return err
		}
		return txn.Set([]byte(key), val)
	})
}

func fetchUTXOs(txn *badger.Txn, address string, utxos *[]shared.UTXO) error {
	prefix := []byte(fmt.Sprintf("utxo-%s-", address))
	log.Printf("Searching with prefix: %s", string(prefix)) // Logging the prefix used in the search

	opts := badger.DefaultIteratorOptions
	opts.Prefix = prefix
	it := txn.NewIterator(opts)
	defer it.Close()

	for it.Rewind(); it.ValidForPrefix(prefix); it.Next() {
		item := it.Item()
		err := item.Value(func(val []byte) error {
			var utxo shared.UTXO
			if err := json.Unmarshal(val, &utxo); err != nil {
				return err
			}
			*utxos = append(*utxos, utxo)
			return nil
		})
		if err != nil {
			log.Printf("Error processing item for prefix %s: %v", string(prefix), err) // Log any processing errors
			return err
		}
	}
	return nil
}

// GetUTXOs retrieves all UTXOs for a specific address.
func (s *store) GetUTXOs(address string) (map[string][]shared.UTXO, error) {
	db := s.db.GetDB()

	utxos := make(map[string][]shared.UTXO)
	err := db.View(func(txn *badger.Txn) error {
		it := txn.NewIterator(badger.DefaultIteratorOptions)
		defer it.Close()

		prefix := []byte("utxo-" + address)
		for it.Seek(prefix); it.ValidForPrefix(prefix); it.Next() {
			item := it.Item()
			err := item.Value(func(val []byte) error {
				var utxo shared.UTXO
				if err := json.Unmarshal(val, &utxo); err != nil {
					return err
				}
				if !utxo.IsSpent {
					utxos[address] = append(utxos[address], utxo)
				}
				return nil
			})
			if err != nil {
				return err
			}
		}
		return nil
	})
	return utxos, err
}

func (s *store) GetAllUTXOs() (map[string][]shared.UTXO, error) {
	db := s.db.GetDB()

	allUTXOs := make(map[string][]shared.UTXO)
	err := db.View(func(txn *badger.Txn) error {
		it := txn.NewIterator(badger.DefaultIteratorOptions)
		defer it.Close()

		prefix := []byte("utxo-")
		for it.Seek(prefix); it.ValidForPrefix(prefix); it.Next() {
			item := it.Item()
			err := item.Value(func(val []byte) error {
				var utxo shared.UTXO
				if err := json.Unmarshal(val, &utxo); err != nil {
					return err
				}
				if !utxo.IsSpent {
					allUTXOs[utxo.OwnerAddress] = append(allUTXOs[utxo.OwnerAddress], utxo)
				}
				return nil
			})
			if err != nil {
				return err
			}
		}
		return nil
	})

	return allUTXOs, err
}

func (s *store) GetUTXOsByAddress(address string) (map[string][]shared.UTXO, error) {
	db := s.db.GetDB()

	utxos := make(map[string][]shared.UTXO)

	err := db.View(func(txn *badger.Txn) error {
		prefix := []byte("utxo-" + address + "-") // Assuming keys are prefixed with utxo-<address>-
		opts := badger.DefaultIteratorOptions
		opts.Prefix = prefix
		it := txn.NewIterator(opts)
		defer it.Close()

		for it.Rewind(); it.ValidForPrefix(prefix); it.Next() {
			item := it.Item()
			err := item.Value(func(val []byte) error {
				var utxo shared.UTXO
				if err := json.Unmarshal(val, &utxo); err != nil {
					return fmt.Errorf("error unmarshalling UTXO: %v", err)
				}

				// Extract the UTXO index from the key, format is "utxo-<address>-<index>"
				keyParts := strings.Split(string(item.Key()), "-")
				if len(keyParts) >= 3 {
					index := keyParts[2]
					utxos[index] = append(utxos[index], utxo)
				}

				return nil
			})
			if err != nil {
				return err
			}
		}

		return nil
	})

	if err != nil {
		return nil, fmt.Errorf("error retrieving UTXOs for address %s: %v", address, err)
	}

	return utxos, nil
}

// TRANSACTION

func (s *store) RetrieveTransaction(txn *badger.Txn, transactionID string) (*shared.Transaction, error) {
	var tx shared.Transaction

	key := []byte("transaction-" + transactionID)

	item, err := txn.Get(key)
	if err != nil {
		return nil, err
	}

	err = item.Value(func(val []byte) error {
		return json.Unmarshal(val, &tx)
	})
	if err != nil {
		return nil, fmt.Errorf("error unmarshaling transaction: %v", err)
	}

	return &tx, nil
}

func (s *store) SendTransaction(fromAddress, toAddress string, amount int, privKey *rsa.PrivateKey) (bool, error) {
	db := s.db.GetDB()

	// Step 1: Create transaction data
	transactionData := map[string]interface{}{
		"from":   fromAddress,
		"to":     toAddress,
		"amount": amount,
	}

	// Step 2: Serialize transaction data to JSON
	jsonData, err := json.Marshal(transactionData)
	if err != nil {
		return false, fmt.Errorf("error serializing transaction data: %v", err)
	}

	// Step 3: Encrypt the transaction data
	encryptedData, err := s.encryptData(jsonData)
	if err != nil {
		return false, fmt.Errorf("error encrypting transaction data: %v", err)
	}

	// Step 4: Sign the encrypted data
	signature, err := rsa.SignPSS(rand.Reader, privKey, stdcrypto.SHA256, s.hashData(encryptedData), nil)
	if err != nil {
		return false, fmt.Errorf("error signing transaction: %v", err)
	}

	// Step 5: Store the encrypted transaction and signature in the database atomically
	txn := db.NewTransaction(true)
	defer txn.Discard()

	err = s.storeTransactionInTxn(txn, encryptedData, signature, fromAddress, toAddress)
	if err != nil {
		return false, fmt.Errorf("error storing transaction in the database: %v", err)
	}

	if err := txn.Commit(); err != nil {
		return false, fmt.Errorf("transaction commit failed: %v", err)
	}

	return true, nil
}

func (s *store) storeTransactionInTxn(txn *badger.Txn, encryptedData, signature []byte, fromAddress, toAddress string) error {
	err := txn.Set([]byte(fmt.Sprintf("transaction:%s:%s", fromAddress, toAddress)), encryptedData)
	if err != nil {
		return err
	}
	err = txn.Set([]byte(fmt.Sprintf("signature:%s:%s", fromAddress, toAddress)), signature)
	if err != nil {
		return err
	}
	return nil
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

func (s *store) SetTransaction(txn *shared.TransactionContext, key []byte, value []byte) error {
	if txn == nil || txn.Txn == nil {
		return fmt.Errorf("invalid transaction context")
	}
	if len(key) == 0 {
		return fmt.Errorf("key cannot be empty")
	}
	return txn.Txn.Set(key, value)
}

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

func (s *store) CreateAndSignTransaction(txID string, inputs, outputs []shared.UTXO, privKey *rsa.PrivateKey) (*shared.Transaction, error) {
	tx := shared.NewTransaction(txID, inputs, outputs) // Returns *shared.Transaction

	// Serialize the transaction without the signature
	txBytes, err := tx.SerializeWithoutSignature()
	if err != nil {
		return tx, fmt.Errorf("error serializing transaction: %v", err) // Return pointer
	}

	// Hash the serialized transaction using BLAKE2b
	hasher, _ := blake2b.New256(nil)
	hasher.Write(txBytes)
	hashedTx := hasher.Sum(nil)

	// Sign the hashed transaction
	signature, err := rsa.SignPKCS1v15(rand.Reader, privKey, stdcrypto.SHA256, hashedTx[:])
	if err != nil {
		return tx, fmt.Errorf("error signing transaction: %v", err) // Return pointer
	}

	sig := mldsa44.NewSignature(signature)

	tx.Signature = sig
	return tx, nil
}

func (s *store) TransactionExists(txn *shared.TransactionContext, txID string) (bool, error) {
	if txn == nil || txn.Txn == nil {
		return false, fmt.Errorf("invalid transaction context")
	}

	key := []byte("transaction-" + txID)
	_, err := txn.Txn.Get(key)
	if err == badger.ErrKeyNotFound {
		return false, nil
	}
	if err != nil {
		return false, fmt.Errorf("error checking transaction existence: %v", err)
	}
	return true, nil
}

// It is essential for verifying transaction signatures and ensuring the integrity of transactions.
func (s *store) RetrievePublicKeyFromAddress(address string) (*mldsa44.PublicKey, error) {
	log.Printf("Attempting to retrieve public key for address: %s", address)
	var publicKeyData []byte
	db := s.db.GetDB()

	err := db.View(func(txn *badger.Txn) error {
		item, err := txn.Get([]byte("publicKey-" + address))
		if err != nil {
			if err == badger.ErrKeyNotFound {
				log.Printf("Public key not found in database for address %s", address)
				return err
			}
			log.Printf("Database error on retrieving public key for address %s: %v", address, err)
			return err
		}
		return item.Value(func(val []byte) error {
			publicKeyData = append([]byte{}, val...) // Ensure you're copying the data correctly
			return nil
		})
	})

	if err != nil {
		return nil, err
	}

	var keys map[string][]byte
	if err := json.Unmarshal(publicKeyData, &keys); err != nil {
		log.Printf("Error unmarshalling public key data for address %s: %v", address, err)
		return nil, err
	}

	mldsaKeyBytes, ok := keys["mldsaPublicKey"]
	if !ok || len(mldsaKeyBytes) == 0 {
		log.Printf("No MLDSA public key found for address %s", address)
		return nil, fmt.Errorf("no MLDSA public key found for address %s", address)
	}

	// Parse the bytes into an MLDSA public key
	pubKey := new(mldsa44.PublicKey)
	err = pubKey.Unmarshal(mldsaKeyBytes)
	if err != nil {
		log.Printf("Failed to parse MLDSA public key for address %s: %v", address, err)
		return nil, fmt.Errorf("failed to parse MLDSA public key: %v", err)
	}

	log.Printf("Successfully retrieved and parsed MLDSA public key for address %s", address)
	return pubKey, nil
}

// BLOCK

func (s *store) InsertBlock(blockData []byte, blockNumber int) error {
	key := fmt.Sprintf("block-%d", blockNumber)
	log.Printf("Inserting block %d into database", blockNumber)
	db := s.db.GetDB()

	err := db.Update(func(txn *badger.Txn) error {
		log.Printf("Storing data at key: %s", key)
		return txn.Set([]byte(key), blockData)
	})

	if err != nil {
		log.Printf("Error inserting block %d: %v", blockNumber, err)
		return fmt.Errorf("error inserting block into BadgerDB: %v", err)
	}

	log.Printf("Block %d inserted successfully", blockNumber)
	return nil
}

func (s *store) GetLatestBlockData() ([]byte, error) {
	var latestBlockData []byte
	db := s.db.GetDB()

	err := db.View(func(txn *badger.Txn) error {
		opts := badger.DefaultIteratorOptions
		opts.Reverse = true // Iterate in reverse order
		it := txn.NewIterator(opts)
		defer it.Close()

		for it.Rewind(); it.Valid(); it.Next() {
			item := it.Item()
			key := item.Key()
			if strings.HasPrefix(string(key), "block-") {
				// We've found the latest block
				err := item.Value(func(val []byte) error {
					// Make a copy of the block data
					latestBlockData = append([]byte(nil), val...)
					return nil
				})
				return err // Return from the View function after finding the latest block
			}
		}

		return fmt.Errorf("no blocks found in the database")
	})

	if err != nil {
		return nil, err
	}
	return latestBlockData, nil
}

func (s *store) GetLastBlockIndex() (int, error) {
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
			if strings.HasPrefix(string(key), "block-") {
				blockNumberStr := strings.TrimPrefix(string(key), "block-")
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

// StoreBlock stores serialized block data.
func (s *store) StoreBlock(blockData []byte, blockNumber int) error {
	db := s.db.GetDB()

	key := fmt.Sprintf("block-%d", blockNumber)
	log.Printf("Storing block %d in the database", blockNumber)

	return db.Update(func(txn *badger.Txn) error {
		log.Printf("Storing data at key: %s", key)
		return txn.Set([]byte(key), blockData)
	})
}

// RetrieveBlock retrieves serialized block data by block number.
func (s *store) RetrieveBlock(blockNumber int) ([]byte, error) {
	key := fmt.Sprintf("block-%d", blockNumber)
	log.Printf("Retrieving block %d from the database", blockNumber)
	var blockData []byte
	db := s.db.GetDB()
	err := db.View(func(txn *badger.Txn) error {
		item, err := txn.Get([]byte(key))
		if err != nil {
			return err
		}
		blockData, err = item.ValueCopy(nil)
		if err != nil {
			log.Printf("Error retrieving block data from key %s: %v", key, err)
		}
		return err
	})

	if err != nil {
		log.Printf("Failed to retrieve block %d: %v", blockNumber, err)
		return nil, fmt.Errorf("failed to retrieve block data: %v", err)
	}
	log.Printf("Block %d retrieved successfully", blockNumber)
	return blockData, nil
}

func (s *store) GetLastBlockData() ([]byte, int, error) {
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
			if strings.HasPrefix(string(key), "block-") {
				blockNumberStr := strings.TrimPrefix(string(key), "block-")
				var parseErr error
				lastIndex, parseErr = strconv.Atoi(blockNumberStr)
				if parseErr != nil {
					return fmt.Errorf("error parsing block number: %v", parseErr)
				}
				blockData, parseErr = item.ValueCopy(nil)
				if parseErr != nil {
					return fmt.Errorf("error retrieving block data: %v", parseErr)
				}
				return nil
			}
		}
		return fmt.Errorf("no blocks found in the database")
	})

	if err != nil {
		return nil, -1, err
	}

	if lastIndex == -1 {
		return nil, -1, fmt.Errorf("no blocks found in the database")
	}

	return blockData, lastIndex, nil
}

// KEY

var publicKeyCache = sync.Map{}

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

func (s *store) GetPublicKeyWithCaching(address string) (*mldsa44.PublicKey, error) {
	if cachedKey, found := publicKeyCache.Load(address); found {
		log.Printf("Public key retrieved from cache for address: %s", address)
		// Type assert to *mldsa44.PublicKey
		return cachedKey.(*mldsa44.PublicKey), nil
	}

	key, err := s.RetrievePublicKeyFromAddress(address)
	if err != nil {
		return nil, err
	}

	publicKeyCache.Store(address, key) // Cache the retrieved key
	return key, nil
}

func (s *store) PublicKeyExists(address string) (bool, error) {
	db := s.db.GetDB()

	formattedAddress, err := s.SanitizeAndFormatAddress(address)
	if err != nil {
		return false, fmt.Errorf("error sanitizing address: %v", err)
	}

	exists := false
	err = db.View(func(txn *badger.Txn) error {
		_, err := txn.Get([]byte("publicKey-" + formattedAddress))
		if err == badger.ErrKeyNotFound {
			// Key not found, publicKey does not exist
			return nil
		} else if err != nil {
			// An error occurred while trying to find the key
			return err
		}
		// Key found, publicKey exists
		exists = true
		return nil
	})

	if err != nil {
		return false, fmt.Errorf("failed to check public key existence: %v", err)
	}

	return exists, nil
}

func (s *store) InsertOrUpdateMLDSAPublicKey(address string, mldsaPublicKey *mldsa44.PublicKey) error {
	log.Printf("Attempting to insert/update MLDSA public key for address: %s", address)
	db := s.db.GetDB()

	formattedAddress, err := s.SanitizeAndFormatAddress(address)
	if err != nil {
		log.Printf("Error sanitizing address %s: %v", address, err)
		return err
	}
	log.Printf("Sanitized and formatted address: %s", formattedAddress)

	// Convert MLDSA public key to bytes
	publicKeyBytes, err := mldsaPublicKey.Marshal()
	if err != nil {
		log.Printf("Failed to marshal MLDSA public key for address %s: %v", formattedAddress, err)
		return fmt.Errorf("failed to marshal MLDSA public key: %v", err)
	}

	// Prepare the data to be inserted or updated
	data, err := json.Marshal(map[string][]byte{"mldsaPublicKey": publicKeyBytes})
	if err != nil {
		log.Printf("Failed to marshal public key data for address %s: %v", formattedAddress, err)
		return fmt.Errorf("failed to marshal public key data: %v", err)
	}
	log.Printf("Marshalled public key data length: %d bytes", len(data))

	// Start a new transaction for the database operation
	txn := db.NewTransaction(true)
	defer txn.Discard() // Ensure that the transaction is discarded if not committed

	log.Printf("Started new transaction for address: %s", formattedAddress)

	// Attempt to set the public key in the database
	key := []byte("publicKey-" + formattedAddress)
	if err := txn.Set(key, data); err != nil {
		log.Printf("Failed to insert MLDSA public key for address %s: %v", formattedAddress, err)
		return fmt.Errorf("failed to insert MLDSA public key for address %s: %v", formattedAddress, err)
	}
	log.Printf("MLDSA public key set in transaction for address: %s", formattedAddress)

	// Commit the transaction
	if err := txn.Commit(); err != nil {
		log.Printf("Transaction commit failed for MLDSA public key update for address %s: %v", formattedAddress, err)
		return fmt.Errorf("transaction commit failed for MLDSA public key update for address %s: %v", formattedAddress, err)
	}

	log.Printf("Transaction committed successfully for address: %s", formattedAddress)
	log.Printf("MLDSA public key successfully updated for address %s", formattedAddress)
	return nil
}

func (s *store) RetrieveMLDSAPublicKey(address string) ([]byte, error) {
	log.Printf("Attempting to retrieve public key for address: %s", address)
	db := s.db.GetDB()

	formattedAddress, err := s.SanitizeAndFormatAddress(address)
	if err != nil {
		log.Printf("Error sanitizing and formatting address %s: %v", address, err)
		return nil, err
	}
	log.Printf("Formatted address: %s", formattedAddress)

	var publicKeyData []byte
	err = db.View(func(txn *badger.Txn) error {
		key := []byte(validatorPublicKeyPrefix + formattedAddress)
		log.Printf("Attempting to retrieve data for key: %s", string(key))

		item, err := txn.Get(key)
		if err != nil {
			log.Printf("Error retrieving item from database for key %s: %v", string(key), err)
			return err
		}

		return item.Value(func(val []byte) error {
			publicKeyData = val
			log.Printf("Retrieved public key data for key %s", string(key))
			return nil
		})
	})

	if err != nil {
		log.Printf("Error in database transaction for address %s: %v", formattedAddress, err)
		return nil, err
	}

	log.Printf("Successfully retrieved public key for address %s", formattedAddress)
	return publicKeyData, nil
}

// VALIDATOR

const validatorPublicKeyPrefix = "validatorPubKey-"

// func (s *store) GetValidator(addr address.Address) (*shared.Validator, error) {
// 	key := []byte(ValidatorPrefix + addr.String())
// 	data, err := s.db.Get(key)
// 	if err != nil {
// 		log.Printf("Failed to retrieve validator: %v", err)
// 		return nil, fmt.Errorf("error retrieving validator: %v", err)
// 	}
// 	var vl shared.Validator
// 	err = vl.Unmarshal(data)
// 	if err != nil {
// 		log.Printf("Failed to unmarshal validator: %v", err)
// 		return nil, fmt.Errorf("error unmarshaling validator: %v", err)
// 	}
// 	return &vl, nil
// }

// func (s *store) UpdateValidator(v *shared.Validator) error {
// 	addr, err := v.PublicKey.Address()
// 	if err != nil {
// 		log.Printf("Failed to get address from public key: %v", err)
// 		return fmt.Errorf("error getting address from public key: %v", err)
// 	}
// 	key := []byte(ValidatorPrefix + addr.String())
// 	data, err := v.Marshal()
// 	if err != nil {
// 		log.Printf("Failed to marshal validator: %v", err)
// 		return fmt.Errorf("error marshaling validator: %v", err)
// 	}
// 	err = s.db.Update(key, data)
// 	if err != nil {
// 		log.Printf("Failed to update validator: %v", err)
// 		return fmt.Errorf("error updating validator: %v", err)
// 	}
// 	return nil
// }

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

func (s *store) GetAllValidatorPublicKeys() (map[string]mldsa44.PublicKey, error) {
	log.Println("Retrieving all validator public keys")
	db := s.db.GetDB()

	publicKeys := make(map[string]mldsa44.PublicKey)

	err := db.View(func(txn *badger.Txn) error {
		opts := badger.DefaultIteratorOptions
		opts.PrefetchSize = 10
		it := txn.NewIterator(opts)
		defer it.Close()

		prefix := []byte(validatorPublicKeyPrefix)
		for it.Seek(prefix); it.ValidForPrefix(prefix); it.Next() {
			item := it.Item()
			key := item.Key()

			err := item.Value(func(val []byte) error {
				// Create a new MLDSA public key
				pubKey := new(mldsa44.PublicKey)
				var err error
				err = pubKey.Unmarshal(val) // Use val instead of mldsaKeyBytes since we're in the Value callback
				if err != nil {
					return fmt.Errorf("failed to parse MLDSA public key for key %s: %v", string(key), err)
				}

				address := string(key[len(prefix):]) // Remove prefix to get address
				publicKeys[address] = *pubKey
				return nil
			})

			if err != nil {
				return err
			}
		}
		return nil
	})

	if err != nil {
		log.Printf("Error retrieving all validator public keys: %v", err)
		return nil, err
	}

	log.Printf("Successfully retrieved %d validator public keys", len(publicKeys))
	return publicKeys, nil
}

// StoreValidatorPublicKey stores a validator's ML-DSA44 public key
func (s *store) StoreValidatorPublicKey(validatorAddress string, publicKeyBytes []byte) error {
	db := s.db.GetDB()

	if !strings.HasPrefix(validatorAddress, "tl1") {
		log.Printf("Invalid address format for validator %s: must start with 'tl1'", validatorAddress)
		return fmt.Errorf("invalid address format: must start with 'tl1'")
	}

	// We'll store the bytes directly since they're already in the correct format
	return db.Update(func(txn *badger.Txn) error {
		key := []byte(validatorPublicKeyPrefix + validatorAddress)
		log.Printf("Storing public key for validator: %s, key: %s", validatorAddress, key)
		err := txn.Set(key, publicKeyBytes)
		if err != nil {
			log.Printf("Failed to store public key for validator %s: %v", validatorAddress, err)
			return fmt.Errorf("failed to store public key: %v", err)
		}
		log.Printf("Stored public key for validator: %s", validatorAddress)
		return nil
	})
}

// Helper function for when you have an ML-DSA44 key
func (s *store) StoreValidatorMLDSAPublicKey(validatorAddress string, publicKey *mldsa44.PublicKey) error {
	publicKeyBytes, err := publicKey.Marshal()
	if err != nil {
		return fmt.Errorf("failed to marshal public key: %v", err)
	}
	return s.StoreValidatorPublicKey(validatorAddress, publicKeyBytes)
}

// And for retrieving as ML-DSA44 key
func (s *store) GetValidatorMLDSAPublicKey(validatorAddress string) (*mldsa44.PublicKey, error) {
	var pubKey mldsa44.PublicKey
	db := s.db.GetDB()
	err := db.View(func(txn *badger.Txn) error {
		key := []byte(validatorPublicKeyPrefix + validatorAddress)
		item, err := txn.Get(key)
		if err != nil {
			return err
		}

		return item.Value(func(val []byte) error {
			return pubKey.Unmarshal(val)
		})
	})

	if err != nil {
		if err == badger.ErrKeyNotFound {
			return nil, fmt.Errorf("no public key found for validator %s", validatorAddress)
		}
		return nil, err
	}

	return &pubKey, nil
}

// BECH32 CHECK IF ADDRESS IS REGISTERED

func (s *store) Bech32AddressExists(bech32Address string) (bool, error) {
	db := s.db.GetDB()

	exists := false

	err := db.View(func(txn *badger.Txn) error {
		// Assuming that the key for Bech32 addresses is stored as 'address-tl1<actual_address>'
		key := []byte("address-" + bech32Address) // Adjust if your key format is different

		_, err := txn.Get(key)

		if err == badger.ErrKeyNotFound {
			// Key not found, address does not exist
			return nil
		} else if err != nil {
			// An error occurred that isn't related to key non-existence
			return err
		}

		// If we get here, it means the key was found and thus the address exists
		exists = true
		return nil
	})

	return exists, err
}

// BALANCE

// GetBalance calculates the total balance for a given address based on its UTXOs.
// This function is useful for determining the spendable balance of a blockchain account.
func (s *store) GetBalance(address string, utxos map[string][]shared.UTXO) (int64, error) {
	var balance int64
	userUTXOs, ok := utxos[address]
	if !ok {
		log.Printf("No UTXOs found for address: %s", address)
		return 0, nil
	}

	log.Printf("Processing UTXOs for address %s:", address)
	for i, utxo := range userUTXOs {
		utxoKey := generateUTXOKey(address, utxo.TransactionID, utxo.Index)
		if !utxo.IsSpent {
			balance += utxo.Amount
			log.Printf("UTXO %d [%s]: Amount=%d nanoTHRYLOS (%.7f THRYLOS) IsSpent=%v",
				i, utxoKey, utxo.Amount, float64(utxo.Amount)/1e7, utxo.IsSpent)
		} else {
			log.Printf("Skipping spent UTXO %d [%s]: Amount=%d IsSpent=%v",
				i, utxoKey, utxo.Amount, utxo.IsSpent)
		}

	}

	log.Printf("Final balance for %s: %d nanoTHRYLOS (%.7f THRYLOS)",
		address, balance, float64(balance)/1e7)
	return balance, nil
}

// ADDRESS

func (s *store) SanitizeAndFormatAddress(address string) (string, error) {
	trimmedAddress := strings.TrimSpace(address)

	if len(trimmedAddress) == 0 {
		return "", fmt.Errorf("invalid address: empty or only whitespace")
	}

	formattedAddress := strings.ToLower(trimmedAddress)

	if !regexp.MustCompile(`^[a-z0-9]+$`).MatchString(formattedAddress) {
		return "", fmt.Errorf("invalid address: contains invalid characters")
	}

	return formattedAddress, nil
}
