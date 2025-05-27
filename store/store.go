package store

import (
	// Alias for standard crypto

	"encoding/binary"
	"encoding/json"
	"fmt"
	"log"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	badger "github.com/dgraph-io/badger/v3" // Note the /v3 suffix
	"github.com/fxamacker/cbor/v2"
	"github.com/thrylos-labs/thrylos"
	"github.com/thrylos-labs/thrylos/amount"
	"github.com/thrylos-labs/thrylos/crypto"
	"github.com/thrylos-labs/thrylos/crypto/address"
	"github.com/thrylos-labs/thrylos/crypto/encryption"
	"github.com/thrylos-labs/thrylos/crypto/hash"
	"github.com/thrylos-labs/thrylos/shared"
	"github.com/thrylos-labs/thrylos/types"
	"golang.org/x/crypto/blake2b"
)

type store struct {
	db             *Database
	cache          *UTXOCache
	validatorStore types.ValidatorKeyStore // Note lowercase first letter for internal field
	utxos          map[string]types.UTXO   // Add this line
	encryptionKey  []byte                  // The AES-256 key used for encryption and decryption
	totalNumShards int                     // NEW: Store the total number of shards here

}

var globalUTXOCache *UTXOCache

// NewStore creates a new store instance with the provided BadgerDB instance and encryption key.
// NewStore creates a new store instance
func NewStore(database *Database, encryptionKey []byte, totalNumShards int) (types.Store, error) { // Added totalNumShards
	if database == nil {
		return nil, fmt.Errorf("database cannot be nil")
	}

	c, err := NewUTXOCache(1024, 10000, 0.01) // Assuming this is correct
	if err != nil {
		return nil, fmt.Errorf("failed to create UTXO cache: %v", err)
	}

	s := &store{
		db:             database,
		cache:          c,
		utxos:          make(map[string]types.UTXO),
		encryptionKey:  encryptionKey,
		totalNumShards: totalNumShards, // NEW: Initialize totalNumShards
	}

	return s, nil
}

// GetUTXO retrieves a UTXO by its key.
func GetUTXO(txID string, index int) (*types.UTXO, error) {
	key := fmt.Sprintf("%s-%d", txID, index)
	utxo, exists := globalUTXOCache.Get(key)
	if !exists {
		return nil, fmt.Errorf("UTXO not found")
	}
	return utxo, nil
}

// UTXO

func (s *store) CreateAndStoreUTXO(id, txID string, index int, owner string, amount float64) error {
	utxo := types.CreateUTXO(id, index, txID, owner, amount, false)
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

// Close closes the underlying database
func (s *store) Close() error {
	if s.db != nil {
		return s.db.Close()
	}
	return nil
}

// GetDataDir returns the data directory path
func (s *store) GetDataDir() string {
	if s.db != nil {
		// This assumes your Database struct has access to the path
		// You might need to add a dataDir field to your Database struct
		return s.db.GetDataDir()
	}
	return ""
}

// GetLockFilePath returns the path to the database lock file
func (s *store) GetLockFilePath() string {
	dataDir := s.GetDataDir()
	if dataDir != "" {
		return filepath.Join(dataDir, "LOCK")
	}
	return ""
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

func (s *store) CreateUTXO(id, txID string, index int, address string, amount float64) (types.UTXO, error) {
	utxo := types.CreateUTXO(id, index, txID, address, amount, false)

	// Marshal UTXO to JSON
	utxoJSON, err := json.Marshal(utxo)
	if err != nil {
		return types.UTXO{}, fmt.Errorf("error marshalling UTXO: %v", err)
	}

	// Store in BadgerDB
	key := []byte("utxo-" + id)
	err = s.db.GetDB().Update(func(txn *badger.Txn) error {
		return txn.Set(key, utxoJSON)
	})
	if err != nil {
		return types.UTXO{}, fmt.Errorf("error storing UTXO: %v", err)
	}

	return *utxo, nil
}

func (s *store) GetUTXOsForUser(address string) ([]types.UTXO, error) {
	db := s.db.GetDB()
	userUTXOs := []types.UTXO{}
	err := db.View(func(txn *badger.Txn) error {
		it := txn.NewIterator(badger.DefaultIteratorOptions)
		defer it.Close()

		prefix := []byte("utxo-" + address + "-")
		for it.Seek(prefix); it.ValidForPrefix(prefix); it.Next() {
			item := it.Item()
			err := item.Value(func(val []byte) error {
				var utxo types.UTXO
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

func (s *store) GetUTXO(addr address.Address) ([]*types.UTXO, error) {
	var userUTXOs []*types.UTXO
	db := s.db.GetDB()
	prefix := []byte(UTXOPrefix) // Iterate all UTXOs
	addrStr := addr.String()

	err := db.View(func(txn *badger.Txn) error {
		opts := badger.DefaultIteratorOptions
		opts.Prefix = prefix
		it := txn.NewIterator(opts)
		defer it.Close()

		for it.Seek(prefix); it.ValidForPrefix(prefix); it.Next() {
			item := it.Item()
			err := item.Value(func(val []byte) error {
				var utxo types.UTXO
				// Standardize on CBOR
				if err := utxo.Unmarshal(val); err != nil {
					// Log problematic key
					log.Printf("WARN: Failed to unmarshal UTXO data for key %s: %v", string(item.Key()), err)
					return nil // Skip this UTXO, continue iteration
				}
				// Check owner and if spent
				if utxo.OwnerAddress == addrStr && !utxo.IsSpent {
					userUTXOs = append(userUTXOs, &utxo)
				}
				return nil
			})
			if err != nil {
				// This error would be from the item.Value() lambda itself, likely critical
				return fmt.Errorf("error processing UTXO item %s: %w", string(item.Key()), err)
			}
		}
		return nil
	})

	if err != nil {
		return nil, fmt.Errorf("error retrieving UTXOs for address %s: %w", addrStr, err)
	}
	return userUTXOs, nil
}

// UpdateUTXOs updates the UTXOs in the database, marking the inputs as spent and adding new outputs.
func (s *store) UpdateUTXOs(inputs []types.UTXO, outputs []types.UTXO) error {
	db := s.db.GetDB()

	badgerTxn := db.NewTransaction(true)
	defer badgerTxn.Discard()

	// Create a concrete TransactionContext implementation
	txn := shared.NewTransactionContext(badgerTxn)

	for _, input := range inputs {
		// Pass s.totalNumShards
		err := s.MarkUTXOAsSpent(txn, input, s.totalNumShards) // FIXED: Added s.totalNumShards
		if err != nil {
			txn.Rollback()
			return fmt.Errorf("error marking UTXO as spent: %w", err)
		}
	}

	for _, output := range outputs {
		// Pass s.totalNumShards
		err := s.AddNewUTXO(txn, output, s.totalNumShards) // FIXED: Added s.totalNumShards
		if err != nil {
			txn.Rollback()
			return fmt.Errorf("error adding new UTXO: %w", err)
		}
	}

	return txn.Commit()
}

func (s *store) updateUTXOsInTxn(txn *badger.Txn, inputs []types.UTXO, outputs []types.UTXO) error {
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

func (s *store) AddNewUTXO(ctx types.TransactionContext, utxo types.UTXO, totalNumShards int) error { // Added totalNumShards
	if utxo.TransactionID == "" {
		return fmt.Errorf("cannot add UTXO without TransactionID")
	}
	badgerTxn := ctx.GetBadgerTxn()
	if badgerTxn == nil {
		return fmt.Errorf("invalid transaction context: nil badger transaction")
	}

	// Use standard key format
	shardID := CalculateShardID(utxo.OwnerAddress, totalNumShards) // Use utxo.OwnerAddress for UTXO shard ID
	keyString := string(GetShardedKey(UTXOPrefix, shardID, utxo.Key()))
	keyBytes := []byte(keyString)

	// Use CBOR Marshal
	val, err := utxo.Marshal()
	if err != nil {
		return fmt.Errorf("failed to marshal UTXO for key %s: %w", keyString, err)
	}

	log.Printf("DEBUG: [AddNewUTXO TX] Setting UTXO key: %s", keyString)
	err = badgerTxn.Set(keyBytes, val)
	if err != nil {
		return fmt.Errorf("failed to save UTXO with key %s: %w", keyString, err)
	}

	ctx.SetModified(keyString) // Track modified key
	// Updating context's UTXO map might be complex/redundant if context is short-lived
	// log.Printf("DEBUG: AddNewUTXO - Successfully added UTXO %s to transaction context", keyString)
	return nil
}

func (s *store) MarkUTXOAsSpent(ctx types.TransactionContext, utxo types.UTXO, totalNumShards int) error { // Added totalNumShards
	if utxo.TransactionID == "" {
		return fmt.Errorf("transaction ID is required")
	}

	badgerTxn := ctx.GetBadgerTxn()
	if badgerTxn == nil {
		return fmt.Errorf("invalid transaction context: nil badger transaction")
	}

	// Use standard key format from the UTXO object passed in
	shardID := CalculateShardID(utxo.OwnerAddress, totalNumShards) // Use utxo.OwnerAddress
	keyString := string(GetShardedKey(UTXOPrefix, shardID, utxo.Key()))
	keyBytes := []byte(keyString)
	log.Printf("DEBUG: [MarkUTXOAsSpent TX] Marking UTXO key: %s", keyString)

	item, err := badgerTxn.Get(keyBytes)
	if err != nil {
		return fmt.Errorf("failed to get UTXO %s: %w", keyString, err) // Error includes KeyNotFound
	}

	var existingUTXO types.UTXO

	err = item.Value(func(val []byte) error {
		// Use CBOR Unmarshal
		return existingUTXO.Unmarshal(val)
	})
	if err != nil {
		return fmt.Errorf("error unmarshaling existing UTXO %s: %w", keyString, err)
	}

	if existingUTXO.IsSpent {
		return fmt.Errorf("UTXO %s is already spent", keyString)
	}

	existingUTXO.IsSpent = true

	// Use CBOR Marshal
	updatedValue, err := existingUTXO.Marshal()
	if err != nil {
		return fmt.Errorf("error marshaling updated UTXO %s: %w", keyString, err)
	}

	err = badgerTxn.Set(keyBytes, updatedValue)
	if err != nil {
		return fmt.Errorf("error saving updated UTXO %s: %w", keyString, err)
	}

	ctx.SetModified(keyString)
	log.Printf("DEBUG: [MarkUTXOAsSpent TX] Successfully marked UTXO %s as spent.", keyString)
	return nil
}

func (s *store) SpendUTXO(ctx types.TransactionContext, utxoKey string, ownerAddress string, totalNumShards int) (amount int64, err error) { // Added ownerAddress, totalNumShards
	badgerTxn := ctx.GetBadgerTxn()
	if badgerTxn == nil {
		return 0, fmt.Errorf("invalid transaction context")
	}

	// Assume utxoKey is in the format "txid-index" as per utxo.Key()
	keyString := fmt.Sprintf("%s%s", UTXOPrefix, utxoKey) // Add prefix
	keyBytes := []byte(keyString)
	log.Printf("DEBUG: [SpendUTXO TX] Spending UTXO key: %s", keyString)

	item, err := badgerTxn.Get(keyBytes)
	if err != nil {
		if err == badger.ErrKeyNotFound {
			return 0, fmt.Errorf("UTXO not found: %s", keyString)
		}
		return 0, fmt.Errorf("error retrieving UTXO %s: %w", keyString, err)
	}

	var existingUTXO types.UTXO
	err = item.Value(func(val []byte) error {
		// Use CBOR Unmarshal
		return existingUTXO.Unmarshal(val)
	})
	if err != nil {
		return 0, fmt.Errorf("error unmarshaling UTXO %s: %w", keyString, err)
	}

	if existingUTXO.IsSpent {
		return 0, fmt.Errorf("UTXO %s is already spent", keyString)
	}

	existingUTXO.IsSpent = true
	updatedValue, err := existingUTXO.Marshal() // Use CBOR Marshal
	if err != nil {
		return 0, fmt.Errorf("error marshaling updated UTXO %s: %w", keyString, err)
	}

	if err = badgerTxn.Set(keyBytes, updatedValue); err != nil {
		return 0, fmt.Errorf("error saving updated UTXO %s: %w", keyString, err)
	}

	ctx.SetModified(keyString)
	log.Printf("DEBUG: [SpendUTXO TX] Marked UTXO %s as spent.", keyString)
	return int64(existingUTXO.Amount), nil // Return amount
}

// Uses standardized key prefix and CBOR.
func (s *store) GetUTXOsForAddress(address string, totalNumShards int) ([]types.UTXO, error) { // Added totalNumShards
	var utxos []types.UTXO
	db := s.db.GetDB()
	err := db.View(func(txn *badger.Txn) error {
		opts := badger.DefaultIteratorOptions
		opts.Prefix = []byte(UTXOPrefix) // Iterate all UTXOs
		it := txn.NewIterator(opts)
		defer it.Close()

		log.Printf("DEBUG: [GetUTXOsForAddress] Searching UTXOs for address: %s", address)
		for it.Seek(opts.Prefix); it.ValidForPrefix(opts.Prefix); it.Next() {
			item := it.Item()
			err := item.Value(func(val []byte) error {
				var utxo types.UTXO
				// Use CBOR Unmarshal
				if err := utxo.Unmarshal(val); err != nil {
					log.Printf("WARN: Failed to unmarshal UTXO data for key %s: %v", string(item.Key()), err)
					return nil // Skip this UTXO
				}
				// Check owner and if spent
				if utxo.OwnerAddress == address && !utxo.IsSpent {
					utxos = append(utxos, utxo)
				}
				return nil
			})
			if err != nil {
				return fmt.Errorf("error processing UTXO item %s: %w", string(item.Key()), err)
			}
		}
		return nil
	})

	if err != nil {
		log.Printf("ERROR: Failed to fetch UTXOs from database for %s: %v", address, err)
		return nil, err
	}
	log.Printf("DEBUG: [GetUTXOsForAddress] Retrieved %d UTXOs for address %s", len(utxos), address)
	return utxos, nil
}

// AddUTXO adds a UTXO using an auto-incrementing index for the address.
// Likely used for genesis/initial funding, not standard transactions.
// WARNING: This method is NOT context-aware and runs in its own transaction.
func (s *store) AddUTXO(utxo types.UTXO) error {
	db := s.db.GetDB()
	return db.Update(func(txn *badger.Txn) error {
		// Ensure we have a TransactionID (use genesis format if needed)
		if utxo.TransactionID == "" {
			utxo.TransactionID = fmt.Sprintf("genesis-%s", utxo.OwnerAddress)
			log.Printf("WARN: Assigning default TransactionID to UTXO for %s: %s", utxo.OwnerAddress, utxo.TransactionID)
		}

		// Retrieve the current index for the address (optional, maybe index isn't needed here?)
		// If using txid-index key, this index counter is redundant. Let's skip it.
		// idxKey := []byte(fmt.Sprintf("%s%s", IndexPrefix, utxo.OwnerAddress))
		// ... (get and increment index logic removed) ...
		// Use index 0 or a fixed index if this is only for genesis-like UTXOs
		if utxo.Index == 0 && strings.HasPrefix(utxo.TransactionID, "genesis-") {
			log.Printf("DEBUG: Using index %d for genesis-like UTXO %s", utxo.Index, utxo.TransactionID)
		} else if utxo.Index == 0 {
			// Assign a default index if needed, maybe -1 to signify non-tx UTXO?
			// utxo.Index = -1 // Or handle appropriately
			log.Printf("WARN: AddUTXO called with Index 0 for non-genesis Tx %s", utxo.TransactionID)
		}

		// Create UTXO key using the standard format txid-index
		keyString := fmt.Sprintf("%s%s", UTXOPrefix, utxo.Key()) // utxo.Key() gives txid-index
		keyBytes := []byte(keyString)

		// Use CBOR Marshal
		val, err := utxo.Marshal()
		if err != nil {
			return fmt.Errorf("failed to marshal UTXO for key %s: %w", keyString, err)
		}
		log.Printf("DEBUG: [AddUTXO] Storing UTXO with key: %s", keyString)
		return txn.Set(keyBytes, val)
	})
}

func fetchUTXOs(txn *badger.Txn, address string, utxos *[]types.UTXO) error {
	prefix := []byte(fmt.Sprintf("utxo-%s-", address))
	log.Printf("Searching with prefix: %s", string(prefix)) // Logging the prefix used in the search

	opts := badger.DefaultIteratorOptions
	opts.Prefix = prefix
	it := txn.NewIterator(opts)
	defer it.Close()

	for it.Rewind(); it.ValidForPrefix(prefix); it.Next() {
		item := it.Item()
		err := item.Value(func(val []byte) error {
			var utxo types.UTXO
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
func (s *store) GetUTXOs(address string) (map[string][]types.UTXO, error) {
	db := s.db.GetDB()

	utxos := make(map[string][]types.UTXO)
	err := db.View(func(txn *badger.Txn) error {
		it := txn.NewIterator(badger.DefaultIteratorOptions)
		defer it.Close()

		prefix := []byte("utxo-" + address)
		for it.Seek(prefix); it.ValidForPrefix(prefix); it.Next() {
			item := it.Item()
			err := item.Value(func(val []byte) error {
				var utxo types.UTXO
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

// GetAllUTXOs retrieves all unspent UTXOs from the database, grouped by owner address.
func (s *store) GetAllUTXOs() (map[string][]types.UTXO, error) {
	db := s.db.GetDB()
	allUTXOs := make(map[string][]types.UTXO)

	err := db.View(func(txn *badger.Txn) error {
		opts := badger.DefaultIteratorOptions
		opts.Prefix = []byte(UTXOPrefix)
		it := txn.NewIterator(opts)
		defer it.Close()

		for it.Seek(opts.Prefix); it.ValidForPrefix(opts.Prefix); it.Next() {
			item := it.Item()
			err := item.Value(func(val []byte) error {
				var utxo types.UTXO
				// Use CBOR Unmarshal
				if err := utxo.Unmarshal(val); err != nil {
					log.Printf("WARN: Failed to unmarshal UTXO data for key %s: %v", string(item.Key()), err)
					return nil // Skip invalid data
				}
				if !utxo.IsSpent {
					allUTXOs[utxo.OwnerAddress] = append(allUTXOs[utxo.OwnerAddress], utxo)
				}
				return nil
			})
			// Handle error from item.Value lambda if it occurs
			if err != nil {
				return fmt.Errorf("error processing UTXO item %s: %w", string(item.Key()), err)
			}
		}
		return nil
	})

	if err != nil {
		return nil, fmt.Errorf("error retrieving all UTXOs: %w", err)
	}
	return allUTXOs, nil
}

func (s *store) GetUTXOsByAddress(address string) (map[string][]types.UTXO, error) {
	db := s.db.GetDB()

	utxos := make(map[string][]types.UTXO)

	err := db.View(func(txn *badger.Txn) error {
		prefix := []byte("utxo-" + address + "-") // Assuming keys are prefixed with utxo-<address>-
		opts := badger.DefaultIteratorOptions
		opts.Prefix = prefix
		it := txn.NewIterator(opts)
		defer it.Close()

		for it.Rewind(); it.ValidForPrefix(prefix); it.Next() {
			item := it.Item()
			err := item.Value(func(val []byte) error {
				var utxo types.UTXO
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

func (s *store) RetrieveTransaction(txn *badger.Txn, transactionID string) (*types.Transaction, error) {
	var tx types.Transaction

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

func (s *store) SendTransaction(fromAddress, toAddress string, amount int, privKey crypto.PrivateKey) (bool, error) {
	db := s.db.GetDB()

	// Step 1: Create transaction data
	transactionData := map[string]interface{}{
		"from":      fromAddress,
		"to":        toAddress,
		"amount":    amount,
		"timestamp": time.Now().Unix(),
	}

	// Step 2: Serialize transaction data to JSON
	jsonData, err := json.Marshal(transactionData)
	if err != nil {
		return false, fmt.Errorf("error serializing transaction data: %v", err)
	}

	// Step 3: Encrypt the transaction data
	encryptedData, err := encryption.EncryptWithAES(s.encryptionKey, jsonData)
	if err != nil {
		return false, fmt.Errorf("error encrypting transaction data: %v", err)
	}

	// Step 4: Create hash of the encrypted data
	dataHash := hash.NewHash(encryptedData)

	// Step 5: Sign the hashed data
	signature := privKey.Sign(dataHash.Bytes())
	if signature == nil {
		return false, fmt.Errorf("error creating signature")
	}

	// Step 6: Store the encrypted transaction and signature in the database atomically
	txn := db.NewTransaction(true)
	defer txn.Discard()

	// Create transaction ID using hash of encrypted data
	txID := dataHash.String()

	// Create and store a new Transaction object
	addr := address.NullAddress()
	if err := addr.Unmarshal([]byte(fromAddress)); err != nil {
		return false, fmt.Errorf("error creating address: %v", err)
	}

	// Create and store a new Transaction object
	transaction := &types.Transaction{
		ID:            txID,
		Timestamp:     time.Now().Unix(),
		SenderAddress: *addr, // Use the address pointer
		Signature:     signature,
		// Add other fields as needed
	}

	// Serialize the transaction
	txData, err := transaction.Marshal()
	if err != nil {
		return false, fmt.Errorf("error marshaling transaction: %v", err)
	}

	// Store transaction data
	if err := txn.Set([]byte("tx-"+txID), txData); err != nil {
		return false, fmt.Errorf("error storing transaction data: %v", err)
	}

	// Store encrypted payload
	if err := txn.Set([]byte("tx-payload-"+txID), encryptedData); err != nil {
		return false, fmt.Errorf("error storing encrypted payload: %v", err)
	}

	// Commit the transaction
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

func (s *store) SaveTransaction(tx *types.Transaction) error {
	db := s.db.GetDB()
	keyString := fmt.Sprintf("%s%s", TransactionPrefix, tx.ID)
	keyBytes := []byte(keyString)

	// Use CBOR Marshal
	txData, err := tx.Marshal()
	if err != nil {
		log.Printf("ERROR: Failed to marshal transaction %s: %v", tx.ID, err)
		return fmt.Errorf("error marshaling transaction %s: %w", tx.ID, err)
	}

	err = db.Update(func(txn *badger.Txn) error {
		log.Printf("DEBUG: [SaveTransaction] Storing transaction key: %s", keyString)
		return txn.Set(keyBytes, txData)
	})

	if err != nil {
		log.Printf("ERROR: Failed to save transaction %s: %v", tx.ID, err)
		return fmt.Errorf("error storing transaction %s in BadgerDB: %w", tx.ID, err)
	}
	log.Printf("DEBUG: [SaveTransaction] Successfully saved transaction %s", tx.ID)
	return nil
}

func (s *store) GetTransaction(id string) (*types.Transaction, error) {
	var tx types.Transaction
	keyString := fmt.Sprintf("%s%s", TransactionPrefix, id)
	keyBytes := []byte(keyString)

	db := s.db.GetDB()
	err := db.View(func(txn *badger.Txn) error {
		item, err := txn.Get(keyBytes)
		if err != nil {
			return err // Includes KeyNotFound
		}
		return item.Value(func(val []byte) error {
			// Use CBOR Unmarshal
			return tx.Unmarshal(val)
		})
	})

	if err != nil {
		if err == badger.ErrKeyNotFound {
			return nil, fmt.Errorf("transaction %s not found", id)
		}
		log.Printf("ERROR: Failed to retrieve/unmarshal transaction %s: %v", id, err)
		return nil, fmt.Errorf("error retrieving transaction %s: %w", id, err)
	}
	return &tx, nil
}

func (s *store) ProcessTransaction(tx *types.Transaction) error {
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

func (s *store) addTransactionInTxn(txn *badger.Txn, tx *types.Transaction) error {
	key := []byte(TransactionPrefix + tx.ID)
	value, err := cbor.Marshal(tx)
	if err != nil {
		log.Fatalf("Failed to marshal transaction: %v", err)
		return err
	}
	return txn.Set(key, value)
}

func (s *store) BeginTransaction() (types.TransactionContext, error) {
	db := s.db.GetDB()
	if db == nil {
		return nil, fmt.Errorf("database not initialized")
	}
	txn := db.NewTransaction(true) // Start read-write transaction
	if txn == nil {
		return nil, fmt.Errorf("failed to create badger transaction")
	}
	log.Printf("DEBUG: Began new DB transaction.")
	return shared.NewTransactionContext(txn), nil
}

func (s *store) RollbackTransaction(ctx types.TransactionContext) error {
	if ctx == nil {
		log.Printf("WARN: Attempted to rollback nil transaction context.")
		return nil // Or return an error?
	}
	log.Printf("DEBUG: Rolling back DB transaction.")
	// Rollback itself doesn't return error in badger/v3 Txn.Discard()
	ctx.Rollback() // Discard() is called internally by shared.TransactionContext Rollback
	return nil
}

func (s *store) CommitTransaction(ctx types.TransactionContext) error {
	if ctx == nil {
		return fmt.Errorf("cannot commit nil transaction context")
	}
	log.Printf("DEBUG: Committing DB transaction.")
	err := ctx.Commit()
	if err != nil {
		log.Printf("ERROR: Failed to commit DB transaction: %v", err)
		// Attempt rollback as a safety measure? Depends on badger behavior on commit failure.
		// _ = ctx.Rollback()
	} else {
		log.Printf("DEBUG: DB transaction committed successfully.")
	}
	return err
}

func (s *store) SetTransaction(txn types.TransactionContext, key []byte, value []byte) error {
	if txn == nil {
		return fmt.Errorf("invalid transaction context")
	}
	if len(key) == 0 {
		return fmt.Errorf("key cannot be empty")
	}

	badgerTxn := txn.GetBadgerTxn()
	if badgerTxn == nil {
		return fmt.Errorf("invalid badger transaction")
	}

	return badgerTxn.Set(key, value)
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

func (s *store) VerifyTransactionSignature(tx *types.Transaction, pubKey *crypto.PublicKey) error {
	// Get the transaction bytes without signature
	txBytes, err := shared.SerializeTransactionWithoutSignature(tx)
	if err != nil {
		return fmt.Errorf("error serializing transaction: %v", err)
	}

	// Hash the transaction bytes
	hasher, err := blake2b.New256(nil)
	if err != nil {
		return fmt.Errorf("error creating hasher: %v", err)
	}
	hasher.Write(txBytes)
	hashedTx := hasher.Sum(nil)

	// Verify the signature using the public key
	err = tx.Signature.Verify(pubKey, hashedTx)
	if err != nil {
		return fmt.Errorf("invalid transaction signature: %v", err)
	}

	return nil
}

func (s *store) TransactionExists(ctx types.TransactionContext, txID string) (bool, error) {
	badgerTxn := ctx.GetBadgerTxn()
	if badgerTxn == nil {
		return false, fmt.Errorf("invalid transaction context: nil badger transaction")
	}

	keyString := fmt.Sprintf("%s%s", TransactionPrefix, txID)
	keyBytes := []byte(keyString)

	_, err := badgerTxn.Get(keyBytes)
	if err == badger.ErrKeyNotFound {
		return false, nil // Not found is not an error here
	}
	if err != nil {
		log.Printf("ERROR: Error checking transaction existence for %s: %v", txID, err)
		return false, fmt.Errorf("error checking transaction existence for %s: %w", txID, err)
	}
	return true, nil // Found
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

func (s *store) GetLastBlockData(shardID types.ShardID) ([]byte, error) { // CORRECTED signature
	var latestBlockData []byte
	db := s.db.GetDB()

	// Use sharded prefix for blocks
	shardedPrefix := GetShardedKey(BlockPrefix, shardID) // GetShardedKey expects types.ShardID now

	err := db.View(func(txn *badger.Txn) error {
		opts := badger.DefaultIteratorOptions
		opts.Reverse = true
		opts.Prefix = shardedPrefix // Iterate only blocks for this shard
		it := txn.NewIterator(opts)
		defer it.Close()

		for it.Rewind(); it.ValidForPrefix(shardedPrefix); it.Next() {
			item := it.Item()
			key := item.Key()
			// Validate key format (e.g., blk-0-123) - it should now be "BlockPrefix + shardID + - + index"
			// So, check if it starts with the sharded prefix.
			if strings.HasPrefix(string(key), string(shardedPrefix)) { // Check if key starts with the specific sharded prefix
				err := item.Value(func(val []byte) error {
					latestBlockData = append([]byte(nil), val...)
					return nil
				})
				return err // Return from the View function after finding the latest block
			}
		}
		return fmt.Errorf("no blocks found in the database for shard %d", shardID)
	})

	if err != nil {
		return nil, err
	}
	return latestBlockData, nil
}

func (s *store) GetLastBlockIndex(shardID types.ShardID) (int, error) { // Already has shardID in signature (GOOD!)
	var lastIndex int = -1 // Default to -1 to indicate no blocks if none found
	db := s.db.GetDB()

	// 1. Construct the sharded prefix for blocks
	shardedBlockPrefix := GetShardedKey(BlockPrefix, shardID) // Use GetShardedKey

	err := db.View(func(txn *badger.Txn) error {
		opts := badger.DefaultIteratorOptions
		opts.Reverse = true // Iterate in reverse order to get the latest block first
		// 2. Set the iterator's prefix to the sharded block prefix
		opts.Prefix = shardedBlockPrefix
		it := txn.NewIterator(opts)
		defer it.Close()

		// 3. Rewind to the end of the specified prefix range
		it.Rewind() // For reverse iteration with prefix, Rewind() typically seeks to the largest key <= prefix + max_byte

		// 4. Check if the iterator is valid and within the prefix
		// ValidForPrefix will check if the current key starts with `shardedBlockPrefix`
		if it.ValidForPrefix(shardedBlockPrefix) {
			item := it.Item()
			key := item.Key()
			// The key format is now "BlockPrefix-ShardID-Index" (e.g., "blk-0-123")
			// So, we need to extract the index correctly.

			// Example: Split key "blk-0-123" into parts: ["blk", "0", "123"]
			// The block number/index is the third part (index 2).
			keyParts := strings.Split(string(key), "-")
			if len(keyParts) < 3 {
				log.Printf("ERROR: Malformed block key encountered in GetLastBlockIndex for shard %d: %s", shardID, string(key))
				return fmt.Errorf("malformed block key for shard %d: %s", shardID, string(key))
			}
			blockNumberStr := keyParts[2] // The block index part of the key
			var parseErr error
			lastIndex, parseErr = strconv.Atoi(blockNumberStr)
			if parseErr != nil {
				log.Printf("Error parsing block number from key %s for shard %d: %v", key, shardID, parseErr)
				return parseErr
			}
			log.Printf("DEBUG: Found last block key %s with index %d for shard %d", string(key), lastIndex, shardID)
			return nil // Stop after finding the latest block for this shard
		}
		// If the loop finishes and ValidForPrefix never returned true
		log.Printf("DEBUG: No blocks found in the database for shard %d (prefix: %s)", shardID, string(shardedBlockPrefix))
		return badger.ErrKeyNotFound // Treat as not found
	})

	if err != nil {
		if err == badger.ErrKeyNotFound {
			return -1, nil // No blocks found for this shard, which is not an error if it's a new shard
		}
		log.Printf("Failed to retrieve the last block index for shard %d: %v", shardID, err)
		return -1, err
	}

	return lastIndex, nil
}

func (s *store) GetLastBlock() (*types.Block, error) {
	lastIndex, err := s.GetLastBlockNumber()
	if err != nil {
		return nil, fmt.Errorf("failed to get last block number: %w", err)
	}
	if lastIndex < 0 {
		return nil, fmt.Errorf("no blocks found in database") // Or return nil, nil
	}
	return s.GetBlock(uint32(lastIndex))
}

func (s *store) GetLastBlockNumber() (int, error) {
	var lastIndex int = -1 // Default if no blocks found
	db := s.db.GetDB()
	err := db.View(func(txn *badger.Txn) error {
		opts := badger.DefaultIteratorOptions
		opts.Prefix = []byte(BlockPrefix)
		opts.Reverse = true // Iterate backwards
		it := txn.NewIterator(opts)
		defer it.Close()

		// Seek to the logical end of the prefix range in reverse
		// Since keys are blk-0, blk-1, etc., seeking to blk-\xff\xff... should work?
		// Simpler: just Rewind in reverse and take the first valid key.
		it.Rewind()

		if it.ValidForPrefix(opts.Prefix) {
			item := it.Item()
			key := item.Key()
			blockNumberStr := strings.TrimPrefix(string(key), BlockPrefix)
			var parseErr error
			lastIndex, parseErr = strconv.Atoi(blockNumberStr)
			if parseErr != nil {
				// Log the problematic key
				log.Printf("ERROR: Failed to parse block number from key '%s': %v", string(key), parseErr)
				// Continue searching? Or return error? Let's return error.
				return fmt.Errorf("failed to parse block number from key %s: %w", string(key), parseErr)
			}
			return nil // Found the latest, stop iteration
		}
		// If loop finishes without finding a key with the prefix
		return badger.ErrKeyNotFound // Treat as not found
	})

	if err != nil && err != badger.ErrKeyNotFound {
		log.Printf("ERROR: Failed to retrieve the last block index: %v", err)
		return -1, err // Return error
	}
	// If ErrKeyNotFound, lastIndex remains -1, return -1 and nil error
	if err == badger.ErrKeyNotFound {
		log.Printf("DEBUG: No blocks found matching prefix %s", BlockPrefix)
		return -1, nil
	}

	return lastIndex, nil
}

func (s *store) GetBlock(blockNumber uint32) (*types.Block, error) {
	var block types.Block
	keyString := fmt.Sprintf("%s%d", BlockPrefix, blockNumber)
	keyBytes := []byte(keyString)

	db := s.db.GetDB()
	err := db.View(func(txn *badger.Txn) error {
		item, err := txn.Get(keyBytes)
		if err != nil {
			return err // Includes KeyNotFound
		}
		return item.Value(func(val []byte) error {
			// Use block's Unmarshal method (assuming it uses CBOR)
			return block.Unmarshal(val)
		})
	})

	if err != nil {
		if err == badger.ErrKeyNotFound {
			return nil, fmt.Errorf("block %d not found", blockNumber)
		}
		log.Printf("ERROR: Failed to retrieve/unmarshal block %d: %v", blockNumber, err)
		return nil, fmt.Errorf("error retrieving block %d: %w", blockNumber, err)
	}
	return &block, nil
}

func (s *store) SaveBlock(b *types.Block) error {
	// Ensure the interface still includes this non-context signature
	keyString := fmt.Sprintf("%s%d", BlockPrefix, b.Index)
	keyBytes := []byte(keyString)
	log.Printf("DEBUG: [SaveBlock] Saving block %d at key %s", b.Index, keyString)

	// Use block's Marshal method (assuming it uses CBOR)
	blockData, err := b.Marshal()
	if err != nil {
		log.Printf("ERROR: Failed to marshal block %d: %v", b.Index, err)
		return fmt.Errorf("error marshaling block %d: %w", b.Index, err)
	}
	if len(blockData) == 0 {
		return fmt.Errorf("marshaled block data is empty for block %d", b.Index)
	}

	db := s.db.GetDB() // Get underlying DB
	err = db.Update(func(txn *badger.Txn) error {
		log.Printf("DEBUG: [SaveBlock] Storing data via db.Update at key: %s", keyString)
		return txn.Set(keyBytes, blockData)
	})

	if err != nil {
		log.Printf("ERROR: Error inserting block %d via SaveBlock: %v", b.Index, err)
		return fmt.Errorf("error inserting block %d into BadgerDB: %w", b.Index, err)
	}
	log.Printf("DEBUG: Block %d inserted successfully via SaveBlock.", b.Index)
	return nil
}

func (s *store) SaveBlockWithContext(ctx types.TransactionContext, b *types.Block) error {
	badgerTxn := ctx.GetBadgerTxn()
	if badgerTxn == nil {
		return fmt.Errorf("invalid transaction context")
	}

	keyString := fmt.Sprintf("%s%d", BlockPrefix, b.Index)
	keyBytes := []byte(keyString)

	// Use block's Marshal method (assuming it uses CBOR)
	blockData, err := b.Marshal()
	if err != nil {
		return fmt.Errorf("error marshaling block %d: %w", b.Index, err)
	}
	if len(blockData) == 0 {
		return fmt.Errorf("marshaled block data is empty for block %d", b.Index)
	}

	log.Printf("DEBUG: [SaveBlockWithContext TX] Storing block %d at key %s", b.Index, keyString)
	if err := badgerTxn.Set(keyBytes, blockData); err != nil {
		return fmt.Errorf("failed to set block %d in transaction: %w", b.Index, err)
	}
	ctx.SetModified(keyString) // Optional: track modified keys
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
func (s *store) RetrieveBlock(shardID types.ShardID, blockNumber int) ([]byte, error) { // MODIFIED signature
	// Construct the sharded key for the block
	// Key format: BlockPrefix-ShardID-BlockNumber (e.g., "blk-0-123")
	keyString := string(GetShardedKey(BlockPrefix, shardID, strconv.Itoa(blockNumber)))
	keyBytes := []byte(keyString)

	log.Printf("Retrieving block %d from shard %d from the database (key: %s)", blockNumber, shardID, keyString)
	var blockData []byte
	db := s.db.GetDB()
	err := db.View(func(txn *badger.Txn) error {
		item, err := txn.Get(keyBytes)
		if err != nil {
			return err // Includes badger.ErrKeyNotFound
		}
		blockData, err = item.ValueCopy(nil)
		if err != nil {
			log.Printf("Error retrieving block data from key %s: %v", keyString, err)
		}
		return err
	})

	if err != nil {
		if err == badger.ErrKeyNotFound {
			log.Printf("Failed to retrieve block %d from shard %d: Key not found.", blockNumber, shardID)
			return nil, fmt.Errorf("block %d not found for shard %d", blockNumber, shardID)
		}
		log.Printf("Failed to retrieve block %d from shard %d: %v", blockNumber, shardID, err)
		return nil, fmt.Errorf("failed to retrieve block data for shard %d: %w", shardID, err)
	}
	log.Printf("Block %d retrieved successfully from shard %d", blockNumber, shardID)
	return blockData, nil
}

// KEY

var publicKeyCache = sync.Map{}

// GetPublicKey retrieves a public key using standard prefix.
func (s *store) GetPublicKey(addr address.Address) (crypto.PublicKey, error) {
	db := s.db.GetDB()
	addrStr := addr.String()
	keyString := fmt.Sprintf("%s%s", PublicKeyPrefix, addrStr)
	keyBytes := []byte(keyString)
	log.Printf("DEBUG: [GetPublicKey] Attempting to get key: %s", keyString)

	var pubKeyBytes []byte
	err := db.View(func(txn *badger.Txn) error {
		item, errGet := txn.Get(keyBytes)
		if errGet != nil {
			return errGet
		}
		pubKeyBytes, errGet = item.ValueCopy(nil) // Copy value out of transaction
		return errGet
	})

	if err != nil {
		if err == badger.ErrKeyNotFound {
			return nil, fmt.Errorf("public key not found for address %s", addrStr)
		}
		log.Printf("ERROR: [GetPublicKey] Failed DB view/get for %s: %v", addrStr, err)
		return nil, fmt.Errorf("error retrieving public key data for %s: %w", addrStr, err)
	}
	if len(pubKeyBytes) == 0 {
		log.Printf("ERROR: [GetPublicKey] Retrieved empty data for %s", addrStr)
		return nil, fmt.Errorf("retrieved empty public key data for address %s", addrStr)
	}
	log.Printf("DEBUG: [GetPublicKey] Retrieved %d bytes for key %s", len(pubKeyBytes), keyString)

	// Use factory function to unmarshal into concrete type
	pubKey, errUnmarshal := crypto.NewPublicKeyFromBytes(pubKeyBytes)
	if errUnmarshal != nil {
		log.Printf("ERROR: [GetPublicKey] Failed unmarshal for %s: %v", addrStr, errUnmarshal)
		return nil, fmt.Errorf("error unmarshaling public key for %s: %w", addrStr, errUnmarshal)
	}

	log.Printf("DEBUG: [GetPublicKey] Successfully retrieved key for %s", addrStr)
	return pubKey, nil
}

// StoreValidatorPublicKey stores a validator's ML-DSA44 public key
func (s *store) SavePublicKey(pubKey crypto.PublicKey) error {
	db := s.db.GetDB()
	addr, err := pubKey.Address()
	if err != nil {
		return fmt.Errorf("error getting address from public key: %w", err)
	}
	addrStr := addr.String()

	// Use MarshalBinary for potentially more standard/compact representation if available
	// Otherwise, use Marshal() if that's the intended method.
	var pubKeyData []byte
	if marshaller, ok := pubKey.(interface{ MarshalBinary() ([]byte, error) }); ok {
		pubKeyData, err = marshaller.MarshalBinary()
	} else {
		pubKeyData, err = pubKey.Marshal() // Fallback to Marshal
	}
	if err != nil {
		return fmt.Errorf("error marshaling public key for %s: %w", addrStr, err)
	}
	if len(pubKeyData) == 0 {
		return fmt.Errorf("marshaled public key data is empty for %s", addrStr)
	}

	keyString := fmt.Sprintf("%s%s", PublicKeyPrefix, addrStr)
	keyBytes := []byte(keyString)

	err = db.Update(func(txn *badger.Txn) error {
		log.Printf("DEBUG: [SavePublicKey] Storing public key for %s, key: %s", addrStr, keyString)
		return txn.Set(keyBytes, pubKeyData)
	})
	if err != nil {
		log.Printf("ERROR: [SavePublicKey] Failed for %s: %v", addrStr, err)
	} else {
		log.Printf("DEBUG: [SavePublicKey] Success for %s", addrStr)
	}
	return err
}

func (s *store) UpdateTransactionStatus(txID string, status string, blockHash []byte) error {
	// Needs a key schema, e.g., "txstatus-<txid>"
	// Needs serialization for status/blockHash
	// Uses db.Update()
	log.Printf("WARN: UpdateTransactionStatus DB persistence not fully implemented.")
	// Example Structure:
	db := s.db.GetDB()
	key := []byte(fmt.Sprintf("txstatus-%s", txID))
	// Simple value: status string + hex block hash
	valueStr := status
	if blockHash != nil {
		valueStr += ":" + fmt.Sprintf("%x", blockHash)
	}
	return db.Update(func(txn *badger.Txn) error {
		return txn.Set(key, []byte(valueStr))
	})
	// return nil // Placeholder
}

// BALANCE
func (s *store) AddToBalance(ctx types.TransactionContext, address string, amount int64, totalNumShards int) error { // Added totalNumShards
	// ... (initial checks) ...

	shardID := CalculateShardID(address, totalNumShards)
	keyString := string(GetShardedKey(BalancePrefix, shardID, address))
	keyBytes := []byte(keyString)
	var currentBalance int64 = 0 // Initialize to 0
	badgerTxn := ctx.GetBadgerTxn()

	// Attempt to retrieve the existing balance item
	item, err := badgerTxn.Get(keyBytes)

	// Handle potential errors during Get
	if err != nil && err != badger.ErrKeyNotFound {
		// If there's an error other than "not found", return it
		return fmt.Errorf("failed to get current balance for %s: %w", address, err)
	}

	// *** If err is nil, the key WAS found ***
	if err == nil { // Key exists, read the value
		log.Printf("DEBUG: [AddToBalance TX] Key %s FOUND. Reading value...", keyString) // ADD THIS
		err = item.Value(func(val []byte) error {
			log.Printf("DEBUG: [AddToBalance TX] Value bytes for %s: %x (length %d)", keyString, val, len(val)) // ADD THIS
			if len(val) == 8 {
				currentBalance = int64(binary.BigEndian.Uint64(val))
				log.Printf("DEBUG: [AddToBalance TX] Successfully decoded balance for %s: %d", keyString, currentBalance) // ADD THIS
				return nil
			}
			// Handle potentially malformed data - log and treat as 0 for recovery?
			if len(val) == 0 {
				log.Printf("WARN: Balance data for %s is empty. Treating as 0.", address)
				currentBalance = 0
				return nil
			}
			// Log warning for unexpected length
			log.Printf("WARN: Balance data for %s has unexpected length %d. Treating as 0.", address, len(val))
			currentBalance = 0 // Treat malformed data as 0 balance
			// Return nil to avoid halting the process, or return an error if strictness is required:
			// return fmt.Errorf("invalid balance data length for %s: %d bytes", address, len(val))
			return nil

		})
		// Check for errors during item.Value() execution
		if err != nil {
			return fmt.Errorf("failed to read current balance value for %s: %w", address, err)
		}
	}
	// *** If err was badger.ErrKeyNotFound, currentBalance remains 0 ***
	log.Printf("DEBUG: [AddToBalance TX] Current balance for %s before change: %d", address, currentBalance)

	// Calculate the new balance
	newBalance := currentBalance + amount
	if newBalance < 0 {
		return fmt.Errorf("insufficient balance for %s: current=%d, attempted change=%d, resulting in %d", address, currentBalance, amount, newBalance)
	}

	// Encode and set the new balance
	balanceBytes := make([]byte, 8)
	binary.BigEndian.PutUint64(balanceBytes, uint64(newBalance))

	log.Printf("DEBUG: [AddToBalance TX] Updating balance for %s: %d -> %d (Change: %d)", address, currentBalance, newBalance, amount)
	if err := badgerTxn.Set(keyBytes, balanceBytes); err != nil {
		return fmt.Errorf("failed to set new balance for %s in transaction: %w", address, err)
	}
	// ... (SetModified, return nil) ...
	ctx.SetModified(keyString)
	return nil
}

func (s *store) SaveStakeholderBalance(address string, balance int64) error {
	db := s.db.GetDB()
	keyString := fmt.Sprintf("%s%s", BalancePrefix, address)
	keyBytes := []byte(keyString)
	log.Printf("DEBUG: [SaveStakeholderBalance] Saving balance for %s: %d", address, balance)

	balanceBytes := make([]byte, 8)
	binary.BigEndian.PutUint64(balanceBytes, uint64(balance))

	err := db.Update(func(txn *badger.Txn) error {
		return txn.Set(keyBytes, balanceBytes)
	})

	if err != nil {
		log.Printf("ERROR: [SaveStakeholderBalance] Failed for %s: %v", address, err)
	} else {
		log.Printf("DEBUG: [SaveStakeholderBalance] Success for %s", address)
	}
	return err
}

func (s *store) GetStakeholderBalance(address string, totalNumShards int) (int64, error) { // Added totalNumShards
	db := s.db.GetDB()
	shardID := CalculateShardID(address, totalNumShards)
	keyString := string(GetShardedKey(BalancePrefix, shardID, address))
	keyBytes := []byte(keyString)
	var balance int64 = 0

	err := db.View(func(txn *badger.Txn) error {
		item, err := txn.Get(keyBytes)
		if err == badger.ErrKeyNotFound {
			return nil // Not found is not an error, balance is 0
		}
		if err != nil {
			return err // Other DB error
		}
		return item.Value(func(val []byte) error {
			if len(val) == 8 {
				balance = int64(binary.BigEndian.Uint64(val))
				return nil
			}
			if len(val) == 0 {
				balance = 0 // Treat empty as 0
				return nil
			}
			return fmt.Errorf("invalid balance data length: %d", len(val))
		})
	})
	if err != nil {
		log.Printf("ERROR: [GetStakeholderBalance] Failed for %s: %v", address, err)
		return 0, err
	}
	log.Printf("DEBUG: [GetStakeholderBalance] Retrieved balance for %s: %d", address, balance)
	return balance, nil
}

// GetBalance calculates the total balance for a given address based on its UTXOs.
// This function is useful for determining the spendable balance of a blockchain account.
func (s *store) GetBalance(address string, utxos map[string][]types.UTXO) (amount.Amount, error) {
	var balance amount.Amount
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

// UpdateBalance updates a stakeholder's balance in the database
func (s *store) UpdateBalance(address string, balance int64) error {
	db := s.db.GetDB()
	log.Printf("DEBUG: Updating balance for address %s to %d nanoTHRYLOS", address, balance)

	key := []byte("balance-" + address)

	err := db.Update(func(txn *badger.Txn) error {
		balanceBytes := make([]byte, 8) // int64 uses 8 bytes
		binary.BigEndian.PutUint64(balanceBytes, uint64(balance))

		err := txn.Set(key, balanceBytes)
		if err != nil {
			log.Printf("Failed to update balance for address %s: %v", address, err)
			return fmt.Errorf("error updating balance in BadgerDB: %v", err)
		}

		return nil
	})

	if err != nil {
		log.Printf("ERROR: Failed to update balance for %s: %v", address, err)
	} else {
		log.Printf("SUCCESS: Updated balance for %s to %d nanoTHRYLOS", address, balance)
	}

	return err
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
