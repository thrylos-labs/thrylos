package store

import (
	"bytes"
	"fmt"
	"log"
	"sync"

	badger "github.com/dgraph-io/badger/v3"
	"github.com/thrylos-labs/thrylos/consensus/validator"
	"github.com/thrylos-labs/thrylos/crypto"
	"github.com/thrylos-labs/thrylos/crypto/address"
	"github.com/thrylos-labs/thrylos/types"
)

func (s *store) SaveValidator(v *types.Validator) error {
	addr := (*v).Address() // Assuming types.Validator has an Address() method returning address.Address
	data, err := (*v).Marshal()
	if err != nil {
		log.Printf("Error marshalling validator: %v\n", err)
		return err
	}
	// Use the official ValidatorPrefx for these types.Validator objects
	key := []byte(ValidatorPrefx + addr.String())
	return s.db.Set(key, data)
}

func (s *store) GetValidator(addr address.Address) (*types.Validator, error) {
	var validatorData []byte
	db := s.db.GetDB() // Assuming s.db is your *Database type which has GetDB()

	err := db.View(func(txn *badger.Txn) error {
		// Use the official ValidatorPrefx
		key := []byte(ValidatorPrefx + addr.String())
		log.Printf("Retrieving validator object: %s, key: %s", addr.String(), string(key))
		item, err := txn.Get(key)
		if err != nil {
			log.Printf("Error getting validator object %s: %v", addr.String(), err)
			return err
		}
		validatorData, err = item.ValueCopy(nil)
		return err
	})

	if err != nil {
		if err == badger.ErrKeyNotFound {
			log.Printf("Validator object not found for %s", addr.String())
			return nil, fmt.Errorf("validator object not found for %s", addr.String())
		}
		log.Printf("Error retrieving validator object for %s: %v", addr.String(), err)
		return nil, fmt.Errorf("error retrieving validator object for %s: %v", addr.String(), err)
	}

	// Assuming validator.NewValidatorFromBytes exists and works as intended for types.Validator
	// If types.Validator has its own unmarshal method, that would be more typical.
	val := validator.NewValidatorFromBytes(validatorData) // This was from your original code
	return &val, nil
}

// ValidatorKeyStoreImpl implements the types.ValidatorKeyStore interface
// This specifically handles *private keys* for validators, using PrivateKeyPrifx ("pk-")
type ValidatorKeyStoreImpl struct {
	keys          map[string]*crypto.PrivateKey
	mu            sync.RWMutex
	db            *Database // Assuming this is your wrapper around BadgerDB
	encryptionKey []byte
}

// NewValidatorKeyStore creates and initializes a new ValidatorKeyStore
func NewValidatorKeyStore(db *Database, encryptionKey []byte) types.ValidatorKeyStore {
	vks := &ValidatorKeyStoreImpl{
		keys:          make(map[string]*crypto.PrivateKey),
		mu:            sync.RWMutex{},
		db:            db,
		encryptionKey: encryptionKey,
	}
	if err := vks.LoadKeysFromDB(); err != nil {
		log.Printf("WARNING: Failed to load validator private keys from DB: %v", err)
	}
	return vks
}

func (vks *ValidatorKeyStoreImpl) LoadKeysFromDB() error {
	vks.mu.Lock()
	defer vks.mu.Unlock()

	// Use the official PrivateKeyPrifx for private keys
	prefix := []byte(PrivateKeyPrifx)
	log.Printf("DEBUG: Starting LoadKeysFromDB scan for private keys with prefix '%s'", string(prefix))
	loadedCount := 0

	err := vks.db.GetDB().View(func(txn *badger.Txn) error {
		opts := badger.DefaultIteratorOptions
		opts.Prefix = prefix
		it := txn.NewIterator(opts)
		defer it.Close()

		vks.keys = make(map[string]*crypto.PrivateKey) // Start with a fresh map

		for it.Rewind(); it.ValidForPrefix(prefix); it.Next() {
			item := it.Item()
			dbKey := item.Key()
			dbKeyCopy := bytes.Clone(dbKey)
			// Derive address string by trimming the prefix
			addrBytes := bytes.TrimPrefix(dbKeyCopy, prefix)
			addressString := string(addrBytes)
			log.Printf("DEBUG: LoadKeys: Found potential private key in DB: %s (Address: %s)", string(dbKeyCopy), addressString)

			val, err := item.ValueCopy(nil)
			if err != nil {
				log.Printf("ERROR: LoadKeys: Failed reading DB value for private key %s: %v", string(dbKeyCopy), err)
				continue
			}

			log.Printf("DEBUG: LoadKeys: Reading private key value for %s (Length: %d)", addressString, len(val))
			keyBytes := val

			// --- Optional Decryption placeholder ---
			finalKeyBytes := keyBytes // Use raw bytes if not encrypting

			privKey, errUnmarshal := crypto.NewPrivateKeyFromBytes(finalKeyBytes)
			if errUnmarshal != nil {
				log.Printf("ERROR: LoadKeys: Failed to unmarshal private key for address %s: %v", addressString, errUnmarshal)
				continue
			}

			var keyInterface crypto.PrivateKey = privKey
			vks.keys[addressString] = &keyInterface
			loadedCount++
			log.Printf("DEBUG: LoadKeys: Successfully loaded and mapped private key for %s", addressString)
		}
		return nil
	})

	if err != nil {
		return fmt.Errorf("failed to iterate over validator private keys in DB: %w", err)
	}

	log.Printf("Finished loading %d validator private keys from DB.", loadedCount)
	return nil
}

// StoreKey stores a private key for a validator and updates the in-memory cache.
func (vks *ValidatorKeyStoreImpl) StoreKey(address string, key *crypto.PrivateKey) error {
	if key == nil || *key == nil {
		return fmt.Errorf("attempted to store nil private key for address %s", address)
	}

	vks.mu.Lock()
	defer vks.mu.Unlock()

	keyBytes, err := (*key).Marshal()
	if err != nil {
		return fmt.Errorf("failed to marshal private key for %s: %w", address, err)
	}

	finalBytesToStore := keyBytes // Placeholder for optional encryption

	// Use the official PrivateKeyPrifx
	dbKey := []byte(PrivateKeyPrifx + address)

	if err := vks.db.Set(dbKey, finalBytesToStore); err != nil {
		return fmt.Errorf("failed to save private key to DB for %s: %w", address, err)
	}
	log.Printf("DEBUG: Successfully saved private key bytes to DB for %s using key %s", address, string(dbKey))

	vks.keys[address] = key
	log.Printf("INFO: Stored private key for %s in DB and updated in-memory cache.", address)

	return nil
}

// GetKey retrieves a private key for a validator from the in-memory cache.
func (vks *ValidatorKeyStoreImpl) GetKey(address string) (*crypto.PrivateKey, bool) {
	vks.mu.RLock()
	defer vks.mu.RUnlock()
	key, exists := vks.keys[address]
	return key, exists
}

// RemoveKey removes a private key for a validator from the in-memory cache and the database.
func (vks *ValidatorKeyStoreImpl) RemoveKey(address string) error {
	vks.mu.Lock()
	defer vks.mu.Unlock()

	if _, exists := vks.keys[address]; exists {
		delete(vks.keys, address)
		log.Printf("DEBUG: Removed private key for address %s from in-memory cache.", address)
	} else {
		log.Printf("WARN: Attempted to remove private key for address %s not found in in-memory cache.", address)
	}

	// Use the official PrivateKeyPrifx for DB deletion
	dbKey := []byte(PrivateKeyPrifx + address)
	err := vks.db.Delete(dbKey)
	if err != nil {
		if err != badger.ErrKeyNotFound { // BadgerDB returns nil for Delete if key not found. This check might be redundant but safe.
			log.Printf("ERROR: Failed to delete private key from DB for %s (key: %s): %v", address, string(dbKey), err)
			return fmt.Errorf("failed to delete private key from DB for %s: %w", address, err)
		}
		log.Printf("DEBUG: Private key for address %s (key: %s) not found in DB for deletion (or already deleted).", address, string(dbKey))
	} else {
		log.Printf("INFO: Successfully deleted private key from DB for %s (key: %s).", address, string(dbKey))
	}
	return nil
}

// HasKey checks if a key exists for a validator in the in-memory cache.
func (vks *ValidatorKeyStoreImpl) HasKey(address string) bool {
	vks.mu.RLock()
	defer vks.mu.RUnlock()
	_, exists := vks.keys[address]
	return exists
}

// GetAllAddresses returns all addresses that have stored keys in the in-memory cache.
func (vks *ValidatorKeyStoreImpl) GetAllAddresses() []string {
	vks.mu.RLock()
	defer vks.mu.RUnlock()
	addresses := make([]string, 0, len(vks.keys))
	for addr := range vks.keys {
		addresses = append(addresses, addr)
	}
	return addresses
}
