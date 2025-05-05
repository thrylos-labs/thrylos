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
	addr := (*v).Address()
	data, err := (*v).Marshal()
	if err != nil {
		log.Printf("Error marshalling validator: %v\n", err)
		return err
	}
	key := []byte(ValidatorPrefix + addr.String())
	return s.db.Set(key, data)
}

func (s *store) GetValidator(addr address.Address) (*types.Validator, error) {
	var validatorData []byte
	db := s.db.GetDB()

	err := db.View(func(txn *badger.Txn) error {
		key := []byte(ValidatorPrefix + addr.String())
		log.Printf("Retrieving validator data: %s, key: %s", addr.String(), key)
		item, err := txn.Get(key)
		if err != nil {
			log.Printf("Error validator data %s: %v", addr.String(), err)
			return err
		}
		validatorData, err = item.ValueCopy(nil)
		return err
	})

	if err != nil {
		if err == badger.ErrKeyNotFound {
			log.Printf("Public key not found for validator %s", addr.String())
			return nil, fmt.Errorf("public key not found for validator %s", addr.String())
		}
		log.Printf("Error retrieving public key for validator %s: %v", addr.String(), err)
		return nil, fmt.Errorf("error retrieving public key for validator %s: %v", addr.String(), err)
	}

	v := validator.NewValidatorFromBytes(validatorData)
	return &v, nil
}

// ValidatorKeyStoreImpl implements the shared.ValidatorKeyStore interface
type ValidatorKeyStoreImpl struct {
	keys          map[string]*crypto.PrivateKey
	mu            sync.RWMutex
	db            *Database
	encryptionKey []byte
}

// NewValidatorKeyStore creates and initializes a new ValidatorKeyStore
// In store/validator_store.go
func NewValidatorKeyStore(db *Database, encryptionKey []byte) types.ValidatorKeyStore {
	vks := &ValidatorKeyStoreImpl{
		keys:          make(map[string]*crypto.PrivateKey),
		mu:            sync.RWMutex{},
		db:            db,
		encryptionKey: encryptionKey,
	}
	// Load existing keys after creating the store
	if err := vks.LoadKeysFromDB(); err != nil {
		log.Printf("WARNING: Failed to load validator keys from DB: %v", err)
		// Decide if this should be fatal or just a warning
	}
	return vks
}
func (vks *ValidatorKeyStoreImpl) LoadKeysFromDB() error {
	vks.mu.Lock() // Lock should cover access to vks.keys map
	defer vks.mu.Unlock()

	// --- Declare prefix HERE, before it's used ---
	prefix := []byte("validator_privkey:")
	// ---

	log.Printf("DEBUG: Starting LoadKeysFromDB scan with prefix '%s'", string(prefix)) // Now prefix is defined
	loadedCount := 0

	// It's generally safer to unlock reads/writes to the vks.keys map
	// before starting potentially long DB operations if possible,
	// but loading needs to populate the map, so the lock must cover the loop.

	err := vks.db.GetDB().View(func(txn *badger.Txn) error {
		opts := badger.DefaultIteratorOptions
		opts.Prefix = prefix // Use the defined prefix
		it := txn.NewIterator(opts)
		defer it.Close()

		// Reset the keys map before loading to ensure clean state
		// Note: This assumes LoadKeysFromDB is ONLY called during initialization
		// before any other StoreKey operations might happen concurrently.
		// If LoadKeysFromDB could be called later, clearing the map needs careful thought.
		vks.keys = make(map[string]*crypto.PrivateKey) // Start with a fresh map

		for it.Rewind(); it.ValidForPrefix(prefix); it.Next() {
			item := it.Item()
			dbKey := item.Key()
			// It's safer to copy the key bytes immediately as they might be reused by the iterator
			dbKeyCopy := bytes.Clone(dbKey)
			addrBytes := bytes.TrimPrefix(dbKeyCopy, prefix)
			address := string(addrBytes)
			log.Printf("DEBUG: LoadKeys: Found potential key in DB: %s (Address: %s)", string(dbKeyCopy), address)

			// Copy the value immediately as well
			val, err := item.ValueCopy(nil) // Use ValueCopy to get a safe copy
			if err != nil {
				log.Printf("ERROR: LoadKeys: Failed reading DB value for key %s: %v", string(dbKeyCopy), err)
				continue // Skip this item if value reading fails
			}

			log.Printf("DEBUG: LoadKeys: Reading value for %s (Length: %d)", address, len(val))
			keyBytes := val // Use the copied value

			// --- Optional Decryption ---
			// decryptedBytes, errDecrypt := decrypt(keyBytes, vks.encryptionKey)
			// if errDecrypt != nil {
			//     log.Printf("ERROR: LoadKeys: Failed decrypt for %s: %v", address, errDecrypt)
			//     continue // Skip this item if decryption fails
			// }
			// finalKeyBytes := decryptedBytes
			// --- End Optional Decryption ---
			finalKeyBytes := keyBytes // Use raw bytes if not encrypting

			// Unmarshal bytes into a new key object
			privKey, errUnmarshal := crypto.NewPrivateKeyFromBytes(finalKeyBytes) // Use finalKeyBytes
			if errUnmarshal != nil {
				log.Printf("ERROR: LoadKeys: Failed to unmarshal key for address %s: %v", address, errUnmarshal)
				continue // Skip this key if unmarshal fails
			}

			// If unmarshal succeeded:
			keyInterface := crypto.PrivateKey(privKey)
			vks.keys[address] = &keyInterface // Store pointer to the newly created interface value
			loadedCount++
			log.Printf("DEBUG: LoadKeys: Successfully loaded and mapped key for %s", address)
		}
		return nil // Return nil from the View function if iteration completed
	})

	if err != nil {
		// This error is from the db.View() call itself or the iterator setup/loop
		return fmt.Errorf("failed to iterate over validator keys in DB: %w", err)
	}

	log.Printf("Finished loading %d validator keys from DB.", loadedCount)
	return nil
}

// StoreKey stores a private key for a validator
func (vks *ValidatorKeyStoreImpl) StoreKey(address string, key *crypto.PrivateKey) error {
	if key == nil || *key == nil {
		return fmt.Errorf("attempted to store nil key for address %s", address)
	}
	vks.mu.Lock()
	defer vks.mu.Unlock()

	// Marshal the key to bytes (Assuming your crypto.PrivateKey interface has Marshal)
	keyBytes, err := (*key).Marshal() // Dereference pointer, call Marshal
	if err != nil {
		return fmt.Errorf("failed to marshal private key for %s: %w", address, err)
	}

	// --- Optional Encryption ---
	// encryptedBytes, err := encrypt(keyBytes, vks.encryptionKey)
	// if err != nil { return fmt.Errorf("failed to encrypt key for %s: %w", address, err)}
	// finalBytesToStore := encryptedBytes
	// --- End Optional Encryption ---
	finalBytesToStore := keyBytes // Use raw bytes if not encrypting

	dbKey := []byte("validator_privkey:" + address) // Use a distinct prefix

	// Inside StoreKey, after saving to DB:
	if err := vks.db.Set(dbKey, finalBytesToStore); err != nil {
		return fmt.Errorf("failed to save private key to DB for %s: %w", address, err)
	}
	// Add this:
	log.Printf("DEBUG: Successfully saved key bytes to DB for %s", address)

	// The in-memory map vks.keys will only be populated by LoadKeysFromDB when the node starts (or if you add a manual reload function).
	log.Printf("Stored private key for %s in memory map and DB marker", address) // Adjust log
	return nil
}

// GetKey retrieves a private key for a validator
func (vks *ValidatorKeyStoreImpl) GetKey(address string) (*crypto.PrivateKey, bool) {
	vks.mu.RLock()
	defer vks.mu.RUnlock()
	key, exists := vks.keys[address]
	return key, exists
}

// RemoveKey removes a private key for a validator
func (vks *ValidatorKeyStoreImpl) RemoveKey(address string) error {
	vks.mu.Lock()
	defer vks.mu.Unlock()
	delete(vks.keys, address)
	return vks.db.Delete([]byte("validator:" + address))
}

// HasKey checks if a key exists for a validator
func (vks *ValidatorKeyStoreImpl) HasKey(address string) bool {
	vks.mu.RLock()
	defer vks.mu.RUnlock()
	_, exists := vks.keys[address]
	return exists
}

// GetAllAddresses returns all addresses that have stored keys
func (vks *ValidatorKeyStoreImpl) GetAllAddresses() []string {
	vks.mu.RLock()
	defer vks.mu.RUnlock()
	addresses := make([]string, 0, len(vks.keys))
	for addr := range vks.keys {
		addresses = append(addresses, addr)
	}
	return addresses
}
