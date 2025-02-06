package store

import (
	"sync"

	"github.com/thrylos-labs/thrylos/crypto/mldsa44"
)

// ValidatorKeyStoreImpl implements the shared.ValidatorKeyStore interface
type ValidatorKeyStoreImpl struct {
	keys          map[string]*mldsa44.PrivateKey
	mu            sync.RWMutex
	db            *Database
	encryptionKey []byte
}

// NewValidatorKeyStore creates and initializes a new ValidatorKeyStore
// In store/validator_store.go
func NewValidatorKeyStore(database *Database, encryptionKey []byte) *ValidatorKeyStoreImpl {
	return &ValidatorKeyStoreImpl{
		keys:          make(map[string]*mldsa44.PrivateKey),
		mu:            sync.RWMutex{},
		db:            database,
		encryptionKey: encryptionKey,
	}
}

// StoreKey stores a private key for a validator
func (vks *ValidatorKeyStoreImpl) StoreKey(address string, key *mldsa44.PrivateKey) error {
	vks.mu.Lock()
	defer vks.mu.Unlock()
	vks.keys[address] = key
	// Persist to database
	return vks.db.Set([]byte("validator:"+address), key.Bytes())
}

// GetKey retrieves a private key for a validator
func (vks *ValidatorKeyStoreImpl) GetKey(address string) (*mldsa44.PrivateKey, bool) {
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
