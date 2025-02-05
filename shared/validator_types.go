package shared

import (
	"sync"

	"github.com/thrylos-labs/thrylos/amount"
	"github.com/thrylos-labs/thrylos/crypto"
	"github.com/thrylos-labs/thrylos/crypto/mldsa44"
)

type Validator struct {
	PublicKey crypto.PublicKey `cbor:"1,keyasint"`
	Number    int32            `cbor:"2,keyasint"`
	Stake     amount.Amount    `cbor:"3,keyasint"`
}

type ValidatorKeyStore struct {
	keys map[string]*mldsa44.PrivateKey
	mu   sync.RWMutex
}

// NewValidatorKeyStore creates and initializes a new ValidatorKeyStore
func NewValidatorKeyStore() *ValidatorKeyStore {
	return &ValidatorKeyStore{
		keys: make(map[string]*mldsa44.PrivateKey),
		mu:   sync.RWMutex{},
	}
}

// StoreKey stores a private key for a validator
func (vks *ValidatorKeyStore) StoreKey(address string, key *mldsa44.PrivateKey) {
	vks.mu.Lock()
	defer vks.mu.Unlock()
	vks.keys[address] = key
}

// GetKey retrieves a private key for a validator
func (vks *ValidatorKeyStore) GetKey(address string) (*mldsa44.PrivateKey, bool) {
	vks.mu.RLock()
	defer vks.mu.RUnlock()
	key, exists := vks.keys[address]
	return key, exists
}

// RemoveKey removes a private key for a validator
func (vks *ValidatorKeyStore) RemoveKey(address string) {
	vks.mu.Lock()
	defer vks.mu.Unlock()
	delete(vks.keys, address)
}

// HasKey checks if a key exists for a validator
func (vks *ValidatorKeyStore) HasKey(address string) bool {
	vks.mu.RLock()
	defer vks.mu.RUnlock()
	_, exists := vks.keys[address]
	return exists
}

// GetAllAddresses returns all addresses that have stored keys
func (vks *ValidatorKeyStore) GetAllAddresses() []string {
	vks.mu.RLock()
	defer vks.mu.RUnlock()
	addresses := make([]string, 0, len(vks.keys))
	for addr := range vks.keys {
		addresses = append(addresses, addr)
	}
	return addresses
}
