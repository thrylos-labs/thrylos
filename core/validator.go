package core

import (
	"sync"
	"time"

	"github.com/cloudflare/circl/sign/mldsa/mldsa44"
)

type ValidatorKeyStore struct {
	keys map[string]*mldsa44.PrivateKey
	mu   sync.RWMutex
}

func NewValidatorKeyStore() *ValidatorKeyStore {
	return &ValidatorKeyStore{
		keys: make(map[string]*mldsa44.PrivateKey),
	}
}
func (vks *ValidatorKeyStore) StoreKey(address string, privKey *mldsa44.PrivateKey) error {
	vks.mu.Lock()
	defer vks.mu.Unlock()

	vks.keys[address] = privKey
	return nil
}

func (vks *ValidatorKeyStore) GetKey(address string) (*mldsa44.PrivateKey, bool) {
	vks.mu.RLock()
	defer vks.mu.RUnlock()

	privateKey, exists := vks.keys[address]
	return privateKey, exists
}

type Validator struct {
	Address          string
	Stake            int64
	NewlyRegistered  bool
	RegistrationTime time.Time
}
