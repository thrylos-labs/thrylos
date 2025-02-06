package shared

import (
	"github.com/thrylos-labs/thrylos/amount"
	"github.com/thrylos-labs/thrylos/crypto"
	"github.com/thrylos-labs/thrylos/crypto/address"
	"github.com/thrylos-labs/thrylos/crypto/mldsa44"
)

// Validator represents the basic validator information
type Validator interface {
	Index() int32
	PrivateKey() *crypto.PrivateKey
	PublicKey() *crypto.PublicKey
	Address() *address.Address
	Stake() amount.Amount
	Marshal() ([]byte, error)
	Unmarshal(data []byte) error
}

// ValidatorKeyStore defines the interface for validator key operations
type ValidatorKeyStore interface {
	StoreKey(address string, key *mldsa44.PrivateKey) error
	GetKey(address string) (*mldsa44.PrivateKey, bool)
	RemoveKey(address string) error
	HasKey(address string) bool
	GetAllAddresses() []string
}
