package shared

import (
	"github.com/thrylos-labs/thrylos/amount"
	"github.com/thrylos-labs/thrylos/crypto"
	"github.com/thrylos-labs/thrylos/crypto/address"
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
	StoreKey(address string, key *crypto.PrivateKey) error
	GetKey(address string) (*crypto.PrivateKey, bool)
	RemoveKey(address string) error
	HasKey(address string) bool
	GetAllAddresses() []string
}
