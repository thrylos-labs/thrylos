package shared

import (
	"github.com/thrylos-labs/thrylos/amount"
	"github.com/thrylos-labs/thrylos/crypto"
	"github.com/thrylos-labs/thrylos/crypto/mldsa44"
)

// Validator represents the basic validator information
type Validator struct {
	PublicKey crypto.PublicKey `cbor:"1,keyasint"`
	Number    int32            `cbor:"2,keyasint"`
	Stake     amount.Amount    `cbor:"3,keyasint"`
}

// ValidatorKeyStore defines the interface for validator key operations
type ValidatorKeyStore interface {
	StoreKey(address string, key *mldsa44.PrivateKey) error
	GetKey(address string) (*mldsa44.PrivateKey, bool)
	RemoveKey(address string) error
	HasKey(address string) bool
	GetAllAddresses() []string
}

// Helper methods for Validator struct
func (v *Validator) GetAddress() string {
	return v.PublicKey.String()
}

func (v *Validator) GetStake() amount.Amount {
	return v.Stake
}

// func (v *Validator) IsActive(minimumStake amount.Amount) bool {
// 	return v.Stake.IsGreaterThanOrEqual(minimumStake)
// }
