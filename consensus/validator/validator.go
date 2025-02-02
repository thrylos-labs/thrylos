package validator

import (
	"github.com/fxamacker/cbor/v2"
	"github.com/thrylos-labs/thrylos/amount"
	"github.com/thrylos-labs/thrylos/crypto"
	"github.com/thrylos-labs/thrylos/crypto/address"
)

type Validator struct {
	PublicKey crypto.PublicKey `cbor:"1,keyasint"`
	Number    int32            `cbor:"2,keyasint"`
	Stake     amount.Amount    `cbor:"3,keyasint"`
}

func NewValidator(publicKey crypto.PublicKey, number int32, stake amount.Amount) *Validator {
	return &Validator{
		PublicKey: publicKey,
		Number:    number,
		Stake:     stake,
	}
}
func (v *Validator) Address() *address.Address {
	addr, err := v.PublicKey.Address()
	if err != nil {
		return address.NullAddress()
	}
	return addr
}

func (v *Validator) Marshal() ([]byte, error) {
	return cbor.Marshal(v)
}

func (v *Validator) Unmarshal(data []byte) error {
	return cbor.Unmarshal(data, v)
}

// type ValidatorKeyStore struct {
// 	keys map[string]*mldsa44.PrivateKey
// 	mu   sync.RWMutex
// }

// func NewValidatorKeyStore() *ValidatorKeyStore {
// 	return &ValidatorKeyStore{
// 		keys: make(map[string]*mldsa44.PrivateKey),
// 	}
// }
// func (vks *ValidatorKeyStore) StoreKey(address string, privKey *mldsa44.PrivateKey) error {
// 	vks.mu.Lock()
// 	defer vks.mu.Unlock()

// 	vks.keys[address] = privKey
// 	return nil
// }

// func (vks *ValidatorKeyStore) GetKey(address string) (*mldsa44.PrivateKey, bool) {
// 	vks.mu.RLock()
// 	defer vks.mu.RUnlock()

// 	privateKey, exists := vks.keys[address]
// 	return privateKey, exists
// }
