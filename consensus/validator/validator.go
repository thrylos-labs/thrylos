package validator

import (
	"github.com/thrylos-labs/thrylos/shared"
)

type ValidatorImpl struct {
	*shared.Validator
}

type ValidatorKeyStoreImpl struct {
	*shared.ValidatorKeyStore
}

// func NewValidator(publicKey crypto.PublicKey, number int32, stake amount.Amount) *ValidatorImpl {
// 	return &ValidatorImpl{
// 		PublicKey: publicKey,
// 		Number:    number,
// 		Stake:     stake,
// 	}
// }
// func (v *ValidatorImpl) Address() *address.Address {
// 	addr, err := v.PublicKey.Address()
// 	if err != nil {
// 		return address.NullAddress()
// 	}
// 	return addr
// }

// func (v *ValidatorImpl) Marshal() ([]byte, error) {
// 	return cbor.Marshal(v)
// }

// func (v *ValidatorImpl) Unmarshal(data []byte) error {
// 	return cbor.Unmarshal(data, v)
// }

// func NewValidatorKeyStore() *ValidatorKeyStoreImpl {
// 	return &ValidatorKeyStoreImpl{
// 		keys: make(map[string]*mldsa44.PrivateKey),
// 	}
// }
// func (vks *ValidatorKeyStoreImpl) StoreKey(address string, privKey *mldsa44.PrivateKey) error {
// 	vks.mu.Lock()
// 	defer vks.mu.Unlock()

// 	vks.keys[address] = privKey
// 	return nil
// }

// func (vks *ValidatorKeyStoreImpl) GetKey(address string) (*mldsa44.PrivateKey, bool) {
// 	vks.mu.RLock()
// 	defer vks.mu.RUnlock()

// 	privateKey, exists := vks.keys[address]
// 	return privateKey, exists
// }
