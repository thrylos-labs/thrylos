package validator

import (
	thrycrypto "github.com/thrylos-labs/thrylos/crypto" // aliased to avoid confusion

	"github.com/fxamacker/cbor/v2"
	"github.com/thrylos-labs/thrylos/amount"
	"github.com/thrylos-labs/thrylos/crypto/address"
	"github.com/thrylos-labs/thrylos/shared"
)

type ValidatorImpl struct {
	*shared.Validator
}

type ValidatorKeyStoreImpl struct {
	*shared.ValidatorKeyStore
}

func NewValidator(publicKey thrycrypto.PublicKey, number int32, stake amount.Amount) *shared.Validator {
	return &shared.Validator{
		PublicKey: publicKey,
		Number:    number,
		Stake:     stake,
	}
}

func (v *ValidatorImpl) Address() *address.Address {
	addr, err := v.PublicKey.Address()
	if err != nil {
		return address.NullAddress()
	}
	return addr
}

func (v *ValidatorImpl) Marshal() ([]byte, error) {
	return cbor.Marshal(v)
}

func (v *ValidatorImpl) Unmarshal(data []byte) error {
	return cbor.Unmarshal(data, v)
}

func NewValidatorKeyStore() *shared.ValidatorKeyStore {
	return shared.NewValidatorKeyStore()
}
