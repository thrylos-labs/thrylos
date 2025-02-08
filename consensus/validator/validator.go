package validator

import (
	"github.com/thrylos-labs/thrylos/crypto"
	"github.com/thrylos-labs/thrylos/shared"

	"github.com/fxamacker/cbor/v2"
	"github.com/thrylos-labs/thrylos/amount"
	"github.com/thrylos-labs/thrylos/crypto/address"
)

type validator struct {
	index      int32             `cbor:"2,keyasint"`
	privateKey crypto.PrivateKey `cbor:"1,keyasint"`
	stake      amount.Amount     `cbor:"3,keyasint"`
}

func NewValidator(privateKey crypto.PrivateKey, index int32, stake amount.Amount) shared.Validator {
	return &validator{
		index:      index,
		privateKey: privateKey,
		stake:      stake,
	}
}

func NewValidatorFromBytes(validatorData []byte) shared.Validator {
	v := validator{}
	err := cbor.Unmarshal(validatorData, v)
	if err != nil {
		return nil
	}
	return v
}
func (v validator) Index() int32 {
	return v.index
}
func (v validator) PrivateKey() *crypto.PrivateKey {
	return &v.privateKey
}
func (v validator) PublicKey() *crypto.PublicKey {
	pub := v.privateKey.PublicKey()
	return &pub
}

func (v validator) Address() *address.Address {
	pub := v.privateKey.PublicKey()
	addr, err := (pub).Address()
	if err != nil {
		return address.NullAddress()
	}
	return addr
}
func (v validator) Stake() amount.Amount {
	return v.stake
}

func (v validator) Marshal() ([]byte, error) {
	return cbor.Marshal(v)
}

func (v validator) Unmarshal(data []byte) error {
	return cbor.Unmarshal(data, v)
}
