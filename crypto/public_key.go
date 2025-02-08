package crypto

import (
	"bytes"
	"errors"

	"github.com/cloudflare/circl/sign/mldsa/mldsa44"
	"github.com/fxamacker/cbor/v2"
	"github.com/thrylos-labs/thrylos/crypto/address"
)

type publicKey struct {
	pubKey *mldsa44.PublicKey
}

func NewPublicKey(pubKey *mldsa44.PublicKey) PublicKey {
	return &publicKey{pubKey: pubKey}
}
func (p publicKey) Bytes() []byte {
	return p.pubKey.Bytes()
}

func (p publicKey) String() string {
	return string(p.Bytes())
}

func (p publicKey) Address() (*address.Address, error) {
	return address.New(p.pubKey)
}

func (p publicKey) Verify(data []byte, sig *Signature) error {
	if sig == nil {
		return errors.New("signature cannot be nil")
	}
	mldsaSig, ok := (*sig).(signature)
	if !ok {
		return errors.New("invalid signature type")
	}
	if !mldsa44.Verify(p.pubKey, data, nil, mldsaSig.Bytes()) {
		return errors.New("invalid signature")
	}
	return nil
}

func (p publicKey) Marshal() ([]byte, error) {
	pub, err := p.pubKey.MarshalBinary()
	if err != nil {
		return nil, err
	}
	return cbor.Marshal(pub)
}

func (p publicKey) Unmarshal(data []byte) error {
	var d []byte
	err := cbor.Unmarshal(data, d)
	if err != nil {
		return err
	}
	return p.pubKey.UnmarshalBinary(d)
}
func (p publicKey) Equal(other *PublicKey) bool {
	if other == nil {
		return false
	}
	return bytes.Equal(p.Bytes(), (*other).Bytes())
}
