package mldsa44

import (
	"bytes"
	"errors"

	mldsa "github.com/cloudflare/circl/sign/mldsa/mldsa44"
	"github.com/fxamacker/cbor/v2"
	"github.com/thrylos-labs/thrylos/crypto/address"
)

type PublicKey struct {
	pk mldsa.PublicKey
}

func NewPublicKey(publicKey mldsa.PublicKey) *PublicKey {
	return &PublicKey{pk: publicKey}
}
func (p *PublicKey) Bytes() []byte {
	return p.pk.Bytes()
}

func (p *PublicKey) String() string {
	return string(p.Bytes())
}

func (p *PublicKey) Marshal() ([]byte, error) {
	pub, err := p.pk.MarshalBinary()
	if err != nil {
		return nil, err
	}
	return cbor.Marshal(pub)
}

func (p *PublicKey) Unmarshal(data []byte) error {
	var d []byte
	err := cbor.Unmarshal(data, d)
	if err != nil {
		return err
	}
	return p.pk.UnmarshalBinary(d)
}

func (p *PublicKey) Verify(data []byte, signature *Signature) error {
	if signature == nil {
		return errors.New("signature cannot be nil")
	}
	if !mldsa.Verify(&p.pk, data, nil, signature.Bytes()) {
		return errors.New("invalid signature")
	}
	return nil
}

func (p *PublicKey) Address() (*address.Address, error) {
	return address.New(&p.pk)
}

func (p *PublicKey) Compare(other *PublicKey) bool {
	return bytes.Equal(p.Bytes(), other.Bytes())
}
