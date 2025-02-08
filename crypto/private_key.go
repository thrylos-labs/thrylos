package crypto

import (
	"bytes"
	"crypto/rand"
	"log"

	"github.com/cloudflare/circl/sign/mldsa/mldsa44"
	"github.com/fxamacker/cbor/v2"
)

type privateKey struct {
	privKey *mldsa44.PrivateKey
}

func NewPrivateKey() (PrivateKey, error) {
	_, key, err := mldsa44.GenerateKey(rand.Reader)
	if err != nil {
		log.Fatalf("failed to generate key: %v", err)
		return nil, err
	}
	return &privateKey{
		privKey: key,
	}, nil
}

func (p privateKey) Bytes() []byte {
	return p.privKey.Bytes()
}

func (p privateKey) String() string {
	return string(p.Bytes())
}

func (p privateKey) Sign(data []byte) Signature {
	sig := make([]byte, mldsa44.SignatureSize)

	err := mldsa44.SignTo(p.privKey, data, nil, false, sig)
	if err != nil {
		log.Fatalf("failed to sign data: %v", err)
		return nil
	}
	return &signature{sig: sig}
}

func (p privateKey) PublicKey() PublicKey {
	pub := p.privKey.Public().(*mldsa44.PublicKey)
	return &publicKey{pubKey: pub}
}

func (p privateKey) Marshal() ([]byte, error) {
	pub, err := p.privKey.MarshalBinary()
	if err != nil {
		return nil, err
	}
	return cbor.Marshal(pub)
}

func (p privateKey) Unmarshal(data []byte) error {
	var d []byte
	err := cbor.Unmarshal(data, d)
	if err != nil {
		return err
	}
	return p.privKey.UnmarshalBinary(d)
}

func (p privateKey) Equal(other *PrivateKey) bool {
	return bytes.Equal(p.Bytes(), (*other).Bytes())
}
