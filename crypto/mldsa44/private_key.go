package mldsa44

import (
	"bytes"
	"log"

	mldsa "github.com/cloudflare/circl/sign/mldsa/mldsa44"
)

type PrivateKey struct {
	sk mldsa.PrivateKey
}

func NewPrivateKey(key mldsa.PrivateKey) *PrivateKey {
	return &PrivateKey{
		sk: key,
	}
}

func (p *PrivateKey) Bytes() []byte {
	return p.sk.Bytes()
}

func (p *PrivateKey) String() string {
	return string(p.Bytes())
}

func (p *PrivateKey) Sign(data []byte) *Signature {
	signature := make([]byte, mldsa.SignatureSize)

	err := mldsa.SignTo(&p.sk, data, nil, false, signature)
	if err != nil {
		log.Fatalf("failed to sign data: %v", err)
		return nil
	}
	return &Signature{sig: signature}
}

func (p *PrivateKey) PublicKey() *PublicKey {
	pub := p.sk.Public().(*mldsa.PublicKey)
	return &PublicKey{pk: *pub}
}

func (p *PrivateKey) Equal(other *PrivateKey) bool {
	return bytes.Equal(p.Bytes(), other.Bytes())
}
