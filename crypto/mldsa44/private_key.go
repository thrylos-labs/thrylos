package mldsa44

import (
	"log"

	mldsa "github.com/cloudflare/circl/sign/mldsa/mldsa44"
)

type PrivateKey struct {
	sk mldsa.PrivateKey
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

func (p *PrivateKey) Compare(other *PrivateKey) bool {
	return string(p.Bytes()) == string(other.Bytes())
}
