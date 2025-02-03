package mldsa44

import (
	"bytes"
	"errors"

	mldsa "github.com/cloudflare/circl/sign/mldsa/mldsa44"
	"github.com/fxamacker/cbor/v2"
	"github.com/thrylos-labs/thrylos/crypto"
)

type Signature struct {
	sig []byte
}

func NewSignature(sig []byte) *Signature {
	return &Signature{sig: sig}
}

func (s *Signature) Bytes() []byte {
	return s.sig
}

func (s *Signature) Verify(pubKey *crypto.PublicKey, data []byte) error {
	if s == nil {
		return errors.New("signature cannot be nil")
	}
	mldsaPubKey, ok := (*pubKey).(*PublicKey)
	if !ok {
		return errors.New("invalid public key type")
	}
	if !mldsa.Verify(&mldsaPubKey.pk, data, nil, s.Bytes()) {
		return errors.New("invalid signature")
	}
	return nil
}

func (s *Signature) VerifyWithSalt(pubKey *crypto.PublicKey, data, salt []byte) error {
	if s == nil {
		return errors.New("signature cannot be nil")
	}
	mldsaPubKey, ok := (*pubKey).(*PublicKey)
	if !ok {
		return errors.New("invalid public key type")
	}
	if !mldsa.Verify(&mldsaPubKey.pk, data, salt, s.Bytes()) {
		return errors.New("invalid signature")
	}
	return nil
}

func (s *Signature) String() string {
	return string(s.Bytes())
}

func (s *Signature) Marshal() ([]byte, error) {
	return cbor.Marshal(s.sig)
}

func (s *Signature) Unmarshal(data []byte) error {
	return cbor.Unmarshal(data, s.sig)
}

func (s *Signature) Equal(other crypto.Signature) bool {
	otherSig, ok := other.(crypto.Signature)
	if !ok {
		return false
	}
	return bytes.Equal(s.Bytes(), otherSig.Bytes())
}
