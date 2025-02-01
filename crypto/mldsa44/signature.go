package mldsa44

import (
	"errors"

	mldsa "github.com/cloudflare/circl/sign/mldsa/mldsa44"
	"github.com/fxamacker/cbor/v2"
)

type Signature struct {
	sig []byte
}

func (s *Signature) Bytes() []byte {
	return s.sig
}

func (s *Signature) Verify(pubKey *PublicKey, data []byte) error {
	if s == nil {
		return errors.New("signature cannot be nil")
	}
	if !mldsa.Verify(&pubKey.pk, data, nil, s.Bytes()) {
		return errors.New("invalid signature")
	}
	return nil
}
func (s *Signature) VerifyWithSalf(pubKey *PublicKey, data, salt []byte) error {
	if s == nil {
		return errors.New("signature cannot be nil")
	}
	if !mldsa.Verify(&pubKey.pk, data, salt, s.Bytes()) {
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

func (s *Signature) Compare(other Signature) bool {
	return string(s.Bytes()) == string(other.Bytes())
}
