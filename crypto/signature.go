package crypto

import (
	"bytes"
	"errors"

	"github.com/cloudflare/circl/sign/mldsa/mldsa44"
	"github.com/fxamacker/cbor/v2"
)

type signature struct {
	sig []byte
}

func NewSignature(sig []byte) Signature {
	return &signature{sig: sig}
}

func (s signature) Bytes() []byte {
	return s.sig
}

func (s signature) Verify(pubKey *PublicKey, data []byte) error {

	mldsaPubKey, ok := (*pubKey).(publicKey)
	if !ok {
		return errors.New("invalid public key type")
	}
	if !mldsa44.Verify(mldsaPubKey.pubKey, data, nil, s.Bytes()) {
		return errors.New("invalid signature")
	}
	return nil
}

func (s signature) VerifyWithSalt(pubKey *PublicKey, data, salt []byte) error {

	mldsaPubKey, ok := (*pubKey).(publicKey)
	if !ok {
		return errors.New("invalid public key type")
	}
	if !mldsa44.Verify(mldsaPubKey.pubKey, data, salt, s.Bytes()) {
		return errors.New("invalid signature")
	}
	return nil
}

func (s signature) String() string {
	return string(s.Bytes())
}

func (s signature) Marshal() ([]byte, error) {
	return cbor.Marshal(s.sig)
}

func (s signature) Unmarshal(data []byte) error {
	return cbor.Unmarshal(data, s.sig)
}

func (s signature) Equal(other Signature) bool {
	otherSig, ok := other.(Signature)
	if !ok {
		return false
	}
	return bytes.Equal(s.Bytes(), otherSig.Bytes())
}
