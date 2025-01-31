package mldsa44

import "github.com/fxamacker/cbor/v2"

type Signature struct {
	sig []byte
}

func (s *Signature) Bytes() []byte {
	return s.sig
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
