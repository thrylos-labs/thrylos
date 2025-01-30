package crypto

import (
	"bytes"

	"github.com/fxamacker/cbor/v2"
)

const (
	AddressSize = 21
)

type Address [AddressSize]byte

func (a Address) Bytes() []byte {
	return a[:]
}
func (a Address) String() string {
	return string(a[:])
}
func (a Address) Marshal() ([]byte, error) {
	return cbor.Marshal(a[:])
}
func (a Address) Unmarshal(data []byte) error {
	return cbor.Unmarshal(data, &a)
}
func (a Address) Compare(other Address) bool {
	return bytes.Equal(a[:], other[:])
}
