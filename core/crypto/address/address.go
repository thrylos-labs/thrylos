package address

import (
	"bytes"
	"encoding/hex"
	"log"

	"github.com/btcsuite/btcutil/bech32"
	"github.com/fxamacker/cbor/v2"
	"github.com/thrylos-labs/thrylos/core/crypto/hash"
)

const (
	AddressSize = 32
)

type Address [AddressSize]byte

func New(publicKeyBytes []byte) (*Address, error) {
	hashBytes := hash.NewHash(publicKeyBytes)
	encoded, err := bech32.Encode("mldsa", hashBytes.Bytes())
	if err != nil {
		log.Printf("error encoding the supplied public key bytes: %v", err)
		return nil, err
	}

	// Decode the hex string into a byte slice
	decoded, err := hex.DecodeString(encoded)
	if err != nil {
		log.Printf("error decoding string: %v", err)
		return nil, err
	}
	var address Address
	copy(address[:], decoded)
	return &address, nil
}

func (a *Address) Bytes() []byte {
	return a[:]
}
func (a *Address) String() string {
	return string(a[:])
}
func (a *Address) Marshal() ([]byte, error) {
	return cbor.Marshal(a[:])
}
func (a *Address) Unmarshal(data []byte) error {
	return cbor.Unmarshal(data, &a)
}
func (a *Address) Compare(other Address) bool {
	return bytes.Equal(a[:], other[:])
}
