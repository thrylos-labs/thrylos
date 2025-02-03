package address

import (
	"bytes"
	"fmt"

	mldsa "github.com/cloudflare/circl/sign/mldsa/mldsa44"

	"github.com/btcsuite/btcutil/bech32"
	"github.com/fxamacker/cbor/v2"
	"github.com/thrylos-labs/thrylos/crypto/hash"
)

const (
	AddressSize   = 32
	AddressPrefix = "tl"
)

type Address [AddressSize]byte

func New(pubKey *mldsa.PublicKey) (*Address, error) {
	hashBytes := hash.NewHash(pubKey.Bytes())
	addressBytes := hashBytes[:20]
	words, err := bech32.ConvertBits(addressBytes[:], 8, 5, true)
	fmt.Printf("words: %v, length: %v\n", words, len(words))
	if err != nil {
		return nil, fmt.Errorf("failed to convert public key to 5-bit words: %v", err)
	}
	var address Address
	copy(address[:], words)
	return &address, nil
}

func NullAddress() *Address {
	return &Address{}
}

func Validate(addr string) bool {
	_, decoded, err := bech32.Decode(addr)
	if err != nil {
		return false
	}
	if len(decoded) != AddressSize {
		return false
	}
	return true
}

func (a *Address) Bytes() []byte {
	return a[:]
}
func (a *Address) String() string {
	encoded, _ := bech32.Encode(AddressPrefix, a.Bytes())
	return encoded
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
