package address

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"fmt"

	mldsa "github.com/cloudflare/circl/sign/mldsa/mldsa44"

	"github.com/btcsuite/btcutil/bech32"
	"github.com/fxamacker/cbor/v2"
	"github.com/thrylos-labs/thrylos/crypto/hash"
)

const (
	AddressSize   = 32
	AddressPrefix = "tl1"
)

type Address [AddressSize]byte

func New(pubKey *mldsa.PublicKey) (*Address, error) {
	pubKeyBytes := pubKey.Bytes()
	// 1. Log Input Public Key (as base64 for comparison)
	fmt.Println("BE: Input PK Base64:", base64.StdEncoding.EncodeToString(pubKeyBytes[:15])+"...") // Log first few bytes as base64
	// 2. Log Raw Bytes (first few)
	fmt.Println("BE: PK Bytes:", hex.EncodeToString(pubKeyBytes[:16]))

	hashBytes := hash.NewHash(pubKeyBytes)
	// 3. Log Full Hash
	fmt.Println("BE: Full Blake2b-256:", hex.EncodeToString(hashBytes[:]))

	addressBytes := hashBytes[:20]
	// 4. Log Truncated Hash (Address Bytes)
	fmt.Println("BE: Truncated Hash (Addr Bytes):", hex.EncodeToString(addressBytes[:]))

	words, err := bech32.ConvertBits(addressBytes[:], 8, 5, true)
	if err != nil {
		return nil, fmt.Errorf("failed to convert public key to 5-bit words: %v", err)
	}
	var address Address
	copy(address[:], words)

	// 6. Log Final Address (using the String method which now uses "tl")
	fmt.Println("BE: Final Address:", address.String())

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

func ConvertToBech32Address(pubKey *mldsa.PublicKey) (string, error) {
	addr, err := New(pubKey)
	if err != nil {
		return "", fmt.Errorf("failed to create address: %v", err)
	}
	return addr.String(), nil
}

// FromString converts a bech32 address string to an Address
func FromString(addr string) (*Address, error) {
	// First validate the bech32 address
	if !Validate(addr) {
		return nil, fmt.Errorf("invalid address format: %s", addr)
	}

	// Decode the bech32 address
	_, decoded, err := bech32.Decode(addr)
	if err != nil {
		return nil, fmt.Errorf("failed to decode bech32 address: %v", err)
	}

	// Convert back to 8-bit bytes
	converted, err := bech32.ConvertBits(decoded, 5, 8, false)
	if err != nil {
		return nil, fmt.Errorf("failed to convert bits: %v", err)
	}

	// Create a new Address
	var newAddr Address
	copy(newAddr[:], converted)

	return &newAddr, nil
}

func (a *Address) Bytes() []byte {
	return a[:]
}
func (a *Address) String() string {
	// Pass only the HRP "tl" to the Encode function
	hrp := "tl"
	encoded, _ := bech32.Encode(hrp, a.Bytes()) // Use "tl", not "tl1"
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
