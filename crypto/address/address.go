package address

import (
	"bytes"
	"fmt"
	"log" // Added for logging errors in String()

	mldsa "github.com/cloudflare/circl/sign/mldsa/mldsa44"

	"github.com/btcsuite/btcutil/bech32" // Corrected import path based on usage
	"github.com/fxamacker/cbor/v2"
	"github.com/thrylos-labs/thrylos/crypto/hash"
)

const (
	// AddressWords is the number of 5-bit words in the data part of the Bech32 address.
	// Derived from 20 bytes hash -> 160 bits / 5 bits/word = 32 words.
	AddressWords = 32
	AddressHRP   = "tl" // Human-Readable Part
)

// Address now represents the 32 5-bit words of the data part.
type Address [AddressWords]byte // Changed size constant name for clarity

// New creates an Address (holding 5-bit words) from a public key.
func New(pubKey *mldsa.PublicKey) (*Address, error) {
	pubKeyBytes := pubKey.Bytes()
	// Optional logging...
	// fmt.Println("BE: Input PK Base64:", base64.StdEncoding.EncodeToString(pubKeyBytes[:15])+"...")
	// fmt.Println("BE: PK Bytes:", hex.EncodeToString(pubKeyBytes[:16]))

	hashBytes := hash.NewHash(pubKeyBytes) // Assuming Blake2b-256
	// fmt.Println("BE: Full Blake2b-256:", hex.EncodeToString(hashBytes[:]))

	addressBytes := hashBytes[:20] // Use first 20 bytes of hash
	// fmt.Println("BE: Truncated Hash (Addr Bytes):", hex.EncodeToString(addressBytes[:]))

	// Convert the 20 8-bit bytes to 32 5-bit words
	words, err := bech32.ConvertBits(addressBytes, 8, 5, true)
	if err != nil {
		return nil, fmt.Errorf("failed to convert public key hash to 5-bit words: %v", err)
	}
	if len(words) != AddressWords {
		// This should not happen if input is 20 bytes
		return nil, fmt.Errorf("unexpected number of words after conversion: got %d, want %d", len(words), AddressWords)
	}

	var address Address
	copy(address[:], words) // Copy the 32 5-bit words into the Address array

	// fmt.Println("BE: Final Address:", address.String()) // Logging uses the new String() method

	return &address, nil
}

// NullAddress creates a zeroed Address.
func NullAddress() *Address {
	return &Address{}
}

// Validate checks if a string is a valid Bech32 address with the correct HRP and data length.
func Validate(addr string) bool {
	hrp, decoded_5bit_words, err := bech32.Decode(addr)
	if err != nil {
		return false // Failed decoding
	}
	if hrp != AddressHRP {
		return false // Incorrect HRP
	}
	if len(decoded_5bit_words) != AddressWords {
		return false // Incorrect data length
	}
	return true
}

// ConvertToBech32Address derives the Bech32 string address from a public key.
func ConvertToBech32Address(pubKey *mldsa.PublicKey) (string, error) {
	addr, err := New(pubKey) // Creates Address with 5-bit words
	if err != nil {
		return "", fmt.Errorf("failed to create address object: %v", err)
	}
	return addr.String(), nil // Calls the corrected String() method
}

// FromString converts a bech32 address string to an Address (holding 5-bit words).
func FromString(addr string) (*Address, error) {
	hrp, decoded_5bit_words, err := bech32.Decode(addr)
	if err != nil {
		return nil, fmt.Errorf("failed to decode bech32 address '%s': %v", addr, err)
	}

	if hrp != AddressHRP {
		return nil, fmt.Errorf("invalid address HRP: expected '%s', got '%s'", AddressHRP, hrp)
	}

	if len(decoded_5bit_words) != AddressWords {
		return nil, fmt.Errorf("invalid decoded data length: expected %d words, got %d", AddressWords, len(decoded_5bit_words))
	}

	// Directly store the decoded 5-bit words
	var newAddr Address
	copy(newAddr[:], decoded_5bit_words) // <<< FIX: Store 5-bit words

	return &newAddr, nil
}

// Bytes returns the raw internal representation (32 5-bit words).
func (a *Address) Bytes() []byte {
	return a[:]
}

// String encodes the internal 5-bit words into a Bech32 string with the correct HRP.
func (a *Address) String() string {
	// Encode the stored 5-bit words (a.Bytes()) directly.
	encoded, err := bech32.Encode(AddressHRP, a.Bytes()) // <<< FIX: Encode stored words
	if err != nil {
		// Log the error, as String() doesn't return an error
		log.Printf("ERROR: Failed to encode address bytes to bech32: %v", err)
		return "" // Return empty string on encoding error
	}
	return encoded
}

// Marshal encodes the Address (as bytes) using CBOR.
func (a *Address) Marshal() ([]byte, error) {
	return cbor.Marshal(a[:]) // Marshal the raw byte slice
}

// Unmarshal decodes CBOR data into the Address.
func (a *Address) Unmarshal(data []byte) error {
	// Need to unmarshal into a slice first if the CBOR is just the byte array,
	// then copy into the fixed-size array.
	var slice []byte
	if err := cbor.Unmarshal(data, &slice); err != nil {
		return err
	}
	if len(slice) != AddressWords {
		return fmt.Errorf("unmarshaled data has incorrect length: expected %d, got %d", AddressWords, len(slice))
	}
	copy(a[:], slice)
	return nil
}

// Compare checks if two Addresses are identical.
func (a *Address) Compare(other Address) bool {
	return bytes.Equal(a[:], other[:])
}