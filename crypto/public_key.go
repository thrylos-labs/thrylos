// publicKey.go (Revised to match interfaces.go)
package crypto

import (
	"bytes"
	"errors"
	"fmt"
	"log"

	"github.com/cloudflare/circl/sign/mldsa/mldsa44"
	// "github.com/fxamacker/cbor/v2"
	"github.com/thrylos-labs/thrylos/crypto/address"
)

type publicKey struct {
	pubKey *mldsa44.PublicKey
}

var _ PublicKey = (*publicKey)(nil) // Interface assertion

func NewPublicKey(key *mldsa44.PublicKey) PublicKey {
	if key == nil {
		// Decide handling: return nil interface or error? Interface allows nil.
		return nil
	}
	return &publicKey{pubKey: key}
}

func NewPublicKeyFromBytes(keyData []byte) (PublicKey, error) {
	pub := &publicKey{}
	err := pub.Unmarshal(keyData) // Calls the *corrected* Unmarshal
	if err != nil {
		// Log the raw key data on error for debugging
		log.Printf("ERROR: NewPublicKeyFromBytes failed Unmarshal. Input keyData (hex, max 64 bytes): %x", keyData[:min(64, len(keyData))])
		return nil, fmt.Errorf("failed to unmarshal public key data: %w", err)
	}
	// This check might be redundant if UnmarshalBinary errors correctly, but safe to keep
	if pub.pubKey == nil {
		return nil, errors.New("unmarshaling resulted in a nil underlying key")
	}
	return pub, nil
}

func (p *publicKey) Bytes() []byte {
	if p.pubKey == nil {
		return nil
	}
	return p.pubKey.Bytes() // Assume this returns packed bytes
}

// String returns a hex-encoded representation.
func (p *publicKey) String() string {
	if p.pubKey == nil {
		return "PubKey(nil)"
	}
	return fmt.Sprintf("PubKeyHex:%x", p.Bytes())
}

func (p *publicKey) Address() (*address.Address, error) {
	if p.pubKey == nil {
		return nil, errors.New("cannot generate address from nil public key")
	}
	return address.New(p.pubKey)
}

// publicKey.go (Corrected Verify method)

// Verify checks the signature against the message using the public key.
// Takes a pointer to a Signature interface value. Returns nil error on success.
func (p *publicKey) Verify(data []byte, sigPtr *Signature) error { // Renamed parameter here
	// 1. Check interface pointer itself is not nil
	if sigPtr == nil { // Use new parameter name
		return errors.New("signature argument (pointer) cannot be nil")
	}
	// 2. Dereference the pointer to get the interface value
	sigInt := *sigPtr // Use new parameter name. sigInt is type Signature (interface)
	if sigInt == nil {
		return errors.New("signature interface value cannot be nil")
	}
	// 3. Check underlying key
	if p.pubKey == nil {
		return errors.New("cannot verify with nil public key")
	}

	// 4. Type assert the interface value sigInt to concrete type *signature
	// Now the compiler knows "signature" refers to the struct type.
	mldsaSig, ok := sigInt.(*signature)
	if !ok {
		return fmt.Errorf("invalid signature type: expected *crypto.signature, got %T", sigInt)
	}

	sigBytes := mldsaSig.Bytes() // Use the Bytes() method which should return a copy
	if len(sigBytes) != mldsa44.SignatureSize {
		return fmt.Errorf("invalid signature size: got %d, want %d", len(sigBytes), mldsa44.SignatureSize)
	}

	ctx := []byte(nil) // Assume nil context
	isValid := mldsa44.Verify(p.pubKey, data, ctx, sigBytes)

	if !isValid {
		return errors.New("invalid signature: mldsa44 verification failed")
	}
	return nil // Success
}

func (p *publicKey) Marshal() ([]byte, error) {
	if p.pubKey == nil {
		return nil, errors.New("cannot marshal nil public key")
	}
	// Return raw bytes directly, NO CBOR encoding
	keyBytes := p.Bytes() // Assumes p.Bytes() returns the raw mldsa44 bytes
	if keyBytes == nil {
		return nil, errors.New("failed to get public key bytes for marshaling")
	}
	log.Printf("DEBUG: [publicKey.Marshal] Returning %d raw bytes.", len(keyBytes))
	return keyBytes, nil
}

func (p *publicKey) Unmarshal(data []byte) error {
	// --- REMOVED CBOR Unmarshal Step ---
	// var keyBytes []byte
	// err := cbor.Unmarshal(data, &keyBytes)
	// if err != nil { ... }
	// ---

	// Use the input 'data' directly as the raw key bytes
	keyBytes := data
	log.Printf("DEBUG: [publicKey.Unmarshal] Received %d raw bytes to unmarshal directly.", len(keyBytes))

	if len(keyBytes) == 0 {
		return errors.New("input key data is empty")
	}
	// Check against the expected *raw* key size for mldsa44
	if len(keyBytes) != mldsa44.PublicKeySize {
		return fmt.Errorf("invalid public key size: got %d, want %d", len(keyBytes), mldsa44.PublicKeySize)
	}

	// Ensure the underlying key struct exists
	if p.pubKey == nil {
		p.pubKey = new(mldsa44.PublicKey)
	}

	// Unmarshal directly into the mldsa44 key object using the raw bytes
	err := p.pubKey.UnmarshalBinary(keyBytes) // <<< USE keyBytes directly
	if err != nil {
		return fmt.Errorf("mldsa44 public key unmarshal binary failed: %w", err)
	}
	log.Printf("DEBUG: [publicKey.Unmarshal] mldsa44PubKey.UnmarshalBinary successful.")
	return nil
}

// Equal takes a pointer to a PublicKey interface value.
func (p *publicKey) Equal(other *PublicKey) bool {
	// 1. Check interface pointer itself
	if other == nil {
		return false // p (receiver) isn't nil
	}
	// 2. Dereference pointer
	otherInt := *other
	if otherInt == nil {
		// Is p also effectively nil?
		return p.pubKey == nil
	}
	// 3. Compare bytes via the interface Bytes() method
	return bytes.Equal(p.Bytes(), otherInt.Bytes())
}
