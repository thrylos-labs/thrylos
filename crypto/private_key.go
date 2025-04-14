// privateKey.go (Revised to match interfaces.go)
package crypto

import (
	"bytes"
	"crypto/rand"
	"errors"
	"fmt"
	"log" // For Fatalf as Sign doesn't return error

	"github.com/cloudflare/circl/sign/mldsa/mldsa44"
	"github.com/fxamacker/cbor/v2"
)

// --- privateKey Struct ---
type privateKey struct {
	privKey *mldsa44.PrivateKey
}

var _ PrivateKey = (*privateKey)(nil) // Interface assertion

// --- Functions ---

func NewPrivateKey() (PrivateKey, error) {
	_, key, err := mldsa44.GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("failed to generate mldsa44 key: %w", err)
	}
	return &privateKey{
		privKey: key,
	}, nil
}

func NewPrivateKeyFromMLDSA(key *mldsa44.PrivateKey) PrivateKey {
	if key == nil {
		return nil
	}
	return &privateKey{
		privKey: key,
	}
}

func NewPrivateKeyFromBytes(keyData []byte) (PrivateKey, error) {
	priv := &privateKey{}
	err := priv.Unmarshal(keyData)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal private key data: %w", err)
	}
	if priv.privKey == nil {
		return nil, errors.New("unmarshaling resulted in a nil underlying key")
	}
	return priv, nil
}

// --- Methods ---

func (p *privateKey) Bytes() []byte {
	if p.privKey == nil {
		return nil
	}
	return p.privKey.Bytes() // Assume packed bytes
}

func (p *privateKey) String() string {
	if p.privKey == nil {
		return "PrivateKey(nil)"
	}
	// Don't expose private key material
	return fmt.Sprintf("PrivateKey(len:%d)", len(p.Bytes()))
}

// Sign implements the interface which doesn't return error.
// Use log.Fatalf or panic on internal failure.
func (p *privateKey) Sign(data []byte) Signature {
	if p.privKey == nil {
		log.Fatalf("cannot sign with nil private key") // Fatalf as per interface contract (no error return)
		return nil                                     // Unreachable, but satisfies compiler
	}
	sigBytes := make([]byte, mldsa44.SignatureSize)
	ctx := []byte(nil)
	useRandomized := false

	err := mldsa44.SignTo(p.privKey, data, ctx, useRandomized, sigBytes)
	if err != nil {
		// Interface doesn't allow returning error, so we must terminate.
		log.Fatalf("mldsa44 signing failed: %v", err)
		return nil // Unreachable
	}

	// Use the constructor that returns the interface type directly
	// This constructor now returns nil on size mismatch, which SignTo shouldn't cause.
	sig := NewSignature(sigBytes)
	if sig == nil {
		// This indicates an internal logic error (SignatureSize mismatch)
		log.Fatalf("internal error: NewSignature failed for correctly sized bytes")
		return nil // Unreachable
	}
	return sig
}

func (p *privateKey) PublicKey() PublicKey {
	if p.privKey == nil {
		return nil
	}
	pub := p.privKey.Public().(*mldsa44.PublicKey)
	return &publicKey{pubKey: pub}
}

func (p *privateKey) Marshal() ([]byte, error) {
	if p.privKey == nil {
		return nil, errors.New("cannot marshal nil private key")
	}
	keyBytes := p.Bytes()
	if keyBytes == nil {
		return nil, errors.New("failed to get private key bytes for marshaling")
	}
	return cbor.Marshal(keyBytes)
}

func (p *privateKey) Unmarshal(data []byte) error {
	var keyBytes []byte
	err := cbor.Unmarshal(data, &keyBytes)
	if err != nil {
		return fmt.Errorf("cbor unmarshal failed: %w", err)
	}
	if len(keyBytes) == 0 {
		return errors.New("unmarshaled key data is empty")
	}
	if len(keyBytes) != mldsa44.PrivateKeySize {
		return fmt.Errorf("invalid private key size after cbor unmarshal: got %d, want %d", len(keyBytes), mldsa44.PrivateKeySize)
	}

	if p.privKey == nil {
		p.privKey = new(mldsa44.PrivateKey)
	}

	err = p.privKey.UnmarshalBinary(keyBytes)
	if err != nil {
		return fmt.Errorf("mldsa44 private key unmarshal binary failed: %w", err)
	}
	return nil
}

// Equal takes a pointer to a PrivateKey interface value.
func (p *privateKey) Equal(other *PrivateKey) bool {
	// 1. Check interface pointer
	if other == nil {
		return false
	}
	// 2. Dereference pointer
	otherInt := *other
	if otherInt == nil {
		return p.privKey == nil
	}
	// 3. Compare bytes via interface method
	return bytes.Equal(p.Bytes(), otherInt.Bytes())
}

// Helper function (ensure defined once)
// func min(a, b int) int { ... }
