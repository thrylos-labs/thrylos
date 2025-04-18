// signature.go (Revised to match interfaces.go)
package crypto

import (
	"bytes"
	"errors"
	"fmt"

	"github.com/cloudflare/circl/sign/mldsa/mldsa44"
	"github.com/fxamacker/cbor/v2"
)

type signature struct {
	sig []byte
}

const MLDSASignatureSize = mldsa44.SignatureSize

var _ Signature = (*signature)(nil) // Interface assertion

// NewSignature constructor matches provided code, returns interface
func NewSignature(sigBytes []byte) Signature {
	if len(sigBytes) != mldsa44.SignatureSize {
		// How to handle error if constructor must return Signature?
		// Option 1: Return nil interface (caller must check)
		// Option 2: Panic (less idiomatic)
		// Let's return nil interface for now.
		fmt.Printf("Error: NewSignature received invalid size %d, expected %d\n", len(sigBytes), mldsa44.SignatureSize) // Log error
		return nil
	}
	s := make([]byte, mldsa44.SignatureSize)
	copy(s, sigBytes)
	return &signature{sig: s}
}

// NewSignatureWithError is an alternative constructor if errors are preferred
func NewSignatureWithError(sigBytes []byte) (Signature, error) {
	if len(sigBytes) != mldsa44.SignatureSize {
		return nil, fmt.Errorf("invalid signature length: got %d, want %d", len(sigBytes), mldsa44.SignatureSize)
	}
	s := make([]byte, mldsa44.SignatureSize)
	copy(s, sigBytes)
	return &signature{sig: s}, nil
}

// Bytes returns a copy of the signature bytes.
func (s *signature) Bytes() []byte {
	if s.sig == nil {
		return nil
	}
	b := make([]byte, len(s.sig))
	copy(b, s.sig)
	return b
}

// Verify takes a pointer to a PublicKey interface value. Returns nil error on success.
func (s *signature) Verify(pubKey *PublicKey, data []byte) error {
	// 1. Check interface pointer
	if pubKey == nil {
		return errors.New("public key argument (pointer) cannot be nil")
	}
	// 2. Dereference pointer
	pubKeyInt := *pubKey
	if pubKeyInt == nil {
		return errors.New("public key interface value cannot be nil")
	}
	// 3. Check underlying signature data
	if s.sig == nil {
		return errors.New("cannot verify with nil signature data")
	}

	// 4. Type assert the dereferenced interface value
	mldsaPubKey, ok := pubKeyInt.(*publicKey)
	if !ok {
		return fmt.Errorf("invalid public key type: expected *crypto.publicKey, got %T", pubKeyInt)
	}
	if mldsaPubKey.pubKey == nil {
		return errors.New("underlying public key is nil")
	}

	sigBytes := s.Bytes() // Use Bytes() method
	if len(sigBytes) != mldsa44.SignatureSize {
		return fmt.Errorf("invalid signature size: got %d, want %d", len(sigBytes), mldsa44.SignatureSize)
	}

	ctx := []byte(nil) // Assume nil context
	isValid := mldsa44.Verify(mldsaPubKey.pubKey, data, ctx, sigBytes)

	if !isValid {
		return errors.New("invalid signature: mldsa44 verification failed")
	}
	return nil // Success
}

// VerifyWithSalt takes a pointer to a PublicKey interface value. Returns nil error on success.
func (s *signature) VerifyWithSalt(pubKey *PublicKey, data, salt []byte) error {
	// 1. Check interface pointer
	if pubKey == nil {
		return errors.New("public key argument (pointer) cannot be nil")
	}
	// 2. Dereference pointer
	pubKeyInt := *pubKey
	if pubKeyInt == nil {
		return errors.New("public key interface value cannot be nil")
	}
	// 3. Check underlying signature data
	if s.sig == nil {
		return errors.New("cannot verify with nil signature data")
	}

	// 4. Type assert the dereferenced interface value
	mldsaPubKey, ok := pubKeyInt.(*publicKey)
	if !ok {
		return fmt.Errorf("invalid public key type: expected *crypto.publicKey, got %T", pubKeyInt)
	}
	if mldsaPubKey.pubKey == nil {
		return errors.New("underlying public key is nil")
	}

	sigBytes := s.Bytes() // Use Bytes() method
	if len(sigBytes) != mldsa44.SignatureSize {
		return fmt.Errorf("invalid signature size: got %d, want %d", len(sigBytes), mldsa44.SignatureSize)
	}

	// Use provided salt as context
	isValid := mldsa44.Verify(mldsaPubKey.pubKey, data, salt, sigBytes)

	if !isValid {
		return errors.New("invalid signature: mldsa44 verification with salt failed")
	}
	return nil // Success
}

// String returns a hex-encoded representation.
func (s *signature) String() string {
	if s.sig == nil {
		return "Signature(nil)"
	}
	return fmt.Sprintf("SigHex:%x", s.sig) // Use internal slice ok here
}

func (s *signature) Marshal() ([]byte, error) {
	if s.sig == nil {
		return nil, errors.New("cannot marshal nil signature")
	}
	return cbor.Marshal(s.sig)
}

func (s *signature) Unmarshal(data []byte) error {
	var sigData []byte
	err := cbor.Unmarshal(data, &sigData) // Use pointer to slice
	if err != nil {
		return fmt.Errorf("cbor unmarshal failed: %w", err)
	}
	if len(sigData) == 0 {
		return errors.New("unmarshaled signature data is empty")
	}
	if len(sigData) != mldsa44.SignatureSize {
		return fmt.Errorf("invalid signature size after cbor unmarshal: got %d, want %d", len(sigData), mldsa44.SignatureSize)
	}
	s.sig = sigData // Assign the unmarshaled data
	return nil
}

// Equal takes a Signature interface value.
func (s *signature) Equal(other Signature) bool {
	if other == nil {
		return false // s (receiver) is not nil
	}
	// Compare bytes via Bytes() method
	return bytes.Equal(s.Bytes(), other.Bytes())
}
