// privateKey.go (Revised for Exporting)
package crypto

import (
	"bytes"
	"crypto/rand"
	"errors"
	"fmt"
	"log" // For Fatalf as Sign doesn't return error

	"github.com/cloudflare/circl/sign/mldsa/mldsa44"
)

// --- Exported PrivateKey Implementation Struct ---
// Renamed 'privateKey' to 'PrivateKeyImpl' (Uppercase P for export)
type PrivateKeyImpl struct {
	// Renamed 'privKey' to 'PrivKey' (Uppercase P for export)
	PrivKey *mldsa44.PrivateKey
}

// Update interface assertion to use the new exported type name
var _ PrivateKey = (*PrivateKeyImpl)(nil)

// --- Functions ---

func NewPrivateKey() (PrivateKey, error) {
	_, key, err := mldsa44.GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("failed to generate mldsa44 key: %w", err)
	}
	// Return the exported type, assigning to the exported field
	return &PrivateKeyImpl{
		PrivKey: key,
	}, nil
}

func NewPrivateKeyFromMLDSA(key *mldsa44.PrivateKey) PrivateKey {
	if key == nil {
		return nil
	}
	// Return the exported type, assigning to the exported field
	return &PrivateKeyImpl{
		PrivKey: key,
	}
}

func NewPrivateKeyFromBytes(keyData []byte) (PrivateKey, error) {
	// Use the exported type name here
	priv := &PrivateKeyImpl{}
	err := priv.Unmarshal(keyData)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal private key data: %w", err)
	}
	// Use the exported field name here
	if priv.PrivKey == nil {
		return nil, errors.New("unmarshaling resulted in a nil underlying key")
	}
	return priv, nil
}

// --- Methods ---
// Update receiver type and internal field access for ALL methods

func (p *PrivateKeyImpl) Bytes() []byte { // Receiver updated
	if p.PrivKey == nil { // Field updated
		return nil
	}
	return p.PrivKey.Bytes() // Field updated
}

func (p *PrivateKeyImpl) String() string { // Receiver updated
	if p.PrivKey == nil { // Field updated
		return "PrivateKey(nil)"
	}
	return fmt.Sprintf("PrivateKey(len:%d)", len(p.Bytes()))
}

func (p *PrivateKeyImpl) Sign(data []byte) Signature { // Receiver updated
	if p.PrivKey == nil { // Field updated
		log.Fatalf("cannot sign with nil private key")
		return nil
	}
	sigBytes := make([]byte, mldsa44.SignatureSize)
	ctx := []byte(nil)
	useRandomized := false

	// Use the exported field
	err := mldsa44.SignTo(p.PrivKey, data, ctx, useRandomized, sigBytes)
	if err != nil {
		log.Fatalf("mldsa44 signing failed: %v", err)
		return nil
	}

	sig := NewSignature(sigBytes)
	if sig == nil {
		log.Fatalf("internal error: NewSignature failed for correctly sized bytes")
		return nil
	}
	return sig
}

func (p *PrivateKeyImpl) PublicKey() PublicKey { // Receiver updated
	if p.PrivKey == nil { // Field updated
		return nil
	}
	// Use the exported field
	pub := p.PrivKey.Public().(*mldsa44.PublicKey)
	// Assuming publicKey struct name is correct (it was already exported)
	return &publicKey{pubKey: pub}
}

func (p *PrivateKeyImpl) Marshal() ([]byte, error) { // Receiver name may differ
	if p.PrivKey == nil { // Field name may differ
		return nil, errors.New("cannot marshal nil private key")
	}
	// Return raw bytes directly, like PublicKey.Marshal
	keyBytes := p.Bytes() // Assumes p.Bytes() returns raw mldsa44 bytes
	if keyBytes == nil {
		return nil, errors.New("failed to get private key bytes for marshaling")
	}
	log.Printf("DEBUG: [PrivateKeyImpl.Marshal] Returning %d raw bytes.", len(keyBytes))
	return keyBytes, nil // <<< REMOVED CBOR Marshal
}

// Unmarshal populates the private key from its raw binary representation.
func (p *PrivateKeyImpl) Unmarshal(data []byte) error { // Receiver name may differ
	log.Printf("DEBUG: [PrivKey Unmarshal] Input RAW data len: %d", len(data)) // Updated log

	// --- REMOVED CBOR Unmarshal Step ---
	// var keyBytes []byte
	// err := cbor.Unmarshal(data, &keyBytes)
	// if err != nil { return ... }
	// ---

	// Use the input 'data' directly as the raw key bytes
	keyBytes := data // <<< Use input data directly

	if len(keyBytes) == 0 {
		return errors.New("input key data is empty")
	}
	// Check against the expected *raw* key size for mldsa44
	if len(keyBytes) != mldsa44.PrivateKeySize {
		err := fmt.Errorf("invalid private key size: got %d, want %d", len(keyBytes), mldsa44.PrivateKeySize)
		log.Printf("ERROR: [PrivKey Unmarshal] %v", err)
		return err
	}

	// Use the exported field name (update if necessary)
	if p.PrivKey == nil {
		p.PrivKey = new(mldsa44.PrivateKey)
	}

	log.Printf("DEBUG: [PrivKey Unmarshal] Calling mldsa44 UnmarshalBinary...")
	// Unmarshal directly into the mldsa44 key object using the raw bytes
	err := p.PrivKey.UnmarshalBinary(keyBytes) // <<< USE keyBytes directly
	if err != nil {
		log.Printf("ERROR: [PrivKey Unmarshal] mldsa44 UnmarshalBinary failed: %v", err)
		return fmt.Errorf("mldsa44 private key unmarshal binary failed: %w", err)
	}
	log.Printf("DEBUG: [PrivKey Unmarshal] mldsa44 UnmarshalBinary succeeded.")
	return nil
}

func (p *PrivateKeyImpl) Equal(other *PrivateKey) bool { // Receiver updated
	if other == nil {
		return false
	}
	otherInt := *other
	if otherInt == nil {
		return p.PrivKey == nil // Field updated
	}
	return bytes.Equal(p.Bytes(), otherInt.Bytes())
}
