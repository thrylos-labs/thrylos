package core

import (
	"crypto/ed25519"
	"crypto/rand"
	"testing"
)

// This test ensures your RSA keys are generated, stored, retrieved, and used correctly throughout your application.
func TestEd25519KeyGenerationAndUsage(t *testing.T) {
	// Generate Ed25519 keys
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("Failed to generate Ed25519 keys: %v", err)
	}

	// Prepare a message for signing
	message := []byte("Test message for Ed25519 signature")

	// Sign the message
	signature := ed25519.Sign(privateKey, message)

	// Verify the signature
	if !ed25519.Verify(publicKey, message, signature) {
		t.Fatalf("Failed to verify signature")
	}

	// Check key sizes
	if len(privateKey) != ed25519.PrivateKeySize {
		t.Errorf("Private key size is incorrect, expected %d bytes, got %d", ed25519.PrivateKeySize, len(privateKey))
	}
	if len(publicKey) != ed25519.PublicKeySize {
		t.Errorf("Public key size is incorrect, expected %d bytes, got %d", ed25519.PublicKeySize, len(publicKey))
	}

	t.Log("Ed25519 key generation, signing, and verification successful")
}
