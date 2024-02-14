package core

import (
	"Thrylos/shared"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"testing"
)

// This test ensures your RSA keys are generated, stored, retrieved, and used correctly throughout your application.
func TestRSAKeyGenerationAndUsage(t *testing.T) {
	// Generate RSA keys
	privateKey, publicKey, err := shared.GenerateRSAKeys(2048)
	if err != nil {
		t.Fatalf("Failed to generate RSA keys: %v", err)
	}

	// Prepare a message for signing
	message := "Test message for RSA signature"
	hashed := sha256.Sum256([]byte(message))

	// Sign the message
	signature, err := rsa.SignPKCS1v15(rand.Reader, privateKey, crypto.SHA256, hashed[:])
	if err != nil {
		t.Fatalf("Failed to sign message: %v", err)
	}

	// Verify the signature
	err = rsa.VerifyPKCS1v15(publicKey, crypto.SHA256, hashed[:], signature)
	if err != nil {
		t.Fatalf("Failed to verify signature: %v", err)
	}

	// Check key sizes
	if privateKey.Size() != 256 { // 2048 bits / 8 = 256 bytes
		t.Errorf("Private key size is incorrect, expected 256 bytes, got %d", privateKey.Size())
	}
	if publicKey.Size() != 256 { // 2048 bits / 8 = 256 bytes
		t.Errorf("Public key size is incorrect, expected 256 bytes, got %d", publicKey.Size())
	}

	t.Log("RSA key generation, signing, and verification successful")
}
