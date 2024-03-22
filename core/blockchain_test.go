package core

import (
	"Thrylos/shared"
	"crypto"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"testing"

	_ "github.com/mattn/go-sqlite3" // SQLite driver
)

func TestNewBlockchain(t *testing.T) {
	bc, err := NewBlockchain()
	if err != nil {
		t.Fatalf("Failed to create blockchain: %v", err)
	}

	if bc.Genesis == nil {
		t.Errorf("Genesis block is nil")
	}
	// Further checks can include validating the initial state of the blockchain, such as the number of blocks, initial UTXOs, etc.
}

func TestTransactionSignatureVerificationWithDifferentKey(t *testing.T) {
	// Generate Ed25519 keys for the first pair
	_, privateKey1, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("Error generating first Ed25519 key pair: %v", err)
	}

	// Generate a different Ed25519 key pair
	publicKey2, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("Error generating second Ed25519 key pair: %v", err)
	}

	// Assume CreateMockSignedTransaction now uses Ed25519 and returns a transaction compatible with Ed25519
	tx, err := shared.CreateMockSignedTransaction("txDifferentKey", privateKey1)
	if err != nil {
		t.Fatalf("Error creating mock signed transaction: %v", err)
	}

	// Assume VerifyTransactionSignature is updated for Ed25519 verification
	err = shared.VerifyTransactionSignature(tx, publicKey2)
	if err == nil {
		t.Error("Verification succeeded for transaction signed with a different key, which is unexpected")
	}
}

func TestValidTransactionSignatureVerification(t *testing.T) {
	// Generate Ed25519 keys for the first pair
	publicKey1, privateKey1, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("Error generating Ed25519 key pair: %v", err)
	}

	// Create a mock signed transaction with privateKey1
	tx, err := shared.CreateMockSignedTransaction("txValid", privateKey1)
	if err != nil {
		t.Fatalf("Error creating mock signed transaction: %v", err)
	}

	// Verify the transaction signature with publicKey1 (the correct matching public key)
	err = shared.VerifyTransactionSignature(tx, publicKey1)
	if err != nil {
		t.Errorf("Failed to verify valid transaction signature: %v", err)
	} else {
		t.Log("Signature verified successfully with the matching public key")
	}
}

func TestManualSigningAndVerification(t *testing.T) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("Failed to generate private key: %v", err)
	}
	publicKey := &privateKey.PublicKey

	// Example data to sign
	data := "This is a test."
	hashed := sha256.Sum256([]byte(data))

	// Sign the data
	signature, err := rsa.SignPKCS1v15(rand.Reader, privateKey, crypto.SHA256, hashed[:])
	if err != nil {
		t.Fatalf("Failed to sign data: %v", err)
	}

	// Verify the signature
	err = rsa.VerifyPKCS1v15(publicKey, crypto.SHA256, hashed[:], signature)
	if err != nil {
		t.Fatalf("Signature verification failed: %v", err)
	} else {
		t.Log("Signature verification succeeded.")
	}
}
