package core

import (
	"Thrylos/shared"
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"io/ioutil"
	"os"
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

func TestAES256EncryptionAndDecryption(t *testing.T) {
	// Generate an AES-256 key
	aesKey, err := shared.GenerateAESKey()
	if err != nil {
		t.Fatalf("Failed to generate AES-256 key: %v", err)
	}

	// Check key size
	if len(aesKey) != 32 { // 256 bits = 32 bytes
		t.Errorf("AES key size is incorrect, expected 32 bytes, got %d", len(aesKey))
	}

	// Prepare data for encryption
	plaintext := []byte("Test message for AES-256 encryption")

	// Encrypt the data
	encryptedData, err := shared.EncryptWithAES(aesKey, plaintext)
	if err != nil {
		t.Fatalf("Failed to encrypt data: %v", err)
	}

	// Decrypt the data
	decryptedData, err := shared.DecryptWithAES(aesKey, encryptedData)
	if err != nil {
		t.Fatalf("Failed to decrypt data: %v", err)
	}

	// Verify that decrypted data matches the original plaintext
	if !bytes.Equal(plaintext, decryptedData) {
		t.Fatalf("Decrypted data does not match original plaintext")
	}

	t.Log("AES-256 encryption and decryption successful")
}

func TestBase64EncodingAndDecoding(t *testing.T) {
	// Generate Ed25519 keys
	_, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("Failed to generate Ed25519 keys: %v", err)
	}

	// Encode the private key using base64
	encodedKey := base64.StdEncoding.EncodeToString(privateKey)
	if len(encodedKey) == 0 {
		t.Errorf("Base64 encoding failed, encoded key is empty")
	}

	// Decode the base64 encoded key
	decodedKey, err := base64.StdEncoding.DecodeString(encodedKey)
	if err != nil {
		t.Fatalf("Base64 decoding failed: %v", err)
	}

	// Compare the original and decoded keys
	if !ed25519.PrivateKey(decodedKey).Equal(privateKey) {
		t.Fatalf("Decoded key does not match the original private key")
	}

	t.Log("Base64 encoding and decoding of Ed25519 keys successful")
}

// Tested the public key ok

func TestInsertAndRetrieveEd25519PublicKey(t *testing.T) {
	// Set up the blockchain with a real database
	tempDir, err := ioutil.TempDir("", "blockchain_test")
	if err != nil {
		t.Fatalf("Failed to create temporary directory: %v", err)
	}
	defer os.RemoveAll(tempDir)

	aesKey, err := shared.GenerateAESKey()
	if err != nil {
		t.Fatalf("Failed to generate AES key: %v", err)
	}

	bc, err := NewBlockchain(tempDir, aesKey)
	if err != nil {
		t.Fatalf("Failed to create blockchain: %v", err)
	}

	// Use a valid hex address for the test
	address := "f291cd4ebab48ee218ab2226562c4ce460994ce7d19d6ffc8b97ea95c43bb6"
	publicKey, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("Failed to generate Ed25519 keys: %v", err)
	}

	// Test insertion
	err = bc.Database.InsertOrUpdateEd25519PublicKey(address, publicKey)
	if err != nil {
		t.Fatalf("Failed to insert Ed25519 public key: %v", err)
	}

	// Test retrieval
	retrievedKey, err := bc.Database.RetrieveEd25519PublicKey(address)
	if err != nil {
		t.Fatalf("Failed to retrieve Ed25519 public key: %v", err)
	}

	if !bytes.Equal(retrievedKey, publicKey) {
		t.Errorf("Retrieved key does not match the inserted key")
	}
}
