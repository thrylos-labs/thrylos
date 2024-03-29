package core

import (
	"Thrylos/shared"
	"crypto/ed25519"
	"crypto/rand"
	"testing"

	"github.com/cloudflare/circl/sign/dilithium"
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

func TestEd25519Signature(t *testing.T) {
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("Ed25519 key generation failed: %v", err)
	}

	// Create a mock transaction (simplified representation)
	tx := "mock transaction"
	txBytes := []byte(tx)

	// Sign the transaction
	signature := ed25519.Sign(privateKey, txBytes)

	// Verify the signature
	if !ed25519.Verify(publicKey, txBytes, signature) {
		t.Fatal("Ed25519 signature verification failed")
	}

	t.Log("Ed25519 signature verification succeeded")
}

func TestDilithiumSignature(t *testing.T) {
	// Generate Dilithium keys
	diPublicKey, diPrivateKey, err := dilithium.Mode3.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("Dilithium key generation failed: %v", err)
	}

	// Create a mock transaction
	tx := "mock transaction"
	txBytes := []byte(tx)

	// Sign the transaction with the Dilithium private key
	signature := dilithium.Mode3.Sign(diPrivateKey, txBytes)

	// Convert the public key from bytes for verification, if needed
	// Since we already have diPublicKey as type PublicKey, we might not need to convert it from bytes in this context
	// However, if you are retrieving the public key from bytes, use the following line:
	// diPublicKeyFromBytes := dilithium.Mode3.PublicKeyFromBytes(diPublicKeyBytes)

	// Verify the signature with the Dilithium public key
	if !dilithium.Mode3.Verify(diPublicKey, txBytes, signature) {
		t.Fatal("Dilithium signature verification failed")
	}

	t.Log("Dilithium signature verification succeeded")
}

func TestDualSignedTransaction(t *testing.T) {
	edPublicKey, edPrivateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("Failed to generate Ed25519 keys: %v", err)
	}

	diPublicKeyBytes, diPrivateKeyBytes, err := shared.GenerateDilithiumKeys()
	if err != nil {
		t.Fatalf("Failed to generate Dilithium keys: %v", err)
	}

	// Convert byte slices back to Dilithium keys
	diPrivateKey := dilithium.Mode3.PrivateKeyFromBytes(diPrivateKeyBytes)
	diPublicKey := dilithium.Mode3.PublicKeyFromBytes(diPublicKeyBytes)

	// Create a mock transaction
	tx := "dual-signed transaction"
	txBytes := []byte(tx)

	// Sign with both keys
	edSignature := ed25519.Sign(edPrivateKey, txBytes)
	diSignature := dilithium.Mode3.Sign(diPrivateKey, txBytes)

	// Verify both signatures
	if !ed25519.Verify(edPublicKey, txBytes, edSignature) {
		t.Fatal("Failed to verify Ed25519 signature")
	}
	if !dilithium.Mode3.Verify(diPublicKey, txBytes, diSignature) {
		t.Fatal("Failed to verify Dilithium signature")
	}

	t.Log("Dual signature verification succeeded")
}

// func TestTransactionSignatureVerification(t *testing.T) {
// 	// Generate Ed25519 keys for the first pair
// 	publicKey1, privateKey1, err := ed25519.GenerateKey(rand.Reader)
// 	if err != nil {
// 		t.Fatalf("Error generating first Ed25519 key pair: %v", err)
// 	}

// 	// Generate a different Ed25519 key pair for testing failure
// 	publicKey2, _, err := ed25519.GenerateKey(rand.Reader)
// 	if err != nil {
// 		t.Fatalf("Error generating second Ed25519 key pair: %v", err)
// 	}

// 	// Generate Dilithium keys
// 	dilithiumPk1, dilithiumSk1, err := dilithium.Mode3.GenerateKey(rand.Reader)
// 	if err != nil {
// 		t.Fatalf("Error generating Dilithium key pair: %v", err)
// 	}

// 	// Generate a different Dilithium key pair for testing failure
// 	dilithiumPk2, _, err := dilithium.Mode3.GenerateKey(rand.Reader)
// 	if err != nil {
// 		t.Fatalf("Error generating a different Dilithium key pair: %v", err)
// 	}

// 	// Create a mock signed transaction with privateKey1 and dilithiumSk1
// 	tx, err := shared.CreateMockDualSignedTransaction("txDifferentKey", privateKey1, dilithiumSk1.Bytes())
// 	if err != nil {
// 		t.Fatalf("Error creating mock signed transaction: %v", err)
// 	}

// 	// Test case 1: Verify the transaction signature with the wrong keys (should fail)
// 	err = shared.VerifyTransactionSignature(tx, publicKey2, dilithiumPk2.Bytes())
// 	if err == nil {
// 		t.Error("Verification succeeded for transaction signed with a different key, which is unexpected")
// 	}

// 	// Test case 2: Verify the transaction signature with the correct keys (should succeed)
// 	err = shared.VerifyTransactionSignature(tx, publicKey1, dilithiumPk1.Bytes())
// 	if err != nil {
// 		t.Errorf("Verification failed for transaction signed with the correct keys: %v", err)
// 	}
// }

// func TestValidTransactionSignatureVerification(t *testing.T) {
// 	// Generate Ed25519 keys for the first pair
// 	publicKey1, privateKey1, err := ed25519.GenerateKey(rand.Reader)
// 	if err != nil {
// 		t.Fatalf("Error generating Ed25519 key pair: %v", err)
// 	}

// 	// Generate Dilithium keys
// 	dilithiumPk1, dilithiumSk1, err := dilithium.Mode3.GenerateKey(rand.Reader)
// 	if err != nil {
// 		t.Fatalf("Error generating Dilithium key pair: %v", err)
// 	}

// 	// Create a mock signed transaction with both privateKey1 and dilithiumSk1
// 	tx, err := shared.CreateMockDualSignedTransaction("txValid", privateKey1, dilithiumSk1.Bytes())
// 	if err != nil {
// 		t.Fatalf("Error creating mock signed transaction: %v", err)
// 	}

// 	// Verify the transaction signature with both publicKey1 and dilithiumPk1
// 	err = shared.VerifyTransactionSignature(tx, publicKey1, dilithiumPk1.Bytes())
// 	if err != nil {
// 		t.Errorf("Failed to verify valid transaction signature: %v", err)
// 	} else {
// 		t.Log("Signature verified successfully with the matching public key")
// 	}
// }

// func TestManualSigningAndVerification(t *testing.T) {
// 	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
// 	if err != nil {
// 		t.Fatalf("Failed to generate private key: %v", err)
// 	}
// 	publicKey := &privateKey.PublicKey

// 	// Example data to sign
// 	data := "This is a test."
// 	hashed := sha256.Sum256([]byte(data))

// 	// Sign the data
// 	signature, err := rsa.SignPKCS1v15(rand.Reader, privateKey, crypto.SHA256, hashed[:])
// 	if err != nil {
// 		t.Fatalf("Failed to sign data: %v", err)
// 	}

// 	// Verify the signature
// 	err = rsa.VerifyPKCS1v15(publicKey, crypto.SHA256, hashed[:], signature)
// 	if err != nil {
// 		t.Fatalf("Signature verification failed: %v", err)
// 	} else {
// 		t.Log("Signature verification succeeded.")
// 	}
// }

// func TestEd25519SigningAndVerification(t *testing.T) {
// 	// Generate Ed25519 key pair
// 	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
// 	if err != nil {
// 		t.Fatalf("Failed to generate Ed25519 key pair: %v", err)
// 	}

// 	// Example message
// 	message := []byte("Test message")

// 	// Sign the message
// 	signature := ed25519.Sign(privateKey, message)

// 	// Verify the signature
// 	if !ed25519.Verify(publicKey, message, signature) {
// 		t.Error("Failed to verify Ed25519 signature")
// 	} else {
// 		t.Log("Ed25519 signature verified successfully")
// 	}
// }

// func TestDilithiumSigningAndVerification(t *testing.T) {
// 	// Generate Dilithium key pair
// 	pk, sk, err := dilithium.Mode3.GenerateKey(rand.Reader)
// 	if err != nil {
// 		t.Fatalf("Failed to generate Dilithium key pair: %v", err)
// 	}

// 	// Example message
// 	message := []byte("Test message")

// 	// Sign the message
// 	signature := dilithium.Mode3.Sign(sk, message)

// 	// Verify the signature
// 	if !dilithium.Mode3.Verify(pk, message, signature) {
// 		t.Error("Failed to verify Dilithium signature")
// 	} else {
// 		t.Log("Dilithium signature verified successfully")
// 	}
// }
