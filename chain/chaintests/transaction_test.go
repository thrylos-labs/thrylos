package chaintests

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"testing"
	"time"

	"github.com/cloudflare/circl/sign/mldsa/mldsa44"
	"github.com/thrylos-labs/thrylos/shared"
)

// ensure this import path is correct

// Verifying with a Different Public Key Than the One Used for Signing

func TestSignatureVerificationWithDifferentPublicKey(t *testing.T) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("Error generating RSA key: %v", err)
	}
	differentPrivateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("Error generating a different RSA key: %v", err)
	}

	// Use the public key from a different key pair for verification
	differentPublicKey := &differentPrivateKey.PublicKey

	serializedData := `{"ID":"tx1", ... }` // Simplified serialized data
	hashed := sha256.Sum256([]byte(serializedData))
	signature, err := rsa.SignPKCS1v15(rand.Reader, privateKey, crypto.SHA256, hashed[:])
	if err != nil {
		t.Fatalf("Error signing data: %v", err)
	}

	// Attempt to verify the signature with a different public key
	err = rsa.VerifyPKCS1v15(differentPublicKey, crypto.SHA256, hashed[:], signature)
	if err == nil {
		t.Errorf("Signature verification erroneously succeeded with a different public key")
	} else {
		t.Log("Correctly failed to verify signature with a different public key")
	}
}

// 2. Altering the Serialized Data After Signing but Before Verification
func TestSignatureVerificationWithAlteredData(t *testing.T) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("Error generating RSA key: %v", err)
	}
	publicKey := &privateKey.PublicKey

	serializedData := `{"ID":"tx1", ... }` // Original serialized data
	hashed := sha256.Sum256([]byte(serializedData))
	signature, err := rsa.SignPKCS1v15(rand.Reader, privateKey, crypto.SHA256, hashed[:])
	if err != nil {
		t.Fatalf("Error signing data: %v", err)
	}

	// Alter the serialized data
	alteredSerializedData := `{"ID":"tx1", "altered": true, ... }`
	alteredHashed := sha256.Sum256([]byte(alteredSerializedData))

	// Attempt to verify the signature with altered data
	err = rsa.VerifyPKCS1v15(publicKey, crypto.SHA256, alteredHashed[:], signature)
	if err == nil {
		t.Errorf("Signature verification erroneously succeeded with altered data")
	} else {
		t.Log("Correctly failed to verify signature with altered data")
	}
}

// 3. Testing with Invalid or Corrupted Signatures
func TestSignatureVerificationWithInvalidSignature(t *testing.T) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("Error generating RSA key: %v", err)
	}
	publicKey := &privateKey.PublicKey

	serializedData := `{"ID":"tx1", ... }` // Simplified serialized data
	hashed := sha256.Sum256([]byte(serializedData))

	// Generate a valid signature
	validSignature, err := rsa.SignPKCS1v15(rand.Reader, privateKey, crypto.SHA256, hashed[:])
	if err != nil {
		t.Fatalf("Error signing data: %v", err)
	}

	// Corrupt the signature by altering its contents
	invalidSignature := validSignature
	invalidSignature[0] ^= 0xFF // Flip bits in the first byte

	// Attempt to verify the signature with the corrupted data
	err = rsa.VerifyPKCS1v15(publicKey, crypto.SHA256, hashed[:], invalidSignature)
	if err == nil {
		t.Errorf("Signature verification erroneously succeeded with an invalid signature")
	} else {
		t.Log("Correctly failed to verify signature with an invalid signature")
	}
}

// setupBlockchain initializes a blockchain with predefined data for testing.

func TestSignatureVerificationSimplified(t *testing.T) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("Error generating keys: %v", err)
	}
	publicKey := &privateKey.PublicKey

	// Simulate transaction data
	data := "Test data"
	hashed := sha256.Sum256([]byte(data))

	// Sign the hashed data
	signature, err := rsa.SignPKCS1v15(rand.Reader, privateKey, crypto.SHA256, hashed[:])
	if err != nil {
		t.Fatalf("Error signing data: %v", err)
	}

	// Verify the signature
	if err := rsa.VerifyPKCS1v15(publicKey, crypto.SHA256, hashed[:], signature); err != nil {
		t.Errorf("Failed to verify signature: %v", err)
	} else {
		t.Log("Signature verification succeeded.")
	}
}

func CreateMockTransactionsWithSigning(privateKey *rsa.PrivateKey) []shared.Transaction {
	// Example: Creating a single mock transaction for simplicity.
	// In a real scenario, you might create several transactions based on your test requirements.

	// Mock transaction details.
	txID := "tx1"
	inputs := []shared.UTXO{
		{
			ID:            "utxo1",
			TransactionID: "tx0",
			Index:         0,
			OwnerAddress:  "Alice",
			Amount:        100,
		},
	}
	outputs := []shared.UTXO{
		{
			ID:            "utxo2",
			TransactionID: txID,
			Index:         0,
			OwnerAddress:  "Bob",
			Amount:        100,
		},
	}

	// Create a new transaction.
	tx := shared.Transaction{
		ID:        txID,
		Inputs:    inputs,
		Outputs:   outputs,
		Timestamp: time.Now().Unix(),
	}

	// 	// Serialize the transaction without the signature for signing.
	// 	txBytes, err := json.Marshal(tx)
	// 	if err != nil {
	// 		fmt.Printf("Error serializing transaction: %v\n", err)
	// 		return nil // In real code, handle errors more gracefully.
	// 	}

	// 	// Sign the transaction.
	// 	rawSignature, err := signTransactionData(txBytes, privateKey)
	// 	if err != nil {
	// 		fmt.Printf("Error signing transaction: %v\n", err)
	// 		return nil // In real code, handle errors more gracefully.
	// 	}

	// 	// Encode the raw signature (byte slice) into a Base64 string.
	// 	signature := base64.StdEncoding.EncodeToString([]byte(rawSignature))

	// 	// Attach the signature to the transaction.
	// 	tx.Signature = signature // The Signature field should be a string.

	// Return a slice containing the signed transaction.
	return []shared.Transaction{tx}
}

// signTransactionData signs the transaction data with the provided RSA private key and returns the base64-encoded signature.
func signTransactionData(data []byte, privateKey *rsa.PrivateKey) (string, error) {
	hashedData := sha256.Sum256(data)
	signature, err := rsa.SignPKCS1v15(rand.Reader, privateKey, crypto.SHA256, hashedData[:])
	if err != nil {
		return "", err
	}
	encodedSignature := base64.StdEncoding.EncodeToString(signature)
	return encodedSignature, nil
}

func TestTransactionSigningAndVerification1(t *testing.T) {
	// Step 1: Generate mldsa44 keys
	publicKey, privateKey, err := mldsa44.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("Failed to generate mldsa44 keys: %v", err)
	}

	// Step 2: Create a new transaction
	tx := shared.Transaction{
		ID:        "txTest123",
		Timestamp: 1630000000,
		Inputs:    []shared.UTXO{{TransactionID: "tx0", Index: 0, OwnerAddress: "Alice", Amount: 100}},
		Outputs:   []shared.UTXO{{TransactionID: "txTest123", Index: 0, OwnerAddress: "Bob", Amount: 100}},
	}

	// Step 3: Serialize the transaction (excluding the signature for now)
	serializedTx, err := json.Marshal(tx)
	if err != nil {
		t.Fatalf("Failed to serialize transaction: %v", err)
	}

	// Step 4: Sign the serialized transaction data with mldsa44
	signature := make([]byte, mldsa44.SignatureSize)
	if err := mldsa44.SignTo(privateKey, serializedTx, nil, false, signature); err != nil {
		t.Fatalf("Failed to sign transaction: %v", err)
	}

	// Step 5: Verify the signature with the mldsa44 public key
	if !mldsa44.Verify(publicKey, serializedTx, nil, signature) {
		t.Fatalf("Signature verification failed")
	}

	t.Log("Transaction signing and verification with mldsa44 successful")
}
