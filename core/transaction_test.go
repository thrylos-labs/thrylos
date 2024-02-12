package core

import (
	"Thrylos/shared"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"testing"
	"time"
)

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
func setupBlockchain() (*Blockchain, error) {
	// Initialize a new blockchain instance
	bc, err := NewBlockchain()
	if err != nil {
		return nil, fmt.Errorf("failed to initialize blockchain: %v", err)
	}

	// Simulate adding a genesis block if your blockchain doesn't automatically do this
	genesisBlock := NewGenesisBlock()
	bc.Blocks = append(bc.Blocks, genesisBlock)

	// Optionally, add more blocks or transactions as needed for your tests
	// For example, if you need to test with specific UTXOs or transaction patterns

	return bc, nil
}

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

	// Serialize the transaction without the signature for signing.
	txBytes, err := json.Marshal(tx)
	if err != nil {
		fmt.Printf("Error serializing transaction: %v\n", err)
		return nil // In real code, handle errors more gracefully.
	}

	// Sign the transaction.
	signature, err := signTransactionData(txBytes, privateKey)
	if err != nil {
		fmt.Printf("Error signing transaction: %v\n", err)
		return nil // In real code, handle errors more gracefully.
	}

	// Attach the signature to the transaction.
	tx.Signature = signature

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

func TestTransactionSignatureVerification(t *testing.T) {
	// Generate RSA keys
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("Error generating RSA key: %v", err)
	}
	publicKey := &privateKey.PublicKey

	// Create transactions and sign them with the generated private key
	// Adjust CreateMockTransactions to accept a private key for signing
	transactions := CreateMockTransactionsWithSigning(privateKey)
	if len(transactions) == 0 {
		t.Fatal("Failed to create mock transactions")
	}

	// Extract a transaction for testing
	tx := transactions[0]

	// Verify the transaction signature using the corresponding public key
	if !shared.VerifyTransactionSignature(&tx, publicKey) {
		t.Errorf("Transaction signature verification failed")
	} else {
		t.Log("Transaction signature verification succeeded.")
	}
}
