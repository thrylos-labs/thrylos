package chaintests

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"testing"
	"time"

	"github.com/cloudflare/circl/sign/mldsa/mldsa44"
	"github.com/thrylos-labs/thrylos/shared"
)

// ensure this import path is correct

// Verifying with a Different Public Key Than the One Used for Signing

func TestSignatureVerificationWithDifferentPublicKey(t *testing.T) {
	// Generate first key pair
	publicKey1, privateKey1, err := mldsa44.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("Error generating first MLDSA44 key pair: %v", err)
	}

	// Generate second key pair (different keys)
	publicKey2, _, err := mldsa44.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("Error generating second MLDSA44 key pair: %v", err)
	}

	// Create test data
	serializedData := []byte(`{"ID":"tx1"}`)

	// Sign with first private key
	signature := make([]byte, mldsa44.SignatureSize)
	if err := mldsa44.SignTo(privateKey1, serializedData, nil, false, signature); err != nil {
		t.Fatalf("Error signing data: %v", err)
	}

	// Verify with second public key (should fail)
	if mldsa44.Verify(publicKey2, serializedData, nil, signature) {
		t.Error("Signature verification erroneously succeeded with a different public key")
	} else {
		t.Log("Correctly failed to verify signature with a different public key")
	}

	// Verify with correct public key (should succeed)
	if !mldsa44.Verify(publicKey1, serializedData, nil, signature) {
		t.Error("Signature verification failed with correct public key")
	}
}

// 2. Altering the Serialized Data After Signing but Before Verification
func TestSignatureVerificationWithAlteredData(t *testing.T) {
	publicKey, privateKey, err := mldsa44.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("Error generating MLDSA44 key: %v", err)
	}

	// Original data
	originalData := []byte(`{"ID":"tx1"}`)

	// Sign original data
	signature := make([]byte, mldsa44.SignatureSize)
	if err := mldsa44.SignTo(privateKey, originalData, nil, false, signature); err != nil {
		t.Fatalf("Error signing data: %v", err)
	}

	// Alter the data
	alteredData := []byte(`{"ID":"tx1","altered":true}`)

	// Attempt to verify the signature with altered data
	if mldsa44.Verify(publicKey, alteredData, nil, signature) {
		t.Error("Signature verification erroneously succeeded with altered data")
	} else {
		t.Log("Correctly failed to verify signature with altered data")
	}

	// Verify original data still works
	if !mldsa44.Verify(publicKey, originalData, nil, signature) {
		t.Error("Signature verification failed with original unaltered data")
	}
}

// 3. Testing with Invalid or Corrupted Signatures
func TestSignatureVerificationWithInvalidSignature(t *testing.T) {
	publicKey, privateKey, err := mldsa44.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("Error generating MLDSA44 key: %v", err)
	}

	data := []byte(`{"ID":"tx1"}`)

	// Generate valid signature
	validSignature := make([]byte, mldsa44.SignatureSize)
	if err := mldsa44.SignTo(privateKey, data, nil, false, validSignature); err != nil {
		t.Fatalf("Error signing data: %v", err)
	}

	// Create corrupted signature by modifying bytes
	invalidSignature := make([]byte, len(validSignature))
	copy(invalidSignature, validSignature)
	invalidSignature[0] ^= 0xFF // Flip bits in the first byte

	// Verify with corrupted signature
	if mldsa44.Verify(publicKey, data, nil, invalidSignature) {
		t.Error("Signature verification erroneously succeeded with corrupted signature")
	} else {
		t.Log("Correctly failed to verify corrupted signature")
	}

	// Verify original signature still works
	if !mldsa44.Verify(publicKey, data, nil, validSignature) {
		t.Error("Signature verification failed with valid signature")
	}
}

// setupBlockchain initializes a blockchain with predefined data for testing.

func TestSignatureVerificationSimplified(t *testing.T) {
	publicKey, privateKey, err := mldsa44.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("Error generating MLDSA44 key: %v", err)
	}

	// Test data
	data := []byte("Test data")

	// Sign the data
	signature := make([]byte, mldsa44.SignatureSize)
	if err := mldsa44.SignTo(privateKey, data, nil, false, signature); err != nil {
		t.Fatalf("Error signing data: %v", err)
	}

	// Verify the signature
	if !mldsa44.Verify(publicKey, data, nil, signature) {
		t.Error("Failed to verify signature")
	} else {
		t.Log("Signature verification succeeded")
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
