package core_test

import (
	"Thrylos/shared"
	"crypto/rand"
	"crypto/rsa"
	"fmt"
	"testing"
)

// Generates RSA key pairs for testing purposes.
func generateTestKeyPairs() (*rsa.PrivateKey, *rsa.PublicKey, error) {
	privKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, nil, fmt.Errorf("error generating RSA key pair: %v", err)
	}
	return privKey, &privKey.PublicKey, nil
}

// Creates mock transactions and verifies their signature.
func CreateMockTransactions(t *testing.T) ([]shared.Transaction, error) {
	privKey, pubKey, err := generateTestKeyPairs()
	if err != nil {
		return nil, fmt.Errorf("failed to generate key pairs: %v", err)
	}

	inputUTXO := shared.UTXO{
		ID:            "utxo1",
		TransactionID: "tx0",
		Index:         0,
		OwnerAddress:  "Alice",
		Amount:        100,
	}

	outputUTXO := shared.UTXO{
		ID:            "utxo2",
		TransactionID: "tx1",
		Index:         0,
		OwnerAddress:  "Bob",
		Amount:        100,
	}

	// Create and sign the transaction
	tx, err := shared.CreateAndSignTransaction("tx1", []shared.UTXO{inputUTXO}, []shared.UTXO{outputUTXO}, privKey)
	if err != nil {
		return nil, fmt.Errorf("failed to create and sign transaction: %v", err)
	}

	// Verify the transaction signature
	isValid := shared.VerifyTransactionSignature(&tx, pubKey)
	if !isValid {
		t.Errorf("Transaction signature verification failed")
		return nil, fmt.Errorf("transaction signature verification failed")
	}

	return []shared.Transaction{tx}, nil
}

// Example test function that uses CreateMockTransactions
func TestTransactionSignatureVerification(t *testing.T) {
	_, err := CreateMockTransactions(t)
	if err != nil {
		t.Fatalf("CreateMockTransactions failed: %v", err)
	}
	// You can further test the transactions returned by CreateMockTransactions here
}
