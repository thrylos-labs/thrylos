package main

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
)

// Transaction represents a simplified version of your transaction structure
type Transaction struct {
	ID        string
	Timestamp int64
}

// GenerateKeyPair generates a new RSA private and public key pair
func GenerateKeyPair(bits int) (*rsa.PrivateKey, *rsa.PublicKey, error) {
	privKey, err := rsa.GenerateKey(rand.Reader, bits)
	if err != nil {
		return nil, nil, err
	}
	return privKey, &privKey.PublicKey, nil
}

// SignTransaction creates a signature for the transaction using the private key
func SignTransaction(tx Transaction, privKey *rsa.PrivateKey) (string, error) {
	txData, err := json.Marshal(tx)
	if err != nil {
		return "", err
	}

	hashed := sha256.Sum256(txData)
	signature, err := rsa.SignPKCS1v15(rand.Reader, privKey, crypto.SHA256, hashed[:])
	if err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(signature), nil
}

// VerifySignature checks the signature of the transaction using the public key
func VerifySignature(tx Transaction, signature string, pubKey *rsa.PublicKey) bool {
	txData, err := json.Marshal(tx)
	if err != nil {
		fmt.Println("Failed to serialize transaction:", err)
		return false
	}

	sigBytes, err := base64.StdEncoding.DecodeString(signature)
	if err != nil {
		fmt.Println("Failed to decode signature:", err)
		return false
	}

	hashed := sha256.Sum256(txData)
	err = rsa.VerifyPKCS1v15(pubKey, crypto.SHA256, hashed[:], sigBytes)
	return err == nil
}

func main() {
	// Generate RSA keys
	privKey, pubKey, err := GenerateKeyPair(2048)
	if err != nil {
		fmt.Println("Error generating key pair:", err)
		os.Exit(1)
	}

	// Create a new transaction
	tx := Transaction{
		ID:        "tx123",
		Timestamp: 1234567890,
	}

	// Sign the transaction
	signature, err := SignTransaction(tx, privKey)
	if err != nil {
		fmt.Println("Error signing transaction:", err)
		os.Exit(1)
	}
	fmt.Println("Signature:", signature)

	// Verify the signature
	isValid := VerifySignature(tx, signature, pubKey)
	fmt.Println("Signature valid:", isValid)
}
