package core

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"log"
	// Adjust the import path to where your database package is
)

// Account represents a blockchain account for testing, with a public key and address.
// The private key is not stored directly within the structure to ensure security.
type Account struct {
	Address            string
	PublicKey          ed25519.PublicKey
	DilithiumPublicKey []byte
	Balance            int // Added to keep track of the account balance
}

// InitializeTestnetAccounts creates and initializes predefined accounts for the testnet.
func (bc *Blockchain) InitializeTestnetAccounts(predefinedAccountCount int) ([]Account, error) {
	var accounts []Account
	startingBalance := 1000 // Set a starting balance for each test account

	for i := 0; i < predefinedAccountCount; i++ {
		edPublicKey, edPrivateKey, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			return nil, err
		}

		diPublicKey, diPrivateKey, err := GenerateDilithiumKeys() // Ensure this function securely generates keys
		if err != nil {
			return nil, err
		}

		address := PublicKeyToAddress(edPublicKey)

		// Encrypt and store the Ed25519 private key in the database
		if err := bc.Database.InsertOrUpdatePrivateKey(address+"-ed25519", edPrivateKey); err != nil {
			log.Fatalf("Error inserting/updating Ed25519 private key: %v", err)
		}

		// Encrypt and store the Dilithium private key in the database
		if err := bc.Database.InsertOrUpdatePrivateKey(address+"-dilithium", diPrivateKey); err != nil {
			log.Fatalf("Error inserting/updating Dilithium private key: %v", err)
		}

		account := Account{
			Address:            address,
			PublicKey:          edPublicKey,
			DilithiumPublicKey: diPublicKey,
			Balance:            startingBalance, // Set the starting balance
		}

		if err := bc.Database.InsertOrUpdateEd25519PublicKey(address, edPublicKey); err != nil {
			log.Fatalf("Error inserting/updating Ed25519 public key: %v", err)
		}
		if err := bc.Database.InsertOrUpdateDilithiumPublicKey(address, diPublicKey); err != nil {
			log.Fatalf("Error inserting/updating Dilithium public key: %v", err)
		}

		accounts = append(accounts, account)
	}

	return accounts, nil
}

// PublicKeyToAddress converts an Ed25519 public key to a blockchain address string.
func PublicKeyToAddress(publicKey ed25519.PublicKey) string {
	publicKeyHash := sha256.Sum256(publicKey)
	return hex.EncodeToString(publicKeyHash[:])
}

// GenerateDilithiumKeys generates a new Dilithium public/private key pair.
// Replace this with actual Dilithium key generation logic.
func GenerateDilithiumKeys() (publicKey []byte, privateKey []byte, err error) {
	// Simulate Dilithium key pair generation.
	return []byte("simulated_dilithium_public_key"), []byte("simulated_dilithium_private_key"), nil
}

// Example function to log account details for debugging purposes.
func logAccountDetails(accounts []Account) {
	for i, account := range accounts {
		log.Printf("Account %d:\n", i)
		log.Printf("Address: %s\n", account.Address)
		log.Printf("Ed25519 Public Key: %s\n", account.PublicKey)
		log.Printf("Balance: %d\n", account.Balance) // Now logging the balance as well
		// Don't log private keys!
	}
}

// You can extend this file with more transaction handling, signing, and verification functionalities as needed for testing.
