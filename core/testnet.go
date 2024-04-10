package core

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"log"
	// Assuming "dilithium" is the package you use for Dilithium key generation and signing
)

// Account represents a blockchain account for testing, with a public/private key pair and address.
type Account struct {
	Address             string
	PublicKey           ed25519.PublicKey
	PrivateKey          ed25519.PrivateKey
	DilithiumPublicKey  []byte
	DilithiumPrivateKey []byte
}

// InitializeTestnetAccounts creates and initializes predefined accounts for the testnet.
// InitializeTestnetAccounts creates and initializes predefined accounts for the testnet.
// It's now a method of the Blockchain type.
func (bc *Blockchain) InitializeTestnetAccounts(predefinedAccountCount int) ([]Account, error) {
	var accounts []Account

	for i := 0; i < predefinedAccountCount; i++ {
		edPublicKey, edPrivateKey, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			return nil, err
		}

		diPublicKey, diPrivateKey, err := GenerateDilithiumKeys()
		if err != nil {
			return nil, err
		}

		address := PublicKeyToAddress(edPublicKey)

		account := Account{
			Address:             address,
			PublicKey:           edPublicKey,
			PrivateKey:          edPrivateKey,
			DilithiumPublicKey:  diPublicKey,
			DilithiumPrivateKey: diPrivateKey,
		}

		// Use the blockchain's database interface to insert or update public keys
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
// Placeholder for actual Dilithium key generation logic.
func GenerateDilithiumKeys() (publicKey []byte, privateKey []byte, err error) {
	// Simulate Dilithium key pair generation.
	// Replace this with actual Dilithium key generation logic.
	return []byte("simulated_dilithium_public_key"), []byte("simulated_dilithium_private_key"), nil
}

// Example function to log account details for debugging purposes.
func logAccountDetails(accounts []Account) {
	for i, account := range accounts {
		log.Printf("Account %d:\n", i)
		log.Printf("Address: %s\n", account.Address)
		log.Printf("Ed25519 Public Key: %s\n", base64.StdEncoding.EncodeToString(account.PublicKey))
		log.Printf("Dilithium Public Key: %s\n", base64.StdEncoding.EncodeToString(account.DilithiumPublicKey))
	}
}

// You can extend this file with more transaction handling, signing, and verification functionalities as needed for testing.
