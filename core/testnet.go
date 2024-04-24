package core

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
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
			log.Printf("Failed to generate Ed25519 keys for account %d: %v", i, err)
			continue
		}

		diPublicKey, diPrivateKey, err := GenerateDilithiumKeys()
		if err != nil {
			log.Printf("Failed to generate Dilithium keys for account %d: %v", i, err)
			continue
		}

		address := PublicKeyToAddress(edPublicKey)
		if err := storeKeys(bc, address, edPrivateKey, diPrivateKey, edPublicKey); err != nil {
			log.Printf("Failed to store keys for address %s: %v", address, err)
			continue
		}

		account := Account{
			Address:            address,
			PublicKey:          edPublicKey,
			DilithiumPublicKey: diPublicKey,
			Balance:            startingBalance,
		}
		accounts = append(accounts, account)

		log.Printf("Successfully initialized account %s with public key and balance", address)
	}

	return accounts, nil
}

func storeKeys(bc *Blockchain, address string, edPrivateKey, diPrivateKey []byte, edPublicKey ed25519.PublicKey) error {
	if err := bc.Database.InsertOrUpdatePrivateKey(address+"-ed25519", edPrivateKey); err != nil {
		return fmt.Errorf("error inserting/updating Ed25519 private key: %v", err)
	}

	if err := bc.Database.InsertOrUpdatePrivateKey(address+"-dilithium", diPrivateKey); err != nil {
		return fmt.Errorf("error inserting/updating Dilithium private key: %v", err)
	}

	if err := bc.Database.InsertOrUpdateEd25519PublicKey(address, edPublicKey); err != nil {
		return fmt.Errorf("failed to insert Ed25519 public key: %v", err)
	}

	retrievedKey, err := bc.Database.RetrieveEd25519PublicKey(address)
	if err != nil {
		return fmt.Errorf("failed to retrieve Ed25519 public key: %v", err)
	}

	if !bytes.Equal(retrievedKey, edPublicKey) {
		return fmt.Errorf("verification failed: retrieved key does not match the inserted key")
	}

	log.Printf("Successfully verified public key for address %s", address)
	return nil
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
		log.Printf("Account %d: Address: %s, Balance: %d\n", i, account.Address, account.Balance)
		log.Printf("Address: %s\n", account.Address)
		log.Printf("Ed25519 Public Key: %s\n", account.PublicKey)
		log.Printf("Balance: %d\n", account.Balance) // Now logging the balance as well
		// Don't log private keys!
	}
}

// You can extend this file with more transaction handling, signing, and verification functionalities as needed for testing.
