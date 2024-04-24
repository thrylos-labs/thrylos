package main

import (
	"Thrylos/database"
	"fmt"
	"log"
	"regexp"
	"strings"
)

func main() {
	// Ensure the database path is correct
	dbPath := "/Users/ned/Documents/GitHub/thrylos/cmd/thrylosnode/node_data"
	log.Println("Using database at:", dbPath)

	// Ensure the encryption key is correctly set up
	encryptionKey := []byte("b8Eq7a0EWz06Ova4VNRN8ad6TkzCZkxNXm926rtNM2I") // Ensure this key matches exactly
	log.Println("Using encryption key:", encryptionKey)

	db, err := database.InitializeDatabase(dbPath)
	if err != nil {
		log.Fatalf("Failed to initialize the database: %v", err)
	}

	blockchainDB := database.NewBlockchainDB(db, encryptionKey)

	address := "52eb97e01605feebcdc870ec543cdd336c6559d2723e8364efab4e55d67008a0"
	// Sanitize and format the address before retrieval
	formattedAddress, err := sanitizeAndFormatAddress(address)
	if err != nil {
		log.Fatalf("Address formatting error: %v", err)
	}

	log.Println("Attempting to retrieve public key for address:", formattedAddress)
	publicKey, err := blockchainDB.RetrieveEd25519PublicKey(formattedAddress)
	if err != nil {
		log.Printf("Error retrieving public key for address %s: %s", formattedAddress, err)
	} else {
		log.Printf("Successfully retrieved public key: %x", publicKey)
	}
}

// sanitizeAndFormatAddress ensures the address is in the correct format and safe to use as a key.
func sanitizeAndFormatAddress(address string) (string, error) {
	// Adjust regex to include potential '0x' prefix and change length as necessary
	if !regexp.MustCompile(`^(0x)?[0-9a-fA-F]{40,64}$`).MatchString(address) {
		return "", fmt.Errorf("invalid address format")
	}
	// Optionally remove the '0x' prefix if present
	address = strings.TrimPrefix(address, "0x")
	return strings.ToLower(address), nil
}
