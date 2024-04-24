package main

import (
	"Thrylos/database"
	"log"
)

// cmd % go run test_public_key_retrieval.go

func main() {
	// Ensure the database path is correct
	dbPath := "./database" // Adjust this path as necessary
	log.Println("Using database at:", dbPath)

	// Ensure the encryption key is correctly set up
	encryptionKey := []byte("b8Eq7a0EWz06Ova4VNRN8ad6TkzCZkxNXm926rtNM2I") // Ensure this key matches exactly
	log.Println("Using encryption key:", encryptionKey)

	db, err := database.InitializeDatabase(dbPath)
	if err != nil {
		log.Fatalf("Failed to initialize the database: %v", err)
	}

	blockchainDB := database.NewBlockchainDB(db, encryptionKey)

	address := "ec5e882d97f8b3d4dd510e4353a3a8aaf9b6a6ffefa0e0f81e2fe3d125550cf0"
	log.Println("Attempting to retrieve public key for address:", address)
	publicKey, err := blockchainDB.RetrieveEd25519PublicKey(address)
	if err != nil {
		log.Printf("Error retrieving public key: %s", err)
	} else {
		log.Printf("Successfully retrieved public key: %x", publicKey)
	}
}
