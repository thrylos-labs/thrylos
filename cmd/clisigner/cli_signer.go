package main

import (
	"Thrylos/core"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"os"
)

// Simulate the Account structure for the CLI tool
type Account struct {
	Address          string
	PrivateKeyBase64 string             `json:"PrivateKey"` // For JSON unmarshalling of the base64-encoded key
	PrivateKey       ed25519.PrivateKey // For cryptographic operations, not unmarshalled from JSON
}

// Read account data securely, for example from a secured JSON file (or other secure sources)
func getAccountByAddress(address string) (*Account, error) {
	data, err := ioutil.ReadFile("secure_accounts.json")
	if err != nil {
		return nil, err
	}

	var accounts []Account
	if err = json.Unmarshal(data, &accounts); err != nil {
		return nil, err
	}

	for i, acc := range accounts {
		if acc.Address == address {
			privateKeyData, err := base64.StdEncoding.DecodeString(acc.PrivateKeyBase64)
			if err != nil {
				return nil, fmt.Errorf("error decoding private key for address %s: %v", address, err)
			}
			acc.PrivateKey = ed25519.PrivateKey(privateKeyData)

			return &accounts[i], nil // Return the modified account with the decoded private key
		}
	}

	return nil, fmt.Errorf("account not found for address: %s", address)
}

func main() {
	address := flag.String("address", "", "Address of the account to use for signing")
	transactionData := flag.String("transaction", "", "Transaction data to sign in JSON format")
	dataDir := flag.String("data", "./blockchain_data", "Directory to store node's blockchain data")
	flag.Parse()

	if *address == "" || *transactionData == "" {
		log.Fatalf("Both address and transaction data are required")
	}

	// Fetch the Base64-encoded AES key from the environment variable
	base64Key := os.Getenv("AES_KEY_ENV_VAR")
	if base64Key == "" {
		log.Fatal("AES key is not set in environment variables")
	}

	// Decode the Base64-encoded key to get the raw bytes
	aesKey, err := base64.StdEncoding.DecodeString(base64Key)
	if err != nil {
		log.Fatalf("Error decoding AES key: %v", err)
	}

	// Initialize the blockchain using the data directory and decoded AES key
	blockchain, err := core.NewBlockchain(*dataDir, aesKey)
	if err != nil {
		log.Fatalf("Failed to initialize the blockchain: %v", err)
	}

	// Retrieve private key from blockchain database
	privateKeyBytes, err := blockchain.Database.RetrievePrivateKey(*address + "-ed25519") // Adjust for actual key type
	if err != nil {
		log.Fatalf("Error retrieving private key: %v", err)
	}

	privateKey := ed25519.PrivateKey(privateKeyBytes)
	signature, err := signTransaction(privateKey, []byte(*transactionData))
	if err != nil {
		log.Fatalf("Error signing transaction: %v", err)
	}

	fmt.Printf("Signature: %s\n", signature)
}

func signTransaction(privateKey ed25519.PrivateKey, transactionData []byte) (string, error) {
	signature := ed25519.Sign(privateKey, transactionData)
	return base64.StdEncoding.EncodeToString(signature), nil
}
