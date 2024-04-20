package main

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
)

// Simulate the Account structure for the CLI tool
type Account struct {
	Address          string
	PrivateKeyBase64 string             `json:"PrivateKey"` // For JSON unmarshalling of the base64-encoded key
	PrivateKey       ed25519.PrivateKey // For cryptographic operations, not unmarshalled from JSON
}

func extendPrivateKey(seed []byte) ed25519.PrivateKey {
	if len(seed) != 32 {
		log.Fatalf("Invalid seed length: %d", len(seed))
	}
	// In Go, the private key is the seed followed by the public key.
	publicKey := ed25519.NewKeyFromSeed(seed).Public().(ed25519.PublicKey)
	return append(seed, publicKey...)
}

// Read account data securely, for example from a secured JSON file (or other secure sources)
func getAccountByAddress(address string) (*Account, error) {
	data, err := ioutil.ReadFile("secure_accounts.json")
	if err != nil {
		log.Printf("Error reading secure accounts file: %v", err)
		return nil, err
	}

	var accounts []Account
	if err = json.Unmarshal(data, &accounts); err != nil {
		log.Printf("Error unmarshalling JSON data: %v", err)
		return nil, err
	}

	for _, acc := range accounts {
		log.Printf("Checking account: %s", acc.Address)
		if acc.Address == address {
			privateKeyData, err := base64.StdEncoding.DecodeString(acc.PrivateKeyBase64)
			if err != nil {
				log.Printf("Error decoding private key for address %s: %v", acc.Address, err)
				return nil, fmt.Errorf("error decoding private key for address %s: %v", acc.Address, err)
			}
			if len(privateKeyData) == 32 { // if it's just the seed
				privateKeyData = extendPrivateKey(privateKeyData)
			}
			acc.PrivateKey = privateKeyData
			log.Printf("Private key decoded and set for account: %s", acc.Address)
			return &acc, nil
		}
	}

	log.Printf("Account not found for address: %s", address)
	return nil, fmt.Errorf("account not found for address: %s", address)
}

func main() {
	address := flag.String("address", "", "Address of the account to use for signing")
	transactionData := flag.String("transaction", "", "Transaction data to sign in JSON format")
	flag.Parse()

	if *address == "" || *transactionData == "" {
		log.Fatalf("Both address and transaction data are required")
	}

	// Retrieve account details including the private key
	account, err := getAccountByAddress(*address)
	if err != nil {
		log.Fatalf("Failed to retrieve account details: %v", err)
	}

	signature, err := signTransaction(account.PrivateKey, []byte(*transactionData))
	if err != nil {
		log.Fatalf("Error signing transaction: %v", err)
	}

	fmt.Printf("Signature: %s\n", signature)
}

func signTransaction(privateKey ed25519.PrivateKey, transactionData []byte) (string, error) {
	signature := ed25519.Sign(privateKey, transactionData)
	return base64.StdEncoding.EncodeToString(signature), nil
}
