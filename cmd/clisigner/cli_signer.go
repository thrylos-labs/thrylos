package main

import (
	"Thrylos/core" // Adjust the import path based on your project's structure
	"crypto/ed25519"
	"encoding/base64"
	"flag"
	"fmt"
	"log"
)

// Assuming you have a way to instantiate or access your Blockchain object in the CLI utility
func getTestAccounts(blockchain *core.Blockchain) ([]core.Account, error) {
	// Directly using the InitializeTestnetAccounts for fetching test accounts
	return blockchain.InitializeTestnetAccounts(10) // or however many you need
}

func signTransaction(privateKey ed25519.PrivateKey, transactionData []byte) (string, error) {
	signature := ed25519.Sign(privateKey, transactionData)
	return base64.StdEncoding.EncodeToString(signature), nil
}

func main() {
	address := flag.String("address", "", "Address of the account to use for signing")
	transactionData := flag.String("transaction", "", "Transaction data to sign in JSON format")
	flag.Parse()

	if *address == "" || *transactionData == "" {
		log.Fatalf("Both address and transaction data are required")
	}

	// Here you would instantiate or access your Blockchain object
	// For this example, let's assume we can directly access it
	blockchain := &core.Blockchain{}
	testAccounts, err := getTestAccounts(blockchain)
	if err != nil {
		log.Fatalf("Error getting test accounts: %v", err)
	}

	var account *core.Account
	for _, acc := range testAccounts {
		if acc.Address == *address {
			account = &acc
			break
		}
	}
	if account == nil {
		log.Fatalf("No account found for the given address: %s", *address)
	}

	signature, err := signTransaction(account.PrivateKey, []byte(*transactionData))
	if err != nil {
		log.Fatalf("Error signing transaction: %v", err)
	}

	fmt.Printf("Signature: %s\n", signature)
}
