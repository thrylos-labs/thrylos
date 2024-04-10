package main

import (
	"Thrylos/core" // Adjust this import to match your project's structure
	"crypto/ed25519"
	"encoding/base64"
	"flag"
	"fmt"
	"log"
)

// Simulate or actually retrieve the account from your test accounts
func getAccountByAddress(address string, testAccounts []core.Account) (*core.Account, error) {
	for _, account := range testAccounts {
		if account.Address == address {
			return &account, nil
		}
	}
	return nil, fmt.Errorf("account not found for address: %s", address)
}

func signTransaction(account *core.Account, transactionData []byte) (string, error) {
	// Signing the transaction using the private key of the account
	signature := ed25519.Sign(account.PrivateKey, transactionData)
	return base64.StdEncoding.EncodeToString(signature), nil
}

func main() {
	// Assuming you have some way to populate this for the CLI usage
	var testAccounts []core.Account

	address := flag.String("address", "", "Address of the account to use for signing")
	data := flag.String("data", "", "Transaction data to sign")
	flag.Parse()

	if *address == "" || *data == "" {
		log.Fatalf("Usage: %s -address=<account_address> -data=<transaction_data>", flag.CommandLine.Name())
	}

	account, err := getAccountByAddress(*address, testAccounts)
	if err != nil {
		log.Fatalf("Error retrieving account: %v", err)
	}

	transactionData := []byte(*data)
	signature, err := signTransaction(account, transactionData)
	if err != nil {
		log.Fatalf("Error signing transaction: %v", err)
	}

	fmt.Printf("Signature: %s\n", signature)
}
