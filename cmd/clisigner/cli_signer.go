package main

import (
	"Thrylos/shared"
	"flag"
	"fmt"
	"log"
)

// Example of CLI command integration for creating and signing a transaction
func main() {
	sender := flag.String("sender", "", "Sender address")
	receiver := flag.String("receiver", "", "Receiver address")
	amount := flag.Int("amount", 0, "Amount to transfer")
	flag.Parse()

	if *sender == "" || *receiver == "" || *amount == 0 {
		log.Fatal("Sender, receiver, and amount must be provided")
	}

	// Generate or retrieve keys and AES key
	_, senderPrivateKey, _ := shared.GenerateEd25519Keys() // Ideally, you would load this from secure storage
	aesKey, _ := shared.GenerateAESKey()

	inputs := []shared.UTXO{{TransactionID: "prevTxID", Index: 0, OwnerAddress: *sender, Amount: 100}} // Example input
	outputs := []shared.UTXO{{TransactionID: "newTxID", Index: 0, OwnerAddress: *receiver, Amount: *amount}}

	// Create and sign the transaction
	transaction, err := shared.CreateAndSignTransaction("tx123", *sender, inputs, outputs, senderPrivateKey, aesKey)
	if err != nil {
		log.Fatalf("Failed to create and sign transaction: %v", err)
	}

	fmt.Printf("Transaction created and signed successfully: %+v\n", transaction)
}
