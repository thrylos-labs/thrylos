package main

import (
	thrylos "Thrylos"
	"Thrylos/core"
	"database/sql"
	"encoding/json"
	"fmt"
	"log"
	"net/http"

	_ "github.com/mattn/go-sqlite3"
	// Import your blockchain package
)

// TransactionRequest struct as defined previously
type TransactionRequest struct {
	Sender     string `json:"sender"`
	Receiver   string `json:"receiver"`
	Amount     int    `json:"amount"`
	PrivateKey string `json:"privateKey"` // Handle private keys securely
}

func main() {
	// Initialize the blockchain
	blockchain, err := core.NewBlockchain()
	if err != nil {
		log.Fatalf("Failed to initialize the blockchain: %v", err)
	}

	// Perform an integrity check on the blockchain
	if !blockchain.CheckChainIntegrity() {
		log.Fatal("Blockchain integrity check failed.")
	} else {
		fmt.Println("Blockchain integrity check passed.")
	}

	// Open the SQLite database
	db, err := sql.Open("sqlite3", "./blockchain.db")
	if err != nil {
		log.Fatalf("Failed to open database: %v", err)
	}
	defer db.Close()

	// Example: Adding a handler to get the blockchain status
	http.HandleFunc("/status", func(w http.ResponseWriter, r *http.Request) {
		// Implement logic to return the blockchain status
		// This might involve calling a method on the blockchain instance to get its current status or statistics.
		fmt.Fprintf(w, "Blockchain status: Operational")

	})

	// Define HTTP routes and handlers
	http.HandleFunc("/submit-transaction", submitTransactionHandler(blockchain))

	// Start the HTTP server
	fmt.Println("Starting server on port 8080...")
	if err := http.ListenAndServe(":8080", nil); err != nil {
		log.Fatalf("Failed to start server: %v", err)
	}
}

// submitTransactionHandler returns an HTTP handler function that processes transactions submissions.
func submitTransactionHandler(bc *core.Blockchain) func(w http.ResponseWriter, r *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		var tx thrylos.Transaction
		err := json.NewDecoder(r.Body).Decode(&tx)
		if err != nil {
			http.Error(w, "Invalid transaction format", http.StatusBadRequest)
			return
		}

		// Add transaction to pending transactions
		bc.AddPendingTransaction(&tx)

		// Respond with success
		w.WriteHeader(http.StatusAccepted)
		fmt.Fprintf(w, "Transaction submitted successfully")
	}
}
