package main

import (
	"Thrylos/core"
	"database/sql"
	"flag"
	"fmt"
	"log"
	"net/http"
	"strings"

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
	// Command-line flags for node configuration
	nodeAddress := flag.String("address", "localhost:8080", "Address for the node to listen on")
	knownPeers := flag.String("peers", "", "Comma-separated list of known peer addresses")
	flag.Parse()

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

	// Initialize a new node with the specified address and known peers
	peersList := []string{}
	if *knownPeers != "" {
		peersList = strings.Split(*knownPeers, ",")
	}

	// Initialize a new node with the specified address and known peers
	node := core.NewNode(*nodeAddress, peersList, nil, false)

	// Define HTTP routes and handlers
	http.HandleFunc("/status", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, "Blockchain status: %s", blockchain.Status())
	})

	http.HandleFunc("/submit-transaction", node.SubmitTransactionHandler())
	http.HandleFunc("/get-block", node.GetBlockHandler())
	http.HandleFunc("/get-transaction", node.GetTransactionHandler())

	// Start the HTTP server
	fmt.Printf("Starting server on %s\n", *nodeAddress)
	if err := http.ListenAndServe(*nodeAddress, nil); err != nil {
		log.Fatalf("Failed to start server: %v", err)
	}
}

// // submitTransactionHandler returns an HTTP handler function that processes transactions submissions.
// func submitTransactionHandler(bc *core.Blockchain) func(w http.ResponseWriter, r *http.Request) {
// 	return func(w http.ResponseWriter, r *http.Request) {
// 		var tx thrylos.Transaction
// 		err := json.NewDecoder(r.Body).Decode(&tx)
// 		if err != nil {
// 			http.Error(w, "Invalid transaction format", http.StatusBadRequest)
// 			return
// 		}

// 		// Add transaction to pending transactions
// 		bc.AddPendingTransaction(&tx)

// 		// Respond with success
// 		w.WriteHeader(http.StatusAccepted)
// 		fmt.Fprintf(w, "Transaction submitted successfully")
// 	}
// }

// // getBlockHandler returns an HTTP handlerfunction that queries blocks
// func getBlockHandler(bc *core.Blockchain) func(w http.ResponseWriter, r *http.Request) {
// 	return func(w http.ResponseWriter, r *http.Request) {
// 		// Extract block identifier from query parameters
// 		blockID := r.URL.Query().Get("id")

// 		// Validate input
// 		if blockID == "" {
// 			http.Error(w, "Block ID is required", http.StatusBadRequest)
// 			return
// 		}

// 		// Retrieve the block by ID
// 		block, err := bc.GetBlockByID(blockID)
// 		if err != nil {
// 			http.Error(w, "Block not found", http.StatusNotFound)
// 			return
// 		}

// 		// Convert the block to JSON
// 		blockJSON, err := json.Marshal(block)
// 		if err != nil {
// 			http.Error(w, "Failed to serialize block", http.StatusInternalServerError)
// 			return
// 		}

// 		w.Header().Set("Content-Type", "application/json")
// 		w.Write(blockJSON)
// 	}
// }

// // getTransactionHandler returns an HTTP handlerfunction that queries transactions
// func getTransactionHandler(bc *core.Blockchain) func(w http.ResponseWriter, r *http.Request) {
// 	return func(w http.ResponseWriter, r *http.Request) {
// 		// Extract transaction identifier from query parameters
// 		txID := r.URL.Query().Get("id")

// 		// Validate input
// 		if txID == "" {
// 			http.Error(w, "Transaction ID is required", http.StatusBadRequest)
// 			return
// 		}

// 		// Retrieve the transaction by ID
// 		tx, err := bc.GetTransactionByID(txID)
// 		if err != nil {
// 			http.Error(w, "Transaction not found", http.StatusNotFound)
// 			return
// 		}

// 		// Convert the transaction to JSON
// 		txJSON, err := json.Marshal(tx)
// 		if err != nil {
// 			http.Error(w, "Failed to serialize transaction", http.StatusInternalServerError)
// 			return
// 		}

// 		w.Header().Set("Content-Type", "application/json")
// 		w.Write(txJSON)
// 	}
// }
