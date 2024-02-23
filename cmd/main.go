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

	// Define main endpoints
	http.HandleFunc("/submit-transaction", node.SubmitTransactionHandler())
	http.HandleFunc("/get-block", node.GetBlockHandler())
	http.HandleFunc("/get-transaction", node.GetTransactionHandler())

	// Start the HTTP server
	fmt.Printf("Starting server on %s\n", *nodeAddress)
	if err := http.ListenAndServe(*nodeAddress, nil); err != nil {
		log.Fatalf("Failed to start server: %v", err)
	}
}
