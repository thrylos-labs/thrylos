package main

import (
	"Thrylos/core"
	"database/sql"
	"fmt"
	"log"
	"net/http"

	_ "github.com/mattn/go-sqlite3"
	// Import your blockchain package
)

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

	// Start the HTTP server
	fmt.Println("Starting server on port 8080...")
	if err := http.ListenAndServe(":8080", nil); err != nil {
		log.Fatalf("Failed to start server: %v", err)
	}
}
