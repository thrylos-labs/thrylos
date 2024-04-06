package main

import (
	"Thrylos/core"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"net/http"
	"strings"

	"github.com/rs/cors"
	// Import your blockchain package
)

func main() {
	// Command-line flags for node configuration
	nodeAddress := flag.String("address", "localhost:8080", "Address for the node to listen on")
	knownPeers := flag.String("peers", "", "Comma-separated list of known peer addresses")
	nodeDataDir := flag.String("data", "./blockchain_data", "Directory to store node's blockchain data")
	flag.Parse() // Parse the command-line flags

	// Initialize the blockchain
	blockchain, err := core.NewBlockchain(*nodeDataDir)
	if err != nil {
		log.Fatalf("Failed to initialize the blockchain: %v", err)
	}

	// Perform an integrity check on the blockchain
	if !blockchain.CheckChainIntegrity() {
		log.Fatal("Blockchain integrity check failed.")
	} else {
		fmt.Println("Blockchain integrity check passed.")
	}

	// Initialize a new node with the specified address and known peers
	peersList := []string{}
	if *knownPeers != "" {
		peersList = strings.Split(*knownPeers, ",")
	}

	// Initialize a new node with the specified address and known peers
	// Initialize a new node with the specified address and known peers
	node := core.NewNode(*nodeAddress, peersList, *nodeDataDir, nil, false)

	// Setup CORS which is for connecting to the backend, remember the localhost will be different for this
	c := cors.New(cors.Options{
		AllowedOrigins: []string{"http://localhost:3000"}, // Allow frontend domain
		AllowedMethods: []string{"GET", "POST", "OPTIONS"},
		AllowedHeaders: []string{"Content-Type"},
	})

	// Define HTTP routes and handlers within a single handler function wrapped by CORS
	handler := c.Handler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/status":
			fmt.Fprintf(w, "Blockchain status: %s", blockchain.Status())
		case "/submit-transaction":
			node.SubmitTransactionHandler()(w, r)
		case "/get-block":
			node.GetBlockHandler()(w, r)
		case "/get-transaction":
			node.GetTransactionHandler()(w, r)
		case "/get-stats":
			stats := node.GetBlockchainStats()
			statsJSON, err := json.Marshal(stats)
			if err != nil {
				http.Error(w, "Failed to serialize blockchain statistics", http.StatusInternalServerError)
				return
			}
			w.Header().Set("Content-Type", "application/json")
			w.Write(statsJSON)
		case "/pending-transactions":
			node.PendingTransactionsHandler()(w, r)
		case "/peers":
			log.Println("Handling /peers request")
			data, err := json.Marshal(node.Peers)
			if err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
			w.Header().Set("Content-Type", "application/json")
			w.Write(data)
		default:
			http.NotFound(w, r)
		}
	}))

	// Start the HTTP server with CORS-enabled handler
	fmt.Printf("Starting server on %s\n", *nodeAddress)
	if err := http.ListenAndServe(*nodeAddress, handler); err != nil {
		log.Fatalf("Failed to start server: %v", err)
	}
}

// first run the blockchain: go run main.go
// open a new terminal and run:

// Get the blockchain stats: curl http://localhost:8080/get-stats
// Retrieve the genesis block: curl "http://localhost:8080/get-block?id=0"
// Retrieve pending transactions: curl http://localhost:8080/pending-transactions
