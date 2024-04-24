package main

import (
	"Thrylos/core"
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"strings"

	"github.com/rs/cors"
	// Import your blockchain package
)

func main() {
	// Command-line flags for node configuration
	nodeAddress := flag.String("address", "localhost:8080", "Address for the node to listen on")
	knownPeers := flag.String("peers", "", "Comma-separated list of known peer addresses")
	nodeDataDir := flag.String("data", "./blockchain_data", "Directory to store node's blockchain data")
	testnet := flag.Bool("testnet", false, "Initialize with testnet settings and predefined accounts")
	flag.Parse() // Parse the command-line flags

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

	// Example of key generation
	_, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		log.Fatalf("Failed to generate genesis key: %v", err)
	}

	// Initialize the blockchain and database with the AES key
	blockchain, err := core.NewBlockchain(*nodeDataDir, aesKey) // Adjust according to your actual constructor method
	if err != nil {
		log.Fatalf("Failed to initialize the blockchain: %v", err)
	}

	// Perform an integrity check on the blockchain
	if !blockchain.CheckChainIntegrity() {
		log.Fatal("Blockchain integrity check failed.")
	} else {
		fmt.Println("Blockchain integrity check passed.")
	}

	if *testnet {
		log.Println("Creating initial funds and test accounts...")
		testAccounts, err := blockchain.InitializeTestnetAccounts(10)
		if err != nil {
			log.Fatalf("Failed to initialize testnet accounts: %v", err)
		}

		err = blockchain.CreateInitialFunds(testAccounts, privateKey)
		if err != nil {
			log.Fatalf("Failed to create initial funds: %v", err)
		} else {
			log.Println("Genesis block transactions created successfully.")
		}

		log.Println("Initialized test accounts:")
		for _, account := range testAccounts {
			log.Printf("Account: Address: %s, Stored PublicKey: %x\n", account.Address, account.PublicKey)
			retrievedKey, err := blockchain.Database.RetrieveEd25519PublicKey(account.Address)
			if err != nil {
				log.Printf("Failed to retrieve public key for address %s: %v", account.Address, err)
			} else {
				log.Printf("Retrieved PublicKey: %x", retrievedKey)
				if bytes.Equal(retrievedKey, account.PublicKey) {
					log.Println("Retrieved key matches the stored key.")
				} else {
					log.Println("Mismatch in retrieved key and stored key.")
					log.Printf("Stored Key: %x, Retrieved Key: %x", account.PublicKey, retrievedKey)
				}
			}
		}
	}

	// Initialize a new node with the specified address and known peers
	peersList := []string{}
	if *knownPeers != "" {
		peersList = strings.Split(*knownPeers, ",")
	}
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
		case "/get-balance":
			node.GetBalanceHandler()(w, r)
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

// go run main.go --address=localhost:8080 --data=./node1_data --testnet

// curl -X POST http://localhost:8080/submit-transaction \
//   -H "Content-Type: application/json" \
//   -d '{
//     "inputs": [
//       {
//         "previousTx": "mock-previous-tx-hash",
//         "index": 0,
//         "signature": "mock-signature",
//         "ownerAddress": "254f89bd52362ee777407df6a9e96f05346b56ef763678a07e004cd76eb7870b"
//       }
//     ],
//     "outputs": [
//       {
//         "amount": 100,
//         "address": "75911a37b6861ac3a81a9aaddf89d7e2c95dfbadac4f7f9e489f4f1f98a4fae2"
//       }
//     ]
//   }'

// Get the blockchain stats: curl http://localhost:8080/get-stats
// Retrieve the genesis block: curl "http://localhost:8080/get-block?id=0"
// Retrieve pending transactions: curl http://localhost:8080/pending-transactions
// Retrive a balance from a specific address: curl "http://localhost:8080/get-balance?address=your_address_here"
