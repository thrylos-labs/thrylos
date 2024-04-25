package main

import (
	"Thrylos/core"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strings"

	"github.com/joho/godotenv"
	"github.com/rs/cors"
	"github.com/wasmerio/wasmer-go/wasmer"
	// Import your blockchain package
)

func main() {
	// Load configuration from .env file
	// Specify the path to your .env file
	envPath := "../../.env"
	if err := godotenv.Load(envPath); err != nil {
		log.Fatalf("Error loading .env file from %s: %v", envPath, err)
	}

	// Environment variables
	nodeAddress := os.Getenv("NODE_ADDRESS")
	knownPeers := os.Getenv("PEERS")
	nodeDataDir := os.Getenv("DATA")
	testnet := os.Getenv("TESTNET") == "true" // Convert to boolean
	wasmPath := os.Getenv("WASM_PATH")

	if wasmPath == "" {
		log.Fatal("WASM_PATH environment variable not set")
	}

	// Load WebAssembly binary
	wasmBytes, err := os.ReadFile(wasmPath)
	if err != nil {
		log.Fatalf("Failed to read wasm file: %v", err)
	}

	// Execute the WebAssembly module
	result := executeWasm(wasmBytes)
	fmt.Printf("Result from wasm: %d\n", result)

	// Fetch the Base64-encoded AES key from the environment variable
	base64Key := os.Getenv("AES_KEY_ENV_VAR")
	if base64Key == "" {
		log.Fatal("AES key is not set in environment variables")
	}
	aesKey, err := base64.StdEncoding.DecodeString(base64Key)
	if err != nil {
		log.Fatalf("Error decoding AES key: %v", err)
	}

	// Example of key generation
	_, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		log.Fatalf("Failed to generate genesis key: %v", err)
	}

	// Get the absolute path of the node data directory
	absPath, err := filepath.Abs(nodeDataDir)
	if err != nil {
		log.Fatalf("Error resolving the absolute path of the blockchain data directory: %v", err)
	}
	log.Printf("Using blockchain data directory: %s", absPath)

	// Initialize the blockchain and database with the AES key
	blockchain, err := core.NewBlockchain(absPath, aesKey)
	if err != nil {
		log.Fatalf("Failed to initialize the blockchain at %s: %v", absPath, err)
	}

	// Perform an integrity check on the blockchain
	if !blockchain.CheckChainIntegrity() {
		log.Fatal("Blockchain integrity check failed.")
	} else {
		fmt.Println("Blockchain integrity check passed.")
	}

	if testnet {
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
			log.Printf("Account: Address: %s, PublicKey: %x\n", account.Address, account.PublicKey)
		}
	}

	// Initialize a new node with the specified address and known peers
	peersList := []string{}
	if knownPeers != "" {
		peersList = strings.Split(knownPeers, ",")
	}
	node := core.NewNode(nodeAddress, peersList, nodeDataDir, nil, false)

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
	fmt.Printf("Starting server on %s\n", nodeAddress)
	if err := http.ListenAndServe(nodeAddress, handler); err != nil {
		log.Fatalf("Failed to start server: %v", err)
	}
}

func executeWasm(wasmBytes []byte) int {
	// Create an instance of the WebAssembly engine
	engine := wasmer.NewEngine()
	store := wasmer.NewStore(engine)

	// Compile the WebAssembly module
	module, err := wasmer.NewModule(store, wasmBytes)
	if err != nil {
		log.Fatalf("Failed to compile module: %v", err)
	}

	// Create an instance of the module
	instance, err := wasmer.NewInstance(module, wasmer.NewImportObject())
	if err != nil {
		log.Fatalf("Failed to instantiate wasm module: %v", err)
	}

	// Get the `process_transaction` function from the module
	processTransaction, err := instance.Exports.GetFunction("process_transaction")
	if err != nil {
		log.Fatalf("Failed to get process_transaction function: %v", err)
	}

	// Call the WebAssembly function
	result, err := processTransaction(10) // passing an example value
	if err != nil {
		log.Fatalf("Failed to execute process_transaction function: %v", err)
	}

	// Assuming the function returns an i32 and converting it properly
	if processedResult, ok := result.(int32); ok {
		return int(processedResult) // convert int32 to int
	} else {
		log.Fatalf("Failed to convert result to int32")
		return 0
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
