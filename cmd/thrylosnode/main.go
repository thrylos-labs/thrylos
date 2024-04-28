package main

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"

	"github.com/thrylos-labs/thrylos/core"
	"github.com/thrylos-labs/thrylos/database"

	pb "github.com/thrylos-labs/thrylos"

	"github.com/joho/godotenv"
	"github.com/rs/cors"
	"github.com/wasmerio/wasmer-go/wasmer"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	// Import your blockchain package
)

type server struct {
	pb.UnimplementedBlockchainServiceServer
	db *database.BlockchainDB // Include a pointer to BlockchainDB
}

func (s *server) SubmitTransaction(ctx context.Context, req *pb.TransactionRequest) (*pb.TransactionResponse, error) {
	if req == nil || req.Transaction == nil {
		return nil, status.Error(codes.InvalidArgument, "Transaction request or transaction data is nil")
	}

	log.Printf("Received transaction %s for processing", req.Transaction.Id)

	// Convert the protobuf Transaction to your shared transaction type
	tx := core.ConvertProtoTransactionToShared(req.Transaction)

	// Process the transaction using your blockchain core logic
	err := s.db.AddTransaction(tx)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "Transaction failed: %v", err)
	}

	log.Printf("Transaction %s added successfully", req.Transaction.Id)
	return &pb.TransactionResponse{Status: "Transaction added successfully"}, nil
}

func init() {
	log.SetOutput(os.Stdout)                     // Change to os.Stdout for visibility in standard output
	log.SetFlags(log.LstdFlags | log.Lshortfile) // Adding file name and line number for clarity
}

func main() {

	// Load configuration from .env file
	// Specify the path to your .env file
	envPath := "../../.env"
	if err := godotenv.Load(envPath); err != nil {
		log.Fatalf("Error loading .env file from %s: %v", envPath, err)
	}

	// Environment variables

	httpAddress := os.Getenv("HTTP_NODE_ADDRESS")
	grpcAddress := os.Getenv("GRPC_NODE_ADDRESS")
	knownPeers := os.Getenv("PEERS")
	nodeDataDir := os.Getenv("DATA")
	testnet := os.Getenv("TESTNET") == "true" // Convert to boolean
	wasmPath := os.Getenv("WASM_PATH")
	dataDir := os.Getenv("DATA_DIR")
	if dataDir == "" {
		log.Fatal("DATA_DIR environment variable is not set")
	}

	if testnet {
		fmt.Println("Running in Testnet Mode")
		// Specific settings for testnet can be configured here
	}

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

	// Initialize the database
	blockchainDB, err := database.InitializeDatabase(dataDir)
	if err != nil {
		log.Fatalf("Failed to create blockchain database: %v", err)
	}

	// Initialize a new node with the specified address and known peers
	peersList := []string{}
	if knownPeers != "" {
		peersList = strings.Split(knownPeers, ",")
	}
	node := core.NewNode(grpcAddress, peersList, nodeDataDir, nil, false)

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

	// Listen for HTTP server
	httpLis, err := net.Listen("tcp", httpAddress)
	if err != nil {
		log.Fatalf("Failed to listen for HTTP: %v", err)
	}

	// Start the HTTP server with CORS-enabled handler
	go func() {
		fmt.Printf("Starting HTTP server on %s\n", httpAddress)
		if err := http.Serve(httpLis, handler); err != nil {
			log.Fatalf("Failed to start HTTP server: %v", err)
		}
	}()

	// Create BlockchainDB instance
	encryptionKey := []byte(aesKey) // This should ideally come from a secure source
	blockchainDatabase := database.NewBlockchainDB(blockchainDB, encryptionKey)

	// Setup and start gRPC server
	lis, err := net.Listen("tcp", grpcAddress)
	if err != nil {
		log.Fatalf("Failed to listen on %s: %v", grpcAddress, err)
	}

	s := grpc.NewServer()
	pb.RegisterBlockchainServiceServer(s, &server{db: blockchainDatabase})

	log.Printf("Starting gRPC server on %s\n", grpcAddress)
	if err := s.Serve(lis); err != nil {
		log.Fatalf("Failed to serve gRPC on %s: %v", grpcAddress, err)
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
