package main

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"net/http"
	_ "net/http/pprof" // This is important as it registers pprof handlers with the default mux.
	"os"
	"path/filepath"
	"strings"

	"github.com/thrylos-labs/thrylos"
	"github.com/thrylos-labs/thrylos/core"
	"github.com/thrylos-labs/thrylos/database"
	"github.com/thrylos-labs/thrylos/shared"

	pb "github.com/thrylos-labs/thrylos"

	"github.com/joho/godotenv"
	"github.com/rs/cors"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	// Import your blockchain package
)

type server struct {
	pb.UnimplementedBlockchainServiceServer
	db           *database.BlockchainDB       // Include a pointer to BlockchainDB
	PublicKeyMap map[string]ed25519.PublicKey // Maps sender addresses to their public keys
}

func NewServer(db *database.BlockchainDB) *server {
	return &server{
		db:           db,
		PublicKeyMap: make(map[string]ed25519.PublicKey),
	}
}

func (s *server) SubmitTransactionBatch(ctx context.Context, req *thrylos.TransactionBatchRequest) (*thrylos.TransactionBatchResponse, error) {
	if req == nil || len(req.Transactions) == 0 {
		return nil, status.Error(codes.InvalidArgument, "Transaction batch request is nil or empty")
	}

	var failedTransactions []*thrylos.FailedTransaction // Use the new FailedTransaction message
	for _, transaction := range req.Transactions {
		if err := s.processTransaction(transaction); err != nil {
			log.Printf("Failed to process transaction %s: %v", transaction.Id, err)
			failedTransaction := &thrylos.FailedTransaction{
				TransactionId: transaction.Id,
				ErrorMessage:  err.Error(),
			}
			failedTransactions = append(failedTransactions, failedTransaction)
		}
	}

	response := &thrylos.TransactionBatchResponse{
		Status:             "Processed with some errors",
		FailedTransactions: failedTransactions,
	}

	if len(failedTransactions) == 0 {
		response.Status = "Batch processed successfully"
	}

	return response, nil
}

func (s *server) processTransaction(transaction *thrylos.Transaction) error {
	if transaction == nil {
		return fmt.Errorf("received nil transaction")
	}

	// Convert thrylos.Transaction to shared.Transaction
	sharedTx := core.ThrylosToShared(transaction)
	if sharedTx == nil {
		return fmt.Errorf("conversion failed for transaction ID %s", transaction.Id)
	}

	// Validate the converted transaction
	if !s.validateTransaction(sharedTx) {
		return fmt.Errorf("validation failed for transaction ID %s", sharedTx.ID)
	}

	// Process the transaction including UTXO updates and adding the transaction
	return s.db.ProcessTransaction(sharedTx)
}

func (s *server) validateTransaction(tx *shared.Transaction) bool {
	if tx == nil || tx.Signature == nil {
		log.Println("Transaction or its signature is nil")
		return false
	}

	// Retrieve the sender's public key from the node's public key map
	publicKey, ok := s.PublicKeyMap[tx.Sender]
	if !ok {
		log.Printf("No public key found for sender: %s", tx.Sender)
		return false
	}

	// Serialize the transaction without its signature
	serializedTx, err := tx.SerializeWithoutSignature()
	if err != nil {
		log.Printf("Failed to serialize transaction without signature: %v", err)
		return false
	}

	// Validate the transaction signature
	if !ed25519.Verify(publicKey, serializedTx, tx.Signature) {
		log.Printf("Invalid signature for transaction ID: %s", tx.ID)
		return false
	}

	// Retrieve UTXOs required to verify inputs and calculate input sum
	totalInputs := 0
	for _, input := range tx.Inputs {
		utxo, err := shared.GetUTXO(input.TransactionID, input.Index)
		if err != nil || utxo == nil {
			log.Printf("UTXO not found or error retrieving UTXO: %v", err)
			return false
		}
		if utxo.IsSpent {
			log.Println("Referenced UTXO has already been spent")
			return false
		}
		totalInputs += utxo.Amount
	}

	// Calculate the total outputs and ensure it matches inputs (conservation of value)
	totalOutputs := 0
	for _, output := range tx.Outputs {
		totalOutputs += output.Amount
	}

	if totalInputs != totalOutputs {
		log.Printf("Input total %d does not match output total %d for transaction ID %s", totalInputs, totalOutputs, tx.ID)
		return false
	}

	return true
}

func (s *server) addPublicKey(sender string, pubKey ed25519.PublicKey) {
	s.PublicKeyMap[sender] = pubKey
}

func (s *server) SubmitTransaction(ctx context.Context, req *pb.TransactionRequest) (*pb.TransactionResponse, error) {
	log.Printf("Received transaction request: %+v", req)
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
	chainID := "0x539" // Default local chain ID (1337 in decimal)

	if dataDir == "" {
		log.Fatal("DATA_DIR environment variable is not set")
	}

	if testnet {
		fmt.Println("Running in Testnet Mode")
		httpAddress = "0.0.0.0:8546" // Example testnet address
		chainID = "0x5"              // Goerli Testnet chain ID
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
	result := thrylos.ExecuteWasm(wasmBytes)
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
	node.SetChainID(chainID) // Set the chain ID for the node

	// Setup CORS which is for connecting to the backend, remember the localhost will be different for this
	c := cors.New(cors.Options{
		AllowedOrigins:   []string{"http://localhost:3000", "http://127.0.0.1:8545", "http://127.0.0.1:8546", "chrome-extension://*"},
		AllowedMethods:   []string{"GET", "POST", "OPTIONS"},
		AllowedHeaders:   []string{"Content-Type", "Authorization"},
		AllowCredentials: true,
	})

	// Define HTTP routes and handlers within a single handler function wrapped by CORS
	handler := c.Handler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/status":
			fmt.Fprintf(w, "Blockchain status: %s", blockchain.Status())
		case "/submit-transaction":
			log.Printf("Received transaction data: %+v", r.Body) // log the incoming request body
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
		case "/jsonrpc":
			jsonRPCHandler := core.NewJSONRPCHandler(node)
			jsonRPCHandler.ServeHTTP(w, r)
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

// Get the blockchain stats: curl http://localhost:6080/get-stats
// Retrieve the genesis block: curl "http://localhost:6080/get-block?id=0"
// Retrieve pending transactions: curl http://localhost:6080/pending-transactions
// Retrive a balance from a specific address: curl "http://localhost:6080/get-balance?address=your_address_here"

// Server-Side Steps
// Blockchain Initialization:
// Initialize the blockchain database and genesis block upon starting the server.
// Load or create stakeholders, UTXOs, and transactions for the genesis block.
// Transaction Handling and Block Management:
// Receive transactions from clients, add to the pending transaction pool, and process them periodically.
// Create new blocks from pending transactions, ensuring transactions are valid, updating the UTXO set, and managing block links.
// Fork Resolution and Integrity Checks:
// Check for forks in the blockchain and resolve by selecting the longest chain.
// Perform regular integrity checks on the blockchain to ensure no tampering or inconsistencies.
