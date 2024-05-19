package main

import (
	"crypto/tls"
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
	"golang.org/x/crypto/acme/autocert"

	pb "github.com/thrylos-labs/thrylos"

	"github.com/joho/godotenv"
	"github.com/rs/cors"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	// Import your blockchain package
)

func main() {
	log.SetOutput(os.Stdout)                     // Change to os.Stdout for visibility in standard output
	log.SetFlags(log.LstdFlags | log.Lshortfile) // Adding file name and line number for clarity

	// Load configuration from .env file
	envPath := "../../.env"
	if err := godotenv.Load(envPath); err != nil {
		log.Fatalf("Error loading .env file from %s: %v", envPath, err)
	}

	// Environment variables
	grpcAddress := os.Getenv("GRPC_NODE_ADDRESS")
	knownPeers := os.Getenv("PEERS")
	nodeDataDir := os.Getenv("DATA")
	testnet := os.Getenv("TESTNET") == "true" // Convert to boolean
	wasmPath := os.Getenv("WASM_PATH")
	dataDir := os.Getenv("DATA_DIR")
	chainID := "0x539" // Default local chain ID (1337 in decimal)
	domainName := os.Getenv("DOMAIN_NAME")

	if dataDir == "" {
		log.Fatal("DATA_DIR environment variable is not set")
	}

	if testnet {
		fmt.Println("Running in Testnet Mode")
		chainID = "0x5" // Goerli Testnet chain ID
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
		AllowedOrigins: []string{
			"chrome-extension://nkbihfbeogaeaoehlefnkodbefgpgknn", // MetaMask extension ID
			"http://localhost:3000",                               // Your development frontend
			"http://127.0.0.1:3000",                               // Another common localhost format
			"http://localhost:8545",
			"http://127.0.0.1:8545",
			"http://localhost:8546",
			"http://127.0.0.1:8546",
		},
		AllowedMethods:   []string{"GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS"},
		AllowedHeaders:   []string{"Content-Type", "Authorization"},
		AllowCredentials: true,
		Debug:            true,
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

	certManager := autocert.Manager{
		Prompt:     autocert.AcceptTOS,
		Cache:      autocert.DirCache("certs"),         // Folder to store the certificates
		HostPolicy: autocert.HostWhitelist(domainName), // Only request certs for your domain
	}

	// Set up HTTPS server
	httpsServer := &http.Server{
		Addr:    ":443",  // Standard HTTPS port
		Handler: handler, // Reference the CORS-wrapped handler
		TLSConfig: &tls.Config{
			GetCertificate: certManager.GetCertificate, // Let autocert handle the certificates
		},
	}

	// Serve using HTTPS, autocert handles the certificates
	log.Printf("Starting HTTPS server on %s\n", httpsServer.Addr)
	go func() {
		err := httpsServer.ListenAndServeTLS("", "")
		if err != nil {
			log.Fatalf("Failed to start HTTPS server: %v", err)
		}
	}()

	// Create BlockchainDB instance
	encryptionKey := []byte(aesKey) // This should ideally come from a secure source
	blockchainDatabase := database.NewBlockchainDB(blockchainDB, encryptionKey)

	// Set up TLS credentials for the gRPC server
	creds := loadTLSCredentials()
	if err != nil {
		log.Fatalf("Failed to load TLS credentials: %v", err)
	}

	// Setup and start gRPC server
	lis, err := net.Listen("tcp", grpcAddress)
	if err != nil {
		log.Fatalf("Failed to listen on %s: %v", grpcAddress, err)
	}

	s := grpc.NewServer(grpc.Creds(creds))
	pb.RegisterBlockchainServiceServer(s, &server{db: blockchainDatabase})

	log.Printf("Starting gRPC server on %s\n", grpcAddress)
	if err := s.Serve(lis); err != nil {
		log.Fatalf("Failed to serve gRPC on %s: %v", grpcAddress, err)
	}
}

func loadTLSCredentials() credentials.TransportCredentials {
	// Load the server's certificate and its private key
	cert, err := tls.LoadX509KeyPair("../../cert.pem", "../../new_key.pem")
	if err != nil {
		log.Fatalf("could not load TLS keys: %v", err)
	}

	// Create the credentials and return them
	config := &tls.Config{
		Certificates: []tls.Certificate{cert},
		// Optionally set ClientCAs and ClientAuth if you need client certificates for mutual TLS
	}

	return credentials.NewTLS(config)
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
