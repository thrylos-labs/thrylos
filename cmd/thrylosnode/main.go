package main

import (
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io/ioutil"
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

	pb "github.com/thrylos-labs/thrylos"

	"github.com/joho/godotenv"
	"github.com/rs/cors"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	// Import your blockchain package
)

func loadEnv() {
	env := os.Getenv("ENV")
	var envPath string
	if env == "production" {
		envPath = "../../.env.prod" // The Cert is managed through the droplet
	} else {
		envPath = "../../.env.dev" // Managed through local host
	}
	if err := godotenv.Load(envPath); err != nil {
		log.Fatalf("Error loading .env file from %s: %v", envPath, err)
	}
}

func main() {
	log.SetOutput(os.Stdout)                     // Change to os.Stdout for visibility in standard output
	log.SetFlags(log.LstdFlags | log.Lshortfile) // Adding file name and line number for clarity

	cwd, err := os.Getwd()
	if err != nil {
		log.Fatalf("Error getting current working directory: %v", err)
	}
	log.Printf("Running from directory: %s", cwd)

	loadEnv()

	// Load configuration from .env file
	// envPath := "../../.env"
	// if err := godotenv.Load(envPath); err != nil {
	// 	log.Fatalf("Error loading .env file from %s: %v", envPath, err)
	// }

	// Environment variables
	grpcAddress := os.Getenv("GRPC_NODE_ADDRESS")
	knownPeers := os.Getenv("PEERS")
	nodeDataDir := os.Getenv("DATA")
	testnet := os.Getenv("TESTNET") == "true" // Convert to boolean
	wasmPath := os.Getenv("WASM_PATH")
	dataDir := os.Getenv("DATA_DIR")
	chainID := "0x539" // Default local chain ID (1337 in decimal)
	// domainName := os.Getenv("DOMAIN_NAME")

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

	// Fetch and load WebAssembly binary
	response, err := http.Get(wasmPath)
	if err != nil {
		log.Fatalf("Failed to fetch wasm file from %s: %v", wasmPath, err)
	}
	defer response.Body.Close()

	// Load WebAssembly binary

	wasmBytes, err := ioutil.ReadAll(response.Body)
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

	// Genesis account
	genesisAccount := os.Getenv("GENESIS_ACCOUNT")
	if genesisAccount == "" {
		log.Fatal("Genesis account is not set in environment variables. Please configure a genesis account before starting.")
	}

	// Get the absolute path of the node data directory
	absPath, err := filepath.Abs(nodeDataDir)
	if err != nil {
		log.Fatalf("Error resolving the absolute path of the blockchain data directory: %v", err)
	}
	log.Printf("Using blockchain data directory: %s", absPath)

	// Initialize the blockchain and database with the AES key
	blockchain, err := core.NewBlockchain(absPath, aesKey, genesisAccount)
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
		AllowedOrigins: []string{"http://localhost:3000"}, // Specify the exact origin for security
		// AllowedOrigins:   []string{"*"}, // for testing purposes only, make sure to replace on production
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
			node.EnhancedSubmitTransactionHandler()(w, r)
		case "/sign-transaction":
			node.SignTransactionHandler()(w, r)
		case "/get-block":
			node.GetBlockHandler()(w, r)
		case "/get-utxo":
			node.GetUTXOsForAddressHandler()(w, r)
		case "/get-transaction":
			node.GetTransactionHandler()(w, r)
		case "/get-balance":
			node.GetBalanceHandler()(w, r)
		case "/network-health":
			node.NetworkHealthHandler()(w, r)
		case "/consensus-info":
			node.ConsensusInfoHandler()(w, r)
		case "/list-transactions-for-block":
			node.ListTransactionsForBlockHandler()(w, r)
		case "/register-public-key":
			node.RegisterPublicKeyHandler()(w, r)
		case "/create-wallet":
			node.CreateWalletHandler()(w, r)
		case "/register-validator":
			node.RegisterValidatorHandler()(w, r)
		case "/update-stake":
			node.UpdateStakeHandler()(w, r)
		case "/delegate-stake":
			node.DelegateStakeHandler()(w, r)
		case "/faucet":
			node.FaucetHandler()(w, r)
		case "/fund-wallet":
			node.FundWalletHandler()(w, r)
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

	// Use static certificate files for local development
	httpsServer := &http.Server{
		Addr:    os.Getenv("HTTPS_NODE_ADDRESS"), // Use the address from the environment variable
		Handler: handler,                         // Reference the CORS-wrapped handler
		TLSConfig: &tls.Config{
			Certificates: []tls.Certificate{loadCertificate()}, // Load static certificate
		},
	}

	// Serve using HTTPS with the static certificate
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
	var certPath, keyPath string

	// Determine paths based on the environment
	if os.Getenv("ENV") == "production" {
		certPath = os.Getenv("TLS_CERT_PATH")
		keyPath = os.Getenv("TLS_KEY_PATH")
	} else { // Default to development paths
		certPath = "../../localhost.crt"
		keyPath = "../../localhost.key"
	}

	// Load the server's certificate and its private key
	cert, err := tls.LoadX509KeyPair(certPath, keyPath)
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

func loadCertificate() tls.Certificate {
	var certPath, keyPath string

	// Determine paths based on the environment
	if os.Getenv("ENV") == "production" {
		certPath = os.Getenv("TLS_CERT_PATH")
		keyPath = os.Getenv("TLS_KEY_PATH")
	} else { // Default to development paths
		certPath = "../../localhost.crt"
		keyPath = "../../localhost.key"
	}

	// Load the server's certificate and its private key
	cert, err := tls.LoadX509KeyPair(certPath, keyPath)
	if err != nil {
		log.Fatalf("could not load TLS keys: %v", err)
	}
	return cert
}

// Get the blockchain stats: curl http://localhost:50051/get-stats
// Retrieve the genesis block: curl "http://localhost:50051/get-block?id=0"
// Retrieve pending transactions: curl http://localhost:50051/pending-transactions
// Retrive a balance from a specific address: curl "http://localhost:50051/get-balance?address=your_address_here"

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
