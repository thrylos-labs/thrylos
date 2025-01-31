package main

import (
	"crypto/tls"
	"encoding/base64"
	"fmt"
	"log"
	"net"
	"net/http"
	_ "net/http/pprof" // This is important as it registers pprof handlers with the default mux.
	"os"
	"path/filepath"
	"strings"

	"github.com/thrylos-labs/thrylos"
	"github.com/thrylos-labs/thrylos/core/chain"
	"github.com/thrylos-labs/thrylos/core/network"
	"github.com/thrylos-labs/thrylos/core/node"
	"github.com/thrylos-labs/thrylos/database"

	"github.com/joho/godotenv"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
)

func loadEnv() (map[string]string, error) {
	env := os.Getenv("ENV")
	if env == "" {
		env = "development" // Default to development if not set
		log.Printf("ENV not set, defaulting to development mode")
	}

	var envPath string
	if env == "production" {
		envPath = "../../.env.prod"
	} else {
		envPath = "../../.env.dev"
	}

	// Get the absolute path for better error reporting
	absPath, err := filepath.Abs(envPath)
	if err != nil {
		return nil, fmt.Errorf("failed to get absolute path for %s: %v", envPath, err)
	}

	// Check if file exists
	if _, err := os.Stat(absPath); os.IsNotExist(err) {
		return nil, fmt.Errorf("environment file not found at %s", absPath)
	}

	// Load the environment file
	envFile, err := godotenv.Read(envPath)
	if err != nil {
		return nil, fmt.Errorf("error reading environment file at %s: %v", absPath, err)
	}

	// Validate required environment variables
	requiredVars := []string{
		"WS_ADDRESS",
		"HTTP_NODE_ADDRESS",
		"GRPC_NODE_ADDRESS",
		"AES_KEY_ENV_VAR",
		"GENESIS_ACCOUNT",
		"DATA_DIR",
	}

	missingVars := []string{}
	for _, v := range requiredVars {
		if envFile[v] == "" {
			missingVars = append(missingVars, v)
		}
	}

	if len(missingVars) > 0 {
		return nil, fmt.Errorf("missing required environment variables: %v", missingVars)
	}

	// Force development mode settings
	if env == "development" {
		log.Println("Running in development mode - TLS will be disabled")
		// Explicitly set development mode variables
		envFile["ENV"] = "development"
		// Clear any TLS-related settings to prevent accidental usage
		envFile["CERT_FILE"] = ""
		envFile["KEY_FILE"] = ""
		envFile["TLS_CERT_PATH"] = ""
		envFile["TLS_KEY_PATH"] = ""
	}

	return envFile, nil
}

func main() {
	// Load environment variables
	envFile, err := loadEnv()
	if err != nil {
		log.Fatalf("Error loading environment variables: %v", err)
	}

	if err != nil {
		log.Fatalf("Error creating Supabase client: %v", err)
	}

	// Environment variables
	grpcAddress := envFile["GRPC_NODE_ADDRESS"]
	knownPeers := envFile["PEERS"]
	nodeDataDir := envFile["DATA"]
	testnet := envFile["TESTNET"] == "true" // Convert to boolea]
	dataDir := envFile["DATA_DIR"]
	chainID := "0x539" // Default local chain ID (1337 in decimal)
	// domainName := envFile["DOMAIN_NAME")

	if dataDir == "" {
		log.Fatal("DATA_DIR environment variable is not set")
	}

	if testnet {
		fmt.Println("Running in Testnet Mode")
		chainID = "0x5" // Goerli Testnet chain ID
	}

	// Fetch the Base64-encoded AES key from the environment variable
	base64Key := envFile["AES_KEY_ENV_VAR"]
	if base64Key == "" {
		log.Fatal("AES key is not set in environment variables")
	}

	aesKey, err := base64.StdEncoding.DecodeString(base64Key)
	if err != nil {
		log.Fatalf("Error decoding AES key: %v", err)
	}

	// Genesis account
	genesisAccount := envFile["GENESIS_ACCOUNT"]
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

	// Remember to set TestMode to false in your production environment to ensure that the fallback mechanism is never used with real transactions.
	blockchain, _, err := chain.NewBlockchainWithConfig(&chain.BlockchainConfig{
		DataDir:           absPath,
		AESKey:            aesKey,
		GenesisAccount:    genesisAccount,
		TestMode:          true,
		DisableBackground: false, // Set based on your requirements
	})
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

	node := node.NewNode(grpcAddress, peersList, nodeDataDir, nil)

	node.SetChainID(chainID)

	// Set up routes
	router := network.NewRouter(node)
	mux := router.SetupRoutes()

	mux.HandleFunc("/status", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, "Blockchain status: %s", blockchain.Status())
	})

	// Start background tasks
	node.StartBackgroundTasks()

	// Create a sample HTTP handler
	// mux := http.NewServeMux()

	// Setup and start servers
	setupServers(mux, envFile)

	// Create BlockchainDB instance
	encryptionKey := []byte(aesKey) // This should ideally come from a secure source
	blockchainDatabase := database.NewBlockchainDB(blockchainDB, encryptionKey)

	// Setup and start gRPC server
	lis, err := net.Listen("tcp", grpcAddress)
	if err != nil {
		log.Fatalf("Failed to listen on %s: %v", grpcAddress, err)
	}

	var s *grpc.Server

	if envFile["ENV"] == "development" {
		// Development mode: No TLS
		log.Println("Starting gRPC server in development mode (no TLS)")
		s = grpc.NewServer()
	} else {
		// Production mode: Use TLS
		log.Println("Starting gRPC server in production mode (with TLS)")
		creds := loadTLSCredentials(envFile)
		if err != nil {
			log.Fatalf("Failed to load TLS credentials: %v", err)
		}
		s = grpc.NewServer(grpc.Creds(creds))
	}

	// Setup and start gRPC server
	// lis, err := net.Listen("tcp", grpcAddress)
	// if err != nil {
	// 	log.Fatalf("Failed to listen on %s: %v", grpcAddress, err)
	// }

	log.Printf("Starting gRPC server on %s\n", grpcAddress)
	if err := s.Serve(lis); err != nil {
		log.Fatalf("Failed to serve gRPC on %s: %v", grpcAddress, err)
	}
	thrylos.RegisterBlockchainServiceServer(s, &server{db: blockchainDatabase})

	log.Printf("Starting gRPC server on %s\n", grpcAddress)
	if err := s.Serve(lis); err != nil {
		log.Fatalf("Failed to serve gRPC on %s: %v", grpcAddress, err)
	}
}

func setupServers(r http.Handler, envFile map[string]string) {
	wsAddress := envFile["WS_ADDRESS"]
	httpAddress := envFile["HTTP_NODE_ADDRESS"]
	isDevelopment := envFile["ENV"] == "development"

	var tlsConfig *tls.Config = nil
	if !isDevelopment {
		tlsConfig = &tls.Config{
			Certificates: []tls.Certificate{loadCertificate(envFile)},
		}
	}

	// WebSocket server
	wsServer := &http.Server{
		Addr:      wsAddress,
		Handler:   r,
		TLSConfig: tlsConfig,
	}
	// HTTP(S) server
	httpServer := &http.Server{
		Addr:      httpAddress,
		Handler:   r,
		TLSConfig: tlsConfig,
	}

	// Start servers
	go startServer(wsServer, "WebSocket", isDevelopment)
	go startServer(httpServer, "HTTP(S)", isDevelopment)
}

func startServer(server *http.Server, serverType string, isDevelopment bool) {
	var err error
	protocol := "HTTP"
	if !isDevelopment {
		protocol = "HTTPS"
		log.Printf("Starting %s server in production mode (with TLS) on %s\n", serverType, server.Addr)
		err = server.ListenAndServeTLS("", "")
	} else {
		log.Printf("Starting %s server in development mode (no TLS) on %s\n", serverType, server.Addr)
		err = server.ListenAndServe()
	}

	if err != nil && err != http.ErrServerClosed {
		log.Fatalf("Failed to start %s %s server: %v", protocol, serverType, err)
	}
}

func loadTLSCredentials(envFile map[string]string) credentials.TransportCredentials {
	var certPath, keyPath string

	// Determine paths based on the environment
	if os.Getenv("ENV") == "production" {
		certPath = envFile["TLS_CERT_PATH"]
		keyPath = envFile["TLS_KEY_PATH"]
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

func loadCertificate(envFile map[string]string) tls.Certificate {
	cert, err := tls.LoadX509KeyPair(envFile["CERT_FILE"], envFile["KEY_FILE"])
	if err != nil {
		log.Fatalf("Failed to load TLS certificate: %v", err)
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
