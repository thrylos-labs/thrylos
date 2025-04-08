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
	"strconv"
	"strings"
	"time"

	"github.com/thrylos-labs/thrylos"
	"github.com/thrylos-labs/thrylos/amount"
	"github.com/thrylos-labs/thrylos/chain"
	"github.com/thrylos-labs/thrylos/network"
	"github.com/thrylos-labs/thrylos/types"

	"github.com/joho/godotenv"
	"github.com/thrylos-labs/thrylos/crypto"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
)

// BlockchainServer implements the gRPC service
type server struct {
	thrylos.UnimplementedBlockchainServiceServer
	blockchain *chain.BlockchainImpl
}

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

	// Environment variables
	grpcAddress := envFile["GRPC_NODE_ADDRESS"]
	wsAddress := envFile["WS_ADDRESS"]
	peersStr := envFile["PEERS"]
	dataDir := envFile["DATA_DIR"]
	testnet := envFile["TESTNET"] == "true" // Convert to boolean
	chainID := "thrylos-testnet"            // Default chain ID for testnet
	domainName := envFile["DOMAIN_NAME"]
	serverHost := envFile["SERVER_HOST"]

	// Parse peer list
	var seedPeers []string
	if peersStr != "" {
		seedPeers = strings.Split(peersStr, ",")
		for i, peer := range seedPeers {
			seedPeers[i] = strings.TrimSpace(peer)
		}
		log.Printf("Configured with %d initial seed peers", len(seedPeers))
	} else {
		log.Println("No initial peers configured")
	}

	if dataDir == "" {
		log.Fatal("DATA_DIR environment variable is not set")
	}

	if testnet {
		fmt.Println("Running in Testnet Mode")
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
	absPath, err := filepath.Abs(dataDir)
	if err != nil {
		log.Fatalf("Error resolving the absolute path of the blockchain data directory: %v", err)
	}
	log.Printf("Using blockchain data directory: %s", absPath)

	// Create a private key for genesis account
	privKey, err := crypto.NewPrivateKey()
	if err != nil {
		log.Fatalf("Error generating private key: %v", err)
	}

	// Initialize the blockchain and database with the AES key
	// Set TestMode to false for testnet deployment
	blockchain, _, err := chain.NewBlockchain(&types.BlockchainConfig{
		DataDir:           absPath,
		AESKey:            aesKey,
		GenesisAccount:    privKey,
		TestMode:          false, // For testnet, we should set this to false
		DisableBackground: false,
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

	// Get the singleton message bus
	messageBus := types.GetGlobalMessageBus()

	// Connect blockchain to message bus
	connectBlockchainToMessageBus(blockchain, messageBus, chainID)

	// Initialize router with message bus
	router := network.NewRouter(messageBus)

	// Create and initialize the peer manager
	peerManager := network.NewPeerManager(messageBus, 50, 20) // 50 inbound, 20 outbound max connections
	peerManager.SeedPeers = seedPeers

	// Determine local address for peer connections
	var localAddress string
	if domainName != "" {
		localAddress = domainName
	} else if serverHost != "" {
		localAddress = serverHost
		if !strings.Contains(localAddress, ":") {
			// Add the WebSocket port if not included
			if strings.HasPrefix(wsAddress, ":") {
				localAddress += wsAddress
			} else {
				localAddress += ":" + wsAddress
			}
		}
	} else {
		// Use localhost with port as fallback
		if strings.HasPrefix(wsAddress, ":") {
			localAddress = "localhost" + wsAddress
		} else {
			localAddress = "localhost:" + wsAddress
		}
	}

	log.Printf("Node identity: %s", localAddress)

	// Start peer discovery and management
	peerManager.StartPeerManagement()

	// Setup HTTP routes with peer manager
	mux := router.SetupRoutes(peerManager)

	// Setup HTTP/WS servers
	setupServers(mux, envFile)

	// Setup and start gRPC server
	lis, err := net.Listen("tcp", grpcAddress)
	if err != nil {
		log.Fatalf("Failed to listen on %s: %v", grpcAddress, err)
	}

	var s *grpc.Server
	if envFile["ENV"] == "development" {
		s = grpc.NewServer()
	} else {
		creds := loadTLSCredentials(envFile)
		if err != nil {
			log.Fatalf("Failed to load TLS credentials: %v", err)
		}
		s = grpc.NewServer(grpc.Creds(creds))
	}

	// Register the blockchain service
	thrylos.RegisterBlockchainServiceServer(s, &server{blockchain: blockchain})

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

// Helper function to connect blockchain to the message bus
func connectBlockchainToMessageBus(blockchain *chain.BlockchainImpl, messageBus types.MessageBusInterface, chainID string) {
	// Create channels to receive messages
	balanceCh := make(chan types.Message, 100)
	blockCh := make(chan types.Message, 100)
	txCh := make(chan types.Message, 100)
	infoCh := make(chan types.Message, 100)

	// Subscribe to messages
	messageBus.Subscribe(types.GetBalance, balanceCh)
	messageBus.Subscribe(types.GetUTXOs, balanceCh)
	messageBus.Subscribe(types.ProcessTransaction, txCh)
	messageBus.Subscribe(types.ProcessBlock, blockCh)
	messageBus.Subscribe(types.GetBlockchainInfo, infoCh)

	// Add to your server initialization code
	go func() {
		time.Sleep(5 * time.Second) // Wait for everything to start up
		log.Println("Running stakeholders map test...")
		blockchain.TestStakeholdersMap()
		log.Println("Stakeholders map test completed.")
	}()

	// Handle balance-related messages
	go func() {
		for msg := range balanceCh {
			switch msg.Type {
			case types.GetBalance:
				if address, ok := msg.Data.(string); ok {
					// Sum unspent outputs for this address
					balance := int64(0)
					for _, utxoList := range blockchain.Blockchain.UTXOs {
						for _, utxo := range utxoList {
							if utxo.OwnerAddress == address && !utxo.IsSpent {
								balance += utxo.Amount
							}
						}
					}
					msg.ResponseCh <- types.Response{Data: balance}
				} else {
					msg.ResponseCh <- types.Response{Error: fmt.Errorf("invalid address format")}
				}
			case types.GetUTXOs:
				if req, ok := msg.Data.(types.UTXORequest); ok {
					address := req.Address
					utxos := []types.UTXO{}

					// Find all UTXOs for this address
					for utxoKey, utxoList := range blockchain.Blockchain.UTXOs {
						for _, utxo := range utxoList {
							if utxo.OwnerAddress == address && !utxo.IsSpent {
								// Convert thrylos.UTXO to types.UTXO
								parts := strings.Split(utxoKey, ":")
								txID := parts[0]
								index, _ := strconv.Atoi(parts[1])

								typesUtxo := types.UTXO{
									ID:            utxoKey,
									TransactionID: txID,
									Index:         index,
									OwnerAddress:  utxo.OwnerAddress,
									Amount:        amount.Amount(utxo.Amount),
									IsSpent:       utxo.IsSpent,
								}
								utxos = append(utxos, typesUtxo)
							}
						}
					}
					msg.ResponseCh <- types.Response{Data: utxos}
				} else {
					msg.ResponseCh <- types.Response{Error: fmt.Errorf("invalid UTXO request format")}
				}
			}
		}
	}()

	// Handle transaction-related messages
	go func() {
		for msg := range txCh {
			switch msg.Type {
			case types.ProcessTransaction:
				if tx, ok := msg.Data.(*thrylos.Transaction); ok {
					// Verify transaction
					// Add to pending transactions or directly to pool
					blockchain.Blockchain.PendingTransactions = append(blockchain.Blockchain.PendingTransactions, tx)

					// If you have a function for processing transactions, use it here
					// err := blockchain.ProcessIncomingTransaction(tx)

					msg.ResponseCh <- types.Response{
						Data:  tx.Id,
						Error: nil,
					}
				} else {
					msg.ResponseCh <- types.Response{Error: fmt.Errorf("invalid transaction format")}
				}
			}
		}
	}()

	// Handle block-related messages
	go func() {
		for msg := range blockCh {
			switch msg.Type {
			case types.ProcessBlock:
				if blockID, ok := msg.Data.(string); ok {
					// Get block by ID
					block, err := blockchain.GetBlockByID(blockID)
					msg.ResponseCh <- types.Response{Data: block, Error: err}
				} else if blockNum, ok := msg.Data.(int32); ok {
					// Get block by number
					block, err := blockchain.GetBlock(int(blockNum))
					msg.ResponseCh <- types.Response{Data: block, Error: err}
				} else {
					msg.ResponseCh <- types.Response{Error: fmt.Errorf("invalid block identifier")}
				}
			}
		}
	}()

	// Handle blockchain info messages
	go func() {
		for msg := range infoCh {
			switch msg.Type {
			case types.GetBlockchainInfo:
				lastBlock, _, _ := blockchain.GetLastBlock()
				info := map[string]interface{}{
					"height":    blockchain.GetBlockCount() - 1,
					"lastBlock": lastBlock,
					"nodeCount": 1, // Default for now
					"chainId":   chainID,
					"isSyncing": false,
				}
				msg.ResponseCh <- types.Response{Data: info}
			}
		}
	}()
}
