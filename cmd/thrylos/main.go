package main

import (
	"context"
	"crypto/tls"
	"encoding/base64"
	"fmt"
	"log"
	"net/http"
	_ "net/http/pprof" // This is important as it registers pprof handlers with the default mux.
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/joho/godotenv"
	"github.com/thrylos-labs/thrylos"
	"github.com/thrylos-labs/thrylos/amount"
	"github.com/thrylos-labs/thrylos/chain"
	"github.com/thrylos-labs/thrylos/config"
	"github.com/thrylos-labs/thrylos/crypto"
	"github.com/thrylos-labs/thrylos/network"
	"github.com/thrylos-labs/thrylos/types"
	// Add this line
)

func main() {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Setup signal handling for graceful shutdown
	signalCh := make(chan os.Signal, 1)
	signal.Notify(signalCh, os.Interrupt, syscall.SIGTERM)

	// Handle shutdown in a separate goroutine
	go func() {
		<-signalCh
		log.Println("Stopping blockchain...")

		// Give time for cleanup operations
		shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer shutdownCancel()

		// Signal all goroutines to stop
		cancel()

		// Wait for graceful shutdown or timeout
		select {
		case <-shutdownCtx.Done():
			log.Println("Shutdown grace period elapsed, exiting")
		}

		// Force exit if needed
		log.Println("Shutdown complete")
		os.Exit(0)
	}()

	// Load environment variables
	envFile, err := loadEnv()
	if err != nil {
		log.Fatalf("Error loading environment variables: %v", err)
	}

	// Environment variables
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

	// --- Load Persistent Genesis Private Key ---
	base64PrivKey := envFile["GENESIS_PRIVATE_KEY_RAW_B64"] // Use the new variable name
	if base64PrivKey == "" {
		log.Fatal("GENESIS_PRIVATE_KEY_RAW_B64 is not set in environment variables.")
	}

	// 1. Base64 Decode the string
	PrivKeyBytes, err := base64.StdEncoding.DecodeString(base64PrivKey)
	if err != nil {
		log.Fatalf("Failed to base64 decode GENESIS_PRIVATE_KEY_CBOR_B64: %v", err)
	}

	// 2. Deserialize using NewPrivateKeyFromBytes (expects CBOR)
	genesisPrivKey, err := crypto.NewPrivateKeyFromBytes(PrivKeyBytes)
	if err != nil {
		log.Fatalf("Failed to deserialize genesis private key: %v", err)
	}
	log.Println("Successfully loaded persistent Genesis private key.")

	if genesisPrivKey != nil && genesisPrivKey.PublicKey() != nil {
		pubKey := genesisPrivKey.PublicKey()
		// Use the Bytes() method which should be returning raw bytes now
		rawPubKeyBytes := pubKey.Bytes() // Get raw bytes from the crypto.PublicKey implementation
		if rawPubKeyBytes != nil {
			// *** ADD THIS LOG ***
			log.Printf("DEBUG: [main] Loaded Genesis RAW Public Key Bytes: %x", rawPubKeyBytes)
		} else {
			log.Printf("ERROR: [main] Failed to get raw bytes from loaded Genesis public key")
		}
	} else {
		log.Printf("ERROR: [main] Loaded Genesis private key or its public key is nil")
	}

	// Get the absolute path of the node data directory
	absPath, err := filepath.Abs(dataDir)
	if err != nil {
		log.Fatalf("Error resolving the absolute path of the blockchain data directory: %v", err)
	}
	log.Printf("Using blockchain data directory: %s", absPath)

	// Attempt to remove any existing lock file
	lockFile := filepath.Join(absPath, "LOCK")
	log.Printf("Attempting to remove lock file: %s", lockFile)
	_ = os.Remove(lockFile) // Ignore errors if file doesn't exist or can't be removed

	// Initialize the blockchain and database with the AES key
	// Set TestMode to false for testnet deployment
	blockchainSetupConfig := &types.BlockchainConfig{
		DataDir:           absPath,
		AESKey:            aesKey,
		GenesisAccount:    genesisPrivKey, // <-- Use the LOADED persistent key
		TestMode:          false,          // For testnet, we should set this to false
		DisableBackground: false,
		// Note: StateManager isn't initialized here yet, NewBlockchain might handle it internally or it might need setup
	}

	// Load the application config
	cfg, err := config.LoadOrCreateConfig("config.toml")
	if err != nil {
		log.Fatalf("Failed to load config: %v", err)
	}

	// Now call NewBlockchain with BOTH config arguments
	blockchain, _, err := chain.NewBlockchain(blockchainSetupConfig, cfg) // <-- PASS cfg HERE
	if err != nil {
		log.Fatalf("Failed to initialize the blockchain at %s: %v", absPath, err)
	}

	if err != nil {
		log.Fatalf("Failed to initialize the blockchain at %s: %v", absPath, err)
	}

	// Ensure blockchain is properly closed on shutdown
	defer func() {
		log.Println("Closing blockchain in defer function...")
		if blockchain != nil {
			if err := blockchain.Close(); err != nil {
				log.Printf("Error closing blockchain: %v", err)
			} else {
				log.Println("Blockchain closed successfully")
			}
		}
	}()

	// Perform an integrity check on the blockchain
	if !blockchain.CheckChainIntegrity() {
		log.Fatal("Blockchain integrity check failed.")
	} else {
		fmt.Println("Blockchain integrity check passed.")
	}

	log.Println("Attempting to generate 4 additional validators...")
	for i := 0; i < 4; i++ {
		log.Printf("Generating validator %d...", i+1)
		newAddr, err := blockchain.GenerateAndStoreValidatorKey()
		if err != nil {
			// !!! Log the error !!!
			log.Printf("ERROR: Failed to generate validator %d: %v", i+1, err)
			// Decide if you want to continue or stop on error
		} else {
			log.Printf("Successfully generated validator %d: %s", i+1, newAddr)
		}
	}
	log.Println("Finished attempting validator generation.")

	// Get the singleton message bus
	messageBus := types.GetGlobalMessageBus()

	// Connect blockchain to message bus
	connectBlockchainToMessageBus(ctx, blockchain, messageBus, chainID)

	// Initialize router with message bus
	router := network.NewRouter(messageBus, cfg)

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

	// Setup HTTP/WS servers with context for graceful shutdown
	wsServer, httpServer := setupServers(mux, envFile)

	// Start servers
	go startServer(ctx, wsServer, "WebSocket", envFile["ENV"] == "development")
	go startServer(ctx, httpServer, "HTTP(S)", envFile["ENV"] == "development")

	// Keep main goroutine running until context is canceled
	<-ctx.Done()
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
		"DATA_DIR",
		"GENESIS_PRIVATE_KEY_RAW_B64",
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

func convertProtoToTypesUTXO(protoUTXO *thrylos.UTXO) types.UTXO {
	if protoUTXO == nil {
		// Return zero value or handle error as appropriate for your logic
		log.Printf("WARN: convertProtoToTypesUTXO received nil input")
		return types.UTXO{}
	}

	// Create the composite ID matching the Key() method format ("txid-index")
	// Note: The Key() method uses "-", previous code might have assumed ":"
	utxoID := fmt.Sprintf("%s-%d", protoUTXO.TransactionId, protoUTXO.Index)

	return types.UTXO{
		ID:            utxoID,                          // Generated composite key
		TransactionID: protoUTXO.TransactionId,         // Direct mapping
		Index:         int(protoUTXO.Index),            // Cast proto's int32 to Go's int
		OwnerAddress:  protoUTXO.OwnerAddress,          // Direct mapping (string)
		Amount:        amount.Amount(protoUTXO.Amount), // Cast proto's int64 to amount.Amount
		IsSpent:       protoUTXO.IsSpent,               // Direct mapping (bool)
	}
}

func setupServers(r http.Handler, envFile map[string]string) (*http.Server, *http.Server) {
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

	return wsServer, httpServer
}

func startServer(ctx context.Context, server *http.Server, serverType string, isDevelopment bool) {
	// Start server in a goroutine
	go func() {
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
	}()

	// Handle server shutdown when context is canceled
	go func() {
		<-ctx.Done()
		log.Printf("Shutting down %s server...", serverType)

		// Create a timeout context for shutdown
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()

		if err := server.Shutdown(shutdownCtx); err != nil {
			log.Printf("Error during %s server shutdown: %v", serverType, err)
		}
	}()
}

func loadCertificate(envFile map[string]string) tls.Certificate {
	cert, err := tls.LoadX509KeyPair(envFile["CERT_FILE"], envFile["KEY_FILE"])
	if err != nil {
		log.Fatalf("Failed to load TLS certificate: %v", err)
	}
	return cert
}

// Helper function to connect blockchain to the message bus with context support
func connectBlockchainToMessageBus(ctx context.Context, blockchain *chain.BlockchainImpl, messageBus types.MessageBusInterface, chainID string) {
	// Create channels to receive messages
	balanceCh := make(chan types.Message, 100)
	blockCh := make(chan types.Message, 100)
	txCh := make(chan types.Message, 100)
	infoCh := make(chan types.Message, 100)
	addTxCh := make(chan types.Message, 100) // <<< NEW Channel for AddTransactionToPool

	// Subscribe to messages
	messageBus.Subscribe(types.GetBalance, balanceCh)
	messageBus.Subscribe(types.GetUTXOs, balanceCh)
	messageBus.Subscribe(types.ProcessTransaction, txCh)
	messageBus.Subscribe(types.ProcessBlock, blockCh)
	messageBus.Subscribe(types.GetBlockchainInfo, infoCh)
	messageBus.Subscribe(types.AddTransactionToPool, addTxCh) // <<< NEW Subscription

	// Add to your server initialization code
	go func() {
		select {
		case <-time.After(5 * time.Second): // Wait for everything to start up
			log.Println("Running stakeholders map test...")
			blockchain.TestStakeholdersMap()
			log.Println("Stakeholders map test completed.")
		case <-ctx.Done():
			return
		}
	}()

	// Handle balance-related messages
	go func() {
		for {
			select {
			case msg := <-balanceCh:
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
					// Inside the `select` within the goroutine handling `balanceCh`
				case types.GetUTXOs:
					if req, ok := msg.Data.(types.UTXORequest); ok {
						address := req.Address
						log.Printf("DEBUG: [GetUTXOs Handler] Request received for address: %s", address)
						utxosResult := []types.UTXO{} // Initialize empty slice for results

						log.Printf("DEBUG: [GetUTXOs Handler] Iterating through %d keys in UTXO map", len(blockchain.Blockchain.UTXOs))
						for utxoKey, utxoListProto := range blockchain.Blockchain.UTXOs { // utxoListProto is []*thrylos.UTXO
							log.Printf("DEBUG: [GetUTXOs Handler] Processing key: %q", utxoKey)

							var txID string
							var index int
							var err error

							// --- CORRECTED Key Parsing using LastIndex ---
							lastDashIndex := strings.LastIndex(utxoKey, "-")
							if lastDashIndex != -1 && lastDashIndex < len(utxoKey)-1 { // Found dash, not at end
								txID = utxoKey[:lastDashIndex]
								indexPart := utxoKey[lastDashIndex+1:]
								index, err = strconv.Atoi(indexPart)
								if err != nil {
									log.Printf("WARN: [GetUTXOs Handler] Could not parse index part %q from key %q using '-': %v. Skipping key.", indexPart, utxoKey, err)
									continue // Skip if index part isn't integer after '-'
								}
								log.Printf("DEBUG: [GetUTXOs Handler] Parsed Key %q using '-' -> TxID: %s, Index: %d", utxoKey, txID, index)
							} else {
								// Fallback attempt for ":" separator (e.g., old genesis key)
								lastColonIndex := strings.LastIndex(utxoKey, ":")
								if lastColonIndex != -1 && lastColonIndex < len(utxoKey)-1 {
									txID = utxoKey[:lastColonIndex]
									indexPart := utxoKey[lastColonIndex+1:]
									index, err = strconv.Atoi(indexPart)
									if err != nil {
										log.Printf("WARN: [GetUTXOs Handler] Could not parse index part %q from key %q using ':': %v. Skipping key.", indexPart, utxoKey, err)
										continue
									}
									log.Printf("DEBUG: [GetUTXOs Handler] Parsed Key %q using ':' -> TxID: %s, Index: %d", utxoKey, txID, index)
								} else {
									// Neither separator worked or format is wrong
									log.Printf("WARN: [GetUTXOs Handler] Could not find valid separator '-' or ':' in key %q to determine TxID/Index. Skipping key.", utxoKey)
									continue // Skip malformed key
								}
							}
							// --- End CORRECTED Key Parsing ---

							// Iterate through the UTXOs associated with this *parsed* key
							for _, utxoProto := range utxoListProto { // utxoProto is *thrylos.UTXO
								// Check owner and spent status
								if utxoProto.OwnerAddress == address && !utxoProto.IsSpent {
									log.Printf("DEBUG: [GetUTXOs Handler] Found matching UTXO for key %q: Owner=%s, Amount=%d", utxoKey, utxoProto.OwnerAddress, utxoProto.Amount)
									// Convert *thrylos.UTXO (proto) to types.UTXO
									typesUtxo := convertProtoToTypesUTXO(utxoProto) // Use helper

									// Assign the key used for lookup as the ID in the result, and ensure parsed TxID/Index match
									typesUtxo.ID = utxoKey
									if typesUtxo.TransactionID != txID || typesUtxo.Index != index {
										log.Printf("WARN: [GetUTXOs Handler] Mismatch after conversion for key %q: Parsed(%s, %d) != Struct(%s, %d). Using parsed values.",
											utxoKey, txID, index, typesUtxo.TransactionID, typesUtxo.Index)
										typesUtxo.TransactionID = txID
										typesUtxo.Index = index
									}

									utxosResult = append(utxosResult, typesUtxo)
								}
							}
						} // End loop through map keys

						log.Printf("DEBUG: [GetUTXOs Handler] Sending %d UTXOs back for address %s", len(utxosResult), address)
						msg.ResponseCh <- types.Response{Data: utxosResult} // Send the results
					} else {
						msg.ResponseCh <- types.Response{Error: fmt.Errorf("invalid UTXO request format")}
					}
				}
				// End case types.GetUTXOs
			// End case types.GetUTXOs
			case <-ctx.Done():
				return
			}
		}
	}()

	// --- ** NEW: Handler for AddTransactionToPool messages ** ---
	log.Println("INFO: Starting AddTransactionToPool handler goroutine...") // Log startup
	go func() {
		log.Println("INFO: [AddTxPool Handler] Goroutine started, entering select loop...") // Log entry
		for {
			select {
			case msg, ok := <-addTxCh: // Read from the NEW channel
				if !ok {
					log.Println("ERROR: [AddTxPool Handler] addTxCh channel was closed!")
					return // Exit if channel closed
				}
				log.Printf("DEBUG: [AddTxPool Handler] Message received on addTxCh (Type: %s)", msg.Type) // Log receipt

				if msg.Type == types.AddTransactionToPool {
					tx, ok := msg.Data.(*types.Transaction) // Expecting *types.Transaction
					if !ok {
						log.Printf("ERROR: [AddTxPool Handler] Invalid data type for AddTransactionToPool, expected *types.Transaction")
						if msg.ResponseCh != nil {
							msg.ResponseCh <- types.Response{Error: fmt.Errorf("invalid tx data type for pool add")}
						}
						continue // Skip this message
					}
					if tx == nil {
						log.Printf("ERROR: [AddTxPool Handler] Received nil transaction for AddTransactionToPool")
						if msg.ResponseCh != nil {
							msg.ResponseCh <- types.Response{Error: fmt.Errorf("received nil transaction")}
						}
						continue
					}

					// Call the actual AddTransactionToPool method on the blockchain instance
					// Use the 'blockchain' instance available in this scope (captured by closure)
					log.Printf("DEBUG: [AddTxPool Handler] Calling blockchain.AddTransactionToPool for TxID: %s", tx.ID)
					err := blockchain.AddTransactionToPool(tx)

					// Send the response back to the caller (handleSubmitSignedTransaction)
					if msg.ResponseCh != nil {
						if err != nil {
							log.Printf("ERROR: [AddTxPool Handler] Failed to add tx %s to pool: %v", tx.ID, err)
							msg.ResponseCh <- types.Response{Error: err}
						} else {
							log.Printf("INFO: [AddTxPool Handler] Successfully added tx %s to pool.", tx.ID)
							// Send back success, Data can be nil or the TxID
							msg.ResponseCh <- types.Response{Data: tx.ID, Error: nil}
						}
					} else {
						log.Printf("WARN: [AddTxPool Handler] No response channel provided for AddTransactionToPool message (TxID: %s)", tx.ID)
					}
				} else {
					log.Printf("WARN: [AddTxPool Handler] Received unexpected message type on addTxCh: %s", msg.Type)
					// Optionally send an error back if there's a response channel
					if msg.ResponseCh != nil {
						msg.ResponseCh <- types.Response{Error: fmt.Errorf("handler received unexpected message type: %s", msg.Type)}
					}
				}
			case <-ctx.Done():
				log.Println("INFO: [AddTxPool Handler] Context cancelled, stopping message processing.")
				return // Exit goroutine
			}
		}
	}()
	// --- ** END NEW Handler ** ---

	// Handle transaction-related messages
	go func() {
		for {
			select {
			case msg := <-txCh: // Got a message
				switch msg.Type {
				case types.ProcessTransaction:
					tx, ok := msg.Data.(*thrylos.Transaction) // Protobuf type
					if !ok {
						log.Printf("ERROR: [txCh Handler] Invalid data type for ProcessTransaction")
						if msg.ResponseCh != nil {
							msg.ResponseCh <- types.Response{Error: fmt.Errorf("invalid tx data type")}
						}
						continue
					}

					log.Printf("INFO: [txCh Handler] Processing TX ID: %s", tx.Id)

					// --- Declare ALL variables used across potential goto jumps ---
					var processingError error
					var dbTxContext types.TransactionContext
					var dbErr error
					var calculatedFee int64
					var totalInputValue int64
					var totalOutputValue int64
					var commitErr error // <<< DECLARED commitErr HERE

					// Data structures to hold changes for DB persistence
					var inputsToMarkSpentDB []types.UTXO
					var outputsToAddDB []types.UTXO
					balancesToUpdateDB := make(map[string]int64)

					// --- Trim Sender Key ---
					senderKey := strings.TrimSpace(tx.Sender)
					log.Printf("DEBUG: [txCh Handler] Trimmed sender key for lookup: %q", senderKey)

					// === BEGIN In-Memory Operations (Under Lock) ===
					blockchain.Blockchain.Mu.Lock() // <<< LOCK MEMORY

					// 1. Check Sender Exists
					_, senderExists := blockchain.Blockchain.Stakeholders[senderKey]
					if !senderExists {
						keys := make([]string, 0, len(blockchain.Blockchain.Stakeholders))
						for k := range blockchain.Blockchain.Stakeholders {
							keys = append(keys, k)
						}
						log.Printf("DEBUG: [txCh Handler] Keys currently in Stakeholders map: %q", keys)
						processingError = fmt.Errorf("sender %q not found in stakeholders map", senderKey)
						blockchain.Blockchain.Mu.Unlock() // Unlock before goto
						goto SendResponse                 // Jump directly to SendResponse logic
					}

					// 2. Validate Inputs, Calculate Value & Mark Spent (In Memory)
					totalInputValue = 0
					if len(tx.Inputs) == 0 {
						processingError = fmt.Errorf("transaction %s has no inputs", tx.Id)
						blockchain.Blockchain.Mu.Unlock()
						goto SendResponse
					}

					inputsToMarkSpentDB = make([]types.UTXO, 0, len(tx.Inputs)) // Initialize slice

					for _, inputProto := range tx.Inputs {
						inputKey := fmt.Sprintf("%s-%d", inputProto.TransactionId, inputProto.Index)
						utxoList, exists := blockchain.Blockchain.UTXOs[inputKey]
						// Add fallback check for ':' if necessary
						if !exists {
							altInputKey := fmt.Sprintf("%s:%d", inputProto.TransactionId, inputProto.Index)
							utxoList, exists = blockchain.Blockchain.UTXOs[altInputKey]
							if !exists {
								processingError = fmt.Errorf("input UTXO key %s (or %s) not found tx %s", inputKey, altInputKey, tx.Id)
								blockchain.Blockchain.Mu.Unlock()
								goto SendResponse
							} else {
								inputKey = altInputKey
								log.Printf("WARN: [txCh Handler] Used fallback key format '%s' for UTXO map lookup.", inputKey)
							}
						}

						found := false
						for _, utxoInMap := range utxoList { // utxoInMap is *thrylos.UTXO
							if utxoInMap.OwnerAddress == senderKey && !utxoInMap.IsSpent && utxoInMap.Amount == inputProto.Amount {
								if utxoInMap.IsSpent {
									processingError = fmt.Errorf("attempt double-spend UTXO %s tx %s", inputKey, tx.Id)
									blockchain.Blockchain.Mu.Unlock()
									goto SendResponse
								}

								utxoInMap.IsSpent = true // Mark spent in memory
								totalInputValue += utxoInMap.Amount
								found = true
								// Add types.UTXO version to list for DB update LATER
								inputsToMarkSpentDB = append(inputsToMarkSpentDB, convertProtoToTypesUTXO(utxoInMap))
								log.Printf("INFO: [txCh Handler] Marked UTXO %s (Val: %d) spent in memory TX %s", inputKey, utxoInMap.Amount, tx.Id)
								break
							}
						}
						if !found {
							processingError = fmt.Errorf("spendable input UTXO %s sender %q not found/spent tx %s", inputKey, senderKey, tx.Id)
							blockchain.Blockchain.Mu.Unlock()
							goto SendResponse
						}
					} // End input loop

					// 3. Calculate Output Value
					totalOutputValue = 0
					for _, output := range tx.Outputs {
						totalOutputValue += output.Amount
					}

					// 4. Verify Fee & Sufficient Input
					calculatedFee = totalInputValue - totalOutputValue
					if calculatedFee < 0 {
						processingError = fmt.Errorf("tx %s outputs exceed inputs (%d > %d)", tx.Id, totalOutputValue, totalInputValue)
						blockchain.Blockchain.Mu.Unlock()
						goto SendResponse
					}
					if calculatedFee != int64(tx.Gasfee) {
						log.Printf("WARN: Fee mismatch tx %s: Calc %d != Stated %d. ALLOWING.", tx.Id, calculatedFee, tx.Gasfee)
					}
					if totalInputValue < totalOutputValue+int64(tx.Gasfee) {
						processingError = fmt.Errorf("insufficient input %d for outputs+fee %d tx %s", totalInputValue, totalOutputValue+int64(tx.Gasfee), tx.Id)
						blockchain.Blockchain.Mu.Unlock()
						goto SendResponse
					}

					// 5. Update Stakeholders Map (In Memory) & Collect Balances for DB
					log.Printf("INFO: [txCh Handler] Updating stakeholder balances in memory TX %s", tx.Id)
					blockchain.Blockchain.Stakeholders[senderKey] -= totalInputValue
					balancesToUpdateDB[senderKey] = blockchain.Blockchain.Stakeholders[senderKey] // Store final sender balance

					for _, output := range tx.Outputs {
						receiverKey := strings.TrimSpace(output.OwnerAddress)
						blockchain.Blockchain.Stakeholders[receiverKey] += output.Amount
						balancesToUpdateDB[receiverKey] = blockchain.Blockchain.Stakeholders[receiverKey] // Store final receiver balance
						log.Printf("DEBUG: [txCh Handler] Updated receiver %s in memory: %d", receiverKey, blockchain.Blockchain.Stakeholders[receiverKey])
					}

					// 6. Add New UTXOs to Memory Map & Collect for DB
					log.Printf("INFO: [txCh Handler] Adding %d new UTXOs memory TX %s", len(tx.Outputs), tx.Id)
					outputsToAddDB = make([]types.UTXO, 0, len(tx.Outputs)) // Initialize slice

					for i, outputProto := range tx.Outputs {
						outputKey := fmt.Sprintf("%s-%d", tx.Id, i)
						ownerAddrKey := strings.TrimSpace(outputProto.OwnerAddress)
						newUTXOProto := &thrylos.UTXO{TransactionId: tx.Id, Index: int32(i), OwnerAddress: ownerAddrKey, Amount: outputProto.Amount, IsSpent: false}
						blockchain.Blockchain.UTXOs[outputKey] = append(blockchain.Blockchain.UTXOs[outputKey], newUTXOProto)
						// Add types.UTXO version to list for DB update LATER
						outputsToAddDB = append(outputsToAddDB, convertProtoToTypesUTXO(newUTXOProto))
						log.Printf("INFO: [txCh Handler] Added new UTXO %s to memory TX %s", outputKey, tx.Id)
					}

					// --- Unlock In-Memory State ---
					log.Printf("DEBUG: [txCh Handler] Releasing memory lock before DB operations for TX %s", tx.Id)
					blockchain.Blockchain.Mu.Unlock() // <<< UNLOCK MEMORY NOW
					// === END In-Memory Operations ===

					// --- Perform Database Operations (Outside Memory Lock, Within DB Transaction) ---
					log.Printf("DEBUG: [txCh Handler] Starting DB operations for TX %s", tx.Id)

					dbTxContext, dbErr = blockchain.Blockchain.Database.BeginTransaction()
					if dbErr != nil {
						log.Printf("ERROR: [txCh Handler] Failed DB begin TX %s: %v", tx.Id, dbErr)
						processingError = fmt.Errorf("failed to begin DB tx: %v", dbErr)
						goto SendResponse // Jump to send error response
					}
					// Defer rollback for DB transaction specifically
					defer func() {
						if processingError != nil && dbTxContext != nil { // Check processingError from outer scope
							log.Printf("WARN: Rolling back DB TX %s: %v", tx.Id, processingError)
							rbErr := blockchain.Blockchain.Database.RollbackTransaction(dbTxContext)
							if rbErr != nil {
								log.Printf("ERROR: Rollback failed TX %s: %v", tx.Id, rbErr)
							}
						}
					}()

					// Persist Spent UTXOs
					log.Printf("DEBUG: [txCh Handler] Persisting %d spent inputs to DB for TX %s", len(inputsToMarkSpentDB), tx.Id)
					for _, spentUtxo := range inputsToMarkSpentDB {
						dbErr = blockchain.Blockchain.Database.MarkUTXOAsSpent(dbTxContext, spentUtxo) // Assign to dbErr
						if dbErr != nil {
							processingError = fmt.Errorf("failed DB mark spent %s-%d: %v", spentUtxo.TransactionID, spentUtxo.Index, dbErr)
							goto EndProcessingDB
						}
						log.Printf("INFO: [txCh Handler] Marked UTXO %s-%d spent in DB TX %s", spentUtxo.TransactionID, spentUtxo.Index, tx.Id)
					}

					// Persist Stakeholder Balances
					log.Printf("DEBUG: [txCh Handler] Persisting %d stakeholder balances to DB for TX %s", len(balancesToUpdateDB), tx.Id)
					for addr, balance := range balancesToUpdateDB {
						dbErr = blockchain.Blockchain.Database.UpdateBalance(addr, balance) // Assign to dbErr
						if dbErr != nil {
							processingError = fmt.Errorf("failed DB update balance %s: %v", addr, dbErr)
							goto EndProcessingDB
						}
						log.Printf("SUCCESS: Updated balance for %s in DB to %d", addr, balance)
					}

					// Persist New UTXOs
					log.Printf("DEBUG: [txCh Handler] Persisting %d new outputs to DB for TX %s", len(outputsToAddDB), tx.Id)
					for _, newUtxo := range outputsToAddDB {
						dbErr = blockchain.Blockchain.Database.AddNewUTXO(dbTxContext, newUtxo) // Assign to dbErr
						if dbErr != nil {
							processingError = fmt.Errorf("failed DB add new UTXO %s-%d: %v", newUtxo.TransactionID, newUtxo.Index, dbErr)
							goto EndProcessingDB
						}
						log.Printf("INFO: [txCh Handler] Added new UTXO %s-%d to DB TX %s", newUtxo.TransactionID, newUtxo.Index, tx.Id)
					}

				EndProcessingDB: // Label for errors DURING DB operations
					if processingError != nil {
						// Error already set, defer func above will rollback
						log.Printf("ERROR: [txCh Handler] Error occurred during DB operations for TX %s: %v", tx.Id, processingError)
						goto SendResponse // Jump to send error response
					}

					// Commit DB Transaction if no errors occurred during DB phase
					log.Printf("DEBUG: [txCh Handler] Attempting DB commit for TX %s", tx.Id)
					commitErr = blockchain.Blockchain.Database.CommitTransaction(dbTxContext) // <<< ASSIGN to commitErr
					if commitErr != nil {
						log.Printf("ERROR: [txCh Handler] Failed DB commit TX %s: %v", tx.Id, commitErr)
						processingError = fmt.Errorf("failed DB commit: %v", commitErr)
						// Rollback handled by defer
						goto SendResponse
					}
					dbTxContext = nil // Prevent rollback by defer if commit succeeded
					log.Printf("INFO: [txCh Handler] Committed DB TX %s", tx.Id)

				SendResponse: // Label for sending response

					// --- Send Response ---
					if msg.ResponseCh != nil {
						if processingError != nil {
							log.Printf("ERROR: [txCh Handler] Final Failure processing TX %s: %v", tx.Id, processingError)
							msg.ResponseCh <- types.Response{Error: processingError}
						} else {
							log.Printf("INFO: [txCh Handler] Final Success processing TX %s", tx.Id)
							msg.ResponseCh <- types.Response{Data: tx.Id, Error: nil} // Send success
						}
					} else { /* Log no response channel */
					}

				// End of case types.ProcessTransaction
				default:
					log.Printf("WARN: [txCh Handler] Received unhandled message type: %s", msg.Type)

				} // End switch msg.Type

			case <-ctx.Done(): // Got context cancellation
				log.Println("INFO: [txCh Handler] Context cancelled, stopping message processing.")
				return // Exit goroutine

			} // End select
		} // End for loop
	}() // End goroutine func

	// Handle block-related messages
	go func() {
		for {
			select {
			case msg := <-blockCh:
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
			case <-ctx.Done():
				return
			}
		}
	}()

	// Handle blockchain info messages
	go func() {
		for {
			select {
			case msg := <-infoCh:
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
			case <-ctx.Done():
				return
			}
		}
	}()
}
