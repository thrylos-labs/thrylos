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
	"github.com/multiformats/go-multiaddr"    // Import multiaddr for libp2p addresses
	thrylos "github.com/thrylos-labs/thrylos" // Assuming 'thrylos' is your protobuf definitions
	"github.com/thrylos-labs/thrylos/amount"
	"github.com/thrylos-labs/thrylos/chain"
	"github.com/thrylos-labs/thrylos/config"
	"github.com/thrylos-labs/thrylos/consensus/staking"
	"github.com/thrylos-labs/thrylos/consensus/validator"
	"github.com/thrylos-labs/thrylos/crypto"
	"github.com/thrylos-labs/thrylos/network" // Your updated network package
	"github.com/thrylos-labs/thrylos/node"
	"github.com/thrylos-labs/thrylos/store" // Import store to use CalculateShardID
	"github.com/thrylos-labs/thrylos/types"
)

func main() {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	signalCh := make(chan os.Signal, 1)
	signal.Notify(signalCh, os.Interrupt, syscall.SIGTERM)

	go func() {
		<-signalCh
		log.Println("Stopping blockchain...")
		shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer shutdownCancel()
		cancel()
		<-shutdownCtx.Done()
		log.Println("Shutdown complete")
		os.Exit(0)
	}()

	envFile, err := loadEnv()
	if err != nil {
		log.Fatalf("Error loading environment variables: %v", err)
	}

	httpAddress := envFile["HTTP_NODE_ADDRESS"]
	peersStr := envFile["PEERS"]
	dataDir := envFile["DATA_DIR"]
	testnet := envFile["TESTNET"] == "true"
	var currentChainID string // Declared here to be accessible later
	serverHost := envFile["SERVER_HOST"]

	gasEstimateURL := envFile["GAS_ESTIMATE_URL"]
	if gasEstimateURL == "" {
		log.Fatal("Gas estimate URL is not set in environment variables")
	}

	useSSL := strings.HasPrefix(httpAddress, "https://")

	if dataDir == "" {
		log.Fatal("DATA_DIR environment variable is not set")
	}
	if testnet {
		fmt.Println("Running in Testnet Mode")
	}

	base64Key := envFile["AES_KEY_ENV_VAR"]
	if base64Key == "" {
		log.Fatal("AES key is not set in environment variables")
	}
	aesKey, err := base64.StdEncoding.DecodeString(base64Key)
	if err != nil {
		log.Fatalf("Error decoding AES key: %v", err)
	}

	base64PrivKey := envFile["GENESIS_PRIVATE_KEY_RAW_B64"]
	if base64PrivKey == "" {
		log.Fatal("GENESIS_PRIVATE_KEY_RAW_B64 is not set in environment variables.")
	}
	PrivKeyBytes, err := base64.StdEncoding.DecodeString(base64PrivKey)
	if err != nil {
		log.Fatalf("Failed to base64 decode GENESIS_PRIVATE_KEY_CBOR_B64: %v", err)
	}
	genesisPrivKey, err := crypto.NewPrivateKeyFromBytes(PrivKeyBytes)
	if err != nil {
		log.Fatalf("Failed to deserialize genesis private key: %v", err)
	}
	log.Println("Successfully loaded persistent Genesis private key.")

	if genesisPrivKey != nil && genesisPrivKey.PublicKey() != nil {
		rawPubKeyBytes := genesisPrivKey.PublicKey().Bytes()
		if rawPubKeyBytes != nil {
			log.Printf("DEBUG: [main] Loaded Genesis RAW Public Key Bytes: %x", rawPubKeyBytes)
		} else {
			log.Printf("ERROR: [main] Failed to get raw bytes from loaded Genesis public key")
		}
	} else {
		log.Printf("ERROR: [main] Loaded Genesis private key or its public key is nil")
	}

	absPath, err := filepath.Abs(dataDir)
	if err != nil {
		log.Fatalf("Error resolving the absolute path of the blockchain data directory: %v", err)
	}
	log.Printf("Using blockchain data directory: %s", absPath)

	// Load global configuration first to get NumShards
	cfg, err := config.LoadOrCreateConfig("config.toml")
	if err != nil {
		log.Fatalf("Failed to load config: %v", err)
	}

	// Retrieve NumShards from the loaded config
	totalNumShards := cfg.NumShards
	if totalNumShards <= 0 {
		log.Fatalf("Invalid NumShards configured: %d. Must be greater than 0.", totalNumShards)
	}
	log.Printf("Network configured with %d shards.", totalNumShards)

	// --- SHARDING MODIFICATION START ---
	// Determine the node's role: Shard Node or Beacon Node
	var nodeShardID *types.ShardID // Pointer to indicate if this node is shard-specific
	myShardIDStr := os.Getenv("SHARD_ID")

	isBeaconNode := false

	if myShardIDStr != "" {
		parsedShardID, err := strconv.Atoi(myShardIDStr)
		if err != nil {
			log.Fatalf("Invalid SHARD_ID environment variable: %v", err)
		}
		if parsedShardID < 0 || parsedShardID >= totalNumShards { // Use totalNumShards here
			log.Fatalf("SHARD_ID (%d) is out of valid range (0 to %d).", parsedShardID, totalNumShards-1)
		}
		id := types.ShardID(parsedShardID)
		nodeShardID = &id
		log.Printf("Node configured to run as a Shard Node for Shard ID: %d", *nodeShardID)
	} else {
		// If no SHARD_ID is set, assume it's a Beacon Chain node.
		log.Println("SHARD_ID not set. Node will run as a Beacon Chain node.")
		isBeaconNode = true
		// The Beacon Chain itself can be considered a special shard (e.g., ShardID(-1))
		beaconID := types.ShardID(-1) // Sentinel value for beacon chain
		nodeShardID = &beaconID
	}

	// Adapt data directory for sharding
	finalDataDir := absPath
	if !isBeaconNode { // Shard-specific directory for shard nodes
		finalDataDir = filepath.Join(absPath, fmt.Sprintf("shard-%d", *nodeShardID))
		if err := os.MkdirAll(finalDataDir, 0755); err != nil {
			log.Fatalf("Failed to create shard data directory %s: %v", finalDataDir, err)
		}
		log.Printf("Using shard-specific data directory: %s", finalDataDir)
	} else { // Global data directory for Beacon Node
		finalDataDir = filepath.Join(absPath, "beacon-chain") // Separate dir for beacon
		if err := os.MkdirAll(finalDataDir, 0755); err != nil {
			log.Fatalf("Failed to create beacon chain data directory %s: %v", finalDataDir, err)
		}
		log.Printf("Using global data directory for Beacon Chain: %s", finalDataDir)
	}

	lockFile := filepath.Join(finalDataDir, "LOCK") // Lock file is now role-specific
	log.Printf("Attempting to remove lock file: %s", lockFile)
	_ = os.Remove(lockFile) // Remove role-specific lock file

	blockchainConfig := &types.BlockchainConfig{
		DataDir:           finalDataDir, // Use the role-specific dataDir
		AESKey:            aesKey,
		GenesisAccount:    genesisPrivKey,
		TestMode:          testnet, // Use testnet from envFile
		DisableBackground: false,
	}
	// --- SHARDING MODIFICATION END ---

	messageBus := types.GetGlobalMessageBus() // Global message bus for inter-component communication

	var libp2pBootstrapPeers []multiaddr.Multiaddr
	if peersStr != "" {
		for _, p := range strings.Split(peersStr, ",") {
			p = strings.TrimSpace(p)
			if p == "" {
				continue
			}
			addr, err := multiaddr.NewMultiaddr(p)
			if err != nil {
				log.Printf("WARN: Invalid libp2p bootstrap peer address '%s': %v", p, err)
				continue
			}
			libp2pBootstrapPeers = append(libp2pBootstrapPeers, addr)
		}
		log.Printf("Configured with %d initial libp2p bootstrap peers", len(libp2pBootstrapPeers))
	} else {
		log.Println("No initial libp2p bootstrap peers configured. Node will rely on mDNS and DHT for discovery.")
	}

	libp2pPort := 4001
	if pStr := os.Getenv("LIBP2P_PORT"); pStr != "" {
		if p, err := strconv.Atoi(pStr); err == nil && p > 0 {
			libp2pPort = p
		} else {
			log.Printf("WARN: Invalid LIBP2P_PORT '%s', using default %d", pStr, libp2pPort)
		}
	}

	// The Libp2pManager needs to be aware of sharding for peer discovery and message routing.
	// It will need to know which shard(s) this node is serving.
	netManager, err := network.NewLibp2pManager(messageBus, libp2pPort, libp2pBootstrapPeers)
	if err != nil {
		log.Fatalf("Failed to create libp2p network manager: %v", err)
	}
	defer netManager.Close()
	netManager.StartLibp2pServices()

	// Channel to signal when message bus handlers are ready to receive queries
	messageBusHandlersReady := make(chan struct{})

	// --- SHARDING MODIFICATION START (Instance creation) ---
	var currentChainImpl *chain.BlockchainImpl // This will hold the single chain instance this node manages (shard or beacon)

	// chain.NewBlockchain must now accept the ShardID and totalNumShards
	currentChainImpl, _, err = chain.NewBlockchain(blockchainConfig, cfg, netManager, *nodeShardID, totalNumShards)
	if err != nil {
		log.Fatalf("Failed to initialize blockchain for role (ShardID: %d) at %s: %v", *nodeShardID, finalDataDir, err)
	}

	if isBeaconNode {
		log.Println("Successfully initialized Beacon Chain blockchain.")
		currentChainID = "thrylos-beacon-chain" // Assign to currentChainID
	} else {
		log.Printf("Successfully initialized Shard %d blockchain.", *nodeShardID)
		currentChainID = fmt.Sprintf("thrylos-shard-%d", *nodeShardID) // Assign to currentChainID
	}

	// Ensure currentChainImpl is not nil (should be handled by the NewBlockchain fatal error)
	if currentChainImpl == nil {
		log.Fatalf("Blockchain initialization failed: currentChainImpl is nil unexpectedly.")
	}
	// --- SHARDING MODIFICATION END (Instance creation) ---

	// Pass the new channel to connectBlockchainToMessageBus.
	// `currentChainID` is now defined and populated.
	connectBlockchainToMessageBus(ctx, currentChainImpl, messageBus, currentChainID, messageBusHandlersReady)

	// Wait for message bus handlers to be ready
	select {
	case <-messageBusHandlersReady:
		log.Println("INFO: Message bus handlers are ready.")
	case <-time.After(15 * time.Second):
		log.Println("WARN: Timeout waiting for message bus handlers to become ready. Proceeding anyway.")
	}

	defer func() {
		log.Println("Closing blockchain in defer function...")
		if currentChainImpl != nil {
			if err := currentChainImpl.Close(); err != nil {
				log.Printf("Error closing blockchain: %v", err)
			} else {
				log.Println("Blockchain closed successfully")
			}
		}
	}()

	// Check chain integrity for the specific shard/beacon chain this node manages
	if !currentChainImpl.CheckChainIntegrity() {
		log.Fatalf("Blockchain integrity check failed for %s.", currentChainID)
	} else {
		fmt.Printf("Blockchain integrity check passed for %s.\n", currentChainID)
	}

	log.Println("Attempting to generate 4 additional validators...")

	// Use the corrected method that generates keys properly
	generatedAddresses, err := currentChainImpl.GenerateAndStoreValidatorKeys(4)
	if err != nil {
		log.Fatalf("Failed to generate validators: %v", err)
	}

	log.Printf("Successfully generated %d validators:", len(generatedAddresses))
	for i, addr := range generatedAddresses {
		log.Printf("  Validator %d: %s", i+1, addr)
	}

	log.Println("Finished validator generation.")

	// Instantiate the Node here, passing all necessary configuration
	mainNode := node.NewNode(
		httpAddress,
		blockchainConfig, // This config is now shard-specific
		gasEstimateURL,
		serverHost,
		useSSL,
		netManager,
		messageBus,
	)

	// Set the *types.ChainState (which is the new name for the core state)
	// You need to change the signature of `mainNode.SetBlockchain`
	// to accept `*types.ChainState` instead of `*types.Blockchain`.
	// Assuming `node.Node` and its `SetBlockchain` method are now updated.
	mainNode.SetBlockchain(currentChainImpl.GetChainState())

	// Staking service would be tied to the specific chain being run (shard or beacon)
	stakingService := staking.NewStakingService(currentChainImpl.GetChainState())
	if stakingService == nil {
		log.Fatalf("Failed to initialize StakingService")
	}
	mainNode.StakingService = stakingService

	isDesignatedVoteCounter := false

	genesisAddr, err := blockchainConfig.GenesisAccount.PublicKey().Address()
	if err != nil {
		log.Fatalf("Failed to get genesis account address: %v", err)

	}

	// This logic `genesisAddr.String() == mainNode.Address` might need re-evaluation
	// in a sharded setup, especially for validator roles.
	if genesisAddr.String() == mainNode.Address {
		isDesignatedVoteCounter = true
	}

	mainNode.VoteCounter = validator.NewVoteCounter(
		mainNode,
		isDesignatedVoteCounter,
		netManager,
		mainNode.Address,
	)

	go func() {
		mainNode.VoteCounter.UpdateRequiredVotes()
		log.Println("INFO: Initial call to UpdateRequiredVotes completed (post-blockchain ready).")
	}()

	// Router and HTTP/WS servers might need to know about shards if API calls specify a shard.
	// For a single-shard node, API calls implicitly target its shard.
	// For a beacon node, APIs might target beacon chain state or route cross-shard queries.
	router := network.NewRouter(messageBus, cfg, netManager)
	mux := router.SetupRoutes()

	wsServer, httpServer := setupServers(mux, envFile)

	go startServer(ctx, wsServer, "WebSocket", envFile["ENV"] == "development")
	go startServer(ctx, httpServer, "HTTP(S)", envFile["ENV"] == "development")

	<-ctx.Done()
}

// loadEnv function is now only in main.go
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

	absPath, err := filepath.Abs(envPath)
	if err != nil {
		return nil, fmt.Errorf("failed to get absolute path for %s: %v", envPath, err)
	}

	if _, err := os.Stat(absPath); os.IsNotExist(err) {
		return nil, fmt.Errorf("environment file not found at %s", absPath)
	}

	envFile, err := godotenv.Read(envPath)
	if err != nil {
		return nil, fmt.Errorf("error reading environment file at %s: %v", absPath, err)
	}

	requiredVars := []string{
		"WS_ADDRESS",
		"HTTP_NODE_ADDRESS",
		"GRPC_NODE_ADDRESS",
		"AES_KEY_ENV_VAR",
		"DATA_DIR",
		"GENESIS_PRIVATE_KEY_RAW_B64",
		"GAS_ESTIMATE_URL", // Added this to requiredVars check
		"SERVER_HOST",      // Added this to requiredVars check, assuming it's for Node's own host
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

	if env == "development" {
		log.Println("Running in development mode - TLS will be disabled")
		envFile["ENV"] = "development"
		envFile["CERT_FILE"] = ""
		envFile["KEY_FILE"] = ""
		envFile["TLS_CERT_PATH"] = ""
		envFile["TLS_KEY_PATH"] = ""
	}

	return envFile, nil
}

func convertProtoToTypesUTXO(protoUTXO *thrylos.UTXO) types.UTXO {
	if protoUTXO == nil {
		log.Printf("WARN: convertProtoToTypesUTXO received nil input")
		return types.UTXO{}
	}

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

	wsServer := &http.Server{
		Addr:      wsAddress,
		Handler:   r,
		TLSConfig: tlsConfig,
	}
	httpServer := &http.Server{
		Addr:      httpAddress,
		Handler:   r,
		TLSConfig: tlsConfig,
	}

	return wsServer, httpServer
}

func startServer(ctx context.Context, server *http.Server, serverType string, isDevelopment bool) {
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

	go func() {
		<-ctx.Done()
		log.Printf("Shutting down %s server...", serverType)

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

// connectBlockchainToMessageBus now expects a *chain.BlockchainImpl, which internally
// manages a *types.ChainState (representing either a shard chain or the beacon chain).
// All message bus handlers must now operate on this specific chain's state.
func connectBlockchainToMessageBus(ctx context.Context, bcImpl *chain.BlockchainImpl, messageBus types.MessageBusInterface, chainID string, handlersReady chan<- struct{}) {
	// Create channels to receive messages
	balanceCh := make(chan types.Message, 100)
	blockCh := make(chan types.Message, 100)
	txCh := make(chan types.Message, 100)
	infoCh := make(chan types.Message, 100)
	addTxCh := make(chan types.Message, 100)

	// Subscribe to messages
	messageBus.Subscribe(types.GetBalance, balanceCh)
	messageBus.Subscribe(types.GetUTXOs, balanceCh)
	messageBus.Subscribe(types.ProcessTransaction, txCh)
	messageBus.Subscribe(types.ProcessBlock, blockCh)
	messageBus.Subscribe(types.GetBlockchainInfo, infoCh)
	messageBus.Subscribe(types.AddTransactionToPool, addTxCh)
	messageBus.Subscribe(types.GetActiveValidators, infoCh)
	messageBus.Subscribe(types.IsActiveValidator, infoCh)
	messageBus.Subscribe(types.GetStakeholders, infoCh)
	messageBus.Subscribe(types.ConfirmBlock, blockCh)

	// Access the specific ChainState this BlockchainImpl manages
	// This assumes bcImpl.GetChainState() exists and returns *types.ChainState
	chainState := bcImpl.GetChainState()
	if chainState == nil {
		log.Fatalf("FATAL: connectBlockchainToMessageBus called with nil ChainState from bcImpl.")
	}

	go func() {
		select {
		case <-time.After(5 * time.Second): // Wait for everything to start up
			log.Println("Running stakeholders map test...")
			// TestStakeholdersMap needs to be updated to operate on chainState
			bcImpl.TestStakeholdersMap() // This method in chain.BlockchainImpl needs access to its ChainState
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
						// Access specific shard's state
						chainState.Mu.RLock()
						balance := int64(0)
						if bal, exists := chainState.Stakeholders[address]; exists {
							balance = bal
						}
						chainState.Mu.RUnlock()
						msg.ResponseCh <- types.Response{Data: balance}
					} else {
						msg.ResponseCh <- types.Response{Error: fmt.Errorf("invalid address format")}
					}
				case types.GetUTXOs:
					if req, ok := msg.Data.(types.UTXORequest); ok {
						address := req.Address
						log.Printf("DEBUG: [GetUTXOs Handler] Request received for address: %s", address)
						utxosResult := []types.UTXO{}

						// IMPORTANT: Instead of iterating in-memory map, query the sharded database.
						// Get UTXOs from the *shard-specific* database
						// This call to GetUTXOsForAddress needs to be shard-aware in its implementation
						// in store/store.go (using shardID in the key prefix).
						// It also needs totalNumShards now.
						dbUTXOs, err := chainState.Database.GetUTXOsForAddress(address, chainState.TotalNumShards) // Added totalNumShards
						if err != nil {
							log.Printf("ERROR: [GetUTXOs Handler] Failed to get UTXOs from DB for address %s: %v", address, err)
							msg.ResponseCh <- types.Response{Error: fmt.Errorf("failed to retrieve UTXOs: %w", err)}
							continue
						}
						utxosResult = dbUTXOs // Assuming dbUTXOs is []types.UTXO

						log.Printf("DEBUG: [GetUTXOs Handler] Sending %d UTXOs back for address %s", len(utxosResult), address)
						msg.ResponseCh <- types.Response{Data: utxosResult}
					} else {
						msg.ResponseCh <- types.Response{Error: fmt.Errorf("invalid UTXO request format")}
					}
				}
			case <-ctx.Done():
				return
			}
		}
	}()

	// Handle AddTransactionToPool messages
	go func() {
		for {
			select {
			case msg, ok := <-addTxCh:
				if !ok {
					log.Println("ERROR: [AddTxPool Handler] addTxCh channel was closed!")
					return
				}
				log.Printf("DEBUG: [AddTxPool Handler] Message received on addTxCh (Type: %s)", msg.Type)

				if msg.Type == types.AddTransactionToPool {
					tx, ok := msg.Data.(*types.Transaction)
					if !ok {
						log.Printf("ERROR: [AddTxPool Handler] Invalid data type for AddTransactionToPool, expected *types.Transaction")
						if msg.ResponseCh != nil {
							msg.ResponseCh <- types.Response{Error: fmt.Errorf("invalid tx data type for pool add")}
						}
						continue
					}
					if tx == nil {
						log.Printf("ERROR: [AddTxPool Handler] Received nil transaction for AddTransactionToPool")
						if msg.ResponseCh != nil {
							msg.ResponseCh <- types.Response{Error: fmt.Errorf("received nil transaction")}
						}
						continue
					}

					// SHARDING AWARENESS: Verify if this transaction belongs to THIS shard
					txSenderAddress := tx.SenderAddress.String()                                          // Assuming SenderAddress is set
					expectedShardID := store.CalculateShardID(txSenderAddress, chainState.TotalNumShards) // Get TotalNumShards from ChainState

					if expectedShardID != chainState.ShardID && chainState.ShardID != types.ShardID(-1) { // If not for this shard, AND not a beacon node
						log.Printf("WARN: [AddTxPool Handler] Transaction %s for sender %s (expected shard %d) received on shard %d node. Rejecting/Forwarding.",
							tx.ID, txSenderAddress, expectedShardID, chainState.ShardID)
						if msg.ResponseCh != nil {
							msg.ResponseCh <- types.Response{Error: fmt.Errorf("transaction %s does not belong to this shard %d; belongs to %d", tx.ID, chainState.ShardID, expectedShardID)}
						}
						continue // Reject the transaction
					}

					err := bcImpl.AddTransactionToPool(tx) // This method needs to be shard-aware

					if msg.ResponseCh != nil {
						if err != nil {
							log.Printf("ERROR: [AddTxPool Handler] Failed to add tx %s to pool: %v", tx.ID, err)
							msg.ResponseCh <- types.Response{Error: err}
						} else {
							log.Printf("INFO: [AddTxPool Handler] Successfully added tx %s to pool.", tx.ID)
							msg.ResponseCh <- types.Response{Data: tx.ID, Error: nil}
						}
					} else {
						log.Printf("WARN: [AddTxPool Handler] No response channel provided for AddTransactionToPool message (TxID: %s)", tx.ID)
					}
				} else {
					log.Printf("WARN: [AddTxPool Handler] Received unexpected message type on addTxCh: %s", msg.Type)
					if msg.ResponseCh != nil {
						msg.ResponseCh <- types.Response{Error: fmt.Errorf("handler received unexpected message type: %s", msg.Type)}
					}
				}
			case <-ctx.Done():
				log.Println("INFO: [AddTxPool Handler] Context cancelled, stopping message processing.")
				return
			}
		}
	}()

	// Handle transaction-related messages (ProcessTransaction)
	go func() {
		for {
			select {
			case msg := <-txCh:
				switch msg.Type {
				case types.ProcessTransaction:
					tx, ok := msg.Data.(*thrylos.Transaction) // Still expecting Protobuf type from old usage
					if !ok {
						log.Printf("ERROR: [txCh Handler] Invalid data type for ProcessTransaction")
						if msg.ResponseCh != nil {
							msg.ResponseCh <- types.Response{Error: fmt.Errorf("invalid tx data type")}
						}
						continue
					}

					log.Printf("INFO: [txCh Handler] Processing TX ID: %s", tx.Id)

					// SHARDING AWARENESS: Re-verify transaction belongs to this shard for processing
					txSenderAddress := tx.Sender // Assuming tx.Sender (protobuf) is the string address
					expectedShardID := store.CalculateShardID(txSenderAddress, chainState.TotalNumShards)

					if expectedShardID != chainState.ShardID && chainState.ShardID != types.ShardID(-1) {
						log.Printf("WARN: [txCh Handler] Transaction %s for sender %s (expected shard %d) received for processing on shard %d node. Skipping.",
							tx.Id, txSenderAddress, expectedShardID, chainState.ShardID)
						if msg.ResponseCh != nil {
							msg.ResponseCh <- types.Response{Error: fmt.Errorf("transaction %s does not belong to this shard %d for processing", tx.Id, chainState.ShardID)}
						}
						continue
					}

					// --- All internal operations now use chainState.Mu, chainState.UTXOs, chainState.Stakeholders, chainState.Database ---
					// This section needs substantial refactoring within chain.BlockchainImpl.ProcessTransaction
					// to use the *shard-specific* state. The `blockchain.Blockchain.Mu.Lock()` etc.
					// calls need to be replaced with `chainState.Mu.Lock()`.
					// The core logic of processing a transaction (inputs, outputs, balances)
					// will now operate *only* on the data belonging to this shard.

					// Since chain.BlockchainImpl.ProcessIncomingTransaction (called from block creation loop)
					// and chain.BlockchainImpl.AddBlockToChain internally handle state updates with locks,
					// this `ProcessTransaction` message handler here (if it's still needed) would also need
					// to call the appropriate methods on `bcImpl` (which would then access `chainState`).

					// For now, I'll update the direct state accesses to use `chainState`.
					// This part is the most complex as it directly interacts with your core logic.

					// --- Declare ALL variables used across potential goto jumps ---
					var processingError error
					var dbTxContext types.TransactionContext
					var dbErr error
					var calculatedFee int64
					var totalInputValue int64
					var totalOutputValue int64
					var commitErr error

					// Data structures to hold changes for DB persistence
					var inputsToMarkSpentDB []types.UTXO
					var outputsToAddDB []types.UTXO
					balancesToUpdateDB := make(map[string]int64)

					// --- Trim Sender Key ---
					senderKey := strings.TrimSpace(tx.Sender) // Protobuf tx.Sender string
					log.Printf("DEBUG: [txCh Handler] Trimmed sender key for lookup: %q", senderKey)

					// === BEGIN In-Memory Operations (Under Lock) ===
					chainState.Mu.Lock()         // <<< LOCK THE SHARD-SPECIFIC MEMORY
					defer chainState.Mu.Unlock() // Ensure unlock on exit

					// 1. Check Sender Exists (within this shard's stakeholders)
					_, senderExists := chainState.Stakeholders[senderKey]
					if !senderExists {
						log.Printf("DEBUG: [txCh Handler] Sender %q not found in stakeholders map for shard %d", senderKey, chainState.ShardID)
						processingError = fmt.Errorf("sender %q not found in stakeholders map for this shard", senderKey)
						goto SendResponse
					}

					// 2. Validate Inputs, Calculate Value & Mark Spent (In Memory)
					totalInputValue = 0
					if len(tx.Inputs) == 0 {
						processingError = fmt.Errorf("transaction %s has no inputs", tx.Id)
						goto SendResponse
					}

					inputsToMarkSpentDB = make([]types.UTXO, 0, len(tx.Inputs))

					for _, inputProto := range tx.Inputs {
						// The key used in `blockchain.Blockchain.UTXOs` is "txid-index"
						inputKey := fmt.Sprintf("%s-%d", inputProto.TransactionId, inputProto.Index)
						utxoList, exists := chainState.UTXOs[inputKey] // Access shard's UTXOs
						if !exists || len(utxoList) == 0 {             // Check both existence and empty slice
							processingError = fmt.Errorf("input UTXO key %s not found or empty for tx %s in shard %d", inputKey, tx.Id, chainState.ShardID)
							goto SendResponse
						}
						// Assume first element is the correct one for now, as per your `blockchain.go` logic
						utxoInMap := utxoList[0] // Assuming single UTXO per key string
						if utxoInMap.OwnerAddress != senderKey || utxoInMap.IsSpent || utxoInMap.Amount != inputProto.Amount {
							// Detailed checks: Owner mismatch, already spent, or amount mismatch
							processingError = fmt.Errorf("spendable input UTXO %s for sender %q not found/spent/amount-mismatch in shard %d for tx %s",
								inputKey, senderKey, chainState.ShardID, tx.Id)
							goto SendResponse
						}
						utxoInMap.IsSpent = true // Mark spent in memory (this directly modifies the map value if it's a pointer)
						totalInputValue += utxoInMap.Amount
						// Add types.UTXO version to list for DB update LATER
						inputsToMarkSpentDB = append(inputsToMarkSpentDB, convertProtoToTypesUTXO(utxoInMap))
						log.Printf("INFO: [txCh Handler] Marked UTXO %s (Val: %d) spent in memory TX %s for shard %d", inputKey, utxoInMap.Amount, tx.Id, chainState.ShardID)
					}

					// 3. Calculate Output Value
					totalOutputValue = 0
					for _, output := range tx.Outputs {
						totalOutputValue += output.Amount
					}

					// 4. Verify Fee & Sufficient Input
					calculatedFee = totalInputValue - totalOutputValue
					if calculatedFee < 0 {
						processingError = fmt.Errorf("tx %s outputs exceed inputs (%d > %d)", tx.Id, totalOutputValue, totalInputValue)
						goto SendResponse
					}
					if calculatedFee != int64(tx.Gasfee) {
						log.Printf("WARN: Fee mismatch tx %s: Calc %d != Stated %d. ALLOWING.", tx.Id, calculatedFee, tx.Gasfee)
					}
					if totalInputValue < totalOutputValue+int64(tx.Gasfee) {
						processingError = fmt.Errorf("insufficient input %d for outputs+fee %d tx %s", totalInputValue, totalOutputValue+int64(tx.Gasfee), tx.Id)
						goto SendResponse
					}

					// 5. Update Stakeholders Map (In Memory) & Collect Balances for DB
					log.Printf("INFO: [txCh Handler] Updating stakeholder balances in memory TX %s for shard %d", tx.Id, chainState.ShardID)
					chainState.Stakeholders[senderKey] -= totalInputValue
					balancesToUpdateDB[senderKey] = chainState.Stakeholders[senderKey] // Store final sender balance

					for _, output := range tx.Outputs {
						receiverKey := strings.TrimSpace(output.OwnerAddress)
						// This is a potential cross-shard issue. If receiverKey is not in this shard,
						// this balance update is incorrect. For simplicity now, we assume all
						// txs are single-shard, or cross-shard transactions handled by a separate mechanism.
						// For now, if a receiver is on a different shard, this update *will not occur*
						// for that shard.
						if store.CalculateShardID(receiverKey, chainState.TotalNumShards) == chainState.ShardID {
							chainState.Stakeholders[receiverKey] += output.Amount
							balancesToUpdateDB[receiverKey] = chainState.Stakeholders[receiverKey] // Store final receiver balance
							log.Printf("DEBUG: [txCh Handler] Updated receiver %s in memory: %d", receiverKey, chainState.Stakeholders[receiverKey])
						} else {
							log.Printf("WARN: [txCh Handler] Skipping in-memory balance update for receiver %s on different shard %d.",
								receiverKey, store.CalculateShardID(receiverKey, chainState.TotalNumShards))
							// This is where cross-shard communication logic would kick in:
							// The tx would need to generate a cross-shard message here.
						}
					}

					// 6. Add New UTXOs to Memory Map & Collect for DB
					log.Printf("INFO: [txCh Handler] Adding %d new UTXOs memory TX %s for shard %d", len(tx.Outputs), tx.Id, chainState.ShardID)
					outputsToAddDB = make([]types.UTXO, 0, len(tx.Outputs))

					for i, outputProto := range tx.Outputs {
						outputKey := fmt.Sprintf("%s-%d", tx.Id, i)
						ownerAddrKey := strings.TrimSpace(outputProto.OwnerAddress)
						newUTXOProto := &thrylos.UTXO{TransactionId: tx.Id, Index: int32(i), OwnerAddress: ownerAddrKey, Amount: outputProto.Amount, IsSpent: false}
						// Only add to in-memory UTXO map if it belongs to this shard
						if store.CalculateShardID(ownerAddrKey, chainState.TotalNumShards) == chainState.ShardID {
							chainState.UTXOs[outputKey] = append(chainState.UTXOs[outputKey], newUTXOProto)
							outputsToAddDB = append(outputsToAddDB, convertProtoToTypesUTXO(newUTXOProto))
							log.Printf("INFO: [txCh Handler] Added new UTXO %s to memory TX %s for shard %d", outputKey, tx.Id, chainState.ShardID)
						} else {
							log.Printf("WARN: [txCh Handler] Skipping in-memory UTXO addition for output %s on different shard %d.",
								outputKey, store.CalculateShardID(ownerAddrKey, chainState.TotalNumShards))
							// Again, cross-shard logic needed here.
						}
					}
					// === END In-Memory Operations (lock automatically released by defer) ===

					// --- Perform Database Operations (Outside Memory Lock, Within DB Transaction) ---
					log.Printf("DEBUG: [txCh Handler] Starting DB operations for TX %s for shard %d", tx.Id, chainState.ShardID)

					// Begin a database transaction for this shard's database
					dbTxContext, dbErr = chainState.Database.BeginTransaction()
					if dbErr != nil {
						log.Printf("ERROR: [txCh Handler] Failed DB begin TX %s for shard %d: %v", tx.Id, chainState.ShardID, dbErr)
						processingError = fmt.Errorf("failed to begin DB tx for shard %d: %v", chainState.ShardID, dbErr)
						goto SendResponse
					}
					defer func() {
						if processingError != nil && dbTxContext != nil {
							log.Printf("WARN: Rolling back DB transaction for TX %s on shard %d due to error: %v", tx.Id, chainState.ShardID, processingError)
							rbErr := chainState.Database.RollbackTransaction(dbTxContext)
							if rbErr != nil {
								log.Printf("ERROR: Rollback failed TX %s on shard %d: %v", tx.Id, chainState.ShardID, rbErr)
							}
						}
					}()

					// Persist Spent UTXOs
					log.Printf("DEBUG: [txCh Handler] Persisting %d spent inputs to DB for TX %s on shard %d", len(inputsToMarkSpentDB), tx.Id, chainState.ShardID)
					for _, spentUtxo := range inputsToMarkSpentDB {
						// MarkUTXOAsSpent needs to be shard-aware in its implementation
						dbErr = chainState.Database.MarkUTXOAsSpent(dbTxContext, spentUtxo, chainState.TotalNumShards) // Added totalNumShards
						if dbErr != nil {
							processingError = fmt.Errorf("failed DB mark spent %s-%d on shard %d: %v", spentUtxo.TransactionID, spentUtxo.Index, chainState.ShardID, dbErr)
							goto EndProcessingDB
						}
						log.Printf("INFO: [txCh Handler] Marked UTXO %s-%d spent in DB TX %s for shard %d", spentUtxo.TransactionID, spentUtxo.Index, tx.Id, chainState.ShardID)
					}

					// Persist Stakeholder Balances
					log.Printf("DEBUG: [txCh Handler] Persisting %d stakeholder balances to DB for TX %s on shard %d", len(balancesToUpdateDB), tx.Id, chainState.ShardID)
					for addr, balance := range balancesToUpdateDB {
						// AddToBalance needs to be shard-aware in its implementation
						// Note: AddToBalance needs delta, not new balance.
						// Assuming current logic calculates delta, not absolute new balance, for AddToBalance
						dbErr = chainState.Database.AddToBalance(dbTxContext, addr, balance, chainState.TotalNumShards) // Added totalNumShards
						if dbErr != nil {
							processingError = fmt.Errorf("failed DB update balance %s on shard %d: %v", addr, chainState.ShardID, dbErr)
							goto EndProcessingDB
						}
						log.Printf("SUCCESS: Updated balance for %s in DB to %d for shard %d", addr, balance, chainState.ShardID)
					}

					// Persist New UTXOs
					log.Printf("DEBUG: [txCh Handler] Persisting %d new outputs to DB for TX %s on shard %d", len(outputsToAddDB), tx.Id, chainState.ShardID)
					for _, newUtxo := range outputsToAddDB {
						// AddNewUTXO needs to be shard-aware in its implementation
						dbErr = chainState.Database.AddNewUTXO(dbTxContext, newUtxo, chainState.TotalNumShards) // Added totalNumShards
						if dbErr != nil {
							processingError = fmt.Errorf("failed DB add new UTXO %s-%d on shard %d: %v", newUtxo.TransactionID, newUtxo.Index, chainState.ShardID, dbErr)
							goto EndProcessingDB
						}
						log.Printf("INFO: [txCh Handler] Added new UTXO %s-%d to DB TX %s for shard %d", newUtxo.TransactionID, newUtxo.Index, tx.Id, chainState.ShardID)
					}

				EndProcessingDB: // Label for errors DURING DB operations
					if processingError != nil {
						log.Printf("ERROR: [txCh Handler] Error occurred during DB operations for TX %s on shard %d: %v", tx.Id, chainState.ShardID, processingError)
						goto SendResponse
					}

					// Commit DB Transaction if no errors occurred during DB phase
					log.Printf("DEBUG: [txCh Handler] Attempting DB commit for TX %s on shard %d", tx.Id, chainState.ShardID)
					commitErr = chainState.Database.CommitTransaction(dbTxContext)
					if commitErr != nil {
						log.Printf("ERROR: [txCh Handler] Failed DB commit TX %s on shard %d: %v", tx.Id, chainState.ShardID, commitErr)
						processingError = fmt.Errorf("failed DB commit for shard %d: %v", chainState.ShardID, commitErr)
						goto SendResponse
					}
					dbTxContext = nil // Prevent defer rollback if commit succeeded
					log.Printf("INFO: [txCh Handler] Committed DB TX %s for shard %d", tx.Id, chainState.ShardID)

				SendResponse: // Label for sending response

					// --- Send Response ---
					if msg.ResponseCh != nil {
						if processingError != nil {
							log.Printf("ERROR: [txCh Handler] Final Failure processing TX %s for shard %d: %v", tx.Id, chainState.ShardID, processingError)
							msg.ResponseCh <- types.Response{Error: processingError}
						} else {
							log.Printf("INFO: [txCh Handler] Final Success processing TX %s for shard %d", tx.Id, chainState.ShardID)
							msg.ResponseCh <- types.Response{Data: tx.Id, Error: nil}
						}
					} else { /* Log no response channel */
					}

				default:
					log.Printf("WARN: [txCh Handler] Received unhandled message type: %s", msg.Type)

				}
			case <-ctx.Done():
				log.Println("INFO: [txCh Handler] Context cancelled, stopping message processing.")
				return
			}
		}
	}()

	// Handle block-related messages
	go func() {
		for {
			select {
			case msg := <-blockCh:
				switch msg.Type {
				case types.ProcessBlock:
					// This handler would typically be for getting a block from this specific chain
					// Block by ID/number will now only return blocks from this shard's chain
					if blockID, ok := msg.Data.(string); ok {
						// GetBlockByID needs to be shard-aware and take shardID
						block, err := bcImpl.GetBlockByID(chainState.ShardID, blockID) // Added shardID
						msg.ResponseCh <- types.Response{Data: block, Error: err}
					} else if blockNum, ok := msg.Data.(int32); ok {
						// GetBlock needs to be shard-aware and take shardID
						block, err := bcImpl.GetBlock(chainState.ShardID, int(blockNum)) // Added shardID
						msg.ResponseCh <- types.Response{Data: block, Error: err}
					} else {
						msg.ResponseCh <- types.Response{Error: fmt.Errorf("invalid block identifier")}
					}
				case types.ConfirmBlock:
					// Confirmation logic would also be shard-specific
					log.Printf("DEBUG: ConfirmBlock message received, need to implement shard-aware confirmation logic.")
					msg.ResponseCh <- types.Response{Data: nil, Error: fmt.Errorf("ConfirmBlock not fully implemented for sharding")}
				}
			case <-ctx.Done():
				return
			}
		}
	}()

	// Handle blockchain info messages
	go func() {
		defer close(handlersReady)

		for {
			select {
			case msg := <-infoCh:
				switch msg.Type {
				case types.GetBlockchainInfo:
					// Get info from this specific chain's state
					// GetLastBlock needs to be shard-aware and take shardID
					lastBlock, _, _ := bcImpl.GetLastBlock(chainState.ShardID) // Added shardID
					info := map[string]interface{}{
						// GetBlockCount needs to be shard-aware and take shardID
						"height":    bcImpl.GetBlockCount(chainState.ShardID) - 1, // Added shardID
						"lastBlock": lastBlock,
						"nodeCount": 1,       // This is just for this node, not whole network
						"chainId":   chainID, // The shard-specific or beacon chainID
						"isSyncing": false,   // Placeholder
					}
					msg.ResponseCh <- types.Response{Data: info}
				case types.GetActiveValidators:
					chainState.Mu.RLock()
					activeValidators := chainState.ActiveValidators // Validators for THIS shard/beacon
					chainState.Mu.RUnlock()
					msg.ResponseCh <- types.Response{Data: activeValidators}
				case types.IsActiveValidator:
					addr, ok := msg.Data.(string)
					isActive := false
					if ok {
						chainState.Mu.RLock()
						for _, v := range chainState.ActiveValidators {
							if v == addr {
								isActive = true
								break
							}
						}
						chainState.Mu.RUnlock()
					}
					msg.ResponseCh <- types.Response{Data: isActive}
				case types.GetStakeholders:
					// Get stakeholders for THIS shard
					chainState.Mu.RLock()
					stakeholdersCopy := make(map[string]int64)
					for k, v := range chainState.Stakeholders {
						stakeholdersCopy[k] = v
					}
					chainState.Mu.RUnlock()
					msg.ResponseCh <- types.Response{Data: stakeholdersCopy}
				}
			case <-ctx.Done():
				return
			}
		}
	}()
}
