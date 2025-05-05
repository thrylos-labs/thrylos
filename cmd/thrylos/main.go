package main

import (
	"context"
	"crypto/tls"
	"encoding/base64"
	"fmt"
	"log"
	"net"
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
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	// Add this line
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

func RunMinimalCryptoTest() {
	fmt.Println("--- Running Minimal Crypto Verification Test (v6 - Using Actual Key & Raw Bytes Logic) ---")

	// --------------------------------------------------------------------
	// 1. Define Input Data (Using the key from your .env)
	// --------------------------------------------------------------------
	// This is the Base64 string from your .env file, representing RAW private key bytes
	base64RawPrivKey := "u44zAxb+zBXE1EQE/wi07utbSleqAPIcE8YpxJJyrSz24n4nEKekNkJW0PUxV0g0dxN4UVHzOmyrG0VPxY//WouaFD5vBVssg1zJaLnWOxMUEvJNcZkfNb839Th/h79E1OQEYDzVXXWQwgAwdjA137NeZGOzcUou2Uem7CEvc3UkxQkhkhFKsDEQNHAcMCEcxAhgpi0So0yYojCcMm6JFA3IADJSoEHAoizRQCZCEmEAR1HMoGDBAokLIGHgyBFbKHBixlETwCAgRiETQUoDk1FISERBRpHgQpGEACpBggQKGBGaNlCEgEQTIYrTpiBaOELbBgwBBoaYoCHEOCQCo1BIECACuEgCh2hByAyjBABSwmQCk0yCto0jRg0jkGgQNoKhBmoUxyDiIiiZQiUINgyEAgJcuJBbEEyhhiUAQmaZqC2BQnCLMA2KpHBaOAyaNEpAgBARBiEMQo6BBIBDpGQiRE4YpYCLJIaBAGoCkwEklikYtSkiySgQwIzhJG0jAXLcJBKKskHkli3IiAmAwBALsCSQAgmRCI6ECJGTsoWDxjEMhgwCszHbxGGSSJBcABAjlQTQMGxCMECIpCxLFIQClEwABEwJNAQBuWmjNGYCSYoBlyESg2iDhjBKFkUMJW4TQ2VhFmCRSGRDtIhkwGTQhmwIGAmciCkSgCAhKUzUsEEhRWWbgmTMSIDYkkzENmqiJkghgYgklpAMRUXESCHSQDISQmBMAEUKyWBgEkZZBhJUtgwLAyBLpmUYkVATmYhASDDkCA5BREwaJQICiIRKFFGaRgJIAiTCCAWRKDISpwEkKDHgSEkDFWXRwCGDsHEINIqBIDEUATFLAnDDRAoJwmHauEghIE0bJkKgsISigiTaIigZgW3SMAwTEQYYECZBlEmQgIlRiI1gQAARlYwUKCCUtEULCYkgNEgghiwYgVFiQG6IQCpjREYZA0kJomkaMoohRGVKgGESkIyIqEwcOACioIEEg2kJQm4hIQYkBkBRqIARB2HJsiVAhi2AQmgBsAWIIiGapACDlkySRgqCAjIBNopjQkFEwCkLxWDLBiEAEykkIjJLMlJTCJJQNCSJMjAkQEXQoDABQEwROQEUmWmYqGTAQGDckDEQEQ2gtmTKhhHSQDDgiCxUpi3EhI0DQAHMhoARgg3RGCXSpIhDoojJhIQbE2TigAGhJir5ITHgHvXPICEeFnz5LPHnEdj4PArPpJ6mxB92QgPna0UtJwM5Kur9VhYuz4DyCjid8qP0P3DR0UFV/ovx74aHMF84Jl4xJd3Lm+44t3nBT7Xcfe45BYTXfD0vUiRA1DwqBvqXgiLdDO/q6+oNOiKYP10+J+VY1sNIUVLLmhGmUWIQQME0E3sdB3pW/cXqbSzYuKDNfsrBfFisr0OfvfoeBFFk/Zc6CY+l98X/MiC/mqaoWmlFDJ2KuGqhu5XsxNZI5iEwnil4Rm44G8yG829jrkFF//q+ftQYKzAxjo3OLTUpt3KH9feKr4fPoc82JAkg00KW5qvy2rxtYCHvXlyJ23dzf+Q7PcDS5+yfTMTqrlU60Rin2WWkPF1Yls4lX9w+/kL12OIVtdTr6em77cA9HQdOU0UB9dq3JhrO78VfiI6STry/Necz3W66gxG+7WjH1lLQ+p8BObht/lcpOvTa0TlBeBaP7ludDzSayVoyKsfxJASqb6jGjXy5L5T5RdUVS83v7xJ7rmJ0kmU+NPEcPNvcEVNcA+WEfrz6ovOofzVeqyW9uj+dwCTmXDJiWSKtaMBC42+ej6lvsX+C59I/x95RGGXyu41IhTaznm9+Lh5v2h8PZy5gsXaTwvwUC6cHQyxhlogPG2E0Yfw0umsXa6FUjj8RKRW6EstkBm5BNmphXGvVPjSseJ2wddc40R8LDcBAFuh9hfymYlG61OWVAA7xSApfPP1ftgeTxnmJYJxweDx7WW53gfrKXY9mZKpoTleKjZynwcWkJQfq+y0rnNrd1ZQlNwIOSBkA3VPuvIvXi+wo8I4rSX+M3PpZqJixSNyarfQ7RWqIlcw0JsodIEvlPb+X73JtPHv0CnvJ+vU81aryuybedWSIKOdsZOVCZ+alSyj7aiJrz4n8ldZ9PPG5aX8AUQ06gIU5iB232mwkBUhXJ2i88oMJvunzjBJYHdM2RMkD9DI7DZUTkul2CSRhoChrufr16dkYZdaE8eRNE4nNk/l6Ov9a+yl5DBVV6Y3hF0Y7PSZf/cK5nhKbUhu0IeVqBhBh7czcWr2QAVOzCfTBcBZeCyiHne33Zf7DpYuaE+3ZZOLtC77cMXPwvQ7SU6GnPHRRgY1v/ygRgmV71h63wIwO7jmy2OGAS4IeN0QAMRnypLacdFid3In/M8D1tA7WIY6zBn3jS04qtcxhGdhphtQKLYnH2UATOFACQZF7WsfrnHzyZDna7RN0QtzW2Q/NomEV+TpghCjuhpIpGTga0SKxflV0h4oXEv4Il7OB8HBUj/DprgfhZLmMQjw9mL1Xpic0m2wISpw1nouQZwkSZcfbDksI82ZEY9jjycMFwPfe4ZxXDdLfRVv6T+/u74++bdQeqqmZ1jwybPUi9eJ0DQl3JxwXKjlKIihK0QcmgruRJihu+yyPZS+MF4KH0T+H9zP0YkmfONiUi5cxEGznUJhZkPk/XqNio9t2k/Zk75FVFE/uuDgOcPasYZCVX5ZjoftDuWYoItFPSYgnqKgjf0dHB0/FQPzYhXhnKShNPXbFL44W4UlE4jeaMoik3uWwzIADHPeK4AMbkhq4rfG+ApXTeWWJLy2XA8gzETlI4JNEBJ57qCYIAmV1LFGNcZ13ifgzBHctomehFEFRkaiILhhW0gSfOfHagC/qbTKZM2rXQDelfOTsni5Dr2VvM1pvT5MUfgYWtVKSQh8Vokg2MqSu9p3jXX904ADL/nE0gSbUqc/IaDp9FeWifdJEF/R/k3JB1mtKsX8zy/sZt6eqaPpItruEMffLa33YuG41xz/Tn2zdOeS33iSBcCKBuDwH+MtZkzvcWJVpiwucdRJxOksdnWhJaY0+AsCH84yvToEOOQq5S9/4TYUTTMba/afkc0I5K/XXXyyBIjjwwH5kPEiXk+UYZDYeXKmbbo6D3Y8q04CzD4hvlWp7vFIdNGiuCozM10k0BliaIiLaPWktInhlTcTaMH9Pr0KuUcofnG7MHjAkddGCOVrORsT24Rsp88Tc/dPSjD3A3/GPrQewS4CPsKZLRxHc49YjlsTiLaGkAZNErv8ruFNywhfLNNp5Oq/7Z/6DOHbbiPCFnFrICu1+MlL4o/zdESMMU+Depop5A5jg88UrO/v9i3MgXqH09u/zkFX4dn04dG2EcRrZxTqWrCY/eEBwZf6GE0qZwHHI0vqbP7IbOnqxWG8bnASknEbV+2aGTyOG/Q=="

	// --------------------------------------------------------------------
	// 2. Load Private Key (Handling RAW bytes)
	// --------------------------------------------------------------------
	rawPrivKeyBytes, err := base64.StdEncoding.DecodeString(base64RawPrivKey)
	if err != nil {
		log.Fatalf("Failed to base64 decode private key string: %v", err)
	}

	// Use the Unmarshal method of the concrete implementation (assuming it's exported or accessible)
	// If PrivateKeyImpl is not exported, you need a factory function like NewPrivateKeyFromRawBytes
	privKeyImpl := &crypto.PrivateKeyImpl{}      // Instantiate the concrete (exported) type
	err = privKeyImpl.Unmarshal(rawPrivKeyBytes) // Call Unmarshal which expects raw bytes
	if err != nil {
		log.Fatalf("Failed to unmarshal raw private key bytes: %v", err)
	}
	privKey := crypto.PrivateKey(privKeyImpl) // Assign to the interface type
	log.Println("Successfully loaded private key from raw bytes.")

	// --------------------------------------------------------------------
	// 3. Derive Public Key Directly using your crypto package method
	// --------------------------------------------------------------------
	pubKey := privKey.PublicKey() // Returns crypto.PublicKey interface
	if pubKey == nil {
		log.Fatal("Failed to derive public key from private key (returned nil).")
	}
	log.Println("Successfully derived public key directly.")

	// --------------------------------------------------------------------
	// 4. Define Sample Message Hash
	// --------------------------------------------------------------------
	// In the real scenario, this would be the block hash bytes
	messageHashBytes := []byte("this represents the block hash to be signed and verified")
	log.Printf("Using sample message hash: %x\n", messageHashBytes)

	// --------------------------------------------------------------------
	// 5. Sign the Hash using your crypto package method
	// --------------------------------------------------------------------
	signature := privKey.Sign(messageHashBytes) // Returns crypto.Signature interface
	if signature == nil {
		log.Fatal("Failed to sign message hash (signature is nil).")
	}
	sigBytes := signature.Bytes()
	if len(sigBytes) == 0 {
		log.Fatal("Failed to sign message hash (signature bytes are empty).")
	}
	log.Printf("Successfully signed message hash. Signature bytes length: %d\n", len(sigBytes))

	// --------------------------------------------------------------------
	// 6. Immediate Verification (Using directly derived key and crypto interface)
	// --------------------------------------------------------------------
	// The Verify method is on the signature object and takes a *pointer* to the PublicKey interface
	errImmediate := signature.Verify(&pubKey, messageHashBytes) // Pass pointer to interface
	isValidImmediate := errImmediate == nil
	log.Printf("IMMEDIATE Verification Result (using derived key): %v (Error: %v)\n", isValidImmediate, errImmediate)

	// --------------------------------------------------------------------
	// 7. Marshal Public Key to Bytes using crypto interface method
	// --------------------------------------------------------------------
	// Use the Marshal method defined in the interface (expects raw bytes output)
	marshalledPubKeyBytes, errMarshal := pubKey.Marshal() // Use the interface method
	if errMarshal != nil {
		log.Fatalf("Failed to marshal public key to bytes: %v", errMarshal)
	}
	if len(marshalledPubKeyBytes) == 0 {
		log.Fatal("Marshalled public key bytes are empty.")
	}
	log.Printf("Successfully marshalled public key (raw bytes). Bytes length: %d\n", len(marshalledPubKeyBytes))

	// --------------------------------------------------------------------
	// 8. Unmarshal Bytes into a NEW Public Key Object using the Factory Function
	// --------------------------------------------------------------------
	// Use the exported NewPublicKeyFromBytes function (expects raw bytes input)
	newPubKey, errUnmarshal := crypto.NewPublicKeyFromBytes(marshalledPubKeyBytes)
	if errUnmarshal != nil {
		// This function already calls the internal Unmarshal method
		log.Fatalf("Failed to create new public key from bytes using NewPublicKeyFromBytes: %v", errUnmarshal)
	}
	// 'newPubKey' is now a crypto.PublicKey interface containing the unmarshalled key
	log.Println("Successfully created new public key object from bytes.")

	// --------------------------------------------------------------------
	// 9. Verification using the UNMARSHALLED Key
	// --------------------------------------------------------------------
	// Call Verify on the original signature object, passing a pointer to the *new* PublicKey interface variable
	errUnmarshalVerify := signature.Verify(&newPubKey, messageHashBytes) // Pass pointer to the new interface variable
	isValidAfterUnmarshal := errUnmarshalVerify == nil
	log.Printf("Verification Result (using UNMARSHALLED key): %v (Error: %v)\n", isValidAfterUnmarshal, errUnmarshalVerify)

	// --------------------------------------------------------------------
	// 10. Compare Results
	// --------------------------------------------------------------------
	fmt.Println("--- Test Summary ---")
	fmt.Printf("Immediate Verification Passed: %v\n", isValidImmediate)
	fmt.Printf("Verification After Unmarshal Passed: %v\n", isValidAfterUnmarshal)

	if isValidImmediate && isValidAfterUnmarshal {
		fmt.Println("✅ SUCCESS: Both verification steps passed. The core crypto signing/verification and key marshalling/unmarshalling (using raw bytes) via your crypto package seem OK.")
		fmt.Println("   The issue in the blockchain likely lies elsewhere (e.g., incorrect key retrieval logic for the specific validator address, hash data mismatch despite logs, state corruption).")
	} else if isValidImmediate && !isValidAfterUnmarshal {
		fmt.Println("❌ FAILURE: Verification failed ONLY after marshalling/unmarshalling the public key.")
		fmt.Println("   This strongly suggests an issue with how the public key is stored/retrieved OR with the Marshal/Unmarshal implementation (expecting raw bytes) in your crypto package, or the NewPublicKeyFromBytes function.")
		fmt.Println("   Double-check your Store's SavePublicKey/GetPublicKey implementation and the Marshal/Unmarshal methods and NewPublicKeyFromBytes.")
	} else {
		fmt.Println("❌ FAILURE: Immediate verification failed. There's a fundamental issue in the signing/verification logic within your crypto package wrappers or the key loading.")
		fmt.Println("   Check the crypto.NewPrivateKeyFromBytes, privKey.Sign, and signature.Verify methods.")
	}
	fmt.Println("-----------------------------------------------------")
}

func main() {
	RunMinimalCryptoTest() // Run the test first
	// Setup clean shutdown with context
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

	// Start gRPC server in a goroutine
	go func() {
		log.Printf("Starting gRPC server on %s\n", grpcAddress)
		if err := s.Serve(lis); err != nil {
			log.Printf("gRPC server stopped: %v", err)
		}
	}()

	// Handle gRPC server shutdown
	go func() {
		<-ctx.Done()
		log.Println("Shutting down gRPC server...")
		s.GracefulStop()
	}()

	// Keep main goroutine running until context is canceled
	<-ctx.Done()
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
