package core

import (
	"bufio"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"strconv"
	"sync"
	"time"

	"github.com/gorilla/mux"
	thrylos "github.com/thrylos-labs/thrylos"
	"github.com/thrylos-labs/thrylos/shared"
	"golang.org/x/crypto/ed25519"
)

func (node *Node) SetupRoutes() *mux.Router {
	r := mux.NewRouter()

	// Helper function to check if request is WebSocket
	isWebSocketRequest := func(r *http.Request) bool {
		return r.Header.Get("Upgrade") == "websocket"
	}

	// Apply CORS middleware with proper origin checking
	// In your SetupRoutes function, update the CORS middleware section
	r.Use(func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			log.Printf("Request received: %s %s", r.Method, r.URL.Path)

			// Allow requests from specific origins
			allowedOrigins := []string{"http://localhost:3000", "https://node.thrylos.org"}
			origin := r.Header.Get("Origin")

			// Check if origin is allowed
			originAllowed := false
			for _, allowedOrigin := range allowedOrigins {
				if origin == allowedOrigin {
					originAllowed = true
					w.Header().Set("Access-Control-Allow-Origin", origin)
					break
				}
			}

			// Set comprehensive CORS headers
			w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
			w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization, X-Requested-With, Accept, Cache-Control")
			w.Header().Set("Access-Control-Allow-Credentials", "true")
			w.Header().Set("Access-Control-Max-Age", "86400")

			// Handle preflight requests
			if r.Method == "OPTIONS" {
				w.WriteHeader(http.StatusNoContent)
				return
			}

			// If no allowed origin found and it's not a WebSocket request
			if !originAllowed && !isWebSocketRequest(r) {
				if r.Method != "OPTIONS" {
					log.Printf("Blocked request from unauthorized origin: %s", origin)
					http.Error(w, "Unauthorized origin", http.StatusForbidden)
					return
				}
			}

			// Add cache control headers for balance endpoint
			if r.URL.Path == "/get-balance" {
				w.Header().Set("Cache-Control", "no-cache, no-store, must-revalidate")
				w.Header().Set("Expires", "0")
			}

			// Set content type for non-WebSocket requests
			if !isWebSocketRequest(r) {
				w.Header().Set("Content-Type", "application/json")
			}

			next.ServeHTTP(w, r)
		})
	})

	// Balance endpoints
	balanceHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == "OPTIONS" {
			return
		}

		address := r.URL.Query().Get("address")
		if address == "" {
			http.Error(w, "Address parameter is required", http.StatusBadRequest)
			return
		}

		balance, err := node.GetBalance(address)
		if err != nil {
			log.Printf("Error getting balance for address %s: %v", address, err)
			http.Error(w, fmt.Sprintf("Error getting balance: %v", err), http.StatusInternalServerError)
			return
		}

		response := struct {
			Balance        int64   `json:"balance"`
			BalanceThrylos float64 `json:"balanceThrylos"`
		}{
			Balance:        balance,
			BalanceThrylos: float64(balance) / 1e7,
		}

		w.Header().Set("Cache-Control", "no-cache, no-store, must-revalidate")
		w.Header().Set("Pragma", "no-cache")
		w.Header().Set("Expires", "0")

		if err := json.NewEncoder(w).Encode(response); err != nil {
			log.Printf("Error encoding balance response: %v", err)
			http.Error(w, "Error encoding response", http.StatusInternalServerError)
			return
		}
	})

	r.Handle("/get-balance", balanceHandler).Methods("GET", "OPTIONS")

	// WebSocket endpoint with specific handling
	r.HandleFunc("/ws/balance", func(w http.ResponseWriter, r *http.Request) {
		if isWebSocketRequest(r) {
			node.WebSocketBalanceHandler(w, r)
			return
		}
		http.Error(w, "Expected WebSocket connection", http.StatusBadRequest)
	})

	// Core blockchain endpoints
	r.HandleFunc("/block", node.BlockHandler).Methods("POST")
	r.HandleFunc("/blockchain", node.BlockchainHandler).Methods("GET")
	r.HandleFunc("/transaction", node.TransactionHandler).Methods("POST")
	r.HandleFunc("/peers", node.PeersHandler).Methods("GET")

	// Transaction related endpoints
	r.HandleFunc("/vote", node.VoteHandler).Methods("POST")
	r.HandleFunc("/get-transaction", node.GetTransactionHandler).Methods("GET")
	r.HandleFunc("/process-transaction", node.ProcessSignedTransactionHandler).Methods("POST", "OPTIONS")
	r.HandleFunc("/pending-transactions", node.PendingTransactionsHandler).Methods("GET")
	r.HandleFunc("/list-transactions-for-block", node.ListTransactionsForBlockHandler).Methods("GET")

	// Wallet and balance endpoints
	r.HandleFunc("/register-wallet", node.RegisterOrImportWalletHandler).Methods("POST", "OPTIONS")
	r.HandleFunc("/fund-wallet", node.FundWalletHandler).Methods("POST")
	r.HandleFunc("/get-utxo", node.GetUTXOsForAddressHandler).Methods("GET", "OPTIONS")

	// Public key and address endpoints
	r.HandleFunc("/check-public-key", node.CheckPublicKeyHandler).Methods("GET")
	r.HandleFunc("/get-publickey", node.GetPublicKeyHandler).Methods("GET", "OPTIONS")
	r.HandleFunc("/register-public-key", node.RegisterPublicKeyHandler).Methods("POST")
	r.HandleFunc("/get-blockchain-address", node.GetBlockchainAddressHandler).Methods("GET")

	// Staking and validator endpoints
	r.HandleFunc("/validators", node.GetValidatorsHandler).Methods("GET", "OPTIONS")
	r.HandleFunc("/staking-stats", node.GetStakingStatsHandler).Methods("GET", "OPTIONS")
	r.HandleFunc("/stake", node.StakeTokensHandler).Methods("POST", "OPTIONS")
	r.HandleFunc("/unstake", node.UnstakeTokensHandler).Methods("POST", "OPTIONS")
	r.HandleFunc("/register-validator", node.RegisterValidatorHandler).Methods("POST")
	r.HandleFunc("/update-stake", node.UpdateStakeHandler).Methods("POST")
	r.HandleFunc("/delegate-stake", node.DelegateStakeHandler).Methods("POST")

	// Utility endpoints
	r.HandleFunc("/gas-fee", node.GasEstimateHandler).Methods("GET", "OPTIONS")
	r.HandleFunc("/network-health", node.NetworkHealthHandler).Methods("GET")
	r.HandleFunc("/get-block", node.GetBlockHandler).Methods("GET")
	r.HandleFunc("/consensus-info", node.ConsensusInfoHandler).Methods("GET")
	r.HandleFunc("/stats", node.StatsHandler).Methods("GET")

	return r
}

func (node *Node) GetBalanceHandler(w http.ResponseWriter, r *http.Request) {
	log.Printf("GetBalanceHandler invoked")

	address := r.URL.Query().Get("address")
	if address == "" {
		http.Error(w, "Address parameter is required", http.StatusBadRequest)
		return
	}

	balance, err := node.GetBalance(address)
	if err != nil {
		log.Printf("Error getting balance for address %s: %v", address, err)
		http.Error(w, fmt.Sprintf("Error getting balance: %v", err), http.StatusInternalServerError)
		return
	}

	response := struct {
		Balance        int64   `json:"balance"`
		BalanceThrylos float64 `json:"balanceThrylos"`
	}{
		Balance:        balance,
		BalanceThrylos: float64(balance) / 1e7,
	}

	// Add additional logging
	log.Printf("Sending balance response for address %s: %+v", address, response)

	if err := json.NewEncoder(w).Encode(response); err != nil {
		log.Printf("Error encoding balance response: %v", err)
		http.Error(w, "Error encoding response", http.StatusInternalServerError)
		return
	}
}

// Core blockchain handlers

func (node *Node) BlockHandler(w http.ResponseWriter, r *http.Request) {
	var block Block
	if err := json.NewDecoder(r.Body).Decode(&block); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	prevBlock, prevIndex, err := node.Blockchain.GetLastBlock()
	if err != nil {
		http.Error(w, fmt.Sprintf("Failed to get the last block: %v", err), http.StatusInternalServerError)
		return
	}

	if prevBlock != nil && !node.Blockchain.ValidateBlock(&block, prevBlock) {
		http.Error(w, "Block validation failed", http.StatusUnprocessableEntity)
		return
	}
	success, err := node.Blockchain.AddBlock(block.Transactions, block.Validator, block.PrevHash, block.Timestamp)
	if err != nil {
		http.Error(w, fmt.Sprintf("Failed to add block: %v", err), http.StatusInternalServerError)
		return
	}
	if !success {
		http.Error(w, "Failed to add block due to validation or other issues", http.StatusBadRequest)
		return
	}

	if prevBlock != nil {
		log.Printf("Previous Block Index: %d, Block Hash: %s", prevIndex, prevBlock.Hash)
	} else {
		log.Println("No previous block exists.")
	}
	w.WriteHeader(http.StatusCreated)
}

func (node *Node) BlockchainHandler(w http.ResponseWriter, r *http.Request) {
	data, err := json.Marshal(node.Blockchain)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.Write(data)
}

func (node *Node) TransactionHandler(w http.ResponseWriter, r *http.Request) {
	var jsonTx thrylos.TransactionJSON
	if err := json.NewDecoder(r.Body).Decode(&jsonTx); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	tx := ConvertJSONToProto(jsonTx)

	node.AddPendingTransaction(tx)
	fmt.Printf("Verified and added transaction %s to pending transactions\n", tx.GetId())
	w.WriteHeader(http.StatusCreated)
}

func (node *Node) PeersHandler(w http.ResponseWriter, r *http.Request) {
	data, err := json.Marshal(node.Peers)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.Write(data)
}

func (node *Node) VoteHandler(w http.ResponseWriter, r *http.Request) {
	var vote Vote
	if err := json.NewDecoder(r.Body).Decode(&vote); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	node.Votes = append(node.Votes, vote)
}

// Transaction related handlers
func (node *Node) GetTransactionHandler(w http.ResponseWriter, r *http.Request) {
	txID := r.URL.Query().Get("id")
	if txID == "" {
		http.Error(w, "Transaction ID is required", http.StatusBadRequest)
		return
	}
	tx, err := node.Blockchain.GetTransactionByID(txID)
	if err != nil {
		http.Error(w, "Transaction not found", http.StatusNotFound)
		return
	}
	txJSON, err := json.Marshal(tx)
	if err != nil {
		http.Error(w, "Failed to serialize transaction", http.StatusInternalServerError)
		return
	}
	sendResponse(w, txJSON)
}

var _ shared.GasEstimator = &Node{} // Ensures Node implements the GasEstimator interface

const MinTransactionAmount int64 = 1 * NanoThrylosPerThrylos // 1 THRYLOS in nanoTHRYLOS

func (n *Node) ProcessSignedTransactionHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodOptions {
		w.WriteHeader(http.StatusOK)
		return
	}

	// Use a buffered reader for better performance
	bodyBytes, err := io.ReadAll(bufio.NewReader(r.Body))
	if err != nil {
		sendJSONErrorResponse(w, "Failed to read request body: "+err.Error(), http.StatusBadRequest)
		return
	}

	var requestData struct {
		Payload   map[string]interface{} `json:"payload"`
		Signature string                 `json:"signature"`
	}

	if err := json.Unmarshal(bodyBytes, &requestData); err != nil {
		sendJSONErrorResponse(w, "Invalid request format: "+err.Error(), http.StatusBadRequest)
		return
	}

	// Fast path validation
	sender, ok := requestData.Payload["sender"].(string)
	if !ok {
		sendJSONErrorResponse(w, "Invalid sender in payload", http.StatusBadRequest)
		return
	}

	// Parallel validation of critical components with timeout
	validationDone := make(chan error, 1)
	var publicKey ed25519.PublicKey
	var signatureBytes []byte
	var messageBytes []byte

	go func() {
		var err error
		// Get public key
		publicKey, err = n.RetrievePublicKey(sender)
		if err != nil {
			validationDone <- fmt.Errorf("could not retrieve public key: %v", err)
			return
		}

		// Decode signature
		signatureBytes, err = base64.StdEncoding.DecodeString(requestData.Signature)
		if err != nil {
			validationDone <- fmt.Errorf("invalid signature encoding: %v", err)
			return
		}

		// Marshal payload
		messageBytes, err = json.Marshal(requestData.Payload)
		if err != nil {
			validationDone <- fmt.Errorf("failed to marshal payload: %v", err)
			return
		}

		// Verify signature
		if !ed25519.Verify(publicKey, messageBytes, signatureBytes) {
			validationDone <- fmt.Errorf("invalid signature")
			return
		}

		validationDone <- nil
	}()

	// Wait for validation with timeout
	select {
	case err := <-validationDone:
		if err != nil {
			sendJSONErrorResponse(w, err.Error(), http.StatusBadRequest)
			return
		}
	case <-time.After(1 * time.Second):
		sendJSONErrorResponse(w, "Validation timeout", http.StatusGatewayTimeout)
		return
	}

	// Process transaction data
	var transactionData shared.Transaction
	transactionData.ID = requestData.Payload["id"].(string)
	transactionData.Sender = sender

	// Direct type assertions instead of JSON marshal/unmarshal
	if gasFeeFloat, ok := requestData.Payload["gasfee"].(float64); ok {
		transactionData.GasFee = int(gasFeeFloat)
	} else {
		sendJSONErrorResponse(w, "Invalid gasfee in payload", http.StatusBadRequest)
		return
	}

	if timestampFloat, ok := requestData.Payload["timestamp"].(float64); ok {
		transactionData.Timestamp = int64(timestampFloat)
	} else {
		sendJSONErrorResponse(w, "Invalid timestamp in payload", http.StatusBadRequest)
		return
	}

	// Process inputs/outputs
	if inputsData, ok := requestData.Payload["inputs"].([]interface{}); ok {
		inputsJSON, err := json.Marshal(inputsData)
		if err != nil {
			sendJSONErrorResponse(w, "Invalid inputs in payload: "+err.Error(), http.StatusBadRequest)
			return
		}
		if err := json.Unmarshal(inputsJSON, &transactionData.Inputs); err != nil {
			sendJSONErrorResponse(w, "Failed to parse inputs: "+err.Error(), http.StatusBadRequest)
			return
		}
	}

	if outputsData, ok := requestData.Payload["outputs"].([]interface{}); ok {
		outputsJSON, err := json.Marshal(outputsData)
		if err != nil {
			sendJSONErrorResponse(w, "Invalid outputs in payload: "+err.Error(), http.StatusBadRequest)
			return
		}
		if err := json.Unmarshal(outputsJSON, &transactionData.Outputs); err != nil {
			sendJSONErrorResponse(w, "Failed to parse outputs: "+err.Error(), http.StatusBadRequest)
			return
		}
	}

	// Convert and validate transaction
	thrylosTx := shared.SharedToThrylos(&transactionData)
	if thrylosTx == nil {
		sendJSONErrorResponse(w, "Failed to convert transaction data", http.StatusInternalServerError)
		return
	}
	thrylosTx.Signature = signatureBytes

	// Start block creation early
	blockCreationDone := make(chan struct{})
	go func() {
		defer close(blockCreationDone)
		if err := n.TriggerBlockCreation(); err != nil {
			log.Printf("Error triggering block creation: %v", err)
		}
	}()

	// Parallel balance fetch and validation with timeout
	validationComplete := make(chan error, 1)
	go func() {
		balance, err := n.GetBalance(transactionData.Sender)
		if err != nil {
			validationComplete <- fmt.Errorf("failed to fetch balance: %v", err)
			return
		}

		if err := shared.ValidateAndConvertTransaction(thrylosTx, n.Database, publicKey, n, balance); err != nil {
			validationComplete <- fmt.Errorf("failed to validate transaction: %v", err)
			return
		}

		if err := n.AddPendingTransaction(thrylosTx); err != nil {
			validationComplete <- fmt.Errorf("failed to add to pending pool: %v", err)
			return
		}
		validationComplete <- nil
	}()

	go func() {
		// Wait a short time for transaction processing
		time.Sleep(500 * time.Millisecond)

		// Send multiple balance updates to ensure delivery
		for i := 0; i < 3; i++ {
			if err := n.SendBalanceUpdate(transactionData.Sender); err != nil {
				log.Printf("Failed to send balance update attempt %d: %v", i+1, err)
			}
			time.Sleep(500 * time.Millisecond)
		}
	}()

	// Wait for validation with timeout
	select {
	case err := <-validationComplete:
		if err != nil {
			sendJSONErrorResponse(w, err.Error(), http.StatusBadRequest)
			return
		}
	case <-time.After(1 * time.Second):
		sendJSONErrorResponse(w, "Transaction processing timeout", http.StatusGatewayTimeout)
		return
	}

	go func() {
		if err := n.BroadcastTransaction(thrylosTx); err != nil {
			log.Printf("Warning: Failed to broadcast transaction: %v", err)
		}
	}()

	// Send immediate response
	resp := map[string]interface{}{
		"message": fmt.Sprintf("Transaction %s submitted successfully", transactionData.ID),
		"status":  "pending",
		"txId":    transactionData.ID,
	}
	json.NewEncoder(w).Encode(resp)
	w.(http.Flusher).Flush()

	// Update balances in background
	go func() {
		addresses := make(map[string]bool)
		addresses[transactionData.Sender] = true
		for _, output := range transactionData.Outputs {
			addresses[output.OwnerAddress] = true
		}

		// Update balances concurrently
		var wg sync.WaitGroup
		for address := range addresses {
			wg.Add(1)
			go func(addr string) {
				defer wg.Done()
				if balance, err := n.GetBalance(addr); err == nil {
					n.notifyBalanceUpdate(addr, balance)
				}
			}(address)
		}
		wg.Wait()
	}()
}

func (node *Node) PendingTransactionsHandler(w http.ResponseWriter, r *http.Request) {
	pendingTransactions := node.GetPendingTransactions()
	txData, err := json.Marshal(pendingTransactions)
	if err != nil {
		http.Error(w, "Failed to serialize pending transactions", http.StatusInternalServerError)
		return
	}
	sendResponse(w, txData)
}

// fetch all transactions for a given block
func (node *Node) ListTransactionsForBlockHandler(w http.ResponseWriter, r *http.Request) {
	blockID := r.URL.Query().Get("id")
	if blockID == "" {
		http.Error(w, "Block ID is required", http.StatusBadRequest)
		return
	}
	block, err := node.Blockchain.GetBlockByID(blockID)
	if err != nil {
		http.Error(w, "Block not found: "+err.Error(), http.StatusNotFound)
		return
	}
	// Serialize the transactions of the block for response
	transactionsJSON, err := json.Marshal(block.Transactions)
	if err != nil {
		http.Error(w, "Failed to serialize transactions", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.Write(transactionsJSON)
}

// Wallet and balance handlers

func (node *Node) FundWalletHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}
	var request struct {
		Address string `json:"address"`
		Amount  int64  `json:"amount"`
	}
	if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
		http.Error(w, fmt.Sprintf("Invalid request: %v", err), http.StatusBadRequest)
		return
	}
	// Debugging log, consider using a conditional flag or environment-based logging.
	fmt.Printf("Attempting to fund wallet: Address=%s, Amount=%d\n", request.Address, request.Amount)

	// Transfer funds from the genesis account
	if err := node.Blockchain.TransferFunds("", request.Address, request.Amount); err != nil {
		http.Error(w, fmt.Sprintf("Failed to fund wallet: %v", err), http.StatusInternalServerError)
		return
	}
	response := map[string]string{
		"message": fmt.Sprintf("Funded wallet with %d successfully", request.Amount),
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response) // Consider error handling for JSON encoding
}

func (node *Node) RegisterOrImportWalletHandler(w http.ResponseWriter, r *http.Request) {
	log.Println("RegisterOrImportWalletHandler request received")

	// Check if Supabase client is initialized
	if node.SupabaseClient == nil {
		log.Printf("Supabase client not initialized")
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}

	// Define request structure
	var req struct {
		PublicKey         string `json:"publicKey"`
		IsImport          bool   `json:"isImport"`
		UserID            string `json:"userId,omitempty"`
		Username          string `json:"username,omitempty"`
		BlockchainAddress string `json:"blockchainAddress,omitempty"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		log.Printf("Failed to decode request: %v", err)
		http.Error(w, "Invalid request body: "+err.Error(), http.StatusBadRequest)
		return
	}

	// Add debug logging for received request
	log.Printf("Received request - PublicKey: %s, IsImport: %v, UserID: %s", req.PublicKey, req.IsImport, req.UserID)

	// Only require UserID for imports
	if req.IsImport && req.UserID == "" {
		log.Printf("No user ID provided for import request")
		http.Error(w, "User ID is required for imports", http.StatusBadRequest)
		return
	}

	// Get username only if UserID is provided
	// After the request validation and before the username section, add:
	// Generate Bech32 address from public key
	bech32Address, err := publicKeyToBech32(req.PublicKey)
	if err != nil {
		log.Printf("Failed to convert public key to Bech32 address: %v", err)
		http.Error(w, "Failed to generate Bech32 address: "+err.Error(), http.StatusInternalServerError)
		return
	}
	log.Printf("Generated Bech32 address: %s", bech32Address)
	var username string
	if req.UserID != "" {
		// Get existing blockchain info
		existingAddress, err := GetBlockchainAddressByUID(node.SupabaseClient, req.UserID)
		if err != nil {
			log.Printf("Failed to get existing blockchain address: %v", err)
			// Don't return error, continue with import
		}

		// If this is an import and the addresses are different, update the blockchain info
		if req.IsImport && existingAddress != bech32Address {
			log.Printf("Updating blockchain address for user %s from %s to %s",
				req.UserID, existingAddress, bech32Address)

			// Use the provided username from the request
			if req.Username != "" {
				username = req.Username
				log.Printf("Using provided username for import: %s", username)
			}

			// Update blockchain info with new address
			err = node.Blockchain.UpdateBlockchainInfo(req.UserID, bech32Address)
			if err != nil {
				log.Printf("Failed to update blockchain info: %v", err)
				// Continue without failing the request
			}
		} else if !req.IsImport {
			// For new account creation, get username from UserID
			username, err = GetUsernameByUID(node.SupabaseClient, req.UserID)
			if err != nil {
				log.Printf("Failed to get username: %v", err)
			} else {
				log.Printf("Got username for UserID %s: %s", req.UserID, username)
			}
		}
	}

	// Decode base64 string to bytes
	publicKeyBytes, err := base64.StdEncoding.DecodeString(req.PublicKey)
	if err != nil {
		log.Printf("Invalid base64 format for public key: %v", err)
		http.Error(w, "Invalid public key format: "+err.Error(), http.StatusBadRequest)
		return
	}

	// Define response structure once
	type WalletResponse struct {
		PublicKey         string        `json:"publicKey"`
		BlockchainAddress string        `json:"blockchainAddress"`
		Balance           int64         `json:"balance"`
		BalanceThrylos    float64       `json:"balanceThrylos"`
		UTXOs             []shared.UTXO `json:"utxos"`
		Username          string        `json:"username"` // Make sure this isn't omitempty
	}

	// Check address existence
	dbExists, err := node.Blockchain.Database.Bech32AddressExists(bech32Address)
	if err != nil {
		log.Printf("Failed to check address in database: %v", err)
		http.Error(w, "Database error: "+err.Error(), http.StatusInternalServerError)
		return
	}

	_, stakeholderExists := node.Blockchain.Stakeholders[bech32Address]

	node.WebSocketMutex.RLock()
	_, wsExists := node.WebSocketConnections[bech32Address]
	node.WebSocketMutex.RUnlock()

	utxos, err := node.Blockchain.GetUTXOsForAddress(bech32Address)
	if err != nil {
		log.Printf("Failed to check UTXOs: %v", err)
		http.Error(w, "Database error: "+err.Error(), http.StatusInternalServerError)
		return
	}

	addressExists := dbExists || stakeholderExists || wsExists || len(utxos) > 0

	log.Printf("Address existence check results - DB: %v, Stakeholder: %v, WebSocket: %v, UTXOs: %d",
		dbExists, stakeholderExists, wsExists, len(utxos))

	var response WalletResponse

	if addressExists {
		if !req.IsImport {
			log.Printf("Attempt to register existing address: %s", bech32Address)
			http.Error(w, "Blockchain address already registered.", http.StatusBadRequest)
			return
		}

		// For imports, verify the blockchain address matches
		if req.IsImport && req.BlockchainAddress != "" {
			if req.BlockchainAddress != bech32Address {
				log.Printf("Blockchain address mismatch. Expected: %s, Got: %s", req.BlockchainAddress, bech32Address)
				http.Error(w, "Blockchain address mismatch", http.StatusBadRequest)
				return
			}
		}

		var totalBalance int64
		if stakeholderBalance, exists := node.Blockchain.Stakeholders[bech32Address]; exists {
			totalBalance = stakeholderBalance
		}

		for _, utxo := range utxos {
			if !utxo.IsSpent {
				totalBalance += utxo.Amount
			}
		}

		response = WalletResponse{
			PublicKey:         req.PublicKey,
			BlockchainAddress: bech32Address,
			Balance:           totalBalance,
			BalanceThrylos:    float64(totalBalance) / NanoThrylosPerThrylos,
			UTXOs:             utxos,
			Username:          username,
		}
	} else {
		if req.IsImport {
			log.Printf("Attempt to import non-existent address: %s", bech32Address)
			http.Error(w, "Blockchain address not found.", http.StatusNotFound)
			return
		}

		initialBalanceThrylos := 70.0
		initialBalanceNano := ThrylosToNanoNode(initialBalanceThrylos)

		currentBalanceNano, genesisExists := node.Blockchain.Stakeholders[node.Blockchain.GenesisAccount]
		if !genesisExists || currentBalanceNano < initialBalanceNano {
			log.Printf("Insufficient funds in genesis account")
			http.Error(w, "Insufficient funds in the genesis account.", http.StatusBadRequest)
			return
		}

		utxo := shared.UTXO{
			TransactionID: fmt.Sprintf("genesis-%s", bech32Address),
			OwnerAddress:  bech32Address,
			Amount:        initialBalanceNano,
			IsSpent:       false,
		}
		if err := node.Blockchain.addUTXO(utxo); err != nil {
			http.Error(w, "Failed to create initial UTXO: "+err.Error(), http.StatusInternalServerError)
			return
		}

		node.Blockchain.Stakeholders[node.Blockchain.GenesisAccount] -= initialBalanceNano
		node.Blockchain.Stakeholders[bech32Address] = initialBalanceNano

		response = WalletResponse{
			PublicKey:         req.PublicKey,
			BlockchainAddress: bech32Address,
			Balance:           initialBalanceNano,
			BalanceThrylos:    initialBalanceThrylos,
			UTXOs:             []shared.UTXO{utxo},
			Username:          username,
		}
	}

	// Save/update public key in database
	if err := node.Blockchain.Database.InsertOrUpdateEd25519PublicKey(bech32Address, publicKeyBytes); err != nil {
		http.Error(w, "Failed to save public key to database: "+err.Error(), http.StatusInternalServerError)
		return
	}

	jsonResponse, err := json.Marshal(response)
	if err != nil {
		log.Printf("Failed to serialize response: %v", err)
		http.Error(w, "Failed to serialize wallet data: "+err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.Write(jsonResponse)
}

func (node *Node) GetUTXOsForAddressHandler(w http.ResponseWriter, r *http.Request) {
	log.Printf("GetUTXOsForAddressHandler called with method: %s", r.Method)

	if r.Method == http.MethodOptions {
		w.WriteHeader(http.StatusOK)
		return
	}

	log.Printf("Request URL: %s", r.URL.String())
	address := r.URL.Query().Get("address")
	if address == "" {
		log.Printf("Address parameter is missing")
		http.Error(w, "Address parameter is missing", http.StatusBadRequest)
		return
	}

	log.Printf("Fetching UTXOs for address: %s", address)
	utxos, err := node.Blockchain.GetUTXOsForAddress(address)
	if err != nil {
		log.Printf("Error fetching UTXOs from database for address %s: %v", address, err)
		http.Error(w, fmt.Sprintf("Error fetching UTXOs: %v", err), http.StatusInternalServerError)
		return
	}

	if len(utxos) == 0 {
		log.Printf("No UTXOs found for address: %s", address)
		http.Error(w, "No UTXOs found", http.StatusNotFound)
		return
	}

	// Log UTXOs before serialization
	for i, utxo := range utxos {
		log.Printf("UTXO %d for address %s: {ID: %s, TransactionID: %s, Index: %d, Amount: %d, IsSpent: %v}",
			i, address, utxo.ID, utxo.TransactionID, utxo.Index, utxo.Amount, utxo.IsSpent)
	}

	response, err := json.Marshal(utxos)
	if err != nil {
		log.Printf("Failed to serialize UTXOs for address %s: %v", address, err)
		http.Error(w, "Failed to serialize UTXOs", http.StatusInternalServerError)
		return
	}

	// Log the final JSON response
	log.Printf("Response JSON for %s: %s", address, string(response))

	w.Header().Set("Content-Type", "application/json")
	w.Write(response)
}

// Public key and address handlers
func (node *Node) CheckPublicKeyHandler(w http.ResponseWriter, r *http.Request) {
	publicKey := r.URL.Query().Get("publicKey") // Use r.URL.Query().Get to fetch query parameters
	if publicKey == "" {
		http.Error(w, "Public key parameter is required", http.StatusBadRequest)
		return
	}
	exists, err := node.Blockchain.Database.PublicKeyExists(publicKey)
	if err != nil {
		http.Error(w, "Internal server error: "+err.Error(), http.StatusInternalServerError)
		return
	}
	response := map[string]bool{"exists": exists}
	if err := json.NewEncoder(w).Encode(response); err != nil {
		http.Error(w, "Failed to encode response: "+err.Error(), http.StatusInternalServerError)
		return
	}
}

// Allows users to register their public keys with Thrylos, enssential for transactions where public keys are needed
func (node *Node) RegisterPublicKeyHandler(w http.ResponseWriter, r *http.Request) {
	var req struct {
		PublicKey string `json:"publicKey"`
	}
	err := json.NewDecoder(r.Body).Decode(&req)
	if err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}
	// Use node.Blockchain to access the RegisterPublicKey method
	if err := node.Blockchain.RegisterPublicKey(req.PublicKey); err != nil {
		http.Error(w, "Failed to register public key: "+err.Error(), http.StatusInternalServerError)
		return
	}
	w.WriteHeader(http.StatusOK)
	w.Write([]byte("Public key registered successfully"))
}

func (node *Node) GetPublicKeyHandler(w http.ResponseWriter, r *http.Request) {
	address := r.URL.Query().Get("address")
	if address == "" {
		http.Error(w, "Address parameter is missing", http.StatusBadRequest)
		return
	}

	publicKey, err := node.RetrievePublicKey(address)
	if err != nil {
		http.Error(w, err.Error(), http.StatusNotFound)
		return
	}
	response := map[string]string{
		"publicKey": base64.StdEncoding.EncodeToString(publicKey),
	}

	jsonResp, err := json.Marshal(response)
	if err != nil {
		http.Error(w, "Failed to serialize public key response", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Write(jsonResp)
}

func (node *Node) GetBlockchainAddressHandler(w http.ResponseWriter, r *http.Request) {
	uid := r.URL.Query().Get("userId")
	if uid == "" {
		http.Error(w, "User ID parameter is missing", http.StatusBadRequest)
		return
	}
	blockchainAddress, err := GetBlockchainAddressByUID(node.SupabaseClient, uid)
	if err != nil {
		log.Printf("Failed to retrieve blockchain address for UID %s: %v", uid, err)
		http.Error(w, "Internal server error: "+err.Error(), http.StatusInternalServerError)
		return
	}
	if blockchainAddress == "" {
		http.Error(w, "Blockchain address not found", http.StatusNotFound)
		return
	}
	response := map[string]string{"blockchainAddress": blockchainAddress}
	jsonResponse, err := json.Marshal(response)
	if err != nil {
		log.Printf("Failed to serialize response: %v", err)
		http.Error(w, "Failed to serialize response", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Write(jsonResponse)
}

// Staking and validator handlers

func (node *Node) GetStakingStatsHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		sendJSONErrorResponse(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	userAddress := r.URL.Query().Get("address")
	if userAddress == "" {
		sendJSONErrorResponse(w, "Address parameter is required", http.StatusBadRequest)
		return
	}

	// Get user's staking stats
	stakes := node.stakingService.stakes[userAddress]

	totalStaked := int64(0)
	rewardsEarned := int64(0)
	pendingRelease := int64(0)
	availableForWithdrawal := int64(0)

	for _, stake := range stakes {
		if stake.IsActive {
			totalStaked += stake.Amount
			rewardsEarned += node.stakingService.CalculateRewards(stake)

			if time.Now().Unix() >= stake.EndTime {
				availableForWithdrawal += stake.Amount + node.stakingService.CalculateRewards(stake)
			} else {
				pendingRelease += stake.Amount + node.stakingService.CalculateRewards(stake)
			}
		}
	}

	response := map[string]interface{}{
		"totalStaked":            totalStaked,
		"rewardsEarned":          rewardsEarned,
		"pendingRelease":         pendingRelease,
		"availableForWithdrawal": availableForWithdrawal,
		"apr":                    node.stakingService.pool.APR,
		"minStakeAmount":         node.stakingService.pool.MinStakeAmount,
	}

	sendResponseProcess(w, response)
}

func (node *Node) GetStakingInfoHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		sendJSONErrorResponse(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	userAddress := r.URL.Query().Get("address")
	if userAddress == "" {
		sendJSONErrorResponse(w, "Address parameter is required", http.StatusBadRequest)
		return
	}

	// Get user's stakes
	stakes := node.stakingService.stakes[userAddress]

	// Calculate total staked and rewards
	var totalStaked, totalRewards int64
	var activeStakes []*Stake
	for _, stake := range stakes {
		if stake.IsActive {
			totalStaked += stake.Amount
			rewards := node.stakingService.CalculateRewards(stake)
			totalRewards += rewards
			activeStakes = append(activeStakes, stake)
		}
	}

	response := map[string]interface{}{
		"totalStaked":  totalStaked,
		"totalRewards": totalRewards,
		"activeStakes": activeStakes,
		"stakingPool":  node.stakingService.pool,
	}

	sendResponseProcess(w, response)
}

func (node *Node) StatsHandler(w http.ResponseWriter, r *http.Request) {
	stats := node.GetBlockchainStats()
	statsJSON, err := json.Marshal(stats)
	if err != nil {
		http.Error(w, "Failed to serialize blockchain statistics", http.StatusInternalServerError)
		return
	}
	sendResponse(w, statsJSON)
}

func (node *Node) UnstakeTokensHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		sendJSONErrorResponse(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req struct {
		UserAddress      string `json:"userAddress"`
		Amount           int64  `json:"amount"`
		ValidatorAddress string `json:"validatorAddress"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		sendJSONErrorResponse(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	// Verify stake exists and can be unstaked
	if err := node.stakingService.UnstakeTokens(req.UserAddress, req.Amount); err != nil {
		sendJSONErrorResponse(w, fmt.Sprintf("Failed to unstake tokens: %v", err), http.StatusBadRequest)
		return
	}

	// Create unstaking transaction
	unstakeTx := &thrylos.Transaction{
		Id:        fmt.Sprintf("unstake-%s-%d", req.UserAddress, time.Now().UnixNano()),
		Sender:    req.ValidatorAddress,
		Timestamp: time.Now().Unix(),
		Status:    "pending",
		Gasfee:    1000,
		Outputs: []*thrylos.UTXO{
			{
				OwnerAddress:  req.UserAddress,
				Amount:        req.Amount,
				Index:         0,
				TransactionId: "", // Will be set after creation
			},
		},
	}

	if err := node.AddPendingTransaction(unstakeTx); err != nil {
		sendJSONErrorResponse(w, fmt.Sprintf("Failed to process unstaking transaction: %v", err), http.StatusInternalServerError)
		return
	}

	// Update UTXO TransactionId
	for _, output := range unstakeTx.Outputs {
		output.TransactionId = unstakeTx.Id
	}

	response := map[string]interface{}{
		"message":       "Tokens unstaked successfully",
		"transactionId": unstakeTx.Id,
	}
	sendResponseProcess(w, response)
}

func (node *Node) UpdateStakeHandler(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Address string `json:"address"`
		Amount  int64  `json:"amount"` // Positive to increase, negative to decrease
	}
	err := json.NewDecoder(r.Body).Decode(&req)
	if err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}
	if err := node.Blockchain.UpdateStake(req.Address, req.Amount); err != nil {
		http.Error(w, "Failed to update stake: "+err.Error(), http.StatusInternalServerError)
		return
	}
	w.WriteHeader(http.StatusOK)
	w.Write([]byte("Stake updated successfully"))
}

func (node *Node) RegisterValidatorHandler(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Address   string `json:"address"`
		PublicKey string `json:"publicKey"`
	}
	err := json.NewDecoder(r.Body).Decode(&req)
	if err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	// TO DO - Set the Stake amount for the validators

	// Verify the requester has sufficient stake
	// stake, err := node.Blockchain.GetStake(req.Address)
	// if err != nil {
	// 	http.Error(w, "Failed to retrieve stake: "+err.Error(), http.StatusInternalServerError)
	// 	return
	// }

	// minStake := node.Blockchain.GetMinStakeForValidator()
	// if stake.Cmp(minStake) < 0 {
	// 	http.Error(w, "Insufficient stake to become a validator", http.StatusBadRequest)
	// 	return
	// }

	// Register the validator without bypassing stake check
	if err := node.Blockchain.RegisterValidator(req.Address, req.PublicKey, false); err != nil {
		http.Error(w, "Failed to register as validator: "+err.Error(), http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusOK)
	w.Write([]byte("Registered as validator successfully"))
}

func (node *Node) DelegateStakeHandler(w http.ResponseWriter, r *http.Request) {
	var req struct {
		From   string `json:"from"`
		To     string `json:"to"`
		Amount int64  `json:"amount"`
	}
	err := json.NewDecoder(r.Body).Decode(&req)
	if err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}
	if err := node.Blockchain.DelegateStake(req.From, req.To, req.Amount); err != nil {
		http.Error(w, "Failed to delegate stake: "+err.Error(), http.StatusInternalServerError)
		return
	}
	w.WriteHeader(http.StatusOK)
	w.Write([]byte("Stake delegated successfully"))
}

func (node *Node) GetValidatorsHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		sendJSONErrorResponse(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Get active validators with their stats
	validators := make([]map[string]interface{}, 0)
	for _, validatorAddr := range node.Blockchain.ActiveValidators {
		stake, exists := node.Blockchain.Stakeholders[validatorAddr]
		if !exists {
			continue
		}

		validators = append(validators, map[string]interface{}{
			"id":     validatorAddr,
			"name":   fmt.Sprintf("Validator %s", validatorAddr[:8]),
			"status": "Active",
			"stake":  stake,
			"apr":    node.stakingService.pool.APR,
		})
	}

	sendResponseProcess(w, validators)
}

func (node *Node) StakeTokensHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		sendJSONErrorResponse(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req struct {
		UserAddress      string `json:"userAddress"`
		Amount           int64  `json:"amount"`
		ValidatorAddress string `json:"validatorAddress"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		sendJSONErrorResponse(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	// Verify validator exists
	if !node.Blockchain.validatorExists(req.ValidatorAddress) {
		sendJSONErrorResponse(w, "Invalid validator address", http.StatusBadRequest)
		return
	}

	// Create staking transaction
	stakingTx := &thrylos.Transaction{
		Id:        fmt.Sprintf("stake-%s-%d", req.UserAddress, time.Now().UnixNano()),
		Sender:    req.UserAddress,
		Timestamp: time.Now().Unix(),
		Status:    "pending", // Use status field instead of type
		Gasfee:    1000,      // Set appropriate gas fee
		Outputs: []*thrylos.UTXO{
			{
				OwnerAddress:  req.ValidatorAddress,
				Amount:        req.Amount,
				Index:         0,  // Set appropriate index
				TransactionId: "", // Will be set to stakingTx.Id after creation
			},
		},
		PreviousTxIds: []string{}, // Add if there are previous transactions to reference
	}

	// Create the stake
	stake, err := node.stakingService.CreateStake(req.UserAddress, req.Amount)
	if err != nil {
		sendJSONErrorResponse(w, fmt.Sprintf("Failed to create stake: %v", err), http.StatusBadRequest)
		return
	}

	// Add to pending transactions
	if err := node.AddPendingTransaction(stakingTx); err != nil {
		sendJSONErrorResponse(w, fmt.Sprintf("Failed to process staking transaction: %v", err), http.StatusInternalServerError)
		return
	}

	// After transaction is added to pending, update UTXO TransactionId
	for _, output := range stakingTx.Outputs {
		output.TransactionId = stakingTx.Id
	}

	response := map[string]interface{}{
		"message":       "Stake created successfully",
		"stake":         stake,
		"transactionId": stakingTx.Id,
	}
	sendResponseProcess(w, response)
}

// Utility handlers
func (node *Node) GasEstimateHandler(w http.ResponseWriter, r *http.Request) {
	// Log the incoming request
	log.Printf("GasEstimateHandler called with method: %s", r.Method)

	// Handle OPTIONS request
	if r.Method == http.MethodOptions {
		w.WriteHeader(http.StatusOK)
		return
	}

	// Ensure the request method is GET
	if r.Method != http.MethodGet {
		log.Printf("Invalid method for GasEstimateHandler: %s", r.Method)
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Get and validate dataSize parameter
	dataSizeStr := r.URL.Query().Get("dataSize")
	if dataSizeStr == "" {
		log.Print("dataSize parameter is missing")
		http.Error(w, "dataSize parameter is missing", http.StatusBadRequest)
		return
	}

	dataSize, err := strconv.Atoi(dataSizeStr)
	if err != nil {
		log.Printf("Invalid dataSize parameter: %v", err)
		http.Error(w, "Invalid dataSize parameter", http.StatusBadRequest)
		return
	}

	// Calculate gas
	gas := CalculateGas(dataSize, 0)

	// Prepare the response
	response := struct {
		GasFee     int    `json:"gasfee"`
		GasFeeUnit string `json:"gasFeeUnit"`
	}{
		GasFee:     gas,
		GasFeeUnit: "nanoTHRYLOS",
	}

	// Set content type and encode response
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(response); err != nil {
		log.Printf("Error encoding response: %v", err)
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}

	log.Printf("Gas fee estimate sent: %d for data size: %d", gas, dataSize)
}

func (node *Node) NetworkHealthHandler(w http.ResponseWriter, r *http.Request) {
	healthInfo := struct {
		Status  string `json:"status"`
		Message string `json:"message"`
	}{
		Status:  "OK",
		Message: "Node is active and connected to peers",
	}
	if len(node.Peers) == 0 {
		healthInfo.Status = "WARNING"
		healthInfo.Message = "Node is not connected to any peers"
	}
}

// GetBlockHandler retrieves a specific block by ID.
func (node *Node) GetBlockHandler(w http.ResponseWriter, r *http.Request) {
	blockID := r.URL.Query().Get("id")
	if blockID == "" {
		http.Error(w, "Block ID is required", http.StatusBadRequest)
		return
	}

	block, err := node.Blockchain.GetBlockByID(blockID)
	if err != nil {
		http.Error(w, "Block not found", http.StatusNotFound)
		return
	}

	// Check if the block transactions are not null
	if block.Transactions == nil {
		log.Printf("No transactions found in block %s", blockID)
	}

	blockJSON, err := json.Marshal(block)
	if err != nil {
		log.Printf("Error serializing block: %v", err)
		http.Error(w, "Failed to serialize block", http.StatusInternalServerError)
		return
	}

	log.Printf("Sending block data: %s", string(blockJSON))
	w.Header().Set("Content-Type", "application/json")
	w.Write(blockJSON)
}

// This handler could expose details about validators, their stakes, the votes they've cast for the most recent blocks, and potentially their historical performance or participation rates.

func (node *Node) ConsensusInfoHandler(w http.ResponseWriter, r *http.Request) {
	var validators []struct {
		Address string `json:"address"`
		Stake   int64  `json:"stake"`
		Votes   []Vote `json:"votes"`
	}
	// Gathering data for each stakeholder
	for address, stake := range node.Blockchain.Stakeholders {
		votes := []Vote{}
		for _, vote := range node.Votes {
			if vote.Validator == address {
				votes = append(votes, vote)
			}
		}
		validators = append(validators, struct {
			Address string `json:"address"`
			Stake   int64  `json:"stake"`
			Votes   []Vote `json:"votes"`
		}{
			Address: address,
			Stake:   stake,
			Votes:   votes,
		})
	}
	// Marshal and send the data
	response, err := json.Marshal(validators)
	if err != nil {
		http.Error(w, "Failed to serialize consensus information", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Write(response)
}

// Helper functions
func sendResponse(w http.ResponseWriter, data []byte) {
	w.Header().Set("Content-Type", "application/json")
	w.Write(data)
}

func sendJSONErrorResponse(w http.ResponseWriter, message string, statusCode int) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(statusCode)
	json.NewEncoder(w).Encode(map[string]string{"error": message})
}

func sendResponseProcess(w http.ResponseWriter, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(data)
}

func enableCors(w *http.ResponseWriter) {
	(*w).Header().Set("Access-Control-Allow-Origin", "http://localhost:3000")
	(*w).Header().Set("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
	(*w).Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization")
}
