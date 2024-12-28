package core

import (
	"bufio"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/btcsuite/btcd/btcutil/bech32"
	"github.com/gorilla/mux"
	"github.com/shopspring/decimal"
	thrylos "github.com/thrylos-labs/thrylos"
	"github.com/thrylos-labs/thrylos/shared"
	"golang.org/x/crypto/ed25519"
)

// Apply CORS middleware to setup the handlers
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
			// More comprehensive logging
			log.Printf("[%s] Request: %s %s from %s",
				time.Now().Format(time.RFC3339),
				r.Method,
				r.URL.Path,
				r.RemoteAddr,
			)

			// Enhanced origin checking with more flexible matching
			allowedOrigins := []string{
				"http://localhost:3000",
				"https://node.thrylos.org",
				"http://localhost:", // Allow all localhost ports
				"https://www.thrylos.org",
			}
			origin := r.Header.Get("Origin")

			// More robust origin validation
			originAllowed := false
			for _, allowedOrigin := range allowedOrigins {
				if origin == allowedOrigin ||
					(allowedOrigin == "http://localhost:" && strings.HasPrefix(origin, "http://localhost:")) {
					originAllowed = true
					w.Header().Set("Access-Control-Allow-Origin", origin)
					break
				}
			}

			// Set comprehensive and secure CORS headers
			w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
			w.Header().Set("Access-Control-Allow-Headers",
				"Content-Type, Authorization, X-Requested-With, Accept, Cache-Control, X-CSRF-Token")
			w.Header().Set("Access-Control-Allow-Credentials", "true")
			w.Header().Set("Access-Control-Max-Age", "86400")

			// Additional security headers
			w.Header().Set("X-Content-Type-Options", "nosniff")
			w.Header().Set("X-Frame-Options", "DENY")
			w.Header().Set("Referrer-Policy", "strict-origin-when-cross-origin")

			// Handle preflight requests
			if r.Method == "OPTIONS" {
				w.WriteHeader(http.StatusNoContent)
				return
			}

			// Enhanced origin and method validation
			if !originAllowed && !isWebSocketRequest(r) {
				if r.Method != "OPTIONS" {
					log.Printf("Blocked request from unauthorized origin: %s", origin)
					http.Error(w, "Unauthorized origin", http.StatusForbidden)
					return
				}
			}

			// Context-specific headers
			switch r.URL.Path {
			case "/get-balance", "/ws/balance":
				w.Header().Set("Cache-Control", "no-cache, no-store, must-revalidate")
				w.Header().Set("Pragma", "no-cache")
				w.Header().Set("Expires", "0")
			}

			// Set content type for non-WebSocket requests
			if !isWebSocketRequest(r) {
				w.Header().Set("Content-Type", "application/json; charset=utf-8")
			}

			// Optional: Basic request tracking
			ctx := context.WithValue(r.Context(), "request_start_time", time.Now())
			r = r.WithContext(ctx)

			next.ServeHTTP(w, r)
		})
	})

	r.HandleFunc("/", node.JSONRPCHandler).Methods("POST")

	// WebSocket endpoint with specific handling
	r.HandleFunc("/ws/balance", func(w http.ResponseWriter, r *http.Request) {
		if isWebSocketRequest(r) {
			node.WebSocketBalanceHandler(w, r)
			return
		}
		http.Error(w, "Expected WebSocket connection", http.StatusBadRequest)
	})
	r.HandleFunc("/ws/balance", node.WebSocketBalanceHandler).Methods("GET")

	// In your SetupRoutes function, update the WebSocket status route
	r.HandleFunc("/ws/status", func(w http.ResponseWriter, r *http.Request) {
		// Set CORS headers specifically for this endpoint
		w.Header().Set("Access-Control-Allow-Origin", "http://localhost:3000")
		w.Header().Set("Access-Control-Allow-Methods", "GET, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type")

		if r.Method == "OPTIONS" {
			w.WriteHeader(http.StatusOK)
			return
		}

		node.WebSocketStatusHandler(w, r)
	}).Methods("GET", "OPTIONS")
	// Core blockchain endpoints
	r.HandleFunc("/block", node.BlockHandler).Methods("POST")
	r.HandleFunc("/transaction", node.TransactionHandler).Methods("POST")
	r.HandleFunc("/peers", node.PeersHandler).Methods("GET")

	// Transaction related endpoints
	r.HandleFunc("/process-transaction", node.ProcessSignedTransactionHandler).Methods("POST", "OPTIONS")
	r.HandleFunc("/pending-transactions", node.PendingTransactionsHandler).Methods("GET")
	r.HandleFunc("/list-transactions-for-block", node.ListTransactionsForBlockHandler).Methods("GET")

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
	r.HandleFunc("/consensus-info", node.ConsensusInfoHandler).Methods("GET")
	r.HandleFunc("/stats", node.StatsHandler).Methods("GET")

	return r
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

// Helper function to derive address from public key
func deriveAddressFromPublicKey(publicKey []byte) (string, error) {
	// Convert public key bytes to 5-bit words for bech32 encoding
	words, err := bech32.ConvertBits(publicKey, 8, 5, true)
	if err != nil {
		return "", fmt.Errorf("failed to convert public key to 5-bit words: %v", err)
	}

	// Encode with your tl1 prefix (matching your frontend)
	address, err := bech32.Encode("tl1", words)
	if err != nil {
		return "", fmt.Errorf("failed to encode bech32 address: %v", err)
	}

	return address, nil
}

var _ shared.GasEstimator = &Node{} // Ensures Node implements the GasEstimator interface

const MinTransactionAmount int64 = 1 * NanoThrylosPerThrylos // 1 THRYLOS in nanoTHRYLOS

func (n *Node) ProcessSignedTransactionHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodOptions {
		w.WriteHeader(http.StatusOK)
		return
	}

	log.Printf("processing transaction...")

	// Use a buffered reader for better performance
	bodyBytes, err := io.ReadAll(bufio.NewReader(r.Body))
	if err != nil {
		sendJSONErrorResponse(w, "Failed to read request body: "+err.Error(), http.StatusBadRequest)
		return
	}
	log.Printf("Request body read successfully")

	var requestData struct {
		Payload   map[string]interface{} `json:"payload"`
		Signature string                 `json:"signature"`
		PublicKey string                 `json:"publicKey"`
	}

	if err := json.Unmarshal(bodyBytes, &requestData); err != nil {
		log.Printf("Failed to unmarshal request: %v", err)
		sendJSONErrorResponse(w, "Invalid request format: "+err.Error(), http.StatusBadRequest)
		return
	}
	log.Printf("Request unmarshaled successfully")

	// Fast path validation
	log.Printf("Validating sender...")
	sender, ok := requestData.Payload["sender"].(string)
	if !ok {
		sendJSONErrorResponse(w, "Invalid sender in payload", http.StatusBadRequest)
		return
	}

	log.Printf("Starting critical validation...")
	// Parallel validation of critical components with timeout
	validationDone := make(chan error, 1)
	var signatureBytes []byte
	var messageBytes []byte
	var publicKeyBytes []byte

	go func() {
		var err error
		// Get public key
		publicKeyBytes, err = base64.StdEncoding.DecodeString(requestData.PublicKey)
		if err != nil {
			validationDone <- fmt.Errorf("invalid public key encoding: %v", err)
			return
		}

		// Verify the public key corresponds to the sender address
		derivedAddress, err := deriveAddressFromPublicKey(publicKeyBytes)
		if err != nil {
			validationDone <- fmt.Errorf("failed to derive address: %v", err)
			return
		}

		// Verify the sender address matches the derived address
		if derivedAddress != sender {
			validationDone <- fmt.Errorf("public key does not match sender address: derived=%s, claimed=%s",
				derivedAddress, sender)
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
		if !ed25519.Verify(publicKeyBytes, messageBytes, signatureBytes) {
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

	log.Printf("Creating transaction data...")
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

	log.Printf("[TX Handler] Created transaction with ID: %s", thrylosTx.GetId())

	log.Printf("[TX Handler] Starting validation process for tx: %s", thrylosTx.GetId())

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
		start := time.Now()
		log.Printf("[TX Handler] Step 1: Starting balance fetch for tx: %s", thrylosTx.GetId())
		balance, err := n.GetBalance(transactionData.Sender)
		if err != nil {
			log.Printf("[TX Handler] Balance fetch failed: %v", err)
			validationComplete <- fmt.Errorf("failed to fetch balance: %v", err)
			return
		}
		log.Printf("[TX Handler] Balance fetch completed in %v", time.Since(start))

		// 2. Validate Transaction
		if err := shared.ValidateAndConvertTransaction(
			thrylosTx,
			n.Database,
			ed25519.PublicKey(publicKeyBytes),
			n,
			balance,
		); err != nil {
			log.Printf("[TX Handler] Transaction validation failed: %v", err)
			validationComplete <- fmt.Errorf("failed to validate transaction: %v", err)
			return
		}
		log.Printf("[TX Handler] Transaction validation completed in %v", time.Since(start))

		// 3. Check components
		if n.DAGManager == nil {
			log.Printf("[TX Handler] DAGManager not initialized")
			validationComplete <- fmt.Errorf("DAGManager not initialized")
			return
		}
		if n.ModernProcessor == nil {
			log.Printf("[TX Handler] ModernProcessor not initialized")
			validationComplete <- fmt.Errorf("ModernProcessor not initialized")
			return
		}

		log.Printf("Starting ProcessIncomingTransaction...")
		// 4. Process Transaction
		log.Printf("[TX Handler] Starting ProcessIncomingTransaction")
		if err := n.ProcessIncomingTransaction(thrylosTx); err != nil {
			log.Printf("[TX Handler] ProcessIncomingTransaction failed: %v", err)
			validationComplete <- fmt.Errorf("failed to process transaction: %v", err)
			return
		}
		log.Printf("[TX Handler] ProcessIncomingTransaction completed in %v", time.Since(start))

		validationComplete <- nil
	}()

	// Wait for validation or timeout
	select {
	case err := <-validationComplete:
		if err != nil {
			log.Printf("[TX Handler] Validation failed with error: %v", err)
			sendJSONErrorResponse(w, err.Error(), http.StatusBadRequest)
			return
		}
		log.Printf("[TX Handler] Validation completed successfully")
	case <-time.After(10 * time.Second): // Increased timeout
		log.Printf("[TX Handler] Transaction processing timed out")
		sendJSONErrorResponse(w, "Transaction processing timeout", http.StatusGatewayTimeout)
		return
	}

	// Update balances in background
	go func() {
		addresses := make(map[string]bool)
		addresses[transactionData.Sender] = true
		for _, output := range transactionData.Outputs {
			addresses[output.OwnerAddress] = true
		}

		// Add delay to allow transaction to be processed
		time.Sleep(500 * time.Millisecond)

		// Update balances multiple times to ensure delivery
		for i := 0; i < 3; i++ {
			for address := range addresses {
				if balance, err := n.GetBalance(address); err == nil {
					n.notifyBalanceUpdate(address, balance)
				}
				time.Sleep(200 * time.Millisecond)
			}
		}
	}()

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
	stakes := node.Blockchain.StakingService.stakes[userAddress]
	currentBlock := int64(node.Blockchain.GetBlockCount())

	totalStaked := int64(0)
	rewardsEarned := int64(0)
	availableForWithdrawal := int64(0)

	for _, stake := range stakes {
		if stake.IsActive {
			totalStaked += stake.Amount
			currentRewards := node.Blockchain.StakingService.CalculateRewards(stake, currentBlock)
			rewardsEarned += currentRewards + stake.TotalRewards

			// Calculate available for withdrawal
			if currentBlock >= stake.LastRewardEpoch+node.Blockchain.StakingService.pool.EpochLength {
				availableForWithdrawal += stake.Amount + currentRewards
			}
		}
	}

	response := map[string]interface{}{
		"totalStaked":            decimal.NewFromFloat(float64(totalStaked) / 1e7), // Convert to decimal for frontend
		"rewardsEarned":          decimal.NewFromFloat(float64(rewardsEarned) / 1e7),
		"availableForWithdrawal": decimal.NewFromFloat(float64(availableForWithdrawal) / 1e7),
	}

	sendResponseProcess(w, response)
}

func getTotalSupply(node *Node) float64 {
	totalSupply := int64(0)
	for _, balance := range node.Blockchain.Stakeholders {
		totalSupply += balance
	}
	return float64(totalSupply) / 1e7
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
	stakes := node.Blockchain.StakingService.stakes[userAddress]
	currentBlock := int64(node.Blockchain.GetBlockCount())

	// Calculate total staked and rewards
	var totalStaked, totalRewards int64
	var activeStakes []*Stake
	for _, stake := range stakes {
		if stake.IsActive {
			totalStaked += stake.Amount
			currentRewards := node.Blockchain.StakingService.CalculateRewards(stake, currentBlock)
			totalRewards += currentRewards + stake.TotalRewards
			activeStakes = append(activeStakes, stake)
		}
	}

	stakingPool := node.Blockchain.StakingService.pool

	// Calculate effective rate based on current supply

	currentSupply := getTotalSupply(node)
	yearlyReward := 4_800_000.0 // Fixed 4.8M
	effectiveRate := (yearlyReward / currentSupply) * 100

	// Create detailed staking pool info
	poolInfo := map[string]interface{}{
		"minStakeAmount": map[string]interface{}{
			"thrylos": float64(stakingPool.MinStakeAmount) / 1e7,
			"nano":    stakingPool.MinStakeAmount,
		},
		"totalStaked": map[string]interface{}{
			"thrylos": float64(stakingPool.TotalStaked) / 1e7,
			"nano":    stakingPool.TotalStaked,
		},
		"epochInfo": map[string]interface{}{
			"current":         currentBlock / stakingPool.EpochLength,
			"length":          stakingPool.EpochLength,
			"blocksUntilNext": stakingPool.EpochLength - (currentBlock % stakingPool.EpochLength),
			"lastRewardBlock": stakingPool.LastEpochBlock,
		},
		"rewardInfo": map[string]interface{}{
			"yearlyReward":     "4.8M",
			"effectiveRate":    fmt.Sprintf("%.2f%%", effectiveRate),
			"nextDistribution": stakingPool.EpochLength - (currentBlock % stakingPool.EpochLength),
		},
	}

	response := map[string]interface{}{
		"address":     userAddress,
		"isValidator": node.Blockchain.IsActiveValidator(userAddress),
		"staking": map[string]interface{}{
			"totalStaked": map[string]interface{}{
				"thrylos": float64(totalStaked) / 1e7,
				"nano":    totalStaked,
			},
			"totalRewards": map[string]interface{}{
				"thrylos": float64(totalRewards) / 1e7,
				"nano":    totalRewards,
			},
			"activeStakesCount": len(activeStakes),
			"activeStakes":      activeStakes,
		},
		"stakingPool": poolInfo,
		"networkStats": map[string]interface{}{
			"totalValidators":      len(node.Blockchain.ActiveValidators),
			"totalStakedAmount":    float64(stakingPool.TotalStaked) / 1e7,
			"currentEffectiveRate": fmt.Sprintf("%.2f%%", effectiveRate),
		},
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

	// Verify validator exists and is active
	if !node.Blockchain.validatorExists(req.ValidatorAddress) {
		sendJSONErrorResponse(w, "Invalid validator address", http.StatusBadRequest)
		return
	}

	// Verify the user has enough staked tokens
	currentStake := node.Blockchain.Stakeholders[req.UserAddress]
	if currentStake < req.Amount {
		sendJSONErrorResponse(w, "Insufficient staked amount", http.StatusBadRequest)
		return
	}

	// Calculate any pending rewards before unstaking
	currentBlock := int64(node.Blockchain.GetBlockCount())
	stakes := node.Blockchain.StakingService.stakes[req.UserAddress]
	var pendingRewards int64
	for _, stake := range stakes {
		if stake.IsActive && stake.Amount == req.Amount {
			pendingRewards = node.Blockchain.StakingService.CalculateRewards(stake, currentBlock)
			break
		}
	}

	// Process unstaking
	if err := node.Blockchain.StakingService.UnstakeTokens(req.UserAddress, req.Amount); err != nil {
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
				Amount:        req.Amount + pendingRewards, // Include any pending rewards
				Index:         0,
				TransactionId: "",
			},
		},
	}

	if err := node.ProcessIncomingTransaction(unstakeTx); err != nil {
		// Rollback unstake if transaction fails
		node.Blockchain.StakingService.CreateStake(req.UserAddress, req.Amount)
		sendJSONErrorResponse(w, fmt.Sprintf("Failed to process unstaking transaction: %v", err), http.StatusInternalServerError)
		return
	}

	// Update UTXO TransactionId
	for _, output := range unstakeTx.Outputs {
		output.TransactionId = unstakeTx.Id
	}

	// Calculate effective rate for response
	currentSupply := getTotalSupply(node)
	yearlyReward := 4_800_000.0 // Fixed 4.8M
	effectiveRate := (yearlyReward / currentSupply) * 100

	response := map[string]interface{}{
		"message":       "Tokens unstaked successfully",
		"transactionId": unstakeTx.Id,
		"unstakeInfo": map[string]interface{}{
			"amount":         float64(req.Amount) / 1e7,
			"pendingRewards": float64(pendingRewards) / 1e7,
			"totalReturn":    float64(req.Amount+pendingRewards) / 1e7,
		},
		"stakingInfo": map[string]interface{}{
			"remainingStake": float64(currentStake-req.Amount) / 1e7,
			"effectiveRate":  fmt.Sprintf("%.2f%%", effectiveRate),
			"nextEpochIn": node.Blockchain.StakingService.pool.EpochLength -
				(currentBlock % node.Blockchain.StakingService.pool.EpochLength),
		},
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
	validators := make([]map[string]interface{}, 0)
	effectiveRate := node.Blockchain.GetEffectiveInflationRate() // Use blockchain method

	// Calculate total supply correctly
	totalSupply := int64(0)
	for _, balance := range node.Blockchain.Stakeholders {
		totalSupply += balance
	}

	// Fixed yearly reward and effective rate calculation
	yearlyReward := 4_800_000.0 // Fixed 4.8M
	effectiveAPR := (yearlyReward / (float64(totalSupply) / 1e7)) * 100

	for _, validatorAddr := range node.Blockchain.ActiveValidators {
		stake, exists := node.Blockchain.Stakeholders[validatorAddr]
		if !exists {
			continue
		}

		validators = append(validators, map[string]interface{}{
			"id":     validatorAddr,
			"name":   fmt.Sprintf("Validator %s", validatorAddr[:8]),
			"staked": fmt.Sprintf("%.2f", float64(stake)/1e7),
			"apr":    effectiveRate,
			"status": "Active",
			"rewardInfo": map[string]interface{}{
				"yearlyReward":  "4.8M",
				"effectiveRate": fmt.Sprintf("%.2f%%", effectiveAPR),
				"totalStaked":   fmt.Sprintf("%.2f", float64(node.Blockchain.StakingService.pool.TotalStaked)/1e7),
				"nextEpochIn": node.Blockchain.StakingService.pool.EpochLength -
					(int64(node.Blockchain.GetBlockCount()) % node.Blockchain.StakingService.pool.EpochLength),
				"currentSupply": fmt.Sprintf("%.2f", float64(totalSupply)/1e7),
			},
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
		Mode             string `json:"mode"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		sendJSONErrorResponse(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	// Check minimum stake amount
	minStake := node.Blockchain.StakingService.pool.MinStakeAmount
	if req.Amount < minStake {
		sendJSONErrorResponse(w, fmt.Sprintf("Stake amount must be at least %d THRYLOS", minStake/1e7), http.StatusBadRequest)
		return
	}

	// Verify validator exists and is active
	if !node.Blockchain.validatorExists(req.ValidatorAddress) {
		sendJSONErrorResponse(w, "Invalid validator address", http.StatusBadRequest)
		return
	}

	if !node.Blockchain.IsActiveValidator(req.ValidatorAddress) {
		sendJSONErrorResponse(w, "Validator is not active", http.StatusBadRequest)
		return
	}

	// Check user's balance
	balance, err := node.GetBalance(req.UserAddress)
	if err != nil {
		sendJSONErrorResponse(w, fmt.Sprintf("Failed to get balance: %v", err), http.StatusInternalServerError)
		return
	}

	if balance < req.Amount+1000 { // Including gas fee
		sendJSONErrorResponse(w, "Insufficient balance for staking", http.StatusBadRequest)
		return
	}

	var stakeRecord *Stake

	if req.Mode == "unstake" {
		if err = node.Blockchain.StakingService.UnstakeTokens(req.UserAddress, req.Amount); err != nil {
			sendJSONErrorResponse(w, fmt.Sprintf("Failed to unstake: %v", err), http.StatusBadRequest)
			return
		}
	} else {
		stakeRecord, err = node.Blockchain.StakingService.CreateStake(req.UserAddress, req.Amount)
		if err != nil {
			sendJSONErrorResponse(w, fmt.Sprintf("Failed to create stake: %v", err), http.StatusBadRequest)
			return
		}
	}

	// Create staking transaction
	stakingTx := &thrylos.Transaction{
		Id:        fmt.Sprintf("stake-%s-%d", req.UserAddress, time.Now().UnixNano()),
		Sender:    req.UserAddress,
		Timestamp: time.Now().Unix(),
		Status:    "pending",
		Gasfee:    1000,
		Outputs: []*thrylos.UTXO{
			{
				OwnerAddress:  req.ValidatorAddress,
				Amount:        req.Amount,
				Index:         0,
				TransactionId: "",
			},
		},
		PreviousTxIds: []string{},
	}

	// Process the transaction
	if err = node.ProcessIncomingTransaction(stakingTx); err != nil {
		if req.Mode != "unstake" {
			node.Blockchain.StakingService.UnstakeTokens(req.UserAddress, req.Amount)
		}
		sendJSONErrorResponse(w, fmt.Sprintf("Failed to process staking transaction: %v", err), http.StatusInternalServerError)
		return
	}

	// Update UTXO TransactionId
	for _, output := range stakingTx.Outputs {
		output.TransactionId = stakingTx.Id
	}

	// Calculate effective rate based on current supply
	effectiveRate := node.Blockchain.GetEffectiveInflationRate()

	// Prepare response
	var message string
	if req.Mode == "unstake" {
		message = "Unstake processed successfully"
	} else {
		message = "Stake created successfully"
	}

	response := map[string]interface{}{
		"message": message,
	}

	if req.Mode != "unstake" && stakeRecord != nil {
		response["stake"] = map[string]interface{}{
			"amount":          float64(stakeRecord.Amount) / 1e7,
			"amountRaw":       stakeRecord.Amount,
			"startTime":       stakeRecord.StartTime,
			"isActive":        stakeRecord.IsActive,
			"validatorRole":   stakeRecord.ValidatorRole,
			"lastRewardEpoch": stakeRecord.LastRewardEpoch,
		}
	}

	response["transactionId"] = stakingTx.Id
	response["stakingInfo"] = map[string]interface{}{
		"currentEpoch":   node.Blockchain.GetBlockCount() / int(node.Blockchain.StakingService.pool.EpochLength),
		"yearlyReward":   "4.8M",
		"effectiveRate":  fmt.Sprintf("%.2f%%", effectiveRate),
		"minStakeAmount": float64(minStake) / 1e7,
		"blocksNextEpoch": node.Blockchain.StakingService.pool.EpochLength -
			(int64(node.Blockchain.GetBlockCount()) % node.Blockchain.StakingService.pool.EpochLength),
	}

	sendResponseProcess(w, response)
}

func (node *Node) ValidateStakingAmount(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Amount int64  `json:"amount"`
		Mode   string `json:"mode"`
	}

	if req.Mode == "stake" && req.Amount < node.Blockchain.StakingService.pool.MinStakeAmount {
		sendJSONErrorResponse(w, fmt.Sprintf("Minimum stake is %d THR",
			node.Blockchain.StakingService.pool.MinStakeAmount/1e7),
			http.StatusBadRequest)
		return
	}

	sendResponseProcess(w, map[string]bool{"valid": true})
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
