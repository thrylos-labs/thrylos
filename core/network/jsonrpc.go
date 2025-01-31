package network

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/btcsuite/btcutil/bech32"
	"github.com/cloudflare/circl/sign/mldsa/mldsa44"
	"github.com/shopspring/decimal"
	"github.com/thrylos-labs/thrylos" // Add this import
	"github.com/thrylos-labs/thrylos/shared"
)

type Handler struct {
	node *node.Node
}

func NewHandler(node *node.Node) *Handler {
	return &Handler{node: node}
}
func sendJSONRPCError(w http.ResponseWriter, jsonrpcErr *JSONRPCError, id interface{}) {
	response := JSONRPCResponse{
		JSONRPC: "2.0",
		Error:   jsonrpcErr,
		ID:      id,
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusBadRequest)
	json.NewEncoder(w).Encode(response)
}

type JSONRPCRequest struct {
	JSONRPC string        `json:"jsonrpc"`
	Method  string        `json:"method"`
	Params  []interface{} `json:"params"`
	ID      interface{}   `json:"id"`
}

type JSONRPCResponse struct {
	JSONRPC string        `json:"jsonrpc"`
	Result  interface{}   `json:"result,omitempty"`
	Error   *JSONRPCError `json:"error,omitempty"`
	ID      interface{}   `json:"id"`
}

type JSONRPCError struct {
	Code    int         `json:"code"`
	Message string      `json:"message"`
	Data    interface{} `json:"data,omitempty"`
}

// Main JSON-RPC handler that routes to these handlers
func (node *node.Node) JSONRPCHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req JSONRPCRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		sendJSONRPCError(w, &JSONRPCError{
			Code:    -32700,
			Message: "Parse error",
		}, req.ID)
		return
	}

	var result interface{}
	var err error

	switch req.Method {
	case "getBalance":
		result, err = node.handleGetBalance(req.Params)
	case "getUTXO":
		result, err = node.handleGetUTXO(req.Params)
	case "getBlock":
		result, err = node.handleGetBlock(req.Params)
	case "getBlockchainInfo":
		result, err = node.handleGetBlockchainInfo(req.Params)
	case "submitBlock":
		result, err = node.handleSubmitBlock(req.Params)
	case "getPeers":
		result, err = node.handleGetPeers(req.Params)
	case "submitSignedTransaction":
		result, err = node.handleSubmitSignedTransaction(req.Params)
	case "estimateGas":
		result, err = node.handleEstimateGas(req.Params)
	case "stake":
		result, err = node.handleStaking(req.Params)
	case "delegate":
		result, err = node.handlePoolDelegation(req.Params)
	case "undelegate":
		result, err = node.handlePoolUndelegation(req.Params)
	case "getPoolStats":
		result, err = node.handleGetPoolStats(req.Params)
	case "getDelegatorInfo":
		result, err = node.handleGetDelegatorInfo(req.Params)
	case "getStakingInfo":
		result, err = node.handleGetStakingInfo(req.Params)
	case "getNetworkHealth":
		result, err = node.handleGetNetworkHealth(req.Params)
	case "getValidators":
		result, err = node.handleGetValidators(req.Params)
	case "getBlockTransactions":
		result, err = node.handleGetBlockTransactions(req.Params)
	case "getStakingStats":
		result, err = node.handleGetStakingStats(req.Params)
	case "registerValidator": // Add this case
		result, err = node.handleRegisterValidator(req.Params)
	case "getStats": // Add this case
		result, err = node.handleGetStats(req.Params)
	case "subscribe":
		if node.isWebSocketRequest(r) {
			node.handleWebSocketSubscription(w, r, req.Params)
			return
		}
		sendJSONRPCError(w, &JSONRPCError{
			Code:    -32600,
			Message: "Subscription requires WebSocket connection",
		}, req.ID)
	case "unsubscribe":
		if node.isWebSocketRequest(r) {
			node.handleWebSocketUnsubscription(w, r, req.Params)
			return
		}
		sendJSONRPCError(w, &JSONRPCError{
			Code:    -32600,
			Message: "Unsubscribe requires WebSocket connection",
		}, req.ID)
		return
	}

	if err != nil {
		sendJSONRPCError(w, &JSONRPCError{
			Code:    -32603,
			Message: err.Error(),
		}, req.ID)
		return
	}

	response := JSONRPCResponse{
		JSONRPC: "2.0",
		Result:  result,
		ID:      req.ID,
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

// Method handlers
// handleGetBalance maps to BalanceHandler
func (node *node.Node) handleGetBalance(params []interface{}) (interface{}, error) {
	if len(params) < 1 {
		return nil, fmt.Errorf("address parameter required")
	}

	address, ok := params[0].(string)
	if !ok {
		return nil, fmt.Errorf("invalid address parameter")
	}

	// Same logic as BalanceHandler
	balance, err := node.GetBalance(address)
	if err != nil {
		log.Printf("Error getting balance for address %s: %v", address, err)
		if strings.Contains(err.Error(), "wallet not found") {
			balance = 700000000 // 70 Thrylos in nanoTHR
		} else {
			return nil, fmt.Errorf("error getting balance: %v", err)
		}
	}

	// Same response structure as before
	return struct {
		Balance        int64   `json:"balance"`
		BalanceThrylos float64 `json:"balanceThrylos"`
	}{
		Balance:        balance,
		BalanceThrylos: float64(balance) / 1e7,
	}, nil
}

// handleGetUTXO maps to GetUTXOsForAddressHandler
func (node *node.Node) handleGetUTXO(params []interface{}) (interface{}, error) {
	if len(params) < 1 {
		return nil, fmt.Errorf("address parameter required")
	}

	address, ok := params[0].(string)
	if !ok {
		return nil, fmt.Errorf("invalid address parameter")
	}

	log.Printf("Fetching UTXOs for address: %s", address)
	utxos, err := node.Blockchain.GetUTXOsForAddress(address)
	if err != nil {
		log.Printf("Error fetching UTXOs from database for address %s: %v", address, err)
		return nil, fmt.Errorf("error fetching UTXOs: %v", err)
	}

	if len(utxos) == 0 {
		log.Printf("No UTXOs found for address: %s", address)
		return []interface{}{}, nil // Empty array instead of error for JSON-RPC
	}

	// Log UTXOs for debugging
	for i, utxo := range utxos {
		log.Printf("UTXO %d for address %s: {ID: %s, TransactionID: %s, Index: %d, Amount: %d, IsSpent: %v}",
			i, address, utxo.ID, utxo.TransactionID, utxo.Index, utxo.Amount, utxo.IsSpent)
	}

	return utxos, nil
}

// handleGetBlock maps to GetBlockHandler
func (node *node.Node) handleGetBlock(params []interface{}) (interface{}, error) {
	if len(params) < 1 {
		return nil, fmt.Errorf("block identifier required")
	}

	var block *Block
	var err error

	// Handle both string (hash) and number (height) parameters
	switch v := params[0].(type) {
	case string:
		block, err = node.Blockchain.GetBlockByID(v)
	case float64:
		// Validate block height against current blockchain count
		blockHeight := int32(v)
		blockCount := node.Blockchain.GetBlockCount()

		if blockHeight < 0 || blockHeight >= int32(blockCount) {
			return nil, fmt.Errorf("block height %d is out of range. Current blockchain height is %d",
				blockHeight, blockCount)
		}

		blockHash := fmt.Sprintf("%d", blockHeight) // Placeholder - adjust to match your block hash generation
		block, err = node.Blockchain.GetBlockByID(blockHash)
	default:
		return nil, fmt.Errorf("invalid block identifier type")
	}

	if err != nil {
		return nil, fmt.Errorf("block not found: %v", err)
	}

	if block.Transactions == nil {
		log.Printf("No transactions found in block %v", params[0])
	}

	return block, nil
}

// handleGetBlockchainInfo maps to BlockchainHandler
func (node *node.Node) handleGetBlockchainInfo(params []interface{}) (interface{}, error) {
	// Enhanced blockchain info
	info := struct {
		Height      int32  `json:"height"`
		ChainID     string `json:"chainId"`
		LastBlock   string `json:"lastBlock"`
		NodeCount   int    `json:"nodeCount"`
		NodeVersion string `json:"nodeVersion"`
		IsSyncing   bool   `json:"isSyncing"`
	}{
		Height:      int32(node.Blockchain.GetBlockCount()),
		ChainID:     node.chainID,
		NodeCount:   len(node.Peers),
		NodeVersion: "1.0.0", // Add your version
		IsSyncing:   false,   // Add sync status
	}

	// Get last block hash
	lastBlock, _, err := node.Blockchain.GetLastBlock()
	if err == nil && lastBlock != nil {
		info.LastBlock = string(lastBlock.Hash)
	}

	return info, nil
}

func (node *node.Node) handleSubmitBlock(params []interface{}) (interface{}, error) {
	// Check if params exist
	if len(params) < 1 {
		return nil, fmt.Errorf("block parameter required")
	}

	// Convert params[0] to Block struct
	blockData, ok := params[0].(map[string]interface{})
	if !ok {
		return nil, fmt.Errorf("invalid block parameter format")
	}

	// Convert the map to JSON then back to Block struct
	blockJSON, err := json.Marshal(blockData)
	if err != nil {
		return nil, fmt.Errorf("error marshaling block data: %v", err)
	}

	var block Block
	if err := json.Unmarshal(blockJSON, &block); err != nil {
		return nil, fmt.Errorf("error unmarshaling block: %v", err)
	}

	// Get the last block - same logic as before
	prevBlock, prevIndex, err := node.Blockchain.GetLastBlock()
	if err != nil {
		return nil, fmt.Errorf("failed to get the last block: %v", err)
	}

	// Validate block
	if prevBlock != nil && !node.Blockchain.ValidateBlock(&block, prevBlock) {
		return nil, fmt.Errorf("block validation failed")
	}

	// Add block
	success, err := node.Blockchain.AddBlock(
		block.Transactions,
		block.Validator,
		block.PrevHash,
		block.Timestamp,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to add block: %v", err)
	}
	if !success {
		return nil, fmt.Errorf("failed to add block due to validation or other issues")
	}

	// Log previous block info
	if prevBlock != nil {
		log.Printf("Previous Block Index: %d, Block Hash: %s", prevIndex, prevBlock.Hash)
	} else {
		log.Println("No previous block exists.")
	}

	// Return success response
	return struct {
		Success bool   `json:"success"`
		Message string `json:"message"`
	}{
		Success: true,
		Message: "Block successfully added",
	}, nil
}

func (node *node.Node) handleGetPeers(params []interface{}) (interface{}, error) {
	// Return the peers in a structured format
	return struct {
		Peers []string `json:"peers"`
		Count int      `json:"count"`
	}{
		Peers: node.GetPeerAddresses(),
		Count: len(node.Peers),
	}, nil
}

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

var _ shared.GasEstimator = &node.Node{} // Ensures Node implements the GasEstimator interface

const MinTransactionAmount int64 = 1 * node.NanoThrylosPerThrylos // 1 THRYLOS in nanoTHRYLOS

func (node *node.Node) handleSubmitSignedTransaction(params []interface{}) (interface{}, error) {
	// Check if params exist
	if len(params) < 1 {
		return nil, fmt.Errorf("transaction parameter required")
	}

	// Extract the request data
	reqData, ok := params[0].(map[string]interface{})
	if !ok {
		return nil, fmt.Errorf("invalid request format")
	}

	// Extract and validate the main components
	payload, ok := reqData["payload"].(map[string]interface{})
	if !ok {
		return nil, fmt.Errorf("invalid payload format")
	}

	signature, ok := reqData["signature"].(string)
	if !ok {
		return nil, fmt.Errorf("invalid signature format")
	}

	publicKey, ok := reqData["publicKey"].(string)
	if !ok {
		return nil, fmt.Errorf("invalid publicKey format")
	}

	// Fast path validation
	sender, ok := payload["sender"].(string)
	if !ok {
		return nil, fmt.Errorf("invalid sender in payload")
	}

	// Critical validation
	validationDone := make(chan error, 1)
	var signatureBytes []byte
	var messageBytes []byte
	var publicKeyBytes []byte

	go func() {
		var err error
		// Get public key
		publicKeyBytes, err = base64.StdEncoding.DecodeString(publicKey)
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
		signatureBytes, err = base64.StdEncoding.DecodeString(signature)
		if err != nil {
			validationDone <- fmt.Errorf("invalid signature encoding: %v", err)
			return
		}

		// Marshal payload
		messageBytes, err = json.Marshal(payload)
		if err != nil {
			validationDone <- fmt.Errorf("failed to marshal payload: %v", err)
			return
		}

		// Verify signature
		pk := new(mldsa44.PublicKey)
		if err := pk.UnmarshalBinary(publicKeyBytes); err != nil {
			validationDone <- fmt.Errorf("failed to unmarshal public key: %v", err)
			return
		}

		// Verify signature using mldsa44
		if !mldsa44.Verify(pk, messageBytes, signatureBytes, nil) {
			validationDone <- fmt.Errorf("invalid signature")
			return
		}

		validationDone <- nil
	}()

	// Wait for validation with timeout
	select {
	case err := <-validationDone:
		if err != nil {
			return nil, err
		}
	case <-time.After(1 * time.Second):
		return nil, fmt.Errorf("validation timeout")
	}

	// Create transaction data
	var transactionData shared.Transaction
	transactionData.ID = payload["id"].(string)
	transactionData.Sender = sender

	// Process numeric fields
	if gasFeeFloat, ok := payload["gasfee"].(float64); ok {
		transactionData.GasFee = int(gasFeeFloat)
	} else {
		return nil, fmt.Errorf("invalid gasfee in payload")
	}

	if timestampFloat, ok := payload["timestamp"].(float64); ok {
		transactionData.Timestamp = int64(timestampFloat)
	} else {
		return nil, fmt.Errorf("invalid timestamp in payload")
	}

	// Process inputs/outputs
	if inputsData, ok := payload["inputs"].([]interface{}); ok {
		inputsJSON, err := json.Marshal(inputsData)
		if err != nil {
			return nil, fmt.Errorf("invalid inputs in payload: %v", err)
		}
		if err := json.Unmarshal(inputsJSON, &transactionData.Inputs); err != nil {
			return nil, fmt.Errorf("failed to parse inputs: %v", err)
		}
	}

	if outputsData, ok := payload["outputs"].([]interface{}); ok {
		outputsJSON, err := json.Marshal(outputsData)
		if err != nil {
			return nil, fmt.Errorf("invalid outputs in payload: %v", err)
		}
		if err := json.Unmarshal(outputsJSON, &transactionData.Outputs); err != nil {
			return nil, fmt.Errorf("failed to parse outputs: %v", err)
		}
	}

	// Convert and validate transaction
	thrylosTx := shared.SharedToThrylos(&transactionData)
	if thrylosTx == nil {
		return nil, fmt.Errorf("failed to convert transaction data")
	}
	thrylosTx.Signature = signatureBytes

	log.Printf("[TX Handler] Created transaction with ID: %s", thrylosTx.GetId())

	// Start block creation early
	go func() {
		if err := node.TriggerBlockCreation(); err != nil {
			log.Printf("Error triggering block creation: %v", err)
		}
	}()

	// Parallel balance fetch and validation with timeout
	validationComplete := make(chan error, 1)
	go func() {
		balance, err := node.GetBalance(transactionData.Sender)
		if err != nil {
			validationComplete <- fmt.Errorf("failed to fetch balance: %v", err)
			return
		}

		pk := new(mldsa44.PublicKey)
		if err := pk.UnmarshalBinary(publicKeyBytes); err != nil {
			validationComplete <- fmt.Errorf("failed to unmarshal public key: %v", err)
			return
		}

		if err := shared.ValidateAndConvertTransaction(
			thrylosTx,
			node.Database,
			pk,
			node,
			balance,
		); err != nil {
			validationComplete <- fmt.Errorf("failed to validate transaction: %v", err)
			return
		}

		if node.DAGManager == nil {
			validationComplete <- fmt.Errorf("DAGManager not initialized")
			return
		}
		if node.ModernProcessor == nil {
			validationComplete <- fmt.Errorf("ModernProcessor not initialized")
			return
		}

		if err := node.ProcessIncomingTransaction(thrylosTx); err != nil {
			validationComplete <- fmt.Errorf("failed to process transaction: %v", err)
			return
		}

		validationComplete <- nil
	}()

	// Wait for validation or timeout
	select {
	case err := <-validationComplete:
		if err != nil {
			return nil, err
		}
	case <-time.After(10 * time.Second):
		return nil, fmt.Errorf("transaction processing timeout")
	}

	// Handle balance updates and broadcasting in background
	go func() {
		addresses := make(map[string]bool)
		addresses[transactionData.Sender] = true
		for _, output := range transactionData.Outputs {
			addresses[output.OwnerAddress] = true
		}

		time.Sleep(500 * time.Millisecond)

		for i := 0; i < 3; i++ {
			for address := range addresses {
				if balance, err := node.GetBalance(address); err == nil {
					node.notifyBalanceUpdate(address, balance)
				}
				time.Sleep(200 * time.Millisecond)
			}
		}
	}()

	go func() {
		if err := node.BroadcastTransaction(thrylosTx); err != nil {
			log.Printf("Warning: Failed to broadcast transaction: %v", err)
		}
	}()

	// Return success response
	return struct {
		Message string `json:"message"`
		Status  string `json:"status"`
		TxID    string `json:"txId"`
	}{
		Message: fmt.Sprintf("Transaction %s submitted successfully", transactionData.ID),
		Status:  "pending",
		TxID:    transactionData.ID,
	}, nil
}

func (node *node.Node) handleEstimateGas(params []interface{}) (interface{}, error) {
	// Log the incoming request
	log.Printf("estimateGas JSON-RPC method called")

	// Check if params exist
	if len(params) < 1 {
		return nil, fmt.Errorf("dataSize parameter required")
	}

	// Extract dataSize from params
	dataSizeFloat, ok := params[0].(float64)
	if !ok {
		return nil, fmt.Errorf("invalid dataSize parameter: must be a number")
	}

	// Convert float64 to int
	dataSize := int(dataSizeFloat)

	// Calculate gas
	gas := node.CalculateGas(dataSize, 0)

	// Log the estimation
	log.Printf("Gas fee estimate calculated: %d for data size: %d", gas, dataSize)

	// Return structured response
	return struct {
		GasFee     int    `json:"gasFee"`
		GasFeeUnit string `json:"gasFeeUnit"`
	}{
		GasFee:     gas,
		GasFeeUnit: "nanoTHRYLOS",
	}, nil
}

func (node *node.Node) handleGetStakingStats(params []interface{}) (interface{}, error) {
	// Check if params exist
	if len(params) < 1 {
		return nil, fmt.Errorf("address parameter required")
	}

	// Extract address from params
	reqData, ok := params[0].(map[string]interface{})
	if !ok {
		return nil, fmt.Errorf("invalid request format")
	}

	userAddress, ok := reqData["address"].(string)
	if !ok {
		return nil, fmt.Errorf("address required")
	}

	// Get user's staking stats
	stakes := node.Blockchain.StakingService.stakes[userAddress]

	totalStaked := stakes.Amount
	rewardsEarned := stakes.TotalStakeRewards + stakes.TotalDelegationRewards
	availableForWithdrawal := int64(0)

	// Return formatted response
	return map[string]interface{}{
		"address": userAddress,
		"stats": map[string]interface{}{
			"totalStaked": map[string]interface{}{
				"thrylos": decimal.NewFromFloat(float64(totalStaked) / 1e7),
				"nano":    totalStaked,
			},
			"rewardsEarned": map[string]interface{}{
				"thrylos": decimal.NewFromFloat(float64(rewardsEarned) / 1e7),
				"nano":    rewardsEarned,
			},
			"availableForWithdrawal": map[string]interface{}{
				"thrylos": decimal.NewFromFloat(float64(availableForWithdrawal) / 1e7),
				"nano":    availableForWithdrawal,
			},
			"isActiveValidator": node.Blockchain.IsActiveValidator(userAddress),
			"lastRewardTime":    node.stakingService.pool.LastRewardTime,
		},
	}, nil
}

func (node *node.Node) handleStaking(params []interface{}) (interface{}, error) {
	if len(params) < 1 {
		return nil, fmt.Errorf("parameters required")
	}

	reqData, ok := params[0].(map[string]interface{})
	if !ok {
		return nil, fmt.Errorf("invalid request format")
	}

	// Extract operation type
	operation, ok := reqData["operation"].(string)
	if !ok {
		return nil, fmt.Errorf("operation field required")
	}

	switch operation {
	case "stake":
		return node.handleStakeOperation(reqData)
	case "unstake":
		return node.handleUnstakeOperation(reqData)
	case "delegate":
		return node.handleDelegateOperation(reqData)
	case "validate":
		return node.handleValidateStakeOperation(reqData)
	default:
		return nil, fmt.Errorf("unknown operation: %s", operation)
	}
}

func (node *node.Node) handleStakeOperation(reqData map[string]interface{}) (interface{}, error) {
	// Extract required fields
	userAddress, ok := reqData["userAddress"].(string)
	if !ok {
		return nil, fmt.Errorf("userAddress required")
	}

	amountFloat, ok := reqData["amount"].(float64)
	if !ok {
		return nil, fmt.Errorf("amount required")
	}
	amount := int64(amountFloat)

	validatorAddress, ok := reqData["validatorAddress"].(string)
	if !ok {
		return nil, fmt.Errorf("validatorAddress required")
	}

	// Validate minimum stake
	minStake := node.Blockchain.StakingService.pool.MinStakeAmount
	if amount < minStake {
		return nil, fmt.Errorf("stake amount must be at least %d THRYLOS", minStake/1e7)
	}

	// Verify validator exists and is active
	if !node.Blockchain.validatorExists(validatorAddress) {
		return nil, fmt.Errorf("invalid validator address")
	}

	if !node.Blockchain.IsActiveValidator(validatorAddress) {
		return nil, fmt.Errorf("validator is not active")
	}

	// Check user's balance
	balance, err := node.GetBalance(userAddress)
	if err != nil {
		return nil, fmt.Errorf("failed to get balance: %v", err)
	}

	if balance < amount+1000 { // Including gas fee
		return nil, fmt.Errorf("insufficient balance for staking")
	}

	// Create stake record
	stakeRecord, err := node.CreateStake(userAddress, amount)
	if err != nil {
		return nil, fmt.Errorf("failed to create stake: %v", err)
	}

	// Create staking transaction
	stakingTx := &thrylos.Transaction{
		Id:        fmt.Sprintf("stake-%s-%d", userAddress, time.Now().UnixNano()),
		Sender:    userAddress,
		Timestamp: time.Now().Unix(),
		Status:    "pending",
		Gasfee:    1000,
		Outputs: []*thrylos.UTXO{
			{
				OwnerAddress:  validatorAddress,
				Amount:        amount,
				Index:         0,
				TransactionId: "",
			},
		},
		PreviousTxIds: []string{},
	}

	// Process the transaction
	if err = node.ProcessIncomingTransaction(stakingTx); err != nil {
		// Rollback stake if transaction fails
		node.UnstakeTokens(userAddress, false, amount)
		return nil, fmt.Errorf("failed to process staking transaction: %v", err)
	}

	// Update UTXO TransactionId
	for _, output := range stakingTx.Outputs {
		output.TransactionId = stakingTx.Id
	}

	effectiveRate := node.Blockchain.GetEffectiveInflationRate()

	// Calculate next reward time
	nextRewardTime := time.Unix(node.stakingService.pool.LastRewardTime, 0).Add(24 * time.Hour)

	return map[string]interface{}{
		"message": "Stake created successfully",
		"stake": map[string]interface{}{
			"amount":         float64(stakeRecord.Amount) / 1e7,
			"amountRaw":      stakeRecord.Amount,
			"startTime":      stakeRecord.StartTime,
			"isActive":       stakeRecord.IsActive,
			"validatorRole":  stakeRecord.ValidatorRole,
			"lastRewardTime": node.stakingService.pool.LastRewardTime,
		},
		"transactionId": stakingTx.Id,
		"stakingInfo": map[string]interface{}{
			"yearlyReward":     "4.8M",
			"effectiveRate":    fmt.Sprintf("%.2f%%", effectiveRate),
			"minStakeAmount":   float64(minStake) / 1e7,
			"nextRewardTime":   nextRewardTime.Unix(),
			"rewardInterval":   "24h",
			"activeValidators": len(node.Blockchain.ActiveValidators),
			// Calculate estimated daily reward per validator
			"estimatedDailyReward": float64(DailyStakeReward) /
				float64(len(node.Blockchain.ActiveValidators)) / 1e7,
		},
	}, nil
}

// Similar implementations for other operations:
func (node *node.Node) handleUnstakeOperation(reqData map[string]interface{}) (interface{}, error) {
	// Extract required fields
	userAddress, ok := reqData["userAddress"].(string)
	if !ok {
		return nil, fmt.Errorf("userAddress required")
	}

	amountFloat, ok := reqData["amount"].(float64)
	if !ok {
		return nil, fmt.Errorf("amount required")
	}
	amount := int64(amountFloat)

	validatorAddress, ok := reqData["validatorAddress"].(string)
	if !ok {
		return nil, fmt.Errorf("validatorAddress required")
	}

	// Verify validator exists
	if !node.Blockchain.validatorExists(validatorAddress) {
		return nil, fmt.Errorf("invalid validator address")
	}

	// Verify the user has enough staked tokens
	currentStake := node.Blockchain.Stakeholders[userAddress]
	if currentStake < amount {
		return nil, fmt.Errorf("insufficient staked amount")
	}

	// Calculate any pending rewards before unstaking
	currentTime := time.Now().Unix()
	//stakes := node.Blockchain.StakingService.stakes[userAddress]
	var pendingRewards int64

	// Process unstaking
	if err := node.UnstakeTokens(userAddress, false, amount); err != nil {
		return nil, fmt.Errorf("failed to unstake tokens: %v", err)
	}

	// Create unstaking transaction
	unstakeTx := &thrylos.Transaction{
		Id:        fmt.Sprintf("unstake-%s-%d", userAddress, time.Now().UnixNano()),
		Sender:    validatorAddress,
		Timestamp: currentTime,
		Status:    "pending",
		Gasfee:    1000,
		Outputs: []*thrylos.UTXO{
			{
				OwnerAddress:  userAddress,
				Amount:        amount + pendingRewards,
				Index:         0,
				TransactionId: "",
			},
		},
	}

	if err := node.ProcessIncomingTransaction(unstakeTx); err != nil {
		// Rollback unstake if transaction fails
		node.Blockchain.StakingService.CreateStake(userAddress, amount)
		return nil, fmt.Errorf("failed to process unstaking transaction: %v", err)
	}

	// Update UTXO TransactionId
	for _, output := range unstakeTx.Outputs {
		output.TransactionId = unstakeTx.Id
	}

	// Calculate effective rate for response
	currentSupply := getTotalSupply(node)
	yearlyReward := 4_800_000.0 // Fixed 4.8M
	effectiveRate := (yearlyReward / currentSupply) * 100

	// Get next reward time for any remaining stakes
	nextRewardTime := node.Blockchain.StakingService.pool.LastRewardTime + (24 * 3600)

	return map[string]interface{}{
		"message":       "Tokens unstaked successfully",
		"transactionId": unstakeTx.Id,
		"unstakeInfo": map[string]interface{}{
			"amount":         float64(amount) / 1e7,
			"pendingRewards": float64(pendingRewards) / 1e7,
			"totalReturn":    float64(amount+pendingRewards) / 1e7,
		},
		"stakingInfo": map[string]interface{}{
			"remainingStake":    float64(currentStake-amount) / 1e7,
			"effectiveRate":     fmt.Sprintf("%.2f%%", effectiveRate),
			"nextRewardTime":    nextRewardTime,
			"isActiveValidator": node.Blockchain.IsActiveValidator(userAddress),
			"activeValidators":  len(node.Blockchain.ActiveValidators),
		},
	}, nil
}

func (node *node.Node) handleDelegateOperation(reqData map[string]interface{}) (interface{}, error) {
	// Extract required fields
	address, ok := reqData["address"].(string)
	if !ok {
		return nil, fmt.Errorf("address required")
	}

	amountFloat, ok := reqData["amount"].(float64)
	if !ok {
		return nil, fmt.Errorf("amount required")
	}
	amount := int64(amountFloat)

	_, err := node.stakingService.createStakeInternal(address, true, amount, time.Now().Unix())
	if err != nil {
		return nil, fmt.Errorf("failed to delegate stake: %v", err)
	}

	return map[string]interface{}{
		"message": "Stake delegated successfully",
		"address": address,
		"amount":  float64(amount) / 1e7,
	}, nil
}

func (node *node.Node) handleValidateStakeOperation(reqData map[string]interface{}) (interface{}, error) {
	amountFloat, ok := reqData["amount"].(float64)
	if !ok {
		return nil, fmt.Errorf("amount required")
	}
	amount := int64(amountFloat)

	if amount < node.Blockchain.StakingService.pool.MinStakeAmount {
		return nil, fmt.Errorf("minimum stake is %d THR",
			node.Blockchain.StakingService.pool.MinStakeAmount/1e7)
	}

	return map[string]interface{}{
		"valid": true,
	}, nil
}

func getTotalSupply(node *node.Node) float64 {
	totalSupply := int64(0)
	for _, balance := range node.Blockchain.Stakeholders {
		totalSupply += balance
	}
	return float64(totalSupply) / 1e7
}

func (node *node.Node) handleGetStakingInfo(params []interface{}) (interface{}, error) {
	if len(params) < 1 {
		return nil, fmt.Errorf("address parameter required")
	}

	// Extract address
	reqData, ok := params[0].(map[string]interface{})
	if !ok {
		return nil, fmt.Errorf("invalid request format")
	}

	userAddress, ok := reqData["address"].(string)
	if !ok {
		return nil, fmt.Errorf("address parameter required")
	}

	// Get user's stakes
	stakes := node.Blockchain.StakingService.stakes[userAddress]
	currentTime := time.Now().Unix()

	// Calculate total staked and rewards
	// var totalStaked, totalRewards int64
	// var activeStakes []*Stake
	// var nextRewardTime int64

	totalStaked := node.Blockchain.StakingService.stakes[userAddress].Amount
	totalRewards := node.Blockchain.StakingService.stakes[userAddress].TotalDelegationRewards + node.Blockchain.StakingService.stakes[userAddress].TotalStakeRewards
	nextRewardTime := node.Blockchain.StakingService.pool.LastRewardTime + (24 * 3600)

	stakingPool := node.Blockchain.StakingService.pool

	// Calculate effective rate based on current supply
	currentSupply := getTotalSupply(node)
	yearlyReward := 4_800_000.0 // Fixed 4.8M
	effectiveRate := (yearlyReward / currentSupply) * 100

	// Get time until next reward distribution
	timeUntilNextReward := nextRewardTime - currentTime
	if timeUntilNextReward < 0 {
		timeUntilNextReward = 0
	}

	// Return updated response structure
	return map[string]interface{}{
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
			"activeStakesCount": 1,                //len(activeStakes), //TODO: we need to get these
			"activeStakes":      []*Stake{stakes}, //activeStakes, //TODO: we do not need this.
			"nextRewardTime":    nextRewardTime,
		},
		"stakingPool": map[string]interface{}{
			"minStakeAmount": map[string]interface{}{
				"thrylos": float64(stakingPool.MinStakeAmount) / 1e7,
				"nano":    stakingPool.MinStakeAmount,
			},
			"totalStaked": map[string]interface{}{
				"thrylos": float64(stakingPool.TotalStaked) / 1e7,
				"nano":    stakingPool.TotalStaked,
			},
			"rewardSchedule": map[string]interface{}{
				"interval":            "24h",
				"lastRewardTime":      stakingPool.LastRewardTime,
				"nextRewardTime":      nextRewardTime,
				"timeUntilNextReward": timeUntilNextReward,
				"estimatedDailyReward": float64(DailyStakeReward) /
					float64(len(node.Blockchain.ActiveValidators)) / 1e7,
			},
			"rewardInfo": map[string]interface{}{
				"yearlyReward":       "4.8M",
				"effectiveRate":      fmt.Sprintf("%.2f%%", effectiveRate),
				"rewardDistribution": "Daily",
			},
		},
		"networkStats": map[string]interface{}{
			"totalValidators":      len(node.Blockchain.ActiveValidators),
			"totalStakedAmount":    float64(stakingPool.TotalStaked) / 1e7,
			"currentEffectiveRate": fmt.Sprintf("%.2f%%", effectiveRate),
			"activeValidators":     node.Blockchain.ActiveValidators,
		},
	}, nil
}

func (node *node.Node) handleGetNetworkHealth(params []interface{}) (interface{}, error) {
	healthInfo := map[string]interface{}{
		"status":  "OK",
		"message": "Node is active and connected to peers",
	}

	if len(node.Peers) == 0 {
		healthInfo["status"] = "WARNING"
		healthInfo["message"] = "Node is not connected to any peers"
	}

	return healthInfo, nil
}

func (node *node.Node) handleGetValidators(params []interface{}) (interface{}, error) {
	validators := make([]map[string]interface{}, 0)
	effectiveRate := node.Blockchain.GetEffectiveInflationRate()

	// Calculate total supply
	totalSupply := int64(0)
	for _, balance := range node.Blockchain.Stakeholders {
		totalSupply += balance
	}

	// Fixed yearly reward and effective rate calculation
	yearlyReward := 4_800_000.0 // Fixed 4.8M
	effectiveAPR := (yearlyReward / (float64(totalSupply) / 1e7)) * 100

	// Calculate daily reward per validator
	// dailyRewardPerValidator := node.Blockchain.StakingService.calculateDailyReward() /
	// 	int64(len(node.Blockchain.ActiveValidators))

	dailyRewardPerValidator := 0 //TODO: we need to get this fixed

	currentTime := time.Now().Unix()
	stakingPool := node.Blockchain.StakingService.pool

	// Build validators list
	for _, validatorAddr := range node.Blockchain.ActiveValidators {
		stake, exists := node.Blockchain.Stakeholders[validatorAddr]
		if !exists {
			continue
		}
		// Get validator's next reward time
		nextRewardTime := node.stakingService.pool.LastRewardTime + (24 * 3600)

		timeUntilNextReward := nextRewardTime - currentTime
		if timeUntilNextReward < 0 {
			timeUntilNextReward = 0
		}

		validators = append(validators, map[string]interface{}{
			"id":     validatorAddr,
			"name":   fmt.Sprintf("Validator %s", validatorAddr[:8]),
			"staked": fmt.Sprintf("%.2f", float64(stake)/1e7),
			"apr":    effectiveRate,
			"status": "Active",
			"rewardInfo": map[string]interface{}{
				"yearlyReward":         "4.8M",
				"effectiveRate":        fmt.Sprintf("%.2f%%", effectiveAPR),
				"totalStaked":          fmt.Sprintf("%.2f", float64(stakingPool.TotalStaked)/1e7),
				"nextRewardTime":       nextRewardTime,
				"timeUntilReward":      timeUntilNextReward,
				"rewardInterval":       "24h",
				"estimatedDailyReward": fmt.Sprintf("%.2f", float64(dailyRewardPerValidator)/1e7),
				"currentSupply":        fmt.Sprintf("%.2f", float64(totalSupply)/1e7),
				"lastRewardTime":       node.Blockchain.StakingService.pool.LastRewardTime,
			},
		})
	}

	// Calculate network-wide next reward time
	nextNetworkReward := stakingPool.LastRewardTime + (24 * 3600)
	timeUntilNextNetworkReward := nextNetworkReward - currentTime
	if timeUntilNextNetworkReward < 0 {
		timeUntilNextNetworkReward = 0
	}

	return map[string]interface{}{
		"validators": validators,
		"count":      len(validators),
		"summary": map[string]interface{}{
			"totalStaked":   fmt.Sprintf("%.2f", float64(stakingPool.TotalStaked)/1e7),
			"totalSupply":   fmt.Sprintf("%.2f", float64(totalSupply)/1e7),
			"effectiveRate": fmt.Sprintf("%.2f%%", effectiveAPR),
			"rewardSchedule": map[string]interface{}{
				"interval":          "24h",
				"nextRewardTime":    nextNetworkReward,
				"timeUntilReward":   timeUntilNextNetworkReward,
				"lastNetworkReward": stakingPool.LastRewardTime,
				"dailyRewardPool":   fmt.Sprintf("%.2f", float64(DailyStakeReward)/1e7),
				"validatorsCount":   len(node.Blockchain.ActiveValidators),
			},
		},
	}, nil
}

func (node *node.Node) handleGetBlockTransactions(params []interface{}) (interface{}, error) {
	// Check if params exist
	if len(params) < 1 {
		return nil, fmt.Errorf("block ID parameter required")
	}

	// Extract blockID from params
	reqData, ok := params[0].(map[string]interface{})
	if !ok {
		return nil, fmt.Errorf("invalid request format")
	}

	blockID, ok := reqData["blockId"].(string)
	if !ok {
		return nil, fmt.Errorf("blockId required")
	}

	// Get block by ID
	block, err := node.Blockchain.GetBlockByID(blockID)
	if err != nil {
		return nil, fmt.Errorf("block not found: %v", err)
	}

	// Return transactions with additional metadata
	return map[string]interface{}{
		"blockId":          blockID,
		"transactionCount": len(block.Transactions),
		"transactions":     block.Transactions,
	}, nil
}

func (node *node.Node) handleRegisterValidator(params []interface{}) (interface{}, error) {
	// Check if params exist
	if len(params) < 1 {
		return nil, fmt.Errorf("parameters required")
	}

	// Extract parameters
	reqData, ok := params[0].(map[string]interface{})
	if !ok {
		return nil, fmt.Errorf("invalid request format")
	}

	// Extract required fields
	address, ok := reqData["address"].(string)
	if !ok {
		return nil, fmt.Errorf("address required")
	}

	publicKey, ok := reqData["publicKey"].(string)
	if !ok {
		return nil, fmt.Errorf("publicKey required")
	}

	// TO DO - Set the Stake amount for the validators

	// Verify the requester has sufficient stake
	// stake, err := node.Blockchain.GetStake(address)
	// if err != nil {
	//     return nil, fmt.Errorf("failed to retrieve stake: %v", err)
	// }

	// minStake := node.Blockchain.GetMinStakeForValidator()
	// if stake.Cmp(minStake) < 0 {
	//     return nil, fmt.Errorf("insufficient stake to become a validator")
	// }

	// Register the validator without bypassing stake check
	if err := node.Blockchain.RegisterValidator(address, publicKey, false); err != nil {
		return nil, fmt.Errorf("failed to register as validator: %v", err)
	}

	return map[string]interface{}{
		"message":   "Registered as validator successfully",
		"address":   address,
		"publicKey": publicKey,
		"status":    "active",
	}, nil
}

func (node *node.Node) handleGetStats(params []interface{}) (interface{}, error) {
	// Simply return the stats - no params needed for this endpoint
	stats := node.GetBlockchainStats()

	// No need to manually marshal to JSON as the JSON-RPC handler will handle that
	return stats, nil
}

// Handler for delegation to pool
func (node *node.Node) handlePoolDelegation(params []interface{}) (interface{}, error) {
	if len(params) < 1 {
		return nil, fmt.Errorf("parameters required")
	}

	reqData, ok := params[0].(map[string]interface{})
	if !ok {
		return nil, fmt.Errorf("invalid request format")
	}

	// Extract parameters
	delegator, ok := reqData["delegator"].(string)
	if !ok {
		return nil, fmt.Errorf("delegator address required")
	}

	amountFloat, ok := reqData["amount"].(float64)
	if !ok {
		return nil, fmt.Errorf("amount required")
	}
	amount := int64(amountFloat)

	// Process delegation
	_, err := node.stakingService.CreateStake(delegator, amount)
	if err != nil {
		return nil, fmt.Errorf("delegation failed: %v", err)
	}

	// Get updated pool stats
	poolStats := node.Blockchain.GetPoolStats()

	return map[string]interface{}{
		"status":    "success",
		"message":   "Successfully delegated to pool",
		"amount":    float64(amount) / 1e7,
		"delegator": delegator,
		"poolStats": poolStats,
		"timestamp": time.Now().Unix(),
	}, nil
}

// Handler for getting pool statistics
func (node *node.Node) handleGetPoolStats(params []interface{}) (interface{}, error) {
	poolStats := node.Blockchain.GetPoolStats()

	// Get active validators info
	validators := make([]map[string]interface{}, 0)
	for _, validatorAddr := range node.Blockchain.ActiveValidators {
		stake := node.Blockchain.Stakeholders[validatorAddr]
		validators = append(validators, map[string]interface{}{
			"address": validatorAddr,
			"stake":   float64(stake) / 1e7,
			"status":  "Active",
		})
	}

	return map[string]interface{}{
		"poolInfo": poolStats,
		"validators": map[string]interface{}{
			"active":   validators,
			"count":    len(validators),
			"minStake": float64(node.Blockchain.StakingService.pool.MinDelegation*40) / 1e7,
		},
		"delegatorInfo": map[string]interface{}{
			"minDelegation": float64(node.Blockchain.StakingService.pool.MinDelegation) / 1e7,
			"count":         len(node.Blockchain.StakingService.stakes),
		},
	}, nil
}

// Handler for getting delegator information
func (node *node.Node) handleGetDelegatorInfo(params []interface{}) (interface{}, error) {
	if len(params) < 1 {
		return nil, fmt.Errorf("address parameter required")
	}

	reqData, ok := params[0].(map[string]interface{})
	if !ok {
		return nil, fmt.Errorf("invalid request format")
	}

	delegator, ok := reqData["address"].(string)
	if !ok {
		return nil, fmt.Errorf("address required")
	}

	// Get delegator's stakes
	stake := node.Blockchain.StakingService.stakes[delegator]

	activeDelegations := make([]map[string]interface{}, 0)
	totalDelegated := int64(0)
	totalRewards := int64(0)

	if stake.IsActive {
		activeDelegations = append(activeDelegations, map[string]interface{}{
			"amount":         float64(stake.Amount) / 1e7,
			"startTime":      stake.StartTime,
			"lastRewardTime": node.stakingService.pool.LastRewardTime,
			"totalRewards":   float64(stake.TotalDelegationRewards+stake.TotalStakeRewards) / 1e7,
		})
	}

	// Calculate next reward time (24 hours after last reward)
	currentTime := time.Now().Unix()
	lastRewardTime := node.Blockchain.StakingService.pool.LastRewardTime
	nextRewardTime := lastRewardTime + (24 * 3600) // 24 hours in seconds

	// Calculate estimated daily reward
	dailyReward := node.Blockchain.StakingService.estimateStakeReward(stake.UserAddress, currentTime)

	return map[string]interface{}{
		"address": delegator,
		"delegations": map[string]interface{}{
			"active":         activeDelegations,
			"totalDelegated": float64(totalDelegated) / 1e7,
			"totalRewards":   float64(totalRewards) / 1e7,
		},
		"rewardInfo": map[string]interface{}{
			"nextRewardTime":       nextRewardTime,
			"timeUntilReward":      nextRewardTime - currentTime,
			"estimatedDailyReward": dailyReward / 1e7,
		},
	}, nil
}

// Handler for undelegation from pool
func (node *Node) handlePoolUndelegation(params []interface{}) (interface{}, error) {
	if len(params) < 1 {
		return nil, fmt.Errorf("parameters required")
	}

	reqData, ok := params[0].(map[string]interface{})
	if !ok {
		return nil, fmt.Errorf("invalid request format")
	}

	delegator, ok := reqData["delegator"].(string)
	if !ok {
		return nil, fmt.Errorf("delegator address required")
	}

	amountFloat, ok := reqData["amount"].(float64)
	if !ok {
		return nil, fmt.Errorf("amount required")
	}
	amount := int64(amountFloat)

	// Process undelegation
	if err := node.stakingService.unstakeTokensInternal(delegator, true, amount, time.Now().Unix()); err != nil {
		return nil, fmt.Errorf("undelegation failed: %v", err)
	}

	return map[string]interface{}{
		"status":    "success",
		"message":   "Successfully undelegated from pool",
		"amount":    float64(amount) / 1e7,
		"delegator": delegator,
		"timestamp": time.Now().Unix(),
	}, nil
}
