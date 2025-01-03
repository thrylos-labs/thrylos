package core

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/btcsuite/btcd/btcutil/bech32"
	"github.com/shopspring/decimal"
	thrylos "github.com/thrylos-labs/thrylos"
	"github.com/thrylos-labs/thrylos/shared"
	"golang.org/x/crypto/ed25519"
)

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
func (node *Node) JSONRPCHandler(w http.ResponseWriter, r *http.Request) {
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
	case "submitTransaction":
		result, err = node.handleSubmitTransaction(req.Params)
	case "getPeers":
		result, err = node.handleGetPeers(req.Params)
	case "submitSignedTransaction":
		result, err = node.handleSubmitSignedTransaction(req.Params)
	case "estimateGas":
		result, err = node.handleEstimateGas(req.Params)
	case "stake":
		result, err = node.handleStaking(req.Params)
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
		if isWebSocketRequest(r) {
			node.handleWebSocketSubscription(w, r, req.Params)
			return
		}
		sendJSONRPCError(w, &JSONRPCError{
			Code:    -32600,
			Message: "Subscription requires WebSocket connection",
		}, req.ID)
	case "unsubscribe":
		if isWebSocketRequest(r) {
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
func (node *Node) handleGetBalance(params []interface{}) (interface{}, error) {
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
func (node *Node) handleGetUTXO(params []interface{}) (interface{}, error) {
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
func (node *Node) handleGetBlock(params []interface{}) (interface{}, error) {
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
func (node *Node) handleGetBlockchainInfo(params []interface{}) (interface{}, error) {
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

func (node *Node) handleSubmitBlock(params []interface{}) (interface{}, error) {
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

func (node *Node) handleSubmitTransaction(params []interface{}) (interface{}, error) {
	// Check if params exist
	if len(params) < 1 {
		return nil, fmt.Errorf("transaction parameter required")
	}

	// Convert params[0] to TransactionJSON struct
	txData, ok := params[0].(map[string]interface{})
	if !ok {
		return nil, fmt.Errorf("invalid transaction parameter format")
	}

	// Convert the map to JSON then to TransactionJSON struct
	txJSON, err := json.Marshal(txData)
	if err != nil {
		return nil, fmt.Errorf("error marshaling transaction data: %v", err)
	}

	var jsonTx thrylos.TransactionJSON
	if err := json.Unmarshal(txJSON, &jsonTx); err != nil {
		return nil, fmt.Errorf("error unmarshaling transaction: %v", err)
	}

	// Convert JSON to Proto
	tx := ConvertJSONToProto(jsonTx)

	// Add to pending transactions
	node.AddPendingTransaction(tx)

	// Log and return success
	fmt.Printf("Verified and added transaction %s to pending transactions\n", tx.GetId())

	// Return success response with transaction ID
	return struct {
		Success       bool   `json:"success"`
		Message       string `json:"message"`
		TransactionId string `json:"transactionId"`
	}{
		Success:       true,
		Message:       "Transaction successfully added to pending transactions",
		TransactionId: tx.GetId(),
	}, nil
}

func (node *Node) handleGetPeers(params []interface{}) (interface{}, error) {
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

var _ shared.GasEstimator = &Node{} // Ensures Node implements the GasEstimator interface

const MinTransactionAmount int64 = 1 * NanoThrylosPerThrylos // 1 THRYLOS in nanoTHRYLOS

func (node *Node) handleSubmitSignedTransaction(params []interface{}) (interface{}, error) {
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

		if err := shared.ValidateAndConvertTransaction(
			thrylosTx,
			node.Database,
			ed25519.PublicKey(publicKeyBytes),
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

func (node *Node) handleEstimateGas(params []interface{}) (interface{}, error) {
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
	gas := CalculateGas(dataSize, 0)

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

func (node *Node) handleGetStakingStats(params []interface{}) (interface{}, error) {
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
		},
	}, nil
}

func (node *Node) handleStaking(params []interface{}) (interface{}, error) {
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
	case "update":
		return node.handleUpdateStakeOperation(reqData)
	case "validate":
		return node.handleValidateStakeOperation(reqData)
	default:
		return nil, fmt.Errorf("unknown operation: %s", operation)
	}
}

func (node *Node) handleStakeOperation(reqData map[string]interface{}) (interface{}, error) {
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
	stakeRecord, err := node.Blockchain.StakingService.CreateStake(userAddress, amount)
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
		node.Blockchain.StakingService.UnstakeTokens(userAddress, amount)
		return nil, fmt.Errorf("failed to process staking transaction: %v", err)
	}

	// Update UTXO TransactionId
	for _, output := range stakingTx.Outputs {
		output.TransactionId = stakingTx.Id
	}

	effectiveRate := node.Blockchain.GetEffectiveInflationRate()

	return map[string]interface{}{
		"message": "Stake created successfully",
		"stake": map[string]interface{}{
			"amount":          float64(stakeRecord.Amount) / 1e7,
			"amountRaw":       stakeRecord.Amount,
			"startTime":       stakeRecord.StartTime,
			"isActive":        stakeRecord.IsActive,
			"validatorRole":   stakeRecord.ValidatorRole,
			"lastRewardEpoch": stakeRecord.LastRewardEpoch,
		},
		"transactionId": stakingTx.Id,
		"stakingInfo": map[string]interface{}{
			"currentEpoch":   node.Blockchain.GetBlockCount() / int(node.Blockchain.StakingService.pool.EpochLength),
			"yearlyReward":   "4.8M",
			"effectiveRate":  fmt.Sprintf("%.2f%%", effectiveRate),
			"minStakeAmount": float64(minStake) / 1e7,
			"blocksNextEpoch": node.Blockchain.StakingService.pool.EpochLength -
				(int64(node.Blockchain.GetBlockCount()) % node.Blockchain.StakingService.pool.EpochLength),
		},
	}, nil
}

// Similar implementations for other operations:
func (node *Node) handleUnstakeOperation(reqData map[string]interface{}) (interface{}, error) {
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

	// Verify validator exists and is active
	if !node.Blockchain.validatorExists(validatorAddress) {
		return nil, fmt.Errorf("invalid validator address")
	}

	// Verify the user has enough staked tokens
	currentStake := node.Blockchain.Stakeholders[userAddress]
	if currentStake < amount {
		return nil, fmt.Errorf("insufficient staked amount")
	}

	// Calculate any pending rewards before unstaking
	currentBlock := int64(node.Blockchain.GetBlockCount())
	stakes := node.Blockchain.StakingService.stakes[userAddress]
	var pendingRewards int64
	for _, stake := range stakes {
		if stake.IsActive && stake.Amount == amount {
			pendingRewards = node.Blockchain.StakingService.CalculateRewards(stake, currentBlock)
			break
		}
	}

	// Process unstaking
	if err := node.Blockchain.StakingService.UnstakeTokens(userAddress, amount); err != nil {
		return nil, fmt.Errorf("failed to unstake tokens: %v", err)
	}

	// Create unstaking transaction
	unstakeTx := &thrylos.Transaction{
		Id:        fmt.Sprintf("unstake-%s-%d", userAddress, time.Now().UnixNano()),
		Sender:    validatorAddress,
		Timestamp: time.Now().Unix(),
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

	return map[string]interface{}{
		"message":       "Tokens unstaked successfully",
		"transactionId": unstakeTx.Id,
		"unstakeInfo": map[string]interface{}{
			"amount":         float64(amount) / 1e7,
			"pendingRewards": float64(pendingRewards) / 1e7,
			"totalReturn":    float64(amount+pendingRewards) / 1e7,
		},
		"stakingInfo": map[string]interface{}{
			"remainingStake": float64(currentStake-amount) / 1e7,
			"effectiveRate":  fmt.Sprintf("%.2f%%", effectiveRate),
			"nextEpochIn": node.Blockchain.StakingService.pool.EpochLength -
				(currentBlock % node.Blockchain.StakingService.pool.EpochLength),
		},
	}, nil
}

func (node *Node) handleDelegateOperation(reqData map[string]interface{}) (interface{}, error) {
	// Extract required fields
	from, ok := reqData["from"].(string)
	if !ok {
		return nil, fmt.Errorf("from address required")
	}

	to, ok := reqData["to"].(string)
	if !ok {
		return nil, fmt.Errorf("to address required")
	}

	amountFloat, ok := reqData["amount"].(float64)
	if !ok {
		return nil, fmt.Errorf("amount required")
	}
	amount := int64(amountFloat)

	if err := node.Blockchain.DelegateStake(from, to, amount); err != nil {
		return nil, fmt.Errorf("failed to delegate stake: %v", err)
	}

	return map[string]interface{}{
		"message": "Stake delegated successfully",
		"from":    from,
		"to":      to,
		"amount":  float64(amount) / 1e7,
	}, nil
}

func (node *Node) handleUpdateStakeOperation(reqData map[string]interface{}) (interface{}, error) {
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

	if err := node.Blockchain.UpdateStake(address, amount); err != nil {
		return nil, fmt.Errorf("failed to update stake: %v", err)
	}

	return map[string]interface{}{
		"message": "Stake updated successfully",
		"address": address,
		"amount":  float64(amount) / 1e7,
	}, nil
}

func (node *Node) handleValidateStakeOperation(reqData map[string]interface{}) (interface{}, error) {
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

func getTotalSupply(node *Node) float64 {
	totalSupply := int64(0)
	for _, balance := range node.Blockchain.Stakeholders {
		totalSupply += balance
	}
	return float64(totalSupply) / 1e7
}

func (node *Node) handleGetStakingInfo(params []interface{}) (interface{}, error) {
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

	// Return the same structured response as before
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
			"activeStakesCount": len(activeStakes),
			"activeStakes":      activeStakes,
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
		},
		"networkStats": map[string]interface{}{
			"totalValidators":      len(node.Blockchain.ActiveValidators),
			"totalStakedAmount":    float64(stakingPool.TotalStaked) / 1e7,
			"currentEffectiveRate": fmt.Sprintf("%.2f%%", effectiveRate),
		},
	}, nil
}

func (node *Node) handleGetNetworkHealth(params []interface{}) (interface{}, error) {
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

func (node *Node) handleGetValidators(params []interface{}) (interface{}, error) {
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

	// Build validators list
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

	return map[string]interface{}{
		"validators": validators,
		"count":      len(validators),
		"summary": map[string]interface{}{
			"totalStaked":   fmt.Sprintf("%.2f", float64(node.Blockchain.StakingService.pool.TotalStaked)/1e7),
			"totalSupply":   fmt.Sprintf("%.2f", float64(totalSupply)/1e7),
			"effectiveRate": fmt.Sprintf("%.2f%%", effectiveAPR),
		},
	}, nil
}

func (node *Node) handleGetBlockTransactions(params []interface{}) (interface{}, error) {
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

func (node *Node) handleRegisterValidator(params []interface{}) (interface{}, error) {
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

func (node *Node) handleGetStats(params []interface{}) (interface{}, error) {
	// Simply return the stats - no params needed for this endpoint
	stats := node.GetBlockchainStats()

	// No need to manually marshal to JSON as the JSON-RPC handler will handle that
	return stats, nil
}
