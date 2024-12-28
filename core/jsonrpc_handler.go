package core

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"strings"
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
	default:
		sendJSONRPCError(w, &JSONRPCError{
			Code:    -32601,
			Message: "Method not found",
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
