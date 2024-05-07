package core

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"strconv"
	"strings"
)

const localChainID = "0x539" // Local development network chain ID (1337 in decimal)

type RPCRequest struct {
	Jsonrpc string        `json:"jsonrpc"`
	Method  string        `json:"method"`
	Params  []interface{} `json:"params"`
	ID      int           `json:"id"`
}

type RPCResponse struct {
	Jsonrpc string      `json:"jsonrpc"`
	Result  interface{} `json:"result,omitempty"`
	Error   *RPCError   `json:"error,omitempty"`
	ID      int         `json:"id"`
}

type RPCError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

type JSONRPCHandler struct {
	node *Node
}

func NewJSONRPCHandler(node *Node) *JSONRPCHandler {
	return &JSONRPCHandler{node: node}
}

func (h *JSONRPCHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	var req RPCRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid JSON-RPC request", http.StatusBadRequest)
		log.Printf("Error decoding JSON-RPC request: %v", err)
		return
	}

	log.Printf("Received JSON-RPC request: %v", req)

	var res RPCResponse
	switch req.Method {
	case "eth_chainId":
		res = h.handleChainID(req)
	case "eth_blockNumber":
		res = h.handleBlockNumber(req)
	case "eth_getBalance":
		res = h.handleGetBalance(req)
	case "eth_getTransactionCount":
		res = h.handleGetTransactionCount(req)
	case "eth_sendTransaction":
		res = h.handleSendTransaction(req)
	default:
		log.Printf("Method not found: %s", req.Method)
		res = RPCResponse{
			Jsonrpc: "2.0",
			Error: &RPCError{
				Code:    -32601,
				Message: "Method not found",
			},
			ID: req.ID,
		}
	}

	log.Printf("Sending JSON-RPC response: %v", res)

	resBytes, _ := json.Marshal(res)
	w.Header().Set("Content-Type", "application/json")
	w.Write(resBytes)
}

func (h *JSONRPCHandler) handleChainID(req RPCRequest) RPCResponse {
	return RPCResponse{
		Jsonrpc: "2.0",
		Result:  localChainID, // Local development network chain ID (1337 in decimal)
		ID:      req.ID,
	}
}

func (h *JSONRPCHandler) handleBlockNumber(req RPCRequest) RPCResponse {
	blockNumber := h.node.Blockchain.GetBlockCount()
	return RPCResponse{
		Jsonrpc: "2.0",
		Result:  fmt.Sprintf("0x%x", blockNumber),
		ID:      req.ID,
	}
}

func (h *JSONRPCHandler) handleGetBalance(req RPCRequest) RPCResponse {
	address, _ := req.Params[0].(string)
	address = strings.ToLower(address)

	balance, err := h.node.Blockchain.GetBalance(address)
	if err != nil {
		log.Printf("Error getting balance for address %s: %v", address, err)
		return RPCResponse{
			Jsonrpc: "2.0",
			Error: &RPCError{
				Code:    -32000,
				Message: "Failed to get balance",
			},
			ID: req.ID,
		}
	}

	return RPCResponse{
		Jsonrpc: "2.0",
		Result:  fmt.Sprintf("0x%x", balance),
		ID:      req.ID,
	}
}

func (h *JSONRPCHandler) handleGetTransactionCount(req RPCRequest) RPCResponse {
	address, _ := req.Params[0].(string)
	address = strings.ToLower(address)

	nonce := h.node.Blockchain.GetTransactionCount(address)
	return RPCResponse{
		Jsonrpc: "2.0",
		Result:  fmt.Sprintf("0x%x", nonce),
		ID:      req.ID,
	}
}

func (h *JSONRPCHandler) handleSendTransaction(req RPCRequest) RPCResponse {
	txMap, _ := req.Params[0].(map[string]interface{})

	to, _ := txMap["to"].(string)
	valueHex, _ := txMap["value"].(string)

	value, _ := strconv.ParseInt(valueHex, 0, 64)

	err := h.node.CreateAndBroadcastTransaction(to, nil, int(value), nil, nil)
	if err != nil {
		log.Printf("Transaction creation failed: %v", err)
		return RPCResponse{
			Jsonrpc: "2.0",
			Error: &RPCError{
				Code:    -32000,
				Message: "Transaction creation failed",
			},
			ID: req.ID,
		}
	}

	return RPCResponse{
		Jsonrpc: "2.0",
		Result:  "0x1", // Dummy value indicating success
		ID:      req.ID,
	}
}
