// jsonrpc.go

package core

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"strings"
)

// RPCRequest defines the structure of an incoming JSON-RPC request.
type RPCRequest struct {
	Jsonrpc string        `json:"jsonrpc"`
	Method  string        `json:"method"`
	Params  []interface{} `json:"params"`
	ID      int           `json:"id"`
}

// RPCResponse defines the structure of an outgoing JSON-RPC response.
type RPCResponse struct {
	Jsonrpc string      `json:"jsonrpc"`
	Result  interface{} `json:"result,omitempty"`
	Error   *RPCError   `json:"error,omitempty"`
	ID      int         `json:"id"`
}

// RPCError defines the structure of a JSON-RPC error response.
type RPCError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

type JSONRPCHandler struct {
	node *Node
}

// NewJSONRPCHandler creates a new handler for JSON-RPC requests.
func NewJSONRPCHandler(node *Node) *JSONRPCHandler {
	return &JSONRPCHandler{node: node}
}

func (h *JSONRPCHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	var req RPCRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid JSON-RPC request", http.StatusBadRequest)
		return
	}

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
		res = RPCResponse{
			Jsonrpc: "2.0",
			Error: &RPCError{
				Code:    -32601,
				Message: "Method not found",
			},
			ID: req.ID,
		}
	}

	resBytes, _ := json.Marshal(res)
	w.Header().Set("Content-Type", "application/json")
	w.Write(resBytes)
}

func (h *JSONRPCHandler) handleChainID(req RPCRequest) RPCResponse {
	// Return the chain ID as a hexadecimal string.
	return RPCResponse{
		Jsonrpc: "2.0",
		Result:  "0x1", // replace with your actual chain ID
		ID:      req.ID,
	}
}

func (h *JSONRPCHandler) handleBlockNumber(req RPCRequest) RPCResponse {
	// Return the latest block number.
	blockNumber := h.node.Blockchain.GetBlockCount()
	return RPCResponse{
		Jsonrpc: "2.0",
		Result:  fmt.Sprintf("0x%x", blockNumber),
		ID:      req.ID,
	}
}

func (h *JSONRPCHandler) handleGetBalance(req RPCRequest) RPCResponse {
	// Assume the address is the first parameter.
	address, _ := req.Params[0].(string)
	address = strings.ToLower(address)

	// Fetch the balance.
	balance, _ := h.node.Blockchain.GetBalance(address)
	return RPCResponse{
		Jsonrpc: "2.0",
		Result:  fmt.Sprintf("0x%x", balance),
		ID:      req.ID,
	}
}

func (h *JSONRPCHandler) handleGetTransactionCount(req RPCRequest) RPCResponse {
	// Assume the address is the first parameter.
	address, _ := req.Params[0].(string)
	address = strings.ToLower(address)

	// Fetch the transaction count (nonce).
	nonce := h.node.Blockchain.GetTransactionCount(address)
	return RPCResponse{
		Jsonrpc: "2.0",
		Result:  fmt.Sprintf("0x%x", nonce),
		ID:      req.ID,
	}
}

func (h *JSONRPCHandler) handleSendTransaction(req RPCRequest) RPCResponse {
	// Assume the transaction object is the first parameter.
	txMap, _ := req.Params[0].(map[string]interface{})

	from, _ := txMap["from"].(string)
	to, _ := txMap["to"].(string)
	valueHex, _ := txMap["value"].(string)
	gasHex, _ := txMap["gas"].(string)

	value, _ := strconv.ParseInt(valueHex, 0, 64)
	gas, _ := strconv.ParseInt(gasHex, 0, 64)

	// Create and send the transaction.
	txID, err := h.node.CreateAndBroadcastTransaction(to, nil, int(value), nil, nil)
	if err != nil {
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
		Result:  fmt.Sprintf("0x%x", txID),
		ID:      req.ID,
	}
}
