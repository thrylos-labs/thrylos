package core

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"strconv"
)

const localChainID = "0x539" // Local development network chain ID (1337 in decimal)

type RPCRequest struct {
	Jsonrpc string        `json:"jsonrpc"`
	Method  string        `json:"method"`
	Params  []interface{} `json:"params"`
	ID      interface{}   `json:"id"` // Now accepts any type
}

type RPCResponse struct {
	Jsonrpc string      `json:"jsonrpc"`
	Result  interface{} `json:"result,omitempty"`
	Error   *RPCError   `json:"error,omitempty"`
	ID      interface{} `json:"id"` // Now matches the type in RPCRequest
}

type RPCError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

type BlockchainNode interface {
	GetBalance(address string) (int64, error)
	GetBlockCount() int
	CreateAndBroadcastTransaction(to string, from *string, value int, data *[]byte, gas *int) error
	GetTransactionReceipt(txHash string) (map[string]interface{}, error)
	EstimateGas(tx map[string]interface{}) (uint64, error)
	CallContract(tx map[string]interface{}) (string, error)
	GetAccounts() ([]string, error)
}

type JSONRPCHandler struct {
	node BlockchainNode
}

func NewJSONRPCHandler(node BlockchainNode) *JSONRPCHandler {
	return &JSONRPCHandler{node: node}
}

func (h *JSONRPCHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	var req RPCRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		log.Printf("Error decoding JSON-RPC request: %v", err)
		http.Error(w, `{"jsonrpc": "2.0", "error": {"code": -32700, "message": "Parse error"}, "id": null}`, http.StatusBadRequest)
		return
	}

	log.Printf("Received JSON-RPC request: %v", req)

	// Validate ID type; only integer and string types are valid
	switch req.ID.(type) {
	case string:
		if _, err := strconv.Atoi(req.ID.(string)); err != nil {
			sendError(w, -32600, "Invalid ID format", nil)
			return
		}
	case float64, int, int64: // JSON numbers are decoded into float64 by default in Go
	default:
		sendError(w, -32600, "Invalid ID type", nil)
		return
	}

	response := h.handleRPCRequest(req, req.ID)

	log.Printf("Sending JSON-RPC response: %v", response)
	respBytes, _ := json.Marshal(response)
	w.Header().Set("Content-Type", "application/json")
	w.Write(respBytes)
}

func sendError(w http.ResponseWriter, code int, msg string, id interface{}) {
	errorResponse := RPCResponse{
		Jsonrpc: "2.0",
		Error: &RPCError{
			Code:    code,
			Message: msg,
		},
		ID: id,
	}
	respBytes, _ := json.Marshal(errorResponse)
	w.Header().Set("Content-Type", "application/json")
	http.Error(w, string(respBytes), http.StatusBadRequest)
}

func (h *JSONRPCHandler) handleRPCRequest(req RPCRequest, id interface{}) RPCResponse {
	switch req.Method {
	case "eth_chainId":
		return RPCResponse{
			Jsonrpc: "2.0",
			Result:  localChainID,
			ID:      id,
		}
	case "eth_blockNumber":
		return h.handleBlockNumber(req)
	case "eth_getBalance":
		return h.handleGetBalance(req)
	case "eth_sendTransaction":
		return h.handleSendTransaction(req)
	case "eth_getTransactionReceipt":
		return h.handleGetTransactionReceipt(req)
	case "eth_estimateGas":
		return h.handleEstimateGas(req)
	case "eth_call":
		return h.handleCall(req)
	case "eth_accounts":
		return h.handleAccounts(req)
	case "net_version":
		return h.handleNetVersion(req)
	default:
		return RPCResponse{
			Jsonrpc: "2.0",
			Error:   &RPCError{-32601, "Method not found"},
			ID:      id,
		}
	}
}

func (h *JSONRPCHandler) handleBlockNumber(req RPCRequest) RPCResponse {
	blockNumber := h.node.GetBlockCount()
	return RPCResponse{
		Jsonrpc: "2.0",
		Result:  fmt.Sprintf("0x%x", blockNumber),
		ID:      req.ID,
	}
}

func (h *JSONRPCHandler) handleGetBalance(req RPCRequest) RPCResponse {
	address, ok := req.Params[0].(string)
	if !ok {
		return RPCResponse{
			Jsonrpc: "2.0",
			Error: &RPCError{
				Code:    -32602,
				Message: "Invalid params",
			},
			ID: req.ID,
		}
	}

	balance, err := h.node.GetBalance(address)
	if err != nil {
		return RPCResponse{
			Jsonrpc: "2.0",
			Error: &RPCError{
				Code:    -32000,
				Message: err.Error(),
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

func (h *JSONRPCHandler) handleSendTransaction(req RPCRequest) RPCResponse {
	var id int
	switch v := req.ID.(type) {
	case string:
		if parsedID, err := strconv.Atoi(v); err == nil {
			id = parsedID
		} else {
			log.Printf("Invalid ID format: %v", err)
			return RPCResponse{
				Jsonrpc: "2.0",
				Error: &RPCError{
					Code:    -32600,
					Message: "Invalid ID format",
				},
				ID: 0,
			}
		}
	case float64:
		id = int(v)
	case int:
		id = v
	default:
		log.Printf("Unsupported ID type: %T", req.ID)
		return RPCResponse{
			Jsonrpc: "2.0",
			Error: &RPCError{
				Code:    -32600,
				Message: "Unsupported ID type",
			},
			ID: 0,
		}
	}

	txMap, _ := req.Params[0].(map[string]interface{})

	to, ok := txMap["to"].(string)
	if !ok {
		return RPCResponse{
			Jsonrpc: "2.0",
			Error: &RPCError{
				Code:    -32000,
				Message: "Missing or invalid 'to' field",
			},
			ID: id,
		}
	}

	valueHex, ok := txMap["value"].(string)
	if !ok {
		return RPCResponse{
			Jsonrpc: "2.0",
			Error: &RPCError{
				Code:    -32000,
				Message: "Missing or invalid 'value' field",
			},
			ID: id,
		}
	}

	value, err := strconv.ParseInt(valueHex, 0, 64)
	if err != nil {
		return RPCResponse{
			Jsonrpc: "2.0",
			Error: &RPCError{
				Code:    -32000,
				Message: "Invalid value format",
			},
			ID: id,
		}
	}

	err = h.node.CreateAndBroadcastTransaction(to, nil, int(value), nil, nil)
	if err != nil {
		log.Printf("Transaction creation failed: %v", err)
		return RPCResponse{
			Jsonrpc: "2.0",
			Error: &RPCError{
				Code:    -32000,
				Message: "Transaction creation failed",
			},
			ID: id,
		}
	}

	return RPCResponse{
		Jsonrpc: "2.0",
		Result:  "0x1",
		ID:      id,
	}
}

func (h *JSONRPCHandler) handleGetTransactionReceipt(req RPCRequest) RPCResponse {
	txHash, ok := req.Params[0].(string)
	if !ok {
		return RPCResponse{
			Jsonrpc: "2.0",
			Error: &RPCError{
				Code:    -32602,
				Message: "Invalid params",
			},
			ID: req.ID,
		}
	}

	receipt, err := h.node.GetTransactionReceipt(txHash)
	if err != nil {
		return RPCResponse{
			Jsonrpc: "2.0",
			Error: &RPCError{
				Code:    -32000,
				Message: err.Error(),
			},
			ID: req.ID,
		}
	}

	return RPCResponse{
		Jsonrpc: "2.0",
		Result:  receipt,
		ID:      req.ID,
	}
}

func (h *JSONRPCHandler) handleEstimateGas(req RPCRequest) RPCResponse {
	txMap, ok := req.Params[0].(map[string]interface{})
	if !ok {
		return RPCResponse{
			Jsonrpc: "2.0",
			Error: &RPCError{
				Code:    -32602,
				Message: "Invalid params",
			},
			ID: req.ID,
		}
	}

	gas, err := h.node.EstimateGas(txMap)
	if err != nil {
		return RPCResponse{
			Jsonrpc: "2.0",
			Error: &RPCError{
				Code:    -32000,
				Message: err.Error(),
			},
			ID: req.ID,
		}
	}

	return RPCResponse{
		Jsonrpc: "2.0",
		Result:  fmt.Sprintf("0x%x", gas),
		ID:      req.ID,
	}
}

func (h *JSONRPCHandler) handleCall(req RPCRequest) RPCResponse {
	txMap, ok := req.Params[0].(map[string]interface{})
	if !ok {
		return RPCResponse{
			Jsonrpc: "2.0",
			Error: &RPCError{
				Code:    -32602,
				Message: "Invalid params",
			},
			ID: req.ID,
		}
	}

	result, err := h.node.CallContract(txMap)
	if err != nil {
		return RPCResponse{
			Jsonrpc: "2.0",
			Error: &RPCError{
				Code:    -32000,
				Message: err.Error(),
			},
			ID: req.ID,
		}
	}

	return RPCResponse{
		Jsonrpc: "2.0",
		Result:  result,
		ID:      req.ID,
	}
}

func (h *JSONRPCHandler) handleAccounts(req RPCRequest) RPCResponse {
	accounts, err := h.node.GetAccounts()
	if err != nil {
		return RPCResponse{
			Jsonrpc: "2.0",
			Error: &RPCError{
				Code:    -32000,
				Message: err.Error(),
			},
			ID: req.ID,
		}
	}

	return RPCResponse{
		Jsonrpc: "2.0",
		Result:  accounts,
		ID:      req.ID,
	}
}

func (h *JSONRPCHandler) handleNetVersion(req RPCRequest) RPCResponse {
	networkID := "1" // Example network ID, change as necessary
	return RPCResponse{
		Jsonrpc: "2.0",
		Result:  networkID,
		ID:      req.ID,
	}
}
