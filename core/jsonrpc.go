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
	GetBlockCount() int // Ensure this matches the return type of your method implementations
	CreateAndBroadcastTransaction(to string, from *string, value int, data *[]byte, gas *int) error
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

	// Default ID value to 0
	id := 0
	var response RPCResponse

	// Determine the appropriate ID based on its type
	switch v := req.ID.(type) {
	case string:
		parsedID, err := strconv.Atoi(v)
		if err != nil {
			log.Printf("Invalid ID format: %v", err)
			response = RPCResponse{
				Jsonrpc: "2.0",
				Error:   &RPCError{-32600, "Invalid ID format"},
				ID:      0, // Set to zero because the ID was invalid
			}
			respBytes, _ := json.Marshal(response)
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusBadRequest)
			w.Write(respBytes)
			return
		}
		id = parsedID
	case float64:
		id = int(v)
	case int:
		id = v
	default:
		log.Printf("Unsupported ID type: %T", req.ID)
		response = RPCResponse{
			Jsonrpc: "2.0",
			Error:   &RPCError{-32600, "Unsupported ID type"},
			ID:      0,
		}
		respBytes, _ := json.Marshal(response)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		w.Write(respBytes)
		return
	}

	// Handle the request based on the method
	response = handleRPCRequest(req, id)

	log.Printf("Sending JSON-RPC response: %v", response)
	respBytes, _ := json.Marshal(response)
	w.Header().Set("Content-Type", "application/json")
	w.Write(respBytes)
}

func handleRPCRequest(req RPCRequest, id int) RPCResponse {
	// Handle specific methods here
	switch req.Method {
	case "eth_chainId":
		return RPCResponse{
			Jsonrpc: "2.0",
			Result:  localChainID,
			ID:      id,
		}
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
	// Perform type assertion to convert req.ID to an int
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
					Code:    -32600, // Standard JSON-RPC error code for invalid request
					Message: "Invalid ID format",
				},
				ID: 0, // Set to zero or some default value to indicate error
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

	// Extract transaction parameters from the request
	txMap, _ := req.Params[0].(map[string]interface{})

	// Ensure the transaction has a valid recipient
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

	// Convert the value to int64
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

	// Parse the hex value
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

	// Attempt to create and broadcast the transaction
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
		Result:  "0x1", // Success indicator
		ID:      id,
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
