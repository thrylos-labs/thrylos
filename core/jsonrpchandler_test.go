package core

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"reflect"
	"testing"
)

// Mock your node and blockchain responses here
type MockNode struct {
	// Implement necessary fields
	balance      map[string]int64
	blockNumber  int64
	transactions []string // to track transactions broadcast
	accounts     []string
}

func (m *MockNode) CreateAndBroadcastTransaction(to string, from *string, value int, data *[]byte, gas *int) error {
	// This is a mock function, so we'll simulate transaction creation and broadcasting.
	// Let's assume that we are just logging the transaction details.

	// Simulate checking for a valid 'to' address and sufficient balance
	if _, exists := m.balance[to]; !exists {
		return errors.New("recipient address does not exist")
	}

	// Optionally check 'from' if it's not nil and if insufficient funds etc.
	if from != nil {
		if balance, exists := m.balance[*from]; !exists || balance < int64(value) {
			return errors.New("insufficient funds for the transaction")
		}
		// Deduct the amount from sender's balance
		m.balance[*from] -= int64(value)
	}

	// Credit the amount to recipient's balance
	m.balance[to] += int64(value)

	// Log or store the transaction details
	transactionDetails := fmt.Sprintf("Transaction from %v to %v of value %d", from, to, value)
	m.transactions = append(m.transactions, transactionDetails)

	return nil
}

// GetBalance simulates retrieving the balance of an address.
func (m *MockNode) GetBalance(address string) (int64, error) {
	if balance, exists := m.balance[address]; exists {
		return balance, nil
	}
	return 0, fmt.Errorf("Failed to get balance")
}

func (m *MockNode) GetBlockCount() int {
	// Return a static block count or a configurable field
	return int(m.blockNumber) // Assuming blockNumber is an int64 and needs to be converted
}

// Constructor for MockNode
func NewMockNode() *MockNode {
	return &MockNode{
		balance: map[string]int64{
			"0x123": 1000,
			"0x456": 0,
		},
		blockNumber: 1024,
		accounts:    []string{"0x123", "0x456"},
	}
}

// Implement GetTransactionReceipt method
func (node *MockNode) GetTransactionReceipt(txHash string) (map[string]interface{}, error) {
	// Return a mock receipt
	return map[string]interface{}{
		"transactionHash":   txHash,
		"transactionIndex":  1,
		"blockHash":         "0xabc",
		"blockNumber":       node.blockNumber,
		"cumulativeGasUsed": 21000,
		"gasUsed":           21000,
		"contractAddress":   nil,
		"logs":              []interface{}{},
		"status":            "1",
	}, nil
}

// Implement EstimateGas method
// Implement EstimateGas method
func (node *MockNode) EstimateGas(tx map[string]interface{}) (uint64, error) {
	// Basic gas cost for a simple transfer
	baseGas := uint64(21000)

	// Check if there is data in the transaction to simulate complexity
	if data, exists := tx["data"]; exists && data != nil {
		// Simulate additional gas for transactions involving data (e.g., contract interactions)
		dataString, ok := data.(string)
		if !ok {
			return 0, fmt.Errorf("invalid data format")
		}

		// Calculate additional gas assuming 10 gas per byte of data
		additionalGas := uint64(len(dataString) * 10)

		// Return the sum of base gas and additional gas
		return baseGas + additionalGas, nil
	}

	// If no additional data, return the base gas cost
	return baseGas, nil
}

// Implement CallContract method
func (node *MockNode) CallContract(tx map[string]interface{}) (string, error) {
	// Return a mock contract call result
	return "0x", nil
}

// Implement GetAccounts method
func (node *MockNode) GetAccounts() ([]string, error) {
	return node.accounts, nil
}

func TestHandleChainID(t *testing.T) {
	node := NewMockNode()
	handler := NewJSONRPCHandler(node)

	reqBody, err := json.Marshal(RPCRequest{
		Jsonrpc: "2.0",
		Method:  "eth_chainId",
		ID:      1,
	})
	if err != nil {
		t.Fatalf("Failed to marshal request: %v", err)
	}

	req := httptest.NewRequest("POST", "/jsonrpc", bytes.NewBuffer(reqBody))
	resp := httptest.NewRecorder()
	handler.ServeHTTP(resp, req)

	var got RPCResponse
	if err := json.Unmarshal(resp.Body.Bytes(), &got); err != nil {
		t.Fatalf("Failed to unmarshal response: %v. Response body: %s", err, resp.Body.String())
	}

	// Define the expected response
	want := RPCResponse{
		Jsonrpc: "2.0",
		Result:  "0x539",
		ID:      1,
	}

	// Perform field-by-field comparison
	if got.Jsonrpc != want.Jsonrpc || got.Result != want.Result || got.ID != want.ID {
		t.Errorf("ServeHTTP() = %#v, want %#v", got, want)
	}

	// Check if there was an error object and if it matched
	if (got.Error != nil && want.Error != nil && *got.Error != *want.Error) || (got.Error != nil && want.Error == nil) || (got.Error == nil && want.Error != nil) {
		t.Errorf("ServeHTTP() error = %#v, want %#v", got.Error, want.Error)
	}
}

func TestHandleGetBalance(t *testing.T) {
	node := NewMockNode()
	handler := NewJSONRPCHandler(node)
	tests := []struct {
		name    string
		address string
		want    RPCResponse
		reqID   interface{} // Use interface{} for ID to match the RPCRequest definition
	}{
		{"Valid Address with Balance", "0x123", RPCResponse{"2.0", "0x3e8", nil, 1}, 1},
		{"Valid Address Zero Balance", "0x456", RPCResponse{"2.0", "0x0", nil, 1}, 1},
		{"Invalid Address", "0x000", RPCResponse{"2.0", nil, &RPCError{-32000, "Failed to get balance"}, 1}, 1},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := RPCRequest{
				Jsonrpc: "2.0",
				Method:  "eth_getBalance",
				Params:  []interface{}{tt.address},
				ID:      tt.reqID,
			}
			got := handler.handleGetBalance(req)
			if got.Jsonrpc != tt.want.Jsonrpc || fmt.Sprintf("%v", got.ID) != fmt.Sprintf("%v", tt.want.ID) || fmt.Sprintf("%v", got.Result) != fmt.Sprintf("%v", tt.want.Result) {
				t.Errorf("handleGetBalance() = %v, want %v", got, tt.want)
			}
			if got.Error != nil && tt.want.Error != nil {
				if got.Error.Code != tt.want.Error.Code || got.Error.Message != tt.want.Error.Message {
					t.Errorf("handleGetBalance() error = %v, want %v", got.Error, tt.want.Error)
				}
			} else if (got.Error != nil && tt.want.Error == nil) || (got.Error == nil && tt.want.Error != nil) {
				t.Errorf("handleGetBalance() error = %v, want %v", got.Error, tt.want.Error)
			}
		})
	}
}

func TestHandleInvalidID(t *testing.T) {
	node := NewMockNode()
	handler := NewJSONRPCHandler(node)

	// Simulate a JSON-RPC request with an invalid ID
	reqBody, err := json.Marshal(RPCRequest{
		Jsonrpc: "2.0",
		Method:  "eth_chainId",
		ID:      "invalid", // non-integer ID
	})
	if err != nil {
		t.Fatalf("Failed to marshal request: %v", err)
	}

	req := httptest.NewRequest("POST", "/jsonrpc", bytes.NewBuffer(reqBody))
	resp := httptest.NewRecorder()
	handler.ServeHTTP(resp, req)

	// Check response status code for the correct error handling
	if status := resp.Code; status != http.StatusBadRequest {
		t.Errorf("Handler returned wrong status code: got %v want %v", status, http.StatusBadRequest)
	}

	var got RPCResponse
	if err := json.Unmarshal(resp.Body.Bytes(), &got); err != nil {
		t.Fatalf("Failed to unmarshal response: %v. Response body: %s", err, resp.Body.String())
	}

	want := RPCResponse{
		Jsonrpc: "2.0",
		Error:   &RPCError{-32600, "Invalid ID format"},
		ID:      0,
	}

	// Use reflect.DeepEqual to compare expected and actual response
	if !reflect.DeepEqual(got, want) {
		t.Errorf("ServeHTTP() with invalid ID format = %v, want %v", got, want)
	}
}

func TestHandleSendTransaction(t *testing.T) {
	node := NewMockNode()
	handler := NewJSONRPCHandler(node)
	txParams := map[string]interface{}{
		"from":  "0x123",
		"to":    "0x456",
		"value": "0x1", // smallest unit of your crypto
	}
	req := RPCRequest{
		Jsonrpc: "2.0",
		Method:  "eth_sendTransaction",
		Params:  []interface{}{txParams},
		ID:      1,
	}

	got := handler.handleSendTransaction(req) // Corrected call here
	want := RPCResponse{
		Jsonrpc: "2.0",
		Result:  "0x1", // Assuming '0x1' indicates success
		ID:      1,
	}

	if !reflect.DeepEqual(got, want) {
		t.Errorf("handleSendTransaction() = %v, want %v", got, want)
	}
}
