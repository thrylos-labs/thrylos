package core

import (
	"bytes"
	"crypto/ed25519"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/mock"
	"github.com/thrylos-labs/thrylos/mocks"
	"github.com/thrylos-labs/thrylos/shared"
)

// Mocking the Node struct to override FetchGasEstimate method
type MockNodeTest struct {
	Node
	mock.Mock
}

func (m *MockNodeTest) FetchGasEstimate(dataSize int) (int, error) {
	args := m.Called(dataSize)
	return args.Int(0), args.Error(1)
}

func TestSignTransactionHandler(t *testing.T) {
	db := new(mocks.BlockchainDBInterface)

	// Mock server setup
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/mocked-gas-estimate" && r.Method == http.MethodGet {
			json.NewEncoder(w).Encode(map[string]int{"gasEstimate": 1})
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))

	defer server.Close()

	node := &MockNodeTest{
		Node: Node{
			Database:       db,
			GasEstimateURL: server.URL + "/mock-gas-estimate",
		},
	}

	_, privateKey, _ := ed25519.GenerateKey(nil)
	privateKeyBytes := privateKey.Seed()
	db.On("RetrievePrivateKey", "Alice").Return(privateKeyBytes, nil)

	transactionData := shared.Transaction{
		ID:        "txTest123",
		Timestamp: 1630000000,
		Inputs:    []shared.UTXO{{TransactionID: "tx0", Index: 0, OwnerAddress: "Alice", Amount: 100}},
		Outputs:   []shared.UTXO{{TransactionID: "txTest123", Index: 0, OwnerAddress: "Bob", Amount: 100}},
		Sender:    "Alice",
	}

	transactionJSON, _ := json.Marshal(transactionData)

	req := httptest.NewRequest(http.MethodPost, "/sign", bytes.NewBuffer(transactionJSON))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()

	handler := node.SignTransactionHandler()
	handler.ServeHTTP(rec, req)

	resp := rec.Result()
	defer resp.Body.Close()
	body, _ := ioutil.ReadAll(resp.Body)

	if resp.StatusCode != http.StatusOK {
		t.Logf("Response Body: %s", string(body))
		t.Errorf("Expected HTTP status OK, got %d", resp.StatusCode)
		return
	}

	var protoTx shared.Transaction
	err := json.Unmarshal(body, &protoTx)
	if err != nil {
		t.Errorf("Failed to unmarshal response: %v, body: %s", err, string(body))
		return
	}

	// Further checks for signature, etc.
}

func TestFetchGasEstimate(t *testing.T) {
	// Setup HTTP server to mock external requests
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/estimate-gas" {
			w.WriteHeader(http.StatusNotFound)
			json.NewEncoder(w).Encode(map[string]string{"error": "Not Found"})
			return
		}

		if r.Method != http.MethodPost {
			w.WriteHeader(http.StatusMethodNotAllowed)
			json.NewEncoder(w).Encode(map[string]string{"error": "Method Not Allowed"})
			return
		}

		err := r.ParseForm()
		if err != nil {
			w.WriteHeader(http.StatusBadRequest)
			json.NewEncoder(w).Encode(map[string]string{"error": "Bad Request"})
			return
		}

		dataSize := r.FormValue("dataSize")
		if dataSize != "10" { // Ensure this matches the test input as string
			w.WriteHeader(http.StatusBadRequest)
			json.NewEncoder(w).Encode(map[string]string{"error": "Invalid data size"})
			return
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(struct {
			GasFee int `json:"gasFee"`
		}{GasFee: 100})
	}))
	defer server.Close()

	// Use server.URL as the GasEstimateURL in your Node configuration for testing
	node := &Node{GasEstimateURL: server.URL + "/estimate-gas"}

	// Now you can test the FetchGasEstimate function
	gasFee, err := node.FetchGasEstimate(10) // Make sure this matches what the server expects, adjust accordingly
	if err != nil {
		t.Fatalf("Failed to fetch gas estimate: %v", err)
	}

	// Validate the returned gas fee
	if gasFee != 100 {
		t.Errorf("Expected gas fee of 100, got %d", gasFee)
	}
}

func TestSignTransactionHandler_GasEstimateError(t *testing.T) {
	db := new(mocks.BlockchainDBInterface)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError) // Simulate an API failure
	}))
	defer server.Close()

	node := &MockNodeTest{
		Node: Node{
			Database:       db,
			GasEstimateURL: server.URL,
		},
	}

	privateKeyBytes := make([]byte, 32)
	for i := range privateKeyBytes {
		privateKeyBytes[i] = byte(i)
	}
	db.On("RetrievePrivateKey", "Alice").Return(privateKeyBytes, nil)

	// Configure the mock to expect a call with any int and return an error
	node.On("FetchGasEstimate", mock.Anything).Return(0, fmt.Errorf("failed to fetch gas estimate"))

	transactionData := shared.Transaction{
		ID:        "txTest123",
		Timestamp: 1630000000,
		Inputs:    []shared.UTXO{{TransactionID: "tx0", Index: 0, OwnerAddress: "Alice", Amount: 100}},
		Outputs:   []shared.UTXO{{TransactionID: "txTest123", Index: 0, OwnerAddress: "Bob", Amount: 100}},
		Sender:    "Alice",
	}

	transactionJSON, _ := json.Marshal(transactionData)
	req := httptest.NewRequest(http.MethodPost, "/sign", bytes.NewBuffer(transactionJSON))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()

	handler := node.SignTransactionHandler()
	handler.ServeHTTP(rec, req)

	if status := rec.Result().StatusCode; status != http.StatusInternalServerError {
		t.Errorf("Expected HTTP status code %d, got %d", http.StatusInternalServerError, status)
	}

	// Output response body for more context on error
	respBody, _ := ioutil.ReadAll(rec.Body)
	fmt.Println("Response body:", string(respBody))

	// Check if all expectations are met
	node.AssertExpectations(t)
	db.AssertExpectations(t)
}
