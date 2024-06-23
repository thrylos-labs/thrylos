package core

import (
	"bytes"
	"crypto/ed25519"
	"encoding/json"
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
	_, privateKey, _ := ed25519.GenerateKey(nil)
	privateKeyBytes := privateKey.Seed()

	db := new(mocks.BlockchainDBInterface)
	db.On("RetrievePrivateKey", "Alice").Return(privateKeyBytes, nil) // Correctly return the generated private key bytes

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/mock-gas-estimate" && r.Method == http.MethodGet {
			// Correctly encode GasFee to match the FetchGasEstimate function expectation
			json.NewEncoder(w).Encode(struct {
				GasFee int `json:"gasFee"`
			}{GasFee: 1})
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer server.Close()

	node := &MockNodeTest{Node: Node{Database: db}} // Ensure Database is assigned
	node.GasEstimateURL = server.URL + "/mock-gas-estimate"
	node.On("FetchGasEstimate", mock.Anything).Return(1, nil) // Ensure this mock matches your function's use

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
	}

	var protoTx shared.Transaction
	if err := json.Unmarshal(body, &protoTx); err != nil {
		t.Errorf("Failed to unmarshal response: %v, body: %s", err, string(body))
	}

	// Additional checks can be added here to validate the response further, such as checking the signature.
}

func TestFetchGasEstimate(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/mock-gas-estimate" {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		if r.Method != http.MethodGet {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		// Assuming the dataSize is passed as a query parameter
		dataSize := r.URL.Query().Get("dataSize")
		if dataSize != "10" {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]int{"gasEstimate": 100}) // Make sure this matches the expected key in the FetchGasEstimate function
	}))
	defer server.Close()

	// Create a Node instance with the URL of the mock server
	node := &Node{GasEstimateURL: server.URL + "/mock-gas-estimate"}

	// Now test FetchGasEstimate
	gasFee, err := node.FetchGasEstimate(10) // This should match what the server expects
	if err != nil {
		t.Fatalf("Failed to fetch gas estimate: %v", err)
	}

	// Validate the returned gas fee
	if gasFee != 100 {
		t.Errorf("Expected gas fee of 100, got %d", gasFee)
	}
}
