package core

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/mock"
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
