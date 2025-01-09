package core

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/thrylos-labs/thrylos/shared"
)

// MockNode for testing without a full node setup
type MockNode struct {
	shared.BlockchainDBInterface
	// RetrievePrivateKeyFunc func(string) ([]byte, error)
}

// func (mn *MockNode) RetrievePrivateKey(sender string) ([]byte, error) {
// 	if mn.RetrievePrivateKeyFunc == nil {
// 		return mn.RetrievePrivateKeyFunc(sender)
// 	}
// 	return nil, fmt.Errorf("retrieve private key function not initialized")
// }

func (mn *MockNode) EnhancedSubmitTransactionHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var tx shared.Transaction
		decoder := json.NewDecoder(r.Body)
		if err := decoder.Decode(&tx); err != nil {
			http.Error(w, "Invalid transaction format", http.StatusBadRequest)
			return
		}

		// Assume validation always passes for simplicity
		if err := mn.signAndProcessTransaction(&tx); err != nil {
			http.Error(w, "Failed to process transaction: "+err.Error(), http.StatusInternalServerError)
			return
		}

		w.WriteHeader(http.StatusOK)
		w.Write([]byte("Transaction processed successfully"))
	}
}

func (mn *MockNode) signAndProcessTransaction(tx *shared.Transaction) error {
	// Mock signing and processing logic
	return nil // Return nil indicating success
}

func TestEnhancedSubmitTransactionHandler(t *testing.T) {
	node := &MockNode{}

	handler := node.EnhancedSubmitTransactionHandler()

	// Creating a valid transaction
	transaction := shared.Transaction{
		ID:        "tx123",
		Timestamp: 1609459200,
		Inputs:    []shared.UTXO{{TransactionID: "tx100", Index: 0, Amount: 50}},
		Outputs:   []shared.UTXO{{TransactionID: "tx123", Index: 0, OwnerAddress: "recipientAddress", Amount: 50}},
		Sender:    "senderPublicKey",
	}

	b, _ := json.Marshal(transaction)
	req, _ := http.NewRequest("POST", "/submit-transaction", bytes.NewBuffer(b))
	rr := httptest.NewRecorder()

	handler.ServeHTTP(rr, req)

	if status := rr.Code; status != http.StatusOK {
		t.Errorf("handler returned wrong status code: got %v want %v", status, http.StatusOK)
	}

	expected := "Transaction processed successfully"
	if rr.Body.String() != expected {
		t.Errorf("handler returned unexpected body: got %v want %v", rr.Body.String(), expected)
	}
}
