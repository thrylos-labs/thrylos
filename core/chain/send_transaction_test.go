package chain

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	thrylos "github.com/thrylos-labs/thrylos"
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

// MockBlockchain for testing propagation
type MockBlockchain struct {
	ActiveValidators      []string
	PendingTxs            []*thrylos.Transaction
	PropagatedTxs         map[string][]string
	TransactionPropagator *TransactionPropagator
	Stakeholders          map[string]int64
	Blocks                []*Block
	mu                    sync.RWMutex
}

// Add this new method to satisfy the interface
func (mb *MockBlockchain) GetActiveValidators() []string {
	mb.mu.RLock()
	defer mb.mu.RUnlock()
	return mb.ActiveValidators
}

func NewMockBlockchain() *MockBlockchain {
	mock := &MockBlockchain{
		ActiveValidators: []string{"validator1", "validator2", "validator3"},
		PendingTxs:       make([]*thrylos.Transaction, 0),
		PropagatedTxs:    make(map[string][]string),
	}
	mock.TransactionPropagator = NewTransactionPropagator(mock)
	return mock
}

func (mb *MockBlockchain) IsActiveValidator(address string) bool {
	mb.mu.RLock()
	defer mb.mu.RUnlock()
	for _, v := range mb.ActiveValidators {
		if v == address {
			return true
		}
	}
	return false
}

func (mb *MockBlockchain) AddPendingTransaction(tx *thrylos.Transaction) error {
	mb.mu.Lock()
	defer mb.mu.Unlock()
	mb.PendingTxs = append(mb.PendingTxs, tx)
	return nil
}

func TestTransactionPropagation(t *testing.T) {
	mockBC := NewMockBlockchain()

	// Create test transaction
	tx := &thrylos.Transaction{
		Id:        "test-tx-1",
		Timestamp: time.Now().Unix(),
		Sender:    "test-sender",
		Salt:      make([]byte, 32),
	}

	// Test propagation
	err := mockBC.TransactionPropagator.PropagateTransaction(tx)
	if err != nil {
		t.Errorf("PropagateTransaction failed: %v", err)
	}

	// Verify transaction was propagated to all validators
	mockBC.mu.RLock()
	txCount := 0
	for _, pendingTx := range mockBC.PendingTxs {
		if pendingTx.Id == tx.Id {
			txCount++
		}
	}
	mockBC.mu.RUnlock()

	if txCount != len(mockBC.ActiveValidators) {
		t.Errorf("Expected transaction to be added %d times (once per validator), got %d times",
			len(mockBC.ActiveValidators), txCount)
	}
}

func TestPropagationWithNoValidators(t *testing.T) {
	mockBC := NewMockBlockchain()
	mockBC.ActiveValidators = []string{} // Empty validator list

	tx := &thrylos.Transaction{
		Id:        "test-tx-2",
		Timestamp: time.Now().Unix(),
		Sender:    "test-sender",
		Salt:      make([]byte, 32),
	}

	err := mockBC.TransactionPropagator.PropagateTransaction(tx)
	if err == nil {
		t.Error("Expected propagation to fail with no validators, but it succeeded")
	}
}

func TestAddPendingTransactionWithPropagation(t *testing.T) {
	// Create mock blockchain
	mockBC := NewMockBlockchain()

	// Create test transaction
	tx := &thrylos.Transaction{
		Id:        "test-tx-3",
		Timestamp: time.Now().Unix(),
		Sender:    "test-sender",
		Salt:      make([]byte, 32),
	}

	// Test AddPendingTransaction
	err := mockBC.AddPendingTransaction(tx)
	if err != nil {
		t.Errorf("AddPendingTransaction failed: %v", err)
	}

	// Verify transaction was added to pending pool
	found := false
	for _, pendingTx := range mockBC.PendingTxs {
		if pendingTx.Id == tx.Id {
			found = true
			break
		}
	}
	if !found {
		t.Error("Transaction was not added to pending transactions")
	}
}
