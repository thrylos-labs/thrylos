package chaintests

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/thrylos-labs/thrylos"
	"github.com/thrylos-labs/thrylos/amount"
	"github.com/thrylos-labs/thrylos/crypto/address"
	"github.com/thrylos-labs/thrylos/types"
)

// // // MockNode for testing without a full node setup
type ProcessedTx struct {
	Transaction *types.Transaction
	ProcessedAt time.Time
}

// MockNode for testing without a full node setup
type MockNode struct {
	types.Store
	RetrievePrivateKeyFunc func(string) ([]byte, error)
	processedTxs           map[string]ProcessedTx
	mu                     sync.RWMutex // protect processedTxs
}

func (mn *MockNode) RetrievePrivateKey(sender string) ([]byte, error) {
	if mn.RetrievePrivateKeyFunc != nil {
		return mn.RetrievePrivateKeyFunc(sender)
	}
	return nil, fmt.Errorf("retrieve private key function not initialized")
}

func (mn *MockNode) EnhancedSubmitTransactionHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(r.Body)
		if err != nil {
			http.Error(w, "Failed to read request body: "+err.Error(), http.StatusBadRequest)
			return
		}

		fmt.Printf("Received JSON: %s\n", string(body))

		// First unmarshal into our JSON-friendly struct
		var jsonTx MockTransactionJSON
		if err := json.Unmarshal(body, &jsonTx); err != nil {
			fmt.Printf("JSON unmarshal error: %v\n", err)
			http.Error(w, "Invalid transaction format", http.StatusBadRequest)
			return
		}

		// Convert to shared.Transaction
		addrBytes, err := base64.StdEncoding.DecodeString(jsonTx.SenderAddress)
		if err != nil {
			fmt.Printf("Address decode error: %v\n", err)
			http.Error(w, "Invalid address format", http.StatusBadRequest)
			return
		}

		pubKeyBytes, err := base64.StdEncoding.DecodeString(jsonTx.SenderPublicKey)
		if err != nil {
			fmt.Printf("Public key decode error: %v\n", err)
			http.Error(w, "Invalid public key format", http.StatusBadRequest)
			return
		}

		sigBytes, err := base64.StdEncoding.DecodeString(jsonTx.Signature)
		if err != nil {
			fmt.Printf("Signature decode error: %v\n", err)
			http.Error(w, "Invalid signature format", http.StatusBadRequest)
			return
		}

		var addr address.Address
		copy(addr[:], addrBytes)

		tx := &types.Transaction{
			ID:               jsonTx.ID,
			Timestamp:        jsonTx.Timestamp,
			Inputs:           jsonTx.Inputs,
			Outputs:          jsonTx.Outputs,
			EncryptedInputs:  jsonTx.EncryptedInputs,
			EncryptedOutputs: jsonTx.EncryptedOutputs,
			EncryptedAESKey:  jsonTx.EncryptedAESKey,
			PreviousTxIds:    jsonTx.PreviousTxIds,
			SenderAddress:    addr,
			SenderPublicKey: &MockPublicKey{
				Key:     string(pubKeyBytes),
				address: &addr,
			},
			Signature: &MockSignature{sig: sigBytes},
			GasFee:    jsonTx.GasFee,
			BlockHash: jsonTx.BlockHash,
			Salt:      jsonTx.Salt,
			Status:    jsonTx.Status,
		}

		if err := mn.signAndProcessTransaction(tx); err != nil {
			http.Error(w, "Failed to process transaction: "+err.Error(), http.StatusInternalServerError)
			return
		}

		w.WriteHeader(http.StatusOK)
		w.Write([]byte("Transaction processed successfully"))
	}
}

func (mn *MockNode) signAndProcessTransaction(tx *types.Transaction) error {
	// Basic validation
	if tx == nil {
		return fmt.Errorf("transaction cannot be nil")
	}

	// Check required fields
	if tx.ID == "" {
		return fmt.Errorf("transaction ID is required")
	}
	if tx.Timestamp == 0 {
		return fmt.Errorf("timestamp is required")
	}
	if len(tx.Inputs) == 0 {
		return fmt.Errorf("transaction must have at least one input")
	}
	if len(tx.Outputs) == 0 {
		return fmt.Errorf("transaction must have at least one output")
	}
	if tx.SenderPublicKey == nil {
		return fmt.Errorf("sender public key is required")
	}

	// Verify input amounts match output amounts
	var totalInput, totalOutput amount.Amount
	for _, input := range tx.Inputs {
		totalInput += input.Amount
	}
	for _, output := range tx.Outputs {
		totalOutput += output.Amount
	}

	// Convert GasFee to int64 for comparison
	gasFee := amount.Amount(tx.GasFee)

	if totalInput != totalOutput+gasFee {
		return fmt.Errorf("input amount (%d) must equal output amount (%d) plus gas fee (%d)",
			totalInput, totalOutput, gasFee)
	}

	// Optional: Verify signature if present
	if tx.Signature != nil {
		err := tx.Signature.Verify(&tx.SenderPublicKey, []byte(tx.ID))
		if err != nil {
			return fmt.Errorf("signature verification failed: %v", err)
		}
	}

	// Optional: Mock UTXO validation
	for _, input := range tx.Inputs {
		if input.IsSpent {
			return fmt.Errorf("input UTXO %s:%d is already spent",
				input.TransactionID, input.Index)
		}
	}

	// Mock successful processing
	for i := range tx.Inputs {
		tx.Inputs[i].IsSpent = true
	}

	return nil
}

func (mn *MockNode) WithTransactionTracking() *MockNode {
	mn.processedTxs = make(map[string]ProcessedTx)
	return mn
}

func (mn *MockNode) GetProcessedTransaction(txID string) (*ProcessedTx, bool) {
	if mn.processedTxs == nil {
		return nil, false
	}
	tx, exists := mn.processedTxs[txID]
	return &tx, exists
}

func TestSignAndProcessTransaction(t *testing.T) {
	tests := []struct {
		name    string
		tx      *types.Transaction
		wantErr bool
		errMsg  string
	}{
		{
			name:    "nil transaction",
			tx:      nil,
			wantErr: true,
			errMsg:  "transaction cannot be nil",
		},
		{
			name: "valid transaction",
			tx: &types.Transaction{
				ID:        "tx123",
				Timestamp: time.Now().Unix(),
				Inputs: []types.UTXO{
					{TransactionID: "prev", Index: 0, Amount: 100},
				},
				Outputs: []types.UTXO{
					{TransactionID: "tx123", Index: 0, Amount: 90},
				},
				SenderPublicKey: NewMockPublicKey("test"),
				GasFee:          10,
			},
			wantErr: false,
		},
		{
			name: "invalid amount balance",
			tx: &types.Transaction{
				ID:        "tx123",
				Timestamp: time.Now().Unix(),
				Inputs: []types.UTXO{
					{TransactionID: "prev", Index: 0, Amount: 100},
				},
				Outputs: []types.UTXO{
					{TransactionID: "tx123", Index: 0, Amount: 100},
				},
				SenderPublicKey: NewMockPublicKey("test"),
				GasFee:          10, // Makes total output (100+10) > input (100)
			},
			wantErr: true,
			errMsg:  "input amount (100) must equal output amount (100) plus gas fee (10)",
		},
		{
			name: "spent input",
			tx: &types.Transaction{
				ID:        "tx123",
				Timestamp: time.Now().Unix(),
				Inputs: []types.UTXO{
					{TransactionID: "prev", Index: 0, Amount: 100, IsSpent: true},
				},
				Outputs: []types.UTXO{
					{TransactionID: "tx123", Index: 0, Amount: 90},
				},
				SenderPublicKey: NewMockPublicKey("test"),
				GasFee:          10,
			},
			wantErr: true,
			errMsg:  "input UTXO prev:0 is already spent",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			node := &MockNode{}
			err := node.signAndProcessTransaction(tt.tx)

			if tt.wantErr {
				if err == nil {
					t.Error("expected error but got none")
				} else if tt.errMsg != "" && !strings.Contains(err.Error(), tt.errMsg) {
					t.Errorf("expected error containing %q but got %q", tt.errMsg, err.Error())
				}
			} else if err != nil {
				t.Errorf("unexpected error: %v", err)
			}

			// Check that valid transaction inputs are marked as spent
			if err == nil && tt.tx != nil {
				for _, input := range tt.tx.Inputs {
					if !input.IsSpent {
						t.Error("expected input to be marked as spent")
					}
				}
			}
		})
	}
}

func TestEnhancedSubmitTransactionHandler(t *testing.T) {
	// Initialize the mock node
	node := &MockNode{}

	// Get the handler from the mock node
	handler := node.EnhancedSubmitTransactionHandler()

	// Create a mock transaction
	txBytes, err := CreateMockTransaction()
	if err != nil {
		t.Fatalf("Failed to create mock transaction: %v", err)
	}

	// Log the JSON for debugging
	t.Logf("JSON Transaction: %s", string(txBytes))

	// Create request with JSON data
	req := httptest.NewRequest("POST", "/submit-transaction", bytes.NewBuffer(txBytes))
	req.Header.Set("Content-Type", "application/json")

	// Create response recorder
	rr := httptest.NewRecorder()

	// Serve the request using our handler
	handler.ServeHTTP(rr, req)

	// Log the response for debugging
	t.Logf("Response Status: %d", rr.Code)
	t.Logf("Response Body: %s", rr.Body.String())

	// Check the status code
	if status := rr.Code; status != http.StatusOK {
		t.Errorf("handler returned wrong status code: got %v want %v", status, http.StatusOK)
	}

	// Check the response body
	expected := "Transaction processed successfully"
	if rr.Body.String() != expected {
		t.Errorf("handler returned unexpected body: got %v want %v",
			rr.Body.String(), expected)
	}
}

// MockBlockchain for testing propagation
type MockBlockchain struct {
	ActiveValidators      []string
	PendingTxs            []*thrylos.Transaction
	PropagatedTxs         map[string][]string
	TransactionPropagator *types.TransactionPropagator
	Stakeholders          map[string]int64
	Blocks                []*types.Block
	mu                    sync.RWMutex
}

// Add this new method to satisfy the interface
func (mb *MockBlockchain) GetActiveValidators() []string {
	mb.mu.RLock()
	defer mb.mu.RUnlock()
	return mb.ActiveValidators
}

// func NewMockBlockchain() *MockBlockchain {
// 	mock := &MockBlockchain{
// 		ActiveValidators: []string{"validator1", "validator2", "validator3"},
// 		PendingTxs:       make([]*thrylos.Transaction, 0),
// 		PropagatedTxs:    make(map[string][]string),
// 	}
// 	mock.TransactionPropagator = network.NewTransactionPropagator(mock)
// 	return mock
// }

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

// func TestTransactionPropagation(t *testing.T) {
// 	mockBC := NewMockBlockchain()

// 	// Create test transaction
// 	tx := &thrylos.Transaction{
// 		Id:        "test-tx-1",
// 		Timestamp: time.Now().Unix(),
// 		Sender:    "test-sender",
// 		Salt:      make([]byte, 32),
// 	}

// 	// Test propagation
// 	err := mockBC.TransactionPropagator.PropagateTransaction(tx)
// 	if err != nil {
// 		t.Errorf("PropagateTransaction failed: %v", err)
// 	}

// 	// Verify transaction was propagated to all validators
// 	mockBC.mu.RLock()
// 	txCount := 0
// 	for _, pendingTx := range mockBC.PendingTxs {
// 		if pendingTx.Id == tx.Id {
// 			txCount++
// 		}
// 	}
// 	mockBC.mu.RUnlock()

// 	if txCount != len(mockBC.ActiveValidators) {
// 		t.Errorf("Expected transaction to be added %d times (once per validator), got %d times",
// 			len(mockBC.ActiveValidators), txCount)
// 	}
// }

// func TestPropagationWithNoValidators(t *testing.T) {
// 	mockBC := NewMockBlockchain()
// 	mockBC.ActiveValidators = []string{} // Empty validator list

// 	tx := &thrylos.Transaction{
// 		Id:        "test-tx-2",
// 		Timestamp: time.Now().Unix(),
// 		Sender:    "test-sender",
// 		Salt:      make([]byte, 32),
// 	}

// 	err := mockBC.TransactionPropagator.PropagateTransaction(tx)
// 	if err == nil {
// 		t.Error("Expected propagation to fail with no validators, but it succeeded")
// 	}
// }

// func TestAddPendingTransactionWithPropagation(t *testing.T) {
// 	// Create mock blockchain
// 	mockBC := NewMockBlockchain()

// 	// Create test transaction
// 	tx := &thrylos.Transaction{
// 		Id:        "test-tx-3",
// 		Timestamp: time.Now().Unix(),
// 		Sender:    "test-sender",
// 		Salt:      make([]byte, 32),
// 	}

// 	// Test AddPendingTransaction
// 	err := mockBC.AddPendingTransaction(tx)
// 	if err != nil {
// 		t.Errorf("AddPendingTransaction failed: %v", err)
// 	}

// 	// Verify transaction was added to pending pool
// 	found := false
// 	for _, pendingTx := range mockBC.PendingTxs {
// 		if pendingTx.Id == tx.Id {
// 			found = true
// 			break
// 		}
// 	}
// 	if !found {
// 		t.Error("Transaction was not added to pending transactions")
// 	}
// }
