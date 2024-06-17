package core

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
)

// Define the interface for blockchain operations
type FundOps interface {
	TransferFunds(from, to string, amount int64) error
}

// Implement the interface for testing
type MockFundManager struct {
	Stakeholders   map[string]int64
	GenesisAccount string
}

func (mfm *MockFundManager) TransferFunds(from, to string, amount int64) error {
	if from == "" {
		from = mfm.GenesisAccount // Use the genesis account if 'from' is not specified
	}
	if mfm.Stakeholders[from] < amount {
		return fmt.Errorf("insufficient funds")
	}
	mfm.Stakeholders[from] -= amount
	mfm.Stakeholders[to] += amount
	return nil
}

// Node struct containing a FundOps
type FundingNode struct {
	FundOps FundOps
}

// Handler function for wallet funding
func (fn *FundingNode) WalletFundingHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "POST" {
			http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
			return
		}

		var request struct {
			Address string `json:"address"`
			Amount  int64  `json:"amount"`
		}

		if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
			http.Error(w, "Invalid request: "+err.Error(), http.StatusBadRequest)
			return
		}

		if err := fn.FundOps.TransferFunds("", request.Address, request.Amount); err != nil {
			http.Error(w, fmt.Sprintf("Failed to fund wallet: %v", err), http.StatusInternalServerError)
			return
		}

		response := map[string]string{
			"message": fmt.Sprintf("Funded wallet with %d successfully", request.Amount),
		}
		json.NewEncoder(w).Encode(response)
	}
}

// Test the handler
func TestWalletFundingHandler(t *testing.T) {
	genesisAccount := "genesis"
	mockFundManager := &MockFundManager{
		Stakeholders: map[string]int64{
			genesisAccount: 1000, // Initial funds
		},
		GenesisAccount: genesisAccount,
	}

	fundingNode := &FundingNode{
		FundOps: mockFundManager,
	}

	body := map[string]interface{}{
		"address": "testAddress",
		"amount":  100,
	}
	bodyBytes, _ := json.Marshal(body)
	request, err := http.NewRequest("POST", "/fund-wallet", bytes.NewBuffer(bodyBytes))
	if err != nil {
		t.Fatal(err)
	}

	rr := httptest.NewRecorder()
	handler := fundingNode.WalletFundingHandler()

	handler.ServeHTTP(rr, request)

	if status := rr.Code; status != http.StatusOK {
		t.Errorf("handler returned wrong status code: got %v want %v", status, http.StatusOK)
	}

	// Decode the JSON response
	var response map[string]string
	if err := json.Unmarshal(rr.Body.Bytes(), &response); err != nil {
		t.Fatalf("could not decode response: %v", err)
	}

	expectedMessage := "Funded wallet with 100 successfully"
	if response["message"] != expectedMessage {
		t.Errorf("handler returned unexpected message: got %v want %v", response["message"], expectedMessage)
	}
}
