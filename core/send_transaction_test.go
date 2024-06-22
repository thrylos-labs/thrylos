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

// func (mn *MockNode) SignTransactionHandler() http.HandlerFunc {
// 	return func(w http.ResponseWriter, r *http.Request) {
// 		// Additional nil checks
// 		if mn == nil {
// 			log.Println("Error: MockNode instance is nil")
// 			http.Error(w, "Server configuration error", http.StatusInternalServerError)
// 			return
// 		}

// 		body, err := ioutil.ReadAll(r.Body)
// 		if err != nil {
// 			log.Printf("Error reading request body: %v", err)
// 			http.Error(w, "Error reading request", http.StatusInternalServerError)
// 			return
// 		}
// 		r.Body = ioutil.NopCloser(bytes.NewBuffer(body))

// 		var transactionData shared.Transaction
// 		err = json.Unmarshal(body, &transactionData)
// 		if err != nil {
// 			http.Error(w, "Invalid transaction format: "+err.Error(), http.StatusBadRequest)
// 			return
// 		}

// 		if mn.RetrievePrivateKey == nil {
// 			log.Println("RetrievePrivateKey method is not initialized")
// 			http.Error(w, "Internal server error", http.StatusInternalServerError)
// 			return
// 		}

// 		privateKeyBytes, err := mn.RetrievePrivateKey(transactionData.Sender)
// 		if err != nil {
// 			http.Error(w, "Could not retrieve private key: "+err.Error(), http.StatusInternalServerError)
// 			return
// 		}

// 		if privateKeyBytes == nil {
// 			log.Println("Private key bytes are nil")
// 			http.Error(w, "Private key not found", http.StatusInternalServerError)
// 			return
// 		}

// 		privateKey, err := shared.DecodePrivateKey(privateKeyBytes)
// 		if err != nil {
// 			http.Error(w, "Could not decode private key", http.StatusInternalServerError)
// 			return
// 		}

// 		aesKey, err := shared.GenerateAESKey()
// 		if err != nil {
// 			http.Error(w, "Could not generate AES key", http.StatusInternalServerError)
// 			return
// 		}

// 		signedTransaction, err := shared.CreateAndSignTransaction(
// 			transactionData.ID,
// 			transactionData.Sender,
// 			transactionData.Inputs,
// 			transactionData.Outputs,
// 			privateKey,
// 			aesKey,
// 		)
// 		if err != nil {
// 			http.Error(w, "Could not sign transaction", http.StatusInternalServerError)
// 			return
// 		}

// 		protoTx, err := shared.ConvertToProtoTransaction(signedTransaction)
// 		if err != nil {
// 			http.Error(w, "Could not convert transaction to protobuf", http.StatusInternalServerError)
// 			return
// 		}

// 		w.Header().Set("Content-Type", "application/json")
// 		if err := json.NewEncoder(w).Encode(protoTx); err != nil {
// 			http.Error(w, "Could not encode response", http.StatusInternalServerError)
// 			return
// 		}
// 	}
// }

// func TestSignTransactionHandler(t *testing.T) {
// 	node := &MockNode{}
// 	handler := node.SignTransactionHandler()

// 	// Create a sample transaction request
// 	transaction := shared.Transaction{
// 		ID:        "tx124",
// 		Sender:    "senderPublicKey",
// 		Inputs:    []shared.UTXO{{TransactionID: "tx100", Index: 0, Amount: 50}},
// 		Outputs:   []shared.UTXO{{TransactionID: "tx124", Index: 0, OwnerAddress: "recipientAddress", Amount: 50}},
// 		Timestamp: 1609459200,
// 	}
// 	b, _ := json.Marshal(transaction)
// 	req, _ := http.NewRequest("POST", "/sign-transaction", bytes.NewBuffer(b))
// 	req.Header.Set("Content-Type", "application/json")

// 	// Setup response recorder
// 	rr := httptest.NewRecorder()

// 	// Serve HTTP
// 	handler.ServeHTTP(rr, req)

// 	if rr.Code != http.StatusOK {
// 		t.Errorf("handler returned wrong status code: got %v want %v", rr.Code, http.StatusOK)
// 	}

// 	// Convert to ProtoTransaction for decoding purpose
// 	// Assuming `ConvertToProtoTransaction` returns a `*thrylos.Transaction`
// 	protoTx, _ := shared.ConvertToProtoTransaction(&transaction)

// 	// Check the response body for a correctly signed transaction
// 	if err := json.NewDecoder(rr.Body).Decode(&protoTx); err != nil {
// 		t.Fatalf("could not decode response: %v", err)
// 	}

// 	// Assert responses and any other properties
// 	if status := rr.Code; status != http.StatusOK {
// 		t.Errorf("handler returned wrong status code: got %v want %v", status, http.StatusOK)
// 	}

// 	// Assert on some properties of the protoTx, like if it contains a valid signature
// 	if protoTx.Signature == nil {
// 		t.Errorf("expected a signature in the transaction")
// 	}

// 	// Additional assertions can be added here based on how the ProtoTransaction is structured and expected behaviors
// }

// func TestSignTransactionHandler_ValidSignature(t *testing.T) {
// 	var publicKey ed25519.PublicKey
// 	node := &MockNode{}
// 	handler := node.SignTransactionHandler()

// 	transaction := shared.Transaction{
// 		ID:        "tx124",
// 		Sender:    "senderPublicKey",
// 		Inputs:    []shared.UTXO{{TransactionID: "tx100", Index: 0, Amount: 50}},
// 		Outputs:   []shared.UTXO{{TransactionID: "tx124", Index: 0, OwnerAddress: "recipientAddress", Amount: 50}},
// 		Timestamp: 1609459200,
// 	}
// 	b, _ := json.Marshal(transaction)
// 	req, _ := http.NewRequest("POST", "/sign-transaction", bytes.NewBuffer(b))
// 	req.Header.Set("Content-Type", "application/json")

// 	rr := httptest.NewRecorder()
// 	handler.ServeHTTP(rr, req)

// 	var protoTx thrylos.Transaction
// 	if err := json.NewDecoder(rr.Body).Decode(&protoTx); err != nil {
// 		t.Fatalf("could not decode response: %v", err)
// 	}

// 	// Prepare the data for signature verification without changing the signature
// 	txBytes, _ := json.Marshal(protoTx) // Ensure you marshal the same structure that was signed

// 	// Verify the signature using the stored public key
// 	if valid := ed25519.Verify(publicKey, txBytes, protoTx.Signature); !valid {
// 		t.Errorf("signature is invalid")
// 	}
// }
