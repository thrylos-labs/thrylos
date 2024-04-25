package core

import (
	"Thrylos/shared"
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
)

// This test ensures your RSA keys are generated, stored, retrieved, and used correctly throughout your application.
func TestEd25519KeyGenerationAndUsage(t *testing.T) {
	// Generate Ed25519 keys
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("Failed to generate Ed25519 keys: %v", err)
	}

	// Prepare a message for signing
	message := []byte("Test message for Ed25519 signature")

	// Sign the message
	signature := ed25519.Sign(privateKey, message)

	// Verify the signature
	if !ed25519.Verify(publicKey, message, signature) {
		t.Fatalf("Failed to verify signature")
	}

	// Check key sizes
	if len(privateKey) != ed25519.PrivateKeySize {
		t.Errorf("Private key size is incorrect, expected %d bytes, got %d", ed25519.PrivateKeySize, len(privateKey))
	}
	if len(publicKey) != ed25519.PublicKeySize {
		t.Errorf("Public key size is incorrect, expected %d bytes, got %d", ed25519.PublicKeySize, len(publicKey))
	}

	t.Log("Ed25519 key generation, signing, and verification successful")
}

func TestAES256EncryptionAndDecryption(t *testing.T) {
	// Generate an AES-256 key
	aesKey, err := shared.GenerateAESKey()
	if err != nil {
		t.Fatalf("Failed to generate AES-256 key: %v", err)
	}

	// Check key size
	if len(aesKey) != 32 { // 256 bits = 32 bytes
		t.Errorf("AES key size is incorrect, expected 32 bytes, got %d", len(aesKey))
	}

	// Prepare data for encryption
	plaintext := []byte("Test message for AES-256 encryption")

	// Encrypt the data
	encryptedData, err := shared.EncryptWithAES(aesKey, plaintext)
	if err != nil {
		t.Fatalf("Failed to encrypt data: %v", err)
	}

	// Decrypt the data
	decryptedData, err := shared.DecryptWithAES(aesKey, encryptedData)
	if err != nil {
		t.Fatalf("Failed to decrypt data: %v", err)
	}

	// Verify that decrypted data matches the original plaintext
	if !bytes.Equal(plaintext, decryptedData) {
		t.Fatalf("Decrypted data does not match original plaintext")
	}

	t.Log("AES-256 encryption and decryption successful")
}

func TestBase64EncodingAndDecoding(t *testing.T) {
	// Generate Ed25519 keys
	_, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("Failed to generate Ed25519 keys: %v", err)
	}

	// Encode the private key using base64
	encodedKey := base64.StdEncoding.EncodeToString(privateKey)
	if len(encodedKey) == 0 {
		t.Errorf("Base64 encoding failed, encoded key is empty")
	}

	// Decode the base64 encoded key
	decodedKey, err := base64.StdEncoding.DecodeString(encodedKey)
	if err != nil {
		t.Fatalf("Base64 decoding failed: %v", err)
	}

	// Compare the original and decoded keys
	if !ed25519.PrivateKey(decodedKey).Equal(privateKey) {
		t.Fatalf("Decoded key does not match the original private key")
	}

	t.Log("Base64 encoding and decoding of Ed25519 keys successful")
}

// Tested the public key ok

func TestInsertAndRetrieveEd25519PublicKey(t *testing.T) {
	// Set up the blockchain with a real database
	tempDir, err := ioutil.TempDir("", "blockchain_test")
	if err != nil {
		t.Fatalf("Failed to create temporary directory: %v", err)
	}
	defer os.RemoveAll(tempDir)

	aesKey, err := shared.GenerateAESKey()
	if err != nil {
		t.Fatalf("Failed to generate AES key: %v", err)
	}

	bc, err := NewBlockchain(tempDir, aesKey)
	if err != nil {
		t.Fatalf("Failed to create blockchain: %v", err)
	}

	// Use a valid hex address for the test
	address := "f291cd4ebab48ee218ab2226562c4ce460994ce7d19d6ffc8b97ea95c43bb6"
	publicKey, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("Failed to generate Ed25519 keys: %v", err)
	}

	// Test insertion
	err = bc.Database.InsertOrUpdateEd25519PublicKey(address, publicKey)
	if err != nil {
		t.Fatalf("Failed to insert Ed25519 public key: %v", err)
	}

	// Test retrieval
	retrievedKey, err := bc.Database.RetrieveEd25519PublicKey(address)
	if err != nil {
		t.Fatalf("Failed to retrieve Ed25519 public key: %v", err)
	}

	if !bytes.Equal(retrievedKey, publicKey) {
		t.Errorf("Retrieved key does not match the inserted key")
	}
}

// Assuming you have a way to mock or create an account for testing
// var testKeyStore = make(map[string]ed25519.PrivateKey)

// func simulateKeyStorage(accounts []Account) {
// 	for _, account := range accounts {
// 		_, privateKey, _ := ed25519.GenerateKey(rand.Reader) // Generate a new key for each account
// 		testKeyStore[account.Address] = privateKey           // Store the key in a map (only for testing)
// 	}
// }

// func getPrivateKeyForAddress(address string) ed25519.PrivateKey {
// 	return testKeyStore[address] // Retrieve the key (only for testing)
// }

// func TestTransactionSubmission(t *testing.T) {

// 	// Mock an AES key for testing
// 	testAESKey := []byte("1234567890123456") // 16 bytes for AES-128
// 	os.Setenv("AES_KEY_ENV_VAR", base64.StdEncoding.EncodeToString(testAESKey))

// 	// Setup: create a test blockchain and node
// 	tempDir, err := ioutil.TempDir("", "blockchain_test")
// 	if err != nil {
// 		t.Fatalf("Failed to create temporary directory: %v", err)
// 	}
// 	defer os.RemoveAll(tempDir)

// 	// Initialize node with nil for shard as it might not be needed for this test
// 	node := NewNode("http://localhost:8080", []string{}, tempDir, nil, true) // true indicates it is a test

// 	// Initialize test accounts
// 	testAccounts, err := node.Blockchain.InitializeTestnetAccounts(10)
// 	if err != nil {
// 		t.Fatalf("Failed to initialize testnet accounts: %v", err)
// 	}

// 	simulateKeyStorage(testAccounts) // Simulate key storage for testing

// 	if len(testAccounts) != 10 {
// 		t.Fatalf("Expected 10 test accounts, got %d", len(testAccounts))
// 	}

// 	// Assume accounts[0] is the sender and accounts[1] is the recipient
// 	sender := testAccounts[0]
// 	recipient := testAccounts[1]

// 	// Create a transaction
// 	tx := shared.Transaction{
// 		ID:        "transaction_id_here",
// 		Timestamp: time.Now().Unix(),
// 		Inputs: []shared.UTXO{
// 			{
// 				TransactionID: "previous_tx_id",
// 				Index:         0,
// 				OwnerAddress:  sender.Address,
// 				Amount:        100,
// 			},
// 		},
// 		Outputs: []shared.UTXO{
// 			{
// 				TransactionID: "transaction_id_here",
// 				Index:         0,
// 				OwnerAddress:  recipient.Address,
// 				Amount:        100,
// 			},
// 		},
// 	}

// 	// Before serializing the transaction:
// 	if sender.Address == "" {
// 		t.Errorf("Sender address is empty before serialization")
// 	}

// 	// Serialize the transaction into JSON
// 	txJSON, err := json.Marshal(tx)
// 	if err != nil {
// 		t.Fatalf("Failed to serialize transaction: %v", err)
// 	}

// 	// Debug log
// 	t.Logf("Serialized transaction JSON: %s", string(txJSON))

// 	// Retrieve the private key for signing (simulated for testing)
// 	privateKey := getPrivateKeyForAddress(sender.Address)

// 	// Sign the transaction
// 	signature, err := signTransaction(privateKey, txJSON)
// 	if err != nil {
// 		t.Fatalf("Failed to sign transaction data: %v", err)
// 	}
// 	log.Printf("Transaction with signature: %+v", tx)

// 	// Append the signature to your transaction
// 	tx.Signature = signature
// 	txJSON, err = json.Marshal(tx)
// 	if err != nil {
// 		t.Fatalf("Failed to serialize transaction with signature: %v", err)
// 	}

// 	// Create an HTTP request to simulate submitting the transaction
// 	req, err := http.NewRequest("POST", "/submit-transaction", bytes.NewReader(txJSON))
// 	if err != nil {
// 		t.Fatalf("Failed to create request: %v", err)
// 	}
// 	req.Header.Set("Content-Type", "application/json")

// 	// Use httptest to record HTTP response
// 	rr := httptest.NewRecorder()
// 	handler := http.HandlerFunc(node.SubmitTransactionHandler())

// 	handler.ServeHTTP(rr, req)

// 	// Check the status code and response body
// 	if status := rr.Code; status != http.StatusOK {
// 		t.Errorf("Handler returned wrong status code: got %v want %v", status, http.StatusOK)
// 	}

// 	expected := "Transaction submitted successfully"
// 	if rr.Body.String() != expected {
// 		t.Errorf("Handler returned unexpected body: got %v want %v", rr.Body.String(), expected)
// 	}
// }

// // Utilize the provided signTransaction method
// func signTransaction(privateKey ed25519.PrivateKey, transactionData []byte) (string, error) {
// 	signature := ed25519.Sign(privateKey, transactionData)
// 	return base64.StdEncoding.EncodeToString(signature), nil
// }

func TestTransactionSubmissionDirectTest(t *testing.T) {
	// Setup server and environment as before
	tempDir, err := ioutil.TempDir("", "blockchain_test")
	if err != nil {
		t.Fatalf("Failed to create temporary directory: %v", err)
	}
	defer os.RemoveAll(tempDir)

	node := NewNode("http://localhost:8080", []string{}, tempDir, nil, true)

	// Hardcoded transaction JSON
	hardcodedJSON := `{
        "ID": "transaction_id_here",
        "Timestamp": 1714042156,
        "Inputs": [{
            "TransactionID": "previous_tx_id",
            "Index": 0,
            "OwnerAddress": "c623f591835d9846f3b0180593956bd213439cc6acec5a11c5afc63792ba3900",
            "Amount": 100
        }],
        "Outputs": [{
            "TransactionID": "transaction_id_here",
            "Index": 0,
            "OwnerAddress": "1efadd9af828a4fdb20c1a149bd798fa798b25b2acfc27489dde00d5b265fd22",
            "Amount": 100
        }],
        "Signature": "dummy_signature"
    }`

	// Create an HTTP request to simulate submitting the transaction
	req, err := http.NewRequest("POST", "/submit-transaction", bytes.NewBufferString(hardcodedJSON))
	if err != nil {
		t.Fatalf("Failed to create request: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")

	// Use httptest to record HTTP response
	rr := httptest.NewRecorder()
	handler := http.HandlerFunc(node.SubmitTransactionHandler())

	handler.ServeHTTP(rr, req)

	// Check the status code and response body
	if status := rr.Code; status != http.StatusOK {
		t.Errorf("Handler returned wrong status code: got %v want %v", status, http.StatusOK)
		t.Errorf("Handler returned unexpected body: got %v want %v", rr.Body.String(), "Transaction submitted successfully")
	} else {
		t.Log("Transaction submitted successfully")
	}
}
