package core

import (
	"Thrylos/shared"
	"crypto"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/cloudflare/circl/sign/dilithium"
)

// Verifying with a Different Public Key Than the One Used for Signing
func TestSignatureVerificationWithDifferentPublicKey(t *testing.T) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("Error generating RSA key: %v", err)
	}
	differentPrivateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("Error generating a different RSA key: %v", err)
	}

	// Use the public key from a different key pair for verification
	differentPublicKey := &differentPrivateKey.PublicKey

	serializedData := `{"ID":"tx1", ... }` // Simplified serialized data
	hashed := sha256.Sum256([]byte(serializedData))
	signature, err := rsa.SignPKCS1v15(rand.Reader, privateKey, crypto.SHA256, hashed[:])
	if err != nil {
		t.Fatalf("Error signing data: %v", err)
	}

	// Attempt to verify the signature with a different public key
	err = rsa.VerifyPKCS1v15(differentPublicKey, crypto.SHA256, hashed[:], signature)
	if err == nil {
		t.Errorf("Signature verification erroneously succeeded with a different public key")
	} else {
		t.Log("Correctly failed to verify signature with a different public key")
	}
}

// 2. Altering the Serialized Data After Signing but Before Verification
func TestSignatureVerificationWithAlteredData(t *testing.T) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("Error generating RSA key: %v", err)
	}
	publicKey := &privateKey.PublicKey

	serializedData := `{"ID":"tx1", ... }` // Original serialized data
	hashed := sha256.Sum256([]byte(serializedData))
	signature, err := rsa.SignPKCS1v15(rand.Reader, privateKey, crypto.SHA256, hashed[:])
	if err != nil {
		t.Fatalf("Error signing data: %v", err)
	}

	// Alter the serialized data
	alteredSerializedData := `{"ID":"tx1", "altered": true, ... }`
	alteredHashed := sha256.Sum256([]byte(alteredSerializedData))

	// Attempt to verify the signature with altered data
	err = rsa.VerifyPKCS1v15(publicKey, crypto.SHA256, alteredHashed[:], signature)
	if err == nil {
		t.Errorf("Signature verification erroneously succeeded with altered data")
	} else {
		t.Log("Correctly failed to verify signature with altered data")
	}
}

// 3. Testing with Invalid or Corrupted Signatures
func TestSignatureVerificationWithInvalidSignature(t *testing.T) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("Error generating RSA key: %v", err)
	}
	publicKey := &privateKey.PublicKey

	serializedData := `{"ID":"tx1", ... }` // Simplified serialized data
	hashed := sha256.Sum256([]byte(serializedData))

	// Generate a valid signature
	validSignature, err := rsa.SignPKCS1v15(rand.Reader, privateKey, crypto.SHA256, hashed[:])
	if err != nil {
		t.Fatalf("Error signing data: %v", err)
	}

	// Corrupt the signature by altering its contents
	invalidSignature := validSignature
	invalidSignature[0] ^= 0xFF // Flip bits in the first byte

	// Attempt to verify the signature with the corrupted data
	err = rsa.VerifyPKCS1v15(publicKey, crypto.SHA256, hashed[:], invalidSignature)
	if err == nil {
		t.Errorf("Signature verification erroneously succeeded with an invalid signature")
	} else {
		t.Log("Correctly failed to verify signature with an invalid signature")
	}
}

// setupBlockchain initializes a blockchain with predefined data for testing.
func setupBlockchain() (*Blockchain, error) {
	// Create a temporary directory for blockchain data
	tempDir, err := ioutil.TempDir("", "blockchain_test")
	if err != nil {
		return nil, fmt.Errorf("failed to create temporary directory: %v", err)
	}
	// Normally, defer os.RemoveAll(tempDir) would be used to clean up after,
	// but in setup function, you'd return the directory path for cleanup in tests

	// Initialize a new blockchain instance using the temporary directory
	bc, err := NewBlockchain(tempDir)
	if err != nil {
		// Clean up the temporary directory in case of initialization failure
		os.RemoveAll(tempDir)
		return nil, fmt.Errorf("failed to initialize blockchain: %v", err)
	}

	// Simulate adding a genesis block if your blockchain doesn't automatically do this
	genesisBlock := NewGenesisBlock()
	bc.Blocks = append(bc.Blocks, genesisBlock)

	// Optionally, add more blocks or transactions as needed for your tests

	return bc, nil
}

func TestSignatureVerificationSimplified(t *testing.T) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("Error generating keys: %v", err)
	}
	publicKey := &privateKey.PublicKey

	// Simulate transaction data
	data := "Test data"
	hashed := sha256.Sum256([]byte(data))

	// Sign the hashed data
	signature, err := rsa.SignPKCS1v15(rand.Reader, privateKey, crypto.SHA256, hashed[:])
	if err != nil {
		t.Fatalf("Error signing data: %v", err)
	}

	// Verify the signature
	if err := rsa.VerifyPKCS1v15(publicKey, crypto.SHA256, hashed[:], signature); err != nil {
		t.Errorf("Failed to verify signature: %v", err)
	} else {
		t.Log("Signature verification succeeded.")
	}
}

func CreateMockTransactionsWithSigning(privateKey *rsa.PrivateKey) []shared.Transaction {
	// Example: Creating a single mock transaction for simplicity.
	// In a real scenario, you might create several transactions based on your test requirements.

	// Mock transaction details.
	txID := "tx1"
	inputs := []shared.UTXO{
		{
			ID:            "utxo1",
			TransactionID: "tx0",
			Index:         0,
			OwnerAddress:  "Alice",
			Amount:        100,
		},
	}
	outputs := []shared.UTXO{
		{
			ID:            "utxo2",
			TransactionID: txID,
			Index:         0,
			OwnerAddress:  "Bob",
			Amount:        100,
		},
	}

	// Create a new transaction.
	tx := shared.Transaction{
		ID:        txID,
		Inputs:    inputs,
		Outputs:   outputs,
		Timestamp: time.Now().Unix(),
	}

	// Serialize the transaction without the signature for signing.
	txBytes, err := json.Marshal(tx)
	if err != nil {
		fmt.Printf("Error serializing transaction: %v\n", err)
		return nil // In real code, handle errors more gracefully.
	}

	// Sign the transaction.
	signature, err := signTransactionData(txBytes, privateKey)
	if err != nil {
		fmt.Printf("Error signing transaction: %v\n", err)
		return nil // In real code, handle errors more gracefully.
	}

	// Attach the signature to the transaction.
	tx.Signature = signature

	// Return a slice containing the signed transaction.
	return []shared.Transaction{tx}
}

// signTransactionData signs the transaction data with the provided RSA private key and returns the base64-encoded signature.
func signTransactionData(data []byte, privateKey *rsa.PrivateKey) (string, error) {
	hashedData := sha256.Sum256(data)
	signature, err := rsa.SignPKCS1v15(rand.Reader, privateKey, crypto.SHA256, hashedData[:])
	if err != nil {
		return "", err
	}
	encodedSignature := base64.StdEncoding.EncodeToString(signature)
	return encodedSignature, nil
}

func TestTransactionSigningAndVerification1(t *testing.T) {
	// Step 1: Generate Ed25519 keys
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("Failed to generate Ed25519 keys: %v", err)
	}

	// Step 2: Create a new transaction
	tx := shared.Transaction{
		ID:        "txTest123",
		Timestamp: 1630000000,
		Inputs:    []shared.UTXO{{TransactionID: "tx0", Index: 0, OwnerAddress: "Alice", Amount: 100}},
		Outputs:   []shared.UTXO{{TransactionID: "txTest123", Index: 0, OwnerAddress: "Bob", Amount: 100}},
	}

	// Step 3: Serialize the transaction (excluding the signature for now)
	serializedTx, err := json.Marshal(tx)
	if err != nil {
		t.Fatalf("Failed to serialize transaction: %v", err)
	}

	// Step 4: Sign the serialized transaction data directly with Ed25519 (no separate hashing needed)
	signature := ed25519.Sign(privateKey, serializedTx)
	if signature == nil {
		t.Fatalf("Failed to sign transaction")
	}

	// Step 5: Verify the signature with the Ed25519 public key
	if !ed25519.Verify(publicKey, serializedTx, signature) {
		t.Fatalf("Signature verification failed")
	}

	t.Log("Transaction signing and verification with Ed25519 successful")
}

// Find out the test
// go test -v -timeout 30s -run ^TestTransactionThroughput$ Thrylos/core
func TestTransactionThroughput(t *testing.T) {
	// Generate Ed25519 keys
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("Error generating Ed25519 key pair: %v", err)
	}

	// Define the number of transactions to simulate
	numTransactions := 1000

	start := time.Now()

	for i := 0; i < numTransactions; i++ {
		// Simulate creating a transaction
		txID := fmt.Sprintf("tx%d", i)
		inputs := []shared.UTXO{{TransactionID: "tx0", Index: 0, OwnerAddress: "Alice", Amount: 100}}
		outputs := []shared.UTXO{{TransactionID: txID, Index: 0, OwnerAddress: "Bob", Amount: 100}}
		tx := shared.Transaction{ID: txID, Inputs: inputs, Outputs: outputs, Timestamp: time.Now().Unix()}

		// Serialize the transaction (excluding the signature for now)
		txBytes, _ := json.Marshal(tx)

		// Sign the serialized transaction data directly with Ed25519 (no separate hashing needed)
		signature := ed25519.Sign(privateKey, txBytes)

		// Verify the signature with the Ed25519 public key
		if !ed25519.Verify(publicKey, txBytes, signature) {
			t.Fatalf("Signature verification failed at transaction %d", i)
		}
	}

	elapsed := time.Since(start)
	tps := float64(numTransactions) / elapsed.Seconds()

	t.Logf("Processed %d transactions in %s. TPS: %f", numTransactions, elapsed, tps)
}

// Testing both Dilitium and Ed25519
// go test -v -timeout 30s -run ^TestTransactionThroughputWithDualSignatures$ Thrylos/core
func TestTransactionThroughputWithDualSignatures(t *testing.T) {
	// Generate Ed25519 keys
	edPublicKey, edPrivateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("Error generating Ed25519 key pair: %v", err)
	}

	// Generate Dilithium keys
	diPublicKeyBytes, diPrivateKeyBytes, err := shared.GenerateDilithiumKeys()
	if err != nil {
		t.Fatalf("Error generating Dilithium keys: %v", err)
	}
	diPrivateKey := dilithium.Mode3.PrivateKeyFromBytes(diPrivateKeyBytes)
	diPublicKey := dilithium.Mode3.PublicKeyFromBytes(diPublicKeyBytes)

	// Define the number of transactions and the size of each batch
	numTransactions := 1000
	batchSize := 10 // Define an appropriate batch size

	start := time.Now()

	var wg sync.WaitGroup

	// Process transactions in batches
	for i := 0; i < numTransactions; i += batchSize {
		wg.Add(1)
		go func(startIndex int) {
			defer wg.Done()
			for j := startIndex; j < startIndex+batchSize && j < numTransactions; j++ {
				// Simulate creating a transaction
				txID := fmt.Sprintf("tx%d", j)
				inputs := []shared.UTXO{{TransactionID: "tx0", Index: 0, OwnerAddress: "Alice", Amount: 100}}
				outputs := []shared.UTXO{{TransactionID: txID, Index: 0, OwnerAddress: "Bob", Amount: 100}}
				tx := shared.Transaction{ID: txID, Inputs: inputs, Outputs: outputs, Timestamp: time.Now().Unix()}

				// Serialize the transaction for signing
				txBytes, _ := json.Marshal(tx)

				// Sign the serialized transaction data with both Ed25519 and Dilithium
				edSignature := ed25519.Sign(edPrivateKey, txBytes)
				diSignature := dilithium.Mode3.Sign(diPrivateKey, txBytes)

				// Verify both signatures
				if !ed25519.Verify(edPublicKey, txBytes, edSignature) {
					t.Errorf("Ed25519 signature verification failed at transaction %d", j)
				}
				if !dilithium.Mode3.Verify(diPublicKey, txBytes, diSignature) {
					t.Errorf("Dilithium signature verification failed at transaction %d", j)
				}
			}
		}(i)
	}

	wg.Wait()

	elapsed := time.Since(start)
	tps := float64(numTransactions) / elapsed.Seconds()

	t.Logf("Processed %d dual-signed transactions in %s. TPS: %f", numTransactions, elapsed, tps)
}

// go test -v -timeout 30s -run ^TestTransactionThroughputWitSignatures$ Thrylos/core

func TestTransactionThroughputWitSignatures(t *testing.T) {
	// Generate Ed25519 keys
	edPublicKey, edPrivateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("Error generating Ed25519 key pair: %v", err)
	}

	// Define the number of transactions and the size of each batch
	numTransactions := 1000
	batchSize := 10 // Define an appropriate batch size

	start := time.Now()

	var wg sync.WaitGroup

	// Process transactions in batches
	for i := 0; i < numTransactions; i += batchSize {
		wg.Add(1)
		go func(startIndex int) {
			defer wg.Done()
			for j := startIndex; j < startIndex+batchSize && j < numTransactions; j++ {
				// Simulate creating a transaction
				txID := fmt.Sprintf("tx%d", j)
				inputs := []shared.UTXO{{TransactionID: "tx0", Index: 0, OwnerAddress: "Alice", Amount: 100}}
				outputs := []shared.UTXO{{TransactionID: txID, Index: 0, OwnerAddress: "Bob", Amount: 100}}
				tx := shared.Transaction{ID: txID, Inputs: inputs, Outputs: outputs, Timestamp: time.Now().Unix()}

				// Serialize the transaction for signing
				txBytes, _ := json.Marshal(tx)

				// Sign the serialized transaction data with both Ed25519 and Dilithium
				edSignature := ed25519.Sign(edPrivateKey, txBytes)

				// Verify both signatures
				if !ed25519.Verify(edPublicKey, txBytes, edSignature) {
					t.Errorf("Ed25519 signature verification failed at transaction %d", j)
				}
			}
		}(i)
	}

	wg.Wait()

	elapsed := time.Since(start)
	tps := float64(numTransactions) / elapsed.Seconds()

	t.Logf("Processed %d dual-signed transactions in %s. TPS: %f", numTransactions, elapsed, tps)
}

// Mock data for simplicity
const numberOfTransactions = 100

func TestDAGTransactionsProcessing(t *testing.T) {
	// Generate Ed25519 keys for transaction signing
	publicKey, privateKey, err := shared.GenerateEd25519Keys()
	if err != nil {
		t.Fatalf("Failed to generate Ed25519 keys: %v", err)
	}

	// Generate Dilithium keys for transaction signing
	dilithiumPublicKey, dilithiumPrivateKey, err := shared.GenerateDilithiumKeys()
	if err != nil {
		t.Fatalf("Failed to generate Dilithium keys: %v", err)
	}

	// Simulate creating and processing a series of transactions in a DAG structure
	var previousTxIds []string // To simulate linking in a DAG
	for i := 0; i < 100; i++ { // Example: Process 100 transactions
		txID := fmt.Sprintf("tx%d", i)

		// Create a new transaction with selected previous transaction IDs
		tx, err := shared.CreateAndSignTransaction(txID, []shared.UTXO{{TransactionID: "input", Index: 0, OwnerAddress: "Alice", Amount: 100}},
			[]shared.UTXO{{TransactionID: txID, Index: 0, OwnerAddress: "Bob", Amount: 100}}, privateKey, dilithiumPrivateKey)
		if err != nil {
			t.Fatalf("Failed to create and sign transaction: %v", err)
		}
		tx.PreviousTxIds = previousTxIds // Link to previous transactions

		// Convert shared.Transaction (local type) to thrylos.Transaction for signature verification
		thrylosTx, err := shared.ConvertLocalTransactionToThrylosTransaction(*tx)
		if err != nil {
			t.Fatalf("Failed to convert transaction for verification: %v", err)
		}

		// Verify the signatures using the converted transaction
		err = shared.VerifyTransactionSignature(thrylosTx, publicKey, dilithiumPublicKey)
		if err != nil {
			t.Errorf("Verification failed for transaction %s: %v", tx.ID, err)
		}

		// Assuming a transaction is successfully processed, add its ID to previousTxIds for future transactions to reference
		previousTxIds = append(previousTxIds, txID)
	}
}
