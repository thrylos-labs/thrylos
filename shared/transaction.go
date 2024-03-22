package shared

import (
	thrylos "Thrylos"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"strconv"
	"sync"
	"time"

	"google.golang.org/protobuf/proto"
)

// Initialize a cache with a mutex for concurrent access control
var (
	addressCache = make(map[string]string)
	cacheMutex   sync.RWMutex
)

// PublicKeyToAddressWithCache converts an Ed25519 public key to a blockchain address string,
// using SHA-256 hashing, and caches the result.
func PublicKeyToAddressWithCache(pubKey ed25519.PublicKey) string {
	pubKeyStr := hex.EncodeToString(pubKey) // Convert public key to string for map key

	// Try to get the address from cache
	cacheMutex.RLock()
	address, found := addressCache[pubKeyStr]
	cacheMutex.RUnlock()

	if found {
		return address // Return cached address if available
	}

	// Compute the address if not found in cache
	address = computeAddressFromPublicKey(pubKey)

	// Cache the newly computed address
	cacheMutex.Lock()
	addressCache[pubKeyStr] = address
	cacheMutex.Unlock()

	return address
}

// computeAddressFromPublicKey performs the actual computation of the address from a public key.
func computeAddressFromPublicKey(pubKey ed25519.PublicKey) string {
	hash := sha256.Sum256(pubKey)
	return hex.EncodeToString(hash[:])
}

// GenerateEd25519Keys generates a new Ed25519 public/private key pair.
func GenerateEd25519Keys() (ed25519.PublicKey, ed25519.PrivateKey, error) {
	publicKey, privateKey, err := ed25519.GenerateKey(nil)
	if err != nil {
		return nil, nil, err
	}
	return publicKey, privateKey, nil
}

// PublicKeyToAddress converts a given RSA public key to a blockchain address string using SHA-256 hashing.
// The address uniquely identifies a participant or entity within the blockchain network.
func PublicKeyToAddress(pub *rsa.PublicKey) string {
	pubBytes := pub.N.Bytes() // Convert public key to bytes
	hash := sha256.Sum256(pubBytes)
	return hex.EncodeToString(hash[:])
}

// CreateMockSignedTransaction generates a transaction and signs it.
// CreateMockSignedTransaction generates a transaction, serializes it without the signature, signs it, and returns the signed transaction.
func CreateMockSignedTransaction(transactionID string, privateKey ed25519.PrivateKey) (*thrylos.Transaction, error) {
	// Initialize the transaction with all fields except the signature
	tx := &thrylos.Transaction{
		Id:        transactionID,
		Timestamp: time.Now().Unix(),
		Inputs: []*thrylos.UTXO{{
			TransactionId: "tx0",
			Index:         0,
			OwnerAddress:  "Alice",
			Amount:        100,
		}},
		Outputs: []*thrylos.UTXO{{
			TransactionId: transactionID,
			Index:         0,
			OwnerAddress:  "Bob",
			Amount:        100,
		}},
	}

	// Temporarily remove the signature to serialize the transaction for signing
	txForSigning := *tx         // Make a shallow copy
	txForSigning.Signature = "" // Remove the signature for signing

	// Serialize the transaction without the signature
	txBytes, err := proto.Marshal(&txForSigning)
	if err != nil {
		return nil, fmt.Errorf("failed to serialize transaction for signing: %v", err)
	}

	// Sign the serialized transaction data directly with Ed25519 (no hashing needed)
	signature := ed25519.Sign(privateKey, txBytes)
	if signature == nil {
		return nil, fmt.Errorf("failed to sign transaction")
	}

	// Encode the signature in base64 and attach it to the original transaction object
	tx.Signature = base64.StdEncoding.EncodeToString(signature)

	return tx, nil
}

// HashData hashes input data using SHA-256 and returns the hash as a byte slice.
func HashData(data []byte) []byte {
	hash := sha256.Sum256(data)
	return hash[:]
}

// Transaction defines the structure for blockchain transactions, including its inputs, outputs, a unique identifier,
// and an optional signature. Transactions are the mechanism through which value is transferred within the blockchain.
type Transaction struct {
	ID        string
	Timestamp int64
	Inputs    []UTXO
	Outputs   []UTXO
	Signature string
}

// CreateAndSignTransaction generates a new transaction and signs it with the sender's private Ed25519 key.
func CreateAndSignTransaction(id string, inputs []UTXO, outputs []UTXO, privKey ed25519.PrivateKey) (Transaction, error) {
	tx := NewTransaction(id, inputs, outputs) // Create the transaction

	// Sign the transaction directly using the Ed25519 private key
	signature, err := SignTransaction(tx, privKey)
	if err != nil {
		return Transaction{}, err
	}

	tx.Signature = signature // Attach the encoded signature to the transaction
	return tx, nil
}

// SignTransaction creates a digital signature for a transaction using the sender's private RSA key.
// The signature is created by first hashing the transaction data, then signing the hash with the private key.
// SignTransaction creates a digital signature for a transaction using the sender's private RSA key.
func SignTransaction(tx Transaction, privateKey ed25519.PrivateKey) (string, error) {
	// Serialize transaction without the signature
	txData, err := json.Marshal(tx)
	if err != nil {
		return "", err
	}

	// Ed25519 does the hashing as part of the signing process
	signature := ed25519.Sign(privateKey, txData)

	return base64.StdEncoding.EncodeToString(signature), nil
}

// SerializeWithoutSignature generates a JSON representation of the transaction without including the signature.
// This is useful for verifying the transaction signature, as the signature itself cannot be part of the signed data.
func (tx *Transaction) SerializeWithoutSignature() ([]byte, error) {
	type TxTemp struct {
		ID        string
		Inputs    []UTXO
		Outputs   []UTXO
		Timestamp int64
	}
	temp := TxTemp{
		ID:        tx.ID,
		Inputs:    tx.Inputs,
		Outputs:   tx.Outputs,
		Timestamp: tx.Timestamp,
	}
	return json.Marshal(temp)
}

// VerifyTransactionSignature verifies the signature of a given transaction using an Ed25519 public key.
func VerifyTransactionSignature(tx *thrylos.Transaction, pubKey ed25519.PublicKey) error {
	// Clone the transaction to avoid modifying the original
	txCopy := proto.Clone(tx).(*thrylos.Transaction)
	// Clear the signature for serialization
	txCopy.Signature = ""

	// Serialize the transaction without the signature
	txBytes, err := proto.Marshal(txCopy)
	if err != nil {
		return fmt.Errorf("failed to serialize transaction for verification: %v", err)
	}

	// Decode the signature from Base64
	sigBytes, err := base64.StdEncoding.DecodeString(tx.Signature)
	if err != nil {
		return fmt.Errorf("failed to decode signature: %v", err)
	}

	// Verify the signature with the public key
	if !ed25519.Verify(pubKey, txBytes, sigBytes) {
		return fmt.Errorf("signature verification failed")
	}

	return nil // Signature is valid
}

// VerifyTransaction ensures the overall validity of a transaction, including the correctness of its signature,
// the existence and ownership of UTXOs in its inputs, and the equality of input and output values.
func VerifyTransaction(tx *thrylos.Transaction, utxos map[string][]*thrylos.UTXO, getPublicKeyFunc func(address string) (ed25519.PublicKey, error)) (bool, error) {
	// Check if there are any inputs in the transaction
	if len(tx.GetInputs()) == 0 {
		return false, errors.New("Transaction has no inputs")
	}

	// Assuming all inputs come from the same sender for simplicity
	senderAddress := tx.GetInputs()[0].GetOwnerAddress()
	senderPublicKey, err := getPublicKeyFunc(senderAddress)
	if err != nil {
		return false, fmt.Errorf("Error retrieving public key for address %s: %v", senderAddress, err)
	}

	// Make a copy of the transaction to manipulate for verification
	txCopy := proto.Clone(tx).(*thrylos.Transaction)
	txCopy.Signature = "" // Reset signature for serialization

	// Serialize the transaction for verification
	txBytes, err := proto.Marshal(txCopy)
	if err != nil {
		return false, fmt.Errorf("Error serializing transaction for verification: %v", err)
	}

	// Log the serialized transaction data without the signature
	log.Printf("Serialized transaction for verification: %x", txBytes)

	// Verify the transaction signature
	err = VerifyTransactionSignature(tx, senderPublicKey)
	if err != nil {
		return false, fmt.Errorf("Transaction signature verification failed: %v", err)
	}

	// Check the UTXOs to verify they exist and calculate the input sum
	inputSum := int64(0)
	for _, input := range tx.GetInputs() {
		utxoKey := fmt.Sprintf("%s-%d", input.GetTransactionId(), input.GetIndex())
		utxoSlice, exists := utxos[utxoKey]
		if !exists || len(utxoSlice) == 0 {
			return false, fmt.Errorf("Input UTXO %s not found", utxoKey)
		}

		// Assuming the first UTXO in the slice is the correct one
		inputSum += utxoSlice[0].GetAmount()
	}

	// Calculate the output sum
	outputSum := int64(0)
	for _, output := range tx.GetOutputs() {
		outputSum += output.GetAmount()
	}

	// Verify if the input sum matches the output sum
	if inputSum != outputSum {
		return false, fmt.Errorf("Failed to validate transaction %s: Input sum (%d) does not match output sum (%d)", tx.GetId(), inputSum, outputSum)
	}

	return true, nil
}

// NewTransaction creates a new Transaction instance with the specified ID, inputs, outputs, and records
func NewTransaction(id string, inputs []UTXO, outputs []UTXO) Transaction {
	// Log the inputs and outputs for debugging
	fmt.Printf("Creating new transaction with ID: %s\n", id)
	fmt.Printf("Inputs: %+v\n", inputs)
	fmt.Printf("Outputs: %+v\n", outputs)

	return Transaction{
		ID:        id,
		Inputs:    inputs,
		Outputs:   outputs,
		Timestamp: time.Now().Unix(),
	}

}

// ValidateTransaction checks the internal consistency of a transaction, ensuring that the sum of inputs matches the sum of outputs.
// It is a crucial part of ensuring no value is created out of thin air within the blockchain system.
// ValidateTransaction checks the internal consistency of a transaction,
// ensuring that the sum of inputs matches the sum of outputs.
func ValidateTransaction(tx Transaction, availableUTXOs map[string][]UTXO) bool {
	inputSum := 0
	for _, input := range tx.Inputs {
		// Construct the key used to find the UTXOs for this input.
		utxoKey := input.TransactionID + strconv.Itoa(input.Index)
		utxos, exists := availableUTXOs[utxoKey]

		if !exists || len(utxos) == 0 {
			fmt.Println("Input UTXO not found or empty slice:", utxoKey)
			return false
		}

		// Iterate through the UTXOs for this input. Assuming the first UTXO in the slice is the correct one.
		// You may need to adjust this logic based on your application's requirements.
		inputSum += utxos[0].Amount
	}

	outputSum := 0
	for _, output := range tx.Outputs {
		outputSum += output.Amount
	}

	if inputSum != outputSum {
		fmt.Printf("Input sum (%d) does not match output sum (%d).\n", inputSum, outputSum)
		return false
	}

	return true
}
