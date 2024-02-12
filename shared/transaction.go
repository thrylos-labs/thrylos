package shared

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"strconv"
	"time"
)

// PublicKeyToAddress converts a given RSA public key to a blockchain address string using SHA-256 hashing.
// The address uniquely identifies a participant or entity within the blockchain network.
func PublicKeyToAddress(pub *rsa.PublicKey) string {
	pubBytes := pub.N.Bytes() // Convert public key to bytes
	hash := sha256.Sum256(pubBytes)
	return hex.EncodeToString(hash[:])
}

// Transaction defines the structure for blockchain transactions, including its inputs, outputs, a unique identifier,
// and an optional signature. Transactions are the mechanism through which value is transferred within the blockchain.
type Transaction struct {
	ID        string `json:"ID"`                  // Unique identifier for the transaction.
	Inputs    []UTXO `json:"Inputs"`              // List of inputs, representing the sources of value (or data) for the transaction.
	Outputs   []UTXO `json:"Outputs"`             // List of outputs, representing the destinations of value (or data) from the transaction.
	Timestamp int64  `json:"Timestamp"`           // Timestamp when the transaction was created.
	Signature string `json:"Signature,omitempty"` // Digital signature to ensure the authenticity and integrity of the transaction.
}

// CreateAndSignTransaction generates a new transaction and signs it with the sender's private RSA key.
// The signature provides security by ensuring that transactions cannot be modified or forged.
func CreateAndSignTransaction(id string, inputs []UTXO, outputs []UTXO, privKey *rsa.PrivateKey) (Transaction, error) {
	tx := NewTransaction(id, inputs, outputs) // Create the transaction
	serializedTx, err := json.Marshal(tx)     // Serialize the transaction excluding the signature
	if err != nil {
		return Transaction{}, err
	}

	// Sign the serialized transaction data
	signature, err := SignTransaction(serializedTx, privKey)
	if err != nil {
		return Transaction{}, err
	}

	tx.Signature = signature // Attach the encoded signature to the transaction
	return tx, nil
}

// SignTransaction creates a digital signature for a transaction using the sender's private RSA key.
// The signature is created by first hashing the transaction data, then signing the hash with the private key.
func SignTransaction(txData []byte, privKey *rsa.PrivateKey) (string, error) {
	hashedData := sha256.Sum256(txData)
	signature, err := rsa.SignPKCS1v15(rand.Reader, privKey, crypto.SHA256, hashedData[:])
	if err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(signature), nil // Encode and return the signature

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

// VerifyTransactionSignature checks whether the provided signature for a transaction is valid.
// It does so by re-serializing the transaction without the signature, hashing this serialized form,
// and then using the public key to verify the signature against the hash.
func VerifyTransactionSignature(tx *Transaction, pubKey *rsa.PublicKey) bool {
	txData, err := tx.SerializeWithoutSignature()
	fmt.Printf("Transaction Timestamp before verification: %d\n", tx.Timestamp)
	if err != nil {
		fmt.Printf("Failed to serialize transaction for verification: %v\n", err)
		return false
	}

	// Decode the base64-encoded signature
	decodedSignature, err := base64.StdEncoding.DecodeString(tx.Signature) // Decode the signature
	if err != nil {
		fmt.Printf("Failed to decode signature: %v\n", err)
		return false
	}

	hashedData := sha256.Sum256(txData)                                                      // Hash the serialized data
	return rsa.VerifyPKCS1v15(pubKey, crypto.SHA256, hashedData[:], decodedSignature) == nil // Verify the signature
}

// VerifyTransaction ensures the overall validity of a transaction, including the correctness of its signature,
// the existence and ownership of UTXOs in its inputs, and the equality of input and output values.
func VerifyTransaction(tx Transaction, utxos map[string][]UTXO, getPublicKeyFunc func(address string) (*rsa.PublicKey, error)) bool {
	// Check if there are any inputs in the transaction
	if len(tx.Inputs) == 0 {
		fmt.Println("Transaction has no inputs")
		return false
	}

	senderAddress := tx.Inputs[0].OwnerAddress
	senderPublicKey, err := getPublicKeyFunc(senderAddress)
	if err != nil {
		fmt.Printf("Error retrieving public key for address %s: %v\n", senderAddress, err)
		return false
	}

	// Serialize transaction without the signature for verification
	serializedTxWithoutSignature, err := tx.SerializeWithoutSignature()
	if err != nil {
		fmt.Printf("Error serializing transaction for verification: %v\n", err)
		return false
	}

	// Log the serialized transaction data without the signature
	log.Printf("Serialized transaction for verification: %x", serializedTxWithoutSignature)

	if !VerifyTransactionSignature(&tx, senderPublicKey) {
		fmt.Println("Transaction signature verification failed.")
		return false
	}

	// Check the UTXOs to verify they exist and calculate the input sum
	inputSum := 0
	for _, input := range tx.Inputs {
		utxoKey := input.TransactionID + strconv.Itoa(input.Index)
		utxoSlice, exists := utxos[utxoKey]
		if !exists || len(utxoSlice) == 0 {
			fmt.Printf("Input UTXO %s not found\n", utxoKey)
			return false
		}

		// Assuming the first UTXO in the slice is the correct one. This logic may need to be adjusted
		// based on how you manage UTXOs that have the same TransactionID and Index.
		inputSum += utxoSlice[0].Amount
	}

	// Calculate the output sum
	outputSum := 0
	for _, output := range tx.Outputs {
		outputSum += output.Amount
	}

	// Verify if the input sum matches the output sum
	if inputSum != outputSum {
		fmt.Printf("Failed to validate transaction %s: Input sum (%d) does not match output sum (%d).\n", tx.ID, inputSum, outputSum)
		return false
	}

	fmt.Printf("Transaction %s validated successfully. Input sum: %d, Output sum: %d\n", tx.ID, inputSum, outputSum)
	return true
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
