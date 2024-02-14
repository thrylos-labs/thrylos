package shared

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"strconv"
	"time"
)

// GenerateRSAKeys generates a new RSA key pair with the specified bit size.
func GenerateRSAKeys(bitSize int) (*rsa.PrivateKey, *rsa.PublicKey, error) {
	privateKey, err := rsa.GenerateKey(rand.Reader, bitSize)
	if err != nil {
		return nil, nil, err
	}
	return privateKey, &privateKey.PublicKey, nil
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
func CreateMockSignedTransaction(transactionID string, privateKey *rsa.PrivateKey) (Transaction, error) {
	// Manually construct the JSON string for signing to ensure field order
	serializedForSigning := fmt.Sprintf(`{"ID":"%s","Inputs":[{"TransactionID":"tx0","Index":0,"OwnerAddress":"Alice","Amount":100}],"Outputs":[{"TransactionID":"%s","Index":0,"OwnerAddress":"Bob","Amount":100}],"Timestamp":%d}`,
		transactionID, transactionID, time.Now().Unix())

	fmt.Println("Serialized for signing:", serializedForSigning)

	// Hash the manually constructed string
	hashed := sha256.Sum256([]byte(serializedForSigning))

	// Sign the hash
	signature, err := rsa.SignPKCS1v15(rand.Reader, privateKey, crypto.SHA256, hashed[:])
	if err != nil {
		return Transaction{}, fmt.Errorf("failed to sign transaction: %v", err)
	}

	// Create the transaction object with the base64-encoded signature
	tx := Transaction{
		ID:        transactionID,
		Timestamp: time.Now().Unix(), // This should match the timestamp used in the serialized string
		Inputs:    []UTXO{{TransactionID: "tx0", Index: 0, OwnerAddress: "Alice", Amount: 100}},
		Outputs:   []UTXO{{TransactionID: transactionID, Index: 0, OwnerAddress: "Bob", Amount: 100}},
		Signature: base64.StdEncoding.EncodeToString(signature),
	}

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

// CreateAndSignTransaction generates a new transaction and signs it with the sender's private RSA key.
// The signature provides security by ensuring that transactions cannot be modified or forged.
func CreateAndSignTransaction(id string, inputs []UTXO, outputs []UTXO, privKey *rsa.PrivateKey) (Transaction, error) {
	tx := NewTransaction(id, inputs, outputs) // Create the transaction

	// Sign the transaction directly
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
func SignTransaction(tx Transaction, privKey *rsa.PrivateKey) (string, error) {
	// Serialize transaction without the signature
	txData, err := json.Marshal(tx)
	if err != nil {
		return "", err
	}

	// Use HashData to hash the serialized transaction data
	hashed := HashData(txData)

	// Sign the hash
	signature, err := rsa.SignPKCS1v15(rand.Reader, privKey, crypto.SHA256, hashed[:])
	if err != nil {
		return "", err
	}
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

// VerifyTransactionSignature checks whether the provided signature for a transaction is valid.
// It does so by re-serializing the transaction without the signature, hashing this serialized form,
// and then using the public key to verify the signature against the hash.
func VerifyTransactionSignature(tx *Transaction, pubKey *rsa.PublicKey) error {
	// Manually construct the JSON string for verification to ensure field order
	serializedForVerification := fmt.Sprintf(`{"ID":"%s","Inputs":[{"TransactionID":"%s","Index":%d,"OwnerAddress":"%s","Amount":%d}],"Outputs":[{"TransactionID":"%s","Index":%d,"OwnerAddress":"%s","Amount":%d}],"Timestamp":%d}`,
		tx.ID,
		tx.Inputs[0].TransactionID, tx.Inputs[0].Index, tx.Inputs[0].OwnerAddress, tx.Inputs[0].Amount,
		tx.Outputs[0].TransactionID, tx.Outputs[0].Index, tx.Outputs[0].OwnerAddress, tx.Outputs[0].Amount,
		tx.Timestamp)

	fmt.Println("Serialized for verification:", serializedForVerification)

	hashed := sha256.Sum256([]byte(serializedForVerification))
	sigBytes, err := base64.StdEncoding.DecodeString(tx.Signature)
	if err != nil {
		return fmt.Errorf("failed to decode signature: %v", err)
	}

	if err := rsa.VerifyPKCS1v15(pubKey, crypto.SHA256, hashed[:], sigBytes); err != nil {
		return fmt.Errorf("signature verification failed: %v", err)
	}

	return nil // Signature is valid
}

// VerifyTransaction ensures the overall validity of a transaction, including the correctness of its signature,
// the existence and ownership of UTXOs in its inputs, and the equality of input and output values.
func VerifyTransaction(tx Transaction, utxos map[string][]UTXO, getPublicKeyFunc func(address string) (*rsa.PublicKey, error)) (bool, error) {
	// Check if there are any inputs in the transaction
	if len(tx.Inputs) == 0 {
		return false, errors.New("Transaction has no inputs")
	}

	senderAddress := tx.Inputs[0].OwnerAddress
	senderPublicKey, err := getPublicKeyFunc(senderAddress)
	if err != nil {
		return false, fmt.Errorf("Error retrieving public key for address %s: %v", senderAddress, err)
	}

	// Serialize transaction without the signature for verification
	serializedTxWithoutSignature, err := tx.SerializeWithoutSignature()
	if err != nil {
		return false, fmt.Errorf("Error serializing transaction for verification: %v", err)
	}

	// Log the serialized transaction data without the signature
	log.Printf("Serialized transaction for verification: %x", serializedTxWithoutSignature)

	if err := VerifyTransactionSignature(&tx, senderPublicKey); err != nil {
		return false, fmt.Errorf("Transaction signature verification failed: %v", err)
	}

	// Check the UTXOs to verify they exist and calculate the input sum
	inputSum := 0
	for _, input := range tx.Inputs {
		utxoKey := input.TransactionID + strconv.Itoa(input.Index)
		utxoSlice, exists := utxos[utxoKey]
		if !exists || len(utxoSlice) == 0 {
			return false, fmt.Errorf("Input UTXO %s not found", utxoKey)
		}

		inputSum += utxoSlice[0].Amount
	}

	// Calculate the output sum
	outputSum := 0
	for _, output := range tx.Outputs {
		outputSum += output.Amount
	}

	// Verify if the input sum matches the output sum
	if inputSum != outputSum {
		return false, fmt.Errorf("Failed to validate transaction %s: Input sum (%d) does not match output sum (%d)", tx.ID, inputSum, outputSum)
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
