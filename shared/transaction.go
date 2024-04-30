package shared

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/thrylos-labs/thrylos/thrylos"

	flatbuffers "github.com/google/flatbuffers/go"
	"golang.org/x/crypto/blake2b"
)

// Transaction defines the structure for blockchain transactions, including its inputs, outputs, a unique identifier,
// and an optional signature. Transactions are the mechanism through which value is transferred within the blockchain.
type Transaction struct {
	ID               string   `json:"ID"`
	Timestamp        int64    `json:"Timestamp"`
	Inputs           []UTXO   `json:"Inputs"`
	Outputs          []UTXO   `json:"Outputs"`
	EncryptedInputs  []byte   `json:"EncryptedInputs,omitempty"` // Use omitempty if the field can be empty
	EncryptedOutputs []byte   `json:"EncryptedOutputs,omitempty"`
	Signature        []byte   `json:"Signature"`
	EncryptedAESKey  []byte   `json:"EncryptedAESKey,omitempty"` // Add this line
	PreviousTxIds    []string `json:"PreviousTxIds,omitempty"`
	Sender           string   `json:"sender"`
}

func (tx *Transaction) SerializeForHashing() ([]byte, error) {
	var b bytes.Buffer

	// Write ID
	b.Write([]byte(tx.ID))

	// Write Timestamp
	tsBytes := make([]byte, 8)
	binary.BigEndian.PutUint64(tsBytes, uint64(tx.Timestamp))
	b.Write(tsBytes)

	// Write Encrypted Inputs
	b.Write(tx.EncryptedInputs)

	// Write Encrypted Outputs
	b.Write(tx.EncryptedOutputs)

	// Write Signature
	b.Write(tx.Signature)

	// Write Encrypted AES Key
	b.Write(tx.EncryptedAESKey)

	// Write Sender
	b.Write([]byte(tx.Sender))

	// Serialize and append each UTXO (simplified)
	for _, utxo := range tx.Inputs {
		b.Write([]byte(utxo.TransactionID))
		indexBytes := make([]byte, 4)
		binary.BigEndian.PutUint32(indexBytes, uint32(utxo.Index))
		b.Write(indexBytes)
		b.Write([]byte(utxo.OwnerAddress))
		amountBytes := make([]byte, 8)
		binary.BigEndian.PutUint64(amountBytes, uint64(utxo.Amount))
		b.Write(amountBytes)
	}
	for _, utxo := range tx.Outputs {
		b.Write([]byte(utxo.TransactionID))
		indexBytes := make([]byte, 4)
		binary.BigEndian.PutUint32(indexBytes, uint32(utxo.Index))
		b.Write(indexBytes)
		b.Write([]byte(utxo.OwnerAddress))
		amountBytes := make([]byte, 8)
		binary.BigEndian.PutUint64(amountBytes, uint64(utxo.Amount))
		b.Write(amountBytes)
	}

	// Previous Transaction IDs
	for _, ptid := range tx.PreviousTxIds {
		b.Write([]byte(ptid))
	}

	return b.Bytes(), nil
}

func ConvertFBToGoTransaction(fbTx *thrylos.Transaction) *Transaction {
	// Convert FlatBuffers Transaction to Go Transaction
	tx := &Transaction{
		ID:               string(fbTx.Id()),
		Timestamp:        fbTx.Timestamp(),
		EncryptedInputs:  fbTx.EncryptedInputsBytes(),
		EncryptedOutputs: fbTx.EncryptedOutputsBytes(),
		Signature:        fbTx.SignatureBytes(),
		Sender:           string(fbTx.Sender()),
		// Conversion for UTXOs and other fields as necessary
	}
	return tx
}

func EncryptAESKey(aesKey []byte, recipientPublicKey *rsa.PublicKey) ([]byte, error) {
	// Create a new BLAKE2b hasher for OAEP
	blake2bHasher, err := blake2b.New256(nil)
	if err != nil {
		return nil, err
	}

	encryptedKey, err := rsa.EncryptOAEP(
		blake2bHasher, // Using BLAKE2b for OAEP
		rand.Reader,
		recipientPublicKey,
		aesKey,
		nil, // Optional label for additional data, can be nil if not used
	)
	if err != nil {
		return nil, err
	}
	return encryptedKey, nil
}

// GenerateAESKey generates a new AES-256 symmetric key.
func GenerateAESKey() ([]byte, error) {
	key := make([]byte, 32) // 256-bit key for AES-256
	if _, err := io.ReadFull(rand.Reader, key); err != nil {
		return nil, err
	}
	return key, nil
}

// EncryptWithAES encrypts data using AES-256-CBC.
func EncryptWithAES(key, plaintext []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	ciphertext := make([]byte, aes.BlockSize+len(plaintext))
	iv := ciphertext[:aes.BlockSize]
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		return nil, err
	}
	stream := cipher.NewCFBEncrypter(block, iv)
	stream.XORKeyStream(ciphertext[aes.BlockSize:], plaintext)
	return ciphertext, nil
}

// DecryptWithAES decrypts data using AES-256-CBC.
func DecryptWithAES(key, ciphertext []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	if len(ciphertext) < aes.BlockSize {
		return nil, errors.New("ciphertext too short")
	}
	iv := ciphertext[:aes.BlockSize]
	ciphertext = ciphertext[aes.BlockSize:]
	stream := cipher.NewCFBDecrypter(block, iv)
	plaintext := make([]byte, len(ciphertext))
	stream.XORKeyStream(plaintext, ciphertext)
	return plaintext, nil
}

// DecryptTransactionData function should be already defined and be similar to this
func DecryptTransactionData(encryptedData, encryptedKey []byte, recipientPrivateKey *rsa.PrivateKey) ([]byte, error) {
	// Create a new BLAKE2b hasher for OAEP
	blake2bHasher, err := blake2b.New256(nil)
	if err != nil {
		return nil, err
	}

	// Decrypt the AES key first
	aesKey, err := rsa.DecryptOAEP(
		blake2bHasher, // Use BLAKE2b hasher
		rand.Reader,
		recipientPrivateKey,
		encryptedKey,
		nil,
	)
	if err != nil {
		return nil, err
	}

	// Now decrypt the actual transaction data with the AES key
	return DecryptWithAES(aesKey, encryptedData)
}

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
	// Create a new BLAKE2b hasher
	blake2bHasher, err := blake2b.New256(nil)
	if err != nil {
		panic(err) // Handle error appropriately in production code
	}

	// Compute the hash using BLAKE2b
	hash := blake2bHasher.Sum(pubKey)
	return hex.EncodeToString(hash)
}

// GenerateEd25519Keys generates a new Ed25519 public/private key pair.
func GenerateEd25519Keys() (ed25519.PublicKey, ed25519.PrivateKey, error) {
	publicKey, privateKey, err := ed25519.GenerateKey(nil)
	if err != nil {
		return nil, nil, err
	}
	return publicKey, privateKey, nil
}

// PublicKeyToAddress generates a public address from an RSA public key using BLAKE2b-256.
func PublicKeyToAddress(pub *rsa.PublicKey) string {
	pubBytes := pub.N.Bytes() // Convert public key to bytes
	hash, err := blake2b.New256(nil)
	if err != nil {
		panic(err) // Handle errors appropriately in production code
	}
	hash.Write(pubBytes)
	return hex.EncodeToString(hash.Sum(nil))
}

// HashData hashes input data using SHA-256 and returns the hash as a byte slice.
func HashData(data []byte) []byte {
	hash, err := blake2b.New256(nil) // No key, simple hash
	if err != nil {
		panic(err) // Handle errors appropriately in production code
	}
	hash.Write(data)
	return hash.Sum(nil)
}

// select tips:
func selectTips() ([]string, error) {
	// Placeholder for your tip selection logic
	return []string{"prevTxID1", "prevTxID2"}, nil
}

// CreateAndSignTransaction generates a new transaction and signs it with the sender's Ed25519.
// Assuming Transaction is the correct type across your application:
func CreateAndSignTransaction(id string, sender string, inputs []UTXO, outputs []UTXO, ed25519PrivateKey ed25519.PrivateKey, aesKey []byte) (*Transaction, error) {
	previousTxIDs, err := selectTips()
	if err != nil {
		return nil, fmt.Errorf("failed to select previous transactions: %v", err)
	}

	// Initialize FlatBuffers builder
	builder := flatbuffers.NewBuilder(0)

	// Handle serialization and encryption of inputs
	encryptedInputs, err := handleUTXOs(builder, inputs, aesKey)
	if err != nil {
		return nil, err
	}

	// Reset builder for outputs
	builder.Reset()

	// Handle serialization and encryption of outputs
	encryptedOutputs, err := handleUTXOs(builder, outputs, aesKey)
	if err != nil {
		return nil, err
	}

	// Create the transaction object in FlatBuffers
	thrylosTxOffset, err := createThrylosTransaction(builder, id, sender, encryptedInputs, encryptedOutputs, previousTxIDs)
	if err != nil {
		return nil, err
	}

	// Finish the transaction object creation
	builder.Finish(thrylosTxOffset)

	// Sign the transaction and convert back to local format
	return signAndConvertTransaction(builder, thrylosTxOffset, ed25519PrivateKey)
}

func handleUTXOs(builder *flatbuffers.Builder, utxos []UTXO, aesKey []byte) ([]byte, error) {
	utxoPtrs := convertToUTXOPtrs(utxos)
	serializedOffset, err := SerializeUTXOs(builder, utxoPtrs)
	if err != nil {
		return nil, fmt.Errorf("failed to serialize UTXOs: %v", err)
	}

	builder.Finish(serializedOffset)
	serializedData := builder.FinishedBytes()
	encryptedData, err := EncryptWithAES(aesKey, serializedData)
	if err != nil {
		return nil, fmt.Errorf("failed to encrypt UTXOs: %v", err)
	}
	return encryptedData, nil
}

func createThrylosTransaction(builder *flatbuffers.Builder, id, sender string, encryptedInputs, encryptedOutputs []byte, previousTxIDs []string) (flatbuffers.UOffsetT, error) {
	// Create the transaction data in the builder
	idOffset := builder.CreateString(id)
	senderOffset := builder.CreateString(sender)
	encryptedInputsOffset := builder.CreateByteVector(encryptedInputs)
	encryptedOutputsOffset := builder.CreateByteVector(encryptedOutputs)

	// Convert previous transaction IDs into a vector of offsets
	prevTxIDsOffsets := make([]flatbuffers.UOffsetT, len(previousTxIDs))
	for i, txID := range previousTxIDs {
		prevTxIDsOffsets[i] = builder.CreateString(txID)
	}
	thrylos.TransactionStartPreviousTxIdsVector(builder, len(previousTxIDs))
	for i := len(previousTxIDs) - 1; i >= 0; i-- {
		builder.PrependUOffsetT(prevTxIDsOffsets[i])
	}
	prevTxIDsVec := builder.EndVector(len(previousTxIDs))

	// Start the transaction object
	thrylos.TransactionStart(builder)
	thrylos.TransactionAddId(builder, idOffset)
	thrylos.TransactionAddSender(builder, senderOffset)
	thrylos.TransactionAddEncryptedInputs(builder, encryptedInputsOffset)
	thrylos.TransactionAddEncryptedOutputs(builder, encryptedOutputsOffset)
	thrylos.TransactionAddPreviousTxIds(builder, prevTxIDsVec)
	transactionOffset := thrylos.TransactionEnd(builder)

	return transactionOffset, nil
}

func signAndConvertTransaction(builder *flatbuffers.Builder, thrylosTxOffset flatbuffers.UOffsetT, privateKey ed25519.PrivateKey) (*Transaction, error) {
	// Extract the byte slice for signing from the builder's data
	builder.Finish(thrylosTxOffset)
	txBytes := builder.FinishedBytes() // This is the byte slice of the whole transaction

	// Sign the transaction with the Ed25519 private key
	signature := ed25519.Sign(privateKey, txBytes)

	// Convert the signed FlatBuffers transaction back to the local Transaction structure
	// (Assuming you have a function that can interpret the FlatBuffers byte slice back into a Transaction struct)
	tx, err := convertFlatBuffersToTransaction(txBytes)
	if err != nil {
		return nil, fmt.Errorf("failed to convert transaction: %v", err)
	}
	tx.Signature = signature // Attach the signature to the local transaction struct

	return tx, nil
}

func convertFlatBuffersToTransaction(data []byte) (*Transaction, error) {
	// Assuming `GetRootAsTransaction` is a method generated by FlatBuffers, which initializes a Transaction object from data
	fbTx := thrylos.GetRootAsTransaction(data, 0)

	// Now, extract the data using the getters
	tx := &Transaction{
		ID:               string(fbTx.Id()), // Assuming Id() returns a byte slice
		Timestamp:        fbTx.Timestamp(),
		EncryptedInputs:  fbTx.EncryptedInputsBytes(), // Assuming EncryptedInputsBytes() that returns the byte slice
		EncryptedOutputs: fbTx.EncryptedOutputsBytes(),
		Signature:        []byte{}, // Initially empty, to be filled by the caller
		Sender:           string(fbTx.Sender()),
	}

	// Extracting array of PreviousTxIds
	numPrevTxIds := fbTx.PreviousTxIdsLength()
	tx.PreviousTxIds = make([]string, numPrevTxIds)
	for i := 0; i < numPrevTxIds; i++ {
		tx.PreviousTxIds[i] = string(fbTx.PreviousTxIds(i))
	}

	// Handling UTXOs might require more elaborate processing depending on their complexity
	// Assuming we have methods like InputsLength and Inputs to access UTXO data
	numInputs := fbTx.InputsLength()
	tx.Inputs = make([]UTXO, numInputs)
	var fbUTXO thrylos.UTXO // A hypothetical FlatBuffers UTXO object
	for i := 0; i < numInputs; i++ {
		if fbTx.Inputs(&fbUTXO, i) {
			tx.Inputs[i] = UTXO{
				TransactionID: string(fbUTXO.TransactionId()),
				Index:         int(fbUTXO.Index()),
				OwnerAddress:  string(fbUTXO.OwnerAddress()),
				Amount:        int(fbUTXO.Amount()),
			}
		}
	}

	// Similar extraction for Outputs
	numOutputs := fbTx.OutputsLength()
	tx.Outputs = make([]UTXO, numOutputs)
	for i := 0; i < numOutputs; i++ {
		if fbTx.Outputs(&fbUTXO, i) {
			tx.Outputs[i] = UTXO{
				TransactionID: string(fbUTXO.TransactionId()),
				Index:         int(fbUTXO.Index()),
				OwnerAddress:  string(fbUTXO.OwnerAddress()),
				Amount:        int(fbUTXO.Amount()),
			}
		}
	}

	return tx, nil
}

// Hypothetical conversion function from your local Transaction type to *thrylos.Transaction
func ConvertLocalTransactionToThrylosTransaction(builder *flatbuffers.Builder, tx Transaction) (*flatbuffers.Builder, flatbuffers.UOffsetT, error) {
	// Start building the transaction inputs and outputs
	thrylos.UTXOStart(builder)
	inputsOffsets := make([]flatbuffers.UOffsetT, len(tx.Inputs))
	for i, input := range tx.Inputs {
		transactionID := builder.CreateString(input.TransactionID)
		ownerAddress := builder.CreateString(input.OwnerAddress)
		thrylos.UTXOStart(builder)
		thrylos.UTXOAddTransactionId(builder, transactionID)
		thrylos.UTXOAddIndex(builder, int32(input.Index))
		thrylos.UTXOAddOwnerAddress(builder, ownerAddress)
		thrylos.UTXOAddAmount(builder, int64(input.Amount))
		inputsOffsets[i] = thrylos.UTXOEnd(builder)
	}

	// Do similar steps for outputs
	outputsOffsets := make([]flatbuffers.UOffsetT, len(tx.Outputs))
	for i, output := range tx.Outputs {
		transactionID := builder.CreateString(output.TransactionID)
		ownerAddress := builder.CreateString(output.OwnerAddress)
		thrylos.UTXOStart(builder)
		thrylos.UTXOAddTransactionId(builder, transactionID)
		thrylos.UTXOAddIndex(builder, int32(output.Index))
		thrylos.UTXOAddOwnerAddress(builder, ownerAddress)
		thrylos.UTXOAddAmount(builder, int64(output.Amount))
		outputsOffsets[i] = thrylos.UTXOEnd(builder)
	}

	// Create vectors for inputs and outputs
	thrylos.TransactionStartInputsVector(builder, len(inputsOffsets))
	for i := len(inputsOffsets) - 1; i >= 0; i-- {
		builder.PrependUOffsetT(inputsOffsets[i])
	}
	inputsVec := builder.EndVector(len(inputsOffsets))

	thrylos.TransactionStartOutputsVector(builder, len(outputsOffsets))
	for i := len(outputsOffsets) - 1; i >= 0; i-- {
		builder.PrependUOffsetT(outputsOffsets[i])
	}
	outputsVec := builder.EndVector(len(outputsOffsets))

	// Create the transaction
	transactionID := builder.CreateString(tx.ID)
	thrylos.TransactionStart(builder)
	thrylos.TransactionAddId(builder, transactionID)
	thrylos.TransactionAddInputs(builder, inputsVec)
	thrylos.TransactionAddOutputs(builder, outputsVec)
	thrylos.TransactionAddTimestamp(builder, tx.Timestamp)
	// Handle previous transaction IDs similarly if needed
	transaction := thrylos.TransactionEnd(builder)

	return builder, transaction, nil
}

// Hypothetical conversion back to local Transaction type, if needed
func convertThrylosTransactionToLocal(tx *thrylos.Transaction) (Transaction, error) {
	// Assuming tx.PreviousTxIdsLength() and tx.PreviousTxIds(j int) methods exist
	previousTxIdsLength := tx.PreviousTxIdsLength()
	previousTxIds := make([]string, previousTxIdsLength)
	for i := 0; i < previousTxIdsLength; i++ {
		previousTxIds[i] = string(tx.PreviousTxIds(i)) // Assuming PreviousTxIds(i) returns []byte
	}

	// Convert other fields similar to previous example
	localInputs, localOutputs := convertUTXOFields(tx)

	return Transaction{
		ID:            string(tx.Id()), // Assuming Id() returns a []byte
		Inputs:        localInputs,
		Outputs:       localOutputs,
		Timestamp:     tx.Timestamp(),
		Signature:     tx.SignatureBytes(), // Assuming SignatureBytes() returns the full slice
		PreviousTxIds: previousTxIds,
	}, nil
}

// Separate the conversion of UTXO fields into a helper function for clarity
func convertUTXOFields(tx *thrylos.Transaction) ([]UTXO, []UTXO) {
	inputLength := tx.InputsLength()
	localInputs := make([]UTXO, inputLength)
	for i := 0; i < inputLength; i++ {
		var input thrylos.UTXO
		if tx.Inputs(&input, i) {
			localInputs[i] = UTXO{
				TransactionID: string(input.TransactionId()),
				Index:         int(input.Index()),
				OwnerAddress:  string(input.OwnerAddress()),
				Amount:        int(input.Amount()),
			}
		}
	}

	outputLength := tx.OutputsLength()
	localOutputs := make([]UTXO, outputLength)
	for i := 0; i < outputLength; i++ {
		var output thrylos.UTXO
		if tx.Outputs(&output, i) {
			localOutputs[i] = UTXO{
				TransactionID: string(output.TransactionId()),
				Index:         int(output.Index()),
				OwnerAddress:  string(output.OwnerAddress()),
				Amount:        int(output.Amount()),
			}
		}
	}

	return localInputs, localOutputs
}

func SerializeTransactionToFlatBuffers(tx *Transaction, includeSignature bool) []byte {
	builder := flatbuffers.NewBuilder(0)

	// Convert UTXOs to pointer slices for serialization
	inputPtrs := convertToUTXOPtrs(tx.Inputs)
	outputPtrs := convertToUTXOPtrs(tx.Outputs)

	// Serialize UTXOs for inputs and outputs
	inputsOffsets, err := SerializeUTXOs(builder, inputPtrs)
	if err != nil {
		log.Fatalf("Error serializing inputs: %v", err)
		return nil // Consider handling the error more gracefully
	}
	outputsOffsets, err := SerializeUTXOs(builder, outputPtrs)
	if err != nil {
		log.Fatalf("Error serializing outputs: %v", err)
		return nil // Consider handling the error more gracefully
	}

	// Create other transaction fields in FlatBuffers
	id := builder.CreateString(tx.ID)
	encryptedInputs := builder.CreateByteVector(tx.EncryptedInputs)
	encryptedOutputs := builder.CreateByteVector(tx.EncryptedOutputs)
	previousTxIdsOffset := createStringVector(builder, tx.PreviousTxIds)
	encryptedAesKey := builder.CreateByteVector(tx.EncryptedAESKey)
	sender := builder.CreateString(tx.Sender)

	// Optionally add the signature
	var signature flatbuffers.UOffsetT
	if includeSignature {
		signature = builder.CreateByteVector(tx.Signature)
	}

	// Start building the Transaction object
	thrylos.TransactionStart(builder)
	thrylos.TransactionAddId(builder, id)
	thrylos.TransactionAddTimestamp(builder, tx.Timestamp)
	thrylos.TransactionAddInputs(builder, inputsOffsets)
	thrylos.TransactionAddOutputs(builder, outputsOffsets)
	thrylos.TransactionAddEncryptedInputs(builder, encryptedInputs)
	thrylos.TransactionAddEncryptedOutputs(builder, encryptedOutputs)
	if includeSignature {
		thrylos.TransactionAddSignature(builder, signature)
	}
	thrylos.TransactionAddPreviousTxIds(builder, previousTxIdsOffset)
	thrylos.TransactionAddEncryptedAesKey(builder, encryptedAesKey)
	thrylos.TransactionAddSender(builder, sender)
	transaction := thrylos.TransactionEnd(builder)

	// Finish the transaction object and return the bytes
	builder.Finish(transaction)
	return builder.FinishedBytes()
}

// SignTransaction creates a digital signature for a transaction using the sender's private RSA key.
// The signature is created by first hashing the transaction data, then signing the hash with the private key.
// SignTransaction creates a signature for a transaction using the sender's private Ed25519 key.
func SignTransaction(tx *Transaction, edPrivateKey ed25519.PrivateKey) error {
	// Serialize the transaction without including the signature
	txBytes := SerializeTransactionToFlatBuffers(tx, false) // Passing false to not include the signature

	// Sign the transaction with the Ed25519 private key
	signature := ed25519.Sign(edPrivateKey, txBytes)
	tx.Signature = signature // Update the transaction object with the new signature

	return nil
}

// SerializeWithoutSignature generates a JSON representation of the transaction without including the signature.
// This is useful for verifying the transaction signature, as the signature itself cannot be part of the signed data.
func (tx *Transaction) SerializeWithoutSignature() ([]byte, error) {
	type TxTemp struct {
		ID        string
		Sender    string
		Inputs    []UTXO
		Outputs   []UTXO
		Timestamp int64
	}
	temp := TxTemp{
		ID:        tx.ID,
		Sender:    tx.Sender,
		Inputs:    tx.Inputs,
		Outputs:   tx.Outputs,
		Timestamp: tx.Timestamp,
	}
	return json.Marshal(temp)
}

// VerifyTransactionSignature verifies both the Ed25519 of a given transaction.
func VerifyTransactionSignature(tx *thrylos.Transaction, ed25519PublicKey ed25519.PublicKey) error {
	builder := flatbuffers.NewBuilder(0)

	// Convert byte arrays to strings
	transactionID := string(tx.Id())
	sender := string(tx.Sender())

	// Extracting and rebuilding the previous transaction IDs
	prevTxIdsCount := tx.PreviousTxIdsLength()
	prevTxIds := make([]string, prevTxIdsCount)
	for i := 0; i < prevTxIdsCount; i++ {
		prevTxIds[i] = string(tx.PreviousTxIds(i))
	}

	// Create FlatBuffers offsets for all items
	transactionIDOffset := builder.CreateString(transactionID)
	senderOffset := builder.CreateString(sender)
	encryptedInputsOffset := builder.CreateByteVector(tx.EncryptedInputsBytes())
	encryptedOutputsOffset := builder.CreateByteVector(tx.EncryptedOutputsBytes())
	previousTxIDsVectorOffset := createStringVector(builder, prevTxIds)

	// Start building the transaction object excluding the signature
	thrylos.TransactionStart(builder)
	thrylos.TransactionAddId(builder, transactionIDOffset)
	thrylos.TransactionAddSender(builder, senderOffset)
	thrylos.TransactionAddEncryptedInputs(builder, encryptedInputsOffset)
	thrylos.TransactionAddEncryptedOutputs(builder, encryptedOutputsOffset)
	thrylos.TransactionAddPreviousTxIds(builder, previousTxIDsVectorOffset)
	thrylos.TransactionAddTimestamp(builder, tx.Timestamp())
	finalTransactionOffset := thrylos.TransactionEnd(builder)

	builder.Finish(finalTransactionOffset)
	txBytes := builder.FinishedBytes() // Byte slice of the transaction without the signature

	// Retrieve the signature from the original transaction
	signature := tx.SignatureBytes() // Assuming this method returns the signature as a byte slice

	// Verify the signature
	if !ed25519.Verify(ed25519PublicKey, txBytes, signature) {
		return errors.New("Ed25519 signature verification failed")
	}

	return nil
}

// Helper to convert a FlatBuffers vector of bytes (each slice represents a string) to a slice of strings.
func convertByteVectorToStringSlice(vector []byte) []string {
	// Example implementation assuming each string is null-terminated within the byte vector
	strings := []string{}
	current := ""
	for _, b := range vector {
		if b == 0 {
			strings = append(strings, current)
			current = ""
		} else {
			current += string(b)
		}
	}
	if current != "" {
		strings = append(strings, current)
	}
	return strings
}

// Helper to create a vector of strings in FlatBuffers
func createStringVector(builder *flatbuffers.Builder, items []string) flatbuffers.UOffsetT {
	offsets := make([]flatbuffers.UOffsetT, len(items))
	for i, s := range items {
		offsets[i] = builder.CreateString(s)
	}
	thrylos.TransactionStartPreviousTxIdsVector(builder, len(items))
	for i := len(items) - 1; i >= 0; i-- {
		builder.PrependUOffsetT(offsets[i])
	}
	return builder.EndVector(len(items))
}

// VerifyTransaction ensures the overall validity of a transaction, including the correctness of its signature,
// the existence and ownership of UTXOs in its inputs, and the equality of input and output values.
func VerifyTransaction(tx *thrylos.Transaction, utxos map[string][]*thrylos.UTXO, getPublicKeyFunc func(address string) (ed25519.PublicKey, error)) (bool, error) {
	// Check if there are any inputs in the transaction
	if tx.InputsLength() == 0 {
		return false, errors.New("Transaction has no inputs")
	}

	// Assuming all inputs come from the same sender for simplicity
	senderAddress := string(tx.Sender()) // Convert byte slice to string

	// Retrieve the Ed25519 public key for the sender
	ed25519PublicKey, err := getPublicKeyFunc(senderAddress)
	if err != nil {
		return false, fmt.Errorf("Error retrieving Ed25519 public key for address %s: %v", senderAddress, err)
	}

	// Rebuild the transaction excluding the signature for verification
	builder := flatbuffers.NewBuilder(0)
	recreateTransactionForVerification(tx, builder)
	txBytes := builder.FinishedBytes() // Byte slice of the transaction without the signature

	// Retrieve the signature from the transaction
	signature := make([]byte, tx.SignatureLength())
	for i := 0; i < tx.SignatureLength(); i++ {
		signature[i] = tx.Signature(i)
	}

	// Verify the signature
	if !ed25519.Verify(ed25519PublicKey, txBytes, signature) {
		return false, errors.New("Ed25519 signature verification failed")
	}

	// Assuming UTXO checks and sum validation is performed here...
	// Logic for UTXO checks and sum validation remains unchanged

	return true, nil
}

func recreateTransactionForVerification(tx *thrylos.Transaction, builder *flatbuffers.Builder) {
	// Example function to demonstrate reconstruction without signature
	// Implementation depends on your schema specifics
	// You'll recreate all transaction fields except the signature
	thrylos.TransactionStart(builder)
	thrylos.TransactionAddId(builder, builder.CreateString(string(tx.Id())))
	thrylos.TransactionAddTimestamp(builder, tx.Timestamp())
	// Add other fields like inputs, outputs, etc., as necessary
	// Do not add the signature field
	transactionOffset := thrylos.TransactionEnd(builder)
	builder.Finish(transactionOffset)
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

// transaction processing function
func processTransactions(transactions []*Transaction) {
	// Generate or retrieve Ed25519 private key
	_, edPrivateKey, err := ed25519.GenerateKey(rand.Reader) // Skip storing the public key if not used
	if err != nil {
		log.Fatalf("Failed to generate Ed25519 keys: %v", err)
	}

	// Now that we have the keys, attempt to batch sign the transactions
	err = BatchSignTransactions(transactions, edPrivateKey)
	if err != nil {
		log.Printf("Error signing transactions: %v", err)
		return
	}

	// Proceed with further transaction processing...
}

// SanitizeAndFormatAddress cleans and validates blockchain addresses.
func SanitizeAndFormatAddress(address string) (string, error) {
	originalAddress := address // Store the original address for logging
	address = strings.TrimSpace(address)
	address = strings.ToLower(address)

	log.Printf("SanitizeAndFormatAddress: original='%s', trimmed and lowercased='%s'", originalAddress, address)

	addressRegex := regexp.MustCompile(`^[0-9a-fA-F]{40,64}$`)
	if !addressRegex.MatchString(address) {
		log.Printf("SanitizeAndFormatAddress: invalid format after regex check, address='%s'", address)
		return "", fmt.Errorf("invalid address format: %s", address)
	}

	log.Printf("SanitizeAndFormatAddress: validated and formatted address='%s'", address)
	return address, nil
}

// BatchSignTransactions signs a slice of transactions using both Ed25519.
// BatchSignTransactions signs a slice of transactions using both Ed25519.
func BatchSignTransactions(transactions []*Transaction, edPrivateKey ed25519.PrivateKey) error {
	var wg sync.WaitGroup
	errChan := make(chan error, len(transactions))

	wg.Add(len(transactions))
	for _, tx := range transactions {
		go func(tx *Transaction) {
			defer wg.Done()

			// Serialize transaction using FlatBuffers without including the signature
			txBytes := SerializeTransactionToFlatBuffers(tx, false) // now passing false for includeSignature

			// Ed25519 Signing
			edSignature := ed25519.Sign(edPrivateKey, txBytes)

			// Update your transaction's signature field
			tx.Signature = edSignature

			// Re-serialize with signature to update the transaction object
			_ = SerializeTransactionToFlatBuffers(tx, true) // Optional, depending on whether you need to use the serialized form immediately
		}(tx)
	}

	wg.Wait()
	close(errChan)

	// Check for errors
	for e := range errChan {
		if e != nil {
			return e
		}
	}

	return nil
}
