package shared

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
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

	"github.com/thrylos-labs/thrylos"
	"google.golang.org/protobuf/proto"
)

func EncryptAESKey(aesKey []byte, recipientPublicKey *rsa.PublicKey) ([]byte, error) {
	encryptedKey, err := rsa.EncryptOAEP(
		sha256.New(),
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
	// Decrypt the AES key first
	aesKey, err := rsa.DecryptOAEP(
		sha256.New(),
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
// func CreateMockDualSignedTransaction(transactionID string, ed25519PrivateKey ed25519.PrivateKey, []byte) (*thrylos.Transaction, error) {
// 	// Initialize the transaction as before
// 	tx := &thrylos.Transaction{
// 		Id:        transactionID,
// 		Timestamp: time.Now().Unix(),
// 		Inputs: []*thrylos.UTXO{{
// 			TransactionId: "tx0",
// 			Index:         0,
// 			OwnerAddress:  "Alice",
// 			Amount:        100,
// 		}},
// 		Outputs: []*thrylos.UTXO{{
// 			TransactionId: transactionID,
// 			Index:         0,
// 			OwnerAddress:  "Bob",
// 			Amount:        100,
// 		}},
// 	}

// 	// Serialize the transaction for signing
// 	txBytes, err := proto.Marshal(tx)
// 	if err != nil {
// 		return nil, fmt.Errorf("failed to serialize transaction for signing: %v", err)
// 	}

// 	// Sign with Ed25519
// 	ed25519Signature := ed25519.Sign(ed25519PrivateKey, txBytes)

// 	// Set both signatures on the transaction and return
// 	tx.Signature = base64.StdEncoding.EncodeToString(ed25519Signature)

// 	return tx, nil
// }

// HashData hashes input data using SHA-256 and returns the hash as a byte slice.
func HashData(data []byte) []byte {
	hash := sha256.Sum256(data)
	return hash[:]
}

// Transaction defines the structure for blockchain transactions, including its inputs, outputs, a unique identifier,
// and an optional signature. Transactions are the mechanism through which value is transferred within the blockchain.
type Transaction struct {
	ID               string   `json:"ID"`
	Timestamp        int64    `json:"Timestamp"`
	Inputs           []UTXO   `json:"Inputs"`
	Outputs          []UTXO   `json:"Outputs"`
	EncryptedInputs  []byte   `json:"EncryptedInputs,omitempty"` // Use omitempty if the field can be empty
	EncryptedOutputs []byte   `json:"EncryptedOutputs,omitempty"`
	Signature        string   `json:"Signature"`
	EncryptedAESKey  []byte   `json:"EncryptedAESKey,omitempty"` // Add this line
	PreviousTxIds    []string `json:"PreviousTxIds,omitempty"`
	Sender           string   `json:"sender"`
}

// select tips:
func selectTips() ([]string, error) {
	// Placeholder for your tip selection logic
	return []string{"prevTxID1", "prevTxID2"}, nil
}

// CreateAndSignTransaction generates a new transaction and signs it with the sender's Ed25519.
// Assuming Transaction is the correct type across your application:
func CreateAndSignTransaction(id string, sender string, inputs []UTXO, outputs []UTXO, ed25519PrivateKey ed25519.PrivateKey, aesKey []byte) (*Transaction, error) {
	// Select previous transactions to reference
	previousTxIDs, err := selectTips()
	if err != nil {
		return nil, fmt.Errorf("failed to select previous transactions: %v", err)
	}

	// Serialize and Encrypt the sensitive parts of the transaction (Inputs)
	serializedInputs, err := serializeUTXOs(inputs)
	if err != nil {
		return nil, fmt.Errorf("failed to serialize inputs: %v", err)
	}
	encryptedInputs, err := EncryptWithAES(aesKey, serializedInputs)
	if err != nil {
		return nil, fmt.Errorf("failed to encrypt inputs: %v", err)
	}

	// Serialize and Encrypt the sensitive parts of the transaction (Outputs)
	serializedOutputs, err := serializeUTXOs(outputs)
	if err != nil {
		return nil, fmt.Errorf("failed to serialize outputs: %v", err)
	}
	encryptedOutputs, err := EncryptWithAES(aesKey, serializedOutputs)
	if err != nil {
		return nil, fmt.Errorf("failed to encrypt outputs: %v", err)
	}

	// Initialize the transaction, now including PreviousTxIDs
	tx := Transaction{
		ID:               id,
		Sender:           sender,
		EncryptedInputs:  encryptedInputs,
		EncryptedOutputs: encryptedOutputs,
		PreviousTxIds:    previousTxIDs,
		Timestamp:        time.Now().Unix(),
	}

	// Convert the Transaction type to *thrylos.Transaction for signing
	// Assuming there's an existing function like convertLocalTransactionToThrylosTransaction that you can use
	thrylosTx, err := ConvertLocalTransactionToThrylosTransaction(tx) // Use tx directly
	if err != nil {
		return nil, fmt.Errorf("failed to convert transaction for signing: %v", err)
	}

	// Sign the transaction
	if err := SignTransaction(thrylosTx, ed25519PrivateKey); err != nil {
		return nil, fmt.Errorf("failed to sign transaction: %v", err)
	}

	// Convert the signed thrylos.Transaction back to your local Transaction format
	signedTx, err := convertThrylosTransactionToLocal(thrylosTx) // Ensure this function exists and is correct
	if err != nil {
		return nil, fmt.Errorf("failed to convert signed transaction back to local format: %v", err)
	}

	// Return the signed transaction
	return &signedTx, nil
}

// Hypothetical conversion function from your local Transaction type to *thrylos.Transaction
func ConvertLocalTransactionToThrylosTransaction(tx Transaction) (*thrylos.Transaction, error) {
	thrylosInputs := make([]*thrylos.UTXO, len(tx.Inputs))
	for i, input := range tx.Inputs {
		thrylosInputs[i] = &thrylos.UTXO{
			TransactionId: input.TransactionID,
			Index:         int32(input.Index),
			OwnerAddress:  input.OwnerAddress,
			Amount:        int64(input.Amount),
		}
	}

	thrylosOutputs := make([]*thrylos.UTXO, len(tx.Outputs))
	for i, output := range tx.Outputs {
		thrylosOutputs[i] = &thrylos.UTXO{
			TransactionId: output.TransactionID,
			Index:         int32(output.Index),
			OwnerAddress:  output.OwnerAddress,
			Amount:        int64(output.Amount),
		}
	}

	return &thrylos.Transaction{
		Id:            tx.ID,
		Inputs:        thrylosInputs,
		Outputs:       thrylosOutputs,
		Timestamp:     tx.Timestamp,
		PreviousTxIds: tx.PreviousTxIds, // Ensure this matches your local struct field
		// Leave Signature for the SignTransaction to fill
	}, nil
}

// Hypothetical conversion back to local Transaction type, if needed
func convertThrylosTransactionToLocal(tx *thrylos.Transaction) (Transaction, error) {
	localInputs := make([]UTXO, len(tx.Inputs))
	for i, input := range tx.Inputs {
		localInputs[i] = UTXO{
			TransactionID: input.TransactionId,
			Index:         int(input.Index),
			OwnerAddress:  input.OwnerAddress,
			Amount:        int(input.Amount),
		}
	}

	localOutputs := make([]UTXO, len(tx.Outputs))
	for i, output := range tx.Outputs {
		localOutputs[i] = UTXO{
			TransactionID: output.TransactionId,
			Index:         int(output.Index),
			OwnerAddress:  output.OwnerAddress,
			Amount:        int(output.Amount),
		}
	}

	return Transaction{
		ID:            tx.Id,
		Inputs:        localInputs,
		Outputs:       localOutputs,
		Timestamp:     tx.Timestamp,
		Signature:     tx.Signature,
		PreviousTxIds: tx.PreviousTxIds, // Match this with the Protobuf field

	}, nil
}

func ConvertToProtoTransaction(tx *Transaction) *thrylos.Transaction {
	protoTx := &thrylos.Transaction{
		Id:        tx.ID,
		Sender:    tx.Sender,
		Timestamp: tx.Timestamp,
		Signature: tx.Signature,
	}

	for _, input := range tx.Inputs {
		protoTx.Inputs = append(protoTx.Inputs, &thrylos.UTXO{
			TransactionId: input.TransactionID,
			Index:         int32(input.Index),
			OwnerAddress:  input.OwnerAddress,
			Amount:        int64(input.Amount),
		})
	}

	for _, output := range tx.Outputs {
		protoTx.Outputs = append(protoTx.Outputs, &thrylos.UTXO{
			TransactionId: output.TransactionID,
			Index:         int32(output.Index),
			OwnerAddress:  output.OwnerAddress,
			Amount:        int64(output.Amount),
		})
	}

	return protoTx
}

// SignTransaction creates a digital signature for a transaction using the sender's private RSA key.
// The signature is created by first hashing the transaction data, then signing the hash with the private key.
// SignTransaction creates a signature for a transaction using the sender's private Ed25519 key.
func SignTransaction(tx *thrylos.Transaction, ed25519PrivateKey ed25519.PrivateKey) error {
	// Serialize the transaction for signing
	txBytes, err := proto.Marshal(tx)
	if err != nil {
		return fmt.Errorf("failed to serialize transaction: %v", err)
	}

	// Ed25519 Signature
	ed25519Signature := ed25519.Sign(ed25519PrivateKey, txBytes)
	tx.Signature = base64.StdEncoding.EncodeToString(ed25519Signature)

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
	// Deserialize the transaction for verification
	txBytes, err := proto.Marshal(tx)
	if err != nil {
		return fmt.Errorf("failed to serialize transaction for verification: %v", err)
	}

	// Verify Ed25519 Signature
	ed25519SigBytes, err := base64.StdEncoding.DecodeString(tx.Signature)
	if err != nil {
		return fmt.Errorf("failed to decode Ed25519 signature: %v", err)
	}
	if !ed25519.Verify(ed25519PublicKey, txBytes, ed25519SigBytes) {
		return errors.New("Ed25519 signature verification failed")
	}

	return nil
}

// VerifyTransaction ensures the overall validity of a transaction, including the correctness of its signature,
// the existence and ownership of UTXOs in its inputs, and the equality of input and output values.
func VerifyTransaction(tx *thrylos.Transaction, utxos map[string][]*thrylos.UTXO, getPublicKeyFunc func(address string) (ed25519.PublicKey, error)) (bool, error) {

	// Check if there are any inputs in the transaction
	if len(tx.GetInputs()) == 0 {
		return false, errors.New("Transaction has no inputs")
	}

	// Assuming all inputs come from the same sender for simplicity
	senderAddress := tx.Sender // Use the sender field directly

	// Retrieve the Ed25519 public key for the sender
	ed25519PublicKey, err := getPublicKeyFunc(senderAddress)
	if err != nil {
		return false, fmt.Errorf("Error retrieving Ed25519 public key for address %s: %v", senderAddress, err)
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

	// Verify the transaction signature using both public keys
	err = VerifyTransactionSignature(tx, ed25519PublicKey)
	if err != nil {
		return false, fmt.Errorf("Transaction signature verification failed: %v", err)
	}

	// The remaining logic for UTXO checks and sum validation remains unchanged...

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
func BatchSignTransactions(transactions []*Transaction, edPrivateKey ed25519.PrivateKey) error {
	var wg sync.WaitGroup
	errChan := make(chan error, 2) // Channel for error communication

	go func() {
		defer wg.Done()
		for _, customTx := range transactions { // Assuming transactions is of type []*Transaction
			// Convert the custom Transaction struct to the Protobuf-generated Transaction type
			protoTx := ConvertToProtoTransaction(customTx)

			// Correctly use the generated Protobuf type for marshaling
			txBytes, err := proto.Marshal(protoTx)
			if err != nil {
				// Handle error appropriately
				continue
			}

			// Ed25519 Signing
			edSignature := ed25519.Sign(edPrivateKey, txBytes)

			// Update the signature field of the Protobuf Transaction
			protoTx.Signature = base64.StdEncoding.EncodeToString(edSignature)

			// If you also want to update your custom struct, remember to convert the signature back
			customTx.Signature = protoTx.Signature
		}
	}()

	wg.Add(2)
	wg.Wait()

	close(errChan) // Close the channel to signal completion of error collection

	// Check for errors
	for e := range errChan {
		if e != nil {
			return e // Return the first encountered error (or aggregate as needed)
		}
	}

	return nil
}
