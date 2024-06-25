package shared

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"hash"
	"io"
	"log"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/asaskevich/govalidator"
	"github.com/dgraph-io/badger"
	"github.com/thrylos-labs/thrylos"
	"github.com/tyler-smith/go-bip39"
	"golang.org/x/crypto/blake2b"
	"golang.org/x/crypto/pbkdf2"
	"google.golang.org/protobuf/proto"
)

var hashCache sync.Map // A thread-safe map to cache hash results

func cachedHashData(data []byte) []byte {
	// Use a fast, fixed-size hash as the cache key to reduce memory and improve lookup speed
	keyHash := blake2b.Sum256(data)
	key := hex.EncodeToString(keyHash[:])

	if val, ok := hashCache.Load(key); ok {
		return val.([]byte)
	}

	hasher := blake2bHasherPool.Get().(hash.Hash)
	defer blake2bHasherPool.Put(hasher)
	hasher.Reset()
	hasher.Write(data)
	computedHash := hasher.Sum(nil)

	hashCache.Store(key, computedHash)
	return computedHash
}

// TransactionContext wraps a BadgerDB transaction to manage its lifecycle.
type TransactionContext struct {
	Txn *badger.Txn
}

// GasEstimator defines an interface for fetching gas estimates.
type GasEstimator interface {
	FetchGasEstimate(dataSize int) (int, error)
}

// NewTransactionContext creates a new context for a database transaction.
func NewTransactionContext(txn *badger.Txn) *TransactionContext {
	return &TransactionContext{Txn: txn}
}

var blake2bHasher, _ = blake2b.New256(nil)

func EncryptAESKey(aesKey []byte, recipientPublicKey *rsa.PublicKey) ([]byte, error) {
	// Use SHA-256 for OAEP, which is standard and safe for this purpose
	hasher := sha256.New()

	// The third parameter here is the hash used for OAEP, not the key or data itself
	encryptedKey, err := rsa.EncryptOAEP(
		hasher,
		rand.Reader,
		recipientPublicKey,
		aesKey,
		nil, // Often no label is used, hence nil
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
	aesKey, err := rsa.DecryptOAEP(
		blake2bHasher,
		rand.Reader,
		recipientPrivateKey,
		encryptedKey,
		nil,
	)
	if err != nil {
		return nil, err
	}
	return DecryptWithAES(aesKey, encryptedData)
}

// Initialize a cache with a mutex for concurrent access control
var (
	addressCache = make(map[string]string)
	cacheMutex   sync.RWMutex
)

// PublicKeyToAddressWithCache converts an Ed25519 public key to a blockchain address string,

func PublicKeyToAddressWithCache(pubKey ed25519.PublicKey) string {
	pubKeyStr := hex.EncodeToString(pubKey) // Convert public key to string for map key

	// First attempt to get the address from cache without writing
	cacheMutex.RLock()
	address, found := addressCache[pubKeyStr]
	cacheMutex.RUnlock()

	if found {
		return address // Return cached address if available
	}

	// Lock for writing if the address was not found
	cacheMutex.Lock()
	defer cacheMutex.Unlock()

	// Double-check: Verify the address was not added while acquiring the lock
	address, found = addressCache[pubKeyStr]
	if found {
		return address
	}

	// Compute the address if still not found in cache
	address = computeAddressFromPublicKey(pubKey)
	addressCache[pubKeyStr] = address

	return address
}

func CreateThrylosTransaction(id int) *thrylos.Transaction {
	return &thrylos.Transaction{
		Id:        fmt.Sprintf("tx%d", id),
		Inputs:    []*thrylos.UTXO{{TransactionId: "prev-tx-id", Index: 0, OwnerAddress: "Alice", Amount: 100}},
		Outputs:   []*thrylos.UTXO{{TransactionId: fmt.Sprintf("tx%d", id), Index: 0, OwnerAddress: "Bob", Amount: 100}},
		Timestamp: time.Now().Unix(),
		Signature: []byte("signature"), // This should be properly generated or mocked
		Sender:    "Alice",
	}
}

// computeAddressFromPublicKey performs the actual computation of the address from a public key.
func computeAddressFromPublicKey(pubKey ed25519.PublicKey) string {
	// Compute hash or another identifier from the public key
	return hex.EncodeToString(pubKey) // Simplified
}

// GenerateEd25519Keys generates a new Ed25519 public/private key pair derived from a mnemonic seed phrase.
func GenerateEd25519Keys() (ed25519.PublicKey, ed25519.PrivateKey, string, error) {
	// Generate a new mnemonic
	entropy, err := bip39.NewEntropy(256)
	if err != nil {
		return nil, nil, "", err
	}
	mnemonic, err := bip39.NewMnemonic(entropy)
	if err != nil {
		return nil, nil, "", err
	}

	// Generate a seed from the mnemonic
	seed := bip39.NewSeed(mnemonic, "") // Use an empty passphrase for simplicity

	// Use PBKDF2 to derive a key from the seed suitable for Ed25519
	key := pbkdf2.Key(seed, []byte("ed25519 seed"), 2048, 32, sha512.New)

	// Generate Ed25519 keys from the derived key
	publicKey, privateKey, err := ed25519.GenerateKey(bytes.NewReader(key))
	if err != nil {
		return nil, nil, "", err
	}

	return publicKey, privateKey, mnemonic, nil
}

// PublicKeyToAddress generates a public address from an Ed25519 public key using SHA-256 and then BLAKE2b-256.
func PublicKeyToAddress(pubKey ed25519.PublicKey) string {
	// First hash using SHA-256
	shaHasher := sha256.New()
	shaHasher.Write(pubKey)
	shaHashedPubKey := shaHasher.Sum(nil)

	// Then hash using BLAKE2b-256
	blakeHasher, _ := blake2b.New256(nil)
	blakeHasher.Write(shaHashedPubKey)
	return hex.EncodeToString(cachedHashData(pubKey))
}

// Use a global hash pool for BLAKE2b hashers to reduce allocation overhead
var blake2bHasherPool = sync.Pool{
	New: func() interface{} {
		hasher, err := blake2b.New256(nil)
		if err != nil {
			panic(err) // Proper error handling is essential, though panic should be avoided in production
		}
		return hasher
	},
}

func HashData(data []byte) []byte {
	hasher := blake2bHasherPool.Get().(hash.Hash)
	defer blake2bHasherPool.Put(hasher)
	hasher.Reset()
	hasher.Write(data)
	return hasher.Sum(nil) // Correct usage of Sum
}

// Transaction defines the structure for blockchain transactions, including its inputs, outputs, a unique identifier,
// and an optional signature. Transactions are the mechanism through which value is transferred within the blockchain.
type Transaction struct {
	ID               string   `json:"id" valid:"required"` // Remove uuid4 validation
	Timestamp        int64    `json:"timestamp" valid:"required"`
	Inputs           []UTXO   `json:"inputs" valid:"required"`
	Outputs          []UTXO   `json:"outputs" valid:"required"`
	EncryptedInputs  []byte   `json:"encryptedInputs,omitempty" valid:"optional"`
	EncryptedOutputs []byte   `json:"encryptedOutputs,omitempty" valid:"optional"`
	Signature        []byte   `json:"signature,omitempty" valid:"optional"` // Make this optional for initial validation
	EncryptedAESKey  []byte   `json:"encryptedAESKey,omitempty" valid:"optional"`
	PreviousTxIds    []string `json:"previousTxIds,omitempty" valid:"optional"`
	Sender           string   `json:"sender" valid:"required"` // Remove ethereum_addr validation
	GasFee           int      `json:"gasFee"`                  // Ensure this is an integer
}

func SharedToThrylos(tx *Transaction) *thrylos.Transaction {
	if tx == nil {
		return nil
	}
	return &thrylos.Transaction{
		Id:            tx.ID,
		Timestamp:     tx.Timestamp,
		Inputs:        SharedToThrylosInputs(tx.Inputs),
		Outputs:       SharedToThrylosOutputs(tx.Outputs),
		Signature:     tx.Signature,
		PreviousTxIds: tx.PreviousTxIds,
	}
}

func SharedToThrylosInputs(inputs []UTXO) []*thrylos.UTXO {
	thrylosInputs := make([]*thrylos.UTXO, len(inputs))
	for i, input := range inputs {
		thrylosInputs[i] = &thrylos.UTXO{
			TransactionId: input.TransactionID,
			Index:         int32(input.Index), // Assuming thrylos.UTXO expects an int32 for Index
			OwnerAddress:  input.OwnerAddress,
			Amount:        int64(input.Amount), // Assuming thrylos.UTXO expects an int64 for Amount
		}
	}
	return thrylosInputs
}

func SharedToThrylosOutputs(outputs []UTXO) []*thrylos.UTXO {
	thrylosOutputs := make([]*thrylos.UTXO, len(outputs))
	for i, output := range outputs {
		thrylosOutputs[i] = &thrylos.UTXO{
			TransactionId: output.TransactionID,
			Index:         int32(output.Index),
			OwnerAddress:  output.OwnerAddress,
			Amount:        int64(output.Amount),
		}
	}
	return thrylosOutputs
}

// UnmarshalJSON custom unmarshalling to handle base64 encoding for byte slices.
func (tx *Transaction) UnmarshalJSON(data []byte) error {
	type Alias Transaction
	aux := &struct {
		Signature string `json:"signature"`
		*Alias
	}{
		Alias: (*Alias)(tx),
	}

	if err := json.Unmarshal(data, &aux); err != nil {
		return err
	}

	if aux.Signature != "" {
		sig, err := base64.StdEncoding.DecodeString(aux.Signature)
		if err != nil {
			return err
		}
		tx.Signature = sig
	}
	return nil
}

// MarshalJSON custom marshalling to handle base64 encoding for byte slices.
func (tx Transaction) MarshalJSON() ([]byte, error) {
	type Alias Transaction
	return json.Marshal(&struct {
		Signature string `json:"signature"`
		Alias
	}{
		Signature: base64.StdEncoding.EncodeToString(tx.Signature),
		Alias:     (Alias)(tx),
	})
}

// Validate ensures the fields of Transaction are correct.
// Validate ensures the fields of Transaction are correct.
func (tx *Transaction) Validate() error {
	// Custom validation logic
	if !isValidUUID(tx.ID) {
		return errors.New("invalid ID: must be a valid UUID")
	}

	// Validates using struct tags and custom logic
	_, err := govalidator.ValidateStruct(tx)
	if err != nil {
		return err
	}

	// Check timestamp validity
	if !validateTimestamp(tx.Timestamp) {
		return errors.New("invalid timestamp: must be recent within an hour")
	}

	return nil
}

// validateTimestamp checks if the transaction timestamp is within the last hour.
func validateTimestamp(timestamp int64) bool {
	return time.Since(time.Unix(timestamp, 0)).Hours() < 1
}

// select tips:
func selectTips() ([]string, error) {
	// Placeholder for your tip selection logic
	return []string{"prevTxID1", "prevTxID2"}, nil
}

// CreateAndSignTransaction generates a new transaction and signs it with the sender's Ed25519.
// Assuming Transaction is the correct type across your application:
func CreateAndSignTransaction(id string, sender string, inputs []UTXO, outputs []UTXO, ed25519PrivateKey ed25519.PrivateKey, aesKey []byte, estimator GasEstimator) (*Transaction, error) {
	// Serialize inputs and outputs for data size calculation
	serializedInputs, err := SerializeUTXOs(inputs)
	if err != nil {
		return nil, fmt.Errorf("failed to serialize inputs: %v", err)
	}
	serializedOutputs, err := SerializeUTXOs(outputs)
	if err != nil {
		return nil, fmt.Errorf("failed to serialize outputs: %v", err)
	}

	// Calculate total data size
	totalDataSize := len(serializedInputs) + len(serializedOutputs)

	// Fetch gas estimate
	gasFee, err := estimator.FetchGasEstimate(totalDataSize)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch gas estimate: %v", err)
	}

	// Adjust the first output to account for the gas fee
	if len(outputs) > 0 {
		outputs[0].Amount -= gasFee
	}

	// Initialize the transaction, now including PreviousTxIDs
	tx := Transaction{
		ID:               id,
		Sender:           sender,
		Inputs:           inputs,
		Outputs:          outputs,
		EncryptedInputs:  nil,
		EncryptedOutputs: nil,
		Timestamp:        time.Now().Unix(),
		GasFee:           gasFee,
	}

	// Convert the Transaction type to *thrylos.Transaction for signing
	thrylosTx, err := ConvertLocalTransactionToThrylosTransaction(tx)
	if err != nil {
		return nil, fmt.Errorf("failed to convert transaction for signing: %v", err)
	}

	// Sign the transaction using Ed25519
	if err := SignTransaction(thrylosTx, ed25519PrivateKey); err != nil {
		return nil, fmt.Errorf("failed to sign transaction: %v", err)
	}

	// Convert the signed thrylos.Transaction back to your local Transaction format
	signedTx, err := ConvertThrylosTransactionToLocal(thrylosTx)
	if err != nil {
		return nil, fmt.Errorf("failed to convert signed transaction back to local format: %v", err)
	}

	// Return the signed transaction
	return &signedTx, nil
}

// Hypothetical conversion function from your local Transaction type to *thrylos.Transaction
// ConvertLocalTransactionToThrylosTransaction converts your local Transaction type to *thrylos.Transaction
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
		GasFee:        int32(tx.GasFee), // Convert the gas fee
		// Signature is left out to be filled during signing
	}, nil
}

// ConvertThrylosTransactionToLocal converts a thrylos.Transaction back to your local Transaction type
func ConvertThrylosTransactionToLocal(tx *thrylos.Transaction) (Transaction, error) {
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
		GasFee:        int(tx.GasFee),   // Convert the gas fee
	}, nil
}

func ConvertToProtoTransaction(tx *Transaction) (*thrylos.Transaction, error) {
	if tx == nil {
		return nil, errors.New("transaction is nil")
	}
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

	return protoTx, nil
}

func BatchSignTransactionsConcurrently(transactions []*Transaction, edPrivateKey ed25519.PrivateKey) error {
	var wg sync.WaitGroup
	errChan := make(chan error, len(transactions))

	for _, customTx := range transactions {
		wg.Add(1)
		go func(customTx *Transaction) {
			defer wg.Done()

			// Convert the transaction to its protobuf representation
			protoTx, err := ConvertToProtoTransaction(customTx)
			if err != nil {
				errChan <- err
				return // ensure we stop processing this transaction on error
			}

			// Marshal the protobuf transaction into bytes
			txBytes, err := proto.Marshal(protoTx)
			if err != nil {
				errChan <- err
				return // stop processing if marshaling fails
			}

			// Sign the marshaled bytes using the Ed25519 private key
			edSignature := ed25519.Sign(edPrivateKey, txBytes)
			protoTx.Signature = edSignature
			customTx.Signature = protoTx.Signature
		}(customTx)
	}

	wg.Wait()
	close(errChan)

	// Check if there were any errors during the goroutines execution
	for e := range errChan {
		if e != nil {
			return e
		}
	}

	return nil
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
	if ed25519Signature == nil {
		return fmt.Errorf("failed to generate signature")
	}

	// Assign the generated signature to the transaction
	tx.Signature = ed25519Signature

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

	// Verify the signature using the public key and transaction bytes
	if !ed25519.Verify(ed25519PublicKey, txBytes, tx.Signature) {
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
	txCopy.Signature = []byte("") // Reset signature for serialization

	// Serialize the transaction for verification
	txBytes, err := proto.Marshal(txCopy)
	if err != nil {
		return false, fmt.Errorf("Error serializing transaction for verification: %v", err)
	}

	// Cache and retrieve the hash of the serialized transaction
	cachedHash := cachedHashData(txBytes)

	// Log the serialized transaction data without the signature
	log.Printf("Serialized transaction for verification: %x", txBytes)

	// Verify the transaction signature using the public key and cached hash
	if !ed25519.Verify(ed25519PublicKey, cachedHash, tx.Signature) {
		return false, fmt.Errorf("Transaction signature verification failed")
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

// GenerateTransactionID creates a unique identifier for a transaction based on its contents.
func GenerateTransactionID(inputs []UTXO, outputs []UTXO, address string, amount, gasFee int) (string, error) {
	var builder strings.Builder

	// Append the sender's address
	builder.WriteString(address)

	// Append the amount and gas fee
	builder.WriteString(fmt.Sprintf("%d%d", amount, gasFee))

	// Append details of inputs and outputs
	for _, input := range inputs {
		builder.WriteString(fmt.Sprintf("%s%d", input.OwnerAddress, input.Amount))
	}
	for _, output := range outputs {
		builder.WriteString(fmt.Sprintf("%s%d", output.OwnerAddress, output.Amount))
	}

	// Use the cachedHashData function to get the hash of the builder's string
	hashBytes := cachedHashData([]byte(builder.String()))
	return hex.EncodeToString(hashBytes), nil
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
func BatchSignTransactions(transactions []*Transaction, edPrivateKey ed25519.PrivateKey, batchSize int) error {
	if batchSize < 1 {
		return fmt.Errorf("invalid batch size: %d", batchSize)
	}

	var wg sync.WaitGroup
	errChan := make(chan error, (len(transactions)+batchSize-1)/batchSize) // +1 to ensure no blocking

	for i := 0; i < len(transactions); i += batchSize {
		end := i + batchSize
		if end > len(transactions) {
			end = len(transactions)
		}

		batch := transactions[i:end]
		wg.Add(1)

		go func(batch []*Transaction) {
			defer wg.Done()
			for _, customTx := range batch {
				protoTx, err := ConvertToProtoTransaction(customTx)
				if err != nil {
					errChan <- fmt.Errorf("conversion error: %w", err)
					return
				}
				txBytes, err := proto.Marshal(protoTx)
				if err != nil {
					errChan <- fmt.Errorf("marshal error: %w", err)
					return
				}
				edSignature := ed25519.Sign(edPrivateKey, txBytes)
				protoTx.Signature = edSignature
				customTx.Signature = protoTx.Signature
			}
		}(batch)
	}

	wg.Wait()
	close(errChan)

	for err := range errChan {
		if err != nil {
			return err
		}
	}
	return nil
}

func ParallelVerifyTransactions(
	transactions []*thrylos.Transaction,
	utxos map[string][]*thrylos.UTXO,
	getPublicKeyFunc func(address string) (ed25519.PublicKey, error),
) (map[string]bool, error) {
	results := make(map[string]bool)
	var mu sync.Mutex
	var wg sync.WaitGroup
	errorChan := make(chan error, len(transactions))

	for _, tx := range transactions {
		wg.Add(1)
		go func(tx *thrylos.Transaction) {
			defer wg.Done()
			isValid, err := VerifyTransaction(tx, utxos, getPublicKeyFunc)
			if err != nil {
				errorChan <- err
			} else {
				mu.Lock()
				results[tx.GetId()] = isValid
				mu.Unlock()
			}
		}(tx)
	}

	wg.Wait()
	close(errorChan)

	for err := range errorChan {
		if err != nil {
			return nil, err
		}
	}

	return results, nil
}

func processTransactionsBatch(transactions []*Transaction, db BlockchainDBInterface) error {
	if len(transactions) == 0 {
		return nil // No transactions to process
	}

	// Start a transaction
	txn, err := db.BeginTransaction()
	if err != nil {
		return err
	}
	defer db.RollbackTransaction(txn) // Ensure rollback if not committed

	// Use a channel to process transactions asynchronously
	txChannel := make(chan *Transaction, len(transactions))
	defer close(txChannel)

	// Worker pool to handle transactions concurrently
	var wg sync.WaitGroup
	for i := 0; i < 5; i++ { // Number of workers, tune this according to your needs
		wg.Add(1)
		go func() {
			defer wg.Done()
			for tx := range txChannel {
				if err := processSingleTransaction(txn, tx, db); err != nil {
					log.Printf("Failed to process transaction: %v", err)
					continue
				}
			}
		}()
	}

	// Dispatch transactions to workers
	for _, tx := range transactions {
		txChannel <- tx
	}
	wg.Wait()

	// Commit all transaction changes as a single batch
	if err := db.CommitTransaction(txn); err != nil {
		return fmt.Errorf("transaction commit failed: %v", err)
	}

	return nil
}

func processSingleTransaction(txn *TransactionContext, tx *Transaction, db BlockchainDBInterface) error {
	// Serialize the transaction data to JSON
	txJSON, err := json.Marshal(tx)
	if err != nil {
		return fmt.Errorf("error serializing transaction: %v", err)
	}

	// Generate a unique key for this transaction
	key := []byte("transaction-" + tx.ID)

	// Store the serialized transaction data
	if err := db.SetTransaction(txn, key, txJSON); err != nil {
		return fmt.Errorf("error storing transaction: %v", err)
	}

	return nil
}

func SerializeTransactionForSigning(tx *Transaction) ([]byte, error) {
	// Create a copy of the transaction to avoid modifying the original
	txCopy := *tx
	txCopy.Signature = nil // Ensure the signature is not included in the serialized data

	return json.Marshal(txCopy)
}

func isValidUUID(uuid string) bool {
	r := regexp.MustCompile("^[a-fA-F0-9]{8}-[a-fA-F0-9]{4}-[a-fA-F0-9]{4}-[a-fA-F0-9]{4}-[a-fA-F0-9]{12}$")
	return r.MatchString(uuid)
}

func SignTransactionData(tx *Transaction, privateKeyBytes []byte) ([]byte, error) {
	data, err := SerializeTransactionForSigning(tx)
	if err != nil {
		return nil, fmt.Errorf("failed to serialize transaction for signing: %v", err)
	}

	// Hash the data
	hasher, err := blake2b.New256(nil)
	hasher.Write(data)
	hashed := hasher.Sum(nil)

	// Assuming the privateKeyBytes is the Ed25519 private key
	privateKey := ed25519.PrivateKey(privateKeyBytes)
	signature := ed25519.Sign(privateKey, hashed) // Sign the hashed data

	return signature, nil
}

func DecodePrivateKey(encodedKey []byte) (ed25519.PrivateKey, error) {
	block, _ := pem.Decode(encodedKey)
	if block == nil || block.Type != "PRIVATE KEY" {
		return nil, errors.New("failed to decode PEM block containing private key")
	}

	key := ed25519.NewKeyFromSeed(block.Bytes)
	return key, nil
}

// VerifySignature method (example based on your provided method)
func VerifySignature(tx *Transaction, publicKey ed25519.PublicKey) bool {
	data, err := tx.SerializeWithoutSignature()
	if err != nil {
		log.Printf("Error serializing transaction data for signature verification: %v", err)
		return false
	}
	return ed25519.Verify(publicKey, data, tx.Signature)
}

func ProcessTransaction(tx *thrylos.Transaction, publicKey ed25519.PublicKey, estimator GasEstimator) error {
	// Calculate total data size from the already prepared transaction data
	totalDataSize := len(tx.EncryptedInputs) + len(tx.EncryptedOutputs)

	// Fetch gas estimate and convert to int64 if necessary
	gasFee, err := estimator.FetchGasEstimate(totalDataSize)
	if err != nil {
		return fmt.Errorf("failed to fetch gas estimate: %v", err)
	}
	intGasFee := int64(gasFee) // Assuming FetchGasEstimate returns int, convert to int64

	// Adjust the transaction outputs for the gas fee
	if len(tx.Outputs) > 0 && intGasFee > int64(tx.Outputs[0].Amount) {
		// Ensure there's enough amount to deduct the gas fee
		return fmt.Errorf("not enough balance to cover gas fees")
	}
	if len(tx.Outputs) > 0 {
		tx.Outputs[0].Amount -= intGasFee
	}

	// Validate transaction signature
	if err := VerifyTransactionSignature(tx, publicKey); err != nil {
		// Handle the error appropriately
		return fmt.Errorf("invalid transaction signature: %v", err)
	}

	// Record the transaction in the database or broadcast to the network
	err = BlockchainDBInterface.AddTransaction(*tx, BlockchainDBInterface)
	if err != nil {
		return fmt.Errorf("failed to add transaction to database: %v", err)
	}

	return nil
}
