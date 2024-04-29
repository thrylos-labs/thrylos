package core

import (
	"bytes"
	"encoding/base64"
	"encoding/gob"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"sync"
	"time"

	flatbuffers "github.com/google/flatbuffers/go"

	"github.com/thrylos-labs/thrylos/shared"
	"github.com/thrylos-labs/thrylos/thrylos"
	"golang.org/x/crypto/blake2b"

	"github.com/gballet/go-verkle"
	// other necessary imports
)

// Block represents a single unit of data within the blockchain, encapsulating transactions,
// and metadata such as its hash, the hash of the previous block, and a timestamp. Each block
// is linked to the previous block, forming the blockchain's immutable ledger.

type Block struct {
	// Index is the position of the block in the blockchain, starting from 0 for the genesis block.
	Index int32 `json:"index"`

	// Timestamp represents the time at which the block was created, measured in seconds since
	// the Unix epoch. It ensures the chronological order of blocks within the blockchain.
	Timestamp int64 `json:"timestamp"`

	// VerkleRoot is the root hash of the Verkle tree constructed from the block's transactions.
	// It provides a succinct proof of the transactions' inclusion in the block.
	VerkleRoot []byte `json:"verkleRootBase64,omitempty"` // Optionally encoded in base64 if to be readable

	// PrevHash stores the hash of the previous block in the chain, establishing the link between
	// this block and its predecessor. This linkage is crucial for the blockchain's integrity.
	PrevHash string `json:"prevHash"`

	// Hash is the block's own hash, computed from its contents and metadata. It uniquely identifies
	// the block and secures the blockchain against tampering.
	Hash string `json:"Hash"` // Ensure the hash is part of the block's structure

	// Transactions is the list of transactions included in the block. Transactions are the actions
	// that modify the blockchain's state, such as transferring assets between parties.
	Transactions []*thrylos.Transaction `json:"transactions"`

	// Validator is the identifier for the node or party that created and validated the block.
	// In proof-of-stake systems, this would be the stakeholder who was entitled to produce the block.
	Validator string `json:"validator"`

	// Store the actual tree for later use if needed
	verkleTree verkle.VerkleNode // Store the actual tree for later use if needed

	Error error // Added to capture errors during block processing

	Data string `json:"data"` // Assuming the block's content is just a string for simplicity

}

// InitializeVerkleTree initializes the Verkle Tree lazily and calculates its root.
func (b *Block) InitializeVerkleTree() error {
	var txData [][]byte
	builder := flatbuffers.NewBuilder(0)

	for _, tx := range b.Transactions {
		builder.Reset()

		// Serialize inputs
		numInputs := tx.InputsLength()
		inputs := make([]shared.UTXO, numInputs)
		var protoInput thrylos.UTXO
		for i := 0; i < numInputs; i++ {
			if tx.Inputs(&protoInput, i) {
				inputs[i] = ConvertFlatUTXOToShared(&protoInput)
			}
		}
		inputsPtrs := shared.ConvertToUTXOPtrs(inputs)
		inputsOffsets, err := shared.SerializeUTXOs(builder, inputsPtrs)
		if err != nil {
			log.Printf("Error serializing inputs: %v", err)
			continue
		}

		// Serialize outputs
		numOutputs := tx.OutputsLength()
		outputs := make([]shared.UTXO, numOutputs)
		var protoOutput thrylos.UTXO
		for i := 0; i < numOutputs; i++ {
			if tx.Outputs(&protoOutput, i) {
				outputs[i] = ConvertFlatUTXOToShared(&protoOutput)
			}
		}
		outputsPtrs := shared.ConvertToUTXOPtrs(outputs)
		outputsOffsets, err := shared.SerializeUTXOs(builder, outputsPtrs)
		if err != nil {
			log.Printf("Error serializing outputs: %v", err)
			continue
		}

		// Serialize other transaction fields
		idOffset := builder.CreateString(string(tx.Id()))
		encryptedInputsOffset := builder.CreateByteVector(tx.EncryptedInputsBytes())
		encryptedOutputsOffset := builder.CreateByteVector(tx.EncryptedOutputsBytes())
		prevTxIds := make([]string, tx.PreviousTxIdsLength())
		for i := 0; i < tx.PreviousTxIdsLength(); i++ {
			prevTxIds[i] = string(tx.PreviousTxIds(i))
		}
		previousTxIdsOffset := createStringVector(builder, prevTxIds)
		encryptedAesKeyOffset := builder.CreateByteVector(tx.EncryptedAesKeyBytes())
		senderOffset := builder.CreateString(string(tx.Sender()))
		signatureBytes := make([]byte, tx.SignatureLength())
		for i := 0; i < tx.SignatureLength(); i++ {
			signatureBytes[i] = tx.Signature(i)
		}
		signatureOffset := builder.CreateByteVector(signatureBytes)

		// Start building the transaction object in FlatBuffers
		thrylos.TransactionStart(builder)
		thrylos.TransactionAddId(builder, idOffset)
		thrylos.TransactionAddTimestamp(builder, tx.Timestamp())
		thrylos.TransactionAddInputs(builder, inputsOffsets)
		thrylos.TransactionAddOutputs(builder, outputsOffsets)
		thrylos.TransactionAddEncryptedInputs(builder, encryptedInputsOffset)
		thrylos.TransactionAddEncryptedOutputs(builder, encryptedOutputsOffset)
		thrylos.TransactionAddSignature(builder, signatureOffset)
		thrylos.TransactionAddPreviousTxIds(builder, previousTxIdsOffset)
		thrylos.TransactionAddEncryptedAesKey(builder, encryptedAesKeyOffset)
		thrylos.TransactionAddSender(builder, senderOffset)
		transactionOffset := thrylos.TransactionEnd(builder)
		builder.Finish(transactionOffset)
		txData = append(txData, builder.FinishedBytes())
	}

	if len(txData) > 0 {
		var wg sync.WaitGroup
		wg.Add(1)
		go func() {
			defer wg.Done()
			var err error
			b.verkleTree, err = NewVerkleTree(txData)
			if err != nil {
				b.Error = fmt.Errorf("failed to create Verkle tree: %v", err)
				return
			}
			root := b.verkleTree.Commitment().BytesUncompressedTrusted()
			b.VerkleRoot = make([]byte, len(root))
			copy(b.VerkleRoot, root[:])
		}()
		wg.Wait()
	}

	return b.Error // Return any error that occurred during processing
}

// NewGenesisBlock creates and returns the genesis block for the blockchain. The genesis block
// is the first block in the blockchain, serving as the foundation upon which the entire chain is built.
func NewGenesisBlock(transactions []*thrylos.Transaction) *Block {
	block := &Block{
		Index:        0,
		Timestamp:    time.Now().Unix(),
		Transactions: transactions, // Include the transactions in the genesis block
		VerkleRoot:   []byte{},     // Or some predefined value, since it's a special case.
		PrevHash:     "",
		Hash:         "",
		Validator:    "",
	}

	// Optionally, compute hashes or perform any initial setup necessary for the transactions
	// For instance, updating the Verkle Tree or computing the overall block hash including transactions
	if len(transactions) > 0 {
		block.ComputeHash()
	}
	block.Hash = block.ComputeHash() // Recompute the hash after adding transactions
	return block
}

// Encoding binary data as base64 in JSON is common as not supported
func (b *Block) GetVerkleRootBase64() string {
	return base64.StdEncoding.EncodeToString(b.VerkleRoot)
}

// Serialize converts the block into a byte slice, facilitating storage or transmission. It encodes
// the block's data into a format that can be easily saved to disk or sent over the network.

func (b *Block) Serialize() ([]byte, error) {
	var result bytes.Buffer

	encoder := gob.NewEncoder(&result)
	if err := encoder.Encode(b); err != nil {
		return nil, err
	}

	return result.Bytes(), nil
}

// Deserialize takes a byte slice and reconstructs the block. This method is essential for reading
// blocks from disk or decoding them from network payloads, restoring the original Block struct.
func Deserialize(data []byte) (*Block, error) {
	var block Block

	decoder := gob.NewDecoder(bytes.NewReader(data))
	if err := decoder.Decode(&block); err != nil {
		return nil, err
	}

	return &block, nil
}

func ConvertFlatTransactionToShared(fbTx *thrylos.Transaction) shared.Transaction {
	// Convert inputs from FlatBuffers format to shared UTXO format
	inputs := make([]shared.UTXO, fbTx.InputsLength())
	for i := 0; i < fbTx.InputsLength(); i++ {
		var fbInput thrylos.UTXO
		if fbTx.Inputs(&fbInput, i) {
			inputs[i] = ConvertFlatUTXOToShared(&fbInput)
		}
	}

	// Convert outputs from FlatBuffers format to shared UTXO format
	outputs := make([]shared.UTXO, fbTx.OutputsLength())
	for i := 0; i < fbTx.OutputsLength(); i++ {
		var fbOutput thrylos.UTXO
		if fbTx.Outputs(&fbOutput, i) {
			outputs[i] = ConvertFlatUTXOToShared(&fbOutput)
		}
	}

	// Collecting the entire signature byte slice
	signatureBytes := make([]byte, fbTx.SignatureLength())
	for j := 0; j < fbTx.SignatureLength(); j++ {
		signatureBytes[j] = fbTx.Signature(j)
	}

	// Accessing fields directly, as Get methods do not exist in FlatBuffers
	return shared.Transaction{
		ID:        string(fbTx.Id()), // FlatBuffers uses direct byte slices, convert to string
		Timestamp: fbTx.Timestamp(),
		Inputs:    inputs,
		Outputs:   outputs,
		Signature: signatureBytes, // Correctly pass the byte slice
		// Additional fields such as EncryptedData if your application uses them
	}
}

// Assuming you have a similar function for converting UTXO
func ConvertFlatUTXOToShared(fbUTXO *thrylos.UTXO) shared.UTXO {
	return shared.UTXO{
		TransactionID: string(fbUTXO.TransactionId()), // Convert byte slice to string
		Index:         int(fbUTXO.Index()),            // Convert int32 to int
		OwnerAddress:  string(fbUTXO.OwnerAddress()),  // Convert byte slice to string
		Amount:        int(fbUTXO.Amount()),           // Convert int64 to int
	}
}

// NewBlock creates a new block with the specified parameters, including the index, transactions,
// previous hash, and validator. This function also calculates the current timestamp and the block's
// hash, ensuring the block is ready to be added to the blockchain.
func NewBlock(index int, transactions []shared.Transaction, prevHash string, validator string, prevTimestamp int64) *Block {
	fmt.Printf("Creating new block at index %d with %d transactions.\n", index, len(transactions))
	currentTimestamp := max(time.Now().Unix(), prevTimestamp+1)

	block := &Block{
		Index:        int32(index),
		Timestamp:    currentTimestamp,
		PrevHash:     prevHash,
		Validator:    validator,
		Transactions: make([]*thrylos.Transaction, 0, len(transactions)),
	}

	for _, tx := range transactions {
		protoTx := ConvertSharedTransactionToThrylos(tx)
		if protoTx == nil {
			fmt.Println("Failed to convert transaction to FlatBuffers format.")
			continue
		}
		block.Transactions = append(block.Transactions, protoTx)
	}

	if len(block.Transactions) == 0 {
		fmt.Println("No valid transactions provided for the block.")
		return nil
	}

	if err := block.InitializeVerkleTree(); err != nil {
		fmt.Printf("Error initializing Verkle Tree: %v\n", err)
		return nil
	}

	block.Hash = block.ComputeHash()
	fmt.Printf("Block created - Index: %d, Hash: %s, Transactions: %d\n", block.Index, block.Hash, len(block.Transactions))
	return block
}

// ConvertSharedTransactionToThrylos converts a shared transaction to a thrylos.Transaction.
func ConvertSharedTransactionToThrylos(tx shared.Transaction) *thrylos.Transaction {
	builder := flatbuffers.NewBuilder(0)

	idOffset := builder.CreateString(tx.ID)
	senderOffset := builder.CreateString(tx.Sender) // Assuming there's a sender field
	signatureOffset := builder.CreateByteVector(tx.Signature)

	// Assuming Inputs and Outputs are already prepared as FlatBuffer vectors elsewhere
	inputsOffset, outputsOffset := prepareInputsOutputs(builder, tx.Inputs, tx.Outputs)

	thrylos.TransactionStart(builder)
	thrylos.TransactionAddId(builder, idOffset)
	thrylos.TransactionAddTimestamp(builder, tx.Timestamp)
	thrylos.TransactionAddSender(builder, senderOffset)
	thrylos.TransactionAddSignature(builder, signatureOffset)
	thrylos.TransactionAddInputs(builder, inputsOffset)
	thrylos.TransactionAddOutputs(builder, outputsOffset)
	txOffset := thrylos.TransactionEnd(builder)

	builder.Finish(txOffset)
	return thrylos.GetRootAsTransaction(builder.FinishedBytes(), 0)
}

// Helper function to create input and output vectors.
func prepareInputsOutputs(builder *flatbuffers.Builder, inputs, outputs []shared.UTXO) (flatbuffers.UOffsetT, flatbuffers.UOffsetT) {
	// Conversion logic here...
	return 0, 0 // Return proper offsets
}

// NewBlockWithTimestamp is similar to NewBlock but allows for specifying the timestamp directly.
// This can be useful in scenarios where the exact creation time of the block needs to be controlled
// or replicated, such as during testing or when integrating with legacy systems.
func NewBlockWithTimestamp(index int, transactions []shared.Transaction, prevHash string, validator string, timestamp int64) *Block {
	var txData [][]byte
	for _, tx := range transactions {
		txByte, _ := json.Marshal(tx)
		txData = append(txData, txByte)
	}

	verkleTree, err := NewVerkleTree(txData)
	if err != nil {
		fmt.Println("Failed to create Verkle tree:", err)
		return nil
	}

	// Get the Verkle root as a point
	verkleRootPoint := verkleTree.Commitment()

	// Use BytesUncompressedTrusted() to get the uncompressed byte array
	verkleRootBytes := verkleRootPoint.BytesUncompressedTrusted() // This returns an array

	// Convert array to slice for use
	verkleRootBytesSlice := verkleRootBytes[:]

	block := &Block{
		Index:      int32(index),         // Convert index to int32
		Timestamp:  timestamp,            // Use the provided timestamp here
		VerkleRoot: verkleRootBytesSlice, // Convert array to slice
		PrevHash:   prevHash,
		Hash:       "",
		Validator:  validator,
	}

	// Debugging: Print the timestamp set in this new block
	fmt.Printf("Timestamp set in the new block: %d\n", block.Timestamp)

	block.Hash = block.ComputeHash()
	return block
}

// Convert the whole hash byte vector to a slice and then to a string.
func getHashAsString(block *thrylos.Block) string {
	hashLength := block.HashLength() // Gets the length of the hash vector.
	hashBytes := make([]byte, hashLength)
	for i := 0; i < hashLength; i++ {
		hashBytes[i] = block.Hash(i) // Access each byte using the index.
	}
	return encodeBytesToString(hashBytes) // Now we have a []byte that can be encoded to string.
}

func convertBlockToJSON(block *thrylos.Block) ([]byte, error) {
	log.Printf("Converting block Index=%d with %d transactions to JSON", block.Index(), block.TransactionsLength()) // Log the block details

	type JSONTransaction struct {
		ID            string        `json:"id"`
		Timestamp     int64         `json:"timestamp"`
		Inputs        []shared.UTXO `json:"inputs"`
		Outputs       []shared.UTXO `json:"outputs"`
		Signature     string        `json:"signature"`
		PreviousTxIds []string      `json:"previousTxIds"`
	}

	type JSONBlock struct {
		Index        int32             `json:"index"`
		Timestamp    int64             `json:"timestamp"`
		Transactions []JSONTransaction `json:"transactions"`
		Hash         string            `json:"hash"`
		Validator    string            `json:"validator"`
	}

	// Use helper function to encode Hash and Validator as strings.
	jsonBlock := JSONBlock{
		Index:     block.Index(),
		Timestamp: block.Timestamp(),
		Hash:      getHashAsString(block),
		Validator: encodeBytesToString(block.Validator()),
	}

	for i := 0; i < block.TransactionsLength(); i++ {
		var trx thrylos.Transaction
		if block.Transactions(&trx, i) {
			signatureBytes := make([]byte, trx.SignatureLength())
			for j := 0; j < trx.SignatureLength(); j++ {
				signatureBytes[j] = trx.Signature(j)
			}

			jsonTrx := JSONTransaction{
				ID:        string(trx.Id()),
				Timestamp: trx.Timestamp(),
				Signature: encodeBytesToString(signatureBytes),
				Inputs:    ConvertProtoInputs(&trx),
				Outputs:   ConvertProtoOutputs(&trx),
			}

			// Convert previous transaction IDs
			for j := 0; j < trx.PreviousTxIdsLength(); j++ {
				jsonTrx.PreviousTxIds = append(jsonTrx.PreviousTxIds, string(trx.PreviousTxIds(j)))
			}

			jsonBlock.Transactions = append(jsonBlock.Transactions, jsonTrx)
			log.Printf("Added transaction %s with %d outputs", jsonTrx.ID, len(jsonTrx.Outputs))
		}
	}

	return json.Marshal(jsonBlock)
}

func encodeBytesToString(data []byte) string {
	return base64.StdEncoding.EncodeToString(data)
}

func (b *Block) ComputeHash() string {
	if b.Hash != "" {
		return b.Hash // Use the cached hash if available
	}

	hasher, err := blake2b.New256(nil)
	if err != nil {
		log.Printf("Failed to create hasher: %v", err)
		return ""
	}

	hasher.Write([]byte(fmt.Sprintf("%d", b.Index)))
	hasher.Write([]byte(fmt.Sprintf("%d", b.Timestamp)))
	hasher.Write([]byte(b.PrevHash))
	hasher.Write([]byte(b.Validator))

	for _, fbTx := range b.Transactions {
		goTx := shared.ConvertFBToGoTransaction(fbTx)
		txBytes, err := goTx.SerializeForHashing()
		if err != nil {
			log.Printf("Error serializing transaction for hashing: %v", err)
			continue
		}
		txHash := blake2b.Sum256(txBytes)
		hasher.Write(txHash[:])
	}

	b.Hash = hex.EncodeToString(hasher.Sum(nil))
	return b.Hash
}
