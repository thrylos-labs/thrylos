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
	"github.com/thrylos-labs/thrylos/thrylos"

	thrylos "github.com/thrylos-labs/thrylos"
	"github.com/thrylos-labs/thrylos/shared"
	"golang.org/x/crypto/blake2b"

	"github.com/gballet/go-verkle"
	"google.golang.org/protobuf/proto"
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

	for _, tx := range b.Transactions {
		builder := flatbuffers.NewBuilder(0)
		// Serialize the transaction - Example based on assuming a method to build the transaction exists
		thrylos.TransactionStart(builder)
		// Assume functions like TransactionAddId, TransactionAddInputs, etc., are available to add transaction fields
		// Example: thrylos.TransactionAddId(builder, builder.CreateString(tx.Id))
		transactionOffset := thrylos.TransactionEnd(builder)
		builder.Finish(transactionOffset)

		// Append the serialized transaction to txData
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
			} else {
				root := b.verkleTree.Commitment().BytesUncompressedTrusted()
				b.VerkleRoot = make([]byte, len(root))
				copy(b.VerkleRoot, root[:])
			}
		}()
		wg.Wait()
	}
	return b.Error // return any error that occurred during processing
}

// NewGenesisBlock creates and returns the genesis block for the blockchain. The genesis block
// is the first block in the blockchain, serving as the foundation upon which the entire chain is built.
func NewGenesisBlock() *Block {
	block := &Block{
		Index:      0,
		Timestamp:  time.Now().Unix(),
		VerkleRoot: []byte{}, // Or some predefined value, since it's a special case.
		PrevHash:   "",
		Hash:       "",
		Validator:  "",
	}
	block.Hash = block.ComputeHash()
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

	// Accessing fields directly, as Get methods do not exist in FlatBuffers
	return shared.Transaction{
		ID:        string(fbTx.Id()), // FlatBuffers uses direct byte slices, convert to string
		Timestamp: fbTx.Timestamp(),
		Inputs:    inputs,
		Outputs:   outputs,
		Signature: fbTx.Signature(), // Already a byte slice
		// Additional fields such as EncryptedData if your application uses them
	}
}

// Assuming you have a similar function for converting UTXO
func ConvertFlatUTXOToShared(fbUTXO *thrylos.UTXO) shared.UTXO {
	return shared.UTXO{
		TransactionID: string(fbUTXO.TransactionId()),
		Index:         fbUTXO.Index(),
		OwnerAddress:  string(fbUTXO.OwnerAddress()),
		Amount:        fbUTXO.Amount(),
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
		protoTx := ConvertSharedTransactionToProto(tx)
		if protoTx == nil {
			fmt.Println("Failed to convert transaction to Protobuf format.")
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

func convertBlockToJSON(block *Block) ([]byte, error) {
	log.Printf("Converting block Index=%d with %d transactions to JSON", block.Index, len(block.Transactions)) // Log the block details

	type JSONTransaction struct {
		ID        string        `json:"id"`
		Timestamp int64         `json:"timestamp"`
		Inputs    []shared.UTXO `json:"inputs"`
		Outputs   []shared.UTXO `json:"outputs"`
		Signature []byte        `json:"signature"`
	}

	type JSONBlock struct {
		Index        int32             `json:"index"`
		Timestamp    int64             `json:"timestamp"`
		Transactions []JSONTransaction `json:"transactions"`
		Hash         string            `json:"hash"`
		Validator    string            `json:"validator"`
	}

	jsonBlock := JSONBlock{
		Index:     block.Index,
		Timestamp: block.Timestamp,
		Hash:      block.Hash,
		Validator: block.Validator,
	}

	for _, trx := range block.Transactions {
		jsonTrx := JSONTransaction{
			ID:        trx.Id,
			Timestamp: trx.Timestamp,
			Signature: trx.Signature,
		}

		for _, input := range trx.Inputs {
			jsonTrx.Inputs = append(jsonTrx.Inputs, ConvertProtoUTXOToShared(input))
		}

		for _, output := range trx.Outputs {
			jsonTrx.Outputs = append(jsonTrx.Outputs, ConvertProtoUTXOToShared(output))
		}

		jsonBlock.Transactions = append(jsonBlock.Transactions, jsonTrx)
		log.Printf("Added transaction %s with %d outputs", trx.Id, len(trx.Outputs)) // Log each transaction detail
	}

	return json.Marshal(jsonBlock)
}

func (b *Block) ComputeHash() string {
	if b.Hash != "" {
		return b.Hash // Use the cached hash if available
	}

	// Create a new BLAKE2b-256 hasher
	hasher, err := blake2b.New256(nil)
	if err != nil {
		log.Printf("Failed to create hasher: %v", err)
		return ""
	}

	// Hash block's static components
	hasher.Write([]byte(fmt.Sprintf("%d", b.Index)))
	hasher.Write([]byte(fmt.Sprintf("%d", b.Timestamp)))
	hasher.Write([]byte(b.PrevHash))
	hasher.Write([]byte(b.Validator))

	// Process transactions
	for _, tx := range b.Transactions {
		txBytes, err := proto.Marshal(tx)
		if err != nil {
			log.Printf("Failed to serialize transaction: %v", err)
			return "" // Return an empty string or handle the error as per your error policy
		}
		txHash := blake2b.Sum256(txBytes)
		hasher.Write(txHash[:])
	}

	if len(b.VerkleRoot) > 0 {
		hasher.Write(b.VerkleRoot)
	}

	// Compute and store the hash
	b.Hash = hex.EncodeToString(hasher.Sum(nil))
	return b.Hash
}
