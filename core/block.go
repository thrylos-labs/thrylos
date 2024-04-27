package core

import (
	thrylos "Thrylos"
	"Thrylos/shared"
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/gob"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"time"

	"google.golang.org/protobuf/proto"
	// other necessary imports
)

// Block represents a single unit of data within the blockchain, encapsulating transactions,
// and metadata such as its hash, the hash of the previous block, and a timestamp. Each block
// is linked to the previous block, forming the blockchain's immutable ledger.

type Block struct {
	// Index is the position of the block in the blockchain, starting from 0 for the genesis block.
	Index int `json:"index"`

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

func ConvertSharedTransactionToProto(tx shared.Transaction) *thrylos.Transaction {
	protoInputs := make([]*thrylos.UTXO, len(tx.Inputs))
	for i, input := range tx.Inputs {
		protoInputs[i] = shared.ConvertSharedUTXOToProto(input)
	}

	protoOutputs := make([]*thrylos.UTXO, len(tx.Outputs))
	for i, output := range tx.Outputs {
		protoOutputs[i] = shared.ConvertSharedUTXOToProto(output)
	}

	return &thrylos.Transaction{
		Id:        tx.ID,
		Timestamp: tx.Timestamp,
		Inputs:    protoInputs,
		Outputs:   protoOutputs,
		Signature: tx.Signature,
	}
}

func ConvertProtoTransactionToShared(protoTx *thrylos.Transaction) shared.Transaction {
	inputs := make([]shared.UTXO, len(protoTx.GetInputs()))
	for i, protoInput := range protoTx.GetInputs() {
		inputs[i] = ConvertProtoUTXOToShared(protoInput)
	}

	outputs := make([]shared.UTXO, len(protoTx.GetOutputs()))
	for i, protoOutput := range protoTx.GetOutputs() {
		outputs[i] = ConvertProtoUTXOToShared(protoOutput)
	}

	return shared.Transaction{
		ID:        protoTx.GetId(),
		Timestamp: protoTx.GetTimestamp(),
		Inputs:    inputs,
		Outputs:   outputs,
		Signature: protoTx.GetSignature(),
	}
}

// NewBlock creates a new block with the specified parameters, including the index, transactions,
// previous hash, and validator. This function also calculates the current timestamp and the block's
// hash, ensuring the block is ready to be added to the blockchain.
func NewBlock(index int, transactions []shared.Transaction, prevHash string, validator string, prevTimestamp int64) *Block {
	fmt.Printf("NewBlock: Creating new block at index %d with %d transactions\n", index, len(transactions))
	currentTimestamp := time.Now().Unix()

	// Calculate the current timestamp ensuring it is at least 1 second greater than the previous timestamp
	if currentTimestamp <= prevTimestamp {
		currentTimestamp = prevTimestamp + 1
	}

	var protoTransactions []*thrylos.Transaction
	for _, tx := range transactions {
		// Convert shared.Transaction to *thrylos.Transaction here
		protoTx := ConvertSharedTransactionToProto(tx)
		if protoTx != nil {
			protoTransactions = append(protoTransactions, protoTx)
		}
	}

	// Debug: Print the number of transactions converted for the Merkle Tree
	fmt.Printf("Number of transactions converted for Merkle Tree: %d\n", len(protoTransactions))

	if len(protoTransactions) == 0 {
		fmt.Println("No transactions converted for Merkle Tree.")
		return nil
	}

	// Since Merkle trees require [][]byte, we serialize the Protobuf transactions
	var txData [][]byte
	for _, protoTx := range protoTransactions {
		txByte, err := proto.Marshal(protoTx)
		if err != nil {
			fmt.Printf("Failed to serialize Protobuf transaction: %v\n", err)
			continue
		}
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
		Index:        index,
		Transactions: protoTransactions, // Use the converted Protobuf transactions
		Timestamp:    currentTimestamp,
		VerkleRoot:   verkleRootBytesSlice, // Use the slice here
		PrevHash:     prevHash,
		Hash:         "",
		Validator:    validator,
	}

	block.Hash = block.ComputeHash()
	fmt.Printf("NewBlock: Block created - Index: %d, Hash: %s, Transactions: %+v\n", block.Index, block.Hash, block.Transactions)
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
		Index:      index,
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
		Signature string        `json:"signature"`
	}

	type JSONBlock struct {
		Index        int               `json:"index"`
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

// ComputeHash generates the hash of the block by concatenating and hashing its key components,
// including the transactions, previous hash, and metadata. This hash serves as both a unique identifier
// for the block and a security mechanism, ensuring the block's contents have not been altered.
// ComputeHash generates the hash of the block only if it has not been computed or if it might have changed.
func (b *Block) ComputeHash() string {
	if b.Hash != "" {
		return b.Hash // Return the cached hash if already computed
	}

	var txHashes []byte
	for _, tx := range b.Transactions {
		txBytes, err := proto.Marshal(tx)
		if err != nil {
			log.Printf("Failed to serialize transaction: %v", err)
			continue
		}
		txHash := sha256.Sum256(txBytes)
		txHashes = append(txHashes, txHash[:]...)
	}

	// Combine all relevant data to form a unique block hash
	data := bytes.Join([][]byte{
		[]byte(fmt.Sprintf("%d", b.Index)),
		[]byte(fmt.Sprintf("%d", b.Timestamp)),
		[]byte(b.VerkleRoot),
		[]byte(b.PrevHash),
		[]byte(b.Validator),
		txHashes,
	}, []byte{})

	// Compute the final hash
	finalHash := sha256.Sum256(data)
	b.Hash = hex.EncodeToString(finalHash[:])
	return b.Hash
}
