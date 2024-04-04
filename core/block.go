package core

import (
	thrylos "Thrylos"
	"Thrylos/shared"
	"bytes"
	"crypto/sha256"
	"encoding/gob"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"time"

	"github.com/gballet/go-verkle"
	"google.golang.org/protobuf/proto"
	// other necessary imports
)

// Block represents a single unit of data within the blockchain, encapsulating transactions,
// and metadata such as its hash, the hash of the previous block, and a timestamp. Each block
// is linked to the previous block, forming the blockchain's immutable ledger.

type Block struct {
	// Index is the position of the block in the blockchain, starting from 0 for the genesis block.
	Index int

	// Timestamp represents the time at which the block was created, measured in seconds since
	// the Unix epoch. It ensures the chronological order of blocks within the blockchain.
	Timestamp int64

	// VerkleRoot is the root hash of the Verkle tree constructed from the block's transactions.
	// It provides a succinct proof of the transactions' inclusion in the block.
	VerkleRoot []byte // Changed from MerkleRoot to VerkleRoot

	// PrevHash stores the hash of the previous block in the chain, establishing the link between
	// this block and its predecessor. This linkage is crucial for the blockchain's integrity.
	PrevHash string

	// Hash is the block's own hash, computed from its contents and metadata. It uniquely identifies
	// the block and secures the blockchain against tampering.
	Hash string

	// Transactions is the list of transactions included in the block. Transactions are the actions
	// that modify the blockchain's state, such as transferring assets between parties.
	Transactions []*thrylos.Transaction // Adjusted to hold Protobuf transactions

	// Validator is the identifier for the node or party that created and validated the block.
	// In proof-of-stake systems, this would be the stakeholder who was entitled to produce the block.
	Validator string
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

	// Ensure the new timestamp is greater than the previous block's timestamp
	for currentTimestamp <= prevTimestamp {
		time.Sleep(1 * time.Millisecond) // wait for 1 ms
		currentTimestamp = time.Now().Unix()
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

	// Create Verkle Tree from serialized transaction data
	var err error                           // Declare err before using it
	var verkleTree verkle.VerkleNode        // Declare verkleTree if not already declared
	verkleTree, err = NewVerkleTree(txData) // Use = instead of := to assign values to existing variables
	if err != nil {
		fmt.Println("Failed to create Verkle tree:", err)
		return nil
	}

	// Assuming the Verkle tree has a method to get the commitment (root hash)
	verkleRoot := verkleTree.Commitment() // Get the commitment (root hash) of the Verkle tree

	// Convert verkleRoot to []byte
	verkleRootBytes := verkleRoot.Bytes() // Assuming banderwagon.Element has a Bytes() method

	// Serialize the verkleRoot
	verkleRootBytes, err := verkleRoot.Serialize()
	if err != nil {
		fmt.Println("Failed to serialize Verkle root:", err)
		return nil
	}

	block := &Block{
		Index:        index,
		Transactions: protoTransactions, // Use the converted Protobuf transactions
		Timestamp:    currentTimestamp,
		VerkleRoot:   verkleRootBytes, // Assign the serialized byte slice
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

	// Create Merkle Tree from serialized Protobuf transactions
	var verkleRoot []byte
	if verkleNode, ok := verkleTree.(interface{ Root() []byte }); ok && verkleNode != nil {
		verkleRoot = verkleNode.Root()
	} else {
		fmt.Println("Failed to extract Verkle root")
		return nil
	}

	block := &Block{
		Index:      index,
		Timestamp:  timestamp, // Use the provided timestamp here
		VerkleRoot: verkleRoot,
		PrevHash:   prevHash,
		Hash:       "",
		Validator:  validator,
	}

	// Debugging: Print the timestamp set in this new block
	fmt.Printf("Timestamp set in the new block: %d\n", block.Timestamp)

	block.Hash = block.ComputeHash()
	return block
}

// ComputeHash generates the hash of the block by concatenating and hashing its key components,
// including the transactions, previous hash, and metadata. This hash serves as both a unique identifier
// for the block and a security mechanism, ensuring the block's contents have not been altered.

func (b *Block) ComputeHash() string {
	data := bytes.Join([][]byte{
		[]byte(fmt.Sprintf("%d", b.Index)),
		[]byte(fmt.Sprintf("%d", b.Timestamp)),
		[]byte(b.VerkleRoot), // Adjust this to use the Merkle Root instead
		[]byte(b.PrevHash),
		[]byte(b.Validator),
	}, []byte{})
	hash := sha256.Sum256(data)
	return hex.EncodeToString(hash[:])
}
