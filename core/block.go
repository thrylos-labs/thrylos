package core

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/gob"
	"encoding/hex"
	"fmt"
	"log"
	"sync"
	"time"

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
	for _, protoTx := range b.Transactions {
		txByte, err := proto.Marshal(protoTx)
		if err != nil {
			b.Error = fmt.Errorf("failed to serialize Protobuf transaction: %v", err)
			return b.Error
		}
		txData = append(txData, txByte)
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

func ConvertSharedTransactionToProto(tx *shared.Transaction) *thrylos.Transaction {
	if tx == nil {
		return nil
	}
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
		Signature: tx.Signature, // Assuming Signature is already a []byte
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
		Signature: protoTx.GetSignature(), // Directly use []byte
	}
}

// NewBlock creates a new block with the specified parameters, including the index, transactions,
// previous hash, and validator. This function also calculates the current timestamp and the block's
// hash, ensuring the block is ready to be added to the blockchain.
func NewBlock(index int, transactions []shared.Transaction, prevHash string, validator string, prevTimestamp int64, privateKey ed25519.PrivateKey, publicKey ed25519.PublicKey) *Block {
	fmt.Printf("Creating new block at index %d with %d transactions.\n", index, len(transactions))
	currentTimestamp := max(time.Now().Unix(), prevTimestamp+1)

	// Convert shared.Transaction to thrylos.Transaction
	protoTransactions := make([]*thrylos.Transaction, 0, len(transactions))
	for i := range transactions {
		protoTx := ConvertSharedTransactionToProto(&transactions[i])
		if protoTx == nil {
			fmt.Println("Failed to convert transaction to Protobuf format.")
			continue
		}
		protoTransactions = append(protoTransactions, protoTx)
	}

	block := &Block{
		Index:        int32(index),
		Timestamp:    currentTimestamp,
		PrevHash:     prevHash,
		Validator:    validator,
		Transactions: make([]*thrylos.Transaction, 0, len(transactions)),
	}

	for i := range transactions {
		protoTx := ConvertSharedTransactionToProto(&transactions[i])
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
