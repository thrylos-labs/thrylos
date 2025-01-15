package core

import (
	"bytes"
	"encoding/base64"
	"encoding/binary"
	"encoding/gob"
	"fmt"
	"log"
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
	PrevHash []byte `json:"prevHash"`

	// Hash is the block's own hash, computed from its contents and metadata. It uniquely identifies
	// the block and secures the blockchain against tampering.
	Hash []byte `json:"Hash"` // Ensure the hash is part of the block's structure

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

	Signature []byte `json:"signature"`

	Salt []byte `json:"salt"`
}

func (b *Block) SerializeForSigning() ([]byte, error) {
	// Create a slice to hold all transaction data including salts
	txsWithSalts := make([]*thrylos.Transaction, len(b.Transactions))

	// Copy transactions and ensure salts are included
	for i, tx := range b.Transactions {
		// Create a copy of the transaction to avoid modifying the original
		txCopy := &thrylos.Transaction{
			Id:        tx.Id,
			Timestamp: tx.Timestamp,
			Inputs:    tx.Inputs,
			Outputs:   tx.Outputs,
			Signature: tx.Signature,
			Salt:      tx.Salt, // Explicitly include salt
			Sender:    tx.Sender,
			Status:    tx.Status,
			BlockHash: tx.BlockHash,
			Gasfee:    tx.Gasfee,
		}
		txsWithSalts[i] = txCopy
	}

	// Create the block protobuf with all transaction data
	pbBlock := &thrylos.Block{
		Index:        b.Index,
		Timestamp:    b.Timestamp,
		PrevHash:     b.PrevHash,
		Validator:    b.Validator,
		Transactions: txsWithSalts, // Use the transactions with explicitly included salts
		Hash:         b.Hash,
	}

	// Marshal the block to bytes
	blockBytes, err := proto.Marshal(pbBlock)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal block for signing: %v", err)
	}

	return blockBytes, nil
}

// Helper function to verify block serialization
func VerifyBlockSerialization(block *Block) error {
	// Serialize the block
	serializedData, err := block.SerializeForSigning()
	if err != nil {
		return fmt.Errorf("failed to serialize block: %v", err)
	}

	// Deserialize to verify all data was included
	var pbBlock thrylos.Block
	err = proto.Unmarshal(serializedData, &pbBlock)
	if err != nil {
		return fmt.Errorf("failed to unmarshal block: %v", err)
	}

	// Verify all transactions including salts were properly serialized
	for i, tx := range pbBlock.Transactions {
		if len(tx.Salt) == 0 {
			return fmt.Errorf("missing salt in transaction %d after serialization", i)
		}
	}

	return nil
}

// InitializeVerkleTree initializes the Verkle Tree lazily and calculates its root.
func (b *Block) InitializeVerkleTree() error {
	if len(b.Transactions) == 0 {
		return nil
	}

	// Pre-allocate slice for better memory efficiency
	txData := make([][]byte, 0, len(b.Transactions))

	// Marshal transactions
	for _, tx := range b.Transactions {
		txByte, err := proto.Marshal(tx)
		if err != nil {
			return fmt.Errorf("failed to serialize transaction: %v", err)
		}
		txData = append(txData, txByte)
	}

	tree, err := NewVerkleTree(txData)
	if err != nil {
		return fmt.Errorf("failed to create Verkle tree: %v", err)
	}

	// Store tree and root
	b.verkleTree = tree
	commitment := tree.Commitment().BytesUncompressedTrusted()
	b.VerkleRoot = commitment[:]

	return nil
}

// NewGenesisBlock creates and returns the genesis block for the blockchain. The genesis block
// is the first block in the blockchain, serving as the foundation upon which the entire chain is built.
func NewGenesisBlock() *Block {

	block := &Block{
		Index:      0,
		Timestamp:  time.Now().Unix(),
		VerkleRoot: []byte{}, // Or some predefined value, since it's a special case.
		PrevHash:   []byte{},
		Hash:       []byte{},
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

// GobEncode overrides the default Gob encoding for Block
func (b *Block) GobEncode() ([]byte, error) {
	var buf bytes.Buffer
	encoder := gob.NewEncoder(&buf)

	// Encode fields manually, could add additional field-specific validation here
	if err := encoder.Encode(b.Transactions); err != nil {
		return nil, fmt.Errorf("error encoding Transactions: %w", err)
	}

	// Add more fields to encode if necessary

	return buf.Bytes(), nil
}

// GobDecode overrides the default Gob decoding for Block
func (b *Block) GobDecode(data []byte) error {
	buf := bytes.NewReader(data)
	decoder := gob.NewDecoder(buf)

	// Decode fields manually, could add additional field-specific validation here
	if err := decoder.Decode(&b.Transactions); err != nil {
		return fmt.Errorf("error decoding Transactions: %w", err)
	}

	// Add more fields to decode if necessary

	return nil
}

func ConvertSharedTransactionToProto(tx *shared.Transaction) *thrylos.Transaction {
	if tx == nil {
		return nil
	}
	// Decode the Base64-encoded signature string back to []byte
	signatureBytes, err := base64.StdEncoding.DecodeString(tx.Signature)
	if err != nil {
		log.Fatalf("Failed to decode signature: %v", err)
		// Proper error handling here depending on your application's requirements
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
		Signature: signatureBytes, // Correctly use the decoded byte slice
	}
}

// NewBlock creates a new block with the specified parameters, including the index, transactions,
// previous hash, and validator. This function also calculates the current timestamp and the block's
// hash, ensuring the block is ready to be added to the blockchain.
func (b *Block) ComputeHash() []byte {
	hasher, err := blake2b.New256(nil)
	if err != nil {
		log.Printf("Failed to create hasher: %v", err)
		return nil
	}

	// Write block metadata in a fixed order
	binary.Write(hasher, binary.BigEndian, b.Index)
	binary.Write(hasher, binary.BigEndian, b.Timestamp)
	hasher.Write(b.PrevHash)
	hasher.Write([]byte(b.Validator))

	// Hash transactions
	for _, tx := range b.Transactions {
		txCopy := proto.Clone(tx).(*thrylos.Transaction)
		txCopy.Signature = []byte("") // Reset signature

		txBytes, err := proto.Marshal(txCopy)
		if err != nil {
			log.Printf("Failed to serialize transaction: %v", err)
			continue
		}

		txHash := blake2b.Sum256(txBytes)
		hasher.Write(txHash[:])

		log.Printf("Transaction %s hash: %x", tx.Id, txHash)
	}

	// Always write VerkleRoot if present
	if len(b.VerkleRoot) > 0 {
		hasher.Write(b.VerkleRoot)
		log.Printf("Including Verkle root in hash: %x", b.VerkleRoot)
	} else {
		log.Printf("Warning: Block hash computed without Verkle root")
	}

	hash := hasher.Sum(nil)
	log.Printf("Final block hash: %x", hash)

	// Only cache after complete computation
	b.Hash = hash
	return b.Hash
}
