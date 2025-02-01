package chain

import (
	"encoding/base64"
	"fmt"
	"log"
	"time"

	"github.com/fxamacker/cbor/v2"
	"github.com/thrylos-labs/thrylos/crypto"
	"github.com/thrylos-labs/thrylos/crypto/address"
	"github.com/thrylos-labs/thrylos/crypto/hash"
	// other necessary imports
)

// Block represents a single unit of data within the blockchain, encapsulating transactions,
// and metadata such as its hash, the hash of the previous block, and a timestamp. Each block
// is linked to the previous block, forming the blockchain's immutable ledger.

type Block struct {
	// Index is the position of the block in the blockchain, starting from 0 for the genesis block.
	Index int64 `cbor:"1,keyasint"`

	// Timestamp represents the time at which the block was created, measured in seconds since
	// the Unix epoch. It ensures the chronological order of blocks within the blockchain.
	Timestamp int64 `cbor:"2,keyasint"`

	// VerkleRoot is the root hash of the Verkle tree constructed from the block's transactions.
	// It provides a succinct proof of the transactions' inclusion in the block.
	VerkleRoot []byte `cbor:"3,keyasint"`

	// PrevHash stores the hash of the previous block in the chain, establishing the link between
	// this block and its predecessor. This linkage is crucial for the blockchain's integrity.
	PrevHash hash.Hash `cbor:"4,keyasint"`

	// Hash is the block's own hash, computed from its contents and metadata. It uniquely identifies
	// the block and secures the blockchain against tampering.
	Hash hash.Hash `cbor:"5,keyasint,omitempty"`

	// Transactions is the list of transactions included in the block. Transactions are the actions
	// that modify the blockchain's state, such as transferring assets between parties.
	Transactions []*Transaction `cbor:"6,keyasint"`
	Data         string         `cbor:"7,keyasint,omitempty"` // Assuming the block's content is just a string for simplicity

	// Validator is the identifier for the node or party that created and validated the block.
	// In proof-of-stake systems, this would be the stakeholder who was entitled to produce the block.
	ValidatorAddress   address.Address  `cbor:"8,keyasint"`
	ValidatorPublicKey crypto.PublicKey `cbor:"9,keyasint"`
	Signature          crypto.Signature `cbor:"10,keyasint,omitempty"`
	Salt               []byte           `cbor:"11,keyasint"`
}

// NewBlock creates a new block with the specified parameters, including the index, transactions,
// previous hash, and validator. This function also calculates the current timestamp and the block's
// hash, ensuring the block is ready to be added to the blockchain.

func NewBlock(index int64, prevHash hash.Hash, transactions []*Transaction, validatorAddress address.Address, validatorPublicKey crypto.PublicKey) (*Block, error) {
	block := &Block{
		Index:              index,
		Timestamp:          time.Now().Unix(),
		PrevHash:           prevHash,
		Transactions:       transactions,
		ValidatorAddress:   validatorAddress,
		ValidatorPublicKey: validatorPublicKey,
	}

	if err := block.InitializeVerkleTree(); err != nil {
		return nil, fmt.Errorf("failed to initialize Verkle tree: %v", err)
	}

	block.ComputeHash()
	return block, nil
}

// NewGenesisBlock creates and returns the genesis block for the blockchain. The genesis block
// is the first block in the blockchain, serving as the foundation upon which the entire chain is built.
func NewGenesisBlock() *Block {
	block := &Block{
		Index:            0,
		Timestamp:        time.Now().Unix(),
		VerkleRoot:       []byte{}, // Or some predefined value, since it's a special case.
		PrevHash:         hash.NullHash(),
		Hash:             hash.NullHash(),
		ValidatorAddress: *address.NullAddress(),
	}
	block.ComputeHash()
	return block
}

// Verify verifies the integrity of the block by checking its hash, previous hash, and transactions.
func (b *Block) Verify() error {
	// Check if the previous hash matches
	if b.PrevHash == hash.NullHash() || !b.PrevHash.Equal(b.Hash) {
		return fmt.Errorf("block's previous hash does not match the hash of the previous block")
	}

	b.ComputeHash()
	if !b.Hash.Equal(hash.NullHash()) {
		return fmt.Errorf("block's hash does not match the computed hash")
	}

	// Check if each transaction has a salt
	for i, tx := range b.Transactions {
		if len(tx.Salt) == 0 {
			return fmt.Errorf("transaction %d is missing salt", i)
		}
	}

	return nil
}

func (b *Block) SerializeForSigning() ([]byte, error) {
	// Create the block protobuf with all transaction data
	blockCopy := *b
	blockCopy.Hash = hash.NullHash()
	blockCopy.Signature = nil
	blockCopy.Salt = nil
	// Marshal the block to bytes
	blockBytes, err := blockCopy.Marshal()
	if err != nil {
		return nil, fmt.Errorf("failed to marshal block for signing: %v", err)
	}
	return blockBytes, nil
}

// MarshalCBOR serializes the block into CBOR format.
func (b *Block) Marshal() ([]byte, error) {
	return cbor.Marshal(b)
}

// UnmarshalCBOR deserializes the block from CBOR format.
func (b *Block) Unmarshal(data []byte) error {
	return cbor.Unmarshal(data, b)
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
		txByte, err := tx.Marshal()
		if err != nil {
			return fmt.Errorf("failed to serialize transaction: %v", err)
		}
		txData = append(txData, txByte)
	}

	tree, err := NewVerkleTree(txData)
	if err != nil {
		return fmt.Errorf("failed to create Verkle tree: %v", err)
	}

	commitment := tree.Commitment().BytesUncompressedTrusted()
	b.VerkleRoot = commitment[:]
	return nil
}

// Encoding binary data as base64 in JSON is common as not supported
func (b *Block) GetVerkleRootBase64() string {
	return base64.StdEncoding.EncodeToString(b.VerkleRoot)
}

func (b *Block) ComputeHash() {
	blockByte, err := b.SerializeForSigning()
	if err != nil {
		log.Printf("Failed to create serialise block: %v", err)
		return
	}
	b.Hash = hash.NewHash(blockByte)
}
