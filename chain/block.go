package chain

import (
	"encoding/hex"
	"errors"
	"fmt"
	"log"
	"time"

	"github.com/thrylos-labs/thrylos/crypto"
	"github.com/thrylos-labs/thrylos/crypto/hash"
	"github.com/thrylos-labs/thrylos/types"
)

// NewBlock creates a new block with the specified parameters, including the index, transactions,
// previous hash, and validator. This function also calculates the current timestamp and the block's
// hash, ensuring the block is ready to be added to the blockchain.

func NewBlock(index int64, prevHash hash.Hash, transactions []*types.Transaction, validatorPublicKey crypto.PublicKey) (*types.Block, error) {
	block := &types.Block{
		Index:              index,
		Timestamp:          time.Now().Unix(),
		PrevHash:           prevHash,
		Transactions:       transactions,
		ValidatorPublicKey: validatorPublicKey,
	}

	if err := InitializeVerkleTree(block); err != nil {
		return nil, fmt.Errorf("failed to initialize Verkle tree: %v", err)
	}

	ComputeBlockHash(block)
	return block, nil
}

// NewGenesisBlock creates and returns the genesis block for the blockchain. The genesis block
// is the first block in the blockchain, serving as the foundation upon which the entire chain is built.
func NewGenesisBlock() *types.Block {
	block := &types.Block{
		Index:      0,
		Timestamp:  time.Now().Unix(),
		VerkleRoot: []byte{}, // Or some predefined value, since it's a special case.
		PrevHash:   hash.NullHash(),
		Hash:       hash.NullHash(),
	}
	ComputeBlockHash(block)
	return block
}

// Verify verifies the integrity of the block by checking its hash, previous hash, and transactions.
func Verify(b *types.Block) error {
	// Check if the previous hash matches
	if b.PrevHash == hash.NullHash() || !b.PrevHash.Equal(b.Hash) {
		return fmt.Errorf("block's previous hash does not match the hash of the previous block")
	}

	ComputeBlockHash(b)
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

func SerializeForSigning(b *types.Block) ([]byte, error) {
	// Create a copy to avoid modifying the original
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

// InitializeVerkleTree initializes the Verkle Tree lazily and calculates its root.
func InitializeVerkleTree(b *types.Block) error {
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

func ComputeBlockHash(b *types.Block) error { // Return an error
	if b == nil {
		return errors.New("cannot compute hash for nil block")
	}
	blockByte, err := SerializeForSigning(b) // Calls the existing SerializeForSigning
	if err != nil {
		log.Printf("ERROR: [ComputeBlockHash] Failed to serialize block %d for hashing: %v", b.Index, err)
		return fmt.Errorf("failed to serialize block for hash: %w", err)
	}
	if len(blockByte) == 0 {
		log.Printf("ERROR: [ComputeBlockHash] Serialized block %d resulted in zero bytes for hashing.", b.Index)
		return errors.New("serialized block for hashing is empty")
	}

	// Log the bytes being hashed for debugging consistency
	log.Printf("DEBUG: [ComputeBlockHash] Bytes for Hashing (Block %d): %s", b.Index, hex.EncodeToString(blockByte))

	b.Hash = hash.NewHash(blockByte) // Compute the hash

	// Optional: Check if the hash computation itself resulted in a zero hash
	// --- CORRECTED METHOD CALL ---
	if b.Hash.Equal(hash.NullHash()) { // Use Equal instead of IsEqual
		log.Printf("ERROR: [ComputeBlockHash] Computed hash for block %d is zero hash.", b.Index)
		return errors.New("computed hash is zero value")
	}
	// --- END CORRECTION ---

	return nil // Indicate success
}
