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
	if b == nil {
		return nil, errors.New("cannot serialize nil block for signing")
	}
	// Create a copy to avoid modifying the original block
	blockCopy := *b
	// Explicitly nil out fields that should not be part of the hash/signature content
	blockCopy.Hash = hash.NullHash() // Zero out the hash field
	blockCopy.Signature = nil        // Remove the signature
	blockCopy.Salt = nil             // Remove the salt

	// Marshal the modified block copy to bytes
	// Assumes blockCopy.Marshal() handles the serialization (e.g., to CBOR)
	blockBytes, err := blockCopy.Marshal()
	if err != nil {
		return nil, fmt.Errorf("failed to marshal block copy for signing (Index %d): %w", b.Index, err)
	}

	// --- ADDED LOGGING ---
	// Log the final byte slice that will be returned (and subsequently hashed)
	log.Printf("DEBUG: [SerializeForSigning] Bytes Serialized for Hashing/Signing (Block %d): %s", b.Index, hex.EncodeToString(blockBytes))
	// --- END ADDED LOGGING ---

	return blockBytes, nil
}

func ComputeBlockHash(b *types.Block) error { // Return an error
	if b == nil {
		return errors.New("cannot compute hash for nil block")
	}

	// Serialize the block specifically for hashing (excluding signature, existing hash, salt)
	blockByte, err := SerializeForSigning(b) // Calls the function below
	if err != nil {
		log.Printf("ERROR: [ComputeBlockHash] Failed to serialize block %d for hashing: %v", b.Index, err)
		return fmt.Errorf("failed to serialize block for hash: %w", err)
	}
	if len(blockByte) == 0 {
		log.Printf("ERROR: [ComputeBlockHash] Serialized block %d resulted in zero bytes for hashing.", b.Index)
		return errors.New("serialized block for hashing is empty")
	}

	// --- Logging the bytes JUST BEFORE hashing ---
	// This log was already present and is crucial for comparison.
	log.Printf("DEBUG: [ComputeBlockHash] Bytes for Hashing (Block %d): %s", b.Index, hex.EncodeToString(blockByte))
	// --- End Logging ---

	// Compute the hash using the serialized bytes
	b.Hash = hash.NewHash(blockByte)

	// Check if the hash computation resulted in a zero hash
	if b.Hash.Equal(hash.NullHash()) {
		log.Printf("ERROR: [ComputeBlockHash] Computed hash for block %d is zero hash.", b.Index)
		return errors.New("computed hash is zero value")
	}

	return nil // Indicate success
}
