package chain

import (
	"bytes" // Needed for Verify function
	"encoding/hex"
	"errors"
	"fmt"
	"log"
	"time"

	// Adjust import paths as per your project structure
	"github.com/thrylos-labs/thrylos/crypto"
	"github.com/thrylos-labs/thrylos/crypto/hash"
	"github.com/thrylos-labs/thrylos/types"
	"github.com/thrylos-labs/thrylos/utils" // Assuming ComputeMerkleRoot is here
)

// NewBlock creates a new block with the specified parameters.
// It calculates the Merkle root of the transactions and the block's hash.
func NewBlock(index int64, prevHash hash.Hash, transactions []*types.Transaction, validatorPublicKey crypto.PublicKey) (*types.Block, error) {
	block := &types.Block{
		Index:              index,
		Timestamp:          time.Now().Unix(),
		PrevHash:           prevHash,
		Transactions:       transactions,
		ValidatorPublicKey: validatorPublicKey, // Assuming this is still needed
		Hash:               hash.NullHash(),    // Initialize hash
		// Signature will be added later
	}

	// --- MERKLE TREE INTEGRATION ---
	// Calculate Merkle Root for transactions
	merkleRoot, err := CalculateTransactionsMerkleRoot(block.Transactions)
	if err != nil {
		return nil, fmt.Errorf("failed to calculate Merkle root for new block %d: %w", index, err)
	}
	block.TransactionsRoot = merkleRoot
	log.Printf("DEBUG: [NewBlock] Calculated Merkle Root for block %d: %s", block.Index, hex.EncodeToString(block.TransactionsRoot))
	// --- END MERKLE TREE INTEGRATION ---

	// Compute block hash *after* setting TransactionsRoot
	if err := ComputeBlockHash(block); err != nil {
		return nil, fmt.Errorf("failed to compute block hash for block %d: %w", index, err)
	}

	return block, nil
}

// NewGenesisBlock creates and returns the genesis block.
func NewGenesisBlock() *types.Block {
	block := &types.Block{
		Index:            0,
		Timestamp:        time.Now().Unix(),
		Transactions:     []*types.Transaction{}, // Empty transactions slice
		PrevHash:         hash.NullHash(),
		Hash:             hash.NullHash(),
		TransactionsRoot: nil, // Explicitly nil for genesis, or a predefined empty hash
		// REMOVED VerkleRoot
	}

	// Compute hash (which includes the nil TransactionsRoot)
	// ComputeBlockHash should handle nil/empty TransactionsRoot gracefully if needed
	if err := ComputeBlockHash(block); err != nil {
		// This should ideally not fail for genesis, but handle defensively
		log.Fatalf("CRITICAL: Failed to compute genesis block hash: %v", err)
		return nil // Or panic, as genesis failure is critical
	}
	log.Printf("DEBUG: [NewGenesisBlock] Computed Genesis Hash: %s", block.Hash.String())
	return block
}

// Verify checks the integrity of the block including the Merkle root.
func Verify(b *types.Block) error {
	if b == nil {
		return errors.New("cannot verify nil block")
	}

	// --- MERKLE ROOT VERIFICATION ---
	// Recalculate the Merkle root from the block's transactions
	recalculatedMerkleRoot, err := CalculateTransactionsMerkleRoot(b.Transactions)
	if err != nil {
		return fmt.Errorf("failed to recalculate Merkle root for block %d verification: %w", b.Index, err)
	}

	// Compare the recalculated root with the one stored in the block
	if !bytes.Equal(recalculatedMerkleRoot, b.TransactionsRoot) {
		log.Printf("ERROR: Merkle Root mismatch for block %d!", b.Index)
		log.Printf("  Stored Root:     %s", hex.EncodeToString(b.TransactionsRoot))
		log.Printf("  Recalculated Root: %s", hex.EncodeToString(recalculatedMerkleRoot))
		return fmt.Errorf("merkle root mismatch for block %d", b.Index)
	}
	log.Printf("DEBUG: [Verify] Merkle Root verified successfully for block %d.", b.Index)
	// --- END MERKLE ROOT VERIFICATION ---

	// --- BLOCK HASH VERIFICATION ---
	// Store the original hash
	originalHash := b.Hash
	if originalHash.Equal(hash.NullHash()) {
		return fmt.Errorf("block %d has zero hash field during verification", b.Index)
	}

	// Recompute the hash based on block content (including TransactionsRoot)
	if err := ComputeBlockHash(b); err != nil {
		// Restore original hash before returning error
		b.Hash = originalHash
		return fmt.Errorf("failed to recompute block hash for verification on block %d: %w", b.Index, err)
	}
	recomputedHash := b.Hash

	// Restore original hash after computation
	b.Hash = originalHash

	// Compare original hash with recomputed hash
	if !originalHash.Equal(recomputedHash) {
		log.Printf("ERROR: Block Hash mismatch for block %d!", b.Index)
		log.Printf("  Stored Hash:     %s", originalHash.String())
		log.Printf("  Recalculated Hash: %s", recomputedHash.String())
		// Log the bytes that were hashed during recomputation for debugging
		serializedBytes, _ := SerializeForSigning(b) // Ignore error for logging
		log.Printf("  Bytes Hashed (Recalculation): %s", hex.EncodeToString(serializedBytes))
		return fmt.Errorf("block hash mismatch for block %d", b.Index)
	}
	log.Printf("DEBUG: [Verify] Block Hash verified successfully for block %d.", b.Index)
	// --- END BLOCK HASH VERIFICATION ---

	// --- PREVIOUS HASH VERIFICATION (Only for non-genesis blocks) ---
	if b.Index > 0 {
		// This check requires access to the *previous* block's hash.
		// This function signature doesn't allow that.
		// This check should likely happen in AddBlockToChain where the previous block is known.
		// Removing the check from here as it cannot be performed correctly without context.
		// log.Printf("WARN: [Verify] Cannot verify PrevHash within this function signature.")
	}
	// --- END PREVIOUS HASH VERIFICATION ---

	// --- TRANSACTION-SPECIFIC CHECKS ---
	// Check if each transaction has a salt (keep this if needed)
	for i, tx := range b.Transactions {
		if len(tx.Salt) == 0 { // Assuming types.Transaction has a Salt field
			return fmt.Errorf("transaction %d in block %d is missing salt", i, b.Index)
		}
		// Add other transaction validation if needed (e.g., signature checks if not done elsewhere)
	}
	// --- END TRANSACTION-SPECIFIC CHECKS ---

	log.Printf("INFO: [Verify] Block %d verified successfully.", b.Index)
	return nil
}

// SerializeForSigning prepares the block data for hashing or signing.
// IMPORTANT: Assumes the types.Block.Marshal method includes TransactionsRoot.
func SerializeForSigning(b *types.Block) ([]byte, error) {
	if b == nil {
		return nil, errors.New("cannot serialize nil block for signing")
	}
	// Create a copy to avoid modifying the original block
	blockCopy := *b
	// Explicitly nil out fields that should not be part of the hash/signature content
	blockCopy.Hash = hash.NullHash() // Zero out the hash field
	blockCopy.Signature = nil        // Remove the signature
	blockCopy.Salt = nil             // Remove the salt if it shouldn't be part of the hash

	// *** CRITICAL ASSUMPTION ***
	// We assume blockCopy.Marshal() correctly includes the TransactionsRoot field.
	// If not, you MUST modify the Marshal method for types.Block.
	blockBytes, err := blockCopy.Marshal()
	if err != nil {
		return nil, fmt.Errorf("failed to marshal block copy for signing/hashing (Index %d): %w", b.Index, err)
	}

	log.Printf("DEBUG: [SerializeForSigning] Bytes Serialized for Hashing/Signing (Block %d): %s", b.Index, hex.EncodeToString(blockBytes))

	return blockBytes, nil
}

// ComputeBlockHash calculates and sets the block's hash.
// It now relies on SerializeForSigning which should include the TransactionsRoot.
func ComputeBlockHash(b *types.Block) error {
	if b == nil {
		return errors.New("cannot compute hash for nil block")
	}

	// Serialize the block including TransactionsRoot, excluding Hash, Signature, Salt
	blockByte, err := SerializeForSigning(b)
	if err != nil {
		log.Printf("ERROR: [ComputeBlockHash] Failed to serialize block %d for hashing: %v", b.Index, err)
		return fmt.Errorf("failed to serialize block for hash: %w", err)
	}
	if len(blockByte) == 0 {
		log.Printf("ERROR: [ComputeBlockHash] Serialized block %d resulted in zero bytes for hashing.", b.Index)
		return errors.New("serialized block for hashing is empty")
	}

	log.Printf("DEBUG: [ComputeBlockHash] Bytes for Hashing (Block %d): %s", b.Index, hex.EncodeToString(blockByte))

	// Compute the hash using the serialized bytes
	b.Hash = hash.NewHash(blockByte) // Assuming hash.NewHash uses SHA256 or similar

	if b.Hash.Equal(hash.NullHash()) {
		log.Printf("ERROR: [ComputeBlockHash] Computed hash for block %d is zero hash.", b.Index)
		return errors.New("computed hash is zero value")
	}

	return nil // Indicate success
}

// CalculateTransactionsMerkleRoot computes the Merkle root for a slice of transactions.
func CalculateTransactionsMerkleRoot(transactions []*types.Transaction) ([]byte, error) {
	if len(transactions) == 0 {
		return nil, nil // No transactions, no root (or return a predefined empty hash)
	}

	// Prepare data for Merkle tree (marshal each transaction)
	txData := make([][]byte, 0, len(transactions))
	for i, tx := range transactions {
		if tx == nil {
			return nil, fmt.Errorf("cannot compute Merkle root: transaction at index %d is nil", i)
		}
		// Assuming types.Transaction has a Marshal method
		txBytes, err := tx.Marshal()
		if err != nil {
			return nil, fmt.Errorf("failed to marshal transaction %s (index %d) for Merkle root: %w", tx.ID, i, err)
		}
		txData = append(txData, txBytes)
	}

	// Compute the Merkle root using the utility function
	merkleRoot, err := utils.ComputeMerkleRoot(txData)
	if err != nil {
		// Wrap error from utility function for context
		return nil, fmt.Errorf("failed during Merkle tree computation: %w", err)
	}

	return merkleRoot, nil
}
