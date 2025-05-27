package chain

import (
	"encoding/hex"
	"errors"
	"fmt"
	"log"
	"time"

	"github.com/cloudflare/circl/sign/mldsa/mldsa44"
	thrylos "github.com/thrylos-labs/thrylos"
	"github.com/thrylos-labs/thrylos/crypto/hash"
	"github.com/thrylos-labs/thrylos/types"
	"github.com/thrylos-labs/thrylos/utils"
)

func (bc *BlockchainImpl) VerifySignedBlock(signedBlock *types.Block) error {
	// Store the original hash
	originalHash := signedBlock.Hash

	// Compute the block hash
	ComputeBlockHash(signedBlock)
	computedHash := signedBlock.Hash

	// Restore the original hash after computation
	signedBlock.Hash = originalHash

	// Compare hashes using the Equal method
	if !computedHash.Equal(originalHash) {
		log.Printf("Block hash mismatch. Computed: %x, Block: %x", computedHash.Bytes(), originalHash.Bytes())
		return errors.New("invalid block hash")
	}

	publicKey, err := bc.GetValidatorPublicKey(signedBlock.Validator)
	if err != nil {
		log.Printf("Failed to get validator public key: %v", err)
		return fmt.Errorf("failed to get validator public key: %v", err)
	}

	pubKeyBytes, err := publicKey.MarshalBinary()
	if err != nil {
		return fmt.Errorf("failed to marshal public key for logging: %v", err)
	}
	log.Printf("Retrieved public key for verification: %x", pubKeyBytes)

	// Convert Hash to bytes for verification
	hashBytes := signedBlock.Hash.Bytes()

	// Get signature bytes
	sigBytes := signedBlock.Signature.Bytes()

	// Verify the signature using MLDSA44
	if !mldsa44.Verify(publicKey, hashBytes, nil, sigBytes) {
		log.Printf("Signature verification failed. Validator: %s, Block Hash: %x, Signature: %x",
			signedBlock.Validator, hashBytes, sigBytes)
		return errors.New("invalid block signature")
	}

	log.Printf("Block signature verified successfully for validator: %s", signedBlock.Validator)
	return nil
}

// // CreateBlock generates a new block with the given transactions, validator, previous hash, and timestamp.
// // This method encapsulates the logic for building a block to be added to the blockchain.
func (bc *BlockchainImpl) CreateUnsignedBlock(transactions []*thrylos.Transaction, validator string) (*types.Block, error) {
	// --- Acquire Lock (Read lock sufficient for getting prev block) ---
	bc.ShardState.Mu.RLock()
	if len(bc.ShardState.Blocks) == 0 {
		bc.ShardState.Mu.RUnlock()
		return nil, errors.New("cannot create new block: blockchain is empty (no genesis block?)")
	}
	prevBlock := bc.ShardState.Blocks[len(bc.ShardState.Blocks)-1]
	nextIndex := int64(len(bc.ShardState.Blocks))
	bc.ShardState.Mu.RUnlock() // Release read lock
	// --- End Lock ---

	// Convert transactions from protobuf (thrylos.Transaction) to shared type (types.Transaction)
	sharedTransactions := make([]*types.Transaction, len(transactions))
	for i, txProto := range transactions {
		// --- FIX: Correct assignment ---
		// ConvertToSharedTransaction only returns *types.Transaction, not an error
		sharedTx := utils.ConvertToSharedTransaction(txProto)
		// --- END FIX ---

		// Check if conversion resulted in nil (ConvertToSharedTransaction handles internal errors by returning nil)
		if sharedTx == nil {
			// Log the specific proto Tx ID if possible
			protoTxID := "unknown"
			if txProto != nil {
				protoTxID = txProto.GetId()
			}
			return nil, fmt.Errorf("conversion returned nil for transaction at index %d (Proto ID: %s)", i, protoTxID)
		}
		sharedTransactions[i] = sharedTx
	}

	// Create the basic block structure
	newBlock := &types.Block{
		Index:        nextIndex,
		Timestamp:    time.Now().Unix(),
		Transactions: sharedTransactions, // Use the converted transactions
		Validator:    validator,
		PrevHash:     prevBlock.Hash,  // Hash from the actual previous block
		Hash:         hash.NullHash(), // Initialize hash
		// Signature will be added later
		// TransactionsRoot will be calculated next
	}

	// --- MERKLE TREE CALCULATION ---
	merkleRoot, err := CalculateTransactionsMerkleRoot(newBlock.Transactions) // Use helper from block.go
	if err != nil {
		return nil, fmt.Errorf("failed to calculate Merkle root for new block %d: %w", nextIndex, err)
	}
	newBlock.TransactionsRoot = merkleRoot
	log.Printf("DEBUG: [CreateUnsignedBlock] Calculated Merkle Root for block %d: %s", newBlock.Index, hex.EncodeToString(newBlock.TransactionsRoot))
	// --- END MERKLE TREE CALCULATION ---

	// Compute the block hash *after* TransactionsRoot is set
	if err := ComputeBlockHash(newBlock); err != nil { // Use helper from block.go
		return nil, fmt.Errorf("failed to compute block hash for unsigned block %d: %w", nextIndex, err)
	}
	log.Printf("DEBUG: [CreateUnsignedBlock] Computed Hash for unsigned block %d: %s", newBlock.Index, newBlock.Hash.String())

	return newBlock, nil
}
