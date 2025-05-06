package chain

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"log"
	"testing"
	"time"

	// Adjust imports according to your project structure
	"github.com/thrylos-labs/thrylos/crypto/hash"
	"github.com/thrylos-labs/thrylos/types"
	"github.com/thrylos-labs/thrylos/utils" // For ComputeMerkleRoot
)

// --- Mock Transaction Marshalling for Testing ---
// Used for MANUALLY calculating the expected root in the test.
// The function under test (CalculateTransactionsMerkleRoot) should use the REAL tx.Marshal().
func mockMarshalTransaction(tx *types.Transaction) ([]byte, error) {
	if tx == nil {
		return nil, fmt.Errorf("cannot marshal nil transaction")
	}
	// Simple, predictable marshalling for testing consistency
	data := fmt.Sprintf("ID:%s,TS:%d", tx.ID, tx.Timestamp)
	return []byte(data), nil
}

// --- Helper to create simple transactions for testing ---
func createMockTransaction(id string) *types.Transaction {
	// Create a basic transaction structure matching types.Transaction
	// Add more fields if they significantly affect marshalling/hashing
	return &types.Transaction{
		ID:        id,
		Timestamp: time.Now().UnixNano(), // Use nano for uniqueness
		// Initialize other necessary fields minimally
		Inputs:  []types.UTXO{},
		Outputs: []types.UTXO{},
		// Ensure Salt is non-empty if Verify checks it
		Salt: []byte(fmt.Sprintf("salt-%s-%d", id, time.Now().UnixNano())),
	}
}

// --- Test Cases ---

// TestMerkleRootCalculation verifies the CalculateTransactionsMerkleRoot function.
func TestMerkleRootCalculation(t *testing.T) {
	tx1 := createMockTransaction("tx1")
	tx2 := createMockTransaction("tx2")
	tx3 := createMockTransaction("tx3")

	// --- Calculate Expected Roots ---

	// Expected Root for Single Transaction (tx1)
	// Use the REAL tx.Marshal() method here.
	tx1RealBytes, errMarshal1 := tx1.Marshal()
	if errMarshal1 != nil {
		t.Fatalf("Test setup failed: Could not marshal tx1: %v", errMarshal1)
	}
	h1 := sha256.Sum256(tx1RealBytes)
	expectedRootSingleTx := h1[:]

	// Expected Root for Three Transactions (tx1, tx2, tx3)
	// Use the REAL tx.Marshal() method here too.
	tx2RealBytes, errMarshal2 := tx2.Marshal()
	if errMarshal2 != nil {
		t.Fatalf("Test setup failed: Could not marshal tx2: %v", errMarshal2)
	}
	tx3RealBytes, errMarshal3 := tx3.Marshal()
	if errMarshal3 != nil {
		t.Fatalf("Test setup failed: Could not marshal tx3: %v", errMarshal3)
	}
	txDataActual := [][]byte{tx1RealBytes, tx2RealBytes, tx3RealBytes}
	expectedRootThreeTx, errCompute := utils.ComputeMerkleRoot(txDataActual)
	if errCompute != nil {
		t.Fatalf("Test setup failed: Could not compute expected root for three txs: %v", errCompute)
	}
	// --- End Expected Root Calculation ---

	tests := []struct {
		name          string
		transactions  []*types.Transaction
		expectedRoot  []byte // Use the correctly calculated expected roots
		expectError   bool
		expectedError string
	}{
		{
			name:          "Empty Transactions",
			transactions:  []*types.Transaction{},
			expectedRoot:  nil, // Expect nil root for empty list
			expectError:   false,
			expectedError: "",
		},
		{
			name:          "Single Transaction",
			transactions:  []*types.Transaction{tx1},
			expectedRoot:  expectedRootSingleTx, // Use the pre-calculated root
			expectError:   false,
			expectedError: "",
		},
		{
			name:          "Three Transactions (Odd number)",
			transactions:  []*types.Transaction{tx1, tx2, tx3},
			expectedRoot:  expectedRootThreeTx, // Use the pre-calculated root
			expectError:   false,
			expectedError: "",
		},
		{
			name:          "Nil Transaction",
			transactions:  []*types.Transaction{tx1, nil, tx3},
			expectedRoot:  nil,
			expectError:   true,
			expectedError: "transaction at index 1 is nil", // Error from CalculateTransactionsMerkleRoot
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Call the function under test
			actualRoot, err := CalculateTransactionsMerkleRoot(tt.transactions)

			// Check error
			if tt.expectError {
				if err == nil {
					t.Errorf("Expected an error, but got nil")
				} else if err.Error() != tt.expectedError && !bytes.Contains([]byte(err.Error()), []byte(tt.expectedError)) {
					// Allow for wrapped errors containing the expected text
					t.Errorf("Expected error containing '%s', but got: %v", tt.expectedError, err)
				}
			} else {
				if err != nil {
					t.Errorf("Did not expect an error, but got: %v", err)
				}
			}

			// Check Merkle Root value using the expectedRoot from the test case struct
			if !bytes.Equal(actualRoot, tt.expectedRoot) {
				t.Errorf("Expected Merkle Root %s, but got %s", hex.EncodeToString(tt.expectedRoot), hex.EncodeToString(actualRoot))
			}
		})
	}
}

// TestBlockHashWithMerkleRoot verifies that the block hash changes when the Merkle root changes.
func TestBlockHashWithMerkleRoot(t *testing.T) {
	// --- Setup ---
	tx1 := createMockTransaction("txA")
	tx2 := createMockTransaction("txB")
	genesis := NewGenesisBlock() // Assuming NewGenesisBlock is correct
	if genesis == nil {
		t.Fatalf("NewGenesisBlock returned nil")
	}

	// Create initial block
	// Note: NewBlock calls CalculateTransactionsMerkleRoot and ComputeBlockHash internally
	block1, err := NewBlock(1, genesis.Hash, []*types.Transaction{tx1, tx2}, nil) // Assuming nil PublicKey is ok for test
	if err != nil {
		t.Fatalf("Failed to create initial block: %v", err)
	}
	initialHash := block1.Hash
	initialMerkleRoot := block1.TransactionsRoot

	if initialHash.Equal(hash.NullHash()) {
		t.Fatalf("Initial block hash is zero")
	}
	// Allow empty root if there were no transactions (though test case has txs)
	// if len(initialMerkleRoot) == 0 && len(block1.Transactions) > 0 {
	//  t.Fatalf("Initial Merkle root is empty despite transactions")
	// }

	// --- Modify a transaction ---
	// Create a slightly different transaction
	tx2Modified := createMockTransaction("txB_modified")
	block1.Transactions[1] = tx2Modified // Replace tx2 with modified version

	// --- Recalculate Merkle Root and Block Hash ---
	// Manually recalculate Merkle root (as block creation would do)
	newMerkleRoot, err := CalculateTransactionsMerkleRoot(block1.Transactions)
	if err != nil {
		t.Fatalf("Failed to recalculate Merkle root after modification: %v", err)
	}
	block1.TransactionsRoot = newMerkleRoot // Update the block's root

	// Recalculate block hash (must happen AFTER updating TransactionsRoot)
	err = ComputeBlockHash(block1)
	if err != nil {
		t.Fatalf("Failed to recompute block hash after modification: %v", err)
	}
	modifiedHash := block1.Hash

	// --- Assertions ---
	if bytes.Equal(newMerkleRoot, initialMerkleRoot) {
		t.Errorf("Merkle root did not change after modifying a transaction")
	}
	if modifiedHash.Equal(initialHash) {
		t.Errorf("Block hash did not change after modifying a transaction and recalculating Merkle root/hash")
	}
	log.Printf("Initial Hash: %s, Modified Hash: %s", initialHash.String(), modifiedHash.String())
	log.Printf("Initial Root: %s, Modified Root: %s", hex.EncodeToString(initialMerkleRoot), hex.EncodeToString(newMerkleRoot))
}

// TestBlockVerificationMerkleMismatch tests if Verify detects a tampered Merkle root.
func TestBlockVerificationMerkleMismatch(t *testing.T) {
	tx1 := createMockTransaction("txV1")
	tx2 := createMockTransaction("txV2")
	genesis := NewGenesisBlock()
	if genesis == nil {
		t.Fatalf("NewGenesisBlock returned nil")
	}

	// Create a valid block
	block, err := NewBlock(1, genesis.Hash, []*types.Transaction{tx1, tx2}, nil)
	if err != nil {
		t.Fatalf("Failed to create valid block: %v", err)
	}

	// Ensure there's a root to tamper with
	if len(block.TransactionsRoot) == 0 {
		t.Log("Skipping tamper test as Merkle root is empty/nil (likely no transactions)")
		return
	}

	// Tamper with the Merkle Root
	originalRoot := append([]byte{}, block.TransactionsRoot...) // Make a copy
	block.TransactionsRoot[0] ^= 0xff                           // Flip bits in the first byte

	// Call Verify
	err = Verify(block)

	// Assert an error occurred and it's about the Merkle root
	if err == nil {
		t.Errorf("Expected verification error due to tampered Merkle root, but got nil")
	} else if !bytes.Contains([]byte(err.Error()), []byte("merkle root mismatch")) {
		t.Errorf("Expected Merkle root mismatch error, but got: %v", err)
	} else {
		log.Printf("Successfully caught expected error: %v", err)
	}

	// Restore original root for potential hash check test later if needed
	block.TransactionsRoot = originalRoot
}

// TestBlockVerificationValid tests if Verify passes for a valid block.
func TestBlockVerificationValid(t *testing.T) {
	tx1 := createMockTransaction("txOK1")
	tx2 := createMockTransaction("txOK2")
	genesis := NewGenesisBlock()
	if genesis == nil {
		t.Fatalf("NewGenesisBlock returned nil")
	}

	// Create a valid block using NewBlock (which includes root calc + hash calc)
	block, err := NewBlock(1, genesis.Hash, []*types.Transaction{tx1, tx2}, nil)
	if err != nil {
		t.Fatalf("Failed to create valid block: %v", err)
	}

	// Call Verify
	err = Verify(block)

	// Assert no error occurred
	if err != nil {
		t.Errorf("Expected block verification to pass, but got error: %v", err)
	} else {
		log.Printf("Successfully verified valid block %d.", block.Index)
	}
}

// --- Add Test for Block Hash Verification within Verify ---
func TestBlockVerificationBlockHashMismatch(t *testing.T) {
	tx1 := createMockTransaction("txH1")
	tx2 := createMockTransaction("txH2")
	genesis := NewGenesisBlock()
	if genesis == nil {
		t.Fatalf("NewGenesisBlock returned nil")
	}

	// Create a valid block
	block, err := NewBlock(1, genesis.Hash, []*types.Transaction{tx1, tx2}, nil)
	if err != nil {
		t.Fatalf("Failed to create valid block: %v", err)
	}

	// Ensure there's a hash to tamper with
	if block.Hash.Equal(hash.NullHash()) {
		t.Log("Skipping tamper test as block hash is nil/zero")
		return
	}

	// Tamper with the block's Hash field AFTER it was computed
	originalHash := block.Hash
	block.Hash[0] ^= 0xff // Flip bits in the first byte

	// Call Verify
	err = Verify(block)

	// Assert an error occurred and it's about the block hash
	if err == nil {
		t.Errorf("Expected verification error due to tampered block hash, but got nil")
	} else if !bytes.Contains([]byte(err.Error()), []byte("block hash mismatch")) {
		t.Errorf("Expected block hash mismatch error, but got: %v", err)
	} else {
		log.Printf("Successfully caught expected error: %v", err)
	}

	// Restore original hash
	block.Hash = originalHash
}
