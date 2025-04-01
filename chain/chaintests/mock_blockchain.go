// File: chain/chaintests/mock_blockchain.go
package chaintests

import (
	"github.com/thrylos-labs/thrylos/crypto/hash"
	"github.com/thrylos-labs/thrylos/types"
)

// MockBlockchain implements the minimal functionality needed for testing the transaction pool
type MockBlockchain struct {
	blocks []*types.Block
}

// NewMockBlockchain creates a new mock blockchain for testing
func NewMockBlockchain() *MockBlockchain {
	// Create an empty hash for testing
	emptyHash, _ := hash.FromBytes(make([]byte, 32))

	return &MockBlockchain{
		blocks: []*types.Block{
			{
				Index:        0,
				Timestamp:    1617192000, // A fixed timestamp for testing
				PrevHash:     emptyHash,  // Use proper hash.Hash type
				Hash:         emptyHash,  // Use proper hash.Hash type
				Transactions: []*types.Transaction{},
			},
		},
	}
}

// GetBlocks returns the mock blocks
func (m *MockBlockchain) GetBlocks() []*types.Block {
	return m.blocks
}

// checkSaltInBlocks implements the method used by the transaction pool
func (m *MockBlockchain) checkSaltInBlocks(salt []byte) bool {
	// For testing purposes, always return false (no duplicate salt)
	return false
}
