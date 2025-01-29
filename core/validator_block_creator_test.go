package core

import (
	"fmt"
	"sync"
	"testing"
	"time"

	thrylos "github.com/thrylos-labs/thrylos"
)

// MockBlockchainForValidator implements the test blockchain
type MockBlockchainForValidator struct {
	ActiveValidators []string
	PendingTxs       []*thrylos.Transaction
	PropagatedTxs    map[string][]string
	Stakeholders     map[string]int64
	Blocks           []*Block
	mu               sync.RWMutex
}

func NewMockBlockchainForValidator() *MockBlockchainForValidator {
	// Create genesis block
	genesis := NewGenesisBlock()

	mock := &MockBlockchainForValidator{
		ActiveValidators: []string{"validator1", "validator2", "validator3"},
		PendingTxs:       make([]*thrylos.Transaction, 0),
		PropagatedTxs:    make(map[string][]string),
		Blocks:           []*Block{genesis},
		Stakeholders: map[string]int64{
			"validator1": 1000,
			"validator2": 2000,
			"validator3": 3000,
		},
	}

	return mock
}

// Add these methods to implement required functionality for tests
func (mb *MockBlockchainForValidator) IsActiveValidator(address string) bool {
	for _, v := range mb.ActiveValidators {
		if v == address {
			return true
		}
	}
	return false
}

func (mb *MockBlockchainForValidator) ProcessPendingTransactions(validator string) (*Block, error) {
	if len(mb.PendingTxs) == 0 {
		return nil, fmt.Errorf("no pending transactions")
	}

	block := &Block{
		Index:        int32(len(mb.Blocks)),
		Timestamp:    time.Now().Unix(),
		Transactions: mb.PendingTxs,
		Validator:    validator,
		PrevHash:     mb.Blocks[len(mb.Blocks)-1].Hash,
	}

	return block, nil
}

func (mb *MockBlockchainForValidator) VerifySignedBlock(block *Block) error {
	// Simplified verification for testing
	if block == nil {
		return fmt.Errorf("nil block")
	}
	return nil
}

func (mb *MockBlockchainForValidator) AddBlock(transactions []*thrylos.Transaction, validator string, prevHash []byte) (bool, error) {
	block := &Block{
		Index:        int32(len(mb.Blocks)),
		Timestamp:    time.Now().Unix(),
		Transactions: transactions,
		Validator:    validator,
		PrevHash:     prevHash,
	}
	mb.Blocks = append(mb.Blocks, block)
	return true, nil
}

func (mb *MockBlockchainForValidator) CreateBlockFromPendingTransactions(validator string) (*Block, error) {
	if !mb.IsActiveValidator(validator) {
		return nil, fmt.Errorf("invalid or inactive validator: %s", validator)
	}

	block, err := mb.ProcessPendingTransactions(validator)
	if err != nil {
		return nil, fmt.Errorf("failed to process pending transactions: %v", err)
	}

	if block == nil {
		return nil, fmt.Errorf("no pending transactions to process")
	}

	if err := mb.VerifySignedBlock(block); err != nil {
		return nil, fmt.Errorf("block verification failed: %v", err)
	}

	success, err := mb.AddBlock(block.Transactions, validator, mb.Blocks[len(mb.Blocks)-1].Hash)
	if !success {
		return nil, fmt.Errorf("failed to add block to chain: %v", err)
	}

	return block, nil
}

func (mb *MockBlockchainForValidator) CreateNextBlock() (*Block, error) {
	selector := NewValidatorSelector(mb)

	validator, err := selector.SelectNextValidator()
	if err != nil {
		return nil, fmt.Errorf("failed to select validator: %v", err)
	}

	return mb.CreateBlockFromPendingTransactions(validator)
}

// Tests
func TestValidatorSelection(t *testing.T) {
	mockBC := NewMockBlockchainForValidator()
	selector := NewValidatorSelector(mockBC)

	validator, err := selector.SelectNextValidator()
	if err != nil {
		t.Errorf("Failed to select validator: %v", err)
	}

	if validator != "validator3" {
		t.Errorf("Expected validator3 to be selected (highest stake), got %s", validator)
	}
}

func (mb *MockBlockchainForValidator) GetActiveValidators() []string {
	return mb.ActiveValidators
}

func (mb *MockBlockchainForValidator) GetStakeholders() map[string]int64 {
	return mb.Stakeholders
}

func TestValidatorSelectionWithNoValidators(t *testing.T) {
	mockBC := NewMockBlockchainForValidator()
	mockBC.ActiveValidators = []string{}
	selector := NewValidatorSelector(mockBC)

	_, err := selector.SelectNextValidator()
	if err == nil {
		t.Error("Expected error when no validators available, got nil")
	}
}

func TestCreateBlockFromPendingTransactions(t *testing.T) {
	mockBC := NewMockBlockchainForValidator()

	tx1 := &thrylos.Transaction{
		Id:        "test-tx-1",
		Timestamp: time.Now().Unix(),
		Sender:    "test-sender",
		Salt:      make([]byte, 32),
	}
	tx2 := &thrylos.Transaction{
		Id:        "test-tx-2",
		Timestamp: time.Now().Unix(),
		Sender:    "test-sender",
		Salt:      make([]byte, 32),
	}

	mockBC.PendingTxs = append(mockBC.PendingTxs, tx1, tx2)

	block, err := mockBC.CreateBlockFromPendingTransactions("validator3")
	if err != nil {
		t.Errorf("Failed to create block: %v", err)
	}

	if block == nil {
		t.Error("Expected block to be created, got nil")
	}

	if block != nil {
		if len(block.Transactions) != 2 {
			t.Errorf("Expected 2 transactions in block, got %d", len(block.Transactions))
		}
		if block.Validator != "validator3" {
			t.Errorf("Expected validator3 as block validator, got %s", block.Validator)
		}
	}
}

func TestCreateBlockWithInvalidValidator(t *testing.T) {
	mockBC := NewMockBlockchainForValidator()

	_, err := mockBC.CreateBlockFromPendingTransactions("invalid-validator")
	if err == nil {
		t.Error("Expected error when using invalid validator, got nil")
	}
}

func TestCreateBlockWithNoPendingTransactions(t *testing.T) {
	mockBC := NewMockBlockchainForValidator()

	_, err := mockBC.CreateBlockFromPendingTransactions("validator3")
	if err == nil {
		t.Error("Expected error when no pending transactions, got nil")
	}
}

func TestCreateNextBlock(t *testing.T) {
	mockBC := NewMockBlockchainForValidator()

	tx := &thrylos.Transaction{
		Id:        "test-tx-1",
		Timestamp: time.Now().Unix(),
		Sender:    "test-sender",
		Salt:      make([]byte, 32),
	}
	mockBC.PendingTxs = append(mockBC.PendingTxs, tx)

	block, err := mockBC.CreateNextBlock()
	if err != nil {
		t.Errorf("Failed to create next block: %v", err)
	}

	if block == nil {
		t.Error("Expected block to be created, got nil")
	}

	if block != nil && block.Validator != "validator3" {
		t.Errorf("Expected block to be created by validator3, got %s", block.Validator)
	}
}
