package core

import (
	"fmt"
	"log"
	"sync"
	"time"
)

// ValidatorSelector manages the selection and coordination of validators
// for creating new blocks from pending transactions in the blockchain.
// It ensures fair selection based on stake amounts and maintains the
// synchronization of block creation across the network.

type BlockchainValidatorInterface interface {
	IsActiveValidator(address string) bool
	GetActiveValidators() []string
	GetStakeholders() map[string]int64
}

// ValidatorSelector handles the selection of validators for block creation
type ValidatorSelector struct {
	blockchain       BlockchainValidatorInterface
	mu               sync.RWMutex
	lastSelectedTime time.Time
}

func NewValidatorSelector(bc BlockchainValidatorInterface) *ValidatorSelector {
	return &ValidatorSelector{
		blockchain:       bc,
		lastSelectedTime: time.Now(),
	}
}

// SelectNextValidator chooses the next validator to create a block
func (vs *ValidatorSelector) SelectNextValidator() (string, error) {
	vs.mu.Lock()
	defer vs.mu.Unlock()

	activeValidators := vs.blockchain.GetActiveValidators()
	if len(activeValidators) == 0 {
		return "", fmt.Errorf("no active validators available")
	}

	// Select based on stakes and last selection time
	selectedValidator := ""
	highestStake := int64(0)

	stakeholders := vs.blockchain.GetStakeholders()
	for _, validator := range activeValidators {
		if stake, exists := stakeholders[validator]; exists {
			if stake > highestStake {
				highestStake = stake
				selectedValidator = validator
			}
		}
	}

	if selectedValidator == "" {
		return "", fmt.Errorf("no eligible validator found")
	}

	vs.lastSelectedTime = time.Now()
	return selectedValidator, nil
}

// CreateBlockFromPendingTransactions handles the block creation process for a selected validator
func (bc *Blockchain) CreateBlockFromPendingTransactions(validator string) (*Block, error) {
	// Verify validator is active and eligible
	if !bc.IsActiveValidator(validator) {
		return nil, fmt.Errorf("invalid or inactive validator: %s", validator)
	}

	// Process pending transactions and create block
	block, err := bc.ProcessPendingTransactions(validator)
	if err != nil {
		return nil, fmt.Errorf("failed to process pending transactions: %v", err)
	}

	if block == nil {
		return nil, fmt.Errorf("no pending transactions to process")
	}

	// Verify and sign the block
	if err := bc.VerifySignedBlock(block); err != nil {
		return nil, fmt.Errorf("block verification failed: %v", err)
	}

	// Add the block to the chain
	success, err := bc.AddBlock(block.Transactions, validator, bc.Blocks[len(bc.Blocks)-1].Hash)
	if !success {
		return nil, fmt.Errorf("failed to add block to chain: %v", err)
	}

	log.Printf("New block created by validator %s with %d transactions",
		validator, len(block.Transactions))

	return block, nil
}
