package core

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"log"
	"time"

	thrylos "github.com/thrylos-labs/thrylos"
)

// Constants for block creation
const (
	checkInterval = 200 * time.Millisecond // Check more frequently
	batchSize     = 100                    // Maximum transactions per batch
)

// HasBlock checks whether a block with the specified hash exists in the node's blockchain.
func (n *Node) HasBlock(blockHash []byte) bool {
	log.Printf("Searching for block with hash: %s", hex.EncodeToString(blockHash))
	for _, block := range n.Blockchain.Blocks {
		if bytes.Equal(block.Hash, blockHash) {
			log.Printf("Block found: %s", hex.EncodeToString(block.Hash))
			return true
		}
	}
	log.Println("Block not found")
	return false
}

// StartBlockCreationTimer monitors for pending transactions and creates blocks
func (node *Node) StartBlockCreationTimer() {
	ticker := time.NewTicker(checkInterval)
	var lastBlockTime time.Time

	go func() {
		for range ticker.C {
			now := time.Now()
			timeSinceLastBlock := now.Sub(lastBlockTime)

			// Get current block time from the blockchain's consensus manager
			targetBlockTime := node.Blockchain.ConsensusManager.GetCurrentBlockTime()

			node.Mu.RLock()
			hasPendingTx := len(node.PendingTransactions) > 0
			node.Mu.RUnlock()

			if hasPendingTx && timeSinceLastBlock >= targetBlockTime {
				if err := node.TriggerBlockCreation(); err != nil {
					log.Printf("Error creating block: %v", err)
					continue
				}
				lastBlockTime = now
			}
		}
	}()
}

// TriggerBlockCreation initiates the block creation process
func (node *Node) TriggerBlockCreation() error {
	node.Mu.Lock()
	defer node.Mu.Unlock()

	pendingCount := len(node.PendingTransactions)
	if pendingCount == 0 {
		return nil
	}

	validator := node.Blockchain.GetCurrentValidator()
	if validator == "" {
		return fmt.Errorf("no validator available")
	}

	// Process in batches if needed
	if pendingCount > batchSize {
		batch := make([]*thrylos.Transaction, batchSize)
		copy(batch, node.PendingTransactions[:batchSize])
		node.PendingTransactions = node.PendingTransactions[batchSize:]

		go func(transactions []*thrylos.Transaction) {
			if _, err := node.Blockchain.ProcessPendingTransactionsWithBatch(validator, transactions); err != nil {
				log.Printf("Error processing transaction batch: %v", err)
			}
		}(batch)
		return nil
	}

	// Process remaining under same lock
	if block, err := node.Blockchain.ProcessPendingTransactions(validator); err != nil {
		return fmt.Errorf("failed to process transactions: %w", err)
	} else if block != nil {
		log.Printf("Created block with %d transactions", len(block.Transactions))
	}

	return nil
}

// ProcessConfirmedTransactions handles newly confirmed transactions in a block
func (node *Node) ProcessConfirmedTransactions(block *Block) {
	addressesToUpdate := make(map[string]bool)

	for _, tx := range block.Transactions {
		balanceCache.Delete(tx.Sender)
		addressesToUpdate[tx.Sender] = true

		for _, output := range tx.Outputs {
			balanceCache.Delete(output.OwnerAddress)
			addressesToUpdate[output.OwnerAddress] = true
		}

		node.Blockchain.StateManager.UpdateState(tx.Sender, 0, nil)
	}

	// Update balances for affected addresses
	for address := range addressesToUpdate {
		balance, err := node.GetBalance(address)
		if err == nil {
			if err := node.SendBalanceUpdate(address); err == nil {
				log.Printf("Updated balance for %s to %d", address, balance)
			}
		}
	}
}

// GetCurrentValidator gets the current validator for block creation
func (bc *Blockchain) GetCurrentValidator() string {
	bc.Mu.RLock()
	defer bc.Mu.RUnlock()

	if len(bc.ActiveValidators) == 0 {
		log.Println("Warning: No active validators available. Attempting to add genesis account as validator.")
		bc.Mu.RUnlock()
		bc.Mu.Lock()
		bc.ActiveValidators = append(bc.ActiveValidators, bc.GenesisAccount)
		bc.Mu.Unlock()
		bc.Mu.RLock()
	}

	if len(bc.ActiveValidators) == 0 {
		log.Println("Error: Still no active validators available after adding genesis account.")
		return ""
	}

	currentTime := time.Now().UnixNano()
	currentHeight := len(bc.Blocks)
	combinedFactor := currentTime + int64(currentHeight)

	index := combinedFactor % int64(len(bc.ActiveValidators))
	selectedValidator := bc.ActiveValidators[index]

	log.Printf("Selected validator: %s (index: %d out of %d)", selectedValidator, index, len(bc.ActiveValidators))

	return selectedValidator
}

func (node *Node) GetBlockCount() int {
	return node.Blockchain.GetBlockCount()
}
