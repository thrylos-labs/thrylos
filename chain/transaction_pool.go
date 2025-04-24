package chain

import (
	"container/list"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"sync"

	"github.com/thrylos-labs/thrylos/types"

	"github.com/thrylos-labs/thrylos/store"
)

// Holds pending transactions before they're added to blocks

type txPoolImpl struct {
	mu           sync.RWMutex
	transactions map[string]*list.Element
	order        *list.List
	db           types.Store // Remove the pointer
	blockchain   *BlockchainImpl
	propagator   *types.TransactionPropagator // Remove as part of validator/consensus removal
}

// GetActiveValidators implements types.TxPool.
func (p *txPoolImpl) GetActiveValidators(tx *types.Transaction) error {
	panic("unimplemented")
}

type txEntry struct {
	txID string
	tx   *types.Transaction
}

// Constructor that returns the interface type
func NewTxPool(db *store.Database, blockchain *BlockchainImpl) types.TxPool {
	return &txPoolImpl{
		transactions: make(map[string]*list.Element),
		order:        list.New(),
		db:           db.Blockchain, // Remove the & operator
		blockchain:   blockchain,
	}
}

// AddTransaction adds a transaction to the pool
func (p *txPoolImpl) AddTransaction(tx *types.Transaction) error {
	p.mu.Lock()
	defer p.mu.Unlock()

	// Check for existing transaction
	if _, exists := p.transactions[tx.ID]; exists {
		return errors.New("transaction already exists in the pool")
	}

	// Generate and set salt if not present
	if len(tx.Salt) == 0 {
		salt, err := generateSalt()
		if err != nil {
			return fmt.Errorf("failed to generate salt: %v", err)
		}
		tx.Salt = salt
	}

	// // Verify salt uniqueness - commenting out as it depends on BlockchainImpl
	if err := p.verifyTransactionUniqueness(tx); err != nil {
		return fmt.Errorf("transaction salt verification failed: %v", err)
	}

	// // Propagate to validators - removing validator propagation
	// if err := p.propagator.PropagateTransaction(tx); err != nil {
	//     return fmt.Errorf("failed to propagate transaction: %v", err)
	// }
	// log.Printf("Transaction %s propagated to all validators", tx.ID)

	// Start database transaction
	// Start database transaction
	dbTx, err := p.db.BeginTransaction()
	if err != nil {
		return fmt.Errorf("failed to begin transaction: %v", err)
	}
	defer dbTx.Rollback()

	// Store transaction with salt
	txKey := []byte("transaction-" + tx.ID)
	tx.Status = "pending"
	txJSON, err := json.Marshal(tx)
	if err != nil {
		return fmt.Errorf("error marshaling transaction: %v", err)
	}

	// Get the badger transaction from the context
	badgerTxn := dbTx.GetBadgerTxn()
	if err := badgerTxn.Set(txKey, txJSON); err != nil {
		return fmt.Errorf("error storing transaction: %v", err)
	}

	// Commit the transaction
	if err := dbTx.Commit(); err != nil {
		return fmt.Errorf("error committing transaction: %v", err)
	}

	// Add to pool
	entry := &txEntry{txID: tx.ID, tx: tx}
	element := p.order.PushBack(entry)
	p.transactions[tx.ID] = element

	log.Printf("Transaction %s with salt added to pool. Total in pool: %d",
		tx.ID, p.order.Len())

	return nil
}

// // Helper function to verify transaction uniqueness using salt - commenting out as depends on BlockchainImpl
func (p *txPoolImpl) verifyTransactionUniqueness(tx *types.Transaction) error {
	if tx == nil {
		return fmt.Errorf("nil transaction")
	}
	if len(tx.Salt) == 0 {
		return fmt.Errorf("empty salt")
	}
	if len(tx.Salt) != 32 {
		return fmt.Errorf("invalid salt length: expected 32 bytes, got %d", len(tx.Salt))
	}

	// Use the efficient helper function to check salt uniqueness
	if p.blockchain.checkSaltInBlocks(tx.Salt) {
		return fmt.Errorf("duplicate salt detected: transaction replay attempt")
	}

	return nil
}

// Comment out network-related operations:
// // BroadcastTransaction broadcasts a transaction to the network
func (p *txPoolImpl) BroadcastTransaction(tx *types.Transaction) error {
	// Broadcast the transaction to the network, will be implemented, e.g by transmitting the transaction through the channel.
	log.Printf("Broadcasting transaction %s to the network", tx.ID)
	return nil
}

func (p *txPoolImpl) GetAllTransactions() ([]*types.Transaction, error) {
	p.mu.RLock()
	defer p.mu.RUnlock()

	txs := make([]*types.Transaction, 0, p.order.Len())
	for e := p.order.Front(); e != nil; e = e.Next() {
		entry := e.Value.(*txEntry)
		txs = append(txs, entry.tx)
	}

	log.Printf("Retrieved all transactions from the pool, count: %d", len(txs))
	return txs, nil
}

func (p *txPoolImpl) GetFirstTransaction() (*types.Transaction, error) {
	p.mu.RLock()
	defer p.mu.RUnlock()

	if p.order.Len() == 0 {
		return nil, errors.New("no transactions in the pool")
	}

	firstElement := p.order.Front()
	entry := firstElement.Value.(*txEntry)
	return entry.tx, nil
}

func (p *txPoolImpl) UpdateTransactionStatus(txID string, status string) error {
	p.mu.Lock()
	defer p.mu.Unlock()

	if elem, exists := p.transactions[txID]; exists {
		entry := elem.Value.(*txEntry)
		entry.tx.Status = status
		return nil
	}
	return fmt.Errorf("transaction not found")
}

func (p *txPoolImpl) GetTransaction(txID string) (*types.Transaction, error) {
	p.mu.RLock()
	defer p.mu.RUnlock()

	element, exists := p.transactions[txID]
	if !exists {
		log.Printf("Transaction %s not found in the pool", txID)
		return nil, errors.New("transaction not found in the pool")
	}

	entry := element.Value.(*txEntry)
	log.Printf("Transaction %s retrieved from the pool", txID)
	return entry.tx, nil
}

func (p *txPoolImpl) Size() int {
	p.mu.RLock()
	defer p.mu.RUnlock()

	return p.order.Len()
}

// It's more efficient than calling RemoveTransaction repeatedly.
func (p *txPoolImpl) RemoveTransactions(txs []*types.Transaction) error {
	if len(txs) == 0 {
		return nil // Nothing to remove
	}

	p.mu.Lock()
	defer p.mu.Unlock()

	removedCount := 0
	notFoundCount := 0 // Optional: Count how many weren't found
	for _, tx := range txs {
		if tx == nil {
			log.Printf("WARN: [RemoveTransactions] encountered nil transaction in list.")
			continue
		}

		element, exists := p.transactions[tx.ID]
		if exists {
			// Remove from the ordered list
			p.order.Remove(element)
			// Remove from the lookup map
			delete(p.transactions, tx.ID)
			removedCount++
		} else {
			// Log if a transaction expected to be in the pool isn't found
			log.Printf("WARN: [RemoveTransactions] Transaction %s not found in pool during batch removal.", tx.ID)
			notFoundCount++
		}
	}

	// Log summary of removal
	if removedCount > 0 || notFoundCount > 0 { // Only log if something happened
		log.Printf("Batch remove: Removed %d transactions, %d not found. Remaining size: %d", removedCount, notFoundCount, p.order.Len())
	}
	return nil
}

func (p *txPoolImpl) RemoveTransaction(tx *types.Transaction) error {
	// Check for nil input early
	if tx == nil {
		return errors.New("cannot remove nil transaction")
	}

	// --- Call the batch function with a single-element slice ---
	// This reuses the locking, lookup, removal, and logging logic
	// from RemoveTransactions.
	err := p.RemoveTransactions([]*types.Transaction{tx})
	// ---

	// Check the error from the batch function (currently it always returns nil, but could change)
	if err != nil {
		return fmt.Errorf("failed during single transaction removal via batch: %w", err)
	}

	// Check if the transaction was actually found and removed by the batch function.
	// We need to check the pool again (under lock) or rely on the batch function's logging/return value.
	// For simplicity here, we assume the batch function logs warnings if not found.
	// If you need a specific error when a single tx isn't found, the logic gets more complex.
	// Let's stick to reusing the batch logic for now.

	// Remove the duplicated code block here if it exists.

	return nil // Return the error status from the batch call
}

func (p *txPoolImpl) GetTransactionStatus(txID string) (string, error) {
	p.mu.RLock()
	defer p.mu.RUnlock()

	if elem, exists := p.transactions[txID]; exists {
		entry := elem.Value.(*txEntry)
		return entry.tx.Status, nil
	}
	return "", fmt.Errorf("transaction not found")
}
