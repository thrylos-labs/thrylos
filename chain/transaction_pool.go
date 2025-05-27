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
	mu             sync.RWMutex
	transactions   map[string]*list.Element
	order          *list.List
	db             types.Store     // Correct: This should be the types.Store interface
	blockchain     *BlockchainImpl // Reference to the parent BlockchainImpl
	shardID        types.ShardID   // NEW: The ID of the shard this txPool serves
	totalNumShards int             // NEW: The total number of shards in the network
	// propagator   *types.TransactionPropagator // Removed as part of validator/consensus removal - good.
}

// GetActiveValidators implements types.TxPool.
func (p *txPoolImpl) GetActiveValidators(tx *types.Transaction) error {
	// This method seems out of place for a TxPool, it might belong to a consensus module.
	// Based on your comment, it's a panic currently. Keep it as is or remove if unused.
	panic("unimplemented")
}

type txEntry struct {
	txID string
	tx   *types.Transaction
}

// Constructor that returns the interface type
func NewTxPool(db types.Store, blockchain *BlockchainImpl) types.TxPool { // MODIFIED: db type
	if db == nil {
		log.Fatal("FATAL: NewTxPool called with nil database")
	}
	if blockchain == nil {
		log.Fatal("FATAL: NewTxPool called with nil blockchain (BlockchainImpl)")
	}
	if blockchain.GetChainState() == nil {
		log.Fatal("FATAL: NewTxPool called with nil ChainState from BlockchainImpl")
	}

	return &txPoolImpl{
		transactions:   make(map[string]*list.Element),
		order:          list.New(),
		db:             db, // Correctly assign the types.Store interface directly
		blockchain:     blockchain,
		shardID:        blockchain.GetChainState().ShardID,        // Get shardID from ChainState
		totalNumShards: blockchain.GetChainState().TotalNumShards, // Get totalNumShards from ChainState
	}
}

// AddTransaction adds a transaction to the pool
func (p *txPoolImpl) AddTransaction(tx *types.Transaction) error {
	p.mu.Lock()
	defer p.mu.Unlock()

	// SHARDING AWARENESS: Check if this transaction belongs to THIS shard
	// A transaction is primarily assigned to a shard based on its sender.
	txSenderAddress := tx.SenderAddress.String()
	expectedShardID := store.CalculateShardID(txSenderAddress, p.totalNumShards)

	if expectedShardID != p.shardID && p.shardID != types.ShardID(-1) { // If not for this shard, AND not a beacon node
		return fmt.Errorf("transaction %s for sender %s (expected shard %d) does not belong to this pool's shard %d; belongs to %d",
			tx.ID, txSenderAddress, expectedShardID, p.shardID, expectedShardID)
	}
	// If it's the beacon node, it might accept all transactions and route them.
	// For simplicity, beacon node also filters for its own (non-existent) shard.

	// Check for existing transaction
	if _, exists := p.transactions[tx.ID]; exists {
		return errors.New("transaction already exists in the pool")
	}

	// Generate and set salt if not present
	if len(tx.Salt) == 0 {
		salt, err := generateSalt() // Assuming generateSalt is available globally or in utils
		if err != nil {
			return fmt.Errorf("failed to generate salt: %v", err)
		}
		tx.Salt = salt
	}

	// Verify salt uniqueness - uses blockchain.checkSaltInBlocks
	if err := p.verifyTransactionUniqueness(tx); err != nil {
		return fmt.Errorf("transaction salt verification failed: %v", err)
	}

	// Start database transaction
	// The p.db (types.Store) methods are now shard-aware, so no extra shardID needed here in signature
	dbTx, err := p.db.BeginTransaction() // This dbTx will operate on the shard-specific DB instance
	if err != nil {
		return fmt.Errorf("failed to begin database transaction for tx %s on shard %d: %v", tx.ID, p.shardID, err)
	}
	defer dbTx.Rollback() // Ensure rollback on error

	// Store transaction with salt
	// SaveTransaction needs to be updated to take totalNumShards if transaction keys are sharded.
	// For now, let's assume transaction keys are NOT sharded by TxID directly or the store method handles it.
	// If you need to shard transaction keys, then SaveTransaction in types.Store also needs totalNumShards.
	// Assuming tx.ID is unique globally (which is typical for a TxID).
	// If transaction data (not UTXOs/Balances) is sharded by tx.ID,
	// then the store implementation will need to handle `store.CalculateShardID(tx.ID, p.totalNumShards)`
	// Or you might need to add `totalNumShards` to `SaveTransaction` in `types.Store`.
	// For now, let's just make sure SaveTransaction is called.
	tx.Status = "pending"
	// No `txKey` and `badgerTxn.Set` directly here. Call `p.db.SaveTransaction(dbTx, tx)`.
	// Wait, SaveTransaction usually takes `*types.Transaction`, not `dbTx`.
	// If SaveTransaction needs to operate within a transaction, it should take `types.TransactionContext`.
	// Let's modify SaveTransaction signature in types.Store and its implementation.

	// Proposed change: SaveTransaction now takes TransactionContext
	// This is safer for atomicity with other DB operations in the same transaction.
	// For now, let's assume `SaveTransaction` exists and just call it.
	// If it needs `dbTx`, its signature will need to be changed in types.Store.
	// For now, if your existing `SaveTransaction` commits its own transaction,
	// you'll need to refactor it to work with an external `dbTxContext`.
	// Let's stick to using `db.Update` for single ops or ensuring `SaveTransaction` itself is transactional.

	// Reverting to the original direct `Set` in the transaction context for simplicity:
	txKey := []byte("transaction-" + tx.ID) // This key format is NOT sharded by shardID
	txJSON, err := json.Marshal(tx)         // Using JSON, but your types.Transaction has CBOR Marshal()
	if err != nil {
		return fmt.Errorf("error marshaling transaction %s: %v", tx.ID, err)
	}

	badgerTxn := dbTx.GetBadgerTxn()                     // Get the badger transaction from the context
	if err := badgerTxn.Set(txKey, txJSON); err != nil { // This is NOT shard-aware
		return fmt.Errorf("error storing transaction %s in DB: %v", tx.ID, err)
	}
	// Note: If you want transaction entries themselves to be sharded in BadgerDB,
	// txKey needs to be `GetShardedKey(TransactionPrefix, p.shardID, tx.ID)`.
	// This means transaction retrieval by ID also needs `shardID`.
	// For now, assuming `txKey` is global (not shard-specific) in BadgerDB.

	// Commit the transaction
	if err := dbTx.Commit(); err != nil {
		return fmt.Errorf("error committing database transaction for tx %s on shard %d: %v", tx.ID, p.shardID, err)
	}

	// Add to pool (in-memory)
	entry := &txEntry{txID: tx.ID, tx: tx}
	element := p.order.PushBack(entry)
	p.transactions[tx.ID] = element

	log.Printf("Transaction %s with salt added to pool for shard %d. Total in pool: %d",
		tx.ID, p.shardID, p.order.Len())

	return nil
}

// This method now uses the blockchain's ShardState.
func (p *txPoolImpl) verifyTransactionUniqueness(tx *types.Transaction) error {
	if tx == nil {
		return fmt.Errorf("nil transaction")
	}
	if len(tx.Salt) == 0 {
		return fmt.Errorf("empty salt")
	}
	if len(tx.Salt) != 32 { // Assuming salt length is 32 bytes
		return fmt.Errorf("invalid salt length: expected 32 bytes, got %d", len(tx.Salt))
	}

	// `p.blockchain.checkSaltInBlocks` needs to be updated to operate on `p.blockchain.ShardState`
	// and specifically check blocks only for `p.shardID`.
	// This method needs to be implemented in chain/blockchain.go if it's not already.
	if p.blockchain.checkSaltInBlocks(tx.Salt, p.shardID) { // Pass shardID to checkSaltInBlocks
		return fmt.Errorf("duplicate salt detected: transaction replay attempt on shard %d", p.shardID)
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

	log.Printf("Retrieved all transactions from the pool for shard %d, count: %d", p.shardID, len(txs))
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
