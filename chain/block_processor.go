package chain

import (
	"fmt"
	"log"
	"sync"
	"sync/atomic"
	"time"

	thrylos "github.com/thrylos-labs/thrylos"
	"github.com/thrylos-labs/thrylos/amount"
	"github.com/thrylos-labs/thrylos/shared"
	"github.com/thrylos-labs/thrylos/types"
)

type BlockProcessor struct {
	config         *BlockProducerConfig
	blockchain     *types.Blockchain
	messageBus     *shared.MessageBus
	isProducing    atomic.Bool
	lastBlockTime  time.Time
	blockchainImpl *BlockchainImpl
	mu             sync.RWMutex
}

// Constants for block creation
const (
	checkInterval = 200 * time.Millisecond // Check more frequently
	batchSize     = 100                    // Maximum transactions per batch
)

func NewBlockProcessor(config *BlockProducerConfig, blockchainImpl *BlockchainImpl, blockchain *types.Blockchain, messageBus *shared.MessageBus) *BlockProcessor {
	bp := &BlockProcessor{
		config:         config,
		blockchain:     blockchain,
		messageBus:     messageBus,
		blockchainImpl: blockchainImpl,
	}
	return bp
}

// HasBlock checks whether a block with the specified hash exists in the node's blockchain.
func (bp *BlockProcessor) HasBlock(blockHash []byte) bool {
	responseCh := make(chan types.Response)
	bp.messageBus.Publish(types.Message{
		Type:       types.HasBlock,
		Data:       blockHash,
		ResponseCh: responseCh,
	})

	response := <-responseCh
	if response.Error != nil {
		log.Printf("Error checking block existence: %v", response.Error)
		return false
	}

	return response.Data.(bool)
}

// StartBlockCreationTimer monitors for pending transactions and creates blocks
func (bp *BlockProcessor) StartBlockCreationTimer() {
	ticker := time.NewTicker(checkInterval)
	var lastBlockTime time.Time

	go func() {
		for range ticker.C {
			now := time.Now()
			timeSinceLastBlock := now.Sub(lastBlockTime)

			// Get current block time through message bus
			timeCh := make(chan types.Response)
			bp.messageBus.Publish(types.Message{
				Type:       types.GetConsensusTime,
				ResponseCh: timeCh,
			})
			timeResponse := <-timeCh
			targetBlockTime := timeResponse.Data.(time.Duration)

			// Check pending transactions through message bus
			pendingCh := make(chan types.Response)
			bp.messageBus.Publish(types.Message{
				Type:       types.GetPendingTxCount,
				ResponseCh: pendingCh,
			})
			pendingResponse := <-pendingCh
			hasPendingTx := pendingResponse.Data.(bool)

			if hasPendingTx && timeSinceLastBlock >= targetBlockTime {
				if err := bp.TriggerBlockCreation(); err != nil {
					log.Printf("Error creating block: %v", err)
					continue
				}
				lastBlockTime = now
			}
		}
	}()
}

// TriggerBlockCreation initiates the block creation process
func (bp *BlockProcessor) TriggerBlockCreation() error {
	bp.mu.Lock()
	defer bp.mu.Unlock()

	// Use BlockProcessor's GetCurrentValidator method
	validator := bp.GetCurrentValidator()
	if validator == "" {
		return fmt.Errorf("no validator available")
	}

	// Get pending transactions count directly from blockchain
	pendingCount := len(bp.blockchain.PendingTransactions)
	if pendingCount == 0 {
		return nil
	}

	// Process in batches if needed
	if pendingCount > batchSize {
		batch := make([]*thrylos.Transaction, batchSize)
		copy(batch, bp.blockchain.PendingTransactions[:batchSize])
		bp.blockchain.PendingTransactions = bp.blockchain.PendingTransactions[batchSize:]

		go func(transactions []*thrylos.Transaction) {
			if _, err := bp.blockchainImpl.ProcessPendingTransactionsWithBatch(validator, transactions); err != nil {
				log.Printf("Error processing transaction batch: %v", err)
			}
		}(batch)
		return nil
	}

	// Process remaining transactions
	if block, err := bp.blockchainImpl.ProcessPendingTransactions(validator); err != nil {
		return fmt.Errorf("failed to process transactions: %w", err)
	} else if block != nil {
		log.Printf("Created block with %d transactions", len(block.Transactions))
	}

	return nil
}

func (bp *BlockProcessor) ProcessConfirmedTransactions(block *types.Block) {
	// Use message bus for node-related operations
	isCounterCh := make(chan types.Response)
	bp.messageBus.Publish(types.Message{
		Type:       types.IsCounterNode,
		ResponseCh: isCounterCh,
	})
	isCounterResponse := <-isCounterCh
	isCounter := isCounterResponse.Data.(bool)

	if !isCounter {
		// Validate block through message bus
		voteCh := make(chan types.Response)
		bp.messageBus.Publish(types.Message{
			Type:       types.ValidateBlock,
			Data:       block,
			ResponseCh: voteCh,
		})
		if voteResponse := <-voteCh; voteResponse.Error != nil {
			log.Printf("Failed to validate block: %v", voteResponse.Error)
			return
		}
	}

	// Get active validators directly from blockchain
	activeValidators := bp.blockchainImpl.GetActiveValidators()
	requiredVotes := (2*len(activeValidators) + 2) / 3

	// Start voting process
	votedValidators := 0
	for _, validator := range activeValidators {
		if bp.isEligibleValidator(validator) {
			// Send vote through message bus
			bp.messageBus.Publish(types.Message{
				Type: types.UpdateState,
				Data: struct {
					Validator string
					BlockNum  int64
				}{
					Validator: validator,
					BlockNum:  block.Index + 1,
				},
				ResponseCh: make(chan types.Response),
			})
			votedValidators++

			if votedValidators >= requiredVotes {
				log.Printf("Achieved 2/3 majority with %d out of %d validators for block %d",
					votedValidators, len(activeValidators), block.Index+1)
				break
			}
		}
	}

	// Process transaction updates
	addressesToUpdate := make(map[string]bool)
	for _, tx := range block.Transactions {
		// Using correct field 'SenderAddress' from the shared.Transaction struct
		senderAddr := tx.SenderAddress.String() // Convert address.Address to string
		addressesToUpdate[senderAddr] = true
		for _, output := range tx.Outputs {
			addressesToUpdate[output.OwnerAddress] = true
		}

		// Update state through message bus since it's node-related
		bp.messageBus.Publish(types.Message{
			Type: types.UpdateState,
			Data: types.UpdateStateRequest{
				Address: senderAddr,
				Balance: amount.Amount(0), // Convert to amount.Amount
			},
			ResponseCh: make(chan types.Response),
		})
	}

	// Update balances for affected addresses through message bus
	for address := range addressesToUpdate {
		balanceCh := make(chan types.Response)
		bp.messageBus.Publish(types.Message{
			Type:       types.GetBalance,
			Data:       address,
			ResponseCh: balanceCh,
		})

		if response := <-balanceCh; response.Error == nil {
			// Convert the returned balance to amount.Amount
			var balance amount.Amount
			switch v := response.Data.(type) {
			case int64:
				balance = amount.Amount(v)
			case amount.Amount:
				balance = v
			default:
				log.Printf("Unexpected balance type: %T", response.Data)
				continue
			}

			bp.messageBus.Publish(types.Message{
				Type: types.UpdateState,
				Data: types.UpdateStateRequest{
					Address: address,
					Balance: balance,
				},
				ResponseCh: make(chan types.Response),
			})
			log.Printf("Updated balance for %s to %d", address, balance)
		}
	}
}

func (bp *BlockProcessor) isEligibleValidator(validatorID string) bool {
	// Get stake requirements directly from blockchain
	stakeholders := bp.blockchainImpl.GetStakeholders()
	minStake := bp.blockchainImpl.GetMinStakeForValidator()

	if stake, exists := stakeholders[validatorID]; exists {
		return stake >= minStake.Int64()
	}
	return false
}

func (bp *BlockProcessor) GetBlockCount() int {
	return bp.blockchainImpl.GetBlockCount()
}

// GetCurrentValidator gets the current validator for block creation
func (bp *BlockProcessor) GetCurrentValidator() string {
	bp.blockchain.Mu.RLock()
	defer bp.blockchain.Mu.RUnlock()

	if len(bp.blockchain.ActiveValidators) == 0 {
		log.Println("Warning: No active validators available. Attempting to add genesis account as validator.")

		// Need to unlock first to avoid deadlock when re-locking
		bp.blockchain.Mu.RUnlock()
		bp.blockchain.Mu.Lock()

		// Get the public key from the genesis account's private key
		genesisPublicKey := bp.blockchain.GenesisAccount.PublicKey()

		// Get the address from the public key
		genesisAddress, err := genesisPublicKey.Address()
		if err != nil {
			log.Printf("Error getting address from genesis account: %v", err)
			bp.blockchain.Mu.Unlock()
			return ""
		}

		// Convert address to string and add to validators
		genesisAddressStr := genesisAddress.String()
		bp.blockchain.ActiveValidators = append(bp.blockchain.ActiveValidators, genesisAddressStr)

		bp.blockchain.Mu.Unlock()
		bp.blockchain.Mu.RLock()
	}

	if len(bp.blockchain.ActiveValidators) == 0 {
		log.Println("Error: Still no active validators available after adding genesis account.")
		return ""
	}

	currentTime := time.Now().UnixNano()
	currentHeight := len(bp.blockchain.Blocks)
	combinedFactor := currentTime + int64(currentHeight)

	index := combinedFactor % int64(len(bp.blockchain.ActiveValidators))
	selectedValidator := bp.blockchain.ActiveValidators[index]

	log.Printf("Selected validator: %s (index: %d out of %d)", selectedValidator, index, len(bp.blockchain.ActiveValidators))

	return selectedValidator
}
