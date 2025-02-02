package chain

// type BlockProcessor struct {
// 	config        *BlockProducerConfig
// 	node          *Node
// 	blockchain    *Blockchain
// 	isProducing   atomic.Bool
// 	lastBlockTime time.Time
// 	mu            sync.RWMutex
// }

// // Constants for block creation
// const (
// 	checkInterval = 200 * time.Millisecond // Check more frequently
// 	batchSize     = 100                    // Maximum transactions per batch
// )

// // HasBlock checks whether a block with the specified hash exists in the node's blockchain.
// func (bpc *BlockProcessor) HasBlock(blockHash []byte) bool {
// 	log.Printf("Searching for block with hash: %s", hex.EncodeToString(blockHash))
// 	for _, block := range n.Blockchain.Blocks {
// 		if bytes.Equal(block.Hash, blockHash) {
// 			log.Printf("Block found: %s", hex.EncodeToString(block.Hash))
// 			return true
// 		}
// 	}
// 	log.Println("Block not found")
// 	return false
// }

// // StartBlockCreationTimer monitors for pending transactions and creates blocks
// func (bpc *BlockProcessor) StartBlockCreationTimer() {
// 	ticker := time.NewTicker(checkInterval)
// 	var lastBlockTime time.Time

// 	go func() {
// 		for range ticker.C {
// 			now := time.Now()
// 			timeSinceLastBlock := now.Sub(lastBlockTime)

// 			// Get current block time from the blockchain's consensus manager
// 			targetBlockTime := node.Blockchain.ConsensusManager.GetCurrentBlockTime()

// 			node.Mu.RLock()
// 			hasPendingTx := len(node.PendingTransactions) > 0
// 			node.Mu.RUnlock()

// 			if hasPendingTx && timeSinceLastBlock >= targetBlockTime {
// 				if err := node.TriggerBlockCreation(); err != nil {
// 					log.Printf("Error creating block: %v", err)
// 					continue
// 				}
// 				lastBlockTime = now
// 			}
// 		}
// 	}()
// }

// // TriggerBlockCreation initiates the block creation process
// func (bpc *BlockProcessor) TriggerBlockCreation() error {
// 	node.Mu.Lock()
// 	defer node.Mu.Unlock()

// 	pendingCount := len(node.PendingTransactions)
// 	if pendingCount == 0 {
// 		return nil
// 	}

// 	validator := node.Blockchain.GetCurrentValidator()
// 	if validator == "" {
// 		return fmt.Errorf("no validator available")
// 	}

// 	// Process in batches if needed
// 	if pendingCount > batchSize {
// 		batch := make([]*thrylos.Transaction, batchSize)
// 		copy(batch, node.PendingTransactions[:batchSize])
// 		node.PendingTransactions = node.PendingTransactions[batchSize:]

// 		go func(transactions []*thrylos.Transaction) {
// 			if _, err := node.Blockchain.ProcessPendingTransactionsWithBatch(validator, transactions); err != nil {
// 				log.Printf("Error processing transaction batch: %v", err)
// 			}
// 		}(batch)
// 		return nil
// 	}

// 	// Process remaining under same lock
// 	if block, err := node.Blockchain.ProcessPendingTransactions(validator); err != nil {
// 		return fmt.Errorf("failed to process transactions: %w", err)
// 	} else if block != nil {
// 		log.Printf("Created block with %d transactions", len(block.Transactions))
// 	}

// 	return nil
// }

// // ProcessConfirmedTransactions handles newly confirmed transactions in a block
// // ProcessConfirmedTransactions handles newly confirmed transactions in a block
// func (bpc *BlockProcessor) ProcessConfirmedTransactions(block *Block) {
// 	// Clear old votes first
// 	node.VoteCounter.ClearOldVotes()

// 	// If this is not the counter node, validate and vote
// 	if !node.IsVoteCounter {
// 		if err := node.ValidateAndVoteForBlock(block); err != nil {
// 			log.Printf("Failed to validate and vote for block: %v", err)
// 			return
// 		}
// 	}

// 	// Start new voting round for next block
// 	activeValidators := node.Blockchain.GetActiveValidators()

// 	// Calculate required votes (2/3 of active validators)
// 	requiredVotes := (2*len(activeValidators) + 2) / 3

// 	// Start voting process for eligible validators
// 	votedValidators := 0
// 	for _, validator := range activeValidators {
// 		if node.isEligibleValidator(validator) {
// 			node.BroadcastVote(validator, block.Index+1)
// 			votedValidators++

// 			// Check if we have reached super majority
// 			if votedValidators >= requiredVotes {
// 				log.Printf("Achieved 2/3 majority with %d out of %d validators for block %d",
// 					votedValidators, len(activeValidators), block.Index+1)
// 				break
// 			}
// 		}
// 	}

// 	if votedValidators < requiredVotes {
// 		log.Printf("Warning: Could not achieve 2/3 majority. Only got %d out of required %d votes",
// 			votedValidators, requiredVotes)
// 	}

// 	// Process transaction updates
// 	addressesToUpdate := make(map[string]bool)
// 	for _, tx := range block.Transactions {
// 		balanceCache.Delete(tx.Sender)
// 		addressesToUpdate[tx.Sender] = true

// 		for _, output := range tx.Outputs {
// 			balanceCache.Delete(output.OwnerAddress)
// 			addressesToUpdate[output.OwnerAddress] = true
// 		}

// 		node.Blockchain.StateManager.UpdateState(tx.Sender, 0, nil)
// 	}

// 	// Update balances for affected addresses
// 	for address := range addressesToUpdate {
// 		balance, err := node.GetBalance(address)
// 		if err == nil {
// 			if err := node.SendBalanceUpdate(address); err == nil {
// 				log.Printf("Updated balance for %s to %d", address, balance)
// 			}
// 		}
// 	}
// }

// func (bpc *BlockProcessor) isEligibleValidator(validatorID string) bool {
// 	// Check if validator meets stake requirements and other criteria
// 	stakeholders := node.Blockchain.GetStakeholders()
// 	minStake := node.Blockchain.GetMinStakeForValidator()

// 	if stake, exists := stakeholders[validatorID]; exists {
// 		return stake >= minStake.Int64()
// 	}
// 	return false
// }

// // GetCurrentValidator gets the current validator for block creation
// func (bpc *BlockProcessor) GetCurrentValidator() string {
// 	bc.Mu.RLock()
// 	defer bc.Mu.RUnlock()

// 	if len(bc.ActiveValidators) == 0 {
// 		log.Println("Warning: No active validators available. Attempting to add genesis account as validator.")
// 		bc.Mu.RUnlock()
// 		bc.Mu.Lock()
// 		bc.ActiveValidators = append(bc.ActiveValidators, bc.GenesisAccount)
// 		bc.Mu.Unlock()
// 		bc.Mu.RLock()
// 	}

// 	if len(bc.ActiveValidators) == 0 {
// 		log.Println("Error: Still no active validators available after adding genesis account.")
// 		return ""
// 	}

// 	currentTime := time.Now().UnixNano()
// 	currentHeight := len(bc.Blocks)
// 	combinedFactor := currentTime + int64(currentHeight)

// 	index := combinedFactor % int64(len(bc.ActiveValidators))
// 	selectedValidator := bc.ActiveValidators[index]

// 	log.Printf("Selected validator: %s (index: %d out of %d)", selectedValidator, index, len(bc.ActiveValidators))

// 	return selectedValidator
// }

// func (bpc *BlockProcessor) GetBlockCount() int {
// 	return node.Blockchain.GetBlockCount()
// }
