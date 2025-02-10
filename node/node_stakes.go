package node

// // This method should be aligned with how we're handling stake determinations
// func (node *Node) UnstakeTokens(userAddress string, isDelegator bool, amount int64) error {
// 	// We should determine if it's a delegator by checking validator status
// 	isValidator := node.StakingService.IsValidator(userAddress)
// 	isDelegator = !isValidator

// 	txType := "unstake"
// 	if isDelegator {
// 		txType = "undelegate"
// 	}

// 	txID := fmt.Sprintf("%s-%s-%d", txType, userAddress, time.Now().UnixNano())
// 	timestamp := time.Now().Unix()

// 	unstakingTx := &thrylos.Transaction{
// 		Id:        txID,
// 		Sender:    "staking_pool",
// 		Timestamp: timestamp,
// 		Outputs: []*thrylos.UTXO{{
// 			OwnerAddress:  userAddress,
// 			Amount:        amount,
// 			Index:         0,
// 			TransactionId: "",
// 		}},
// 	}

// 	if err := node.Blockchain.AddPendingTransaction(unstakingTx); err != nil {
// 		return fmt.Errorf("failed to create unstaking transaction: %v", err)
// 	}

// 	return node.StakingService.unstakeTokensInternal(userAddress, isDelegator, amount, timestamp)
// }

// // // These methods are correct as they simply proxy the calls
// func (node *Node) GetStakingStats() map[string]interface{} {
// 	return node.StakingService.GetPoolStats()
// }

// func (node *Node) CreateStake(userAddress string, amount int64) (*staking.Stake, error) {
// 	return node.StakingService.CreateStake(userAddress, amount)
// }

// // These delegation-specific methods are correct
// func (node *Node) DelegateToPool(delegator string, amount int64) (*staking.Stake, error) {
// 	return node.StakingService.CreateStake(delegator, amount)
// }

// func (node *Node) UndelegateFromPool(delegator string, amount int64) error {
// 	return node.UnstakeTokens(delegator, true, amount)
// }

// // // GetStakeholders returns a map of addresses to their staked amounts
// func (node *Node) GetStakeholders() map[string]int64 {
// 	node.Mu.RLock()
// 	defer node.Mu.RUnlock()

// 	stakeholders := make(map[string]int64)

// 	// Get all stakes from the staking service
// 	stats := node.StakingService.GetPoolStats()

// 	// Extract stakes from the pool stats
// 	if stakes, ok := stats["stakes"].(map[string]interface{}); ok {
// 		for address, stakeInfo := range stakes {
// 			if stake, ok := stakeInfo.(map[string]interface{}); ok {
// 				if amount, ok := stake["amount"].(int64); ok {
// 					stakeholders[address] = amount
// 				}
// 			}
// 		}
// 	}

// 	return stakeholders
// }
