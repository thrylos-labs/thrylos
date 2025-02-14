package staking

// type StakingService struct {
// 	mu         sync.RWMutex
// 	pool       *types.StakingPool
// 	stakes     map[string]*types.Stake
// 	blockchain *types.Blockchain
// }

// func (s *StakingService) GetPool() *types.StakingPool {
// 	s.mu.RLock()
// 	defer s.mu.RUnlock()
// 	return s.pool
// }

// func NewStakingService(blockchain *types.Blockchain) *StakingService {
// 	return &StakingService{
// 		pool: &types.StakingPool{
// 			MinStakeAmount:    config.MinimumStakeAmount, // From constants.go
// 			MinDelegation:     config.MinimumStakeAmount, // Use same minimum for delegation
// 			FixedYearlyReward: config.AnnualStakeReward,  // From constants.go
// 			LastRewardTime:    time.Now().Unix(),
// 			TotalStaked:       0,
// 			TotalDelegated:    0,
// 		},
// 		stakes:     make(map[string]*types.Stake),
// 		blockchain: blockchain,
// 	}
// }

// // calculateStakeReward calculates daily reward for each validator and delegator
// func (s *StakingService) CalculateStakeReward(rewardDistributionTime int64) map[string]float64 {
// 	// Add validation for time parameters
// 	if rewardDistributionTime <= s.pool.LastRewardTime {
// 		return nil
// 	}

// 	// finalise stake period before reward distribution
// 	totalStakeTimeAverage := float64(0)
// 	for _, stake := range s.stakes {
// 		if stake.LastStakeUpdateTime < rewardDistributionTime {
// 			stakeTime := stake.Amount * (rewardDistributionTime - stake.LastStakeUpdateTime)
// 			stake.StakeTimeSum += float64(stakeTime)
// 			stake.LastStakeUpdateTime = rewardDistributionTime
// 			stake.StakeTimeAverage = stake.StakeTimeSum / float64(rewardDistributionTime-s.pool.LastRewardTime)
// 			totalStakeTimeAverage += stake.StakeTimeAverage
// 		}
// 	}

// 	rewards := make(map[string]float64)
// 	extraRewardsFromDelegation := float64(0)
// 	validatorsTotalStakeTimeAverage := float64(0)
// 	//distribution of rewards to delegators and validators
// 	if totalStakeTimeAverage > 0 {
// 		for addr, stake := range s.stakes {
// 			reward := (stake.StakeTimeAverage / float64(totalStakeTimeAverage)) * float64(config.DailyStakeReward)
// 			if stake.ValidatorRole {
// 				rewards[addr] = reward
// 				stake.TotalStakeRewards += reward
// 				validatorsTotalStakeTimeAverage += stake.StakeTimeAverage
// 			} else {
// 				rewards[addr] = reward * config.DelegationRewardPercent
// 				extraRewardsFromDelegation += reward * (1 - config.DelegationRewardPercent)
// 				stake.TotalDelegationRewards += reward * config.DelegationRewardPercent
// 			}
// 		}
// 	}

// 	//distribute extra rewards from delegation
// 	if extraRewardsFromDelegation > 0 && validatorsTotalStakeTimeAverage > 0 {
// 		for addr, stake := range s.stakes {
// 			if stake.ValidatorRole {
// 				reward := (stake.StakeTimeAverage / float64(validatorsTotalStakeTimeAverage)) * extraRewardsFromDelegation
// 				rewards[addr] += reward
// 				stake.TotalDelegationRewards += reward
// 			}
// 		}
// 	}
// 	return rewards
// }

// func (s *StakingService) EstimateStakeReward(targetAddress string, currentTimeStamp int64) float64 {
// 	totalStakeTimeAverage := float64(0)
// 	addressStakeTimeAverage := float64(0)
// 	validatorsStakeTimeAverage := float64(0)
// 	delegatorsStakeTimeAverage := float64(0)
// 	isDelegator := false

// 	for addr, stake := range s.stakes {
// 		if stake.LastStakeUpdateTime < currentTimeStamp {
// 			stakeTime := stake.Amount * (currentTimeStamp - stake.LastStakeUpdateTime)
// 			stakeTimeSum := stake.StakeTimeSum + float64(stakeTime)
// 			totalStakeTimeAverage += stakeTimeSum / float64(currentTimeStamp-s.pool.LastRewardTime)

// 			if addr == targetAddress {
// 				addressStakeTimeAverage = stakeTimeSum / float64(currentTimeStamp-s.pool.LastRewardTime)
// 				if !stake.ValidatorRole {
// 					isDelegator = true
// 				}
// 			}
// 			if stake.ValidatorRole {
// 				validatorsStakeTimeAverage += stakeTimeSum / float64(currentTimeStamp-s.pool.LastRewardTime)
// 			} else {
// 				delegatorsStakeTimeAverage += stakeTimeSum / float64(currentTimeStamp-s.pool.LastRewardTime)
// 			}
// 		}
// 	}
// 	if totalStakeTimeAverage == 0 {
// 		return 0
// 	}

// 	if isDelegator {
// 		return (addressStakeTimeAverage / totalStakeTimeAverage) * float64(config.DailyStakeReward) * config.DelegationRewardPercent
// 	}

// 	if delegatorsStakeTimeAverage == 0 {
// 		return (addressStakeTimeAverage / totalStakeTimeAverage) * float64(config.DailyStakeReward) * (1 - config.DelegationRewardPercent)
// 	}

// 	extraDelegationReward := delegatorsStakeTimeAverage * float64(config.DailyStakeReward) * (1 - config.DelegationRewardPercent) / totalStakeTimeAverage

// 	extraAddressReward := extraDelegationReward * addressStakeTimeAverage / validatorsStakeTimeAverage

// 	reward := (addressStakeTimeAverage / totalStakeTimeAverage) * float64(config.DailyStakeReward)
// 	return extraAddressReward + reward
// }

// // Add this method to your StakingService struct
// func (s *StakingService) GetPoolStats() map[string]interface{} {
// 	s.mu.RLock()
// 	defer s.mu.RUnlock()

// 	currentTime := time.Now().Unix()
// 	lastRewardTime := s.pool.LastRewardTime // Changed from LastEpochBlock to LastRewardTime

// 	// Calculate next reward time (24 hours after last reward)
// 	nextRewardTime := lastRewardTime + (24 * 3600)
// 	timeUntilReward := nextRewardTime - currentTime

// 	return map[string]interface{}{
// 		"totalStaked": map[string]interface{}{
// 			"thrylos": float64(s.pool.TotalStaked) / 1e7,
// 			"nano":    s.pool.TotalStaked,
// 		},
// 		"delegatorCount": len(s.stakes),
// 		"rewardSchedule": map[string]interface{}{
// 			"nextRewardTime":  nextRewardTime,
// 			"timeUntilReward": timeUntilReward,
// 			"lastRewardTime":  lastRewardTime, // Using LastRewardTime consistently
// 			"rewardInterval":  "24h",
// 			"dailyRewardPool": config.DailyStakeReward / 1e7,
// 			"validatorShare":  "50%",
// 			"delegatorShare":  "50%",
// 		},
// 		"validatorInfo": map[string]interface{}{
// 			"activeCount":    len(s.blockchain.ActiveValidators),
// 			"minStakeAmount": float64(s.pool.MinStakeAmount) / 1e7,
// 		},
// 	}
// }

// func (s *StakingService) IsValidator(address string) bool {
// 	s.mu.RLock()
// 	defer s.mu.RUnlock()
// 	for _, validator := range s.blockchain.ActiveValidators {
// 		if validator == address {
// 			return true
// 		}
// 	}
// 	return false
// }

// func (s *StakingService) CreateStake(userAddress string, amount int64) (*types.Stake, error) {
// 	s.mu.Lock()
// 	defer s.mu.Unlock()

// 	// Automatically determine if address is a validator
// 	isValidator := s.isValidator(userAddress)
// 	isDelegator := !isValidator // isDelegator is opposite of isValidator

// 	// Use appropriate minimum based on status
// 	minRequired := s.pool.MinStakeAmount
// 	if isDelegator {
// 		minRequired = s.pool.MinDelegation
// 	}

// 	if amount < minRequired {
// 		return nil, fmt.Errorf("minimum amount required is %d THRYLOS", minRequired/1e7)
// 	}

// 	// Create transaction based on type
// 	txType := "stake"
// 	if isDelegator {
// 		txType = "delegate"
// 	}
// 	txID := fmt.Sprintf("%s-%s-%d", txType, userAddress, time.Now().UnixNano())

// 	stakingTx := &thrylos.Transaction{
// 		Id:        txID,
// 		Sender:    userAddress,
// 		Timestamp: time.Now().Unix(),
// 		Outputs: []*thrylos.UTXO{{
// 			OwnerAddress:  "staking_pool",
// 			Amount:        amount,
// 			Index:         0,
// 			TransactionId: "",
// 		}},
// 	}

// 	// Create the stake transaction
// 	if err := s.blockchain.AddPendingTransaction(stakingTx); err != nil {
// 		return nil, fmt.Errorf("failed to create staking transaction: %v", err)
// 	}

// 	return s.createStakeInternal(userAddress, isDelegator, amount, stakingTx.Timestamp)
// }

// // Keep internal function for testing
// func (s *StakingService) createStakeInternal(userAddress string, isDelegator bool, amount int64, timestamp int64) (*types.Stake, error) {
// 	now := timestamp

// 	// Initialize stake if it doesn't exist
// 	if s.stakes[userAddress] == nil {
// 		s.stakes[userAddress] = &types.Stake{
// 			UserAddress:            userAddress,
// 			Amount:                 0,
// 			StartTime:              now,
// 			LastStakeUpdateTime:    now,
// 			TotalStakeRewards:      0,
// 			TotalDelegationRewards: 0,
// 			IsActive:               true,
// 			ValidatorRole:          !isDelegator, // Set based on delegation status
// 		}
// 	}

// 	// Update stakes
// 	stake := s.stakes[userAddress]
// 	duration := now - stake.LastStakeUpdateTime
// 	totalDuration := now - s.pool.LastRewardTime
// 	stakeTime := stake.Amount * duration

// 	stake.Amount += amount
// 	stake.StakeTimeSum += float64(stakeTime)
// 	if totalDuration > 0 {
// 		stake.StakeTimeAverage = stake.StakeTimeSum / float64(totalDuration)
// 	}
// 	stake.LastStakeUpdateTime = now

// 	// Update pool totals
// 	if isDelegator {
// 		s.pool.TotalDelegated += amount
// 	} else {
// 		s.pool.TotalStaked += amount
// 	}

// 	return stake, nil
// }

// func (s *StakingService) DistributeRewards() error {
// 	s.mu.Lock()
// 	defer s.mu.Unlock()

// 	currentTime := time.Now().Unix()

// 	// Check if 24 hours have passed
// 	if currentTime-s.pool.LastRewardTime < config.RewardDistributionTimeInterval {
// 		return nil // Not time for rewards yet
// 	}

// 	rewards := s.CalculateStakeReward(currentTime)
// 	if rewards == nil {
// 		return nil
// 	}

// 	// Distribute rewards to active validators and delegators
// 	for validatorAddr, reward := range rewards {
// 		rewardTx := &thrylos.Transaction{
// 			Id:        fmt.Sprintf("reward-%s-%d", validatorAddr, time.Now().UnixNano()),
// 			Sender:    "network",
// 			Timestamp: currentTime,
// 			Outputs: []*thrylos.UTXO{{
// 				OwnerAddress:  validatorAddr,
// 				Amount:        int64(reward),
// 				Index:         0,
// 				TransactionId: "",
// 			}},
// 		}

// 		if err := s.blockchain.AddPendingTransaction(rewardTx); err != nil {
// 			return fmt.Errorf("failed to add reward transaction: %v", err)
// 		}
// 	}

// 	s.pool.LastRewardTime = currentTime
// 	return nil
// }

// func (s *StakingService) unstakeTokensInternal(userAddress string, isDelegator bool, amount int64, timestamp int64) error {
// 	stake, exists := s.stakes[userAddress]
// 	if !exists {
// 		return errors.New("no stake found for address")
// 	}

// 	if stake.Amount < amount {
// 		return errors.New("insufficient staked amount")
// 	}

// 	// Calculate time-based values first
// 	now := timestamp
// 	duration := now - stake.LastStakeUpdateTime
// 	totalDuration := now - s.pool.LastRewardTime
// 	stakeTime := stake.Amount * duration

// 	// Update stake amount (removed oldAmount declaration)
// 	stake.Amount -= amount
// 	stake.StakeTimeSum += float64(stakeTime)
// 	if totalDuration > 0 {
// 		stake.StakeTimeAverage = stake.StakeTimeSum / float64(totalDuration)
// 	}
// 	stake.LastStakeUpdateTime = now

// 	// Update pool totals based on stake type
// 	if isDelegator {
// 		s.pool.TotalDelegated = s.pool.TotalDelegated - amount
// 	} else {
// 		s.pool.TotalStaked = s.pool.TotalStaked - amount
// 	}

// 	// Update Stakeholders map
// 	if stake.Amount == 0 {
// 		delete(s.stakes, userAddress)
// 	}

// 	// Update blockchain stakeholders
// 	currentStake := s.blockchain.Stakeholders[userAddress]
// 	if currentStake <= amount {
// 		delete(s.blockchain.Stakeholders, userAddress)
// 	} else {
// 		s.blockchain.Stakeholders[userAddress] = currentStake - amount
// 	}

// 	return nil
// }

// // Support methods for compatibility
// func (s *StakingService) GetTotalStaked() int64 {
// 	s.mu.RLock()
// 	defer s.mu.RUnlock()
// 	return s.pool.TotalStaked
// }
// func (s *StakingService) GetTotalDelegated() int64 {
// 	s.mu.RLock()
// 	defer s.mu.RUnlock()
// 	return s.pool.TotalDelegated
// }
// func (s *StakingService) GetTotalStakedDelegated() int64 {
// 	s.mu.RLock()
// 	defer s.mu.RUnlock()
// 	return s.pool.TotalDelegated + s.pool.TotalStaked
// }

// func (s *StakingService) GetEffectiveInflationRate() float64 {
// 	s.mu.RLock()
// 	defer s.mu.RUnlock()

// 	currentTotalSupply := float64(s.getTotalSupply()) / 1e7
// 	fixedYearlyReward := float64(s.pool.FixedYearlyReward) / 1e7
// 	return (fixedYearlyReward / currentTotalSupply) * 100
// }

// func (s *StakingService) getTotalSupply() int64 {
// 	// No need for additional locking as this is called from locked methods
// 	totalSupply := int64(0)
// 	for _, balance := range s.blockchain.Stakeholders {
// 		totalSupply += balance
// 	}
// 	return totalSupply
// }
