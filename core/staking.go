package core

import (
	"errors"
	"fmt"
	"sync"
	"time"

	thrylos "github.com/thrylos-labs/thrylos"
)

type StakingManager interface {
	GetPoolStats() map[string]interface{}
	CreateStake(userAddress string, amount int64) (*Stake, error)
	UnstakeTokens(userAddress string, amount int64) error
	DelegateToPool(delegator string, amount int64) error
	UndelegateFromPool(delegator string, amount int64) error
	DistributeRewards() error
	GetTotalStaked() int64
	GetEffectiveInflationRate() float64
}

type StakingPool struct {
	MinStakeAmount    int64 `json:"minStakeAmount"`
	MinDelegation     int64 `json:"minDelegation"`     // Added for pool delegations
	FixedYearlyReward int64 `json:"fixedYearlyReward"` // Always 4.8M
	TotalStaked       int64 `json:"totalStaked"`       // Track total stake for monitoring
	TotalDelegated    int64 `json:"totalDelegated"`    // Added for pool delegations
	LastRewardTime    int64 `json:"lastRewardTime"`    // Last reward distribution time (in seconds)
}

type Stake struct {
	UserAddress            string  `json:"userAddress"`
	Amount                 int64   `json:"amount"`
	StartTime              int64   `json:"startTime"`
	LastStakeUpdateTime    int64   `json:"lastStakeUpdateTime"` // Last time stake was updated
	StakeTimeSum           float64 `json:"stakeTimeSum"`        // Accumulated stake-time (stake * duration)
	StakeTimeAverage       float64 `json:"stakeTimeAverage"`    // Moving average of stake-time
	TotalStakeRewards      float64 `json:"totalStakeRewards"`
	TotalDelegationRewards float64 `json:"totalDelegationRewards"`
	IsActive               bool    `json:"isActive"`
	ValidatorRole          bool    `json:"validatorRole"`
}

type StakingService struct {
	mu         sync.RWMutex
	pool       *StakingPool
	stakes     map[string]*Stake
	blockchain *Blockchain
}

func NewStakingService(blockchain *Blockchain) *StakingService {
	return &StakingService{
		pool: &StakingPool{
			MinStakeAmount:    MinimumStakeAmount,
			FixedYearlyReward: AnnualStakeReward,
			LastRewardTime:    time.Now().Unix(),
			TotalStaked:       0,
		},
		stakes:     make(map[string]*Stake),
		blockchain: blockchain,
	}
}

// calculateStakeReward calculates daily reward for each validator and delegator
func (s *StakingService) calculateStakeReward(rewardDistributionTime int64) map[string]float64 {
	// Add validation for time parameters
	if rewardDistributionTime <= s.pool.LastRewardTime {
		return nil
	}

	// finalise stake period before reward distribution
	totalStateTimeAverage := float64(0)
	for _, stake := range s.stakes {
		if stake.LastStakeUpdateTime < rewardDistributionTime {
			stakeTime := stake.Amount * (rewardDistributionTime - stake.LastStakeUpdateTime)
			stake.StakeTimeSum += float64(stakeTime)
			stake.LastStakeUpdateTime = rewardDistributionTime
			stake.StakeTimeAverage = stake.StakeTimeSum / float64(rewardDistributionTime-s.pool.LastRewardTime)
			totalStateTimeAverage += stake.StakeTimeAverage
		}
	}

	rewards := make(map[string]float64)
	extraRewardsFromDelegation := float64(0)
	//distribution of rewards to delegators and validators
	if totalStateTimeAverage > 0 {
		for addr, stake := range s.stakes {
			reward := (stake.StakeTimeAverage / float64(totalStateTimeAverage)) * float64(DailyStakeReward)
			if stake.ValidatorRole {
				rewards[addr] = reward
				stake.TotalStakeRewards += reward
			} else {
				rewards[addr] = reward * DelegationRewardPercent
				extraRewardsFromDelegation += reward * (1 - DelegationRewardPercent)
				stake.TotalDelegationRewards += reward * DelegationRewardPercent
			}
		}
	}
	//distribute extra rewards from delegation
	if extraRewardsFromDelegation > 0 {
		for addr, stake := range s.stakes {
			if stake.ValidatorRole {
				reward := (stake.StakeTimeAverage / float64(totalStateTimeAverage)) * extraRewardsFromDelegation
				rewards[addr] += reward
				stake.TotalDelegationRewards += reward
			}
		}
	}
	return rewards
}

func (s *StakingService) estimateStakeReward(targetAddress string, currentTimeStamp int64) float64 {
	totalStakeTimeAverage := float64(0)
	addressStakeTimeAverage := float64(0)
	extraStakeTimeAverage := float64(0)
	isDelegator := false

	for addr, stake := range s.stakes {
		if stake.LastStakeUpdateTime < currentTimeStamp {
			stakeTime := stake.Amount * (currentTimeStamp - stake.LastStakeUpdateTime)
			stakeTimeSum := stake.StakeTimeSum + float64(stakeTime)
			stakeTimeAverage := stakeTimeSum / float64(currentTimeStamp-s.pool.LastRewardTime)
			totalStakeTimeAverage += stakeTimeAverage
			if !stake.ValidatorRole {
				extraStakeTimeAverage += stakeTimeAverage * (1 - DelegationRewardPercent)
			}

			if addr == targetAddress && stake.ValidatorRole {
				addressStakeTimeAverage = stakeTimeAverage
			} else if addr == targetAddress && !stake.ValidatorRole {
				isDelegator = true
				addressStakeTimeAverage = stakeTimeAverage * DelegationRewardPercent
			}
		}
	}

	if totalStakeTimeAverage == 0 {
		return 0
	}
	if isDelegator {
		return (addressStakeTimeAverage / totalStakeTimeAverage) * float64(DailyStakeReward)
	}

	extra := addressStakeTimeAverage * extraStakeTimeAverage / totalStakeTimeAverage
	return ((addressStakeTimeAverage + extra) / totalStakeTimeAverage) * float64(DailyStakeReward) * DelegationRewardPercent
}

// Add this method to your StakingService struct
func (s *StakingService) GetPoolStats() map[string]interface{} {
	s.mu.RLock()
	defer s.mu.RUnlock()

	currentTime := time.Now().Unix()
	lastRewardTime := s.pool.LastRewardTime // Changed from LastEpochBlock to LastRewardTime

	// Calculate next reward time (24 hours after last reward)
	nextRewardTime := lastRewardTime + (24 * 3600)
	timeUntilReward := nextRewardTime - currentTime

	// Calculate daily reward from yearly reward
	dailyReward := s.pool.FixedYearlyReward / 365

	return map[string]interface{}{
		"totalStaked": map[string]interface{}{
			"thrylos": float64(s.pool.TotalStaked) / 1e7,
			"nano":    s.pool.TotalStaked,
		},
		"delegatorCount": len(s.stakes),
		"rewardSchedule": map[string]interface{}{
			"nextRewardTime":  nextRewardTime,
			"timeUntilReward": timeUntilReward,
			"lastRewardTime":  lastRewardTime, // Using LastRewardTime consistently
			"rewardInterval":  "24h",
			"dailyRewardPool": float64(dailyReward) / 1e7,
			"validatorShare":  "50%",
			"delegatorShare":  "50%",
		},
		"validatorInfo": map[string]interface{}{
			"activeCount":    len(s.blockchain.ActiveValidators),
			"minStakeAmount": float64(s.pool.MinStakeAmount) / 1e7,
		},
	}
}

func (s *StakingService) CreateStake(userAddress string, isDelegator bool, amount int64) (*Stake, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	txID := fmt.Sprintf("stake-%s-%d", userAddress, time.Now().UnixNano())
	txOwnerAddress := "staking_pool"

	if isDelegator {
		txID = fmt.Sprintf("delegate-%s-%d", userAddress, time.Now().UnixNano())
	}

	// Create staking transaction
	stakingTx := &thrylos.Transaction{
		Id:        txID,
		Sender:    userAddress,
		Timestamp: time.Now().Unix(),
		Outputs: []*thrylos.UTXO{{
			OwnerAddress:  txOwnerAddress,
			Amount:        amount,
			Index:         0,
			TransactionId: "", // Will be set when added to blockchain
		}},
	}

	// Add transaction to pending pool
	if err := s.blockchain.AddPendingTransaction(stakingTx); err != nil {
		return nil, fmt.Errorf("failed to create staking transaction: %v", err)
	}

	// Use existing internal logic with the transaction timestamp
	return s.createStakeInternal(userAddress, isDelegator, amount, stakingTx.Timestamp)
}

// Keep internal function for testing
func (s *StakingService) createStakeInternal(userAddress string, isDelegator bool, amount int64, timestamp int64) (*Stake, error) {
	// Existing validation
	if amount < s.pool.MinStakeAmount {
		return nil, fmt.Errorf("minimum stake amount is %d THRYLOS", s.pool.MinStakeAmount/1e7)
	}

	now := timestamp
	if _, ok := s.blockchain.Stakeholders[userAddress]; !ok {
		stake := &Stake{
			UserAddress:            userAddress,
			Amount:                 0,
			StartTime:              now,
			LastStakeUpdateTime:    now,
			TotalStakeRewards:      0,
			TotalDelegationRewards: 0,
			IsActive:               true,
			ValidatorRole:          true,
		}
		s.stakes[userAddress] = stake
		s.blockchain.Stakeholders[userAddress] = 0
	}

	// Update stakes
	currentStake := s.blockchain.Stakeholders[userAddress]
	s.blockchain.Stakeholders[userAddress] = currentStake + amount
	if isDelegator {
		s.pool.TotalDelegated += amount
	} else {
		s.pool.TotalStaked += amount
	}

	// Update stake record with time calculations
	duration := now - s.stakes[userAddress].LastStakeUpdateTime
	totalDuration := now - s.pool.LastRewardTime
	stakeTime := s.stakes[userAddress].Amount * duration
	s.stakes[userAddress].Amount += amount
	s.stakes[userAddress].StakeTimeSum += float64(stakeTime)
	s.stakes[userAddress].StakeTimeAverage = s.stakes[userAddress].StakeTimeSum / float64(totalDuration)
	s.stakes[userAddress].LastStakeUpdateTime = now
	return s.stakes[userAddress], nil
}

func (s *StakingService) DistributeRewards() error {
	s.mu.Lock()
	defer s.mu.Unlock()

	currentTime := time.Now().Unix()

	// Check if 24 hours have passed
	if currentTime-s.pool.LastRewardTime < RewardDistributionTimeInterval {
		return nil // Not time for rewards yet
	}

	rewards := s.calculateStakeReward(currentTime)
	if rewards == nil {
		return nil
	}

	// Distribute rewards to active validators and delegators
	for validatorAddr, reward := range rewards {
		rewardTx := &thrylos.Transaction{
			Id:        fmt.Sprintf("reward-%s-%d", validatorAddr, time.Now().UnixNano()),
			Sender:    "network",
			Timestamp: currentTime,
			Outputs: []*thrylos.UTXO{{
				OwnerAddress:  validatorAddr,
				Amount:        int64(reward),
				Index:         0,
				TransactionId: "",
			}},
		}

		if err := s.blockchain.AddPendingTransaction(rewardTx); err != nil {
			return fmt.Errorf("failed to add reward transaction: %v", err)
		}
	}

	s.pool.LastRewardTime = currentTime
	return nil
}

func (s *StakingService) UnstakeTokens(userAddress string, isDelegator bool, amount int64) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	txID := fmt.Sprintf("unstake-%s-%d", userAddress, time.Now().UnixNano())

	if isDelegator {
		txID = fmt.Sprintf("undelegate-%s-%d", userAddress, time.Now().UnixNano())
	}

	// Create unstaking transaction
	unstakingTx := &thrylos.Transaction{
		Id:        txID,
		Sender:    "staking_pool",
		Timestamp: time.Now().Unix(),
		Outputs: []*thrylos.UTXO{{
			OwnerAddress:  userAddress,
			Amount:        amount,
			Index:         0,
			TransactionId: "", // Will be set when added to blockchain
		}},
	}

	// Add transaction to pending pool
	if err := s.blockchain.AddPendingTransaction(unstakingTx); err != nil {
		return fmt.Errorf("failed to create unstaking transaction: %v", err)
	}

	// Use internal unstaking logic with transaction timestamp
	return s.unstakeTokensInternal(userAddress, isDelegator, amount, unstakingTx.Timestamp)
}

func (s *StakingService) unstakeTokensInternal(userAddress string, isDelegator bool, amount int64, timestamp int64) error {
	currentStake := s.blockchain.Stakeholders[userAddress]
	if currentStake < amount {
		return errors.New("insufficient staked amount")
	}

	// Update Stakeholders map
	if currentStake == amount {
		delete(s.blockchain.Stakeholders, userAddress)
	} else {
		s.blockchain.Stakeholders[userAddress] = currentStake - amount
	}

	if isDelegator {
		s.pool.TotalDelegated -= amount
	} else {
		s.pool.TotalStaked -= amount
	}

	now := timestamp

	// Update stake record
	duration := now - s.stakes[userAddress].LastStakeUpdateTime
	totalDuration := now - s.pool.LastRewardTime // total duration since last reward
	stakeTime := s.stakes[userAddress].Amount * duration
	s.stakes[userAddress].Amount -= amount
	s.stakes[userAddress].StakeTimeSum += float64(stakeTime)
	s.stakes[userAddress].StakeTimeAverage = s.stakes[userAddress].StakeTimeSum / float64(totalDuration)
	s.stakes[userAddress].LastStakeUpdateTime = now

	return nil
}

// Support methods for compatibility
func (s *StakingService) GetTotalStaked() int64 {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.pool.TotalStaked
}
func (s *StakingService) GetTotalDelegated() int64 {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.pool.TotalDelegated
}
func (s *StakingService) GetTotalStakedDelegated() int64 {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.pool.TotalDelegated + s.pool.TotalStaked
}

func (s *StakingService) GetEffectiveInflationRate() float64 {
	s.mu.RLock()
	defer s.mu.RUnlock()

	currentTotalSupply := float64(s.getTotalSupply()) / 1e7
	fixedYearlyReward := float64(s.pool.FixedYearlyReward) / 1e7
	return (fixedYearlyReward / currentTotalSupply) * 100
}

func (s *StakingService) getTotalSupply() int64 {
	// No need for additional locking as this is called from locked methods
	totalSupply := int64(0)
	for _, balance := range s.blockchain.Stakeholders {
		totalSupply += balance
	}
	return totalSupply
}
