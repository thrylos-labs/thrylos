package core

import (
	"errors"
	"fmt"
	"log"
	"time"

	thrylos "github.com/thrylos-labs/thrylos"
)

type StakingPool struct {
	MinStakeAmount    int64 `json:"minStakeAmount"`
	MinDelegation     int64 `json:"minDelegation"`     // Added for pool delegations
	FixedYearlyReward int64 `json:"fixedYearlyReward"` // Always 4.8M
	TotalStaked       int64 `json:"totalStaked"`       // Track total stake for monitoring
	LastRewardTime    int64 `json:"lastRewardTime"`    // Last reward distribution time (in seconds)
}

type Stake struct {
	UserAddress         string  `json:"userAddress"`
	Amount              int64   `json:"amount"`
	StartTime           int64   `json:"startTime"`
	LastStakeUpdateTime int64   `json:"lastStakeUpdateTime"` // Last time stake was updated
	StakeTimeSum        float64 `json:"stakeTimeSum"`        // Accumulated stake-time (stake * duration)
	StakeTimeAverage    float64 `json:"stakeTimeAverage"`    // Moving average of stake-time
	TotalRewards        float64 `json:"totalRewards"`
	IsActive            bool    `json:"isActive"`
	ValidatorRole       bool    `json:"validatorRole"`
}

type Delegation struct {
	DelegatorAddress string
	ValidatorAddress string
	Amount           int64
	StartTime        int64
	LastRewardTime   int64
	TotalRewards     int64
	IsActive         bool
}

type StakingService struct {
	pool        *StakingPool
	stakes      map[string]*Stake
	delegations map[string][]*Delegation
	blockchain  *Blockchain
}

type DelegationPool struct {
	TotalDelegated    int64 `json:"totalDelegated"`
	MinDelegation     int64 `json:"minDelegation"`     // Minimum delegation amount
	FixedYearlyReward int64 `json:"fixedYearlyReward"` // 4.8M yearly
	LastRewardTime    int64 `json:"lastRewardTime"`    // Last reward distribution time
	RewardInterval    int64 `json:"rewardInterval"`    // 24 hours in seconds
}

func NewStakingService(blockchain *Blockchain) *StakingService {
	return &StakingService{
		pool: &StakingPool{
			MinStakeAmount:    MinimumStakeAmount,
			FixedYearlyReward: AnnualStakeReward,
			LastRewardTime:    time.Now().Unix(),
			TotalStaked:       0,
		},
		stakes:      make(map[string]*Stake),
		delegations: make(map[string][]*Delegation),
		blockchain:  blockchain,
	}
}

// calculateRewardPerValidator distributes daily reward equally among active validators
func (s *StakingService) calculateRewardPerValidator(rewardDistributionTime int64) map[string]float64 {
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

	if totalStateTimeAverage > 0 {
		for validatorAddress, stake := range s.stakes {
			reward := (stake.StakeTimeAverage / float64(totalStateTimeAverage)) * float64(DailyStakeReward)
			rewards[validatorAddress] = reward
			stake.TotalRewards += reward
		}
	}
	return rewards
}

func (s *StakingService) estimateValidatorReward(validatorAddress string, currentTimeStamp int64) float64 {
	// finalise stake period before reward distribution
	totalStateTimeAverage := float64(0)
	validatorStakeTimeAvarege := float64(0)
	for validatorAddress, stake := range s.stakes {
		if stake.LastStakeUpdateTime < currentTimeStamp {
			stakeTime := stake.Amount * (currentTimeStamp - stake.LastStakeUpdateTime)
			stakeTimeSum := stake.StakeTimeSum + float64(stakeTime)
			stakeTimeAverage := stakeTimeSum / float64(currentTimeStamp-s.pool.LastRewardTime)
			totalStateTimeAverage += stakeTimeAverage

			if validatorAddress == validatorAddress {
				validatorStakeTimeAvarege = stakeTimeAverage
			}
		}
	}
	return (validatorStakeTimeAvarege / float64(totalStateTimeAverage)) * float64(DailyStakeReward)
}

// Add this method to your StakingService struct
func (s *StakingService) GetPoolStats() map[string]interface{} {
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

// TODO: Timestamp is needed for testing puproses. Remove it after testing
func (s *StakingService) CreateStake(userAddress string, amount int64, timestap int64) (*Stake, error) {
	if amount < s.pool.MinStakeAmount {
		return nil, fmt.Errorf("minimum stake amount is %d THRYLOS", s.pool.MinStakeAmount/1e7)
	}
	//now := time.Now().Unix()
	now := timestap
	if _, ok := s.blockchain.Stakeholders[userAddress]; !ok {
		// Create new stake record
		stake := &Stake{
			UserAddress:         userAddress,
			Amount:              0,
			StartTime:           now,
			LastStakeUpdateTime: now,
			TotalRewards:        0,
			IsActive:            true,
			ValidatorRole:       true,
		}
		s.stakes[userAddress] = stake // we have assumed that if the address is not in the list of stakeholders, then it does not have any stake.
		s.blockchain.Stakeholders[userAddress] = 0
	}

	// Update blockchain's Stakeholders map
	currentStake := s.blockchain.Stakeholders[userAddress]
	s.blockchain.Stakeholders[userAddress] = currentStake + amount
	s.pool.TotalStaked += amount

	// Update stake record
	// Finalize the previous stake period
	duration := now - s.stakes[userAddress].LastStakeUpdateTime
	totalDuration := now - s.pool.LastRewardTime // total duration since last reward
	stakeTime := s.stakes[userAddress].Amount * duration
	s.stakes[userAddress].Amount += amount
	s.stakes[userAddress].StakeTimeSum += float64(stakeTime)
	s.stakes[userAddress].StakeTimeAverage = s.stakes[userAddress].StakeTimeSum / float64(totalDuration)
	s.stakes[userAddress].LastStakeUpdateTime = now

	return s.stakes[userAddress], nil
}

func (s *StakingService) DistributeRewards() error {
	currentTime := time.Now().Unix()

	// Check if 24 hours have passed
	if currentTime-s.pool.LastRewardTime < RewardDistributionTimeInterval {
		return nil // Not time for rewards yet
	}

	rewards := s.calculateRewardPerValidator(currentTime)
	if rewards == nil {
		return nil
	}

	// Distribute rewards to active validators
	//for _, validatorAddr := range s.blockchain.ActiveValidators { we need to distribute rewards to all validators, no active only
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

func (s *StakingService) UnstakeTokens(userAddress string, amount int64, timestamp int64) error {
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

	s.pool.TotalStaked -= amount

	//now := time.Now().Unix()
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
	return s.pool.TotalStaked
}

func (s *StakingService) GetEffectiveInflationRate() float64 {
	currentTotalSupply := float64(s.getTotalSupply()) / 1e7
	fixedYearlyReward := float64(s.pool.FixedYearlyReward) / 1e7
	return (fixedYearlyReward / currentTotalSupply) * 100
}

func (s *StakingService) getTotalSupply() int64 {
	totalSupply := int64(0)
	for _, balance := range s.blockchain.Stakeholders {
		totalSupply += balance
	}
	return totalSupply
}

// Add these methods to your StakingService struct

func (s *StakingService) DelegateToPool(delegator string, amount int64) error {
	// Add debug logging
	log.Printf("DelegateToPool - Starting delegation for %s with amount %d", delegator, amount)
	log.Printf("DelegateToPool - Current total staked: %d", s.pool.TotalStaked)

	if amount < s.pool.MinStakeAmount {
		return fmt.Errorf("minimum delegation amount is %d THRYLOS", s.pool.MinStakeAmount/1e7)
	}

	// Check delegator's balance
	balance, err := s.blockchain.GetBalance(delegator)
	if err != nil {
		return fmt.Errorf("failed to get delegator balance: %v", err)
	}

	if balance < amount {
		return errors.New("insufficient balance for delegation")
	}

	// Create delegation record
	now := time.Now().Unix()
	stake := &Stake{
		UserAddress:         delegator,
		Amount:              amount,
		StartTime:           now,
		LastStakeUpdateTime: now,
		IsActive:            true,
		ValidatorRole:       false, // This is a delegation, not a validator
		TotalRewards:        0,
	}

	// Create transaction first (before modifying state)
	delegationTx := &thrylos.Transaction{
		Id:        fmt.Sprintf("delegate-%s-%d", delegator, time.Now().UnixNano()),
		Sender:    delegator,
		Timestamp: now,
		Outputs: []*thrylos.UTXO{{
			OwnerAddress: "delegation_pool",
			Amount:       amount,
			Index:        0,
		}},
	}

	// Add the transaction
	if err := s.blockchain.AddPendingTransaction(delegationTx); err != nil {
		return fmt.Errorf("failed to add delegation transaction: %v", err)
	}

	// Update state under lock
	s.blockchain.Mu.Lock()
	defer s.blockchain.Mu.Unlock()

	// Update pool total
	s.pool.TotalStaked += amount
	s.stakes[delegator] = stake

	log.Printf("DelegateToPool - After delegation - Total staked: %d", s.pool.TotalStaked)
	log.Printf("DelegateToPool - After delegation - Stakes for %s: %+v", delegator, s.stakes[delegator])

	return nil
}

func (s *StakingService) UndelegateFromPool(delegator string, amount int64) error {
	log.Printf("UndelegateFromPool - Starting undelegation for %s with amount %d", delegator, amount)
	log.Printf("UndelegateFromPool - Current total staked: %d", s.pool.TotalStaked)

	// First create the transaction object
	undelegationTx := &thrylos.Transaction{
		Id:        fmt.Sprintf("undelegate-%s-%d", delegator, time.Now().UnixNano()),
		Sender:    "delegation_pool",
		Timestamp: time.Now().Unix(),
		Outputs: []*thrylos.UTXO{{
			OwnerAddress: delegator,
			Amount:       amount,
			Index:        0,
		}},
	}

	// Add transaction first
	if err := s.blockchain.AddPendingTransaction(undelegationTx); err != nil {
		return fmt.Errorf("failed to add undelegation transaction: %v", err)
	}

	// Then update stake amounts under a single lock
	s.blockchain.Mu.Lock()
	defer s.blockchain.Mu.Unlock()

	// Verify total delegated amount under lock
	totalDelegated := s.stakes[delegator].Amount
	activeStake := s.stakes[delegator]

	log.Printf("UndelegateFromPool - Found active stake for %s: %+v", delegator, activeStake)
	log.Printf("UndelegateFromPool - Total delegated: %d", totalDelegated)

	if totalDelegated < amount {
		return fmt.Errorf("insufficient delegated amount: have %d, requested %d", totalDelegated, amount)
	}

	if activeStake == nil {
		return fmt.Errorf("no active stake found for delegator %s", delegator)
	}

	// Calculate new stake amount
	newAmount := activeStake.Amount - amount
	if newAmount < 0 {
		return fmt.Errorf("invalid undelegation amount: would result in negative stake")
	}

	// Update the stake amount
	if newAmount == 0 {
		activeStake.IsActive = false
	} else {
		activeStake.Amount = newAmount
	}

	// Update total staked amount
	s.pool.TotalStaked -= amount

	log.Printf("UndelegateFromPool - After undelegation - Total staked: %d", s.pool.TotalStaked)
	log.Printf("UndelegateFromPool - After undelegation - Updated stake: %+v", activeStake)

	return nil
}
