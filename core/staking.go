package core

import (
	"errors"
	"fmt"
	"time"

	thrylos "github.com/thrylos-labs/thrylos"
)

type StakingPool struct {
	MinStakeAmount    int64 `json:"minStakeAmount"`
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
