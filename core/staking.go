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
	LastRewardTime    int64 `json:"lastRewardTime"`    // Last reward distribution time
}

type Stake struct {
	UserAddress    string `json:"userAddress"`
	Amount         int64  `json:"amount"`
	StartTime      int64  `json:"startTime"`
	LastRewardTime int64  `json:"lastRewardTime"`
	TotalRewards   int64  `json:"totalRewards"`
	IsActive       bool   `json:"isActive"`
	ValidatorRole  bool   `json:"validatorRole"`
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
	stakes      map[string][]*Stake
	delegations map[string][]*Delegation
	blockchain  *Blockchain
}

func NewStakingService(blockchain *Blockchain) *StakingService {
	return &StakingService{
		pool: &StakingPool{
			MinStakeAmount:    int64(40 * 1e7),
			FixedYearlyReward: int64(4_800_000 * 1e7),
			LastRewardTime:    time.Now().Unix(),
			TotalStaked:       0,
		},
		stakes:      make(map[string][]*Stake),
		delegations: make(map[string][]*Delegation),
		blockchain:  blockchain,
	}
}

// calculateDailyReward determines the daily reward amount
func (s *StakingService) calculateDailyReward() int64 {
	return s.pool.FixedYearlyReward / 365
}

// calculateRewardPerValidator distributes daily reward equally among active validators
func (s *StakingService) calculateRewardPerValidator() int64 {
	activeValidators := len(s.blockchain.ActiveValidators)
	if activeValidators == 0 {
		return 0
	}
	dailyReward := s.calculateDailyReward()
	return dailyReward / int64(activeValidators)
}

func (s *StakingService) CreateStake(userAddress string, amount int64) (*Stake, error) {
	if amount < s.pool.MinStakeAmount {
		return nil, fmt.Errorf("minimum stake amount is %d THRYLOS", s.pool.MinStakeAmount/1e7)
	}

	// Update blockchain's Stakeholders map
	currentStake := s.blockchain.Stakeholders[userAddress]
	s.blockchain.Stakeholders[userAddress] = currentStake + amount
	s.pool.TotalStaked += amount

	// Create stake record
	now := time.Now().Unix()
	stake := &Stake{
		UserAddress:    userAddress,
		Amount:         amount,
		StartTime:      now,
		LastRewardTime: now,
		TotalRewards:   0,
		IsActive:       true,
		ValidatorRole:  true,
	}

	s.stakes[userAddress] = append(s.stakes[userAddress], stake)
	return stake, nil
}

func (s *StakingService) DistributeRewards() error {
	currentTime := time.Now().Unix()

	// Check if 24 hours have passed
	if currentTime-s.pool.LastRewardTime < 24*3600 {
		return nil // Not time for rewards yet
	}

	rewardPerValidator := s.calculateRewardPerValidator()
	if rewardPerValidator <= 0 {
		return nil
	}

	// Distribute rewards to active validators
	for _, validatorAddr := range s.blockchain.ActiveValidators {
		rewardTx := &thrylos.Transaction{
			Id:        fmt.Sprintf("reward-%s-%d", validatorAddr, time.Now().UnixNano()),
			Sender:    "network",
			Timestamp: currentTime,
			Outputs: []*thrylos.UTXO{{
				OwnerAddress:  validatorAddr,
				Amount:        rewardPerValidator,
				Index:         0,
				TransactionId: "",
			}},
		}

		if err := s.blockchain.AddPendingTransaction(rewardTx); err != nil {
			return fmt.Errorf("failed to add reward transaction: %v", err)
		}

		// Update stake records
		for _, stake := range s.stakes[validatorAddr] {
			if stake.IsActive {
				stake.LastRewardTime = currentTime
				stake.TotalRewards += rewardPerValidator
			}
		}
	}

	s.pool.LastRewardTime = currentTime
	return nil
}

func (s *StakingService) UnstakeTokens(userAddress string, amount int64) error {
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

	// Update stake records
	for _, stake := range s.stakes[userAddress] {
		if stake.Amount == amount && stake.IsActive {
			stake.IsActive = false
			break
		}
	}

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
