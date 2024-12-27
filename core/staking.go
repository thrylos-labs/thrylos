package core

import (
	"errors"
	"fmt"
	"time"

	thrylos "github.com/thrylos-labs/thrylos"
)

// First, let's enhance the StakingPool structure to include inflation parameters
type StakingPool struct {
	MinStakeAmount      int64   `json:"minStakeAmount"`
	BaseRewardFactor    float64 `json:"baseRewardFactor"` // Base reward rate
	TotalStaked         int64   `json:"totalStaked"`
	AnnualInflationRate float64 `json:"annualInflationRate"` // Annual inflation rate
	EpochLength         int64   `json:"epochLength"`         // Blocks per epoch
	LastEpochBlock      int64   `json:"lastEpochBlock"`      // Last block where rewards were distributed
}

// Modify the Stake structure to track epochs
type Stake struct {
	UserAddress     string `json:"userAddress"`
	Amount          int64  `json:"amount"`
	StartTime       int64  `json:"startTime"`
	LastRewardEpoch int64  `json:"lastRewardEpoch"`
	TotalRewards    int64  `json:"totalRewards"`
	IsActive        bool   `json:"isActive"`
	ValidatorRole   bool   `json:"validatorRole"` // Indicates if stake is for validator
}

// Update StakingService to work with the blockchain
type StakingService struct {
	pool       *StakingPool
	stakes     map[string][]*Stake
	blockchain *Blockchain // Add reference to blockchain
}

func NewStakingService(blockchain *Blockchain) *StakingService {
	minStakeAmount := int64(40 * 1e7) // min stake 40 THRYLOS converted to nano

	return &StakingService{
		pool: &StakingPool{
			MinStakeAmount:      minStakeAmount,
			BaseRewardFactor:    0.0001,
			AnnualInflationRate: 0.04,
			EpochLength:         240,
			LastEpochBlock:      0,
			TotalStaked:         0,
		},
		stakes:     make(map[string][]*Stake),
		blockchain: blockchain,
	}
}

func (s *StakingService) CreateStake(userAddress string, amount int64) (*Stake, error) {
	if amount < s.pool.MinStakeAmount {
		return nil, fmt.Errorf("minimum stake amount is %d THRYLOS", s.pool.MinStakeAmount/1e7)
	}

	// Update the blockchain's Stakeholders map
	currentStake := s.blockchain.Stakeholders[userAddress]
	s.blockchain.Stakeholders[userAddress] = currentStake + amount

	// Update total staked amount
	s.pool.TotalStaked += amount

	// Create stake record
	now := time.Now().Unix()
	currentBlock := int64(s.blockchain.GetBlockCount())

	stake := &Stake{
		UserAddress:     userAddress,
		Amount:          amount,
		StartTime:       now,
		LastRewardEpoch: currentBlock / s.pool.EpochLength,
		TotalRewards:    0,
		IsActive:        true,
		ValidatorRole:   true, // Since it's in Stakeholders, it's a validator
	}

	// Store stake in our tracking map
	s.stakes[userAddress] = append(s.stakes[userAddress], stake)

	return stake, nil
}

// Add method to calculate inflation rewards
func (s *StakingService) calculateEpochInflation() int64 {
	totalSupply := s.blockchain.Stakeholders[s.blockchain.GenesisAccount]
	annualInflation := float64(totalSupply) * s.pool.AnnualInflationRate
	epochInflation := int64(annualInflation / (365 * 24 * float64(s.pool.EpochLength))) // Per epoch
	return epochInflation
}

// Update reward calculation to use inflation model
func (s *StakingService) CalculateRewards(stake *Stake, currentBlock int64) int64 {
	if !stake.IsActive {
		return 0
	}

	currentEpoch := currentBlock / s.pool.EpochLength
	if currentEpoch <= stake.LastRewardEpoch {
		return 0
	}

	// Use actual stake amount from Stakeholders map
	actualStake := s.blockchain.Stakeholders[stake.UserAddress]
	if actualStake == 0 {
		return 0
	}

	// Calculate base reward using square root of total stake
	baseReward := int64(float64(s.pool.TotalStaked) * s.pool.BaseRewardFactor)

	// Calculate participation rate using actual stake
	participationRate := float64(actualStake) / float64(s.pool.TotalStaked)

	// Calculate epoch inflation share
	epochInflation := s.calculateEpochInflation()
	inflationShare := int64(float64(epochInflation) * participationRate)

	totalReward := baseReward + inflationShare
	return totalReward
}

// Add method to distribute epoch rewards
func (s *StakingService) DistributeEpochRewards(currentBlock int64) error {
	// If no currentBlock provided, get current block count
	if currentBlock == 0 {
		currentBlock = int64(s.blockchain.GetBlockCount())
	}

	if currentBlock <= s.pool.LastEpochBlock+s.pool.EpochLength {
		return nil // Not time for new epoch rewards yet
	}

	for userAddress, userStakes := range s.stakes {
		for _, stake := range userStakes {
			if !stake.IsActive {
				continue
			}

			reward := s.CalculateRewards(stake, currentBlock)
			if reward > 0 {
				// Create reward transaction
				rewardTx := &thrylos.Transaction{
					Id:        fmt.Sprintf("reward-%s-%d", userAddress, time.Now().UnixNano()),
					Sender:    "network", // Special sender for network rewards
					Timestamp: time.Now().Unix(),
					Outputs: []*thrylos.UTXO{{
						OwnerAddress:  userAddress,
						Amount:        reward,
						Index:         0,
						TransactionId: "",
					}},
				}

				// Add to blockchain's pending transactions
				if err := s.blockchain.AddPendingTransaction(rewardTx); err != nil {
					return fmt.Errorf("failed to add reward transaction: %v", err)
				}

				stake.TotalRewards += reward
				stake.LastRewardEpoch = currentBlock / s.pool.EpochLength
			}
		}
	}

	s.pool.LastEpochBlock = currentBlock
	return nil
}

// Update StakingService method to accept int64 for amount
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

	// Update total staked
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

func (s *StakingService) GetTotalStaked() int64 {
	// Calculate total staked directly from Stakeholders map
	total := int64(0)
	for _, stake := range s.blockchain.Stakeholders {
		total += stake
	}
	s.pool.TotalStaked = total // Keep our pool total in sync
	return total
}
