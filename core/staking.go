package core

import (
	"errors"
	"fmt"
	"time"

	thrylos "github.com/thrylos-labs/thrylos"
)

type StakingPool struct {
	MinStakeAmount    int64 `json:"minStakeAmount"`
	FixedYearlyReward int64 `json:"fixedYearlyReward"` // Always 4.8M (4% of original 120M)
	TotalStaked       int64 `json:"totalStaked"`
	EpochLength       int64 `json:"epochLength"`
	LastEpochBlock    int64 `json:"lastEpochBlock"`
}

type Stake struct {
	UserAddress     string `json:"userAddress"`
	Amount          int64  `json:"amount"`
	StartTime       int64  `json:"startTime"`
	LastRewardEpoch int64  `json:"lastRewardEpoch"`
	TotalRewards    int64  `json:"totalRewards"`
	IsActive        bool   `json:"isActive"`
	ValidatorRole   bool   `json:"validatorRole"`
}

type StakingService struct {
	pool       *StakingPool
	stakes     map[string][]*Stake
	blockchain *Blockchain
}

func NewStakingService(blockchain *Blockchain) *StakingService {
	fixedYearlyReward := int64(4_800_000 * 1e7) // Fixed 4.8M (4% of 120M) in nano

	return &StakingService{
		pool: &StakingPool{
			MinStakeAmount:    int64(40 * 1e7),   // 40 THRYLOS
			FixedYearlyReward: fixedYearlyReward, // Always 4.8M per year
			EpochLength:       240,               // Blocks per epoch
			LastEpochBlock:    0,
			TotalStaked:       0,
		},
		stakes:     make(map[string][]*Stake),
		blockchain: blockchain,
	}
}

// Calculate rewards per epoch (fixed amount)
func (s *StakingService) calculateEpochRewards() int64 {
	// Divide fixed yearly reward (4.8M) by number of epochs per year
	epochReward := s.pool.FixedYearlyReward / (365 * 24 * s.pool.EpochLength)
	return epochReward
}

// Add method to get current effective inflation rate
func (s *StakingService) GetEffectiveInflationRate() float64 {
	currentTotalSupply := float64(s.getTotalSupply()) / 1e7
	fixedYearlyReward := float64(s.pool.FixedYearlyReward) / 1e7

	// Calculate effective rate (will decrease as total supply grows)
	effectiveRate := (fixedYearlyReward / currentTotalSupply) * 100
	return effectiveRate
}

func (s *StakingService) getTotalSupply() int64 {
	totalSupply := int64(0)
	for _, balance := range s.blockchain.Stakeholders {
		totalSupply += balance
	}
	return totalSupply
}

func (s *StakingService) CalculateRewards(stake *Stake, currentBlock int64) int64 {
	if !stake.IsActive {
		return 0
	}

	currentEpoch := currentBlock / s.pool.EpochLength
	if currentEpoch <= stake.LastRewardEpoch {
		return 0
	}

	// Get actual stake amount
	actualStake := s.blockchain.Stakeholders[stake.UserAddress]
	if actualStake == 0 {
		return 0
	}

	// Calculate share of epoch rewards based on stake ratio
	epochRewards := s.calculateEpochRewards()
	stakingRatio := float64(actualStake) / float64(s.pool.TotalStaked)
	reward := int64(float64(epochRewards) * stakingRatio)

	return reward
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

func (s *StakingService) DistributeEpochRewards(currentBlock int64) error {
	if currentBlock == 0 {
		currentBlock = int64(s.blockchain.GetBlockCount())
	}

	if currentBlock <= s.pool.LastEpochBlock+s.pool.EpochLength {
		return nil // Not time for rewards yet
	}

	epochRewards := s.calculateEpochRewards()
	rewardsDistributed := int64(0)

	for userAddress, userStakes := range s.stakes {
		for _, stake := range userStakes {
			if !stake.IsActive {
				continue
			}

			reward := s.CalculateRewards(stake, currentBlock)
			if reward > 0 {
				// Ensure we don't exceed fixed epoch rewards
				if rewardsDistributed+reward > epochRewards {
					reward = epochRewards - rewardsDistributed
				}
				if reward <= 0 {
					continue
				}

				rewardTx := &thrylos.Transaction{
					Id:        fmt.Sprintf("reward-%s-%d", userAddress, time.Now().UnixNano()),
					Sender:    "network",
					Timestamp: time.Now().Unix(),
					Outputs: []*thrylos.UTXO{{
						OwnerAddress:  userAddress,
						Amount:        reward,
						Index:         0,
						TransactionId: "",
					}},
				}

				if err := s.blockchain.AddPendingTransaction(rewardTx); err != nil {
					return fmt.Errorf("failed to add reward transaction: %v", err)
				}

				stake.TotalRewards += reward
				stake.LastRewardEpoch = currentBlock / s.pool.EpochLength
				rewardsDistributed += reward
			}

			// Stop if we've distributed all epoch rewards
			if rewardsDistributed >= epochRewards {
				break
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
