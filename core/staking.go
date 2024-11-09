// In your Go backend
package core

import (
	"errors"
	"fmt"
	"time"

	"github.com/thrylos-labs/thrylos/shared"
)

type StakingPool struct {
	MinStakeAmount int64   `json:"minStakeAmount"` // Minimum amount that can be staked (in nanoTHRYLOS)
	APR            float64 `json:"apr"`            // Annual Percentage Rate
	LockPeriod     int64   `json:"lockPeriod"`     // Lock period in seconds
	TotalStaked    int64   `json:"totalStaked"`    // Total amount staked in the pool
}

type Stake struct {
	UserAddress string `json:"userAddress"`
	Amount      int64  `json:"amount"`
	StartTime   int64  `json:"startTime"`
	EndTime     int64  `json:"endTime"`
	Rewards     int64  `json:"rewards"`
	IsActive    bool   `json:"isActive"`
}

// StakingService handles staking operations
type StakingService struct {
	pool     *StakingPool
	stakes   map[string][]*Stake          // Map of user address to their stakes
	Database shared.BlockchainDBInterface // Updated the type to interface
}

func NewStakingService(db *shared.BlockchainDBInterface) *StakingService {

	return &StakingService{
		pool: &StakingPool{
			MinStakeAmount: 100000000, // 10 THRYLOS minimum
			APR:            5.0,       // 5% APR
			LockPeriod:     86400 * 7, // 7 days in seconds
			TotalStaked:    0,
		},
		stakes:   make(map[string][]*Stake),
		Database: *db,
	}
}

func (s *StakingService) CreateStake(userAddress string, amount int64) (*Stake, error) {
	if amount < s.pool.MinStakeAmount {
		return nil, fmt.Errorf("minimum stake amount is %d THRYLOS", s.pool.MinStakeAmount/1e7)
	}

	// Check user's balance
	// balance, err := s.Database.GetBalance(userAddress)
	// if err != nil || balance < amount {
	// 	return nil, errors.New("insufficient balance")
	// }

	// Create new stake
	now := time.Now().Unix()
	stake := &Stake{
		UserAddress: userAddress,
		Amount:      amount,
		StartTime:   now,
		EndTime:     now + s.pool.LockPeriod,
		Rewards:     0,
		IsActive:    true,
	}

	// Lock the tokens
	// err = s.Database.DeductBalance(userAddress, amount)
	// if err != nil {
	// 	return nil, err
	// }

	// Update total staked
	s.pool.TotalStaked += amount

	// Store stake
	s.stakes[userAddress] = append(s.stakes[userAddress], stake)
	return stake, nil
}

func (s *StakingService) CalculateRewards(stake *Stake) int64 {
	if !stake.IsActive {
		return 0
	}

	duration := time.Now().Unix() - stake.StartTime
	if duration < 0 {
		return 0
	}

	// Calculate rewards: (amount * APR * duration) / (365 * 24 * 3600)
	rewards := float64(stake.Amount) * s.pool.APR * float64(duration) / (365 * 24 * 3600 * 100)
	return int64(rewards)
}

func (s *StakingService) UnstakeTokens(userAddress string, stakeIndex int) error {
	userStakes := s.stakes[userAddress]
	if stakeIndex >= len(userStakes) {
		return errors.New("invalid stake index")
	}

	stake := userStakes[stakeIndex]
	if !stake.IsActive {
		return errors.New("stake already withdrawn")
	}

	if time.Now().Unix() < stake.EndTime {
		return errors.New("tokens are still locked")
	}

	// Calculate final rewards
	rewards := s.CalculateRewards(stake)

	// Return staked amount plus rewards
	// totalReturn := stake.Amount + rewards
	// err := s.Database.AddBalance(userAddress, totalReturn)
	// if err != nil {
	// 	return err
	// }

	// Update stake status
	stake.IsActive = false
	stake.Rewards = rewards
	s.pool.TotalStaked -= stake.Amount

	return nil
}
