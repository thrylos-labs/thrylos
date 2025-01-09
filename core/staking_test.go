package core

import (
	"testing"
	"time"
)

func (s *StakingService) CreateStakeForTest(userAddress string, isDelegator bool, amount int64, timestamp int64) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	_, err := s.createStakeInternal(userAddress, isDelegator, amount, timestamp)
	return err
}

func (s *StakingService) UnstakeTokensForTest(userAddress string, isDelegator bool, amount int64, timestamp int64) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.unstakeTokensInternal(userAddress, isDelegator, amount, timestamp)
}

func TestRewardDistribution(t *testing.T) {
	// Define the reward period (from midnight to the next midnight)
	stakingPeriodStartTime := time.Date(2025, 1, 4, 0, 0, 0, 0, time.UTC).Unix()
	stakingPeriodEndTime := time.Date(2025, 1, 5, 0, 0, 0, 0, time.UTC).Unix()

	blockchain := &Blockchain{
		Stakeholders: make(map[string]int64),
	}

	stakingService := NewStakingService(blockchain)
	stakingService.pool.LastRewardTime = stakingPeriodStartTime

	// Simulate stakeing for address 1
	stakingAddress1 := "0x1234567890"
	// Staking 100 THRLY at midnight
	a1t1 := time.Date(2025, 1, 4, 0, 0, 0, 0, time.UTC).Unix()
	stakingService.CreateStakeForTest(stakingAddress1, false, ThrylosToNano(100.0), a1t1)
	// Unstaking 50 THRLY at noon, and the remaining 50 THRLY up to the end of reward distribution
	a1t2 := time.Date(2025, 1, 4, 12, 0, 0, 0, time.UTC).Unix()
	stakingService.UnstakeTokensForTest(stakingAddress1, false, ThrylosToNano(50.0), a1t2)

	// Simulate stakeing for address 2
	stakingAddress2 := "0x0987654321"
	// Staking 200 THRLY stakeing at midnight, and 150 THRLY at 0500 making total stake to be 350 THRLY
	a2t1 := time.Date(2025, 1, 4, 0, 0, 0, 0, time.UTC).Unix()
	stakingService.CreateStakeForTest(stakingAddress2, false, ThrylosToNano(200.0), a2t1)
	a2t2 := time.Date(2025, 1, 4, 5, 0, 0, 0, time.UTC).Unix()
	stakingService.CreateStakeForTest(stakingAddress2, false, ThrylosToNano(150.0), a2t2)

	// Simulate stakeing for address 3
	stakingAddress3 := "0x1357924680"
	// Staking 150 THRLY at midday, and unstaking 100 THRLY at 2000
	a3t1 := time.Date(2025, 1, 4, 12, 0, 0, 0, time.UTC).Unix()
	stakingService.CreateStakeForTest(stakingAddress3, false, ThrylosToNano(150.0), a3t1)
	a3t2 := time.Date(2025, 1, 4, 20, 0, 0, 0, time.UTC).Unix()
	stakingService.UnstakeTokensForTest(stakingAddress3, false, ThrylosToNano(100.0), a3t2)

	// Expected rewards

	expectedRewards := map[string]float64{
		stakingAddress1: 21816804494.67,
		stakingAddress2: 92721419102.28,
		stakingAddress3: 16968625718.07,
	}

	// Distribute rewards
	rewards := stakingService.calculateStakeReward(stakingPeriodEndTime)

	// Validate rewards
	for id, expected := range expectedRewards {
		if actual := rewards[id]; absFloat(float64(actual)-expected) > 0.1 {
			t.Errorf("Reward for %s: expected %.2f, got %.2f", id, expected, float64(actual))
		}
	}
}

func TestDeletationStakeRewardDistribution(t *testing.T) {
	// Define the reward period (from midnight to the next midnight)
	stakingPeriodStartTime := time.Date(2025, 1, 4, 0, 0, 0, 0, time.UTC).Unix()
	stakingPeriodEndTime := time.Date(2025, 1, 5, 0, 0, 0, 0, time.UTC).Unix()

	blockchain := &Blockchain{
		Stakeholders: make(map[string]int64),
	}

	stakingService := NewStakingService(blockchain)
	stakingService.pool.LastRewardTime = stakingPeriodStartTime

	// Simulate stakeing for address 1
	delegatingAddress1 := "0x1234567890"
	// Delegating 1000 THRLY at midnight
	d1t1 := time.Date(2025, 1, 4, 0, 0, 0, 0, time.UTC).Unix()
	stakingService.CreateStakeForTest(delegatingAddress1, true, ThrylosToNano(1000.0), d1t1)

	// Simulate staking for address 2
	stakingAddress2 := "0x0987654321"
	// Staking 1000 THRLY stakeing at midnight
	a2t1 := time.Date(2025, 1, 4, 0, 0, 0, 0, time.UTC).Unix()
	stakingService.CreateStakeForTest(stakingAddress2, false, ThrylosToNano(1000.0), a2t1)

	// Simulate stakeing for address 3
	stakingAddress3 := "0x1357924680"
	// Staking 1000 THRLY at midnight
	a3t1 := time.Date(2025, 1, 4, 0, 0, 0, 0, time.UTC).Unix()
	stakingService.CreateStakeForTest(stakingAddress3, false, ThrylosToNano(1000.0), a3t1)

	// Expected rewards
	// there are three addresses, one deleting and two staking
	// each has equal amount of time and equal coins.
	// Each address is expected to receive 1/3 of the reward => 1/3 * 4.8 M/365 = 4,383.5616
	// But one address is a delegator, so will receive half of the amount another half will be distributed to validators
	// delegatingAddress1 = 2,191.78
	// stakingAddress2 = 4,383.5616 + 2,191.78/2 = 5,479.4520
	// stakingAddress3 = 4,383.5616 + 2,191.78/2 = 5,479.4520

	expectedRewards := map[string]float64{
		delegatingAddress1: 21917808219.18,
		stakingAddress2:    54794520547.95,
		stakingAddress3:    54794520547.95,
	}

	// Distribute rewards
	rewards := stakingService.calculateStakeReward(stakingPeriodEndTime)
	// Validate rewards
	for id, expected := range expectedRewards {
		if actual := rewards[id]; absFloat(float64(actual)-expected) > 0.1 {
			t.Errorf("Reward for %s: expected %.2f, got %.2f", id, expected, float64(actual))
		}
	}
}

func TestEstimateStakingReward(t *testing.T) {
	// Define the reward period (from midnight to the next midnight)
	stakingPeriodStartTime := time.Date(2025, 1, 4, 0, 0, 0, 0, time.UTC).Unix()
	stakingPeriodEndTime := time.Date(2025, 1, 5, 0, 0, 0, 0, time.UTC).Unix()

	blockchain := &Blockchain{
		Stakeholders: make(map[string]int64),
	}

	stakingService := NewStakingService(blockchain)
	stakingService.pool.LastRewardTime = stakingPeriodStartTime

	// Simulate stakeing for address 1
	delegatingAddress1 := "0x1234567890"
	// Delegating 1000 THRLY at midnight
	d1t1 := time.Date(2025, 1, 4, 0, 0, 0, 0, time.UTC).Unix()
	stakingService.CreateStakeForTest(delegatingAddress1, true, ThrylosToNano(1000.0), d1t1)

	// Simulate staking for address 2
	stakingAddress2 := "0x0987654321"
	// Staking 1000 THRLY stakeing at midnight
	a2t1 := time.Date(2025, 1, 4, 0, 0, 0, 0, time.UTC).Unix()
	stakingService.CreateStakeForTest(stakingAddress2, false, ThrylosToNano(1000.0), a2t1)

	// Simulate stakeing for address 3
	stakingAddress3 := "0x1357924680"
	// Staking 1000 THRLY at midnight
	a3t1 := time.Date(2025, 1, 4, 0, 0, 0, 0, time.UTC).Unix()
	stakingService.CreateStakeForTest(stakingAddress3, false, ThrylosToNano(1000.0), a3t1)

	// Expected rewards
	// there are three addresses, one deleting and two staking
	// each has equal amount of time and equal coins.
	// Each address is expected to receive 1/3 of the reward => 1/3 * 4.8 M/365 = 4,383.5616
	// But one address is a delegator, so will receive half of the amount another half will be distributed to validators
	// delegatingAddress1 = 2,191.78
	// stakingAddress2 = 4,383.5616 + 2,191.78/2 = 5,479.4520
	// stakingAddress3 = 4,383.5616 + 2,191.78/2 = 5,479.4520

	expectedRewards := map[string]float64{
		delegatingAddress1: 21917808219.18,
		stakingAddress2:    54794520547.95,
		stakingAddress3:    54794520547.95,
	}

	for addr, expected := range expectedRewards {
		actual := stakingService.estimateStakeReward(addr, stakingPeriodEndTime)
		if absFloat(float64(actual)-expected) > 0.1 {
			t.Errorf("Reward for %s: expected %.2f, got %.2f", addr, expected, float64(actual))
		}
	}

}

// Helper function to calculate absolute difference
func absFloat(a float64) float64 {
	if a < 0 {
		return -a
	}
	return a
}
