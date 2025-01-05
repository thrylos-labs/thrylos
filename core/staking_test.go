package core

import (
	"testing"
	"time"
)

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
	stakingService.CreateStake(stakingAddress1, 100*1e7, a1t1)
	// Unstaking 50 THRLY at noon, and the remaining 50 THRLY up to the end of reward distribution
	a1t2 := time.Date(2025, 1, 4, 12, 0, 0, 0, time.UTC).Unix()
	stakingService.UnstakeTokens(stakingAddress1, 50*1e7, a1t2)

	// Simulate stakeing for address 2
	stakingAddress2 := "0x0987654321"
	// Staking 200 THRLY stakeing at midnight, and 150 THRLY at 0500 making total stake to be 350 THRLY
	a2t1 := time.Date(2025, 1, 4, 0, 0, 0, 0, time.UTC).Unix()
	stakingService.CreateStake(stakingAddress2, 200*1e7, a2t1)
	a2t2 := time.Date(2025, 1, 4, 5, 0, 0, 0, time.UTC).Unix()
	stakingService.CreateStake(stakingAddress2, 150*1e7, a2t2)

	// Simulate stakeing for address 3
	stakingAddress3 := "0x1357924680"
	// Staking 150 THRLY at midday, and unstaking 100 THRLY at 2000
	a3t1 := time.Date(2025, 1, 4, 12, 0, 0, 0, time.UTC).Unix()
	stakingService.CreateStake(stakingAddress3, 150*1e7, a3t1) // 150 THRLY was added at 1200
	a3t2 := time.Date(2025, 1, 4, 20, 0, 0, 0, time.UTC).Unix()
	stakingService.UnstakeTokens(stakingAddress3, 100*1e7, a3t2) // 100 THRLY was removed at 2000, and 50 THRLY remained

	// Expected rewards

	expectedRewards := map[string]float64{
		stakingAddress1: 21816804494.67,
		stakingAddress2: 92721419102.28,
		stakingAddress3: 16968625718.07,
	}

	// Distribute rewards
	rewards := stakingService.calculateRewardPerValidator(stakingPeriodEndTime)

	// Validate rewards
	for id, expected := range expectedRewards {
		if actual := rewards[id]; abs(float64(actual)-expected) > 0.1 {
			t.Errorf("Reward for %s: expected %.2f, got %.2f", id, expected, float64(actual))
		}
	}
}

// Helper function to calculate absolute difference
func abs(a float64) float64 {
	if a < 0 {
		return -a
	}
	return a
}
