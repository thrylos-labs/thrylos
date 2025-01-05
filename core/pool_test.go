package core

import (
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func abs(n int64) int64 {
	if n < 0 {
		return -n
	}
	return n
}

func TestPoolStaking(t *testing.T) {
	// Use a predefined valid Bech32 address for genesis
	genesisAddress := "tl11d26lhajjmg2xw95u66xathy7sge36t83zyfvwq"

	tempDir, err := os.MkdirTemp("", "blockchain-test-")
	require.NoError(t, err, "Failed to create temp directory")
	defer os.RemoveAll(tempDir)

	// Initialize blockchain with configuration
	bc, _, err := NewBlockchainWithConfig(&BlockchainConfig{
		DataDir:           tempDir,
		AESKey:            []byte("test-key"),
		GenesisAccount:    genesisAddress,
		TestMode:          true,
		DisableBackground: true,
	})
	require.NoError(t, err, "Failed to create blockchain")
	require.NotNil(t, bc, "Blockchain should not be nil")

	// Test initial pool configuration
	t.Run("Initial Pool Configuration", func(t *testing.T) {
		require.NotNil(t, bc.StakingService, "StakingService should not be nil")
		require.NotNil(t, bc.StakingService.pool, "StakingPool should not be nil")

		if bc.StakingService.pool.MinStakeAmount != int64(40*1e7) {
			t.Errorf("Expected min stake amount 40 THRYLOS, got %v", float64(bc.StakingService.pool.MinStakeAmount)/1e7)
		}

		if bc.StakingService.pool.FixedYearlyReward != int64(4_800_000*1e7) {
			t.Errorf("Expected yearly reward 4.8M THRYLOS, got %v", float64(bc.StakingService.pool.FixedYearlyReward)/1e7)
		}
	})

	// Test delegation to pool
	t.Run("Delegate to Pool", func(t *testing.T) {
		delegator := "tl11d26lhajjmg2xw95u66xathy7sge36t83zyfvwq"
		amount := int64(100 * 1e7)

		// Create initial UTXO first
		err := bc.CreateInitialWalletUTXO(delegator, amount*2)
		require.NoError(t, err, "Failed to create initial UTXO for delegator")

		// Ensure the balance is set in Stakeholders map
		bc.Mu.Lock()
		bc.Stakeholders[delegator] = amount * 2
		bc.Mu.Unlock()

		// Try delegation
		err = bc.DelegateToPool(delegator, amount)
		require.NoError(t, err, "Failed to delegate to pool")

		// Verify delegation was recorded
		bc.Mu.RLock()
		stakes := bc.StakingService.stakes[delegator]
		bc.Mu.RUnlock()

		require.Greater(t, len(stakes), 0, "No stake record created")

		stake := stakes[0]
		require.True(t, stake.IsActive, "Stake should be active")
		require.Equal(t, amount, stake.Amount, "Stake amount mismatch")
		require.Equal(t, amount, bc.StakingService.pool.TotalStaked, "Total staked amount mismatch")
	})

	// Test undelegation from pool
	t.Run("Undelegate from Pool", func(t *testing.T) {
		// Reset the staking pool state before test
		bc.StakingService.pool.TotalStaked = 0
		bc.StakingService.stakes = make(map[string][]*Stake)

		delegator := "delegator1"
		initialAmount := int64(100 * 1e7)
		undelegateAmount := int64(50 * 1e7)
		expectedRemainingStake := initialAmount - undelegateAmount

		// Create initial UTXO first
		err := bc.CreateInitialWalletUTXO(delegator, initialAmount*2)
		require.NoError(t, err, "Failed to create initial UTXO for delegator")

		// Ensure the balance is set in Stakeholders map
		bc.Mu.Lock()
		bc.Stakeholders[delegator] = initialAmount * 2
		bc.Mu.Unlock()

		t.Logf("Before delegation - Total staked: %d", bc.StakingService.pool.TotalStaked)

		// First delegate
		err = bc.DelegateToPool(delegator, initialAmount)
		require.NoError(t, err, "Failed to delegate initial amount")

		// Log initial stakes for debugging
		t.Logf("Stakes after delegation: %+v", bc.StakingService.stakes[delegator])
		t.Logf("Initial total staked: %d", bc.StakingService.pool.TotalStaked)
		t.Logf("Stakes before undelegation: %+v", bc.StakingService.stakes[delegator])

		err = bc.UndelegateFromPool(delegator, undelegateAmount)
		require.NoError(t, err, "Failed to undelegate")

		t.Logf("Stakes after undelegation: %+v", bc.StakingService.stakes[delegator])
		t.Logf("Final total staked: %d", bc.StakingService.pool.TotalStaked)

		// Check stake records
		bc.Mu.RLock()
		stakes := bc.StakingService.stakes[delegator]
		bc.Mu.RUnlock()

		// Look for stake with remaining amount
		var foundStake *Stake
		for _, stake := range stakes {
			if stake.IsActive && !stake.ValidatorRole {
				foundStake = stake
				break
			}
		}

		// Verify the remaining stake
		if foundStake == nil {
			t.Error("No active delegation stake found")
		} else if foundStake.Amount != expectedRemainingStake {
			t.Errorf("Incorrect remaining stake amount. Expected: %d, Got: %d",
				expectedRemainingStake, foundStake.Amount)
		}

		// Verify total staked amount in pool
		if bc.StakingService.pool.TotalStaked != expectedRemainingStake {
			t.Errorf("Incorrect total staked amount. Expected: %d, Got: %d",
				expectedRemainingStake, bc.StakingService.pool.TotalStaked)
		}
	})

	// Test reward distribution
	t.Run("Reward Distribution", func(t *testing.T) {
		// Set up validators
		validator1 := "validator1"
		validator2 := "validator2"
		validatorStake := int64(50 * 1e7)

		bc.Stakeholders[validator1] = validatorStake
		bc.Stakeholders[validator2] = validatorStake
		bc.ActiveValidators = []string{validator1, validator2}

		// Set last reward time to 24 hours ago
		bc.StakingService.pool.LastRewardTime = time.Now().Add(-25 * time.Hour).Unix()

		// Distribute rewards
		err := bc.StakingService.DistributeRewards()
		if err != nil {
			t.Errorf("Failed to distribute rewards: %v", err)
		}

		// Verify reward distribution
		dailyReward := bc.StakingService.calculateDailyReward()
		if dailyReward <= 0 {
			t.Error("Daily reward should be greater than 0")
		}

		rewardPerValidator := bc.StakingService.calculateRewardPerValidator()
		expectedReward := dailyReward / int64(len(bc.ActiveValidators))
		if rewardPerValidator != expectedReward {
			t.Errorf("Expected reward per validator %v, got %v", expectedReward, rewardPerValidator)
		}
	})

	// Test pool statistics
	t.Run("Pool Statistics", func(t *testing.T) {
		stats := bc.GetPoolStats()
		if stats == nil {
			t.Fatal("Failed to get pool stats")
		}

		// Verify pool stats structure
		totalStaked, ok := stats["totalStaked"].(map[string]interface{})
		if !ok {
			t.Error("Missing totalStaked in pool stats")
		} else {
			if _, ok := totalStaked["thrylos"]; !ok {
				t.Error("Missing thrylos amount in totalStaked")
			}
		}

		// Verify reward schedule
		rewardSchedule, ok := stats["rewardSchedule"].(map[string]interface{})
		if !ok {
			t.Error("Missing rewardSchedule in pool stats")
		} else {
			if _, ok := rewardSchedule["nextRewardTime"]; !ok {
				t.Error("Missing nextRewardTime in rewardSchedule")
			}
		}
	})

	// Test minimum delegation amount
	t.Run("Minimum Delegation Amount", func(t *testing.T) {
		delegator := "delegator2"
		amount := int64(0.5 * 1e7) // 0.5 THRYLOS (below minimum)

		bc.Stakeholders[delegator] = amount * 2 // Ensure enough balance

		err := bc.DelegateToPool(delegator, amount)
		if err == nil {
			t.Error("Expected error for delegation below minimum amount")
		}
	})

	// Test reward calculation
	t.Run("Reward Calculation", func(t *testing.T) {
		dailyReward := bc.StakingService.calculateDailyReward()
		yearlyReward := dailyReward * 365

		tolerance := int64(100) // Allow for small rounding differences
		difference := abs(yearlyReward - bc.StakingService.pool.FixedYearlyReward)

		if difference > tolerance {
			t.Errorf("Daily reward calculation incorrect. Expected yearly total %v, got %v",
				bc.StakingService.pool.FixedYearlyReward, yearlyReward)
		}
	})
}
