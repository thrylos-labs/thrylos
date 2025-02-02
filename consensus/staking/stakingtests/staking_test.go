package stakingtests

// import (
// 	"os"
// 	"testing"
// 	"time"

// 	"github.com/stretchr/testify/require"
// 	"github.com/thrylos-labs/thrylos/balance"
// 	"github.com/thrylos-labs/thrylos/chain"
// 	"github.com/thrylos-labs/thrylos/consensus/staking"
// 	"github.com/thrylos-labs/thrylos/testutils"
// )

// func TestRewardDistribution(t *testing.T) {
// 	// Define the reward period (from midnight to the next midnight)
// 	stakingPeriodStartTime := time.Date(2025, 1, 4, 0, 0, 0, 0, time.UTC).Unix()
// 	stakingPeriodEndTime := time.Date(2025, 1, 5, 0, 0, 0, 0, time.UTC).Unix()

// 	blockchain := &chain.Blockchain{
// 		Stakeholders: make(map[string]int64),
// 	}

// 	stakingService := staking.NewStakingService(blockchain)
// 	stakingService.pool.LastRewardTime = stakingPeriodStartTime

// 	// Simulate stakeing for address 1
// 	stakingAddress1 := "0x1234567890"
// 	// Staking 100 THRLY at midnight
// 	a1t1 := time.Date(2025, 1, 4, 0, 0, 0, 0, time.UTC).Unix()
// 	stakingService.CreateStakeForTest(stakingAddress1, false, balance.ThrylosToNano(100.0), a1t1)
// 	// Unstaking 50 THRLY at noon, and the remaining 50 THRLY up to the end of reward distribution
// 	a1t2 := time.Date(2025, 1, 4, 12, 0, 0, 0, time.UTC).Unix()
// 	stakingService.UnstakeTokensForTest(stakingAddress1, false, balance.ThrylosToNano(50.0), a1t2)

// 	// Simulate stakeing for address 2
// 	stakingAddress2 := "0x0987654321"
// 	// Staking 200 THRLY stakeing at midnight, and 150 THRLY at 0500 making total stake to be 350 THRLY
// 	a2t1 := time.Date(2025, 1, 4, 0, 0, 0, 0, time.UTC).Unix()
// 	stakingService.CreateStakeForTest(stakingAddress2, false, balance.ThrylosToNano(200.0), a2t1)
// 	a2t2 := time.Date(2025, 1, 4, 5, 0, 0, 0, time.UTC).Unix()
// 	stakingService.CreateStakeForTest(stakingAddress2, false, balance.ThrylosToNano(150.0), a2t2)

// 	// Simulate stakeing for address 3
// 	stakingAddress3 := "0x1357924680"
// 	// Staking 150 THRLY at midday, and unstaking 100 THRLY at 2000
// 	a3t1 := time.Date(2025, 1, 4, 12, 0, 0, 0, time.UTC).Unix()
// 	stakingService.CreateStakeForTest(stakingAddress3, false, balance.ThrylosToNano(150.0), a3t1)
// 	a3t2 := time.Date(2025, 1, 4, 20, 0, 0, 0, time.UTC).Unix()
// 	stakingService.UnstakeTokensForTest(stakingAddress3, false, balance.ThrylosToNano(100.0), a3t2)

// 	// Expected rewards

// 	expectedRewards := map[string]float64{
// 		stakingAddress1: 21816804494.67,
// 		stakingAddress2: 92721419102.28,
// 		stakingAddress3: 16968625718.07,
// 	}

// 	// Distribute rewards
// 	rewards := stakingService.CalculateStakeReward(stakingPeriodEndTime)

// 	// Validate rewards
// 	for id, expected := range expectedRewards {
// 		if actual := rewards[id]; absFloat(float64(actual)-expected) > 0.1 {
// 			t.Errorf("Reward for %s: expected %.2f, got %.2f", id, expected, float64(actual))
// 		}
// 	}
// }

// func TestDeletationStakeRewardDistribution(t *testing.T) {
// 	// Define the reward period (from midnight to the next midnight)
// 	stakingPeriodStartTime := time.Date(2025, 1, 4, 0, 0, 0, 0, time.UTC).Unix()
// 	stakingPeriodEndTime := time.Date(2025, 1, 5, 0, 0, 0, 0, time.UTC).Unix()

// 	blockchain := &chain.Blockchain{
// 		Stakeholders: make(map[string]int64),
// 	}

// 	stakingService := staking.NewStakingService(blockchain)
// 	stakingService.pool.LastRewardTime = stakingPeriodStartTime

// 	// Simulate stakeing for address 1
// 	delegatingAddress1 := "0x1234567890"
// 	// Delegating 1000 THRLY at midnight
// 	d1t1 := time.Date(2025, 1, 4, 0, 0, 0, 0, time.UTC).Unix()
// 	stakingService.CreateStakeForTest(delegatingAddress1, true, balance.ThrylosToNano(1000.0), d1t1)

// 	// Simulate staking for address 2
// 	stakingAddress2 := "0x0987654321"
// 	// Staking 1000 THRLY stakeing at midnight
// 	a2t1 := time.Date(2025, 1, 4, 0, 0, 0, 0, time.UTC).Unix()
// 	stakingService.CreateStakeForTest(stakingAddress2, false, balance.ThrylosToNano(1000.0), a2t1)

// 	// Simulate stakeing for address 3
// 	stakingAddress3 := "0x1357924680"
// 	// Staking 1000 THRLY at midnight
// 	a3t1 := time.Date(2025, 1, 4, 0, 0, 0, 0, time.UTC).Unix()
// 	stakingService.CreateStakeForTest(stakingAddress3, false, balance.ThrylosToNano(1000.0), a3t1)

// 	// Expected rewards
// 	// there are three addresses, one deleting and two staking
// 	// each has equal amount of time and equal coins.
// 	// Each address is expected to receive 1/3 of the reward => 1/3 * 4.8 M/365 = 4,383.5616
// 	// But one address is a delegator, so will receive half of the amount another half will be distributed to validators
// 	// delegatingAddress1 = 2,191.78
// 	// stakingAddress2 = 4,383.5616 + 2,191.78/2 = 5,479.4520
// 	// stakingAddress3 = 4,383.5616 + 2,191.78/2 = 5,479.4520

// 	expectedRewards := map[string]float64{
// 		delegatingAddress1: 21917808219.18,
// 		stakingAddress2:    54794520547.95,
// 		stakingAddress3:    54794520547.95,
// 	}

// 	// Distribute rewards
// 	rewards := stakingService.CalculateStakeReward(stakingPeriodEndTime)
// 	// Validate rewards
// 	for id, expected := range expectedRewards {
// 		if actual := rewards[id]; absFloat(float64(actual)-expected) > 0.1 {
// 			t.Errorf("Reward for %s: expected %.2f, got %.2f", id, expected, float64(actual))
// 		}
// 	}
// }

// func TestEstimateStakingReward(t *testing.T) {
// 	// Define the reward period (from midnight to the next midnight)
// 	stakingPeriodStartTime := time.Date(2025, 1, 4, 0, 0, 0, 0, time.UTC).Unix()
// 	stakingPeriodEndTime := time.Date(2025, 1, 5, 0, 0, 0, 0, time.UTC).Unix()

// 	blockchain := &chain.Blockchain{
// 		Stakeholders: make(map[string]int64),
// 	}

// 	stakingService := staking.NewStakingService(blockchain)
// 	stakingService.pool.LastRewardTime = stakingPeriodStartTime

// 	// Simulate stakeing for address 1
// 	delegatingAddress1 := "0x1234567890"
// 	// Delegating 1000 THRLY at midnight
// 	d1t1 := time.Date(2025, 1, 4, 0, 0, 0, 0, time.UTC).Unix()
// 	stakingService.CreateStakeForTest(delegatingAddress1, true, balance.ThrylosToNano(1000.0), d1t1)

// 	// Simulate staking for address 2
// 	stakingAddress2 := "0x0987654321"
// 	// Staking 1000 THRLY stakeing at midnight
// 	a2t1 := time.Date(2025, 1, 4, 0, 0, 0, 0, time.UTC).Unix()
// 	stakingService.CreateStakeForTest(stakingAddress2, false, balance.ThrylosToNano(1000.0), a2t1)

// 	// Simulate stakeing for address 3
// 	stakingAddress3 := "0x1357924680"
// 	// Staking 1000 THRLY at midnight
// 	a3t1 := time.Date(2025, 1, 4, 0, 0, 0, 0, time.UTC).Unix()
// 	stakingService.CreateStakeForTest(stakingAddress3, false, balance.ThrylosToNano(1000.0), a3t1)

// 	// Expected rewards
// 	// there are three addresses, one deleting and two staking
// 	// each has equal amount of time and equal coins.
// 	// Each address is expected to receive 1/3 of the reward => 1/3 * 4.8 M/365 = 4,383.5616
// 	// But one address is a delegator, so will receive half of the amount another half will be distributed to validators
// 	// delegatingAddress1 = 2,191.78
// 	// stakingAddress2 = 4,383.5616 + 2,191.78/2 = 5,479.4520
// 	// stakingAddress3 = 4,383.5616 + 2,191.78/2 = 5,479.4520

// 	expectedRewards := map[string]float64{
// 		delegatingAddress1: 21917808219.18,
// 		stakingAddress2:    54794520547.95,
// 		stakingAddress3:    54794520547.95,
// 	}

// 	for addr, expected := range expectedRewards {
// 		actual := stakingService.EstimateStakeReward(addr, stakingPeriodEndTime)
// 		if absFloat(float64(actual)-expected) > 0.1 {
// 			t.Errorf("Reward for %s: expected %.2f, got %.2f", addr, expected, float64(actual))
// 		}
// 	}

// }

// // Helper function to calculate absolute difference
// func absFloat(a float64) float64 {
// 	if a < 0 {
// 		return -a
// 	}
// 	return a
// }

// // POOL TESTING

// func TestPoolStaking(t *testing.T) {
// 	// Use a predefined valid Bech32 address for genesis
// 	genesisAddress := "tl11d26lhajjmg2xw95u66xathy7sge36t83zyfvwq"

// 	tempDir, err := os.MkdirTemp("", "blockchain-test-")
// 	require.NoError(t, err, "Failed to create temp directory")
// 	defer os.RemoveAll(tempDir)

// 	// Initialize blockchain with configuration
// 	bc, _, err := chain.NewBlockchainWithConfig(&chain.BlockchainConfig{
// 		DataDir:           tempDir,
// 		AESKey:            []byte("test-key"),
// 		GenesisAccount:    genesisAddress,
// 		TestMode:          true,
// 		DisableBackground: true,
// 	})
// 	require.NoError(t, err, "Failed to create blockchain")
// 	require.NotNil(t, bc, "Blockchain should not be nil")

// 	node := testutils.NewTestNode("test-address", nil, tempDir, bc)
// 	require.NotNil(t, node)
// 	require.NotNil(t, node.StakingService) // Note: Uppercase S

// 	// Test initial pool configuration
// 	t.Run("Initial Pool Configuration", func(t *testing.T) {
// 		require.NotNil(t, node.StakingService, "StakingService should not be nil")
// 		pool := node.StakingService.GetPool()
// 		require.NotNil(t, pool, "StakingPool should not be nil")

// 		if pool.MinStakeAmount != int64(40*1e7) {
// 			t.Errorf("Expected min stake amount 40 THRYLOS, got %v", float64(pool.MinStakeAmount)/1e7)
// 		}

// 		if pool.FixedYearlyReward != int64(4_800_000*1e7) {
// 			t.Errorf("Expected yearly reward 4.8M THRYLOS, got %v", float64(pool.FixedYearlyReward)/1e7)
// 		}
// 	})

// 	// Test delegation to pool
// 	// In pool_test.go, modify the "Delegate to Pool" test case:
// 	// Example test update
// 	t.Run("Delegate to Pool", func(t *testing.T) {
// 		delegator := "tl11d26lhajjmg2xw95u66xathy7sge36t83zyfvwq"
// 		amount := int64(100 * 1e7)

// 		// Create stake without specifying isDelegator
// 		stake, err := node.StakingService.CreateStake(delegator, amount)
// 		require.NoError(t, err, "Failed to create stake")
// 		require.NotNil(t, stake, "Stake should not be nil")

// 		// Verify stake was created with correct validator status
// 		require.Equal(t, amount, stake.Amount, "Stake amount mismatch")
// 		require.Equal(t, delegator, stake.UserAddress, "Stake address mismatch")
// 		require.True(t, stake.IsActive, "Stake should be active")

// 		// Check if validator status was correctly determined
// 		expectedValidatorStatus := node.StakingService.IsValidator(delegator)
// 		require.Equal(t, expectedValidatorStatus, stake.ValidatorRole,
// 			"Validator role mismatch")
// 	})

// 	// Test undelegation from pool
// 	// Modify the "Undelegate from Pool" test case
// 	t.Run("Undelegate from Pool", func(t *testing.T) {
// 		// Reset pool state
// 		node.StakingService.SetPoolValues(0, 0)

// 		delegator := "delegator1"
// 		initialAmount := int64(100 * 1e7)
// 		undelegateAmount := int64(50 * 1e7)
// 		expectedRemainingStake := initialAmount - undelegateAmount

// 		// Create initial UTXO
// 		err := node.Blockchain.CreateInitialWalletUTXO(delegator, initialAmount*2)
// 		require.NoError(t, err, "Failed to create initial UTXO for delegator")

// 		// Set stakeholder balance
// 		node.Blockchain.Stakeholders[delegator] = initialAmount * 2

// 		t.Logf("Before delegation - Total delegated: %d", node.StakingService.GetTotalDelegated())

// 		// Create delegation
// 		stake, err := node.StakingService.CreateStake(delegator, initialAmount)
// 		require.NoError(t, err, "Failed to create stake")

// 		// Verify delegation
// 		require.False(t, stake.ValidatorRole, "Should be marked as delegator")
// 		require.Equal(t, initialAmount, stake.Amount, "Stake amount mismatch")
// 		require.Equal(t, initialAmount, node.StakingService.GetTotalDelegated(),
// 			"Initial delegation amount mismatch")

// 		// Undelegate
// 		err = node.StakingService.UnstakeTokens(delegator, undelegateAmount)
// 		require.NoError(t, err, "Failed to undelegate")

// 		// Verify final amounts
// 		require.Equal(t, expectedRemainingStake, stake.Amount,
// 			"Incorrect remaining stake amount")
// 		require.Equal(t, expectedRemainingStake, node.StakingService.GetTotalDelegated(),
// 			"Incorrect total delegated amount")
// 	})

// 	// Test reward distribution
// 	t.Run("Reward Distribution", func(t *testing.T) {
// 		// Reset state
// 		node.StakingService.SetPoolValues(0, 0)
// 		node.Blockchain.ActiveValidators = []string{}

// 		validator1 := "validator1"
// 		validator2 := "validator2"
// 		validatorStake := int64(50 * 1e7)

// 		// Create UTXOs
// 		err := node.Blockchain.CreateInitialWalletUTXO(validator1, validatorStake*2)
// 		require.NoError(t, err)
// 		err = node.Blockchain.CreateInitialWalletUTXO(validator2, validatorStake*2)
// 		require.NoError(t, err)

// 		// Create validator stakes
// 		timeStart := time.Now().Add(-25 * time.Hour).Unix()
// 		stake1, err := node.StakingService.CreateStake(validator1, validatorStake)
// 		require.NoError(t, err)
// 		stake2, err := node.StakingService.CreateStake(validator2, validatorStake)
// 		require.NoError(t, err)

// 		// Set active validators
// 		node.Blockchain.ActiveValidators = []string{validator1, validator2}

// 		// Set last reward time
// 		node.StakingService.SetLastRewardTime(timeStart)

// 		// Calculate rewards
// 		currentTime := time.Now().Unix()
// 		rewards := node.StakingService.CalculateStakeReward(currentTime)
// 		require.NotNil(t, rewards)
// 		require.Len(t, rewards, 2)

// 		// Verify validator rewards
// 		for _, validator := range []string{validator1, validator2} {
// 			reward := rewards[validator]
// 			require.Greater(t, reward, float64(0))
// 		}

// 		// Distribute rewards
// 		err = node.StakingService.DistributeRewards()
// 		require.NoError(t, err)
// 	})

// 	// Test pool statistics
// 	t.Run("Pool Statistics", func(t *testing.T) {
// 		stats := node.GetStakingStats()
// 		require.NotNil(t, stats, "Failed to get pool stats")

// 		// Verify pool stats structure
// 		totalStaked, ok := stats["totalStaked"].(map[string]interface{})
// 		require.True(t, ok, "Missing totalStaked in pool stats")
// 		_, ok = totalStaked["thrylos"]
// 		require.True(t, ok, "Missing thrylos amount in totalStaked")

// 		// Verify reward schedule
// 		rewardSchedule, ok := stats["rewardSchedule"].(map[string]interface{})
// 		require.True(t, ok, "Missing rewardSchedule in pool stats")
// 		_, ok = rewardSchedule["nextRewardTime"]
// 		require.True(t, ok, "Missing nextRewardTime in rewardSchedule")
// 	})

// 	// Test minimum delegation amount
// 	t.Run("Minimum Delegation Amount", func(t *testing.T) {
// 		delegator := "delegator2"
// 		amount := int64(0.5 * 1e7) // 0.5 THRYLOS (below minimum)

// 		node.Blockchain.Stakeholders[delegator] = amount * 2 // Ensure enough balance

// 		// Removed isDelegator parameter
// 		_, err := node.DelegateToPool(delegator, amount)
// 		require.Error(t, err, "Should error for delegation below minimum amount")
// 		require.Contains(t, err.Error(), "minimum amount required",
// 			"Error should mention minimum amount requirement")
// 	})
// }
