package core

import (
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"github.com/thrylos-labs/thrylos/shared"
	"golang.org/x/crypto/ed25519"
)

// Add this to node.go
func NewTestNode(address string, knownPeers []string, dataDir string, blockchain *Blockchain) *Node {
	node := &Node{
		Address:              address,
		Peers:                make(map[string]*PeerConnection),
		Blockchain:           blockchain,
		PublicKeyMap:         make(map[string]ed25519.PublicKey),
		ResponsibleUTXOs:     make(map[string]shared.UTXO),
		WebSocketConnections: make(map[string]*WebSocketConnection),
		stakingService:       NewStakingService(blockchain),
		BlockTrigger:         make(chan struct{}, 1),
		MaxInbound:           30,
		MaxOutbound:          20,
	}

	return node
}

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

	// Create a Node with the blockchain and staking service
	node := NewTestNode("test-address", nil, tempDir, bc)
	require.NotNil(t, node, "Node should not be nil")
	require.NotNil(t, node.stakingService, "StakingService should not be nil")

	// Test initial pool configuration
	t.Run("Initial Pool Configuration", func(t *testing.T) {
		require.NotNil(t, node.stakingService, "StakingService should not be nil")
		require.NotNil(t, node.stakingService.pool, "StakingPool should not be nil")

		if node.stakingService.pool.MinStakeAmount != int64(40*1e7) {
			t.Errorf("Expected min stake amount 40 THRYLOS, got %v", float64(node.stakingService.pool.MinStakeAmount)/1e7)
		}

		if node.stakingService.pool.FixedYearlyReward != int64(4_800_000*1e7) {
			t.Errorf("Expected yearly reward 4.8M THRYLOS, got %v", float64(node.stakingService.pool.FixedYearlyReward)/1e7)
		}
	})

	// Test delegation to pool
	t.Run("Delegate to Pool", func(t *testing.T) {
		delegator := "tl11d26lhajjmg2xw95u66xathy7sge36t83zyfvwq"
		amount := int64(100 * 1e7)

		// Create initial UTXO first
		err := node.Blockchain.CreateInitialWalletUTXO(delegator, amount*2)
		require.NoError(t, err, "Failed to create initial UTXO for delegator")

		// Ensure the balance is set in Stakeholders map
		node.Blockchain.Mu.Lock()
		node.Blockchain.Stakeholders[delegator] = amount * 2
		node.Blockchain.Mu.Unlock()

		// Try delegation
		_, err = node.DelegateToPool(delegator, true, amount)
		require.NoError(t, err, "Failed to delegate to pool")

		// Verify delegation was recorded
		stake := node.stakingService.stakes[delegator]
		require.NotNil(t, stake, "Stake should not be nil")
		require.True(t, stake.IsActive, "Stake should be active")
		require.Equal(t, amount, stake.Amount, "Stake amount mismatch")
		require.Equal(t, amount, node.stakingService.pool.TotalStaked, "Total staked amount mismatch")
	})

	// Test undelegation from pool
	t.Run("Undelegate from Pool", func(t *testing.T) {
		// Reset the staking pool state before test
		node.stakingService.pool.TotalStaked = 0
		node.stakingService.stakes = make(map[string]*Stake)

		delegator := "delegator1"
		initialAmount := int64(100 * 1e7)
		undelegateAmount := int64(50 * 1e7)
		expectedRemainingStake := initialAmount - undelegateAmount

		// Create initial UTXO first
		err := node.Blockchain.CreateInitialWalletUTXO(delegator, initialAmount*2)
		require.NoError(t, err, "Failed to create initial UTXO for delegator")

		// Ensure the balance is set in Stakeholders map
		node.Blockchain.Mu.Lock()
		node.Blockchain.Stakeholders[delegator] = initialAmount * 2
		node.Blockchain.Mu.Unlock()

		t.Logf("Before delegation - Total staked: %d", node.stakingService.pool.TotalStaked)

		// Delegate first
		_, err = node.DelegateToPool(delegator, true, initialAmount)
		require.NoError(t, err, "Failed to delegate to pool")

		// Log initial stakes for debugging
		t.Logf("Stakes after delegation: %+v", node.stakingService.stakes[delegator])
		t.Logf("Initial total staked: %d", node.stakingService.pool.TotalStaked)
		t.Logf("Stakes before undelegation: %+v", node.stakingService.stakes[delegator])

		// Then undelegate
		err = node.UndelegateFromPool(delegator, true, undelegateAmount)
		require.NoError(t, err, "Failed to undelegate")

		t.Logf("Stakes after undelegation: %+v", node.stakingService.stakes[delegator])
		t.Logf("Final total staked: %d", node.stakingService.pool.TotalStaked)

		// Check stake records
		stake := node.stakingService.stakes[delegator]
		require.NotNil(t, stake, "Stake should not be nil")

		// Verify the remaining stake
		require.Equal(t, expectedRemainingStake, stake.Amount, "Incorrect remaining stake amount")
		require.Equal(t, expectedRemainingStake, node.stakingService.pool.TotalStaked, "Incorrect total staked amount")
	})

	// Test reward distribution
	t.Run("Reward Distribution", func(t *testing.T) {
		// Reset staking state before test
		node.stakingService.stakes = make(map[string]*Stake)
		node.stakingService.pool.TotalStaked = 0
		node.Blockchain.ActiveValidators = []string{} // Clear active validators

		// Set up validators
		validator1 := "validator1"
		validator2 := "validator2"
		validatorStake := int64(50 * 1e7)

		// Create initial UTXOs
		err := node.Blockchain.CreateInitialWalletUTXO(validator1, validatorStake*2)
		require.NoError(t, err, "Failed to create initial UTXO for validator1")
		err = node.Blockchain.CreateInitialWalletUTXO(validator2, validatorStake*2)
		require.NoError(t, err, "Failed to create initial UTXO for validator2")

		// Create stakes for validators with ValidatorRole set to true
		stake1 := &Stake{
			UserAddress:         validator1,
			Amount:              validatorStake,
			StartTime:           time.Now().Add(-25 * time.Hour).Unix(),
			LastStakeUpdateTime: time.Now().Add(-25 * time.Hour).Unix(),
			IsActive:            true,
			ValidatorRole:       true, // Important: this should be true for validators
		}
		stake2 := &Stake{
			UserAddress:         validator2,
			Amount:              validatorStake,
			StartTime:           time.Now().Add(-25 * time.Hour).Unix(),
			LastStakeUpdateTime: time.Now().Add(-25 * time.Hour).Unix(),
			IsActive:            true,
			ValidatorRole:       true, // Important: this should be true for validators
		}

		// Add stakes directly to avoid delegation logic
		node.stakingService.stakes[validator1] = stake1
		node.stakingService.stakes[validator2] = stake2
		node.stakingService.pool.TotalStaked = validatorStake * 2

		// Set active validators
		node.Blockchain.ActiveValidators = []string{validator1, validator2}

		// Set last reward time to 24 hours ago
		node.stakingService.pool.LastRewardTime = time.Now().Add(-25 * time.Hour).Unix()

		// Calculate rewards
		currentTime := time.Now().Unix()
		rewards := node.stakingService.calculateStakeReward(currentTime)
		require.NotNil(t, rewards, "Rewards should not be nil")
		require.Len(t, rewards, 2, "Should have rewards for both validators")

		// Verify each validator gets a reward
		for _, validator := range []string{validator1, validator2} {
			reward := rewards[validator]
			require.Greater(t, reward, float64(0), "Reward should be greater than 0")
		}

		// Distribute rewards
		err = node.stakingService.DistributeRewards()
		require.NoError(t, err, "Failed to distribute rewards")
	})

	// Test pool statistics
	t.Run("Pool Statistics", func(t *testing.T) {
		stats := node.GetStakingStats()
		require.NotNil(t, stats, "Failed to get pool stats")

		// Verify pool stats structure
		totalStaked, ok := stats["totalStaked"].(map[string]interface{})
		require.True(t, ok, "Missing totalStaked in pool stats")
		_, ok = totalStaked["thrylos"]
		require.True(t, ok, "Missing thrylos amount in totalStaked")

		// Verify reward schedule
		rewardSchedule, ok := stats["rewardSchedule"].(map[string]interface{})
		require.True(t, ok, "Missing rewardSchedule in pool stats")
		_, ok = rewardSchedule["nextRewardTime"]
		require.True(t, ok, "Missing nextRewardTime in rewardSchedule")
	})

	// Test minimum delegation amount
	t.Run("Minimum Delegation Amount", func(t *testing.T) {
		delegator := "delegator2"
		amount := int64(0.5 * 1e7) // 0.5 THRYLOS (below minimum)

		node.Blockchain.Stakeholders[delegator] = amount * 2 // Ensure enough balance

		_, err := node.DelegateToPool(delegator, true, amount)
		require.Error(t, err, "Should error for delegation below minimum amount")
	})
}
