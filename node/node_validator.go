package node

import "log"

// // // IsActiveValidator checks if a given address is an active validator
func (node *Node) IsActiveValidator(address string) bool {
	node.Mu.RLock()
	defer node.Mu.RUnlock()

	// Get stake amount for the address
	stakeholders := node.GetStakeholders()
	stake, exists := stakeholders[address]
	if !exists {
		return false
	}

	// Get minimum stake requirement
	stakingStats := node.StakingService.GetPoolStats()
	minStake, ok := stakingStats["minimumStake"].(int64)
	if !ok {
		log.Printf("Warning: Could not get minimum stake requirement, using default")
		minStake = 40 // Default minimum stake in THRYLOS tokens
	}

	// Check if stake meets minimum requirement
	return stake >= minStake
}

// // GetActiveValidators returns a list of addresses for currently active validators
func (node *Node) GetActiveValidators() []string {
	node.Mu.RLock()
	defer node.Mu.RUnlock()

	// Get all staking data from the staking service
	stakingStats := node.StakingService.GetPoolStats()
	validators := make([]string, 0)

	// Extract the minimum stake requirement
	minStake, ok := stakingStats["minimumStake"].(int64)
	if !ok {
		log.Printf("Warning: Could not get minimum stake requirement, using default")
		minStake = 40 // Default minimum stake in THRYLOS tokens
	}

	// 	// Get all stakeholders
	stakeholders := node.GetStakeholders()

	// Filter for addresses that meet the minimum stake requirement
	for address, stake := range stakeholders {
		if stake >= minStake {
			validators = append(validators, address)
		}
	}

	return validators
}
