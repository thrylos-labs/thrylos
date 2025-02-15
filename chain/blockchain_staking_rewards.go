package chain

// // VerifyPoSRules verifies the PoS rules for the given block
// func (bc *BlockchainImpl) VerifyPoSRules(block types.Block) bool {
// 	// Check if the validator had a stake at the time of block creation
// 	_, exists := bc.Stakeholders[block.Validator]
// 	return exists
// }

// func (bc *BlockchainImpl) GetEffectiveInflationRate() float64 {
// 	currentTotalSupply := utils.NanoToThrylos(bc.GetTotalSupply())
// 	// Calculate effective rate (will decrease as total supply grows)
// 	effectiveRate := (utils.NanoToThrylos(config.AnnualStakeReward) / currentTotalSupply) * 100
// 	return effectiveRate
// }

// func contains(slice []string, item string) bool {
// 	for _, a := range slice {
// 		if a == item {
// 			return true
// 		}
// 	}
// 	return false
// }

// // // // // FIXME: The total supply is not correct, it needs to be improved
// func (bc *BlockchainImpl) GetTotalSupply() int64 {
// 	totalSupply := int64(0)
// 	for _, balance := range bc.Stakeholders {
// 		totalSupply += balance
// 	}
// 	return totalSupply
// }

// func (bc *BlockchainImpl) TransferFunds(from, to string, amount int64) error {
// 	bc.Mu.Lock()
// 	defer bc.Mu.Unlock()

// 	if from == "" {
// 		from = bc.GenesisAccount // Default to the genesis account if 'from' is not specified
// 	}

// 	// Check if the sender has enough funds
// 	if bc.Stakeholders[from] < amount {
// 		return fmt.Errorf("insufficient funds")
// 	}

// 	// Perform the transfer
// 	bc.Stakeholders[from] -= amount
// 	bc.Stakeholders[to] += amount

// 	return nil
// }

// func (bc *BlockchainImpl) GetStakeholders() map[string]int64 {
// 	bc.Mu.RLock()
// 	defer bc.Mu.RUnlock()
// 	return bc.Stakeholders
// }
