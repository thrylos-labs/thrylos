package chain

import (
	"fmt"

	"github.com/thrylos-labs/thrylos/config"
	"github.com/thrylos-labs/thrylos/types"
	"github.com/thrylos-labs/thrylos/utils"
)

// // VerifyPoSRules verifies the PoS rules for the given block
func (bc *BlockchainImpl) VerifyPoSRules(block types.Block) bool {
	// Check if the validator had a stake at the time of block creation
	_, exists := bc.ShardState.Stakeholders[block.Validator]
	return exists
}

func (bc *BlockchainImpl) GetEffectiveInflationRate() float64 {
	currentTotalSupply := utils.NanoToThrylos(bc.GetTotalSupply())
	// Calculate effective rate (will decrease as total supply grows)
	effectiveRate := (utils.NanoToThrylos(config.AnnualStakeReward) / currentTotalSupply) * 100
	return effectiveRate
}

func contains(slice []string, item string) bool {
	for _, a := range slice {
		if a == item {
			return true
		}
	}
	return false
}

// // // // FIXME: The total supply is not correct, it needs to be improved
func (bc *BlockchainImpl) GetTotalSupply() int64 {
	totalSupply := int64(0)
	for _, balance := range bc.ShardState.Stakeholders {
		totalSupply += balance
	}
	return totalSupply
}

func (bc *BlockchainImpl) Stakeholders() map[string]int64 {
	bc.ShardState.Mu.RLock()
	defer bc.ShardState.Mu.RUnlock()

	return bc.ShardState.Stakeholders
}

func (bc *BlockchainImpl) TransferFunds(from, to string, amount int64) error {
	bc.ShardState.Mu.Lock()
	defer bc.ShardState.Mu.Unlock()

	fromAddr := from
	if from == "" {
		// Get public key from genesis account
		genesisPublicKey := bc.ShardState.GenesisAccount.PublicKey()

		// Get address from public key
		genesisAddr, err := genesisPublicKey.Address()
		if err != nil {
			return fmt.Errorf("failed to get genesis address: %v", err)
		}

		// Convert address to string representation
		fromAddr = genesisAddr.String()
	}

	// Check if the sender has enough funds
	if bc.ShardState.Stakeholders[fromAddr] < amount {
		return fmt.Errorf("insufficient funds")
	}

	// Perform the transfer
	bc.ShardState.Stakeholders[fromAddr] -= amount
	bc.ShardState.Stakeholders[to] += amount

	return nil
}

func (bc *BlockchainImpl) GetStakeholders() map[string]int64 {
	bc.ShardState.Mu.RLock()
	defer bc.ShardState.Mu.RUnlock()
	return bc.ShardState.Stakeholders
}
