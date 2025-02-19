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
	_, exists := bc.Blockchain.Stakeholders[block.Validator]
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
	for _, balance := range bc.Blockchain.Stakeholders {
		totalSupply += balance
	}
	return totalSupply
}

func (bc *BlockchainImpl) Stakeholders() map[string]int64 {
	bc.Blockchain.Mu.RLock()
	defer bc.Blockchain.Mu.RUnlock()

	return bc.Blockchain.Stakeholders
}

func (bc *BlockchainImpl) TransferFunds(from, to string, amount int64) error {
	bc.Blockchain.Mu.Lock()
	defer bc.Blockchain.Mu.Unlock()

	fromAddr := from
	if from == "" {
		// Get public key from genesis account
		genesisPublicKey := bc.Blockchain.GenesisAccount.PublicKey()

		// Get address from public key
		genesisAddr, err := genesisPublicKey.Address()
		if err != nil {
			return fmt.Errorf("failed to get genesis address: %v", err)
		}

		// Convert address to string representation
		fromAddr = genesisAddr.String()
	}

	// Check if the sender has enough funds
	if bc.Blockchain.Stakeholders[fromAddr] < amount {
		return fmt.Errorf("insufficient funds")
	}

	// Perform the transfer
	bc.Blockchain.Stakeholders[fromAddr] -= amount
	bc.Blockchain.Stakeholders[to] += amount

	return nil
}

func (bc *BlockchainImpl) GetStakeholders() map[string]int64 {
	bc.Blockchain.Mu.RLock()
	defer bc.Blockchain.Mu.RUnlock()
	return bc.Blockchain.Stakeholders
}
