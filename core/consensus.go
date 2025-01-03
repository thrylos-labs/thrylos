package core

import (
	"crypto/rand"
	"fmt"
	"math/big"
)

// TotalStake calculates the total stake from all stakeholders
func (bc *Blockchain) TotalStake() int64 {
	var total int64
	for _, stake := range bc.Stakeholders {
		total += stake
	}
	return total
}

// SecureRandomInt generates a cryptographically secure random integer
func SecureRandomInt(max int64) (int64, error) {
	nBig, err := rand.Int(rand.Reader, big.NewInt(int64(max)))
	if err != nil {
		return 0, err
	}
	return int64(nBig.Int64()), nil
}

// SelectValidator chooses a validator based on stake weight
func (bc *Blockchain) SelectValidator() string {
	bc.Mu.RLock()
	defer bc.Mu.RUnlock()

	if len(bc.ActiveValidators) == 0 {
		fmt.Println("No active validators available.")
		return ""
	}

	var totalStake int64
	validatorStakes := make(map[string]int64)

	for _, validator := range bc.ActiveValidators {
		stake := bc.Stakeholders[validator]
		totalStake += stake
		validatorStakes[validator] = stake
	}

	if totalStake == 0 {
		fmt.Println("No stake available among active validators.")
		return ""
	}

	randStake, err := SecureRandomInt(totalStake)
	if err != nil {
		fmt.Println("Failed to generate secure random number:", err)
		return ""
	}

	for validator, stake := range validatorStakes {
		randStake -= stake
		if randStake < 0 {
			return validator
		}
	}

	return ""
}
