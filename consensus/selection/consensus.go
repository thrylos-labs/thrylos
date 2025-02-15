// consensus/selection/consensus.go
package selection

// // Define interface for required blockchain methods
// type BlockchainInterface interface {
// 	GetStakeholders() map[string]int64
// 	// GetActiveValidators() []string
// }

// // Validator selector type
// type ValidatorSelector struct {
// 	blockchain BlockchainInterface
// 	mu         sync.RWMutex
// }

// func NewValidatorSelector(bc BlockchainInterface) *ValidatorSelector {
// 	return &ValidatorSelector{
// 		blockchain: bc,
// 	}
// }

// // TotalStake calculates the total stake from all stakeholders
// func (vs *ValidatorSelector) TotalStake() int64 {
// 	var total int64
// 	for _, stake := range vs.blockchain.GetStakeholders() {
// 		total += stake
// 	}
// 	return total
// }

// // SecureRandomInt generates a cryptographically secure random integer
// func SecureRandomInt(max int64) (int64, error) {
// 	nBig, err := rand.Int(rand.Reader, big.NewInt(int64(max)))
// 	if err != nil {
// 		return 0, err
// 	}
// 	return int64(nBig.Int64()), nil
// }

// // SelectValidator chooses a validator based on stake weight
// func (vs *ValidatorSelector) SelectValidator() string {
// 	vs.mu.RLock()
// 	defer vs.mu.RUnlock()

// 	activeValidators := vs.blockchain.GetActiveValidators()
// 	if len(activeValidators) == 0 {
// 		fmt.Println("No active validators available.")
// 		return ""
// 	}

// 	var totalStake int64
// 	validatorStakes := make(map[string]int64)
// 	stakeholders := vs.blockchain.GetStakeholders()

// 	for _, validator := range activeValidators {
// 		if stake, exists := stakeholders[validator]; exists {
// 			totalStake += stake
// 			validatorStakes[validator] = stake
// 		}
// 	}

// 	if totalStake == 0 {
// 		fmt.Println("No stake available among active validators.")
// 		return ""
// 	}

// 	randStake, err := SecureRandomInt(totalStake)
// 	if err != nil {
// 		fmt.Println("Failed to generate secure random number:", err)
// 		return ""
// 	}

// 	for validator, stake := range validatorStakes {
// 		randStake -= stake
// 		if randStake < 0 {
// 			return validator
// 		}
// 	}

// 	return ""
// }
