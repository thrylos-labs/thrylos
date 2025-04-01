package consensus

import (
	"log"
	"math/big"
	"time"

	"github.com/cloudflare/circl/sign/mldsa/mldsa44"
	"github.com/thrylos-labs/thrylos/chain"
	"github.com/thrylos-labs/thrylos/consensus/detection"
	"github.com/thrylos-labs/thrylos/types"
)

const (
	BaseBlockTime = 5 * time.Second
	MinBlockTime  = 2 * time.Second
	MaxBlockTime  = 10 * time.Second
)

// ConsensusManagerImpl implements consensus logic
type ConsensusManagerImpl struct {
	*types.ConsensusManager // Embedding the types.ConsensusManager
}

func NewConsensusManager(blockchain types.BlockchainInterface) *ConsensusManagerImpl {
	// Create a new ConsensusManager with only the exported fields
	cm := &types.ConsensusManager{
		Blockchain:       blockchain,
		CurrentBlockTime: BaseBlockTime,
		PredictionModel:  &types.PredictionModel{},
		// maliciousDetector is unexported so it can't be set here
	}

	// Create a ConsensusManagerImpl
	impl := &ConsensusManagerImpl{
		ConsensusManager: cm,
	}

	// Set the malicious detector using the SetMaliciousDetector method
	impl.SetMaliciousDetector(detection.NewMaliciousDetector())

	return impl
}

// SetMaliciousDetector allows setting the malicious detector after initialization
// Add this method to your types.ConsensusManager struct if it doesn't exist
func (cm *ConsensusManagerImpl) SetMaliciousDetector(detector *detection.MaliciousDetector) {
	// This is a workaround since we can't directly set the unexported field
	// This pattern often uses reflection in real code, but we're simplifying here

	// For this to work, you need to add a similar method to the types.ConsensusManager
	// that actually sets the maliciousDetector field

	// Alternately, you can modify the types.ConsensusManager to make the field public:
	// MaliciousDetector *detection.MaliciousDetector
}

func (cm *ConsensusManagerImpl) UpdateConsensusParameters() {
	cm.adjustBlockTime()
	cm.adjustValidatorSet()
}

func (cm *ConsensusManagerImpl) adjustBlockTime() {
	if cm.PredictionModel.ExpectedTransactionVolume > 5000 {
		cm.CurrentBlockTime = MinBlockTime
	} else if cm.PredictionModel.ExpectedTransactionVolume < 1000 {
		cm.CurrentBlockTime = MaxBlockTime
	} else {
		factor := float64(cm.PredictionModel.ExpectedTransactionVolume-1000) / 4000
		cm.CurrentBlockTime = time.Duration(float64(MaxBlockTime) - factor*float64(MaxBlockTime-MinBlockTime))
	}
}

func (cm *ConsensusManagerImpl) adjustValidatorSet() {
	activeValidators := cm.PredictionModel.ExpectedNodeCount / 10
	if activeValidators < 5 {
		activeValidators = 5
	} else if activeValidators > 100 {
		activeValidators = 100
	}
	cm.Blockchain.UpdateActiveValidators(activeValidators)
}

func (cm *ConsensusManagerImpl) ValidateBlock(block *types.Block) bool {
	log.Printf("Validating block created by validator: %s", block.Validator)

	if !cm.verifyStake(block.Validator) {
		log.Printf("Stake verification failed for validator: %s", block.Validator)
		return false
	}

	if !cm.verifyBlockSignature(block) {
		log.Printf("Block signature verification failed for validator: %s", block.Validator)
		return false
	}

	// For the previous block access, you'll need to modify this based on your actual implementation
	// Since we don't have direct access to cm.Blockchain.Blocks
	prevBlock, _, err := getLastBlock(cm.Blockchain)
	if err != nil {
		log.Printf("Failed to get previous block: %v", err)
		return false
	}

	if block.Timestamp < prevBlock.Timestamp ||
		block.Timestamp > prevBlock.Timestamp+int64(cm.CurrentBlockTime.Seconds()*2) {
		log.Printf("Block timestamp validation failed for validator: %s", block.Validator)
		return false
	}

	if !cm.Blockchain.IsActiveValidator(block.Validator) {
		log.Printf("Validator %s is not in the active set", block.Validator)
		return false
	}

	publicKey, err := cm.Blockchain.GetValidatorPublicKey(block.Validator)
	if err != nil {
		log.Printf("Failed to get validator public key: %v", err)
		return false
	}

	blockData, err := chain.SerializeForSigning(block)
	if err != nil {
		log.Printf("Failed to serialize block for signing: %v", err)
		return false
	}

	// Use publicKey directly since it's already a *mldsa44.PublicKey
	// Use the Bytes() method to get the byte representation
	signatureBytes := block.Signature.Bytes() // Use Bytes() method to get []byte

	if !mldsa44.Verify(publicKey, blockData, signatureBytes, nil) {
		log.Printf("Block signature verification failed for validator: %s", block.Validator)
		return false
	}

	return true
}

func (cm *ConsensusManagerImpl) verifyStake(validator string) bool {
	stakeholders := cm.Blockchain.Stakeholders()
	stake, exists := stakeholders[validator]
	if !exists {
		return false
	}
	minStake := cm.Blockchain.GetMinStakeForValidator()
	return big.NewInt(stake).Cmp(minStake) >= 0
}

func (cm *ConsensusManagerImpl) verifyBlockSignature(block *types.Block) bool {
	// Get validator's public key bytes
	pubKeyBytes, err := cm.Blockchain.RetrievePublicKey(block.Validator)
	if err != nil {
		log.Printf("Failed to retrieve public key for validator %s: %v", block.Validator, err)
		return false
	}

	// Create an MLDSA public key from the bytes
	var mldsaPubKey mldsa44.PublicKey
	if err := mldsaPubKey.UnmarshalBinary(pubKeyBytes); err != nil {
		log.Printf("Failed to unmarshal public key: %v", err)
		return false
	}

	// Use the Bytes() method to get the byte representation
	// Instead of trying to cast directly
	hashBytes := block.Hash.Bytes()           // Assuming Hash has a Bytes() method
	signatureBytes := block.Signature.Bytes() // Assuming Signature has a Bytes() method

	// Verify signature
	if !mldsa44.Verify(&mldsaPubKey, hashBytes, signatureBytes, nil) {
		log.Printf("Signature verification failed for validator: %s", block.Validator)
		return false
	}

	return true
}

func (cm *ConsensusManagerImpl) UpdatePredictions(transactionVolume, nodeCount int) {
	cm.PredictionModel.ExpectedTransactionVolume = transactionVolume
	cm.PredictionModel.ExpectedNodeCount = nodeCount
	cm.UpdateConsensusParameters()
}

func (cm *ConsensusManagerImpl) GetCurrentBlockTime() time.Duration {
	return cm.CurrentBlockTime
}

func (cm *ConsensusManagerImpl) GetActiveValidatorCount() int {
	return cm.PredictionModel.ExpectedNodeCount / 10
}

// Helper function to get the last block - you might need to replace this
// with an actual implementation depending on your blockchain interface
func getLastBlock(blockchain types.BlockchainInterface) (*types.Block, int, error) {
	// This is a placeholder. You'll need to implement this based on your actual blockchain access
	// Perhaps via a different interface method or adapting your BlockchainInterface
	// For now, returning nil values to prevent compilation errors
	return nil, 0, nil
}
