package consensus

import (
	"time"

	"github.com/thrylos-labs/thrylos/shared"
)

type ConsensusManagerImpl struct {
	*shared.ConsensusManager
}

const (
	BaseBlockTime = 5 * time.Second
	MinBlockTime  = 2 * time.Second
	MaxBlockTime  = 10 * time.Second
)

// func NewConsensusManager(blockchain BlockchainInterface) *ConsensusManagerImpl {
// 	cm := &ConsensusManagerImpl{
// 		Blockchain:       blockchain,
// 		CurrentBlockTime: BaseBlockTime,
// 		PredictionModel:  &PredictionModel{},
// 	}

// 	cm.maliciousDetector = detection.NewMaliciousDetector()
// 	return cm
// }

// func (cm *ConsensusManagerImpl) UpdateConsensusParameters() {
// 	cm.adjustBlockTime()
// 	cm.adjustValidatorSet()
// }

// func (cm *ConsensusManagerImpl) adjustBlockTime() {
// 	if cm.PredictionModel.ExpectedTransactionVolume > 5000 {
// 		cm.CurrentBlockTime = MinBlockTime
// 	} else if cm.PredictionModel.ExpectedTransactionVolume < 1000 {
// 		cm.CurrentBlockTime = MaxBlockTime
// 	} else {
// 		factor := float64(cm.PredictionModel.ExpectedTransactionVolume-1000) / 4000
// 		cm.CurrentBlockTime = time.Duration(float64(MaxBlockTime) - factor*float64(MaxBlockTime-MinBlockTime))
// 	}
// }

// func (cm *ConsensusManagerImpl) adjustValidatorSet() {
// 	activeValidators := cm.PredictionModel.ExpectedNodeCount / 10
// 	if activeValidators < 5 {
// 		activeValidators = 5
// 	} else if activeValidators > 100 {
// 		activeValidators = 100
// 	}
// 	cm.Blockchain.UpdateActiveValidators(activeValidators)
// }

// func (cm *ConsensusManagerImpl) ValidateBlock(block *thrylos.Block) bool {
// 	log.Printf("Validating block created by validator: %s", block.Validator)

// 	if !cm.verifyStake(block.Validator) {
// 		log.Printf("Stake verification failed for validator: %s", block.Validator)
// 		return false
// 	}

// 	if !cm.verifyBlockSignature(block) {
// 		log.Printf("Block signature verification failed for validator: %s", block.Validator)
// 		return false
// 	}

// 	prevBlock := cm.Blockchain.Blocks[len(cm.Blockchain.Blocks)-1]
// 	if block.Timestamp < prevBlock.Timestamp ||
// 		block.Timestamp > prevBlock.Timestamp+int64(cm.CurrentBlockTime.Seconds()*2) {
// 		log.Printf("Block timestamp validation failed for validator: %s", block.Validator)
// 		return false
// 	}

// 	if !cm.Blockchain.IsActiveValidator(block.Validator) {
// 		log.Printf("Validator %s is not in the active set", block.Validator)
// 		return false
// 	}

// 	publicKey, err := cm.Blockchain.GetValidatorPublicKey(block.Validator)
// 	if err != nil {
// 		log.Printf("Failed to get validator public key: %v", err)
// 		return false
// 	}

// 	blockData, err := chain.SerializeForSigning(&shared.Block{})
// 	if err != nil {
// 		log.Printf("Failed to serialize block for signing: %v", err)
// 		return false
// 	}

// 	if !mldsa44.Verify(publicKey, blockData, nil, block.Signature) {
// 		log.Printf("Block signature verification failed for validator: %s", block.Validator)
// 		return false
// 	}

// 	return true
// }

// func (cm *ConsensusManagerImpl) verifyStake(validator string) bool {
// 	stake, exists := cm.Blockchain.Stakeholders[validator]
// 	if !exists {
// 		return false
// 	}
// 	minStake := cm.Blockchain.GetMinStakeForValidator()
// 	return big.NewInt(stake).Cmp(minStake) >= 0
// }

// func (cm *ConsensusManagerImpl) verifyBlockSignature(block *Block) bool {
// 	mldsaPubKey, err := cm.Blockchain.RetrievePublicKey(block.Validator)
// 	if err != nil {
// 		log.Printf("Failed to retrieve public key for validator %s: %v", block.Validator, err)
// 		return false
// 	}

// 	signatureValid := mldsa44.Verify(mldsaPubKey, []byte(block.Hash), []byte{}, block.Signature)
// 	if !signatureValid {
// 		log.Printf("Signature verification failed for validator: %s", block.Validator)
// 		return false
// 	}

// 	return true
// }

// func (cm *ConsensusManagerImpl) UpdatePredictions(transactionVolume, nodeCount int) {
// 	cm.PredictionModel.ExpectedTransactionVolume = transactionVolume
// 	cm.PredictionModel.ExpectedNodeCount = nodeCount
// 	cm.UpdateConsensusParameters()
// }

// func (cm *ConsensusManagerImpl) GetCurrentBlockTime() time.Duration {
// 	return cm.CurrentBlockTime
// }

// func (cm *ConsensusManagerImpl) GetActiveValidatorCount() int {
// 	return cm.PredictionModel.ExpectedNodeCount / 10
// }
