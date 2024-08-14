package core

import (
	"math/big"
	"time"

	"golang.org/x/crypto/ed25519"
)

const (
	BaseBlockTime = 5 * time.Second
	MinBlockTime  = 2 * time.Second
	MaxBlockTime  = 10 * time.Second
)

type ConsensusManager struct {
	Blockchain       *Blockchain
	CurrentBlockTime time.Duration
	PredictionModel  *PredictionModel
}

type PredictionModel struct {
	ExpectedTransactionVolume int
	ExpectedNodeCount         int
}

func NewConsensusManager(blockchain *Blockchain) *ConsensusManager {
	return &ConsensusManager{
		Blockchain:       blockchain,
		CurrentBlockTime: BaseBlockTime,
		PredictionModel:  &PredictionModel{},
	}
}

func (cm *ConsensusManager) UpdateConsensusParameters() {
	cm.adjustBlockTime()
	cm.adjustValidatorSet()
}

func (cm *ConsensusManager) adjustBlockTime() {
	if cm.PredictionModel.ExpectedTransactionVolume > 5000 {
		cm.CurrentBlockTime = MinBlockTime
	} else if cm.PredictionModel.ExpectedTransactionVolume < 1000 {
		cm.CurrentBlockTime = MaxBlockTime
	} else {
		factor := float64(cm.PredictionModel.ExpectedTransactionVolume-1000) / 4000
		cm.CurrentBlockTime = time.Duration(float64(MaxBlockTime) - factor*float64(MaxBlockTime-MinBlockTime))
	}
}

func (cm *ConsensusManager) adjustValidatorSet() {
	activeValidators := cm.PredictionModel.ExpectedNodeCount / 10
	if activeValidators < 5 {
		activeValidators = 5
	} else if activeValidators > 100 {
		activeValidators = 100
	}
	cm.Blockchain.UpdateActiveValidators(activeValidators)
}

func (cm *ConsensusManager) ValidateBlock(block *Block) bool {
	if !cm.verifyStake(block.Validator) {
		return false
	}

	if !cm.verifyBlockSignature(block) {
		return false
	}

	prevBlock := cm.Blockchain.Blocks[len(cm.Blockchain.Blocks)-1]
	if block.Timestamp < prevBlock.Timestamp ||
		block.Timestamp > prevBlock.Timestamp+int64(cm.CurrentBlockTime.Seconds()*2) {
		return false
	}

	if !cm.Blockchain.IsActiveValidator(block.Validator) {
		return false
	}

	return true
}

func (cm *ConsensusManager) verifyStake(validator string) bool {
	stake, exists := cm.Blockchain.Stakeholders[validator]
	if !exists {
		return false
	}
	minStake := cm.Blockchain.GetMinStakeForValidator()
	return big.NewInt(stake).Cmp(minStake) >= 0
}

func (cm *ConsensusManager) verifyBlockSignature(block *Block) bool {
	pubKey, err := cm.Blockchain.RetrievePublicKey(block.Validator)
	if err != nil {
		return false
	}
	return ed25519.Verify(pubKey, []byte(block.Hash), block.Signature)
}

func (cm *ConsensusManager) UpdatePredictions(transactionVolume, nodeCount int) {
	cm.PredictionModel.ExpectedTransactionVolume = transactionVolume
	cm.PredictionModel.ExpectedNodeCount = nodeCount
	cm.UpdateConsensusParameters()
}

func (cm *ConsensusManager) GetCurrentBlockTime() time.Duration {
	return cm.CurrentBlockTime
}

func (cm *ConsensusManager) GetActiveValidatorCount() int {
	return cm.PredictionModel.ExpectedNodeCount / 10
}
