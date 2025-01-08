package core

import (
	"bytes"
	"fmt"
	"log"
	"math/big"
	"time"

	"github.com/cloudflare/circl/sign/mldsa/mldsa44"
)

const (
	BaseBlockTime = 5 * time.Second
	MinBlockTime  = 2 * time.Second
	MaxBlockTime  = 10 * time.Second
)

type ConsensusManager struct {
	Blockchain        *Blockchain
	CurrentBlockTime  time.Duration
	PredictionModel   *PredictionModel
	maliciousDetector *MaliciousDetector
}

type PredictionModel struct {
	ExpectedTransactionVolume int
	ExpectedNodeCount         int
}

type ValidatorBehavior struct {
	DoubleSignings    int
	MissedBlocks      int
	InvalidBlocks     int
	LastActiveBlock   int32
	ConsecutiveMisses int
}

type MaliciousDetector struct {
	behaviors        map[string]*ValidatorBehavior
	consensusManager *ConsensusManager
	signatures       map[string][]byte // Add this field
	thresholds       struct {
		doubleSignings    int
		missedBlocks      int
		invalidBlocks     int
		consecutiveMisses int
	}
}

func (cm *ConsensusManager) DetectMaliciousActivity(block *Block) {
	detector := cm.maliciousDetector
	totalStake := cm.Blockchain.GetTotalSupply()

	// Double signing detection
	if detector.checkDoubleSigningAtHeight(block.Index, block.Validator, block.Signature) {
		cm.Blockchain.SlashMaliciousValidator(block.Validator, calculateSlashAmount("double_signing", totalStake))
	}

	// Invalid block proposal
	if !cm.ValidateBlock(block) {
		detector.behaviors[block.Validator].InvalidBlocks++
		if detector.behaviors[block.Validator].InvalidBlocks >= detector.thresholds.invalidBlocks {
			cm.Blockchain.SlashMaliciousValidator(block.Validator, calculateSlashAmount("invalid_blocks", totalStake))
		}
	}

	// Missed blocks tracking
	detector.updateMissedBlocks(block)
}

func (md *MaliciousDetector) checkDoubleSigningAtHeight(height int32, validator string, signature []byte) bool {
	// Store signatures per height and validator
	key := fmt.Sprintf("%d:%s", height, validator)
	previousSignature := md.signatures[key]
	if previousSignature != nil && !bytes.Equal(previousSignature, signature) {
		return true
	}
	md.signatures[key] = signature
	return false
}

func calculateSlashAmount(violation string, totalStake int64) int64 {
	slashAmounts := map[string]float64{
		"double_signing": 0.05,
		"invalid_blocks": 0.02,
		"missed_blocks":  0.01,
	}
	return int64(slashAmounts[violation] * float64(totalStake))
}

func NewConsensusManager(blockchain *Blockchain) *ConsensusManager {
	md := &MaliciousDetector{
		behaviors: make(map[string]*ValidatorBehavior),
		thresholds: struct {
			doubleSignings    int
			missedBlocks      int
			invalidBlocks     int
			consecutiveMisses int
		}{
			doubleSignings:    1,  // Immediate slash for double signing
			missedBlocks:      50, // Allow 50 missed blocks
			invalidBlocks:     10, // Allow 10 invalid blocks
			consecutiveMisses: 20, // Allow 20 consecutive misses
		},
	}

	cm := &ConsensusManager{
		Blockchain:        blockchain,
		CurrentBlockTime:  BaseBlockTime,
		PredictionModel:   &PredictionModel{},
		maliciousDetector: md,
	}
	md.consensusManager = cm
	return cm
}

// Add this helper method
func (md *MaliciousDetector) updateMissedBlocks(block *Block) {
	behavior := md.behaviors[block.Validator]
	if behavior == nil {
		behavior = &ValidatorBehavior{}
		md.behaviors[block.Validator] = behavior
	}

	if block.Index-behavior.LastActiveBlock > 1 {
		behavior.MissedBlocks++
		behavior.ConsecutiveMisses++
	} else {
		behavior.ConsecutiveMisses = 0
	}
	behavior.LastActiveBlock = block.Index

	if behavior.MissedBlocks >= md.thresholds.missedBlocks ||
		behavior.ConsecutiveMisses >= md.thresholds.consecutiveMisses {
		totalStake := md.consensusManager.Blockchain.GetTotalSupply()
		md.consensusManager.Blockchain.SlashMaliciousValidator(
			block.Validator,
			calculateSlashAmount("missed_blocks", totalStake),
		)
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
	log.Printf("Validating block created by validator: %s", block.Validator)

	if !cm.verifyStake(block.Validator) {
		log.Printf("Stake verification failed for validator: %s", block.Validator)
		return false
	}
	log.Printf("Stake verified successfully for validator: %s", block.Validator)

	if !cm.verifyBlockSignature(block) {
		log.Printf("Block signature verification failed for validator: %s", block.Validator)
		return false
	}
	log.Printf("Block signature verified successfully for validator: %s", block.Validator)

	prevBlock := cm.Blockchain.Blocks[len(cm.Blockchain.Blocks)-1]
	if block.Timestamp < prevBlock.Timestamp ||
		block.Timestamp > prevBlock.Timestamp+int64(cm.CurrentBlockTime.Seconds()*2) {
		log.Printf("Block timestamp validation failed for validator: %s. Current: %d, Previous: %d, Max allowed: %d",
			block.Validator, block.Timestamp, prevBlock.Timestamp, prevBlock.Timestamp+int64(cm.CurrentBlockTime.Seconds()*2))
		return false
	}
	log.Printf("Block timestamp verified successfully for validator: %s", block.Validator)

	if !cm.Blockchain.IsActiveValidator(block.Validator) {
		log.Printf("Validator %s is not in the active set", block.Validator)
		return false
	}
	log.Printf("Validator %s confirmed as active", block.Validator)

	// Verify block signature
	publicKey, err := cm.Blockchain.GetValidatorPublicKey(block.Validator)
	if err != nil {
		log.Printf("Failed to get validator public key: %v", err)
		return false
	}

	blockData, err := block.SerializeForSigning()
	if err != nil {
		log.Printf("Failed to serialize block for signing: %v", err)
		return false
	}

	// Note: passing nil as the context parameter since we're not using a context in block signing
	if !mldsa44.Verify(publicKey, blockData, nil, block.Signature) {
		log.Printf("Block signature verification failed for validator: %s", block.Validator)
		return false
	}

	log.Printf("Block validation successful for validator: %s", block.Validator)
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
	log.Printf("Attempting to verify block signature for validator: %s", block.Validator)

	mldsaPubKey, err := cm.Blockchain.RetrievePublicKey(block.Validator)
	if err != nil {
		log.Printf("Failed to retrieve public key for validator %s: %v", block.Validator, err)
		return false
	}
	log.Printf("Successfully retrieved public key for validator: %s", block.Validator)

	// Use an empty context (as per ML-DSA-44 signature scheme requirements)
	context := []byte{}

	// Verify the block signature using the mldsa44.Verify function
	signatureValid := mldsa44.Verify(mldsaPubKey, []byte(block.Hash), context, block.Signature)
	if !signatureValid {
		log.Printf("Signature verification failed for validator: %s", block.Validator)
		return false
	}

	log.Printf("Signature verified successfully for validator: %s", block.Validator)
	return true
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
