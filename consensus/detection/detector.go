// consensus/detection/detector.go
package detection

import (
	"bytes"
	"fmt"
)

type Thresholds struct {
	DoubleSignings    int
	MissedBlocks      int
	InvalidBlocks     int
	ConsecutiveMisses int
}

type MaliciousDetector struct {
	behaviors        map[string]*ValidatorBehavior
	consensusManager ConsensusManagerInterface
	signatures       map[string][]byte
	thresholds       Thresholds
}

func NewMaliciousDetector() *MaliciousDetector {
	return &MaliciousDetector{
		behaviors:  make(map[string]*ValidatorBehavior),
		signatures: make(map[string][]byte),
		thresholds: Thresholds{
			DoubleSignings:    1,  // Immediate slash
			MissedBlocks:      50, // Allow 50 missed blocks
			InvalidBlocks:     10, // Allow 10 invalid blocks
			ConsecutiveMisses: 20, // Allow 20 consecutive misses
		},
	}
}

func (md *MaliciousDetector) CheckDoubleSigningAtHeight(height int32, validator string, signature []byte) bool {
	key := fmt.Sprintf("%d:%s", height, validator)
	previousSignature := md.signatures[key]
	if previousSignature != nil && !bytes.Equal(previousSignature, signature) {
		return true
	}
	md.signatures[key] = signature
	return false
}

func (md *MaliciousDetector) UpdateMissedBlocks(block BlockInterface) {
	behavior := md.behaviors[block.GetValidator()]
	if behavior == nil {
		behavior = &ValidatorBehavior{}
		md.behaviors[block.GetValidator()] = behavior
	}

	if block.GetIndex()-behavior.LastActiveBlock > 1 {
		behavior.UpdateMissedBlock()
	} else {
		behavior.ResetConsecutiveMisses()
	}
	behavior.LastActiveBlock = block.GetIndex()

	if behavior.MissedBlocks >= md.thresholds.MissedBlocks ||
		behavior.ConsecutiveMisses >= md.thresholds.ConsecutiveMisses {
		totalStake := md.consensusManager.GetTotalSupply()
		md.consensusManager.SlashMaliciousValidator(
			block.GetValidator(),
			CalculateSlashAmount("missed_blocks", totalStake),
		)
	}
}

func CalculateSlashAmount(violation string, totalStake int64) int64 {
	slashAmounts := map[string]float64{
		"double_signing": 0.05,
		"invalid_blocks": 0.02,
		"missed_blocks":  0.01,
	}
	return int64(slashAmounts[violation] * float64(totalStake))
}
