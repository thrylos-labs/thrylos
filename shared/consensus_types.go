package shared

import (
	"math/big"
	"time"

	"github.com/thrylos-labs/thrylos/consensus/detection"
)

type BlockchainInterface interface {
	GetTotalSupply() int64
	IsActiveValidator(address string) bool
	UpdateActiveValidators(count int)
	GetValidatorPublicKey(validator string) ([]byte, error)
	RetrievePublicKey(validator string) ([]byte, error)
	GetMinStakeForValidator() *big.Int
	Stakeholders() map[string]int64
}

type ConsensusManager struct {
	Blockchain        BlockchainInterface
	CurrentBlockTime  time.Duration
	PredictionModel   *PredictionModel
	maliciousDetector *detection.MaliciousDetector
}

type PredictionModel struct {
	ExpectedTransactionVolume int
	ExpectedNodeCount         int
}
