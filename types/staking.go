package types

import "sync"

type StakingManager interface {
	GetPoolStats() map[string]interface{}
	CreateStake(userAddress string, amount int64) (*Stake, error)
	UnstakeTokens(userAddress string, amount int64) error
	DelegateToPool(delegator string, amount int64) error
	UndelegateFromPool(delegator string, amount int64) error
	DistributeRewards() error
	GetTotalStaked() int64
	GetEffectiveInflationRate() float64
}

type StakingPool struct {
	MinStakeAmount    int64 `json:"minStakeAmount"`
	MinDelegation     int64 `json:"minDelegation"`     // Added for pool delegations
	FixedYearlyReward int64 `json:"fixedYearlyReward"` // Always 4.8M
	TotalStaked       int64 `json:"totalStaked"`       // Track total stake for monitoring
	TotalDelegated    int64 `json:"totalDelegated"`    // Added for pool delegations
	LastRewardTime    int64 `json:"lastRewardTime"`    // Last reward distribution time (in seconds)
}

type Stake struct {
	UserAddress            string  `json:"userAddress"`
	Amount                 int64   `json:"amount"`
	StartTime              int64   `json:"startTime"`
	LastStakeUpdateTime    int64   `json:"lastStakeUpdateTime"` // Last time stake was updated
	StakeTimeSum           float64 `json:"stakeTimeSum"`        // Accumulated stake-time (stake * duration)
	StakeTimeAverage       float64 `json:"stakeTimeAverage"`    // Moving average of stake-time
	TotalStakeRewards      float64 `json:"totalStakeRewards"`
	TotalDelegationRewards float64 `json:"totalDelegationRewards"`
	IsActive               bool    `json:"isActive"`
	ValidatorRole          bool    `json:"validatorRole"`
}

type StakingService struct {
	mu         sync.RWMutex
	pool       *StakingPool
	stakes     map[string]*Stake
	blockchain *Blockchain
}
