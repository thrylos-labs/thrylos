package detection

type BlockInterface interface {
	GetValidator() string
	GetIndex() int32
}

type ConsensusManagerInterface interface {
	GetTotalSupply() int64
	SlashMaliciousValidator(validator string, amount int64)
}
