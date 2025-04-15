package config

const (
	// Token Related
	NanoPerThrylos     = 1e7
	InitialTotalSupply = 120_000_000 // 120 million tokens

	// Staking Related
	AnnualStakeReward  = 4_800_000 * NanoPerThrylos
	DailyStakeReward   = AnnualStakeReward / 365
	MinimumStakeAmount = 40 * NanoPerThrylos
	MinStakePercentage = 0.1 // 0.1% of total supply

	// Time Related
	RewardDistributionTimeInterval = 24 * 60 * 60 // one day in seconds

	// Delegation Related
	DelegationRewardPercent = 0.5 // 50%

	DefaultGasFee int = 1000000 // Example: 0.1 THRYLOS (1,000,000 nanoTHR) - Adjust as needed
	MinGasFee     int = 10000   // Example: 0.001 THRYLOS (10,000 nanoTHR) - Adjust as needed
)
