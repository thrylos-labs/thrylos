package core

const (
	NanoPerThrylos                 = 1e7
	AnnualStakeReward              = 4_800_000 * NanoPerThrylos
	DailyStakeReward               = AnnualStakeReward / 365
	MinimumStakeAmount             = 40 * NanoPerThrylos
	RewardDistributionTimeInterval = 24 * 60 * 60 // one day in seconds
	DelegationRewardPercent        = 0.5          //50%
	InitialTotalSupply             = 120_000_000  // 120 million tokens
	MinStakePercentage             = 0.1          // 0.1% of total supply as minimum stake

)
