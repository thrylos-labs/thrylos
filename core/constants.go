package core

const (
	AnnualStakeReward              = 4_800_000 * 1e7
	DailyStakeReward               = AnnualStakeReward / 365
	MinimumStakeAmount             = 40 * 1e7
	RewardDistributionTimeInterval = 24 * 60 * 60 // one day in seconds
	DelegationRewardPercent        = 0.5          //50%
)
