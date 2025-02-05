package config

import (
	"os"

	"github.com/BurntSushi/toml"
)

type Config struct {
	NanoPerThrylos                 float64 `toml:"nano_per_thrylos"`
	InitialTotalSupply             float64 `toml:"initial_total_supply"`
	AnnualStakeReward              float64 `toml:"annual_stake_reward"`
	DailyStakeReward               float64 `toml:"daily_stake_reward"`
	MinimumStakeAmount             float64 `toml:"minimum_stake_amount"`
	MinStakePercentage             float64 `toml:"min_stake_percentage"`
	RewardDistributionTimeInterval int     `toml:"reward_distribution_time_interval"`
	DelegationRewardPercent        float64 `toml:"delegation_reward_percent"`
}

func LoadConfigFromFile(filePath string) (*Config, error) {
	var config Config
	if _, err := toml.DecodeFile(filePath, &config); err != nil {
		return nil, err
	}
	return &config, nil
}

func GenerateDefaultConfig() *Config {
	return &Config{
		NanoPerThrylos:                 NanoPerThrylos,
		InitialTotalSupply:             InitialTotalSupply,
		AnnualStakeReward:              AnnualStakeReward,
		DailyStakeReward:               DailyStakeReward,
		MinimumStakeAmount:             MinimumStakeAmount,
		MinStakePercentage:             MinStakePercentage,
		RewardDistributionTimeInterval: RewardDistributionTimeInterval,
		DelegationRewardPercent:        DelegationRewardPercent,
	}
}

func SaveConfigToFile(config *Config, filePath string) error {
	file, err := os.Create(filePath)
	if err != nil {
		return err
	}
	defer file.Close()

	encoder := toml.NewEncoder(file)
	if err := encoder.Encode(config); err != nil {
		return err
	}
	return nil
}

func LoadOrCreateConfig(filePath string) (*Config, error) {
	config, err := LoadConfigFromFile(filePath)
	if os.IsNotExist(err) {
		config = GenerateDefaultConfig()
		if err := SaveConfigToFile(config, filePath); err != nil {
			return nil, err
		}
	} else if err != nil {
		return nil, err
	}
	return config, nil
}
