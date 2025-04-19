package config

import (
	"os"

	"github.com/BurntSushi/toml"
)

type Config struct {
	DataDir           string `toml:"data_dir"`
	AESKey            string `toml:"aes_key"` // Store key as string (e.g., hex/base64) in TOML
	TestMode          bool   `toml:"test_mode"`
	DisableBackground bool   `toml:"disable_background"`

	NanoPerThrylos                 float64 `toml:"nano_per_thrylos"`
	InitialTotalSupply             float64 `toml:"initial_total_supply"`
	AnnualStakeReward              float64 `toml:"annual_stake_reward"`
	DailyStakeReward               float64 `toml:"daily_stake_reward"`
	MinimumStakeAmount             float64 `toml:"minimum_stake_amount"`
	MinStakePercentage             float64 `toml:"min_stake_percentage"`
	RewardDistributionTimeInterval int     `toml:"reward_distribution_time_interval"`
	DelegationRewardPercent        float64 `toml:"delegation_reward_percent"`

	// --- ADDED Gas Fee Fields ---
	MinGasFee     int `toml:"min_gas_fee"`     // Minimum fee required (nanoTHR)
	MaxGasFee     int `toml:"max_gas_fee"`     // Optional: Max fee allowed (nanoTHR)
	DefaultGasFee int `toml:"default_gas_fee"` // Optional: Default fee if not specified (nanoTHR)
}

// --- Define default values here (used if config file is missing) ---
// You can choose to keep these separate or define them right before GenerateDefaultConfig
const (
	// Default values for config generation
	defaultNanoPerThrylos                 = 1e7
	defaultInitialTotalSupply             = 120_000_000.0
	defaultAnnualStakeReward              = 4_800_000.0 * defaultNanoPerThrylos
	defaultDailyStakeReward               = defaultAnnualStakeReward / 365.0
	defaultMinimumStakeAmount             = 40.0 * defaultNanoPerThrylos
	defaultMinStakePercentage             = 0.1
	defaultRewardDistributionTimeInterval = 24 * 60 * 60 // one day in seconds
	defaultDelegationRewardPercent        = 0.5          // 50%

	// Default Gas Values (can be overridden by config file)
	defaultMinGasFee     int = 10000   // nanoTHR (0.001 THR)
	defaultMaxGasFee     int = 1000000 // nanoTHR (0.1 THR)
	defaultDefaultGasFee int = 50000   // nanoTHR (0.005 THR)
)

func LoadConfigFromFile(filePath string) (*Config, error) {
	var config Config
	if _, err := toml.DecodeFile(filePath, &config); err != nil {
		return nil, err
	}
	return &config, nil
}

func GenerateDefaultConfig() *Config {
	return &Config{
		NanoPerThrylos:                 defaultNanoPerThrylos,
		InitialTotalSupply:             defaultInitialTotalSupply,
		AnnualStakeReward:              defaultAnnualStakeReward,
		DailyStakeReward:               defaultDailyStakeReward,
		MinimumStakeAmount:             defaultMinimumStakeAmount,
		MinStakePercentage:             defaultMinStakePercentage,
		RewardDistributionTimeInterval: defaultRewardDistributionTimeInterval,
		DelegationRewardPercent:        defaultDelegationRewardPercent,
		// --- Assign Default Gas Fees ---
		MinGasFee:     defaultMinGasFee,
		MaxGasFee:     defaultMaxGasFee,
		DefaultGasFee: defaultDefaultGasFee,
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
