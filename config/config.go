package config

import (
	"bufio"
	"fmt"
	"log"
	"os"
	"strconv"
	"strings"

	// Import time package
	"github.com/BurntSushi/toml"
)

// ---- ADDED: Nested Struct for Consensus Parameters ----
type ConsensusConfig struct {
	ValidatorUpdateInterval int `toml:"validator_update_interval"` // Interval in seconds
	MaxActiveValidators     int `toml:"max_active_validators"`     // Max number of validators in the active set
	BlockInterval           int `toml:"block_interval"`            // Target block creation interval in seconds
}

// --- Main Config Struct ---
type Config struct {
	DataDir           string `toml:"data_dir"`
	AESKey            string `toml:"aes_key"` // Store key as string (e.g., hex/base64) in TOML
	TestMode          bool   `toml:"test_mode"`
	DisableBackground bool   `toml:"disable_background"`

	NanoPerThrylos     float64 `toml:"nano_per_thrylos"`
	InitialTotalSupply float64 `toml:"initial_total_supply"`
	AnnualStakeReward  float64 `toml:"annual_stake_reward"`
	DailyStakeReward   float64 `toml:"daily_stake_reward"`

	// Change to float64 here to accept the float value from TOML
	MinimumStakeAmountFloat float64 `toml:"minimum_stake_amount"`

	MinStakePercentage             float64 `toml:"min_stake_percentage"`
	RewardDistributionTimeInterval int     `toml:"reward_distribution_time_interval"`
	DelegationRewardPercent        float64 `toml:"delegation_reward_percent"`

	MinGasFee     int `toml:"min_gas_fee"`     // Minimum fee required (nanoTHR)
	MaxGasFee     int `toml:"max_gas_fee"`     // Optional: Max fee allowed (nanoTHR)
	DefaultGasFee int `toml:"default_gas_fee"` // Optional: Default fee if not specified (nanoTHR)

	// --- ADDED: Consensus Field (Pointer to allow optional section in TOML) ---
	Consensus *ConsensusConfig `toml:"Consensus"`
}

// --- Define default values here ---
const (
	defaultNanoPerThrylos                 = 1e7
	defaultInitialTotalSupply             = 120_000_000.0
	defaultAnnualStakeReward              = 4_800_000.0 * defaultNanoPerThrylos
	defaultDailyStakeReward               = defaultAnnualStakeReward / 365.0
	defaultMinimumStakeAmount             = int64(40 * defaultNanoPerThrylos) // Directly calculate int64 nanoTHR
	defaultMinStakePercentage             = 0.1
	defaultRewardDistributionTimeInterval = 24 * 60 * 60 // one day in seconds
	defaultDelegationRewardPercent        = 0.5          // 50%
	defaultMinGasFee                      = 10000        // nanoTHR (0.001 THR)
	defaultMaxGasFee                      = 1000000      // nanoTHR (0.1 THR)
	defaultDefaultGasFee                  = 50000        // nanoTHR (0.005 THR)

	// --- ADDED: Default Consensus Values ---
	defaultValidatorUpdateInterval = 60 // seconds (1 minute)
	defaultMaxActiveValidators     = 5  // validators
	defaultBlockInterval           = 10 // seconds
)

func LoadConfigFromFile(filePath string) (*Config, error) {
	log.Printf("INFO: Attempting to load TOML config from: %s", filePath)

	// --- TEMPORARY DEBUGGING: Check the specific value string before TOML parsing ---
	file, errOpen := os.Open(filePath)
	if errOpen == nil {
		scanner := bufio.NewScanner(file)
		log.Println("--- DEBUG: Raw config file check for MinimumStakeAmount ---")
		found := false
		lineNumber := 0
		for scanner.Scan() {
			lineNumber++
			line := scanner.Text()
			trimmedLine := strings.TrimSpace(line)
			// Check specifically for the key assignment
			if strings.HasPrefix(trimmedLine, "minimum_stake_amount") && strings.Contains(trimmedLine, "=") {
				parts := strings.SplitN(trimmedLine, "=", 2)
				if len(parts) == 2 {
					valueStr := strings.TrimSpace(parts[1])
					// Remove potential trailing comments
					if commentIdx := strings.Index(valueStr, "#"); commentIdx != -1 {
						valueStr = strings.TrimSpace(valueStr[:commentIdx])
					}
					log.Printf("DEBUG: Found line %d, extracted value string: [%s]", lineNumber, valueStr)
					log.Println("DEBUG: minimum_stake_amount line not found or not parsed in raw scan.") // Updated log message

					// Try parsing the extracted string as int
					_, errInt := strconv.ParseInt(valueStr, 10, 64)
					if errInt == nil {
						log.Println("DEBUG: Go strconv successfully parsed value string as INT.")
					} else {
						log.Printf("DEBUG: Go strconv FAILED to parse value string as INT: %v", errInt)
					}

					// Try parsing the extracted string as float
					_, errFloat := strconv.ParseFloat(valueStr, 64)
					if errFloat == nil {
						log.Println("DEBUG: Go strconv successfully parsed value string as FLOAT.")
					} else {
						log.Printf("DEBUG: Go strconv FAILED to parse value string as FLOAT: %v", errFloat)
					}
					found = true
					break // Stop after finding the line
				}
			}
		}
		if !found {
			log.Println("DEBUG: MinimumStakeAmount line not found or not parsed in raw scan.")
		}
		log.Println("--- DEBUG: End raw check ---")
		file.Close() // Close the file manually after reading
	} else {
		log.Printf("WARN: Could not open file '%s' for raw debug reading: %v", filePath, errOpen)
	}
	// --- END TEMPORARY DEBUGGING ---

	// Now, let TOML try to parse it again
	var config Config
	if _, err := toml.DecodeFile(filePath, &config); err != nil {
		return nil, fmt.Errorf("error decoding TOML file '%s': %w", filePath, err)
	}

	// Apply Consensus defaults if needed
	if config.Consensus == nil {
		log.Println("DEBUG: Consensus section missing in TOML, applying defaults.")
		defaultConf := GenerateDefaultConfig()
		if defaultConf != nil {
			config.Consensus = defaultConf.Consensus
		} else {
			// Fallback if GenerateDefaultConfig fails (shouldn't happen)
			config.Consensus = &ConsensusConfig{
				ValidatorUpdateInterval: defaultValidatorUpdateInterval,
				MaxActiveValidators:     defaultMaxActiveValidators,
				BlockInterval:           defaultBlockInterval,
			}
		}
	}
	return &config, nil
}

func (c *Config) MinimumStakeAmount() int64 {
	return int64(c.MinimumStakeAmountFloat)
}

func GenerateDefaultConfig() *Config {
	return &Config{
		NanoPerThrylos:                 defaultNanoPerThrylos,
		InitialTotalSupply:             defaultInitialTotalSupply,
		AnnualStakeReward:              defaultAnnualStakeReward,
		DailyStakeReward:               defaultDailyStakeReward,
		MinimumStakeAmountFloat:        float64(defaultMinimumStakeAmount), // Convert int64 to float64
		MinStakePercentage:             defaultMinStakePercentage,
		RewardDistributionTimeInterval: defaultRewardDistributionTimeInterval,
		DelegationRewardPercent:        defaultDelegationRewardPercent,
		MinGasFee:                      defaultMinGasFee,
		MaxGasFee:                      defaultMaxGasFee,
		DefaultGasFee:                  defaultDefaultGasFee,
		// --- ADDED: Assign Default Consensus Struct ---
		Consensus: &ConsensusConfig{
			ValidatorUpdateInterval: defaultValidatorUpdateInterval,
			MaxActiveValidators:     defaultMaxActiveValidators,
			BlockInterval:           defaultBlockInterval,
		},
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

// LoadOrCreateConfig ensures defaults are applied correctly, especially for nested structs
func LoadOrCreateConfig(filePath string) (*Config, error) {
	config, err := LoadConfigFromFile(filePath)
	if os.IsNotExist(err) {
		// If file doesn't exist, generate full defaults and save
		config = GenerateDefaultConfig()
		if errSave := SaveConfigToFile(config, filePath); errSave != nil {
			return nil, errSave
		}
		// Return the fully defaulted config
		return config, nil
	} else if err != nil {
		// Other error during loading
		return nil, err
	}
	// If file existed and was loaded, ensure Consensus defaults are applied if needed
	// (LoadConfigFromFile already handles this now)
	return config, nil
}
