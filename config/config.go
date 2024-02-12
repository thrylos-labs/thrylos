package config

import (
	"encoding/json"
	"os"
)

type Config struct {
	CertPath string `json:"CERT_PATH"`
	KeyPath  string `json:"KEY_PATH"`
}

func LoadConfig(configPath string) (*Config, error) {
	// Open the JSON file
	configFile, err := os.Open(configPath)
	if err != nil {
		return nil, err
	}
	defer configFile.Close()

	// Decode the JSON file into `Config`
	var config Config
	if err := json.NewDecoder(configFile).Decode(&config); err != nil {
		return nil, err
	}

	return &config, nil
}
