package node

import (
	"os"

	"github.com/joho/godotenv"
)

func loadEnv() (map[string]string, error) {
	env := os.Getenv("ENV")
	var envPath string
	if env == "production" {
		envPath = "../../.env.prod" // The Cert is managed through the droplet
	} else {
		envPath = "../../.env.dev" // Managed through local host
	}
	envFile, err := godotenv.Read(envPath)

	return envFile, err
}
