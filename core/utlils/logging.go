package utils

import "log"

func LogError(stage string, err error) {
	log.Printf("[%s] error: %v", stage, err)
}
