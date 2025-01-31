package utils

import "github.com/thrylos-labs/thrylos/core/config"

func ThrylosToNano(thrylos float64) int64 {
	return int64(thrylos * config.NanoPerThrylos)
}

func NanoToThrylos(nano int64) float64 {
	return float64(nano) / config.NanoPerThrylos
}
