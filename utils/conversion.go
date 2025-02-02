package utils

import "github.com/thrylos-labs/thrylos/config"

func ThrylosToNano(thrylos ...float64) int64 {
	var amount float64
	if len(thrylos) > 0 {
		amount = thrylos[0]
	} else {
		amount = config.InitialTotalSupply
	}
	return int64(amount * config.NanoPerThrylos)
}

func NanoToThrylos(nano int64) float64 {
	return float64(nano) / config.NanoPerThrylos
}
