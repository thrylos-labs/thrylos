package utils

import "time"

// ValidateTimestamp checks if the transaction timestamp is within the last hour.
func IsTimestampWithinOneHour(timestamp int64) bool {
	return time.Since(time.Unix(timestamp, 0)).Hours() < 1
}
