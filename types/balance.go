package types

import (
	"time"

	"github.com/thrylos-labs/thrylos/amount"
)

type BalanceNotifier interface {
	SendBalanceUpdate(address string) error
	NotifyBalanceUpdate(address string, balance amount.Amount)
}

type PendingBalanceUpdate struct {
	Address   string
	Balance   int64
	Timestamp time.Time
}

type BalanceUpdateRequest struct {
	Address string
	Retries int
}
