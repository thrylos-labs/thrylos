package templates

type TransactionJSON struct {
	ID            string     `json:"id"`
	Timestamp     int64      `json:"timestamp"`
	Inputs        []UTXOJSON `json:"inputs"`
	Outputs       []UTXOJSON `json:"outputs"`
	Signature     string     `json:"signature"`
	PreviousTxIds []string   `json:"previous_tx_ids"`
	Sender        string     `json:"sender"`
}

type UTXOJSON struct {
	TransactionID string `json:"transaction_id"`
	Index         int    `json:"index"`
	OwnerAddress  string `json:"owner_address"`
	Amount        int64  `json:"amount"`
}
