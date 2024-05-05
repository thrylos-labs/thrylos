package thrylos

// This needs to stay in the same directory as the Protobuf definitions

// TransactionJSON mirrors the JSON structure of your transaction data
type TransactionJSON struct {
	ID        string     `json:"id"`
	Timestamp int64      `json:"timestamp"`
	Inputs    []UTXOJSON `json:"inputs"`
	Outputs   []UTXOJSON `json:"outputs"`
	Signature string     `json:"signature"`
}

// UTXOJSON mirrors the JSON structure of your UTXO data
type UTXOJSON struct {
	TransactionID string `json:"transactionId"`
	Index         int32  `json:"index"`
	OwnerAddress  string `json:"ownerAddress"`
	Amount        int64  `json:"amount"`
}
