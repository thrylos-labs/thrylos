package database

import "github.com/fxamacker/cbor/v2"

type TransactionData struct {
	FromAddress string `cbor:"1,keyasint"`
	ToAddress   string `cbor:"2,keyasint"`
	Amount      int    `cbor:"3,keyasint"`
}

func (td *TransactionData) Marshal() ([]byte, error) {
	return cbor.Marshal(td)
}

func (td *TransactionData) Unmarshal(data []byte) error {
	return cbor.Unmarshal(data, td)
}
