package store

import (
	"github.com/thrylos-labs/thrylos/chain"
	"github.com/thrylos-labs/thrylos/shared"

	"github.com/thrylos-labs/thrylos/consensus/validator"
	"github.com/thrylos-labs/thrylos/crypto"
	"github.com/thrylos-labs/thrylos/crypto/address"
)

type Store interface {
	GetUTXO(addr address.Address) ([]*shared.UTXO, error)
	GetTransaction(id string) (*shared.Transaction, error)
	GetLastBlock() (*chain.Block, error)
	GetLastBlockNumber() (int, error)
	GetBlock(blockNumber uint32) (*chain.Block, error)
	GetPublicKey(addr address.Address) (crypto.PublicKey, error)
	GetValidator(addr address.Address) (*validator.Validator, error)

	//writer
	UpdateUTXO(utxo *shared.UTXO) error
	SaveTransaction(tx *shared.Transaction) error
	SaveBlock(blk *chain.Block) error
	UpdateValidator(v *validator.Validator) error
}
