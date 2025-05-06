package store

// Storage prefices
const (
	AddressPrefix     = "ad-"
	TransactionPrefix = "tx-"
	UTXOPrefix        = "ux-"
	BalancePrefix     = "bal-"
	BlockPrefix       = "bl-"
	PublicKeyPrefix   = "pu-"
	PrivateKeyPrifx   = "pk-" // Corrected variable name to match Go conventions (Prifx -> Prefix)
	SignaturePrifx    = "sn-" // Corrected variable name
	ValidatorPrefx    = "vd-" // Corrected variable name, used for types.Validator objects
)
