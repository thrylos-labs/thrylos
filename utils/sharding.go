package utils // Or sharding_utils if you rename the file/package

import (
	"crypto/sha256"
	"math/big"

	"github.com/thrylos-labs/thrylos/types" // Import your types package
)

// GetShardID deterministically assigns an address to a shard.
// It returns types.ShardID to be consistent with your custom type.
func GetShardID(addr string, numShards int) types.ShardID { // Use types.ShardID
	// Use a cryptographic hash for even distribution
	h := sha256.Sum256([]byte(addr))
	// Convert hash to big.Int and take modulo
	bigIntHash := new(big.Int).SetBytes(h[:])
	shardID := bigIntHash.Mod(bigIntHash, big.NewInt(int64(numShards))).Int64()
	return types.ShardID(shardID) // Cast to types.ShardID
}
