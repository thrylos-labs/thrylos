// In store/store.go or a new store/sharding_keys.go

package store

import (
	"crypto/sha256"
	"fmt"
	"math/big"

	"github.com/thrylos-labs/thrylos/types"
)

// CalculateShardID deterministically assigns an address to a shard.
func CalculateShardID(addr string, numShards int) types.ShardID { // <--- THIS MUST BE types.ShardID
	h := sha256.Sum256([]byte(addr))
	bigIntHash := new(big.Int).SetBytes(h[:])
	shardID := bigIntHash.Mod(bigIntHash, big.NewInt(int64(numShards))).Int64()
	return types.ShardID(shardID) // <--- THIS MUST BE A CAST TO types.ShardID
}

// GetShardedKey generates a BadgerDB key with a shard prefix.
func GetShardedKey(prefix string, shardID types.ShardID, originalKeyParts ...string) []byte { // CHANGED: shardID type
	key := prefix + fmt.Sprintf("%d", shardID) // fmt.Sprintf works with custom integer types
	for _, part := range originalKeyParts {
		key += "-" + part
	}
	return []byte(key)
}
