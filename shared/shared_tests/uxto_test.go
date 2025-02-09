package shared

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/thrylos-labs/thrylos/crypto/address"
	"github.com/thrylos-labs/thrylos/shared"
)

func TestUTXO(t *testing.T) {
	// Create a null address for testing
	nullAddr := address.NullAddress()
	validAddress := nullAddr.String() // This will give us a valid tl1 address

	t.Run("UTXO Creation", func(t *testing.T) {
		// Test successful creation
		utxo := shared.CreateUTXO(
			"test-utxo-1",
			0,
			"test-tx-1",
			validAddress,
			100.0,
			false,
		)
		assert.NotNil(t, utxo)
		assert.Equal(t, "test-utxo-1", utxo.ID)
		assert.Equal(t, 0, utxo.Index)
		assert.Equal(t, "test-tx-1", utxo.TransactionID)
		assert.Equal(t, validAddress, utxo.OwnerAddress)
		assert.False(t, utxo.IsSpent)

		// Test creation with negative amount - should still create but will fail validation
		negativeUtxo := shared.CreateUTXO(
			"test-utxo-2",
			0,
			"test-tx-2",
			validAddress,
			-100.0,
			false,
		)
		assert.NotNil(t, negativeUtxo)
	})

	t.Run("UTXO Validation", func(t *testing.T) {
		// Test valid UTXO
		validUtxo := shared.CreateUTXO(
			"test-utxo-1",
			0,
			"test-tx-1",
			validAddress,
			100.0,
			false,
		)
		err := validUtxo.Validate()
		assert.NoError(t, err)

		// Test UTXO with invalid address
		invalidUtxo := shared.CreateUTXO(
			"test-utxo-2",
			0,
			"test-tx-2",
			"invalid_address",
			100.0,
			false,
		)
		assert.NotNil(t, invalidUtxo)
		err = invalidUtxo.Validate()
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "invalid owner address format")
	})

	t.Run("UTXO Key Generation", func(t *testing.T) {
		utxo := shared.CreateUTXO(
			"test-utxo-1",
			5,
			"test-tx-1",
			validAddress,
			100.0,
			false,
		)
		key := utxo.Key()
		expectedKey := "test-tx-1-5"
		assert.Equal(t, expectedKey, key)
	})

	t.Run("UTXO Serialization", func(t *testing.T) {
		original := shared.CreateUTXO(
			"test-utxo-1",
			0,
			"test-tx-1",
			validAddress,
			100.0,
			false,
		)

		// Test Marshal
		data, err := original.Marshal()
		assert.NoError(t, err)
		assert.NotNil(t, data)

		// Test Unmarshal
		var reconstructed shared.UTXO
		err = reconstructed.Unmarshal(data)
		assert.NoError(t, err)

		// Verify all fields match
		assert.Equal(t, original.ID, reconstructed.ID)
		assert.Equal(t, original.Index, reconstructed.Index)
		assert.Equal(t, original.TransactionID, reconstructed.TransactionID)
		assert.Equal(t, original.OwnerAddress, reconstructed.OwnerAddress)
		assert.Equal(t, original.Amount, reconstructed.Amount)
		assert.Equal(t, original.IsSpent, reconstructed.IsSpent)
	})

	t.Run("Mark UTXO as Spent", func(t *testing.T) {
		// Create a map of UTXOs
		utxos := make(map[string]shared.UTXO)
		utxo := shared.CreateUTXO(
			"test-utxo-1",
			0,
			"test-tx-1",
			validAddress,
			100.0,
			false,
		)
		utxos[utxo.ID] = *utxo

		// Verify UTXO exists
		_, exists := utxos[utxo.ID]
		assert.True(t, exists)

		// Mark as spent
		shared.MarkUTXOAsSpent(utxo.ID, utxos)

		// Verify UTXO no longer exists
		_, exists = utxos[utxo.ID]
		assert.False(t, exists)
	})
}
