package core

import (
	"testing"

	flatbuffers "github.com/google/flatbuffers/go"
	"github.com/stretchr/testify/assert"
	"github.com/thrylos-labs/thrylos/thrylos"
)

// TestTransactionSerialization tests the serialization and deserialization of a Transaction
func TestTransactionSerialization(t *testing.T) {
	builder := flatbuffers.NewBuilder(0)

	// Create UTXOs for inputs and outputs
	inputID := builder.CreateString("input_tx_id")
	outputID := builder.CreateString("output_tx_id")
	ownerAddress := builder.CreateString("owner_address")

	// Start and end an UTXO for input and output
	thrylos.UTXOStart(builder)
	thrylos.UTXOAddTransactionId(builder, inputID)
	thrylos.UTXOAddIndex(builder, 0)
	thrylos.UTXOAddOwnerAddress(builder, ownerAddress)
	thrylos.UTXOAddAmount(builder, 100)
	inputUTXO := thrylos.UTXOEnd(builder)

	thrylos.UTXOStart(builder)
	thrylos.UTXOAddTransactionId(builder, outputID)
	thrylos.UTXOAddIndex(builder, 1)
	thrylos.UTXOAddOwnerAddress(builder, ownerAddress)
	thrylos.UTXOAddAmount(builder, 95)
	outputUTXO := thrylos.UTXOEnd(builder)

	// Create vectors for inputs and outputs
	thrylos.TransactionStartInputsVector(builder, 1)
	builder.PrependUOffsetT(inputUTXO)
	inputs := builder.EndVector(1)

	thrylos.TransactionStartOutputsVector(builder, 1)
	builder.PrependUOffsetT(outputUTXO)
	outputs := builder.EndVector(1)

	// Create the transaction
	transactionID := builder.CreateString("tx123")
	signature := builder.CreateByteVector([]byte("signature"))
	thrylos.TransactionStart(builder)
	thrylos.TransactionAddId(builder, transactionID)
	thrylos.TransactionAddInputs(builder, inputs)
	thrylos.TransactionAddOutputs(builder, outputs)
	thrylos.TransactionAddSignature(builder, signature)
	transaction := thrylos.TransactionEnd(builder)

	builder.Finish(transaction)

	// Get the byte slice for the serialized transaction
	buf := builder.FinishedBytes()

	// Now let's deserialize and check the contents
	tx := thrylos.GetRootAsTransaction(buf, 0)
	assert.Equal(t, "tx123", string(tx.Id()), "Transaction ID mismatch")
	assert.Equal(t, "signature", string(tx.SignatureBytes()), "Signature mismatch")

	// Check inputs
	var utxo thrylos.UTXO
	assert.True(t, tx.Inputs(&utxo, 0), "Failed to get input UTXO")
	assert.Equal(t, "input_tx_id", string(utxo.TransactionId()), "Input transaction ID mismatch")
	assert.Equal(t, "owner_address", string(utxo.OwnerAddress()), "Owner address mismatch")
	assert.Equal(t, int64(100), utxo.Amount(), "Amount mismatch")

	// Check outputs
	assert.True(t, tx.Outputs(&utxo, 0), "Failed to get output UTXO")
	assert.Equal(t, "output_tx_id", string(utxo.TransactionId()), "Output transaction ID mismatch")
	assert.Equal(t, int64(95), utxo.Amount(), "Output amount mismatch")
}
