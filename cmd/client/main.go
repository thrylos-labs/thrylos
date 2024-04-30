package main

import (
	"context"
	"log"
	"time"

	"github.com/thrylos-labs/thrylos/thrylos"

	flatbuffers "github.com/google/flatbuffers/go"
	"google.golang.org/grpc"
	"google.golang.org/grpc/keepalive"
)

func main() {
	var kacp = keepalive.ClientParameters{
		Time:                10 * time.Second, // send keepalive pings every 10 seconds if there is no activity
		Timeout:             time.Second,      // wait 1 second for ping ack before considering the connection dead
		PermitWithoutStream: true,             // send pings even without active streams
	}

	// Connect to the gRPC server with keepalive parameters
	conn, err := grpc.Dial("localhost:50051", grpc.WithInsecure(),
		grpc.WithBlock(),
		grpc.WithKeepaliveParams(kacp),
		grpc.WithDefaultCallOptions(grpc.MaxCallRecvMsgSize(1024*1024*10))) // 10 MB
	if err != nil {
		log.Fatalf("Did not connect: %v", err)
	}
	defer conn.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second) // Adjust timeout based on expected operation time
	defer cancel()

	builder := flatbuffers.NewBuilder(0)

	// Create UTXO for inputs
	transactionIdInput := builder.CreateString("prev-tx-id")
	ownerAddressInput := builder.CreateString("owner-address-example")
	thrylos.UTXOStart(builder)
	thrylos.UTXOAddTransactionId(builder, transactionIdInput)
	thrylos.UTXOAddIndex(builder, 0)
	thrylos.UTXOAddOwnerAddress(builder, ownerAddressInput)
	thrylos.UTXOAddAmount(builder, 50)
	utxoInput := thrylos.UTXOEnd(builder)

	// Create UTXO for outputs
	transactionIdOutput := builder.CreateString("new-tx-id")
	ownerAddressOutput := builder.CreateString("recipient-address-example")
	thrylos.UTXOStart(builder)
	thrylos.UTXOAddTransactionId(builder, transactionIdOutput)
	thrylos.UTXOAddIndex(builder, 0)
	thrylos.UTXOAddOwnerAddress(builder, ownerAddressOutput)
	thrylos.UTXOAddAmount(builder, 100)
	utxoOutput := thrylos.UTXOEnd(builder)

	// Create an array for inputs and outputs
	thrylos.TransactionStartInputsVector(builder, 1)
	builder.PrependUOffsetT(utxoInput)
	inputs := builder.EndVector(1)
	thrylos.TransactionStartOutputsVector(builder, 1)
	builder.PrependUOffsetT(utxoOutput)
	outputs := builder.EndVector(1)

	// Create Transaction
	transactionId := builder.CreateString("transaction-id")
	signature := builder.CreateByteVector([]byte("transaction-signature"))
	encryptedInputs := builder.CreateByteVector([]byte("encrypted-inputs-data"))
	encryptedOutputs := builder.CreateByteVector([]byte("encrypted-outputs-data"))
	sender := builder.CreateString("sender-address")
	thrylos.TransactionStart(builder)
	thrylos.TransactionAddId(builder, transactionId)
	thrylos.TransactionAddTimestamp(builder, time.Now().Unix())
	thrylos.TransactionAddInputs(builder, inputs)
	thrylos.TransactionAddOutputs(builder, outputs)
	thrylos.TransactionAddSignature(builder, signature)
	thrylos.TransactionAddEncryptedInputs(builder, encryptedInputs)
	thrylos.TransactionAddEncryptedOutputs(builder, encryptedOutputs)
	thrylos.TransactionAddSender(builder, sender)
	transaction := thrylos.TransactionEnd(builder)

	thrylos.TransactionRequestStart(builder)
	thrylos.TransactionRequestAddTransaction(builder, transaction)
	transReq := thrylos.TransactionRequestEnd(builder)
	builder.Finish(transReq)

	// Assuming `c` is a client of the generated FlatBuffers gRPC service
	c := thrylos.NewBlockchainServiceClient(conn)
	r, err := c.SubmitTransaction(ctx, builder) // Directly pass the builder
	if err != nil {
		log.Fatalf("Could not submit transaction: %v", err)
	}

	// Assuming `r` is the response object that has a method to access its data
	status := string(r.Status()) // How you access this depends on your generated code
	log.Printf("Transaction Status: %s", status)
}
