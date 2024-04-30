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
		Time:                10 * time.Second,
		Timeout:             time.Second,
		PermitWithoutStream: true,
	}

	conn, err := grpc.Dial("localhost:50051", grpc.WithInsecure(),
		grpc.WithBlock(),
		grpc.WithKeepaliveParams(kacp),
		grpc.WithDefaultCallOptions(grpc.MaxCallRecvMsgSize(1024*1024*10))) // 10 MB
	if err != nil {
		log.Fatalf("Did not connect: %v", err)
	}
	defer conn.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	builder := flatbuffers.NewBuilder(0)

	// Example transaction building
	transactionId := builder.CreateString("transaction-id")
	sender := builder.CreateString("sender-address")

	thrylos.TransactionStart(builder)
	thrylos.TransactionAddId(builder, transactionId)
	thrylos.TransactionAddSender(builder, sender)
	transaction := thrylos.TransactionEnd(builder)

	thrylos.TransactionRequestStart(builder)
	thrylos.TransactionRequestAddTransaction(builder, transaction)
	reqOffset := thrylos.TransactionRequestEnd(builder)
	builder.Finish(reqOffset) // Important: Finish building the buffer

	client := thrylos.NewBlockchainServiceClient(conn)

	// Send the transaction using the client
	responseBuf, err := client.SubmitTransaction(ctx, builder)
	if err != nil {
		log.Fatalf("Could not submit transaction: %v", err)
	}

	// Assume responseBuf is now a *TransactionResponse object
	if responseBuf == nil {
		log.Fatalf("Failed to parse transaction response")
	}

	// Access the status field
	statusBytes := responseBuf.Status() // Make sure you handle the byte slice correctly
	if statusBytes == nil {
		log.Println("No status returned in the response")
	} else {
		status := string(statusBytes)
		log.Printf("Transaction Status: %s", status)
	}
}
