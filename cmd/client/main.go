package main

import (
	"context"
	"log"
	"time"

	pb "github.com/thrylos-labs/thrylos" // ensure this import path is correct
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

	c := pb.NewBlockchainServiceClient(conn) // Use the correct client constructor from generated protobuf code

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second) // Adjust timeout based on expected operation time
	defer cancel()

	// Correctly prepare Inputs and Outputs according to the UTXO structure
	inputs := []*pb.UTXO{{
		TransactionId: "prev-tx-id",
		Index:         0,
		OwnerAddress:  "owner-address-example",
		Amount:        50, // Example amount, ensure this matches the expected logic
	}}
	outputs := []*pb.UTXO{{
		TransactionId: "new-tx-id",
		Index:         0,
		OwnerAddress:  "recipient-address-example",
		Amount:        100, // As an example
	}}

	// Build the transaction
	transaction := &pb.Transaction{
		Id:               "transaction-id",
		Timestamp:        time.Now().Unix(),
		Inputs:           inputs,
		Outputs:          outputs,
		Signature:        []byte("transaction-signature"),
		PreviousTxIds:    []string{"prev-tx-id1", "prev-tx-id2"},
		EncryptedAesKey:  []byte("example-encrypted-key"),
		EncryptedInputs:  []byte("encrypted-inputs-data"),
		EncryptedOutputs: []byte("encrypted-outputs-data"),
		Sender:           "sender-address",
	}

	// Create TransactionRequest with the transaction
	r, err := c.SubmitTransaction(ctx, &pb.TransactionRequest{Transaction: transaction})
	if err != nil {
		log.Fatalf("Could not submit transaction: %v", err)
	}
	log.Printf("Transaction Status: %s", r.Status)
}
