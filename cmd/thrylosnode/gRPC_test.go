package main

import (
	"context"
	"log"
	"net"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	pb "github.com/thrylos-labs/thrylos"
	"google.golang.org/grpc"
	"google.golang.org/grpc/test/bufconn"
)

const bufSize = 1024 * 1024

var lis *bufconn.Listener

func init() {
	// Initialize the listener for the in-memory connection
	lis = bufconn.Listen(bufSize)
}

func bufDialer(context.Context, string) (net.Conn, error) {
	return lis.Dial()
}

func startMockServer() *grpc.Server {
	server := grpc.NewServer()
	pb.RegisterBlockchainServiceServer(server, &mockBlockchainServer{})
	go func() {
		if err := server.Serve(lis); err != nil {
			log.Fatalf("Server exited with error: %v", err)
		}
	}()
	return server
}

func TestSubmitTransaction(t *testing.T) {
	server := startMockServer()
	defer server.Stop()

	// Set up the client connection to the server
	ctx := context.Background()
	conn, err := grpc.DialContext(ctx, "", grpc.WithContextDialer(bufDialer), grpc.WithInsecure())
	if err != nil {
		log.Fatalf("Failed to dial: %v", err)
	}
	defer conn.Close()

	client := pb.NewBlockchainServiceClient(conn)

	// Prepare and send the request
	transaction := &pb.Transaction{
		Id:        "transaction-id",
		Timestamp: time.Now().Unix(),
		Inputs: []*pb.UTXO{
			{
				TransactionId: "prev-tx-id",
				Index:         0,
				OwnerAddress:  "owner-address-example",
				Amount:        50,
			},
		},
		Outputs: []*pb.UTXO{
			{
				TransactionId: "new-tx-id",
				Index:         0,
				OwnerAddress:  "recipient-address-example",
				Amount:        50,
			},
		},
		Signature: "transaction-signature",
		Sender:    "sender-address",
	}
	r, err := client.SubmitTransaction(ctx, &pb.TransactionRequest{Transaction: transaction})
	assert.NoError(t, err)
	assert.NotNil(t, r)
	assert.Equal(t, "Transaction added successfully", r.Status)
}

type mockBlockchainServer struct {
	pb.UnimplementedBlockchainServiceServer
}

func (s *mockBlockchainServer) SubmitTransaction(ctx context.Context, req *pb.TransactionRequest) (*pb.TransactionResponse, error) {
	return &pb.TransactionResponse{Status: "Transaction added successfully"}, nil
}
