# TestNet Setup

## Step 1: Create a .env file within the thrylos directory


HTTP_NODE_ADDRESS=localhost:6080
GRPC_NODE_ADDRESS=localhost:50051
PEERS=
DATA=./blockchain_data
TESTNET=true
AES_KEY_ENV_VAR=['Generatethiskey']
WASM_PATH=[LeaveOut]
DATA_DIR=/database

## Step 2: Start the blockchain

cd cmd/thrylosnode

go run main.go --address=localhost:8080 --data=./node_data --testnet

## Step 3: Send a transaction

cd cmd/clisigner

go run . --sender=6ab5fbf652da1467169cd68dd5dc9e82331d2cf17eb64e9a5b8b644dcb0e3d19 --receiver=8bcd8b1c3e3487743ed7caf19b688f83d6f86cf7d246bc71d5f7d322a64189f7 --amount=500