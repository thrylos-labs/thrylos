cd cmd/thrylosnode

go run main.go --address=localhost:8080 --data=./node_data --testnet

How to run a test sending a transaction:

cd cmd/clisigner

go run . --sender=6ab5fbf652da1467169cd68dd5dc9e82331d2cf17eb64e9a5b8b644dcb0e3d19 --receiver=8bcd8b1c3e3487743ed7caf19b688f83d6f86cf7d246bc71d5f7d322a64189f7 --amount=500

