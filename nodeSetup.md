Configuration Options:

Navigate to the directory containing your main.go using 'cd cmd'

Run the first node: go run main.go --address=localhost:8080 --data=./node1_data

Start Subsequent Nodes with Peers:
Once the first node is running, you can start other nodes and specify the first node as a known peer.

go run main.go --address=localhost:8081 --peers=http://localhost:8080 --data=./node2_data

This way, the new node at localhost:8081 will attempt to connect with the existing node at localhost:8080.

By following these steps, you'll establish a local blockchain network where nodes are aware of each other and can synchronize data, allowing you to test the network's functionality more effectively.

Interacting with the Node:

Submit Transaction: Send a POST request to /submit-transaction with a transaction payload.
Get Block: Retrieve a block by its ID by sending a GET request to /get-block?id=<block_id>.
Get Transaction: Fetch a transaction by itts ID through a GET request to /get-transaction?id=<transaction_id>.

This setup assumes that you will adapt the handlers (SubmitTransactionHandler, GetBlockHandler, and GetTransactionHandler) to fit your actual implementation. Each handler should encapsulate the logic for handling its respective request, interacting with the blockchain stored within the Node instance.

Remember, running a node requires keeping your application and dependencies up to date to ensure compatibility and security with the network. Always test your node in a controlled environment before connecting to a live network. 