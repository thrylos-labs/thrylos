Configuration Options:

address: Specifies the network address the node should listen on. Example usage: --address=localhost:8080
peers: A comma-separated list of addresses of known peers in the network. This helps the node to quickly connect and synchronize with the network. Example usage: --peers=localhost:8081,localhost:8082
Running the Node:

Ensure you have Go installed on your machine.
Navigate to the directory containing your main.go.
Compile your project or run it directly using go run main.go --address=<your_address> --peers=<peer1_address,peer2_address>.
Your node will start and attempt to connect to the provided peers, synchronize the blockchain, and listen for incoming requests.
Interacting with the Node:

Submit Transaction: Send a POST request to /submit-transaction with a transaction payload.
Get Block: Retrieve a block by its ID by sending a GET request to /get-block?id=<block_id>.
Get Transaction: Fetch a transaction by itts ID through a GET request to /get-transaction?id=<transaction_id>.
This setup assumes that you will adapt the handlers (SubmitTransactionHandler, GetBlockHandler, and GetTransactionHandler) to fit your actual implementation. Each handler should encapsulate the logic for handling its respective request, interacting with the blockchain stored within the Node instance.

Remember, running a node requires keeping your application and dependencies up to date to ensure compatibility and security with the network. Always test your node in a controlled environment before connecting to a live network.