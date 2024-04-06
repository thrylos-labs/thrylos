Configuration Options:

Navigate to the directory containing your main.go using 'cd cmd'

First, start a node on localhost:8080 if it is supposed to be a peer:

Start the nodes in any order, but ensure all are running:










address: Specifies the network address the node should listen on. Example usage: --address=localhost:8080
peers: A comma-separated list of addresses of known peers in the network. This helps the node to quickly connect and synchronize with the network. Example usage: --peers=localhost:8081,localhost:8082
Running the Node:

Ensure you have Go installed on your machine.
Navigate to the directory containing your main.go using 'cd cmd'
Compile your project or run it directly using 'go run main.go'


For example run: 

go run main.go --address=localhost:8080 --peers=localhost:8081,localhost:8082

or try: 

go run main.go --address=localhost:8080 --peers=http://localhost:8081,http://localhost:8082


This command will start the node, which will listen on the specified address and attempt to connect to the peers.

Your node will start and attempt to connect to the provided peers, synchronize the blockchain, and listen for incoming requests.

Interacting with the Node:

Submit Transaction: Send a POST request to /submit-transaction with a transaction payload.
Get Block: Retrieve a block by its ID by sending a GET request to /get-block?id=<block_id>.
Get Transaction: Fetch a transaction by itts ID through a GET request to /get-transaction?id=<transaction_id>.

This setup assumes that you will adapt the handlers (SubmitTransactionHandler, GetBlockHandler, and GetTransactionHandler) to fit your actual implementation. Each handler should encapsulate the logic for handling its respective request, interacting with the blockchain stored within the Node instance.

Remember, running a node requires keeping your application and dependencies up to date to ensure compatibility and security with the network. Always test your node in a controlled environment before connecting to a live network. 