How to start the app in terminal
// cd cmd
// go run main.go

Core Blockchain Components
Blocks: Contain transactions, a reference to the previous block's hash, and their own hash. They form the immutable chain.
Transactions: Represent the movement of assets between parties. Each transaction is signed and verified for authenticity.
Blockchain: A sequence of blocks linked by hashes. It serves as a public ledger of all transactions.

Database Interactions
SQLite Database: Stores the blockchain data, including blocks and transactions. It provides persistence and enables efficient data retrieval.
BlockchainDB: An abstraction layer on top of the SQLite database. It handles blockchain-specific operations like adding transactions, retrieving UTXOs (Unspent Transaction Outputs), and updating the UTXO set.
HTTP Server Functionality

Initialization: The blockchain is initialized, and the HTTP server starts listening on a specified port. This serves as the entry point for user interactions.

Endpoints: The server exposes various endpoints, such as /status for fetching blockchain status and others for adding transactions, querying blockchain data, etc.

Request Handling: Incoming HTTP requests are parsed, validated, and processed. This involves interacting with the blockchain to add transactions, compute UTXOs, or validate the chain's integrity.

Protobuf Serialization
Protobuf (Protocol Buffers): Used for serializing the blockchain data, including transactions and blocks. It ensures a compact, efficient binary format that is both forward-compatible and backward-compatible.
Conversion Functions: To interface between the application's internal data structures (e.g., transactions as Go structs) and Protobuf's binary format, conversion functions are used. These functions convert back and forth as needed for operations like signing, verifying, or storing transactions.

User Flow Description
Initialization: The application starts by initializing the blockchain and the HTTP server. The blockchain loads existing data from the SQLite database, establishing the current state.
Transaction Submission: Users submit transactions through an HTTP endpoint. The server validates the request data, converts it into the blockchain's internal format using Protobuf, and then attempts to add the transaction to the blockchain.
Transaction Processing: The blockchain processes the transaction by verifying its signature, ensuring it doesn't spend more than available in the input UTXOs, and updating the UTXO set accordingly.
Block Creation: Periodically or upon certain conditions (like reaching a transaction limit), new blocks are created, containing a set of verified transactions. These blocks are added to the blockchain after validation.
Blockchain Validation: At various points, the blockchain's integrity is checked, ensuring that blocks are correctly linked and data hasn't been tampered with.
Querying Data: Users can query blockchain data, such as transaction history or the status of the blockchain, through specific HTTP endpoints. The server retrieves this data from the blockchain and the database, presenting it to the user in a readable format.
This setup provides a secure, persistent, and accessible blockchain system. Protobuf ensures efficient data handling, while the HTTP server interface allows for easy interaction with the blockchain system.