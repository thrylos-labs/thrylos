# Thrylos Blockchain Project

Welcome to our Blockchain Project, an open-source blockchain, developed in Go. This platform emphasizes security, efficiency, and decentralization, offering a robust solution for maintaining a transparent ledger.

## Quick Start

Jump into action with these simple steps:

1. **Set Up**: Clone the repository to your local machine.

2. **Generate AES Key**: This key needs to be generated for encryption.

3. **Create a .env file**: in the .env file it needs to have the following:

ENV=development
HTTP_NODE_ADDRESS=localhost:8546
GRPC_NODE_ADDRESS=localhost:50051
WS_NODE_ADDRESS=localhost:8444
DOMAIN_NAME=
PEERS=XXXXXXXXX
DATA=./blockchain_data
TESTNET=true
AES_KEY_ENV_VAR=XXXXXXXXX
DATA_DIR=/database
GENESIS_ACCOUNT=XXXXXXXXX
GAS_ESTIMATE_URL=https://localhost:8546/api/gas-estimate


4. **Run_Thrylos**: Execute `./run_thrylos.sh` in your terminal to run thyrlos testnet in development. Try 'run_thrylos' just in the terminal

How to run manaully without using run_thrylos.sh:

**Navigate**: In terminal change directory to `cd cmd/thrylos`.

**Run**: Execute `'export ENV=development'` in your terminal. 

**Run**: Execute `'go run .'` in your terminal. 

If you delete the blockchain_data the account and balances will be wiped

## Inside the Blockchain

Dive deeper into the core components that power our blockchain:

### Blocks
- **Purpose**: Serve as the backbone, housing transactions, linking to the previous block via hash, and ensuring integrity through their own hash.
- **Role**: Create an immutable chain, securing the ledger's history.

### Transactions
- **Function**: Facilitate asset exchange between parties, backed by signatures for authenticity.
- **Significance**: Act as the heartbeat of our blockchain, enabling decentralized finance.

### Blockchain
- **Description**: A chain of blocks, each connected by hashes, functioning as the public ledger for all transactions.
- **Utility**: Ensures transparency, security, and accessibility of transaction records.

## Data Management

### Badger Database
- **Utility**: Stores blockchain data (blocks and transactions), ensuring durability and swift access.
- **Features**: Offers a solid foundation for blockchain persistence and efficient data queries.

### BlockchainDB
- **Overview**: An abstraction over Badger, tailored for blockchain operations.
- **Capabilities**: Handles transaction additions, UTXO retrieval, and UTXO set updates, streamlining database interactions.

## How transactions flow through the system

Entry Point:

Transaction Entry:
Client submits a signed transaction
System performs basic validation (signature, format, etc.)

Parallel Processing:
DAG Manager: Needs 5+ references to confirm transaction
Modern Processor: Verifies transaction validity and details
Both must complete before proceeding

State Management:
System determines which shard handles the addresses (using tl1 prefix)
Updates state in the correct partition
Manages balances and UTXOs for that address range

Block Creation:
Validated transactions go to pending pool
Creates blocks when:

100 transactions are ready (batch size), or
Every 200ms if transactions are pending
Processes transactions in batches

Final Updates:
Updates balances in the appropriate shards
Cleans up transaction state
Notifies relevant parts of the system

The key innovation is that each step knows which shard to interact with based on the address prefix (tl1), allowing the system to scale horizontally.

## When are blocks created

blocks are only created when there are pending transactions (hasPendingTx := len(node.PendingTransactions) > 0) and enough time has passed since the last block (timeSinceLastBlock >= targetBlockTime)

The system checks these conditions every 200ms (checkInterval).
Two ways blocks get triggered:

Timer based: If pending transactions exist and block time requirement is met
Batch based: When pending transactions reach batch size (100 transactions)

If no transactions are being sent through the system:

No blocks will be created
The timer will keep checking but take no action
System remains idle until new transactions arrive

This is efficient because we're not creating empty blocks unnecessarily - blocks are only created when there's actual work to be done.

## Interfacing with the Blockchain

### HTTP Server
- **Initiation**: Launches alongside the blockchain, opening a gateway for user interactions on a designated port.
- **Endpoints**: Features a variety of access points for blockchain interaction, including transaction submissions and status checks.

### Handling Requests
- **Process**: Parses and validates incoming requests, translating them into blockchain actions like adding transactions or validating the chain's integrity.

## Efficient Data Handling

### Protobuf Serialization
- **Advantage**: Ensures data is compact and efficiently stored or transmitted, using Google's Protobuf for serialization.
- **Conversion**: Bridges the gap between Go's native data structures and Protobuf's binary format, facilitating seamless data operations.

## VerkleTree
- **Purpose**: Enhances the efficiency and scalability of data storage and retrieval in the blockchain.
- **Functionality**: Implements a novel data structure for organizing transactions in a compact, efficient manner, reducing the size of proof and improving verification times.
- **Integration**: Used within the blockchain to form a succinct, cryptographically secure representation of transaction states, facilitating quicker and lighter consensus verification.

## Engaging with the Blockchain

1. **Start**: Initialization kicks off with the blockchain and HTTP server, loading the current state from the database.
2. **Interact**: Submit transactions, query data, and explore the blockchain through our intuitive HTTP endpoints.
3. **Contribute**: Enhance the ecosystem by adding transactions, creating blocks, and maintaining the network's integrity.

## Contributing

Join our mission to make decentralized transactions the norm. Here's how you can contribute:

- **Get Started**: Fork the repo, then create a feature or bug fix branch.
- **Follow Guidelines**: Adhere to our coding standards and commit message conventions.
- **Test Rigorously**: Ensure your changes are thoroughly tested.
- **Submit a PR**: Push your branch and open a pull request.

### Community Guidelines

We're committed to fostering an inclusive environment. Please review our [Code of Conduct](./CODE_OF_CONDUCT.md) to understand our community standards.

### Reporting Security Issues

Stumbled upon a security flaw? Email us at hello@thrylos.org. Let's keep our discussions private until we've addressed the issue.

## License

This project is proudly licensed under the MIT License. For more details, see the [LICENSE](./LICENSE) file.