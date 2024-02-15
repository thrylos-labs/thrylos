# Thrylos Blockchain Project

Welcome to our Blockchain Project, an open-source initiative designed to revolutionize the way transactions are managed and recorded. Developed in Go, this platform emphasizes security, efficiency, and decentralization, offering a robust solution for maintaining a transparent ledger.

## Quick Start

Jump into action with these simple steps:

1. **Set Up**: Clone the repository to your local machine.
2. **Navigate**: Change directory to `cmd`.
3. **Run**: Execute `go run main.go` in your terminal.

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

### SQLite Database
- **Utility**: Stores blockchain data (blocks and transactions), ensuring durability and swift access.
- **Features**: Offers a solid foundation for blockchain persistence and efficient data queries.

### BlockchainDB
- **Overview**: An abstraction over SQLite, tailored for blockchain operations.
- **Capabilities**: Handles transaction additions, UTXO retrieval, and UTXO set updates, streamlining database interactions.

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