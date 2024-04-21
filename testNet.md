To run the testnet in terminal type:

Navigate to the directory containing your main.go using: 
cd cmd/thrylosnode

Then run: 
export AES_KEY_ENV_VAR='b8Eq7a0EWz06Ova4VNRN8ad6TkzCZkxNXm926rtNM2I='

then: 
go run main.go --address=localhost:8080 --data=./node_data --testnet

To run the cli signer to sign the transactions in terminal type:

Navigate to the directory containing your main.go using: 
cd cmd/clisigner

Sign the transaction: 

go run cli_signer.go -address="ad6675d7db1245a58c9ce1273bf66a79063d3574b5c917fbb007e83736bd839c" -transaction='{"sender": "ad6675d7db1245a58c9ce1273bf66a79063d3574b5c917fbb007e83736bd839c", "recipient": "523202816395084d5f100f03f6787560c4b1048ed1872fe8b4647cfabc41e2c0", "amount": 100}'


Sugmit the transaction using Curl:

curl -X POST http://localhost:8080/submit-transaction \
-H "Content-Type: application/json" \
-d '{
    "inputs": [
        {
            "previousTx": "abcd1234",
            "index": 0,
            "signature": "T+z9qyQaNpMiSS08SAECNRgFyhe4JGT8sggchkJZ5MxdIVs1k7Z0vHJUN77S1k8q4CmeiJ0KVLJCwFX6pzGABA=="
        }
    ],
    "outputs": [
        {
            "amount": 100,
            "address": "523202816395084d5f100f03f6787560c4b1048ed1872fe8b4647cfabc41e2c0"
        }
    ],
    "sender": "ad6675d7db1245a58c9ce1273bf66a79063d3574b5c917fbb007e83736bd839c",
    "recipient": "523202816395084d5f100f03f6787560c4b1048ed1872fe8b4647cfabc41e2c0",
    "amount": 100,
    "signature": "T+z9qyQaNpMiSS08SAECNRgFyhe4JGT8sggchkJZ5MxdIVs1k7Z0vHJUN77S1k8q4CmeiJ0KVLJCwFX6pzGABA=="
}'


Summary
Generate Transaction Data: Define the essential attributes of your transaction, like sender, recipient, and amount.
Sign the Transaction: Use your CLI utility to sign the transaction data, generating a digital signature.
Submit the Transaction: Send the signed transaction to your blockchain network for processing.



curl -X POST http://localhost:8080/submit-transaction \
-H "Content-Type: application/json" \
-d '{
  "inputs": [
    {
      "previousTx": "0000000000000000000000000000000000000000000000000000000000000000",
      "index": 0,
      "signature": "test_signature",
      "ownerAddress": "5d736a7b5896d873cc640f729b7b14e38dabc568de075e309efb97ac0cff2570"
    }
  ],
  "outputs": [
    {
      "amount": 100,
      "address": "e66308a7b7cd63c73c99ea6e9939318667916f83664eafb143b3044f80a591bd"
    }
  ]
}'
