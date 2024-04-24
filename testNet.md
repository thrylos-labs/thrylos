To run the testnet in terminal type:

Navigate to the directory containing your main.go using: 
cd cmd/thrylosnode

Then run the encryption: 
export AES_KEY_ENV_VAR='b8Eq7a0EWz06Ova4VNRN8ad6TkzCZkxNXm926rtNM2I='

By starting with new addresses, you can test how the system handles initialization, empty blocks, new transactions, and other edge cases more effectively.

then:
go run main.go --address=localhost:8080 --data=./node_data --testnet

Update the secure_accounts.json with the new addresses and info from the testnet

To run the cli signer to sign the transactions in terminal type:

Navigate to the directory containing your main.go using: 
cd cmd/clisigner

Sign the transaction: 

go run cli_signer.go -address="4a1740103cc6827e5548224213d55a1035e4e6d9b7c6cde9d64ea89a080701cb" -transaction='{"sender": "4a1740103cc6827e5548224213d55a1035e4e6d9b7c6cde9d64ea89a080701cb", "recipient": "08052616d698ab065244ef85894ce51df4a51eb111aea77817926178898fae66", "amount": 100}'


Sugmit the transaction using Curl:

curl -X POST http://localhost:8080/submit-transaction \
  -H "Content-Type: application/json" \
  -d '{
    "inputs": [
      {
        "previousTx": "genesis_d6df6065959c403051e8bf5dd33c05a62cb7edb27c4b5c6e90b7975a720b3c43",
        "index": 0,
        "signature": "VO3zzLTQqctS9kZ+lh2AZ1rGbHfe6TyDu5wFUJFr309ghlIt5NOm1YgbauEJcTQoMdNj3wNnUwB5uatPsSoXCw==",
        "ownerAddress": "d6df6065959c403051e8bf5dd33c05a62cb7edb27c4b5c6e90b7975a720b3c43"
      }
    ],
    "outputs": [
      {
        "amount": 100,
        "address": "ee118296485e39cc8818e6c89fc4104cc29c2d51a415c5627281a339a6ec5d3d"
      },
      {
        "amount": 900,
        "address": "d6df6065959c403051e8bf5dd33c05a62cb7edb27c4b5c6e90b7975a720b3c43"
      }
    ]
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
            "previousTx": "abcd1234",  # Replace with the actual transaction ID from your blockchain
            "index": 0,
            "signature": "OerEAtzxvz6Lpp3BUqhIpjGPmWRfrQ39hsyi+rk+C2EChXQvFPshbrXSIWnu5soDgle3yem8LGe6mRrx4nZGCQ=="  
        }
    ],
    "outputs": [
        {
            "amount": 100,
            "address": "276b3b8a5fa2e9bfba6c9c535440e13906ba2ad0aa45e8ffea398cd13f564515"
        }
    ],
    "sender": "83bd6c7abd525db141737207aa170c539581b57685158512e6ca78da463bf801",
    "recipient": "276b3b8a5fa2e9bfba6c9c535440e13906ba2ad0aa45e8ffea398cd13f564515",
    "amount": 100,
    "signature": "OerEAtzxvz6Lpp3BUqhIpjGPmWRfrQ39hsyi+rk+C2EChXQvFPshbrXSIWnu5soDgle3yem8LGe6mRrx4nZGCQ=="  
}