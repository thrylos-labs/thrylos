To run the testnet in terminal type:

Navigate to the directory containing your main.go using: 
cd cmd/thrylosnode

By starting with new addresses, you can test how the system handles initialization, empty blocks, new transactions, and other edge cases more effectively.

then:
go run main.go --address=localhost:8080 --data=./node_data --testnet

Update the secure_accounts.json with the new addresses and info from the testnet

To run the cli signer to sign the transactions in terminal type:

Navigate to the directory containing your main.go using: 
cd cmd/clisigner

Sign the transaction: 

go run cli_signer.go -address="6ab5fbf652da1467169cd68dd5dc9e82331d2cf17eb64e9a5b8b644dcb0e3d19" -transaction='{"sender": "6ab5fbf652da1467169cd68dd5dc9e82331d2cf17eb64e9a5b8b644dcb0e3d19", "recipient": "8bcd8b1c3e3487743ed7caf19b688f83d6f86cf7d246bc71d5f7d322a64189f7", "amount": 100}'

[
    {
        "Address": "6ab5fbf652da1467169cd68dd5dc9e82331d2cf17eb64e9a5b8b644dcb0e3d19",
        "PrivateKey": "K0ePAElFeRugR+zMlajHN+aAvnxs21g78Sg/0+IqOLfcMUho7QcGG8dPn7D5f5cMWyLHW1kMSVLeyzjKXTz0zw==",
        "PublicKey": "dc314868ed07061bc74f9fb0f97f970c5b22c75b590c4952decb38ca5d3cf4cf"
    },
    {
        "Address": "8bcd8b1c3e3487743ed7caf19b688f83d6f86cf7d246bc71d5f7d322a64189f7",
        "PrivateKey": "MQedW0vZ6LhJXiZ5X53yZ84R8oFUYwFPezV9UgOxGE6nGGfYlA/cB8Foyyhphrj1/su8uMrBQGAct+skC1Lj4Q==",
        "PublicKey": "a71867d8940fdc07c168cb286986b8f5fecbbcb8cac140601cb7eb240b52e3e1"
    }
]





Retreive the public key first:

 Before attempting another transaction submission, directly test the retrieval function for the public key in your code to confirm that it can indeed find and return the correct key. This can help isolate the issue:


Sugmit the transaction using Curl:

curl -X POST -H "Content-Type: application/json" -d '{
    "sender": "6ab5fbf652da1467169cd68dd5dc9e82331d2cf17eb64e9a5b8b644dcb0e3d19",
    "recipient": "8bcd8b1c3e3487743ed7caf19b688f83d6f86cf7d246bc71d5f7d322a64189f7",
    "amount": 100,
    "signature": "zgxBpq439sTVn1qLOaALzqHdtYbmyBuZpajGZceXZd4oZiHwhDGfGEbM+OVLuo7UOdtQowAsfxql3EgcegGBA==",
    "inputs": [
        {
            "transactionId": "genesis_6ab5fbf652da1467169cd68dd5dc9e82331d2cf17eb64e9a5b8b644dcb0e3d19",
            "outputIndex": 0,
            "signature": "zgxBpq439sTVn1qLOaALzqHdtYbmyBuZpajGZceXZd4oZiHwhDGfGEbM+OVLuo7UOdtQowAsfxql3EgcegGBA=="
        }
    ]
}' http://localhost:8080/submit-transaction



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