from blockchain import *

blockchain = Blockchain(difficulty=4)

alice_wallet = Wallet()
bob_wallet = Wallet()

transaction1 = alice_wallet.create_transaction(bob_wallet.public_key, 100)
transaction2 = bob_wallet.create_transaction(alice_wallet.public_key, 50)

blockchain.add_block([str(transaction1), str(transaction2)])

for block in blockchain.chain:
    print(f"Block #{block.index}")
    print(f"Timestamp: {block.timestamp}")
    print(f"Previous Hash: {block.previous_hash}")
    print(f"Merkle Root: {block.merkle_root}")
    print(f"Hash: {block.hash}")
    print(f"Nonce: {block.nonce}")
    print(f"Transactions: {block.transactions}")
    print("-" * 40)

if blockchain.validate_blockchain():
    print("Blockchain is valid.")
else:
    print("Blockchain is invalid.")
