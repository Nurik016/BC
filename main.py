from blockchain import *


blockchain = Blockchain(difficulty=4)

blockchain.add_block(["Transaction 1", "Transaction 2", "Transaction 3"])
blockchain.add_block(["Transaction 4", "Transaction 5"])

for block in blockchain.chain:
    print(f"Block #{block.index}")
    print(f"Timestamp: {block.timestamp}")
    print(f"Previous Hash: {block.previous_hash}")
    print(f"Merkle Root: {block.merkle_root}")
    print(f"Hash: {block.hash}")
    print(f"Nonce: {block.nonce}")
    print("-" * 40)

if blockchain.validate_blockchain():
    print("Blockchain is valid.")
else:
    print("Blockchain is invalid.")
