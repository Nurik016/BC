import pytest
from hashlib import sha256 as hash256
from blockchain import sha256, merkle_tree, Block, Blockchain


def test_hash():
    assert sha256("hello") == hash256("hello".encode('utf-8')).hexdigest()
    assert sha256("12345") == hash256("12345".encode('utf-8')).hexdigest()
    assert sha256("hello") != sha256("world")


def test_merkle_tree():
    transactions = [
        "Alice sends 1 BTC to Bob",
        "Bob sends 0.5 BTC to Charlie",
        "Charlie sends 0.2 BTC to Dave",
        "Eve sends 0.1 BTC to Alice"
    ]

    merkle_root = merkle_tree(transactions)
    assert isinstance(merkle_root, str)
    assert len(merkle_root) == 64

    single_transaction = [sha256("Alice pays Bob 10")]
    assert merkle_tree(single_transaction) == single_transaction[0]

    transactions_odd = [
        sha256("Alice pays Bob 10"),
        sha256("Bob pays Charlie 5"),
        sha256("Charlie pays Dave 2")
    ]
    merkle_root_odd = merkle_tree(transactions_odd)
    assert isinstance(merkle_root_odd, str)
    assert len(merkle_root_odd) == 64


def test_block():
    transactions = ["Alice pays Bob 10", "Bob pays Charlie 5"]
    previous_hash = sha256("previous block")
    block = Block(1, previous_hash, transactions)

    assert block.index == 1
    assert block.previous_hash == previous_hash
    assert len(block.merkle_root) == 64
    assert block.hash == block.calculate_hash()

    # Test mining
    block.mine_block(difficulty=2)
    assert block.hash.startswith("00")


def test_blockchain():
    blockchain = Blockchain(difficulty=2)

    # Validate genesis block
    genesis_block = blockchain.chain[0]
    assert genesis_block.index == 0
    assert genesis_block.previous_hash == "0"
    assert genesis_block.transactions == ["Genesis Block"]
    assert genesis_block.hash == genesis_block.calculate_hash()

    # Add a block and validate
    blockchain.add_block(["Alice pays Bob 10", "Bob pays Charlie 5"])
    assert len(blockchain.chain) == 2
    new_block = blockchain.chain[1]
    assert new_block.index == 1
    assert new_block.previous_hash == genesis_block.hash

    # Validate blockchain integrity
    assert blockchain.validate_blockchain()

    # Tamper with the blockchain
    blockchain.chain[1].transactions = ["Tampered data"]
    assert not blockchain.validate_blockchain()


if __name__ == "__main__":
    pytest.main()
