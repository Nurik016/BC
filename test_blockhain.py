import pytest
from hashlib import sha256 as hash256
from blockhain import sha256, merkle_tree
import time


class Block:
    def __init__(self, index, previous_hash, transactions):
        self.index = index
        self.previous_hash = previous_hash
        self.timestamp = time.time()
        self.transactions = transactions
        self.merkle_root = merkle_tree([sha256(tx) for tx in transactions])
        self.nonce = 0
        self.hash = self.calculate_hash()

    def calculate_hash(self):
        block_data = (
            str(self.index)
            + self.previous_hash
            + str(self.timestamp)
            + self.merkle_root
            + str(self.nonce)
        )
        return sha256(block_data)

    def mine_block(self, difficulty):
        target = "0" * difficulty
        while not self.hash.startswith(target):
            self.nonce += 1
            self.hash = self.calculate_hash()




def test_hash():
    assert sha256("hello") == hash256("hello".encode('utf-8')).hexdigest()
    assert sha256("12345") == hash256("12345".encode('utf-8')).hexdigest()
    assert sha256("hello") != sha256("world")


def test_merkle_tree():
    transactions = [
        sha256("Alice pays Bob 10"),
        sha256("Bob pays Charlie 5"),
        sha256("Charlie pays Dave 2"),
        sha256("Dave pays Eve 1")
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


if __name__ == "__main__":
    pytest.main()
