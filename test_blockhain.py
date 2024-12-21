import pytest
from hashlib import sha256 as hash256
from blockhain import sha256, merkle_tree


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
