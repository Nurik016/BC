import pytest
from hashlib import sha256
from blockhain import hash, merkle_tree


def test_hash():
    assert hash("hello") == sha256("hello".encode('utf-8')).hexdigest()
    assert hash("12345") == sha256("12345".encode('utf-8')).hexdigest()
    assert hash("hello") != hash("world")


def test_merkle_tree():
    transactions = [
        hash("Alice pays Bob 10"),
        hash("Bob pays Charlie 5"),
        hash("Charlie pays Dave 2"),
        hash("Dave pays Eve 1")
    ]

    merkle_root = merkle_tree(transactions)
    assert isinstance(merkle_root, str)
    assert len(merkle_root) == 64

    single_transaction = [hash("Alice pays Bob 10")]
    assert merkle_tree(single_transaction) == single_transaction[0]

    transactions_odd = [
        hash("Alice pays Bob 10"),
        hash("Bob pays Charlie 5"),
        hash("Charlie pays Dave 2")
    ]
    merkle_root_odd = merkle_tree(transactions_odd)
    assert isinstance(merkle_root_odd, str)
    assert len(merkle_root_odd) == 64


if __name__ == "__main__":
    pytest.main()
