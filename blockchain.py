import time
import random
from math import gcd


def right_rotate(value, bits):
    return ((value >> bits) | (value << (32 - bits))) & 0xFFFFFFFF


def sha256(text):
    # Constants defined by the SHA-256 standard
    k = [
        0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
        0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
        0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
        0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
        0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
        0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
        0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
        0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
    ]

    # Initial hash values
    h = [
        0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19
    ]

    # Preprocessing
    message = bytearray(text, 'utf-8')
    original_length_bits = len(message) * 8
    message.append(0x80)

    while (len(message) * 8 + 64) % 512 != 0:
        message.append(0)

    message += original_length_bits.to_bytes(8, 'big')

    # Process the message in 512-bit chunks
    for chunk_start in range(0, len(message), 64):
        chunk = message[chunk_start:chunk_start + 64]

        # Prepare the message schedule
        w = [int.from_bytes(chunk[i:i+4], 'big') for i in range(0, 64, 4)]
        for i in range(16, 64):
            s0 = right_rotate(w[i-15], 7) ^ right_rotate(w[i-15], 18) ^ (w[i-15] >> 3)
            s1 = right_rotate(w[i-2], 17) ^ right_rotate(w[i-2], 19) ^ (w[i-2] >> 10)
            w.append((w[i-16] + s0 + w[i-7] + s1) & 0xFFFFFFFF)

        # Initialize working variables
        a, b, c, d, e, f, g, h_var = h

        # Main compression function
        for i in range(64):
            s1 = right_rotate(e, 6) ^ right_rotate(e, 11) ^ right_rotate(e, 25)
            ch = (e & f) ^ (~e & g)
            temp1 = (h_var + s1 + ch + k[i] + w[i]) & 0xFFFFFFFF
            s0 = right_rotate(a, 2) ^ right_rotate(a, 13) ^ right_rotate(a, 22)
            maj = (a & b) ^ (a & c) ^ (b & c)
            temp2 = (s0 + maj) & 0xFFFFFFFF

            h_var = g
            g = f
            f = e
            e = (d + temp1) & 0xFFFFFFFF
            d = c
            c = b
            b = a
            a = (temp1 + temp2) & 0xFFFFFFFF

        # Add the compressed chunk to the current hash value
        h = [
            (h[0] + a) & 0xFFFFFFFF,
            (h[1] + b) & 0xFFFFFFFF,
            (h[2] + c) & 0xFFFFFFFF,
            (h[3] + d) & 0xFFFFFFFF,
            (h[4] + e) & 0xFFFFFFFF,
            (h[5] + f) & 0xFFFFFFFF,
            (h[6] + g) & 0xFFFFFFFF,
            (h[7] + h_var) & 0xFFFFFFFF
        ]

    # Produce the final hash value (big-endian)
    return ''.join(f'{value:08x}' for value in h)


# Func for tree and get root hash
def merkle_tree(transactions):
    if len(transactions) == 1:
        return transactions[0]

    new_level = []
    for i in range(0, len(transactions), 2):
        combined = transactions[i] + (transactions[i + 1] if i + 1 < len(transactions) else transactions[i])
        new_level.append(sha256(combined))

    return merkle_tree(new_level)


# Helper functions for RSA
def is_prime(num):
    if num <= 1:
        return False
    if num <= 3:
        return True
    if num % 2 == 0 or num % 3 == 0:
        return False
    i = 5
    while i * i <= num:
        if num % i == 0 or num % (i + 2) == 0:
            return False
        i += 6
    return True


def generate_prime(bits=32):
    while True:
        num = random.getrandbits(bits)
        if is_prime(num):
            return num


# Key generation
def generate_keypair():
    p = generate_prime()
    q = generate_prime()
    while p == q:
        q = generate_prime()

    n = p * q
    phi = (p - 1) * (q - 1)

    e = random.randrange(2, phi)
    while gcd(e, phi) != 1:
        e = random.randrange(2, phi)

    d = pow(e, -1, phi)

    return ((e, n), (d, n))

# Encryption and decryption

def encrypt(public_key, message):
    e, n = public_key
    cipher = [pow(ord(char), e, n) for char in message]
    return cipher

def decrypt(private_key, ciphertext):
    d, n = private_key
    plain = ''.join([chr(pow(char, d, n)) for char in ciphertext])
    return plain

# Digital signature

def sign(private_key, document):
    d, n = private_key
    hash_value = hash(document)
    signature = pow(hash_value, d, n)
    return signature

def verify(public_key, document, signature):
    e, n = public_key
    hash_value = hash(document)
    decrypted_hash = pow(signature, e, n)
    return hash_value == decrypted_hash


# Block Class
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
        start_time = time.time()
        while not self.hash.startswith(target):
            self.nonce += 1
            self.hash = self.calculate_hash()
            if self.nonce % 100000 == 0:
                print(f"Nonce: {self.nonce}, Hash: {self.hash}")
        end_time = time.time()
        print(f"Block mined! Nonce: {self.nonce}, Hash: {self.hash}, Time: {end_time - start_time:.2f}s")


# Blockchain Class
class Blockchain:
    def __init__(self, difficulty=4):
        self.chain = [self.create_genesis_block()]
        self.difficulty = difficulty

    def create_genesis_block(self):
        return Block(0, "0", ["Genesis Block"])

    def add_block(self, transactions):
        previous_block = self.chain[-1]
        new_block = Block(len(self.chain), previous_block.hash, transactions)
        new_block.mine_block(self.difficulty)
        self.chain.append(new_block)

    def validate_blockchain(self):
        for i in range(1, len(self.chain)):
            current_block = self.chain[i]
            previous_block = self.chain[i - 1]

            if current_block.hash != current_block.calculate_hash():
                return False

            if current_block.previous_hash != previous_block.hash:
                return False

            recalculated_merkle_root = merkle_tree([sha256(tx) for tx in current_block.transactions])
            if current_block.merkle_root != recalculated_merkle_root:
                return False

        return True

# Transaction Class
class Transaction:
    def __init__(self, sender, receiver, amount, signature):
        self.sender = sender
        self.receiver = receiver
        self.amount = amount
        self.signature = signature

    def verify_transaction(self):
        return verify(self.sender, f"{self.receiver}{self.amount}", self.signature)

# Wallet Class
class Wallet:
    def __init__(self):
        self.private_key, self.public_key = generate_keypair()

    def create_transaction(self, receiver, amount):
        document = f"{receiver}{amount}"
        signature = sign(self.private_key, document)
        return Transaction(self.public_key, receiver, amount, signature)

