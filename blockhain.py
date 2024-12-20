import hashlib

# for sha256 hash
def hash(text):
    return hashlib.sha256(text.encode('utf-8')).hexdigest()


# Func for tree and get root hash
def merkle_tree(transactions):
    if len(transactions) == 1:
        return transactions[0]

    new_level = []
    for i in range(0, len(transactions), 2):
        combined = transactions[i] + (transactions[i + 1] if i + 1 < len(transactions) else transactions[i])
        new_level.append(hash(combined))

    return merkle_tree(new_level)