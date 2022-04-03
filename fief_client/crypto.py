import base64
import hashlib
import secrets


def get_validation_hash(value: str) -> str:
    hasher = hashlib.sha256()
    hasher.update(value.encode("utf-8"))
    hash = hasher.digest()

    half_hash = hash[0 : int(len(hash) / 2)]
    # Remove the Base64 padding "==" at the end
    base64_hash = base64.urlsafe_b64encode(half_hash)[:-2]

    return base64_hash.decode("utf-8")


def is_valid_hash(value: str, hash: str) -> bool:
    value_hash = get_validation_hash(value)
    return secrets.compare_digest(value_hash, hash)
