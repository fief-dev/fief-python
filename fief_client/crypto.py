import base64
import hashlib
import secrets


def get_validation_hash(value: str) -> str:
    """
    Return the validation hash of a value.

    Useful to check the validity `c_hash` and `at_hash` claims.
    """
    hasher = hashlib.sha256()
    hasher.update(value.encode("utf-8"))
    hash = hasher.digest()

    half_hash = hash[0 : int(len(hash) / 2)]
    # Remove the Base64 padding "==" at the end
    base64_hash = base64.urlsafe_b64encode(half_hash)[:-2]

    return base64_hash.decode("utf-8")


def is_valid_hash(value: str, hash: str) -> bool:
    """
    Check if a hash corresponds to the provided value.

    Useful to check the validity `c_hash` and `at_hash` claims.
    """
    value_hash = get_validation_hash(value)
    return secrets.compare_digest(value_hash, hash)
