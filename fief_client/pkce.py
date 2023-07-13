import base64
import hashlib
import secrets
from typing import Literal


def get_code_verifier() -> str:
    """
    Generate a code verifier suitable for PKCE.
    """
    return secrets.token_urlsafe(96)


Method = Literal["plain", "S256"]


def get_code_challenge(code: str, method: Method = "S256") -> str:
    """
    Generate the PKCE code challenge for the given code and method.

    :param code: The code to generate the challenge for.
    :param method: The method to use for generating the challenge. Either `plain` or `S256`.
    """
    if method == "plain":
        return code

    if method == "S256":
        hasher = hashlib.sha256()
        hasher.update(code.encode("ascii"))
        digest = hasher.digest()
        b64_digest = base64.urlsafe_b64encode(digest).decode("ascii")
        return b64_digest[:-1]  # Remove the padding "=" at the end
