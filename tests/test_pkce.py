import pytest

from fief_client.pkce import Method, get_code_challenge, get_code_verifier


def test_get_code_verifier():
    code = get_code_verifier()
    assert isinstance(code, str)
    assert len(code) == 128


@pytest.mark.parametrize(
    "code,method",
    [
        ("A" * 128, "plain"),
        ("A" * 128, "S256"),
    ],
)
def test_code_challenge(code: str, method: Method):
    challenge = get_code_challenge(code, method)
    assert isinstance(challenge, str)

    if method == "plain":
        assert challenge == code
    elif method == "S256":
        assert len(challenge) == 43
