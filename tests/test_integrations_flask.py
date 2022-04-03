from typing import Generator

import pytest
from flask import Flask, g
from flask.testing import FlaskClient

from fief_client.client import Fief
from fief_client.integrations.flask import (
    FiefAuth,
    FiefAuthForbidden,
    FiefAuthUnauthorized,
    get_authorization_scheme_token,
    get_cookie,
)


@pytest.fixture(scope="module")
def fief_client() -> Fief:
    return Fief("https://bretagne.fief.dev", "CLIENT_ID", "CLIENT_SECRET")


@pytest.fixture(scope="module")
def flask_app(fief_client: Fief) -> Generator[Flask, None, None]:
    auth = FiefAuth(fief_client, get_authorization_scheme_token())
    app = Flask(__name__)
    app.config.update({"TESTING": True})

    @app.errorhandler(FiefAuthUnauthorized)
    def fief_unauthorized_error(e):
        return "", 401

    @app.errorhandler(FiefAuthForbidden)
    def fief_forbidden_error(e):
        return "", 403

    @app.get("/current-user")
    @auth.current_user()
    def get_current_user():
        return g.user

    @app.get("/current-user-scope")
    @auth.current_user(scope=["required_scope"])
    def get_current_user_scope():
        return g.user

    yield app


@pytest.fixture
def test_client(flask_app: Flask) -> FlaskClient:
    return flask_app.test_client()


def test_missing_token(test_client: FlaskClient):
    response = test_client.get("/current-user")

    assert response.status_code == 401


def test_invalid_authorization_header(test_client: FlaskClient):
    response = test_client.get("/current-user", headers={"Authorization": "TOKEN"})

    assert response.status_code == 401


def test_expired_token(test_client: FlaskClient, generate_token):
    access_token = generate_token(encrypt=False, exp=0)

    response = test_client.get(
        "/current-user", headers={"Authorization": f"Bearer {access_token}"}
    )

    assert response.status_code == 401


def test_valid_token(test_client: FlaskClient, generate_token, user_id: str):
    access_token = generate_token(encrypt=False, scope="openid")

    response = test_client.get(
        "/current-user", headers={"Authorization": f"Bearer {access_token}"}
    )

    assert response.status_code == 200

    json = response.json
    assert json == {"id": user_id, "scope": ["openid"], "access_token": access_token}


def test_missing_scope(test_client: FlaskClient, generate_token):
    access_token = generate_token(encrypt=False, scope="openid")

    response = test_client.get(
        "/current-user-scope", headers={"Authorization": f"Bearer {access_token}"}
    )

    assert response.status_code == 403


def test_valid_scope(test_client: FlaskClient, generate_token, user_id: str):
    access_token = generate_token(encrypt=False, scope="openid required_scope")

    response = test_client.get(
        "/current-user-scope", headers={"Authorization": f"Bearer {access_token}"}
    )

    assert response.status_code == 200

    json = response.json
    assert json == {
        "id": user_id,
        "scope": ["openid", "required_scope"],
        "access_token": access_token,
    }


def test_get_cookie():
    cookie_getter = get_cookie("COOKIE_NAME")
    app = Flask(__name__)
    with app.test_request_context():
        result = cookie_getter()
        assert result is None

    with app.test_request_context(headers={"Cookie": "COOKIE_NAME=VALUE"}):
        result = cookie_getter()
        assert result == "VALUE"
