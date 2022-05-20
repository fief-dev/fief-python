import uuid
from typing import Dict, Generator, Optional

import pytest
import respx
from flask import Flask, g, session
from flask.testing import FlaskClient
from httpx import Response

from fief_client.client import Fief, FiefUserInfo
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
    def get_userinfo_cache(id: uuid.UUID) -> Optional[FiefUserInfo]:
        return session.get(f"userinfo-{str(id)}")

    def set_userinfo_cache(id: uuid.UUID, userinfo: FiefUserInfo) -> None:
        session[f"userinfo-{str(id)}"] = userinfo

    auth = FiefAuth(
        fief_client,
        get_authorization_scheme_token(),
        get_userinfo_cache=get_userinfo_cache,
        set_userinfo_cache=set_userinfo_cache,
    )
    app = Flask(__name__)
    app.secret_key = "SECRET_KEY"
    app.config.update({"TESTING": True})

    @app.errorhandler(FiefAuthUnauthorized)
    def fief_unauthorized_error(e):
        return "", 401

    @app.errorhandler(FiefAuthForbidden)
    def fief_forbidden_error(e):
        return "", 403

    @app.get("/authenticated")
    @auth.authenticated()
    def get_authenticated():
        return g.access_token_info

    @app.get("/authenticated-scope")
    @auth.authenticated(scope=["required_scope"])
    def get_authenticated_scope():
        return g.access_token_info

    @app.get("/current-user")
    @auth.current_user()
    def get_current_user():
        return g.user

    @app.get("/current-user-refresh")
    @auth.current_user(refresh=True)
    def get_current_user_refresh():
        return g.user

    @app.get("/current-user-scope")
    @auth.current_user(scope=["required_scope"])
    def get_current_user_scope():
        return g.user

    yield app


@pytest.fixture
def test_client(flask_app: Flask) -> FlaskClient:
    return flask_app.test_client()


class TestAuthenticated:
    def test_missing_token(self, test_client: FlaskClient):
        response = test_client.get("/authenticated")

        assert response.status_code == 401

    def test_invalid_authorization_header(self, test_client: FlaskClient):
        response = test_client.get("/authenticated", headers={"Authorization": "TOKEN"})

        assert response.status_code == 401

    def test_expired_token(self, test_client: FlaskClient, generate_token):
        access_token = generate_token(encrypt=False, exp=0)

        response = test_client.get(
            "/authenticated", headers={"Authorization": f"Bearer {access_token}"}
        )

        assert response.status_code == 401

    def test_valid_token(self, test_client: FlaskClient, generate_token, user_id: str):
        access_token = generate_token(encrypt=False, scope="openid")

        response = test_client.get(
            "/authenticated", headers={"Authorization": f"Bearer {access_token}"}
        )

        assert response.status_code == 200

        json = response.json
        assert json == {
            "id": user_id,
            "scope": ["openid"],
            "access_token": access_token,
        }

    def test_missing_scope(self, test_client: FlaskClient, generate_token):
        access_token = generate_token(encrypt=False, scope="openid")

        response = test_client.get(
            "/authenticated-scope", headers={"Authorization": f"Bearer {access_token}"}
        )

        assert response.status_code == 403

    def test_valid_scope(self, test_client: FlaskClient, generate_token, user_id: str):
        access_token = generate_token(encrypt=False, scope="openid required_scope")

        response = test_client.get(
            "/authenticated-scope", headers={"Authorization": f"Bearer {access_token}"}
        )

        assert response.status_code == 200

        json = response.json
        assert json == {
            "id": user_id,
            "scope": ["openid", "required_scope"],
            "access_token": access_token,
        }


class TestCurrentUser:
    def test_missing_token(self, test_client: FlaskClient):
        response = test_client.get("/current-user")

        assert response.status_code == 401

    def test_invalid_authorization_header(self, test_client: FlaskClient):
        response = test_client.get("/current-user", headers={"Authorization": "TOKEN"})

        assert response.status_code == 401

    def test_expired_token(self, test_client: FlaskClient, generate_token):
        access_token = generate_token(encrypt=False, exp=0)

        response = test_client.get(
            "/current-user", headers={"Authorization": f"Bearer {access_token}"}
        )

        assert response.status_code == 401

    def test_valid_token(
        self,
        test_client: FlaskClient,
        generate_token,
        mock_api_requests: respx.MockRouter,
        user_id: str,
    ):
        mock_api_requests.get("/userinfo").reset()
        mock_api_requests.get("/userinfo").return_value = Response(
            200, json={"sub": user_id}
        )

        access_token = generate_token(encrypt=False, scope="openid")

        response = test_client.get(
            "/current-user", headers={"Authorization": f"Bearer {access_token}"}
        )

        assert response.status_code == 200

        json = response.json
        assert json == {"sub": user_id}

        # Check cache is working
        response_2 = test_client.get(
            "/current-user", headers={"Authorization": f"Bearer {access_token}"}
        )

        assert response_2.status_code == 200

        json = response_2.json
        assert json == {"sub": user_id}

        assert mock_api_requests.get("/userinfo").call_count == 1

    def test_missing_scope(self, test_client: FlaskClient, generate_token):
        access_token = generate_token(encrypt=False, scope="openid")

        response = test_client.get(
            "/current-user-scope", headers={"Authorization": f"Bearer {access_token}"}
        )

        assert response.status_code == 403

    def test_valid_scope(
        self,
        test_client: FlaskClient,
        generate_token,
        mock_api_requests: respx.MockRouter,
        user_id: str,
    ):
        mock_api_requests.get("/userinfo").return_value = Response(
            200, json={"sub": user_id}
        )

        access_token = generate_token(encrypt=False, scope="openid required_scope")

        response = test_client.get(
            "/current-user-scope", headers={"Authorization": f"Bearer {access_token}"}
        )

        assert response.status_code == 200

        json = response.json
        assert json == {"sub": user_id}

    def test_valid_refresh(
        self,
        test_client: FlaskClient,
        generate_token,
        mock_api_requests: respx.MockRouter,
        user_id: str,
    ):
        mock_api_requests.get("/userinfo").reset()
        mock_api_requests.get("/userinfo").return_value = Response(
            200, json={"sub": user_id}
        )

        access_token = generate_token(encrypt=False, scope="openid")

        response = test_client.get(
            "/current-user-refresh", headers={"Authorization": f"Bearer {access_token}"}
        )

        assert response.status_code == 200

        json = response.json
        assert json == {"sub": user_id}

        # Check cache is not used with refresh
        response_2 = test_client.get(
            "/current-user-refresh", headers={"Authorization": f"Bearer {access_token}"}
        )

        assert response_2.status_code == 200

        json = response_2.json
        assert json == {"sub": user_id}

        assert mock_api_requests.get("/userinfo").call_count == 2


def test_get_cookie():
    cookie_getter = get_cookie("COOKIE_NAME")
    app = Flask(__name__)
    with app.test_request_context():
        result = cookie_getter()
        assert result is None

    with app.test_request_context(headers={"Cookie": "COOKIE_NAME=VALUE"}):
        result = cookie_getter()
        assert result == "VALUE"
