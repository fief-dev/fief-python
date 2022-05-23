import uuid

import pytest
import respx
from django.conf import settings
from django.test import Client
from httpx import Response

from fief_client.integrations.django.backend import FiefBackend
from fief_client.integrations.django.models import FiefUser
from fief_client.integrations.django.views import NEXT_PATH_KEY


@pytest.fixture
def backend() -> FiefBackend:
    return FiefBackend()


@pytest.fixture
def client() -> Client:
    return Client()


@pytest.mark.django_db
def test_fief_user(user_id: str):
    user = FiefUser(
        fief_id=uuid.UUID(user_id), email="anne@bretagne.duchy", is_staff=True
    )
    user.save()

    assert user.is_anonymous is False
    assert user.is_authenticated is True
    assert user.is_active is True
    assert user.get_full_name() == user.email
    assert user.get_short_name() == user.email
    assert user.get_username() == user.email
    assert str(user) == user.email


@pytest.mark.django_db
class TestBackend:
    def test_authenticate_none_fief_id(self, backend: FiefBackend):
        user = backend.authenticate(None, fief_id=None)
        assert user is None

    def test_authenticate_user_exists(self, backend: FiefBackend, user_id: str):
        existing_user = FiefUser(
            fief_id=uuid.UUID(user_id), email="anne@bretagne.duchy"
        )
        existing_user.save()

        user = backend.authenticate(None, fief_id=existing_user.fief_id)
        assert user is not None
        assert user.id == existing_user.id

    def test_authenticate_user_not_exists(self, backend: FiefBackend, user_id: str):
        user = backend.authenticate(
            None, fief_id=uuid.UUID(user_id), email="anne@bretagne.duchy"
        )
        assert user is not None

    def test_authenticate_user_exists_update_email(
        self, backend: FiefBackend, user_id: str
    ):
        existing_user = FiefUser(
            fief_id=uuid.UUID(user_id), email="anne@bretagne.duchy"
        )
        existing_user.save()

        user = backend.authenticate(
            None, fief_id=existing_user.fief_id, email="anne@nantes.city"
        )
        assert user is not None
        assert user.id == existing_user.id
        assert user.email == "anne@nantes.city"

    def test_get_user(self, backend: FiefBackend, user_id: str):
        existing_user = FiefUser(
            fief_id=uuid.UUID(user_id), email="anne@bretagne.duchy"
        )
        existing_user.save()

        user = backend.get_user(existing_user.id)
        assert user is not None

        user = backend.get_user(123)
        assert user is None


@pytest.mark.django_db
class TestLogin:
    def test_get(self, client: Client):
        response = client.get("/login/")

        assert response.status_code == 302
        assert response.headers["Location"].startswith(
            f"{settings.FIEF_BASE_URL}/authorize"
        )

    def test_get_with_next(self, client: Client):
        response = client.get("/login/", {"next": "/protected"})

        assert response.status_code == 302

        assert response.headers["Location"].startswith(
            f"{settings.FIEF_BASE_URL}/authorize"
        )
        assert client.session[NEXT_PATH_KEY] == "/protected"


@pytest.mark.django_db
class TestCallback:
    def test_get(
        self,
        client: Client,
        mock_api_requests: respx.MockRouter,
        access_token: str,
        signed_id_token: str,
        user_id: str,
    ):
        token_route = mock_api_requests.post("/token")
        token_route.return_value = Response(
            200,
            json={
                "access_token": access_token,
                "id_token": signed_id_token,
                "token_type": "bearer",
            },
        )

        response = client.get("/callback/", {"code": "AUTHORIZATION_CODE"})

        assert response.status_code == 302
        assert response.headers["Location"] == "/"

        session = client.session
        django_user_id = session.get("_auth_user_id")
        backend = session.get("_auth_user_backend")
        assert backend == "fief_client.integrations.django.backend.FiefBackend"
        assert django_user_id is not None

        user = FiefUser.objects.get(id=django_user_id)
        assert user is not None
        assert str(user.fief_id) == user_id
        assert user.email == "anne@bretagne.duchy"

    def test_get_with_next(
        self,
        client: Client,
        mock_api_requests: respx.MockRouter,
        access_token: str,
        signed_id_token: str,
    ):
        session = client.session
        session[NEXT_PATH_KEY] = "/protected"
        session.save()

        token_route = mock_api_requests.post("/token")
        token_route.return_value = Response(
            200,
            json={
                "access_token": access_token,
                "id_token": signed_id_token,
                "token_type": "bearer",
            },
        )

        response = client.get("/callback/", {"code": "AUTHORIZATION_CODE"})

        assert response.status_code == 302
        assert response.headers["Location"] == "/protected"


@pytest.mark.django_db
class TestLogout:
    def test_get(self, client: Client, user_id: str):
        user = FiefUser(fief_id=uuid.UUID(user_id), email="anne@bretagne.duchy")
        user.save()
        client.login(fief_id=user.fief_id, email=user.email)

        response = client.get("/logout/")

        assert response.status_code == 302
        assert response.headers["Location"].startswith(
            f"{settings.FIEF_BASE_URL}/logout"
        )

        session = client.session
        django_user_id = session.get("_auth_user_id")
        backend = session.get("_auth_user_backend")
        assert django_user_id is None
        assert backend is None


@pytest.mark.django_db
class TestProtected:
    def test_unauthenticated(self, client: Client):
        response = client.get("/protected/")

        assert response.status_code == 302
        assert response.headers["Location"] == "/login?next=/protected/"

    def test_authenticated(self, client: Client, user_id: str):
        user = FiefUser(fief_id=uuid.UUID(user_id), email="anne@bretagne.duchy")
        user.save()
        client.login(fief_id=user.fief_id, email=user.email)

        response = client.get("/protected/")

        assert response.status_code == 200

        assert response.content == b"Hello, anne@bretagne.duchy"


@pytest.mark.django_db
class TestAdmin:
    def test_unauthenticated(self, client: Client):
        response = client.get("/admin/")

        assert response.status_code == 302
        assert response.headers["Location"] == "/admin/login/?next=/admin/"

    def test_authenticated(self, client: Client, user_id: str):
        user = FiefUser(
            fief_id=uuid.UUID(user_id), email="anne@bretagne.duchy", is_staff=True
        )
        user.save()
        client.login(fief_id=user.fief_id, email=user.email)

        response = client.get("/admin/")

        assert response.status_code == 200
