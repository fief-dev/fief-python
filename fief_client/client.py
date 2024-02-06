import contextlib
import json
import uuid
from enum import Enum
from typing import Any, Dict, List, Mapping, Optional, Tuple, TypedDict, Union
from urllib.parse import urlencode

import httpx
from httpx._types import CertTypes, VerifyTypes
from jwcrypto import jwk, jwt

from fief_client.crypto import is_valid_hash

HTTPXClient = Union[httpx.Client, httpx.AsyncClient]


class FiefACR(str, Enum):
    """
    List of defined Authentication Context Class Reference.
    """

    LEVEL_ZERO = "0"
    """Level 0. No authentication was performed, a previous session was used."""
    LEVEL_ONE = "1"
    """Level 1. Password authentication was performed."""

    def __lt__(self, other: object) -> bool:
        return self._compare(other, True, True)

    def __le__(self, other: object) -> bool:
        return self._compare(other, False, True)

    def __gt__(self, other: object) -> bool:
        return self._compare(other, True, False)

    def __ge__(self, other: object) -> bool:
        return self._compare(other, False, False)

    def _compare(self, other: object, strict: bool, asc: bool) -> bool:
        if not isinstance(other, FiefACR):
            return NotImplemented  # pragma: no cover

        if self == other:
            return not strict

        for elem in FiefACR:
            if self == elem:
                return asc
            elif other == elem:
                return not asc
        raise RuntimeError()  # pragma: no cover


class FiefTokenResponse(TypedDict):
    """
    Typed dictionary containing the tokens and related information returned by Fief after a successful authentication.
    """

    access_token: str
    """Access token you can use to call the Fief API."""
    id_token: str
    """ID token containing user information."""
    token_type: str
    """Type of token, usually `bearer`."""
    expires_in: int
    """Number of seconds after which the tokens will expire."""
    refresh_token: Optional[str]
    """Token provided only if scope `offline_access` was granted. Allows you to retrieve fresh tokens using the `Fief.auth_refresh_token` method."""


class FiefAccessTokenInfo(TypedDict):
    """
    Typed dictionary containing information about the access token.

    **Example:**

    ```json
    {
        "id": "aeeb8bfa-e8f4-4724-9427-c3d5af66190e",
        "scope": ["openid", "required_scope"],
        "acr": "1",
        "permissions": ["castles:read", "castles:create", "castles:update", "castles:delete"],
        "access_token": "ACCESS_TOKEN",
    }
    ```
    """

    id: uuid.UUID
    """ID of the user."""
    scope: List[str]
    """List of granted scopes for this access token."""
    acr: FiefACR
    """Level of Authentication Context class Reference."""
    permissions: List[str]
    """List of [granted permissions](https://docs.fief.dev/getting-started/access-control/) for this user."""
    access_token: str
    """Access token you can use to call the Fief API."""


class FiefUserInfo(TypedDict):
    """
    Dictionary containing user information.

    **Example:**

    ```json
    {
        "sub": "aeeb8bfa-e8f4-4724-9427-c3d5af66190e",
        "email": "anne@bretagne.duchy",
        "tenant_id": "c91ecb7f-359c-4244-8385-51ecd6c0d06b",
        "fields": {
            "first_name": "Anne",
            "last_name": "De Bretagne"
        }
    }
    ```
    """

    sub: str
    """
    ID of the user.
    """
    email: str
    """
    Email address of the user.
    """
    tenant_id: str
    """
    ID of the [tenant](https://docs.fief.dev/getting-started/tenants/) associated to the user.
    """
    fields: Dict[str, Any]
    """
    [User fields](https://docs.fief.dev/getting-started/user-fields/) values for this user, indexed by their slug.
    """


class FiefError(Exception):
    """Base Fief client error."""


class FiefRequestError(FiefError):
    """The request to Fief server resulted in an error."""

    def __init__(self, status_code: int, detail: str) -> None:
        self.status_code = status_code
        self.detail = detail
        self.message = f"[{status_code}] - {detail}"
        super().__init__(self.message)


class FiefAccessTokenInvalid(FiefError):
    """The access token is invalid."""


class FiefAccessTokenExpired(FiefError):
    """The access token is expired."""


class FiefAccessTokenMissingScope(FiefError):
    """The access token is missing a required scope."""


class FiefAccessTokenACRTooLow(FiefError):
    """The access token doesn't meet the minimum ACR level."""


class FiefAccessTokenMissingPermission(FiefError):
    """The access token is missing a required permission."""


class FiefIdTokenInvalid(FiefError):
    """The ID token is invalid."""


class BaseFief:
    """
    Base Fief authentication client.
    """

    base_url: str
    """Base URL of your Fief tenant."""
    client_id: str
    """ID of your Fief client."""
    client_secret: Optional[str] = None
    """
    Secret of your Fief client.

    If you're implementing a desktop app, it's not recommended to use it,
    since it can be easily found by the end-user in the source code.
    The recommended way is to use a [Public client](https://docs.fief.dev/getting-started/clients/#public-clients).
    """
    encryption_key: Optional[jwk.JWK] = None
    """"""

    _openid_configuration: Optional[Dict[str, Any]] = None
    _jwks: Optional[jwk.JWKSet] = None

    _verify: VerifyTypes
    _cert: CertTypes

    def __init__(
        self,
        base_url: str,
        client_id: str,
        client_secret: Optional[str] = None,
        *,
        encryption_key: Optional[str] = None,
        host: Optional[str] = None,
        verify: VerifyTypes = True,
        cert: Optional[CertTypes] = None,
    ) -> None:
        """
        Initialize the client.

        :param base_url: Base URL of your Fief tenant.
        :param client_id: ID of your Fief client.
        :param client_secret: Secret of your Fief client.
        If you're implementing a desktop app, it's not recommended to use it,
        since it can be easily found by the end-user in the source code.
        The recommended way is to use a [Public client](https://docs.fief.dev/getting-started/clients/#public-clients).
        :param encryption_key: Encryption key of your Fief client.
        Necessary only if [ID Token encryption](https://docs.fief.dev/going-further/id-token-encryption/) is enabled.
        :param verify: Corresponds to the [verify parameter of HTTPX](https://www.python-httpx.org/advanced/#changing-the-verification-defaults).
        Useful to customize SSL connection handling.
        :param cert: Corresponds to the [cert parameter of HTTPX](https://www.python-httpx.org/advanced/#client-side-certificates).
        Useful to customize SSL connection handling.
        """
        self.base_url = base_url
        self.client_id = client_id
        self.client_secret = client_secret
        if encryption_key is not None:
            self.encryption_key = jwk.JWK.from_json(encryption_key)
        self.host = host
        self.verify = verify
        self.cert = cert

    def _get_endpoint_url(
        self,
        openid_configuration: Dict[str, Any],
        field: str,
        *,
        absolute: bool = False,
    ) -> str:
        """
        Return the specified endpoint from OpenID configuration.

        If `absolute` is `False`, we only retain the path,
        as the host might is not always relevant in our context.

        Typically, we might be in a Docker environment where the client app has to make
        request to the Fief server through Docker networking. Therefore, we do not
        want the client to use the absolute URL generated by OpenID Configuration, but
        rather stick to the host specified on the client configuration.
        """
        if not absolute:
            issuer = openid_configuration["issuer"]
            return openid_configuration[field].split(issuer)[1]
        return openid_configuration[field]

    def _auth_url(
        self,
        openid_configuration: Dict[str, Any],
        redirect_uri: str,
        *,
        state: Optional[str] = None,
        scope: Optional[List[str]] = None,
        code_challenge: Optional[str] = None,
        code_challenge_method: Optional[str] = None,
        lang: Optional[str] = None,
        extras_params: Optional[Mapping[str, str]] = None,
    ) -> str:
        params = {
            "response_type": "code",
            "client_id": self.client_id,
            "redirect_uri": redirect_uri,
        }

        if state is not None:
            params["state"] = state

        if scope is not None:
            params["scope"] = " ".join(scope)

        if code_challenge is not None and code_challenge_method is not None:
            params["code_challenge"] = code_challenge
            params["code_challenge_method"] = code_challenge_method

        if lang is not None:
            params["lang"] = lang

        if extras_params is not None:
            params = {**params, **extras_params}

        authorization_endpoint = self._get_endpoint_url(
            openid_configuration, "authorization_endpoint", absolute=True
        )
        return f"{authorization_endpoint}?{urlencode(params)}"

    def _validate_access_token(
        self,
        access_token: str,
        jwks: jwk.JWKSet,
        *,
        required_scope: Optional[List[str]] = None,
        required_acr: Optional[FiefACR] = None,
        required_permissions: Optional[List[str]] = None,
    ) -> FiefAccessTokenInfo:
        try:
            decoded_token = jwt.JWT(jwt=access_token, algs=["RS256"], key=jwks)
            claims = json.loads(decoded_token.claims)
            access_token_scope = claims["scope"].split()
            if required_scope is not None:
                for scope in required_scope:
                    if scope not in access_token_scope:
                        raise FiefAccessTokenMissingScope()

            try:
                acr = FiefACR(claims["acr"])
            except ValueError as e:
                raise FiefAccessTokenInvalid() from e

            if required_acr is not None:
                if acr < required_acr:
                    raise FiefAccessTokenACRTooLow()

            permissions: List[str] = claims["permissions"]
            if required_permissions is not None:
                for required_permission in required_permissions:
                    if required_permission not in permissions:
                        raise FiefAccessTokenMissingPermission()

            return {
                "id": uuid.UUID(claims["sub"]),
                "scope": access_token_scope,
                "acr": acr,
                "permissions": permissions,
                "access_token": access_token,
            }

        except jwt.JWTExpired as e:
            raise FiefAccessTokenExpired() from e
        except (jwt.JWException, KeyError, ValueError) as e:
            raise FiefAccessTokenInvalid() from e

    def _decode_id_token(
        self,
        id_token: str,
        jwks: jwk.JWKSet,
        *,
        code: Optional[str] = None,
        access_token: Optional[str] = None,
    ) -> FiefUserInfo:
        try:
            if self.encryption_key is not None:
                decrypted_id_token = jwt.JWT(jwt=id_token, key=self.encryption_key)
                id_token_claims = decrypted_id_token.claims
            else:
                id_token_claims = id_token

            signed_id_token = jwt.JWT(jwt=id_token_claims, algs=["RS256"], key=jwks)
            claims = json.loads(signed_id_token.claims)

            if "c_hash" in claims:
                if code is None or not is_valid_hash(code, claims["c_hash"]):
                    raise FiefIdTokenInvalid()

            if "at_hash" in claims:
                if access_token is None or not is_valid_hash(
                    access_token, claims["at_hash"]
                ):
                    raise FiefIdTokenInvalid()

        except (jwt.JWException, TypeError) as e:
            raise FiefIdTokenInvalid() from e
        else:
            return claims

    def _get_openid_configuration_request(self, client: HTTPXClient) -> httpx.Request:
        return client.build_request("GET", "/.well-known/openid-configuration")

    def _get_auth_exchange_token_request(
        self,
        client: HTTPXClient,
        *,
        endpoint: str,
        code: str,
        redirect_uri: str,
        code_verifier: Optional[str] = None,
    ) -> httpx.Request:
        data = {
            "client_id": self.client_id,
            "grant_type": "authorization_code",
            "code": code,
            "redirect_uri": redirect_uri,
            "code_verifier": code_verifier,
        }
        if self.client_secret is not None:
            data["client_secret"] = self.client_secret
        return client.build_request("POST", endpoint, data=data)

    def _get_auth_refresh_token_request(
        self,
        client: HTTPXClient,
        *,
        endpoint: str,
        refresh_token: str,
        scope: Optional[List[str]] = None,
    ) -> httpx.Request:
        data = {
            "client_id": self.client_id,
            "grant_type": "refresh_token",
            "refresh_token": refresh_token,
        }
        if self.client_secret is not None:
            data["client_secret"] = self.client_secret
        if scope is not None:
            data["scope"] = " ".join(scope)

        return client.build_request("POST", endpoint, data=data)

    def _get_userinfo_request(
        self, client: HTTPXClient, *, endpoint: str, access_token: str
    ) -> httpx.Request:
        return client.build_request(
            "GET", endpoint, headers={"Authorization": f"Bearer {access_token}"}
        )

    def _get_update_profile_request(
        self,
        client: HTTPXClient,
        *,
        endpoint: str,
        access_token: str,
        data: Dict[str, Any],
    ) -> httpx.Request:
        return client.build_request(
            "PATCH",
            endpoint,
            headers={"Authorization": f"Bearer {access_token}"},
            json=data,
        )

    def _get_change_password_request(
        self,
        client: HTTPXClient,
        *,
        endpoint: str,
        access_token: str,
        new_password: str,
    ) -> httpx.Request:
        return client.build_request(
            "PATCH",
            endpoint,
            headers={"Authorization": f"Bearer {access_token}"},
            json={"password": new_password},
        )

    def _get_email_change_request(
        self,
        client: HTTPXClient,
        *,
        endpoint: str,
        access_token: str,
        email: str,
    ) -> httpx.Request:
        return client.build_request(
            "PATCH",
            endpoint,
            headers={"Authorization": f"Bearer {access_token}"},
            json={"email": email},
        )

    def _get_email_verify_request(
        self,
        client: HTTPXClient,
        *,
        endpoint: str,
        access_token: str,
        code: str,
    ) -> httpx.Request:
        return client.build_request(
            "POST",
            endpoint,
            headers={"Authorization": f"Bearer {access_token}"},
            json={"code": code},
        )

    def _handle_request_error(self, response: httpx.Response):
        if response.is_error:
            raise FiefRequestError(response.status_code, response.text)


class Fief(BaseFief):
    """Sync Fief authentication client."""

    def __init__(
        self,
        base_url: str,
        client_id: str,
        client_secret: Optional[str] = None,
        *,
        encryption_key: Optional[str] = None,
        host: Optional[str] = None,
        verify: VerifyTypes = True,
        cert: Optional[CertTypes] = None,
    ) -> None:
        super().__init__(
            base_url,
            client_id,
            client_secret,
            encryption_key=encryption_key,
            host=host,
            verify=verify,
            cert=cert,
        )

    def auth_url(
        self,
        redirect_uri: str,
        *,
        state: Optional[str] = None,
        scope: Optional[List[str]] = None,
        code_challenge: Optional[str] = None,
        code_challenge_method: Optional[str] = None,
        lang: Optional[str] = None,
        extras_params: Optional[Mapping[str, str]] = None,
    ) -> str:
        """
        Return an authorization URL.

        :param redirect_uri: Your callback URI where the user will be redirected after Fief authentication.
        :param state: Optional string that will be returned back in the callback parameters to allow you to retrieve state information.
        :param scope: Optional list of scopes to ask for.
        :param code_challenge: Optional code challenge for
        [PKCE process](https://docs.fief.dev/going-further/pkce/).
        :param code_challenge_method: Method used to hash the PKCE code challenge.
        :param lang: Optional parameter to set the user locale.
        Should be a valid [RFC 3066](https://www.rfc-editor.org/rfc/rfc3066) language identifier, like `fr` or `pt-PT`.
        If not provided, the user locale is determined by their browser settings.
        :param extras_params: Optional dictionary containing [specific parameters](https://docs.fief.dev/going-further/authorize-url/).

        **Example:**

        ```py
        auth_url = fief.auth_url("http://localhost:8000/callback", scope=["openid"])
        ```
        """
        openid_configuration = self._get_openid_configuration()
        return self._auth_url(
            openid_configuration,
            redirect_uri,
            state=state,
            scope=scope,
            code_challenge=code_challenge,
            code_challenge_method=code_challenge_method,
            lang=lang,
            extras_params=extras_params,
        )

    def auth_callback(
        self, code: str, redirect_uri: str, *, code_verifier: Optional[str] = None
    ) -> Tuple[FiefTokenResponse, FiefUserInfo]:
        """
        Return a `FiefTokenResponse` and `FiefUserInfo` in exchange of an authorization code.

        :param code: The authorization code.
        :param redirect_uri: The exact same `redirect_uri` you passed to the authorization URL.
        :param code_verifier:  The raw
        [PKCE](https://docs.fief.dev/going-further/pkce/) code used to generate the code challenge during authorization.

        **Example:**

        ```py
        tokens, userinfo = fief.auth_callback("CODE", "http://localhost:8000/callback")
        ```
        """
        token_response = self._auth_exchange_token(
            code, redirect_uri, code_verifier=code_verifier
        )
        jwks = self._get_jwks()
        userinfo = self._decode_id_token(
            token_response["id_token"],
            jwks,
            code=code,
            access_token=token_response.get("access_token"),
        )
        return token_response, userinfo

    def auth_refresh_token(
        self, refresh_token: str, *, scope: Optional[List[str]] = None
    ) -> Tuple[FiefTokenResponse, FiefUserInfo]:
        """
        Return fresh `FiefTokenResponse` and `FiefUserInfo` in exchange of a refresh token

        :param refresh_token: A valid refresh token.
        :param scope: Optional list of scopes to ask for.
        If not provided, the access token will share the same list of scopes as requested the first time.
        Otherwise, it should be a subset of the original list of scopes.

        **Example:**

        ```py
        tokens, userinfo = fief.auth_refresh_token("REFRESH_TOKEN")
        ```
        """
        token_endpoint = self._get_endpoint_url(
            self._get_openid_configuration(), "token_endpoint"
        )
        with self._get_httpx_client() as client:
            request = self._get_auth_refresh_token_request(
                client,
                endpoint=token_endpoint,
                refresh_token=refresh_token,
                scope=scope,
            )
            response = client.send(request)

            self._handle_request_error(response)

            token_response = response.json()
        jwks = self._get_jwks()
        userinfo = self._decode_id_token(
            token_response["id_token"],
            jwks,
            access_token=token_response.get("access_token"),
        )
        return token_response, userinfo

    def validate_access_token(
        self,
        access_token: str,
        *,
        required_scope: Optional[List[str]] = None,
        required_acr: Optional[FiefACR] = None,
        required_permissions: Optional[List[str]] = None,
    ) -> FiefAccessTokenInfo:
        """
        Check if an access token is valid and optionally that it has a required list of scopes,
        or a required list of [permissions](https://docs.fief.dev/getting-started/access-control/).
        Returns a `FiefAccessTokenInfo`.

        :param access_token: The access token to validate.
        :param required_scope: Optional list of scopes to check for.
        :param required_acr: Optional minimum ACR level required.
        Read more: https://docs.fief.dev/going-further/acr/
        :param required_permissions: Optional list of permissions to check for.

        **Example: Validate access token with required scopes**

        ```py
        try:
            access_token_info = fief.validate_access_token("ACCESS_TOKEN", required_scope=["required_scope"])
        except FiefAccessTokenInvalid:
            print("Invalid access token")
        except FiefAccessTokenExpired:
            print("Expired access token")
        except FiefAccessTokenMissingScope:
            print("Missing required scope")

        print(access_token_info)
        ```

        **Example: Validate access token with minimum ACR level**

        ```py
        try:
            access_token_info = fief.validate_access_token("ACCESS_TOKEN", required_acr=FiefACR.LEVEL_ONE)
        except FiefAccessTokenInvalid:
            print("Invalid access token")
        except FiefAccessTokenExpired:
            print("Expired access token")
        except FiefAccessTokenACRTooLow:
            print("ACR too low")

        print(access_token_info)
        ```

        **Example: Validate access token with required permissions**

        ```py
        try:
            access_token_info = fief.validate_access_token("ACCESS_TOKEN", required_permissions=["castles:create", "castles:read"])
        except FiefAccessTokenInvalid:
            print("Invalid access token")
        except FiefAccessTokenExpired:
            print("Expired access token")
        except FiefAccessTokenMissingPermission:
            print("Missing required permission")

        print(access_token_info)
        ```
        """
        jwks = self._get_jwks()
        return self._validate_access_token(
            access_token,
            jwks,
            required_scope=required_scope,
            required_acr=required_acr,
            required_permissions=required_permissions,
        )

    def userinfo(self, access_token: str) -> FiefUserInfo:
        """
        Return fresh `FiefUserInfo` from the Fief API using a valid access token.

        :param access_token: A valid access token.

        **Example:**

        ```py
        userinfo = fief.userinfo("ACCESS_TOKEN")
        ```
        """
        userinfo_endpoint = self._get_endpoint_url(
            self._get_openid_configuration(), "userinfo_endpoint"
        )
        with self._get_httpx_client() as client:
            request = self._get_userinfo_request(
                client, endpoint=userinfo_endpoint, access_token=access_token
            )
            response = client.send(request)

            self._handle_request_error(response)

            return response.json()

    def update_profile(self, access_token: str, data: Dict[str, Any]) -> FiefUserInfo:
        """
        Update user information with the Fief API using a valid access token.

        :param access_token: A valid access token.
        :param data: A dictionary containing the data to update.

        **Example: Update user field**

        To update [user field](https://docs.fief.dev/getting-started/user-fields/) values, you need to nest them into a `fields` dictionary, indexed by their slug.

        ```py
        userinfo = fief.update_profile("ACCESS_TOKEN", { "fields": { "first_name": "Anne" } })
        ```
        """
        update_profile_endpoint = f"{self.base_url}/api/profile"

        with self._get_httpx_client() as client:
            request = self._get_update_profile_request(
                client,
                endpoint=update_profile_endpoint,
                access_token=access_token,
                data=data,
            )
            response = client.send(request)

            self._handle_request_error(response)

            return response.json()

    def change_password(self, access_token: str, new_password: str) -> FiefUserInfo:
        """
        Change the user password with the Fief API using a valid access token.

        **An access token with an ACR of at least level 1 is required.**

        :param access_token: A valid access token.
        :param new_password: The new password.

        **Example**

        ```py
        userinfo = fief.change_password("ACCESS_TOKEN", "herminetincture")
        ```
        """
        change_password_profile_endpoint = f"{self.base_url}/api/password"

        with self._get_httpx_client() as client:
            request = self._get_change_password_request(
                client,
                endpoint=change_password_profile_endpoint,
                access_token=access_token,
                new_password=new_password,
            )
            response = client.send(request)

            self._handle_request_error(response)

            return response.json()

    def email_change(self, access_token: str, email: str) -> FiefUserInfo:
        """
        Request an email change with the Fief API using a valid access token.

        The user will receive a verification code on this new email address.
        It shall be used with the method `email_verify` to complete the modification.

        **An access token with an ACR of at least level 1 is required.**

        :param access_token: A valid access token.
        :param email: The new email address.

        **Example**

        ```py
        userinfo = fief.email_change("ACCESS_TOKEN", "anne@nantes.city")
        ```
        """
        email_change_endpoint = f"{self.base_url}/api/email/change"

        with self._get_httpx_client() as client:
            request = self._get_email_change_request(
                client,
                endpoint=email_change_endpoint,
                access_token=access_token,
                email=email,
            )
            response = client.send(request)

            self._handle_request_error(response)

            return response.json()

    def email_verify(self, access_token: str, code: str) -> FiefUserInfo:
        """
        Verify the user email with the Fief API using a valid access token and verification code.

        **An access token with an ACR of at least level 1 is required.**

        :param access_token: A valid access token.
        :param code: The verification code received by email.

        **Example**

        ```py
        userinfo = fief.email_verify("ACCESS_TOKEN", "ABCDE")
        ```
        """
        email_verify_endpoint = f"{self.base_url}/api/email/verify"

        with self._get_httpx_client() as client:
            request = self._get_email_verify_request(
                client,
                endpoint=email_verify_endpoint,
                access_token=access_token,
                code=code,
            )
            response = client.send(request)

            self._handle_request_error(response)

            return response.json()

    def logout_url(self, redirect_uri: str) -> str:
        """
        Returns a logout URL. If you redirect the user to this page, Fief will clear the session stored on its side.

        **You're still responsible for clearing your own session mechanism if any.**

        :param redirect_uri: A valid URL where the user will be redirected after the logout process.

        **Example:**

        ```py
        logout_url = fief.logout_url("http://localhost:8000")
        ```
        """
        params = {"redirect_uri": redirect_uri}
        return f"{self.base_url}/logout?{urlencode(params)}"

    @contextlib.contextmanager
    def _get_httpx_client(self):
        headers = {}
        if self.host is not None:
            headers["Host"] = self.host

        with httpx.Client(
            base_url=self.base_url, headers=headers, verify=self.verify, cert=self.cert
        ) as client:
            yield client

    def _get_openid_configuration(self) -> Dict[str, Any]:
        if self._openid_configuration is not None:
            return self._openid_configuration

        with self._get_httpx_client() as client:
            request = self._get_openid_configuration_request(client)
            response = client.send(request)
            json = response.json()
            self._openid_configuration = json
            return json

    def _get_jwks(self) -> jwk.JWKSet:
        if self._jwks is not None:
            return self._jwks

        jwks_uri = self._get_endpoint_url(self._get_openid_configuration(), "jwks_uri")
        with self._get_httpx_client() as client:
            response = client.get(jwks_uri)
            self._jwks = jwk.JWKSet.from_json(response.text)
            return self._jwks

    def _auth_exchange_token(
        self, code: str, redirect_uri: str, *, code_verifier: Optional[str] = None
    ) -> FiefTokenResponse:
        token_endpoint = self._get_endpoint_url(
            self._get_openid_configuration(), "token_endpoint"
        )
        with self._get_httpx_client() as client:
            request = self._get_auth_exchange_token_request(
                client,
                endpoint=token_endpoint,
                code=code,
                redirect_uri=redirect_uri,
                code_verifier=code_verifier,
            )
            response = client.send(request)

            self._handle_request_error(response)

            return response.json()


class FiefAsync(BaseFief):
    """Async Fief authentication client."""

    def __init__(
        self,
        base_url: str,
        client_id: str,
        client_secret: Optional[str] = None,
        *,
        encryption_key: Optional[str] = None,
        host: Optional[str] = None,
        verify: VerifyTypes = True,
        cert: Optional[CertTypes] = None,
    ) -> None:
        super().__init__(
            base_url,
            client_id,
            client_secret,
            encryption_key=encryption_key,
            host=host,
            verify=verify,
            cert=cert,
        )

    async def auth_url(
        self,
        redirect_uri: str,
        *,
        state: Optional[str] = None,
        scope: Optional[List[str]] = None,
        code_challenge: Optional[str] = None,
        code_challenge_method: Optional[str] = None,
        lang: Optional[str] = None,
        extras_params: Optional[Mapping[str, str]] = None,
    ) -> str:
        """
        Return an authorization URL.

        :param redirect_uri: Your callback URI where the user will be redirected after Fief authentication.
        :param state: Optional string that will be returned back in the callback parameters to allow you to retrieve state information.
        :param scope: Optional list of scopes to ask for.
        :param code_challenge: Optional code challenge for
        [PKCE process](https://docs.fief.dev/going-further/pkce/).
        :param code_challenge_method: Method used to hash the PKCE code challenge.
        :param lang: Optional parameter to set the user locale.
        Should be a valid [RFC 3066](https://www.rfc-editor.org/rfc/rfc3066) language identifier, like `fr` or `pt-PT`.
        If not provided, the user locale is determined by their browser settings.
        :param extras_params: Optional dictionary containing [specific parameters](https://docs.fief.dev/going-further/authorize-url/).

        **Example:**

        ```py
        auth_url = await fief.auth_url("http://localhost:8000/callback", scope=["openid"])
        ```
        """
        openid_configuration = await self._get_openid_configuration()
        return self._auth_url(
            openid_configuration,
            redirect_uri,
            state=state,
            scope=scope,
            code_challenge=code_challenge,
            code_challenge_method=code_challenge_method,
            lang=lang,
            extras_params=extras_params,
        )

    async def auth_callback(
        self, code: str, redirect_uri: str, *, code_verifier: Optional[str] = None
    ) -> Tuple[FiefTokenResponse, FiefUserInfo]:
        """
        Return a `FiefTokenResponse` and `FiefUserInfo` in exchange of an authorization code.

        :param code: The authorization code.
        :param redirect_uri: The exact same `redirect_uri` you passed to the authorization URL.
        :param code_verifier:  The raw
        [PKCE](https://docs.fief.dev/going-further/pkce/) code used to generate the code challenge during authorization.

        **Example:**

        ```py
        tokens, userinfo = await fief.auth_callback("CODE", "http://localhost:8000/callback")
        ```
        """
        token_response = await self._auth_exchange_token(
            code, redirect_uri, code_verifier=code_verifier
        )
        jwks = await self._get_jwks()
        userinfo = self._decode_id_token(
            token_response["id_token"],
            jwks,
            code=code,
            access_token=token_response.get("access_token"),
        )
        return token_response, userinfo

    async def auth_refresh_token(
        self, refresh_token: str, *, scope: Optional[List[str]] = None
    ) -> Tuple[FiefTokenResponse, FiefUserInfo]:
        """
        Return fresh `FiefTokenResponse` and `FiefUserInfo` in exchange of a refresh token

        :param refresh_token: A valid refresh token.
        :param scope: Optional list of scopes to ask for.
        If not provided, the access token will share the same list of scopes as requested the first time.
        Otherwise, it should be a subset of the original list of scopes.

        **Example:**

        ```py
        tokens, userinfo = await fief.auth_refresh_token("REFRESH_TOKEN")
        ```
        """
        token_endpoint = self._get_endpoint_url(
            await self._get_openid_configuration(), "token_endpoint"
        )
        async with self._get_httpx_client() as client:
            request = self._get_auth_refresh_token_request(
                client,
                endpoint=token_endpoint,
                refresh_token=refresh_token,
                scope=scope,
            )
            response = await client.send(request)

            self._handle_request_error(response)

            token_response = response.json()

        jwks = await self._get_jwks()
        userinfo = self._decode_id_token(
            token_response["id_token"],
            jwks,
            access_token=token_response.get("access_token"),
        )
        return token_response, userinfo

    async def validate_access_token(
        self,
        access_token: str,
        *,
        required_scope: Optional[List[str]] = None,
        required_acr: Optional[FiefACR] = None,
        required_permissions: Optional[List[str]] = None,
    ) -> FiefAccessTokenInfo:
        """
        Check if an access token is valid and optionally that it has a required list of scopes,
        or a required list of [permissions](https://docs.fief.dev/getting-started/access-control/).
        Returns a `FiefAccessTokenInfo`.

        :param access_token: The access token to validate.
        :param required_scope: Optional list of scopes to check for.
        :param required_acr: Optional minimum ACR level required.
        Read more: https://docs.fief.dev/going-further/acr/
        :param required_permissions: Optional list of permissions to check for.

        **Example: Validate access token with required scopes**

        ```py
        try:
            access_token_info = await fief.validate_access_token("ACCESS_TOKEN", required_scope=["required_scope"])
        except FiefAccessTokenInvalid:
            print("Invalid access token")
        except FiefAccessTokenExpired:
            print("Expired access token")
        except FiefAccessTokenMissingScope:
            print("Missing required scope")

        print(access_token_info)
        ```

        **Example: Validate access token with minimum ACR level**

        ```py
        try:
            access_token_info = await fief.validate_access_token("ACCESS_TOKEN", required_acr=FiefACR.LEVEL_ONE)
        except FiefAccessTokenInvalid:
            print("Invalid access token")
        except FiefAccessTokenExpired:
            print("Expired access token")
        except FiefAccessTokenACRTooLow:
            print("ACR too low")

        print(access_token_info)
        ```

        **Example: Validate access token with required permissions**

        ```py
        try:
            access_token_info = await fief.validate_access_token("ACCESS_TOKEN", required_permissions=["castles:create", "castles:read"])
        except FiefAccessTokenInvalid:
            print("Invalid access token")
        except FiefAccessTokenExpired:
            print("Expired access token")
        except FiefAccessTokenMissingPermission:
            print("Missing required permission")

        print(access_token_info)
        ```
        """
        jwks = await self._get_jwks()
        return self._validate_access_token(
            access_token,
            jwks,
            required_scope=required_scope,
            required_acr=required_acr,
            required_permissions=required_permissions,
        )

    async def userinfo(self, access_token: str) -> FiefUserInfo:
        """
        Return fresh `FiefUserInfo` from the Fief API using a valid access token.

        :param access_token: A valid access token.

        **Example:**

        ```py
        userinfo = await fief.userinfo("ACCESS_TOKEN")
        ```
        """
        userinfo_endpoint = self._get_endpoint_url(
            await self._get_openid_configuration(), "userinfo_endpoint"
        )
        async with self._get_httpx_client() as client:
            request = self._get_userinfo_request(
                client, endpoint=userinfo_endpoint, access_token=access_token
            )
            response = await client.send(request)

            self._handle_request_error(response)

            return response.json()

    async def update_profile(
        self, access_token: str, data: Dict[str, Any]
    ) -> FiefUserInfo:
        """
        Update user information with the Fief API using a valid access token.

        :param access_token: A valid access token.
        :param data: A dictionary containing the data to update.

        **Example: Update user field**

        To update [user field](https://docs.fief.dev/getting-started/user-fields/) values, you need to nest them into a `fields` dictionary, indexed by their slug.

        ```py
        userinfo = await fief.update_profile("ACCESS_TOKEN", { "fields": { "first_name": "Anne" } })
        ```
        """
        update_profile_endpoint = f"{self.base_url}/api/profile"

        async with self._get_httpx_client() as client:
            request = self._get_update_profile_request(
                client,
                endpoint=update_profile_endpoint,
                access_token=access_token,
                data=data,
            )
            response = await client.send(request)

            self._handle_request_error(response)

            return response.json()

    async def change_password(
        self, access_token: str, new_password: str
    ) -> FiefUserInfo:
        """
        Change the user password with the Fief API using a valid access token.

        **An access token with an ACR of at least level 1 is required.**

        :param access_token: A valid access token.
        :param new_password: The new password.

        **Example**

        ```py
        userinfo = await fief.change_password("ACCESS_TOKEN", "herminetincture")
        ```
        """
        change_password_profile_endpoint = f"{self.base_url}/api/password"

        async with self._get_httpx_client() as client:
            request = self._get_change_password_request(
                client,
                endpoint=change_password_profile_endpoint,
                access_token=access_token,
                new_password=new_password,
            )
            response = await client.send(request)

            self._handle_request_error(response)

            return response.json()

    async def email_change(self, access_token: str, email: str) -> FiefUserInfo:
        """
        Request an email change with the Fief API using a valid access token.

        The user will receive a verification code on this new email address.
        It shall be used with the method `email_verify` to complete the modification.

        **An access token with an ACR of at least level 1 is required.**

        :param access_token: A valid access token.
        :param email: The new email address.

        **Example**

        ```py
        userinfo = await fief.email_change("ACCESS_TOKEN", "anne@nantes.city")
        ```
        """
        email_change_endpoint = f"{self.base_url}/api/email/change"

        async with self._get_httpx_client() as client:
            request = self._get_email_change_request(
                client,
                endpoint=email_change_endpoint,
                access_token=access_token,
                email=email,
            )
            response = await client.send(request)

            self._handle_request_error(response)

            return response.json()

    async def email_verify(self, access_token: str, code: str) -> FiefUserInfo:
        """
        Verify the user email with the Fief API using a valid access token and verification code.

        **An access token with an ACR of at least level 1 is required.**

        :param access_token: A valid access token.
        :param code: The verification code received by email.

        **Example**

        ```py
        userinfo = fief.email_verify("ACCESS_TOKEN", "ABCDE")
        ```
        """
        email_verify_endpoint = f"{self.base_url}/api/email/verify"

        async with self._get_httpx_client() as client:
            request = self._get_email_verify_request(
                client,
                endpoint=email_verify_endpoint,
                access_token=access_token,
                code=code,
            )
            response = await client.send(request)

            self._handle_request_error(response)

            return response.json()

    async def logout_url(self, redirect_uri: str) -> str:
        """
        Returns a logout URL. If you redirect the user to this page, Fief will clear the session stored on its side.

        **You're still responsible for clearing your own session mechanism if any.**

        :param redirect_uri: A valid URL where the user will be redirected after the logout process:

        **Example:**

        ```py
        logout_url = await fief.logout_url("http://localhost:8000")
        ```
        """
        params = {"redirect_uri": redirect_uri}
        return f"{self.base_url}/logout?{urlencode(params)}"

    @contextlib.asynccontextmanager
    async def _get_httpx_client(self):
        headers = {}
        if self.host is not None:
            headers["Host"] = self.host

        async with httpx.AsyncClient(
            base_url=self.base_url, headers=headers, verify=self.verify, cert=self.cert
        ) as client:
            yield client

    async def _get_openid_configuration(self) -> Dict[str, Any]:
        if self._openid_configuration is not None:
            return self._openid_configuration

        async with self._get_httpx_client() as client:
            request = self._get_openid_configuration_request(client)
            response = await client.send(request)
            json = response.json()
            self._openid_configuration = json
            return json

    async def _get_jwks(self) -> jwk.JWKSet:
        if self._jwks is not None:
            return self._jwks

        jwks_uri = self._get_endpoint_url(
            await self._get_openid_configuration(), "jwks_uri"
        )
        async with self._get_httpx_client() as client:
            response = await client.get(jwks_uri)
            self._jwks = jwk.JWKSet.from_json(response.text)
            return self._jwks

    async def _auth_exchange_token(
        self, code: str, redirect_uri: str, *, code_verifier: Optional[str] = None
    ) -> FiefTokenResponse:
        token_endpoint = self._get_endpoint_url(
            await self._get_openid_configuration(), "token_endpoint"
        )
        async with self._get_httpx_client() as client:
            request = self._get_auth_exchange_token_request(
                client,
                endpoint=token_endpoint,
                code=code,
                redirect_uri=redirect_uri,
                code_verifier=code_verifier,
            )
            response = await client.send(request)

            self._handle_request_error(response)

            return response.json()
