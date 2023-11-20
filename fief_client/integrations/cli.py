"""CLI integration."""
import functools
import http
import http.server
import json
import pathlib
import queue
import typing
import urllib.parse
import webbrowser

from halo import Halo

from fief_client import (
    Fief,
    FiefAccessTokenExpired,
    FiefAccessTokenInfo,
    FiefTokenResponse,
    FiefUserInfo,
)
from fief_client.pkce import get_code_challenge, get_code_verifier


class FiefAuthError(Exception):
    """
    Base error for FiefAuth integration.
    """


class FiefAuthNotAuthenticatedError(FiefAuthError):
    """
    The user is not authenticated.
    """

    pass


class FiefAuthAuthorizationCodeMissingError(FiefAuthError):
    """
    The authorization code was not found in the redirection URL.
    """

    pass


class FiefAuthRefreshTokenMissingError(FiefAuthError):
    """
    The refresh token is missing in the saved credentials.
    """

    pass


class CallbackHTTPServer(http.server.ThreadingHTTPServer):
    pass


class CallbackHTTPRequestHandler(http.server.BaseHTTPRequestHandler):
    def __init__(
        self,
        *args,
        queue: "queue.Queue[str]",
        render_success_page,
        render_error_page,
        **kwargs,
    ) -> None:
        self.queue = queue
        self.render_success_page = render_success_page
        self.render_error_page = render_error_page
        super().__init__(*args, **kwargs)

    def log_message(self, format: str, *args: typing.Any) -> None:
        pass

    def do_GET(self):
        parsed_url = urllib.parse.urlparse(self.path)
        query_params = urllib.parse.parse_qs(parsed_url.query)

        try:
            code = query_params["code"][0]
        except (KeyError, IndexError):
            output = self.render_error_page(query_params).encode("utf-8")
            self.send_response(http.HTTPStatus.BAD_REQUEST)
            self.send_header("Content-type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(output)))
            self.end_headers()
            self.wfile.write(output)
        else:
            self.queue.put(code)

            output = self.render_success_page().encode("utf-8")
            self.send_response(http.HTTPStatus.OK)
            self.send_header("Content-type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(output)))
            self.end_headers()
            self.wfile.write(output)

        self.server.shutdown()


class FiefAuth:
    """
    Helper class to integrate Fief authentication in a CLI tool.

    **Example:**

    ```py
    from fief_client import Fief
    from fief_client.integrations.cli import FiefAuth

    fief = Fief(
        "https://example.fief.dev",
        "YOUR_CLIENT_ID",
    )
    auth = FiefAuth(fief, "./credentials.json")
    ```
    """

    _userinfo: typing.Optional[FiefUserInfo] = None
    _tokens: typing.Optional[FiefTokenResponse] = None

    def __init__(self, client: Fief, credentials_path: str) -> None:
        """
        :param client: Instance of a Fief client.
        :param credentials_path: Path where the credentials will be stored on the user machine.
        We recommend you to use a library like [appdir](https://github.com/ActiveState/appdirs)
        to determine a reasonable path depending on the user's operating system.
        """
        self.client = client
        self.credentials_path = pathlib.Path(credentials_path)
        self._load_stored_credentials()

    def access_token_info(self, refresh: bool = True) -> FiefAccessTokenInfo:
        """
        Return credentials information saved on disk.

        Optionally, it can automatically get a fresh `access_token` if
        the saved one is expired.

        :param refresh: Whether the client should automatically refresh the token.
        Defaults to `True`.

        :raises: `FiefAuthNotAuthenticatedError` if the user is not authenticated.
        :raises: `fief_client.FiefAccessTokenExpired` if the access token is expired and automatic refresh is disabled.
        """
        if self._tokens is None:
            raise FiefAuthNotAuthenticatedError()

        access_token = self._tokens["access_token"]
        try:
            return self.client.validate_access_token(access_token)
        except FiefAccessTokenExpired:
            if refresh:
                self._refresh_access_token()
                return self.access_token_info()
            raise

    def current_user(self, refresh: bool = False) -> FiefUserInfo:
        """
        Return user information saved on disk.

        Optionally, it can automatically refresh it from the server if there
        is a valid access token.

        :param refresh: Whether the client should refresh the user information.
        Defaults to `False`.

        :raises: `FiefAuthNotAuthenticatedError` if the user is not authenticated.
        """
        if self._tokens is None or self._userinfo is None:
            raise FiefAuthNotAuthenticatedError()
        if refresh:
            access_token_info = self.access_token_info()
            userinfo = self.client.userinfo(access_token_info["access_token"])
            self._save_credentials(self._tokens, userinfo)
        return self._userinfo

    def authorize(
        self,
        server_address: typing.Tuple[str, int] = ("localhost", 51562),
        redirect_path: str = "/callback",
        *,
        scope: typing.Optional[typing.List[str]] = None,
        lang: typing.Optional[str] = None,
        extras_params: typing.Optional[typing.Mapping[str, str]] = None,
    ) -> typing.Tuple[FiefTokenResponse, FiefUserInfo]:
        """
        Perform a user authentication with the Fief server.

        It'll automatically open the user's default browser and redirect them
        to the Fief authorization page.

        Under the hood, the client opens a temporary web server.

        After a successful authentication, Fief will redirect to this web server
        so the client can catch the authorization code and generate a valid access token.

        Finally, it'll automatically save the credentials on disk.

        :param server_address: The address of the temporary web server the client should open.
        It's a tuple composed of the IP and the port. Defaults to `("localhost", 51562)`.
        :param redirect_path: Redirect URI where Fief will redirect after a successful authentication.
        Defaults to `/callback`.
        :param scope: Optional list of scopes to ask for.
        The client will **always** ask at least for `openid` and `offline_access`.
        :param lang: Optional parameter to set the user locale on the authentication pages.
        Should be a valid [RFC 3066](https://www.rfc-editor.org/rfc/rfc3066) language identifier, like `fr` or `pt-PT`.
        :param extras_params: Optional dictionary containing [specific parameters](https://docs.fief.dev/going-further/authorize-url/).

        **Example:**

        ```py
        tokens, userinfo = auth.authorize()
        ```
        """
        redirect_uri = f"http://{server_address[0]}:{server_address[1]}{redirect_path}"

        scope_set: typing.Set[str] = set(scope) if scope else set()
        scope_set.add("openid")
        scope_set.add("offline_access")

        code_verifier = get_code_verifier()
        code_challenge = get_code_challenge(code_verifier)

        authorization_url = self.client.auth_url(
            redirect_uri,
            scope=list(scope_set),
            code_challenge=code_challenge,
            code_challenge_method="S256",
            lang=lang,
            extras_params=extras_params,
        )
        webbrowser.open(authorization_url)

        spinner = Halo(
            text="Please complete authentication in your browser.", spinner="dots"
        )
        spinner.start()

        code_queue: queue.Queue[str] = queue.Queue()
        server = CallbackHTTPServer(
            server_address,
            functools.partial(
                CallbackHTTPRequestHandler,
                queue=code_queue,
                render_success_page=self.render_success_page,
                render_error_page=self.render_error_page,
            ),
        )

        server.serve_forever()

        try:
            code = code_queue.get(block=False)
        except queue.Empty as e:
            raise FiefAuthAuthorizationCodeMissingError() from e

        spinner.text = "Getting a token..."

        tokens, userinfo = self.client.auth_callback(
            code, redirect_uri, code_verifier=code_verifier
        )
        self._save_credentials(tokens, userinfo)

        spinner.succeed("Successfully authenticated")

        return tokens, userinfo

    def render_success_page(self) -> str:
        """
        Generate the HTML page that'll be shown to the user after a successful redirection.

        By default, it just tells the user that it can go back to the CLI.

        You can override this method if you want to customize this page.
        """
        return f"""
        <html>
            <head>
                <link href="{self.client.base_url}/static/auth.css" rel="stylesheet">
            </head>
            <body class="antialiased">
                <main>
                    <div class="relative flex">
                        <div class="w-full">
                            <div class="min-h-screen h-full flex flex flex-col after:flex-1">
                                <div class="flex-1"></div>
                                <div class="w-full max-w-sm mx-auto px-4 py-8 text-center">
                                    <h1 class="text-3xl text-accent font-bold mb-6">Done! You can go back to your terminal!</h1>
                                </div>
                            </div>
                        </div>
                    </div>
                </main>
                <script>
                    window.addEventListener("DOMContentLoaded", () => {{
                        setTimeout(() => {{
                            window.close();
                        }}, 5000);
                    }});
                </script>
            </body>
        </html>
        """

    def render_error_page(self, query_params: typing.Dict[str, typing.Any]) -> str:
        """
        Generate the HTML page that'll be shown to the user when something goes wrong during redirection.

        You can override this method if you want to customize this page.
        """
        return f"""
        <html>
            <head>
                <link href="{self.client.base_url}/static/auth.css" rel="stylesheet">
            </head>
            <body class="antialiased">
                <main>
                    <div class="relative flex">
                        <div class="w-full">
                            <div class="min-h-screen h-full flex flex flex-col after:flex-1">
                                <div class="flex-1"></div>
                                <div class="w-full max-w-sm mx-auto px-4 py-8 text-center">
                                    <h1 class="text-3xl text-accent font-bold mb-6">Something went wrong! You're not authenticated.</h1>
                                    <p>Error detail: {json.dumps(query_params)}</p>
                                </div>
                            </div>
                        </div>
                    </div>
                </main>
            </body>
        </html>
        """

    def _refresh_access_token(self):
        refresh_token = self._tokens.get("refresh_token")
        if refresh_token is None:
            raise FiefAuthRefreshTokenMissingError()
        tokens, userinfo = self.client.auth_refresh_token(refresh_token)
        self._save_credentials(tokens, userinfo)

    def _load_stored_credentials(self):
        if self.credentials_path.exists():
            with open(self.credentials_path) as file:
                try:
                    data = json.loads(file.read())
                    self._userinfo = data["userinfo"]
                    self._tokens = data["tokens"]
                except json.decoder.JSONDecodeError:
                    pass

    def _save_credentials(self, tokens: FiefTokenResponse, userinfo: FiefUserInfo):
        self._tokens = tokens
        self._userinfo = userinfo
        with open(self.credentials_path, "w") as file:
            data = {"userinfo": userinfo, "tokens": tokens}
            file.write(json.dumps(data))


__all__ = [
    "FiefAuth",
    "FiefAuthError",
    "FiefAuthNotAuthenticatedError",
    "FiefAuthAuthorizationCodeMissingError",
    "FiefAuthRefreshTokenMissingError",
]
