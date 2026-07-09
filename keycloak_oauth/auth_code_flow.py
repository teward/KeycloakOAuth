from datetime import datetime, timezone
import html
import re
from urllib.parse import urlparse, parse_qs

from ._base import BaseAuthHandler
from .util import generate_pkce, jwt_decode


class AuthCodeFlow(BaseAuthHandler):
    # noinspection PyTypeChecker
    def __init__(self, auth_server: str, realm: str, client_id: str, client_secret: str,
                 user_id: str, user_password: str, use_pkce: bool = False):
        super().__init__(auth_server, realm, client_id, client_secret)

        # Initialize certain properties as Empty
        self._access_token: str = None
        self._access_token_expiry: datetime = None
        self._refresh_token: str = None
        self._refresh_token_expiry: datetime = None

        # Auth Code Flow uses the BaseAuthHandler but also has some extra bits we have to do.
        # Namely, we need user credentials, and determine if we need PKCE or not.

        # Auth Code Flow depends on the authorization endpoint, which is NOT
        # instantiated as a property in the Base Auth handler
        self._authorization_endpoint = self._openid_config["authorization_endpoint"]

        # We only add PKCE data if it's needed
        if use_pkce:
            self._pkce = generate_pkce()
        else:
            self._pkce = {}

        # We can now, however, set up dictionaries we'll need later.
        self._user_credentials = {
            "username": user_id,
            "password": user_password
        }

        self._auth_login_parameters = {
            "response_type": "code",
            "client_id": self.client_id,
            "scope": "openid",
            "redirect_uri": self._redirect_uri,
            "state": self._state
        }

        self._token_endpoint_base_data = {
            "grant_type": "authorization_code",
            "client_id": self.client_id,
            "client_secret": self.client_secret,
            "redirect_uri": self._redirect_uri,
        }

        if self._pkce:  # This will only work if the dictionary is not empty!
            # If the self._pkce dict is NOT an empty dictionary, then we have to use PKCE
            self._auth_login_parameters["code_challenge"] = self._pkce['challenge']
            self._auth_login_parameters["code_challenge_method"] = "S256"
            self._token_endpoint_base_data["code_verifier"] = self._pkce["verifier"]

    def __repr__(self):
        struct = ["<KeycloakOAuth.AuthCodeFlow",
                  f"pkce={'yes' if self._pkce else 'no'}",
                  f"realm={self._realm}",
                  f"ClientID={self.client_id}"]
        if self.access_token:
            # noinspection PyUnresolvedReferences
            if self.access_token_expiry < datetime.now(tz=timezone.utc):
                struct.append("access_token=expired")
            else:
                struct.append("access_token=available")
        else:
            struct.append("access_token=empty")

        if self.refresh_token:
            # noinspection PyUnresolvedReferences
            if self.refresh_token_expiry < datetime.now(tz=timezone.utc):
                struct.append("refresh_token=expired")
            else:
                struct.append("refresh_token=available")
        else:
            struct.append("refresh_token=empty")

        return " ".join(struct) + ">"

    @property
    def authorization_endpoint(self) -> str:
        # This is added here because it is not part of the core BaseAuthHandler class
        return self._authorization_endpoint

    # noinspection PyUnresolvedReferences
    @property
    def access_token(self) -> str | None:
        if self._access_token and self.access_token_expiry < datetime.now(tz=timezone.utc):
            raise RuntimeWarning("WARNING: The retrieved access key is expired.")
        return self._access_token

    @property
    def access_token_expiry(self) -> datetime | None:
        return self._access_token_expiry

    # noinspection PyUnresolvedReferences
    @property
    def refresh_token(self) -> str | None:
        if self._refresh_token and self.refresh_token_expiry < datetime.now(tz=timezone.utc):
            raise RuntimeWarning("WARNING: The retrieved refresh key is expired.")
        return self._refresh_token

    @property
    def refresh_token_expiry(self) -> datetime | None:
        return self._refresh_token_expiry

    # noinspection PyUnresolvedReferences
    def get_authorization_code(self) -> str:
        login_page = self._session.get(
            self.authorization_endpoint, params=self._auth_login_parameters, allow_redirects=False
        )
        if login_page.status_code != 200:
            raise RuntimeError("Could not get login page or login endpoint URL, invalid response"
                               f"code from server: {login_page.status_code}")

        form_action = html.unescape(
            re.search(r'<form\s+.*?\s+action="(.*?)"',
                      login_page.text, re.DOTALL).group(1)
        )

        auth_resp = self._session.post(
            form_action, data=self._user_credentials, allow_redirects=False
        )
        if auth_resp.status_code not in [300, 301, 302]:
            raise RuntimeError("Unable to get an authorization code with provided login "
                               "credentials; possible login failure or invalid creds.")

        auth_redirect_params = parse_qs(urlparse(auth_resp.headers['Location']).query)
        try:
            auth_code = auth_redirect_params['code'][0]
        except KeyError:
            raise RuntimeError(f"No code in response.")

        return auth_code

    def get_tokens_from_code(self, code: str) -> dict:
        data = dict(self._token_endpoint_base_data)
        data['code'] = code

        token_request = self._session.post(
            self.token_endpoint, data=data, allow_redirects=False
        )
        if token_request.status_code != 200:
            raise RuntimeError("Unable to exchange authorization code for token.")

        # Store current access token and expiry in object
        self._access_token = token_request.json()['access_token']
        self._access_token_expiry = datetime.fromtimestamp(
            int(jwt_decode(self._access_token)['exp']), tz=timezone.utc
        )

        # Store current refresh token and expiry in object
        self._refresh_token = token_request.json()['refresh_token']
        self._refresh_token_expiry = datetime.fromtimestamp(
            int(jwt_decode(self._refresh_token)['exp']), tz=timezone.utc
        )

        return token_request.json()

    # noinspection PyTypeChecker
    def refresh_access_token(self, refresh_token: str):
        # First we need to check the refresh token, which is a JWT,
        # and its embedded 'exp' UNIX timestamp against now.
        expiry = datetime.fromtimestamp(
            int(jwt_decode(refresh_token)['exp']),
            tz=timezone.utc
            )
        if expiry < datetime.now(tz=timezone.utc):
            raise RuntimeError("Your refresh token has expired. You must start over with "
                               "the entire OAuth flow from the beginning.")

        data = {
            "refresh_token": refresh_token,
            "grant_type": "refresh_token",
            "client_id": self.client_id,
            "client_secret": self.client_secret
        }

        refresh_req = self._session.post(
            self.token_endpoint, data=data, allow_redirects=False
        )
        if refresh_req.status_code != 200:
            raise RuntimeError("Unable to refresh token.")

        # Store current access token and expiry in object
        self._access_token = refresh_req.json()['access_token']
        self._access_token_expiry = datetime.fromtimestamp(
            int(jwt_decode(self.access_token)['exp']), tz=timezone.utc
        )

        # Store current refresh token and expiry in object
        self._refresh_token = refresh_req.json()['refresh_token']
        self._refresh_token_expiry = datetime.fromtimestamp(
            int(jwt_decode(self.refresh_token)['exp']), tz=timezone.utc
        )

        return refresh_req.json()

    def run_auth_flow(self) -> dict:
        auth_code = self.get_authorization_code()
        tokens = self.get_tokens_from_code(auth_code)

        return tokens

    # noinspection PyTypeChecker
    def run_refresh_flow(self) -> dict:
        return self.refresh_access_token(self.refresh_token)
