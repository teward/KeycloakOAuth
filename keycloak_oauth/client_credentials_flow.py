from datetime import datetime, timezone

from _base import BaseAuthHandler
from util import jwt_decode


class ClientCredentialsFlow(BaseAuthHandler):
    # noinspection PyTypeChecker
    def __init__(self, auth_server: str, realm: str, client_id: str, client_secret: str):
        super().__init__(auth_server, realm, client_id, client_secret)

        # Initialize certain properties
        self._access_token: str = None
        self._access_token_expiry: datetime = None
        self._refresh_token: str = None
        self._refresh_token_expiry: datetime = None

        # Get the token endpoint.
        self._token_endpoint = self._openid_config["token_endpoint"]

        self._auth_parameters = {
            "grant_type": "client_credentials",
            "client_id": client_id,
            "client_secret": client_secret
        }

    def __repr__(self):
        struct = ["<KeycloakOAuth.ClientCredentialFlow",
                  f"realm={self._realm}",
                  f"ClientID={self.client_id}"]
        if self._access_token:
            if self._access_token_expiry < datetime.now(tz=timezone.utc):
                struct.append("access_token=expired")
            else:
                struct.append("access_token=available")
        else:
            struct.append("access_token=empty")

        if self._refresh_token:
            if self._refresh_token_expiry < datetime.now(tz=timezone.utc):
                struct.append("refresh_token=expired")
            else:
                struct.append("refresh_token=available")
        else:
            struct.append("refresh_token=empty")

        return " ".join(struct) + ">"

    @property
    def token_endpoint(self) -> str:
        return self._token_endpoint

    # noinspection PyUnresolvedReferences
    @property
    def access_token(self) -> str | None:
        if self._access_token and self._access_token_expiry < datetime.now(tz=timezone.utc):
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

    def get_tokens(self) -> dict:
        data = dict(self._auth_parameters)
        token_request = self._session.post(
            self.token_endpoint, data=data, allow_redirects=False
        )

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
    def _refresh_access_token(self, refresh_token: str) -> dict:
        if not self._access_token:
            raise RuntimeError("You do not have a refresh token. Have you run through "
                               "the client credentials flow yet?")

        if self._refresh_token_expiry < datetime.now(tz=timezone.utc):
            raise RuntimeError("Your refresh token has expired. You must start over with "
                               "the entire OAuth flow from the beginning.")

        data = {
            "refresh_token": refresh_token,
            "grant_type": "refresh_token",
            "client_id": self.client_id,
            "client_secret": self.client_secret
        }

        refresh_req = self._session.post(self.token_endpoint, data=data, allow_redirects=False)

        if refresh_req.status_code != 200:
            raise RuntimeError("Unable to refresh token.")

        # Store current access token and expiry.
        self._access_token = refresh_token.json()["access_token"]
        self._access_token_expiry = datetime.fromtimestamp(
            int(jwt_decode(self.access_token)['exp']), tz=timezone.utc
        )

        # Store current refresh token and expiry in object
        self._refresh_token = refresh_req.json()['refresh_token']
        self._refresh_token_expiry = datetime.fromtimestamp(
            int(jwt_decode(self.refresh_token)['exp']), tz=timezone.utc
        )

        return refresh_req.json()

    # noinspection PyTypeChecker
    def refresh_access_token(self):
        return self._refresh_access_token(self.refresh_token)
