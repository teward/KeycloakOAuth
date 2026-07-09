"""
Client Credentials Flow module
"""

from datetime import datetime, timezone

from _base import BaseAuthHandler
from util import jwt_decode


class ClientCredentialsFlow(BaseAuthHandler):
    """
    An authorization handler that handles the Client Credentials Flow for OAuth 2.0
    requests to a Keycloak server.  Inherits from the :class:`BaseAuthHandler <keycloak_oauth._base.BaseAuthHandler` class.

    :param auth_server: Refer to :class:`BaseAuthHandler <keycloak_oauth._base.BaseAuthHandler` class.
    :param realm: Refer to :class:`BaseAuthHandler <keycloak_oauth._base.BaseAuthHandler` class.
    :param client_id: Refer to :class:`BaseAuthHandler <keycloak_oauth._base.BaseAuthHandler` class.
    :param client_secret: Refer to :class:`BaseAuthHandler <keycloak_oauth._base.BaseAuthHandler` class.

    :ivar _access_token: Internal class property to hold retrieved access token.
    :ivar _access_token_expiry: Internal class property to hold retrieved access token expiration.
    :ivar _refresh_token: Internal class property to hold retrieved refresh token.
    :ivar _refresh_token_expiry: Internal class property to hold retrieved refresh token expiration.

    :ivar _auth_parameters: Generated dictionary containing the client id and secret, and the
        grant type used for the client credentials flow.

    :raises RuntimeWarning: When using the access_token or refresh_token properties, the class
        will throw this warning if the token has already expired, based on its expiration time.

    :raises RuntimeError: Whenever an error is encountered during authentication processes,
        a RuntimeError will be raised that explains the encountered problem.
    """
    # noinspection PyTypeChecker
    def __init__(self, auth_server: str, realm: str, client_id: str, client_secret: str):
        super().__init__(auth_server, realm, client_id, client_secret)

        # Initialize certain properties
        self._access_token: str = None
        self._access_token_expiry: datetime = None
        self._refresh_token: str = None
        self._refresh_token_expiry: datetime = None

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

    # noinspection PyUnresolvedReferences
    @property
    def access_token(self) -> str | None:
        """
        The access token that was last retrieved using this OAuth handler instance, or None
        if an access token has not yet been retrieved.

        :raises RuntimeWarning: RuntimeWarning if the access token has expired.
        """
        if self._access_token and self._access_token_expiry < datetime.now(tz=timezone.utc):
            raise RuntimeWarning("WARNING: The retrieved access key is expired.")
        return self._access_token

    @property
    def access_token_expiry(self) -> datetime | None:
        """
        The access token expiration (as a datetime object) for the last retrieved access token, or
        None if an access token has not yet been retrieved.
        """
        return self._access_token_expiry

    # noinspection PyUnresolvedReferences
    @property
    def refresh_token(self) -> str | None:
        """
        The refresh tokekn that was last retrieved using this OAuth handler instance, or None
        if a refresh token has not yet been retrieved.

        :raises RuntimeWarning: RuntimeWarning if the refresh token has expired.
        """
        if self._refresh_token and self.refresh_token_expiry < datetime.now(tz=timezone.utc):
            raise RuntimeWarning("WARNING: The retrieved refresh key is expired.")
        return self._refresh_token

    @property
    def refresh_token_expiry(self) -> datetime | None:
        """
        The refresh token expiration (as a datetime object) for the last retrieved refresh token, or
        None if an refresh token has not yet been retrieved.
        """
        return self._refresh_token_expiry

    def get_tokens(self) -> dict:
        """
        Executes the exchange of the client id and secret for tokens using the Client
            Credentials flow

        Also updates internal variables and properties with the retrieved access and refresh
        tokens.

        :return: A dict built from the JSON response from the token endpoint after the code is
            exchanged.

        :raises RuntimeError: Raised when we failed to exchange the authorization code.
        """
        data = dict(self._auth_parameters)
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
    def _refresh_access_token(self, refresh_token: str) -> dict:
        """
        Executes the process to exchange a refresh token for a new access token.

        Also updates internal variables and properties with newly retrieved access and refresh
        tokens.

        :param refresh_token: The refresh token to use to get a new access token.
        :return: A dict built from the JSON response from the token endpoint after the refresh
            token is exchanged for new access tokens.

        :raises RuntimeError: Raised when a step in the process fails, with
            details about what failed or what issue was encountered.
        """
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

        refresh_req = self._session.post(self.token_endpoint, data=data, allow_redirects=False)

        if refresh_req.status_code != 200:
            raise RuntimeError("Unable to refresh token.")

        # Store current access token and expiry.
        self._access_token = refresh_token.json().get("access_token", None)
        self._access_token_expiry = datetime.fromtimestamp(
            int(jwt_decode(self.access_token)['exp']), tz=timezone.utc
        )

        # Store current refresh token and expiry in object
        self._refresh_token = refresh_req.json().get('refresh_token', None)
        self._refresh_token_expiry = datetime.fromtimestamp(
            int(jwt_decode(self.refresh_token)['exp']), tz=timezone.utc
        )

        return refresh_req.json()

    # noinspection PyTypeChecker
    def refresh_access_token(self):
        """
        Executes the refresh token flow to get a new access token from a refresh token,
        using the data already stored in the class.

        Essentially a helper function that wraps around the refresh flow using data from the
        object instance.

        :return: A dict containing the tokens from the `refresh_access_token` flow.

        :raises RuntimeError: Errors if you do not have a refresh token available for use.
        """
        if not self.refresh_token:
            raise RuntimeError("You do not have a refresh token available for use.")
        return self._refresh_access_token(self.refresh_token)
