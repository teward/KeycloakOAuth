"""
Device Code Flow module
"""

from datetime import datetime, timezone

import pyqrcode

from _base import BaseAuthHandler
from util import jwt_decode, max_seconds


class DeviceCodeFlow(BaseAuthHandler):
    """
    An authorization handler that handles the Device Code Flow for OAuth 2.0
    requests to a Keycloak server. Inherits from the `BaseAuthHandler` class.

    :param auth_server: Refer to `BaseAuthHandler` class.
    :param realm: Refer to `BaseAuthHandler` class.
    :param client_id: Refer to `BaseAuthHandler` class.
    :param client_secret: Refer to `BaseAuthHandler` class.

    :ivar _access_token: Internal class property to hold retrieved access token.
    :ivar _access_token_expiry: Internal class property to hold retrieved access token expiration.
    :ivar _refresh_token: Internal class property to hold retrieved refresh token.
    :ivar _refresh_token_expiry: Internal class property to hold retrieved refresh token expiration.

    :ivar _device_code_endpoint: Stored instance variable of the device code endpoint from
        _openid_config

    :raises RuntimeWarning: When using the access_token or refresh_token properties, the class
        will throw this warning if the token has already expired, based on its expiration time.

    :raises RuntimeError: Whenever an error is encountered during authentication processes,
        a RuntimeError will be raised that explains the encountered problem.
    """
    # noinspection PyTypeChecker
    def __init__(self, auth_server: str, realm: str, client_id: str, client_secret: str):
        super().__init__(auth_server, realm, client_id, client_secret)

        # Initialize certain properties as Empty
        self._access_token: str = None
        self._access_token_expiry: datetime = None
        self._refresh_token: str = None
        self._refresh_token_expiry: datetime = None

        self._device_code_endpoint = self._openid_config['device_authorization_endpoint']

    def __repr__(self):
        struct = ["<KeycloakOAuth.DeviceCodeFlow",
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

    # noinspection PyUnresolvedReferences
    @property
    def access_token(self) -> str | None:
        """
        The access token that was last retrieved using this OAuth handler instance, or None
        if an access token has not yet been retrieved.

        :raises RuntimeWarning: RuntimeWarning if the access token has expired.
        """
        if self._access_token and self.access_token_expiry < datetime.now(tz=timezone.utc):
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

    def _get_user_code(self) -> dict:
        """
        Executes the exchange between the client and the Keycloak server, and gets the
        verification code URL and the device code to enter on the Keycloak server page.
        :return: JSON object from the Keycloak device code endpoint containing all relevant
            data about the user code exchange.
        """

        # TODO: Make this code a little more robust including status code checking from endpoint.

        req = self._session.post(
            self._device_code_endpoint,
            data={"client_id": self.client_id, "client_secret": self.client_secret},
            allow_redirects=False
        )

        # self._device_code = req.json()["device_code"]
        # self._user_code = req.json()["user_code"]
        # self._verification_uri = req.json()["verification_uri"]
        # self._verification_uri_complete = req.json()["verification_uri_complete"]
        # self._expires_in = req.json()["expires_in"]
        # self._poll_interval = req.json()["interval"]

        return req.json()

    def authenticate(self) -> dict:
        """
        Executes the complete device code flow, including a QR code and link/code text output
        as part of the Python process.

        Polls the token endpoint at the Keycloak server's specified polling interval, until
        the maximum expiration time of the user code is reached.

        :return: A dict containing the JSON output from the token endpoint.

        :raises RuntimeError: Raised when a step in the process fails, with
            details about what failed or what issue was encountered.
        """
        print("To finish authentication, please scan the QR code (or use the link)")
        print("and the specified device code to complete login on the next screen.\n")
        input("Press Enter to generate the QR code, URL, and device code.")

        user_code = self._get_user_code()
        qr = pyqrcode.create(user_code["verification_uri_complete"])
        print(qr.terminal(quiet_zone=1))
        print(f"URL: {user_code["verification_uri_complete"]}")
        print(f"Device code: {user_code["device_code"]}\n")

        print("Waiting for authentication to complete...")

        for _ in max_seconds(max_seconds=user_code["expires_in"], interval=user_code["interval"]):
            token_request = self._session.post(
                self._token_endpoint,
                data={"device_code": user_code["device_code"],
                      "client_id": self.client_id,
                      "client_secret": self.client_secret,
                      "grant_type": "urn:ietf:params:oauth:grant-type:device_code"},
                allow_redirects=False)

            if 'error' in token_request.keys():
                continue
            elif 'access_token' in token_request.keys():
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
            else:
                raise RuntimeError("Unable to authenticate, unknown error.")

        raise RuntimeError("Device login timed out, restart the device code flow.")
