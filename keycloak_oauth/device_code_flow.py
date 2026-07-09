from datetime import datetime, timezone

import pyqrcode

from ._base import BaseAuthHandler
from .util import jwt_decode, max_seconds


class DeviceCodeFlow(BaseAuthHandler):
    # noinspection PyTypeChecker
    def __init__(self, auth_server: str, realm: str, client_id: str, client_secret: str):
        super().__init__(auth_server, realm, client_id, client_secret)

        # Initialize certain properties as Empty
        self._access_token: str = None
        self._access_token_expiry: datetime = None
        self._refresh_token: str = None
        self._refresh_token_expiry: datetime = None

        self._device_code_endpoint = self._openid_config['device_authorization_endpoint']

    def _get_user_code(self) -> dict:
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

        raise RuntimeError("Device login timed out, restart auth process.")
