from urllib.parse import parse_qs, urljoin

import requests

from .util import generate_random_string


# noinspection HttpUrlsUsage
class BaseAuthHandler:
    def __init__(self, auth_server_base_url: str, realm: str, client_id: str, client_secret: str):
        # Initialize a new HTTP requests Session for cookie integrity
        self._session = requests.Session()

        # Initialize certain static data values we'll need.
        if (not auth_server_base_url.lower().startswith('http://')
                and not auth_server_base_url.lower().startswith('https://')):
            raise ValueError("You did not provide a proper base URL for the Keycloak server you "
                             "wish to use. It must start with 'http://' or 'https://'")
        self._auth_server = auth_server_base_url  # Keycloak URL
        self._redirect_uri = "http://localhost/callback"

        # Some values are from input
        self._realm = realm  # auth realm in Keycloak
        self.client_id = client_id
        self.client_secret = client_secret

        # And now we also provide some fetched and calculated items.
        ## _oidc is used to get the OpenID Connect configuration which includes
        ## requisite items for the auth flows.  This is stored in _openid_config if
        ## the request returned a 200 OK response.
        _oidc = self._session.get(
            urljoin(self._auth_server, f'/realms/{self.realm}/.well-known/openid-configuration'),
        )
        if _oidc.status_code != 200:
            raise RuntimeError("Could not get requisite information from specified auth server. "
                               "Double check the realm you specified.")
        ## We store the OpenID Configuration data here
        self._openid_config = _oidc.json()

        ## Only instantiate token endpoint which is common to all auth formats
        self._token_endpoint = self._openid_config["token_endpoint"]

        ## State is not used in every type of request, but it doesn't hurt to generate.
        self._state = generate_random_string(32)

    @property
    def realm(self) -> str:
        return self._realm

    @property
    def auth_server(self) -> str:
        return self._auth_server

    @property
    def token_endpoint(self) -> str:
        return self._token_endpoint

    @property
    def openid_configuration(self) -> dict:
        return self._openid_config


class BaseAuthParameterGenerator:
    def __init__(self, auth_server: str, realm: str, client_id: str, client_secret: str):
        # Initialize a new HTTP requests Session for cookie integrity
        self._session = requests.Session()

        # Initialize certain static data values we'll need.
        self._auth_server = auth_server
        self._redirect_uri = "http://localhost/callback"

        # Some values are from input
        self._realm = realm  # auth realm in Keycloak
        self.client_id = client_id
        self.client_secret = client_secret

        # And now we also provide some fetched and calculated items.
        ## _oidc is used to get the OpenID Connect configuration which includes
        ## requisite items for the auth flows.  This is stored in _openid_config if
        ## the request returned a 200 OK response.

        ## Only instantiate token endpoint which is common to all auth formats
        self._token_endpoint = urljoin(self._auth_server,
                                       f"/realms/{self._realm}/protocol/openid-connect/token")

        ## State is not used in every type of request, but it doesn't hurt to generate.
        self._state = generate_random_string(32)

    @property
    def realm(self) -> str:
        return self._realm

    @property
    def auth_server(self) -> str:
        return self._auth_server

    @property
    def token_endpoint(self) -> str:
        return self._token_endpoint
