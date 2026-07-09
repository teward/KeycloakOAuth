from urllib.parse import urljoin

import requests

from util import generate_random_string


# noinspection HttpUrlsUsage
class BaseAuthHandler:
    """
    Base class for various authentication handlers used in the application

    :ivar _session: The `requests.Session` object that is stored (with session cookies) for the
        OAuth processes.

    :param auth_server_base_url: The base URL for the Keycloak server being used
    :ivar _auth_server: Stored instance variable of the base URL

    :param realm: The realm you are using in Keycloak
    :ivar _realm: Stored instance variable of the realm.

    :param client_id: The Client ID for OAuth
    :ivar client_id: Stored instance variable of the Client ID

    :param client_secret: The Client Secret for OAuth
    :ivar client_secret: Stored instance variable of the Client Secret

    :ivar _redirect_uri: The Redirect URI to provide for OAuth, used for programmatic identification
        of redirect calls in HTTP status 301 callbacks from the Keycloak server

    :ivar _openid_config: Holds a JSON representation of the openid-configuration as obtained from
        the remote Keycloak auth server.

    :ivar _token_endpoint: Stored instance variable of the token endpoint, from _openid_config

    :raises ValueError: ValueError triggers when you do not have a proper base URL for the
        Keycloak server.
    :raises RuntimeError: RuntimeError triggers when we are unable to request the OpenID config
        from the remote Keycloak server.
    """
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
            raise RuntimeError("Could not get requisite information from NCFTA auth servers. "
                               "Double check the realm you specified.")
        ## We store the OpenID Configuration data here
        self._openid_config = _oidc.json()

        ## Only instantiate token endpoint which is common to all auth formats
        self._token_endpoint = self._openid_config["token_endpoint"]

        ## State is not used in every type of request, but it doesn't hurt to generate.
        self._state = generate_random_string(32)

    @property
    def realm(self) -> str:
        """
        The realm configured for use in Keycloak
        """
        return self._realm

    @property
    def auth_server(self) -> str:
        """
        The base URL for the auth server
        """
        return self._auth_server

    @property
    def token_endpoint(self) -> str:
        """
        The URL for the token endpoint on Keycloak
        """
        return self._token_endpoint

    @property
    def openid_configuration(self) -> dict:
        """
        The dictionary of the parsed openid-configuration from Keycloak
        """
        return self._openid_config
