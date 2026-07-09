"""
Example script using the Auth Code Flow module in KeycloakOAuth
"""

# Install this with `pip install -U keycloak-oauth-system>=v0.1.0a4`
from keycloak_oauth import AuthCodeFlow

# Defined variables and parameters to use in the authorization code components.
base_url = "https://keycloak.example.com"
realm = "Example"
client_id = "31aec45b-f77e-4b19-9083-e2710bf8bb30"
client_secret = "x1eSS2CoH1nsOhc0CxiQl4iwunCB7Xuw"
user_id = "user@example.com"
user_password = "NotARealPassword!"

# Instantiate the Keycloak client that uses the AuthCodeFlow
oauth = AuthCodeFlow(
    auth_server=base_url,
    realm=realm,
    client_id=client_id,
    client_secret=client_secret,
    user_id=user_id,
    user_password=user_password
)

# Execute the complete auth flow. Then you can access the tokens from the object itself.
oauth.run_auth_flow()
print(f"access_token:\n{oauth.access_token}")
print(f"access_token_expiry: "
      f"{oauth.access_token_expiry.isoformat() if oauth.access_token_expiry else None}")
print(f"\nrefresh_token:\n{oauth.refresh_token}")
print(f"refresh_token_expiry: "
      f"{oauth.refresh_token_expiry.isoformat() if oauth.refresh_token_expiry else None}")

# You can run the refresh flow easily too, and it'll update the tokens in the object.
oauth.run_refresh_flow()
print(f"access_token:\n{oauth.access_token}")
print(f"access_token_expiry: "
      f"{oauth.access_token_expiry.isoformat() if oauth.access_token_expiry else None}")
print(f"\nrefresh_token:\n{oauth.refresh_token}")
print(f"refresh_token_expiry: "
      f"{oauth.refresh_token_expiry.isoformat() if oauth.refresh_token_expiry else None}")