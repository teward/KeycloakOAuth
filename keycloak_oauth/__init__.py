"""
A set of classes that make it easy to handle OAuth 2.0 methods with Keycloak servers,
without the need to have a callback server by handling everything natively and programmatically.
"""

from .auth_code_flow import AuthCodeFlow
from .client_credentials_flow import ClientCredentialsFlow
from .device_code_flow import DeviceCodeFlow

__version__ = "0.1.0-alpha1"
