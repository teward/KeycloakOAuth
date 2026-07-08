import base64
import time
from datetime import datetime, timezone
import hashlib
import json
import secrets

from string import ascii_letters, digits


def generate_random_string(length: int = 32) -> str:
    """
    Helper function used to generate random cryptographically-safe strings
    :param length: (int) length of string to generate, defaults to 32
    :return: random string of letters and numbers of specified length.
    """
    return "".join(secrets.choice(ascii_letters + digits) for _ in range(length))


def generate_pkce(length: int = 64) -> dict[str, str]:
    """
    Helper function that can generate PKCE parameters.
    :param length:
    :return:
    """
    verifier = generate_random_string(length)
    challenge = base64.urlsafe_b64encode(
        hashlib.sha256(
            verifier.encode('utf-8')
        ).digest()).decode('utf-8').replace('=', '')
    return {
        'verifier': verifier,
        'challenge': challenge
    }


def jwt_decode(jwt: str) -> dict:
    _, payload, _ = jwt.split('.')
    data = payload + "=" * (4 - len(jwt) % 4)
    decoded = base64.b64decode(data).decode('utf-8')
    return json.loads(decoded)


def token_is_valid(token: str) -> tuple[bool, str | None]:
    # noinspection PyBroadException
    try:
        jwt = jwt_decode(token)
    except Exception:
        return False, "Token could not be decoded"
    expiry = datetime.fromtimestamp(int(jwt['exp']), tz=timezone.utc)
    if expiry < datetime.now(tz=timezone.utc):
        return False, "Expired"

    return True, "Presumed valid, but can only be confirmed against the auth server."


def max_seconds(max_seconds: int, interval: int = 5):
    start_time = time.time()
    end_time = start_time + max_seconds
    yield 0
    while time.time() < end_time:
        if interval > 0:
            next_time = start_time
            while next_time < time.time():
                next_time += interval
            time.sleep(int(round(next_time - time.time())))
        yield int(round(time.time() - start_time))
        if int(round(time.time() + interval)) > int(round(end_time)):
            return
