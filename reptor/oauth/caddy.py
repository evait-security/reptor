import base64
import json
import time
from urllib.parse import urlparse

import requests

from reptor.oauth import config


class OAuthError(RuntimeError):
    pass


def login_url(server, mount=None):
    mount = mount or config.portal_mount()
    return f"{server.rstrip('/')}{mount}/login"


def provider_url(server, provider=None, mount=None):
    provider = provider or config.provider()
    mount = mount or config.portal_mount()
    if not provider:
        return login_url(server, mount=mount)
    return f"{server.rstrip('/')}{mount}/oauth2/{provider}"


def api_url(server):
    return f"{server.rstrip('/')}/api/v1/"


def _base64url_decode(segment):
    padded = segment + "=" * (-len(segment) % 4)
    return base64.urlsafe_b64decode(padded)


def jwt_expires_at(token):
    try:
        payload = token.split(".")[1]
        data = json.loads(_base64url_decode(payload))
        exp = data.get("exp")
        return int(exp) if exp else None
    except (IndexError, ValueError, TypeError):
        return None


def _host_matches(cookie_domain, host):
    domain = (cookie_domain or "").lstrip(".").lower()
    host = (host or "").lower()
    return host == domain or host.endswith("." + domain)


def extract_tokens(cookies, server):
    host = urlparse(server).hostname or ""
    access_name = config.access_cookie()
    refresh_name = config.refresh_cookie()
    result = {}
    for cookie in cookies:
        if not _host_matches(cookie.get("domain", ""), host):
            continue
        if cookie.get("name") == access_name:
            result["access_token"] = cookie.get("value")
            result["access_expires_at"] = jwt_expires_at(cookie.get("value", ""))
        elif cookie.get("name") == refresh_name:
            result["refresh_token"] = cookie.get("value")
    return result


def _token_from_set_cookie(response):
    result = {}
    access_name = config.access_cookie()
    refresh_name = config.refresh_cookie()
    for raw in response.headers.get_all("Set-Cookie", []):
        name, _, rest = raw.partition("=")
        value = rest.split(";", 1)[0]
        if value in ("", "delete"):
            continue
        if name == access_name:
            result["access_token"] = value
            result["access_expires_at"] = jwt_expires_at(value)
        elif name == refresh_name:
            result["refresh_token"] = value
    return result


def refresh_access_token(server, refresh_token, timeout=30):
    url = f"{server.rstrip('/')}{config.refresh_path()}"
    response = requests.post(
        url,
        json={"refresh_token": refresh_token},
        headers={"Accept": "application/json"},
        timeout=timeout,
        verify=not config.insecure(),
        allow_redirects=False,
    )
    if response.status_code != 200:
        return None
    result = {}
    try:
        body = response.json()
    except ValueError:
        body = {}
    if body.get("access_token"):
        result["access_token"] = body["access_token"]
        result["access_expires_at"] = jwt_expires_at(body["access_token"]) or body.get(
            "access_expires_at"
        )
    if body.get("refresh_token"):
        result["refresh_token"] = body["refresh_token"]
    if not result.get("access_token"):
        result.update(_token_from_set_cookie(response))
    if not result.get("access_token"):
        return None
    return result


def logout(server, refresh_token, timeout=15):
    url = f"{server.rstrip('/')}{config.refresh_path()}"
    try:
        requests.post(
            url,
            json={"refresh_token": refresh_token},
            timeout=timeout,
            verify=not config.insecure(),
            allow_redirects=False,
        )
    except requests.RequestException:
        pass


def token_valid(data, margin=30):
    if not data or not data.get("access_token"):
        return False
    expires = data.get("access_expires_at")
    if expires is None:
        return True
    return int(expires) - margin > int(time.time())
