import os
import pathlib
import shutil

import reptor.settings as settings
from reptor.lib.conf import Config

DEFAULT_PORTAL_MOUNT = "/0x00_auth"
DEFAULT_ACCESS_COOKIE = "AUTHP_ACCESS_TOKEN"
DEFAULT_REFRESH_COOKIE = "AUTHP_REFRESH_TOKEN"
DEFAULT_PORTAL_URL_COOKIE = "AUTHP_SESSION_ID"

CHROME_CANDIDATES = [
    "google-chrome-stable",
    "google-chrome",
    "chromium",
    "chromium-browser",
    "brave-browser",
    "brave",
    "microsoft-edge",
    "microsoft-edge-stable",
]


def _value(env_name, config_key, default=None):
    value = os.environ.get(env_name)
    if value is not None:
        return value
    return Config().get(config_key, default)


def _as_bool(value, default=False):
    if value is None:
        return default
    if isinstance(value, bool):
        return value
    return str(value).strip().lower() in ("1", "true", "yes", "on")


def _as_int(value, default):
    if value is None or value == "":
        return default
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


def enabled():
    return _as_bool(_value("REPTOR_OAUTH_ENABLED", "oauth_enabled", False))


def server():
    return Config().get_server()


def portal_mount():
    mount = _value("REPTOR_OAUTH_PORTAL_MOUNT", "oauth_portal_mount", DEFAULT_PORTAL_MOUNT)
    mount = "/" + str(mount).strip("/")
    return mount


def provider():
    return _value("REPTOR_OAUTH_PROVIDER", "oauth_provider", "google")


def access_cookie():
    return _value("REPTOR_OAUTH_ACCESS_COOKIE", "oauth_access_cookie", DEFAULT_ACCESS_COOKIE)


def refresh_cookie():
    return _value(
        "REPTOR_OAUTH_REFRESH_COOKIE", "oauth_refresh_cookie", DEFAULT_REFRESH_COOKIE
    )


def refresh_path():
    return _value(
        "REPTOR_OAUTH_REFRESH_PATH", "oauth_refresh_path", f"{portal_mount()}/api/refresh_token"
    )


def chrome_binary():
    configured = _value("REPTOR_OAUTH_CHROME", "oauth_chrome", None)
    if configured:
        return str(configured)
    for candidate in CHROME_CANDIDATES:
        found = shutil.which(candidate)
        if found:
            return found
    return None


def profile_dir():
    configured = _value("REPTOR_OAUTH_PROFILE_DIR", "oauth_profile_dir", None)
    if configured:
        return pathlib.Path(configured).expanduser()
    return settings.PERSONAL_SYSREPTOR_HOME / "chrome"


def token_file():
    configured = _value("REPTOR_OAUTH_TOKEN_FILE", "oauth_token_file", None)
    if configured:
        return pathlib.Path(configured).expanduser()
    return settings.PERSONAL_SYSREPTOR_HOME / "oauth_token.json"


def auto_login():
    return _as_bool(_value("REPTOR_OAUTH_AUTO_LOGIN", "oauth_auto_login", True))


def headless():
    return _as_bool(_value("REPTOR_OAUTH_HEADLESS", "oauth_headless", False))


def timeout():
    return _as_int(_value("REPTOR_OAUTH_TIMEOUT", "oauth_timeout", 300), 300)


def insecure():
    return _as_bool(Config().get("insecure", False))
