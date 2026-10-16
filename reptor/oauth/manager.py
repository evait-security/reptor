import sys
import time

from reptor.lib.conf import Config
from reptor.oauth import caddy, config
from reptor.oauth.store import TokenStore

_cache = {}


class LoginRequired(caddy.OAuthError):
    pass


def _login_hint(server):
    return (
        f"No valid OAuth token for {server}. Run 'reptor oauth login' "
        f"or open {caddy.login_url(server)} and complete the login."
    )


def _login_message(enabled_auto):
    if enabled_auto:
        return (
            "Waiting for Google/Caddy login in the opened browser window "
            "(close it to abort)..."
        )
    return "OAuth login required."


def _enable():
    cfg = Config()
    cfg.set("oauth_enabled", True)
    try:
        cfg._write_to_file({"oauth_enabled": True})
    except Exception:
        pass


def capture_via_browser(
    server, timeout=None, headless=None, binary=None, profile=None, force=False
):
    from reptor.oauth.browser import Chrome

    timeout = timeout or config.timeout()
    headless = config.headless() if headless is None else headless
    binary = binary or config.chrome_binary()
    profile = profile or config.profile_dir()
    if not binary:
        raise caddy.OAuthError(
            "No Chrome/Chromium binary found. Set REPTOR_OAUTH_CHROME or "
            "oauth_chrome in the config."
        )

    url = caddy.provider_url(server)
    print(
        f"[oauth] Opening {url} in Chrome. Log in with Google to continue.",
        file=sys.stderr,
    )
    if headless:
        print(
            "[oauth] Headless mode: an existing browser session is required.",
            file=sys.stderr,
        )
    chrome = Chrome(binary, profile, headless=headless)
    try:
        devtools = chrome.open(url, timeout=30)
        deadline = time.time() + timeout
        while time.time() < deadline:
            tokens = caddy.extract_tokens(devtools.cookies(), server)
            if caddy.token_valid(tokens):
                return tokens
            time.sleep(1)
        raise caddy.OAuthError(
            f"Timed out after {timeout}s waiting for the login to complete."
        )
    finally:
        chrome.close()


def login(
    server=None,
    force=False,
    headless=None,
    timeout=None,
    binary=None,
    profile=None,
    enable=True,
):
    server = server or config.server()
    store = TokenStore()
    if not force:
        data = store.load()
        if data and data.get("server") == server and caddy.token_valid(data):
            return data, False
    tokens = capture_via_browser(
        server,
        timeout=timeout,
        headless=headless,
        binary=binary,
        profile=profile,
        force=force,
    )
    tokens["server"] = server
    tokens["obtained_at"] = int(time.time())
    tokens["portal_mount"] = config.portal_mount()
    store.save(tokens)
    _cache["data"] = tokens
    if enable:
        _enable()
    return tokens, True


def _refresh(server, data):
    refresh_token = data.get("refresh_token")
    if not refresh_token:
        return None
    refreshed = caddy.refresh_access_token(server, refresh_token, timeout=30)
    if not refreshed:
        return None
    data.update(refreshed)
    data["obtained_at"] = int(time.time())
    TokenStore().save(data)
    _cache["data"] = data
    return data


def maybe_token():
    if not config.enabled():
        return None

    server = config.server()
    cached = _cache.get("data")
    if cached and cached.get("server") == server and caddy.token_valid(cached):
        return cached["access_token"]

    store = TokenStore()
    data = store.load()
    if data and data.get("server") == server:
        if caddy.token_valid(data):
            _cache["data"] = data
            return data["access_token"]
        refreshed = _refresh(server, data)
        if refreshed:
            return refreshed["access_token"]

    if config.auto_login():
        data, _ = login(server=server, enable=True)
        return data["access_token"]

    raise LoginRequired(_login_hint(server))


def status():
    server = config.server()
    store = TokenStore()
    data = store.load()
    info = {
        "enabled": config.enabled(),
        "server": server,
        "token_file": str(store.path),
        "has_token": bool(data and data.get("access_token")),
        "valid": caddy.token_valid(data) if data else False,
        "has_refresh": bool(data and data.get("refresh_token")),
        "access_expires_at": data.get("access_expires_at") if data else None,
        "login_url": caddy.login_url(server),
        "provider_url": caddy.provider_url(server),
    }
    return info


def logout(server=None):
    server = server or config.server()
    store = TokenStore()
    data = store.load()
    if data and data.get("server") == server and data.get("refresh_token"):
        caddy.logout(server, data["refresh_token"])
    store.clear()
    _cache.pop("data", None)
