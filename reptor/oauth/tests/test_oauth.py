import base64
import json
from unittest.mock import MagicMock, patch

import pytest

from reptor.lib.conf import Config
from reptor.oauth import caddy, config
from reptor.oauth.install import install
from reptor.oauth.store import TokenStore

SERVER = "https://reptor.example.test"


def _jwt(exp):
    header = base64.urlsafe_b64encode(b'{"alg":"RS256"}').rstrip(b"=").decode()
    payload = base64.urlsafe_b64encode(json.dumps({"exp": exp}).encode()).rstrip(b"=").decode()
    return f"{header}.{payload}.signature"


class TestJwt:
    def test_exp_is_decoded(self):
        assert caddy.jwt_expires_at(_jwt(2000000000)) == 2000000000

    def test_invalid_token_returns_none(self):
        assert caddy.jwt_expires_at("not-a-jwt") is None


class TestExtractTokens:
    def test_extracts_access_and_refresh_for_matching_domain(self):
        host = "reptor.example.test"
        token = _jwt(2000000000)
        cookies = [
            {"name": config.access_cookie(), "value": token, "domain": host},
            {"name": config.refresh_cookie(), "value": "refresh-value", "domain": "." + host},
            {"name": "OTHER", "value": "x", "domain": "other.example.test"},
        ]
        result = caddy.extract_tokens(cookies, SERVER)
        assert result["access_token"] == token
        assert result["access_expires_at"] == 2000000000
        assert result["refresh_token"] == "refresh-value"

    def test_ignores_other_domains(self):
        cookies = [
            {"name": config.access_cookie(), "value": _jwt(1), "domain": "other.test"}
        ]
        assert caddy.extract_tokens(cookies, SERVER) == {}


class TestTokenValidity:
    def test_valid_when_not_expired(self):
        assert caddy.token_valid({"access_token": "t", "access_expires_at": 2000000000})

    def test_invalid_when_expired(self):
        assert not caddy.token_valid({"access_token": "t", "access_expires_at": 1})

    def test_invalid_without_token(self):
        assert not caddy.token_valid({"access_expires_at": 2000000000})


class TestTokenStore:
    def test_roundtrip(self, tmp_path):
        store = TokenStore(tmp_path / "token.json")
        store.save({"server": SERVER, "access_token": "abc"})
        assert store.load()["access_token"] == "abc"
        store.clear()
        assert store.load() is None

    def test_missing_file_returns_none(self, tmp_path):
        assert TokenStore(tmp_path / "nope.json").load() is None


class TestConfig:
    def test_defaults(self, monkeypatch):
        for name in list(__import__("os").environ):
            if name.startswith("REPTOR_OAUTH_"):
                monkeypatch.delenv(name, raising=False)
        Config()._raw_config = {"server": SERVER}
        assert config.enabled() is False
        assert config.portal_mount() == config.DEFAULT_PORTAL_MOUNT
        assert config.refresh_path() == "/0x00_auth/api/refresh_token"

    def test_env_overrides(self, monkeypatch):
        monkeypatch.setenv("REPTOR_OAUTH_ENABLED", "true")
        monkeypatch.setenv("REPTOR_OAUTH_PORTAL_MOUNT", "auth")
        Config()._raw_config = {"server": SERVER}
        assert config.enabled() is True
        assert config.portal_mount() == "/auth"

    def test_login_url(self, monkeypatch):
        monkeypatch.delenv("REPTOR_OAUTH_PORTAL_MOUNT", raising=False)
        Config()._raw_config = {"server": SERVER}
        assert caddy.login_url(SERVER) == SERVER + "/0x00_auth/login"

    def test_provider_url(self, monkeypatch):
        monkeypatch.delenv("REPTOR_OAUTH_PORTAL_MOUNT", raising=False)
        monkeypatch.delenv("REPTOR_OAUTH_PROVIDER", raising=False)
        Config()._raw_config = {"server": SERVER}
        assert caddy.provider_url(SERVER) == SERVER + "/0x00_auth/oauth2/google"


class TestRefresh:
    def test_parses_json_body(self, monkeypatch):
        response = MagicMock()
        response.status_code = 200
        response.json.return_value = {
            "access_token": _jwt(2000000000),
            "refresh_token": "new-refresh",
        }
        response.headers.get_all.return_value = []
        with patch("reptor.oauth.caddy.requests.post", return_value=response):
            result = caddy.refresh_access_token(SERVER, "old-refresh")
        assert result["access_token"] == _jwt(2000000000)
        assert result["access_expires_at"] == 2000000000
        assert result["refresh_token"] == "new-refresh"

    def test_falls_back_to_set_cookie(self):
        response = MagicMock()
        response.status_code = 200
        response.json.return_value = {}
        response.headers.get_all.return_value = [
            f"{config.access_cookie()}={_jwt(2000000000)}; Path=/; HttpOnly"
        ]
        with patch("reptor.oauth.caddy.requests.post", return_value=response):
            result = caddy.refresh_access_token(SERVER, "old-refresh")
        assert result["access_token"] == _jwt(2000000000)

    def test_returns_none_on_error_status(self):
        response = MagicMock()
        response.status_code = 401
        with patch("reptor.oauth.caddy.requests.post", return_value=response):
            assert caddy.refresh_access_token(SERVER, "old-refresh") is None


class TestManager:
    @pytest.fixture(autouse=True)
    def setUp(self, tmp_path, monkeypatch):
        from reptor.oauth import manager

        manager._cache.clear()
        monkeypatch.setenv("REPTOR_OAUTH_TOKEN_FILE", str(tmp_path / "token.json"))
        monkeypatch.setenv("REPTOR_OAUTH_ENABLED", "true")
        monkeypatch.delenv("REPTOR_OAUTH_AUTO_LOGIN", raising=False)
        Config()._raw_config = {"server": SERVER}
        self.manager = manager

    def _store(self, data):
        TokenStore().save(data | {"server": SERVER})

    def test_disabled_returns_none(self, monkeypatch):
        monkeypatch.setenv("REPTOR_OAUTH_ENABLED", "false")
        assert self.manager.maybe_token() is None

    def test_valid_stored_token_is_returned(self):
        token = _jwt(2000000000)
        self._store({"access_token": token, "access_expires_at": 2000000000})
        assert self.manager.maybe_token() == token

    def test_expired_token_uses_refresh(self):
        self._store(
            {"access_token": _jwt(1), "access_expires_at": 1, "refresh_token": "r"}
        )
        new_token = _jwt(2000000000)
        with patch(
            "reptor.oauth.manager.caddy.refresh_access_token",
            return_value={"access_token": new_token, "access_expires_at": 2000000000},
        ):
            assert self.manager.maybe_token() == new_token

    def test_missing_token_raises_without_auto_login(self, monkeypatch):
        monkeypatch.setenv("REPTOR_OAUTH_AUTO_LOGIN", "false")
        with pytest.raises(self.manager.LoginRequired):
            self.manager.maybe_token()

    def test_auto_login_is_used(self, monkeypatch):
        monkeypatch.setenv("REPTOR_OAUTH_AUTO_LOGIN", "true")
        token = _jwt(2000000000)
        with patch(
            "reptor.oauth.manager.login",
            return_value=(
                {"access_token": token, "access_expires_at": 2000000000},
                True,
            ),
        ):
            assert self.manager.maybe_token() == token


class TestInstall:
    def test_install_is_idempotent(self):
        from reptor.lib.conf import Config as C

        install()
        first = C.get_token
        install()
        assert C.get_token is first
