# -*- coding: utf-8 -*-
# ---------------------------------------------------------
# Name:         OAuth
# Purpose:      Login via the Caddy/Google OAuth portal and
#               manage the OAuth access token used by the API client
# ---------------------------------------------------------

import datetime
import sys

from reptor.lib.plugins.Base import Base


class OAuth(Base):
    meta = {
        "name": "OAuth",
        "summary": "Authenticate via Caddy/Google OAuth portal",
    }

    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.action = kwargs.get("action") or "status"
        self.force = kwargs.get("force", False)
        self.headless = kwargs.get("headless", False)
        self.timeout = kwargs.get("timeout", None)
        self.server = kwargs.get("server", None)

    @classmethod
    def add_arguments(cls, parser, plugin_filepath=None):
        super().add_arguments(parser, plugin_filepath=plugin_filepath)
        parser.add_argument(
            "action",
            nargs="?",
            default="status",
            choices=["login", "status", "logout"],
            help="Action to perform (default: status)",
        )
        parser.add_argument(
            "--force",
            action="store_true",
            help="Force a new login even if a valid token exists",
        )
        parser.add_argument(
            "--headless",
            action="store_true",
            help="Run Chrome headless (requires an existing browser session)",
        )
        parser.add_argument(
            "--timeout",
            dest="timeout",
            type=int,
            metavar="SECONDS",
            help="Maximum time to wait for the login to complete",
        )

    def _login(self):
        from reptor.oauth import manager

        data, fresh = manager.login(
            server=self.server,
            force=self.force,
            headless=self.headless or None,
            timeout=self.timeout,
        )
        if fresh:
            self.success("OAuth login successful. Token stored.")
        else:
            self.display("Existing OAuth token is still valid.")
        expires = data.get("access_expires_at")
        if expires:
            stamp = datetime.datetime.fromtimestamp(expires).isoformat()
            self.display(f"Access token expires at {stamp}.")
        if not data.get("refresh_token"):
            self.display(
                "No refresh token available; re-login is required on expiry."
            )

    def _status(self):
        from reptor.oauth import manager

        info = manager.status()
        self.display("OAuth status")
        self.print(f"Server:      {info['server']}")
        self.print(f"Enabled:     {info['enabled']}")
        self.print(f"Token file:  {info['token_file']}")
        self.print(f"Has token:   {info['has_token']}")
        self.print(f"Valid:       {info['valid']}")
        self.print(f"Has refresh: {info['has_refresh']}")
        if info.get("access_expires_at"):
            stamp = datetime.datetime.fromtimestamp(
                info["access_expires_at"]
            ).isoformat()
            self.print(f"Expires at:  {stamp}")
        self.print(f"Login URL:   {info['login_url']}")
        self.print(f"Provider:    {info['provider_url']}")

    def _logout(self):
        from reptor.oauth import manager

        manager.logout(server=self.server)
        self.success("OAuth token removed.")

    def run(self):
        if self.action == "login":
            self._login()
        elif self.action == "logout":
            self._logout()
        else:
            self._status()


loader = OAuth
