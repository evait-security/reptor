def install():
    from reptor.lib.conf import Config

    if getattr(Config, "_reptor_oauth_installed", False):
        return

    original_get_token = Config.get_token

    def get_token(self):
        from reptor.oauth import caddy, manager

        try:
            token = manager.maybe_token()
        except caddy.OAuthError as error:
            raise ValueError(str(error)) from error
        if token:
            return token
        return original_get_token(self)

    Config.get_token = get_token
    Config._reptor_oauth_installed = True
