"""OAuth / pre-authentication support for SysReptor behind caddy-security.

This package is an additive fork extension. It hooks into the existing
configuration so the API client transparently uses a token obtained via the
Caddy authentication portal instead of a static SysReptor API token.
"""

from reptor.oauth.install import install

__all__ = ["install"]
