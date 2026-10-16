from reptor.lib.reptor import Reptor
from reptor.oauth import install as _install_oauth

_install_oauth()

__all__ = ["Reptor"]
