"""Authentication module for RE-Architect."""

from .middleware import login_required

__all__ = ['login_required']