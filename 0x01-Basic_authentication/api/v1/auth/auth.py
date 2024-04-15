#!/usr/bin/env python3
"""auth class implementation"""
from flask import request
from typing import List, TypeVar


class Auth:
    """Auth class implementation"""
    def require_auth(self, path: str, excluded_paths: List[str]) -> bool:
        """return False"""
        return False

    def authorization_header(self, request=None) -> str:
        """return None"""
        return None

    def current_user(self, request=None) -> TypeVar('User'):
        """return None"""
        return None
