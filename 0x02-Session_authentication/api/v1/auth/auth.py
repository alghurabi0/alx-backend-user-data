#!/usr/bin/env python3
"""auth class implementation"""
from flask import request
from typing import List, TypeVar


class Auth:
    """Auth class implementation"""
    def require_auth(self, path: str, excluded_paths: List[str]) -> bool:
        """return False"""
        if path is None or excluded_paths is None:
            return True
        if excluded_paths == []:
            return True
        if path in excluded_paths or path+'/' in excluded_paths:
            return False
        return True

    def authorization_header(self, request=None) -> str:
        """return None"""
        if request is None:
            return None
        if request.headers.get('Authorization') is not None:
            return request.headers.get('Authorization', None)
        return None

    def current_user(self, request=None) -> TypeVar('User'):
        """return None"""
        return None
