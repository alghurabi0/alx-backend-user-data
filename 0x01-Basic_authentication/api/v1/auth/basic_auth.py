#!/usr/bin/env python3
"""basic auth class"""
from werkzeug.datastructures import Authorization
from api.v1.auth.auth import Auth


class BasicAuth(Auth):
    """basic auth class"""
    def extract_base64_authorization_header(self, authorization_header: str) -> str:  # noqa
        """extract base auth head"""
        if authorization_header is None:
            return None
        if type(authorization_header) is not str:
            return None
        prefix = 'Basic '
        if not authorization_header.startswith(prefix):
            return None
        value = authorization_header[len(prefix):].strip()
        return value
