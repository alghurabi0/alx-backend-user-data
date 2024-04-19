#!/usr/bin/env python3
"""basic auth class"""
from werkzeug.datastructures import Authorization
from api.v1.auth.auth import Auth
from base64 import b64decode
import base64
from typing import Tuple, TypeVar
from models.user import User


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

    def decode_base64_authorization_header(self, base64_authorization_header: str) -> str:  # noqa
        """decode base auth head"""
        if base64_authorization_header is None:
            return None
        if type(base64_authorization_header) is not str:
            return None
        try:
            decoded = b64decode(base64_authorization_header)
            decodedStr = decoded.decode('utf-8')
            return decodedStr
        except (base64.binascii.Error, UnicodeDecodeError):
            return None

    def extract_user_credentials(self, decoded_base64_authorization_header: str) -> Tuple[str, str]:  # noqa
        """extract user whatever"""
        if decoded_base64_authorization_header is None:
            return None, None
        if type(decoded_base64_authorization_header) is not str:
            return None, None
        char = ':'
        if char not in decoded_base64_authorization_header:
            return None, None
        cred = decoded_base64_authorization_header.split(char)
        return cred[0], cred[1]

    def user_object_from_credentials(
            self,
            user_email: str,
            user_pwd: str) -> TypeVar('User'):
        """user object from cred.
        """
        if type(user_email) == str and type(user_pwd) == str:
            try:
                users = User.search({'email': user_email})
            except Exception:
                return None
            if len(users) <= 0:
                return None
            if users[0].is_valid_password(user_pwd):
                return users[0]
        return None

    def current_user(self, request=None) -> TypeVar('User'):
        """current user full impl
        """
        auth_header = self.authorization_header(request)
        b64_auth_token = self.extract_base64_authorization_header(auth_header)
        auth_token = self.decode_base64_authorization_header(b64_auth_token)
        email, password = self.extract_user_credentials(auth_token)
        return self.user_object_from_credentials(email, password)
