#!/usr/bin/env python3
"""session auth implementation"""
from api.v1.auth.auth import Auth
from uuid import uuid4


class SessionAuth(Auth):
    """sesssion auth class"""
    session_id_by_user_id = {}

    def create_session(self, user_id: str = None) -> str:
        """create session function"""
        if user_id is None:
            return None
        if not isinstance(user_id, str):
            return None
        session_id = uuid4()
        self.session_id_by_user_id[str(session_id)] = user_id
        return str(session_id)
