#!/usr/bin/env python3
"""obfuscating sensitive data"""
import re
from typing import List
import logging
import os
import mysql.connector


PII_FIELDS = ("name", "email", "password", "ssn", "phone")


def filter_datum(
        fields: List[str],
        redaction: str,
        message: str,
        separator: str
        ) -> str:
    """filter piece of data"""
    for field in fields:
        message = re.sub(f'{field}=(.*?){separator}',
                         f'{field}={redaction}{separator}', message)
    return message


class RedactingFormatter(logging.Formatter):
    """ Redacting Formatter class
        """

    REDACTION = "***"
    FORMAT = "[HOLBERTON] %(name)s %(levelname)s %(asctime)-15s: %(message)s"
    SEPARATOR = ";"

    def __init__(self, fields: List[str]):
        """instance init"""
        super(RedactingFormatter, self).__init__(self.FORMAT)
        self.fields = fields

    def format(self, record: logging.LogRecord) -> str:
        """filter piece of data"""
        return filter_datum(
            self.fields,
            self.REDACTION,
            super().format(record),
            self.SEPARATOR
            )


def get_logger() -> logging.Logger:
    """create a logger"""
    logger = logging.getLogger("user_data")
    logger.setLevel(logging.INFO)
    logger.propagate = False
    handler = logging.StreamHandler()
    handler.setLevel(logging.INFO)
    formatter = RedactingFormatter(list(PII_FIELDS))
    handler.setFormatter(formatter)
    logger.addHandler(handler)
    return logger


def get_db() -> mysql.connector.connection.MySQLConnection:
    """connect to a db"""
    user = os.getenv('PERSONAL_DATA_DB_USERNAME', 'root')
    password = os.getenv('PERSONAL_DATA_DB_PASSWORD', '')
    host = os.getenv('PERSONAL_DATA_DB_HOST', 'localhost')
    name = os.getenv('PERSONAL_DATA_DB_NAME')
    return mysql.connector.connect(
        user=user,
        host=host,
        password=password,
        database=name
        )


def main() -> None:
    """main function program"""
    db = get_db()
    cursor = db.cursor()
    cursor.execute("SELECT * FROM users;")

    headers = [field[0] for field in cursor.description]
    logger = get_logger()

    for row in cursor:
        info_answer = ''
        for f, p in zip(row, headers):
            info_answer += f'{p}={(f)}; '
        logger.info(info_answer)

    cursor.close()
    db.close()
