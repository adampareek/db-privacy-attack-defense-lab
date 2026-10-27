import hashlib
import hmac
import os
import secrets
import time

from .db import connection

SESSION_TTL_SECONDS = int(os.getenv("SESSION_TTL_SECONDS", "3600"))


def hash_password(password: str, salt_hex: str) -> str:
    salt = bytes.fromhex(salt_hex)
    derived = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, 200_000)
    return derived.hex()


def verify_password(plain: str, salt_hex: str, expected_hex: str) -> bool:
    actual = hash_password(plain, salt_hex)
    return hmac.compare_digest(actual, expected_hex)


def create_session(user_id: int, role: str) -> str:
    raw_token = secrets.token_urlsafe(32)
    token_hash = hashlib.sha256(raw_token.encode()).hexdigest()
    expires_at = int(time.time()) + SESSION_TTL_SECONDS

    with connection() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                INSERT INTO sessions (token_hash, user_id, role, expires_at)
                VALUES (%s, %s, %s, %s)
                """,
                (token_hash, user_id, role, expires_at),
            )
        conn.commit()

    return raw_token


def get_session(raw_token: str):
    token_hash = hashlib.sha256(raw_token.encode()).hexdigest()
    now = int(time.time())

    with connection() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                SELECT s.user_id, s.role, u.email
                FROM sessions s
                JOIN users u ON u.id = s.user_id
                WHERE s.token_hash = %s
                  AND s.expires_at > %s
                """,
                (token_hash, now),
            )
            return cur.fetchone()
