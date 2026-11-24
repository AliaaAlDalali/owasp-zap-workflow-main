import asyncio
import base64
import functools
import hashlib
import hmac
import logging
import secrets
import sqlite3
import time
from collections import defaultdict, deque

from config import settings
from database import Database
from modules.auth.repository import SessionRepository, UserRecord, UserRepository
from modules.organizations.repository import OrganizationRepository
from utils.errors import AuthenticationError, ConflictError, TooManyAttemptsError

logger = logging.getLogger(__name__)

_SCRYPT_N, _SCRYPT_R, _SCRYPT_P = 2 ** 14, 8, 1

# Failed sign-in attempts per email, kept in memory (the API runs as one instance).
_login_failures: dict[str, deque[float]] = defaultdict(deque)


def _b64(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")


def _hash_password(password: str) -> str:
    salt = secrets.token_bytes(16)
    derived = hashlib.scrypt(password.encode("utf-8"), salt=salt, n=_SCRYPT_N, r=_SCRYPT_R, p=_SCRYPT_P, dklen=32)
    return f"scrypt${_SCRYPT_N}${_SCRYPT_R}${_SCRYPT_P}${_b64(salt)}${_b64(derived)}"


def _verify_password(password: str, stored: str) -> bool:
    try:
        _, n, r, p, salt, expected = stored.split("$")
        derived = hashlib.scrypt(password.encode("utf-8"), salt=base64.b64decode(salt),
                                 n=int(n), r=int(r), p=int(p), dklen=32)
    except (ValueError, TypeError):
        return False
    return hmac.compare_digest(derived, base64.b64decode(expected))


@functools.cache
def _dummy_hash() -> str:
    """Checked when the email is unknown, so a wrong email takes as long as a wrong password."""
    return _hash_password(secrets.token_urlsafe(16))


def _token_hash(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


class AuthService:
    async def register(self, email: str, name: str, password: str,
                       organization_name: str) -> tuple[str, UserRecord]:
        """Creates the user and their first organization (as owner), then signs them in."""
        email = email.strip().lower()
        if await UserRepository.get_by_email(email):
            raise ConflictError("هذا البريد مسجّل مسبقاً.")

        password_hash = await asyncio.to_thread(_hash_password, password)
        try:
            async with Database.transaction() as connection:
                user_id = await UserRepository.create(email, name.strip(), password_hash, connection)
                organization_id = await OrganizationRepository.create(organization_name.strip(), connection)
                await OrganizationRepository.add_member(organization_id, user_id, "owner", connection)
        except sqlite3.IntegrityError:
            raise ConflictError("هذا البريد مسجّل مسبقاً.") from None

        logger.info("Registered user %s with organization %s", user_id, organization_id)
        user = UserRecord(id=user_id, email=email, name=name.strip())
        return await self._start_session(user), user

    async def login(self, email: str, password: str) -> tuple[str, UserRecord]:
        key = email.strip().lower()
        self._ensure_not_locked(key)

        credentials = await UserRepository.get_credentials(key)
        stored = credentials["password_hash"] if credentials else _dummy_hash()
        valid = await asyncio.to_thread(_verify_password, password, stored)
        if credentials is None or not valid:
            _login_failures[key].append(time.monotonic())
            raise AuthenticationError("البريد أو كلمة المرور غير صحيحة.")

        _login_failures.pop(key, None)
        await SessionRepository.delete_expired()
        user = UserRecord(id=credentials["id"], email=credentials["email"], name=credentials["name"])
        return await self._start_session(user), user

    async def logout(self, token: str) -> None:
        await SessionRepository.delete(_token_hash(token))

    async def user_for_session(self, token: str) -> UserRecord | None:
        return await SessionRepository.get_user(_token_hash(token))

    async def _start_session(self, user: UserRecord) -> str:
        token = secrets.token_urlsafe(32)
        await SessionRepository.create(_token_hash(token), user["id"], settings.session_days)
        return token

    def _ensure_not_locked(self, key: str) -> None:
        window = settings.login_lockout_minutes * 60
        attempts = _login_failures[key]
        now = time.monotonic()
        while attempts and now - attempts[0] > window:
            attempts.popleft()
        if len(attempts) >= settings.login_max_failures:
            raise TooManyAttemptsError(
                f"محاولات دخول خاطئة كثيرة. حاول مجدداً بعد {settings.login_lockout_minutes} دقيقة."
            )
