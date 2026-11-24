from typing import TypedDict

import aiosqlite

from database import Database


class UserRecord(TypedDict):
    id: int
    email: str
    name: str


class UserCredentials(UserRecord):
    password_hash: str


class UserRepository:
    @staticmethod
    async def create(email: str, name: str, password_hash: str,
                     connection: aiosqlite.Connection | None = None) -> int:
        return await Database.insert(
            "INSERT INTO users (email, name, password_hash) VALUES (?, ?, ?)",
            (email, name, password_hash),
            connection,
        )

    @staticmethod
    async def get_credentials(email: str) -> UserCredentials | None:
        row = await Database.fetch_one(
            "SELECT id, email, name, password_hash FROM users WHERE email = ?",
            (email,),
        )
        return UserCredentials(**row) if row else None

    @staticmethod
    async def get_by_email(email: str) -> UserRecord | None:
        row = await Database.fetch_one("SELECT id, email, name FROM users WHERE email = ?", (email,))
        return UserRecord(**row) if row else None


class SessionRepository:
    @staticmethod
    async def create(token_hash: str, user_id: int, days: int) -> None:
        await Database.execute(
            "INSERT INTO sessions (token_hash, user_id, expires_at) "
            "VALUES (?, ?, datetime('now', '+' || ? || ' days'))",
            (token_hash, user_id, int(days)),
        )

    @staticmethod
    async def get_user(token_hash: str) -> UserRecord | None:
        row = await Database.fetch_one(
            """
            SELECT u.id, u.email, u.name
            FROM sessions s JOIN users u ON u.id = s.user_id
            WHERE s.token_hash = ? AND s.expires_at > datetime('now')
            """,
            (token_hash,),
        )
        return UserRecord(**row) if row else None

    @staticmethod
    async def delete(token_hash: str) -> None:
        await Database.execute("DELETE FROM sessions WHERE token_hash = ?", (token_hash,))

    @staticmethod
    async def delete_expired() -> None:
        await Database.execute("DELETE FROM sessions WHERE expires_at <= datetime('now')")
