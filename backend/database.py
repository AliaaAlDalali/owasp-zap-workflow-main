import logging
from contextlib import asynccontextmanager
from typing import Any, AsyncIterator

import aiosqlite

from config import settings
from migrations.migrations import run_migrations

logger = logging.getLogger(__name__)

Params = tuple[Any, ...]


class Database:
    """Connection management and generic query helpers. No feature-specific SQL here.

    Every helper accepts an optional open connection so several repository calls
    can share one transaction (see `transaction`).
    """

    @classmethod
    @asynccontextmanager
    async def connection(cls) -> AsyncIterator[aiosqlite.Connection]:
        async with aiosqlite.connect(settings.database_path) as connection:
            connection.row_factory = aiosqlite.Row
            await connection.execute("PRAGMA foreign_keys = ON")
            await connection.execute("PRAGMA busy_timeout = 5000")
            yield connection

    @classmethod
    @asynccontextmanager
    async def transaction(cls, immediate: bool = False) -> AsyncIterator[aiosqlite.Connection]:
        """Runs the block as one transaction: commit on success, roll back on any error."""
        async with cls.connection() as connection:
            await connection.execute("BEGIN IMMEDIATE" if immediate else "BEGIN")
            try:
                yield connection
            except BaseException:
                await connection.rollback()
                raise
            await connection.commit()

    @classmethod
    async def initialize(cls) -> None:
        settings.database_path.parent.mkdir(parents=True, exist_ok=True)
        async with cls.connection() as connection:
            # WAL is persistent once set: readers do not block the scan worker's writes.
            await connection.execute("PRAGMA journal_mode = WAL")
            await connection.execute("PRAGMA synchronous = NORMAL")
            await run_migrations(connection)
        logger.info("Database ready at %s", settings.database_path)

    @classmethod
    async def execute(cls, query: str, params: Params = (), connection: aiosqlite.Connection | None = None) -> int:
        """Runs a write and returns the number of affected rows."""
        if connection is not None:
            cursor = await connection.execute(query, params)
            return cursor.rowcount
        async with cls.connection() as own:
            cursor = await own.execute(query, params)
            await own.commit()
            return cursor.rowcount

    @classmethod
    async def insert(cls, query: str, params: Params = (), connection: aiosqlite.Connection | None = None) -> int:
        """Runs an INSERT and returns the new row id."""
        if connection is not None:
            cursor = await connection.execute(query, params)
            return int(cursor.lastrowid)
        async with cls.connection() as own:
            cursor = await own.execute(query, params)
            await own.commit()
            return int(cursor.lastrowid)

    @classmethod
    async def fetch_one(cls, query: str, params: Params = (),
                        connection: aiosqlite.Connection | None = None) -> dict[str, Any] | None:
        if connection is not None:
            cursor = await connection.execute(query, params)
            row = await cursor.fetchone()
            return dict(row) if row else None
        async with cls.connection() as own:
            cursor = await own.execute(query, params)
            row = await cursor.fetchone()
            return dict(row) if row else None

    @classmethod
    async def fetch_all(cls, query: str, params: Params = (),
                        connection: aiosqlite.Connection | None = None) -> list[dict[str, Any]]:
        if connection is not None:
            cursor = await connection.execute(query, params)
            return [dict(row) for row in await cursor.fetchall()]
        async with cls.connection() as own:
            cursor = await own.execute(query, params)
            return [dict(row) for row in await cursor.fetchall()]
