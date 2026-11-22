"""Ordered schema migrations. The applied version is kept in SQLite's PRAGMA user_version.

Never edit or renumber a migration that may have run; add a new one instead.
"""

import logging

import aiosqlite

logger = logging.getLogger(__name__)


class Migration:
    version: int
    description: str

    @staticmethod
    async def up(connection: aiosqlite.Connection) -> None:
        raise NotImplementedError


class Migration001(Migration):
    version = 1
    description = "Users, sessions, organizations, targets, scans and findings"

    @staticmethod
    async def up(connection: aiosqlite.Connection) -> None:
        statements = [
            """
            CREATE TABLE users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                email TEXT NOT NULL UNIQUE COLLATE NOCASE,
                name TEXT NOT NULL,
                password_hash TEXT NOT NULL,
                created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
            )
            """,
            """
            CREATE TABLE sessions (
                token_hash TEXT PRIMARY KEY,
                user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
                created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                expires_at TEXT NOT NULL
            )
            """,
            "CREATE INDEX idx_sessions_user ON sessions(user_id)",
            """
            CREATE TABLE organizations (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL,
                created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
            )
            """,
            """
            CREATE TABLE memberships (
                organization_id INTEGER NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
                user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
                role TEXT NOT NULL CHECK (role IN ('owner', 'member')),
                created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                PRIMARY KEY (organization_id, user_id)
            )
            """,
            "CREATE INDEX idx_memberships_user ON memberships(user_id)",
            """
            CREATE TABLE targets (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                organization_id INTEGER NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
                url TEXT NOT NULL,
                host TEXT NOT NULL,
                verification_token TEXT NOT NULL,
                verification_method TEXT CHECK (verification_method IN ('dns', 'file')),
                verified_at TEXT,
                created_by INTEGER REFERENCES users(id) ON DELETE SET NULL,
                created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                UNIQUE (organization_id, url)
            )
            """,
            """
            CREATE TABLE scans (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                organization_id INTEGER NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
                target_id INTEGER NOT NULL REFERENCES targets(id) ON DELETE CASCADE,
                scan_type TEXT NOT NULL DEFAULT 'baseline' CHECK (scan_type IN ('baseline')),
                status TEXT NOT NULL DEFAULT 'queued'
                    CHECK (status IN ('queued', 'running', 'completed', 'failed')),
                requested_by INTEGER REFERENCES users(id) ON DELETE SET NULL,
                error TEXT,
                zap_version TEXT,
                score INTEGER,
                release_status TEXT CHECK (release_status IN ('blocked', 'conditional', 'approved')),
                high_count INTEGER NOT NULL DEFAULT 0,
                medium_count INTEGER NOT NULL DEFAULT 0,
                low_count INTEGER NOT NULL DEFAULT 0,
                info_count INTEGER NOT NULL DEFAULT 0,
                total_instances INTEGER NOT NULL DEFAULT 0,
                created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                started_at TEXT,
                finished_at TEXT
            )
            """,
            "CREATE INDEX idx_scans_org_created ON scans(organization_id, id DESC)",
            "CREATE INDEX idx_scans_target ON scans(target_id, id DESC)",
            "CREATE INDEX idx_scans_status ON scans(status, id)",
            # At most one queued or running scan per target, enforced by the database.
            "CREATE UNIQUE INDEX idx_scans_one_active_per_target ON scans(target_id) "
            "WHERE status IN ('queued', 'running')",
            """
            CREATE TABLE findings (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                scan_id INTEGER NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
                fingerprint TEXT NOT NULL,
                plugin_id TEXT NOT NULL,
                name TEXT NOT NULL,
                name_ar TEXT NOT NULL,
                risk_code INTEGER NOT NULL CHECK (risk_code BETWEEN 0 AND 3),
                cwe_id TEXT NOT NULL DEFAULT '',
                owasp TEXT NOT NULL DEFAULT '',
                instance_count INTEGER NOT NULL DEFAULT 0,
                description TEXT NOT NULL DEFAULT '',
                solution TEXT NOT NULL DEFAULT '',
                reference TEXT NOT NULL DEFAULT '',
                other_info TEXT NOT NULL DEFAULT '',
                remediation_title TEXT NOT NULL DEFAULT '',
                remediation_code TEXT NOT NULL DEFAULT '',
                instances_json TEXT NOT NULL DEFAULT '[]'
            )
            """,
            "CREATE INDEX idx_findings_scan ON findings(scan_id, risk_code DESC)",
        ]
        for statement in statements:
            await connection.execute(statement)


MIGRATIONS: list[type[Migration]] = [Migration001]


async def run_migrations(connection: aiosqlite.Connection) -> None:
    cursor = await connection.execute("PRAGMA user_version")
    current = (await cursor.fetchone())[0]
    for migration in MIGRATIONS:
        if migration.version <= current:
            continue
        logger.info("Applying migration %03d: %s", migration.version, migration.description)
        await connection.execute("BEGIN")
        try:
            await migration.up(connection)
            # PRAGMA cannot take a bound parameter; the version is a trusted integer constant.
            await connection.execute(f"PRAGMA user_version = {int(migration.version)}")
        except BaseException:
            await connection.rollback()
            raise
        await connection.commit()
