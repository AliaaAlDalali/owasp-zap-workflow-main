from typing import Any, TypedDict

import aiosqlite

from database import Database

_SELECT = """
    SELECT s.id, s.organization_id, s.target_id, t.url AS target_url, s.scan_type, s.status, s.error,
           s.zap_version, s.score, s.release_status, s.high_count, s.medium_count, s.low_count,
           s.info_count, s.total_instances, s.created_at, s.started_at, s.finished_at
    FROM scans s JOIN targets t ON t.id = s.target_id
"""


class ScanRecord(TypedDict):
    id: int
    organization_id: int
    target_id: int
    target_url: str
    scan_type: str
    status: str
    error: str | None
    zap_version: str | None
    score: int | None
    release_status: str | None
    high_count: int
    medium_count: int
    low_count: int
    info_count: int
    total_instances: int
    created_at: str
    started_at: str | None
    finished_at: str | None


class ScanRepository:
    @staticmethod
    async def create(organization_id: int, target_id: int, requested_by: int) -> int:
        return await Database.insert(
            "INSERT INTO scans (organization_id, target_id, requested_by) VALUES (?, ?, ?)",
            (organization_id, target_id, requested_by),
        )

    @staticmethod
    async def count_active(organization_id: int) -> int:
        row = await Database.fetch_one(
            "SELECT COUNT(*) AS n FROM scans WHERE organization_id = ? AND status IN ('queued', 'running')",
            (organization_id,),
        )
        return int(row["n"]) if row else 0

    @staticmethod
    async def list_for_organization(organization_id: int, target_id: int | None, limit: int) -> list[ScanRecord]:
        if target_id is None:
            rows = await Database.fetch_all(
                _SELECT + " WHERE s.organization_id = ? ORDER BY s.id DESC LIMIT ?",
                (organization_id, limit),
            )
        else:
            rows = await Database.fetch_all(
                _SELECT + " WHERE s.organization_id = ? AND s.target_id = ? ORDER BY s.id DESC LIMIT ?",
                (organization_id, target_id, limit),
            )
        return [ScanRecord(**row) for row in rows]

    @staticmethod
    async def get(organization_id: int, scan_id: int) -> ScanRecord | None:
        row = await Database.fetch_one(_SELECT + " WHERE s.organization_id = ? AND s.id = ?",
                                       (organization_id, scan_id))
        return ScanRecord(**row) if row else None

    @staticmethod
    async def get_previous_completed(target_id: int, before_scan_id: int) -> ScanRecord | None:
        row = await Database.fetch_one(
            _SELECT + " WHERE s.target_id = ? AND s.id < ? AND s.status = 'completed' ORDER BY s.id DESC LIMIT 1",
            (target_id, before_scan_id),
        )
        return ScanRecord(**row) if row else None

    @staticmethod
    async def claim_next() -> ScanRecord | None:
        """Moves the oldest queued scan to 'running' and returns it (None when the queue is empty)."""
        async with Database.transaction(immediate=True) as connection:
            row = await Database.fetch_one(
                _SELECT + " WHERE s.status = 'queued' ORDER BY s.id LIMIT 1", (), connection,
            )
            if row is None:
                return None
            await Database.execute(
                "UPDATE scans SET status = 'running', started_at = CURRENT_TIMESTAMP WHERE id = ?",
                (row["id"],), connection,
            )
        return ScanRecord(**{**row, "status": "running"})

    @staticmethod
    async def fail_interrupted() -> int:
        """Scans left 'running' by a previous process can never finish; mark them failed."""
        return await Database.execute(
            "UPDATE scans SET status = 'failed', error = ?, finished_at = CURRENT_TIMESTAMP "
            "WHERE status = 'running'",
            ("توقف الفحص بسبب إعادة تشغيل الخادم. أعد طلب الفحص.",),
        )

    @staticmethod
    async def mark_failed(scan_id: int, error: str) -> None:
        await Database.execute(
            "UPDATE scans SET status = 'failed', error = ?, finished_at = CURRENT_TIMESTAMP WHERE id = ?",
            (error, scan_id),
        )

    @staticmethod
    async def mark_completed(scan_id: int, summary: dict[str, Any], connection: aiosqlite.Connection) -> None:
        await Database.execute(
            """
            UPDATE scans SET status = 'completed', error = NULL, zap_version = ?, score = ?, release_status = ?,
                   high_count = ?, medium_count = ?, low_count = ?, info_count = ?, total_instances = ?,
                   finished_at = CURRENT_TIMESTAMP
            WHERE id = ?
            """,
            (summary["zap_version"], summary["score"], summary["release_status"], summary["high_count"],
             summary["med_count"], summary["low_count"], summary["info_count"], summary["total_instances"],
             scan_id),
            connection,
        )
