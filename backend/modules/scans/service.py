import asyncio
import logging
import sqlite3
from typing import Any

from himaak_core.zap import summarize_report

from config import settings
from database import Database
from modules.findings.repository import FindingRepository
from modules.organizations.repository import MembershipRecord
from modules.scans.repository import ScanRecord, ScanRepository
from modules.scans.runner import ScanRunError, ZapRunner
from modules.targets.repository import TargetRepository
from utils.errors import AppError, ConflictError, NotFoundError, RuleViolationError
from utils.network import normalize_target_url, resolve_public_addresses

logger = logging.getLogger(__name__)


class ScanService:
    def __init__(self, runner: ZapRunner | None = None):
        self.runner = runner or ZapRunner()

    async def request(self, membership: MembershipRecord, target_id: int) -> ScanRecord:
        organization_id = membership["organization_id"]
        target = await TargetRepository.get(organization_id, target_id)
        if target is None:
            raise NotFoundError("الموقع غير موجود.")
        if not target["verified_at"]:
            raise RuleViolationError("يجب التحقق من ملكية الموقع قبل فحصه.")
        if await ScanRepository.count_active(organization_id) >= settings.max_active_scans_per_organization:
            raise RuleViolationError(
                f"وصلت المنظمة للحد الأقصى من الفحوصات المتزامنة ({settings.max_active_scans_per_organization}). "
                "انتظر حتى ينتهي أحدها."
            )

        # Fail early if the domain now points somewhere internal; the worker checks again.
        target_url = normalize_target_url(target["url"])
        await resolve_public_addresses(target_url.host, target_url.port)

        try:
            scan_id = await ScanRepository.create(organization_id, target_id, membership["user_id"])
        except sqlite3.IntegrityError:
            raise ConflictError("يوجد فحص قيد الانتظار أو التنفيذ لهذا الموقع.") from None
        logger.info("Scan %s queued for target %s", scan_id, target_id)
        return await self.get(membership, scan_id)

    async def get(self, membership: MembershipRecord, scan_id: int) -> ScanRecord:
        scan = await ScanRepository.get(membership["organization_id"], scan_id)
        if scan is None:
            raise NotFoundError("الفحص غير موجود.")
        return scan

    async def complete(self, scan_id: int, report: dict[str, Any]) -> None:
        """Stores a ZAP JSON report as the scan's findings and release decision, atomically."""
        summary = summarize_report(report)
        async with Database.transaction() as connection:
            await FindingRepository.insert_many(scan_id, summary["alerts"], connection)
            await ScanRepository.mark_completed(scan_id, summary, connection)
        logger.info("Scan %s completed: score %s, %s", scan_id, summary["score"], summary["release_status"])

    async def process_next(self) -> bool:
        """Runs the oldest queued scan. Returns False when there was nothing to do."""
        scan = await ScanRepository.claim_next()
        if scan is None:
            return False
        try:
            target_url = normalize_target_url(scan["target_url"])
            # Checked here and pinned inside the container, so the domain cannot be re-pointed
            # at an internal address between this check and ZAP's own lookup (DNS rebinding).
            addresses = await resolve_public_addresses(target_url.host, target_url.port)
            report = await self.runner.run_baseline(scan["id"], target_url.url, target_url.host, addresses)
            await self.complete(scan["id"], report)
        except (AppError, ScanRunError) as error:
            logger.warning("Scan %s failed: %s", scan["id"], error.message)
            await ScanRepository.mark_failed(scan["id"], error.message)
        except Exception:
            logger.exception("Scan %s failed unexpectedly", scan["id"])
            await ScanRepository.mark_failed(scan["id"], "حدث خطأ غير متوقع أثناء الفحص. أعد المحاولة لاحقاً.")
        return True

    async def run_worker(self, stop: asyncio.Event) -> None:
        """Background loop started by main.py: one scan at a time, polling the queue."""
        interrupted = await ScanRepository.fail_interrupted()
        if interrupted:
            logger.warning("Marked %s interrupted scan(s) as failed", interrupted)
        logger.info("Scan worker started")
        while not stop.is_set():
            try:
                worked = await self.process_next()
            except Exception:
                logger.exception("Scan worker loop error")
                worked = False
            if not worked:
                try:
                    await asyncio.wait_for(stop.wait(), timeout=settings.scan_worker_poll_seconds)
                except asyncio.TimeoutError:
                    pass
        logger.info("Scan worker stopped")
