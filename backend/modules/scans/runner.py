"""Runs one OWASP ZAP baseline scan in a throwaway Docker container.

Kept apart from service.py because it owns process and filesystem handling
(container limits, timeouts, cleanup) that the scan workflow should not mix with.
Arguments are passed as a list, never through a shell.
"""

import asyncio
import json
import logging
import os
import shutil
from pathlib import Path
from typing import Any

from config import settings

logger = logging.getLogger(__name__)


class ScanRunError(Exception):
    """A scan could not finish. The message is safe to show to the customer."""

    def __init__(self, message: str):
        super().__init__(message)
        self.message = message


class ZapRunner:
    async def run_baseline(self, scan_id: int, url: str) -> dict[str, Any]:
        if not url.startswith(("http://", "https://")):
            raise ScanRunError("رابط الفحص غير صالح.")

        work_dir = settings.scan_work_dir / f"scan-{int(scan_id)}"
        shutil.rmtree(work_dir, ignore_errors=True)
        work_dir.mkdir(parents=True)
        os.chmod(work_dir, 0o777)  # the ZAP image runs as its own non-root user and writes here
        container = f"himaak-scan-{int(scan_id)}"

        args = [
            "docker", "run", "--rm", "--name", container,
            "--memory", settings.scan_memory_limit,
            "--cpus", settings.scan_cpu_limit,
            "--pids-limit", "1024",
            "--security-opt", "no-new-privileges",
            "-v", f"{work_dir}:/zap/wrk/:rw",
            settings.zap_image,
            "zap-baseline.py", "-t", url, "-J", "zap_report.json", "-I",
        ]
        try:
            try:
                process = await asyncio.create_subprocess_exec(
                    *args, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.STDOUT,
                )
            except FileNotFoundError:
                logger.error("Docker is not installed or not on PATH; scan %s cannot run", scan_id)
                raise ScanRunError("محرك الفحص غير متاح على الخادم حالياً. حاول لاحقاً.") from None

            try:
                output, _ = await asyncio.wait_for(process.communicate(), timeout=settings.scan_timeout_seconds)
            except asyncio.TimeoutError:
                await self._stop_container(container)
                process.kill()
                raise ScanRunError("تجاوز الفحص الحد الزمني المسموح.") from None

            report_path = work_dir / "zap_report.json"
            if not report_path.is_file():
                tail = output.decode("utf-8", errors="replace")[-2000:]
                logger.warning("Scan %s produced no report (exit %s): %s", scan_id, process.returncode, tail)
                raise ScanRunError("لم يُنتج محرك الفحص تقريراً. تأكد أن الموقع يعمل ومتاح من الإنترنت.")
            return await asyncio.to_thread(self._read_report, report_path)
        finally:
            shutil.rmtree(work_dir, ignore_errors=True)

    @staticmethod
    def _read_report(path: Path) -> dict[str, Any]:
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            raise ScanRunError("تقرير محرك الفحص تالف ولا يمكن قراءته.") from None
        if not isinstance(data, dict):
            raise ScanRunError("تقرير محرك الفحص بصيغة غير متوقعة.")
        return data

    @staticmethod
    async def _stop_container(container: str) -> None:
        try:
            killer = await asyncio.create_subprocess_exec(
                "docker", "kill", container,
                stdout=asyncio.subprocess.DEVNULL, stderr=asyncio.subprocess.DEVNULL,
            )
            await asyncio.wait_for(killer.wait(), timeout=30)
        except (OSError, asyncio.TimeoutError):
            logger.error("Could not stop timed-out container %s", container)
