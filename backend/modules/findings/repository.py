import json
from typing import Any, TypedDict

import aiosqlite

from database import Database

_SUMMARY_COLUMNS = "id, scan_id, fingerprint, plugin_id, name, name_ar, risk_code, cwe_id, instance_count"
_DETAIL_COLUMNS = (_SUMMARY_COLUMNS + ", owasp, description, solution, reference, other_info, "
                   "remediation_title, remediation_code, instances_json")


class FindingSummaryRecord(TypedDict):
    id: int
    scan_id: int
    fingerprint: str
    plugin_id: str
    name: str
    name_ar: str
    risk_code: int
    cwe_id: str
    instance_count: int


class FindingRecord(FindingSummaryRecord):
    owasp: str
    description: str
    solution: str
    reference: str
    other_info: str
    remediation_title: str
    remediation_code: str
    instances: list[dict[str, str]]


def fingerprint_of(alert: dict[str, Any]) -> str:
    """Identifies the same issue across scans of one target: ZAP plugin id plus alert name."""
    return f"{alert['id']}:{alert['name']}"


class FindingRepository:
    @staticmethod
    async def insert_many(scan_id: int, alerts: list[dict[str, Any]], connection: aiosqlite.Connection) -> None:
        """Stores alerts already normalised by himaak_core.zap (plain text, validated risk codes)."""
        for alert in alerts:
            await Database.execute(
                """
                INSERT INTO findings (scan_id, fingerprint, plugin_id, name, name_ar, risk_code, cwe_id, owasp,
                    instance_count, description, solution, reference, other_info, remediation_title,
                    remediation_code, instances_json)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (scan_id, fingerprint_of(alert), alert["id"], alert["name"], alert["name_ar"], alert["riskcode"],
                 alert["cweid"], alert["owasp"], alert["count"], alert["desc"], alert["solution"],
                 alert["reference"], alert["otherinfo"], alert["remediation_title"], alert["remediation_code"],
                 json.dumps(alert["instances"], ensure_ascii=False)),
                connection,
            )

    @staticmethod
    async def list_for_scan(scan_id: int, risk_code: int | None = None) -> list[FindingSummaryRecord]:
        if risk_code is None:
            rows = await Database.fetch_all(
                f"SELECT {_SUMMARY_COLUMNS} FROM findings WHERE scan_id = ? ORDER BY risk_code DESC, id",
                (scan_id,),
            )
        else:
            rows = await Database.fetch_all(
                f"SELECT {_SUMMARY_COLUMNS} FROM findings WHERE scan_id = ? AND risk_code = ? ORDER BY id",
                (scan_id, risk_code),
            )
        return [FindingSummaryRecord(**row) for row in rows]

    @staticmethod
    async def get(scan_id: int, finding_id: int) -> FindingRecord | None:
        row = await Database.fetch_one(
            f"SELECT {_DETAIL_COLUMNS} FROM findings WHERE scan_id = ? AND id = ?",
            (scan_id, finding_id),
        )
        if row is None:
            return None
        instances = json.loads(row.pop("instances_json") or "[]")
        return FindingRecord(**row, instances=instances)
