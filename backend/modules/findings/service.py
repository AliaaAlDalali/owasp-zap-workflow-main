from modules.findings.repository import FindingRecord, FindingRepository, FindingSummaryRecord
from modules.organizations.repository import MembershipRecord
from modules.scans.repository import ScanRecord, ScanRepository
from utils.errors import NotFoundError, RuleViolationError


class FindingService:
    async def list(self, membership: MembershipRecord, scan_id: int,
                   risk_code: int | None) -> list[FindingSummaryRecord]:
        scan = await self._scan(membership, scan_id)
        return await FindingRepository.list_for_scan(scan["id"], risk_code)

    async def get(self, membership: MembershipRecord, scan_id: int, finding_id: int) -> FindingRecord:
        scan = await self._scan(membership, scan_id)
        finding = await FindingRepository.get(scan["id"], finding_id)
        if finding is None:
            raise NotFoundError("الثغرة غير موجودة.")
        return finding

    async def compare(self, membership: MembershipRecord, head_scan_id: int,
                      base_scan_id: int | None) -> dict:
        """What is new, fixed and still open between two completed scans of the same site.

        Without base_scan_id, the head scan is compared with the previous completed scan
        of the same target.
        """
        head = await self._completed_scan(membership, head_scan_id)
        if base_scan_id is None:
            base = await ScanRepository.get_previous_completed(head["target_id"], head["id"])
        else:
            base = await self._completed_scan(membership, base_scan_id)
            if base["target_id"] != head["target_id"]:
                raise RuleViolationError("لا يمكن مقارنة فحصين لموقعين مختلفين.")

        head_findings = await FindingRepository.list_for_scan(head["id"])
        base_findings = await FindingRepository.list_for_scan(base["id"]) if base else []
        base_keys = {f["fingerprint"] for f in base_findings}
        head_keys = {f["fingerprint"] for f in head_findings}
        return {
            "head_scan_id": head["id"],
            "base_scan_id": base["id"] if base else None,
            "new": [f for f in head_findings if f["fingerprint"] not in base_keys],
            "fixed": [f for f in base_findings if f["fingerprint"] not in head_keys],
            "persisting": [f for f in head_findings if f["fingerprint"] in base_keys],
        }

    async def _scan(self, membership: MembershipRecord, scan_id: int) -> ScanRecord:
        scan = await ScanRepository.get(membership["organization_id"], scan_id)
        if scan is None:
            raise NotFoundError("الفحص غير موجود.")
        return scan

    async def _completed_scan(self, membership: MembershipRecord, scan_id: int) -> ScanRecord:
        scan = await self._scan(membership, scan_id)
        if scan["status"] != "completed":
            raise RuleViolationError("لا تمكن المقارنة إلا بين فحوصات مكتملة.")
        return scan
