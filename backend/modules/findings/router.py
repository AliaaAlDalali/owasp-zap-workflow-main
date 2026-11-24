from fastapi import APIRouter, Depends, Query

from modules.findings.schemas import ComparisonResponse, FindingResponse, FindingSummaryResponse
from modules.findings.service import FindingService
from modules.organizations.repository import MembershipRecord
from modules.organizations.router import require_membership

router = APIRouter(prefix="/organizations/{organization_id}/scans/{scan_id}", tags=["findings"])


@router.get("/findings", response_model=list[FindingSummaryResponse])
async def list_findings(scan_id: int, risk_code: int | None = Query(None, ge=0, le=3),
                        membership: MembershipRecord = Depends(require_membership)) -> list[FindingSummaryResponse]:
    rows = await FindingService().list(membership, scan_id, risk_code)
    return [FindingSummaryResponse(**row) for row in rows]


@router.get("/findings/{finding_id}", response_model=FindingResponse)
async def get_finding(scan_id: int, finding_id: int,
                      membership: MembershipRecord = Depends(require_membership)) -> FindingResponse:
    return FindingResponse(**await FindingService().get(membership, scan_id, finding_id))


@router.get("/compare", response_model=ComparisonResponse)
async def compare_scans(scan_id: int, base_scan_id: int | None = None,
                        membership: MembershipRecord = Depends(require_membership)) -> ComparisonResponse:
    return ComparisonResponse(**await FindingService().compare(membership, scan_id, base_scan_id))
