from fastapi import APIRouter, Depends, Query, status

from modules.organizations.repository import MembershipRecord
from modules.organizations.router import require_membership
from modules.scans.repository import ScanRepository
from modules.scans.schemas import ScanResponse
from modules.scans.service import ScanService

router = APIRouter(prefix="/organizations/{organization_id}", tags=["scans"])


@router.post("/targets/{target_id}/scans", response_model=ScanResponse, status_code=status.HTTP_202_ACCEPTED)
async def request_scan(target_id: int, membership: MembershipRecord = Depends(require_membership)) -> ScanResponse:
    return ScanResponse(**await ScanService().request(membership, target_id))


@router.get("/scans", response_model=list[ScanResponse])
async def list_scans(target_id: int | None = None, limit: int = Query(50, ge=1, le=200),
                     membership: MembershipRecord = Depends(require_membership)) -> list[ScanResponse]:
    rows = await ScanRepository.list_for_organization(membership["organization_id"], target_id, limit)
    return [ScanResponse(**row) for row in rows]


@router.get("/scans/{scan_id}", response_model=ScanResponse)
async def get_scan(scan_id: int, membership: MembershipRecord = Depends(require_membership)) -> ScanResponse:
    return ScanResponse(**await ScanService().get(membership, scan_id))
