from fastapi import APIRouter, Depends, HTTPException, status

from modules.auth.repository import UserRecord
from modules.auth.router import current_user
from modules.organizations.repository import MembershipRecord, OrganizationRepository
from modules.organizations.schemas import (
    AddMemberRequest, CreateOrganizationRequest, MemberResponse, OrganizationResponse,
)
from modules.organizations.service import OrganizationService

router = APIRouter(prefix="/organizations", tags=["organizations"])


async def require_membership(organization_id: int, user: UserRecord = Depends(current_user)) -> MembershipRecord:
    """Dependency for every organization route. Non-members get 404 so they cannot probe ids."""
    membership = await OrganizationRepository.get_membership(organization_id, user["id"])
    if membership is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="المنظمة غير موجودة.")
    return membership


@router.get("", response_model=list[OrganizationResponse])
async def list_organizations(user: UserRecord = Depends(current_user)) -> list[OrganizationResponse]:
    return [OrganizationResponse(**row) for row in await OrganizationRepository.list_for_user(user["id"])]


@router.post("", response_model=OrganizationResponse, status_code=status.HTTP_201_CREATED)
async def create_organization(body: CreateOrganizationRequest,
                              user: UserRecord = Depends(current_user)) -> OrganizationResponse:
    return OrganizationResponse(**await OrganizationService().create(user, body.name))


@router.get("/{organization_id}/members", response_model=list[MemberResponse])
async def list_members(membership: MembershipRecord = Depends(require_membership)) -> list[MemberResponse]:
    rows = await OrganizationRepository.list_members(membership["organization_id"])
    return [MemberResponse(**row) for row in rows]


@router.post("/{organization_id}/members", response_model=MemberResponse, status_code=status.HTTP_201_CREATED)
async def add_member(body: AddMemberRequest,
                     membership: MembershipRecord = Depends(require_membership)) -> MemberResponse:
    return MemberResponse(**await OrganizationService().add_member(membership, body.email, body.role))
