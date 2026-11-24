from fastapi import APIRouter, Depends, status

from modules.organizations.repository import MembershipRecord
from modules.organizations.router import require_membership
from modules.targets.repository import TargetRecord, TargetRepository
from modules.targets.schemas import CreateTargetRequest, TargetResponse, VerificationInstructions
from modules.targets.service import TargetService

router = APIRouter(prefix="/organizations/{organization_id}/targets", tags=["targets"])


def _to_response(target: TargetRecord) -> TargetResponse:
    verified = target["verified_at"] is not None
    instructions = None if verified else VerificationInstructions(**TargetService().verification_instructions(target))
    return TargetResponse(
        id=target["id"], url=target["url"], host=target["host"], verified=verified,
        verification_method=target["verification_method"], verified_at=target["verified_at"],
        created_at=target["created_at"], verification=instructions,
    )


@router.get("", response_model=list[TargetResponse])
async def list_targets(membership: MembershipRecord = Depends(require_membership)) -> list[TargetResponse]:
    return [_to_response(t) for t in await TargetRepository.list_for_organization(membership["organization_id"])]


@router.post("", response_model=TargetResponse, status_code=status.HTTP_201_CREATED)
async def create_target(body: CreateTargetRequest,
                        membership: MembershipRecord = Depends(require_membership)) -> TargetResponse:
    return _to_response(await TargetService().create(membership, body.url))


@router.get("/{target_id}", response_model=TargetResponse)
async def get_target(target_id: int, membership: MembershipRecord = Depends(require_membership)) -> TargetResponse:
    return _to_response(await TargetService().get(membership, target_id))


@router.post("/{target_id}/verify", response_model=TargetResponse)
async def verify_target(target_id: int,
                        membership: MembershipRecord = Depends(require_membership)) -> TargetResponse:
    return _to_response(await TargetService().verify(membership, target_id))


@router.delete("/{target_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_target(target_id: int, membership: MembershipRecord = Depends(require_membership)) -> None:
    await TargetService().delete(membership, target_id)
