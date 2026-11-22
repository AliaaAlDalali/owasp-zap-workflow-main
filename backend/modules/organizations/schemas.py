from typing import Literal

from pydantic import BaseModel, Field

from modules.auth.schemas import EMAIL_PATTERN

Role = Literal["owner", "member"]


class CreateOrganizationRequest(BaseModel):
    name: str = Field(min_length=1, max_length=120)


class OrganizationResponse(BaseModel):
    id: int
    name: str
    role: Role


class AddMemberRequest(BaseModel):
    email: str = Field(pattern=EMAIL_PATTERN, max_length=254)
    role: Role = "member"


class MemberResponse(BaseModel):
    user_id: int
    email: str
    name: str
    role: Role
