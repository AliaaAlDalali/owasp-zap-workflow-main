from typing import Literal

from pydantic import BaseModel, Field


class CreateTargetRequest(BaseModel):
    url: str = Field(min_length=8, max_length=2048)


class VerificationInstructions(BaseModel):
    """Either option proves ownership: a DNS TXT record, or a file served by the site."""
    dns_record_name: str | None
    dns_record_value: str
    file_url: str
    file_content: str


class TargetResponse(BaseModel):
    id: int
    url: str
    host: str
    verified: bool
    verification_method: Literal["dns", "file"] | None
    verified_at: str | None
    created_at: str
    verification: VerificationInstructions | None = None
