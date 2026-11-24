from pydantic import BaseModel


class InstanceResponse(BaseModel):
    uri: str
    method: str
    param: str
    attack: str
    evidence: str


class FindingSummaryResponse(BaseModel):
    id: int
    scan_id: int
    fingerprint: str
    plugin_id: str
    name: str
    name_ar: str
    risk_code: int
    cwe_id: str
    instance_count: int


class FindingResponse(FindingSummaryResponse):
    """All text fields are plain text (converted from ZAP's HTML); clients render them as text."""
    owasp: str
    description: str
    solution: str
    reference: str
    other_info: str
    remediation_title: str
    remediation_code: str
    instances: list[InstanceResponse]


class ComparisonResponse(BaseModel):
    """head = the newer scan. base = the scan it is compared with (None: no earlier scan)."""
    head_scan_id: int
    base_scan_id: int | None
    new: list[FindingSummaryResponse]
    fixed: list[FindingSummaryResponse]
    persisting: list[FindingSummaryResponse]
