from typing import Literal

from pydantic import BaseModel


class ScanResponse(BaseModel):
    id: int
    target_id: int
    target_url: str
    scan_type: Literal["baseline"]
    status: Literal["queued", "running", "completed", "failed"]
    error: str | None
    zap_version: str | None
    score: int | None
    release_status: Literal["blocked", "conditional", "approved"] | None
    high_count: int
    medium_count: int
    low_count: int
    info_count: int
    total_instances: int
    created_at: str
    started_at: str | None
    finished_at: str | None
