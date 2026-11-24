from typing import TypedDict

from database import Database

_COLUMNS = ("id, organization_id, url, host, verification_token, verification_method, "
            "verified_at, created_at")


class TargetRecord(TypedDict):
    id: int
    organization_id: int
    url: str
    host: str
    verification_token: str
    verification_method: str | None
    verified_at: str | None
    created_at: str


class TargetRepository:
    @staticmethod
    async def create(organization_id: int, url: str, host: str, token: str, created_by: int) -> int:
        return await Database.insert(
            "INSERT INTO targets (organization_id, url, host, verification_token, created_by) "
            "VALUES (?, ?, ?, ?, ?)",
            (organization_id, url, host, token, created_by),
        )

    @staticmethod
    async def list_for_organization(organization_id: int) -> list[TargetRecord]:
        rows = await Database.fetch_all(
            f"SELECT {_COLUMNS} FROM targets WHERE organization_id = ? ORDER BY id DESC",
            (organization_id,),
        )
        return [TargetRecord(**row) for row in rows]

    @staticmethod
    async def get(organization_id: int, target_id: int) -> TargetRecord | None:
        row = await Database.fetch_one(
            f"SELECT {_COLUMNS} FROM targets WHERE organization_id = ? AND id = ?",
            (organization_id, target_id),
        )
        return TargetRecord(**row) if row else None

    @staticmethod
    async def mark_verified(target_id: int, method: str) -> None:
        await Database.execute(
            "UPDATE targets SET verification_method = ?, verified_at = CURRENT_TIMESTAMP WHERE id = ?",
            (method, target_id),
        )

    @staticmethod
    async def delete(organization_id: int, target_id: int) -> int:
        return await Database.execute(
            "DELETE FROM targets WHERE organization_id = ? AND id = ?",
            (organization_id, target_id),
        )
