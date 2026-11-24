from typing import TypedDict

import aiosqlite

from database import Database


class OrganizationRecord(TypedDict):
    id: int
    name: str
    role: str


class MemberRecord(TypedDict):
    user_id: int
    email: str
    name: str
    role: str


class MembershipRecord(TypedDict):
    organization_id: int
    user_id: int
    role: str


class OrganizationRepository:
    @staticmethod
    async def create(name: str, connection: aiosqlite.Connection | None = None) -> int:
        return await Database.insert("INSERT INTO organizations (name) VALUES (?)", (name,), connection)

    @staticmethod
    async def add_member(organization_id: int, user_id: int, role: str,
                         connection: aiosqlite.Connection | None = None) -> None:
        await Database.execute(
            "INSERT INTO memberships (organization_id, user_id, role) VALUES (?, ?, ?)",
            (organization_id, user_id, role),
            connection,
        )

    @staticmethod
    async def list_for_user(user_id: int) -> list[OrganizationRecord]:
        rows = await Database.fetch_all(
            """
            SELECT o.id, o.name, m.role
            FROM memberships m JOIN organizations o ON o.id = m.organization_id
            WHERE m.user_id = ?
            ORDER BY o.id
            """,
            (user_id,),
        )
        return [OrganizationRecord(**row) for row in rows]

    @staticmethod
    async def get_membership(organization_id: int, user_id: int) -> MembershipRecord | None:
        row = await Database.fetch_one(
            "SELECT organization_id, user_id, role FROM memberships WHERE organization_id = ? AND user_id = ?",
            (organization_id, user_id),
        )
        return MembershipRecord(**row) if row else None

    @staticmethod
    async def list_members(organization_id: int) -> list[MemberRecord]:
        rows = await Database.fetch_all(
            """
            SELECT u.id AS user_id, u.email, u.name, m.role
            FROM memberships m JOIN users u ON u.id = m.user_id
            WHERE m.organization_id = ?
            ORDER BY m.role DESC, u.name
            """,
            (organization_id,),
        )
        return [MemberRecord(**row) for row in rows]
