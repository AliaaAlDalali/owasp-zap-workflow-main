import logging
import sqlite3

from database import Database
from modules.auth.repository import UserRecord, UserRepository
from modules.organizations.repository import (
    MemberRecord, MembershipRecord, OrganizationRecord, OrganizationRepository,
)
from utils.errors import ConflictError, NotFoundError, PermissionDeniedError

logger = logging.getLogger(__name__)


class OrganizationService:
    async def create(self, user: UserRecord, name: str) -> OrganizationRecord:
        async with Database.transaction() as connection:
            organization_id = await OrganizationRepository.create(name.strip(), connection)
            await OrganizationRepository.add_member(organization_id, user["id"], "owner", connection)
        return OrganizationRecord(id=organization_id, name=name.strip(), role="owner")

    async def add_member(self, membership: MembershipRecord, email: str, role: str) -> MemberRecord:
        if membership["role"] != "owner":
            raise PermissionDeniedError("إضافة الأعضاء متاحة لمالك المنظمة فقط.")
        user = await UserRepository.get_by_email(email.strip().lower())
        if user is None:
            raise NotFoundError("لا يوجد مستخدم مسجّل بهذا البريد. اطلب منه إنشاء حساب أولاً.")
        try:
            await OrganizationRepository.add_member(membership["organization_id"], user["id"], role)
        except sqlite3.IntegrityError:
            raise ConflictError("هذا المستخدم عضو في المنظمة مسبقاً.") from None
        logger.info("User %s added to organization %s as %s", user["id"], membership["organization_id"], role)
        return MemberRecord(user_id=user["id"], email=user["email"], name=user["name"], role=role)
