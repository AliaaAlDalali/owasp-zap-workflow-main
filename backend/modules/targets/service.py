import ipaddress
import logging
import secrets
import sqlite3

import dns.asyncresolver
import dns.exception
import httpx

from config import settings
from modules.organizations.repository import MembershipRecord
from modules.targets.repository import TargetRecord, TargetRepository
from utils.errors import ConflictError, NotFoundError, PermissionDeniedError, RuleViolationError
from utils.network import normalize_target_url, resolve_public_addresses

logger = logging.getLogger(__name__)

DNS_RECORD_PREFIX = "_himaak-verify"
VERIFICATION_FILE_PATH = "/.well-known/himaak-verify.txt"
MAX_VERIFICATION_FILE_BYTES = 1024


def _is_ip_literal(host: str) -> bool:
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        return False


class TargetService:
    async def create(self, membership: MembershipRecord, raw_url: str) -> TargetRecord:
        target_url = normalize_target_url(raw_url)
        token = secrets.token_hex(16)
        try:
            target_id = await TargetRepository.create(
                membership["organization_id"], target_url.url, target_url.host, token, membership["user_id"],
            )
        except sqlite3.IntegrityError:
            raise ConflictError("هذا الموقع مضاف مسبقاً في المنظمة.") from None
        logger.info("Target %s added to organization %s", target_id, membership["organization_id"])
        return await self.get(membership, target_id)

    async def get(self, membership: MembershipRecord, target_id: int) -> TargetRecord:
        target = await TargetRepository.get(membership["organization_id"], target_id)
        if target is None:
            raise NotFoundError("الموقع غير موجود.")
        return target

    async def delete(self, membership: MembershipRecord, target_id: int) -> None:
        if membership["role"] != "owner":
            raise PermissionDeniedError("حذف المواقع متاح لمالك المنظمة فقط.")
        if not await TargetRepository.delete(membership["organization_id"], target_id):
            raise NotFoundError("الموقع غير موجود.")

    def verification_instructions(self, target: TargetRecord) -> dict[str, str | None]:
        value = f"himaak-verify={target['verification_token']}"
        base = target["url"].split("/", 3)  # scheme:, '', netloc, rest
        return {
            "dns_record_name": None if _is_ip_literal(target["host"]) else f"{DNS_RECORD_PREFIX}.{target['host']}",
            "dns_record_value": value,
            "file_url": f"{base[0]}//{base[2]}{VERIFICATION_FILE_PATH}",
            "file_content": value,
        }

    async def verify(self, membership: MembershipRecord, target_id: int) -> TargetRecord:
        """Checks the DNS record first, then the file. Scans stay locked until one passes."""
        target = await self.get(membership, target_id)
        if target["verified_at"]:
            return target

        expected = f"himaak-verify={target['verification_token']}"
        method = None
        if not _is_ip_literal(target["host"]) and await self._dns_has_token(target["host"], expected):
            method = "dns"
        elif await self._file_has_token(target, expected):
            method = "file"

        if method is None:
            raise RuleViolationError(
                "لم نعثر على رمز التحقق بعد. أضف سجل TXT أو ملف التحقق كما في التعليمات، "
                "ثم أعد المحاولة (قد يستغرق انتشار سجل DNS بضع دقائق)."
            )
        await TargetRepository.mark_verified(target["id"], method)
        logger.info("Target %s verified by %s", target["id"], method)
        return await self.get(membership, target_id)

    async def _dns_has_token(self, host: str, expected: str) -> bool:
        resolver = dns.asyncresolver.Resolver()
        resolver.lifetime = settings.verification_timeout_seconds
        try:
            answers = await resolver.resolve(f"{DNS_RECORD_PREFIX}.{host}", "TXT")
        except dns.exception.DNSException:
            return False
        for record in answers:
            text = b"".join(record.strings).decode("utf-8", errors="ignore").strip()
            if text == expected:
                return True
        return False

    async def _file_has_token(self, target: TargetRecord, expected: str) -> bool:
        target_url = normalize_target_url(target["url"])
        # Resolve once, refuse private addresses, then connect to that exact address so a
        # second DNS answer cannot redirect the request to an internal host (DNS rebinding).
        address = (await resolve_public_addresses(target_url.host, target_url.port))[0]
        ip_netloc = f"[{address}]" if ":" in address else address
        host_header = f"[{target_url.host}]" if ":" in target_url.host else target_url.host
        if target_url.port not in (80, 443):
            host_header = f"{host_header}:{target_url.port}"

        request_url = f"{target_url.scheme}://{ip_netloc}:{target_url.port}{VERIFICATION_FILE_PATH}"
        extensions = {"sni_hostname": target_url.host} if target_url.scheme == "https" else {}
        try:
            async with httpx.AsyncClient(follow_redirects=False, timeout=settings.verification_timeout_seconds) as client:
                async with client.stream("GET", request_url, headers={"Host": host_header},
                                         extensions=extensions) as response:
                    if response.status_code != 200:
                        return False
                    body = b""
                    async for chunk in response.aiter_bytes():
                        body += chunk
                        if len(body) > MAX_VERIFICATION_FILE_BYTES:
                            return False
        except httpx.HTTPError:
            return False
        return expected in body.decode("utf-8", errors="ignore").split()
