"""Target URL normalisation and public-address checks, shared by targets and scans.

Himaak makes outbound requests to customer-supplied hosts (ownership checks and
scans), so every host must resolve only to public internet addresses. This blocks
requests to the server itself, cloud metadata endpoints and private networks.
"""

import asyncio
import ipaddress
import socket
from dataclasses import dataclass
from urllib.parse import urlsplit, urlunsplit

from utils.errors import RuleViolationError

MAX_URL_LENGTH = 2048
_BLOCKED_HOST_SUFFIXES = (".localhost", ".local", ".internal", ".lan", ".home.arpa")


@dataclass(frozen=True)
class TargetUrl:
    url: str
    scheme: str
    host: str
    port: int


def _ip_literal(host: str) -> ipaddress.IPv4Address | ipaddress.IPv6Address | None:
    try:
        return ipaddress.ip_address(host)
    except ValueError:
        return None


def is_public_address(address: ipaddress.IPv4Address | ipaddress.IPv6Address) -> bool:
    if isinstance(address, ipaddress.IPv6Address) and address.ipv4_mapped:
        address = address.ipv4_mapped
    return address.is_global and not address.is_multicast


def normalize_target_url(raw: str) -> TargetUrl:
    """Validates a user-supplied site URL and returns its canonical form."""
    value = (raw or "").strip()
    if not value or len(value) > MAX_URL_LENGTH or any(ch.isspace() or ord(ch) < 32 for ch in value):
        raise RuleViolationError("الرابط غير صالح.")

    parts = urlsplit(value)
    scheme = parts.scheme.lower()
    if scheme not in ("http", "https"):
        raise RuleViolationError("يجب أن يبدأ الرابط بـ http:// أو https://")
    if parts.username or parts.password:
        raise RuleViolationError("لا يُسمح بوضع اسم مستخدم أو كلمة مرور داخل الرابط.")
    if not parts.hostname:
        raise RuleViolationError("الرابط لا يحتوي على اسم نطاق.")

    try:
        port = parts.port or (443 if scheme == "https" else 80)
    except ValueError:
        raise RuleViolationError("رقم المنفذ في الرابط غير صالح.") from None

    host = parts.hostname.lower().rstrip(".")
    literal = _ip_literal(host)
    if literal is None:
        try:
            host = host.encode("idna").decode("ascii")
        except UnicodeError:
            raise RuleViolationError("اسم النطاق غير صالح.") from None
        if host == "localhost" or host.endswith(_BLOCKED_HOST_SUFFIXES) or "." not in host:
            raise RuleViolationError("لا يمكن فحص عناوين الشبكة الداخلية.")
    elif not is_public_address(literal):
        raise RuleViolationError("لا يمكن فحص عناوين الشبكة الداخلية.")

    host_for_netloc = f"[{host}]" if isinstance(literal, ipaddress.IPv6Address) else host
    default_port = 443 if scheme == "https" else 80
    netloc = host_for_netloc if port == default_port else f"{host_for_netloc}:{port}"
    url = urlunsplit((scheme, netloc, parts.path or "/", parts.query, ""))
    return TargetUrl(url=url, scheme=scheme, host=host, port=port)


async def resolve_public_addresses(host: str, port: int) -> list[str]:
    """Resolves a host and refuses it unless every address is a public internet address."""
    literal = _ip_literal(host)
    if literal is not None:
        if not is_public_address(literal):
            raise RuleViolationError("لا يمكن فحص عناوين الشبكة الداخلية.")
        return [str(literal)]

    loop = asyncio.get_running_loop()
    try:
        infos = await asyncio.wait_for(loop.getaddrinfo(host, port, type=socket.SOCK_STREAM), timeout=10)
    except (socket.gaierror, asyncio.TimeoutError):
        raise RuleViolationError("تعذّر العثور على هذا النطاق في نظام أسماء النطاقات (DNS).") from None

    addresses = sorted({info[4][0] for info in infos})
    if not addresses:
        raise RuleViolationError("تعذّر العثور على هذا النطاق في نظام أسماء النطاقات (DNS).")
    if not all(is_public_address(ipaddress.ip_address(a.split("%")[0])) for a in addresses):
        raise RuleViolationError("يشير هذا النطاق إلى عنوان داخلي أو خاص، ولا يمكن فحصه.")
    return addresses
