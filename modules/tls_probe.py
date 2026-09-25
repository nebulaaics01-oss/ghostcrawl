"""
GhostCrawl — TLS/SSL Probe
Developer: ANZZ
Detect TLS version support, weak ciphers, cert expiry, misconfig surface.
"""

import asyncio
import ssl
import socket
from datetime import datetime, timezone
from dataclasses import dataclass, field


# ============================================================
# CONSTANTS
# ============================================================

WEAK_CIPHERS = [
    "RC4", "MD5", "DES", "3DES", "NULL", "EXPORT",
    "ANON", "ADH", "AECDH", "PSK", "SRP",
]

TLS_VERSIONS = {
    "TLSv1.0": ssl.TLSVersion.TLSv1,
    "TLSv1.1": ssl.TLSVersion.TLSv1_1,
    "TLSv1.2": ssl.TLSVersion.TLSv1_2,
    "TLSv1.3": ssl.TLSVersion.TLSv1_3,
}

DEPRECATED_VERSIONS = {"TLSv1.0", "TLSv1.1"}


# ============================================================
# DATA MODEL
# ============================================================

@dataclass
class CertInfo:
    subject: str = ""
    issuer: str = ""
    not_before: str = ""
    not_after: str = ""
    days_remaining: int = 0
    expired: bool = False
    san: list = field(default_factory=list)
    self_signed: bool = False


@dataclass
class TLSProbeResult:
    host: str
    port: int
    supported_versions: list = field(default_factory=list)
    deprecated_versions: list = field(default_factory=list)
    negotiated_cipher: str = ""
    weak_cipher_detected: bool = False
    cert: CertInfo = field(default_factory=CertInfo)
    hsts: bool = False
    issues: list = field(default_factory=list)
    severity: str = "INFO"


# ============================================================
# PROBE ENGINE
# ============================================================

class TLSProbe:
    def __init__(self, logger=None):
        self.logger = logger

    def _parse_cert(self, cert: dict) -> CertInfo:
        info = CertInfo()
        subj = dict(x[0] for x in cert.get("subject", []))
        info.subject = subj.get("commonName", "")
        iss = dict(x[0] for x in cert.get("issuer", []))
        info.issuer = iss.get("organizationName", "")
        info.self_signed = info.subject == info.issuer

        not_after_str = cert.get("notAfter", "")
        not_before_str = cert.get("notBefore", "")
        info.not_before = not_before_str
        info.not_after = not_after_str

        try:
            expiry = datetime.strptime(not_after_str, "%b %d %H:%M:%S %Y %Z")
            expiry = expiry.replace(tzinfo=timezone.utc)
            now = datetime.now(tz=timezone.utc)
            info.days_remaining = (expiry - now).days
            info.expired = info.days_remaining < 0
        except Exception:
            pass

        san_raw = cert.get("subjectAltName", [])
        info.san = [v for _, v in san_raw]
        return info

    def _check_weak_cipher(self, cipher_name: str) -> bool:
        return any(w in cipher_name.upper() for w in WEAK_CIPHERS)

    async def _try_version(self, host: str, port: int, version_label: str,
                            tls_version) -> bool:
        loop = asyncio.get_event_loop()

        def _connect():
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            ctx.minimum_version = tls_version
            ctx.maximum_version = tls_version
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            try:
                with socket.create_connection((host, port), timeout=5) as sock:
                    with ctx.wrap_socket(sock, server_hostname=host):
                        return True
            except Exception:
                return False

        try:
            return await asyncio.wait_for(
                loop.run_in_executor(None, _connect), timeout=6
            )
        except Exception:
            return False

    async def _get_cert_and_cipher(self, host: str, port: int) -> tuple[dict, str, bool]:
        loop = asyncio.get_event_loop()

        def _connect():
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            try:
                with socket.create_connection((host, port), timeout=5) as sock:
                    with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                        cert = ssock.getpeercert()
                        cipher = ssock.cipher()
                        cipher_name = cipher[0] if cipher else ""
                        return cert or {}, cipher_name
            except Exception:
                return {}, ""

        try:
            cert, cipher_name = await asyncio.wait_for(
                loop.run_in_executor(None, _connect), timeout=6
            )
            weak = self._check_weak_cipher(cipher_name)
            return cert, cipher_name, weak
        except Exception:
            return {}, "", False

    async def _check_hsts(self, host: str, port: int) -> bool:
        import httpx
        try:
            async with httpx.AsyncClient(verify=False) as client:
                r = await client.get(f"https://{host}:{port}/", timeout=5)
                return "strict-transport-security" in r.headers
        except Exception:
            return False

    def _compute_issues(self, result: TLSProbeResult) -> tuple[list, str]:
        issues = []
        if result.deprecated_versions:
            issues.append(f"Deprecated TLS: {', '.join(result.deprecated_versions)}")
        if result.weak_cipher_detected:
            issues.append(f"Weak cipher: {result.negotiated_cipher}")
        if result.cert.expired:
            issues.append("Certificate expired")
        elif 0 < result.cert.days_remaining < 30:
            issues.append(f"Certificate expiring soon ({result.cert.days_remaining}d)")
        if result.cert.self_signed:
            issues.append("Self-signed certificate")
        if not result.hsts:
            issues.append("HSTS not set")

        if any("Deprecated" in i or "expired" in i for i in issues):
            severity = "HIGH"
        elif any("Weak cipher" in i or "Self-signed" in i for i in issues):
            severity = "MEDIUM"
        elif issues:
            severity = "LOW"
        else:
            severity = "INFO"
        return issues, severity

    async def probe(self, host: str, port: int = 443) -> TLSProbeResult:
        result = TLSProbeResult(host=host, port=port)

        version_tasks = {
            label: self._try_version(host, port, label, ver)
            for label, ver in TLS_VERSIONS.items()
        }
        version_results = {}
        for label, coro in version_tasks.items():
            try:
                ok = await coro
                version_results[label] = ok
            except Exception:
                version_results[label] = False

        result.supported_versions = [v for v, ok in version_results.items() if ok]
        result.deprecated_versions = [
            v for v in result.supported_versions if v in DEPRECATED_VERSIONS
        ]

        cert, cipher, weak = await self._get_cert_and_cipher(host, port)
        result.negotiated_cipher = cipher
        result.weak_cipher_detected = weak
        if cert:
            result.cert = self._parse_cert(cert)

        result.hsts = await self._check_hsts(host, port)
        result.issues, result.severity = self._compute_issues(result)

        if self.logger:
            self.logger.info(
                f"TLS [{host}:{port}] versions={result.supported_versions}, "
                f"severity={result.severity}"
            )
        return result
