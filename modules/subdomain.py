"""
GhostCrawl — Subdomain Enumerator
Developer: ANZZ
Wordlist-based subdomain discovery + live host detection + basic port probe.
"""

import asyncio
import socket
import httpx
from dataclasses import dataclass, field


# ============================================================
# WORDLIST
# ============================================================

DEFAULT_WORDLIST = [
    "www", "mail", "ftp", "smtp", "pop", "imap", "webmail",
    "admin", "administrator", "portal", "vpn", "remote", "api",
    "dev", "development", "staging", "stage", "test", "uat",
    "prod", "production", "app", "apps", "beta", "alpha",
    "cdn", "static", "assets", "media", "img", "images",
    "upload", "uploads", "files", "docs", "wiki", "help",
    "support", "shop", "store", "payment", "checkout", "cart",
    "login", "auth", "sso", "oauth", "id", "account", "accounts",
    "blog", "news", "forum", "community", "chat", "slack",
    "git", "gitlab", "github", "jenkins", "ci", "build",
    "jira", "confluence", "kanban", "monitoring", "grafana",
    "kibana", "elk", "prometheus", "metrics", "status",
    "db", "database", "mysql", "postgres", "redis", "mongo",
    "backup", "backups", "archive", "old", "legacy",
    "internal", "intranet", "corp", "corporate", "private",
    "secure", "ssl", "tls", "mx", "ns", "dns",
    "m", "mobile", "wap", "ios", "android",
    "ws", "websocket", "socket", "stream",
    "data", "analytics", "report", "reports", "bi",
    "crm", "erp", "hr", "hris", "finance", "accounting",
]

COMMON_PORTS = [80, 443, 8080, 8443, 8000, 3000, 5000]


# ============================================================
# DATA MODELS
# ============================================================

@dataclass
class SubdomainResult:
    subdomain: str
    fqdn: str
    resolved: bool
    ip: str = ""
    http_status: int = 0
    https_status: int = 0
    open_ports: list = field(default_factory=list)
    server: str = ""
    title: str = ""


# ============================================================
# ENUMERATOR
# ============================================================

class SubdomainEnumerator:
    def __init__(self, domain: str, client: httpx.AsyncClient,
                 concurrency: int = 20, logger=None):
        self.domain = domain.strip().lstrip("http://").lstrip("https://").split("/")[0]
        self.client = client
        self.sem = asyncio.Semaphore(concurrency)
        self.logger = logger
        self.results: list[SubdomainResult] = []

    async def _resolve(self, fqdn: str) -> str:
        loop = asyncio.get_event_loop()
        try:
            info = await loop.run_in_executor(None, socket.gethostbyname, fqdn)
            return info
        except socket.gaierror:
            return ""

    async def _http_probe(self, fqdn: str) -> tuple[int, int, str, str]:
        http_status = 0
        https_status = 0
        server = ""
        title = ""
        for scheme in ("http", "https"):
            url = f"{scheme}://{fqdn}"
            try:
                r = await self.client.get(url, timeout=5, follow_redirects=True)
                if scheme == "http":
                    http_status = r.status_code
                else:
                    https_status = r.status_code
                if not server:
                    server = r.headers.get("server", "")
                if not title:
                    import re
                    m = re.search(r"<title[^>]*>(.*?)</title>", r.text, re.IGNORECASE | re.DOTALL)
                    title = m.group(1).strip()[:80] if m else ""
            except Exception:
                pass
        return http_status, https_status, server, title

    async def _port_probe(self, ip: str) -> list[int]:
        open_ports = []
        loop = asyncio.get_event_loop()

        async def check_port(port):
            try:
                fut = loop.run_in_executor(None, socket.create_connection, (ip, port), 2)
                conn = await asyncio.wait_for(fut, timeout=2)
                conn.close()
                return port
            except Exception:
                return None

        results = await asyncio.gather(*[check_port(p) for p in COMMON_PORTS])
        return [p for p in results if p is not None]

    async def _probe_subdomain(self, word: str) -> SubdomainResult | None:
        async with self.sem:
            fqdn = f"{word}.{self.domain}"
            ip = await self._resolve(fqdn)
            if not ip:
                return None

            if self.logger:
                self.logger.info(f"Subdomain live: {fqdn} -> {ip}")

            http_s, https_s, server, title = await self._http_probe(fqdn)
            open_ports = await self._port_probe(ip)

            return SubdomainResult(
                subdomain=word, fqdn=fqdn, resolved=True,
                ip=ip, http_status=http_s, https_status=https_s,
                open_ports=open_ports, server=server, title=title,
            )

    async def run(self, wordlist: list[str] | None = None) -> list[SubdomainResult]:
        words = wordlist or DEFAULT_WORDLIST
        tasks = [self._probe_subdomain(w) for w in words]
        raw = await asyncio.gather(*tasks)
        self.results = [r for r in raw if r is not None]
        if self.logger:
            self.logger.info(f"Subdomain: {len(self.results)} live found")
        return self.results
