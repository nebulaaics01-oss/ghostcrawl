"""
GhostCrawl — Core Scraper + Interactive Menu
Developer: ANZZ
"""

import asyncio
import re
import httpx
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse

from rich.console import Console
from rich.table import Table
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn
from rich.prompt import Prompt, IntPrompt
from rich import box

from .config import AuthConfig, AuthMode, ScraperConfig, Findings, setup_logging
from .auth import AuthHandler
from .fingerprint import FingerprintEngine
from .risk import RiskEngine
from .exploit import SQLiProbe, IDOREnumerator
from .subdomain import SubdomainEnumerator
from .header_probe import HeaderInjectionProbe
from .tls_probe import TLSProbe
from .report import (
    render_recon_report, render_sqli_report, render_idor_report,
    render_subdomain_report, render_header_probe_report, render_tls_report,
    export, console,
)

BANNER = r"""
[bold cyan]
 ██████╗ ██╗  ██╗ ██████╗ ███████╗████████╗ ██████╗██████╗  █████╗ ██╗    ██╗██╗
██╔════╝ ██║  ██║██╔═══██╗██╔════╝╚══██╔══╝██╔════╝██╔══██╗██╔══██╗██║    ██║██║
██║  ███╗███████║██║   ██║███████╗   ██║   ██║     ██████╔╝███████║██║ █╗ ██║██║
██║   ██║██╔══██║██║   ██║╚════██║   ██║   ██║     ██╔══██╗██╔══██║██║███╗██║██║
╚██████╔╝██║  ██║╚██████╔╝███████║   ██║   ╚██████╗██║  ██║██║  ██║╚███╔███╔╝███████╗
 ╚═════╝ ╚═╝  ╚═╝ ╚═════╝ ╚══════╝   ╚═╝    ╚═════╝╚═╝  ╚═╝╚═╝  ╚═╝ ╚══╝╚══╝ ╚══════╝
[/]
[bold white]           Recon Scraper v3.3 "Report Intelligence"[/]
[dim]           Developer: ANZZ  |  Cybercrime Universe[/]
"""

JS_PATTERNS = {
    "api_route": r'["\'](?:/api/[a-zA-Z0-9/_-]+)["\']',
    "possible_key": r'["\'][A-Za-z0-9_-]{24,}["\']',
    "endpoint_url": r'https?://[a-zA-Z0-9.-]+/[a-zA-Z0-9/_-]*',
}

COMMON_PATHS = [
    "robots.txt", "sitemap.xml", ".env", "admin", "api",
    "config.json", ".git/HEAD", "backup.zip",
    ".well-known/security.txt", "swagger.json", ".htaccess",
]

LOGIN_WALL_MARKERS = [
    "login", "sign in", "authentication required", "please log in",
]


# ============================================================
# CORE SCRAPER
# ============================================================

class GhostCrawl:
    def __init__(self, config: ScraperConfig):
        self.cfg = config
        self.base = config.base_url.rstrip("/")
        self.domain = urlparse(self.base).netloc
        self.sem = asyncio.Semaphore(config.concurrency)
        self.visited: set = set()
        self.findings = Findings()
        self.logger = setup_logging(config.log_file)
        self.client = httpx.AsyncClient(
            headers={"User-Agent": config.user_agent},
            timeout=config.timeout, follow_redirects=True,
        )
        self.auth_handler = AuthHandler(self.client, config.auth, self.logger)
        self.fp_engine = FingerprintEngine(self.logger)
        self.risk_engine = RiskEngine(self.logger)

    async def _get(self, url: str) -> httpx.Response | None:
        async with self.sem:
            await asyncio.sleep(self.cfg.delay)
            for attempt in range(self.cfg.retries + 1):
                try:
                    r = await self.client.get(url)
                    self.logger.info(f"GET {url} -> {r.status_code}")
                    return r
                except httpx.RequestError as e:
                    self.logger.warning(f"Retry {attempt}: {url} — {e}")
                    if attempt == self.cfg.retries:
                        return None
                    await asyncio.sleep(0.5 * (attempt + 1))

    def _is_login_wall(self, r: httpx.Response) -> bool:
        if r.status_code in (401, 403):
            return True
        return any(m in r.text.lower()[:2000] for m in LOGIN_WALL_MARKERS)

    async def fingerprint(self):
        r = await self._get(self.base)
        if r:
            self.findings.headers = dict(r.headers)
            self.findings.cookies = dict(r.cookies)
            self.findings.tech_stack = self.fp_engine.detect_cms(
                self.findings.headers, r.text, self.findings.cookies
            )
            self.findings.waf = self.fp_engine.detect_waf(self.findings.headers)
        return (
            self.findings.headers.get("server", "unknown"),
            self.findings.headers.get("x-powered-by", "unknown"),
        )

    async def check_common_paths(self, progress, task_id):
        for p in COMMON_PATHS:
            url = f"{self.base}/{p}"
            r = await self._get(url)
            if r and r.status_code == 200:
                self.findings.exposed_paths.append((p, r.status_code, len(r.content)))
            progress.advance(task_id)

    async def crawl(self, url: str, depth: int = 0):
        if url in self.visited or depth > self.cfg.max_depth:
            return
        self.visited.add(url)
        r = await self._get(url)
        if not r:
            return
        if self._is_login_wall(r):
            self.findings.login_walls.append(url)
            return
        if "text/html" not in r.headers.get("content-type", ""):
            return
        soup = BeautifulSoup(r.text, "html.parser")
        tasks = []
        for link in soup.find_all("a", href=True):
            full = urljoin(url, link["href"]).split("#")[0]
            if urlparse(full).netloc == self.domain and full not in self.visited:
                self.findings.endpoints.add(full)
                tasks.append(self.crawl(full, depth + 1))
        for form in soup.find_all("form"):
            self.findings.forms.append({
                "source": url,
                "action": form.get("action"),
                "method": form.get("method", "GET").upper(),
                "inputs": [i.get("name") for i in form.find_all("input") if i.get("name")],
            })
        for script in soup.find_all("script", src=True):
            self.findings.js_files.add(urljoin(url, script["src"]))
        if tasks:
            await asyncio.gather(*tasks)

    async def extract_js_secrets(self):
        for js_url in list(self.findings.js_files)[:20]:
            r = await self._get(js_url)
            if not r:
                continue
            hits = {}
            for name, pat in JS_PATTERNS.items():
                found = list(set(re.findall(pat, r.text)))[:5]
                if found:
                    hits[name] = found
            if hits:
                self.findings.secrets[js_url] = hits

    async def compute_risk(self):
        overall = self.risk_engine.compute_overall(self.findings)
        overall["summary"] = self.risk_engine.auto_summary(self.findings, overall)
        self.findings.risk_report = overall

    async def run_full_scan(self):
        with Progress(
            SpinnerColumn(), TextColumn("[progress.description]{task.description}"),
            BarColumn(), console=console,
        ) as progress:
            t0 = progress.add_task("[blue]Applying auth...", total=1)
            auth_ok = await self.auth_handler.apply()
            progress.advance(t0)
            if self.cfg.auth.mode != AuthMode.NONE:
                status = "[green]OK[/]" if auth_ok else "[red]FAILED[/]"
                console.print(f"[blue]Auth:[/] {status}")

            t1 = progress.add_task("[cyan]Fingerprinting...", total=1)
            server, powered_by = await self.fingerprint()
            progress.advance(t1)

            t2 = progress.add_task("[yellow]Probing common paths...", total=len(COMMON_PATHS))
            await self.check_common_paths(progress, t2)

            t3 = progress.add_task("[green]Crawling...", total=1)
            await self.crawl(self.base)
            progress.update(t3, completed=1)

            t4 = progress.add_task("[magenta]Extracting JS secrets...", total=1)
            await self.extract_js_secrets()
            progress.update(t4, completed=1)

            t5 = progress.add_task("[red]Computing risk scores...", total=1)
            await self.compute_risk()
            progress.update(t5, completed=1)

        return server, powered_by

    async def close(self):
        await self.client.aclose()


# ============================================================
# AUTH PROMPT
# ============================================================

async def prompt_auth() -> AuthConfig:
    console.print("\n[bold blue]Auth Setup[/]")
    modes = {
        "1": AuthMode.NONE, "2": AuthMode.COOKIE,
        "3": AuthMode.BEARER, "4": AuthMode.API_KEY, "5": AuthMode.FORM_LOGIN,
    }
    t = Table(box=box.SIMPLE, show_header=False)
    for k, v in [("1", "None"), ("2", "Cookie"), ("3", "Bearer Token"),
                  ("4", "API Key"), ("5", "Form Login")]:
        t.add_row(f"[cyan]{k}[/]", v)
    console.print(t)

    choice = Prompt.ask("Mode", choices=list(modes), default="1")
    mode = modes[choice]
    auth = AuthConfig(mode=mode)

    if mode == AuthMode.COOKIE:
        raw = Prompt.ask("Cookies (key1=val1;key2=val2)", default="")
        auth.cookies = dict(kv.split("=", 1) for kv in raw.split(";") if "=" in kv)
    elif mode == AuthMode.BEARER:
        auth.token = Prompt.ask("Bearer token", password=True)
    elif mode == AuthMode.API_KEY:
        auth.header_name = Prompt.ask("Header name", default="X-API-Key")
        auth.token = Prompt.ask("API key", password=True)
    elif mode == AuthMode.FORM_LOGIN:
        auth.login_url = Prompt.ask("Login URL")
        user_field = Prompt.ask("Username field name", default="username")
        pw_field = Prompt.ask("Password field name", default="password")
        auth.login_payload = {
            user_field: Prompt.ask("Username value"),
            pw_field: Prompt.ask("Password value", password=True),
        }
        auth.login_success_marker = Prompt.ask("Success marker (optional)", default="")
    return auth


# ============================================================
# INTERACTIVE MENU
# ============================================================

def show_menu():
    console.clear()
    console.print(BANNER)
    t = Table(box=box.ROUNDED, border_style="cyan", show_header=False)
    t.add_row("[bold cyan]1[/]", "Full Recon Scan")
    t.add_row("[bold cyan]2[/]", "Quick Fingerprint Only")
    t.add_row("[bold cyan]3[/]", "Common Path Probe Only")
    t.add_row("[bold cyan]4[/]", "SQLi Probe")
    t.add_row("[bold cyan]5[/]", "IDOR Enumeration")
    t.add_row("[bold cyan]6[/]", "Full Recon + Exploit Probe")
    t.add_row("[bold cyan]7[/]", "Subdomain Enumeration")
    t.add_row("[bold cyan]8[/]", "Header Injection Probe")
    t.add_row("[bold cyan]9[/]", "TLS/SSL Probe")
    t.add_row("[bold cyan]0[/]", "Exit")
    console.print(t)


async def interactive_main():
    show_menu()
    choice = IntPrompt.ask("[bold yellow]Select mode[/]", choices=["0","1","2","3","4","5","6","7","8","9"])

    if choice == 0:
        console.print("[dim]Session closed.[/]")
        return

    url = Prompt.ask("[bold]Target URL[/]", default="http://web-092.fictional-target.local")

    if choice in (1, 2, 3, 6):
        depth = IntPrompt.ask("Max crawl depth", default=2)
        auth_cfg = await prompt_auth()
        cfg = ScraperConfig(base_url=url, max_depth=depth, auth=auth_cfg)
        scraper = GhostCrawl(cfg)

        if choice == 1:
            server, powered_by = await scraper.run_full_scan()
            render_recon_report(scraper.findings, scraper.auth_handler)
            export(scraper.findings, scraper.auth_handler,
                    scraper.cfg.output_dir, formats=("json", "md", "csv"))

        elif choice == 2:
            await scraper.auth_handler.apply()
            await scraper.fingerprint()
            render_recon_report(scraper.findings, scraper.auth_handler)
            export(scraper.findings, scraper.auth_handler, scraper.cfg.output_dir, formats=("json",))

        elif choice == 3:
            await scraper.auth_handler.apply()
            with Progress(SpinnerColumn(), TextColumn("{task.description}"),
                           BarColumn(), console=console) as progress:
                t2 = progress.add_task("[yellow]Probing paths...", total=len(COMMON_PATHS))
                await scraper.check_common_paths(progress, t2)
            render_recon_report(scraper.findings, scraper.auth_handler)
            export(scraper.findings, scraper.auth_handler, scraper.cfg.output_dir, formats=("json", "md"))

        elif choice == 6:
            server, powered_by = await scraper.run_full_scan()
            render_recon_report(scraper.findings, scraper.auth_handler)

            endpoint = Prompt.ask("SQLi endpoint", default="/search.php")
            param = Prompt.ask("SQLi param", default="q")
            sqli_probe = SQLiProbe(scraper.client, url)
            sqli_result = await sqli_probe.run(endpoint, param)
            render_sqli_report(sqli_result)

            idor_endpoint = Prompt.ask("IDOR endpoint", default="/order/view.php")
            idor_param = Prompt.ask("IDOR param", default="order_id")
            own_id = IntPrompt.ask("Your own resource ID", default=1042)
            idor_enum = IDOREnumerator(scraper.client, url)
            idor_results = await idor_enum.probe(idor_endpoint, idor_param, own_id)
            render_idor_report(idor_results, own_id)

            export(scraper.findings, scraper.auth_handler,
                    scraper.cfg.output_dir, formats=("json", "md", "csv"))

        await scraper.close()

    elif choice == 4:
        client = httpx.AsyncClient(headers={"User-Agent": "GhostCrawl-Exploit/3.3; ANZZ"})
        endpoint = Prompt.ask("Endpoint", default="/search.php")
        param = Prompt.ask("Param", default="q")
        probe = SQLiProbe(client, url)
        result = await probe.run(endpoint, param)
        render_sqli_report(result)
        await client.aclose()

    elif choice == 5:
        client = httpx.AsyncClient(headers={"User-Agent": "GhostCrawl-Exploit/3.3; ANZZ"})
        endpoint = Prompt.ask("Endpoint", default="/order/view.php")
        param = Prompt.ask("Param", default="order_id")
        own_id = IntPrompt.ask("Your own resource ID", default=1042)
        probe_range = IntPrompt.ask("Probe range (±)", default=5)
        enum = IDOREnumerator(client, url)
        results = await enum.probe(endpoint, param, own_id, probe_range)
        render_idor_report(results, own_id)
        await client.aclose()

    elif choice == 7:
        from urllib.parse import urlparse
        domain = urlparse(url).netloc or url
        client = httpx.AsyncClient(
            headers={"User-Agent": "GhostCrawl/3.3; ANZZ"},
            verify=False, timeout=10,
        )
        custom = Prompt.ask(
            "Custom wordlist? (comma-separated, blank = default)", default=""
        )
        wordlist = [w.strip() for w in custom.split(",") if w.strip()] or None
        console.print(f"\n[cyan]Enumerating subdomains of:[/] [bold]{domain}[/]")
        enum = SubdomainEnumerator(domain, client, logger=None)
        results = await enum.run(wordlist)
        render_subdomain_report(results)
        await client.aclose()

    elif choice == 8:
        client = httpx.AsyncClient(
            headers={"User-Agent": "GhostCrawl/3.3; ANZZ"},
            verify=False, timeout=10,
        )
        endpoint = Prompt.ask("Endpoint to probe", default="/")
        probe = HeaderInjectionProbe(client, url)
        console.print(f"\n[cyan]Running header injection probe on:[/] [bold]{url}{endpoint}[/]")
        all_results = await probe.run_all(endpoint)
        summary = probe.summarize(all_results)
        render_header_probe_report(all_results, summary)
        await client.aclose()

    elif choice == 9:
        from urllib.parse import urlparse
        parsed = urlparse(url)
        host = parsed.hostname or url
        port = parsed.port or 443
        console.print(f"\n[cyan]TLS probe:[/] [bold]{host}:{port}[/]")
        probe = TLSProbe()
        result = await probe.probe(host, port)
        render_tls_report(result)

    console.print("\n[bold green]Done.[/] [dim]— GhostCrawl v3.3 by ANZZ[/]")
