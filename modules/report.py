"""
GhostCrawl — Report & Export
Developer: ANZZ
Rich rendering + JSON/MD/CSV export.
"""

import json
import csv
from pathlib import Path
from datetime import datetime

from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich import box

from .exploit import SQLiResult, IDORResult
from .subdomain import SubdomainResult
from .header_probe import HeaderProbeResult
from .tls_probe import TLSProbeResult

console = Console()

SEV_COLOR = {
    "CRITICAL": "red", "HIGH": "red",
    "MEDIUM": "yellow", "LOW": "cyan", "INFO": "white",
}


# ============================================================
# RECON REPORT
# ============================================================

def render_recon_report(findings, auth_handler):
    server = findings.headers.get("server", "unknown")
    powered = findings.headers.get("x-powered-by", "unknown")

    console.print(Panel.fit(
        f"[bold]Server:[/] {server}\n[bold]Powered-By:[/] {powered}\n"
        f"[bold]Cookies:[/] {len(findings.cookies)}\n"
        f"[bold]Authenticated:[/] {auth_handler.authenticated}",
        title="[bold cyan]Fingerprint[/]", border_style="cyan", box=box.ROUNDED,
    ))

    if findings.tech_stack:
        t = Table(title="Tech Stack / CMS", border_style="cyan", box=box.SIMPLE_HEAVY)
        t.add_column("Name"); t.add_column("Confidence"); t.add_column("Evidence")
        for name, info in findings.tech_stack.items():
            t.add_row(name, f"{info['confidence']}%", ", ".join(info["evidence"]))
        console.print(t)

    if findings.waf:
        t = Table(title="WAF / CDN", border_style="red", box=box.SIMPLE_HEAVY)
        t.add_column("Name"); t.add_column("Confidence"); t.add_column("Evidence")
        for name, info in findings.waf.items():
            t.add_row(name, f"{info['confidence']}%", ", ".join(info["evidence"]))
        console.print(t)

    if findings.exposed_paths:
        t = Table(title="Exposed Paths", border_style="red", box=box.SIMPLE_HEAVY)
        t.add_column("Path"); t.add_column("Status"); t.add_column("Size")
        for p, s, sz in findings.exposed_paths:
            t.add_row(p, str(s), f"{sz}b")
        console.print(t)

    if findings.login_walls:
        t = Table(title="Login Walls", border_style="blue", box=box.SIMPLE_HEAVY)
        t.add_column("URL")
        for u in findings.login_walls:
            t.add_row(u)
        console.print(t)

    t = Table(title=f"Endpoints ({len(findings.endpoints)})",
               border_style="green", box=box.SIMPLE_HEAVY)
    t.add_column("URL")
    for e in list(findings.endpoints)[:20]:
        t.add_row(e)
    console.print(t)

    if findings.forms:
        t = Table(title=f"Forms ({len(findings.forms)})",
                   border_style="yellow", box=box.SIMPLE_HEAVY)
        t.add_column("Source"); t.add_column("Method"); t.add_column("Inputs")
        for f in findings.forms:
            t.add_row(f["source"], f["method"], ", ".join(f["inputs"]))
        console.print(t)

    if findings.secrets:
        t = Table(title="JS Secrets", border_style="magenta", box=box.SIMPLE_HEAVY)
        t.add_column("Source JS"); t.add_column("Type"); t.add_column("Match")
        for js, hits in findings.secrets.items():
            for typ, matches in hits.items():
                for m in matches[:3]:
                    t.add_row(js, typ, m)
        console.print(t)

    if findings.risk_report:
        rr = findings.risk_report
        c = SEV_COLOR.get(rr["highest_severity"], "white")
        console.print(Panel.fit(
            f"[bold]Highest Severity:[/] [{c}]{rr['highest_severity']}[/]\n"
            f"[bold]Risk Weight:[/] {rr['total_weight']}\n"
            f"[bold]Paths:[/] {rr['exposed_path_count']}  "
            f"[bold]Secrets:[/] {rr['secret_count']}  "
            f"[bold]Walls:[/] {rr['login_wall_count']}\n\n"
            f"[dim]{rr['summary']}[/]",
            title="[bold red]Risk Summary[/]", border_style="red", box=box.HEAVY,
        ))


# ============================================================
# EXPLOIT REPORT
# ============================================================

def render_sqli_report(result: dict):
    c = {"high": "red", "medium": "yellow", "low": "cyan", "none": "green"}.get(
        result["overall_confidence"], "white"
    )
    console.print(Panel.fit(
        f"[bold]Endpoint:[/] {result['endpoint']}\n"
        f"[bold]Param:[/] {result['param']}\n"
        f"[bold]Confidence:[/] [{c}]{result['overall_confidence'].upper()}[/]",
        title="[bold red]SQLi Probe[/]", border_style="red", box=box.ROUNDED,
    ))

    t = Table(title="Error-Based", border_style="red", box=box.SIMPLE_HEAVY)
    t.add_column("Payload"); t.add_column("Status"); t.add_column("Signature"); t.add_column("Confidence")
    for r in result["error_based"]:
        c2 = "red" if r.confidence == "high" else "white"
        t.add_row(r.payload, str(r.status), r.error_signature or "—", f"[{c2}]{r.confidence}[/]")
    console.print(t)

    t2 = Table(title="Boolean-Based", border_style="yellow", box=box.SIMPLE_HEAVY)
    t2.add_column("Payload Pair"); t2.add_column("Confidence")
    for r in result["boolean_based"]:
        c2 = "yellow" if r.confidence == "medium" else "white"
        t2.add_row(r.payload, f"[{c2}]{r.confidence}[/]")
    console.print(t2)


def render_idor_report(results: list, own_id: int):
    t = Table(
        title=f"IDOR Probe (baseline id={own_id})",
        border_style="magenta", box=box.SIMPLE_HEAVY,
    )
    t.add_column("ID"); t.add_column("Status"); t.add_column("Accessible")
    t.add_column("Content Differs"); t.add_column("Len")
    for r in results:
        if not r:
            continue
        c = "red" if r.accessible else "green"
        t.add_row(
            str(r.resource_id), str(r.status),
            f"[{c}]{r.accessible}[/]",
            str(r.content_differs), str(r.content_len),
        )
    console.print(t)
    exposed = [r for r in results if r and r.accessible and r.content_differs]
    if exposed:
        console.print(
            f"[bold red]⚠ {len(exposed)} unauthorized-access candidate(s)[/]"
        )


# ============================================================
# EXPORT
# ============================================================

def export(findings, auth_handler, output_dir: str, formats=("json", "md")):
    out = Path(output_dir)
    out.mkdir(parents=True, exist_ok=True)
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    from urllib.parse import urlparse
    slug = urlparse(findings.headers.get("x-original-url", "target")).netloc or "target"
    slug = slug.replace(":", "_").replace(".", "_") or "target"
    paths = []

    data = {
        "developer": "ANZZ",
        "module": "GhostCrawl v3.3",
        "timestamp": ts,
        "authenticated": auth_handler.authenticated,
        "headers": findings.headers,
        "cookies": findings.cookies,
        "session_cookies": auth_handler.session_snapshot(),
        "tech_stack": findings.tech_stack,
        "waf": findings.waf,
        "risk_report": findings.risk_report,
        "exposed_paths": findings.exposed_paths,
        "login_walls": findings.login_walls,
        "endpoints": list(findings.endpoints),
        "forms": findings.forms,
        "js_files": list(findings.js_files),
        "secrets": findings.secrets,
    }

    if "json" in formats:
        p = out / f"{slug}_{ts}.json"
        p.write_text(json.dumps(data, indent=2), encoding="utf-8")
        paths.append(p)

    if "md" in formats:
        rr = findings.risk_report
        lines = [
            f"# GhostCrawl Report — {ts}",
            f"**Developer:** ANZZ | **Module:** GhostCrawl v3.3",
            f"**Authenticated:** {auth_handler.authenticated}",
            "",
        ]
        if rr:
            lines += [
                "## Risk Summary",
                f"- **Highest Severity:** {rr.get('highest_severity', 'N/A')}",
                f"- **Risk Weight:** {rr.get('total_weight', 0)}",
                f"- **Summary:** {rr.get('summary', '')}",
            ]
        if findings.tech_stack:
            lines.append("\n## Tech Stack / CMS")
            for name, info in findings.tech_stack.items():
                lines.append(f"- **{name}** ({info['confidence']}%): {', '.join(info['evidence'])}")
        if findings.waf:
            lines.append("\n## WAF / CDN")
            for name, info in findings.waf.items():
                lines.append(f"- **{name}** ({info['confidence']}%): {', '.join(info['evidence'])}")
        lines.append("\n## Exposed Paths")
        for path, s, sz in findings.exposed_paths:
            lines.append(f"- `{path}` — {s} — {sz}b")
        if findings.login_walls:
            lines.append("\n## Login Walls")
            for u in findings.login_walls:
                lines.append(f"- {u}")
        lines.append(f"\n## Endpoints ({len(findings.endpoints)})")
        for e in list(findings.endpoints)[:30]:
            lines.append(f"- {e}")
        lines.append(f"\n## Forms ({len(findings.forms)})")
        for f in findings.forms:
            lines.append(f"- `{f['method']}` {f['source']} → {', '.join(f['inputs'])}")
        if findings.secrets:
            lines.append("\n## JS Secrets")
            for js, hits in findings.secrets.items():
                lines.append(f"### {js}")
                for typ, matches in hits.items():
                    lines.append(f"- **{typ}**: {matches}")
        p = out / f"{slug}_{ts}.md"
        p.write_text("\n".join(lines), encoding="utf-8")
        paths.append(p)

    if "csv" in formats:
        p = out / f"{slug}_{ts}_endpoints.csv"
        with open(p, "w", newline="", encoding="utf-8") as f:
            w = csv.writer(f)
            w.writerow(["endpoint"])
            for e in findings.endpoints:
                w.writerow([e])
        paths.append(p)

    for p in paths:
        console.print(f"[green]✓ Exported:[/] {p}")
    return paths


# ============================================================
# SUBDOMAIN REPORT
# ============================================================

def render_subdomain_report(results: list):
    if not results:
        console.print("[yellow]No live subdomains found.[/]")
        return

    t = Table(
        title=f"Subdomains — {len(results)} live",
        border_style="cyan", box=box.SIMPLE_HEAVY,
    )
    t.add_column("FQDN"); t.add_column("IP"); t.add_column("HTTP")
    t.add_column("HTTPS"); t.add_column("Ports"); t.add_column("Server"); t.add_column("Title")

    for r in sorted(results, key=lambda x: x.fqdn):
        http_c = "green" if r.http_status == 200 else "yellow" if r.http_status else "dim"
        https_c = "green" if r.https_status == 200 else "yellow" if r.https_status else "dim"
        t.add_row(
            r.fqdn, r.ip,
            f"[{http_c}]{r.http_status or '—'}[/]",
            f"[{https_c}]{r.https_status or '—'}[/]",
            ", ".join(str(p) for p in r.open_ports) or "—",
            r.server or "—",
            r.title[:40] or "—",
        )
    console.print(t)


# ============================================================
# HEADER PROBE REPORT
# ============================================================

def render_header_probe_report(all_results: dict, summary: dict):
    console.print(Panel.fit(
        f"[bold]Total Probes:[/] {summary['total_probes']}\n"
        f"[bold]Positive Hits:[/] {summary['positive_hits']}\n"
        f"[bold]Overall:[/] {'[red]vulnerable_surface[/]' if summary['overall'] == 'vulnerable_surface' else '[green]clean[/]'}",
        title="[bold red]Header Injection Summary[/]", border_style="red", box=box.ROUNDED,
    ))

    for test_name, results in all_results.items():
        hits = [r for r in results if r.confidence != "none"]
        if not hits:
            continue
        t = Table(title=test_name.replace("_", " ").title(),
                   border_style="yellow", box=box.SIMPLE_HEAVY)
        t.add_column("Header"); t.add_column("Base Status"); t.add_column("Probed Status")
        t.add_column("Len Diff"); t.add_column("Reflected"); t.add_column("Confidence")
        for r in hits:
            c = "red" if r.confidence == "high" else "yellow" if r.confidence == "medium" else "cyan"
            t.add_row(
                str(r.header_sent),
                str(r.status_baseline), str(r.status_probed),
                str(r.len_diff), str(r.reflected),
                f"[{c}]{r.confidence}[/]",
            )
        console.print(t)


# ============================================================
# TLS REPORT
# ============================================================

def render_tls_report(result: TLSProbeResult):
    sev_color = SEV_COLOR.get(result.severity, "white")
    cert = result.cert

    console.print(Panel.fit(
        f"[bold]Host:[/] {result.host}:{result.port}\n"
        f"[bold]Severity:[/] [{sev_color}]{result.severity}[/]\n"
        f"[bold]TLS Supported:[/] {', '.join(result.supported_versions) or 'none'}\n"
        f"[bold]Deprecated:[/] [red]{', '.join(result.deprecated_versions) or 'none'}[/]\n"
        f"[bold]Cipher:[/] {result.negotiated_cipher or 'unknown'}"
        f"{' [red](WEAK)[/]' if result.weak_cipher_detected else ''}\n"
        f"[bold]HSTS:[/] {'[green]Yes[/]' if result.hsts else '[red]No[/]'}",
        title="[bold cyan]TLS/SSL Probe[/]", border_style="cyan", box=box.ROUNDED,
    ))

    if cert.subject:
        t = Table(title="Certificate", border_style="green", box=box.SIMPLE_HEAVY)
        t.add_column("Field"); t.add_column("Value")
        t.add_row("Subject", cert.subject)
        t.add_row("Issuer", cert.issuer)
        t.add_row("Not Before", cert.not_before)
        t.add_row("Not After", cert.not_after)
        exp_color = "red" if cert.expired else "yellow" if cert.days_remaining < 30 else "green"
        t.add_row("Days Remaining", f"[{exp_color}]{cert.days_remaining}[/]")
        t.add_row("Self-Signed", f"[red]{cert.self_signed}[/]" if cert.self_signed else str(cert.self_signed))
        if cert.san:
            t.add_row("SAN", ", ".join(cert.san[:5]))
        console.print(t)

    if result.issues:
        t2 = Table(title="Issues", border_style="red", box=box.SIMPLE_HEAVY)
        t2.add_column("Finding")
        for issue in result.issues:
            t2.add_row(f"[yellow]{issue}[/]")
        console.print(t2)
