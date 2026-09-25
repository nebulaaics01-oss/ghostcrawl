"""
GhostCrawl — Risk Engine
Developer: ANZZ
Rule-based severity scoring + auto-summary for recon findings.
"""

from .config import Severity


class RiskEngine:
    PATH_SEVERITY = {
        ".env": Severity.CRITICAL,
        ".git/HEAD": Severity.HIGH,
        "backup.zip": Severity.HIGH,
        "config.json": Severity.MEDIUM,
        "swagger.json": Severity.MEDIUM,
        ".htaccess": Severity.LOW,
        "admin": Severity.MEDIUM,
        "api": Severity.LOW,
        "robots.txt": Severity.INFO,
        "sitemap.xml": Severity.INFO,
        ".well-known/security.txt": Severity.INFO,
    }

    PATH_RATIONALE = {
        ".env": "Environment file — credential/secret leak",
        ".git/HEAD": "Git metadata — source disclosure via .git dump",
        "backup.zip": "Backup archive — full source/data leak",
        "config.json": "Config file — internal config disclosure",
        "swagger.json": "API schema — attack surface mapping for API abuse",
        ".htaccess": "Server config — minor info disclosure",
        "admin": "Admin panel — auth bypass / brute candidate",
        "api": "API root — enumerate for further testing",
    }

    def __init__(self, logger):
        self.logger = logger

    def score_exposed_paths(self, exposed_paths: list) -> list:
        scored = []
        for path, status, size in exposed_paths:
            sev = self.PATH_SEVERITY.get(path, Severity.LOW)
            scored.append({
                "path": path, "status": status, "size": size,
                "severity": sev.label, "weight": sev.weight,
                "rationale": self.PATH_RATIONALE.get(path, "Review manually"),
            })
        scored.sort(key=lambda x: x["weight"], reverse=True)
        return scored

    def score_secrets(self, secrets: dict) -> list:
        scored = []
        for js_url, hits in secrets.items():
            for typ, matches in hits.items():
                sev = Severity.HIGH if typ == "possible_key" else Severity.LOW
                scored.append({
                    "source": js_url, "type": typ,
                    "count": len(matches), "severity": sev.label, "weight": sev.weight,
                })
        scored.sort(key=lambda x: x["weight"], reverse=True)
        return scored

    def score_login_walls(self, login_walls: list) -> list:
        return [
            {
                "url": u, "severity": Severity.MEDIUM.label,
                "rationale": "Auth boundary — credential/session testing candidate",
            }
            for u in login_walls
        ]

    def compute_overall(self, findings) -> dict:
        path_scores = self.score_exposed_paths(findings.exposed_paths)
        secret_scores = self.score_secrets(findings.secrets)
        wall_scores = self.score_login_walls(findings.login_walls)

        total_weight = (
            sum(p["weight"] for p in path_scores) +
            sum(s["weight"] for s in secret_scores) +
            sum(2 for _ in wall_scores)
        )
        highest = Severity.INFO
        for p in path_scores:
            if Severity[p["severity"]].weight > highest.weight:
                highest = Severity[p["severity"]]

        result = {
            "total_weight": total_weight,
            "highest_severity": highest.label,
            "exposed_path_count": len(path_scores),
            "secret_count": len(secret_scores),
            "login_wall_count": len(wall_scores),
            "critical_findings": [p for p in path_scores if p["severity"] == "CRITICAL"],
            "scored_paths": path_scores,
            "scored_secrets": secret_scores,
        }
        self.logger.info(f"Risk: weight={total_weight}, highest={highest.label}")
        return result

    def auto_summary(self, findings, overall: dict) -> str:
        parts = []
        parts.append(
            f"Target exposes {overall['exposed_path_count']} flagged path(s), "
            f"{overall['secret_count']} JS-derived secret candidate(s), "
            f"and {overall['login_wall_count']} auth boundary(ies)."
        )
        parts.append(f"Highest severity: {overall['highest_severity']}.")
        if overall["critical_findings"]:
            crit = ", ".join(p["path"] for p in overall["critical_findings"])
            parts.append(f"CRITICAL: {crit} — prioritize for exploitation phase.")
        if findings.tech_stack:
            top = max(findings.tech_stack.items(), key=lambda kv: kv[1]["confidence"])
            parts.append(f"Primary stack: {top[0]} ({top[1]['confidence']}% confidence).")
        if findings.waf:
            top_waf = max(findings.waf.items(), key=lambda kv: kv[1]["confidence"])
            parts.append(
                f"WAF detected: {top_waf[0]} — factor into stealth planning."
            )
        return " ".join(parts)
