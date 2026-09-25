"""
GhostCrawl — Header Injection Probe
Developer: ANZZ
Detect cache poisoning surface, SSRF via header, host header injection,
X-Forwarded-For bypass, and response differential via header manipulation.
"""

import asyncio
import httpx
from dataclasses import dataclass, field


# ============================================================
# PROBE DEFINITIONS
# ============================================================

HEADER_TEST_SETS = {
    "host_injection": [
        {"Host": "evil.fictional-target.local"},
        {"Host": "127.0.0.1"},
        {"Host": "localhost"},
    ],
    "xff_bypass": [
        {"X-Forwarded-For": "127.0.0.1"},
        {"X-Forwarded-For": "::1"},
        {"X-Forwarded-For": "192.168.1.1"},
        {"X-Forwarded-For": "10.0.0.1"},
    ],
    "cache_poison": [
        {"X-Forwarded-Host": "evil.fictional-target.local"},
        {"X-Original-URL": "/admin"},
        {"X-Rewrite-URL": "/admin"},
        {"X-Override-URL": "/admin"},
    ],
    "ssrf_headers": [
        {"X-Forwarded-For": "http://169.254.169.254/latest/meta-data/"},
        {"True-Client-IP": "127.0.0.1"},
        {"CF-Connecting-IP": "127.0.0.1"},
        {"X-Real-IP": "127.0.0.1"},
    ],
    "method_override": [
        {"X-HTTP-Method-Override": "PUT"},
        {"X-HTTP-Method-Override": "DELETE"},
        {"X-Method-Override": "PATCH"},
    ],
}


# ============================================================
# DATA MODEL
# ============================================================

@dataclass
class HeaderProbeResult:
    test_name: str
    header_sent: dict
    status_baseline: int
    status_probed: int
    len_baseline: int
    len_probed: int
    status_changed: bool = False
    len_diff: int = 0
    reflected: bool = False
    confidence: str = "none"


# ============================================================
# PROBE ENGINE
# ============================================================

class HeaderInjectionProbe:
    def __init__(self, client: httpx.AsyncClient, base_url: str, logger=None):
        self.client = client
        self.base = base_url.rstrip("/")
        self.logger = logger

    async def _get(self, url: str, headers: dict | None = None) -> httpx.Response | None:
        try:
            return await self.client.get(url, headers=headers or {}, timeout=10)
        except httpx.RequestError as e:
            if self.logger:
                self.logger.warning(f"HeaderProbe fetch failed: {url} — {e}")
            return None

    async def _baseline(self, endpoint: str) -> httpx.Response | None:
        return await self._get(f"{self.base}{endpoint}")

    def _evaluate(self, test_name: str, headers_sent: dict,
                   baseline: httpx.Response, probed: httpx.Response) -> HeaderProbeResult:
        status_changed = baseline.status_code != probed.status_code
        len_diff = abs(len(probed.content) - len(baseline.content))

        reflected = any(
            str(v).lower() in probed.text.lower()
            for v in headers_sent.values()
            if len(str(v)) > 6
        )

        if status_changed or reflected:
            confidence = "high"
        elif len_diff > 100:
            confidence = "medium"
        elif len_diff > 20:
            confidence = "low"
        else:
            confidence = "none"

        return HeaderProbeResult(
            test_name=test_name,
            header_sent=headers_sent,
            status_baseline=baseline.status_code,
            status_probed=probed.status_code,
            len_baseline=len(baseline.content),
            len_probed=len(probed.content),
            status_changed=status_changed,
            len_diff=len_diff,
            reflected=reflected,
            confidence=confidence,
        )

    async def probe_set(self, endpoint: str, test_name: str,
                         header_list: list[dict]) -> list[HeaderProbeResult]:
        baseline = await self._baseline(endpoint)
        if not baseline:
            return []

        results = []
        for headers in header_list:
            probed = await self._get(f"{self.base}{endpoint}", headers=headers)
            if not probed:
                continue
            result = self._evaluate(test_name, headers, baseline, probed)
            if self.logger:
                self.logger.info(
                    f"HeaderProbe [{test_name}] {headers} -> confidence={result.confidence}"
                )
            results.append(result)
        return results

    async def run_all(self, endpoint: str = "/") -> dict[str, list[HeaderProbeResult]]:
        all_results = {}
        tasks = [
            (test_name, self.probe_set(endpoint, test_name, header_list))
            for test_name, header_list in HEADER_TEST_SETS.items()
        ]
        for test_name, coro in tasks:
            all_results[test_name] = await coro
        return all_results

    def summarize(self, all_results: dict) -> dict:
        total = 0
        hits = 0
        high = []
        for test_name, results in all_results.items():
            for r in results:
                total += 1
                if r.confidence in ("high", "medium"):
                    hits += 1
                if r.confidence == "high":
                    high.append(f"{test_name}: {r.header_sent}")
        return {
            "total_probes": total,
            "positive_hits": hits,
            "high_confidence": high,
            "overall": "vulnerable_surface" if hits > 0 else "clean",
        }
