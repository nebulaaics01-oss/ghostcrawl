"""
GhostCrawl — Fingerprint Engine
Developer: ANZZ
CMS / Framework / WAF / CDN signature detection.
"""


class FingerprintEngine:
    CMS_SIGNATURES = {
        "WordPress": {
            "headers": [("x-powered-by", "wordpress")],
            "body": ["wp-content/", "wp-includes/", "wp-json"],
            "cookies": ["wordpress_", "wp-settings"],
        },
        "Laravel": {
            "headers": [],
            "body": ["laravel_session", "csrf-token"],
            "cookies": ["laravel_session", "XSRF-TOKEN"],
        },
        "Django": {
            "headers": [("x-powered-by", "django")],
            "body": ["csrfmiddlewaretoken"],
            "cookies": ["csrftoken", "sessionid"],
        },
        "Express/Node": {
            "headers": [("x-powered-by", "express")],
            "body": [],
            "cookies": ["connect.sid"],
        },
        "ASP.NET": {
            "headers": [("x-powered-by", "asp.net"), ("x-aspnet-version", "")],
            "body": ["__VIEWSTATE", "__EVENTVALIDATION"],
            "cookies": ["asp.net_sessionid"],
        },
        "Rails": {
            "headers": [("x-powered-by", "phusion passenger")],
            "body": ["csrf-param", "data-turbo"],
            "cookies": ["_session_id"],
        },
        "Shopify": {
            "headers": [],
            "body": ["cdn.shopify.com", "Shopify.theme"],
            "cookies": ["_shopify_"],
        },
        "Magento": {
            "headers": [],
            "body": ["Mage.Cookies", "/static/version"],
            "cookies": ["frontend", "PHPSESSID"],
        },
        "Joomla": {
            "headers": [],
            "body": ["/media/jui/", "Joomla!"],
            "cookies": ["joomla_"],
        },
        "Drupal": {
            "headers": [("x-generator", "drupal")],
            "body": ["Drupal.settings", "/sites/default/files/"],
            "cookies": ["SESS"],
        },
        "Next.js": {
            "headers": [("x-powered-by", "next.js")],
            "body": ["__NEXT_DATA__", "_next/static/"],
            "cookies": [],
        },
        "Nuxt.js": {
            "headers": [],
            "body": ["__nuxt", "__NUXT_JSONP__", "_nuxt/"],
            "cookies": [],
        },
    }

    WAF_SIGNATURES = {
        "Cloudflare": {
            "headers": [("server", "cloudflare"), ("cf-ray", "")],
        },
        "AWS WAF / CloudFront": {
            "headers": [("x-amz-cf-id", ""), ("via", "cloudfront")],
        },
        "Akamai": {
            "headers": [("server", "akamaighost"), ("x-akamai", "")],
        },
        "Sucuri": {
            "headers": [("x-sucuri-id", ""), ("server", "sucuri")],
        },
        "Imperva / Incapsula": {
            "headers": [("x-iinfo", ""), ("x-cdn", "incapsula")],
        },
        "F5 BIG-IP ASM": {
            "headers": [("server", "bigip"), ("x-waf-event", "")],
        },
        "Barracuda": {
            "headers": [("x-barracuda-connect", "")],
        },
        "Reblaze": {
            "headers": [("x-reblaze-protection", "")],
        },
    }

    def __init__(self, logger):
        self.logger = logger

    def _match_headers(self, headers: dict, sig_headers: list) -> list:
        hits = []
        low = {k.lower(): str(v).lower() for k, v in headers.items()}
        for name, needle in sig_headers:
            val = low.get(name)
            if val is not None and (needle == "" or needle in val):
                hits.append(f"header:{name}")
        return hits

    def _match_body(self, body: str, markers: list) -> list:
        return [f"body:{m}" for m in markers if m.lower() in body.lower()]

    def _match_cookies(self, cookies: dict, names: list) -> list:
        low = {k.lower() for k in cookies}
        return [f"cookie:{n}" for n in names if any(n.lower() in c for c in low)]

    def detect_cms(self, headers: dict, body: str, cookies: dict) -> dict:
        results = {}
        for name, sig in self.CMS_SIGNATURES.items():
            evidence = (
                self._match_headers(headers, sig["headers"]) +
                self._match_body(body, sig["body"]) +
                self._match_cookies(cookies, sig["cookies"])
            )
            if evidence:
                results[name] = {
                    "confidence": min(100, len(evidence) * 35),
                    "evidence": evidence,
                }
        self.logger.info(f"CMS detected: {list(results) or 'none'}")
        return results

    def detect_waf(self, headers: dict) -> dict:
        results = {}
        for name, sig in self.WAF_SIGNATURES.items():
            evidence = self._match_headers(headers, sig["headers"])
            if evidence:
                results[name] = {
                    "confidence": min(100, len(evidence) * 50),
                    "evidence": evidence,
                }
        self.logger.info(f"WAF detected: {list(results) or 'none'}")
        return results
