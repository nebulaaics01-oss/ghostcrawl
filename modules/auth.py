"""
GhostCrawl — Auth Handler
Developer: ANZZ
"""

import httpx
from .config import AuthConfig, AuthMode


class AuthHandler:
    def __init__(self, client: httpx.AsyncClient, auth: AuthConfig, logger):
        self.client = client
        self.auth = auth
        self.logger = logger
        self.authenticated = False

    async def apply(self) -> bool:
        if self.auth.mode == AuthMode.NONE:
            return True
        if self.auth.mode == AuthMode.COOKIE:
            self.client.cookies.update(self.auth.cookies)
            self.logger.info(f"Auth: cookie injected ({len(self.auth.cookies)} keys)")
            self.authenticated = True
            return True
        if self.auth.mode == AuthMode.BEARER:
            self.client.headers["Authorization"] = f"Bearer {self.auth.token}"
            self.logger.info("Auth: bearer token set")
            self.authenticated = True
            return True
        if self.auth.mode == AuthMode.API_KEY:
            self.client.headers[self.auth.header_name] = self.auth.token
            self.logger.info(f"Auth: api key set on '{self.auth.header_name}'")
            self.authenticated = True
            return True
        if self.auth.mode == AuthMode.FORM_LOGIN:
            return await self._form_login()
        return False

    async def _form_login(self) -> bool:
        if not self.auth.login_url or not self.auth.login_payload:
            self.logger.warning("Auth: form_login — login_url/payload kosong")
            return False
        try:
            r = await self.client.post(self.auth.login_url, data=self.auth.login_payload)
            success = True
            if self.auth.login_success_marker:
                success = self.auth.login_success_marker in r.text
            self.authenticated = success and r.status_code < 400
            self.logger.info(f"Auth: form_login -> {r.status_code}, ok={self.authenticated}")
            return self.authenticated
        except httpx.RequestError as e:
            self.logger.error(f"Auth: form_login error — {e}")
            return False

    def session_snapshot(self) -> dict:
        return dict(self.client.cookies)
