"""
GhostCrawl — Config
Developer: ANZZ
"""

from dataclasses import dataclass, field
from enum import Enum
import logging
from pathlib import Path


class AuthMode(Enum):
    NONE = "none"
    COOKIE = "cookie"
    BEARER = "bearer"
    API_KEY = "api_key"
    FORM_LOGIN = "form_login"


class Severity(Enum):
    INFO = ("INFO", 1)
    LOW = ("LOW", 2)
    MEDIUM = ("MEDIUM", 3)
    HIGH = ("HIGH", 4)
    CRITICAL = ("CRITICAL", 5)

    def __init__(self, label, weight):
        self.label = label
        self.weight = weight


@dataclass
class AuthConfig:
    mode: AuthMode = AuthMode.NONE
    token: str = ""
    header_name: str = "Authorization"
    login_url: str = ""
    login_payload: dict = field(default_factory=dict)
    login_success_marker: str = ""
    cookies: dict = field(default_factory=dict)


@dataclass
class ScraperConfig:
    base_url: str
    max_depth: int = 2
    concurrency: int = 5
    delay: float = 0.3
    retries: int = 2
    timeout: int = 10
    output_dir: str = "./output"
    user_agent: str = "Mozilla/5.0 (GhostCrawl/3.3; ANZZ-recon-module)"
    log_file: str = "./output/ghostcrawl.log"
    auth: AuthConfig = field(default_factory=AuthConfig)


@dataclass
class Findings:
    endpoints: set = field(default_factory=set)
    forms: list = field(default_factory=list)
    js_files: set = field(default_factory=set)
    secrets: dict = field(default_factory=dict)
    headers: dict = field(default_factory=dict)
    exposed_paths: list = field(default_factory=list)
    cookies: dict = field(default_factory=dict)
    login_walls: list = field(default_factory=list)
    tech_stack: dict = field(default_factory=dict)
    waf: dict = field(default_factory=dict)
    risk_report: dict = field(default_factory=dict)


def setup_logging(log_path: str) -> logging.Logger:
    Path(log_path).parent.mkdir(parents=True, exist_ok=True)
    logger = logging.getLogger("GhostCrawl")
    logger.setLevel(logging.INFO)
    logger.handlers.clear()
    fh = logging.FileHandler(log_path, encoding="utf-8")
    fh.setFormatter(logging.Formatter("%(asctime)s [%(levelname)s] %(message)s"))
    logger.addHandler(fh)
    return logger
