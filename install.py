"""
GHOSTCRAWL — Auto Installer
Developer: ANZZ
Checks Python version, installs dependencies, then launches the tool.
"""

import sys
import subprocess
import importlib.util
from pathlib import Path

REQUIRED_PYTHON = (3, 10)
REQUIREMENTS = Path(__file__).parent / "requirements.txt"

BANNER = r"""
 ██████╗ ██╗  ██╗ ██████╗ ███████╗████████╗ ██████╗██████╗  █████╗ ██╗    ██╗██╗
██╔════╝ ██║  ██║██╔═══██╗██╔════╝╚══██╔══╝██╔════╝██╔══██╗██╔══██╗██║    ██║██║
██║  ███╗███████║██║   ██║███████╗   ██║   ██║     ██████╔╝███████║██║ █╗ ██║██║
██║   ██║██╔══██║██║   ██║╚════██║   ██║   ██║     ██╔══██╗██╔══██║██║███╗██║██║
╚██████╔╝██║  ██║╚██████╔╝███████║   ██║   ╚██████╗██║  ██║██║  ██║╚███╔███╔╝███████╗
 ╚═════╝ ╚═╝  ╚═╝ ╚═════╝ ╚══════╝   ╚═╝    ╚═════╝╚═╝  ╚═╝╚═╝  ╚═╝ ╚══╝╚══╝ ╚══════╝
"""


def check_python():
    if sys.version_info < REQUIRED_PYTHON:
        print(f"[!] Python {REQUIRED_PYTHON[0]}.{REQUIRED_PYTHON[1]}+ required. "
              f"Got {sys.version_info.major}.{sys.version_info.minor}")
        sys.exit(1)
    print(f"[+] Python {sys.version_info.major}.{sys.version_info.minor} OK")


def check_pip():
    result = subprocess.run(
        [sys.executable, "-m", "pip", "--version"],
        capture_output=True, text=True
    )
    if result.returncode != 0:
        print("[!] pip not found. Install pip first.")
        sys.exit(1)
    print("[+] pip OK")


def install_deps():
    print("[*] Installing dependencies...")
    result = subprocess.run(
        [sys.executable, "-m", "pip", "install", "-r", str(REQUIREMENTS),
         "--quiet", "--disable-pip-version-check"],
        capture_output=True, text=True
    )
    if result.returncode != 0:
        print(f"[!] Dependency install failed:\n{result.stderr}")
        sys.exit(1)
    print("[+] All dependencies installed")


def verify_imports():
    packages = ["httpx", "bs4", "rich", "lxml"]
    missing = [p for p in packages if importlib.util.find_spec(p) is None]
    if missing:
        print(f"[!] Still missing after install: {missing}")
        sys.exit(1)
    print("[+] Import verification OK")


def launch():
    print("[*] Launching GhostCrawl...\n")
    import asyncio
    # dynamic import biar install.py bisa jalan standalone
    sys.path.insert(0, str(Path(__file__).parent))
    from modules.core import interactive_main
    asyncio.run(interactive_main())


if __name__ == "__main__":
    print(BANNER)
    print("GhostCrawl v3.3 — Installer")
    print("Developer: ANZZ\n")
    check_python()
    check_pip()
    install_deps()
    verify_imports()
    launch()
