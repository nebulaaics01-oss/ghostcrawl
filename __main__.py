"""
GhostCrawl — python -m ghostcrawl entrypoint
Developer: ANZZ
"""

import asyncio
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from modules.core import interactive_main

if __name__ == "__main__":
    asyncio.run(interactive_main())
