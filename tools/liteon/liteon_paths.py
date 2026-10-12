"""Make every Lite-On tool category importable by plain module name.

Tools import each other as top-level modules (`from read_flash import ...`).
Scripts and tests put this directory on sys.path and import this module once.
"""
from pathlib import Path
import sys

TOOLS = Path(__file__).resolve().parent
CATEGORIES = ('device', 'dump_analysis', 'reverse_engineering',
              'update_emulation', 'patch_build', 'patch_verify')

for category in reversed(CATEGORIES):
    if str(TOOLS / category) not in sys.path:
        sys.path.insert(0, str(TOOLS / category))


def tool(name):
    """Path of the tool script for module `name`."""
    for category in CATEGORIES:
        path = TOOLS / category / f'{name}.py'
        if path.exists():
            return path
    raise FileNotFoundError(f'No Lite-On tool named {name}')
