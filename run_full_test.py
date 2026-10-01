"""Run isolated tests; never start or mutate the runtime database."""
from pathlib import Path
import subprocess
import sys

if __name__ == '__main__':
    raise SystemExit(subprocess.call([sys.executable,'-m','pytest','-v'],cwd=Path(__file__).resolve().parent))
