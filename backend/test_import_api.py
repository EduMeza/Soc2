"""Compatibility launcher for isolated E2E tests."""
from pathlib import Path
import subprocess
import sys
if __name__ == '__main__':
    raise SystemExit(subprocess.call([sys.executable,'-m','pytest','tests/test_pipeline.py::test_e2e'],cwd=Path(__file__).resolve().parents[1]))
