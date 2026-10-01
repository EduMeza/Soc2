"""Portable entry point for isolated API integration tests."""
from pathlib import Path
import subprocess
import sys

if __name__ == '__main__':
    raise SystemExit(subprocess.call([sys.executable,'-m','pytest','tests/test_pipeline.py','-v'],cwd=Path(__file__).resolve().parent))
