"""Streamlit Cloud entry point — delegates to the dashboard module."""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
exec(open(str(Path(__file__).parent / "src" / "dashboard" / "app.py"), encoding="utf-8").read())
