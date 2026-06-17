"""Streamlit Cloud entry point — delegates to the dashboard module."""

import sys
from pathlib import Path

# Ensure the project root is on the Python path
sys.path.insert(0, str(Path(__file__).parent))

# The dashboard app.py does the same sys.path setup,
# so we can just exec it as a script.
dashboard_path = Path(__file__).parent / "src" / "dashboard" / "app.py"
with open(dashboard_path, "r", encoding="utf-8") as f:
    code = f.read()
exec(compile(code, str(dashboard_path), "exec"))
