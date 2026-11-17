"""Entry point for `python -m contauth.agent` (and the PyInstaller build).

All logic lives in main.py; this just invokes it so the module and the frozen app
share one code path.
"""
from contauth.agent.main import main

if __name__ == "__main__":
    main()
