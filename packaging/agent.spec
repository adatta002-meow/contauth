# PyInstaller spec for the ContAuth desktop agent.
# Build (on Windows, from the repo root):
#     pip install -r requirements.txt -r requirements-agent.txt pyinstaller
#     python -m contauth.ml.train            # ensures models/population.joblib exists
#     pyinstaller packaging/agent.spec --noconfirm
# Result: dist/ContAuth.exe  (one file, no console window).
#
# The same spec works on macOS and Linux (it produces a binary for whatever OS you
# run it on; PyInstaller does not cross-compile). On macOS it yields dist/ContAuth.
import os
from PyInstaller.utils.hooks import collect_submodules, collect_data_files

ROOT = os.path.abspath(os.getcwd())

# The trained model is bundled next to the code so the frozen app finds it at
# sys._MEIPASS/population.joblib (see contauth/agent/main.resolve_population).
datas = [(os.path.join(ROOT, "models", "population.joblib"), ".")]
datas += collect_data_files("sklearn")

# scikit-learn / scipy / pynput load submodules dynamically; collect them so the
# frozen build doesn't miss an import at runtime.
hidden = []
for pkg in ("sklearn", "scipy", "joblib", "pynput", "cryptography", "contauth"):
    hidden += collect_submodules(pkg)

a = Analysis(
    [os.path.join(ROOT, "contauth", "agent", "__main__.py")],
    pathex=[ROOT],
    binaries=[],
    datas=datas,
    hiddenimports=hidden,
    hookspath=[],
    runtime_hooks=[],
    excludes=["flask", "werkzeug", "pytest", "matplotlib"],  # not used by the agent
    noarchive=False,
)
pyz = PYZ(a.pure)

exe = EXE(
    pyz, a.scripts, a.binaries, a.datas, [],
    name="ContAuth",
    debug=False,
    strip=False,
    upx=True,
    console=False,          # windowed app, no terminal
    disable_windowed_traceback=False,
    icon=None,
)
