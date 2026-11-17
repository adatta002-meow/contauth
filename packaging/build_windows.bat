@echo off
REM Build ContAuth.exe on Windows. Run this from the repository root:
REM     packaging\build_windows.bat
setlocal
cd /d "%~dp0\.."

echo === Installing dependencies ===
python -m pip install -r requirements.txt -r requirements-agent.txt pyinstaller || goto :err

echo === Training the model (creates models\population.joblib) ===
if not exist models\population.joblib python -m contauth.ml.train || goto :err

echo === Building ContAuth.exe ===
pyinstaller packaging\agent.spec --noconfirm --distpath dist --workpath build\pyi || goto :err

echo.
echo Done. The app is at:  dist\ContAuth.exe
echo Double-click it to run, or set it to start on login with:
echo     python -m contauth.agent.autostart install --exe "%cd%\dist\ContAuth.exe"
goto :eof

:err
echo.
echo Build failed. See the messages above.
exit /b 1
