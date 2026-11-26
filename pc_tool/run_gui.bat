@echo off
setlocal
rem ==========================================================================
rem  Pico USB Sniffer GUI launcher
rem    run_gui.bat                  open the app
rem    run_gui.bat --demo           start a capture with synthetic data
rem    run_gui.bat file.pusb        open a capture file (also for "Open with")
rem    run_gui.bat --console ...    keep the console (shows Python errors)
rem  First run creates a local virtual environment (.venv) with the packages.
rem ==========================================================================

rem script folder (saved first: "shift" also shifts %0)
set "HERE=%~dp0"
set "CONSOLE="
if /i "%~1"=="--console" (
    set "CONSOLE=1"
    shift
)

rem resolve the argument before changing directory (relative paths)
set "ARG="
if "%~1"=="" goto :have_arg
if exist "%~1" (set "ARG=%~f1") else (set "ARG=%~1")
:have_arg

cd /d "%HERE%"
set "VPY=%HERE%.venv\Scripts\python.exe"
set "VPYW=%HERE%.venv\Scripts\pythonw.exe"

rem A venv is tied to the Python it was created with (absolute path in
rem pyvenv.cfg). If the folder was copied from another PC, that Python does
rem not exist here: detect it by actually running the venv and rebuild it.
if not exist "%VPY%" goto :make_venv
"%VPY%" -c "import sys" >nul 2>&1
if not errorlevel 1 goto :check_pkgs
echo The existing .venv does not work on this PC (copied from another machine?).
echo Recreating it...
rmdir /s /q "%HERE%.venv"
if exist "%HERE%.venv" goto :err

:make_venv
rem ---- find a real Python (skip the Microsoft Store "python" stub)
set "PY="
where py >nul 2>&1 && py -3 -c "import sys" >nul 2>&1 && set "PY=py -3"
if not defined PY python -c "import sys" >nul 2>&1 && set "PY=python"
if not defined PY goto :no_python
%PY% -c "import sys; sys.exit(0 if sys.version_info >= (3, 9) else 1)" >nul 2>&1
if errorlevel 1 goto :old_python
echo Creating virtual environment (first run)...
%PY% -m venv "%HERE%.venv"
if errorlevel 1 goto :err

:check_pkgs
"%VPY%" -c "import PySide6, serial" >nul 2>&1
if not errorlevel 1 goto :run
echo Installing packages (PySide6, pyserial)...
"%VPY%" -m pip install --disable-pip-version-check -r "%HERE%requirements.txt"
if errorlevel 1 goto :err

:run
if defined CONSOLE goto :run_console
if not exist "%VPYW%" goto :run_console
if defined ARG (
    start "" "%VPYW%" "%HERE%usb_sniffer_gui.py" "%ARG%"
) else (
    start "" "%VPYW%" "%HERE%usb_sniffer_gui.py"
)
exit /b 0

:run_console
if defined ARG (
    "%VPY%" "%HERE%usb_sniffer_gui.py" "%ARG%"
) else (
    "%VPY%" "%HERE%usb_sniffer_gui.py"
)
if errorlevel 1 pause
exit /b %errorlevel%

:no_python
echo Python was not found. Install Python 3.9+ from https://www.python.org
echo (tick "Add python.exe to PATH" during setup) and run this file again.
pause
exit /b 1

:old_python
echo Python 3.9 or newer is required. Found:
%PY% --version
echo Install a newer Python from https://www.python.org and run this file again.
pause
exit /b 1

:err
echo.
echo Setup failed. Check the internet connection / Python installation and retry.
echo To start from scratch, delete the folder "%HERE%.venv".
pause
exit /b 1
