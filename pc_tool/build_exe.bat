@echo off
setlocal
rem ==========================================================================
rem  Build the stand-alone Pico USB Sniffer program (see build_exe.py)
rem    build_exe.bat                 zip package + single exe into ..\dist
rem    build_exe.bat --mode exe      single exe only
rem    build_exe.bat --mode zip      zip package only
rem    build_exe.bat --help          all options
rem ==========================================================================

set "PY="
where py >nul 2>&1 && py -3 -c "import sys" >nul 2>&1 && set "PY=py -3"
if not defined PY python -c "import sys" >nul 2>&1 && set "PY=python"
if not defined PY goto :no_python

%PY% "%~dp0build_exe.py" %*
set "RC=%errorlevel%"
rem started without options (double click): keep the window open
if "%~1"=="" pause
exit /b %RC%

:no_python
echo Python was not found. Install Python 3.10+ from https://www.python.org
echo (tick "Add python.exe to PATH" during setup) and run this file again.
pause
exit /b 1
