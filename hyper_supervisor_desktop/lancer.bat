@echo off
cd /d "%~dp0"
if not exist venv (
  echo Premiere installation, patientez...
  python -m venv venv
  call venv\Scripts\activate.bat
  python -m pip install --upgrade pip
  pip install -r requirements.txt
) else (
  call venv\Scripts\activate.bat
)
python main.py
if errorlevel 1 pause
