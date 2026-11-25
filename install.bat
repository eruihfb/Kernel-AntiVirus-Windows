@echo off
TITLE Kernel-AntiVirus Installer
echo [1/3] Creating virtual environment in %%USERPROFILE%%/.kernel_av/venv...
python -m venv %USERPROFILE%\.kernel_av\venv

echo [2/3] Installing dependencies (psutil, requests)...
call %USERPROFILE%\.kernel_av\venv\Scripts\activate
python -m pip install --upgrade pip
pip install psutil requests

echo [3/3] Installation complete!
echo You can now run your antivirus scripts using the virtual environment python.
pause
