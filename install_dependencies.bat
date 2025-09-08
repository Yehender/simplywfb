@echo off
REM SimplifyWFB - Script de Instalación de Dependencias para Windows
REM Instala todas las dependencias necesarias para el funcionamiento del script

echo 🔧 SimplifyWFB - Instalación de Dependencias
echo ==================================================

REM Verificar si Python está instalado
python --version >nul 2>&1
if %errorlevel% neq 0 (
    echo ❌ Python no encontrado. Instala Python desde https://python.org
    pause
    exit /b 1
)

echo ✅ Python encontrado

REM Verificar si pip está instalado
pip --version >nul 2>&1
if %errorlevel% neq 0 (
    echo ❌ Pip no encontrado. Instala pip
    pause
    exit /b 1
)

echo ✅ Pip encontrado

REM Instalar dependencias de Python
echo 🐍 Instalando dependencias de Python...
pip install -r requirements.txt

REM Verificar instalación de paramiko
python -c "import paramiko; print('✅ Paramiko instalado')" 2>nul
if %errorlevel% neq 0 (
    echo ❌ Error instalando paramiko
    echo 💡 Intenta: pip install paramiko
)

REM Verificar instalación de netifaces
python -c "import netifaces; print('✅ Netifaces instalado')" 2>nul
if %errorlevel% neq 0 (
    echo ❌ Error instalando netifaces
    echo 💡 Intenta: pip install netifaces
)

echo.
echo 🎯 Instalación completada
echo 💡 Ejecuta: python simplifywfb.py
echo.
echo ⚠️ ADVERTENCIA: Este script ejecuta ataques REALES
echo ⚠️ Solo use en sistemas que posea o tenga autorización explícita
echo.
echo 📝 NOTA: En Windows necesitarás instalar manualmente:
echo    - Nmap (desde https://nmap.org)
echo    - Hydra (desde https://github.com/vanhauser-thc/thc-hydra)
echo    - Netcat (desde https://eternallybored.org/misc/netcat/)
echo    - FFmpeg (desde https://ffmpeg.org)
echo.
pause
