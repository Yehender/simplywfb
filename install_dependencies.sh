#!/bin/bash

# SimplifyWFB - Script de Instalación de Dependencias
# Instala todas las dependencias necesarias para el funcionamiento del script

echo "🔧 SimplifyWFB - Instalación de Dependencias"
echo "=" * 50

# Detectar el sistema operativo
if [ -f /etc/debian_version ]; then
    echo "📦 Detectado sistema Debian/Ubuntu/Kali"
    
    # Actualizar repositorios
    echo "🔄 Actualizando repositorios..."
    sudo apt update
    
    # Instalar herramientas del sistema
    echo "📦 Instalando herramientas del sistema..."
    sudo apt install -y \
        nmap \
        hydra \
        netcat-openbsd \
        openssh-client \
        smbclient \
        openssl \
        ssh-keygen \
        openvpn \
        nginx \
        ffmpeg \
        curl \
        wget
    
    echo "✅ Herramientas del sistema instaladas"
    
elif [ -f /etc/redhat-release ]; then
    echo "📦 Detectado sistema RedHat/CentOS/Fedora"
    
    # Instalar herramientas del sistema
    echo "📦 Instalando herramientas del sistema..."
    sudo yum install -y \
        nmap \
        hydra \
        nc \
        openssh-clients \
        samba-client \
        openssl \
        openvpn \
        nginx \
        ffmpeg \
        curl \
        wget
    
    echo "✅ Herramientas del sistema instaladas"
    
else
    echo "⚠️ Sistema operativo no reconocido"
    echo "💡 Instala manualmente: nmap, hydra, netcat, openssh, smbclient, ffmpeg"
fi

# Instalar dependencias de Python
echo "🐍 Instalando dependencias de Python..."
pip3 install -r requirements.txt

# Verificar instalación
echo "🔍 Verificando instalación..."

# Verificar Python
if command -v python3 &> /dev/null; then
    echo "✅ Python3 instalado"
else
    echo "❌ Python3 no encontrado"
fi

# Verificar paramiko
python3 -c "import paramiko; print('✅ Paramiko instalado')" 2>/dev/null || echo "❌ Paramiko no instalado"

# Verificar nmap
if command -v nmap &> /dev/null; then
    echo "✅ Nmap instalado"
else
    echo "❌ Nmap no encontrado"
fi

# Verificar hydra
if command -v hydra &> /dev/null; then
    echo "✅ Hydra instalado"
else
    echo "❌ Hydra no encontrado"
fi

# Verificar netcat
if command -v nc &> /dev/null; then
    echo "✅ Netcat instalado"
else
    echo "❌ Netcat no encontrado"
fi

# Verificar ffmpeg
if command -v ffmpeg &> /dev/null; then
    echo "✅ FFmpeg instalado"
else
    echo "❌ FFmpeg no encontrado"
fi

echo ""
echo "🎯 Instalación completada"
echo "💡 Ejecuta: python3 simplifywfb.py"
echo ""
echo "⚠️ ADVERTENCIA: Este script ejecuta ataques REALES"
echo "⚠️ Solo use en sistemas que posea o tenga autorización explícita"
