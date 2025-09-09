#!/usr/bin/env python3
"""
Instalador de dependencias para el tester de backdoors
"""

import subprocess
import sys
import os

def install_package(package):
    """Instalar paquete Python"""
    try:
        subprocess.check_call([sys.executable, "-m", "pip", "install", package])
        print(f"✅ {package} instalado correctamente")
        return True
    except subprocess.CalledProcessError:
        print(f"❌ Error instalando {package}")
        return False

def check_command(command):
    """Verificar si un comando está disponible"""
    try:
        subprocess.run([command, "--version"], capture_output=True, check=True)
        print(f"✅ {command} está disponible")
        return True
    except (subprocess.CalledProcessError, FileNotFoundError):
        print(f"❌ {command} no está disponible")
        return False

def main():
    """Función principal"""
    print("🔧 SimplifyWFB - Instalador de Dependencias para Tester de Backdoors")
    print("=" * 70)
    
    # Dependencias Python opcionales
    python_packages = [
        "pymongo",  # Para MongoDB
        "redis",    # Para Redis
    ]
    
    # Comandos del sistema requeridos
    system_commands = [
        "ssh",      # Para pruebas SSH
    ]
    
    print("\n📦 INSTALANDO DEPENDENCIAS PYTHON OPCIONALES")
    print("-" * 50)
    
    for package in python_packages:
        print(f"🔍 Verificando {package}...")
        try:
            __import__(package)
            print(f"✅ {package} ya está instalado")
        except ImportError:
            print(f"📥 Instalando {package}...")
            install_package(package)
    
    print("\n🔧 VERIFICANDO COMANDOS DEL SISTEMA")
    print("-" * 50)
    
    for command in system_commands:
        check_command(command)
    
    print("\n📋 RESUMEN")
    print("-" * 30)
    print("✅ Dependencias básicas: urllib, socket, subprocess (incluidas en Python)")
    print("✅ Dependencias opcionales: pymongo, redis (instaladas si es posible)")
    print("✅ Comando SSH: Requerido para pruebas SSH")
    
    print("\n🎯 USO DE LOS SCRIPTS:")
    print("-" * 30)
    print("1. Prueba completa: python test_backdoors.py")
    print("2. Prueba rápida: python quick_backdoor_test.py ssh 192.168.1.1 22 admin admin")
    print("3. Solo puerto: python quick_backdoor_test.py port 192.168.1.1 22")
    
    print("\n📄 NOTAS:")
    print("-" * 30)
    print("• El script test_backdoors.py lee automáticamente report.json")
    print("• Puedes especificar otro archivo: python test_backdoors.py mi_reporte.json")
    print("• Las pruebas SSH requieren que el comando 'ssh' esté disponible")
    print("• Las pruebas HTTP funcionan con urllib (incluido en Python)")

if __name__ == "__main__":
    main()
