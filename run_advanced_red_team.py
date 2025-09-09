#!/usr/bin/env python3
"""
Run Advanced Red Team Tool - Ejecutor del Advanced Red Team Tool
Script de inicialización que verifica dependencias y ejecuta la herramienta
"""

import sys
import os
import subprocess
from pathlib import Path

def check_dependencies():
    """Verifica que las dependencias estén instaladas"""
    print("🔍 Verificando dependencias...")
    
    try:
        # Ejecutar verificador de dependencias
        result = subprocess.run([
            sys.executable, 'tools/dependency_checker.py'
        ], capture_output=True, text=True, timeout=60)
        
        if result.returncode == 0:
            print("✅ Dependencias verificadas correctamente")
            return True
        else:
            print("❌ Faltan dependencias")
            print(result.stdout)
            return False
            
    except subprocess.TimeoutExpired:
        print("⏰ Timeout verificando dependencias")
        return False
    except Exception as e:
        print(f"❌ Error verificando dependencias: {e}")
        return False

def install_dependencies():
    """Instala dependencias faltantes"""
    print("📦 Instalando dependencias...")
    
    try:
        # Instalar paquetes Python
        result = subprocess.run([
            sys.executable, '-m', 'pip', 'install', '-r', 'requirements.txt'
        ], capture_output=True, text=True, timeout=300)
        
        if result.returncode == 0:
            print("✅ Dependencias Python instaladas")
            return True
        else:
            print(f"❌ Error instalando dependencias: {result.stderr}")
            return False
            
    except subprocess.TimeoutExpired:
        print("⏰ Timeout instalando dependencias")
        return False
    except Exception as e:
        print(f"❌ Error: {e}")
        return False

def main():
    """Función principal"""
    print("🔥 ADVANCED RED TEAM TOOL v2.0 - INICIALIZADOR 🔥")
    print("=" * 60)
    
    # Verificar que estamos en el directorio correcto
    required_files = [
        'simplifywfb.py',
        'config.json',
        'requirements.txt',
        'tools/dependency_checker.py'
    ]
    
    missing_files = []
    for file in required_files:
        if not Path(file).exists():
            missing_files.append(file)
    
    if missing_files:
        print(f"❌ Archivos faltantes: {', '.join(missing_files)}")
        print("💡 Asegúrate de estar en el directorio correcto")
        sys.exit(1)
    
    # Verificar dependencias
    if not check_dependencies():
        print("\n❓ ¿Desea instalar las dependencias automáticamente? (y/n): ", end="")
        choice = input().strip().lower()
        
        if choice in ['y', 'yes', 'sí', 'si']:
            if not install_dependencies():
                print("❌ No se pudieron instalar las dependencias")
                print("💡 Instala manualmente con: pip install -r requirements.txt")
                sys.exit(1)
        else:
            print("❌ Dependencias requeridas no instaladas")
            print("💡 Instala manualmente con: pip install -r requirements.txt")
            sys.exit(1)
    
    # Ejecutar script principal
    print("\n🚀 Iniciando Advanced Red Team Tool...")
    print("=" * 60)
    
    try:
        # Importar y ejecutar el script principal
        import simplifywfb
        
        # Ejecutar función main
        simplifywfb.main()
        
    except KeyboardInterrupt:
        print("\n⚠️ Operación interrumpida por el usuario")
        sys.exit(1)
    except Exception as e:
        print(f"\n❌ Error ejecutando la herramienta: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()
