#!/usr/bin/env python3
"""
Test Installation - Prueba de Instalación
Script de prueba para verificar que la instalación sea correcta
"""

import sys
import os
import subprocess
from pathlib import Path

def test_basic_imports():
    """Prueba imports básicos"""
    print("🔍 Probando imports básicos...")
    
    try:
        import json
        import time
        import threading
        import os
        import tempfile
        import sys
        import base64
        import socket
        import ipaddress
        from datetime import datetime
        from pathlib import Path
        import re
        
        print("   ✅ Imports básicos OK")
        return True
    except ImportError as e:
        print(f"   ❌ Error en imports básicos: {e}")
        return False

def test_optional_imports():
    """Prueba imports opcionales"""
    print("🔍 Probando imports opcionales...")
    
    optional_imports = [
        ('paramiko', 'SSH connections'),
        ('requests', 'HTTP requests'),
        ('psutil', 'System information'),
        ('cryptography', 'Encryption'),
        ('scapy', 'Packet manipulation'),
        ('netaddr', 'IP address manipulation'),
        ('nmap', 'Network scanning'),
        ('netifaces', 'Network interfaces')
    ]
    
    success_count = 0
    
    for module, description in optional_imports:
        try:
            __import__(module)
            print(f"   ✅ {module} - {description}")
            success_count += 1
        except ImportError:
            print(f"   ⚠️ {module} - {description} (no instalado)")
    
    print(f"   📊 {success_count}/{len(optional_imports)} módulos opcionales disponibles")
    return success_count > 0

def test_system_tools():
    """Prueba herramientas del sistema"""
    print("🔍 Probando herramientas del sistema...")
    
    system_tools = [
        ('nmap', 'Network scanner'),
        ('python3', 'Python interpreter'),
        ('git', 'Version control'),
        ('curl', 'HTTP client')
    ]
    
    success_count = 0
    
    for tool, description in system_tools:
        if shutil.which(tool):
            print(f"   ✅ {tool} - {description}")
            success_count += 1
        else:
            print(f"   ⚠️ {tool} - {description} (no encontrado)")
    
    print(f"   📊 {success_count}/{len(system_tools)} herramientas del sistema disponibles")
    return success_count > 0

def test_main_script():
    """Prueba el script principal"""
    print("🔍 Probando script principal...")
    
    try:
        # Intentar importar el script principal
        import simplifywfb
        
        # Verificar que la clase existe
        if hasattr(simplifywfb, 'SimplifyWFB'):
            print("   ✅ Clase SimplifyWFB encontrada")
        else:
            print("   ❌ Clase SimplifyWFB no encontrada")
            return False
        
        # Verificar que los métodos principales existen
        required_methods = [
            'run_full_scan',
            'run_cold_pentest',
            '_create_camera_backdoor',
            '_test_credential'
        ]
        
        missing_methods = []
        for method in required_methods:
            if hasattr(simplifywfb.SimplifyWFB, method):
                print(f"   ✅ Método {method} encontrado")
            else:
                print(f"   ❌ Método {method} no encontrado")
                missing_methods.append(method)
        
        if missing_methods:
            print(f"   ❌ Métodos faltantes: {', '.join(missing_methods)}")
            return False
        
        print("   ✅ Script principal OK")
        return True
        
    except ImportError as e:
        print(f"   ❌ Error importando script principal: {e}")
        return False
    except Exception as e:
        print(f"   ❌ Error inesperado: {e}")
        return False

def test_config_file():
    """Prueba el archivo de configuración"""
    print("🔍 Probando archivo de configuración...")
    
    try:
        if not Path('config.json').exists():
            print("   ❌ Archivo config.json no encontrado")
            return False
        
        import json
        with open('config.json', 'r') as f:
            config = json.load(f)
        
        # Verificar secciones principales
        required_sections = [
            'remote_access',
            'ssh_upload',
            'c2_config',
            'stealth',
            'persistence',
            'privilege_escalation',
            'ssh_tunneling',
            'log_cleanup',
            'credentials'
        ]
        
        missing_sections = []
        for section in required_sections:
            if section in config:
                print(f"   ✅ Sección {section} encontrada")
            else:
                print(f"   ❌ Sección {section} no encontrada")
                missing_sections.append(section)
        
        if missing_sections:
            print(f"   ❌ Secciones faltantes: {', '.join(missing_sections)}")
            return False
        
        print("   ✅ Archivo de configuración OK")
        return True
        
    except json.JSONDecodeError as e:
        print(f"   ❌ Error parseando config.json: {e}")
        return False
    except Exception as e:
        print(f"   ❌ Error inesperado: {e}")
        return False

def test_tools_modules():
    """Prueba los módulos de herramientas"""
    print("🔍 Probando módulos de herramientas...")
    
    tools_modules = [
        'tools.tplink_exploiter',
        'tools.credential_sniffer',
        'tools.network_analyzer'
    ]
    
    success_count = 0
    
    for module in tools_modules:
        try:
            __import__(module)
            print(f"   ✅ {module} importado correctamente")
            success_count += 1
        except ImportError as e:
            print(f"   ⚠️ {module} - Error: {e}")
    
    print(f"   📊 {success_count}/{len(tools_modules)} módulos de herramientas disponibles")
    return success_count > 0

def main():
    """Función principal"""
    print("🧪 PRUEBA DE INSTALACIÓN - ADVANCED RED TEAM TOOL v2.0 🧪")
    print("=" * 70)
    
    # Importar shutil para verificar herramientas del sistema
    import shutil
    
    tests = [
        ("Imports Básicos", test_basic_imports),
        ("Imports Opcionales", test_optional_imports),
        ("Herramientas del Sistema", test_system_tools),
        ("Script Principal", test_main_script),
        ("Archivo de Configuración", test_config_file),
        ("Módulos de Herramientas", test_tools_modules)
    ]
    
    results = []
    
    for test_name, test_func in tests:
        print(f"\n📋 {test_name}:")
        try:
            result = test_func()
            results.append((test_name, result))
        except Exception as e:
            print(f"   ❌ Error ejecutando prueba: {e}")
            results.append((test_name, False))
    
    # Mostrar resumen
    print("\n" + "=" * 70)
    print("📊 RESUMEN DE PRUEBAS")
    print("=" * 70)
    
    passed = 0
    total = len(results)
    
    for test_name, result in results:
        status = "✅ PASÓ" if result else "❌ FALLÓ"
        print(f"   {test_name}: {status}")
        if result:
            passed += 1
    
    print(f"\n🎯 Resultado: {passed}/{total} pruebas pasaron")
    
    if passed == total:
        print("\n🎉 ¡TODAS LAS PRUEBAS PASARON!")
        print("🚀 El Advanced Red Team Tool está listo para usar")
        print("📖 Ejecuta: python3 run_advanced_red_team.py")
    elif passed >= total * 0.8:
        print("\n⚠️ La mayoría de las pruebas pasaron")
        print("💡 Algunas funcionalidades opcionales pueden no estar disponibles")
        print("📖 Ejecuta: python3 run_advanced_red_team.py")
    else:
        print("\n❌ Varias pruebas fallaron")
        print("💡 Ejecuta: python3 tools/install_complete.py")
        print("📖 O instala manualmente las dependencias faltantes")
    
    print("=" * 70)

if __name__ == "__main__":
    main()