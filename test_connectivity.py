#!/usr/bin/env python3
"""
Script de diagnóstico de conectividad para SimplifyWFB
Prueba la conectividad al servidor remoto y verifica credenciales
"""

import socket
import json
import sys
import os

def test_ssh_connectivity():
    """Probar conectividad SSH al servidor"""
    print("🔍 DIAGNÓSTICO DE CONECTIVIDAD SSH")
    print("=" * 50)
    
    # Cargar configuración
    try:
        with open('config.json', 'r') as f:
            config = json.load(f)
        
        ssh_config = config['ssh_upload']
        host = ssh_config['host']
        port = ssh_config['port']
        username = ssh_config['username']
        password = ssh_config['password']
        
        print(f"📍 Servidor: {host}:{port}")
        print(f"👤 Usuario: {username}")
        print(f"🔑 Contraseña: {'*' * len(password)}")
        print()
        
    except Exception as e:
        print(f"❌ Error cargando configuración: {e}")
        return False
    
    # 1. Probar conectividad básica
    print("1️⃣ Probando conectividad básica...")
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(10)
        result = sock.connect_ex((host, port))
        sock.close()
        
        if result == 0:
            print(f"✅ Puerto {port} está abierto en {host}")
        else:
            print(f"❌ Puerto {port} está cerrado o no accesible en {host}")
            return False
            
    except Exception as e:
        print(f"❌ Error de conectividad: {e}")
        return False
    
    # 2. Probar SSH con paramiko
    print("\n2️⃣ Probando conexión SSH...")
    try:
        import paramiko
        
        ssh = paramiko.SSHClient()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        
        print("   🔐 Intentando autenticación...")
        ssh.connect(host, port=port, username=username, password=password, timeout=10)
        
        print("   ✅ Conexión SSH exitosa")
        
        # Probar comando básico
        stdin, stdout, stderr = ssh.exec_command('whoami')
        user = stdout.read().decode().strip()
        print(f"   👤 Usuario conectado: {user}")
        
        # Probar creación de directorio
        stdin, stdout, stderr = ssh.exec_command('mkdir -p /reports')
        exit_status = stdout.channel.recv_exit_status()
        
        if exit_status == 0:
            print("   ✅ Directorio /reports creado/verificado")
        else:
            print("   ⚠️ Error creando directorio /reports")
        
        ssh.close()
        return True
        
    except ImportError:
        print("   ❌ Módulo 'paramiko' no instalado")
        print("   💡 Instalar con: pip install paramiko")
        return False
    except Exception as e:
        print(f"   ❌ Error SSH: {e}")
        return False

def test_http_connectivity():
    """Probar conectividad HTTP al servidor"""
    print("\n🌐 DIAGNÓSTICO DE CONECTIVIDAD HTTP")
    print("=" * 50)
    
    try:
        with open('config.json', 'r') as f:
            config = json.load(f)
        
        ssh_config = config['ssh_upload']
        host = ssh_config['host']
        
        print(f"📍 Servidor: {host}")
        print()
        
    except Exception as e:
        print(f"❌ Error cargando configuración: {e}")
        return False
    
    # Probar HTTP
    print("1️⃣ Probando conectividad HTTP...")
    try:
        import urllib.request
        
        # Probar puerto 80
        url = f"http://{host}/"
        req = urllib.request.Request(url)
        req.add_header('User-Agent', 'SimplifyWFB/1.0')
        
        with urllib.request.urlopen(req, timeout=10) as response:
            print(f"✅ HTTP accesible en puerto 80 (Status: {response.status})")
            return True
            
    except Exception as e:
        print(f"❌ HTTP no accesible: {e}")
        return False

def main():
    """Función principal"""
    print("🔧 SimplifyWFB - Diagnóstico de Conectividad")
    print("=" * 60)
    
    # Verificar que existe config.json
    if not os.path.exists('config.json'):
        print("❌ Archivo config.json no encontrado")
        print("💡 Asegúrate de estar en el directorio correcto")
        return
    
    # Probar SSH
    ssh_ok = test_ssh_connectivity()
    
    # Probar HTTP
    http_ok = test_http_connectivity()
    
    # Resumen
    print("\n📊 RESUMEN")
    print("=" * 30)
    print(f"SSH: {'✅ OK' if ssh_ok else '❌ FALLO'}")
    print(f"HTTP: {'✅ OK' if http_ok else '❌ FALLO'}")
    
    if ssh_ok:
        print("\n🎯 El servidor está configurado correctamente para SSH")
    elif http_ok:
        print("\n⚠️ SSH falla pero HTTP funciona (método alternativo)")
    else:
        print("\n❌ El servidor no está accesible")
        print("💡 Verifica:")
        print("   • IP y puerto correctos")
        print("   • Servidor encendido")
        print("   • Firewall configurado")
        print("   • Credenciales correctas")

if __name__ == "__main__":
    main()
