#!/usr/bin/env python3
"""
Test de Backdoors Locales - SimplifyWFB
Script para probar solo los backdoors locales accesibles
"""

import json
import socket
import time
import sys
import os

def test_port_open(host, port, timeout=2):
    """Probar si un puerto está abierto"""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        result = sock.connect_ex((host, port))
        sock.close()
        return result == 0
    except:
        return False

def test_http_access(host, port, username, password):
    """Probar acceso HTTP básico"""
    try:
        import urllib.request
        import base64
        
        auth_string = f"{username}:{password}"
        auth_bytes = auth_string.encode('ascii')
        auth_b64 = base64.b64encode(auth_bytes).decode('ascii')
        
        url = f"http://{host}:{port}/"
        req = urllib.request.Request(url)
        req.add_header('Authorization', f'Basic {auth_b64}')
        req.add_header('User-Agent', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36')
        
        with urllib.request.urlopen(req, timeout=3) as response:
            return response.status == 200
            
    except:
        return False

def main():
    """Función principal"""
    print("🏠 SimplifyWFB - Test de Backdoors Locales")
    print("=" * 50)
    
    # Cargar reporte
    try:
        with open('report.json', 'r', encoding='utf-8') as f:
            report_data = json.load(f)
        print("✅ Reporte cargado: report.json")
    except Exception as e:
        print(f"❌ Error cargando reporte: {e}")
        return
    
    # Contadores
    total_tested = 0
    successful = 0
    failed = 0
    
    print("\n🔍 PROBANDO BACKDOORS LOCALES")
    print("=" * 50)
    
    # 1. Probar acceso al router
    print("\n🌐 ROUTER (192.168.1.1)")
    print("-" * 30)
    
    router_access = report_data.get('phase_4_persistence', {}).get('router_access', [])
    for router in router_access:
        gateway = router['gateway']
        credentials = router['credentials']
        
        print(f"🔍 Probando router: {gateway}")
        print(f"   Credenciales: {credentials['username']}:{credentials['password']}")
        
        total_tested += 1
        
        # Probar puerto 80
        if test_port_open(gateway, 80):
            print(f"   ✅ Puerto 80 abierto")
            
            # Probar acceso HTTP
            if test_http_access(gateway, 80, credentials['username'], credentials['password']):
                print(f"   ✅ Acceso HTTP exitoso")
                print(f"   🔗 URL: http://{gateway}:80/")
                successful += 1
            else:
                print(f"   ❌ Acceso HTTP falló")
                failed += 1
        else:
            print(f"   ❌ Puerto 80 cerrado")
            failed += 1
    
    # 2. Probar acceso a cámaras
    print("\n📹 CÁMARAS")
    print("-" * 30)
    
    cameras_accessed = report_data.get('phase_4_persistence', {}).get('cameras_accessed', [])
    for camera in cameras_accessed:
        host = camera['host']
        port = camera['port']
        credentials = camera['credentials']
        camera_type = camera['camera_type']
        
        print(f"🔍 Probando cámara: {camera_type} en {host}:{port}")
        print(f"   Credenciales: {credentials['username']}:{credentials['password']}")
        
        total_tested += 1
        
        # Probar puerto
        if test_port_open(host, port):
            print(f"   ✅ Puerto {port} abierto")
            
            # Probar acceso HTTP
            if test_http_access(host, port, credentials['username'], credentials['password']):
                print(f"   ✅ Acceso a cámara exitoso")
                print(f"   🔗 URL: http://{host}:{port}/")
                successful += 1
            else:
                print(f"   ❌ Acceso a cámara falló")
                failed += 1
        else:
            print(f"   ❌ Puerto {port} cerrado")
            failed += 1
    
    # 3. Probar servicios encontrados en el reconocimiento
    print("\n🔍 SERVICIOS ENCONTRADOS")
    print("-" * 30)
    
    services_found = report_data.get('phase_1_reconnaissance', {}).get('services_found', [])
    for service in services_found:
        host = service['host']
        port = service['port']
        service_name = service['service']
        
        print(f"🔍 Probando servicio: {service_name} en {host}:{port}")
        
        total_tested += 1
        
        if test_port_open(host, port):
            print(f"   ✅ Puerto {port} abierto")
            print(f"   🔗 Servicio: {service_name}")
            successful += 1
        else:
            print(f"   ❌ Puerto {port} cerrado")
            failed += 1
    
    # 4. Probar credenciales encontradas
    print("\n🔐 CREDENCIALES ENCONTRADAS")
    print("-" * 30)
    
    credentials_found = report_data.get('phase_2_credentials', {}).get('credentials_found', [])
    for cred in credentials_found:
        host = cred['host']
        port = cred['port']
        service = cred['service']
        username = cred['username']
        password = cred['password']
        
        print(f"🔍 Probando credenciales: {username}:{password} en {host}:{port} ({service})")
        
        total_tested += 1
        
        if test_port_open(host, port):
            print(f"   ✅ Puerto {port} abierto")
            
            if service == 'http':
                if test_http_access(host, port, username, password):
                    print(f"   ✅ Acceso HTTP exitoso")
                    print(f"   🔗 URL: http://{host}:{port}/")
                    successful += 1
                else:
                    print(f"   ❌ Acceso HTTP falló")
                    failed += 1
            else:
                print(f"   🔗 Servicio: {service}")
                successful += 1
        else:
            print(f"   ❌ Puerto {port} cerrado")
            failed += 1
    
    # Mostrar resumen
    print("\n" + "=" * 50)
    print("📊 RESUMEN DE PRUEBAS")
    print("=" * 50)
    print(f"🔍 Total probado: {total_tested}")
    print(f"✅ Exitosos: {successful}")
    print(f"❌ Fallidos: {failed}")
    
    if total_tested > 0:
        success_rate = (successful / total_tested) * 100
        print(f"📈 Tasa de éxito: {success_rate:.1f}%")
    
    # Mostrar comandos de acceso
    print(f"\n🔧 COMANDOS DE ACCESO DISPONIBLES:")
    print("-" * 40)
    
    # Router
    for router in router_access:
        gateway = router['gateway']
        credentials = router['credentials']
        if test_port_open(gateway, 80):
            print(f"🌐 Router: http://{credentials['username']}:{credentials['password']}@{gateway}:80/")
    
    # Cameras
    for camera in cameras_accessed:
        host = camera['host']
        port = camera['port']
        credentials = camera['credentials']
        if test_port_open(host, port):
            print(f"📹 Cámara: http://{credentials['username']}:{credentials['password']}@{host}:{port}/")
    
    # Servicios
    for service in services_found:
        host = service['host']
        port = service['port']
        service_name = service['service']
        if test_port_open(host, port):
            if service_name == 'ssh':
                print(f"🔐 SSH: ssh {host} -p {port}")
            elif service_name == 'ftp':
                print(f"📁 FTP: ftp {host} {port}")
            elif service_name == 'telnet':
                print(f"📞 Telnet: telnet {host} {port}")
            elif service_name == 'mysql':
                print(f"🗄️ MySQL: mysql -h {host} -P {port}")
            else:
                print(f"🔗 {service_name}: {host}:{port}")

if __name__ == "__main__":
    main()
