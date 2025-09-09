#!/usr/bin/env python3
"""
Network Analyzer - Analizador de Red Real
Implementa análisis real de red, rutas y topología
"""

import subprocess
import socket
import struct
import time
import json
import re
from typing import Dict, List, Any, Optional, Tuple
import logging
from datetime import datetime
import ipaddress
import platform

class NetworkAnalyzer:
    """Analizador real de red y topología"""
    
    def __init__(self):
        self.logger = logging.getLogger('NetworkAnalyzer')
        self.system = platform.system().lower()
        
    def get_local_ip(self) -> str:
        """Obtiene la IP local real"""
        try:
            # Conectar a un servidor externo para obtener IP local
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            local_ip = s.getsockname()[0]
            s.close()
            return local_ip
        except:
            return "127.0.0.1"
    
    def get_network_interfaces(self) -> List[Dict[str, Any]]:
        """Obtiene interfaces de red reales"""
        interfaces = []
        
        try:
            if self.system == 'linux':
                interfaces = self._get_linux_interfaces()
            elif self.system == 'windows':
                interfaces = self._get_windows_interfaces()
            else:
                interfaces = self._get_generic_interfaces()
                
        except Exception as e:
            self.logger.error(f"Error obteniendo interfaces: {e}")
        
        return interfaces
    
    def _get_linux_interfaces(self) -> List[Dict[str, Any]]:
        """Obtiene interfaces de Linux"""
        interfaces = []
        
        try:
            # Usar ip command
            result = subprocess.run(['ip', 'addr', 'show'], capture_output=True, text=True, timeout=10)
            if result.returncode == 0:
                interfaces = self._parse_ip_addr_output(result.stdout)
            else:
                # Fallback a ifconfig
                result = subprocess.run(['ifconfig'], capture_output=True, text=True, timeout=10)
                if result.returncode == 0:
                    interfaces = self._parse_ifconfig_output(result.stdout)
                    
        except Exception as e:
            self.logger.error(f"Error obteniendo interfaces Linux: {e}")
        
        return interfaces
    
    def _get_windows_interfaces(self) -> List[Dict[str, Any]]:
        """Obtiene interfaces de Windows"""
        interfaces = []
        
        try:
            # Usar ipconfig
            result = subprocess.run(['ipconfig', '/all'], capture_output=True, text=True, timeout=10)
            if result.returncode == 0:
                interfaces = self._parse_ipconfig_output(result.stdout)
                
        except Exception as e:
            self.logger.error(f"Error obteniendo interfaces Windows: {e}")
        
        return interfaces
    
    def _get_generic_interfaces(self) -> List[Dict[str, Any]]:
        """Obtiene interfaces de forma genérica"""
        interfaces = []
        
        try:
            import netifaces
            
            for interface in netifaces.interfaces():
                addrs = netifaces.ifaddresses(interface)
                
                interface_info = {
                    'name': interface,
                    'type': 'unknown',
                    'status': 'unknown',
                    'ip_addresses': [],
                    'mac_address': None,
                    'mtu': None
                }
                
                # IPv4 addresses
                if netifaces.AF_INET in addrs:
                    for addr in addrs[netifaces.AF_INET]:
                        interface_info['ip_addresses'].append({
                            'ip': addr['addr'],
                            'netmask': addr['netmask'],
                            'broadcast': addr.get('broadcast', '')
                        })
                
                # MAC address
                if netifaces.AF_LINK in addrs:
                    interface_info['mac_address'] = addrs[netifaces.AF_LINK][0]['addr']
                
                interfaces.append(interface_info)
                
        except ImportError:
            self.logger.warning("netifaces no disponible, usando método alternativo")
        except Exception as e:
            self.logger.error(f"Error obteniendo interfaces genéricas: {e}")
        
        return interfaces
    
    def _parse_ip_addr_output(self, output: str) -> List[Dict[str, Any]]:
        """Parsea salida de ip addr show"""
        interfaces = []
        current_interface = None
        
        for line in output.split('\n'):
            line = line.strip()
            
            # Nueva interfaz
            if line.startswith(('1:', '2:', '3:', '4:', '5:', '6:', '7:', '8:', '9:')):
                if current_interface:
                    interfaces.append(current_interface)
                
                parts = line.split(':')
                if len(parts) >= 3:
                    current_interface = {
                        'name': parts[1].strip(),
                        'type': 'unknown',
                        'status': 'up' if 'UP' in line else 'down',
                        'ip_addresses': [],
                        'mac_address': None,
                        'mtu': None
                    }
            
            # Dirección IP
            elif line.startswith('inet ') and current_interface:
                ip_match = re.search(r'inet\s+([0-9.]+)/([0-9]+)', line)
                if ip_match:
                    ip = ip_match.group(1)
                    prefix_len = int(ip_match.group(2))
                    netmask = self._prefix_to_netmask(prefix_len)
                    
                    current_interface['ip_addresses'].append({
                        'ip': ip,
                        'netmask': netmask,
                        'prefix_length': prefix_len
                    })
            
            # Dirección MAC
            elif line.startswith('link/ether ') and current_interface:
                mac_match = re.search(r'link/ether\s+([0-9a-f:]{17})', line)
                if mac_match:
                    current_interface['mac_address'] = mac_match.group(1)
            
            # MTU
            elif 'mtu' in line and current_interface:
                mtu_match = re.search(r'mtu\s+([0-9]+)', line)
                if mtu_match:
                    current_interface['mtu'] = int(mtu_match.group(1))
        
        if current_interface:
            interfaces.append(current_interface)
        
        return interfaces
    
    def _parse_ifconfig_output(self, output: str) -> List[Dict[str, Any]]:
        """Parsea salida de ifconfig"""
        interfaces = []
        current_interface = None
        
        for line in output.split('\n'):
            line = line.strip()
            
            # Nueva interfaz
            if line and not line.startswith(' ') and ':' in line:
                if current_interface:
                    interfaces.append(current_interface)
                
                interface_name = line.split(':')[0]
                current_interface = {
                    'name': interface_name,
                    'type': 'unknown',
                    'status': 'up' if 'UP' in line else 'down',
                    'ip_addresses': [],
                    'mac_address': None,
                    'mtu': None
                }
            
            # Dirección IP
            elif 'inet ' in line and current_interface:
                ip_match = re.search(r'inet\s+([0-9.]+)\s+netmask\s+([0-9.]+)', line)
                if ip_match:
                    ip = ip_match.group(1)
                    netmask = ip_match.group(2)
                    
                    current_interface['ip_addresses'].append({
                        'ip': ip,
                        'netmask': netmask
                    })
            
            # Dirección MAC
            elif 'ether ' in line and current_interface:
                mac_match = re.search(r'ether\s+([0-9a-f:]{17})', line)
                if mac_match:
                    current_interface['mac_address'] = mac_match.group(1)
            
            # MTU
            elif 'mtu ' in line and current_interface:
                mtu_match = re.search(r'mtu\s+([0-9]+)', line)
                if mtu_match:
                    current_interface['mtu'] = int(mtu_match.group(1))
        
        if current_interface:
            interfaces.append(current_interface)
        
        return interfaces
    
    def _parse_ipconfig_output(self, output: str) -> List[Dict[str, Any]]:
        """Parsea salida de ipconfig /all"""
        interfaces = []
        current_interface = None
        
        for line in output.split('\n'):
            line = line.strip()
            
            # Nueva interfaz
            if line.startswith('Ethernet adapter ') or line.startswith('Wireless LAN adapter '):
                if current_interface:
                    interfaces.append(current_interface)
                
                interface_name = line.split(':')[0].replace('Ethernet adapter ', '').replace('Wireless LAN adapter ', '')
                current_interface = {
                    'name': interface_name,
                    'type': 'ethernet' if 'Ethernet' in line else 'wireless',
                    'status': 'unknown',
                    'ip_addresses': [],
                    'mac_address': None,
                    'mtu': None
                }
            
            # Dirección IP
            elif 'IPv4 Address' in line and current_interface:
                ip_match = re.search(r'IPv4 Address[^:]*:\s*([0-9.]+)', line)
                if ip_match:
                    ip = ip_match.group(1)
                    
                    # Buscar subnet mask
                    netmask = '255.255.255.0'  # Default
                    
                    current_interface['ip_addresses'].append({
                        'ip': ip,
                        'netmask': netmask
                    })
            
            # Dirección MAC
            elif 'Physical Address' in line and current_interface:
                mac_match = re.search(r'Physical Address[^:]*:\s*([0-9A-F-]{17})', line)
                if mac_match:
                    current_interface['mac_address'] = mac_match.group(1).replace('-', ':')
        
        if current_interface:
            interfaces.append(current_interface)
        
        return interfaces
    
    def _prefix_to_netmask(self, prefix_len: int) -> str:
        """Convierte prefix length a netmask"""
        mask = (0xffffffff >> (32 - prefix_len)) << (32 - prefix_len)
        return socket.inet_ntoa(struct.pack('>I', mask))
    
    def get_routing_table(self) -> List[Dict[str, Any]]:
        """Obtiene tabla de rutas real"""
        routes = []
        
        try:
            if self.system == 'linux':
                routes = self._get_linux_routes()
            elif self.system == 'windows':
                routes = self._get_windows_routes()
            else:
                routes = self._get_generic_routes()
                
        except Exception as e:
            self.logger.error(f"Error obteniendo tabla de rutas: {e}")
        
        return routes
    
    def _get_linux_routes(self) -> List[Dict[str, Any]]:
        """Obtiene rutas de Linux"""
        routes = []
        
        try:
            # Usar ip route
            result = subprocess.run(['ip', 'route', 'show'], capture_output=True, text=True, timeout=10)
            if result.returncode == 0:
                routes = self._parse_ip_route_output(result.stdout)
            else:
                # Fallback a route
                result = subprocess.run(['route', '-n'], capture_output=True, text=True, timeout=10)
                if result.returncode == 0:
                    routes = self._parse_route_output(result.stdout)
                    
        except Exception as e:
            self.logger.error(f"Error obteniendo rutas Linux: {e}")
        
        return routes
    
    def _get_windows_routes(self) -> List[Dict[str, Any]]:
        """Obtiene rutas de Windows"""
        routes = []
        
        try:
            result = subprocess.run(['route', 'print'], capture_output=True, text=True, timeout=10)
            if result.returncode == 0:
                routes = self._parse_route_print_output(result.stdout)
                
        except Exception as e:
            self.logger.error(f"Error obteniendo rutas Windows: {e}")
        
        return routes
    
    def _get_generic_routes(self) -> List[Dict[str, Any]]:
        """Obtiene rutas de forma genérica"""
        routes = []
        
        try:
            import netifaces
            
            # Ruta por defecto
            default_gateway = netifaces.gateways()['default']
            if netifaces.AF_INET in default_gateway:
                gateway_info = default_gateway[netifaces.AF_INET]
                routes.append({
                    'destination': '0.0.0.0/0',
                    'gateway': gateway_info[0],
                    'interface': gateway_info[1],
                    'metric': 0,
                    'type': 'default'
                })
            
            # Rutas de interfaz
            for interface in netifaces.interfaces():
                addrs = netifaces.ifaddresses(interface)
                if netifaces.AF_INET in addrs:
                    for addr in addrs[netifaces.AF_INET]:
                        ip = addr['addr']
                        netmask = addr['netmask']
                        network = ipaddress.IPv4Network(f"{ip}/{netmask}", strict=False)
                        
                        routes.append({
                            'destination': str(network),
                            'gateway': '0.0.0.0',
                            'interface': interface,
                            'metric': 0,
                            'type': 'local'
                        })
                        
        except ImportError:
            self.logger.warning("netifaces no disponible para rutas genéricas")
        except Exception as e:
            self.logger.error(f"Error obteniendo rutas genéricas: {e}")
        
        return routes
    
    def _parse_ip_route_output(self, output: str) -> List[Dict[str, Any]]:
        """Parsea salida de ip route show"""
        routes = []
        
        for line in output.split('\n'):
            line = line.strip()
            if not line:
                continue
            
            route = {
                'destination': '0.0.0.0/0',
                'gateway': '0.0.0.0',
                'interface': 'unknown',
                'metric': 0,
                'type': 'unknown'
            }
            
            parts = line.split()
            
            # Ruta por defecto
            if parts[0] == 'default':
                route['type'] = 'default'
                if len(parts) >= 3:
                    route['gateway'] = parts[2]
                if len(parts) >= 5:
                    route['interface'] = parts[4]
            else:
                # Ruta específica
                route['destination'] = parts[0]
                if len(parts) >= 3:
                    route['gateway'] = parts[2]
                if len(parts) >= 5:
                    route['interface'] = parts[4]
            
            routes.append(route)
        
        return routes
    
    def _parse_route_output(self, output: str) -> List[Dict[str, Any]]:
        """Parsea salida de route -n"""
        routes = []
        lines = output.split('\n')
        
        # Saltar encabezados
        for line in lines[2:]:
            line = line.strip()
            if not line:
                continue
            
            parts = line.split()
            if len(parts) >= 8:
                route = {
                    'destination': parts[0],
                    'gateway': parts[1],
                    'interface': parts[7],
                    'metric': int(parts[6]) if parts[6].isdigit() else 0,
                    'type': 'default' if parts[0] == '0.0.0.0' else 'specific'
                }
                routes.append(route)
        
        return routes
    
    def _parse_route_print_output(self, output: str) -> List[Dict[str, Any]]:
        """Parsea salida de route print"""
        routes = []
        lines = output.split('\n')
        
        # Buscar tabla de rutas IPv4
        in_ipv4_table = False
        for line in lines:
            line = line.strip()
            
            if 'IPv4 Route Table' in line:
                in_ipv4_table = True
                continue
            
            if in_ipv4_table and line.startswith('='):
                break
            
            if in_ipv4_table and line and not line.startswith('='):
                parts = line.split()
                if len(parts) >= 5:
                    route = {
                        'destination': parts[0],
                        'gateway': parts[2],
                        'interface': parts[3],
                        'metric': int(parts[4]) if parts[4].isdigit() else 0,
                        'type': 'default' if parts[0] == '0.0.0.0' else 'specific'
                    }
                    routes.append(route)
        
        return routes
    
    def get_network_topology(self) -> Dict[str, Any]:
        """Obtiene topología de red real"""
        topology = {
            'local_ip': self.get_local_ip(),
            'interfaces': self.get_network_interfaces(),
            'routes': self.get_routing_table(),
            'gateway': self._find_default_gateway(),
            'dns_servers': self._get_dns_servers(),
            'timestamp': datetime.now().isoformat()
        }
        
        return topology
    
    def _find_default_gateway(self) -> Optional[str]:
        """Encuentra el gateway por defecto"""
        routes = self.get_routing_table()
        
        for route in routes:
            if route.get('type') == 'default':
                return route.get('gateway')
        
        return None
    
    def _get_dns_servers(self) -> List[str]:
        """Obtiene servidores DNS"""
        dns_servers = []
        
        try:
            if self.system == 'linux':
                # Leer /etc/resolv.conf
                with open('/etc/resolv.conf', 'r') as f:
                    for line in f:
                        if line.startswith('nameserver'):
                            dns_server = line.split()[1]
                            dns_servers.append(dns_server)
            
            elif self.system == 'windows':
                # Usar nslookup
                result = subprocess.run(['nslookup', 'google.com'], capture_output=True, text=True, timeout=10)
                if result.returncode == 0:
                    lines = result.stdout.split('\n')
                    for line in lines:
                        if 'Server:' in line:
                            dns_server = line.split(':')[1].strip()
                            dns_servers.append(dns_server)
                            break
                            
        except Exception as e:
            self.logger.error(f"Error obteniendo servidores DNS: {e}")
        
        return dns_servers
    
    def discover_network_hosts(self, network: str, timeout: int = 1) -> List[Dict[str, Any]]:
        """Descubre hosts en la red usando ping real"""
        hosts = []
        
        try:
            network_obj = ipaddress.IPv4Network(network, strict=False)
            
            # Ping a cada IP en la red
            for ip in network_obj.hosts():
                if self._ping_host(str(ip), timeout):
                    host_info = {
                        'ip': str(ip),
                        'status': 'up',
                        'response_time': self._get_ping_time(str(ip), timeout),
                        'hostname': self._get_hostname(str(ip))
                    }
                    hosts.append(host_info)
                    
        except Exception as e:
            self.logger.error(f"Error descubriendo hosts: {e}")
        
        return hosts
    
    def _ping_host(self, ip: str, timeout: int) -> bool:
        """Hace ping real a un host"""
        try:
            if self.system == 'linux':
                result = subprocess.run(['ping', '-c', '1', '-W', str(timeout), ip], 
                                      capture_output=True, timeout=timeout+2)
                return result.returncode == 0
            elif self.system == 'windows':
                result = subprocess.run(['ping', '-n', '1', '-w', str(timeout*1000), ip], 
                                      capture_output=True, timeout=timeout+2)
                return result.returncode == 0
            else:
                # Ping genérico usando socket
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(timeout)
                result = sock.connect_ex((ip, 80))
                sock.close()
                return result == 0
                
        except Exception:
            return False
    
    def _get_ping_time(self, ip: str, timeout: int) -> float:
        """Obtiene tiempo de respuesta del ping"""
        try:
            if self.system == 'linux':
                result = subprocess.run(['ping', '-c', '1', '-W', str(timeout), ip], 
                                      capture_output=True, text=True, timeout=timeout+2)
                if result.returncode == 0:
                    # Extraer tiempo de respuesta
                    time_match = re.search(r'time=([0-9.]+)', result.stdout)
                    if time_match:
                        return float(time_match.group(1))
            elif self.system == 'windows':
                result = subprocess.run(['ping', '-n', '1', '-w', str(timeout*1000), ip], 
                                      capture_output=True, text=True, timeout=timeout+2)
                if result.returncode == 0:
                    # Extraer tiempo de respuesta
                    time_match = re.search(r'time[<=]([0-9]+)ms', result.stdout)
                    if time_match:
                        return float(time_match.group(1))
                        
        except Exception:
            pass
        
        return 0.0
    
    def _get_hostname(self, ip: str) -> str:
        """Obtiene hostname de una IP"""
        try:
            hostname = socket.gethostbyaddr(ip)[0]
            return hostname
        except:
            return ip