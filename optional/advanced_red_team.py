#!/usr/bin/env python3
"""
Advanced Red Team Tool - Herramienta Avanzada de Red Teaming
Implementa TTPs realistas de atacantes persistentes y sigilosos
"""

import subprocess
import json
import time
import threading
import os
import tempfile
import sys
import random
import base64
import hashlib
import socket
import ipaddress
from typing import Dict, List, Any, Optional, Tuple
from pathlib import Path
import re
from datetime import datetime, timedelta
import logging
import shutil
import platform
import psutil
import requests
from urllib.parse import urlparse
import dns.resolver
import dns.query
import dns.message

class AdvancedRedTeam:
    """Herramienta avanzada de red teaming con TTPs realistas"""
    
    def __init__(self):
        self.start_time = time.time()
        self.config_data = self._load_config()
        self.session_id = self._generate_session_id()
        self.logger = self._setup_logging()
        
        # Configuración de sigilo
        self.stealth_config = self.config_data.get('stealth', {})
        self.obfuscated_names = self.stealth_config.get('obfuscated_names', {})
        self.hidden_dirs = self.stealth_config.get('hidden_directories', [])
        
        # Configuración C2
        self.c2_config = self.config_data.get('c2_config', {})
        self.meterpreter_config = self.c2_config.get('meterpreter', {})
        
        # Configuración de persistencia
        self.persistence_config = self.config_data.get('persistence', {})
        
        # Configuración de escalada de privilegios
        self.priv_esc_config = self.config_data.get('privilege_escalation', {})
        
        # Configuración SSH tunneling
        self.ssh_tunnel_config = self.config_data.get('ssh_tunneling', {})
        
        # Configuración de limpieza de logs
        self.log_cleanup_config = self.config_data.get('log_cleanup', {})
        
        self.report = self._initialize_report()
        
    def _load_config(self) -> Dict:
        """Carga la configuración desde config.json"""
        try:
            with open('config.json', 'r', encoding='utf-8') as f:
                return json.load(f)
        except FileNotFoundError:
            self.logger.error("Archivo config.json no encontrado")
            sys.exit(1)
        except json.JSONDecodeError as e:
            self.logger.error(f"Error al parsear config.json: {e}")
            sys.exit(1)
    
    def _generate_session_id(self) -> str:
        """Genera un ID de sesión único y ofuscado"""
        timestamp = str(int(time.time()))
        random_part = ''.join(random.choices('abcdefghijklmnopqrstuvwxyz0123456789', k=8))
        return hashlib.md5(f"{timestamp}{random_part}".encode()).hexdigest()[:12]
    
    def _setup_logging(self) -> logging.Logger:
        """Configura logging sigiloso"""
        logger = logging.getLogger('AdvancedRedTeam')
        logger.setLevel(logging.DEBUG)
        
        # Crear directorio de logs oculto
        log_dir = Path('/tmp/.X11-unix') if platform.system() == 'Linux' else Path('C:\\Windows\\Temp\\')
        log_dir.mkdir(exist_ok=True)
        
        # Archivo de log con nombre ofuscado
        log_file = log_dir / 'systemd-resolver.log'
        
        handler = logging.FileHandler(log_file)
        formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
        handler.setFormatter(formatter)
        logger.addHandler(handler)
        
        return logger
    
    def _initialize_report(self) -> Dict:
        """Inicializa el reporte con estructura avanzada"""
        return {
            'metadata': {
                'script_name': 'AdvancedRedTeam',
                'version': '2.0.0',
                'session_id': self.session_id,
                'start_time': datetime.now().isoformat(),
                'mode': 'advanced_red_team',
                'target_network': None,
                'local_ip': self._get_local_ip(),
                'external_ip': self.config_data['remote_access']['external_ip'],
                'external_port': self.config_data['remote_access']['external_port'],
                'stealth_mode': True,
                'meterpreter_enabled': self.meterpreter_config.get('enabled', False)
            },
            'phase_1_reconnaissance': {
                'status': 'pending',
                'stealth_scan_performed': False,
                'hosts_discovered': [],
                'services_found': [],
                'technologies_detected': [],
                'network_topology': {},
                'evasion_techniques_used': [],
                'errors': []
            },
            'phase_2_privilege_escalation': {
                'status': 'pending',
                'tools_used': [],
                'vulnerabilities_found': [],
                'privileges_escalated': [],
                'exploits_attempted': [],
                'errors': []
            },
            'phase_3_credential_harvesting': {
                'status': 'pending',
                'credentials_found': [],
                'attack_methods_used': [],
                'password_hashes': [],
                'tokens_stolen': [],
                'errors': []
            },
            'phase_4_lateral_movement': {
                'status': 'pending',
                'compromised_systems': [],
                'access_methods': [],
                'lateral_connections': [],
                'pivoting_established': [],
                'errors': []
            },
            'phase_5_persistence': {
                'status': 'pending',
                'persistent_access': [],
                'backdoors_created': [],
                'users_created': [],
                'services_installed': [],
                'registry_modifications': [],
                'cron_jobs_created': [],
                'ssh_keys_installed': [],
                'wmi_subscriptions': [],
                'errors': []
            },
            'phase_6_c2_establishment': {
                'status': 'pending',
                'meterpreter_sessions': [],
                'dns_tunnels': [],
                'domain_fronting': [],
                'ssh_tunnels': [],
                'jitter_configured': False,
                'errors': []
            },
            'phase_7_network_persistence': {
                'status': 'pending',
                'router_access': [],
                'port_forwarding': [],
                'vpn_configuration': [],
                'network_modifications': [],
                'errors': []
            },
            'phase_8_verification': {
                'status': 'pending',
                'persistence_checks': [],
                'access_verification': [],
                'c2_connectivity': [],
                'errors': []
            },
            'cleanup': {
                'status': 'pending',
                'logs_cleaned': [],
                'artifacts_removed': [],
                'traces_obfuscated': [],
                'errors': []
            },
            'summary': {
                'total_hosts': 0,
                'compromised_hosts': 0,
                'persistent_access_points': 0,
                'total_credentials': 0,
                'meterpreter_sessions': 0,
                'execution_time': 0,
                'success_rate': 0.0,
                'stealth_score': 0.0
            }
        }
    
    def _get_local_ip(self) -> str:
        """Obtiene la IP local de forma sigilosa"""
        try:
            # Conectar a un servidor externo para obtener IP local
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            local_ip = s.getsockname()[0]
            s.close()
            return local_ip
        except:
            return "127.0.0.1"
    
    def stealth_network_scan(self, target_network: str) -> Dict:
        """Realiza escaneo de red con técnicas de evasión"""
        self.logger.info(f"Iniciando escaneo sigiloso de {target_network}")
        
        scan_results = {
            'hosts': [],
            'services': [],
            'evasion_techniques': [],
            'scan_duration': 0
        }
        
        start_time = time.time()
        
        try:
            # Configuración de evasión
            evasion_config = self.stealth_config.get('scan_evasion', {})
            nmap_options = evasion_config.get('nmap_options', '-sS -T2 --scan-delay 1-3')
            decoy_ips = evasion_config.get('decoy_ips', 'RND:10')
            
            # Construir comando nmap con evasión
            cmd = [
                'nmap',
                *nmap_options.split(),
                '--randomize-hosts',
                f'-D {decoy_ips}',
                '--data-length 25',
                '--ttl 64',
                '--spoof-mac 0',
                target_network
            ]
            
            self.logger.info(f"Ejecutando comando sigiloso: {' '.join(cmd)}")
            
            # Ejecutar escaneo con timeout
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=300  # 5 minutos máximo
            )
            
            if result.returncode == 0:
                scan_results['hosts'] = self._parse_nmap_output(result.stdout)
                scan_results['evasion_techniques'] = [
                    'SYN Scan',
                    'Timing Template T2',
                    'Random Host Ordering',
                    'Decoy IPs',
                    'MAC Address Spoofing',
                    'Packet Fragmentation'
                ]
                
                self.logger.info(f"Escaneo completado. {len(scan_results['hosts'])} hosts encontrados")
            else:
                self.logger.error(f"Error en escaneo: {result.stderr}")
                
        except subprocess.TimeoutExpired:
            self.logger.warning("Escaneo timeout - continuando con hosts conocidos")
        except Exception as e:
            self.logger.error(f"Error en escaneo sigiloso: {e}")
        
        scan_results['scan_duration'] = time.time() - start_time
        return scan_results
    
    def _parse_nmap_output(self, output: str) -> List[Dict]:
        """Parsea la salida de nmap para extraer hosts y servicios"""
        hosts = []
        current_host = None
        
        for line in output.split('\n'):
            line = line.strip()
            
            # Detectar nuevo host
            if line.startswith('Nmap scan report for'):
                if current_host:
                    hosts.append(current_host)
                
                # Extraer IP y hostname
                parts = line.split()
                ip = parts[-1].strip('()')
                hostname = parts[4] if len(parts) > 4 else None
                
                current_host = {
                    'ip': ip,
                    'hostname': hostname,
                    'services': [],
                    'os': None,
                    'open_ports': []
                }
            
            # Detectar puertos abiertos
            elif line and '/' in line and 'open' in line:
                if current_host:
                    port_info = line.split()
                    if len(port_info) >= 3:
                        port = port_info[0]
                        state = port_info[1]
                        service = port_info[2] if len(port_info) > 2 else 'unknown'
                        
                        current_host['open_ports'].append({
                            'port': port,
                            'state': state,
                            'service': service
                        })
            
            # Detectar OS
            elif 'OS details:' in line or 'Running:' in line:
                if current_host:
                    current_host['os'] = line.split(':', 1)[1].strip()
        
        if current_host:
            hosts.append(current_host)
        
        return hosts
    
    def privilege_escalation_scan(self, target_ip: str) -> Dict:
        """Realiza escaneo de escalada de privilegios"""
        self.logger.info(f"Iniciando escaneo de escalada de privilegios en {target_ip}")
        
        priv_esc_results = {
            'tools_used': [],
            'vulnerabilities_found': [],
            'exploits_available': [],
            'privileges_escalated': False
        }
        
        try:
            # Determinar sistema operativo
            os_type = self._detect_os_type(target_ip)
            
            if os_type == 'linux':
                priv_esc_results = self._linux_privilege_escalation(target_ip)
            elif os_type == 'windows':
                priv_esc_results = self._windows_privilege_escalation(target_ip)
            else:
                self.logger.warning(f"Sistema operativo no identificado para {target_ip}")
                
        except Exception as e:
            self.logger.error(f"Error en escalada de privilegios: {e}")
            priv_esc_results['errors'] = [str(e)]
        
        return priv_esc_results
    
    def _detect_os_type(self, target_ip: str) -> str:
        """Detecta el tipo de sistema operativo"""
        try:
            # Usar nmap para detectar OS
            cmd = ['nmap', '-O', '--osscan-guess', target_ip]
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
            
            if 'Windows' in result.stdout:
                return 'windows'
            elif 'Linux' in result.stdout:
                return 'linux'
            else:
                return 'unknown'
        except:
            return 'unknown'
    
    def _linux_privilege_escalation(self, target_ip: str) -> Dict:
        """Escalada de privilegios en Linux"""
        results = {
            'tools_used': [],
            'vulnerabilities_found': [],
            'exploits_available': [],
            'privileges_escalated': False
        }
        
        # Herramientas de escalada de privilegios para Linux
        linux_tools = self.priv_esc_config.get('linux_tools', [])
        
        for tool in linux_tools:
            try:
                if tool == 'linpeas.sh':
                    results['tools_used'].append('LinPEAS')
                    # Simular ejecución de LinPEAS
                    vulns = self._simulate_linpeas_scan(target_ip)
                    results['vulnerabilities_found'].extend(vulns)
                    
                elif tool == 'linux-exploit-suggester.sh':
                    results['tools_used'].append('Linux Exploit Suggester')
                    exploits = self._simulate_exploit_suggester(target_ip)
                    results['exploits_available'].extend(exploits)
                    
            except Exception as e:
                self.logger.error(f"Error ejecutando {tool}: {e}")
        
        return results
    
    def _windows_privilege_escalation(self, target_ip: str) -> Dict:
        """Escalada de privilegios en Windows"""
        results = {
            'tools_used': [],
            'vulnerabilities_found': [],
            'exploits_available': [],
            'privileges_escalated': False
        }
        
        # Herramientas de escalada de privilegios para Windows
        windows_tools = self.priv_esc_config.get('windows_tools', [])
        
        for tool in windows_tools:
            try:
                if tool == 'winpeas.exe':
                    results['tools_used'].append('WinPEAS')
                    vulns = self._simulate_winpeas_scan(target_ip)
                    results['vulnerabilities_found'].extend(vulns)
                    
                elif tool == 'powerup.ps1':
                    results['tools_used'].append('PowerUp')
                    vulns = self._simulate_powerup_scan(target_ip)
                    results['vulnerabilities_found'].extend(vulns)
                    
            except Exception as e:
                self.logger.error(f"Error ejecutando {tool}: {e}")
        
        return results
    
    def _simulate_linpeas_scan(self, target_ip: str) -> List[Dict]:
        """Simula escaneo de LinPEAS"""
        # Simular vulnerabilidades comunes encontradas por LinPEAS
        vulnerabilities = [
            {
                'type': 'SUID Binary',
                'description': 'find binary with SUID bit set',
                'severity': 'medium',
                'exploit': 'CVE-2021-4034'
            },
            {
                'type': 'Writable Directory',
                'description': '/tmp directory is world-writable',
                'severity': 'low',
                'exploit': 'Path traversal'
            },
            {
                'type': 'Weak Permissions',
                'description': 'Configuration files with weak permissions',
                'severity': 'medium',
                'exploit': 'Configuration manipulation'
            }
        ]
        
        return vulnerabilities
    
    def _simulate_winpeas_scan(self, target_ip: str) -> List[Dict]:
        """Simula escaneo de WinPEAS"""
        vulnerabilities = [
            {
                'type': 'Unquoted Service Path',
                'description': 'Service with unquoted path vulnerability',
                'severity': 'high',
                'exploit': 'Service path manipulation'
            },
            {
                'type': 'Weak Registry Permissions',
                'description': 'Registry keys with weak permissions',
                'severity': 'medium',
                'exploit': 'Registry manipulation'
            },
            {
                'type': 'AlwaysInstallElevated',
                'description': 'AlwaysInstallElevated policy enabled',
                'severity': 'high',
                'exploit': 'MSI package installation'
            }
        ]
        
        return vulnerabilities
    
    def _simulate_exploit_suggester(self, target_ip: str) -> List[Dict]:
        """Simula Linux Exploit Suggester"""
        exploits = [
            {
                'cve': 'CVE-2021-4034',
                'description': 'PwnKit - Local Privilege Escalation',
                'severity': 'critical',
                'affected_versions': 'All versions of pkexec'
            },
            {
                'cve': 'CVE-2021-3156',
                'description': 'Sudo Heap-based Buffer Overflow',
                'severity': 'critical',
                'affected_versions': 'Sudo 1.8.2 - 1.8.31p2'
            }
        ]
        
        return exploits
    
    def _simulate_powerup_scan(self, target_ip: str) -> List[Dict]:
        """Simula escaneo de PowerUp"""
        vulnerabilities = [
            {
                'type': 'Unquoted Service Path',
                'service': 'VulnerableService',
                'path': 'C:\\Program Files\\Vulnerable Service\\service.exe',
                'severity': 'high'
            },
            {
                'type': 'Weak Service Permissions',
                'service': 'AnotherService',
                'permissions': 'FullControl for Everyone',
                'severity': 'high'
            }
        ]
        
        return vulnerabilities
