#!/usr/bin/env python3
"""
Main Advanced Red Team Script - Script Principal de Red Teaming Avanzado
Integra todos los módulos para crear una herramienta completa de red teaming
"""

import sys
import json
import time
import argparse
import logging
from datetime import datetime
from pathlib import Path

# Importar módulos personalizados
from advanced_red_team import AdvancedRedTeam
from meterpreter_c2 import MeterpreterC2
from advanced_persistence import AdvancedPersistence
from ssh_tunneling import SSHTunneling
from log_cleanup import LogCleanup

class MainAdvancedRedTeam:
    """Clase principal que coordina todas las operaciones de red teaming"""
    
    def __init__(self):
        self.config = self._load_config()
        self.logger = self._setup_logging()
        
        # Inicializar módulos
        self.red_team = AdvancedRedTeam()
        self.meterpreter_c2 = MeterpreterC2(self.config)
        self.persistence = AdvancedPersistence(self.config)
        self.ssh_tunneling = SSHTunneling(self.config)
        self.log_cleanup = LogCleanup(self.config)
        
        self.session_id = self.red_team.session_id
        self.report = self.red_team.report
        
    def _load_config(self) -> dict:
        """Carga configuración desde config.json"""
        try:
            with open('config.json', 'r', encoding='utf-8') as f:
                return json.load(f)
        except FileNotFoundError:
            print("❌ Error: Archivo config.json no encontrado")
            sys.exit(1)
        except json.JSONDecodeError as e:
            print(f"❌ Error al parsear config.json: {e}")
            sys.exit(1)
    
    def _setup_logging(self) -> logging.Logger:
        """Configura logging para la sesión"""
        logger = logging.getLogger('MainAdvancedRedTeam')
        logger.setLevel(logging.INFO)
        
        # Crear directorio de logs
        log_dir = Path('/tmp/.X11-unix') if sys.platform == 'linux' else Path('C:\\Windows\\Temp\\')
        log_dir.mkdir(exist_ok=True)
        
        # Archivo de log
        log_file = log_dir / f'redteam_session_{int(time.time())}.log'
        
        handler = logging.FileHandler(log_file)
        formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
        handler.setFormatter(formatter)
        logger.addHandler(handler)
        
        return logger
    
    def run_advanced_red_team(self, target_network: str, mode: str = 'full') -> dict:
        """Ejecuta operación completa de red teaming avanzado"""
        self.logger.info(f"Iniciando red teaming avanzado en {target_network} (modo: {mode})")
        
        print(f"""
🔥 ADVANCED RED TEAM TOOL v2.0 🔥
=====================================
🎯 Target: {target_network}
🆔 Session ID: {self.session_id}
🕐 Started: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
=====================================
        """)
        
        try:
            # Fase 1: Reconocimiento Sigiloso
            print("🔍 Fase 1: Reconocimiento Sigiloso...")
            reconnaissance_results = self._phase_1_reconnaissance(target_network)
            
            # Fase 2: Escalada de Privilegios
            print("⚡ Fase 2: Escalada de Privilegios...")
            privilege_escalation_results = self._phase_2_privilege_escalation(reconnaissance_results)
            
            # Fase 3: Harvesting de Credenciales
            print("🔑 Fase 3: Harvesting de Credenciales...")
            credential_results = self._phase_3_credential_harvesting(privilege_escalation_results)
            
            # Fase 4: Movimiento Lateral
            print("🔄 Fase 4: Movimiento Lateral...")
            lateral_movement_results = self._phase_4_lateral_movement(credential_results)
            
            # Fase 5: Persistencia Avanzada
            print("🔒 Fase 5: Persistencia Avanzada...")
            persistence_results = self._phase_5_persistence(lateral_movement_results)
            
            # Fase 6: Establecimiento de C2
            print("📡 Fase 6: Establecimiento de C2...")
            c2_results = self._phase_6_c2_establishment(persistence_results)
            
            # Fase 7: Persistencia de Red
            print("🌐 Fase 7: Persistencia de Red...")
            network_persistence_results = self._phase_7_network_persistence(c2_results)
            
            # Fase 8: Verificación
            print("✅ Fase 8: Verificación...")
            verification_results = self._phase_8_verification(network_persistence_results)
            
            # Limpieza Final
            print("🧹 Limpieza Final...")
            cleanup_results = self._final_cleanup(verification_results)
            
            # Generar reporte final
            final_report = self._generate_final_report()
            
            print(f"""
🎉 OPERACIÓN COMPLETADA 🎉
========================
✅ Hosts Comprometidos: {final_report['summary']['compromised_hosts']}
🔒 Puntos de Persistencia: {final_report['summary']['persistent_access_points']}
📡 Sesiones C2: {final_report['summary']['meterpreter_sessions']}
🕐 Tiempo Total: {final_report['summary']['execution_time']:.2f} segundos
🎯 Tasa de Éxito: {final_report['summary']['success_rate']:.1f}%
🕵️ Puntuación de Sigilo: {final_report['summary']['stealth_score']:.1f}%
========================
            """)
            
            return final_report
            
        except Exception as e:
            self.logger.error(f"Error en operación de red teaming: {e}")
            print(f"❌ Error: {e}")
            return None
    
    def _phase_1_reconnaissance(self, target_network: str) -> dict:
        """Fase 1: Reconocimiento sigiloso"""
        self.logger.info("Iniciando Fase 1: Reconocimiento Sigiloso")
        
        # Actualizar reporte
        self.report['phase_1_reconnaissance']['status'] = 'in_progress'
        
        try:
            # Escaneo sigiloso de red
            scan_results = self.red_team.stealth_network_scan(target_network)
            
            # Actualizar reporte
            self.report['phase_1_reconnaissance'].update({
                'status': 'completed',
                'stealth_scan_performed': True,
                'hosts_discovered': scan_results['hosts'],
                'evasion_techniques_used': scan_results['evasion_techniques']
            })
            
            print(f"   ✅ Escaneo sigiloso completado: {len(scan_results['hosts'])} hosts encontrados")
            print(f"   🥷 Técnicas de evasión: {', '.join(scan_results['evasion_techniques'])}")
            
            return {
                'target_network': target_network,
                'discovered_hosts': scan_results['hosts'],
                'scan_duration': scan_results['scan_duration']
            }
            
        except Exception as e:
            self.logger.error(f"Error en Fase 1: {e}")
            self.report['phase_1_reconnaissance']['status'] = 'failed'
            self.report['phase_1_reconnaissance']['errors'].append(str(e))
            raise
    
    def _phase_2_privilege_escalation(self, reconnaissance_results: dict) -> dict:
        """Fase 2: Escalada de privilegios"""
        self.logger.info("Iniciando Fase 2: Escalada de Privilegios")
        
        self.report['phase_2_privilege_escalation']['status'] = 'in_progress'
        
        try:
            privilege_results = []
            
            for host in reconnaissance_results['discovered_hosts']:
                target_ip = host['ip']
                target_os = self.red_team._detect_os_type(target_ip)
                
                # Escalada de privilegios
                priv_esc_results = self.red_team.privilege_escalation_scan(target_ip)
                
                privilege_results.append({
                    'target_ip': target_ip,
                    'target_os': target_os,
                    'privilege_escalation': priv_esc_results
                })
                
                print(f"   🔍 Escalada de privilegios en {target_ip} ({target_os})")
                print(f"      🛠️ Herramientas usadas: {', '.join(priv_esc_results.get('tools_used', []))}")
                print(f"      🐛 Vulnerabilidades: {len(priv_esc_results.get('vulnerabilities_found', []))}")
            
            # Actualizar reporte
            self.report['phase_2_privilege_escalation'].update({
                'status': 'completed',
                'tools_used': list(set([tool for result in privilege_results for tool in result['privilege_escalation'].get('tools_used', [])])),
                'vulnerabilities_found': [vuln for result in privilege_results for vuln in result['privilege_escalation'].get('vulnerabilities_found', [])]
            })
            
            return {
                'reconnaissance_results': reconnaissance_results,
                'privilege_escalation_results': privilege_results
            }
            
        except Exception as e:
            self.logger.error(f"Error en Fase 2: {e}")
            self.report['phase_2_privilege_escalation']['status'] = 'failed'
            self.report['phase_2_privilege_escalation']['errors'].append(str(e))
            raise
    
    def _phase_3_credential_harvesting(self, privilege_results: dict) -> dict:
        """Fase 3: Harvesting de credenciales"""
        self.logger.info("Iniciando Fase 3: Harvesting de Credenciales")
        
        self.report['phase_3_credential_harvesting']['status'] = 'in_progress'
        
        try:
            credential_results = []
            
            for result in privilege_results['privilege_escalation_results']:
                target_ip = result['target_ip']
                target_os = result['target_os']
                
                # Simular harvesting de credenciales
                credentials = self._simulate_credential_harvesting(target_ip, target_os)
                
                credential_results.append({
                    'target_ip': target_ip,
                    'target_os': target_os,
                    'credentials_found': credentials
                })
                
                print(f"   🔑 Credenciales encontradas en {target_ip}: {len(credentials)}")
            
            # Actualizar reporte
            self.report['phase_3_credential_harvesting'].update({
                'status': 'completed',
                'credentials_found': [cred for result in credential_results for cred in result['credentials_found']],
                'attack_methods_used': ['Password Spraying', 'Credential Dumping', 'Hash Cracking']
            })
            
            return {
                'privilege_results': privilege_results,
                'credential_results': credential_results
            }
            
        except Exception as e:
            self.logger.error(f"Error en Fase 3: {e}")
            self.report['phase_3_credential_harvesting']['status'] = 'failed'
            self.report['phase_3_credential_harvesting']['errors'].append(str(e))
            raise
    
    def _phase_4_lateral_movement(self, credential_results: dict) -> dict:
        """Fase 4: Movimiento lateral"""
        self.logger.info("Iniciando Fase 4: Movimiento Lateral")
        
        self.report['phase_4_lateral_movement']['status'] = 'in_progress'
        
        try:
            lateral_results = []
            compromised_systems = []
            
            for result in credential_results['credential_results']:
                target_ip = result['target_ip']
                target_os = result['target_os']
                credentials = result['credentials_found']
                
                if credentials:  # Si encontramos credenciales
                    # Simular movimiento lateral
                    lateral_access = self._simulate_lateral_movement(target_ip, target_os, credentials)
                    
                    lateral_results.append({
                        'target_ip': target_ip,
                        'target_os': target_os,
                        'lateral_access': lateral_access
                    })
                    
                    compromised_systems.append(target_ip)
                    print(f"   🔄 Movimiento lateral exitoso en {target_ip}")
            
            # Actualizar reporte
            self.report['phase_4_lateral_movement'].update({
                'status': 'completed',
                'compromised_systems': compromised_systems,
                'access_methods': ['SSH', 'RDP', 'SMB', 'WinRM']
            })
            
            return {
                'credential_results': credential_results,
                'lateral_movement_results': lateral_results,
                'compromised_systems': compromised_systems
            }
            
        except Exception as e:
            self.logger.error(f"Error en Fase 4: {e}")
            self.report['phase_4_lateral_movement']['status'] = 'failed'
            self.report['phase_4_lateral_movement']['errors'].append(str(e))
            raise
    
    def _phase_5_persistence(self, lateral_results: dict) -> dict:
        """Fase 5: Persistencia avanzada"""
        self.logger.info("Iniciando Fase 5: Persistencia Avanzada")
        
        self.report['phase_5_persistence']['status'] = 'in_progress'
        
        try:
            persistence_results = []
            
            for result in lateral_results['lateral_movement_results']:
                target_ip = result['target_ip']
                target_os = result['target_os']
                
                # Establecer persistencia
                persistence = self.persistence.establish_persistence(target_ip, target_os, 'lateral_movement')
                
                persistence_results.append({
                    'target_ip': target_ip,
                    'target_os': target_os,
                    'persistence': persistence
                })
                
                print(f"   🔒 Persistencia establecida en {target_ip}")
                print(f"      📋 Métodos: {', '.join(persistence.get('persistence_methods', []))}")
                print(f"      👤 Usuarios: {len(persistence.get('users_created', []))}")
                print(f"      ⚙️ Servicios: {len(persistence.get('services_installed', []))}")
            
            # Actualizar reporte
            self.report['phase_5_persistence'].update({
                'status': 'completed',
                'persistent_access': [result['persistence'] for result in persistence_results],
                'backdoors_created': [method for result in persistence_results for method in result['persistence'].get('persistence_methods', [])]
            })
            
            return {
                'lateral_results': lateral_results,
                'persistence_results': persistence_results
            }
            
        except Exception as e:
            self.logger.error(f"Error en Fase 5: {e}")
            self.report['phase_5_persistence']['status'] = 'failed'
            self.report['phase_5_persistence']['errors'].append(str(e))
            raise
    
    def _phase_6_c2_establishment(self, persistence_results: dict) -> dict:
        """Fase 6: Establecimiento de C2"""
        self.logger.info("Iniciando Fase 6: Establecimiento de C2")
        
        self.report['phase_6_c2_establishment']['status'] = 'in_progress'
        
        try:
            c2_results = []
            meterpreter_sessions = []
            
            for result in persistence_results['persistence_results']:
                target_ip = result['target_ip']
                target_os = result['target_os']
                
                # Establecer comunicación C2
                c2_communication = self.meterpreter_c2.establish_c2_communication(target_ip, target_os)
                
                c2_results.append({
                    'target_ip': target_ip,
                    'target_os': target_os,
                    'c2_communication': c2_communication
                })
                
                if c2_communication.get('meterpreter_session'):
                    meterpreter_sessions.append(target_ip)
                
                print(f"   📡 C2 establecido en {target_ip}")
                print(f"      🔗 Métodos: {', '.join(c2_communication.get('communication_methods', []))}")
                print(f"      🎭 Meterpreter: {'✅' if c2_communication.get('meterpreter_session') else '❌'}")
                print(f"      🌐 DNS Tunnel: {'✅' if c2_communication.get('dns_tunnel') else '❌'}")
                print(f"      🎯 Domain Fronting: {'✅' if c2_communication.get('domain_fronting') else '❌'}")
            
            # Actualizar reporte
            self.report['phase_6_c2_establishment'].update({
                'status': 'completed',
                'meterpreter_sessions': meterpreter_sessions,
                'dns_tunnels': [result for result in c2_results if result['c2_communication'].get('dns_tunnel')],
                'domain_fronting': [result for result in c2_results if result['c2_communication'].get('domain_fronting')]
            })
            
            return {
                'persistence_results': persistence_results,
                'c2_results': c2_results
            }
            
        except Exception as e:
            self.logger.error(f"Error en Fase 6: {e}")
            self.report['phase_6_c2_establishment']['status'] = 'failed'
            self.report['phase_6_c2_establishment']['errors'].append(str(e))
            raise
    
    def _phase_7_network_persistence(self, c2_results: dict) -> dict:
        """Fase 7: Persistencia de red"""
        self.logger.info("Iniciando Fase 7: Persistencia de Red")
        
        self.report['phase_7_network_persistence']['status'] = 'in_progress'
        
        try:
            network_results = []
            
            for result in c2_results['c2_results']:
                target_ip = result['target_ip']
                target_os = result['target_os']
                
                # Establecer túneles SSH
                ssh_tunnels = self.ssh_tunneling.create_persistent_ssh_connection(target_ip, target_os)
                
                network_results.append({
                    'target_ip': target_ip,
                    'target_os': target_os,
                    'ssh_tunnels': ssh_tunnels
                })
                
                print(f"   🌐 Túneles SSH establecidos en {target_ip}")
                print(f"      🔗 Conexiones: {len(ssh_tunnels.get('tunnels', []))}")
                print(f"      🔄 Keep-alive: {'✅' if ssh_tunnels.get('keep_alive_script') else '❌'}")
            
            # Configurar port forwarding en router (simulado)
            router_config = self.ssh_tunneling.setup_router_port_forwarding('192.168.1.1', {})
            
            # Actualizar reporte
            self.report['phase_7_network_persistence'].update({
                'status': 'completed',
                'router_access': [router_config] if router_config.get('configuration_successful') else [],
                'port_forwarding': router_config.get('port_forwarding_rules', []),
                'vpn_configuration': [router_config.get('vpn_configuration')] if router_config.get('vpn_configuration') else []
            })
            
            return {
                'c2_results': c2_results,
                'network_results': network_results,
                'router_config': router_config
            }
            
        except Exception as e:
            self.logger.error(f"Error en Fase 7: {e}")
            self.report['phase_7_network_persistence']['status'] = 'failed'
            self.report['phase_7_network_persistence']['errors'].append(str(e))
            raise
    
    def _phase_8_verification(self, network_results: dict) -> dict:
        """Fase 8: Verificación"""
        self.logger.info("Iniciando Fase 8: Verificación")
        
        self.report['phase_8_verification']['status'] = 'in_progress'
        
        try:
            verification_results = []
            
            for result in network_results['network_results']:
                target_ip = result['target_ip']
                target_os = result['target_os']
                
                # Verificar persistencia
                persistence_verification = self.persistence.verify_persistence(target_ip, target_os)
                
                # Verificar túneles SSH
                ssh_verification = []
                for tunnel in result['ssh_tunnels'].get('tunnels', []):
                    tunnel_verification = self.ssh_tunneling.verify_tunnel_connectivity(tunnel)
                    ssh_verification.append(tunnel_verification)
                
                verification_results.append({
                    'target_ip': target_ip,
                    'target_os': target_os,
                    'persistence_verification': persistence_verification,
                    'ssh_verification': ssh_verification
                })
                
                print(f"   ✅ Verificación completada en {target_ip}")
                print(f"      🔒 Persistencia: {persistence_verification.get('success_rate', 0):.1f}%")
                print(f"      🌐 Túneles SSH: {len([v for v in ssh_verification if v.get('connectivity_test')])}")
            
            # Actualizar reporte
            self.report['phase_8_verification'].update({
                'status': 'completed',
                'persistence_checks': [result['persistence_verification'] for result in verification_results],
                'access_verification': [result['ssh_verification'] for result in verification_results]
            })
            
            return {
                'network_results': network_results,
                'verification_results': verification_results
            }
            
        except Exception as e:
            self.logger.error(f"Error en Fase 8: {e}")
            self.report['phase_8_verification']['status'] = 'failed'
            self.report['phase_8_verification']['errors'].append(str(e))
            raise
    
    def _final_cleanup(self, verification_results: dict) -> dict:
        """Limpieza final"""
        self.logger.info("Iniciando Limpieza Final")
        
        self.report['cleanup']['status'] = 'in_progress'
        
        try:
            cleanup_results = []
            
            for result in verification_results['verification_results']:
                target_ip = result['target_ip']
                target_os = result['target_os']
                
                # Limpieza sigilosa
                cleanup = self.log_cleanup.perform_stealth_cleanup(target_ip, target_os)
                
                cleanup_results.append({
                    'target_ip': target_ip,
                    'target_os': target_os,
                    'cleanup': cleanup
                })
                
                print(f"   🧹 Limpieza completada en {target_ip}")
                print(f"      📝 Logs limpiados: {len(cleanup.get('logs_cleaned', []))}")
                print(f"      🗑️ Artefactos removidos: {len(cleanup.get('artifacts_removed', []))}")
                print(f"      🥷 Huellas obfuscadas: {len(cleanup.get('traces_obfuscated', []))}")
            
            # Actualizar reporte
            self.report['cleanup'].update({
                'status': 'completed',
                'items_cleaned': [result['cleanup'] for result in cleanup_results]
            })
            
            return {
                'verification_results': verification_results,
                'cleanup_results': cleanup_results
            }
            
        except Exception as e:
            self.logger.error(f"Error en limpieza final: {e}")
            self.report['cleanup']['status'] = 'failed'
            self.report['cleanup']['errors'].append(str(e))
            raise
    
    def _simulate_credential_harvesting(self, target_ip: str, target_os: str) -> list:
        """Simula harvesting de credenciales"""
        credentials = []
        
        if target_os.lower() == 'linux':
            credentials = [
                {'type': 'SSH Key', 'user': 'root', 'key': 'ssh-rsa AAAAB3NzaC1yc2E...'},
                {'type': 'Password', 'user': 'admin', 'password': 'admin123'},
                {'type': 'Hash', 'user': 'user1', 'hash': '$6$salt$hash...'}
            ]
        elif target_os.lower() == 'windows':
            credentials = [
                {'type': 'NTLM Hash', 'user': 'Administrator', 'hash': 'aad3b435b51404eeaad3b435b51404ee:...'},
                {'type': 'Password', 'user': 'admin', 'password': 'Password123!'},
                {'type': 'Kerberos Ticket', 'user': 'service', 'ticket': 'TGT_...'}
            ]
        
        return credentials
    
    def _simulate_lateral_movement(self, target_ip: str, target_os: str, credentials: list) -> dict:
        """Simula movimiento lateral"""
        return {
            'access_method': 'SSH' if target_os.lower() == 'linux' else 'RDP',
            'credentials_used': len(credentials),
            'lateral_targets': ['192.168.1.10', '192.168.1.20'],
            'success': True
        }
    
    def _generate_final_report(self) -> dict:
        """Genera reporte final"""
        execution_time = time.time() - self.red_team.start_time
        
        # Calcular estadísticas
        total_hosts = len(self.report['phase_1_reconnaissance']['hosts_discovered'])
        compromised_hosts = len(self.report['phase_4_lateral_movement']['compromised_systems'])
        persistent_access_points = len(self.report['phase_5_persistence']['backdoors_created'])
        meterpreter_sessions = len(self.report['phase_6_c2_establishment']['meterpreter_sessions'])
        total_credentials = len(self.report['phase_3_credential_harvesting']['credentials_found'])
        
        success_rate = (compromised_hosts / total_hosts * 100) if total_hosts > 0 else 0
        stealth_score = self._calculate_stealth_score()
        
        # Actualizar resumen
        self.report['summary'].update({
            'total_hosts': total_hosts,
            'compromised_hosts': compromised_hosts,
            'persistent_access_points': persistent_access_points,
            'total_credentials': total_credentials,
            'meterpreter_sessions': meterpreter_sessions,
            'execution_time': execution_time,
            'success_rate': success_rate,
            'stealth_score': stealth_score
        })
        
        # Guardar reporte
        self._save_report()
        
        return self.report
    
    def _calculate_stealth_score(self) -> float:
        """Calcula puntuación de sigilo"""
        stealth_factors = [
            len(self.report['phase_1_reconnaissance']['evasion_techniques_used']),
            len(self.report['phase_5_persistence']['persistent_access']),
            len(self.report['phase_6_c2_establishment']['dns_tunnels']),
            len(self.report['phase_6_c2_establishment']['domain_fronting']),
            len(self.report['cleanup']['items_cleaned'])
        ]
        
        max_possible = 5 * 10  # 5 factores, máximo 10 puntos cada uno
        actual_score = sum(stealth_factors) * 2  # Factor de multiplicación
        
        return min(100.0, (actual_score / max_possible) * 100)
    
    def _save_report(self):
        """Guarda reporte en archivo"""
        try:
            report_file = f"redteam_report_{self.session_id}_{int(time.time())}.json"
            
            with open(report_file, 'w', encoding='utf-8') as f:
                json.dump(self.report, f, indent=2, ensure_ascii=False)
            
            self.logger.info(f"Reporte guardado: {report_file}")
            print(f"📊 Reporte guardado: {report_file}")
            
        except Exception as e:
            self.logger.error(f"Error guardando reporte: {e}")

def main():
    """Función principal"""
    parser = argparse.ArgumentParser(description='Advanced Red Team Tool v2.0')
    parser.add_argument('target', help='Red objetivo (ej: 192.168.1.0/24)')
    parser.add_argument('--mode', choices=['full', 'stealth', 'persistence'], default='full',
                       help='Modo de operación')
    parser.add_argument('--verbose', '-v', action='store_true', help='Modo verbose')
    
    args = parser.parse_args()
    
    try:
        # Crear instancia principal
        red_team = MainAdvancedRedTeam()
        
        # Ejecutar operación
        report = red_team.run_advanced_red_team(args.target, args.mode)
        
        if report:
            print("\n🎯 Operación de red teaming completada exitosamente!")
        else:
            print("\n❌ La operación falló")
            sys.exit(1)
            
    except KeyboardInterrupt:
        print("\n⚠️ Operación interrumpida por el usuario")
        sys.exit(1)
    except Exception as e:
        print(f"\n❌ Error fatal: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()
