#!/usr/bin/env python3
"""
Complete Installation Script - Instalador Completo
Instala todas las dependencias necesarias para el Advanced Red Team Tool
"""

import subprocess
import sys
import os
import platform
import shutil
from pathlib import Path

class CompleteInstaller:
    """Instalador completo para Advanced Red Team Tool"""
    
    def __init__(self):
        self.system = platform.system().lower()
        self.arch = platform.machine().lower()
        
    def install_all(self):
        """Instala todas las dependencias"""
        print("🔥 INSTALADOR COMPLETO - ADVANCED RED TEAM TOOL v2.0 🔥")
        print("=" * 70)
        print(f"🖥️ Sistema: {platform.system()} {platform.release()}")
        print(f"🏗️ Arquitectura: {platform.machine()}")
        print("=" * 70)
        
        try:
            # 1. Instalar paquetes Python
            print("\n📦 Fase 1: Instalando paquetes Python...")
            self._install_python_packages()
            
            # 2. Instalar herramientas del sistema
            print("\n🛠️ Fase 2: Instalando herramientas del sistema...")
            self._install_system_tools()
            
            # 3. Configurar Metasploit
            print("\n💥 Fase 3: Configurando Metasploit...")
            self._setup_metasploit()
            
            # 4. Crear directorios necesarios
            print("\n📁 Fase 4: Creando directorios...")
            self._create_directories()
            
            # 5. Configurar permisos
            print("\n🔐 Fase 5: Configurando permisos...")
            self._setup_permissions()
            
            # 6. Verificar instalación
            print("\n✅ Fase 6: Verificando instalación...")
            self._verify_installation()
            
            print("\n🎉 ¡INSTALACIÓN COMPLETADA EXITOSAMENTE! 🎉")
            print("=" * 70)
            print("🚀 El Advanced Red Team Tool está listo para usar")
            print("📖 Ejecuta: python3 run_advanced_red_team.py")
            print("=" * 70)
            
        except Exception as e:
            print(f"\n❌ Error durante la instalación: {e}")
            sys.exit(1)
    
    def _install_python_packages(self):
        """Instala paquetes Python"""
        packages = [
            'paramiko',
            'dnspython',
            'requests',
            'psutil',
            'cryptography',
            'scapy',
            'netaddr',
            'python-nmap',
            'netifaces',
            'colorama',
            'tqdm',
            'rich',
            'click',
            'jinja2',
            'matplotlib',
            'seaborn',
            'pandas'
        ]
        
        for package in packages:
            try:
                print(f"   📦 Instalando {package}...")
                result = subprocess.run([
                    sys.executable, '-m', 'pip', 'install', package, '--upgrade'
                ], capture_output=True, text=True, timeout=300)
                
                if result.returncode == 0:
                    print(f"   ✅ {package} instalado correctamente")
                else:
                    print(f"   ⚠️ Error instalando {package}: {result.stderr}")
                    
            except subprocess.TimeoutExpired:
                print(f"   ⏰ Timeout instalando {package}")
            except Exception as e:
                print(f"   ❌ Error instalando {package}: {e}")
    
    def _install_system_tools(self):
        """Instala herramientas del sistema"""
        if self.system == 'linux':
            self._install_linux_tools()
        elif self.system == 'windows':
            self._install_windows_tools()
        else:
            print(f"   ⚠️ Sistema operativo no soportado: {self.system}")
    
    def _install_linux_tools(self):
        """Instala herramientas para Linux"""
        # Detectar distribución
        distro = self._detect_linux_distro()
        
        if distro in ['ubuntu', 'debian']:
            self._install_apt_packages()
        elif distro in ['centos', 'rhel', 'fedora']:
            self._install_yum_packages()
        elif distro == 'arch':
            self._install_pacman_packages()
        else:
            print(f"   ⚠️ Distribución no soportada: {distro}")
    
    def _detect_linux_distro(self):
        """Detecta la distribución de Linux"""
        try:
            with open('/etc/os-release', 'r') as f:
                content = f.read().lower()
                
            if 'ubuntu' in content or 'debian' in content:
                return 'ubuntu'
            elif 'centos' in content or 'rhel' in content:
                return 'centos'
            elif 'fedora' in content:
                return 'fedora'
            elif 'arch' in content:
                return 'arch'
            else:
                return 'unknown'
        except:
            return 'unknown'
    
    def _install_apt_packages(self):
        """Instala paquetes usando apt"""
        packages = [
            'nmap', 'masscan', 'zmap', 'metasploit-framework',
            'john', 'hashcat', 'hydra', 'medusa', 'nikto',
            'dirb', 'gobuster', 'wfuzz', 'sqlmap',
            'wireshark', 'tcpdump', 'netcat', 'socat',
            'sshpass', 'ffmpeg', 'git', 'curl', 'wget',
            'python3-pip', 'python3-dev', 'build-essential',
            'libssl-dev', 'libffi-dev'
        ]
        
        # Actualizar repositorios
        print("   🔄 Actualizando repositorios...")
        subprocess.run(['sudo', 'apt', 'update'], check=True)
        
        # Instalar paquetes
        for package in packages:
            try:
                print(f"   📦 Instalando {package}...")
                result = subprocess.run([
                    'sudo', 'apt', 'install', '-y', package
                ], capture_output=True, text=True, timeout=300)
                
                if result.returncode == 0:
                    print(f"   ✅ {package} instalado correctamente")
                else:
                    print(f"   ⚠️ Error instalando {package}")
                    
            except subprocess.TimeoutExpired:
                print(f"   ⏰ Timeout instalando {package}")
            except Exception as e:
                print(f"   ❌ Error instalando {package}: {e}")
    
    def _install_yum_packages(self):
        """Instala paquetes usando yum/dnf"""
        packages = [
            'nmap', 'masscan', 'zmap', 'metasploit',
            'john', 'hashcat', 'hydra', 'medusa', 'nikto',
            'dirb', 'gobuster', 'wfuzz', 'sqlmap',
            'wireshark', 'tcpdump', 'netcat', 'socat',
            'sshpass', 'ffmpeg', 'git', 'curl', 'wget',
            'python3-pip', 'python3-devel', 'gcc', 'gcc-c++',
            'openssl-devel', 'libffi-devel'
        ]
        
        # Actualizar repositorios
        print("   🔄 Actualizando repositorios...")
        subprocess.run(['sudo', 'yum', 'update', '-y'], check=True)
        
        # Instalar paquetes
        for package in packages:
            try:
                print(f"   📦 Instalando {package}...")
                result = subprocess.run([
                    'sudo', 'yum', 'install', '-y', package
                ], capture_output=True, text=True, timeout=300)
                
                if result.returncode == 0:
                    print(f"   ✅ {package} instalado correctamente")
                else:
                    print(f"   ⚠️ Error instalando {package}")
                    
            except subprocess.TimeoutExpired:
                print(f"   ⏰ Timeout instalando {package}")
            except Exception as e:
                print(f"   ❌ Error instalando {package}: {e}")
    
    def _install_pacman_packages(self):
        """Instala paquetes usando pacman"""
        packages = [
            'nmap', 'masscan', 'zmap', 'metasploit',
            'john', 'hashcat', 'hydra', 'medusa', 'nikto',
            'dirb', 'gobuster', 'wfuzz', 'sqlmap',
            'wireshark', 'tcpdump', 'netcat', 'socat',
            'sshpass', 'ffmpeg', 'git', 'curl', 'wget',
            'python-pip', 'python-dev', 'base-devel',
            'openssl', 'libffi'
        ]
        
        # Actualizar repositorios
        print("   🔄 Actualizando repositorios...")
        subprocess.run(['sudo', 'pacman', '-Sy'], check=True)
        
        # Instalar paquetes
        for package in packages:
            try:
                print(f"   📦 Instalando {package}...")
                result = subprocess.run([
                    'sudo', 'pacman', '-S', '--noconfirm', package
                ], capture_output=True, text=True, timeout=300)
                
                if result.returncode == 0:
                    print(f"   ✅ {package} instalado correctamente")
                else:
                    print(f"   ⚠️ Error instalando {package}")
                    
            except subprocess.TimeoutExpired:
                print(f"   ⏰ Timeout instalando {package}")
            except Exception as e:
                print(f"   ❌ Error instalando {package}: {e}")
    
    def _install_windows_tools(self):
        """Instala herramientas para Windows"""
        print("   ⚠️ Instalación manual requerida en Windows")
        print("   📋 Herramientas a instalar:")
        
        tools = [
            'Nmap', 'Metasploit', 'John the Ripper', 'Hashcat',
            'Hydra', 'Nikto', 'Burp Suite', 'Wireshark',
            'Netcat', 'FFmpeg', 'Git', 'Python', 'Pip'
        ]
        
        for tool in tools:
            print(f"      - {tool}")
        
        print("\n   🔗 Enlaces útiles:")
        print("      - Nmap: https://nmap.org/download.html")
        print("      - Metasploit: https://www.metasploit.com/download")
        print("      - John the Ripper: http://www.openwall.com/john/")
        print("      - Hashcat: https://hashcat.net/hashcat/")
        print("      - Otras herramientas: https://www.kali.org/tools/")
    
    def _setup_metasploit(self):
        """Configura Metasploit"""
        if self.system == 'linux':
            try:
                # Inicializar base de datos de Metasploit
                print("   🗄️ Inicializando base de datos de Metasploit...")
                subprocess.run(['sudo', 'msfdb', 'init'], check=True)
                
                # Actualizar módulos
                print("   🔄 Actualizando módulos de Metasploit...")
                subprocess.run(['sudo', 'msfupdate'], check=True)
                
                print("   ✅ Metasploit configurado correctamente")
                
            except Exception as e:
                print(f"   ⚠️ Error configurando Metasploit: {e}")
        else:
            print("   ⚠️ Configuración manual de Metasploit requerida en Windows")
    
    def _create_directories(self):
        """Crea directorios necesarios"""
        directories = [
            '/tmp/.X11-unix',
            '/var/lib/dbus',
            '/usr/share/doc/redteam',
            '/opt/.cache/redteam'
        ]
        
        for directory in directories:
            try:
                if self.system == 'linux':
                    Path(directory).mkdir(parents=True, exist_ok=True)
                    print(f"   📁 Directorio creado: {directory}")
            except Exception as e:
                print(f"   ⚠️ Error creando directorio {directory}: {e}")
    
    def _setup_permissions(self):
        """Configura permisos necesarios"""
        if self.system == 'linux':
            try:
                # Hacer ejecutables los scripts
                scripts = [
                    'simplifywfb.py',
                    'run_advanced_red_team.py',
                    'dependency_checker.py',
                    'install_complete.py'
                ]
                
                for script in scripts:
                    if os.path.exists(script):
                        os.chmod(script, 0o755)
                        print(f"   🔐 Permisos configurados: {script}")
                
                # Configurar permisos para directorios ocultos
                hidden_dirs = ['/tmp/.X11-unix', '/var/lib/dbus']
                for directory in hidden_dirs:
                    if os.path.exists(directory):
                        os.chmod(directory, 0o755)
                        print(f"   🔐 Permisos configurados: {directory}")
                
            except Exception as e:
                print(f"   ⚠️ Error configurando permisos: {e}")
    
    def _verify_installation(self):
        """Verifica que la instalación sea correcta"""
        print("   🔍 Verificando instalación...")
        
        # Verificar paquetes Python
        python_packages = ['paramiko', 'requests', 'psutil', 'cryptography', 'scapy']
        python_ok = 0
        
        for package in python_packages:
            try:
                __import__(package)
                python_ok += 1
            except ImportError:
                pass
        
        # Verificar herramientas del sistema
        system_tools = ['nmap', 'python3', 'git', 'curl']
        system_ok = 0
        
        for tool in system_tools:
            if shutil.which(tool):
                system_ok += 1
        
        # Verificar Metasploit
        metasploit_ok = False
        if shutil.which('msfconsole'):
            metasploit_ok = True
        
        # Mostrar resumen
        print(f"\n📊 RESUMEN DE VERIFICACIÓN:")
        print(f"   📦 Paquetes Python: {python_ok}/{len(python_packages)}")
        print(f"   🛠️ Herramientas del sistema: {system_ok}/{len(system_tools)}")
        print(f"   💥 Metasploit: {'✅' if metasploit_ok else '❌'}")
        
        if python_ok == len(python_packages) and system_ok == len(system_tools) and metasploit_ok:
            print("\n🎉 ¡Instalación verificada exitosamente!")
        else:
            print("\n⚠️ Algunas dependencias pueden no estar instaladas correctamente")

def main():
    """Función principal"""
    installer = CompleteInstaller()
    installer.install_all()

if __name__ == "__main__":
    main()
