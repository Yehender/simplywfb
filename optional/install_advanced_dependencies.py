#!/usr/bin/env python3
"""
Advanced Dependencies Installer - Instalador de Dependencias Avanzadas
Instala todas las dependencias necesarias para el Advanced Red Team Tool
"""

import subprocess
import sys
import os
import platform
import json
from pathlib import Path

class AdvancedDependenciesInstaller:
    """Instalador de dependencias para Advanced Red Team Tool"""
    
    def __init__(self):
        self.system = platform.system().lower()
        self.arch = platform.machine().lower()
        self.dependencies = self._load_dependencies()
        
    def _load_dependencies(self):
        """Carga lista de dependencias desde archivo JSON"""
        dependencies = {
            'python_packages': [
                'paramiko',
                'dnspython',
                'requests',
                'psutil',
                'cryptography',
                'scapy',
                'netaddr',
                'python-nmap',
                'impacket',
                'pycryptodome'
            ],
            'system_tools': {
                'linux': [
                    'nmap',
                    'masscan',
                    'zmap',
                    'metasploit-framework',
                    'john',
                    'hashcat',
                    'hydra',
                    'medusa',
                    'nikto',
                    'dirb',
                    'gobuster',
                    'wfuzz',
                    'sqlmap',
                    'burpsuite',
                    'wireshark',
                    'tcpdump',
                    'netcat',
                    'socat',
                    'sshpass',
                    'curl',
                    'wget',
                    'git',
                    'python3-pip',
                    'python3-dev',
                    'build-essential',
                    'libssl-dev',
                    'libffi-dev'
                ],
                'windows': [
                    'nmap',
                    'metasploit',
                    'john',
                    'hashcat',
                    'hydra',
                    'nikto',
                    'burpsuite',
                    'wireshark',
                    'netcat',
                    'curl',
                    'git',
                    'python',
                    'pip'
                ]
            },
            'metasploit_modules': [
                'exploit/multi/handler',
                'post/multi/manage/shell_to_meterpreter',
                'post/windows/manage/migrate',
                'post/linux/manage/shell_to_meterpreter',
                'auxiliary/scanner/ssh/ssh_login',
                'auxiliary/scanner/smb/smb_login',
                'auxiliary/scanner/rdp/rdp_scanner',
                'auxiliary/scanner/vnc/vnc_login'
            ]
        }
        return dependencies
    
    def install_all_dependencies(self):
        """Instala todas las dependencias"""
        print("🔥 INSTALADOR DE DEPENDENCIAS - ADVANCED RED TEAM TOOL v2.0 🔥")
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
            print("📖 Ejecuta: python3 main_advanced_red_team.py --help")
            print("=" * 70)
            
        except Exception as e:
            print(f"\n❌ Error durante la instalación: {e}")
            sys.exit(1)
    
    def _install_python_packages(self):
        """Instala paquetes Python"""
        for package in self.dependencies['python_packages']:
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
        packages = self.dependencies['system_tools']['linux']
        
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
        packages = self.dependencies['system_tools']['linux']
        
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
        packages = self.dependencies['system_tools']['linux']
        
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
        
        for tool in self.dependencies['system_tools']['windows']:
            print(f"      - {tool}")
        
        print("\n   🔗 Enlaces útiles:")
        print("      - Nmap: https://nmap.org/download.html")
        print("      - Metasploit: https://www.metasploit.com/download")
        print("      - John the Ripper: http://www.openwall.com/john/")
        print("      - Hashcat: https://hashcat.net/hashcat/")
    
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
            '/opt/.cache/redteam',
            'C:\\Windows\\Temp\\redteam',
            'C:\\ProgramData\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\redteam'
        ]
        
        for directory in directories:
            try:
                if self.system == 'linux' and directory.startswith('/'):
                    Path(directory).mkdir(parents=True, exist_ok=True)
                    print(f"   📁 Directorio creado: {directory}")
                elif self.system == 'windows' and directory.startswith('C:'):
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
                    'main_advanced_red_team.py',
                    'advanced_red_team.py',
                    'meterpreter_c2.py',
                    'advanced_persistence.py',
                    'ssh_tunneling.py',
                    'log_cleanup.py'
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
        verification_results = {
            'python_packages': 0,
            'system_tools': 0,
            'metasploit': False,
            'directories': 0
        }
        
        # Verificar paquetes Python
        print("   🔍 Verificando paquetes Python...")
        for package in self.dependencies['python_packages']:
            try:
                __import__(package.replace('-', '_'))
                verification_results['python_packages'] += 1
                print(f"      ✅ {package}")
            except ImportError:
                print(f"      ❌ {package}")
        
        # Verificar herramientas del sistema
        print("   🔍 Verificando herramientas del sistema...")
        system_tools = self.dependencies['system_tools'].get(self.system, [])
        for tool in system_tools[:10]:  # Verificar solo las primeras 10
            try:
                result = subprocess.run(['which', tool], capture_output=True)
                if result.returncode == 0:
                    verification_results['system_tools'] += 1
                    print(f"      ✅ {tool}")
                else:
                    print(f"      ❌ {tool}")
            except:
                print(f"      ❌ {tool}")
        
        # Verificar Metasploit
        print("   🔍 Verificando Metasploit...")
        try:
            result = subprocess.run(['msfconsole', '-v'], capture_output=True)
            if result.returncode == 0:
                verification_results['metasploit'] = True
                print("      ✅ Metasploit")
            else:
                print("      ❌ Metasploit")
        except:
            print("      ❌ Metasploit")
        
        # Mostrar resumen
        print("\n📊 RESUMEN DE VERIFICACIÓN:")
        print(f"   📦 Paquetes Python: {verification_results['python_packages']}/{len(self.dependencies['python_packages'])}")
        print(f"   🛠️ Herramientas del sistema: {verification_results['system_tools']}/{len(system_tools[:10])}")
        print(f"   💥 Metasploit: {'✅' if verification_results['metasploit'] else '❌'}")
        
        # Guardar resultados
        with open('installation_verification.json', 'w') as f:
            json.dump(verification_results, f, indent=2)
        
        print("   📄 Resultados guardados en: installation_verification.json")

def main():
    """Función principal"""
    installer = AdvancedDependenciesInstaller()
    installer.install_all_dependencies()

if __name__ == "__main__":
    main()
