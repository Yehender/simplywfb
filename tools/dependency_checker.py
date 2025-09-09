#!/usr/bin/env python3
"""
Dependency Checker - Verificador de Dependencias
Verifica que todas las dependencias necesarias estén instaladas
"""

import sys
import subprocess
import platform
import shutil
from pathlib import Path

class DependencyChecker:
    """Verificador de dependencias para Advanced Red Team Tool"""
    
    def __init__(self):
        self.system = platform.system().lower()
        self.missing_python_packages = []
        self.missing_system_tools = []
        self.warnings = []
        
    def check_all_dependencies(self) -> bool:
        """Verifica todas las dependencias"""
        print("🔍 Verificando dependencias del Advanced Red Team Tool...")
        print("=" * 60)
        
        # Verificar paquetes Python
        python_ok = self._check_python_packages()
        
        # Verificar herramientas del sistema
        system_ok = self._check_system_tools()
        
        # Mostrar resumen
        self._show_summary(python_ok, system_ok)
        
        return python_ok and system_ok
    
    def _check_python_packages(self) -> bool:
        """Verifica paquetes de Python"""
        print("\n📦 Verificando paquetes de Python...")
        
        required_packages = [
            'paramiko',
            'dns',
            'requests',
            'psutil',
            'cryptography',
            'scapy',
            'netaddr',
            'nmap',
            'netifaces',
            'colorama',
            'tqdm'
        ]
        
        optional_packages = [
            'impacket',
            'shodan',
            'censys',
            'rich',
            'click',
            'jinja2',
            'matplotlib',
            'seaborn',
            'pandas'
        ]
        
        all_ok = True
        
        # Verificar paquetes requeridos
        for package in required_packages:
            if self._check_python_package(package):
                print(f"   ✅ {package}")
            else:
                print(f"   ❌ {package} (REQUERIDO)")
                self.missing_python_packages.append(package)
                all_ok = False
        
        # Verificar paquetes opcionales
        for package in optional_packages:
            if self._check_python_package(package):
                print(f"   ✅ {package} (opcional)")
            else:
                print(f"   ⚠️ {package} (opcional - no instalado)")
        
        return all_ok
    
    def _check_python_package(self, package_name: str) -> bool:
        """Verifica si un paquete de Python está instalado"""
        try:
            # Mapear nombres de paquetes a nombres de importación
            import_map = {
                'dns': 'dns',
                'nmap': 'nmap',
                'netifaces': 'netifaces',
                'colorama': 'colorama',
                'tqdm': 'tqdm',
                'rich': 'rich',
                'click': 'click',
                'jinja2': 'jinja2',
                'matplotlib': 'matplotlib',
                'seaborn': 'seaborn',
                'pandas': 'pandas',
                'shodan': 'shodan',
                'censys': 'censys'
            }
            
            import_name = import_map.get(package_name, package_name)
            __import__(import_name)
            return True
        except ImportError:
            return False
    
    def _check_system_tools(self) -> bool:
        """Verifica herramientas del sistema"""
        print("\n🛠️ Verificando herramientas del sistema...")
        
        if self.system == 'linux':
            return self._check_linux_tools()
        elif self.system == 'windows':
            return self._check_windows_tools()
        else:
            print(f"   ⚠️ Sistema operativo no soportado: {self.system}")
            return False
    
    def _check_linux_tools(self) -> bool:
        """Verifica herramientas de Linux"""
        required_tools = [
            'nmap',
            'python3',
            'pip3',
            'git',
            'curl',
            'wget'
        ]
        
        optional_tools = [
            'masscan',
            'zmap',
            'msfconsole',
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
            'ffmpeg'
        ]
        
        all_ok = True
        
        # Verificar herramientas requeridas
        for tool in required_tools:
            if shutil.which(tool):
                print(f"   ✅ {tool}")
            else:
                print(f"   ❌ {tool} (REQUERIDO)")
                self.missing_system_tools.append(tool)
                all_ok = False
        
        # Verificar herramientas opcionales
        for tool in optional_tools:
            if shutil.which(tool):
                print(f"   ✅ {tool} (opcional)")
            else:
                print(f"   ⚠️ {tool} (opcional - no instalado)")
        
        return all_ok
    
    def _check_windows_tools(self) -> bool:
        """Verifica herramientas de Windows"""
        required_tools = [
            'python',
            'pip',
            'git',
            'curl'
        ]
        
        optional_tools = [
            'nmap',
            'msfconsole',
            'john',
            'hashcat',
            'hydra',
            'nikto',
            'burpsuite',
            'wireshark',
            'netcat',
            'ffmpeg'
        ]
        
        all_ok = True
        
        # Verificar herramientas requeridas
        for tool in required_tools:
            if shutil.which(tool):
                print(f"   ✅ {tool}")
            else:
                print(f"   ❌ {tool} (REQUERIDO)")
                self.missing_system_tools.append(tool)
                all_ok = False
        
        # Verificar herramientas opcionales
        for tool in optional_tools:
            if shutil.which(tool):
                print(f"   ✅ {tool} (opcional)")
            else:
                print(f"   ⚠️ {tool} (opcional - no instalado)")
        
        return all_ok
    
    def _show_summary(self, python_ok: bool, system_ok: bool):
        """Muestra resumen de verificación"""
        print("\n" + "=" * 60)
        print("📊 RESUMEN DE VERIFICACIÓN")
        print("=" * 60)
        
        if python_ok and system_ok:
            print("🎉 ¡Todas las dependencias están instaladas!")
            print("🚀 El Advanced Red Team Tool está listo para usar")
        else:
            print("⚠️ Faltan algunas dependencias:")
            
            if self.missing_python_packages:
                print(f"\n📦 Paquetes Python faltantes:")
                for package in self.missing_python_packages:
                    print(f"   - {package}")
                print(f"\n💡 Instalar con: pip install {' '.join(self.missing_python_packages)}")
            
            if self.missing_system_tools:
                print(f"\n🛠️ Herramientas del sistema faltantes:")
                for tool in self.missing_system_tools:
                    print(f"   - {tool}")
                
                if self.system == 'linux':
                    print(f"\n💡 Instalar con:")
                    print(f"   Ubuntu/Debian: sudo apt install {' '.join(self.missing_system_tools)}")
                    print(f"   CentOS/RHEL: sudo yum install {' '.join(self.missing_system_tools)}")
                    print(f"   Arch: sudo pacman -S {' '.join(self.missing_system_tools)}")
                elif self.system == 'windows':
                    print(f"\n💡 Instalar manualmente desde:")
                    print(f"   - Nmap: https://nmap.org/download.html")
                    print(f"   - Metasploit: https://www.metasploit.com/download")
                    print(f"   - Otras herramientas: https://www.kali.org/tools/")
        
        print("\n" + "=" * 60)
    
    def install_missing_python_packages(self):
        """Instala paquetes Python faltantes"""
        if not self.missing_python_packages:
            return True
        
        print(f"\n📦 Instalando paquetes Python faltantes...")
        
        try:
            cmd = [sys.executable, '-m', 'pip', 'install'] + self.missing_python_packages
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
            
            if result.returncode == 0:
                print("✅ Paquetes Python instalados correctamente")
                self.missing_python_packages = []
                return True
            else:
                print(f"❌ Error instalando paquetes: {result.stderr}")
                return False
                
        except subprocess.TimeoutExpired:
            print("⏰ Timeout instalando paquetes")
            return False
        except Exception as e:
            print(f"❌ Error: {e}")
            return False
    
    def show_installation_guide(self):
        """Muestra guía de instalación"""
        print("\n📖 GUÍA DE INSTALACIÓN RÁPIDA")
        print("=" * 60)
        
        print("\n1️⃣ Instalar paquetes Python:")
        print("   pip install -r requirements.txt")
        
        print("\n2️⃣ Instalar herramientas del sistema:")
        
        if self.system == 'linux':
            print("   Ubuntu/Debian:")
            print("   sudo apt update && sudo apt install nmap masscan zmap metasploit-framework john hashcat hydra medusa nikto dirb gobuster wfuzz sqlmap burpsuite wireshark tcpdump netcat socat sshpass ffmpeg")
            
            print("\n   CentOS/RHEL:")
            print("   sudo yum install nmap masscan zmap metasploit john hashcat hydra medusa nikto dirb gobuster wfuzz sqlmap burpsuite wireshark tcpdump netcat socat sshpass ffmpeg")
            
            print("\n   Arch Linux:")
            print("   sudo pacman -S nmap masscan zmap metasploit john hashcat hydra medusa nikto dirb gobuster wfuzz sqlmap burpsuite wireshark tcpdump netcat socat sshpass ffmpeg")
        
        elif self.system == 'windows':
            print("   Instalar manualmente:")
            print("   - Nmap: https://nmap.org/download.html")
            print("   - Metasploit: https://www.metasploit.com/download")
            print("   - John the Ripper: http://www.openwall.com/john/")
            print("   - Hashcat: https://hashcat.net/hashcat/")
            print("   - Otras herramientas: https://www.kali.org/tools/")
        
        print("\n3️⃣ Configurar Metasploit (Linux):")
        print("   sudo msfdb init")
        print("   sudo msfupdate")
        
        print("\n4️⃣ Verificar instalación:")
        print("   python3 dependency_checker.py")

def main():
    """Función principal"""
    checker = DependencyChecker()
    
    if not checker.check_all_dependencies():
        print("\n❓ ¿Desea instalar automáticamente los paquetes Python faltantes? (y/n): ", end="")
        choice = input().strip().lower()
        
        if choice in ['y', 'yes', 'sí', 'si']:
            if checker.install_missing_python_packages():
                print("\n🔄 Verificando nuevamente...")
                checker.check_all_dependencies()
            else:
                print("\n❌ No se pudieron instalar todos los paquetes")
                checker.show_installation_guide()
        else:
            checker.show_installation_guide()
    else:
        print("\n🎯 ¡Todo listo! Puedes ejecutar el Advanced Red Team Tool")

if __name__ == "__main__":
    main()
