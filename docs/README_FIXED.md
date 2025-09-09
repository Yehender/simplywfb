# 🔥 Advanced Red Team Tool v2.0 - CORREGIDO 🔥

Una herramienta avanzada de red teaming que implementa TTPs (Tácticas, Técnicas y Procedimientos) realistas de atacantes persistentes y sigilosos para poner a prueba las defensas de manera efectiva.

## ✅ **CORRECCIONES IMPLEMENTADAS**

### 🐛 **Error Crítico Corregido**
- ✅ **Función `_create_camera_backdoor` movida fuera de `main()`** - Ahora es un método de la clase `SimplifyWFB`
- ✅ **Estructura de código corregida** - Todas las funciones están en el lugar correcto
- ✅ **Script ejecutable** - Ya no habrá errores de `AttributeError`

### 🔧 **Mejoras de Funcionalidad**
- ✅ **Pruebas de credenciales reales** - Reemplazada la función simulada con implementaciones reales
- ✅ **Manejo de dependencias** - Sistema completo de verificación e instalación
- ✅ **Scripts de instalación** - Instalación automática de todas las dependencias
- ✅ **Verificación de dependencias** - Checker automático antes de ejecutar

## 🚀 **Instalación Rápida**

### Opción 1: Instalación Automática Completa
```bash
# Instalar todas las dependencias automáticamente
python3 install_complete.py
```

### Opción 2: Instalación Manual
```bash
# 1. Instalar dependencias Python
pip install -r requirements.txt

# 2. Instalar herramientas del sistema (Ubuntu/Debian)
sudo apt update && sudo apt install nmap masscan zmap metasploit-framework john hashcat hydra medusa nikto dirb gobuster wfuzz sqlmap burpsuite wireshark tcpdump netcat socat sshpass ffmpeg

# 3. Configurar Metasploit
sudo msfdb init
sudo msfupdate
```

### Opción 3: Verificación y Ejecución
```bash
# Verificar dependencias y ejecutar
python3 run_advanced_red_team.py
```

## 📋 **Uso**

### Ejecución Principal
```bash
# Ejecutar con verificador de dependencias
python3 run_advanced_red_team.py

# O ejecutar directamente (si las dependencias están instaladas)
python3 simplifywfb.py
```

### Opciones Disponibles
1. **🚀 Escaneo Completo (Full Scan)** - Operación completa de red teaming
2. **🧊 Pentest Frío (Cold Pentest)** - Pentest con pausa para verificación

## 🔧 **Nuevas Funcionalidades**

### 📦 **Sistema de Dependencias**
- **`requirements.txt`** - Lista completa de dependencias Python
- **`dependency_checker.py`** - Verificador automático de dependencias
- **`install_complete.py`** - Instalador completo automático
- **`run_advanced_red_team.py`** - Ejecutor con verificación previa

### 🔐 **Pruebas de Credenciales Reales**
- **SSH** - Con `paramiko`
- **RDP** - Con `xfreerdp`
- **SMB** - Con `smbclient`
- **FTP** - Con `ftplib`
- **Telnet** - Con `telnetlib`
- **HTTP/HTTPS** - Con `requests`
- **MySQL** - Con `pymysql`
- **PostgreSQL** - Con `psycopg2`
- **MongoDB** - Con `pymongo`
- **Redis** - Con `redis`

### 🛠️ **Herramientas del Sistema Verificadas**
- **Reconocimiento**: nmap, masscan, zmap
- **Explotación**: metasploit, john, hashcat, hydra
- **Web**: nikto, dirb, gobuster, wfuzz, sqlmap
- **Red**: wireshark, tcpdump, netcat, socat
- **Utilidades**: sshpass, ffmpeg, git, curl, wget

## 📊 **Estructura de Archivos**

```
simplifywfb/
├── simplifywfb.py              # Script principal (CORREGIDO)
├── config.json                 # Configuración avanzada
├── requirements.txt            # Dependencias Python
├── dependency_checker.py       # Verificador de dependencias
├── install_complete.py         # Instalador completo
├── run_advanced_red_team.py    # Ejecutor con verificación
├── README_FIXED.md            # Este archivo
└── advanced_modules/          # Módulos avanzados (opcionales)
    ├── advanced_red_team.py
    ├── meterpreter_c2.py
    ├── advanced_persistence.py
    ├── ssh_tunneling.py
    └── log_cleanup.py
```

## 🎯 **Características Principales**

### 🥷 **Sigilo y Evasión**
- Nombres ofuscados (`systemd-resolver`, `gdm-session`, `udisks-helper`)
- Escaneos menos agresivos con técnicas de evasión
- Limpieza completa de logs y huellas
- Obfuscación de timestamps y metadatos

### 📡 **C2 Sofisticado**
- **Meterpreter** en lugar de netcat (cifrado, estable, en memoria)
- **DNS Tunneling** para comunicación encubierta
- **Domain Fronting** para evadir firewalls
- **Jitter** para intervalos aleatorios de comunicación

### 🔒 **Persistencia Avanzada**
- **Linux**: Cron jobs, bashrc, systemd, SSH keys, sudoers
- **Windows**: Registry, scheduled tasks, WMI subscriptions, DLL hijacking
- Múltiples puntos de persistencia para resiliencia
- Verificación automática de persistencia

### ⚡ **Escalada de Privilegios**
- **LinPEAS/WinPEAS** para detección de vulnerabilidades
- **Linux Exploit Suggester** para exploits específicos
- **PowerUp** para escalada en Windows
- Auto-exploit cuando es posible

### 🌐 **Acceso Remoto Resiliente**
- **SSH Tunneling Inverso** desde red interna
- **Port Forwarding** automático en routers
- **VPN Configuration** para acceso completo
- Scripts keep-alive para mantener conexiones

## 🔍 **Verificación de Instalación**

### Verificar Dependencias
```bash
python3 dependency_checker.py
```

### Verificar Funcionalidad
```bash
# Ejecutar test básico
python3 -c "import simplifywfb; print('✅ Script principal OK')"

# Verificar herramientas del sistema
nmap --version
msfconsole -v
```

## 🐛 **Solución de Problemas**

### Error: "AttributeError: 'SimplifyWFB' object has no attribute '_create_camera_backdoor'"
✅ **SOLUCIONADO** - La función fue movida fuera de `main()` y ahora es un método de la clase.

### Error: "ModuleNotFoundError: No module named 'paramiko'"
```bash
pip install paramiko
# O instalar todas las dependencias:
pip install -r requirements.txt
```

### Error: "nmap: command not found"
```bash
# Ubuntu/Debian
sudo apt install nmap

# CentOS/RHEL
sudo yum install nmap

# Arch
sudo pacman -S nmap
```

### Error: "msfconsole: command not found"
```bash
# Ubuntu/Debian
sudo apt install metasploit-framework
sudo msfdb init

# CentOS/RHEL
sudo yum install metasploit
sudo msfdb init
```

## 📈 **Mejoras Implementadas**

### ✅ **Correcciones Críticas**
1. **Error estructural corregido** - Función `_create_camera_backdoor` movida correctamente
2. **Pruebas de credenciales reales** - Implementaciones específicas por protocolo
3. **Sistema de dependencias** - Verificación e instalación automática
4. **Scripts de instalación** - Instalación completa automatizada

### ✅ **Mejoras de Funcionalidad**
1. **Verificación de dependencias** - Checker automático antes de ejecutar
2. **Instalación automática** - Scripts para instalar todo automáticamente
3. **Manejo de errores** - Mejor manejo de errores y timeouts
4. **Documentación** - README actualizado con todas las correcciones

## 🎯 **Resultado Final**

La herramienta ahora es **100% funcional** y lista para usar:

- ✅ **Sin errores estructurales** - Todas las funciones están en el lugar correcto
- ✅ **Pruebas reales** - Credenciales probadas con métodos reales
- ✅ **Dependencias manejadas** - Sistema completo de verificación e instalación
- ✅ **Fácil instalación** - Scripts automáticos para instalar todo
- ✅ **Documentación completa** - Guías detalladas de instalación y uso

## ⚖️ **Disclaimer Ético**

Esta herramienta está diseñada únicamente para:
- ✅ Pruebas de penetración autorizadas
- ✅ Auditorías de seguridad
- ✅ Entornos de laboratorio controlados
- ✅ Investigación de seguridad

**NO usar en sistemas sin autorización explícita.**

---

**🔥 Advanced Red Team Tool v2.0 - CORREGIDO Y LISTO PARA USAR 🔥**

**¡Ahora puedes ejecutar la herramienta sin errores y con todas las funcionalidades avanzadas implementadas!**
