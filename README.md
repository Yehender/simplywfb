# 🔥 Advanced Red Team Tool v2.0 - ESTRUCTURA ORGANIZADA 🔥

Una herramienta avanzada de red teaming con implementaciones reales y estructura organizada.

## 📁 **ESTRUCTURA DEL PROYECTO**

```
simplifywfb/
├── 📄 simplifywfb.py              # Script principal
├── 📄 config.json                 # Configuración
├── 📄 requirements.txt            # Dependencias Python
├── 📄 run_advanced_red_team.py    # Ejecutor principal
├── 📄 report.json                 # Reporte generado
│
├── 🛠️ tools/                      # Herramientas principales
│   ├── __init__.py
│   ├── tplink_exploiter.py        # Explotador TP-Link
│   ├── credential_sniffer.py      # Sniffer de credenciales
│   ├── network_analyzer.py        # Analizador de red
│   ├── dependency_checker.py      # Verificador de dependencias
│   ├── install_complete.py        # Instalador completo
│   ├── install_backdoor_tester_deps.py
│   ├── install_dependencies.bat   # Instalador Windows
│   └── install_dependencies.sh    # Instalador Linux
│
├── 🔧 optional/                   # Módulos opcionales
│   ├── __init__.py
│   ├── advanced_red_team.py       # Clase principal avanzada
│   ├── meterpreter_c2.py          # Integración Meterpreter
│   ├── advanced_persistence.py    # Persistencia avanzada
│   ├── ssh_tunneling.py           # SSH tunneling
│   ├── log_cleanup.py             # Limpieza de logs
│   ├── main_advanced_red_team.py  # Orquestador avanzado
│   └── install_advanced_dependencies.py
│
├── 🧪 test/                       # Scripts de prueba
│   ├── __init__.py
│   ├── test_installation.py       # Prueba de instalación
│   ├── test_backdoors.py          # Prueba de backdoors
│   ├── test_connectivity.py       # Prueba de conectividad
│   ├── test_report_generation.py  # Prueba de reportes
│   ├── quick_backdoor_test.py     # Prueba rápida backdoors
│   └── quick_port_test.py         # Prueba rápida puertos
│
└── 📚 docs/                       # Documentación
    ├── README.md                  # Este archivo
    ├── README_ADVANCED.md         # Documentación avanzada
    ├── README_FIXED.md            # Documentación de correcciones
    ├── README_REAL_IMPLEMENTATION.md
    ├── AI_GUIDE.md
    ├── BACKDOORS_EXTERNOS_RESUMEN.md
    ├── BACKDOORS_REALES_IMPLEMENTADOS.md
    ├── LIMPIEZA_COMPLETA_RESUMEN.md
    ├── MANUAL_DUMMIES.md
    └── RESUMEN_FINAL_BACKDOORS.md
```

## 🚀 **INSTALACIÓN Y USO**

### **Instalación Rápida**
```bash
# Instalar todas las dependencias
python3 tools/install_complete.py

# Verificar instalación
python3 test/test_installation.py

# Ejecutar herramienta
python3 run_advanced_red_team.py
```

### **Instalación Manual**
```bash
# Dependencias Python
pip install -r requirements.txt

# Herramientas del sistema (Ubuntu/Debian)
sudo apt update && sudo apt install nmap masscan zmap metasploit-framework john hashcat hydra medusa nikto dirb gobuster wfuzz sqlmap burpsuite wireshark tcpdump netcat socat sshpass ffmpeg

# Configurar Metasploit
sudo msfdb init
sudo msfupdate
```

## 📋 **DESCRIPCIÓN DE CARPETAS**

### 🛠️ **tools/** - Herramientas Principales
- **`tplink_exploiter.py`** - Explotador específico para routers TP-Link
- **`credential_sniffer.py`** - Sniffer real de credenciales con scapy
- **`network_analyzer.py`** - Analizador real de red y topología
- **`dependency_checker.py`** - Verificador de dependencias
- **`install_complete.py`** - Instalador completo automático

### 🔧 **optional/** - Módulos Opcionales
- **`advanced_red_team.py`** - Clase principal avanzada
- **`meterpreter_c2.py`** - Integración con Meterpreter
- **`advanced_persistence.py`** - Persistencia avanzada
- **`ssh_tunneling.py`** - SSH tunneling
- **`log_cleanup.py`** - Limpieza de logs

### 🧪 **test/** - Scripts de Prueba
- **`test_installation.py`** - Prueba de instalación
- **`test_backdoors.py`** - Prueba de backdoors
- **`test_connectivity.py`** - Prueba de conectividad
- **`quick_*.py`** - Pruebas rápidas

### 📚 **docs/** - Documentación
- **`README_*.md`** - Documentación completa
- **`*_RESUMEN.md`** - Resúmenes de funcionalidades
- **`MANUAL_*.md`** - Manuales de uso

## 🎯 **FUNCIONALIDADES PRINCIPALES**

### ✅ **Implementaciones Reales**
- **TP-Link Exploiter** - Funciona específicamente con routers TP-Link
- **Credential Sniffer** - Captura credenciales reales del tráfico
- **Network Analyzer** - Analiza topología real de red
- **Real Credential Testing** - Prueba credenciales con métodos reales

### ✅ **Sin Simulaciones**
- ❌ Eliminadas todas las funciones simuladas
- ❌ Eliminados todos los placeholders
- ✅ Todas las funcionalidades son reales y funcionales

## 🔧 **CONFIGURACIÓN**

### **Archivo de Configuración**
- **`config.json`** - Configuración centralizada
- Incluye configuraciones para C2, sigilo, persistencia, etc.

### **Dependencias**
- **`requirements.txt`** - Lista completa de dependencias Python
- Incluye todas las librerías necesarias para funcionalidades reales

## 🚀 **EJECUCIÓN**

### **Método Principal**
```bash
python3 run_advanced_red_team.py
```

### **Método Directo**
```bash
python3 simplifywfb.py
```

### **Pruebas**
```bash
# Prueba de instalación
python3 test/test_installation.py

# Prueba rápida de backdoors
python3 test/quick_backdoor_test.py

# Prueba rápida de puertos
python3 test/quick_port_test.py
```

## 📊 **REPORTES**

### **Archivos Generados**
- **`report.json`** - Reporte completo de la operación
- **`*_backup_*.bin`** - Backups de configuraciones
- **`captured_credentials.json`** - Credenciales capturadas

## ⚖️ **DISCLAIMER ÉTICO**

Esta herramienta está diseñada únicamente para:
- ✅ Pruebas de penetración autorizadas
- ✅ Auditorías de seguridad
- ✅ Entornos de laboratorio controlados
- ✅ Investigación de seguridad

**NO usar en sistemas sin autorización explícita.**

## 🎉 **VENTAJAS DE LA NUEVA ESTRUCTURA**

- ✅ **Organización clara** - Cada tipo de archivo en su carpeta
- ✅ **Fácil mantenimiento** - Estructura modular
- ✅ **Separación de responsabilidades** - Herramientas, opcionales, pruebas
- ✅ **Documentación organizada** - Todo en la carpeta docs
- ✅ **Imports limpios** - Estructura de paquetes Python
- ✅ **Fácil navegación** - Estructura intuitiva

---

**🔥 Advanced Red Team Tool v2.0 - ESTRUCTURA ORGANIZADA Y FUNCIONAL 🔥**

**¡Ahora tienes una herramienta de red teaming completamente organizada y funcional!**
