# 🔥 Advanced Red Team Tool v2.0 🔥

Una herramienta avanzada de red teaming que implementa TTPs (Tácticas, Técnicas y Procedimientos) realistas de atacantes persistentes y sigilosos para poner a prueba las defensas de manera efectiva.

## 🎯 Características Principales

### 🥷 **Sigilo y Evasión**
- **Nombres Ofuscados**: Usuarios y servicios con nombres que se camuflan con el sistema (`systemd-resolver`, `gdm-session`, `udisks-helper`)
- **Escaneos Menos Agresivos**: Técnicas de evasión con `nmap` (SYN Scan, timing T2, decoy IPs, fragmentación)
- **Limpieza de Logs**: Eliminación/modificación de logs relevantes para ocultar huellas
- **Obfuscación de Huellas**: Modificación de timestamps y metadatos de archivos

### 📡 **C2 Sofisticado con Meterpreter**
- **Meterpreter Integration**: Reemplaza `netcat` con payloads cifrados y estables
- **DNS Tunneling**: Comunicación oculta a través de peticiones DNS
- **Domain Fronting**: C2 que se hace pasar por tráfico legítimo (Google, Cloudflare)
- **Jitter**: Intervalos aleatorios de comunicación para evadir detección
- **Payloads Avanzados**: Cifrado, anti-debugging, evasión de sandbox

### 🔒 **Persistencia Avanzada y Resiliente**

#### Linux:
- **Múltiples Mecanismos**: Cron jobs, modificación de `.bashrc`/`.profile`, servicios systemd
- **Claves SSH**: Instalación de claves para acceso persistente
- **Modificación de Sudoers**: Privilegios elevados sin contraseña

#### Windows:
- **Registro de Windows**: Múltiples ubicaciones (`Run`, `RunOnce`)
- **Tareas Programadas**: Tareas con diferentes horarios y triggers
- **WMI Event Subscriptions**: Persistencia avanzada difícil de detectar
- **DLL Hijacking**: Reemplazo de DLLs del sistema
- **Servicios de Windows**: Instalación de servicios maliciosos

### ⚡ **Escalada de Privilegios Automatizada**
- **LinPEAS/WinPEAS**: Escaneo automático de vulnerabilidades
- **Linux Exploit Suggester**: Sugerencias de exploits específicos
- **PowerUp**: Escalada de privilegios en Windows
- **Auto-exploit**: Ejecución automática de exploits cuando es posible

### 🌐 **Acceso Remoto Resiliente**
- **SSH Tunneling Inverso**: Conexiones desde la red interna hacia el exterior
- **Port Forwarding**: Configuración automática en routers
- **VPN Configuration**: Configuración de VPN para acceso completo a la red
- **Keep-alive Scripts**: Mantenimiento automático de conexiones

## 🚀 Instalación

### 1. Instalar Dependencias
```bash
python3 install_advanced_dependencies.py
```

### 2. Configurar Metasploit (Linux)
```bash
sudo msfdb init
sudo msfupdate
```

### 3. Verificar Instalación
```bash
python3 main_advanced_red_team.py --help
```

## 📋 Uso

### Uso Básico
```bash
python3 main_advanced_red_team.py 192.168.1.0/24
```

### Modos de Operación
```bash
# Modo completo (recomendado)
python3 main_advanced_red_team.py 192.168.1.0/24 --mode full

# Modo sigiloso (más lento, menos detectable)
python3 main_advanced_red_team.py 192.168.1.0/24 --mode stealth

# Solo persistencia (si ya tienes acceso)
python3 main_advanced_red_team.py 192.168.1.0/24 --mode persistence
```

### Modo Verbose
```bash
python3 main_advanced_red_team.py 192.168.1.0/24 --verbose
```

## 🔧 Configuración

El archivo `config.json` contiene todas las configuraciones avanzadas:

### C2 Configuration
```json
{
  "c2_config": {
    "meterpreter": {
      "enabled": true,
      "payload_type": "linux/x64/meterpreter/reverse_tcp",
      "encryption": true
    },
    "dns_tunneling": {
      "enabled": true,
      "domain": "cdn.google-analytics.com"
    },
    "domain_fronting": {
      "enabled": true,
      "front_domain": "cloudflare.com"
    }
  }
}
```

### Stealth Configuration
```json
{
  "stealth": {
    "obfuscated_names": {
      "linux_user": "systemd-resolver",
      "windows_user": "udisks-helper",
      "service_name": "gdm-session"
    },
    "scan_evasion": {
      "nmap_options": "-sS -T2 --scan-delay 1-3 --randomize-hosts"
    }
  }
}
```

## 📊 Fases de la Operación

### 🔍 **Fase 1: Reconocimiento Sigiloso**
- Escaneo de red con técnicas de evasión
- Detección de sistemas operativos
- Identificación de servicios y puertos

### ⚡ **Fase 2: Escalada de Privilegios**
- Ejecución de LinPEAS/WinPEAS
- Análisis de vulnerabilidades
- Sugerencias de exploits

### 🔑 **Fase 3: Harvesting de Credenciales**
- Password spraying
- Credential dumping
- Hash cracking

### 🔄 **Fase 4: Movimiento Lateral**
- Uso de credenciales obtenidas
- Pivoting entre sistemas
- Expansión del acceso

### 🔒 **Fase 5: Persistencia Avanzada**
- Múltiples mecanismos de persistencia
- Usuarios sigilosos
- Servicios y tareas programadas

### 📡 **Fase 6: Establecimiento de C2**
- Payloads Meterpreter
- Túneles DNS
- Domain fronting

### 🌐 **Fase 7: Persistencia de Red**
- SSH tunneling inverso
- Port forwarding en routers
- Configuración de VPN

### ✅ **Fase 8: Verificación**
- Verificación de persistencia
- Test de conectividad C2
- Validación de acceso

### 🧹 **Limpieza Final**
- Limpieza de logs
- Eliminación de artefactos
- Obfuscación de huellas

## 📈 Reportes

La herramienta genera reportes detallados en JSON que incluyen:

- **Metadatos**: Información de la sesión y configuración
- **Resultados por Fase**: Detalles de cada fase de la operación
- **Estadísticas**: Hosts comprometidos, persistencia, C2, etc.
- **Puntuación de Sigilo**: Métrica de qué tan sigilosa fue la operación
- **Tasa de Éxito**: Porcentaje de éxito general

### Ejemplo de Reporte
```json
{
  "summary": {
    "total_hosts": 15,
    "compromised_hosts": 8,
    "persistent_access_points": 12,
    "meterpreter_sessions": 5,
    "execution_time": 1847.32,
    "success_rate": 53.3,
    "stealth_score": 87.5
  }
}
```

## 🛡️ Consideraciones de Seguridad

### ⚠️ **Solo para Uso Ético**
- Esta herramienta está diseñada únicamente para pruebas de penetración autorizadas
- El usuario es responsable del uso ético y legal
- No usar en sistemas sin autorización explícita

### 🔒 **Recomendaciones**
- Usar en entornos de laboratorio controlados
- Documentar todas las actividades
- Limpiar completamente después de las pruebas
- Seguir las leyes y regulaciones aplicables

## 🐛 Solución de Problemas

### Error: "Metasploit no encontrado"
```bash
# Linux
sudo apt install metasploit-framework
sudo msfdb init

# Verificar instalación
msfconsole -v
```

### Error: "Permisos insuficientes"
```bash
# Hacer ejecutables los scripts
chmod +x *.py

# Verificar permisos de directorios
ls -la /tmp/.X11-unix/
```

### Error: "Dependencias faltantes"
```bash
# Reinstalar dependencias
python3 install_advanced_dependencies.py

# Verificar instalación
python3 -c "import paramiko, dns, requests"
```

## 📚 Módulos del Sistema

### `advanced_red_team.py`
- Clase principal con funcionalidades de reconocimiento
- Escalada de privilegios automatizada
- Detección de sistemas operativos

### `meterpreter_c2.py`
- Integración con Metasploit
- Generación de payloads avanzados
- Configuración de C2 encubierto

### `advanced_persistence.py`
- Múltiples mecanismos de persistencia
- Implementación específica por OS
- Verificación de persistencia

### `ssh_tunneling.py`
- Túneles SSH inversos
- Port forwarding automático
- Configuración de VPN

### `log_cleanup.py`
- Limpieza sigilosa de logs
- Obfuscación de huellas
- Eliminación de artefactos

## 🔄 Actualizaciones

### v2.0.0 (Actual)
- ✅ Integración completa con Meterpreter
- ✅ Técnicas de evasión avanzadas
- ✅ Persistencia multi-plataforma
- ✅ C2 encubierto (DNS tunneling, domain fronting)
- ✅ SSH tunneling inverso
- ✅ Limpieza sigilosa de logs

### Próximas Versiones
- 🔮 Integración con Cobalt Strike
- 🔮 Evasión de EDR/AV
- 🔮 Living off the Land techniques
- 🔮 Memory-only payloads
- 🔮 Advanced obfuscation

## 🤝 Contribuciones

Las contribuciones son bienvenidas. Por favor:

1. Fork el repositorio
2. Crea una rama para tu feature
3. Commit tus cambios
4. Push a la rama
5. Abre un Pull Request

## 📄 Licencia

Este proyecto está bajo la Licencia MIT. Ver `LICENSE` para más detalles.

## ⚖️ Disclaimer

Esta herramienta es solo para fines educativos y de prueba de penetración autorizada. Los desarrolladores no son responsables del mal uso de esta herramienta. El usuario debe cumplir con todas las leyes y regulaciones aplicables.

---

**🔥 Advanced Red Team Tool v2.0 - Por un red teaming más realista y efectivo 🔥**
