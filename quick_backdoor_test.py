#!/usr/bin/env python3
"""
Script rápido para probar backdoors específicos
Uso: python quick_backdoor_test.py <tipo> <host> <puerto> <usuario> <contraseña>
"""

import sys
import socket
import subprocess
import time

def test_ssh(host, port, username, password):
    """Probar conexión SSH"""
    print(f"🔍 Probando SSH {username}@{host}:{port}")
    
    try:
        # Probar conectividad
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(5)
        result = sock.connect_ex((host, port))
        sock.close()
        
        if result != 0:
            print(f"❌ Puerto {port} no accesible")
            return False
        
        # Probar SSH
        ssh_cmd = [
            'ssh', '-o', 'ConnectTimeout=10',
            '-o', 'StrictHostKeyChecking=no',
            '-o', 'UserKnownHostsFile=/dev/null',
            '-o', 'LogLevel=ERROR',
            f'{username}@{host}',
            'echo "SUCCESS"'
        ]
        
        process = subprocess.run(
            ssh_cmd,
            input=f'{password}\n',
            text=True,
            capture_output=True,
            timeout=15
        )
        
        if process.returncode == 0 and "SUCCESS" in process.stdout:
            print(f"✅ SSH exitoso: {username}@{host}")
            return True
        else:
            print(f"❌ SSH falló: {process.stderr.strip()}")
            return False
            
    except Exception as e:
        print(f"❌ Error SSH: {e}")
        return False

def test_http(host, port, username, password):
    """Probar conexión HTTP"""
    print(f"🔍 Probando HTTP {username}@{host}:{port}")
    
    try:
        import urllib.request
        import base64
        
        # Crear autenticación básica
        auth_string = f"{username}:{password}"
        auth_bytes = auth_string.encode('ascii')
        auth_b64 = base64.b64encode(auth_bytes).decode('ascii')
        
        url = f"http://{host}:{port}/"
        req = urllib.request.Request(url)
        req.add_header('Authorization', f'Basic {auth_b64}')
        req.add_header('User-Agent', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36')
        
        with urllib.request.urlopen(req, timeout=10) as response:
            if response.status == 200:
                print(f"✅ HTTP exitoso: {username}@{host}")
                return True
            else:
                print(f"❌ HTTP falló: Status {response.status}")
                return False
                
    except Exception as e:
        print(f"❌ Error HTTP: {e}")
        return False

def test_port(host, port):
    """Probar solo conectividad de puerto"""
    print(f"🔍 Probando puerto {host}:{port}")
    
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(5)
        result = sock.connect_ex((host, port))
        sock.close()
        
        if result == 0:
            print(f"✅ Puerto {port} accesible en {host}")
            return True
        else:
            print(f"❌ Puerto {port} no accesible en {host}")
            return False
            
    except Exception as e:
        print(f"❌ Error probando puerto: {e}")
        return False

def main():
    """Función principal"""
    if len(sys.argv) < 2:
        print("🔧 SimplifyWFB - Prueba Rápida de Backdoors")
        print("=" * 50)
        print("Uso:")
        print("  python quick_backdoor_test.py ssh <host> <puerto> <usuario> <contraseña>")
        print("  python quick_backdoor_test.py http <host> <puerto> <usuario> <contraseña>")
        print("  python quick_backdoor_test.py port <host> <puerto>")
        print("\nEjemplos:")
        print("  python quick_backdoor_test.py ssh 192.168.1.1 22 admin admin")
        print("  python quick_backdoor_test.py http 192.168.1.1 80 admin admin")
        print("  python quick_backdoor_test.py port 192.168.1.1 22")
        return
    
    test_type = sys.argv[1].lower()
    
    if test_type == "ssh":
        if len(sys.argv) != 6:
            print("❌ Uso: python quick_backdoor_test.py ssh <host> <puerto> <usuario> <contraseña>")
            return
        
        host, port, username, password = sys.argv[2], int(sys.argv[3]), sys.argv[4], sys.argv[5]
        test_ssh(host, port, username, password)
        
    elif test_type == "http":
        if len(sys.argv) != 6:
            print("❌ Uso: python quick_backdoor_test.py http <host> <puerto> <usuario> <contraseña>")
            return
        
        host, port, username, password = sys.argv[2], int(sys.argv[3]), sys.argv[4], sys.argv[5]
        test_http(host, port, username, password)
        
    elif test_type == "port":
        if len(sys.argv) != 4:
            print("❌ Uso: python quick_backdoor_test.py port <host> <puerto>")
            return
        
        host, port = sys.argv[2], int(sys.argv[3])
        test_port(host, port)
        
    else:
        print("❌ Tipo de prueba no válido. Use: ssh, http, o port")

if __name__ == "__main__":
    main()
