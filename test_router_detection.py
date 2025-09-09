#!/usr/bin/env python3
"""
Script de prueba para verificar detección de router
"""

import sys
import os
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from simplifywfb import SimplifyWFB

def test_router_detection():
    """Probar detección de router"""
    print("🔍 Probando detección de router...")
    
    wfb = SimplifyWFB()
    
    # Simular hosts descubiertos (basado en pt.json)
    wfb.report['phase_1_reconnaissance']['hosts_discovered'] = [
        {
            'ip': '192.168.1.1',
            'vendor': 'Huawei Technologies',
            'mac': 'C4:5E:5C:27:C0:36'
        }
    ]
    
    # Probar detección por MAC
    gateway = '192.168.1.1'
    router_type = wfb._detect_router_type_by_mac(gateway)
    
    print(f"🎯 Gateway: {gateway}")
    print(f"🔍 Tipo detectado: {router_type}")
    
    # Probar detección completa
    print("\n🔍 Probando detección completa...")
    full_type = wfb._detect_router_type(gateway)
    print(f"🔍 Tipo completo: {full_type}")
    
    # Probar fuerza bruta (solo mostrar que no se cuelga)
    print("\n🔑 Probando fuerza bruta (limitado)...")
    credentials = wfb._brute_force_router_credentials(gateway)
    if credentials:
        print(f"✅ Credenciales encontradas: {credentials}")
    else:
        print("⚠️ No se encontraron credenciales (esperado)")

if __name__ == "__main__":
    test_router_detection()
