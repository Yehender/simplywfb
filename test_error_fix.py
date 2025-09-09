#!/usr/bin/env python3
"""
Script de prueba para verificar que el error de NoneType está arreglado
"""

import sys
import os
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from simplifywfb import SimplifyWFB

def test_error_fix():
    """Probar que el error de NoneType está arreglado"""
    print("🔍 Probando arreglo del error NoneType...")
    
    wfb = SimplifyWFB()
    
    # Simular datos del reporte con elementos None (caso problemático)
    wfb.report['phase_4_persistence'] = {
        'router_access': [
            {
                'gateway': '192.168.1.1',
                'router_type': 'huawei',
                'credentials': {
                    'username': 'admin',
                    'password': 'admin'
                },
                'configuration': {
                    'port_forwarding': [
                        {'external_port': 33389, 'internal_port': 3389, 'configured': True}
                    ]
                }
            },
            None,  # Elemento None que causaba el error
            {
                'gateway': '192.168.1.2',
                'router_type': 'generic',
                'credentials': None,  # Credenciales None
                'configuration': None  # Configuración None
            }
        ],
        'cameras_accessed': [],
        'network_persistence': [],
        'backdoors_created': [],
        'users_created': []
    }
    
    # Probar la función de limpieza
    print("🧹 Probando limpieza de datos...")
    wfb._clean_report_data()
    
    # Probar las funciones auxiliares
    print("🔍 Probando verificación de port forwarding...")
    success = wfb._check_port_forwarding_success()
    print(f"   Port forwarding exitoso: {success}")
    
    details = wfb._get_port_forwarding_details()
    print(f"   Detalles encontrados: {len(details)}")
    
    # Probar análisis detallado (esto debería funcionar ahora)
    print("📊 Probando análisis detallado...")
    try:
        wfb._generate_detailed_analysis()
        print("✅ Análisis detallado completado sin errores!")
    except Exception as e:
        print(f"❌ Error en análisis detallado: {e}")
        return False
    
    # Probar la función que causaba el error
    print("🌐 Probando _show_remote_access_summary...")
    try:
        wfb._show_remote_access_summary()
        print("✅ _show_remote_access_summary completado sin errores!")
    except Exception as e:
        print(f"❌ Error en _show_remote_access_summary: {e}")
        return False
    
    print("✅ Todas las pruebas pasaron - El error está arreglado!")
    return True

if __name__ == "__main__":
    test_error_fix()
