#!/usr/bin/env python3
"""
Script de prueba para verificar la generación de reportes
"""

import json
import time
import os

def test_report_generation():
    """Probar generación de reporte"""
    print("🧪 PRUEBA DE GENERACIÓN DE REPORTE")
    print("=" * 50)
    
    # Crear reporte de prueba
    test_report = {
        "metadata": {
            "timestamp": time.time(),
            "mode": "test",
            "version": "1.0"
        },
        "summary": {
            "total_hosts": 5,
            "compromised_hosts": 2,
            "success_rate": 40.0
        },
        "test_data": {
            "message": "Este es un reporte de prueba",
            "hosts": ["192.168.1.1", "192.168.1.2"],
            "credentials": ["admin:password", "user:123456"]
        }
    }
    
    # Generar nombre de archivo
    report_file = f"simplifywfb_report_{int(time.time())}.json"
    print(f"📄 Generando archivo: {report_file}")
    
    # Guardar archivo
    try:
        with open(report_file, 'w', encoding='utf-8') as f:
            json.dump(test_report, f, indent=2, ensure_ascii=False)
        
        print(f"✅ Archivo guardado exitosamente")
        print(f"🔍 Archivo existe: {os.path.exists(report_file)}")
        print(f"📏 Tamaño: {os.path.getsize(report_file)} bytes")
        print(f"📁 Directorio actual: {os.getcwd()}")
        
        # Listar archivos de reporte
        report_files = [f for f in os.listdir('.') if f.startswith('simplifywfb_report_')]
        print(f"📁 Archivos de reporte encontrados: {report_files}")
        
        # Leer y verificar contenido
        with open(report_file, 'r', encoding='utf-8') as f:
            loaded_report = json.load(f)
        
        print(f"✅ Contenido verificado: {len(loaded_report)} secciones")
        print(f"✅ Timestamp: {loaded_report['metadata']['timestamp']}")
        print(f"✅ Hosts: {loaded_report['summary']['total_hosts']}")
        
        return report_file
        
    except Exception as e:
        print(f"❌ Error generando reporte: {e}")
        return None

def test_file_upload_simulation(report_file):
    """Simular envío de archivo"""
    print(f"\n📤 SIMULANDO ENVÍO DE ARCHIVO")
    print("=" * 50)
    
    if not report_file:
        print("❌ No hay archivo para enviar")
        return
    
    print(f"🔍 Verificando archivo: {report_file}")
    print(f"🔍 Archivo existe: {os.path.exists(report_file)}")
    
    if os.path.exists(report_file):
        print(f"📏 Tamaño: {os.path.getsize(report_file)} bytes")
        print(f"📁 Directorio: {os.getcwd()}")
        print("✅ Archivo listo para envío")
    else:
        print("❌ Archivo no encontrado")

def main():
    """Función principal"""
    print("🔧 SimplifyWFB - Prueba de Generación de Reportes")
    print("=" * 60)
    
    # Probar generación
    report_file = test_report_generation()
    
    # Probar simulación de envío
    test_file_upload_simulation(report_file)
    
    print(f"\n📊 RESUMEN")
    print("=" * 30)
    if report_file and os.path.exists(report_file):
        print("✅ Generación de reporte: EXITOSA")
        print("✅ Verificación de archivo: EXITOSA")
        print(f"📄 Archivo: {report_file}")
    else:
        print("❌ Generación de reporte: FALLO")
        print("❌ Verificación de archivo: FALLO")

if __name__ == "__main__":
    main()
