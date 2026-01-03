#!/usr/bin/env python3
"""
Script Host B - Recepción de Paquetes IP (Capa 3)
=================================================
Este script escucha paquetes IP en la red y analiza tanto la capa Ethernet
como la capa IP. Permite a los estudiantes ver los campos de ambas capas
en tiempo real mientras capturan con Wireshark.

Muestra información detallada de:
- Capa 2 (Ethernet): direcciones MAC, EtherType
- Capa 3 (IP): direcciones IP, TTL, protocolo, flags, checksum

NOTA: Requiere privilegios de administrador (sudo).
"""

from scapy.all import Ether, IP, sniff, conf
import sys

conf.verb = 1

# Diccionario de protocolos IP comunes
PROTOCOLOS_IP = {
    1: "ICMP",
    6: "TCP",
    17: "UDP",
    89: "OSPF",
    253: "Experimental",
    254: "Experimental"
}

def analizar_paquete_ip(paquete):
    """
    Función callback que analiza y muestra los campos de un paquete IP.
    """
    
    # Verificar que tenga capa IP
    if IP in paquete:
        print("\n" + "=" * 70)
        print("PAQUETE IP RECIBIDO (Capa 2 + Capa 3)")
        print("=" * 70)
        
        # ===== ANÁLISIS DE CAPA 2 (ETHERNET) =====
        if Ether in paquete:
            eth = paquete[Ether]
            print("\n[*] CAPA 2 - ETHERNET:")
            print(f"    - MAC Origen:      {eth.src}")
            print(f"    - MAC Destino:     {eth.dst}")
            print(f"    - EtherType:       0x{eth.type:04x}", end="")
            
            if eth.type == 0x0800:
                print(" (IPv4)")
            elif eth.type == 0x86DD:
                print(" (IPv6)")
            else:
                print()
        
        # ===== ANÁLISIS DE CAPA 3 (IP) =====
        ip = paquete[IP]
        print("\n[*] CAPA 3 - IP:")
        print(f"    - IP Origen:       {ip.src}")
        print(f"    - IP Destino:      {ip.dst}")
        print(f"    - Versión:         {ip.version}")
        print(f"    - Longitud Cabecera: {ip.ihl * 4} bytes")
        print(f"    - Longitud Total:  {ip.len} bytes")
        print(f"    - TTL:             {ip.ttl}")
        print(f"    - ID del Paquete:  {ip.id}")
        
        # Analizar flags de fragmentación
        print(f"    - Flags:           {ip.flags}", end="")
        if ip.flags == "DF":
            print(" (Don't Fragment)")
        elif ip.flags == "MF":
            print(" (More Fragments)")
        else:
            print()
        
        print(f"    - Fragment Offset: {ip.frag}")
        
        # Identificar el protocolo
        protocolo_nombre = PROTOCOLOS_IP.get(ip.proto, f"Desconocido ({ip.proto})")
        print(f"    - Protocolo:       {ip.proto} ({protocolo_nombre})")
        print(f"    - Checksum:        0x{ip.chksum:04x}")
        
        # Mostrar opciones IP si existen
        if ip.ihl > 5:  # Si hay opciones (header > 20 bytes)
            print(f"    - Opciones IP:     Presentes ({(ip.ihl - 5) * 4} bytes)")
        
        # ===== ANÁLISIS DEL PAYLOAD =====
        if paquete.haslayer('Raw'):
            payload = bytes(paquete['Raw'])
            print(f"\n[*] PAYLOAD (Datos):")
            print(f"    - Tamaño: {len(payload)} bytes")
            
            # Intentar mostrar como texto
            try:
                texto = payload.decode('utf-8')
                print(f"    - Contenido (texto): {texto}")
            except:
                # Si no es texto, mostrar en hexadecimal
                print(f"    - Contenido (hex): {payload.hex()[:100]}...")
        
        # Mostrar resumen del paquete completo
        print(f"\n[*] Resumen del paquete completo:")
        print("-" * 70)
        paquete.show()
        
        print("\n" + "=" * 70)

def escuchar_paquetes_ip():
    """
    Captura y procesa paquetes IP en la interfaz especificada.
    """
    
    print("=" * 70)
    print("HOST B - ESCUCHANDO PAQUETES IP (Capa 2 + Capa 3)")
    print("=" * 70)
    
    # Configuración
    interfaz = "eth0"  # Modificar según tu sistema
    
    # Filtro BPF para capturar solo ciertos paquetes
    # Opciones de filtro:
    filtro = "ip and (proto 253 or proto 254 or dst host 192.168.1.200)"
    # - "ip" = solo paquetes IPv4
    # - "proto 253" = solo protocolo experimental 253
    # - "dst host 192.168.1.200" = destino a IP específica
    # - "src host 192.168.1.100" = origen desde IP específica
    # - "broadcast" = paquetes broadcast
    
    print(f"\n[*] Configuración:")
    print(f"    - Interfaz: {interfaz}")
    print(f"    - Filtro BPF: {filtro}")
    print(f"\n[*] Esperando paquetes IP...")
    print("[*] Presionar Ctrl+C para detener\n")
    
    try:
        # Capturar paquetes
        sniff(
            prn=analizar_paquete_ip,
            filter=filtro,
            iface=interfaz,
            store=0
        )
        
    except PermissionError:
        print("\n[ERROR] Se requieren privilegios de administrador.")
        print("        Ejecutar con: sudo python3 ip_host_B.py")
        sys.exit(1)
    except Exception as e:
        print(f"\n[ERROR] Error al capturar paquetes: {e}")
        print(f"        Verificar interfaz '{interfaz}' y filtro.")
        sys.exit(1)

if __name__ == "__main__":
    print("\n[!] IMPORTANTE: Este script requiere privilegios de administrador")
    print("    Ejecutar con: sudo python3 ip_host_B.py\n")
    print("[INFO] Para el laboratorio:")
    print("       1. Iniciar este script en Host B")
    print("       2. Iniciar captura en Wireshark en la misma interfaz")
    print("       3. Ejecutar ip_host_A.py en Host A")
    print("       4. Comparar la salida del script con lo capturado en Wireshark")
    print("       5. Analizar campos de Capa 2 y Capa 3 en ambos lugares\n")
    
    try:
        escuchar_paquetes_ip()
    except KeyboardInterrupt:
        print("\n\n[*] Captura detenida por el usuario.")
        sys.exit(0)
