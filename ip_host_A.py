#!/usr/bin/env python3
"""
Script Host A - Intercambio de Paquetes IP (Capa 3)
===================================================
Este script envía paquetes IP personalizados sobre una trama Ethernet.
Los estudiantes pueden capturar con Wireshark y analizar los campos de:
- Capa 2 (Ethernet): MAC origen/destino
- Capa 3 (IP): IP origen/destino, TTL, protocolo, flags, etc.

Campos importantes de IP para observar en Wireshark:
- Dirección IP de origen y destino
- TTL (Time To Live)
- Protocol (TCP=6, UDP=17, ICMP=1)
- Header Checksum
- Flags de fragmentación
- Identificación del paquete

NOTA: Requiere privilegios de administrador (sudo).
"""

from scapy.all import Ether, IP, Raw, sendp, conf
import sys

conf.verb = 1

def enviar_paquete_ip():
    """
    Crea y envía un paquete IP personalizado sobre Ethernet.
    """
    
    print("=" * 60)
    print("HOST A - ENVIANDO PAQUETE IP (Capa 2 + Capa 3)")
    print("=" * 60)
    
    # ===== CAPA 2: ETHERNET =====
    mac_destino = "02:42:ac:11:00:20"  # Broadcast
    mac_origen = "02:42:ac:11:00:10"   # MAC de Host A
    
    # ===== CAPA 3: IP =====
    # Configuración de direcciones IP
    # IMPORTANTE: Modificar según la red del laboratorio
    ip_origen = "192.168.100.10"      # IP de Host A
    ip_destino = "192.168.100.20"     # IP de Host B
    # Para broadcast en la red: "192.168.1.255"
    
    # Configuración de la interfaz de red
    interfaz = "eth0"  # Modificar según tu sistema
    
    print(f"\n[*] Configuración de Capa 2 (Ethernet):")
    print(f"    - Interfaz: {interfaz}")
    print(f"    - MAC Origen: {mac_origen}")
    print(f"    - MAC Destino: {mac_destino}")
    
    print(f"\n[*] Configuración de Capa 3 (IP):")
    print(f"    - IP Origen: {ip_origen}")
    print(f"    - IP Destino: {ip_destino}")
    
    # Construcción del paquete IP
    # Ether() = Capa 2
    capa_ethernet = Ether(
        dst=mac_destino,
        src=mac_origen
    )
    
    # IP() = Capa 3
    capa_ip = IP(
        src=ip_origen,        # IP de origen
        dst=ip_destino,       # IP de destino
        ttl=64,               # Time To Live (decrece en cada router)
        id=12345,             # Identificador del paquete
        flags="DF",           # Don't Fragment (no fragmentar)
        proto=253             # Protocolo experimental (253-254 reservados)
                              # 1=ICMP, 6=TCP, 17=UDP, 89=OSPF
    )
    
    # Payload (datos del paquete)
    mensaje = b"Mensaje desde Host A - Paquete IP Capa 3"
    
    # Ensamblar las capas: Ethernet / IP / Datos
    paquete = capa_ethernet / capa_ip / Raw(load=mensaje)
    
    print(f"    - TTL: {capa_ip.ttl}")
    print(f"    - ID: {capa_ip.id}")
    print(f"    - Flags: {capa_ip.flags}")
    print(f"    - Protocolo: {capa_ip.proto}")
    print(f"    - Payload: {mensaje.decode('utf-8')}")
    
    # Mostrar el paquete completo construido
    print(f"\n[*] Paquete completo construido:")
    paquete.show()
    
    # Calcular el tamaño total del paquete
    print(f"\n[*] Tamaño del paquete: {len(paquete)} bytes")
    print(f"    - Cabecera Ethernet: 14 bytes")
    print(f"    - Cabecera IP: 20 bytes (sin opciones)")
    print(f"    - Payload: {len(mensaje)} bytes")
    
    # Enviar el paquete
    print(f"\n[*] Enviando paquete por interfaz {interfaz}...")
    
    try:
        sendp(paquete, iface=interfaz, verbose=True)
        
        print("\n[✓] Paquete IP enviado exitosamente!")
        print("\n[INFO] Instrucciones para análisis con Wireshark:")
        print(f"      1. Capturar en interfaz '{interfaz}'")
        print(f"      2. Filtro sugerido: ip.addr == {ip_origen}")
        print("      3. Analizar campos de Capa 2 (Ethernet):")
        print("         - Destination/Source MAC")
        print("         - EtherType (0x0800 = IPv4)")
        print("      4. Analizar campos de Capa 3 (IP):")
        print("         - Source/Destination IP")
        print("         - TTL, Protocol, Flags")
        print("         - Header Checksum")
        print("         - Packet ID")
        print("      5. Ver payload en hexadecimal y ASCII")
        
    except PermissionError:
        print("\n[ERROR] Se requieren privilegios de administrador.")
        print("        Ejecutar con: sudo python3 ip_host_A.py")
        sys.exit(1)
    except Exception as e:
        print(f"\n[ERROR] Error al enviar paquete: {e}")
        print(f"        Verificar interfaz '{interfaz}' y direcciones IP.")
        sys.exit(1)

if __name__ == "__main__":
    print("\n[!] IMPORTANTE: Este script requiere privilegios de administrador")
    print("    Ejecutar con: sudo python3 ip_host_A.py\n")
    
    try:
        enviar_paquete_ip()
    except KeyboardInterrupt:
        print("\n\n[*] Proceso interrumpido por el usuario.")
        sys.exit(0)
