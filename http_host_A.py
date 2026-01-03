#!/usr/bin/env python3
"""
Script Host A - Envío de Request HTTP con Handshake TCP Completo (Capa 7)
=========================================================================
Este script establece una conexión TCP completa (handshake de 3 vías),
envía un request HTTP, y cierra la conexión correctamente.

Muestra todas las capas del modelo OSI/TCP-IP:
- Capa 2 (Ethernet): MAC origen/destino
- Capa 3 (IP): IP origen/destino, TTL, flags
- Capa 4 (TCP): handshake SYN/SYN-ACK/ACK, puertos, flags, números de secuencia
- Capa 7 (HTTP): método, headers, body

Flujo TCP completo:
1. Cliente envía SYN
2. Servidor responde SYN-ACK
3. Cliente envía ACK (conexión establecida)
4. Cliente envía datos HTTP con PSH-ACK
5. Servidor responde ACK
6. Cliente cierra con FIN-ACK
7. Servidor responde FIN-ACK
8. Cliente confirma con ACK final

Los estudiantes pueden analizar con Wireshark el flujo TCP completo y ver
cómo se establece y cierra una conexión TCP.
"""

from scapy.all import Ether, IP, TCP, Raw, sendp, sniff, conf
import sys
import random

conf.verb = 0  # Reducir verbosidad de Scapy

def enviar_request_http():
    """
    Establece conexión TCP, envía HTTP request, y cierra conexión.
    """
    
    print("=" * 80)
    print("HOST A - ENVIANDO REQUEST HTTP CON HANDSHAKE TCP COMPLETO")
    print("=" * 80)
    
    # ===== CONFIGURACIÓN =====
    
    # Capa 2 - Ethernet
    mac_origen = "02:42:ac:11:00:10"     # MAC de Host A
    mac_destino = "02:42:ac:11:00:20"    # MAC de Host B
    
    # Capa 3 - IP
    ip_origen = "192.168.100.10"         # IP de Host A
    ip_destino = "192.168.100.20"        # IP de Host B
    
    # Capa 4 - TCP
    puerto_origen = random.randint(50000, 60000)  # Puerto aleatorio del cliente
    puerto_destino = 80                  # Puerto HTTP estándar
    
    # Interfaz de red
    interfaz = "eth0"
    
    # Números de secuencia iniciales aleatorios
    seq_inicial = random.randint(1000, 10000)
    
    print(f"\n[*] Configuración:")
    print(f"    - Interfaz: {interfaz}")
    print(f"    - MAC Origen: {mac_origen} → MAC Destino: {mac_destino}")
    print(f"    - IP Origen: {ip_origen} → IP Destino: {ip_destino}")
    print(f"    - Puerto Origen: {puerto_origen} → Puerto Destino: {puerto_destino}")
    print(f"    - SEQ inicial: {seq_inicial}")
    
    # Capas base que se reutilizarán
    eth = Ether(src=mac_origen, dst=mac_destino)
    ip = IP(src=ip_origen, dst=ip_destino, ttl=64)
    
    # ===== PASO 1: ENVIAR SYN (Cliente inicia conexión) =====
    print(f"\n[1/7] Enviando SYN (iniciar handshake)...")
    
    tcp_syn = TCP(
        sport=puerto_origen,
        dport=puerto_destino,
        seq=seq_inicial,
        flags="S",  # SYN flag
        window=8192,
        options=[('MSS', 1460)]
    )
    
    syn_pkt = eth / ip / tcp_syn
    sendp(syn_pkt, iface=interfaz, verbose=False)
    print(f"    → SYN enviado [SEQ={seq_inicial}]")
    
    # ===== PASO 2: ESPERAR SYN-ACK del servidor =====
    print(f"[2/7] Esperando SYN-ACK del servidor...")
    
    def es_syn_ack(pkt):
        return (TCP in pkt and 
                pkt[TCP].sport == puerto_destino and 
                pkt[TCP].dport == puerto_origen and
                pkt[TCP].flags == "SA")
    
    syn_ack_pkt = sniff(
        filter=f"tcp and src host {ip_destino} and dst host {ip_origen}",
        iface=interfaz,
        lfilter=es_syn_ack,
        count=1,
        timeout=5
    )
    
    if not syn_ack_pkt:
        print("    ✗ ERROR: No se recibió SYN-ACK. Asegúrate de que Host B esté ejecutando.")
        sys.exit(1)
    
    server_seq = syn_ack_pkt[0][TCP].seq
    server_ack = syn_ack_pkt[0][TCP].ack
    print(f"    ← SYN-ACK recibido [SEQ={server_seq}, ACK={server_ack}]")
    
    # ===== PASO 3: ENVIAR ACK (Completar handshake) =====
    print(f"[3/7] Enviando ACK (completar handshake)...")
    
    tcp_ack = TCP(
        sport=puerto_origen,
        dport=puerto_destino,
        seq=server_ack,
        ack=server_seq + 1,
        flags="A",  # ACK flag
        window=8192
    )
    
    ack_pkt = eth / ip / tcp_ack
    sendp(ack_pkt, iface=interfaz, verbose=False)
    print(f"    → ACK enviado [SEQ={server_ack}, ACK={server_seq + 1}]")
    print(f"    ✓ Conexión TCP establecida!")
    
    # ===== PASO 4: ENVIAR HTTP REQUEST =====
    print(f"\n[4/7] Enviando HTTP Request...")
    
    http_request = (
        "GET /index.html HTTP/1.1\r\n"
        f"Host: {ip_destino}\r\n"
        "User-Agent: Scapy-Lab-Client/1.0\r\n"
        "Accept: text/html,application/xhtml+xml\r\n"
        "Accept-Language: es-ES,es;q=0.9\r\n"
        "Connection: close\r\n"
        "\r\n"
    )
    
    tcp_psh = TCP(
        sport=puerto_origen,
        dport=puerto_destino,
        seq=server_ack,
        ack=server_seq + 1,
        flags="PA",  # PSH + ACK flags
        window=8192
    )
    
    http_pkt = eth / ip / tcp_psh / Raw(load=http_request)
    sendp(http_pkt, iface=interfaz, verbose=False)
    print(f"    → HTTP GET enviado [SEQ={server_ack}, ACK={server_seq + 1}]")
    print(f"    → Tamaño payload: {len(http_request)} bytes")
    
    # Actualizar seq number para siguiente paquete
    client_seq = server_ack + len(http_request)
    
    # ===== PASO 5: ESPERAR ACK del servidor =====
    print(f"[5/7] Esperando ACK del servidor...")
    
    def es_ack_datos(pkt):
        return (TCP in pkt and 
                pkt[TCP].sport == puerto_destino and 
                pkt[TCP].dport == puerto_origen and
                "A" in str(pkt[TCP].flags))
    
    data_ack_pkt = sniff(
        filter=f"tcp and src host {ip_destino} and dst host {ip_origen}",
        iface=interfaz,
        lfilter=es_ack_datos,
        count=1,
        timeout=5
    )
    
    if data_ack_pkt:
        print(f"    ← ACK recibido [ACK={data_ack_pkt[0][TCP].ack}]")
        print(f"    ✓ Datos HTTP recibidos por el servidor!")
    
    # ===== PASO 6: ENVIAR FIN (Cerrar conexión) =====
    print(f"\n[6/7] Enviando FIN (cerrar conexión)...")
    
    tcp_fin = TCP(
        sport=puerto_origen,
        dport=puerto_destino,
        seq=client_seq,
        ack=server_seq + 1,
        flags="FA",  # FIN + ACK flags
        window=8192
    )
    
    fin_pkt = eth / ip / tcp_fin
    sendp(fin_pkt, iface=interfaz, verbose=False)
    print(f"    → FIN-ACK enviado [SEQ={client_seq}]")
    
    # ===== PASO 7: ESPERAR FIN-ACK del servidor =====
    print(f"[7/7] Esperando FIN-ACK del servidor...")
    
    def es_fin_ack(pkt):
        return (TCP in pkt and 
                pkt[TCP].sport == puerto_destino and 
                pkt[TCP].dport == puerto_origen and
                "F" in str(pkt[TCP].flags))
    
    fin_ack_pkt = sniff(
        filter=f"tcp and src host {ip_destino} and dst host {ip_origen}",
        iface=interfaz,
        lfilter=es_fin_ack,
        count=1,
        timeout=5
    )
    
    if fin_ack_pkt:
        server_fin_seq = fin_ack_pkt[0][TCP].seq
        print(f"    ← FIN-ACK recibido [SEQ={server_fin_seq}]")
        
        # Enviar ACK final
        tcp_final_ack = TCP(
            sport=puerto_origen,
            dport=puerto_destino,
            seq=client_seq + 1,
            ack=server_fin_seq + 1,
            flags="A",
            window=8192
        )
        
        final_ack_pkt = eth / ip / tcp_final_ack
        sendp(final_ack_pkt, iface=interfaz, verbose=False)
        print(f"    → ACK final enviado [ACK={server_fin_seq + 1}]")
        print(f"    ✓ Conexión TCP cerrada correctamente!")
    
    # ===== RESUMEN =====
    print(f"\n" + "=" * 80)
    print("RESUMEN DEL FLUJO TCP/HTTP")
    print("=" * 80)
    print(f"""
    Cliente (Host A)              Servidor (Host B)
    {ip_origen}:{puerto_origen}    {ip_destino}:{puerto_destino}
    
    1. SYN          ────────────→    (Iniciar conexión)
    2. SYN-ACK      ←────────────    (Aceptar conexión)
    3. ACK          ────────────→    (Conexión establecida)
    4. PSH-ACK      ────────────→    (Enviar HTTP GET)
       [HTTP GET]
    5. ACK          ←────────────    (Datos recibidos)
    6. FIN-ACK      ────────────→    (Cerrar conexión)
    7. FIN-ACK      ←────────────    (Confirmar cierre)
    8. ACK          ────────────→    (Cierre completo)
    """)
    
    print("\n[INFO] Análisis con Wireshark - Filtros sugeridos:")
    print(f"      - tcp.stream eq 0  (seguir todo el flujo TCP)")
    print(f"      - http             (ver solo el request HTTP)")
    print(f"      - tcp.flags.syn==1 (ver handshake)")
    print(f"      - tcp.flags.fin==1 (ver cierre de conexión)")
    
    print("\n[INFO] Campos TCP importantes a observar:")
    print("      - Sequence numbers (aumentan con cada byte enviado)")
    print("      - Acknowledgment numbers (confirman bytes recibidos)")
    print("      - TCP flags: SYN, ACK, PSH, FIN")
    print("      - Window Size (control de flujo)")
    
    print("\n[TIP] Hacer clic derecho en Wireshark y seleccionar:")
    print("      'Follow > TCP Stream' para ver toda la conversación")
    print("=" * 80)

if __name__ == "__main__":
    try:
        enviar_request_http()
    except KeyboardInterrupt:
        print("\n\n[*] Proceso interrumpido por el usuario.")
        sys.exit(0)
    except Exception as e:
        print(f"\n[ERROR] Error: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)
