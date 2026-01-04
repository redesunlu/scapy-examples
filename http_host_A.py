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
import random
import sys
import subprocess

conf.verb = 0  # Reducir verbosidad de Scapy

def configurar_iptables(puerto):
    """
    Configura iptables para bloquear paquetes RST del kernel en el puerto del cliente.
    
    ¿Por qué necesitamos esto?
    - Cuando el servidor responde SYN-ACK, el kernel del cliente también lo ve
    - Como no hay un socket real en ese puerto, el kernel envía RST
    - Bloqueamos ese RST para que Scapy maneje todo
    """
    print(f"[*] Configurando iptables para bloquear RST en puerto {puerto}...")
    
    try:
        cmd = [
            "iptables", "-A", "OUTPUT",
            "-p", "tcp",
            "--tcp-flags", "RST", "RST",
            "--sport", str(puerto),
            "-j", "DROP"
        ]
        subprocess.run(cmd, check=True, capture_output=True)
        print(f"    ✓ Regla iptables aplicada\n")
        return True
    except subprocess.CalledProcessError:
        print(f"    ✗ Error al configurar iptables")
        print(f"    [TIP] Ejecuta con sudo: sudo python3 http_host_A.py")
        return False
    except FileNotFoundError:
        print(f"    ✗ iptables no encontrado")
        return False

def limpiar_iptables(puerto):
    """
    Elimina la regla de iptables al finalizar.
    """
    print(f"\n[*] Limpiando regla de iptables...")
    try:
        cmd = [
            "iptables", "-D", "OUTPUT",
            "-p", "tcp",
            "--tcp-flags", "RST", "RST",
            "--sport", str(puerto),
            "-j", "DROP"
        ]
        subprocess.run(cmd, check=True, capture_output=True)
        print(f"    ✓ Regla eliminada")
    except:
        pass

def enviar_request_http(puerto_origen):
    """
    Establece conexión TCP, envía HTTP request, y cierra conexión.
    
    Args:
        puerto_origen: Puerto TCP del cliente (ya configurado en iptables)
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
    print(f"    - SEQ inicial: {seq_inicial}\n")
    
    # Capas base que se reutilizarán
    eth = Ether(src=mac_origen, dst=mac_destino)
    ip = IP(src=ip_origen, dst=ip_destino, ttl=64)
    
    # ===== PASO 1: ENVIAR SYN (Cliente inicia conexión) =====
    print(f"[1/7] Enviando SYN (iniciar handshake)...")
    
    tcp_syn = TCP(
        sport=puerto_origen,
        dport=puerto_destino,
        seq=seq_inicial,
        flags="S",
        window=8192,
        options=[('MSS', 1460)]
    )
    
    syn_pkt = eth / ip / tcp_syn
    sendp(syn_pkt, iface=interfaz, verbose=False)
    print(f"    → SYN enviado [SEQ={seq_inicial}]")
    
    # ===== PASO 2: ESPERAR SYN-ACK del servidor =====
    print(f"[2/7] Esperando SYN-ACK del servidor...")
    
    paquetes = sniff(
        filter=f"tcp and src {ip_destino} and dst {ip_origen} and src port {puerto_destino} and dst port {puerto_origen}",
        iface=interfaz,
        count=1,
        timeout=5
    )
    
    if not paquetes:
        print(f"    ✗ No se recibió respuesta del servidor (timeout)")
        return
    
    pkt = paquetes[0]
    
    # Verificar que sea SYN-ACK
    if not (TCP in pkt and pkt[TCP].flags.S and pkt[TCP].flags.A):
        print(f"    ✗ Se recibió un paquete pero no es SYN-ACK: {pkt.summary()}")
        return
    
    server_seq = pkt[TCP].seq
    server_ack = pkt[TCP].ack
    print(f"    ← SYN-ACK recibido [SEQ={server_seq}, ACK={server_ack}]")
    
    # ===== PASO 3: ENVIAR ACK (Completar handshake) =====
    print(f"[3/7] Enviando ACK (completar handshake)...")
    
    tcp_ack = TCP(
        sport=puerto_origen,
        dport=puerto_destino,
        seq=server_ack,
        ack=server_seq + 1,
        flags="A",
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
        flags="PA",
        window=8192
    )
    
    http_pkt = eth / ip / tcp_psh / Raw(load=http_request)
    sendp(http_pkt, iface=interfaz, verbose=False)
    
    print(f"    → HTTP GET Request enviado:")
    print(f"       {http_request.split(chr(13))[0]}")
    print(f"       [SEQ={server_ack}, ACK={server_seq + 1}]")
    print(f"    → Tamaño payload: {len(http_request)} bytes")

    
    # ===== PASO 5: ESPERAR ACK del servidor =====
    print(f"\n[5/7] Esperando ACK del servidor...")
    
    paquetes = sniff(
        filter=f"tcp and src {ip_destino} and dst {ip_origen} and src port {puerto_destino} and dst port {puerto_origen}",
        iface=interfaz,
        count=1,
        timeout=5
    )
    
    if paquetes and TCP in paquetes[0]:
        print(f"    ← ACK recibido del servidor")
        print(f"    ✓ Datos HTTP confirmados!")
    
    # ===== PASO 6: ENVIAR FIN-ACK (Cerrar conexión) =====
    print(f"\n[6/7] Enviando FIN-ACK (cerrar conexión)...")
    
    tcp_fin = TCP(
        sport=puerto_origen,
        dport=puerto_destino,
        seq=server_ack + len(http_request),
        ack=server_seq + 1,
        flags="FA",
        window=8192
    )
    
    fin_pkt = eth / ip / tcp_fin
    sendp(fin_pkt, iface=interfaz, verbose=False)
    print(f"    → FIN-ACK enviado")
    
    # ===== PASO 7: ESPERAR FIN-ACK del servidor =====
    print(f"[7/7] Esperando FIN-ACK del servidor...")
    
    paquetes = sniff(
        filter=f"tcp and src {ip_destino} and dst {ip_origen} and src port {puerto_destino} and dst port {puerto_origen}",
        iface=interfaz,
        count=1,
        timeout=5
    )
    
    if not paquetes:
        print(f"    ✗ No se recibió FIN-ACK (timeout)")
        return
    
    fin_pkt = paquetes[0]
    
    if TCP in fin_pkt and fin_pkt[TCP].flags.F:
        print(f"    ← FIN-ACK recibido del servidor")
        
        # Enviar ACK final
        final_ack = TCP(
            sport=puerto_origen,
            dport=puerto_destino,
            seq=fin_pkt[TCP].ack,
            ack=fin_pkt[TCP].seq + 1,
            flags="A",
            window=8192
        )
        
        final_pkt = eth / ip / final_ack
        sendp(final_pkt, iface=interfaz, verbose=False)
        print(f"    → ACK final enviado")
        print(f"    ✓ Conexión cerrada correctamente!")
    
    print("\n" + "=" * 80)
    print("REQUEST HTTP COMPLETADO EXITOSAMENTE")
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
    print("\n[INFO] Este script envía un request HTTP completo con handshake TCP")
    print("       manejado manualmente con Scapy.\n")
    
    print("[IMPORTANTE] Requiere permisos de root para:")
    print("             1. Enviar paquetes raw con Scapy")
    print("             2. Configurar regla de iptables")
    print("             Ejecuta: sudo python3 http_host_A.py\n")
    
    puerto = None
    try:
        # Generar puerto aleatorio
        puerto = random.randint(50000, 60000)
        
        # Configurar iptables ANTES de enviar paquetes
        if not configurar_iptables(puerto):
            print("\n[ERROR] No se pudo configurar iptables.")
            sys.exit(1)
        
        # Enviar el request HTTP usando el mismo puerto
        enviar_request_http(puerto)
        
    except KeyboardInterrupt:
        print("\n\n[*] Script interrumpido por el usuario.")
    except Exception as e:
        print(f"\n[ERROR] Error inesperado: {e}")
        import traceback
        traceback.print_exc()
    finally:
        # SIEMPRE limpiar iptables
        if puerto:
            limpiar_iptables(puerto)
        sys.exit(0)
