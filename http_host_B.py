#!/usr/bin/env python3
"""
Script Host B - Servidor HTTP Simple con TCP Completo (Capa 7)
==============================================================
Este script actúa como un servidor TCP que:
1. Responde al handshake TCP (SYN-ACK)
2. Recibe el request HTTP
3. Envía ACK de confirmación
4. Responde al cierre de conexión (FIN-ACK)

Analiza y muestra todas las capas del modelo OSI/TCP-IP:
- Capa 2 (Ethernet): direcciones MAC, EtherType
- Capa 3 (IP): direcciones IP, TTL, flags, protocolo
- Capa 4 (TCP): handshake, puertos, flags, números de secuencia, ventana
- Capa 7 (HTTP): método, URI, versión, headers, body

NOTA TÉCNICA: Problema del RST
===============================
Cuando usamos Scapy para manejar TCP manualmente, el kernel del sistema operativo
también ve los paquetes que llegan. Como NO hay un programa real escuchando en
el puerto 80, el kernel automáticamente envía un paquete RST (Reset) para
rechazar la conexión.

Solución: Usar iptables para bloquear los paquetes RST que envía el kernel.
Esto permite que Scapy maneje toda la comunicación TCP sin interferencia.

Ideal para que los estudiantes comprendan el flujo TCP completo
y puedan comparar la salida del script con lo que ven en Wireshark.
"""

from scapy.all import Ether, IP, TCP, Raw, sendp, sniff, conf
import sys
import subprocess
import random

conf.verb = 0  # Reducir verbosidad

def configurar_iptables(puerto=80):
    """
    Configura iptables para bloquear paquetes RST del kernel.
    
    ¿Por qué necesitamos esto?
    - El kernel ve el paquete SYN que llega al puerto 80
    - Como no hay un servidor real (solo Scapy), envía RST
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
        print(f"    ✓ Regla iptables aplicada")
        print(f"    ✓ El kernel ya NO enviará RST")
        return True
    except subprocess.CalledProcessError:
        print(f"    ✗ Error al configurar iptables")
        print(f"    [TIP] Ejecuta con sudo: sudo python3 http_host_B.py")
        return False
    except FileNotFoundError:
        print(f"    ✗ iptables no encontrado en el sistema")
        return False

def limpiar_iptables(puerto=80):
    """
    Elimina la regla de iptables al finalizar el script.
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

# Diccionario para mantener estado de conexiones
conexiones = {}

def enviar_respuesta(pkt, tcp_flags, payload=None, server_seq=None):
    """
    Envía una respuesta TCP al cliente.
    
    Args:
        pkt: Paquete recibido
        tcp_flags: Flags TCP para la respuesta
        payload: Datos opcionales
        server_seq: Número de secuencia del servidor (para SYN-ACK)
    """
    # Intercambiar origen y destino
    eth = Ether(src=pkt[Ether].dst, dst=pkt[Ether].src)
    ip = IP(src=pkt[IP].dst, dst=pkt[IP].src, ttl=64)
    
    # Para SYN-ACK necesitamos un seq inicial aleatorio
    if tcp_flags == "SA":
        if server_seq is None:
            server_seq = 0  # Número de secuencia inicial del servidor
        seq_num = server_seq
        ack_num = pkt[TCP].seq + 1  # ACK del SYN del cliente
    else:
        # Para otros paquetes, usar el esquema normal
        seq_num = pkt[TCP].ack
        payload_len = len(pkt[TCP].payload) if pkt[TCP].payload else 0
        # Solo sumar 1 si hay flags especiales (SYN o FIN)
        if "S" in str(pkt[TCP].flags) or "F" in str(pkt[TCP].flags):
            ack_num = pkt[TCP].seq + payload_len + 1
        else:
            ack_num = pkt[TCP].seq + payload_len if payload_len > 0 else pkt[TCP].seq
    
    # Intercambiar puertos y ajustar seq/ack
    tcp = TCP(
        sport=pkt[TCP].dport,
        dport=pkt[TCP].sport,
        seq=seq_num,
        ack=ack_num,
        flags=tcp_flags,
        window=8192
    )
    
    if payload:
        respuesta = eth / ip / tcp / Raw(load=payload)
    else:
        respuesta = eth / ip / tcp
    
    sendp(respuesta, iface=pkt.sniffed_on, verbose=False)
    return respuesta

def mostrar_paquete(pkt, titulo):
    """
    Muestra información detallada del paquete.
    """
    print(f"\n{'─' * 80}")
    print(f"[{titulo}]")
    print(f"{'─' * 80}")
    
    if Ether in pkt:
        print(f"[CAPA 2 - ETHERNET]")
        print(f"  MAC Origen:  {pkt[Ether].src}")
        print(f"  MAC Destino: {pkt[Ether].dst}")
    
    if IP in pkt:
        print(f"\n[CAPA 3 - IP]")
        print(f"  IP Origen:   {pkt[IP].src}")
        print(f"  IP Destino:  {pkt[IP].dst}")
        print(f"  TTL:         {pkt[IP].ttl}")
        print(f"  Protocolo:   {pkt[IP].proto} (TCP)")
    
    if TCP in pkt:
        flags_desc = {
            'S': 'SYN', 'A': 'ACK', 'F': 'FIN', 
            'P': 'PSH', 'R': 'RST', 'U': 'URG'
        }
        flags = str(pkt[TCP].flags)
        flags_nombres = [flags_desc.get(f, f) for f in flags]
        
        print(f"\n[CAPA 4 - TCP]")
        print(f"  Puerto Origen:  {pkt[TCP].sport}")
        print(f"  Puerto Destino: {pkt[TCP].dport}")
        print(f"  SEQ Number:     {pkt[TCP].seq}")
        print(f"  ACK Number:     {pkt[TCP].ack}")
        print(f"  Flags:          {flags} [{', '.join(flags_nombres)}]")
        print(f"  Window Size:    {pkt[TCP].window}")
        
        if pkt[TCP].payload:
            print(f"  Payload:        {len(pkt[TCP].payload)} bytes")

def procesar_paquete(pkt):
    """
    Procesa cada paquete TCP y responde apropiadamente.
    """
    if not (Ether in pkt and IP in pkt and TCP in pkt):
        return
    
    # Identificador de conexión
    conn_id = (pkt[IP].src, pkt[TCP].sport, pkt[IP].dst, pkt[TCP].dport)
    
    # ===== HANDSHAKE: SYN =====
    if pkt[TCP].flags == "S":
        print("\n" + "=" * 80)
        print("NUEVA CONEXIÓN TCP - INICIANDO HANDSHAKE")
        print("=" * 80)
        mostrar_paquete(pkt, "1/7 RECIBIDO: SYN")
        
        # Generar número de secuencia inicial del servidor
        server_seq_inicial = 0  # Podría ser random.randint(1000, 10000)
        
        # Responder con SYN-ACK
        print(f"\n[2/7 ENVIANDO: SYN-ACK]")
        syn_ack = enviar_respuesta(pkt, "SA", server_seq=server_seq_inicial)
        print(f"  → SYN-ACK enviado [SEQ={syn_ack[TCP].seq}, ACK={syn_ack[TCP].ack}]")
        
        # Guardar estado de conexión con el SEQ correcto
        conexiones[conn_id] = {
            'seq': syn_ack[TCP].seq + 1,  # Próximo seq del servidor
            'ack': syn_ack[TCP].ack,       # Lo que esperamos del cliente
            'estado': 'SYN_RECEIVED'
        }
    
    # ===== HANDSHAKE: ACK (Conexión establecida) =====
    elif pkt[TCP].flags == "A" and conn_id in conexiones and conexiones[conn_id]['estado'] == 'SYN_RECEIVED':
        mostrar_paquete(pkt, "3/7 RECIBIDO: ACK")
        print(f"\n  ✓ Conexión TCP establecida!")
        print(f"    Cliente: {pkt[IP].src}:{pkt[TCP].sport}")
        print(f"    Servidor: {pkt[IP].dst}:{pkt[TCP].dport}")
        
        conexiones[conn_id]['estado'] = 'ESTABLISHED'
    
    # ===== DATOS: PSH+ACK (Request HTTP) =====
    elif "P" in str(pkt[TCP].flags) and pkt[TCP].payload:
        mostrar_paquete(pkt, "4/7 RECIBIDO: PSH-ACK (HTTP REQUEST)")
        
        # Decodificar HTTP
        try:
            http_data = bytes(pkt[TCP].payload).decode('utf-8', errors='ignore')
            print(f"\n[CAPA 7 - HTTP]")
            print(f"{'─' * 80}")
            
            # Parsear HTTP request
            if '\r\n' in http_data:
                lineas = http_data.split('\r\n')
                primera_linea = lineas[0]
                
                # Request line
                if ' ' in primera_linea:
                    partes = primera_linea.split(' ', 2)
                    if len(partes) >= 2:
                        metodo = partes[0]
                        uri = partes[1]
                        version = partes[2] if len(partes) == 3 else ''
                        
                        print(f"Request Line: {primera_linea}")
                        print(f"  → Método:  {metodo}")
                        print(f"  → URI:     {uri}")
                        print(f"  → Versión: {version}")
                
                # Headers
                print(f"\nHTTP Headers:")
                for i, linea in enumerate(lineas[1:], 1):
                    if linea.strip():
                        print(f"  {i}. {linea}")
                    else:
                        break
            
            print(f"{'─' * 80}")
            print(f"\nPayload completo ({len(http_data)} bytes):")
            print(http_data)
            print(f"{'─' * 80}")
            
        except Exception as e:
            print(f"  (No se pudo decodificar como HTTP: {e})")
        
        # Responder con ACK
        print(f"\n[5/7 ENVIANDO: ACK]")
        ack = enviar_respuesta(pkt, "A")
        print(f"  → ACK enviado [ACK={ack[TCP].ack}]")
        print(f"  ✓ Datos HTTP recibidos y confirmados!")
        
        if conn_id in conexiones:
            conexiones[conn_id]['ack'] = ack[TCP].ack
    
    # ===== CIERRE: FIN+ACK =====
    elif "F" in str(pkt[TCP].flags):
        mostrar_paquete(pkt, "6/7 RECIBIDO: FIN-ACK")
        print(f"\n  Cliente solicita cerrar conexión...")
        
        # Responder con FIN-ACK
        print(f"\n[7/7 ENVIANDO: FIN-ACK]")
        fin_ack = enviar_respuesta(pkt, "FA")
        print(f"  → FIN-ACK enviado [SEQ={fin_ack[TCP].seq}, ACK={fin_ack[TCP].ack}]")
        
        # Esperar ACK final del cliente (se recibirá automáticamente)
        print(f"  ✓ Conexión TCP cerrada!")
        
        # Limpiar estado
        if conn_id in conexiones:
            del conexiones[conn_id]
        
        print("\n" + "=" * 80)
        print("CONEXIÓN CERRADA CORRECTAMENTE")
        print("=" * 80)
        print(f"""
Flujo TCP completado:
  1. ← SYN        (Cliente inicia)
  2. → SYN-ACK    (Servidor acepta)
  3. ← ACK        (Conexión establecida)
  4. ← PSH-ACK    (Cliente envía HTTP)
  5. → ACK        (Servidor confirma)
  6. ← FIN-ACK    (Cliente cierra)
  7. → FIN-ACK    (Servidor confirma cierre)
  8. ← ACK        (Cierre completo)
        """)

def servidor_http():
    """
    Inicia el servidor HTTP que responde a conexiones TCP.
    """
    print("=" * 80)
    print("HOST B - SERVIDOR HTTP CON TCP COMPLETO")
    print("=" * 80)
    
    interfaz = "eth0"
    puerto = 80
    
    # IMPORTANTE: Configurar iptables ANTES de empezar
    if not configurar_iptables(puerto):
        print("\n[ERROR] No se pudo configurar iptables.")
        print("        Este script requiere permisos de root.")
        return
    
    print(f"\n[*] Configuración:")
    print(f"    - Interfaz: {interfaz}")
    print(f"    - Puerto: {puerto}")
    print(f"    - Protocolo: HTTP sobre TCP (Scapy manual)")
    
    print(f"\n[*] Servidor escuchando en puerto {puerto}...")
    print("[*] Esperando conexiones TCP...")
    print("[*] Presionar Ctrl+C para detener\n")
    
    try:
        sniff(
            prn=procesar_paquete,
            filter=f"tcp port {puerto}",
            iface=interfaz,
            store=0
        )
    except Exception as e:
        print(f"\n[ERROR] Error: {e}")
        sys.exit(1)

if __name__ == "__main__":
    print("\n[INFO] Este script implementa un servidor TCP/HTTP básico usando Scapy")
    print("       para manejar manualmente el protocolo TCP.\n")
    
    print("[IMPORTANTE] Requiere permisos de root para:")
    print("             1. Capturar paquetes con Scapy")
    print("             2. Configurar regla de iptables")
    print("             Ejecuta: sudo python3 http_host_B.py\n")
    
    print("[INFO] Guía para el laboratorio:")
    print("       1. Iniciar este script en Host B: sudo python3 http_host_B.py")
    print("       2. Abrir Wireshark/tcpdump en el Monitor")
    print("       3. Aplicar filtro: tcp.port == 80")
    print("       4. Ejecutar http_host_A.py en Host A")
    print("       5. Observar el flujo TCP completo:")
    print("          - Handshake (SYN, SYN-ACK, ACK)")
    print("          - Transferencia de datos (PSH-ACK)")
    print("          - Cierre (FIN-ACK, FIN-ACK, ACK)")
    print("       6. Comparar los números de secuencia y ACK")
    print("       7. Usar 'Follow TCP Stream' en Wireshark\n")
    
    try:
        servidor_http()
    except KeyboardInterrupt:
        print("\n\n[*] Servidor detenido por el usuario.")
    finally:
        limpiar_iptables()
        print("[*] Limpieza completada. Adiós!")
        sys.exit(0)
