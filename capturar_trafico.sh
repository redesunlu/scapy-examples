#!/bin/bash
# Script para capturar todo el tráfico entre contenedores
# ========================================================

BRIDGE="br-scapy-lab"
CAPTURE_DIR="capturas"

# Determinar nombre del archivo
if [ -z "$1" ]; then
    # Si no se proporciona nombre, usar timestamp
    TIMESTAMP=$(date +%Y%m%d_%H%M%S)
    FILENAME="trafico_${TIMESTAMP}.pcap"
else
    # Usar el nombre proporcionado y agregar .pcap si no lo tiene
    if [[ "$1" == *.pcap ]]; then
        FILENAME="$1"
    else
        FILENAME="${1}.pcap"
    fi
fi

OUTPUT="${CAPTURE_DIR}/${FILENAME}"

# Crear directorio si no existe
mkdir -p "$CAPTURE_DIR"

# Verificar que el bridge existe
if ! ip link show "$BRIDGE" &> /dev/null; then
    echo " Error: Bridge $BRIDGE no encontrado"
    echo "  Asegúrate de que los contenedores estén corriendo:"
    echo "  docker compose up -d"
    exit 1
fi

echo "=========================================="
echo "CAPTURA DE TRÁFICO DEL LABORATORIO"
echo "=========================================="
echo "Bridge:      $BRIDGE"
echo "Archivo:     $OUTPUT"
echo "Directorio:  $(pwd)/$CAPTURE_DIR"
echo ""
echo "Capturando tráfico... (Ctrl+C para detener)"
echo ""

# Ejecutar tcpdump
sudo tcpdump -i "$BRIDGE" -w "$OUTPUT" -v

echo ""
echo "✓ Captura guardada en: $OUTPUT"
echo ""
echo "Para analizar el archivo:"
echo "  tcpdump -r $OUTPUT"
echo "  tshark -r $OUTPUT"
echo "  wireshark $OUTPUT"