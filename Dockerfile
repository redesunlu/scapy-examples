# Dockerfile para entorno de laboratorio de redes con Scapy
# ========================================================
# Imagen base con Python 3.11
FROM python:3.11-slim

# Metadata
LABEL maintainer="Labredes - UNLu"
LABEL description="Contenedor para experimentación con Scapy y análisis de protocolos de red"

# Variables de entorno
ENV PYTHONUNBUFFERED=1
ENV DEBIAN_FRONTEND=noninteractive

# Instalar dependencias del sistema necesarias para Scapy y captura de paquetes
RUN apt-get update && apt-get install -y \
    # Herramientas de red
    net-tools \
    iputils-ping \
    iproute2 \
    tcpdump \
    # Tshark para captura de paquetes (Wireshark CLI)
    tshark \
    # Editor de texto simple
    nano \
    vim \
    # Utilidades adicionales
    curl \
    wget \
    # Librerías necesarias para Scapy
    libpcap-dev \
    && rm -rf /var/lib/apt/lists/*

# Crear directorio de trabajo
WORKDIR /lab

# Copiar requirements.txt e instalar dependencias Python
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copiar todos los scripts del laboratorio
COPY *.py ./

# Dar permisos de ejecución a todos los scripts Python
RUN chmod +x *.py

# Script de ayuda para estudiantes
RUN echo '#!/bin/bash\n\
    echo "================================================="\n\
    echo "  LABORATORIO DE REDES CON SCAPY"\n\
    echo "================================================="\n\
    echo ""\n\
    echo "Scripts disponibles:"\n\
    echo "  1. Capa 2 (Ethernet):"\n\
    echo "     - python3 ethernet_host_A.py"\n\
    echo "     - python3 ethernet_host_B.py"\n\
    echo ""\n\
    echo "  2. Capa 3 (IP):"\n\
    echo "     - python3 ip_host_A.py"\n\
    echo "     - python3 ip_host_B.py"\n\
    echo ""\n\
    echo "  3. Capas 2-7 (HTTP):"\n\
    echo "     - python3 http_host_A.py"\n\
    echo "     - python3 http_host_B.py"\n\
    echo ""\n\
    echo "Herramientas de red disponibles:"\n\
    echo "  - ifconfig          : Ver interfaces de red"\n\
    echo "  - ip addr           : Ver direcciones IP"\n\
    echo "  - ping <host>       : Probar conectividad"\n\
    echo "  - tcpdump           : Capturar paquetes"\n\
    echo "  - tshark            : Wireshark en línea de comandos"\n\
    echo ""\n\
    echo "Ejemplos de captura:"\n\
    echo "  tcpdump -i eth0 -n"\n\
    echo "  tshark -i eth0"\n\
    echo ""\n\
    echo "================================================="\n\
    ' > /usr/local/bin/help.sh && chmod +x /usr/local/bin/help.sh

# Exponer el script de ayuda al iniciar
RUN echo "help.sh" >> /root/.bashrc

# Mantener el contenedor activo
CMD ["/bin/bash"]
