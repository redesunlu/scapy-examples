# Scapy-examples
## Ejemplos prácticos de Fundamentos de Redes

Este repositorio contiene 3 pares de scripts Python que utilizan Scapy para generar tráfico de red a diferentes niveles del modelo OSI/TCP-IP. Son ideales para laboratorios de Fundamentos de Redes donde los estudiantes pueden capturar y analizar el tráfico con tcpdump/tshark o Wireshark.

**Todos los ejemplos deben ejecutarse dentro de contenedores Docker** para garantizar un entorno aislado, reproducible y sin necesidad de permisos de administrador en la máquina host.

## 📋 Contenido

### 1. Intercambio de Tramas Ethernet (Capa 2)
- **`ethernet_host_A.py`**: Envía tramas Ethernet personalizadas
- **`ethernet_host_B.py`**: Recibe y analiza tramas Ethernet

**Conceptos cubiertos**: Direcciones MAC, EtherType, encapsulación de capa 2

### 2. Intercambio de Paquetes IP (Capa 3)
- **`ip_host_A.py`**: Envía paquetes IP sobre Ethernet
- **`ip_host_B.py`**: Recibe y analiza paquetes IP

**Conceptos cubiertos**: Direcciones IP, TTL, protocolo, flags de fragmentación, encapsulación IP

### 3. Intercambio de Request HTTP (Capas 2-7)
- **`http_host_A.py`**: Envía request HTTP completo (GET)
- **`http_host_B.py`**: Recibe y analiza requests HTTP

**Conceptos cubiertos**: Stack completo TCP/IP, puertos TCP, flags TCP, headers HTTP, encapsulación completa

## Requisitos Previos

### Instalar Docker y Docker Compose
Nota: Si ya tenés [Kathará](https://www.kathara.org/) instalado para los laboratorios de la cátedra, podés saltear este paso.

**macOS**:
```bash
brew install --cask docker
# O descargar Docker Desktop desde docker.com
```

**Linux (Ubuntu/Debian)**:
```bash
# Docker
curl -fsSL https://get.docker.com -o get-docker.sh
sudo sh get-docker.sh
sudo usermod -aG docker $USER

# Docker Compose
sudo apt-get install docker-compose-plugin
```

**Windows**:
- Descargar e instalar Docker Desktop desde [docker.com](https://www.docker.com/products/docker-desktop/)

Verificar instalación:
```bash
docker --version
docker compose version
```

### Wireshark (Opcional para análisis local)

Para analizar capturas guardadas en tu máquina local:
- **macOS**: `brew install --cask wireshark`
- **Linux**: `sudo apt install wireshark` o `sudo yum install wireshark`
- **Windows**: Descargar desde [wireshark.org](https://www.wireshark.org/)

## Inicio Rápido

### 1. Construir las imágenes

```bash
# Desde el directorio del proyecto
docker compose build
```

### 2. Iniciar el laboratorio

```bash
# Iniciar todos los contenedores
docker compose up -d

# Verificar que estén corriendo
docker compose ps
```

### 3. Acceder a los contenedores

```bash
# Acceder a Host A
docker exec -it lab_host_a bash

# Acceder a Host B (en otra terminal)
docker exec -it lab_host_b bash

# Acceder a Host C (opcional, en otra terminal)
docker exec -it lab_host_c bash
```

### 4. Capturar tráfico desde el host

**Método recomendado**: Usar el script `capturar_trafico.sh` desde tu máquina (fuera de Docker):

```bash
# En una terminal separada, desde el directorio del proyecto
./capturar_trafico.sh              # Guardará con timestamp
./capturar_trafico.sh ethernet     # Guardará como capturas/ethernet.pcap
./capturar_trafico.sh mi_prueba    # Guardará como capturas/mi_prueba.pcap
```

Este script captura **todo el tráfico** entre los contenedores desde el bridge Docker (`br-scapy-lab`), permitiendo ver la comunicación completa entre hosts.

**Método alternativo** (captura manual):
```bash
# Capturar todo el tráfico del bridge
sudo tcpdump -i br-scapy-lab -w capturas/trafico.pcap -v

# O con tshark
sudo tshark -i br-scapy-lab -w capturas/trafico.pcap
```

### 5. Ejecutar los scripts

**En Host B (terminal 1)**:
```bash
# Ver interfaz de red
ifconfig eth0

# Ejecutar receptor (no requiere sudo en Docker)
python3 ethernet_host_B.py
```

**En Host A (terminal 2)**:
```bash
# Ejecutar emisor
python3 ethernet_host_A.py
```

### 6. Analizar capturas

```bash
# Detener la captura con Ctrl+C

# Ver con tcpdump
tcpdump -r capturas/ethernet.pcap -A

# O abrir con Wireshark
wireshark capturas/ethernet.pcap
```

### 7. Detener el laboratorio

```bash
# Detener contenedores
docker compose down

# Detener y eliminar volúmenes
docker compose down -v
```

## Arquitectura del Laboratorio

```
┌─────────────────────────────────────────────┐
│         Red: 192.168.100.0/24               │
│         Bridge: br-scapy-lab                │
│                                             │
│  ┌──────────┐  ┌──────────┐  ┌──────────┐  │
│  │ Host A   │  │ Host B   │  │ Host C   │  │
│  │ .10      │  │ .20      │  │ .30      │  │
│  │ Sender   │  │ Receiver │  │ Optional │  │
│  └──────────┘  └──────────┘  └──────────┘  │
│                                             │
└─────────────────────────────────────────────┘
           ↓ Captura desde el host
    ┌─────────────────┐
    │ br-scapy-lab    │
    │ (Docker Bridge) │
    └─────────────────┘
           ↓
    capturar_trrafico.sh
```

**Ventaja de capturar desde el host**: El bridge Docker (`br-scapy-lab`) ve **todo** el tráfico entre contenedores, a diferencia de capturar desde dentro de un contenedor donde solo se ve el tráfico destinado a ese contenedor específico.

## Configuración del Entorno Docker

### Direcciones Configuradas

| Host    | IP            | MAC               | Rol        |
|---------|---------------|-------------------|------------|
| Host A  | 192.168.100.10| 02:42:ac:11:00:10 | Emisor     |
| Host B  | 192.168.100.20| 02:42:ac:11:00:20 | Receptor   |
| Host C  | 192.168.100.30| 02:42:ac:11:00:30 | Opcional   |

### Scripts Pre-configurados para Docker

Los scripts ya están configurados con los valores correctos para el entorno Docker:

**Scripts Ethernet** (`ethernet_host_A.py`, `ethernet_host_B.py`):
```python
interfaz = "eth0"  # En Docker siempre es eth0
mac_origen = "02:42:ac:11:00:10"     # MAC de Host A
mac_destino = "02:42:ac:11:00:20"    # MAC de Host B
```

**Scripts IP y HTTP** (`ip_host_*.py`, `http_host_*.py`):
```python
interfaz = "eth0"
ip_origen = "192.168.100.10"         # IP de Host A
ip_destino = "192.168.100.20"        # IP de Host B
```

## Ejercicios Prácticos

### Ejercicio 1: Tramas Ethernet

**Objetivo**: Comprender la estructura de una trama Ethernet y los campos de capa 2.

**Pasos**:

```bash
# Terminal 1: Iniciar captura desde el host
./capturar_trafico.sh ethernet

# Terminal 2: Host B (receptor)
docker exec -it lab_host_b bash
python3 ethernet_host_B.py

# Terminal 3: Host A (emisor)
docker exec -it lab_host_a bash
python3 ethernet_host_A.py

# Detener captura (Ctrl+C en terminal 1)
# Analizar
wireshark capturas/ethernet.pcap
```

**Análisis**:
- Observar la dirección MAC de origen y destino
- Ver el campo EtherType (0x9000 en este caso)
- Analizar el payload en hexadecimal y ASCII
- Comparar salida del script con la captura

### Ejercicio 2: Paquetes IP

**Objetivo**: Entender el encapsulado IP sobre Ethernet.

**Pasos**:

```bash
# Terminal 1: Captura
./capturar_trafico.sh ip

# Terminal 2: Host B
docker exec -it lab_host_b bash
python3 ip_host_B.py

# Terminal 3: Host A
docker exec -it lab_host_a bash
python3 ip_host_A.py

# Analizar con tshark o Wireshark
tshark -r capturas/ip.pcap -Y "ip.addr == 192.168.100.10"
```

**Análisis**:
- Ver cómo Ethernet encapsula IP (EtherType = 0x0800)
- Analizar campos IP: versión, TTL, protocolo, flags
- Observar el checksum de IP
- Experimentar cambiando el TTL y flags

### Ejercicio 3: Request HTTP

**Objetivo**: Comprender el stack completo TCP/IP y la capa de aplicación.

**Pasos**:

```bash
# Terminal 1: Captura
./capturar_trafico.sh http

# Terminal 2: Host B
docker exec -it lab_host_b bash
python3 http_host_B.py

# Terminal 3: Host A
docker exec -it lab_host_a bash
python3 http_host_A.py

# Analizar
wireshark capturas/http.pcap
```

**Análisis**:
- Ver todas las capas: Ethernet → IP → TCP → HTTP
- Analizar puertos TCP (origen alto, destino 80)
- Observar flags TCP (PSH, ACK)
- Leer los headers HTTP (Host, User-Agent, etc.)
- Usar "Follow TCP Stream" en Wireshark

### Ejercicio 4: Análisis Comparativo

```bash
# Capturar múltiples escenarios
./capturar_trafico.sh escenario1
# ... ejecutar scripts ...

./capturar_trafico.sh escenario2
# ... ejecutar scripts con cambios ...

# Comparar capturas
tcpdump -r capturas/escenario1.pcap -A > escenario1.txt
tcpdump -r capturas/escenario2.pcap -A > escenario2.txt
diff escenario1.txt escenario2.txt
```

## Script de Captura: capturar_trafico.sh

### Uso

```bash
# Sintaxis
./capturar_trafico.sh [nombre_archivo]

# Ejemplos
./capturar_trrafico.sh                    # Guarda con timestamp automático
./capturar_trafico.sh ethernet           # Guarda como capturas/ethernet.pcap
./capturar_trafico.sh prueba_tcp         # Guarda como capturas/prueba_tcp.pcap
./capturar_trafico.sh laboratorio_http   # Guarda como capturas/laboratorio_http.pcap
```

### Características

- ✅ Captura desde el bridge Docker (ve todo el tráfico)
- ✅ Verifica que el bridge exista antes de capturar
- ✅ Crea el directorio `capturas/` automáticamente
- ✅ Permite nombre personalizado o usa timestamp
- ✅ Muestra comandos útiles para análisis posterior
- ✅ Requiere `sudo` (solo para captura, no afecta contenedores)

### Salida del Script

```bash
$ ./capturar_trafico.sh mi_captura
==========================================
CAPTURA DE TRÁFICO DEL LABORATORIO
==========================================
Bridge:      br-scapy-lab
Archivo:     capturas/mi_captura.pcap
Directorio:  /Users/usuario/scapy-examples/capturas

Capturando tráfico... (Ctrl+C para detener)

tcpdump: listening on br-scapy-lab, link-type EN10MB (Ethernet), snapshot length 262144 bytes
^C15 packets captured
15 packets received by filter
0 packets dropped by kernel

✓ Captura guardada en: capturas/mi_captura.pcap

Para analizar el archivo:
  tcpdump -r capturas/mi_captura.pcap
  tshark -r capturas/mi_captura.pcap
  wireshark capturas/mi_captura.pcap
```

## Actividades Sugeridas para Estudiantes

1. **Modificar campos de cada capa**:
   - Cambiar direcciones MAC/IP en los scripts
   - Modificar TTL y observar su efecto
   - Cambiar puertos TCP
   - Agregar/modificar headers HTTP

2. **Experimentar con diferentes configuraciones**:
   - Usar broadcast vs unicast
   - Probar diferentes EtherTypes
   - Cambiar flags TCP (SYN, FIN, RST)
   - Enviar POST en vez de GET

3. **Análisis comparativo**:
   - Comparar salida del script Python con capturas de tshark/tcpdump
   - Verificar checksums
   - Calcular tamaños de cabeceras
   - Identificar campos automáticos vs manuales

4. **Troubleshooting**:
   - ¿Qué pasa si la MAC destino es incorrecta?
   - ¿Qué pasa si la IP no existe en la red?
   - ¿Cómo afecta el TTL al ruteo?
   - ¿Por qué algunos campos se calculan automáticamente?

## Comandos Útiles de Docker

### Gestión de Contenedores

```bash
# Ver logs de un contenedor
docker compose logs host_a

# Ver logs en tiempo real
docker compose logs -f host_b

# Reiniciar un contenedor
docker compose restart host_a

# Ejecutar comando sin entrar al contenedor
docker exec lab_host_a python3 ethernet_host_A.py
```

### Inspección de Red

```bash
# Inspeccionar la red
docker network inspect scapy_lab_network

# Ver interfaces dentro de un contenedor
docker exec lab_host_a ifconfig

# Ver rutas
docker exec lab_host_a ip route

# Probar conectividad
docker exec lab_host_a ping -c 4 192.168.100.20

# Ver el bridge desde el host
ip link show br-scapy-lab
```

### Limpieza

```bash
# Detener todo
docker compose down

# Eliminar imágenes
docker compose down --rmi all

# Eliminar volúmenes y capturas
docker compose down -v

# Limpiar sistema Docker completo
docker system prune -a
```

## Ventajas del Entorno Docker

✅ **No requiere sudo**: Docker gestiona los privilegios internamente (excepto para captura en host)  
✅ **Aislamiento total**: No afecta la red del host  
✅ **Reproducible**: Mismo entorno en cualquier máquina  
✅ **MACs/IPs fijas**: Facilita los ejercicios de laboratorio  
✅ **Múltiples hosts**: Simula una red completa  
✅ **Fácil reset**: `docker compose down && docker compose up -d`  
✅ **Capturas centralizadas**: Carpeta `./capturas` compartida  
✅ **Sin conflictos**: Cada estudiante puede tener su propio entorno  
✅ **Visibilidad completa**: Captura desde el bridge ve todo el tráfico  

## Referencias

- **Scapy Documentation**: https://scapy.readthedocs.io/
- **Docker Documentation**: https://docs.docker.com/
- **Docker Compose**: https://docs.docker.com/compose/
- **Docker Networking**: https://docs.docker.com/network/
- **Wireshark User Guide**: https://www.wireshark.org/docs/wsug_html_chunked/
- **TCP/IP Protocol Suite**: RFC 791 (IP), RFC 793 (TCP), RFC 2616 (HTTP)

## Troubleshooting

### Problema: Script de captura no encuentra el bridge

**Solución**: Verificar que los contenedores estén corriendo:
```bash
docker compose ps
docker network ls | grep scapy
ip link show | grep br-scapy-lab  # En Linux/Mac
```

### Problema: No se puede capturar tráfico (permiso denegado)

**Solución**: El script requiere `sudo` para capturar en el bridge:
```bash
sudo ./capturar_trafico.sh mi_captura
```

### Problema: No hay comunicación entre contenedores

**Solución**: Verificar conectividad:
```bash
docker exec lab_host_a ping 192.168.100.20
docker network inspect scapy_lab_network
```

### Problema: Scripts fallan al enviar paquetes

**Solución**: Verificar interfaz (debe ser `eth0` en Docker):
```bash
docker exec lab_host_a ifconfig
# Modificar scripts si es necesario
```

### Problema: Capturas vacías o incompletas

**Solución**: 
1. Asegurarse de iniciar la captura **antes** de ejecutar los scripts
2. Verificar que el bridge esté activo: `ip link show br-scapy-lab`
3. Usar el script `capturar_trafico.sh` en lugar de capturar manualmente

### Problema: Contenedores no inician

**Solución**: Verificar que Docker esté corriendo y reconstruir:
```bash
docker compose down
docker compose build --no-cache
docker compose up -d
```

## Escenarios Avanzados

### Escenario 1: Múltiples Redes

Modificar `docker-compose.yaml` para crear múltiples redes y simular routing:

```yaml
networks:
  red_a:
    ipam:
      config:
        - subnet: 192.168.100.0/24
  
  red_b:
    ipam:
      config:
        - subnet: 192.168.200.0/24

services:
  router:
    networks:
      - red_a
      - red_b
```

### Escenario 2: Limitación de Ancho de Banda

```bash
# Dentro del contenedor
tc qdisc add dev eth0 root tbf rate 1mbit burst 32kbit latency 400ms
```

### Escenario 3: Simulación de Pérdida de Paquetes

```bash
# Simular 10% de pérdida de paquetes
tc qdisc add dev eth0 root netem loss 10%
```

## Tips para Instructores

1. **Pre-construir imágenes**: Distribuir imágenes Docker pre-construidas para ahorrar tiempo
2. **Docker Hub**: Subir la imagen a Docker Hub para fácil distribución
3. **Scripts automatizados**: El script `capturar_trafico.sh` simplifica la captura para estudiantes
4. **Capturas pre-generadas**: Proporcionar archivos .pcap de ejemplo para análisis offline
5. **Nomenclatura consistente**: Usar nombres descriptivos para capturas (ethernet.pcap, tcp.pcap, etc.)
6. **Jupyter Notebooks**: Integrar con Jupyter para análisis interactivo
7. **CI/CD**: Usar GitHub Actions para validar scripts automáticamente

## Notas Importantes

1. **Uso Responsable**: Estos scripts son para fines educativos en entornos controlados de laboratorio.

2. **Aislamiento**: El entorno Docker aísla completamente el tráfico de la red del host, haciéndolo seguro para experimentar.

3. **Portabilidad**: Los scripts y configuraciones funcionan igual en cualquier sistema operativo con Docker instalado.

4. **Capturas Compartidas**: El directorio `./capturas` es accesible tanto desde el host como desde los contenedores.

5. **Permisos de Captura**: Solo la captura desde el host (usando `capturar_trafico.sh`) requiere `sudo`. Los scripts dentro de los contenedores no lo necesitan.

## Licencia

Ver archivo `LICENSE` para detalles.

## Contribuciones

Este material es para uso educativo. Sugerencias y mejoras son bienvenidas.
