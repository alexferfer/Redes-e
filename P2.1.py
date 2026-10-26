# =============================================================================
# CHULETA COMPLETA Y CÓDIGO LISTO PARA COPIAR Y PEGAR - PRÁCTICA 2 (ETHERNET Y ARP)
# =============================================================================
# ÍNDICE DE ESTE ARCHIVO:
#   SECCIÓN 0: Comandos de Terminal, Mininet, Ejecutable del Profesor y Wireshark
#   SECCIÓN 1: Las 6 Modificaciones Típicas de Examen (listas para copiar y pegar)
#   SECCIÓN 2: Código completo de ethernet.py (con fix de registerCallback)
#   SECCIÓN 3: Código completo de ethmsg.py
#   SECCIÓN 4: Código completo de arp.py (con fix de orden en initARP)
#   SECCIÓN 5: Código completo de practica2.py
# =============================================================================


# =============================================================================
# SECCIÓN 0: COMANDOS DE TERMINAL, MININET Y WIRESHARK
# =============================================================================
"""
1. ANTES DE ENTRAR A MININET (Terminal de Linux):
   cd ~/Desktop/practica2_1322_P01
   chmod +x nombre_ejecutable
   sudo mn -c
   sudo mn --nat

2. DENTRO DE MININET (mininet>):
   xterm h1 h2
   xterm h1 h1 h2     # (Si quieres 2 terminales en h1 y 1 en h2)
   exit               # (Para salir al terminar)

3. DENTRO DE LAS VENTANAS XTERM DE h1 Y h2:
   ifconfig                         # Ver IP y MAC
   ifconfig h2-eth0 10.0.0.1        # Cambiar IP de h2 (para prueba de conflicto de IP)
   ifconfig h2-eth0 10.0.0.2        # Restaurar IP original de h2
   wireshark &                      # Abrir Wireshark en segundo plano (elegir h1-eth0 o h2-eth0, NO 'any')
   python3 practica2.py --itf h1-eth0
   python3 practica2.py --itf h2-eth0
   ./nombre_ejecutable -h           # Ver ayuda del ejecutable del profesor
   ./nombre_ejecutable --itf h2-eth0

4. FILTROS DE WIRESHARK:
   arp
   eth.type == 0x0aa0
   arp or eth.type == 0x0aa0
"""


# =============================================================================
# SECCIÓN 1: LAS 6 MODIFICACIONES TÍPICAS DE EXAMEN (COPIAR Y PEGAR)
# =============================================================================

# -----------------------------------------------------------------------------
# MODIFICACIÓN 1: Enviar mensaje 'm' en UNICAST a una IP concreta usando ARP
#                 Formato por consola: m <IP> <mensaje> (ej: m 10.0.0.2 Hola)
# -----------------------------------------------------------------------------

# 1A) En ethmsg.py -> Pegar arriba del archivo:
from arp import ARPResolution

# 1B) En ethmsg.py -> Reemplazar sendEthMsg por esta versión que recibe (ip, message):
def sendEthMsg_unicast(ip: int, message: bytes) -> bytes:
    dstMac = ARPResolution(ip)
    if dstMac is None:
        logging.error('sendEthMsg: No se pudo resolver la MAC para la IP indicada')
        print('Error: No se pudo resolver la MAC destino')
        return None

    if isinstance(message, str):
        msg_bytes = message.encode('utf-8')
    elif isinstance(message, bytes):
        msg_bytes = message
    else:
        msg_bytes = str(message).encode('utf-8')

    msg_len = len(msg_bytes)
    payload = struct.pack('!H', msg_len) + msg_bytes
    total_len = len(payload)

    ret = sendEthernetFrame(payload, total_len, ETHTYPE, dstMac)
    if ret == 0:
        return msg_len
    else:
        logging.error('sendEthMsg: Error al enviar la trama Ethernet')
        return None

# 1C) En practica2.py -> Reemplazar el bloque 'elif comando.startswith("m "):' por:
"""
            elif comando.startswith("m "):
                partes = comando.split(" ")
                if len(partes) < 3:
                    print("Formato incorrecto. Uso: m <IP> <mensaje>")
                else:
                    ipstr = partes[1]
                    mensaje = " ".join(partes[2:])
                    try:
                        ip = struct.unpack('!I', socket.inet_aton(ipstr))[0]
                        print(f"Enviando mensaje de {len(mensaje)} Bytes a {ipstr}: {mensaje}")
                        sendEthMsg(ip, mensaje)
                    except OSError:
                        print('Formato de IP incorrecta\n')
"""


# -----------------------------------------------------------------------------
# MODIFICACIÓN 2: Guardar en la caché ARP al recibir un ARP Request (en arp.py)
# -----------------------------------------------------------------------------

# En arp.py -> Reemplazar processARPRequest por esta versión:
def processARPRequest_con_cache(data: bytes, MAC: bytes) -> None:
    global myMAC, myIP

    if data[0:6] == ARPHeader:
        data = data[8:]
    if len(data) < 20:
        return

    senderMAC = data[0:6]
    senderIP = struct.unpack('!I', data[6:10])[0]
    targetMAC = data[10:16]
    targetIP = struct.unpack('!I', data[16:20])[0]

    if senderMAC != MAC:
        return
    if senderMAC == myMAC:
        return

    # Si piden guardar SIEMPRE aunque no sea para nuestra IP, descomentar aquí:
    # with cacheLock:
    #     cache[senderIP] = senderMAC

    if targetIP != myIP:
        return

    # Guardar en caché al emisor que pregunta por nuestra IP:
    with cacheLock:
        cache[senderIP] = senderMAC

    reply = createARPReply(senderIP, senderMAC)
    sendEthernetFrame(reply, len(reply), 0x0806, senderMAC)


# -----------------------------------------------------------------------------
# MODIFICACIÓN 3: Variantes de formato en ethmsg.py (Longitud 4B, ID extra, ignorar propios)
# -----------------------------------------------------------------------------

# 3A) Si la longitud ocupa 4 bytes (!I en vez de !H) en ethmsg.py:
def process_ethMsg_frame_4bytes(us, header, data: bytes, srcMac: bytes) -> None:
    if len(data) < 4:
        return
    msg_len = struct.unpack('!I', data[0:4])[0]
    msg_bytes = data[4:4 + msg_len]
    mensaje = msg_bytes.decode('utf-8', errors='ignore')
    mac_str = ':'.join(['{:02X}'.format(b) for b in srcMac])
    fecha_base = time.strftime('%Y/%m/%d %H:%M:%S', time.localtime(header.ts.tv_sec))
    timestamp_str = f"{fecha_base}.{header.ts.tv_usec:06d}"
    print(f"[{timestamp_str}] {mac_str} ({msg_len} bytes) : {mensaje}")

def sendEthMsg_4bytes(message: bytes) -> bytes:
    msg_bytes = message.encode('utf-8') if isinstance(message, str) else message
    msg_len = len(msg_bytes)
    payload = struct.pack('!I', msg_len) + msg_bytes
    ret = sendEthernetFrame(payload, len(payload), ETHTYPE, broadcast)
    return msg_len if ret == 0 else None

# 3B) Si lleva un campo ID de 2 bytes antes de la longitud (data[0:2]=ID, data[2:4]=len):
def process_ethMsg_frame_con_id(us, header, data: bytes, srcMac: bytes) -> None:
    if len(data) < 4:
        return
    msg_id = struct.unpack('!H', data[0:2])[0]
    msg_len = struct.unpack('!H', data[2:4])[0]
    msg_bytes = data[4:4 + msg_len]
    mensaje = msg_bytes.decode('utf-8', errors='ignore')
    mac_str = ':'.join(['{:02X}'.format(b) for b in srcMac])
    fecha_base = time.strftime('%Y/%m/%d %H:%M:%S', time.localtime(header.ts.tv_sec))
    timestamp_str = f"{fecha_base}.{header.ts.tv_usec:06d}"
    print(f"[{timestamp_str}] {mac_str} [ID={msg_id}] ({msg_len} bytes) : {mensaje}")

# 3C) Para NO imprimir nuestros propios mensajes enviados en broadcast (añadir al inicio de process_ethMsg_frame):
"""
    import ethernet
    if srcMac == ethernet.macAddress:
        return
"""


# -----------------------------------------------------------------------------
# MODIFICACIÓN 4: Detectar conflicto de IP con el comando 'g' o en recepción ARP
# -----------------------------------------------------------------------------

# 4A) En practica2.py -> Reemplazar 'elif comando == "g":' para que compruebe duplicidad con ARPResolution:
"""
            elif comando == 'g':
                print("Enviando ARP gratuito y comprobando duplicidad...")
                propia_ip = getIP(args.interface)
                with cacheLock:
                    cache.pop(propia_ip, None)  # Quitamos de caché para forzar el envío a red
                mac_conflicto = ARPResolution(propia_ip)
                if mac_conflicto is not None:
                    mac_str = ':'.join(['{:02X}'.format(b) for b in mac_conflicto])
                    print(f"¡CONFLICTO DETECTADO! La IP ya está en uso por la MAC {mac_str}")
                else:
                    print("ARP gratuito finalizado: No hay conflicto de IP.")
                with cacheLock:
                    cache[propia_ip] = myMAC
"""

# 4B) En arp.py (dentro de processARPRequest) -> Detectar si nos llega un ARP con nuestra propia IP origen:
"""
    if senderIP == myIP and senderMAC != myMAC:
        mac_conflicto = ':'.join(['{:02X}'.format(b) for b in senderMAC])
        print(f"¡ALERTA! Conflicto de IP detectado con el equipo MAC: {mac_conflicto}")
        return
"""


# -----------------------------------------------------------------------------
# MODIFICACIÓN 5: Añadir comando en practica2.py para borrar/limpiar la caché ARP
# -----------------------------------------------------------------------------
"""
            elif comando == 'c':
                with cacheLock:
                    cache.clear()
                print("Caché ARP vaciada correctamente.")
"""


# -----------------------------------------------------------------------------
# MODIFICACIÓN 6: Cambiar tiempos, reintentos o caducidad de caché en arp.py
# -----------------------------------------------------------------------------
"""
- Cambiar caducidad de caché (línea 40 de arp.py):
  cache = ExpiringDict(max_len=100, max_age_seconds=10)  # Cambiar 10 por los segundos pedidos

- Cambiar número de intentos en ARPResolution (línea 268 de arp.py):
  for intento in range(3):  # Cambiar 3 por el número de intentos (ej. 4 para 1 envío + 3 reintentos)

- Cambiar timeout de espera por intento en ARPResolution (líneas 271-272 de arp.py):
  for _ in range(20):       # 20 * 0.05s = 1.0 segundo (poner range(10) para 0.5s, range(40) para 2.0s)
      time.sleep(0.05)
"""


# =============================================================================
# SECCIÓN 2: ARCHIVO COMPLETO -> ethernet.py
# =============================================================================

ETHERNET_PY_COMPLETO = """
from rc1_pcap import *
import logging
import socket
import struct
from binascii import hexlify
import threading

ETH_FRAME_MAX = 1514
ETH_FRAME_MIN = 60
PROMISC = 1
NO_PROMISC = 0
TO_MS = 10
broadcastAddr = bytes([0xFF]*6)
EthernetProtocols = {}
macAddress = None
handle = None
recvThread = None
levelInitialized = False


def getHwAddr(interface:str):
    s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW)
    s.bind((interface,0))
    mac = (s.getsockname()[4])
    s.close()
    return mac


def process_Ethernet_frame(us:ctypes.c_void_p,header:pcap_pkthdr,data:bytes) -> None:
    global macAddress, EthernetProtocols, broadcastAddr

    if len(data) < 14:
        return

    dstMac = data[0:6]
    srcMac = data[6:12]
    ethertype = struct.unpack('!H', data[12:14])[0]
    payload = data[14:]

    if dstMac != macAddress and dstMac != broadcastAddr:
        return

    if ethertype in EthernetProtocols:
        callback_func = EthernetProtocols[ethertype]
        callback_func(us, header, payload, srcMac)
    else:
        return


def process_frame(us:ctypes.c_void_p,header:pcap_pkthdr,data:bytes) -> None:
    threading.Thread(target=process_Ethernet_frame,args=(us,header,data)).start()


class rxThread(threading.Thread):
    def __init__(self):
        threading.Thread.__init__(self)

    def run(self):
        global handle
        if handle is not None:
            pcap_loop(handle,-1,process_frame,None)

    def stop(self):
        global handle
        if handle is not None:
            pcap_breakloop(handle)


def registerEthCallback(callback_func: Callable[[ctypes.c_void_p,pcap_pkthdr,bytes],None], ethertype:int) -> None:
    global EthernetProtocols
    EthernetProtocols[ethertype] = callback_func

registerCallback = registerEthCallback


def startEthernetLevel(interface:str) -> int:
    global macAddress,handle,levelInitialized,recvThread

    if levelInitialized:
        logging.error('startEthernetLevel: Nivel Ethernet ya estaba inicializado')
        return -1

    try:
        macAddress = getHwAddr(interface)
    except Exception as e:
        logging.error(f"startEthernetLevel: Error al obtener MAC de {interface}: {e}")
        return -1

    errbuf = bytearray()
    handle = pcap_open_live(interface, ETH_FRAME_MAX, PROMISC, TO_MS, errbuf)
    if handle is None:
        logging.error(f"startEthernetLevel: Error al abrir {interface}: {errbuf.decode('utf-8', 'ignore')}")
        return -1

    levelInitialized = True

    recvThread = rxThread()
    recvThread.daemon = True
    recvThread.start()
    return 0


def stopEthernetLevel()->int:
    global macAddress,handle,levelInitialized,recvThread

    if not levelInitialized or handle is None:
        logging.error('stopEthernetLevel: El nivel Ethernet no está inicializado')
        return -1

    if recvThread is not None:
        recvThread.stop()
        recvThread.join(timeout=1.0)
        recvThread = None

    pcap_close(handle)
    handle = None

    levelInitialized = False
    macAddress = None

    return 0


def sendEthernetFrame(data:bytes,length:int,etherType:int,dstMac:bytes) -> int:
    global macAddress,handle

    if handle is None or macAddress is None:
        logging.error('sendEthernetFrame: El nivel Ethernet no está inicializado')
        return -1

    header = dstMac + macAddress + struct.pack('!H', etherType)
    payload = data[:length]
    frame = bytearray(header + payload)

    if len(frame) > ETH_FRAME_MAX:
        logging.error(f'sendEthernetFrame: Trama demasiado grande ({len(frame)} > {ETH_FRAME_MAX} bytes)')
        return -1

    if len(frame) < ETH_FRAME_MIN:
        padding = bytes([0x00] * (ETH_FRAME_MIN - len(frame)))
        frame.extend(padding)

    bytes_enviados = pcap_inject(handle, bytes(frame), len(frame))
    if bytes_enviados != len(frame):
        logging.error(f'sendEthernetFrame: Error en pcap_inject (enviados {bytes_enviados} de {len(frame)} bytes)')
        return -1

    return 0
"""


# =============================================================================
# SECCIÓN 3: ARCHIVO COMPLETO -> ethmsg.py
# =============================================================================

ETHMSG_PY_COMPLETO = """
from ethernet import *
import logging
import socket
import struct
import fcntl
import time
from threading import Lock
from expiringdict import ExpiringDict

ETHTYPE = 0x0AA0
broadcast = bytes([0xFF]*6)


def process_ethMsg_frame(us:ctypes.c_void_p,header:pcap_pkthdr,data:bytes,srcMac:bytes) -> None:
    if len(data) < 2:
        return

    msg_len = struct.unpack('!H', data[0:2])[0]
    msg_bytes = data[2:2 + msg_len]
    mensaje = msg_bytes.decode('utf-8', errors='ignore')

    mac_str = ':'.join(['{:02X}'.format(b) for b in srcMac])
    fecha_base = time.strftime('%Y/%m/%d %H:%M:%S', time.localtime(header.ts.tv_sec))
    timestamp_str = f"{fecha_base}.{header.ts.tv_usec:06d}"

    print(f"[{timestamp_str}] {mac_str} ({msg_len} bytes) : {mensaje}")


def initEthMsg(interface:str) -> int:
    registerEthCallback(process_ethMsg_frame, ETHTYPE)
    return 0


def sendEthMsg(message:bytes) -> bytes:
    if isinstance(message, str):
        msg_bytes = message.encode('utf-8')
    elif isinstance(message, bytes):
        msg_bytes = message
    else:
        msg_bytes = str(message).encode('utf-8')

    msg_len = len(msg_bytes)
    payload = struct.pack('!H', msg_len) + msg_bytes
    total_len = len(payload)

    ret = sendEthernetFrame(payload, total_len, ETHTYPE, broadcast)
    if ret == 0:
        return msg_len
    else:
        logging.error('sendEthMsg: Error al enviar la trama Ethernet')
        return None
"""


# =============================================================================
# SECCIÓN 4: ARCHIVO COMPLETO -> arp.py
# =============================================================================

ARP_PY_COMPLETO = """
from ethernet import *
import logging
import socket
import struct
import fcntl
import time
from threading import Lock
from expiringdict import ExpiringDict

globalLock = Lock()
broadcastAddr = bytes([0xFF]*6)
ARPHeader = bytes([0x00,0x01,0x08,0x00,0x06,0x04])
ARP_HLEN = 6

requestedIP = None
resolvedMAC = None
awaitingResponse = False

myIP = None
myMAC = None
arpInitialized = False

cacheLock = Lock()
cache = ExpiringDict(max_len=100, max_age_seconds=10)


def getIP(interface:str) -> int:
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    ip = fcntl.ioctl(
        s.fileno(),
        0x8915,
        struct.pack('256s', (interface[:15].encode('utf-8')))
    )[20:24]
    s.close()
    return struct.unpack('!I',ip)[0]


def printCache()->None:
    print('{:>12}\t\t{:>12}'.format('IP', 'MAC'))
    with cacheLock:
        for k in list(cache.keys()):
            if k in cache:
                print('{:>12}\t\t{:>12}'.format(
                    socket.inet_ntoa(struct.pack('!I', k)),
                    ':'.join(['{:02X}'.format(b) for b in cache[k]])
                ))


def processARPRequest(data:bytes,MAC:bytes)->None:
    global myMAC, myIP

    if data[0:6] == ARPHeader:
        data = data[8:]
    if len(data) < 20:
        return

    senderMAC = data[0:6]
    senderIP = struct.unpack('!I', data[6:10])[0]
    targetMAC = data[10:16]
    targetIP = struct.unpack('!I', data[16:20])[0]

    if senderMAC != MAC:
        return
    if senderMAC == myMAC:
        return
    if targetIP != myIP:
        return

    reply = createARPReply(senderIP, senderMAC)
    sendEthernetFrame(reply, len(reply), 0x0806, senderMAC)


def processARPReply(data:bytes,MAC:bytes)->None:
    global requestedIP,resolvedMAC,awaitingResponse,cache

    if data[0:6] == ARPHeader:
        data = data[8:]
    if len(data) < 20:
        return

    senderMAC = data[0:6]
    senderIP = struct.unpack('!I', data[6:10])[0]
    targetMAC = data[10:16]
    targetIP = struct.unpack('!I', data[16:20])[0]

    if senderMAC != MAC:
        return
    if targetIP != myIP:
        return

    with globalLock:
        if awaitingResponse and senderIP == requestedIP:
            resolvedMAC = senderMAC
            with cacheLock:
                cache[senderIP] = senderMAC
            awaitingResponse = False
            requestedIP = None


def createARPRequest(ip:int) -> bytes:
    global myMAC,myIP
    opcode = struct.pack('!H', 0x0001)
    sender_mac = myMAC
    sender_ip = struct.pack('!I', myIP)
    target_mac = bytes([0x00] * 6)
    target_ip = struct.pack('!I', ip)

    frame = ARPHeader + opcode + sender_mac + sender_ip + target_mac + target_ip
    return frame


def createARPReply(IP:int ,MAC:bytes) -> bytes:
    global myMAC,myIP
    opcode = struct.pack('!H', 0x0002)
    sender_mac = myMAC
    sender_ip = struct.pack('!I', myIP)
    target_mac = MAC
    target_ip = struct.pack('!I', IP)

    frame = ARPHeader + opcode + sender_mac + sender_ip + target_mac + target_ip
    return frame


def process_arp_frame(us:ctypes.c_void_p,header:pcap_pkthdr,data:bytes,srcMac:bytes) -> None:
    if len(data) < 28:
        return

    if data[0:6] != ARPHeader:
        return

    opcode = struct.unpack('!H', data[6:8])[0]

    if opcode == 0x0001:
        processARPRequest(data[8:], srcMac)
    elif opcode == 0x0002:
        processARPReply(data[8:], srcMac)
    else:
        return


def initARP(interface:str) -> int:
    global myIP,myMAC,arpInitialized

    try:
        myMAC = getHwAddr(interface)
        myIP = getIP(interface)
    except Exception as e:
        logging.error(f"initARP: Error al obtener datos de la interfaz {interface}: {e}")
        return -1

    registerEthCallback(process_arp_frame, 0x0806)

    if ARPResolution(myIP) is not None:
        logging.error("initARP: Conflicto detectado. La IP ya está en uso por otro equipo.")
        return -1

    with cacheLock:
        cache[myIP] = myMAC

    arpInitialized = True
    return 0


def ARPResolution(ip:int) -> bytes:
    global requestedIP,awaitingResponse,resolvedMAC

    with cacheLock:
        if ip in cache:
            return cache[ip]

    with globalLock:
        requestedIP = ip
        awaitingResponse = True
        resolvedMAC = None

    request = createARPRequest(ip)

    for intento in range(3):
        sendEthernetFrame(request, len(request), 0x0806, broadcastAddr)

        for _ in range(20):
            time.sleep(0.05)
            with globalLock:
                if not awaitingResponse:
                    return resolvedMAC

    with globalLock:
        awaitingResponse = False
        requestedIP = None
        return None
"""


# =============================================================================
# SECCIÓN 5: ARCHIVO COMPLETO -> practica2.py
# =============================================================================

PRACTICA2_PY_COMPLETO = """
from ethernet import *
from arp import *
from ethmsg import *
import sys
import binascii
import signal
import argparse
import struct
from argparse import RawTextHelpFormatter
import time
import logging
import socket

def printHelp():
    print("Ayuda Consola:\n")
    print("\tm <mensaje> : Envia un mensaje utilizando protocolo Ethernet\n")
    print("\ta <direccionIP> : Solicita ARP Request sobre la IP indicada\n")
    print("\tp : Imprime cache ARP\n")
    print("\th : Muestra la ayuda\n")
    print("\tg : ARP gratuito\n")
    print("\tq : Salir del programa\n")


if __name__ == "__main__":
    global pdumper,args,el,stop
    parser = argparse.ArgumentParser(
        description='Esta práctica ejecuta resoluciones ARP. Dada una dirección IP devuelve cual es la MAC asociada en la LAN actual',
        formatter_class=RawTextHelpFormatter
    )
    parser.add_argument('--itf', dest='interface', default=False, help='Interfaz a abrir')
    parser.add_argument('--debug', dest='debug', default=False, action='store_true', help='Activar Debug messages')
    args = parser.parse_args()

    if args.debug:
        logging.basicConfig(level=logging.DEBUG, format='[%(asctime)s %(levelname)s]\t%(message)s')
    else:
        logging.basicConfig(level=logging.INFO, format='[%(asctime)s %(levelname)s]\t%(message)s')

    if args.interface is False:
        logging.error('No se ha especificado interfaz')
        parser.print_help()
        sys.exit(-1)

    if startEthernetLevel(args.interface) != 0:
        logging.error('Ethernet no inicializado')
        sys.exit(-1)

    initEthMsg(args.interface)

    if initARP(args.interface) == -1:
        logging.error('ARP no inicializado')
        stopEthernetLevel()
        sys.exit(-1)

    print("Introduce la orden correspondiente:\n")

    while True:
        try:
            comando = input(">> ")
            if comando == "q":
                print("Saliendo de la consola.")
                break
            elif comando == 'p':
                printCache()
            elif comando == 'h':
                printHelp()
            elif comando.startswith("a "):
                ipstr = comando.split(" ")[1]
                print(f"Enviando solicitud ARP a {ipstr}...")
                try:
                    ip = struct.unpack('!I', socket.inet_aton(ipstr))[0]
                    ret = ARPResolution(ip)
                    if ret is not None:
                        print(':'.join(['{:02X}'.format(b) for b in ret]))
                    else:
                        print('Dirección no encontrada\n')
                except OSError:
                    print('Formato de IP incorrecta\n')
            elif comando.startswith("m "):
                partes = comando.split(" ")
                mensaje = " ".join(partes[1:])
                print(f"Enviando mensaje de {len(mensaje)} Bytes: {mensaje}")
                sendEthMsg(mensaje)
            elif comando == 'g':
                print("Enviando ARP gratuito...")
                propia_ip = getIP(args.interface)
                trama_g = createARPRequest(propia_ip)
                sendEthernetFrame(trama_g, len(trama_g), 0x0806, broadcastAddr)
                print("ARP gratuito emitido.")
            else:
                print("Comando no reconocido. 'h' para ayuda.\n")
        except KeyboardInterrupt:
            print('\n')
            break

    logging.info('Cerrando ....')
    if stopEthernetLevel() != 0:
        logging.error('Parando nivel Ethernet')
        sys.exit(-1)
"""
