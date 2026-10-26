# =============================================================================
# CHULETA EXCLUSIVA DE MODIFICACIONES Y WIRESHARK (.pcap) - PRÁCTICA 2
# (Sin ficheros completos, solo fragmentos listos para copiar y pegar)
# =============================================================================


# =============================================================================
# PARTE 1: SI TE DAN UN ARCHIVO .PCAP PARA ANALIZAR EN WIRESHARK (FILTROS)
# =============================================================================
# Cómo abrirlo desde terminal:   wireshark archivo.pcap &
# Pega estos filtros en la barra superior de Wireshark y pulsa Enter:

"""
1. ¿Cuáles son de tipo 'g' (ARP Gratuito / ARP Announcement)?
   - Filtro exacto en Wireshark:
     arp.isgratuitous == 1
     (Alternativa manual: arp.opcode == 1 and arp.src.proto_ipv4 == arp.dst.proto_ipv4)
   - Cómo identificarlos a ojo en la lista:
     En la columna 'Info' pone "ARP Announcement for X.X.X.X" o "Gratuitous ARP".
     Si abres el paquete: Sender IP == Target IP, Opcode = 1 (request) y Target MAC = 00:00:00:00:00:00.

2. ¿Cuáles son peticiones ARP normales ('a <IP>', ARP Request SIN ser gratuitos)?
   - Filtro exacto en Wireshark:
     arp.opcode == 1 and arp.src.proto_ipv4 != arp.dst.proto_ipv4
   - Cómo identificarlos:
     En 'Info' pone "Who has X.X.X.X? Tell Y.Y.Y.Y" (donde X e Y son IPs distintas).
     En Ethernet: Destination = Broadcast (ff:ff:ff:ff:ff:ff).

3. ¿Cuáles son respuestas ARP (ARP Reply)?
   - Filtro exacto en Wireshark:
     arp.opcode == 2
   - Cómo distinguir en el .pcap cuál respuesta es de VUESTRO PROGRAMA y cuál del SISTEMA OPERATIVO (Linux):
     * Respuesta de VUESTRO PROGRAMA (arp.py): Length == 60 bytes (lleva 18 bytes de 00 de padding al final).
       Filtro: arp.opcode == 2 and frame.len == 60
     * Respuesta del SISTEMA OPERATIVO: Length == 42 bytes (no lleva padding).
       Filtro: arp.opcode == 2 and frame.len == 42

4. ¿Cuáles son mensajes enviados con el comando 'm' (Protocolo EthMsg 0x0AA0)?
   - Filtro exacto en Wireshark:
     eth.type == 0x0aa0
   - Cómo leer el mensaje y su longitud dentro de Wireshark:
     Pincha en el paquete -> Abajo despliega "Data" (46 bytes o más):
     * Los 2 primeros bytes en hexadecimal son la longitud (ej: '00 04' = 4 bytes).
     * Los siguientes N bytes son el mensaje en ASCII (lo ves en la columna derecha de texto de Wireshark).
     * Todo lo que va después hasta completar 60 bytes son '00' de relleno (padding).

5. Otros filtros útiles si te preguntan "cuántos paquetes envía la máquina X":
   - Filtrar por MAC origen:     eth.src == 00:00:00:00:00:01
   - Filtrar por MAC destino:    eth.dst == 00:00:00:00:00:02
   - Solo tramas en Broadcast:   eth.dst == ff:ff:ff:ff:ff:ff
   - Filtrar por IP en ARP:      arp.src.proto_ipv4 == 10.0.0.1
"""


# =============================================================================
# PARTE 2: SI TE PIDEN LEER UN ARCHIVO .PCAP CON TU CÓDIGO PYTHON (OFFLINE)
# =============================================================================
# Si en vez de abrir Wireshark te dan un "traza.pcap" y te piden que tu código
# lo lea e imprima los mensajes o procese los ARPs guardados en ese fichero:

# En ethernet.py -> Reemplazar en startEthernetLevel la línea de pcap_open_live por:
"""
    errbuf = bytearray()
    # Si 'interface' termina en .pcap o .cap, abrimos fichero offline en vez de interfaz viva:
    if interface.endswith('.pcap') or interface.endswith('.cap'):
        handle = pcap_open_offline(interface, errbuf)
    else:
        handle = pcap_open_live(interface, ETH_FRAME_MAX, PROMISC, TO_MS, errbuf)
"""
# (Y en process_Ethernet_frame comentar el filtro 'if dstMac != macAddress...' para ver todos los paquetes del pcap).


# =============================================================================
# PARTE 3: MODIFICACIONES DE CÓDIGO MÁS PEDIDAS EN EXAMEN (COPIAR Y PEGAR)
# =============================================================================

# -----------------------------------------------------------------------------
# MOD 1: Enviar mensaje 'm' en UNICAST a una IP concreta (m <IP> <mensaje>)
# -----------------------------------------------------------------------------

# 1.1) En ethmsg.py -> Añadir arriba del todo:
from arp import ARPResolution

# 1.2) En ethmsg.py -> Sustituir sendEthMsg(message:bytes) por:
def sendEthMsg(ip: int, message: bytes) -> bytes:
    dstMac = ARPResolution(ip)
    if dstMac is None:
        print("Error: No se pudo resolver la MAC para esa IP")
        return None

    msg_bytes = message.encode('utf-8') if isinstance(message, str) else message
    msg_len = len(msg_bytes)
    payload = struct.pack('!H', msg_len) + msg_bytes

    ret = sendEthernetFrame(payload, len(payload), ETHTYPE, dstMac)
    return msg_len if ret == 0 else None

# 1.3) En practica2.py -> Sustituir el bloque 'elif comando.startswith("m "):' por:
"""
			elif comando.startswith("m "):
				partes = comando.split(" ")
				if len(partes) < 3:
					print("Uso: m <IP> <mensaje>")
				else:
					ipstr = partes[1]
					mensaje = " ".join(partes[2:])
					try:
						ip = struct.unpack('!I', socket.inet_aton(ipstr))[0]
						sendEthMsg(ip, mensaje)
					except OSError:
						print('Formato de IP incorrecta
')
"""


# -----------------------------------------------------------------------------
# MOD 2: Enviar mensaje 'm' directamente a una MAC concreta (m <MAC> <mensaje>)
#        Ejemplo: m 00:00:00:00:00:02 Hola que tal
# -----------------------------------------------------------------------------

# 2.1) En ethmsg.py -> Sustituir sendEthMsg por:
def sendEthMsg_mac(dstMac: bytes, message: bytes) -> bytes:
    msg_bytes = message.encode('utf-8') if isinstance(message, str) else message
    msg_len = len(msg_bytes)
    payload = struct.pack('!H', msg_len) + msg_bytes
    ret = sendEthernetFrame(payload, len(payload), ETHTYPE, dstMac)
    return msg_len if ret == 0 else None

# 2.2) En practica2.py -> Cómo convertir un string "00:00:00:00:00:02" a bytes (6B):
"""
			elif comando.startswith("m "):
				partes = comando.split(" ")
				mac_str = partes[1]
				mensaje = " ".join(partes[2:])
				dstMac = bytes([int(b, 16) for b in mac_str.split(":")])
				sendEthMsg_mac(dstMac, mensaje)
"""


# -----------------------------------------------------------------------------
# MOD 3: Cambios en la cabecera de ethmsg.py (Longitud de 1B o 4B, o campo extra)
# -----------------------------------------------------------------------------
"""
Recuerda los formatos de struct.pack / struct.unpack:
  '!B' -> 1 byte  (unsigned char,  0..255)        -> data[0:1], mensaje en data[1 : 1+msg_len]
  '!H' -> 2 bytes (unsigned short, 0..65535)      -> data[0:2], mensaje en data[2 : 2+msg_len]  (EL ACTUAL)
  '!I' -> 4 bytes (unsigned int,   32 bits)       -> data[0:4], mensaje en data[4 : 4+msg_len]
"""

# Ejemplo si te piden añadir un número de secuencia / contador de mensajes (2B) antes de la longitud (2B):
seq_num = 0  # Variable global arriba en ethmsg.py

def sendEthMsg_con_seq(message: bytes) -> bytes:
    global seq_num
    msg_bytes = message.encode('utf-8') if isinstance(message, str) else message
    msg_len = len(msg_bytes)
    payload = struct.pack('!HH', seq_num, msg_len) + msg_bytes
    seq_num += 1
    ret = sendEthernetFrame(payload, len(payload), ETHTYPE, broadcast)
    return msg_len if ret == 0 else None

def process_ethMsg_frame_con_seq(us, header, data: bytes, srcMac: bytes) -> None:
    if len(data) < 4:
        return
    rec_seq, msg_len = struct.unpack('!HH', data[0:4])
    mensaje = data[4:4 + msg_len].decode('utf-8', errors='ignore')
    mac_str = ':'.join(['{:02X}'.format(b) for b in srcMac])
    fecha_base = time.strftime('%Y/%m/%d %H:%M:%S', time.localtime(header.ts.tv_sec))
    print(f"[{fecha_base}.{header.ts.tv_usec:06d}] {mac_str} (Seq: {rec_seq}, {msg_len} bytes) : {mensaje}")


# -----------------------------------------------------------------------------
# MOD 4: NO imprimir tus propios mensajes en broadcast (en ethmsg.py)
# -----------------------------------------------------------------------------
# Pegar justo al principio de process_ethMsg_frame:
"""
    import ethernet
    if srcMac == ethernet.macAddress:
        return
"""


# -----------------------------------------------------------------------------
# MOD 5: Guardar en la caché ARP también cuando recibes un ARP Request (en arp.py)
# -----------------------------------------------------------------------------
# Pegar dentro de processARPRequest (justo antes de 'reply = createARPReply(...)'):
"""
    with cacheLock:
        cache[senderIP] = senderMAC
"""


# -----------------------------------------------------------------------------
# MOD 6: Que el comando 'g' compruebe si hay IP duplicada y avise por pantalla
# -----------------------------------------------------------------------------
# En practica2.py -> Sustituir el bloque 'elif comando == "g":' por:
"""
			elif comando == 'g':
				print("Enviando ARP gratuito...")
				propia_ip = getIP(args.interface)
				with cacheLock:
					cache.pop(propia_ip, None)
				mac_dup = ARPResolution(propia_ip)
				if mac_dup is not None:
					print("¡CONFLICTO DE IP! En uso por:", ':'.join(['{:02X}'.format(b) for b in mac_dup]))
				else:
					print("ARP gratuito OK: Sin conflicto.")
				with cacheLock:
					cache[propia_ip] = myMAC
"""


# -----------------------------------------------------------------------------
# MOD 7: Contar paquetes enviados/recibidos (Estadísticas al salir o con comando 's')
# -----------------------------------------------------------------------------
# Si te piden llevar la cuenta de tramas ARP o Ethernet enviadas y recibidas:
"""
# 1) En ethernet.py (arriba):
tx_frames = 0
rx_frames = 0

# 2) En sendEthernetFrame (justo antes de 'return 0'):
global tx_frames
tx_frames += 1

# 3) En process_Ethernet_frame (después de comprobar dstMac):
global rx_frames
rx_frames += 1
"""


# -----------------------------------------------------------------------------
# MOD 8: Los 2 pequeños fixes de vuestro código original (por si hacen test unitario)
# -----------------------------------------------------------------------------
"""
1) En ethernet.py (línea 133):
   Sacar 'registerCallback = registerEthCallback' FUERA de la función (sin espacios a la izquierda).

2) En arp.py (en processARPRequest y processARPReply):
   Cambiar 'if len(data) == 28:' por:
   if data[0:6] == ARPHeader:
       data = data[8:]
"""
