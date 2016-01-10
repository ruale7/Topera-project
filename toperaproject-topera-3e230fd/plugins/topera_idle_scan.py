#!/usr/bin/python
# -*- coding: utf-8 -*-

__license__ = '''
Topera - IPv6 Analysis tool

Copyright (C) 2011-2012  Daniel Garcia a.k.a cr0hn (@ggdaniel) | cr0hn<@>cr0hn.com
Copyright (C) 2011-2012  Rafael Sanchez (@r_a_ff_a_e_ll_o) | rafa<@>iniqua.com

Project page: https://github.com/toperaproject/topera/

This program is free software; you can redistribute it and/or
modify it under the terms of the GNU General Public License
as published by the Free Software Foundation; either version 2
of the License, or (at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program; if not, write to the Free Software
Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
'''

import logging
# Delete warning messages for scapy
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)

# System imports
import multiprocessing
from time import *
#from time import sleep, time
#from time import gmtime, strftime, clock, time
from random import randint
from topera.utils import *

try:
	from scapy.all import *
except ImportError:
	print ""
	print "[!] You need to install scapy libs."
	print ""
	print "To install it, run:"
	print "   apt-get install python-scapy"
	print ""
	exit(1)


# Topera imports
from topera.common import cmdParams, setup_firewall
from topera.plugins.plugins import ToperaPlugin
from topera.payloader import make_payload
from topera.iodebug import *
from topera.utils import split_ports, sniff

# Manager proporciona una forma para crear datos que pueden ser compartidos entre los diferentes procesos. Un objeto Manager controla un proceso de servidor que gestiona los objetos compartidos. Otros procesos pueden acceder a los objetos compartidos utilizando proxies.
# list() Crea un objeto "lista compartida" (un arraylist en Java) y devuelve un proxy para acceder a él.
PORTS_LIST   = multiprocessing.Manager().list()

INCREASE_ASSIGNMENT_IPID=0

IPID_LIST_CHECKING_IDLEHOST=multiprocessing.Manager().list()

ICMPM_ID_RST_ID=multiprocessing.Manager().list()
IPID_LIST=multiprocessing.Manager().list()

PORTS_OPEN=multiprocessing.Manager().list()
PORTS_CLOSED=multiprocessing.Manager().list()

#------------------------------------------------------------------------------
#Esta clase hereda de multiprocessing.Process, por lo que contendrá sus métodos. Un multiprocessing.Process se ejecutará con la llamada a su método start(), el cual ejecutará el código contenido dentro del método run() que deberemos implementar.
class ToperaIdleScan(multiprocessing.Process):
	""""""

	#----------------------------------------------------------------------
	# Aquí se esta definiendo la función __init__ que es el método contructor de la clase (Python reserva el nombre de la función __init__ para los métodos 	constructores). Es decir, cuando se cree un objeto de esta clase (un proceso), este tendrá los atributos y valores definidos en __init__
	#Un método constructor de una clase, es una función que se ejecuta automáticamente cuando crea un objeto. Puede contener llamadas a otros métodos
	def __init__(self, target, idlehost, attacker,partial_header_attacker_to_idlehost, partial_header_target_to_idlehost, partial_header_idlehost_to_target, send_function, sleep_time = 0, dest_ports = ["80"], output_iface = "eth0", debuging = 0): 
		"""Constructor"""
		super(ToperaIdleScan, self).__init__()

		self.__TARGET               = target		# dirección IPv6 del objetivo a atacar
		self.__IDLEHOST             = idlehost		# dirección IPv6 del idle host
		self.__ATTACKER             = attacker		# dirección IPv6 del atacante
		self.__DEBUG                = debuging		# se pone a 0 (por defecto) para no mostrar los mensajes de debugging. A 1 si se quieren mostra.
		self.__OUTIFACE             = output_iface	# interfaz de salida de los paquetes que enviemos. Por defecto es eth0.
		self.__PORTS                = dest_ports	# es un list() con los puertos a escanear sobre el TARGET
		self.__TOTAL_PORTS          = len(dest_ports)	# nº total de puertos a escanear
		
		self.__PARTIAL_HEADER_IDLEHOST_TO_TARGET       = partial_header_idlehost_to_target	# cabecera MAC con mac_origen=IDLEHOST y mac_destino=TARGET
		self.__PARTIAL_HEADER_TARGET_TO_IDLEHOST       = partial_header_target_to_idlehost  	# cabecera MAC con mac_origen=TARGET y mac_destino=IDLEHOST
		self.__PARTIAL_HEADER_ATTACKER_TO_IDLEHOST     = partial_header_attacker_to_idlehost	# cabecera MAC con mac_origen=ATTACKER y mac_destino=IDLEHOST

		self.__USED_PORTS           = multiprocessing.Manager().list() # aquí se irán almacenando los puertos que el ATTACKER ha usado como origen para atacar
		self.__PORTS_COUNT          = 0
		self.__SEND_FUNC            = send_function	# es la función de Scapy que se elige para enviar los paquets creados. Normalmente será send o sendp
		self.__SLEEP_TIME           = sleep_time	# tiempo de espera entre escaneo y escaneo. Escaneo 1 puerto-espero SLEEP_TIME-escaneo el siguiente. 
		self.__DONE                 = False 		# si DONE esta a True, el sniff para. Si está a False, sigue y para cuando se agote el tiempo 									establecido
		
		# Configure the firewall. Definida en common.py (junto a las clases Proxy(object), cmdParams(object) y Singleton (object))
		#setup_firewall(self.__TARGET)

	#----------------------------------------------------------------------
	# Se ejecutan los pasos 1, 2 y 3. Solo es para forzar a que siempre se introduzca la cabecera de fragmentación desde idlehost al target. No se tiene que anotar nada.
	def forcing_fragmentation_target_to_idlehost(self):
		# MTU quue sera anunciada en el mensaje PTB 
		newmtu=1278

		# Checksum que llevará el mensaje PTB 
		checksum=0xe390

		# 1. Creamos y enviamos un ping fragmentado con origen el target y destino el idlehost. CabeceraIPv6 = 40 bytes
		ping_target=fragment6(IPv6(src=self.__TARGET, dst=self.__IDLEHOST)/IPv6ExtHdrFragment()/ICMPv6EchoRequest(id=123,data="A"*1800),1400)
		send(ping_target[0])
		send(ping_target[1])

		# Como nosotros (attacker) no respondemos ya que la dirección ha sido falseada, tenemos que crear la respuesta (paso 2)
		response=IPv6(plen=1248,nh=0x3a,hlim=64,src=self.__IDLEHOST,dst=self.__TARGET)/ICMPv6EchoReply(id=123,cksum=checksum,data="A"*1800)

		# Cogemos solo la capa IPv6 de la respuesta
		ipv6response=response[IPv6]

		# Reducimos la cantidad de datos que se envian en la respuesta( un mensaje PTB message solo tendra una máximo de 1280 bytes)
		ipv6response[IPv6][ICMPv6EchoReply].data="A"*(newmtu-96)

		# Le damos al target suficiente tiempo para que responda.
		time.sleep(1)

		# 3.Le decimos al idlehost que su respuesta fue demasiado grande, la MTU que se necesita tiene que ser más pequeña
		mtu_target_to_idlehost=IPv6(src=self.__TARGET, dst=self.__IDLEHOST)/ICMPv6PacketTooBig(mtu=newmtu)/ipv6response
		send(mtu_target_to_idlehost)
 
	#----------------------------------------------------------------------
	#En esta funcion se ejecutan los pasos 4, 5 y 6 para forzar la fragmentación desde idlehost al attacker.
	def forcing_fragmentation_attacker_to_idlehost(self):
		# 4. Se crea un ping suficientemente grande. Se fragmentará para enviarlo al idle host
		fragments=fragment6(IPv6(src=self.__ATTACKER, dst=self.__IDLEHOST,nh=0x2c)/IPv6ExtHdrFragment()/ICMPv6EchoRequest(id=124,data="A"*1800),1400)

		# Enviamos el ping
		send(fragments[0])
		send(fragments[1])
		
		# Le damos al idlehost suficiente tiempo para que responda.
		time.sleep(1)

		#En el sniff capturariamos el paquete echo reply guardariamos su IPID=x en la variable global
		# MTU quue sera anunciada en el mensaje PTB 
		newmtu=1278

		# Checksum que llevará el mensaje PTB. Lo miro con wireshark y pongo el que saldría de hacerle el checksum al paquete. Te indica si es [correct] o no
		checksum=0xe38f

		# Como el idle host responde viene una respuesta.
		response=IPv6(plen=1248,nh=0x3a,hlim=64,src=self.__IDLEHOST,dst=self.__ATTACKER)/ICMPv6EchoReply(id=124,cksum=checksum,data="A"*1800)

		# Cogemos solo la capa IPv6 de la respuesta
		ipv6response=response[IPv6]

		# Reducimos la ccantidad de datos que se envian en la respuesta( un mensaje PTB message solo tendra una máximo de 1280 bytes)
		ipv6response[IPv6][ICMPv6EchoReply].data="A"*(newmtu-96)

		# 6.Le decimos al idlehost que su respuesta fue demasiado grande, la MTU que se necesita tiene que ser más pequeña
		mtu_attacker_to_idlehost=IPv6(src=self.__ATTACKER, dst=self.__IDLEHOST)/ICMPv6PacketTooBig(mtu=newmtu)/ipv6response
		send(mtu_attacker_to_idlehost)

	#----------------------------------------------------------------------
	#Paso 7. Para enviar un SYN desde idlehost al target al puerto destino. Usamos sendp para poner la MAC del idle host
	def send_syn_idlehost_to_target(self, port):
		syn=self.__PARTIAL_HEADER_IDLEHOST_TO_TARGET/IPv6(src=self.__IDLEHOST, dst=self.__TARGET)/TCP(dport=port,sport=RandNum(1,8000),flags="S")
		sendp(syn)
		
	#Pasos 8 y 9. El paquete de respuesta de ese puerto será un RST o un SYN/ACK. Si es SYN/ACK (target->idlehost), el puerto esta abierto y el idle host 		responderá con un RST con un IPID=x+1 al target (estos IPIDs no se captura) 
	
	#----------------------------------------------------------------------
	#Paso 10. Enviar un SYN/ACK (attacker->idlehost). Paso 11, el idlehost me responde con un RST cuyo IPID anotaremos. Puede ser: x+1(puerto cerrado) o x+2(puerto abierto)
	def send_syn_ack_attacker_to_idlehost(self,port):
		syn_ack=IPv6(src=self.__ATTACKER, dst=self.__IDLEHOST)/TCP(dport=port,sport=RandNum(1,8000),flags="SA")
		send(syn_ack)

	
	#----------------------------------------------------------------------
	# Pasos 4 (ping echo request), 5 (ping echo reply) y 6 (PTB). Para enviar un ping desde el attacker al idle host (paso 4).Se anotará el IPID=x del fragmento del ping de respuesta (paso 5). Será necesario que lo lea el sniff
	def sending_ping_fragmented_attacker_to_idlehost(self):
		# 4. Se crea un ping suficientemente grande. Se fragmentará para enviarlo al idle host
		fragments=fragment6(IPv6(src=self.__ATTACKER, dst=self.__IDLEHOST,nh=0x2c)/IPv6ExtHdrFragment()/ICMPv6EchoRequest(id=124,data="A"*1800),1400)
		# Enviamos el ping
		send(fragments[0])
		send(fragments[1])
		
		# Le damos al idlehost suficiente tiempo para que responda.
		time.sleep(1)

	#----------------------------------------------------------------------
	# Cuando más abajo llamamos a start(), esta es la función que se ejecuta.
	# Va a sevir para crea otra hebra que se ponga a escuchar los paquetes y así podamos interpretar lo que devuelve el target
	def run(self):
		"""Run the attack"""
		m_filter     = "src host %s and dst host %s and ip6" % (str(self.__IDLEHOST),str(self.__ATTACKER))
		m_timeout    = 9 if self.__TOTAL_PORTS < 4 else self.__TOTAL_PORTS * 4
		sniff(filter = m_filter, prn = self.store_ipid, store=0, var_stop=self.__DONE, timeout = m_timeout) # esperar 3 segundos por puerto(1s + 1s + 1s )
		# Ejemplo de sniff con la funcion de SCAPY: sniff(filter="host fd17:625c:f037:2:a00:27ff:fe80:8091",prn=lambda x: x.summary()). Sin embargo, esta 
		# sniff(...) es definida por TOPERA en la clase utils.py para usar la función de igual forma que en SCAPY pero añadiendo que el sniff pueda ser 		parado forzosamente con el atributo var_stop (DONE)
		#count: número de paquetes a capturar (0 significa infinitos)
		#store: (0 o 1) Ya sea para almacenar paquetes o descartarlos
		#prn: es la función que se aplicará a cada paquete. Ej: prn = lambda x: x.summary()
		#timeout: parar el sniffing despues de un tiempo dado (default: None)
		#var_stop (true o false): sirve para si está a TRUE decir que se pare definitivamente y no siga. Si está a FALSE que no se pare el sniff y 			siga  hasta que pase el tiempo de la variable timeout

	#----------------------------------------------------------------------
	def store_ipid(self, pkt):
		global ICMPV6_ECHO_REPLY_IDLEHOST_TO_ATTACKER, RST_IDLEHOST_TO_TARGET, ICMPM_ID_RST_ID
		
		try:
			if pkt[IPv6][IPv6ExtHdrFragment][ICMPv6EchoReply].code !=2: 
				ID_ICMPV6_ECHO_REPLY_IDLEHOST_TO_ATTACKER=pkt[IPv6][IPv6ExtHdrFragment].id				
				ICMPM_ID_RST_ID.insert(0,ID_ICMPV6_ECHO_REPLY_IDLEHOST_TO_ATTACKER)
		except IndexError:
			IODebug.displayDebugInfo("No se puede recuperar el código ICMPv6 del paquete")

		try:
			if pkt[TCP].sport!=1025:
				ID_RST_IDLEHOST_TO_TARGET=pkt[IPv6][IPv6ExtHdrFragment].id
				ICMPM_ID_RST_ID.insert(1,ID_RST_IDLEHOST_TO_TARGET)
				IPID_LIST.insert(self.__PORTS_COUNT, copy.deepcopy(ICMPM_ID_RST_ID))
				del ICMPM_ID_RST_ID[:]
				self.__PORTS_COUNT += 1	
		except IndexError:
			IODebug.displayDebugInfo("No se puede recuperar el puerto origen del paquete")
			return

		if self.__PORTS_COUNT == self.__TOTAL_PORTS:
			self.__DONE = True # A esto no le hace caso
	

#------------------------------------------------------------------------------
#Esta clase hereda de multiprocessing.Process. Un multiprocessing.Process se ejecutará con la llamada a su método start(), el cual ejecutará el código contenido dentro del método run() que deberemos implementar.
class ToperaCheckingIdleHost(multiprocessing.Process):
	""""""
	#----------------------------------------------------------------------
	def __init__(self, target, idlehost, attacker,partial_header_attacker_to_idlehost, partial_header_target_to_idlehost, partial_header_idlehost_to_target, send_function, sleep_time = 0, dest_ports = ["80"], output_iface = "eth0", debuging = 0): 
		"""Constructor"""
		super(ToperaCheckingIdleHost, self).__init__()

		self.__TARGET               = target		
		self.__IDLEHOST             = idlehost
		self.__ATTACKER             = attacker
		self.__DEBUG                = debuging		
		self.__OUTIFACE             = output_iface	
		self.__PORTS                = dest_ports	
		self.__TOTAL_PORTS          = len(dest_ports)	
		self.__PARTIAL_HEADER_IDLEHOST_TO_TARGET       = partial_header_idlehost_to_target	
		self.__PARTIAL_HEADER_TARGET_TO_IDLEHOST       = partial_header_target_to_idlehost 
		self.__PARTIAL_HEADER_ATTACKER_TO_IDLEHOST     = partial_header_attacker_to_idlehost		
		self.__USED_PORTS           = multiprocessing.Manager().list() 
		self.__PORTS_COUNT          = 0
		self.__SEND_FUNC            = send_function	
		self.__SLEEP_TIME           = sleep_time	 
		self.__DONE                 = False 

	#----------------------------------------------------------------------
	def forcing_fragmentation_attacker_to_idlehost(self):
		fragments=fragment6(IPv6(src=self.__ATTACKER, dst=self.__IDLEHOST,nh=0x2c)/IPv6ExtHdrFragment()/ICMPv6EchoRequest(id=124,data="A"*1800),1400)
		send(fragments[0])
		send(fragments[1])
		# Le damos al idlehost suficiente tiempo para que responda.
		time.sleep(1)
		#En el sniff capturariamos el paquete echo reply guardariamos su IPID=x en la variable global
		# MTU quue sera anunciada en el mensaje PTB 
		newmtu=1278
		# Checksum que llevará el mensaje PTB. Lo miro con wirshark y pongo el que saldría de hacerle el checksum al paquete. Te indica si es [correct] o no
		checksum=0xe38f
		# Como el idle host responde viene una respuesta.
		response=IPv6(plen=1248,nh=0x3a,hlim=64,src=self.__IDLEHOST,dst=self.__ATTACKER)/ICMPv6EchoReply(id=124,cksum=checksum,data="A"*1800)
		# Cogemos solo la capa IPv6 de la respuesta
		ipv6response=response[IPv6]
		# Reducimos la ccantidad de datos que se envian en la respuesta( un mensaje PTB message solo tendra una máximo de 1280 bytes)
		ipv6response[IPv6][ICMPv6EchoReply].data="A"*(newmtu-96)
		# 6.Le decimos al idlehost que su respuesta fue demasiado grande, la MTU que se necesita tiene que ser más pequeña
		mtu_attacker_to_idlehost=IPv6(src=self.__ATTACKER, dst=self.__IDLEHOST)/ICMPv6PacketTooBig(mtu=newmtu)/ipv6response
		send(mtu_attacker_to_idlehost)


	#----------------------------------------------------------------------
	# No se tiene que anotar nada. Solo es para forzar a que siempre se introduzca la cabecera de fragmentación desde idlehost  al target
	#def checking_idlehost(self):
		#ans=sr1( IPv6(dst=self.__IDLEHOST)/IPv6ExtHdrFragment()/TCP(dport=80,sport=RandNum(1,8000),flags="SA") , timeout=4)
		#ans.show()
		#ans2=sr1( IPv6(src=self.__TARGET, dst=self.__IDLEHOST)/IPv6ExtHdrFragment()/ICMPv6EchoRequest(id=123,data="A"*1800) )
		#ans2.show()
		#pkt=sr1( IPv6(dst="fd17:625c:f037:2:a00:27ff:fe21:f21d")/IPv6ExtHdrFragment()/TCP(dport=80,sport=RandNum(1,8000),flags="SA") , timeout=4)
		#topera.forcing_fragmentation_attacker_to_idlehost()
		#ans=sr1(IPv6(dst="fd17:625c:f037:2:a00:27ff:fe21:f21d")/IPv6ExtHdrFragment()/ICMPv6EchoRequest(id=123,data="A"*100), timeout=4)
		#ans.show()
		#ans=sr1( IPv6(dst="fd17:625c:f037:2:a00:27ff:fe21:f21d")/IPv6ExtHdrFragment()/TCP(dport=80,sport=RandNum(1,8000),flags="SA") , nofilter=1, filter=None, iface=None, timeout=2, inter=0, verbose=None, chainCC=0, retry=0, multi=True )
		#print ("El ipid del checking es: %s" % str(ans[IPv6][IPv6ExtHdrFragment].id)  )
		#print 
		#sniff
		#sniff(prn=lambda x: x.summary())		
		#except IndexError:
			#print ("Error in cheking")	
	

	#----------------------------------------------------------------------
	#Cuando llamamos a start(), esta es la función que se ejecuta. Va a servir para iniciar el sniff, para lanzar otra hebra que se ponga a escuchar los paquetes 
	def run(self):
		"""Run the attack"""
		m_filter     = "src host %s and dst host %s and ip6" % (str(self.__IDLEHOST),str(self.__ATTACKER))
		sniff(filter = m_filter, prn = self.store_ipid, store=0, var_stop=self.__DONE, timeout = 6) 

	#----------------------------------------------------------------------
	def store_ipid(self, pkt):
		global  IPID_LIST_CHECKING_IDLEHOST 
		try:
			if pkt[TCP].sport!=1025:
				print ("Este es el paquete del checking")
				pkt.show()
				IPID_LIST_CHECKING_IDLEHOST.append(pkt[IPv6][IPv6ExtHdrFragment].id)
		except IndexError:
			IODebug.displayDebugInfo("Error cheking idle host")
			return
		

#------------------------------------------------------------------------------
class ToperaIdleScanPlugin(ToperaPlugin):

	#----------------------------------------------------------------------
	def get_parser(self, main_parser):
		if not main_parser:
			raise ValueError("Main parser can't be null")
		grmode = main_parser.add_argument_group("Idle scan options")
		grmode.add_argument('--scan-delay2', action='store', dest='sleep', help='adjust delay between probes. Default 0ms', default=0.01, type=float)
		grmode.add_argument('-id', action='store', dest='idle_host',metavar="TARGET", help='"IPv6 idle host"')
		grmode.add_argument('-idm', action='store', dest='mac_idle_host', help='"idle host mac"', default=None)
		grmode.add_argument('-isp', action='store', dest='ports_idle_scan', help='ports to scan. Format: 22,23,43|22-34. Default: 0-1024', default="1-1024")
	
	#----------------------------------------------------------------------
	def run(self, plugin_Params, global_params):
		"""Get the help message for this plugin."""

		TARGET            = global_params.target
		DST_MAC           = global_params.mac_dst
		OUT_IFACE         = global_params.iface_out
		SEND_FUNCTION     = global_params.send_function
		PORTS             = split_ports(plugin_Params.ports_idle_scan)
		SLEEP_TIME        = plugin_Params.sleep / 1000.0
		# Añadido nuevo
		IDLEHOST	  = plugin_Params.idle_host
		IDLEHOST_MAC	  = plugin_Params.mac_idle_host
		ATTACKER	  = global_params.ip_src 

		global PORTS_LIST, INCREASE_ASSIGNMENT_IPID #, PORTS_CLOSED, PORTS_FILTERED
		PORTS_LIST.extend(PORTS)
		PORTS_LIST.reverse()
		
		PARTIAL_HEADER_IDLEHOST_TO_TARGET = Ether(src=IDLEHOST_MAC,dst=DST_MAC) #Cabecera MAC
		PARTIAL_HEADER_TARGET_TO_IDLEHOST = Ether(src=DST_MAC,dst=IDLEHOST_MAC) #Cabecera MAC
		PARTIAL_HEADER_ATTACKER_TO_IDLEHOST = Ether(dst=IDLEHOST_MAC) #Cabecera MAC
		
		try:
			# Passed idle host as parameter?
			if not IDLEHOST:
				IODebug.displayInfo("%s: error: too few arguments\n" % __prog__)
				exit(1)

			# Check if destination are reachable
			IODebug.displayDebugInfo("DEBUG 1: Checking if destination are reachable")
			# Get remote MAC
			if not IDLEHOST_MAC:
				try:
					IDLEHOST_MAC = get_remote_addr(IDLEHOST, ATTACKER, OUT_IFACE)
					SEND_FUNCTION = sendp
					print "level = 2"
				except RuntimeError:
					# Check if address is accesible without net level 2
					test = sr1(IPv6(dst=IDLEHOST)/ICMPv6EchoRequest(), iface = OUT_IFACE, timeout=4, verbose = 0)
					print "level = 3"
					SEND_FUNCTION  = send

					if not test:
						raise RuntimeError("Idle host is not reachable")
		except IOError,e:
			IODebug.displayInfo("\nError: %s\n" % str(e))
			sys.exit(1)
		except KeyboardInterrupt:
			IODebug.displayInfo("\nstopping...\n")
			sys.exit(1)
		except EOFError:
			print "CTRL+D"
			sys.exit(1)

		# Iniciamos el cronómetro
		m_start_init1      = time.time()

		################ Checking idlehost ################
		checking=ToperaCheckingIdleHost(TARGET,
			    idlehost       = IDLEHOST,
			    attacker       = ATTACKER,
		            partial_header_idlehost_to_target = PARTIAL_HEADER_IDLEHOST_TO_TARGET,
			    partial_header_target_to_idlehost = PARTIAL_HEADER_TARGET_TO_IDLEHOST,
			    partial_header_attacker_to_idlehost= PARTIAL_HEADER_ATTACKER_TO_IDLEHOST,
		            send_function  = SEND_FUNCTION,
		            dest_ports     = PORTS,
		            sleep_time     = SLEEP_TIME,
		            output_iface   = OUT_IFACE,
		            debuging       = global_params.verbosity)

		# start() para lanzar sniff. Al abrir el sniff tengo que esperar 3 segundos porque sino el primer IPID del ping del primer puerto no lo pilla. Tarda 			demasiado en abrise el sniff...
		checking.start()			
		sleep(2)
		
		#Fuerzo a la fragmentación desde idlehost a attacker
		checking.forcing_fragmentation_attacker_to_idlehost()
		
		#Envio los 5 SYN/ACK de la fase de comprobacion de idle host
		send( IPv6(dst=IDLEHOST)/IPv6ExtHdrFragment()/TCP(dport=80,sport=RandNum(1,8000),flags="SA") )
		send( IPv6(dst=IDLEHOST)/IPv6ExtHdrFragment()/TCP(dport=80,sport=RandNum(1,8000),flags="SA") )
		send( IPv6(dst=IDLEHOST)/IPv6ExtHdrFragment()/TCP(dport=80,sport=RandNum(1,8000),flags="SA") )
		send( IPv6(dst=IDLEHOST)/IPv6ExtHdrFragment()/TCP(dport=80,sport=RandNum(1,8000),flags="SA") )
		send( IPv6(dst=IDLEHOST)/IPv6ExtHdrFragment()/TCP(dport=80,sport=RandNum(1,8000),flags="SA") )

		#Muestros IPIDs 
		print ("Estos son los IPIDs del Checking")
		for i in range(0,len(IPID_LIST_CHECKING_IDLEHOST)):
			print("IPID nº %s almacenado en IPID_LIST_CHECKING_IDLEHOST: %s" % (  str(i) , str(IPID_LIST_CHECKING_IDLEHOST[i]) )  )
    			
		print ("Finalizando Checking... waiting")
		checking.join()

		# Compruebo los IPID_LIST_CHECKING_IDLEHOST
		difference=[]
		run_attack=False
		INCREASE_ASSIGNMENT_IPID=0

		if len(IPID_LIST_CHECKING_IDLEHOST)==5:
			print ("Calculando diferencia entre los ipid del checking...")
			for i in range(0,len(IPID_LIST_CHECKING_IDLEHOST)-1):
				increase=IPID_LIST_CHECKING_IDLEHOST[i+1]-IPID_LIST_CHECKING_IDLEHOST[i]
				difference.append(increase)
				print("IPID nº %s almacenado en DIFFERENCE: %s" % (  str(i) , str(increase) )  )
	
		if difference[0]==difference[1]==difference[2]==difference[3]:
			INCREASE_ASSIGNMENT_IPID=difference[0]
			run_attack=True
			print("El idle host es adecuado: no está procesando tráfico y asigna el ipid de forma global ")
			print("con un incremento de %s)" % (   str(INCREASE_ASSIGNMENT_IPID) )  )

		if run_attack:
			print ("Comenzando ataque")
			# Process Idle Scan
			topera  = ToperaIdleScan(TARGET,
				    idlehost       = IDLEHOST,
				    attacker       = ATTACKER,
				    partial_header_idlehost_to_target = PARTIAL_HEADER_IDLEHOST_TO_TARGET,
				    partial_header_target_to_idlehost = PARTIAL_HEADER_TARGET_TO_IDLEHOST,
				    partial_header_attacker_to_idlehost= PARTIAL_HEADER_ATTACKER_TO_IDLEHOST,
				    send_function  = SEND_FUNCTION,
				    dest_ports     = PORTS,
				    sleep_time     = SLEEP_TIME,
				    output_iface   = OUT_IFACE,
				    debuging       = global_params.verbosity)
			try:
				IODebug.displayInfo("Scanning %s [%s ports]" % (TARGET, str(len(PORTS))))
				m_timeout         = len(PORTS) * 2
				m_timeout_counter = 0

				#Fuerzo a la fragmentacion
				topera.forcing_fragmentation_target_to_idlehost()
				topera.forcing_fragmentation_attacker_to_idlehost()

				# Start. Para lazar sniff. Al abrir el sniff tengo que esperar 3 segundos porque sino el primer del primer puerto ping no lo pilla. 					Tarda demasiado en abrise el sniff...
				topera.start()
				m_start_init1      = time.time()			
				sleep(3)

				#Muestros los puertos que se van a escanear
				for i in range(0,len(PORTS_LIST)):
					print("Puerto a escanear nº %s de PORTS_LIST:" % str(i)  )
	    				print PORTS_LIST[i] 
	 			
				#Para cada puerto lanzo todos sus paquetes y guardo en el vector los dos IPID que me interesan con el sniff
				for i in PORTS_LIST:
					port=int (i) 
					IODebug.displayInfo("El IDLEHOST es: %s " % (IDLEHOST))
	
					topera.sending_ping_fragmented_attacker_to_idlehost()				
					topera.send_syn_idlehost_to_target(port)
					topera.send_syn_ack_attacker_to_idlehost(port)
					sleep(1)
			
				#Muestros los 2 IPIDs de interés de todos los puertos
				for i in range(0,len(IPID_LIST)):
					print("IPIDS almacenados en la posicion nª %s de IPID_LIST (puerto %s):" % (  str(i) , PORTS_LIST[i] )  )
	    				print IPID_LIST[i]

				IODebug.displayInfo("\nTiempo de escaneo: %s seconds" % (str( (time.time() - m_start_init1)) )  )
			
				topera.join()

				#Comprobar el vector IPID_LIST y el PORT_LIST para saber si un puerto esta abierto o cerrado
				for i in range(0,len(IPID_LIST)):
					if IPID_LIST[i][1]== IPID_LIST[i][0]+(2*INCREASE_ASSIGNMENT_IPID):
						PORTS_OPEN.append(PORTS_LIST[i])
					else:
						PORTS_CLOSED.append(PORTS_LIST[i])
	
				#print PORTS_LIST 
				IODebug.displayInfo("Not shown: %s closed ports" % str(len(PORTS_CLOSED)))
				IODebug.displayInfo("%s scan report for %s" % ("Topera", TARGET))
				IODebug.displayInfo("PORT\t\tSTATE")

				for po in PORTS_OPEN:
					IODebug.displayInfo("%s/tcp\t\topen" % (str(po)))

				#IODebug.displayInfo("\nTopera done: 1 IP address (1 host up) scanned in %s seconds" % (str(clock() - m_start_init)))
				IODebug.displayInfo("Finalizado el modulo IDLE SCAN")

			except KeyboardInterrupt:
				print "\n[*] Stoping, please be patient..."
				topera.terminate()
				print ""
		else:
			print ("El idle host no es adecuado:o esta recibiendo diferente tráfico o asigna los ipid de forma aleatoria")

	#----------------------------------------------------------------------
	def display_help(self):
		"""Display help for this plugin."""
		return """
A IPv6 TCP scanner undetectable for Snort."""


	#----------------------------------------------------------------------
	# No se tiene que anotar nada. Solo es para forzar a que siempre se introduzca la cabecera de fragmentación desde idlehost  al target
	#def checking_idlehost(self):
		#ans=sr1( IPv6(dst=self.__IDLEHOST)/IPv6ExtHdrFragment()/TCP(dport=80,sport=RandNum(1,8000),flags="SA") , timeout=4)
		#ans.show()
		#ans2=sr1( IPv6(src=self.__TARGET, dst=self.__IDLEHOST)/IPv6ExtHdrFragment()/ICMPv6EchoRequest(id=123,data="A"*1800) )
		#ans2.show()

		#pkt=sr1( IPv6(dst="fd17:625c:f037:2:a00:27ff:fe21:f21d")/IPv6ExtHdrFragment()/TCP(dport=80,sport=RandNum(1,8000),flags="SA") , timeout=4)
		#sr1(IPv6(dst="fd17:625c:f037:2:a00:27ff:fe21:f21d")/IPv6ExtHdrFragment()/ICMPv6EchoRequest(id=123,data="A"*100) )
		#sniff
		#sniff(prn=lambda x: x.summary())
