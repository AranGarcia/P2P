"""
Modulo principal para la funcionalidad P2P.

Los P2PNodes son cada uno de los
elementos pertenecientes a la red, que cuentan con la funcionalidad de atender
y solicitar a otros nodos servicios como conexion y transferencia de archivos.
"""

import os.path
import socket
import threading

from enum import Enum

import message


class P2Pnode:
    def __init__(self, args, sharedir='./share'):
        self.port = int(args["port"])
        self.__initcomm(self.port)

        # Lista inicial vacía de los demás nodos en la red P2P
        self.peersocks = []

        # Creacion de la carpeta compartida
        self.sharedir = os.path.abspath(sharedir)
        P2Pnode.__create_shared(self.sharedir)

        # Si no se pasan peers, una nueva red se inicia desde cero
        self.peernames = []
        if args["peers"]:
            self.__search_peers(args["peers"].split(','))
        else:
            print("No se pasaron peers. Este es el primero en la red P2P.")

    def start(self):
        while(True):
            try:
                instruccion = input(">")
                # TODO: Procesar instruccion
            except KeyboardInterrupt:
                print("\nNodo P2P finalizado...")

                self.stop()
                exit(0)

    def stop(self):
        """
        Avisa a los demas nodos que se va a desconectar
        """
        pass

    def __initcomm(self, port):
        """
        Metodo privado que inicializa el socket del nodo en donde atenderá todas
        las solicitudes.
        """

        # Socket propio del nodo
        self.sock = socket.socket()
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock.bind(("localhost", port))
        self.sock.listen(3)

        # Se delega trabajo de atender las solicitudes a un hilo
        self.__commthread = threading.Thread(target=self.__serveraccept)
        self.__commthread.name = "server"
        self.__commthread.start()

    def __search_peers(self, peernames):
        """
        Se conecta con uno de los nodos en la red P2P. Si se pasaron las IP de mas de un
        nodo, entonces solicitara a todas hasta que conecte con solo una.

        Al conectar con uno, recibirá la lista de todos los demás nodos.
        """

        for p in peernames:
            try:
                # Cada peer debe estar de la forma IP:PUERTO
                peern = p.split(':')

                if peern[0] == "localhost":
                    peern[0] = "127.0.0.1"

                self.peernames.append(peern)
            except ValueError as ve:
                raise ValueError(
                    "error al parsear nodo P2P; debe ser del formato IP:PUERTO")

        for pn in self.peernames:
            if self.__requestconnection(pn):
                print("[P2P] Conexion exitosa con", pn)
                return
            else:
                print("[P2P] Intento fallido de conectarse a red P2P.")

        raise ValueError("no se pudo conectar con los peers proporcionados.")

    def __serveraccept(self):
        print("Atendiendo solicitudes...")
        while(True):
            con, addr = self.sock.accept()
            print("Mensaje recibido de", addr)

            msg = con.recv(1024)

            thr = threading.Thread(
                target=self.__processmsg, args=(msg, con, addr,))
            thr.start()

    def __requestconnection(self, peer_con):
        """
        Solicita una conexion a la red P2P mediante cualquiera de los nodos ya
        conectados.

        peer_con: Tupla con el nombre de direccion de algun peeer de la format
            (IP, PORT)
        """
        tmpsock = socket.socket()

        try:
            tmpsock.connect((peer_con[0], int(peer_con[1])))
        except ConnectionRefusedError:
            return False

        tmpsock.send(message.NCONNMSG)
        resp = tmpsock.recv(5)
        if resp[0] == message.PEERS:
            bsize = int.from_bytes(resp[1:], byteorder="big")
            buff = tmpsock.recv(bsize)

            self.peernames.extend(message.parse_ip_bytes(buff))
            print("[CONEXION] Se actualizo la lista de peers:", self.peernames)

            # Se le comparte al peer el puerto de comunicacion
            tmpsock.send(message.build_addme_message(self.port))
        else:
            print("ERROR: se devolvio un mensaje no procesable.")
            return False

        return True

    def __processmsg(self, msg, con, addr):
        """
        Procesa los 5 bytes recibidos y determina el tipo de mensaje y la accion
        correspondiente.
        """

        msgid = msg[0]
        if msgid == message.NCONNECT:
            # Se conecta con un nodo y depsues con los demas
            print("[P2P] Solicitud de conexion de", addr)
            self.__process_connection(msg, con, addr)
        elif msgid == message.ADDTHIS:
            print("[P2P] Se agrego un nuevo nodo.")
            self.__process_add(msg, con, addr)
        else:
            print("[P2P] Mensaje no procesable de", addr, ":\n", msg)

        con.close()

    def __process_connection(self, msg, con, addr):
        con.send(message.build_peers_message(self.peernames))

        # Se recibe el puerto del nuevo nodo
        resp = con.recv(3)
        if resp[0] == message.ADDME:
            newport = int.from_bytes(resp[1:], byteorder="big")

            # Manda a todos avisar que se agrega un nuevo nodo
            for pn in self.peernames:
                tmpsock = socket.socket()
                tmpsock.connect((pn[0], int(pn[1])))
                tmpsock.send(message.build_addthis_message(addr[0], newport))
                tmpsock.close()

            self.peernames.append((addr[0], newport))
            print("[CONEXION] Red P2P actualizada:", self.peernames)

    def __process_add(self, msg, con, addr):
        self.peernames.append(
            (
                '.'.join(message.octets_to_ip_iter(msg[1:5])),
                int.from_bytes(msg[5:7], byteorder="big")
            )
        )

        print("[P2P] Red P2P actualizada:", self.peernames)

    @staticmethod
    def __create_shared(sd):
        print("Directorio shared: ", sd)

        if not os.path.exists(sd):
            os.makedirs(sd)
