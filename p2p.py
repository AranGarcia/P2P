"""
Modulo principal para la funcionalidad P2P.

Los P2PNodes son cada uno de los
elementos pertenecientes a la red, que cuentan con la funcionalidad de atender
y solicitar a otros nodos servicios como conexion y transferencia de archivos.
"""

import os.path
import socket
import threading
import time

from enum import Enum

import message
import files


class P2Pnode:
    def __init__(self, args):
        # Creacion de la carpeta compartida
        self.sharedir = os.path.abspath(args["shared"])
        P2Pnode.__create_shared(self.sharedir)
        self.files = files.list_files(self.sharedir + "/")
        self.virtualdir = {}
        print("[SHARED]", self.sharedir)
        for f in self.files:
            print("\t", f)

        self.__resource = []
        self.__sem = None

        self.port = int(args["port"])

        # Lista inicial vacía de los demás nodos en la red P2P
        self.peersocks = []

        # Si no se pasan peers, una nueva red se inicia desde cero
        self.peernames = []
        if args["peers"]:
            self.__search_peers(args["peers"].split(','))
        else:
            print("No se pasaron peers. Este es el primero en la red P2P.")

        # Se inicializa el servicio de este nodo
        self.__initcomm(self.port)

    def start(self):
        while(True):
            try:
                instruccion = input(">")
                self.__execute_instruction(instruccion)
            except KeyboardInterrupt:
                print("\nNodo P2P finalizado...")

                self.stop()
                exit(0)

    def stop(self):
        """
        Avisa a los demas nodos que se va a desconectar
        """
        pass

    def __execute_instruction(self, inst):
        words = inst.split()

        if words[0] == "get":
            self.__request_getfile(words[1])
        else:
            print("[P2P] Instruccion desconocida:", words[0])

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
        self.__commthread.daemon = True
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

                self.peernames.append((peern[0], int(peern[1])))
            except ValueError:
                raise ValueError(
                    "error al parsear nodo P2P; debe ser del formato IP:PUERTO")

        # TODO: Verificar que direcciones erroneas no se agreguen a la list
        for pn in self.peernames:
            if self.__requestconnection(pn):
                print("[P2P] Conexion exitosa con", pn)
                print("[SHARE] Solicitando archivos a todos los peers")
                self.__request_virdir()

                return
            else:
                print("[P2P] Intento fallido de conectarse con:", pn)

        raise ValueError("no se pudo conectar con los peers proporcionados.")

    def __serveraccept(self):
        print("Atendiendo solicitudes...")
        while(True):
            con, addr = self.sock.accept()

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
            tmpsock.connect((peer_con[0], peer_con[1]))
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

    def __request_virdir(self):
        """
        Solicita los archivos a los nodos en la red P2P. Todos los nombres de
        archivos recibidos se almacenaran en 'sharefiles'.
        """
        for pn in self.peernames:
            with socket.socket() as tmpsock:
                tmpsock.connect(tuple(pn))

                # Solicitud
                tmpsock.send(message.REQDIRMSG)
                header = tmpsock.recv(5)

                if header[0] != message.GIVEDIR:
                    raise ValueError(
                        "[SHARE] error al solicitar archivos a", pn)

                # Primero se le piden sus archivos
                bodysize = int.from_bytes(header[1:5], byteorder="big")
                body = tmpsock.recv(bodysize)
                port, sharelist = message.parse_file_bytes(body, bodysize)
                self.__add_sharefiles(sharelist, pn)

                # Despues le comparte los suyos
                tmpsock.send(message.build_givedir_message(
                    self.port, self.files))

    def __request_getfile(self, fname):
        print("[GET] Solicitando archivo")
        peerswithfile = self.virtualdir[fname]

        self.__resource = [b'' for i in range(len(peerswithfile))]

        print("[REQFILE] Se esperan", len(self.__resource), "partes.")

        self.__sem = threading.Semaphore(0)

        for index, p in enumerate(peerswithfile, 1):
            t = threading.Thread(target=self.__recvfile_partitioned,
                                 args=(p, fname, index, len(peerswithfile)))
            t.start()

        for i in range(len(peerswithfile)):
            self.__sem.acquire()
            print("Peer #", i + 1, "terminado.")

        buff = bytearray()
        for r in self.__resource:
            print("WRITING:", len(r), "bytes.")
            buff.extend(r)
        
        with open(self.sharedir + '/' + fname, "wb") as rfile:
            rfile.write(buff)


        print("[REQFILE ]Archivo recibido.")

        # self.__update_virdir(fname)

    # def __update_virdir(self, fname):
    #     for p in self.peernames:
    #         with socket.socket() as tsock:
    #             tsock.connect(p)

    def __processmsg(self, msg, con, addr):
        """
        Procesa los 5 bytes recibidos y determina el tipo de mensaje y la accion
        correspondiente.
        """

        msgid = msg[0]
        if msgid == message.NCONNECT:
            # Se conecta con un nodo y depsues con los demas
            print("\n[P2P] Solicitud de conexion de", addr)
            self.__process_connection(msg, con, addr)
        elif msgid == message.ADDTHIS:
            print("[P2P] Se agrego un nuevo nodo.")
            self.__process_add(msg, con, addr)
        elif msgid == message.REQDIR:
            print("[SHARE] Se comparten elementos de la carpeta compartida.")
            self.__process_reqdir(con, addr)
        elif msgid == message.GETFILE:
            self.__process_getfile(msg, con, addr)
        elif msgid == message.UPDIR:
            self.__process_updir(msg, con, addr)
        else:
            print("[PROCESSING] Mensaje no procesable de", addr, ":\n", msg)

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
                tmpsock.connect((pn[0], pn[1]))
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

    def __process_reqdir(self, conn, addr):
        conn.send(message.build_givedir_message(self.port, self.files))

        header = conn.recv(5)
        if header[0] != message.GIVEDIR:
            raise ValueError("[SHARE] Error al recibir nombres de archivos \
            de nuevo nodo.")

        bodysize = int.from_bytes(header[1:5], byteorder="big")
        body = conn.recv(bodysize)
        port, sharefiles = message.parse_file_bytes(body, bodysize)
        self.__add_sharefiles(sharefiles, (addr[0], port))

    def __process_givedir(self, conn, addr):
        header = conn.recv(5)

        if header[0] != message.GIVEDIR:
            raise ValueError(
                "[SHARED] Error al recibir los archivos del nuevo nodo: \
                    mensaje no procesable.")
        bodysize = int.from_bytes(header[1:5], byteorder="big")
        body = conn.recv(bodysize)

    def __process_getfile(self, msg, conn, addr):
        fname, part, totalparts = message.parse_getfile_bytes(msg)

        with open(self.sharedir + '/' + fname, "rb") as f:
            fbytes = f.read()
            left, right = message.get_rangebytes(part, len(fbytes), totalparts)

        print("[SEND] Se mandara archivo",
              fname, "(", part, "/", totalparts, ") de", left, "a", right)
        print("[SEND] Tamano de trama:", right -
              left, "\tTamano:", len(fbytes))

        msg = message.build_sendfile_message(fbytes[left:right])
        start = 0
        buff = msg[:1024]
        while buff:
            print("Sending...")
            conn.send(buff)
            start += 1024
            buff = msg[start:start+1024]

    def __process_updir(self, msg, conn, addr):
        port = msg

    def __add_sharefiles(self, shfiles, pn):
        peerkey = makename(pn)
        print("[SHARE] Agregando archivos de", peerkey)

        for sf in shfiles:
            if sf not in self.virtualdir:
                self.virtualdir[sf] = set()

            self.virtualdir[sf].add(pn)

        print("[SHARE] Nuevo directorio")
        for k, v in self.virtualdir.items():
            print("\t", k, v)

    def __recvfile_partitioned(self, peer, fname, partnum, totalparts):
        with socket.socket() as filesock:
            filesock.connect(peer)
            filesock.send(message.build_getfile_message(
                fname, partnum, totalparts))

            buff = bytearray()
            resp = filesock.recv(1024)
            while resp:
                buff.extend(resp)
                resp = filesock.recv(1024)

            if buff[0] != message.SENDFILE:
                raise ValueError("no se recibio un mensaje con archivo.")

            bsize = int.from_bytes(resp[1:5], byteorder="big")
            print("Se recibieron", bsize, "bytes")
            del(buff[:5])
            self.__resource[partnum - 1] = buff

            print("BUFF", partnum, "finished:", len(
                self.__resource[partnum - 1]), "bytes")
            self.__sem.release()

    @staticmethod
    def __create_shared(sd):
        print("Directorio shared: ", sd)

        if not os.path.exists(sd):
            os.makedirs(sd)


def makename(ip):
    return ip[0] + ':' + str(ip[1])
