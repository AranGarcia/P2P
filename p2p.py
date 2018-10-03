import os.path
import socket
import threading

from enum import Enum


class P2Pnode:
    def __init__(self, args, sharedir='./share'):
        self.__initcomm(int(args["port"]))

        # Lista inicial vacía de los demás nodos en la red P2P
        self.peersocks = []

        # Creacion de la carpeta compartida
        self.sharedir = os.path.abspath(sharedir)
        P2Pnode.__create_shared(self.sharedir)

        # Si no se pasan peers, una nueva red se inicia desde cero
        if args["peers"]:
            self.peernames = args["peers"].split(';')
            print("Se intentara conectar con los siguientes peers", self.peernames)
            self.__search_peers()
        else:
            print("No se pasaron peers. Este es el primero en la red P2P.")
            self.peernames = []

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

    def __search_peers(self):
        """
        Se conecta con uno de los nodos en la red P2P. Si se pasaron las IP de mas de un
        nodo, entonces solicitara a todas hasta que conecte con solo una.

        Al conectar con uno, recibirá la lista de todos los demás nodos.
        """

        for p in self.peernames:
            try:
                # Cada peer debe estar de la forma IP:PUERTO
                peern = p.split(':')
            except ValueError as ve:
                raise ValueError(
                    "error al parsear nodo P2P; debe ser del formato IP:PUERTO")

            self.__requestconnection(peern)

    def __serveraccept(self):
        print("Atendiendo solicitudes...")
        while(True):
            con, addr = self.sock.accept()
            print("Mensaje recibido de", addr)

            msg = con.recv(1024)

            thr = threading.Thread(target=self.__processmsg, args=(msg,))
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

        # TODO: Envio de mensaje de a acuerdo a un protocolo
        tmpsock.send("Me mandas peers?".encode())

        return True

    def __processmsg(self, msg):
        print("Procesando mensaje:", msg)

    @staticmethod
    def __create_shared(sd):
        print("Directorio shared: ", sd)

        if not os.path.exists(sd):
            os.makedirs(sd)
