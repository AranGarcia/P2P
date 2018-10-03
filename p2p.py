import os.path
import socket
import threading

from enum import Enum


class P2PMessage(Enum):
    """
    Constantes para los mensajes que se utilizaran para el protocolo en la red
    P2P.
    """
    LIST = 0
    GET = 1
    SEND = 2
    DISC = 3


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
            self.peernames = arg["peers"]
            self.__search_peers()
        else:
            print("No se pasaron peers. Este es el primero en la red P2P.")
            self.peernames = []

        # TODO: Iniciar servicio del nodo

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
        self._t = threading.Thread(target=self.__serveraccept)
        self._t.start()

    def __search_peers(self):
        """
        Se conecta con uno de los nodos en la red P2P. Si se pasaron las IP de mas de un
        nodo, entonces solicitara a todas hasta que conecte con solo una.

        Al conectar con uno, recibirá la lista de todos los demás nodos.
        """

        tempsock = socket.socket()

        for p in self.peernames:
            try:
                # Cada peer debe estar de la forma IP:PUERTO
                peer_ip, peer_sck = p.split(':')
            except ValueError as ve:
                raise ValueError(
                    "error al parsear nodo P2P; debe ser del formato IP:PUERTO")

            print("Conectando con", peer_ip, peer_sck)
            tempsock.connect((peer_ip, int(peer_sck)))

    def __serveraccept(self):
        print("Atendiendo solicitudes...")
        while(True):
            con, addr = self.sock.accept()
            print("Se recibio una solicitud de", addr)

    @staticmethod
    def __create_shared(sd):
        print("Directorio shared: ", sd)

        if not os.path.exists(sd):
            os.makedirs(sd)
