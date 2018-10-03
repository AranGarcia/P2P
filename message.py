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

class Message:
    """docstring for Message."""
    def __init__(self, mtype):
        self.mtype = mtype

    def __bytes__(self):
        raise NotImplementedError
