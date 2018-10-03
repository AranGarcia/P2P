#!/usr/bin/env python3

import argparse
import sys

import p2p

parser = argparse.ArgumentParser(description="Inicia el nodo P2P. Si no se \
    proporciona una lista de peers, el nodo inicializara la red.")
parser.add_argument('--port', type=int, default=8888, required=False,
                    help="puerto para el socket del nodo")
parser.add_argument('--peers', help="lista de peers en la red P2P")

args = parser.parse_args()
print(args)

argv = vars(args)

pnode = p2p.P2Pnode(argv)
pnode.start()
