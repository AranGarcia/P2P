#!/usr/bin/env python3

import p2p
import sys

if len(sys.argv) < 2:
    print("run.py [IP]")
    exit(1)

pnode = p2p.P2Pnode(sys.argv[1:])
pnode.start()
