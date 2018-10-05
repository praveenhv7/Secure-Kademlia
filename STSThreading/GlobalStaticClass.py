import time
import socket
import threading
import logging
import sys, traceback
import struct
from Queue import Queue
import base64
import random
import xxhash
import pysodium
from Trees import Trees

class GlobalStaticVaraible():
    #STS Queue.
    inbound_queue = Queue()
    outbound_queue = Queue()

    # send for processing in DHT
    inbound_queue_dht = Queue()
    # output of DHT Processing
    outbound_queue_dht = Queue()

    outbound_queue_three = Queue()

    transSession = {}

    dhtTransSession={}

    rootNode = Trees(None, None, '', [], None, None)

    recurFindNodeEvent = threading.Event()

    requestNumbers=[0,2,4,6]

    responseNumbers=[1,3,5,7]