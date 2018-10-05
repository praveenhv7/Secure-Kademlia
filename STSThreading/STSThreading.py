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
from STSClass import StsBox
import DHTClass
from GlobalStaticClass import GlobalStaticVaraible

#################################CONSTANTS##################################################
STS_PROPOSE_MSG = 0
STS_ACCEPT_MSG = 1
STS_DATA_EXG_MSG = 2
STS_TERMINATE_MSG = 3
INBOUND_MSG = 'INBOUND'
OUTBOUND_MSG = 'OUTBOUND'
SIG_VALIDATION = False
IP_VALIDATION = False
MY_Home = '/home/netsec64/'

###################################GLOBAL###########################################



####################################LOGGER###############################################

logging.basicConfig(level=logging.DEBUG,
                    format='(%(threadName)-10s) %(message)s',
                    )

transSession = {}

connectionStates={}
connectionStates.update({'P':'Propose'})
connectionStates.update({'WA':'Waiting for Accept Message'})
connectionStates.update({'A':'Accept Message'})
connectionStates.update({'DS':'Data Sent'})
connectionStates.update({'WD':'Waiting for Data'})
connectionStates.update({'C':'Completed'})

#####################################SESSION RELATED################################################
class SessionRecvObject():
    def __init__(self, ipAddress, port, sessionKey, dhtMessage, msgDirection, cipherSuiteReq, cipherSuiteNxt,
                 connectionState):
        self.ipAddress = ipAddress
        self.port = port
        self.sessionKey = sessionKey
        self.findNodeEvent = None
        self.findValueEvent = None
        self.storeReqEvent = None
        self.dhtMessage = dhtMessage
        self.msgDirection = msgDirection
        self.cipherSuiteReq = cipherSuiteReq
        self.cipherSuiteNxt = cipherSuiteNxt
        self.cipherSuiteCount = 0
        self.connectionState = connectionState
        self.his_public_key = None
        self.my_public_key = None
        self.my_secret_key = None

    def getCipherSuiteNxt(self):
        return self.cipherSuiteNxt

    def setCipherSuiteNxt(self, cipherSuite):
        self.cipherSuiteNxt = cipherSuite

    def setFindNodeEvent(self, event):
        self.findNodeEvent = event

    def setFindValueEvent(self, event):
        self.findValueEvent = event

    def setStoreReqEvent(self, event):
        self.storeReqEvent = event

    def setDhtMessage(self, message):
        self.dhtMessage = message

    def getDhtMessage(self):
        return self.dhtMessage

    def setcipherSuiteCount(self):
        self.cipherSuiteCount = self.cipherSuiteCount + 1
        logging.debug('New value of cipher suite count is ' + str(self.cipherSuiteCount))

    def getcipherSuiteCount(self):
        return self.cipherSuiteCount

    def setConnectionState(self, state):
        self.connectionState = state

    def getMsgDirection(self):
        return self.msgDirection

    def getHisPublicKey(self):
        return self.his_public_key

    def setHisPublicKey(self, key):
        self.his_public_key = key

    def getMySecretKey(self):
        return self.my_secret_key

    def setMySecretKey(self, key):
        self.my_secret_key = key

    def getMyPublicKey(self):
        return self.my_public_key

    def setMyPublicKey(self, key):
        self.my_public_key = key

    def getSessionKey(self):
        return self.sessionKey

    def setSessionKey(self, key):
        self.sessionKey = key


######################################QUEUE Related###################################################

class OutBoundQueue():
    def __init__(self, stsMessageToSend, addr):
        self.stsMessageToSend = stsMessageToSend
        self.address = addr

    def getStsMessageToSend(self):
        return self.stsMessageToSend

    def getAddress(self):
        return self.address

    def setStsMessageToSend(self, message):
        self.stsMessageToSend = message

    def setAddress(self, addr):
        self.address = addr

class DHTQueue():
    def __init__(self, dhtMessage, addr):
        self.dhtMessage = dhtMessage
        self.address = addr

    def getDhtMessage(self):
        return self.dhtMessage

    def getAddress(self):
        return self.address

    def setDhtMessage(self, message):
        self.stsMessageToSend = message

    def setAddress(self, addr):
        self.address = addr


#####################################STS PROPOSE######################################################
def getNextCipherSuite(currentCipherSuite):
    if (currentCipherSuite == 0):
        return 1
    elif (currentCipherSuite == 1):
        return 1
    elif (currentCipherSuite == 2):
        return 2
    if (currentCipherSuite == 3):
        return 4
    elif (currentCipherSuite == 4):
        return 4
    elif (currentCipherSuite == 5):
        return 5


#################################### STS #############################################################
def generateIpPortKey(addr):
    return (addr[0] + ':' + str(addr[1]))


def listenToAllReq(sock, message, addr):
    logging.debug('New Sub Thread Created ')
    logging.debug('Received Message to Server ' + repr(message) + 'From address ' + str(addr))

    msg_type = struct.unpack('>B', message[:1])[0]

    if (msg_type == STS_PROPOSE_MSG):

        sessionObj = None
        stsBox = StsBox(message[1:], addr[0], addr[1])
        logging.debug('Decoding propose message ' + repr(message[1:]))
        proposeMsgReq = stsBox.proposeMsgDecode(message[1:])

        if (transSession.has_key(generateIpPortKey(addr))):
            logging.debug('Session exists extracting session info')
            cipherSuiteReq = proposeMsgReq.get('cipherSuite')
            cipherSuiteNxt = getNextCipherSuite(cipherSuiteReq)
            sessionObj = transSession.get(generateIpPortKey(addr))
            sessionObj.setCipherSuiteNxt(cipherSuiteNxt)
        else:
            #this is for incoming new connection
            logging.debug('Session does not exist creating session info')
            cipherSuiteReq = proposeMsgReq.get('cipherSuite')
            cipherSuiteNxt = getNextCipherSuite(cipherSuiteReq)
            sessionObj = SessionRecvObject(addr[0], addr[1], '', '', INBOUND_MSG, cipherSuiteReq, cipherSuiteNxt, 'P')
        sessionObj.setcipherSuiteCount()

        logging.debug('Send a propose Message by putting it in queue')
        logging.debug('cipher suite count is ' + str(sessionObj.getcipherSuiteCount()))
        # (self,ipAddress,port,sessionKey,dhtMessage,msgDirection,cipherSuite,cipherSuiteNxt,connectionState):
        # check to see if a session exists.

        if (sessionObj.getcipherSuiteCount() > 6):
            transSession.pop(generateIpPortKey(addr))
            outboundObj = OutBoundQueue(stsBox.terminateSession(0), addr)
            GlobalStaticVaraible.outbound_queue.put(outboundObj)
            logging.debug('Send a Terminate Message as suite limit is passed')
            return

        logging.debug('Cipher Suite Req ' + str(cipherSuiteReq) + ' : cipher suite next ' + str(cipherSuiteNxt))
        logging.debug('Message direction ' + sessionObj.getMsgDirection())
        messageResponse = ''
        # checking if a propose was already sent and if cipher suite matched
        if (cipherSuiteReq == cipherSuiteNxt and sessionObj.getMsgDirection() == OUTBOUND_MSG):
            logging.debug('Send a Accept message message')
            sessionObj.setConnectionState('A')
            my_secret_key = sessionObj.getMySecretKey()
            my_public_key = sessionObj.getMyPublicKey()
            his_public_key = proposeMsgReq.get('his_pub_key')
            sessionObj.setHisPublicKey(his_public_key)
            messageResponse, session_key = stsBox.createAcceptMessage(my_secret_key, my_public_key,
                                                                      his_public_key, cipherSuiteNxt)
            sessionObj.setSessionKey(session_key)

        # checking if message is new one.
        elif (cipherSuiteReq == cipherSuiteNxt and sessionObj.getMsgDirection() == INBOUND_MSG):
            logging.debug('Send a propose message')
            sessionObj.setConnectionState('WA')
            messageResponse, proposeMsgInfo = stsBox.proposeMessage012(cipherSuiteNxt)


        else:
            # To do check for ciphher suite 3,4,5
            sessionObj.setConnectionState('P')
            messageResponse, proposeMsgInfo = stsBox.proposeMessage012(cipherSuiteNxt)

        transSession.update({generateIpPortKey(addr): sessionObj})

        outboundObj = OutBoundQueue(messageResponse, addr)
        GlobalStaticVaraible.outbound_queue.put(outboundObj)

    elif (msg_type == STS_ACCEPT_MSG):
        logging.debug('Received accept message send a reponse accept message')
        logging.debug('establish session Key for this session and also change state')
        acceptMessage = message[1:]
        messageResponse = ''
        stsBox = StsBox('', addr[0], addr[1])
        # TO verify the accept message
        if (transSession.has_key(generateIpPortKey(addr))):
            sessionObj = transSession.get(generateIpPortKey(addr))
            msgDirection = sessionObj.getMsgDirection()
            if (msgDirection == INBOUND_MSG and sessionObj.getConnectionState() == 'WA'):
                messageResponse, session_key = stsBox.createAcceptMessage(sessionObj.getSecretKey(),
                                                                          sessionObj.getPublicKey(),
                                                                          sessionObj.getHisPublicKey())
                sessionObj.setConnectionState('A')
                sessionObj.setSessionKey(session_key)
            else:
                #for an outbound message
                sessionObj.setConnectionState('DS')
                # check for accept message..
                stsBox.setMessageToSend(sessionObj.getDhtMessage())
                messageResponse = stsBox.createDataPacketWithEncr(sessionObj.getSessionKey(),
                                                                  sessionObj.getCipherSuiteNxt())

        outboundObj = OutBoundQueue(messageResponse, addr)
        GlobalStaticVaraible.outbound_queue.put(outboundObj)


    elif (msg_type == STS_DATA_EXG_MSG):
        dataMessage = message[1:]
        messageResponse = ''
        stsBox = StsBox('', addr[0], addr[1])
        logging.debug('Received data message send a reponse data message')
        logging.debug('establish session Key for this session and also change state')
        if (transSession.has_key(generateIpPortKey(addr))):
            sessionObj = transSession.get(generateIpPortKey(addr))
            msgDirection = sessionObj.getMsgDirection()
            if (msgDirection == INBOUND_MSG):
                messageResponse = ''
                stsBox.decryptDataPacketEncr(sessionObj.getSessionKey(), dataMessage, sessionObj.getCipherSuiteNxt())
                # need to put message
                sendToDHTQueue(stsBox, (addr[0], addr[1]))
                #keep the session
                sessionObj.setConnectionState('WD')
            else:
                #taking the data and then terminating the connection.
                stsBox.decryptDataPacketEncr(sessionObj.getSessionKey(), dataMessage, sessionObj.getCipherSuiteNxt())
                #need to put message
                sendToDHTQueue(stsBox, (addr[0],addr[1]))

                outboundObj = OutBoundQueue(stsBox.terminateSession(0), addr)
                GlobalStaticVaraible.outbound_queue.put(outboundObj)
                transSession.pop(generateIpPortKey(addr))



    elif (msg_type == STS_TERMINATE_MSG):
        stsBox=StsBox('',addr[0],addr[1])
        logging.debug('Received terminate message send a reponse terminate message')
        logging.debug('remove session Key for this session and also change state')
        transSession.pop(generateIpPortKey(addr))
        outboundObj = OutBoundQueue(stsBox.terminateSession(0), addr)
        GlobalStaticVaraible.outbound_queue.put(outboundObj)



def listenSts(sock):
    logging.debug('Started Listening')
    while True:
        logging.debug('total threads ' + str(threading.active_count()))
        message, addr = sock.recvfrom(1024)
        if (threading.active_count() < 50):
            logging.debug('Creating listen thread for each msg')
            threadSts = threading.Thread(target=listenToAllReq, args=(sock_tmp, message, addr))
            threadSts.start()
            threadSts.join()
        else:
            logging.debug('Thread Pool is full send terminate message')

def waitForDHTMessages():
    logging.debug('Waiting for a DHT Message')
    while True:
        if(GlobalStaticVaraible.outbound_queue_dht.put.not_empty):
            addressReqState=GlobalStaticVaraible.outbound_queue_dht.get()
            interfaceDHTToSTSOutbound(addressReqState.getMessage(),addressReqState.getSockAddress())

def sendToDHTQueue(stsBox,addr):
    logging.debug('Sending message to DHT')
    GlobalStaticVaraible.inbound_queue_dht.put((stsBox.getMessageToRcv(), addr[0], addr[1]))



# get message from DHT and then wrap it with STS
# if the message is new create a propose message
# if the message is for previous request get the session object details
# encrypt the data and push it to outbound queue.
#
def interfaceDHTToSTSOutbound(messageToSend, addr):

    if(transSession.has_key(generateIpPortKey(addr))):
        sessionObj = transSession.get(generateIpPortKey(addr))
        msgDirection = sessionObj.getMsgDirection()
        if(msgDirection == INBOUND_MSG and sessionObj.getConnectionState() == 'WD'):
            stsBox = StsBox(messageToSend, addr[0], addr[1])
            messageResponse = stsBox.createDataPacketWithEncr(sessionObj.getSessionKey(),
                                                              sessionObj.getCipherSuiteNxt())
            outboundObj = OutBoundQueue(messageResponse, addr)
            GlobalStaticVaraible.outbound_queue.put(outboundObj)
    else:
        cipherSuiteReq = 1
        cipherSuiteNxt = -1
        sessionObj = SessionRecvObject(addr[0], addr[1], '', messageToSend, OUTBOUND_MSG, cipherSuiteReq, cipherSuiteNxt,
                                       'P')

        stsBox = StsBox(messageToSend, addr[0], addr[1])
        proposeMsg, proposeMsgInfo = stsBox.proposeMessage012(1)

        sessionObj.setMyPublicKey(proposeMsgInfo.get('my_public_key'))
        sessionObj.setMySecretKey(proposeMsgInfo.get('my_secret_key'))
        logging.debug('******************************')
        logging.debug(str(addr))
        logging.debug('My Public Key ' + proposeMsgInfo.get('my_public_key').encode("hex"))
        logging.debug('My Secret Key ' + proposeMsgInfo.get('my_secret_key').encode("hex"))
        logging.debug('******************************')
        transSession.update({generateIpPortKey(addr): sessionObj})
        outboundObj = OutBoundQueue(proposeMsg, addr)
        GlobalStaticVaraible.outbound_queue.put(outboundObj)


def createFIND_NODEPacket(nodeIdNext):
    nodeId = 'netsec64'
    nodeIdHashed = xxhash.xxh64(nodeId).intdigest() & 0xffff
    lenHashedId = int(2)
    nonce = int(random.randrange(65535))
    lenNonce = int(2)
    lenKey = int(2)
    nodeIdNextHashed = nodeIdNext
    stPkdVal = struct.pack('>bIHIHIH', int(4), lenHashedId, nodeIdHashed, lenNonce, nonce, lenKey, nodeIdHashed)
    return stPkdVal, lenNonce, lenHashedId


# get message from DHT and check if a connection exists for the same
# and the connection is inbound . get the session details
# encrypt the message and push it to outbound queue
# might need a dht object
#
def interfaceSTSToDHTInbound(messageToSend, addr):
    key = generateIpPortKey(addr)
    if transSession.has_key(key):
        sessionObj = transSession.get(key)
        # encrypt the message and pack it with STS
        GlobalStaticVaraible.outbound_queue.put('')

#Thread can be used to clear the queue
#might not be needed as it just sends
#
#
def sendSts(sock):
    while True:
        if (GlobalStaticVaraible.outbound_queue.not_empty):
            objectToSend = GlobalStaticVaraible.outbound_queue.get()
            logging.debug('Read from queue')
            ipAddress = objectToSend.getAddress()[0]
            port = objectToSend.getAddress()[1]
            logging.debug('Ip Address' + ipAddress)
            logging.debug('Port' + str(port))

            key = generateIpPortKey((ipAddress, port))
            if(transSession.has_key(key)):
                sessionObj = transSession.get(key)
                # if session exists and inbound just send no need to track.
                logging.debug(
                    'Sending message ' + repr(objectToSend.getStsMessageToSend()) + ' to address ' + str((ipAddress, port)))

                if (sessionObj.getMsgDirection() == INBOUND_MSG):
                    sock.sendto(objectToSend.getStsMessageToSend(), (ipAddress, port))
                else:
                    sock.sendto(objectToSend.getStsMessageToSend(), (ipAddress, port))
            # else create a session with outbound tag.
            else:
                stsBox=StsBox('',ipAddress,port)
                sock.sendto(stsBox.terminateSession(0),(ipAddress,port))


################################### MAIN #######################################################

localIp = '0.0.0.0'
sock_tmp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
server_address = '0.0.0.0'
server_port = 1337
server = (server_address, server_port)
sock_tmp.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
sock_tmp.bind(server)

StsBox.initAll(sock_tmp)

packet, lenNonce, lenHashedId = createFIND_NODEPacket('netsec64')
bootstrapNodeDetails = ('xxx.xxx.xxx.xxx', 1337)
interfaceDHTToSTSOutbound(packet, bootstrapNodeDetails)

logging.debug('starting threads')
threadOne = threading.Thread(target=listenSts, args=(sock_tmp,))
logging.debug( 'Thread 1 Created')
threadTwo = threading.Thread(target=sendSts, args=(sock_tmp,))
logging.debug('Thread 2 Created')
threadDHTIntf=threading.Thread(target=DHTClass.startDHT, args=())

threadOne.start()
threadTwo.start()
threadDHTIntf.start()
logging.debug('All Threads Started')



