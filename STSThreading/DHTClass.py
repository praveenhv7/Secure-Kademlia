import socket
import sys
import base64
import struct
import random
import xxhash
import time
from threading import Thread
import logging
import threading
from GlobalStaticClass import GlobalStaticVaraible
from Trees import TuplesIPPortId

####################################LOGGER###############################################

logging.basicConfig(level=logging.DEBUG,
                    format='(%(threadName)-10s) %(message)s',
                    )

#############################################################################################

storedData = {}
dataWithme = {}



class AddressRequestState():
    def __init__(self, reqState, ipAddress, port, message):
        self.reqState = reqState
        self.ipAdress = ipAddress
        self.port = port
        self.message = message
        self.destinationAddress = [(ipAddress, port)]

    def getPort(self):
        return self.port

    def getIpAddress(self):
        return self.ipAdress

    def getMessage(self):
        return self.message

    def getSockAddress(self):
        return (self.ipAdress, self.port)


def generateIpPortKey(addr, reqState):
    return (addr[0] + ':' + str(addr[1]) + ':' + str(reqState))


# class to handle triples having ip port node id and timeout
class DataWithTimeOut:
    data = ''
    timeOut = 100

    def __init__(self, dataToStore, timeOut):
        self.data = dataToStore
        self.timeOut = timeOut


# returns longest prefix for a list of values
def checkLongestPrefix(bucket):
    checkBit = 1
    stringBucket = []
    result = ''
    length = len(bucket)
    for elem in bucket:
        temp = str(bin(elem))[2:]
        if (len(temp) < 8):
            padding = 8 - len(temp)
            while (padding > 0):
                temp = '0' + temp
                padding = padding - 1

        stringBucket.append(temp)

    # print 'resultant string ', stringBucket
    matched = [];
    minMatched = 8;
    elemNCount = {}
    for elem in stringBucket:
        counter = 1
        msbBit = elem[0]
        for ch in elem[1:]:
            if (ch == msbBit):
                counter = counter + 1
            else:
                break
        matched.append(msbBit + ':' + str(counter))
        # print 'elem ', elem, ' matched ', counter
        elemNCount.update({elem: counter})

    matched.sort()
    # print 'longest prefix is ', matched[0], ' matched element '
    return matched, elemNCount


def createAErrorPacket(msg):
    nodeId = 'netsec64'
    nodeIdHashed = xxhash.xxh64(nodeId).intdigest() & 0xffff
    lenHashedId = int(2)
    nonce = int(random.randrange(65535))
    lenNonce = int(2)
    msgLen = len(msg)
    errorPacket = struct.pack('>BIHIHI' + str(msgLen) + 's', int(8), nodeIdHashed, lenNonce, nonce, msgLen, msg)
    return errorPacket


# Routing table implementation
# to-do split on self node


def createPINGReqOrRes(req, clientAddress, packedRcvd, node):
    myNodeId = 'netsec64'
    nodeIdHashed = xxhash.xxh64(myNodeId).intdigest() & 0xffff
    lenHashedId = int(2)
    nonce = int(random.randrange(65535))
    lenNonce = int(2)
    reqRes = -1
    # update the node in the routing table
    # dataRcvd=struct.unpack('>BIHIH',packedRcvd)
    # node.addElement(TuplesIPPort(clientAddress[0],clientAddress[1],dataRcvd[2]))
    if (req == True):
        reqRes = 0
    else:
        reqRes = 1
    packet = struct.pack('>BIHIH', reqRes, lenHashedId, nodeIdHashed, lenNonce, nonce)
    return packet


# converts decimal to IP address.
def convertDecimalToIP(num):
    number = int(num)
    return (
        (str((number >> 24) & 0xFF)) + '.' + (str((number >> 16) & 0xFF)) + '.' + (str((number >> 8) & 0xFF)) + '.' + (
            str((number & 0xFF))))


# convert Ip to decimal
def convertIpToDecimal(ipAddr):
    splitIpAddr = ipAddr.split('.')
    # print 'split ip address ',splitIpAddr
    ipDecimal = int(int(splitIpAddr[0]) << 24) + int(int(splitIpAddr[1]) << 16) + int(int(splitIpAddr[2]) << 8) + int(
        splitIpAddr[3])
    return ipDecimal


def convertDecimalToIPv6(num):
    number = int(num)
    return (str(hex(number >> 96 & 0xFFFF).rstrip("L")[2:])) + ':' + (
        str(hex(number >> 80 & 0xFFFF).rstrip("L")[2:])) + ':' + (
           str(hex(number >> 64 & 0xFFFF).rstrip("L")[2:])) + ':' + (
               str(hex(number >> 48 & 0xFFFF).rstrip("L")[2:])) + ':' + (
               str(hex(number >> 32 & 0xFFFF).rstrip("L")[2:])) + ':' + (
               str(hex(number >> 16 & 0xFFFF).rstrip("L")[2:])) + ':' + (str(hex(number & 0xFFFF).rstrip("L")[2:]))


def convertIPV6toDecimal(ipAddr):
    splitIpAddr = ipAddr.split(':')
    # print 'split ip address ', splitIpAddr
    count = 128 - 16
    ipDecimal = 0
    index = 0
    while (count > -1):
        ipDecimal = ipDecimal + long(long(splitIpAddr[index], 16) << count)
        count = count - 16
        index = index + 1
    return ipDecimal


def readFIND_NODERequest(node, payload):
    unpackedData = struct.unpack('>BIHIHIH', payload)
    return unpackedData[6]


# creates a response for the K nearest nodes found. for  a ID given
def createFIND_NODEResponse(requestNodeId, response, node):

    #recursiveFindNearestNodes(node, nodeId, seenNodes, notSeenNodes):
    #nodeTuples = node.findKNearestNodesFeeder(requestNodeId, node, [])
    nodeTuples = recursiveFindNearestNodes(node,requestNodeId,[] , [])
    sizeOfReply = 13 * len(nodeTuples)
    nodeId = 'netsec64'
    nodeIdHashed = xxhash.xxh64(nodeId).intdigest() & 0xffff
    lenHashedId = int(2)
    nonce = int(random.randrange(65535))
    lenNonce = int(2)
    packedData = []
    packedIpPortNodeId = ''
    for tuple in nodeTuples:
        ipAddr = 0
        if "." in tuple.ipAddress:
            # print 'IPV4'
            ipAddr = convertIpToDecimal(tuple.ipAddress)
            packedData.append(struct.pack('>BIHIH', int(4), ipAddr, int(tuple.port), int(2), tuple.nodeId))
        elif ":" in tuple.ipAddress:
            # print 'IPV6'
            ipAddr = convertIPV6toDecimal(tuple.ipAddress)
            packedData.append(struct.pack('>BQQHIH', int(6), ipAddr, int(tuple.port), int(2), tuple.nodeId))
    # print 'raw packed data ',repr(packedData[0])
    for elem in packedData:
        packedIpPortNodeId = packedIpPortNodeId + elem

    packedReponse = struct.pack('>BIHIHI', int(5), lenHashedId, nodeIdHashed, lenNonce, nonce, sizeOfReply)

    packedReponse = packedReponse + packedIpPortNodeId
    return packedReponse


# reads data from response obtained for K nearest ndoes.
# returns list of TuplesIPPortId
def readFindNodeReponse(data):
    bucketList = []
    if (len(data) > 17):
        # print 'rcvd data ', repr(data), '\n in string ', data, ' length of the data received ', len(data)
        # print 'hexed data ', data.encode('hex')
        unpackRcvdData = struct.unpack('>BIHIHI', data[0:17])
        # print 'un packed data ', unpackRcvdData
        # print ' un packed data ', unpackRcvdData[5]

        lenToBeParsed = unpackRcvdData[5]
        count = 0
        # ipType = struct.unpack('>B', data[17 + count])
        # print 'Testing ', ipType[0]
        while (count < lenToBeParsed):
            ipType = struct.unpack('>B', data[17 + count])
            # print 'ipType obtained ', ipType[0]
            if (ipType[0] == 4):
                endCount = count + 13 + 17
                ipData = struct.unpack('>IHIH', data[17 + 1 + count:endCount])
                # print 'received IP4 data ', ipData, 'Ip Address', socket.inet_ntoa(struct.pack('!L', ipData[0]))
                # bucketList.append(IpPortNode(ipData[0], ipData[1], ipData[3]))
                bucketList.append(TuplesIPPortId(socket.inet_ntoa(struct.pack('!L', ipData[0])), ipData[1], ipData[3]))
                count = count + 13
            elif (ipType[0] == 6):
                endCount = count + 25 + 17
                ipData = struct.unpack('>QQHIH', data[17 + 1 + count:endCount])
                finaData = (ipData[0] << 64) | ipData[1]
                ipV6Address = convertDecimalToIPv6(finaData)
                # print 'received IP6 data', ipData, ' ipv6 address ', ipV6Address
                bucketList.append(TuplesIPPortId(ipV6Address, ipData[1], ipData[3]))
                count = count + 25
            else:
                print 'ERROR -> NOT A IP TYPE'
                break
        for ipSaved in bucketList:
            print 'Ip address ', ipSaved.ipAddress, ' port ', ipSaved.port, ' node id :', ipSaved.nodeId
        return bucketList
    else:
        return bucketList


def createFIND_NODEPacket(nodeIdNext):
    nodeId = 'netsec64'
    nodeIdHashed = xxhash.xxh64(nodeId).intdigest() & 0xffff
    # print 'node id hashed ', nodeIdHashed
    lenHashedId = int(2)
    # print 'length of hash Node id', int(lenHashedId)
    nonce = int(random.randrange(65535))
    lenNonce = int(2)
    # print 'length of nonce ', int(lenNonce)
    # print 'nonce is ', nonce
    # print 'len of nonce is ', lenNonce
    lenKey = int(2)
    nodeIdNextHashed = nodeIdNext
    stPkdVal = struct.pack('>bIHIHIH', int(4), lenHashedId, nodeIdHashed, lenNonce, nonce, lenKey, nodeIdNextHashed)
    return stPkdVal, lenNonce, lenHashedId


# returns a response packet of find Node
# socket used to send to a perfect node.
def sendNearestNodeRequest(nodeIdTuple):
    # print 'Debugging : inside sendNearestNodeRequest'
    # construct the packet
    nodeId = nodeIdTuple.nodeId
    packet, lenNonce, lenHashId = createFIND_NODEPacket(nodeId)
    # print 'Debugging : packet ',packet
    try:
        # sock.settimeout(1)
        # sock.sendto(packet,(nodeIdTuple.ipAddress,nodeIdTuple.port))
        # dataReceived=sock.recv(1500)
        pushRequestMessagesToSTS(packet, nodeIdTuple.ipAddress, nodeIdTuple.port)

    except:
        print 'Exception Raised No Reply'
        return ''


# recursively find 3 nearest nodes
# 1. add nodes
# 2  send request to another 3 nodes from the obtained k nearest nodes (k=4 and alpha = 3)
# 3  keep track of nodes that are seen and are checked to avoid repeating find node calls to same node
# 4  keep finding nearest nodes till all nodes have been checked and distance is not decreasing.
# 5  update the routing table
# 6   Used by find value and store value.
# Returns tuples ipAddress, Port, nodeID using tree routing table
def recursiveFindNearestNodes(node, nodeId, seenNodes, notSeenNodes):
    # sends the 4 nearest node for a node ID
    # tuples are received
    # print 'Debugging : Inside recursiveFindNearestNodes '

    nodeTuples = node.findKNearestNodesFeeder(nodeId, node, [])
    # print 'Debugging : value of nodeTuples ',len(nodeTuples)
    nearestNodes = nodeTuples[:3]
    # print 'Debugging : value of nearestNodes ', len(nearestNodes)
    # compute the lowest distance observed
    lowestDistance = (nearestNodes[0].nodeId ^ nodeId)
    # to check
    notSeenNodes = nearestNodes[3:]
    # print 'Debugging : value of notSeenNodes ', len(notSeenNodes)
    # each TuplesIpPortNodeId
    # querying for 3 nearest node
    # and storing results in not seenNodes. for further parsing...
    ipAddressList=[]
    for elem in nearestNodes:
        ipAddressList.append((elem.ipAddress,elem.port))
        sendNearestNodeRequest(elem)

    # setting the event
    GlobalStaticVaraible.recurFindNodeEvent.set()
    dataRcvd = removeReponseMessageFromSTSSync(ipAddressList)
    tempBucket = readFindNodeReponse(dataRcvd)
    ipAddressList=[]
    # contains the objests TuplesIpPortNodeId
    # find the nearest node for the received response; response contains the Tuples
    for elem in tempBucket:
        node.addElement(elem)
        distance = (elem.nodeId ^ nodeId)
        if (distance <= lowestDistance):
            lowestDistance = distance
            if (elem.nodeId not in notSeenNodes):
                notSeenNodes.append(elem)

    for elem in notSeenNodes:
        node.addElement(elem)
        sendNearestNodeRequest(elem)

    GlobalStaticVaraible.recurFindNodeEvent.set()
    dataRcvd = removeReponseMessageFromSTSSync(ipAddressList)
    tempBucket = readFindNodeReponse(dataRcvd)
    ipAddressList = []
    for elem in tempBucket:
        distance = (elem.nodeId ^ nodeId)
        if (distance <= lowestDistance):
            lowestDistance = distance
            if (elem.nodeId not in notSeenNodes):
                notSeenNodes.append(elem)

    lenOfNotSeenNodes = len(notSeenNodes)
    if (lenOfNotSeenNodes > 4):
        lenStart = lenOfNotSeenNodes - 4
        retNodes = notSeenNodes[lenStart:]
        return retNodes
    else:
        return notSeenNodes


def constructFindValueReponse(data):
    # sizeOfReply = 13 * len(nodeTuples)
    nodeId = 'netsec64'
    nodeIdHashed = xxhash.xxh64(nodeId).intdigest() & 0xffff
    lenHashedId = int(2)
    nonce = int(random.randrange(65535))
    lenNonce = int(2)
    sizeOfData = len(data)
    packedReponse = struct.pack('>BIHIHII' + str(sizeOfData) + 's', int(7), lenHashedId, nodeIdHashed, lenNonce, nonce,
                                int(0), sizeOfData, data)
    return packedReponse


def createFIND_VALUEPacket(dataId):
    nodeId = 'netsec64'
    nodeIdHashed = xxhash.xxh64(nodeId).intdigest() & 0xffff
    # print 'node id hashed ', nodeIdHashed
    lenHashedId = int(2)
    # print 'length of hash Node id', int(lenHashedId)
    nonce = int(random.randrange(65535))
    lenNonce = int(2)
    # print 'length of nonce ', int(lenNonce)
    # print 'nonce is ', nonce
    # print 'len of nonce is ', lenNonce
    lenKey = int(2)
    nodeIdNextHashed = xxhash.xxh64(dataId).intdigest() & 0xffff
    stPkdVal = struct.pack('>bIHIHIH', int(6), lenHashedId, nodeIdHashed, lenNonce, nonce, lenKey, nodeIdNextHashed)
    return stPkdVal, lenNonce, lenHashedId


def sendNearestValueRequest(sock, elem, nodeId):
    # construct the packet
    # nodeId = nodeId
    packet, lenNonce, lenHashId = createFIND_VALUEPacket(nodeId)
    try:
        # sock.settimeout(1)
        # sock.sendto(packet, (elem.ipAddress, elem.port))
        dataReceived = pushRequestMessagesToSTS(packet, elem.ipAddress, elem.port)
        if (len(dataReceived) > 0):
            return dataReceived
        else:
            return ''
    except:
        return ''


def readFindValueReponse(data):
    # print 'rcvd data ', repr(data), '\n in string ', data, ' length of the data received ', len(data)
    # print 'hexed data ', data.encode('hex')
    unpackRcvdData = struct.unpack('>BIHIHI', data[0:17])
    # print 'un packed data ', unpackRcvdData
    # print ' un packed data ', unpackRcvdData[5]
    bucketList = []
    lenToBeParsed = unpackRcvdData[5]
    if (lenToBeParsed > 0):
        count = 0
        # ipType = struct.unpack('>B', data[17 + count])
        # print 'Testing ', ipType[0]
        while (count < lenToBeParsed):
            ipType = struct.unpack('>B', data[17 + count])
            # print 'ipType obtained ', ipType[0]
            if (ipType[0] == 4):
                endCount = count + 13 + 17
                ipData = struct.unpack('>IHIH', data[17 + 1 + count:endCount])
                # print 'received IP4 data ', ipData, 'Ip Address', socket.inet_ntoa(struct.pack('!L', ipData[0]))
                # bucketList.append(IpPortNode(ipData[0], ipData[1], ipData[3]))
                bucketList.append(TuplesIPPortId(ipData[0], ipData[1], ipData[3]))
                count = count + 13
            elif (ipType[0] == 6):
                endCount = count + 25 + 17
                ipData = struct.unpack('>QQHIH', data[17 + 1 + count:endCount])
                finaData = (ipData[0] << 64) | ipData[1]
                ipV6Address = convertDecimalToIPv6(finaData)
                # print 'received IP6 data', ipData, ' ipv6 address ', ipV6Address
                bucketList.append(TuplesIPPortId(ipV6Address, ipData[1], ipData[3]))
                count = count + 25
            else:
                print 'ERROR -> NOT A IP TYPE'
                break
        for ipSaved in bucketList:
            print 'Ip address ', ipSaved.ipAddress, ' port ', ipSaved.port, ' node id :', ipSaved.nodeId
        return bucketList, False
    else:
        dataAvail = struct.unpack('>I', data[17:21])
        dataStored = struct.unpack('>' + str(dataAvail) + 's', data[21:])
        return dataStored, True


        # recursively find 3 nearest nodes
        # 1. add nodes
        # 2  send request to another 3 nodes from the obtained k nearest nodes (k=4 and alpha = 3)
        # 3  keep track of nodes that are seen and are checked to avoid repeating find node calls to same node
        # 4  keep finding nearest nodes till all nodes have been checked and distance is not decreasing.
        # 5  update the routing table
        # 6   Used by find value and store value.
        # IMP node id is value hash.
        #


def recursiveFindNearestNodeValues(node, nodeId, sock, seenNodes, notSeenNodes):
    # sends the 4 nearest node for a node ID
    # tuples are received
    checkData = storedData.get(nodeId)
    checkDataAvail = checkData.data
    if (checkDataAvail is not None and len(checkDataAvail) > 0):
        respose = constructFindValueReponse(checkDataAvail)
        return respose
    else:
        nodeTuples = node.findKNearestNodesFeeder(nodeId, node, [])
        nearestNodes = nodeTuples[:3]
        # compute the lowest distance observed
        lowestDistance = (nearestNodes[0].nodeId ^ nodeId)
        # to check
        notSeenNodes = nearestNodes[3:]
        # each TuplesIpPortNodeId
        # querying for 3 nearest node
        # and storing results in not seenNodes. for further parsing...
        for elem in nearestNodes:
            dataRcvd = sendNearestValueRequest(sock, elem, nodeId)
            tempBucket, isDataRcvd = readFindValueReponse(dataRcvd)  # contains the objests TuplesIpPortNodeId
            # find the nearest node for the received response; response contains the Tuples
            if (isDataRcvd == True):
                return tempBucket
            for elem in tempBucket:
                distance = (elem.nodeId ^ nodeId)
                if (distance <= lowestDistance):
                    lowestDistance = distance
                    if (elem.nodeId not in notSeenNodes):
                        notSeenNodes.append(elem)

        for elem in notSeenNodes:
            dataRcvd = sendNearestValueRequest(sock, elem)
            tempBucket, isDataRcvd = readFindValueReponse(dataRcvd)
            if (isDataRcvd == True):
                return tempBucket
            for elem in tempBucket:
                distance = (elem.nodeId ^ nodeId)
                if (distance <= lowestDistance):
                    lowestDistance = distance
                    if (elem.nodeId not in notSeenNodes):
                        notSeenNodes.append(elem)

        lenOfNotSeenNodes = len(notSeenNodes)
        if (lenOfNotSeenNodes > 4):
            lenStart = lenOfNotSeenNodes - 4
            retNodes = notSeenNodes[lenStart:]
            return retNodes
        else:
            return notSeenNodes


def createFIND_VALUEPacketResponse(data, isDataIfTrue):
    if (isDataIfTrue == True):
        dataFinal = None
        if (type(data) is list):
            dataFinal = data[0]
        elif (type(data) == '<type \'tuple\'>'):
            dataFinal = data[0]
        elif (type(data) is str):
            dataFinal = data
        else:
            dataFinal = data[0]

        nodeId = 'netsec64'
        nodeIdHashed = xxhash.xxh64(nodeId).intdigest() & 0xffff
        # print 'node id hashed ', nodeIdHashed
        lenHashedId = int(2)
        # print 'length of hash Node id', int(lenHashedId)
        nonce = int(random.randrange(65535))
        lenNonce = int(2)
        # print 'length of nonce ', int(lenNonce)
        # print 'nonce is ', nonce
        # print 'len of nonce is ', lenNonce
        lenTuples = int(0)
        lenData = len(dataFinal)
        packet = struct.pack('>BIHIHII' + str(lenData) + 's', int(7), lenHashedId, nodeIdHashed, lenNonce, nonce,
                             lenTuples, lenData, dataFinal)
        return packet
    else:
        newData = None
        if (type(data) is not str):
            newData = data
        nodeId = 'netsec64'
        nodeIdHashed = xxhash.xxh64(nodeId).intdigest() & 0xffff
        # print 'node id hashed ', nodeIdHashed
        lenHashedId = int(2)
        # print 'length of hash Node id', int(lenHashedId)
        nonce = int(random.randrange(65535))
        lenNonce = int(2)
        # print 'length of nonce ', int(lenNonce)
        # print 'nonce is ', nonce
        # print 'len of nonce is ', lenNonce
        sizeOfReply = 13 * len(newData)
        packedData = []
        packedIpPortNodeId = ''
        for tuple in newData:
            ipAddr = 0
            if "." in tuple.ipAddress:
                # print 'IPV4'
                ipAddr = convertIpToDecimal(tuple.ipAddress)
                packedData.append(struct.pack('>BIHIH', int(4), ipAddr, int(tuple.port), int(2), tuple.nodeId))
            elif ":" in tuple.ipAddress:
                # print 'IPV6'
                ipAddr = convertIPV6toDecimal(tuple.ipAddress)
                packedData.append(struct.pack('>BQQHIH', int(6), ipAddr, int(tuple.port), int(2), tuple.nodeId))

        # print 'raw packed data ', repr(packedData[0])
        for elem in packedData:
            packedIpPortNodeId = packedIpPortNodeId + elem

        packedReponse = struct.pack('>BIHIHI', int(5), lenHashedId, nodeIdHashed, lenNonce, nonce, sizeOfReply)

        packedReponse = packedReponse + packedIpPortNodeId
        return packedReponse


def readFIND_VALUERequest(rootNode, payload):
    unpackedData = struct.unpack('>BIHIHIH', payload)
    return unpackedData[6]


def findValueofDataRcvd(node, dataId):
    checkData = storedData.get(dataId)
    checkDataAvail = checkData.data
    if (checkDataAvail is not None):
        # print 'To do create a packet and send '
        packet = createFIND_VALUEPacketResponse(checkDataAvail, True)
        return packet
    else:
        checkDataAvail = dataWithme.get(dataId)
        if (checkDataAvail is not None):
            # print 'To do create a packet and send '
            packet = createFIND_VALUEPacketResponse(checkDataAvail, True)
            return packet
    bucket = recursiveFindNearestNodes(node, dataId, [], [])
    packet = createFIND_VALUEPacketResponse(bucket, False)
    return packet


def createStorePacketSend(data):
    nodeId = 'netsec64'
    nodeIdHashed = xxhash.xxh64(nodeId).intdigest() & 0xffff
    # print 'node id hashed ', nodeIdHashed
    lenHashedId = int(2)
    # print 'length of hash Node id', int(lenHashedId)
    nonce = int(random.randrange(65535))
    lenNonce = int(2)
    lenData = len(data)
    packet = struct.pack('>BIHIHI' + str(lenData) + 's', int(2), lenHashedId, nodeIdHashed, lenNonce, nonce, lenData,
                         data)
    return packet


def createStorePacketResponse():
    nodeId = 'netsec64'
    nodeIdHashed = xxhash.xxh64(nodeId).intdigest() & 0xffff
    # print 'node id hashed ', nodeIdHashed
    lenHashedId = int(2)
    # print 'length of hash Node id', int(lenHashedId)
    nonce = int(random.randrange(65535))
    lenNonce = int(2)
    packet = struct.pack('>BIHIH', int(3), lenHashedId, nodeIdHashed, lenNonce, nonce)
    return packet


def storeValuesInNodes(node):
    lines = tuple(open('/home/netsec64/dht_data', 'r'))
    for line in lines:
        dataId = xxhash.xxh64(line).intdigest() & 0xffff
        # print 'data id ->' , dataId
        kbucketNodes = recursiveFindNearestNodes(node, dataId, [], [])
        for elem in kbucketNodes:
            packet = createStorePacketSend(line)
            try:
                # sock.settimeout(5)
                # sock.sendto(packet,(elem.ipAddress,elem.port))
                # sock.settimeout(5)
                dataRcvd = pushRequestMessagesToSTS(packet, elem.ipAddress, elem.port)
                msgTypeRcvd = struct.unpack('>B', dataRcvd[:1])
                if (msgTypeRcvd[0] == 3):
                    print 'successfull'

                elif (msgTypeRcvd[0] == 8):
                    msgTypeRcvd = struct.unpack('>BIHIHI', dataRcvd)
                    print 'error received ', struct.unpack('>' + str(msgTypeRcvd[5]) + 's', dataRcvd[17:])
            except:
                print 'Value not stored'


def storeValuesFromNode(storeRequestData):
    dataUnpacked = struct.unpack('>BIHIHI', storeRequestData[:17])
    lenOfData = dataUnpacked[5]
    dataString = struct.unpack('>' + str(lenOfData) + 's', storeRequestData[17:])
    hashedIdForData = xxhash.xxh64(dataString[0]).intdigest() & 0xffff
    storedData.update({hashedIdForData: DataWithTimeOut(dataString, 100)})
    return createStorePacketResponse()


# bootstrap your routing table by adding the node <xxx.xxx.xxx.xxx, 1337, 0xffff>.
def bootStrapNode(node):
    # print 'BootStrapping '
    myNodeId = 'netsec64'
    myNodeIdHashed = xxhash.xxh64(myNodeId).intdigest() & 0xffff
    bootstrapNodeDetails = ('xxx.xxx.xxx.xxx', 1337)
    node.addElement(TuplesIPPortId('xxx.xxx.xxx.xxx', 1337, 0xffff))
    packet, lenNonce, lenHashedId = createFIND_NODEPacket(myNodeIdHashed)
    # sock.sendto(packet,bootstrapNodeDetails)
    pushRequestMessagesToSTS(packet, bootstrapNodeDetails[0], bootstrapNodeDetails[1])

    # TO-DO
    # node.findKNearestNodes(myNodeIdHashed, node, node, [], [])
    # node.printBucketData(node)
    # storeValuesInNodes(node)
    # node.printBucketData(node)
    # sock.settimeout(None)


def addElementsOfFindNodeReponse(node, message):
    logging.debug('Root node ' + str(node))
    logging.debug('Inside addElementsOfFindNodeReponse with message ' + repr(message))
    logging.debug('Root node details ' + node.getNodeData())
    bucket = readFindNodeReponse(message)
    logging.debug('Bucket size ' + str(len(bucket)))
    for elem in bucket:
        logging.debug( 'Ip Address :' + str(elem.ipAddress) + '|| port :'+ str(elem.port) + '|| node id : '+ str(elem.nodeId ))
        node.addElement(elem)
    node.printBucketData(node)


def checkEvictOrUpdate(nodeId):
    if (storedData.get(nodeId) is not None):
        data = storedData.get(nodeId)
        storedData.update({nodeId: DataWithTimeOut(data.data, 100)})
    else:
        for elem in storedData.keys():
            # print 'decreasing time out ',elem
            data = storedData.get(elem)
            timeOutVal = data.timeOut - 1
            # print 'Time out value ',timeOutVal
            storedData.update({elem: DataWithTimeOut(data.data, timeOutVal)})
    elem = storedData.keys()[0]
    minObj = storedData.get(elem)
    minTimeOut = minObj.timeOut
    minNodeId = elem
    for elems in storedData.keys():
        obj = storedData.get(elems)
        if (obj.timeOut < minTimeOut):
            minTimeOut = obj.timeOut
            minNodeId = elems
    storedData.pop(minNodeId)


def updateDataStoreNodes(node):
    # print 'Updating time out'
    while True:
        storeValuesInNodes(node)
        checkEvictOrUpdate(None)
        time.sleep(300)

def readPingResponse(rootNode,message,addr):
    logging.debug('Read Ping Response')
    packet=struct.unpack('>BIHIH',message)
    type=packet[0]
    lenNodeId=packet[1]
    nodeId=packet[2]
    lenNonce=packet[3]
    nonce=packet[4]
    return nodeId

def readStoreResponse(message,addr,node):
    logging.debug('Read Save Response')
    packet=struct.unpack('>BIHIH',message)
    type = packet[0]
    lenNodeId = packet[1]
    nodeId = packet[2]
    lenNonce = packet[3]
    nonce = packet[4]
    lenOfData=packet[5]
    logging.debug('Store was successful from node :' + nodeId + '| having address '+ str(addr))


#check for requests and response : seperate requests and response
def listenForRequests(rootNode, message, addr):
    payload = message
    firstByte = struct.unpack('>B', payload[0])
    if (firstByte[0] == 0):
        # sendPingResponse
        logging.debug('sending ping response')
        packet = createPINGReqOrRes(False, '', payload, rootNode)
        pushRequestMessagesToSTS(packet,addr[0],addr[1])
    # discarding as not sending any code below..
    elif (firstByte[0] == 1):
        #To-DO
        logging.debug('Reading Ping Response')
        readPingResponse(rootNode,message,addr)
        GlobalStaticVaraible.dhtTransSession.pop(generateIpPortKey(addr, getRequest(1)))
    elif (firstByte[0] == 2):
        logging.debug('store request received')
        packet = storeValuesFromNode(payload)
        pushRequestMessagesToSTS(packet, addr[0], addr[1])

    elif (firstByte[0] == 3):
        logging.debug('store reponse obtained discard')
        readStoreResponse(message,addr,rootNode)
        GlobalStaticVaraible.dhtTransSession.pop(generateIpPortKey(addr, getRequest(3)))
    elif (firstByte[0] == 4):
        logging.debug('find node request obtained')
        requestNodeId = readFIND_NODERequest(rootNode, payload)
        response = ''
        packet = createFIND_NODEResponse(requestNodeId, response,
                                         rootNode)  # can be implemented using recursive nearest node
        pushRequestMessagesToSTS(packet, addr[0], addr[1])
    elif (firstByte[0] == 5):
        logging.debug('Find node response received...')
        addElementsOfFindNodeReponse(rootNode, message)
        logging.debug('Find node processing done...')
        GlobalStaticVaraible.dhtTransSession.pop(generateIpPortKey(addr, getRequest(5)))
    elif (firstByte[0] == 6):
        logging.debug('find value request obtained')
        dataId = readFIND_VALUERequest(rootNode, payload)
        packet = findValueofDataRcvd(rootNode, dataId)
        pushRequestMessagesToSTS(packet, addr[0], addr[1])
    elif (firstByte[0] == 7):
        logging.debug('find value response discard')
    elif (firstByte[0] == 8):
        logging.debug( 'received error discard')
    else:
        packet = createAErrorPacket('Not a valid Message')
        pushRequestMessagesToSTS(packet, addr[0], addr[1])


def getRequest(request):
    if (request == 0):
        return 'PRQ'
    elif (request == 2):
        return 'SRQ'
    elif (request == 4):
        return 'FNRQ'
    elif (request == 5):
        return 'FNRP'
    elif (request == 6):
        return 'FNVRQ'


def pushRequestMessagesToSTS(message, ipAddress, port):
    # check for previous request and if its done/ completed push the message to outbound queue.

    logging.debug('Inside pushRequestMessagesToSTS')
    messageType = struct.unpack('>B', message[0:1])[0]
    reqState = getRequest(messageType)

    # These are response to a requests so no need to wait for reponse hence remove from session
    if (GlobalStaticVaraible.dhtTransSession.has_key(generateIpPortKey((ipAddress, port), reqState))):

        logging.debug('Session created previously')
        addressReqState = AddressRequestState(reqState, ipAddress, port, message)
        GlobalStaticVaraible.outbound_queue_dht.put(addressReqState)
        GlobalStaticVaraible.dhtTransSession.pop(generateIpPortKey((ipAddress, port), reqState))

    # These are requests from My DHT hence create session and wait for response.
    # push request to outbound queue
    else:
        messageType = struct.unpack('>B', message[0:1])[0]
        reqState = getRequest(int(messageType) + 1)
        logging.debug('Session will be created with reqState and IP ' + str(reqState)+':'+ str((ipAddress,port)))
        addressReqState = AddressRequestState(reqState, ipAddress, port, message)
        GlobalStaticVaraible.dhtTransSession.update({generateIpPortKey((ipAddress, port), reqState): addressReqState})
        GlobalStaticVaraible.outbound_queue_dht.put(addressReqState)


def removeReponseMessageFromSTSSync(listOfIpAddress):
#set the recurFindNode event take elements from Q and then check thr address received from address if tat matches and
# if its of type 5 return it to the function called for recur find node/value
        while(GlobalStaticVaraible.recurFindNodeEvent.isSet()):
            time.sleep(10)
            if (GlobalStaticVaraible.inbound_queue_dht.not_empty):
                rawData = GlobalStaticVaraible.inbound_queue_dht.get()
                logging.debug('Message in Queue' + repr(rawData))
                actualMessage = rawData[0]
                ipAddress = rawData[1]
                port = rawData[2]
                messageType = (struct.unpack('>B', actualMessage[0:1]))[0]
                reqState = getRequest(messageType)

                if(ipAddress in listOfIpAddress and messageType == 5):
                    for ipTuple in listOfIpAddress:
                        GlobalStaticVaraible.dhtTransSession.pop(generateIpPortKey(ipTuple,5))
                    GlobalStaticVaraible.recurFindNodeEvent.clear()
                    return actualMessage
                else:
                    #storing the values back into the Q for processing later.
                    GlobalStaticVaraible.inbound_queue_dht.put(rawData)




def removeReponseMessageFromSTS(rootNode):
    logging.debug('inside removeReponseMessageToSTS')
    #lock this while loop using a if statement since a three parallel request must be sent. do not read from Q till then.
    #if the
    while True:
        while (not GlobalStaticVaraible.recurFindNodeEvent.isSet()):
            if (GlobalStaticVaraible.inbound_queue_dht.not_empty):
                # if elem in Q and is a reponse to prev request use it or create a session for it.
                rawData = GlobalStaticVaraible.inbound_queue_dht.get()
                logging.debug('Message in Queue' + repr(rawData))

                actualMessage = rawData[0]
                ipAddress = rawData[1]
                port = rawData[2]
                messageType = (struct.unpack('>B', actualMessage[0:1]))[0]
                reqState = getRequest(messageType)
                # waiting for a reponse for My request hence key must be there once reponse is received and processed
                # delete from session.
                if (GlobalStaticVaraible.dhtTransSession.has_key(generateIpPortKey((ipAddress, port), reqState)) and messageType in GlobalStaticVaraible.responseNumbers):
                    logging.debug('Session available')
                    addressReqStateObj = AddressRequestState(reqState, ipAddress, port, actualMessage)
                    listenForRequests(rootNode, actualMessage, (ipAddress, port))

                # reqqeust from some other node hence create the session.
                # with a request Key. request is incremented
                elif(messageType in GlobalStaticVaraible.requestNumbers):
                    logging.debug('Creating session as there was no session created')

                    logging.debug('Request Type ' + messageType)

                    reqState = getRequest(messageType + 1)
                    addressReqState = AddressRequestState(reqState, ipAddress, port, actualMessage)
                    listenForRequests(rootNode, actualMessage, (ipAddress, port))

                else:
                    GlobalStaticVaraible.dhtTransSession.pop(generateIpPortKey((ipAddress,port),reqState))
                    if(messageType == 8):
                        listenForRequests(rootNode, actualMessage, (ipAddress, port))

        time.sleep(10)


def startDHT():
    logging.debug('Starting DHT')
    rootNode = GlobalStaticVaraible.rootNode
    rootNode.rootNode = rootNode
    logging.debug('Root node ' + str(rootNode))
    logging.debug('Root node details ' + rootNode.getNodeData())
    bootStrapNode(rootNode)
    threadDHTRead = threading.Thread(target=removeReponseMessageFromSTS, args=(rootNode,))
    logging.debug('Thread dht Created and started')
    threadDHTRead.start()








