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

####################################LOGGER###############################################

logging.basicConfig(level=logging.DEBUG,
                    format='(%(threadName)-10s) %(message)s',
                    )
#########################################################################################


class TuplesIPPortId:
    ipAddress = ''
    port = 0
    nodeId = 0
    timeout = 5

    def __init__(self, ipAddress, port, nodeId):
        self.ipAddress = ipAddress
        self.port = port
        self.nodeId = nodeId

class Trees:
    leftNode = None
    rightNode = None
    nodeData = ''
    isLeafNode = True
    bucket = []
    rootNode = None
    commonPrefix = None
    parent = None

    def __init__(self, leftNode, rightNode, nodeData, bucket, rootNode, commonPrefix):
        self.leftNode = leftNode
        self.rightNode = rightNode
        self.nodeData = nodeData
        self.bucket = bucket
        self.rootNode = rootNode
        self.commonPrefix = commonPrefix
        self.lock = threading.Lock()

    def getNodeData(self):
        return self.nodeData

    # slit the node and try insertion. doesnt insert node instead splits a node and gives back control to addFromBucket to add all values
    # the parent node is free of bucket values
    def splitNode(self, node, data, root):
        # print 'performing split at node ',node.nodeData
        node.isLeafNode = False
        nodeLeft = Trees(None, None, node.nodeData + '0', [], node, '')
        nodeRight = Trees(None, None, node.nodeData + '1', [], node, '')
        # need to split bucket between the two.
        node.leftNode = nodeLeft
        node.rightNode = nodeRight
        nodeLeft.isLeafNode = True;
        nodeRight.isLeafNode = True;
        nodeLeft.parent = node
        nodeRight.parent = node
        self.addFromBucket(node, root)
        node.bucket = []

    # manages parent nodes bucket once it has been split
    def addFromBucket(self, node, root):
        for data in node.bucket:
            # print 'adding data again ',data.nodeId
            self.addMoreData(data, root, data, root)

    # pads all id's to 16 bit
    def withPadding(self, data):
        temp = ''
        bits = str(bin(data))[2:]
        if (len(bits) < 16):
            padding = 16 - len(bits)
            while (padding > 0):
                bits = '0' + bits
                padding = padding - 1
        return bits

    # adding data at the right node and finding the right node to split.
    # removes duplicate.
    # To-do refresh timeout.
    def addMoreData(self, data, node, originalData, root):
        # print 'add more data called with values ',data.nodeId,' and node ',node.nodeData
        # dataBits = str(bin(data))[2:]
        dataBits = self.withPadding(data.nodeId)
        # print 'data Bits ',dataBits
        if (node.leftNode is None and node.rightNode is None):
            if (len(node.bucket) < 4):
                # print 'adding data', originalData,'to node ',node.nodeData
                for elem in node.bucket:
                    if (elem.nodeId == originalData.nodeId):
                        return
                node.bucket.append(originalData)
                return
            else:
                node.bucket.append(originalData)
                self.splitNode(node, originalData, root)
        else:
            if (dataBits[0] == '0'):
                temp = TuplesIPPortId(data.ipAddress, data.port, ((data.nodeId << 1) & 0xFFFF))
                self.addMoreData(temp, node.leftNode, originalData, root)
            else:
                temp = TuplesIPPortId(data.ipAddress, data.port, ((data.nodeId << 1) & 0xFFFF))
                self.addMoreData(temp, node.rightNode, originalData, root)

    # traverses the tree to find the matching node id's location but goes up to parent nodes if bucket is not full.
    def findKNearestNodes(self, nodeId, node, parent, sendBucket, stopParsing):
        parent = node
        dataBits = self.withPadding(nodeId)
        if (node.leftNode is None and node.rightNode is None and node.isLeafNode == True):
            for elem in node.bucket:
                sendBucket.append(elem)
                # print 'element added to sendBucket is ',elem.nodeId ,' parent is ',int(parent.nodeData,2)
            stopParsing = True
        if (stopParsing == False):

            if (dataBits[0] == '0'):
                self.findKNearestNodes(((nodeId << 1) & 0xFFFF), node.leftNode, node, sendBucket, stopParsing)
            else:
                self.findKNearestNodes((nodeId << 1 & 0xFFFF), node.rightNode, node, sendBucket, stopParsing)

        else:
            temp = []
            # print 'selected parent is ',int(node.parent.nodeData,2)
            while (len(sendBucket) < 6):
                # print 'length of send bucket is ',len(sendBucket)
                tempNodes = self.findAllParentBuckets(parent, temp)
                for elem in tempNodes:
                    if (elem not in sendBucket and len(sendBucket) < 6):
                        sendBucket.append(elem)
                    elif (len(sendBucket) == 6):
                        break
                    else:
                        continue
                if (parent.parent is not None):
                    # print 'parent ', parent.nodeData
                    parent = parent.parent
                else:
                    # print 'parent ',parent.nodeData
                    break
        return sendBucket

    # traveres parent nodes goes up the tree.
    def findAllParentBuckets(self, node, temp):

        if (node != None):
            # print 'running down from parent ', int(node.nodeData,2)
            self.findAllParentBuckets(node.leftNode, temp)
            # print 'at node ', node.nodeData
            for elem in node.bucket:
                temp.append(elem)
            self.findAllParentBuckets(node.rightNode, temp)
        return temp

    # initial function  to take values from a call manages distance and sends k nearest nodes
    def findKNearestNodesFeeder(self, nodeId, node, sendBucket):
        sendBucket = self.findKNearestNodes(nodeId, node, node, sendBucket, False)
        # print 'bucket values selected',sendBucket
        nearNodes = []
        nearNodesComp = []
        min = nodeId
        for elem in sendBucket:
            # print 'nearest ndoe selected ',elem.nodeId
            nearNodes.append(elem.nodeId ^ nodeId)

        nearNodes.sort();
        # print ' all nodes selected ',nearNodes
        for elem in nearNodes[:4]:
            for buckElem in sendBucket:
                if ((elem ^ buckElem.nodeId) == nodeId):
                    nearNodesComp.append(buckElem)
                    # print 'Near Nodes for the node ',nodeId ,'-> ',buckElem.nodeId

        return nearNodesComp

    # prints the tree data.
    def printBucketData(self, node):
        if (node != None):
            self.printBucketData(node.leftNode)
            logging.debug('at node ' + node.nodeData)
            for elem in node.bucket:
                logging.debug('bucket data :' + str(elem.nodeId) + '| Time out value :' + str(elem.timeout))
            self.printBucketData(node.rightNode)

    # decrements timer for a node
    def decrementTimer(self, node):
        if (node != None):
            self.decrementTimer(node.leftNode)
            for elem in node.bucket:
                elem.timeout = elem.timeout - 1;
            self.decrementTimer(node.rightNode)

    # removes a element from  a bucket having low timeout
    # to do check for pings as alive nodes must not be removed
    def evictOldNodes(self, node):
        if (node != None):
            self.evictOldNodes(node.leftNode)
            if (len(node.bucket) > 0):
                node.bucket.sort(key=lambda tuplesIpPortNode: tuplesIpPortNode.timeout)
                tempElem = node.bucket[0]
                # pint the node before removing
                node.bucket.remove(tempElem)
            self.evictOldNodes(node.rightNode)

    # initial function to add nodes.
    def addElement(self, data):
        # print 'add Element ',data.nodeId
        self.lock.acquire()
        try:
            logging.debug('Acquired lock inserting data' + str(data.nodeId))
            self.addMoreData(data, self.rootNode, data, self.rootNode)
            self.lock.release()
        finally:

            logging.debug('released lock')
