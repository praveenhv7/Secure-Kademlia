import time
import socket
import threading
import logging
import sys,traceback
import struct
from Queue import Queue
import base64
import random
import xxhash
import pysodium

#################################CONSTANTS##################################################
STS_PROPOSE_MSG=0
STS_ACCEPT_MSG=1
STS_DATA_EXG_MSG=2
STS_TERMINATE_MSG=3
INBOUND_MSG='INBOUND'
OUTBOUND_MSG='OUTBOUND'
SIG_VALIDATION=False
IP_VALIDATION=False
#/home/praveen/Documents/NetSec/tlsdht
#/home/netsec64/
MY_Home = '/home/netsec64/'
####################################LOGGER###############################################

logging.basicConfig(level=logging.DEBUG,
                    format='(%(threadName)-10s) %(message)s',
                    )

#####################################SESSION RELATED################################################

class StsBox:
    certificate = ''
    my_encr_pub_key = ''
    my_encr_sec_key = ''
    my_signing_key = ''
    sock = 0
    certificate_status = ''
    publicKeyCaCert=[]

    @staticmethod
    def initAll(socket):
        StsBox.loadCaCerts()
        StsBox.initializeMyCertificate()
        StsBox.initializeKeys()
        #StsBox.createSocketForTransmission()
        StsBox.sock=socket
        StsBox.getCertificateStatus()


    @staticmethod
    def loadCaCerts():
        rawPub = tuple(open(MY_Home + 'ca_certs.pub', 'r'))
        print 'Loading Ca certs'
        for cert in rawPub:
            allCaCertInfo = StsBox.getCertificateInfo('', str(cert), False)
            StsBox.publicKeyCaCert.append(allCaCertInfo.get('signingPubKey'))


    @staticmethod
    def initializeMyCertificate():
        rawCert = tuple(open(MY_Home + 'node.pub', 'r'))
        StsBox.certificate = base64.b64decode(str(rawCert[0]))
        certificateInfo = StsBox.getCertificateInfo('', rawCert[0], True)
        StsBox.my_encr_pub_key = certificateInfo.get('encrptPubKey')

    @staticmethod
    def createSocketForTransmission():
        sock_tmp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        server_address = '0.0.0.0'
        server_port = 1337
        server = (server_address, server_port)
        sock_tmp.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock_tmp.bind(server)
        StsBox.sock = sock_tmp

    @staticmethod
    def verifyCertificateSignature(signatureVal, certificate,caName):
        print 'Issuer Name ',caName
        print 'Certificate is ',certificate
        certWithVector=certificate[:-64] + b'\x00' * 64
        certPass=False
        for pubKey in StsBox.publicKeyCaCert:
            try:
                val = pysodium.crypto_sign_verify_detached(signatureVal, certWithVector, pubKey)
                certPass=True
            except ValueError:
                print 'Failed'
        print 'Returning ',certPass
        if(SIG_VALIDATION):
            return certPass
        else:
            return True


    # revisit as Ip's and port must be changed.
    def sendPacketToServer(self, message):
        StsBox.sock.sendto(message, (self.ipAddress, self.port))
        dataRcvd = (StsBox.sock.recvfrom(1500))[0]
        return dataRcvd

    def sendPacketToserverNoRecv(self, message):
        StsBox.sock.sendto(message, (self.ipAddress, self.port))

    @staticmethod
    def initializeKeys():
        encrptySigningSec = base64.b64decode(tuple(open(MY_Home + 'node.sec', 'r'))[0])
        encrpt_sign_sec = struct.unpack('>I32sI64s', encrptySigningSec[:])
        StsBox.my_encr_sec_key = encrpt_sign_sec[1]
        StsBox.my_signing_key = encrpt_sign_sec[3]

    @staticmethod
    def getCertificateStatus():
        logging.debug('Get Certificate Status')
        sock=StsBox.sock
        hostPort = 3333
        dataRaw = StsBox.certificate
        hasedData = pysodium.crypto_generichash(dataRaw, '', 64)
        dataInFormat = struct.pack('>I64s', 64, hasedData)
        hostIp = 'xxx.xxx.xxx.xxx'
        sock.sendto(dataInFormat, (hostIp, int(hostPort)))
        certStatusData = (sock.recvfrom(1500))[0]
        StsBox.certificate_status = certStatusData

    def __init__(self, messageToSend, ipAddress, port):
        self.messageToSend = messageToSend
        self.ipAddress = ipAddress
        self.port = port
        self.messageToRcv = ''

    def setMessageToSend(self,message):
        self.messageToSend=message
    def getMessageToSend(self):
        return self.messageToSend

    def setMessageToRcv(self,message):
        self.messageToRcv=message
    def setMessageToRcv(self):
        return self.messageToRcv

    @staticmethod
    def getIssuerPrincipal(certificateDecoded, start, end):
        decodeFmt = '>B'
        identifier = struct.unpack(decodeFmt, certificateDecoded[start:end])
        logging.debug('string encoded principal identifier is ' + str(identifier[0]))
        lenIssuerPrincipal = 0
        principal = ''
        ipAddress = ''
        port = 0
        node_id = ''
        newEnd = 0

        if (identifier[0] == 0):
            start = start + 1
            end = start + 4
            logging.debug('string encoded principal identifier is ' + str(identifier[0]))
            lenIssuerPrincipal = struct.unpack('>I', certificateDecoded[start:end])
            decodeFmt = '>' + str(lenIssuerPrincipal[0]) + 's'
            start = end
            end = end + lenIssuerPrincipal[0]
            principal = struct.unpack(decodeFmt, certificateDecoded[start:end])
            return principal[0], end
        elif (identifier[0] == 4):
            start = start + 1
            decodeFmt = '>IHI'
            end = end + 4 + 2 + 4
            ip_port = struct.unpack(decodeFmt, certificateDecoded[start:end])
            ipAddress = ip_port[0]
            port = ip_port[1]
            lenOfNodeId = ip_port[2]
            start = end
            end = end + lenOfNodeId
            node_id = struct.unpack('>' + str(lenOfNodeId) + 's', certificateDecoded[start:end])
            return ipAddress, port, node_id, end

    @staticmethod
    def getCertificateInfo(path, certToExtract, flagForValidation):
        allCertInfo = {}
        certificate = ''
        if (path != ''):
            rawPub = tuple(open(path, 'r'))
            certificate = str(rawPub[0])[0:-1]
        elif (certToExtract != ''):
            certificate = certToExtract

        logging.debug('Certificate Node.pub contents ' + certificate + ' \n Length of certificate ' + str(len(certificate)))
        certificateDecoded = base64.decodestring(certificate)
        allCertInfo.update({'certificateComplete': certificate})
        logging.debug('\n Decoded Certificate ' + certificateDecoded)

        logging.debug('Decoding certificate')

        retValue = (StsBox.getIssuerPrincipal(certificateDecoded, 0, 1))
        logging.debug('Pricipal values' + str(retValue))
        principalName = ''
        caPrincipalName = ''
        endLen = 0
        retLen = len(retValue)
        if (retLen == 2):
            caPrincipalName = retValue[0]
            endLen = retValue[1]
        logging.debug('Principal Name is ' + caPrincipalName)
        logging.debug('Principal name length ' + str(len(caPrincipalName)))
        allCertInfo.update({'issuerPrincipalLength': len(caPrincipalName)})
        allCertInfo.update({'issuerPrincipal': caPrincipalName})
        begin = int(endLen)
        logging.debug('New Begin position is ' + str(begin))
        end = begin + 4
        lenOfSubPrinciapl = ((struct.unpack('>I', certificateDecoded[begin:end])))[0]
        allCertInfo.update({'subjectPrincipalLen': lenOfSubPrinciapl})
        logging.debug(' debug info ' + str(lenOfSubPrinciapl))
        start = end
        logging.debug('New start position is ' + str(start))
        end = start + lenOfSubPrinciapl
        subjectPrincipal = (struct.unpack('>' + str(lenOfSubPrinciapl) + 's', certificateDecoded[start:end]))[0]
        allCertInfo.update({'completeSubPrincipal': subjectPrincipal})
        logging.debug('Complete sub principal ' + str(subjectPrincipal))
        subjectPrincipalStart = 0
        subjectPrincipalEnd = 1
        while (lenOfSubPrinciapl > 0):
            logging.debug('len of sub principal is ' + str(lenOfSubPrinciapl))
            retValue = StsBox.getIssuerPrincipal(subjectPrincipal, subjectPrincipalStart, subjectPrincipalEnd)
            if (len(retValue) == 2):
                principalName = retValue[0]
                logging.debug('Principal Name is ' + principalName)
                allCertInfo.update({'subjectPrincipallen': len(principalName)})
                allCertInfo.update({'subjectPrincipalName': principalName})
                logging.debug(
                    'Obtained values ' + str(principalName) + ' length of prinicipal name ' + str(len(principalName)))
                endLen = retValue[1]
            elif (len(retValue) == 4):
                ipAddress = retValue[0]
                port = retValue[1]
                nodeId = retValue[2]
                endLen = retValue[3]
                logging.debug('Obtained values ' + str(ipAddress) + ':' + str(port) + '/' + str(nodeId))
                allCertInfo.update(
                    {'subjectPrincipalIpPortNodeId': str(ipAddress) + ':' + str(port) + '/' + str(nodeId)})

            subjectPrincipalStart = endLen
            subjectPrincipalEnd = subjectPrincipalStart + 1
            logging.debug('New start position is ' + str(subjectPrincipalStart) + ' -> new end position is ' + str(
                subjectPrincipalEnd))
            lenOfSubPrinciapl = lenOfSubPrinciapl - endLen

        logging.debug('End of message parsed index is ' + str(subjectPrincipalStart))

        start = start + subjectPrincipalStart
        end = start + 4
        logging.debug('value of start and  end ' + str(start) + ' ' + str(end))
        capability = (struct.unpack('>I', certificateDecoded[start:end]))[0]
        logging.debug('capability value ' + str(capability))
        allCertInfo.update({'capabilityValue': capability})

        logging.debug('raw hex is ' + repr(capability))
        logging.debug('sixth part capabilities is ' + str(capability & 0xf000) + ' Next three parts are ' + str(
            capability & 0x0fff))
        start = end
        end = start + 4
        lenOfEncrPubKey = (struct.unpack('>I', certificateDecoded[start:end]))[0]
        logging.debug('lenOfEncrPubKey value ' + str(lenOfEncrPubKey))
        start = end
        end = start + lenOfEncrPubKey
        encrPubKey = struct.unpack('>' + str(lenOfEncrPubKey) + 's', certificateDecoded[start:end])[0]
        logging.debug('encrPubKey value ' + str(encrPubKey))
        allCertInfo.update({'encrptPubKeyLen': lenOfEncrPubKey})
        allCertInfo.update({'encrptPubKey': encrPubKey})
        start = end
        end = start + 4
        lenOfSignPubKey = struct.unpack('>I', certificateDecoded[start:end])[0]
        logging.debug('lenOfSignPubKey value ' + str(lenOfSignPubKey))
        start = end
        end = start + lenOfSignPubKey
        signPubKey = struct.unpack('>' + str(lenOfSignPubKey) + 's', certificateDecoded[start:end])[0]
        logging.debug('sign pub key is ' + str(signPubKey))
        allCertInfo.update({'signingPubKeyLen': lenOfSignPubKey})
        allCertInfo.update({'signingPubKey': signPubKey})
        start = end
        end = start + 4
        lenOfSignature = struct.unpack('>I', certificateDecoded[start:end])[0]
        start = end
        end = start + lenOfSignature
        signatureVal = struct.unpack('>' + str(lenOfSignature) + 's', certificateDecoded[start:end])[0]
        logging.debug('Signature len ' + str(lenOfSignature))
        logging.debug('Signature value ' + str(signatureVal))
        allCertInfo.update({'signatureValLen': lenOfSignature})
        allCertInfo.update({'signatureVal': signatureVal})
        logging.debug('End index ' + str(end) + ' : total len ' + str(len(certificateDecoded)))
        if (len(certificateDecoded) == end):
            logging.debug('INFO: Decoding Complete')
        allCertInfo.update({'totalCertLen': end})
        if(flagForValidation):
            validCertificate=StsBox.verifyCertificateSignature(signatureVal,certificateDecoded,caPrincipalName)
            allCertInfo.update({'validCertificate': validCertificate})
        print 'Valid Certificate'
        return allCertInfo

    def getMessageToRcv(self):
        return self.messageToRcv

    # while decoding verify signature
    def decodeCertificateStatus(self, certificateStatus):
        certStatus = {}
        start = 0
        end = 5
        lenOfCertStatus = len(certificateStatus)
        logging.debug('Length of certificate status' + str(lenOfCertStatus))
        status_lenHash = struct.unpack('>BI', certificateStatus[start:end])
        status = status_lenHash[0]
        logging.debug('status of certificate ' + str(status))
        certStatus.update({'status': str(status)})
        lenOfHash = status_lenHash[1]
        logging.debug('length of hash ' + str(lenOfHash))
        start = end
        end = start + lenOfHash + 8 + 8 + 8
        hash_time_valid_endTime = struct.unpack('>' + str(lenOfHash) + 'sQQQ', certificateStatus[start:end])
        hash = hash_time_valid_endTime[0]
        timestamp = hash_time_valid_endTime[1]
        certStatus.update({'timeStampCertStat': timestamp})
        validity = hash_time_valid_endTime[2]
        certStatus.update({'validityCertStat': validity})
        endTime = hash_time_valid_endTime[3]
        certStatus.update({'endTimeCertStat': endTime})
        start = end
        end = start + 5
        issuerName = struct.unpack('>BI', certificateStatus[start:end])
        lenIssuerName = issuerName[1]
        start = end
        end = end + lenIssuerName
        caNameIssuer = struct.unpack('>' + str(lenIssuerName) + 's', certificateStatus[start:end])
        logging.debug('Ca issuer name ' + caNameIssuer[0])
        start = end
        end = start + 4
        signature_len = struct.unpack('>I', certificateStatus[start:end])[0]
        start = end
        end = start + signature_len
        signature = struct.unpack('>' + str(signature_len) + 's', certificateStatus[start:end])
        if (lenOfCertStatus == end):
            logging.debug('INFO : Decoding Complete')

    ############################################################################################
    def proposeMessage012(self, option):

        logging.debug('Propose')
        proposeMsgInfo = {}

        if (option != 0):
            my_public_key, my_secret_key = pysodium.crypto_kx_keypair()
        else:
            my_public_key = '' + b'\x00' * 32
            my_secret_key = '' + b'\x00' * 32

        proposeMsg = struct.pack(
            '>BBI32s' + str(len(StsBox.certificate)) + 's' + str(len(StsBox.certificate_status)) + 'sI', 0,
            option,
            len(my_public_key), my_public_key, StsBox.certificate, StsBox.certificate_status, 64)

        proposeMsg = proposeMsg + b'\x00' * 64
        print 'Signing Key ',repr(StsBox.my_signing_key)
        signature_propose = pysodium.crypto_sign_detached(proposeMsg, StsBox.my_signing_key)  # Signing key node.sec...
        proposeMsg = proposeMsg[:-64] + signature_propose
        proposeMsgInfo.update({'my_public_key': my_public_key})
        proposeMsgInfo.update({'my_secret_key': my_secret_key})
        return proposeMsg, proposeMsgInfo

        ################################################################################

    def proposeMsgDecode(self, dataRcvd):
        start = 0
        end = 5
        dataInHex = dataRcvd
        dataVector=dataRcvd[:-64]+b'\x00' * 64
        unpackedMsg = struct.unpack('>BI', dataInHex[start:end])
        lenOfKey = str(unpackedMsg[1])
        start = end
        end = start + int(lenOfKey)
        his_publicKey = struct.unpack('>' + str(lenOfKey) + 's', dataInHex[start:end])[0]
        start = end
        allCertInfo = self.getCertificateInfo('', base64.b64encode(dataInHex[start:]), True)
        validCertificate=allCertInfo.get('validCertificate')
        #str(ipAddress) + ':' + str(port) + '/' + str(nodeId)              2886860964:1337/2)
        ip_port_sender=allCertInfo.get('subjectPrincipalIpPortNodeId')
        splitRes=ip_port_sender.split(':', 1)
        ip=splitRes[0]
        port=int((splitRes[1]).split('/',1)[0])
        ip_address=convertDecimalToIP(int(ip))
        if(IP_VALIDATION):
            if(ip_address != self.ipAddress or port != self.port):
                 raise Exception('IP Mismatch from certificate')

        if(validCertificate == False):
            raise  Exception('Certificate Vallidation Failed')


        pubKey=allCertInfo.get('signingPubKey')
        start = start + allCertInfo.get('totalCertLen')
        end = len(dataInHex) - 68  # 64 signature and its length
        allCertStatusInfo = self.decodeCertificateStatus(dataInHex[start:end])
        start = end
        end = end + 4
        signatureLen = struct.unpack('>I', dataInHex[start:end])[0]
        start = end
        end = end + signatureLen
        signature = struct.unpack('>' + str(signatureLen) + 's', dataInHex[start:end])
        try:
            pysodium.crypto_sign_verify_detached(signature, dataVector, pubKey)
        except:
            print 'Value error'
        allProMsg = {}
        #allProMsg.update({'msgType': unpackedMsg[0]})
        allProMsg.update({'cipherSuite': unpackedMsg[0]})
        allProMsg.update({'his_pub_key': his_publicKey})
        allProMsg.update({'his_cert': allCertInfo})
        allProMsg.update({'his_cert_status': allCertStatusInfo})
        allProMsg.update({'his_signature': signature})
        return allProMsg

    #####################################################################
    def createAcceptMessageRequest(self, my_secret_key, my_public_key, his_public_key, option):
        hash_round_off_64 = 64
        logging.debug('Accept Message')
        logging.debug('*************************************')
        logging.debug('My_secret_key ' + my_secret_key.encode("hex"))
        logging.debug('My_public_key ' + my_public_key.encode("hex"))
        logging.debug('his_public_key ' + his_public_key.encode("hex"))
        logging.debug('*************************************')

        sec_key_derived = pysodium.crypto_scalarmult_curve25519(my_secret_key, his_public_key)
        state = pysodium.crypto_generichash_init(outlen=hash_round_off_64)
        state = pysodium.crypto_generichash_update(state, sec_key_derived)
        state = pysodium.crypto_generichash_update(state, his_public_key)
        state = pysodium.crypto_generichash_update(state, my_public_key)
        session_key_derived_final = pysodium.crypto_generichash_final(state, outlen=hash_round_off_64)
        timeInSec = time.time()
        timeInSecPacked = struct.pack('>Q', int(timeInSec))

        if (option == 1):
            addData = struct.pack('>BI', int(1), pysodium.crypto_aead_chacha20poly1305_ietf_NONCEBYTES)
            key_nonce = pysodium.randombytes(pysodium.crypto_aead_chacha20poly1305_ietf_NONCEBYTES)
        elif (option == 2):
            addData = struct.pack('>BI', int(1), pysodium.crypto_aead_chacha20poly1305_NPUBBYTES)
            key_nonce = pysodium.randombytes(pysodium.crypto_aead_chacha20poly1305_NPUBBYTES)
        elif (option == 0 or option == 3):
            addData = struct.pack('>BI', int(1), pysodium.crypto_aead_chacha20poly1305_ietf_NONCEBYTES)
            key_nonce = pysodium.randombytes(pysodium.crypto_aead_chacha20poly1305_ietf_NONCEBYTES)

        if (option == 1):
            timestamp_encr = pysodium.crypto_aead_chacha20poly1305_ietf_encrypt(timeInSecPacked, addData, key_nonce,
                                                                                session_key_derived_final[:32])
        elif (option == 2):
            # (message, ad, nonce, key):
            timestamp_encr = pysodium.crypto_aead_chacha20poly1305_encrypt(timeInSecPacked, addData, key_nonce,
                                                                           session_key_derived_final[:32])
        elif (option == 0 or option == 3):
            timestamp_encr=timeInSecPacked
        acceptMessage = addData + key_nonce + timestamp_encr
        return acceptMessage, session_key_derived_final

    #####################################################################
    def createAcceptMessage(self, my_secret_key, my_public_key, his_public_key, option):
        hash_round_off_64 = 64
        logging.debug('Accept Message')
        logging.debug('My_secret_key ' + my_secret_key.encode("hex"))
        logging.debug('My_public_key ' + my_public_key.encode("hex"))
        logging.debug('his_public_key ' + his_public_key.encode("hex"))


        sec_key_derived = pysodium.crypto_scalarmult_curve25519(my_secret_key, his_public_key)
        state = pysodium.crypto_generichash_init(outlen=hash_round_off_64)
        state = pysodium.crypto_generichash_update(state, sec_key_derived)
        state = pysodium.crypto_generichash_update(state, my_public_key)
        state = pysodium.crypto_generichash_update(state, his_public_key)
        session_key_derived_final = pysodium.crypto_generichash_final(state, outlen=hash_round_off_64)
        timeInSec = time.time()
        timeInSecPacked = struct.pack('>Q', int(timeInSec))

        if (option == 1):
            addData = struct.pack('>BI', int(1), pysodium.crypto_aead_chacha20poly1305_ietf_NONCEBYTES)
            key_nonce = pysodium.randombytes(pysodium.crypto_aead_chacha20poly1305_ietf_NONCEBYTES)
        elif (option == 2):
            addData = struct.pack('>BI', int(1), pysodium.crypto_aead_chacha20poly1305_NPUBBYTES)
            key_nonce = pysodium.randombytes(pysodium.crypto_aead_chacha20poly1305_NPUBBYTES)
        elif (option == 0 or option == 3):
            addData = struct.pack('>BI', int(1), pysodium.crypto_aead_chacha20poly1305_NPUBBYTES)
            key_nonce = pysodium.randombytes(pysodium.crypto_aead_chacha20poly1305_NPUBBYTES)

        if (option == 1):
            timestamp_encr = pysodium.crypto_aead_chacha20poly1305_ietf_encrypt(timeInSecPacked, addData, key_nonce,
                                                                                session_key_derived_final[:32])
        elif (option == 2):
            # (message, ad, nonce, key):
            timestamp_encr = pysodium.crypto_aead_chacha20poly1305_encrypt(timeInSecPacked, addData, key_nonce,
                                                                           session_key_derived_final[:32])
        elif (option == 0 or option == 3):
            timestamp_encr=timeInSecPacked
        acceptMessage = addData + key_nonce + timestamp_encr
        return acceptMessage, session_key_derived_final

    ####################################################################################################
    def createDataPacketWithEncr(self, session_key, option):
        hash_round_off_64 = 64
        logging.debug('Seding Encr packet')
        logging.debug('Session Key '+ session_key.encode("hex"))
        if (option == 1 or option == 4):
            addData = struct.pack('>BI', int(2), pysodium.crypto_aead_chacha20poly1305_ietf_NONCEBYTES)
            key_nonce = pysodium.randombytes(pysodium.crypto_aead_chacha20poly1305_ietf_NONCEBYTES)
        elif (option == 2 or option == 5):
            addData = struct.pack('>BI', int(2), pysodium.crypto_aead_chacha20poly1305_NPUBBYTES)
            key_nonce = pysodium.randombytes(pysodium.crypto_aead_chacha20poly1305_NPUBBYTES)
        elif (option == 0 or option == 3):
            ddData = struct.pack('>BI', int(2), pysodium.crypto_aead_chacha20poly1305_ietf_NONCEBYTES)
            key_nonce = pysodium.randombytes(pysodium.crypto_aead_chacha20poly1305_ietf_NONCEBYTES)

        dataPacket = self.messageToSend
        print 'Data to be encrypted ',repr(dataPacket)
        if (option == 1 or option == 4):
            dataPacket_encr = pysodium.crypto_aead_chacha20poly1305_ietf_encrypt(dataPacket, addData, key_nonce,
                                                                                 session_key[:32])
        elif (option == 2 or option == 5):
            dataPacket_encr = pysodium.crypto_aead_chacha20poly1305_encrypt(dataPacket, addData, key_nonce,
                                                                            session_key[:32])
        elif(option == 0 or option == 3):
            dataPacket_encr=dataPacket

        completeDataPacket = addData + key_nonce + dataPacket_encr
        return completeDataPacket
    ###################################################################################################
    #def encryptDataPacket(self,session,option):

    ###################################################################################################
    def decryptDataPacketEncr(self, session_key, encrMsg, option):

        if (option == 1 or option == 4):
            addData = struct.pack('>BI', int(2), pysodium.crypto_aead_chacha20poly1305_ietf_NONCEBYTES)
        elif (option == 2 or option == 5):
            addData = struct.pack('>BI', int(2), pysodium.crypto_aead_chacha20poly1305_NPUBBYTES)

        addData_rev = struct.unpack('>I', encrMsg[:4])
        lenNonce = addData_rev[0]
        end = 4 + lenNonce
        nonce = encrMsg[4:end]
        if (option == 1 or option == 4):
            decryptMsg = pysodium.crypto_aead_chacha20poly1305_ietf_decrypt(encrMsg[end:], addData, nonce,session_key[:32])
        elif (option == 2 or option == 5):
            decryptMsg = pysodium.crypto_aead_chacha20poly1305_decrypt(encrMsg[end:], addData, nonce, session_key[:32])
        elif (option == 0 or option == 3):
            decryptMsg=encrMsg[end:]
        self.messageToRcv = decryptMsg
        logging.debug( 'Decrypt message =' + repr(decryptMsg))

    ##################################################################################################
    def terminateSession(self, session_key):

        addData = struct.pack('>BI', int(3), pysodium.crypto_aead_chacha20poly1305_ietf_NONCEBYTES)
        key_nonce = pysodium.randombytes(pysodium.crypto_aead_chacha20poly1305_ietf_NONCEBYTES)

        if(session_key ==0 ):
            session_key=b'\x00' * 64


        timestamp_encr = pysodium.crypto_aead_chacha20poly1305_ietf_encrypt(struct.pack('>Q', int(time.time())),
                                                                            addData,
                                                                            key_nonce,
                                                                            session_key[:32])
        self.messageToSend = ''
        self.messageToRcv = ''
        terminateMsg = addData + key_nonce + timestamp_encr
        return terminateMsg

    ##################################################################################################
    def proposeMessage345(self, option):
        proposeMsgInfo = {}

        my_public_key = pysodium.crypto_scalarmult_curve25519_base(StsBox.my_encr_sec_key)

        proposeMsg = struct.pack('>BBI', int(0), int(option), int(72))
        proposeMsg = proposeMsg + b'\x00' * 72
        proposeMsg = proposeMsg + StsBox.certificate + StsBox.certificate_status

        sigLenPack = struct.pack('>I', 64)
        proposeMsg = proposeMsg + sigLenPack

        proposeMsg = proposeMsg + b'\x00' * 64
        signature_propose = pysodium.crypto_sign_detached(proposeMsg, StsBox.my_signing_key)
        proposeMsg = proposeMsg[:-64] + signature_propose
        proposeMsgInfo.update({'my_public_key': my_public_key})
        proposeMsgInfo.update({'my_secret_key': StsBox.my_encr_sec_key})
        print 'My propose message ', repr(proposeMsg)
        return proposeMsg, proposeMsgInfo


        return proposeMsg

    #################################################################################################
    def proposeMessage45(self, his_encr_pub_key, option):
        proposeMsgInfo = {}
        # print 'Sending a valid packet with a Key'


        sessionKey = pysodium.crypto_box_beforenm(StsBox.my_encr_pub_key, StsBox.my_encr_sec_key)
        # print 'session key ', repr(sessionKey), ' : length of session key ', len(sessionKey)
        # sessionKey=pysodium.randombytes(32)
        nonce = pysodium.randombytes(pysodium.crypto_box_NONCEBYTES)
        # crypto_box(msg, nonce, pk, sk):
        encr_session_key = pysodium.crypto_box(sessionKey, nonce, his_encr_pub_key, StsBox.my_encr_sec_key)

        lenOfk = len(nonce) + len(encr_session_key)
        # print 'Lenght of nonce+session key is ', lenOfk
        proposeMsg = struct.pack('>BBI', int(0), int(option), int(lenOfk))
        proposeMsg = proposeMsg + nonce + encr_session_key
        proposeMsg = proposeMsg + StsBox.certificate + StsBox.certificate_status

        sigLenPack = struct.pack('>I', 64)
        proposeMsg = proposeMsg + sigLenPack

        proposeMsg = proposeMsg + b'\x00' * 64
        signature_propose = pysodium.crypto_sign_detached(proposeMsg, StsBox.my_signing_key)
        proposeMsg = proposeMsg[:-64] + signature_propose
        proposeMsgInfo.update({'my_public_key': StsBox.my_encr_pub_key})
        proposeMsgInfo.update({'my_secret_key': StsBox.my_encr_sec_key})
        proposeMsgInfo.update({'session_key': sessionKey})

        # print 'My secret Key', repr(StsBox.my_encr_sec_key), ' : length of secret key ', len(StsBox.my_encr_sec_key)
        # print 'his public Key', repr(his_encr_pub_key), ' : length of pub key ', len(his_encr_pub_key)
        # print 'My propose message ', repr(proposeMsg), ' : len propose msg ', len(proposeMsg)
        return proposeMsg, proposeMsgInfo

    #########################################################################################
    def decodeRcvdProposeMsg345Request(self, dataRcvd):
        print 'n should be crypto_box_NONCEBYTES bytes.', pysodium.crypto_box_NONCEBYTES
        dataVector=dataRcvd[:-64]
        start = 0
        end = 6
        threePosPropose = struct.unpack('>BBI', dataRcvd[start:end])
        msgType = threePosPropose[0]
        msgSuite = threePosPropose[1]
        lenKey = threePosPropose[2]
        start = end
        end = end + lenKey
        nonce_key = struct.unpack('>' + str(lenKey) + 's', dataRcvd[start:end])[0]
        his_nonce = nonce_key[:pysodium.crypto_box_NONCEBYTES]
        his_ecr_seesion_key = nonce_key[pysodium.crypto_box_NONCEBYTES:]
        start = end
        allCertInfo = StsBox.getCertificateInfo('', base64.b64encode(dataRcvd[start:]), True)

        ip_port_sender = allCertInfo.get('subjectPrincipalIpPortNodeId')
        splitRes = ip_port_sender.split(':', 1)
        ip = splitRes[0]
        port = int((splitRes[1]).split('/', 1)[0])
        ip_address = convertDecimalToIP(int(ip))
        if (IP_VALIDATION):
            if (ip_address != self.ipAddress or port != self.port):
                raise Exception('IP Mismatch from certificate')

        validCertificate = allCertInfo.get('validCertificate')
        if (validCertificate == False):
            raise Exception('Certificate Vallidation Failed')

        start = start + allCertInfo.get('totalCertLen')
        his_encr_pub_key = allCertInfo.get('encrptPubKey')
        end = len(dataRcvd) - 68  # 64 signature and its length
        print 'Data in Hex cert status ', repr(dataRcvd[start:end])
        allCertStatusInfo = self.decodeCertificateStatus(dataRcvd[start:end])
        # (msg, nonce, k):
        session_key = pysodium.crypto_box_open(his_ecr_seesion_key, his_nonce, his_encr_pub_key, StsBox.my_encr_sec_key)

        start = end
        end = end + 4
        signatureLen = struct.unpack('>I', dataRcvd[start:end])[0]
        start = end
        end = end + signatureLen
        signature = struct.unpack('>' + str(signatureLen) + 's', dataRcvd[start:end])
        pubSignKey=allCertInfo.get('signatureVal')
        try:
            pysodium.crypto_sign_verify_detached(signature, dataVector, pubSignKey)
        except:
            print 'Value error'

        allProMsg = {}
        allProMsg.update({'session_key': session_key})
        allProMsg.update({'msgType': msgType})
        allProMsg.update({'cipherSuite': msgSuite})
        # allProMsg.update({'his_pub_key': his_public_key})
        allProMsg.update({'his_encr_pub_key': his_encr_pub_key})
        allProMsg.update({'his_cert': allCertInfo})
        allProMsg.update({'his_cert_status': allCertStatusInfo})
        allProMsg.update({'his_signature': signature})
        if (len(dataRcvd) == end):
            print 'decoded successfully '
        return allProMsg

    #########################################################################################
    def decodeRcvdProposeMsg345(self, dataRcvd):
        print 'n should be crypto_box_NONCEBYTES bytes.', pysodium.crypto_box_NONCEBYTES
        dataVector=dataRcvd[:-64]
        start = 0
        end = 6
        threePosPropose = struct.unpack('>BBI', dataRcvd[start:end])
        msgType = threePosPropose[0]
        msgSuite = threePosPropose[1]
        lenKey = threePosPropose[2]
        start = end
        end = end + lenKey
        nonce_key = struct.unpack('>' + str(lenKey) + 's', dataRcvd[start:end])[0]
        his_nonce = nonce_key[:pysodium.crypto_box_NONCEBYTES]
        his_public_key = nonce_key[pysodium.crypto_box_NONCEBYTES:]
        start = end
        allCertInfo = StsBox.getCertificateInfo('', base64.b64encode(dataRcvd[start:]), True)

        ip_port_sender = allCertInfo.get('subjectPrincipalIpPortNodeId')
        splitRes = ip_port_sender.split(':', 1)
        ip = splitRes[0]
        port = int((splitRes[1]).split('/', 1)[0])
        ip_address = convertDecimalToIP(int(ip))
        if (IP_VALIDATION):
            if (ip_address != self.ipAddress or port != self.port):
                raise Exception('IP Mismatch from certificate')

        validCertificate = allCertInfo.get('validCertificate')
        if (validCertificate == False):
            raise Exception('Certificate Vallidation Failed')
        start = start + allCertInfo.get('totalCertLen')
        his_encr_pub_key = allCertInfo.get('encrptPubKey')
        end = len(dataRcvd) - 68  # 64 signature and its length
        print 'Data in Hex cert status ', repr(dataRcvd[start:end])
        allCertStatusInfo = self.decodeCertificateStatus(dataRcvd[start:end])

        start = end
        end = end + 4
        signatureLen = struct.unpack('>I', dataRcvd[start:end])[0]
        start = end
        end = end + signatureLen
        signature = struct.unpack('>' + str(signatureLen) + 's', dataRcvd[start:end])
        allProMsg = {}

        pubSignKey = allCertInfo.get('signatureVal')
        try:
            pysodium.crypto_sign_verify_detached(signature, dataVector, pubSignKey)
        except:
            print 'Value error'

        allProMsg.update({'msgType': msgType})
        allProMsg.update({'cipherSuite': msgSuite})
        allProMsg.update({'his_pub_key': his_public_key})
        allProMsg.update({'his_encr_pub_key': his_encr_pub_key})
        allProMsg.update({'his_cert': allCertInfo})
        allProMsg.update({'his_cert_status': allCertStatusInfo})
        allProMsg.update({'his_signature': signature})
        if (len(dataRcvd) == end):
            print 'decoded successfully '
        return allProMsg

    ####################################################################################################
    def sendAcceptMessage345(self, session_key, option):

        print 'Session key derived ', session_key.encode("hex"), ' session key length ', len(
            session_key)
        timeInSec = time.time()
        timeInSecPacked = struct.pack('>Q', int(timeInSec))

        if (option == 4):
            addData = struct.pack('>BI', int(1), pysodium.crypto_aead_chacha20poly1305_ietf_NONCEBYTES)
            key_nonce = pysodium.randombytes(pysodium.crypto_aead_chacha20poly1305_ietf_NONCEBYTES)
        elif (option == 5):
            addData = struct.pack('>BI', int(1), pysodium.crypto_aead_chacha20poly1305_NPUBBYTES)
            key_nonce = pysodium.randombytes(pysodium.crypto_aead_chacha20poly1305_NPUBBYTES)
        elif (option == 0 or option == 3):
            addData = struct.pack('>BI', int(1), pysodium.crypto_aead_chacha20poly1305_ietf_NONCEBYTES)
            key_nonce = pysodium.randombytes(pysodium.crypto_aead_chacha20poly1305_ietf_NONCEBYTES)

        if (option == 4):
            timestamp_encr = pysodium.crypto_aead_chacha20poly1305_ietf_encrypt(timeInSecPacked, addData, key_nonce,
                                                                                session_key)
        elif (option == 5):
            # (message, ad, nonce, key):
            timestamp_encr = pysodium.crypto_aead_chacha20poly1305_encrypt(timeInSecPacked, addData, key_nonce,
                                                                           session_key)
        elif (option == 0 or option == 3):
            timestamp_encr=timeInSecPacked

        print 'Raw Msg ', timestamp_encr

        acceptMessage = addData + key_nonce + timestamp_encr

        print 'ACCEPT MSG in base64 ', acceptMessage.encode("hex")

        return acceptMessage

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