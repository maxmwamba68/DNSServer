import dns.message
import dns.rdatatype
import dns.rdataclass
import dns.rdtypes
import dns.rdtypes.ANY
from dns.rdtypes.ANY.MX import MX
from dns.rdtypes.ANY.SOA import SOA
import dns.rdata
import socket
import threading
import signal
import os
import sys

import hashlib
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import base64
import ast

def generate_aes_key(password, salt):
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        iterations=100000,
        salt=salt,
        length=32
    )
    key = kdf.derive(password.encode('utf-8'))
    key = base64.urlsafe_b64encode(key)
    return key

# Lookup details on fernet in the cryptography.io documentation    
def encrypt_with_aes(input_string, password, salt):
    key = generate_aes_key(password, salt)
    f = Fernet(key)
    encrypted_data = f.encrypt(input_string.encode('utf-8')) #call the Fernet encrypt method
    return encrypted_data    

def decrypt_with_aes(encrypted_data, password, salt):
    key = generate_aes_key(password, salt)
    f = Fernet(key)
    decrypted_data = f.decrypt(encrypted_data) #call the Fernet decrypt method
    return decrypted_data.decode('utf-8')

salt = b'Tandon' # Remember it should be a byte-object (prefix with 'b')
password = "mnm9803@nyu.edu"
input_string = "AlwaysWatching"

encrypted_value = encrypt_with_aes(input_string, password, salt) # exfil function
decrypted_value = decrypt_with_aes(encrypted_value, password, salt)  # exfil function

# Cast encrypted bytes to string so it can be stored in a TXT record
encrypted_str = str(encrypted_value)

# For future use    
def generate_sha256_hash(input_string):
    sha256_hash = hashlib.sha256()
    sha256_hash.update(input_string.encode('utf-8'))
    return sha256_hash.hexdigest()

# A dictionary containing DNS records mapping hostnames to different types of DNS data.
dns_records = {
    'example.com.': {
        dns.rdatatype.A: '192.168.1.101',
        dns.rdatatype.AAAA: '2001:0db8:85a3:0000:0000:8a2e:0370:7334',
        dns.rdatatype.MX: [(10, 'mail.example.com.')],
        dns.rdatatype.CNAME: 'www.example.com.',
        dns.rdatatype.NS: 'ns.example.com.',
        dns.rdatatype.TXT: ('This is a TXT record',),
        dns.rdatatype.SOA: (
            'ns1.example.com.',
            'admin.example.com.',
            2023081401,
            3600,
            1800,
            604800,
            86400,
        ),
     },
    'safebank.com.': {
        dns.rdatatype.A: '192.168.1.102',
        dns.rdatatype.AAAA: '2001:0db8:85a3:0000:0000:8a2e:0370:1111',
        dns.rdatatype.MX: [(10, 'mail.safebank.com.')],
        dns.rdatatype.NS: 'ns1.safebank.com.',
        dns.rdatatype.TXT: ('v=spf1 include:_spf.safebank.com ~all',),
        dns.rdatatype.SOA: (
            'ns1.example.com.',
            'admin.example.com.',
            2023081401,
            3600,
            1800,
            604800,
            86400,
        ),
    },
    'google.com.': {
        dns.rdatatype.A: '192.168.1.103',
        dns.rdatatype.AAAA: '2001:0db8:85a3:0000:0000:8a2e:0370:7334',
        dns.rdatatype.MX: [(10, 'mail.google.com.')],
        dns.rdatatype.NS: 'ns1.google.com.',
        dns.rdatatype.TXT: ('v=spf1 include:_spf.google.com ~all',),
        dns.rdatatype.SOA: (
            'ns1.google.com.',
            'admin.google.com.',
            2023081401,
            3600,
            1800,
            604800,
            86400,
        ),
    },
    'legitsite.com.': {
        dns.rdatatype.A: '192.168.1.104',
        dns.rdatatype.AAAA: '2001:0db8:0000:0000:0000:0000:0000:0104',
        dns.rdatatype.MX: [(10, 'mail.legitsite.com.')],
        dns.rdatatype.NS: 'ns1.legitsite.com.',
        dns.rdatatype.TXT: ('v=spf1 include:_spf.google.com ~all',),
        dns.rdatatype.SOA: (
            'ns1.legitsite.com.',
            'admin.legitsite.com.',
            2023081401,
            3600,
            1800,
            604800,
            86400,
        ),
    },
    'yahoo.com.': {
        dns.rdatatype.A: '192.168.1.105',
        dns.rdatatype.AAAA: '2001:0db8:85a3:0000:0000:8a2e:0370:7334',
        dns.rdatatype.MX: [(10, 'mail.yahoo.com.')],
        dns.rdatatype.NS: 'ns1.yahoo.com.',
        dns.rdatatype.TXT: ('v=spf1 ip4:192.168.1.105 -all',),
        dns.rdatatype.SOA: (
            'ns1.yahoo.com.',
            'admin.yahoo.com.',
            2023081401,
            3600,
            1800,
            604800,
            86400,
        ),
    },
    'nyu.edu.': {
        dns.rdatatype.A: '192.168.1.106',
        dns.rdatatype.AAAA: '2001:0db8:85a3:0000:0000:8a2e:0373:7312',
        dns.rdatatype.MX: [(10, 'mxa-00256a01.gslb.pphosted.com.')],
        dns.rdatatype.NS: 'ns1.nyu.edu.',
        # Cast bytes to string so it stores cleanly as a TXT record; use ast.literal_eval() to recover bytes on retrieval
        dns.rdatatype.TXT: (encrypted_str,),
        dns.rdatatype.SOA: (
            'ns1.nyu.edu.',
            'admin.nyu.edu.',
            2023081401,
            3600,
            1800,
            604800,
            86400,
        ),
    },
}

def run_dns_server():
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM) 
    server_socket.bind(('127.0.0.1', 53))

    while True:
        try:
            data, addr = server_socket.recvfrom(1024)
            request = dns.message.from_wire(data)
            response = dns.message.make_response(request)

            question = request.question[0]
            qname = question.name.to_text()
            qtype = question.rdtype

            if qname in dns_records and qtype in dns_records[qname]:
                answer_data = dns_records[qname][qtype]

                rdata_list = []

                if qtype == dns.rdatatype.MX:
                    for pref, server in answer_data:
                        rdata_list.append(MX(dns.rdataclass.IN, dns.rdatatype.MX, pref, server))
                elif qtype == dns.rdatatype.SOA:
                    mname, rname, serial, refresh, retry, expire, minimum = answer_data 
                    rdata = SOA(dns.rdataclass.IN, dns.rdatatype.SOA, mname, rname, serial, refresh, retry, expire, minimum) 
                    rdata_list.append(rdata)
                else:
                    if isinstance(answer_data, str):
                        rdata_list = [dns.rdata.from_text(dns.rdataclass.IN, qtype, answer_data)]
                    else:
                        rdata_list = [dns.rdata.from_text(dns.rdataclass.IN, qtype, data) for data in answer_data]

                for rdata in rdata_list:
                    response.answer.append(dns.rrset.RRset(question.name, dns.rdataclass.IN, qtype))
                    response.answer[-1].add(rdata)

            response.flags |= 1 << 10

            print("Responding to request:", qname)
            server_socket.sendto(response.to_wire(), addr) 
        except KeyboardInterrupt:
            print('\nExiting...')
            server_socket.close()
            sys.exit(0)


def run_dns_server_user():
    print("Input 'q' and hit 'enter' to quit")
    print("DNS server is running...")

    def user_input():
        while True:
            cmd = input()
            if cmd.lower() == 'q':
                print('Quitting...')
                os.kill(os.getpid(), signal.SIGINT)

    input_thread = threading.Thread(target=user_input)
    input_thread.daemon = True
    input_thread.start()
    run_dns_server()


if __name__ == '__main__':
    # Uncomment these if you want to test the AES functions at startup
    # print("Encrypted Value:", encrypted_value)
    # print("Decrypted Value:", decrypted_value)
    run_dns_server_user()
