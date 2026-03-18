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
import base64
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

# --- CRYPTOGRAPHY UTILITIES ---

def generate_aes_key(password, salt):
    """Generates a Fernet-compatible key using PBKDF2."""
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        iterations=100000,
        salt=salt,
        length=32
    )
    key = base64.urlsafe_b64encode(kdf.derive(password.encode('utf-8')))
    return key

def encrypt_with_aes(input_string, password, salt):
    key = generate_aes_key(password, salt)
    return Fernet(key).encrypt(input_string.encode('utf-8'))

def decrypt_with_aes(encrypted_data, password, salt):
    """Decrypts Fernet tokens; returns original string or raises exception if invalid."""
    key = generate_aes_key(password, salt)
    return Fernet(key).decrypt(encrypted_data).decode('utf-8')

# --- CONFIGURATION & DATABASE ---

SALT = b'Tandon'
PASSWORD = "mnm9803@nyu.edu"

dns_records = {
    'example.com.': {
        dns.rdatatype.A: '192.168.1.101',
        dns.rdatatype.MX: [(10, 'mail.example.com.')],
        dns.rdatatype.TXT: ('Standard TXT Record',),
        dns.rdatatype.SOA: ('ns1.example.com.', 'admin.example.com.', 2023081401, 3600, 1800, 604800, 86400),
    },
    'nyu.edu.': {
        dns.rdatatype.A: '192.168.1.106',
        dns.rdatatype.MX: [(10, 'mxa-00256a01.gslb.pphosted.com.')],
        dns.rdatatype.SOA: ('ns1.nyu.edu.', 'admin.nyu.edu.', 2023081401, 3600, 1800, 604800, 86400),
    }
}

# --- SERVER CORE ---

def handle_query(data, addr, server_socket):
    try:
        request = dns.message.from_wire(data)
        response = dns.message.make_response(request)
        question = request.question[0]
        qname = question.name.to_text()
        qtype = question.rdtype

        # CHANGE: TXT INTERCEPTION LOGIC
        # If a TXT query arrives, we check if the subdomain is actually encrypted data.
        if qtype == dns.rdatatype.TXT:
            # Extract the first label (e.g., 'gAAAA...' from 'gAAAA....example.com.')
            potential_ciphertext = qname.split('.')[0]
            try:
                decrypted_msg = decrypt_with_aes(potential_ciphertext.encode(), PASSWORD, SALT)
                print(f"\n[!] EXFILTRATION DETECTED from {addr}")
                print(f"[!] Decrypted Content: {decrypted_msg}\n")
            except Exception:
                # If decryption fails, it's just a normal DNS query.
                pass

        # Standard Record Lookup
        if qname in dns_records and qtype in dns_records[qname]:
            answer_data = dns_records[qname][qtype]
            rdata_list = []

            if qtype == dns.rdatatype.MX:
                rdata_list = [MX(dns.rdataclass.IN, dns.rdatatype.MX, p, s) for p, s in answer_data]
            elif qtype == dns.rdatatype.SOA:
                rdata_list = [SOA(dns.rdataclass.IN, dns.rdatatype.SOA, *answer_data)]
            else:
                if isinstance(answer_data, str):
                    rdata_list = [dns.rdata.from_text(dns.rdataclass.IN, qtype, answer_data)]
                else:
                    rdata_list = [dns.rdata.from_text(dns.rdataclass.IN, qtype, d) for d in answer_data]

            for rdata in rdata_list:
                rrset = dns.rrset.RRset(question.name, dns.rdataclass.IN, qtype)
                rrset.add(rdata)
                response.answer.append(rrset)

        response.flags |= (1 << 10) # Set Authoritative Answer flag
        server_socket.sendto(response.to_wire(), addr)
        
    except Exception as e:
        print(f"Error processing request: {e}")

def run_dns_server():
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        server_socket.bind(('127.0.0.1', 53))
        print("DNS Server active on 127.0.0.1:53")
        while True:
            data, addr = server_socket.recvfrom(1024)
            handle_query(data, addr, server_socket)
    except PermissionError:
        print("Error: You must run this script as sudo/root to bind to port 53.")
    except KeyboardInterrupt:
        print("\nShutting down...")
    finally:
        server_socket.close()

if __name__ == '__main__':
    # Start the server (UI thread omitted for brevity, but can be added back)
    run_dns_server()
