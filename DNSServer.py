import dns.message
import dns.rdatatype
import dns.rdataclass
from dns.rdtypes.ANY.MX import MX
from dns.rdtypes.ANY.SOA import SOA
import dns.rdata
import socket
import threading
import signal
import os
import sys
import base64
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

# --- CRYPTOGRAPHY ---

def generate_aes_key(password, salt):
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        iterations=100000,
        salt=salt,
        length=32
    )
    key = base64.urlsafe_b64encode(kdf.derive(password.encode('utf-8')))
    return key

def decrypt_with_aes(encrypted_data, password, salt):
    key = generate_aes_key(password, salt)
    f = Fernet(key)
    # Fernet expects bytes
    if isinstance(encrypted_data, str):
        encrypted_data = encrypted_data.encode('utf-8')
    return f.decrypt(encrypted_data).decode('utf-8')

# --- CONFIG ---
SALT = b'Tandon'
PASSWORD = "mnm9803@nyu.edu"

dns_records = {
    'nyu.edu.': {
        dns.rdatatype.A: '192.168.1.106',
        dns.rdatatype.MX: [(10, 'mxa-00256a01.gslb.pphosted.com.')],
        dns.rdatatype.SOA: ('ns1.nyu.edu.', 'admin.nyu.edu.', 2023081401, 3600, 1800, 604800, 86400),
    },
}

# --- SERVER LOGIC ---

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

            # CHANGE: Advanced TXT Decryption Handling
            if qtype == dns.rdatatype.TXT:
                # 1. Extract the first label (the payload)
                raw_payload = qname.split('.')[0]
                
                try:
                    # DNS is case-insensitive, but Fernet/Base64 IS case-sensitive.
                    # If your client sends uppercase, this might still fail unless 
                    # the client and server use a consistent encoding (like Hex).
                    # For now, we assume the token is passed correctly.
                    
                    decrypted_value = decrypt_with_aes(raw_payload, PASSWORD, SALT)
                    print(f"SUCCESS: Decrypted Value: {decrypted_value}")
                except Exception as e:
                    # This captures the 'InvalidToken' error without crashing
                    print(f"TXT Query received, but decryption failed. (Normal query or bad token)")

            # Standard Lookup Logic
            if qname in dns_records and qtype in dns_records[qname]:
                answer_data = dns_records[qname][qtype]
                if qtype == dns.rdatatype.MX:
                    for pref, server in answer_data:
                        response.answer.append(dns.rrset.from_text(question.name, 3600, dns.rdataclass.IN, dns.rdatatype.MX, f"{pref} {server}"))
                elif qtype == dns.rdatatype.SOA:
                    soa_text = " ".join(map(str, answer_data))
                    response.answer.append(dns.rrset.from_text(question.name, 3600, dns.rdataclass.IN, dns.rdatatype.SOA, soa_text))
                else:
                    record_val = answer_data if isinstance(answer_data, str) else answer_data[0]
                    response.answer.append(dns.rrset.from_text(question.name, 3600, dns.rdataclass.IN, qtype, record_val))

            response.flags |= 1 << 10
            server_socket.sendto(response.to_wire(), addr)

        except KeyboardInterrupt:
            break
    server_socket.close()

if __name__ == '__main__':
    run_dns_server()
