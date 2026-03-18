import dns.message, dns.rdatatype, dns.rdataclass, dns.rdata, socket, sys, base64
from dns.rdtypes.ANY.MX import MX
from dns.rdtypes.ANY.SOA import SOA
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

def generate_aes_key(password, salt):
    kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), iterations=100000, salt=salt, length=32)
    return base64.urlsafe_b64encode(kdf.derive(password.encode()))

def encrypt_with_aes(s, p, salt):
    return Fernet(generate_aes_key(p, salt)).encrypt(s.encode())

salt = b'static_salt_value'
password = "mnm9803@nyu.edu"
encrypted_value = encrypt_with_aes("exfiltrated_data", password, salt)

dns_records = {
    'example.com.': {dns.rdatatype.A: '192.168.1.101'},
    'nyu.edu.': {
        dns.rdatatype.A: '128.122.138.132',
        dns.rdatatype.AAAA: '2001:468:1500:2::4',
        dns.rdatatype.MX: [(10, 'mx1.nyu.edu.')],
        dns.rdatatype.NS: 'ns1.nyu.edu.',
        dns.rdatatype.TXT: (encrypted_value.decode(),)
    },
    'safebank.com.': {dns.rdatatype.A: '192.168.1.102'}
}

def run_dns_server():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.bind(('0.0.0.0', 53))
    while True:
        data, addr = s.recvfrom(1024)
        req = dns.message.from_wire(data)
        resp = dns.message.make_response(req)
        q = req.question[0]
        qname, qtype = q.name.to_text(), q.rdtype
        if qname in dns_records and qtype in dns_records[qname]:
            adata = dns_records[qname][qtype]
            if qtype == dns.rdatatype.MX:
                rr = dns.rrset.from_rdata(q.name, 300, *(MX(dns.rdataclass.IN, dns.rdatatype.MX, p, s) for p, s in adata))
            elif qtype == dns.rdatatype.SOA:
                m, r, sr, ref, rty, exp, minv = adata
                rr = dns.rrset.from_rdata(q.name, 300, SOA(dns.rdataclass.IN, dns.rdatatype.SOA, m, r, sr, ref, rty, exp, minv))
            elif isinstance(adata, str):
                rr = dns.rrset.from_text(q.name, 300, dns.rdataclass.IN, dns.rdatatype.to_text(qtype), adata)
            else:
                rr = dns.rrset.from_text_list(q.name, 300, dns.rdataclass.IN, dns.rdatatype.to_text(qtype), adata)
            resp.answer.append(rr)
        s.sendto(resp.to_wire(), addr)

if __name__ == '__main__':
    run_dns_server()


