import base64
import sys
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend

import warnings
from cryptography.utils import CryptographyDeprecationWarning
warnings.filterwarnings("ignore", category=CryptographyDeprecationWarning)

def fix_padding(s):
    while len(s) % 4 != 0:
        s += "="
    return s


def decode_header(s):
    return base64.b64decode(fix_padding(s)).decode()


# cat csr | openssl req -text -noout -verify
def decode_csr(csr):
    csr_pem = f"-----BEGIN CERTIFICATE REQUEST-----\n{csr}\n-----END CERTIFICATE REQUEST-----"
    try:
        parsed = x509.load_pem_x509_csr(csr_pem.encode(), default_backend())
        if not parsed.is_signature_valid:
            raise Exception("bad signature")
    except Exception as e:
        raise Exception(f"invalid csr: {e}")

    return csr_pem


# cat csr | openssl x509 -text -noout
def decode_cert(s):
    csr_pem = f"-----BEGIN CERTIFICATE-----\n{s}\n-----END CERTIFICATE-----"
    try:
        x509.load_pem_x509_certificate(csr_pem.encode(), default_backend())
    except Exception as e:
        raise Exception(f"invalid cert: {e}")
    return csr_pem


def decode_csr_param(param):
    parts = param.split(".")
    head, body = parts[0], parts[1]
    body = fix_padding(base64.urlsafe_b64decode(body + '===').decode())
    return decode_header(head), decode_csr(body)


def decode_cert_param(param):
    parts = param.split(".")
    for i, part in enumerate(parts):
        print(f"======part {i}======\n{part}")
    head, body = parts[0], parts[1]
    body = fix_padding(base64.urlsafe_b64decode(body + '===').decode())
    parts = body.split(".")
    for i, part in enumerate(parts):
        print(f"======body part {i}======\n{part}")
    return decode_header(head), decode_cert(body)


def decode_login_param(param):
    parts = param.split(".")
    head, body = parts[0], parts[1]
    for i, part in enumerate(parts):
        print(f"======part {i}======\n{part}")
    body = base64.b64decode(body + '===').decode()
    subs = body.split(".")
    return decode_header(head), [decode_cert(s) for s in subs]


def sign(message):
    # Generate an EC private key
    private_key = ec.generate_private_key(ec.SECP256R1(), default_backend())

    signature = private_key.sign(
        message.encode(),
        ec.ECDSA(hashes.SHA256())
    )

    pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption()
    )
    print(pem)
    return signature

def main():
    cmd = sys.argv[1] if len(sys.argv) > 1 else None
    data = sys.stdin.read()
    if cmd == "decode_csrForLogin":
        _, pem = decode_csr_param(data)
        print(pem)
    elif cmd == "decode_certificateForLogin":
        _, pem = decode_cert_param(data)
        print(pem)
    elif cmd == "decode_login":
        _, certs = decode_login_param(data)
        if len(sys.argv) > 2:
            idx = int(sys.argv[2])
            print(certs[idx])
        else:
            for cert in certs:
                continue
                #print(cert)

        #print(pem)
    elif cmd == "sign":
        sig = sign(data)
        print(base64.b64encode(sig).decode('utf-8'))
    else:
        print("Usage: python tools.py decode_csrForLogin")
        sys.exit(1)

if __name__ == "__main__":
    main()