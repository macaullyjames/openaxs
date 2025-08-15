import base64
import datetime
import hashlib
import textwrap

from Crypto.Cipher import AES as AES_Crypto
from Crypto.Util.Padding import unpad

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives._serialization import Encoding
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.serialization import load_pem_private_key, load_der_public_key
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import serialization, hashes


class Enclave:
    def __init__(self, private_key_pem=None, login_leaf_cert=None, login_intermediate_cert=None, signing_leaf_cert=None, signing_intermediate_cert=None):
        if private_key_pem is None:
            private_key = ec.generate_private_key(ec.SECP256R1(), default_backend())
            pem = private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=serialization.NoEncryption()
            )
            private_key_pem = pem.decode('utf-8')
        self.private_key_pem = private_key_pem

        if isinstance(login_leaf_cert, str):
            login_leaf_cert = x509.load_pem_x509_certificate(login_leaf_cert.encode(), default_backend())
        self.login_leaf_cert = login_leaf_cert

        if isinstance(login_intermediate_cert, str):
            login_intermediate_cert = x509.load_pem_x509_certificate(login_intermediate_cert.encode(),
                                                                     default_backend())
        self.login_intermediate_cert = login_intermediate_cert

        if isinstance(signing_leaf_cert, str):
            signing_leaf_cert = x509.load_pem_x509_certificate(signing_leaf_cert.encode(), default_backend())
        self.signing_leaf_cert = signing_leaf_cert

        if isinstance(signing_intermediate_cert, str):
            signing_intermediate_cert = x509.load_pem_x509_certificate(signing_intermediate_cert.encode(),
                                                                       default_backend())
        self.signing_intermediate_cert = signing_intermediate_cert

    def encode_proof_message(self):
        private_key_pem = self.private_key_pem
        private_key = load_pem_private_key(private_key_pem.encode("utf-8"), password=None, backend=default_backend())

        intermediate_bytes = self.login_intermediate_cert.public_bytes(Encoding.DER)
        leaf_bytes = self.login_leaf_cert.public_bytes(Encoding.DER)
        encoded_intermediate_cert = base64.b64encode(intermediate_bytes).decode("ascii")
        encoded_leaf_cert = base64.b64encode(leaf_bytes).decode("ascii")

        base64_certs = base64.urlsafe_b64encode(f"{encoded_leaf_cert}.{encoded_intermediate_cert}".encode("utf-8")).decode(
            "utf-8").rstrip("=")

        # Round down to closest 5 seconds
        now = datetime.datetime.now()
        rounded_seconds = now.second - (now.second % 5)
        rounded_time = now.replace(second=rounded_seconds, microsecond=0)
        timestamp = str(int(rounded_time.timestamp()))
        base64_timestamp = base64.urlsafe_b64encode(timestamp.encode("utf-8")).decode("utf-8").rstrip("=")

        body = f"YXhzLjEuNA.{base64_certs}.{base64_timestamp}"  # YXhzLjEuNA == axs.1.4

        # Sign the message
        signature = private_key.sign(
            body.encode("utf-8"),
            ec.ECDSA(hashes.SHA256())
        )

        # Append the signature
        signature_base64 = base64.urlsafe_b64encode(signature).decode("utf-8").rstrip("=")
        msg = f"{body}.{signature_base64}"
        return msg

    def decode_certificate_message(self, msg):
        # Step 1: Split the input message into parts
        components = msg.split(".")

        # Extract the key exchange public key from part 2
        peer_public_key_encoded = base64.urlsafe_b64decode(fix_padding(components[2]))
        peer_public_key = load_der_public_key(peer_public_key_encoded, backend=default_backend())

        # Load the private key for login (this represents the entity's private key)
        private_key_pem = self.private_key_pem.encode('utf-8')
        private_key = load_pem_private_key(private_key_pem, password=None, backend=default_backend())

        # Step 2: Perform ECDH key exchange to derive the shared secret
        shared_secret = private_key.exchange(ec.ECDH(), peer_public_key)

        # Step 3: Hash the shared secret using SHA-512 (as indicated in the Android Java implementation)
        hashed_shared_secret = hashlib.sha512(shared_secret).digest()

        # Step 4: Extract the encrypted message from components[3]
        encrypted_message = base64.urlsafe_b64decode(fix_padding(components[3])).decode("utf-8")

        # Step 5: Split the encrypted message into parts using '.' as a delimiter
        encrypted_message_parts = encrypted_message.split('.')

        if len(encrypted_message_parts) != 3:
            print("Invalid number of components in the encrypted message.")
            return

        # Step 6: Extract components from the encrypted message
        iv_encoded = encrypted_message_parts[0]
        ciphertext_encoded = encrypted_message_parts[1]

        # Decode the base64url encoded parts
        iv = base64.urlsafe_b64decode(fix_padding(iv_encoded))
        ciphertext = base64.urlsafe_b64decode(fix_padding(ciphertext_encoded))

        # Step 7: Validate IV length
        if len(iv) != 16:
            print("Invalid IV length, must be 16 bytes.")
            return

        # Step 8: Decrypt the message using AES in CBC mode
        # Create a cipher using AES CBC mode and the hashed shared secret as the key
        cipher = AES_Crypto.new(hashed_shared_secret[:32], AES_Crypto.MODE_CBC,
                                iv)  # Use only the first 32 bytes for AES-256
        # Decrypt the ciphertext
        decrypted_padded_message = cipher.decrypt(ciphertext)
        decrypted_message = unpad(decrypted_padded_message, AES_Crypto.block_size)
        decrypted_message_str = decrypted_message.decode('utf-8')

        # Extract the DER encoded certs
        der_certs = decrypted_message_str.split(".")

        # Parse the certs
        certs = []
        for der in der_certs:
            der = base64.b64decode(der, validate=True)
            cert = x509.load_der_x509_certificate(der)
            certs.append(cert)
        return certs

    def create_csr(self, jti, device_id):
        # Load the private key from PEM
        private_key = serialization.load_pem_private_key(
            self.private_key_pem.encode('utf-8'),
            password=None,
            backend=default_backend()
        )

        # Create subject information
        subject = x509.Name([
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, jti),
            x509.NameAttribute(NameOID.COMMON_NAME, device_id),
        ])

        # Create the CSR
        csr = x509.CertificateSigningRequestBuilder().subject_name(subject).sign(
            private_key, hashes.SHA256(), default_backend()
        )

        csr_der = csr.public_bytes(serialization.Encoding.DER)
        encoded = base64.b64encode(csr_der).decode('utf-8')
        return encoded


def fix_padding(s):
    while len(s) % 4 != 0:
        s += "="
    return s
