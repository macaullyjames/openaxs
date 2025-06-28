import base64

import requests
import json
import argparse
import os
import urllib3
import jwt
import datetime
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.serialization import load_pem_private_key, load_der_public_key, Encoding, PrivateFormat, NoEncryption
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers.algorithms import AES
from Crypto.Cipher import AES as AES_Crypto
from Crypto.Util.Padding import pad, unpad
import hashlib



def step_generate_private_keys(data):
    # Check if this step should be run
    if 'privateKeyForLogin' in data:
        print("privateKey is already set, skipping step")
        return

    private_key_login = ec.generate_private_key(ec.SECP256R1(), default_backend())
    pem = private_key_login.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption()
    )
    data['privateKeyForLogin'] = pem.decode('utf-8')
    data['privateKeyForSigning'] = pem.decode('utf-8')

    """
    private_key_signing = ec.generate_private_key(ec.SECP256R1(), default_backend())
    pem = private_key_signing.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption()
    )
    data['privateKeyForSigning'] = pem.decode('utf-8')
    """

def step_input_phone_number(data):
    # Check if this step should be run
    if 'msisdn' in data:
        print("msisdn is already set, skipping step")
        return

    msisdn = input("Please enter your phone number: ")
    data['msisdn'] = msisdn

def step_input_recovery_key(data):
    # Check if this step should be run
    if 'recoveryKey' in data:
        print("recoveryKey is already set, skipping step")
        return

    recovery_key = input("Please enter the recovery key: ")
    data['recoveryKey'] = recovery_key


def step_init_recovery(data):
    if 'verificationCodeId' in data:
        return

    url = "https://api.accessy.se/auth/recover"
    headers = {
        "x-axs-plan": "accessy",
        "content-type": "application/json"
    }
    payload = {
        "msisdn": data['msisdn']
    }

    response = requests.post(url, headers=headers, json=payload)
    if response.status_code == 200:
        response_data = response.json()
        data.update(response_data)
    else:
        print(f"Error: {response.status_code}, {response.text}")

def step_input_sms_code(data):
    # Check if this step should be run
    if 'verificationCode' in data:
        print("verificationCode is already set, skipping enter_code step.")
        return

    # Ask the user for the SMS code
    verification_code = input("Please enter the SMS code you received: ")
    data['verificationCode'] = verification_code

def step_get_enrollment_token(data):
    # Check if this step should be run
    if 'enrollmentToken' in data:
        print("enrollmentToken is already set, skipping enroll_device step.")
        return

    url = "https://api.accessy.se/auth/mobile-device/enroll/token"
    headers = {
        "x-axs-plan": "accessy",
        "content-type": "application/json",
    }
    payload = {
        "code": data['verificationCode'],
        "id": data['verificationCodeId']
    }

    response = requests.post(url, headers=headers, json=payload)
    if response.status_code == 200:
        response_data = response.json()
        data['enrollmentToken'] = response_data['token']
    else:
        print(f"Error: {response.status_code}, {response.text}")


def step_extract_enrollment_token_details(data):
    decoded = jwt.decode(data['enrollmentToken'], options={"verify_signature": False})
    data['enrollmentJti'] = decoded['jti']
    data['enrollmentDeviceId'] = decoded['deviceId']


def step_generate_login_cert(data):
    # Decode the intermediate certificate and load it
    intermediate_cert_der = base64.b64decode(data['certificateForLogin'])
    intermediate_cert = x509.load_der_x509_certificate(intermediate_cert_der, default_backend())

    # Load the intermediate private key
    private_key_pem = data['privateKeyForLogin'].encode()
    private_key = load_pem_private_key(private_key_pem, password=None, backend=default_backend())

    # Generate a new EC key pair for the leaf certificate
    leaf_key = ec.generate_private_key(ec.SECP256R1(), default_backend())

    # Create a subject name for the leaf certificate
    subject = x509.Name([
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, data['enrollmentJti']),
        x509.NameAttribute(NameOID.COMMON_NAME, data['enrollmentDeviceId'])
    ])

    # Use the issuer's name from the intermediate certificate
    issuer = intermediate_cert.subject

    # Build the leaf certificate
    leaf_cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(leaf_key.public_key())
        .serial_number(0x6d42d847)
        .not_valid_before(datetime.datetime(2024, 10, 14, 17, 30, 38))  # Match the Not Before date
        .not_valid_after(datetime.datetime(2025, 10, 14, 17, 30, 38))  # Match the Not After date
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .sign(private_key, hashes.SHA256(), default_backend())
    )

    # Convert the leaf certificate to PEM format
    leaf_cert_der = leaf_cert.public_bytes(Encoding.DER)
    leaf_cert_der_encoded = base64.b64encode(leaf_cert_der).decode('utf-8')
    leaf_key_pem = leaf_key.private_bytes(
        Encoding.PEM,
        PrivateFormat.TraditionalOpenSSL,
        NoEncryption()
    )

    data["loginLeafCert"] = leaf_cert_der_encoded
    data["loginPrivateKey"] = leaf_key_pem.decode("utf-8")


def step_do_login(data):
    leaf_key_pem = data["privateKeyForLogin"]
    leaf_key = load_pem_private_key(leaf_key_pem.encode("utf-8"), password=None, backend=default_backend())

    # intermediate_key_pem = data["privateKeyForLogin"]
    # intermediate_key = load_pem_private_key(intermediate_key_pem.encode("utf-8"), password=None, backend=default_backend())

    encoded_intermediate_cert = data['loginDecryptedCert1']
    encoded_leaf_cert = data['loginDecryptedCert0']
    base64_certs = base64.urlsafe_b64encode(f"{encoded_leaf_cert}.{encoded_intermediate_cert}".encode("utf-8")).decode(
        "utf-8").rstrip("=")

    # Round down to closest 5 seconds
    now = datetime.datetime.now()
    rounded_seconds = now.second - (now.second % 5)
    rounded_time = now.replace(second=rounded_seconds, microsecond=0)
    timestamp = str(int(rounded_time.timestamp()))
    base64_timestamp = base64.urlsafe_b64encode(timestamp.encode("utf-8")).decode("utf-8").rstrip("=")

    body = f"YXhzLjEuNA.{base64_certs}.{base64_timestamp}"

    # Sign the message
    signature = leaf_key.sign(
        body.encode("utf-8"),
        ec.ECDSA(hashes.SHA256())
    )

    # Encode the signature in base64 format for easy transmission
    signature_base64 = base64.urlsafe_b64encode(signature).decode("utf-8").rstrip("=")
    body = f"{body}.{signature_base64}"
    print(body)

    url = "https://api.accessy.se/auth/mobile-device/login"
    headers = {
        "x-axs-plan": "accessy",
        "content-type": "application/json",
    }

    response = requests.post(url, headers=headers, data=body)
    if response.status_code == 200:
        response_data = response.json()
        print(response_data)
        data['authToken'] = response_data['auth_token']
    else:
        print(f"Error: {response.status_code}, {response.text}")

def step_do_enroll(data):
    if 'certificateForLoginParam' in data:
        print("certificateForLogin is already set, skipping do_enroll step.")
        return
    csr_for_login = create_csr(data['privateKeyForLogin'], data)
    csr_for_signing = create_csr(data['privateKeyForSigning'], data)
    encoded_csr_for_login = base64.urlsafe_b64encode(csr_for_login.encode('utf-8')).decode('utf-8').rstrip('=')
    encoded_csr_for_signing = base64.urlsafe_b64encode(csr_for_signing.encode('utf-8')).decode('utf-8').rstrip('=')
    payload = {
        "csrForLogin": f"YXhzLjEuMA.{encoded_csr_for_login}",
        "appName": "Accessy-iOS",
        "csrForSigning": f"YXhzLjEuMA.{encoded_csr_for_signing}",
        "deviceName": "iPhone (iPhone)",
        "recoveryKey": data["recoveryKey"]
    }
    payload = json.dumps(payload, separators=(',', ':'))
    url = "https://api.accessy.se/auth/mobile-device/enroll"
    headers = {
        "x-axs-plan": "accessy",
        "content-type": "application/json",
        "authorization": f"Bearer {data['enrollmentToken']}",
        "user-agent": "Accessy-iOS-v2.12.0-b2634",
        "accept": "application/vnd.axessions.v2+json",
        'Accept-Encoding': urllib3.util.SKIP_HEADER,
        'connection': None
    }
    response = requests.post(url, headers=headers, data=payload)
    if response.status_code == 200:
        response_data = response.json()
        data['certificateForLoginParam'] = response_data['certificateForLogin']
        data['certificateForSigningParam'] = response_data['certificateForSigning']
    else:
        print(f"Error: {response.status_code}, {response.text}")


def step_extract_certs_from_params(data):
    # Step 1: Split the components of the certificateForLoginParam
    components = data['certificateForLoginParam'].split(".")
    """
    for i, s in enumerate(components):
        print(f"part {i}")
        print(s)
    """

    # Step 1: Split the input message into parts
    components = data['certificateForLoginParam'].split(".")

    # Extract the key exchange public key from part 2
    peer_public_key_encoded = base64.urlsafe_b64decode(fix_padding(components[2]))
    peer_public_key = load_der_public_key(peer_public_key_encoded, backend=default_backend())

    # Load the private key for login (this represents the entity's private key)
    private_key_pem = data['privateKeyForLogin'].encode('utf-8')
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
    tag_encoded = encrypted_message_parts[2]

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
    # Convert decrypted bytes to a string and store it
    decrypted_message_str = decrypted_message.decode('utf-8')
    # Print or store the decrypted message
    certs = decrypted_message_str.split(".")
    data['loginDecryptedCert0'] = certs[0]
    data['loginDecryptedCert1'] = certs[1]


def fix_padding(s):
    while len(s) % 4 != 0:
        s += "="
    return s

def create_csr(private_key_pem, data):
    # Load the private key from PEM
    private_key = serialization.load_pem_private_key(
        private_key_pem.encode('utf-8'),
        password=None,
        backend=default_backend()
    )

    # Create subject information
    subject = x509.Name([
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, data['enrollmentJti']),
        x509.NameAttribute(NameOID.COMMON_NAME, data['enrollmentDeviceId']),
    ])

    # Create the CSR
    csr = x509.CertificateSigningRequestBuilder().subject_name(subject).sign(
        private_key, hashes.SHA256(), default_backend()
    )

    csr_der = csr.public_bytes(serialization.Encoding.DER)
    encoded = base64.b64encode(csr_der).decode('utf-8')
    return encoded

def setup(playbook_file):
    # Load the data from the file if it exists
    data = {}
    if os.path.exists(playbook_file):
        with open(playbook_file, 'r') as file:
            data = json.load(file)

    # Define the list of steps to run
    steps = [
        lambda: step_generate_private_keys(data),
        lambda: step_input_phone_number(data),
        lambda: step_input_recovery_key(data),
        lambda: step_init_recovery(data),
        lambda: step_input_sms_code(data),
        lambda: step_get_enrollment_token(data),
        lambda: step_extract_enrollment_token_details(data),
        lambda: step_do_enroll(data),
        lambda: step_extract_certs_from_params(data),
        # lambda: step_generate_login_cert(data),
        lambda: step_do_login(data),
    ]

    # Run all steps
    for step in steps:
        step()
        with open(args.file, 'w') as file:
            json.dump(data, file, indent=4)

class APIClient:
    def __init__(self, auth_token, base_url="https://api.accessy.se"):
        self.session = requests.Session()
        self.session.headers.update({
            "authorization": f"Bearer {auth_token}"
        })
        self.base_url = base_url

    def get(self, path, **kwargs):
        return self.session.get(self.base_url + path, **kwargs)

    def post(self, path, **kwargs):
        return self.session.post(self.base_url + path, **kwargs)

    # add .put, .delete if needed



def list_assets(api_client):
    url = "/asset/my-asset-publication?page_size=100"
    response = api_client.get(url)
    if response.status_code == 200:
        print(json.dumps(response.json(), indent=2))
    else:
        print(f"Error: {response.status_code}, {response.text}")


def validate_auth_token(api_client):
    url = "/auth/action"
    response = api_client.get(url)
    if 200 <= response.status_code < 300:
        print("Token is valid.")
    else:
        print(f"Token validation failed: {response.status_code}, {response.text}")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Accessy CLI")
    parser.add_argument("command", choices=["login", "setup", "list-assets", "validate-auth-token"], help="Command to run")
    parser.add_argument("file", type=str, help="The file to save or read the data")
    args = parser.parse_args()

    if args.command == "setup":
        setup(args.file)
    elif args.command == "login":
        with open(args.file, 'r') as file:
            data = json.load(file)
        step_do_login(data)
    elif args.command == "list-assets":
        with open(args.file, 'r') as file:
            data = json.load(file)
        client = APIClient(data['authToken'])
        list_assets(client)
    elif args.command == "validate-auth-token":
        with open(args.file, 'r') as file:
            data = json.load(file)
        client = APIClient(data['authToken'])
        validate_auth_token(client)
