import base64
import json
import os

import jwt
import requests
import urllib3
from cryptography.hazmat.primitives._serialization import Encoding

from api_client import APIClient
from enclave import Enclave


class AxsClient:
    def __init__(self, playbook=None):
        self.playbook = playbook
        self.auth_token = None

        if playbook is not None and os.path.exists(playbook):
            self.load()
        else:
            self.enclave = Enclave()

    def load(self):
        with open(self.playbook, 'r') as file:
            data = json.load(file)
            self.enclave = Enclave(
                private_key_pem=data.get("privateKeyPem"),
                login_leaf_cert=data.get("loginDecryptedCert0"),
                login_intermediate_cert=data.get("loginDecryptedCert1"),
                signing_leaf_cert=data.get("signingDecryptedCert0"),
                signing_intermediate_cert=data.get("signingDecryptedCert1"),
            )
            self.auth_token = data.get("authToken")

    def save(self):
        if self.playbook is not None:
            with open(self.playbook, 'w') as file:
                data = {
                    "privateKeyPem": self.enclave.private_key_pem,
                    "loginDecryptedCert0": self.enclave.login_leaf_cert.public_bytes(Encoding.PEM).decode("ascii"),
                    "loginDecryptedCert1": self.enclave.login_intermediate_cert.public_bytes(Encoding.PEM).decode("ascii"),
                    "signingDecryptedCert0": self.enclave.signing_leaf_cert.public_bytes(Encoding.PEM).decode("ascii"),
                    "signingDecryptedCert1": self.enclave.signing_intermediate_cert.public_bytes(Encoding.PEM).decode("ascii"),
                    "authToken": self.auth_token,
                }
                json.dump(data, file, indent=4)

    def init_recovery(self, msisdn):
        client = APIClient()
        response = client.post("/auth/recover", json={"msisdn": msisdn})
        response.raise_for_status()
        response_data = response.json()
        return response_data["verificationCodeId"]

    def enroll_device(self, recovery_key, verification_code_id, sms_code):
        client = APIClient()
        response = client.post("/auth/mobile-device/enroll/token", json={
            "code": sms_code,
            "id": verification_code_id
        })
        response.raise_for_status()
        response_data = response.json()
        token = response_data['token']
        decoded = jwt.decode(token, options={"verify_signature": False})
        enrollment_jti = decoded['jti']
        enrollment_device_id = decoded['deviceId']

        csr = self.enclave.create_csr(enrollment_jti, enrollment_device_id)
        encoded_csr = base64.urlsafe_b64encode(csr.encode('utf-8')).decode('utf-8').rstrip('=')
        payload = {
            "csrForLogin": f"YXhzLjEuMA.{encoded_csr}",  # YXhzLjEuMA == "axs.1.0"
            "csrForSigning": f"YXhzLjEuMA.{encoded_csr}",
            "appName": "Accessy-iOS",
            "deviceName": "iPhone (iPhone)",
            "recoveryKey": recovery_key
        }
        payload = json.dumps(payload, separators=(',', ':'))
        url = "https://api.accessy.se/auth/mobile-device/enroll"
        headers = {
            "x-axs-plan": "accessy",
            "content-type": "application/json",
            "authorization": f"Bearer {token}",
            "user-agent": "Accessy-iOS-v2.12.0-b2634",
            "accept": "application/vnd.axessions.v2+json",
            'Accept-Encoding': urllib3.util.SKIP_HEADER,
            'connection': None
        }
        response = requests.post(url, headers=headers, data=payload)
        if response.status_code == 200:
            response_data = response.json()

            login_cert_message = response_data['certificateForLogin']
            login_certs = self.enclave.decode_certificate_message(login_cert_message)
            self.enclave.login_leaf_cert = login_certs[0]
            self.enclave.login_intermediate_cert = login_certs[1]

            signing_cert_message = response_data['certificateForSigning']
            signing_certs = self.enclave.decode_certificate_message(signing_cert_message)
            self.enclave.signing_leaf_cert = signing_certs[0]
            self.enclave.signing_intermediate_cert = signing_certs[1]
        else:
            raise RuntimeError(f"Error: {response.status_code}, {response.text}")

    def login(self):
        client = APIClient()
        data = self.enclave.encode_proof_message()
        response = client.post("/auth/mobile-device/login", data=data)
        response.raise_for_status()
        response_data = response.json()
        self.auth_token = response_data['auth_token']

    def unlock(self, uuid):
        proof_header = self.enclave.encode_proof_message()
        client = APIClient(self.auth_token)
        headers = {"x-axs-proof": proof_header}
        response = client.put(f"/asset/asset-operation/{uuid}/invoke", headers=headers, json={})
        response.raise_for_status()
        print(response.json())

    def list_assets(self):
        client = APIClient(self.auth_token)
        url = "/asset/my-asset-publication?page_size=100"
        response = client.get(url)
        response.raise_for_status()
        return response.json()["items"]

    def validate_auth_token(self):
        url = "/auth/action"
        client = APIClient(self.auth_token)
        response = client.get(url)
        if 200 <= response.status_code < 300:
            print("Token is valid.")
        else:
            print(f"Token validation failed: {response.status_code}, {response.text}")
