import base64

import requests
import json
import argparse
import os
import urllib3
import jwt

from enclave import Enclave


def step_init_recovery(data):
    if 'verificationCodeId' in data:
        return

    if 'msisdn' not in data:
        msisdn = input("Please enter your phone number: ")
        data['msisdn'] = msisdn

    if 'recoveryKey' not in data:
        recovery_key = input("Please enter the recovery key: ")
        data['recoveryKey'] = recovery_key

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
        token = response_data['token']
        decoded = jwt.decode(token, options={"verify_signature": False})
        data['enrollmentToken'] = token
        data['enrollmentJti'] = decoded['jti']
        data['enrollmentDeviceId'] = decoded['deviceId']
    else:
        print(f"Error: {response.status_code}, {response.text}")


def step_do_login(data):
    enclave = Enclave(
        private_key_pem=data["privateKeyPem"],
        login_leaf_cert=data["loginDecryptedCert0"],
        login_intermediate_cert=data["loginDecryptedCert1"]
    )
    body = enclave.encode_proof_message()

    client = APIClient()
    response = client.post("/auth/mobile-device/login", data=body)
    response.raise_for_status()
    response_data = response.json()
    data['authToken'] = response_data['auth_token']


def step_do_enroll(data):
    if 'certificateForLoginParam' in data:
        print("certificateForLogin is already set, skipping do_enroll step.")
        return

    enclave = Enclave()
    data['privateKeyPem'] = enclave.private_key_pem

    csr_for_login = enclave.create_csr(data['enrollmentJti'], data['enrollmentDeviceId'])
    csr_for_signing = enclave.create_csr(data['enrollmentJti'], data['enrollmentDeviceId'])
    encoded_csr_for_login = base64.urlsafe_b64encode(csr_for_login.encode('utf-8')).decode('utf-8').rstrip('=')
    encoded_csr_for_signing = base64.urlsafe_b64encode(csr_for_signing.encode('utf-8')).decode('utf-8').rstrip('=')
    payload = {
        "csrForLogin": f"YXhzLjEuMA.{encoded_csr_for_login}",  # YXhzLjEuMA == "axs.1.0"
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

        enclave = Enclave(
            private_key_pem=data["privateKeyPem"],
            login_leaf_cert=None,
            login_intermediate_cert=None
        )

        login_cert_message = response_data['certificateForLogin']
        login_certs = enclave.decode_certificate_message(login_cert_message)
        data['loginDecryptedCert0'], data['loginDecryptedCert1'] = login_certs[0], login_certs[1]

        signing_cert_message = response_data['certificateForSigning']
        signing_certs = enclave.decode_certificate_message(signing_cert_message)
        data['signingDecryptedCert0'], data['signingDecryptedCert1'] = signing_certs[0], signing_certs[1]
    else:
        raise RuntimeError(f"Error: {response.status_code}, {response.text}")


def setup(playbook_file):
    # Load the data from the file if it exists
    data = {}
    if os.path.exists(playbook_file):
        with open(playbook_file, 'r') as file:
            data = json.load(file)

    # Define the list of steps to run
    steps = [
        lambda: step_init_recovery(data),
        lambda: step_input_sms_code(data),
        lambda: step_get_enrollment_token(data),
        lambda: step_do_enroll(data),
        lambda: step_do_login(data),
    ]

    # Run all steps
    for step in steps:
        step()
        with open(args.file, 'w') as file:
            json.dump(data, file, indent=4)


def unlock(uuid, data):
    enclave = Enclave(
        private_key_pem=data["privateKeyPem"],
        login_leaf_cert=data["loginDecryptedCert0"],
        login_intermediate_cert=data["loginDecryptedCert1"]
    )
    proof_header = enclave.encode_proof_message()
    client = APIClient(data['authToken'])
    headers = {"x-axs-proof": proof_header}
    response = client.put(f"/asset/asset-operation/{uuid}/invoke", headers=headers, json={})
    response.raise_for_status()
    print(response.json())


class APIClient:
    def __init__(self, auth_token=None, base_url="https://api.accessy.se"):
        self.session = requests.Session()
        self.session.headers.update({
            "authorization": f"Bearer {auth_token}"
        })
        self.base_url = base_url

    def get(self, path, **kwargs):
        return self.session.get(self.base_url + path, **kwargs)

    def post(self, path, **kwargs):
        return self.session.post(self.base_url + path, **kwargs)

    def put(self, path, **kwargs):
        return self.session.put(self.base_url + path, **kwargs)

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
    parser.add_argument("command", choices=["setup", "list-assets", "validate-auth-token", "unlock"],
                        help="Command to run")
    parser.add_argument("file", type=str, help="The file to save or read the data")
    args = parser.parse_args()

    if args.command == "setup":
        setup(args.file)
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
    elif args.command == "unlock":
        with open(args.file, 'r') as file:
            data = json.load(file)
        unlock("458BCFE4-69F6-4499-8A88-6CB094141B36", data)
