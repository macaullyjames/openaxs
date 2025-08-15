import argparse

from axs_client import AxsClient

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Accessy CLI")
    parser.add_argument("command", choices=["login", "setup", "list-assets", "validate-auth-token", "unlock"],
                        help="Command to run")
    parser.add_argument("file", type=str, nargs="?", default="axs_playbook", help="The file to save or read the data")
    args = parser.parse_args()

    client = AxsClient(playbook=args.file)
    if args.command == "login":
        client.login()
        client.save()

    if args.command == "setup":
        msisdn = input("Please enter your phone number: ")
        recovery_key = input("Please enter the recovery key: ")
        verification_code_id = client.init_recovery(msisdn)
        sms_code = input("Please enter the SMS code you received: ")
        client.enroll_device(recovery_key, verification_code_id, sms_code)
        client.login()
        client.save()
    elif args.command == "list-assets":
        client.list_assets()
    elif args.command == "validate-auth-token":
        client.validate_auth_token()
    elif args.command == "unlock":
        client.unlock("458BCFE4-69F6-4499-8A88-6CB094141B36")
