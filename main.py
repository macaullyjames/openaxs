#!/usr/bin/env python3
import typer
from axs_client import AxsClient
from server import run_server

client = AxsClient()
app = typer.Typer(help="Accessy CLI")
tools = typer.Typer(help="Debugging tools")


@app.command()
def login():
    """Log in and save session."""
    client.login()
    client.save()


@app.command()
def setup(msisdn=typer.Option(None, help="Phone number"),
          recovery_key=typer.Option(None, help="Recovery key")):
    """Enroll device via recovery flow."""
    msisdn = msisdn or typer.prompt("Phone number (msisdn)")
    recovery_key = recovery_key or typer.prompt("Recovery key", hide_input=True)
    verification_code_id = client.init_recovery(msisdn)
    sms_code = typer.prompt("SMS code")
    client.enroll_device(recovery_key, verification_code_id, sms_code)
    client.login()
    client.save()


@tools.command("validate-token")
def validate_auth_token():
    """Validate current auth token."""
    client.validate_auth_token()


@app.command("list")
def list_assets():
    """List assets and operation IDs."""
    for item in client.list_assets():
        name = item.get("name", "")
        for op in item.get("asset", {}).get("operations", []):
            typer.echo(f"{op['id']}\t{name}")


@app.command("serve")
def serve(
    operation_id=typer.Argument(..., help="Operation ID to execute"),
    host: str = "0.0.0.0",
    port: int = 8000,
):
    """Serves a webpage with an unlock button"""
    run_server(client, operation_id, host=host, port=port)


@app.command()
def unlock(operation_id=typer.Argument(..., help="Operation ID to execute")):
    """Unlock using an operation ID."""
    client.unlock(operation_id)


app.add_typer(tools, name="tools")

if __name__ == "__main__":
    client = AxsClient(playbook="axs_playbook")
    app()
