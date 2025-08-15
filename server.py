# server.py (Bottle version)
from bottle import Bottle, template


def create_app(client, operation_id):
    app = Bottle()

    @app.get("/")
    def index():
        return template("index", button_text="Unlock", message=None)

    @app.post("/unlock")
    def unlock():
        try:
            client.unlock(operation_id)
            return template("index", button_text="Unlock", message="Unlocked!")
        except Exception as e:
            # Surface a minimal error message; keep 500 status.
            return template("index", button_text="Unlock", message=f"Failed to unlock: {e}"), 500

    return app


def run_server(client, operation_id, host="0.0.0.0", port=8000):
    app = create_app(client, operation_id)
    print(f"Serving on http://{host}:{port}, press ctrl+c to quit")
    app.run(host=host, port=port, debug=False, reloader=False, quiet=True)
