# server.py
import http.server
import socketserver
from jinja2 import Template
import os


def _load_template():
    template_path = os.path.join(os.path.dirname(__file__), "template.html")
    with open(template_path, "r", encoding="utf-8") as f:
        return Template(f.read().strip())


def _make_handler(client, operation_id):
    class Handler(http.server.SimpleHTTPRequestHandler):
        def do_GET(self):
            self.send_response(200)
            self.send_header("Content-type", "text/html")
            self.end_headers()
            rendered_html = _load_template().render(button_text="Unlock", message=None)
            self.wfile.write(rendered_html.encode())

        def do_POST(self):
            if self.path == "/unlock":
                client.unlock(operation_id)
                self.send_response(200)
                self.send_header("Content-type", "text/html")
                self.end_headers()
                rendered_html = _load_template().render(button_text="Unlock", message="Unlocked!")
                self.wfile.write(rendered_html.encode())
            else:
                self.send_error(404)

        # Keep logs quiet (optional)
        def log_message(self, _, *args):
            return

    return Handler


def run_server(client, operation_id, host="0.0.0.0", port=8000):
    handler = _make_handler(client, operation_id)
    with socketserver.TCPServer((host, port), handler) as httpd:
        print(f"Serving on http://{host}:{port}")
        httpd.serve_forever()
