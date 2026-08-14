FROM python:3-slim

# Minimal test client: dumps the environment (secrets injected via compose) and
# serves an HTTP health endpoint on 8080 so the deployer/continuity healthcheck
# on /health gets an HTTP 200.
EXPOSE 8080

CMD ["python", "-c", "\
import os\n\
from http.server import BaseHTTPRequestHandler, HTTPServer\n\
for k, v in sorted(os.environ.items()):\n\
    print(f'{k}={v}', flush=True)\n\
class H(BaseHTTPRequestHandler):\n\
    def do_GET(self):\n\
        body = b'ok' if self.path == '/health' else b'test client'\n\
        code = 200 if self.path == '/health' else 404\n\
        self.send_response(code)\n\
        self.send_header('Content-Type', 'text/plain')\n\
        self.send_header('Content-Length', str(len(body)))\n\
        self.end_headers()\n\
        self.wfile.write(body)\n\
    def log_message(self, *a):\n\
        pass\n\
print('serving /health on :8080', flush=True)\n\
HTTPServer(('0.0.0.0', 8080), H).serve_forever()\n\
"]
