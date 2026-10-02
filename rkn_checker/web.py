import json
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

from . import __version__
from .targets import WHITE_URLS, BLACK_URLS
from .core import iter_check_urls, get_self_info

class RknWebHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path == "/":
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.end_headers()
            html_path = Path(__file__).parent / "index.html"
            self.wfile.write(html_path.read_bytes())
            
        elif self.path == "/api/init":
            self.send_response(200)
            self.send_header("Content-Type", "application/json; charset=utf-8")
            self.end_headers()
            data = {
                "meta": {"version": __version__},
                "whitelist": [{"name": k, "url": v} for k, v in WHITE_URLS.items()],
                "blacklist": [{"name": k, "url": v} for k, v in BLACK_URLS.items()]
            }
            self.wfile.write(json.dumps(data).encode("utf-8"))
            
        elif self.path == "/api/self-info":
            self.send_response(200)
            self.send_header("Content-Type", "application/json; charset=utf-8")
            self.end_headers()
            self.wfile.write(json.dumps(get_self_info(timeout=3.0)).encode("utf-8"))
            
        else:
            self.send_error(404)

    def do_POST(self):
        if self.path == "/api/scan":
            length = int(self.headers.get("Content-Length", 0))
            req = json.loads(self.rfile.read(length).decode("utf-8"))
            
            targets = req.get("targets", {})
            workers = req.get("workers", 10)
            timeout = req.get("timeout", 5.0)
            identify = req.get("identify", False)
            
            self.send_response(200)
            self.send_header("Content-Type", "application/x-ndjson; charset=utf-8")
            self.send_header("Cache-Control", "no-cache")
            self.end_headers()
            
            for res in iter_check_urls(targets, max_workers=workers, timeout=timeout, identify=identify):
                line = json.dumps(res.to_dict()) + "\n"
                self.wfile.write(line.encode("utf-8"))
                self.wfile.flush()
        else:
            self.send_error(404)
            
    def log_message(self, format, *args):
        pass

def run_server(host: str, port: int) -> int:
    server = ThreadingHTTPServer((host, port), RknWebHandler)
    print(f"[*] RKN Block Checker Web UI v{__version__}")
    print(f"[*] Starting local server at http://{host}:{port}/")
    print("[*] Press Ctrl+C to stop.")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\n[*] Shutting down...")
    return 0