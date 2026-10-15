#!/usr/bin/env python3
"""
SentinelGuard Web GUI Server:
Zero-dependency HTTP server providing an interactive control center
for executing and visualizing all 10 analysis and security phases.

Usage:
    python gui.py
    python gui.py --port 8080 --no-browser
"""

import os
import sys
import json
import time
import argparse
import webbrowser
import threading
from http.server import HTTPServer, BaseHTTPRequestHandler
from urllib.parse import urlparse

# Ensure local modules are importable
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from pipeline import run_pipeline

STATIC_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "web")
_CACHED_SAMPLE = None


class SentinelRequestHandler(BaseHTTPRequestHandler):
    """HTTP Request handler serving static UI assets and the execution API."""

    def _set_headers(self, status=200, content_type="application/json"):
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type")
        self.end_headers()

    def do_OPTIONS(self):
        self._set_headers(204)

    def do_GET(self):
        parsed = urlparse(self.path)
        path = parsed.path

        if path in ("/", "/index.html"):
            self._serve_file(os.path.join(STATIC_DIR, "index.html"), "text/html; charset=utf-8")
        elif path == "/style.css":
            self._serve_file(os.path.join(STATIC_DIR, "style.css"), "text/css; charset=utf-8")
        elif path == "/app.js":
            self._serve_file(os.path.join(STATIC_DIR, "app.js"), "application/javascript; charset=utf-8")
        elif path == "/api/health":
            self._set_headers(200, "application/json")
            self.wfile.write(json.dumps({
                "status": "healthy",
                "engine": "SentinelGuard Multi-Phase Pipeline",
                "version": "1.0.0",
                "phases": ["0", "1", "2", "3a", "4a", "5a", "6", "7", "8", "9", "all"]
            }).encode("utf-8"))
        elif path == "/api/report":
            report_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "final_report.md")
            if os.path.exists(report_path):
                with open(report_path, "r", encoding="utf-8") as f:
                    content = f.read()
                self._set_headers(200, "application/json")
                self.wfile.write(json.dumps({"success": True, "markdown": content}).encode("utf-8"))
            else:
                self._set_headers(404, "application/json")
                self.wfile.write(json.dumps({"success": False, "error": "final_report.md not found"}).encode("utf-8"))
        elif path == "/api/sample":
            # Return pre-computed or on-demand cached pipeline results for instant exploration
            global _CACHED_SAMPLE
            if _CACHED_SAMPLE is None:
                try:
                    _CACHED_SAMPLE = run_pipeline(source=".", phase="all")
                except Exception as e:
                    self._set_headers(500, "application/json")
                    self.wfile.write(json.dumps({"success": False, "error": str(e)}).encode("utf-8"))
                    return
            self._set_headers(200, "application/json")
            self.wfile.write(json.dumps({
                "success": True,
                "phase": "all",
                "duration_seconds": 0.01,
                "is_cached": True,
                "data": _CACHED_SAMPLE
            }).encode("utf-8"))
        else:
            self.send_error(404, "Not Found")

    def do_POST(self):
        parsed = urlparse(self.path)

        if parsed.path == "/api/run":
            content_length = int(self.headers.get("Content-Length", 0))
            body = self.rfile.read(content_length)

            try:
                payload = json.loads(body.decode("utf-8"))
            except Exception as e:
                self._set_headers(400, "application/json")
                self.wfile.write(json.dumps({"success": False, "error": f"Invalid JSON payload: {str(e)}"}).encode("utf-8"))
                return

            source = payload.get("source", ".")
            source_type = payload.get("source_type") or None
            phase = payload.get("phase", "all")

            start_time = time.time()
            try:
                result = run_pipeline(source=source, source_type=source_type, phase=phase)
                duration = time.time() - start_time

                response_data = {
                    "success": True,
                    "phase": phase,
                    "duration_seconds": round(duration, 3),
                    "data": result
                }
                self._set_headers(200, "application/json")
                self.wfile.write(json.dumps(response_data, indent=2).encode("utf-8"))

            except Exception as e:
                self._set_headers(500, "application/json")
                self.wfile.write(json.dumps({
                    "success": False,
                    "error": str(e)
                }).encode("utf-8"))

        else:
            self.send_error(404, "Endpoint Not Found")

    def _serve_file(self, filepath, content_type):
        if not os.path.exists(filepath):
            self.send_error(404, "File Not Found")
            return

        try:
            with open(filepath, "rb") as f:
                content = f.read()
            self._set_headers(200, content_type)
            self.wfile.write(content)
        except Exception as e:
            self.send_error(500, f"Error reading static file: {str(e)}")

    def log_message(self, format, *args):
        # Override to keep terminal clean while logging errors
        if args and str(args[1]) in ("404", "500"):
            super().log_message(format, *args)


def start_server(host: str = "127.0.0.1", port: int = 8080, open_browser: bool = True):
    server_address = (host, port)
    try:
        httpd = HTTPServer(server_address, SentinelRequestHandler)
    except OSError:
        # Fall back to alternative port if 8080 is busy
        port = 8081
        server_address = (host, port)
        httpd = HTTPServer(server_address, SentinelRequestHandler)

    url = f"http://{host}:{port}/"
    print(f"============================================================")
    print(f"  SentinelGuard Pipeline Control Center Running!")
    print(f"  Web Interface: {url}")
    print(f"  Press Ctrl+C to terminate server.")
    print(f"============================================================")

    if open_browser:
        def _launch():
            time.sleep(0.8)
            webbrowser.open(url)
        threading.Thread(target=_launch, daemon=True).start()

    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\nShutting down SentinelGuard Control Center...")
        httpd.server_close()


def main():
    parser = argparse.ArgumentParser(description="SentinelGuard Web GUI Control Center")
    parser.add_argument("--host", default="127.0.0.1", help="Host address to bind (default: 127.0.0.1)")
    parser.add_argument("--port", type=int, default=8080, help="Port to bind (default: 8080)")
    parser.add_argument("--no-browser", action="store_true", help="Do not automatically launch web browser")
    args = parser.parse_args()

    start_server(host=args.host, port=args.port, open_browser=not args.no_browser)


if __name__ == "__main__":
    main()
