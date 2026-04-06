import http.server
import socketserver

PORT = 8080

class WasmHandler(http.server.SimpleHTTPRequestHandler):
    def end_headers(self):
        # Ensure browsers recognize the WASM mime type correctly
        if self.path.endswith('.wasm'):
            self.send_header('Content-Type', 'application/wasm')
        super().end_headers()

with socketserver.TCPServer(("", PORT), WasmHandler) as httpd:
    print(f"Serving at http://localhost:{PORT}")
    httpd.serve_forever()
