from http.server import BaseHTTPRequestHandler, HTTPServer
import threading
import urllib.parse
import time

class DummyHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        parsed = urllib.parse.urlparse(self.path)
        qs = urllib.parse.parse_qs(parsed.query)
        
        # Simple HTML page with links
        if parsed.path == "/":
            self.send_response(200)
            self.send_header("Content-Type", "text/html")
            self.end_headers()
            self.wfile.write(b"""
            <html><body>
                <a href="/profile?user=123">Profile</a>
                <a href="/search?q=test">Search</a>
            </body></html>
            """)
        elif parsed.path == "/search":
            self.send_response(200)
            self.send_header("Content-Type", "text/html")
            self.end_headers()
            
            # Very basic reflection vulnerability
            q = qs.get("q", [""])[0]
            if "sntnl_rflct_" in q:
                # Vulnerable!
                self.wfile.write(f"<html><body>You searched for {q}</body></html>".encode())
            else:
                self.wfile.write(b"<html><body>Search results</body></html>")
        elif parsed.path == "/profile":
            self.send_response(200)
            self.send_header("Content-Type", "text/html")
            self.end_headers()
            self.wfile.write(b"<html><body>User profile</body></html>")
        else:
            self.send_response(404)
            self.end_headers()

def run_server():
    server = HTTPServer(("localhost", 8081), DummyHandler)
    server.serve_forever()

if __name__ == "__main__":
    run_server()
