"""Local test HTTP server for safe ZeroTrace testing."""

from http.server import HTTPServer, BaseHTTPRequestHandler
import threading
import json


class SecureTestHandler(BaseHTTPRequestHandler):
    """HTTP handler that returns various security header configurations for testing."""
    
    # Class-level config for different test scenarios
    response_headers = {
        "Content-Type": "text/html",
        "X-Frame-Options": "DENY",
        "X-Content-Type-Options": "nosniff",
        "Strict-Transport-Security": "max-age=31536000; includeSubDomains",
        "Content-Security-Policy": "default-src 'self'",
        "Referrer-Policy": "strict-origin-when-cross-origin",
        "Permissions-Policy": "camera=(), microphone=(), geolocation=()",
    }
    
    body = b"""<!DOCTYPE html>
<html>
<head><title>Test Server</title></head>
<body>
    <h1>Safe Local Test Target</h1>
    <p>This is a test server for ZeroTrace scanning.</p>
    <img src="/favicon.ico" alt="test">
</body>
</html>"""
    
    def do_GET(self):
        """Handle GET requests."""
        if self.path == "/robots.txt":
            self.send_response(200)
            self.send_header("Content-Type", "text/plain")
            self.end_headers()
            self.wfile.write(b"User-agent: *\nDisallow: /admin/")
        elif self.path == "/security.txt":
            self.send_response(200)
            self.send_header("Content-Type", "text/plain")
            self.end_headers()
            self.wfile.write(b"Contact: security@example.com\n")
        elif self.path == "/favicon.ico":
            self.send_response(204)  # No content
            self.end_headers()
        else:
            self.send_response(200)
            for header, value in self.response_headers.items():
                self.send_header(header, value)
            self.end_headers()
            self.wfile.write(self.body)
    
    def log_message(self, format, *args):
        """Suppress log output."""
        pass


class WeakSecurityHandler(BaseHTTPRequestHandler):
    """Handler with weak security headers for testing detection."""
    
    response_headers = {
        "Content-Type": "text/html",
        "Server": "Apache/2.4.52",
        "X-Powered-By": "PHP/8.1.12",
    }
    
    body = b"""<!DOCTYPE html>
<html>
<head><title>Weak Security Test</title></head>
<body>
    <h1>Intentionally Weak Configuration</h1>
    <p>This server has missing security headers for testing.</p>
</body>
</html>"""
    
    def do_GET(self):
        """Handle GET requests."""
        self.send_response(200)
        for header, value in self.response_headers.items():
            self.send_header(header, value)
        self.end_headers()
        self.wfile.write(self.body)
    
    def log_message(self, format, *args):
        """Suppress log output."""
        pass


class ReuseHTTPServer(HTTPServer):
    """HTTPServer with SO_REUSEADDR enabled for quick port recycling."""
    allow_reuse_address = True


def start_test_server(port=8080, secure=True):
    """Start a test HTTP server in a background thread.
    
    Args:
        port: Port to run the server on (default: 8080)
        secure: If True, use secure headers; otherwise use weak headers
    
    Returns:
        Tuple of (server_thread, server)
    """
    handler = SecureTestHandler if secure else WeakSecurityHandler
    server = ReuseHTTPServer(("127.0.0.1", port), handler)
    thread = threading.Thread(target=server.serve_forever, daemon=False)
    thread.start()
    return thread, server


if __name__ == "__main__":
    import sys
    
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 8080
    secure = "--weak" not in sys.argv
    
    print(f"Starting {'secure' if secure else 'weak'} test server on port {port}...")
    thread, server = start_test_server(port, secure)
    print(f"Test server running at http://127.0.0.1:{port}")
    print("Press Ctrl+C to stop")
    
    try:
        while True:
            import time
            time.sleep(1)
    except KeyboardInterrupt:
        print("\nStopping test server...")
        server.shutdown()