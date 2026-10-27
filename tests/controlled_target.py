"""
Leadline - Controlled Test Target Server

A deterministic local HTTP server for testing the recon engine.
Exposes controlled routes, headers, JavaScript, and parameters.
"""
from http.server import HTTPServer, SimpleHTTPRequestHandler
import json

class ControlledTargetHandler(SimpleHTTPRequestHandler):
    """HTTP handler for controlled test target."""

    # Controlled HTML responses with links, forms, and parameters
    HTML_INDEX = """
    <!DOCTYPE html>
    <html>
    <head>
        <title>Controlled Test Target</title>
        <script src="/static/app.js"></script>
        <script src="/static/utils.js"></script>
    </head>
    <body>
        <h1>Controlled Test Target</h1>
        <nav>
            <a href="/login">Login</a>
            <a href="/admin">Admin Panel</a>
            <a href="/api/users">API Users</a>
            <a href="/api/orders">API Orders</a>
            <a href="/debug">Debug Interface</a>
        </nav>
        <form action="/search" method="GET">
            <input name="q" placeholder="Search query">
            <input name="page" value="1">
            <button type="submit">Search</button>
        </form>
        <form action="/api/data" method="POST">
            <input name="id" value="123">
            <input name="action" value="fetch">
        </form>
        <a href="/users?id=456&sort=name">Users List</a>
        <a href="/api/items?category=electronics&limit=10">Items API</a>
    </body>
    </html>
    """

    JS_APP = """
    // Main application JavaScript
    const API_BASE = '/api';
    const ENDPOINTS = {
        users: '/api/users',
        orders: '/api/orders',
        products: '/api/products',
        settings: '/api/settings'
    };

    function fetchUsers(userId) {
        return fetch(`${API_BASE}/users/${userId}?include=profile`);
    }

    function fetchOrders(orderId, status) {
        return fetch(`${API_BASE}/orders/${orderId}?status=${status}`);
    }

    // Debug endpoint reference
    const DEBUG_URL = '/debug/trace';
    """

    JS_UTILS = """
    // Utility functions
    const Utils = {
        apiUrl: (path) => `/api${path}`,
        params: {
            filter: 'active',
            sort: 'created_at',
            limit: 50
        }
    };

    // Admin panel reference
    const ADMIN_PATH = '/admin/config';
    """

    def do_GET(self):
        """Handle GET requests with controlled responses."""
        # Add security headers to all responses
        self.send_response(200)

        if self.path == '/':
            self.send_header('Content-Type', 'text/html; charset=utf-8')
            self.send_header('X-Powered-By', 'TestServer/1.0')
            self.send_header('X-Frame-Options', 'DENY')
            # Intentionally missing some security headers for testing
            self.end_headers()
            self.wfile.write(self.HTML_INDEX.encode())

        elif self.path == '/login':
            self.send_header('Content-Type', 'text/html')
            self.end_headers()
            html = """
            <html><head><title>Login</title></head>
            <body>
                <h1>Login Page</h1>
                <form method="POST" action="/auth">
                    <input name="username" placeholder="Username">
                    <input name="password" type="password">
                    <input type="hidden" name="csrf_token" value="abc123">
                </form>
            </body></html>
            """
            self.wfile.write(html.encode())

        elif self.path == '/admin':
            self.send_header('Content-Type', 'text/html')
            self.end_headers()
            html = """
            <html><head><title>Admin Panel</title></head>
            <body>
                <h1>Admin Panel</h1>
                <p>Restricted area</p>
                <a href="/admin/users">Manage Users</a>
                <a href="/admin/config">Configuration</a>
                <a href="/debug/logs">View Logs</a>
            </body></html>
            """
            self.wfile.write(html.encode())

        elif self.path.startswith('/api/') or self.path.startswith('/static/'):
            if self.path.endswith('.js'):
                self.send_header('Content-Type', 'application/javascript')
                if '/app.js' in self.path:
                    self.end_headers()
                    self.wfile.write(self.JS_APP.encode())
                elif '/utils.js' in self.path:
                    self.end_headers()
                    self.wfile.write(self.JS_UTILS.encode())
                else:
                    self.end_headers()
                    self.wfile.write(b'// Empty JS file')
            else:
                self.send_header('Content-Type', 'application/json')
                self.end_headers()
                response = {"status": "ok", "endpoint": self.path}
                self.wfile.write(json.dumps(response).encode())

        elif self.path == '/debug':
            self.send_header('Content-Type', 'text/html')
            # Missing security headers intentionally
            self.end_headers()
            html = """
            <html><head><title>Debug Interface</title></head>
            <body>
                <h1>Debug Interface - EXPOSED</h1>
                <p>This debug interface should not be publicly accessible.</p>
                <a href="/debug/trace">Trace</a>
                <a href="/debug/logs">Logs</a>
                <form action="/debug/exec">
                    <input name="cmd" placeholder="Command">
                </form>
            </body></html>
            """
            self.wfile.write(html.encode())

        else:
            self.send_header('Content-Type', 'text/html')
            self.end_headers()
            self.wfile.write(f'<html><body><h1>404 - {self.path}</h1></body></html>'.encode())

    def do_POST(self):
        """Handle POST requests."""
        self.send_response(200)
        self.send_header('Content-Type', 'application/json')
        self.end_headers()
        response = {"status": "received", "method": "POST", "path": self.path}
        self.wfile.write(json.dumps(response).encode())

    def log_message(self, format, *args):
        """Suppress logging for cleaner test output."""
        pass


def run_server(port=8765):
    """Run the controlled test server."""
    server = HTTPServer(('127.0.0.1', port), ControlledTargetHandler)
    print(f"Controlled test target running at http://127.0.0.1:{port}")
    print("Exposed routes:")
    print("  / - Index with links")
    print("  /login - Login form")
    print("  /admin - Admin panel")
    print("  /api/* - API endpoints")
    print("  /static/*.js - JavaScript files")
    print("  /debug - Debug interface (intentionally exposed)")
    server.serve_forever()


if __name__ == '__main__':
    run_server()
