#!/usr/bin/env python3
"""
Simple Web Interface for TLS Mesh Server
=========================================
Run alongside tls_server.py to monitor and control the mesh.

Usage: python web_interface.py [port]
Default port: 8080
"""

import http.server
import json
import os
import sys
from urllib.parse import parse_qs

STATE_FILE = 'server_state.json'
MESSAGE_FILE = 'server_message.txt'
PORT = int(sys.argv[1]) if len(sys.argv) > 1 else 8080

HTML = '''<!DOCTYPE html>
<html>
<head>
    <title>Mesh Server Control</title>
    <meta http-equiv="refresh" content="5">
    <style>
        body { font-family: monospace; background: #1a1a1a; color: #0f0; padding: 20px; }
        h1 { color: #0f0; }
        table { border-collapse: collapse; margin: 20px 0; }
        th, td { border: 1px solid #0f0; padding: 8px 16px; text-align: left; }
        th { background: #0f0; color: #1a1a1a; }
        input[type=text] { width: 400px; padding: 8px; font-family: monospace;
                          background: #333; color: #0f0; border: 1px solid #0f0; }
        button { padding: 8px 16px; background: #0f0; color: #1a1a1a;
                border: none; cursor: pointer; font-family: monospace; }
        button:hover { background: #0a0; }
        .status { padding: 10px; margin: 10px 0; background: #333; }
    </style>
</head>
<body>
    <h1>MESH SERVER CONTROL</h1>

    <div class="status">
        <strong>Parent IP:</strong> {parent_ip}<br>
        <strong>Last Contact:</strong> {parent_time}<br>
        <strong>Total Peers:</strong> {peer_count}
    </div>

    <h2>Peer Table</h2>
    <table>
        <tr><th>IP Address</th><th>Last Seen</th></tr>
        {peer_rows}
    </table>

    <h2>Message to Parent</h2>
    <form method="POST">
        <input type="text" name="message" value="{current_message}" />
        <button type="submit">Update</button>
    </form>

    <p style="color:#666; margin-top:40px;">Auto-refresh every 5 seconds</p>
</body>
</html>
'''

class Handler(http.server.BaseHTTPRequestHandler):
    def log_message(self, format, *args):
        pass  # Suppress logging

    def do_GET(self):
        self.send_response(200)
        self.send_header('Content-type', 'text/html')
        self.end_headers()
        self.wfile.write(self.render_page().encode())

    def do_POST(self):
        length = int(self.headers.get('Content-Length', 0))
        data = self.rfile.read(length).decode()
        params = parse_qs(data)

        if 'message' in params:
            with open(MESSAGE_FILE, 'w') as f:
                f.write(params['message'][0])

        self.send_response(303)
        self.send_header('Location', '/')
        self.end_headers()

    def render_page(self):
        # Load state
        state = {'peers': {}, 'parent_ip': 'None', 'last_contact': 0}
        try:
            with open(STATE_FILE, 'r') as f:
                state = json.load(f)
        except:
            pass

        # Load current message
        message = "No commands"
        try:
            with open(MESSAGE_FILE, 'r') as f:
                message = f.read().strip() or "No commands"
        except:
            pass

        # Build peer rows
        from datetime import datetime
        peers = state.get('peers', {})
        rows = ""
        for ip, data in peers.items():
            ts = data.get('timestamp', 0)
            time_str = datetime.fromtimestamp(ts).strftime('%Y-%m-%d %H:%M:%S') if ts else 'Never'
            rows += f"<tr><td>{ip}</td><td>{time_str}</td></tr>\n"

        if not rows:
            rows = "<tr><td colspan='2'>No peers connected</td></tr>"

        # Parent info
        parent_ip = state.get('parent_ip', 'None')
        last_contact = state.get('last_contact', 0)
        parent_time = datetime.fromtimestamp(last_contact).strftime('%Y-%m-%d %H:%M:%S') if last_contact else 'Never'

        return HTML.format(
            parent_ip=parent_ip,
            parent_time=parent_time,
            peer_count=len(peers),
            peer_rows=rows,
            current_message=message
        )

print(f"Web interface running on http://localhost:{PORT}")
http.server.HTTPServer(('', PORT), Handler).serve_forever()
