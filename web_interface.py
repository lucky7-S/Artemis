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

# Track previous timestamps to calculate intervals
previous_timestamps = {}
previous_parent_contact = 0

HTML_TEMPLATE = '''<!DOCTYPE html>
<html>
<head>
    <title>Mesh Server Control</title>
    <meta http-equiv="refresh" content="5">
    <style>
        body {{ font-family: monospace; background: #1a1a1a; color: #0f0; padding: 20px; }}
        h1 {{ color: #0f0; }}
        table {{ border-collapse: collapse; margin: 20px 0; }}
        th, td {{ border: 1px solid #0f0; padding: 8px 16px; text-align: left; }}
        th {{ background: #0f0; color: #1a1a1a; }}
        input[type=text] {{ width: 400px; padding: 8px; font-family: monospace;
                          background: #333; color: #0f0; border: 1px solid #0f0; }}
        button {{ padding: 8px 16px; background: #0f0; color: #1a1a1a;
                border: none; cursor: pointer; font-family: monospace; }}
        button:hover {{ background: #0a0; }}
        .status {{ padding: 10px; margin: 10px 0; background: #333; }}
        .diagram {{ background: #222; padding: 20px; margin: 20px 0; text-align: center; }}
        .node {{ display: inline-block; border: 2px solid #0f0; padding: 8px 16px; margin: 5px; }}
        .server {{ border-color: #0ff; color: #0ff; }}
        .parent {{ border-color: #0f0; }}
        .child {{ font-size: 12px; }}
        .windows {{ border-color: #0af; color: #0af; }}
        .linux {{ border-color: #f80; color: #f80; }}
        .line {{ color: #555; }}
    </style>
</head>
<body>
    <h1>MESH SERVER CONTROL</h1>

    <div class="status">
        <strong>Parent IP:</strong> {parent_ip}<br>
        <strong>Last Contact:</strong> {parent_time}<br>
        <strong>Total Peers:</strong> {peer_count}
    </div>

    <h2>Network Topology</h2>
    <div class="diagram">
        <div class="node server">SERVER</div>
        <div class="line">| https: {https_interval}</div>
        <div class="node parent">{parent_ip}</div>
        {child_diagram}
        <div style="margin-top:15px; font-size:11px; color:#666;">
            <span style="color:#0af;">[W] Windows</span> &nbsp;
            <span style="color:#f80;">[L] Linux</span>
        </div>
    </div>

    <h2>Peer Table</h2>
    <table>
        <tr><th>IP Address</th><th>Hostname</th><th>OS</th><th>Last Seen</th><th>Interval</th></tr>
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

        # Build peer rows and calculate intervals
        from datetime import datetime
        global previous_timestamps, previous_parent_contact
        peers = state.get('peers', {})
        rows = ""
        intervals = {}  # Store intervals for diagram use

        for ip, data in peers.items():
            ts = data.get('timestamp', 0)
            hostname = data.get('hostname', 'unknown')
            os_info = data.get('os', 'unknown')
            time_str = datetime.fromtimestamp(ts).strftime('%Y-%m-%d %H:%M:%S') if ts else 'Never'

            # Calculate interval from previous timestamp
            interval_str = "-"
            if ip in previous_timestamps and ts > 0:
                interval = ts - previous_timestamps[ip]
                if interval > 0:
                    interval_str = f"{interval}s"
                    intervals[ip] = interval_str

            # Store current timestamp for next calculation
            if ts > 0:
                previous_timestamps[ip] = ts

            rows += f"<tr><td>{ip}</td><td>{hostname}</td><td>{os_info}</td><td>{time_str}</td><td>{interval_str}</td></tr>\n"

        if not rows:
            rows = "<tr><td colspan='5'>No peers connected</td></tr>"

        # Parent info and HTTPS interval
        parent_ip = state.get('parent_ip', 'None')
        last_contact = state.get('last_contact', 0)
        parent_time = datetime.fromtimestamp(last_contact).strftime('%Y-%m-%d %H:%M:%S') if last_contact else 'Never'

        # Calculate HTTPS interval for parent
        https_interval = "-"
        if previous_parent_contact > 0 and last_contact > 0:
            interval = last_contact - previous_parent_contact
            if interval > 0:
                https_interval = f"{interval}s"
        if last_contact > 0:
            previous_parent_contact = last_contact

        # Build child diagram with UDP intervals
        child_diagram = ""
        if peers:
            child_diagram = '<div class="line">'
            for ip in peers:
                udp_int = intervals.get(ip, '-')
                child_diagram += f" udp:{udp_int} "
            child_diagram += '</div><div>'
            for ip, data in peers.items():
                os_info = data.get('os', '').lower()
                if 'windows' in os_info:
                    os_class = 'windows'
                    os_label = 'W'
                else:
                    os_class = 'linux'
                    os_label = 'L'
                child_diagram += f'<span class="node child {os_class}">[{os_label}] {ip}</span>'
            child_diagram += '</div>'

        return HTML_TEMPLATE.format(
            parent_ip=parent_ip,
            parent_time=parent_time,
            peer_count=len(peers),
            peer_rows=rows,
            current_message=message,
            child_diagram=child_diagram,
            https_interval=https_interval
        )

print(f"Web interface running on http://localhost:{PORT}")
http.server.HTTPServer(('', PORT), Handler).serve_forever()
