#!/usr/bin/env python3
"""
Web Interface for TLS Mesh Server - Monitor peers and send commands.
Usage: python web_interface.py [port]
"""

import http.server, json, sys
from datetime import datetime
from urllib.parse import parse_qs

STATE_FILE = 'server_state.json'
MESSAGE_FILE = 'server_message.txt'
PORT = int(sys.argv[1]) if len(sys.argv) > 1 else 8080

HTML = '''<!DOCTYPE html>
<html>
<head>
    <title>Mesh Control</title>
    <meta http-equiv="refresh" content="5">
    <style>
        body {{ font-family: monospace; background: #1a1a1a; color: #0f0; padding: 20px; }}
        table {{ border-collapse: collapse; margin: 20px 0; }}
        th, td {{ border: 1px solid #0f0; padding: 8px 16px; }}
        th {{ background: #0f0; color: #1a1a1a; }}
        input {{ width: 400px; padding: 8px; background: #333; color: #0f0; border: 1px solid #0f0; }}
        button {{ padding: 8px 16px; background: #0f0; color: #1a1a1a; border: none; cursor: pointer; }}
        .status {{ padding: 10px; margin: 10px 0; background: #333; }}
        .diagram {{ background: #222; padding: 20px; margin: 20px 0; text-align: center; }}
        .node {{ display: inline-block; border: 2px solid #0f0; padding: 8px 16px; margin: 5px; }}
        .server {{ border-color: #0ff; color: #0ff; }}
        .win {{ border-color: #0af; color: #0af; font-size: 12px; }}
        .lin {{ border-color: #f80; color: #f80; font-size: 12px; }}
        .line {{ color: #555; }}
    </style>
</head>
<body>
    <h1>MESH CONTROL</h1>

    <!-- Status -->
    <div class="status">
        <b>Parent:</b> {parent_ip} | <b>Last Contact:</b> {parent_time} | <b>Peers:</b> {peer_count}
    </div>

    <!-- Network Diagram -->
    <div class="diagram">
        <div class="node server">SERVER</div>
        <div class="line">|</div>
        <div class="node">{parent_ip}</div>
        {child_diagram}
        <div style="margin-top:10px; font-size:11px; color:#666;">
            <span style="color:#0af;">[W] Windows</span>
            <span style="color:#f80;">[L] Linux</span>
        </div>
    </div>

    <!-- Peer Table -->
    <table>
        <tr><th>IP</th><th>Hostname</th><th>OS</th><th>Last Seen</th></tr>
        {peer_rows}
    </table>

    <!-- Message Form -->
    <h3>Command</h3>
    <form method="POST">
        <input name="message" value="{message}" />
        <button type="submit">Send</button>
    </form>

    <!-- Last Result -->
    <h3>Last Result</h3>
    <div class="status">
        <b>Cmd:</b> {last_cmd}<br>
        <b>Output:</b> {last_output}
    </div>
</body>
</html>'''

class Handler(http.server.BaseHTTPRequestHandler):
    def log_message(self, *args): pass

    def do_GET(self):
        self.send_response(200)
        self.send_header('Content-type', 'text/html')
        self.end_headers()
        self.wfile.write(self.render().encode())

    def do_POST(self):
        data = self.rfile.read(int(self.headers.get('Content-Length', 0))).decode()
        params = parse_qs(data)
        if 'message' in params:
            open(MESSAGE_FILE, 'w').write(params['message'][0])
        self.send_response(303)
        self.send_header('Location', '/')
        self.end_headers()

    def render(self):
        # Load state
        try:
            state = json.load(open(STATE_FILE))
        except:
            state = {'peers': {}, 'parent_ip': 'None', 'last_contact': 0}

        # Load message
        try:
            message = open(MESSAGE_FILE).read().strip() or "No commands"
        except:
            message = "No commands"

        peers = state.get('peers', {})
        parent_ip = state.get('parent_ip', 'None')
        last_contact = state.get('last_contact', 0)
        parent_time = datetime.fromtimestamp(last_contact).strftime('%H:%M:%S') if last_contact else 'Never'

        # Build peer table rows
        rows = ""
        for ip, data in peers.items():
            ts = data.get('timestamp', 0)
            time_str = datetime.fromtimestamp(ts).strftime('%H:%M:%S') if ts else '-'
            rows += f"<tr><td>{ip}</td><td>{data.get('hostname', '?')}</td><td>{data.get('os', '?')}</td><td>{time_str}</td></tr>"
        if not rows:
            rows = "<tr><td colspan='4'>No peers</td></tr>"

        # Build diagram
        child_diagram = ""
        if peers:
            child_diagram = '<div class="line">' + ' | ' * len(peers) + '</div><div>'
            for ip, data in peers.items():
                os_class = 'win' if 'windows' in data.get('os', '').lower() else 'lin'
                label = 'W' if os_class == 'win' else 'L'
                child_diagram += f'<span class="node {os_class}">[{label}] {ip}</span>'
            child_diagram += '</div>'

        # Last command result
        result = state.get('last_result', {})
        last_cmd = result.get('cmd', '-')
        last_output = result.get('output', '-')

        return HTML.format(
            parent_ip=parent_ip, parent_time=parent_time, peer_count=len(peers),
            peer_rows=rows, message=message, child_diagram=child_diagram,
            last_cmd=last_cmd, last_output=last_output
        )

print(f"[*] Web interface on http://localhost:{PORT}")
http.server.HTTPServer(('', PORT), Handler).serve_forever()
