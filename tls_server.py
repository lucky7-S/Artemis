#!/usr/bin/env python3
"""
TLS Mesh Server
===============
Receives peer table from parent node via POST, returns configurable message via GET.

Usage:
    python tls_server.py [options]

Options:
    -i, --ip <addr>     IP to bind to (default: 0.0.0.0)
    -p, --port <num>    Port to listen on (default: 4433)

Certificate generation:
    openssl req -x509 -newkey rsa:2048 -keyout key.pem -out cert.pem \
        -days 365 -nodes -subj "/CN=localhost"

To change the message returned to clients:
    echo "your command here" > server_message.txt
"""

import ssl
import socket
import json
import time
import sys

# =============================================================================
# CONFIGURATION
# =============================================================================

HOST = '0.0.0.0'        # IP to bind to ('0.0.0.0' for all interfaces)
PORT = 4433             # Port to listen on
MESSAGE_FILE = 'server_message.txt'  # File containing message for clients

# Parse command line arguments
i = 1
while i < len(sys.argv):
    arg = sys.argv[i]
    if arg in ('-i', '--ip') and i + 1 < len(sys.argv):
        HOST = sys.argv[i + 1]
        i += 2
    elif arg in ('-p', '--port') and i + 1 < len(sys.argv):
        PORT = int(sys.argv[i + 1])
        i += 2
    elif arg in ('-h', '--help'):
        print(__doc__)
        sys.exit(0)
    else:
        i += 1

# =============================================================================
# STATE
# =============================================================================

peer_table = {}  # Master peer table: {ip: {"timestamp": ..., "active": True}}

def get_message():
    """Read message from file, or return default if file doesn't exist."""
    try:
        with open(MESSAGE_FILE, 'r') as f:
            msg = f.read().strip()
            return msg if msg else "No commands"
    except:
        return "No commands"

# =============================================================================
# TLS SETUP
# =============================================================================

# Create TCP socket with address reuse (avoids "address in use" on restart)
sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
sock.bind((HOST, PORT))
sock.listen(5)

# Create TLS context and load certificates
context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
context.load_cert_chain('cert.pem', 'key.pem')

# SNI callback - captures the hostname client requested (for logging)
def sni_callback(ssl_sock, server_name, ssl_context):
    ssl_sock.sni = server_name
    return None

context.sni_callback = sni_callback

# =============================================================================
# MAIN SERVER LOOP
# =============================================================================

print("=" * 50)
print("  TLS MESH SERVER")
print("=" * 50)
print(f"Listening: {HOST}:{PORT}")
print(f"Message:   {get_message()}")
print(f"Change:    echo 'cmd' > {MESSAGE_FILE}")
print("=" * 50)

try:
    while True:
        # Accept incoming TCP connection
        client_sock, addr = sock.accept()
        print(f"\n[+] Connection from {addr}")

        try:
            # Wrap with TLS (performs handshake)
            ssl_sock = context.wrap_socket(client_sock, server_side=True)
            sni = getattr(ssl_sock, 'sni', None)
            print(f"    SNI: {sni}")

            # Handle HTTP requests until client disconnects
            while True:
                data = ssl_sock.recv(4096)
                if not data:
                    break

                # Parse HTTP request
                request = data.decode('utf-8')
                lines = request.split('\r\n')
                parts = lines[0].split(' ') if lines else []
                method = parts[0] if len(parts) > 0 else 'UNKNOWN'
                path = parts[1] if len(parts) > 1 else '/'

                print(f"    {method} {path}")

                # Handle POST - receive peer table from parent
                if method == 'POST':
                    body_start = request.find('\r\n\r\n')
                    if body_start != -1:
                        body = request[body_start + 4:]
                        try:
                            data = json.loads(body)
                            # Update peer table with received client data
                            if 'clients' in data:
                                for client in data['clients']:
                                    ip = client.get('ip', 'unknown')
                                    ts = client.get('timestamp', int(time.time()))
                                    peer_table[ip] = {"timestamp": ts, "active": True}
                                print(f"    Peers: {list(peer_table.keys())}")
                        except json.JSONDecodeError:
                            pass

                    response_body = json.dumps({
                        "received": True,
                        "peers_count": len(peer_table)
                    })

                # Handle GET - return configurable message
                elif method == 'GET':
                    msg = get_message()
                    response_body = json.dumps({"message": msg})
                    print(f"    Message: {msg}")

                else:
                    response_body = json.dumps({"error": "Unknown method"})

                # Send HTTP response
                response = (
                    f"HTTP/1.1 200 OK\r\n"
                    f"Content-Type: application/json\r\n"
                    f"Content-Length: {len(response_body)}\r\n"
                    f"Connection: keep-alive\r\n"
                    f"\r\n"
                    f"{response_body}"
                )
                ssl_sock.send(response.encode())

            print(f"[-] Client {addr} disconnected")
            ssl_sock.close()

        except ssl.SSLError as e:
            print(f"[!] TLS error: {e}")
        except ConnectionResetError:
            print(f"[!] Client {addr} reset connection")

except KeyboardInterrupt:
    print("\n[*] Shutting down...")

finally:
    sock.close()
