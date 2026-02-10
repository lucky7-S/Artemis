#!/usr/bin/env python3
"""
TLS Mesh Server - Receives peer data from parent, returns commands.

Usage: python tls_server.py [-i IP] [-p PORT]
Certs: openssl req -x509 -newkey rsa:2048 -keyout key.pem -out cert.pem -days 365 -nodes
"""

import ssl, socket, json, time, sys

# --- Configuration ---
HOST = '0.0.0.0'
PORT = 4433
MESSAGE_FILE = 'server_message.txt'
STATE_FILE = 'server_state.json'

# Parse args: -i IP, -p PORT
i = 1
while i < len(sys.argv):
    if sys.argv[i] in ('-i', '--ip') and i + 1 < len(sys.argv):
        HOST = sys.argv[i + 1]; i += 2
    elif sys.argv[i] in ('-p', '--port') and i + 1 < len(sys.argv):
        PORT = int(sys.argv[i + 1]); i += 2
    else:
        i += 1

# --- State ---
peer_table = {}   # {ip: {timestamp, hostname, os}}
parent_ip = None
last_contact = 0
last_result = {}  # {cmd, output, timestamp}

def save_state():
    """Save state to JSON for web interface."""
    try:
        with open(STATE_FILE, 'w') as f:
            json.dump({
                'peers': peer_table,
                'parent_ip': parent_ip,
                'last_contact': last_contact,
                'last_result': last_result
            }, f)
    except: pass

def get_message():
    """Read command message from file."""
    try:
        with open(MESSAGE_FILE, 'r') as f:
            return f.read().strip() or "No commands"
    except:
        return "No commands"

# --- TLS Setup ---
sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
sock.bind((HOST, PORT))
sock.listen(5)

context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
context.load_cert_chain('cert.pem', 'key.pem')

print(f"[*] TLS Server on {HOST}:{PORT}")

# --- Main Loop ---
try:
    while True:
        client_sock, addr = sock.accept()
        print(f"\n[+] {addr[0]}")

        try:
            ssl_sock = context.wrap_socket(client_sock, server_side=True)

            while True:
                data = ssl_sock.recv(4096)
                if not data: break

                # Parse HTTP request line
                request = data.decode('utf-8')
                parts = request.split(' ')
                method = parts[0]
                path = parts[1] if len(parts) > 1 else '/'

                if method == 'POST' and 'result' in path:
                    # Receive command output from parent
                    body = request.split('\r\n\r\n', 1)[-1]
                    try:
                        result = json.loads(body)
                        last_result = {
                            'cmd': result.get('cmd', ''),
                            'output': result.get('output', ''),
                            'timestamp': int(time.time())
                        }
                        print(f"\n{'='*50}")
                        print(f"  CMD: {last_result['cmd']}")
                        print(f"  OUT: {last_result['output']}")
                        print(f"{'='*50}")
                    except: pass

                    save_state()
                    body = json.dumps({'received': True})

                elif method == 'POST':
                    # Receive peer table from parent
                    parent_ip = addr[0]
                    last_contact = int(time.time())

                    body = request.split('\r\n\r\n', 1)[-1]
                    try:
                        for client in json.loads(body).get('clients', []):
                            peer_table[client['ip']] = {
                                'timestamp': client.get('timestamp', int(time.time())),
                                'hostname': client.get('hostname', 'unknown'),
                                'os': client.get('os', 'unknown')
                            }
                        print(f"    Peers: {list(peer_table.keys())}")
                    except: pass

                    save_state()
                    body = json.dumps({'received': True})

                elif method == 'GET':
                    # Return command message
                    msg = get_message()
                    body = json.dumps({'message': msg}, separators=(',', ':'))
                    print(f"    Message: {msg}")

                else:
                    body = '{}'

                # Send response
                response = f"HTTP/1.1 200 OK\r\nContent-Length: {len(body)}\r\nConnection: keep-alive\r\n\r\n{body}"
                ssl_sock.send(response.encode())

            ssl_sock.close()

        except (ssl.SSLError, ConnectionResetError) as e:
            print(f"[!] {e}")

except KeyboardInterrupt:
    print("\n[*] Shutdown")
finally:
    sock.close()
