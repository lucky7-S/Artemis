#!/usr/bin/env python3
"""
============================================================================
TLS/HTTPS Server with HTTP Protocol Support
============================================================================

DESCRIPTION:
    A TLS server that accepts encrypted connections and handles HTTP
    requests (GET and POST). The server maintains persistent connections
    and responds with JSON data to mimic a REST API.

USAGE:
    python tls_server.py

REQUIREMENTS:
    - Python 3.6+
    - OpenSSL certificates (cert.pem, key.pem)

CERTIFICATE GENERATION:
    To generate a self-signed certificate for testing:

    openssl req -x509 -newkey rsa:2048 -keyout key.pem -out cert.pem \
        -days 365 -nodes -subj "/CN=localhost"

CONFIGURATION:
    HOST - IP address to bind to (default: 127.0.0.1)
    PORT - Port number to listen on (default: 4433)

TRAFFIC CHARACTERISTICS:
    - Accepts TLS 1.2 and 1.3 connections
    - Captures SNI (Server Name Indication) from clients
    - Handles HTTP GET and POST requests
    - Returns JSON responses
    - Supports persistent connections (Connection: keep-alive)

============================================================================
"""

import ssl      # Python's SSL/TLS wrapper for secure socket communication
import socket   # Low-level networking interface (TCP/UDP sockets)
import sys      # System-specific parameters (unused but available for extensions)
import json     # JSON parsing for extracting client_ip from POST body
import time     # For timestamps in peer table

# ==============================================================================
# MESH NETWORK STATE
# ==============================================================================
#
# The server maintains state about the mesh network:
#   - is_parent_assigned: Whether we've assigned a parent node
#   - peer_table: Master list of all peers (parent + children)

is_parent_assigned = False
peer_table = {}  # {ip: {"timestamp": ..., "active": True}}

# ==============================================================================
# SERVER CONFIGURATION
# ==============================================================================
#
# HOST: The IP address to bind the server to.
#   - '127.0.0.1' (localhost) - Only accept connections from this machine
#   - '0.0.0.0' - Accept connections from any network interface
#
# PORT: The port number to listen on.
#   - 443 is the standard HTTPS port (requires root/admin privileges)
#   - 4433 is commonly used for testing (no special privileges needed)
#   - Ports below 1024 are "privileged" on Unix systems

HOST = '127.0.0.8'
PORT = 4433

# ==============================================================================
# STEP 1: CREATE TCP SOCKET
# ==============================================================================
#
# Before we can do TLS, we need a TCP socket. The socket is the low-level
# endpoint for network communication.
#
# socket.socket() creates a new socket:
#   socket.AF_INET    - Use IPv4 addressing
#   socket.SOCK_STREAM - Use TCP (reliable, connection-oriented)
#
# For IPv6, you would use socket.AF_INET6 instead.

sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

# ==============================================================================
# STEP 2: CONFIGURE SOCKET OPTIONS
# ==============================================================================
#
# SO_REUSEADDR allows the socket to bind to an address that's in TIME_WAIT state.
#
# WHY THIS IS NEEDED:
#   When a TCP connection closes, the port enters TIME_WAIT state for ~60 seconds
#   to ensure all packets are delivered. Without SO_REUSEADDR, you'd get
#   "Address already in use" errors when restarting the server quickly.
#
# Parameters:
#   socket.SOL_SOCKET - Set option at the socket level
#   socket.SO_REUSEADDR - The specific option to set
#   1 - Enable the option (0 would disable)

sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

# ==============================================================================
# STEP 3: BIND SOCKET TO ADDRESS
# ==============================================================================
#
# bind() associates the socket with a specific IP address and port.
# After binding, this socket "owns" that address - no other process can use it.
#
# The argument is a tuple: (host, port)
#
# Common errors:
#   - "Address already in use" - Another process is using this port
#   - "Permission denied" - Need root/admin for ports < 1024

sock.bind((HOST, PORT))

# ==============================================================================
# STEP 4: START LISTENING FOR CONNECTIONS
# ==============================================================================
#
# listen() marks the socket as a "server socket" that will accept connections.
#
# The argument (5) is the "backlog" - the maximum number of pending connections
# waiting to be accepted. If more clients try to connect while the backlog is
# full, they'll receive "Connection refused" errors.
#
# After listen(), we can call accept() to receive incoming connections.

sock.listen(5)

# ==============================================================================
# STEP 5: CREATE TLS CONTEXT
# ==============================================================================
#
# ssl.SSLContext is the configuration object for TLS connections.
# It holds settings that are shared across all connections:
#   - Protocol version (TLS 1.2, 1.3, etc.)
#   - Certificate and private key
#   - Verification settings
#   - Cipher suite preferences
#
# PROTOCOL_TLS_SERVER:
#   - Indicates this is a server-side context
#   - Supports TLS 1.2 and 1.3 (negotiated with client)
#   - For clients, use PROTOCOL_TLS_CLIENT instead

context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)

# ==============================================================================
# STEP 6: LOAD CERTIFICATE AND PRIVATE KEY
# ==============================================================================
#
# load_cert_chain() loads the server's certificate and private key.
#
# Certificate (cert.pem):
#   - The server's X.509 certificate
#   - Contains the server's public key
#   - Sent to clients during the TLS handshake
#   - Clients use this to verify the server's identity
#
# Private Key (key.pem):
#   - The server's private key (KEEP THIS SECRET!)
#   - Used to decrypt data encrypted with the public key
#   - Used to sign data to prove the server's identity
#
# For production, you would use a certificate signed by a trusted CA.
# For testing, a self-signed certificate works fine.
#
# Common errors:
#   - "No such file or directory" - Certificate files not found
#   - "PEM routines" - Certificate/key format is invalid
#   - "key values mismatch" - Certificate and key don't match

context.load_cert_chain('cert.pem', 'key.pem')

# ==============================================================================
# STEP 7: CONFIGURE SNI CALLBACK
# ==============================================================================
#
# SNI (Server Name Indication) is a TLS extension that allows clients to
# specify which hostname they want to connect to. This is useful when one
# IP address hosts multiple HTTPS websites.
#
# The SNI callback is called during the TLS handshake, BEFORE encryption
# begins. It receives:
#   ssl_sock    - The SSL socket object (partially initialized)
#   server_name - The hostname the client requested (e.g., "www.example.com")
#   ssl_context - The SSL context
#
# The callback can:
#   - Return None to use the default context/certificate
#   - Return a different SSLContext to use a different certificate
#   - Raise an exception to abort the connection
#
# In our case, we capture the SNI for logging but always use the same
# certificate regardless of what hostname the client requests.

def sni_callback(ssl_sock, server_name, ssl_context):
    """
    SNI (Server Name Indication) callback function.

    This function is called during the TLS handshake when the client
    sends the SNI extension. We store the requested hostname on the
    socket object for later access, but always return None to use
    the default certificate.

    Args:
        ssl_sock: The SSL socket being set up
        server_name: The hostname the client requested (e.g., "www.microsoft.com")
        ssl_context: The SSL context being used

    Returns:
        None - Use the default context and certificate

    Note:
        In a production server hosting multiple domains, you would:
        1. Look up the certificate for server_name
        2. Create/retrieve an SSLContext with that certificate
        3. Return that context
    """
    # Store the SNI value on the socket so we can access it later
    # We use a custom attribute 'sni' since server_hostname doesn't
    # get populated automatically on the server side
    ssl_sock.sni = server_name

    # Return None to use the default context (our single certificate)
    # If we had multiple certificates, we could return a different
    # SSLContext here based on the server_name
    return None

# Register the SNI callback with the SSL context
# This callback will be invoked for every incoming TLS connection
context.sni_callback = sni_callback

# ==============================================================================
# STEP 8: START SERVER
# ==============================================================================

print("=" * 60, flush=True)
print("  TLS MESH SERVER v2.0 - WITH PARENT ASSIGNMENT", flush=True)
print("=" * 60, flush=True)
print(f"Server listening on {HOST}:{PORT}", flush=True)
print(f"Parent assigned: {is_parent_assigned}", flush=True)
print("Press Ctrl+C to stop", flush=True)
print("=" * 60, flush=True)

# ==============================================================================
# STEP 9: MAIN SERVER LOOP
# ==============================================================================
#
# The server runs in an infinite loop:
#   1. Wait for a client connection (accept)
#   2. Wrap the connection with TLS (wrap_socket)
#   3. Handle HTTP requests until client disconnects
#   4. Go back to step 1

try:
    while True:
        # ==================================================================
        # STEP 9a: ACCEPT INCOMING CONNECTION
        # ==================================================================
        #
        # accept() blocks until a client connects. It returns:
        #   client_sock - A new socket for communicating with this client
        #   addr - The client's address as a tuple (ip, port)
        #
        # At this point, we have a TCP connection but NO encryption yet.
        # The TCP three-way handshake (SYN, SYN-ACK, ACK) has completed.

        client_sock, addr = sock.accept()
        print(f"\nConnection from {addr}", flush=True)

        try:
            # ==============================================================
            # STEP 9b: WRAP SOCKET WITH TLS
            # ==============================================================
            #
            # wrap_socket() performs the TLS handshake and returns an
            # encrypted socket. All read/write operations on this socket
            # are automatically encrypted/decrypted.
            #
            # server_side=True indicates we're the server in this handshake.
            #
            # The TLS handshake process:
            #   1. Client sends ClientHello (supported versions, ciphers, SNI)
            #   2. Server sends ServerHello (chosen version, cipher)
            #   3. Server sends Certificate (our cert.pem)
            #   4. Server sends ServerKeyExchange (for ECDHE)
            #   5. Server sends ServerHelloDone
            #   6. Client sends ClientKeyExchange
            #   7. Both send ChangeCipherSpec
            #   8. Both send Finished (encrypted)
            #
            # After wrap_socket() returns, encryption is active.

            ssl_sock = context.wrap_socket(client_sock, server_side=True)

            # ==============================================================
            # STEP 9c: LOG SNI INFORMATION
            # ==============================================================
            #
            # Retrieve the SNI value that was captured by our callback.
            # This tells us what hostname the client requested.
            #
            # getattr() with a default of None handles the case where
            # the SNI callback wasn't called (client didn't send SNI).

            sni = getattr(ssl_sock, 'sni', None)
            print(f"SNI: {sni}", flush=True)

            # ==============================================================
            # STEP 9d: HTTP REQUEST/RESPONSE LOOP
            # ==============================================================
            #
            # Handle HTTP requests until the client disconnects.
            # HTTP/1.1 with Connection: keep-alive allows multiple
            # requests over a single TCP connection.

            while True:
                # ----------------------------------------------------------
                # RECEIVE HTTP REQUEST
                # ----------------------------------------------------------
                #
                # recv() reads data from the encrypted connection.
                # The TLS layer automatically decrypts incoming data.
                #
                # We read up to 4096 bytes at a time. For larger requests,
                # we might need to call recv() multiple times.
                #
                # recv() returns empty bytes (b'') when the connection closes.

                data = ssl_sock.recv(4096)
                if not data:
                    # Empty data means the client closed the connection
                    break

                print(f"  [RECV] Got {len(data)} bytes", flush=True)

                # ----------------------------------------------------------
                # PARSE HTTP REQUEST
                # ----------------------------------------------------------
                #
                # HTTP/1.1 request format:
                #   METHOD /path HTTP/1.1\r\n
                #   Header-Name: Header-Value\r\n
                #   Header-Name: Header-Value\r\n
                #   \r\n
                #   [Body for POST/PUT]
                #
                # We decode the bytes to a string and split on \r\n
                # to get individual lines.

                request = data.decode('utf-8')
                lines = request.split('\r\n')

                # The first line is the "request line"
                # Format: "METHOD /path HTTP/1.1"
                request_line = lines[0] if lines else ''

                # Split request line into components
                # Example: "GET /api/status HTTP/1.1" -> ["GET", "/api/status", "HTTP/1.1"]
                parts = request_line.split(' ')
                method = parts[0] if len(parts) > 0 else 'UNKNOWN'
                path = parts[1] if len(parts) > 1 else '/'

                print(f"{method} {path}", flush=True)

                # ----------------------------------------------------------
                # EXTRACT POST BODY (if applicable)
                # ----------------------------------------------------------
                #
                # For POST requests, the body comes after the headers,
                # separated by a blank line (\r\n\r\n).
                #
                # In a production server, you would:
                #   1. Check Content-Length header for body size
                #   2. Possibly receive more data if body is large
                #   3. Parse body based on Content-Type header

                if method == 'POST':
                    # Find the blank line that separates headers from body
                    body_start = request.find('\r\n\r\n')
                    if body_start != -1:
                        # Everything after \r\n\r\n is the body
                        body = request[body_start + 4:]
                        print(f"  Body: {body}", flush=True)

                        # Extract and process the JSON body
                        try:
                            body_json = json.loads(body)

                            # Handle aggregated client data from parent node
                            if 'clients' in body_json:
                                print(f"  Received aggregated data from parent", flush=True)
                                for client in body_json['clients']:
                                    client_ip = client.get('ip', 'unknown')
                                    timestamp = client.get('timestamp', int(time.time()))
                                    peer_table[client_ip] = {
                                        "timestamp": timestamp,
                                        "active": True
                                    }
                                    print(f"    Peer: {client_ip} @ {timestamp}", flush=True)
                                print(f"  Master peer table: {list(peer_table.keys())}", flush=True)

                            # Handle single client telemetry
                            elif 'client_ip' in body_json:
                                client_ip = body_json['client_ip']
                                timestamp = body_json.get('timestamp', int(time.time()))
                                peer_table[client_ip] = {
                                    "timestamp": timestamp,
                                    "active": True
                                }
                                print(f"  Client IP: {client_ip}", flush=True)
                                print(f"  Master peer table: {list(peer_table.keys())}", flush=True)
                        except json.JSONDecodeError:
                            pass  # Body is not valid JSON, ignore

                # ----------------------------------------------------------
                # BUILD HTTP RESPONSE
                # ----------------------------------------------------------
                #
                # HTTP/1.1 response format:
                #   HTTP/1.1 STATUS_CODE STATUS_TEXT\r\n
                #   Header-Name: Header-Value\r\n
                #   Header-Name: Header-Value\r\n
                #   \r\n
                #   Response body
                #
                # Common status codes:
                #   200 OK - Request succeeded
                #   201 Created - Resource created (for POST)
                #   400 Bad Request - Invalid request syntax
                #   404 Not Found - Resource doesn't exist
                #   500 Internal Server Error - Server-side error
                #
                # Required headers:
                #   Content-Length - Size of response body in bytes
                #
                # Recommended headers:
                #   Content-Type - MIME type of response body
                #   Connection - keep-alive or close

                # Choose response based on request method and mesh state
                print(f"  [Debug] method={method}, is_parent_assigned={is_parent_assigned}", flush=True)

                if method == 'GET':
                    # First connection becomes the parent node
                    if not is_parent_assigned:
                        is_parent_assigned = True
                        response_body = json.dumps({
                            "status": "healthy",
                            "version": "1.0",
                            "role": "parent",
                            "listen_port": 4434
                        })
                        print(f"  >>> ASSIGNED AS PARENT NODE <<<", flush=True)
                        print(f"  Response body: {response_body}", flush=True)
                    else:
                        response_body = json.dumps({
                            "status": "healthy",
                            "version": "1.0"
                        })
                        print(f"  Response body: {response_body}", flush=True)
                else:
                    # For POST responses, include peer table for parent
                    peer_list = [{"ip": ip, "timestamp": data["timestamp"]}
                                 for ip, data in peer_table.items()]
                    response_body = json.dumps({
                        "received": True,
                        "peer_table": peer_list
                    })

                # Build the complete HTTP response
                # Note: Content-Length MUST match the actual body length
                response = (
                    f"HTTP/1.1 200 OK\r\n"
                    f"Content-Type: application/json\r\n"
                    f"Content-Length: {len(response_body)}\r\n"
                    f"Connection: keep-alive\r\n"
                    f"\r\n"
                    f"{response_body}"
                )

                # ----------------------------------------------------------
                # SEND HTTP RESPONSE
                # ----------------------------------------------------------
                #
                # send() writes data to the encrypted connection.
                # The TLS layer automatically encrypts outgoing data.
                #
                # We encode the string to bytes before sending.

                ssl_sock.send(response.encode())

            # ==============================================================
            # STEP 9e: CLIENT DISCONNECTED CLEANLY
            # ==============================================================

            print(f"Client {addr} disconnected", flush=True)
            ssl_sock.close()

        # ==================================================================
        # STEP 9f: HANDLE ERRORS
        # ==================================================================
        #
        # Various errors can occur during TLS communication:
        #
        # ssl.SSLError - TLS-specific errors:
        #   - Certificate verification failed
        #   - Handshake failed (protocol mismatch, cipher mismatch)
        #   - Record MAC verification failed
        #
        # ConnectionResetError - TCP connection was reset:
        #   - Client closed connection abruptly (without TLS close_notify)
        #   - Network interruption
        #   - Firewall terminated connection

        except ssl.SSLError as e:
            print(f"TLS error: {e}", flush=True)
        except ConnectionResetError:
            print(f"Client {addr} disconnected abruptly", flush=True)

# ==============================================================================
# STEP 10: GRACEFUL SHUTDOWN
# ==============================================================================
#
# KeyboardInterrupt is raised when the user presses Ctrl+C.
# We catch it to shut down gracefully instead of crashing.

except KeyboardInterrupt:
    print("\nShutting down server...", flush=True)

# ==============================================================================
# STEP 11: CLEANUP
# ==============================================================================
#
# The finally block runs whether we exit normally or due to an exception.
# We close the server socket to release the port.
#
# Note: Individual client sockets are closed in the main loop.

finally:
    sock.close()
