import ssl
import socket
import sys

# Server configuration
HOST = '127.0.0.1'
PORT = 4433

# Create TCP socket
sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
sock.bind((HOST, PORT))
sock.listen(5)

# Create TLS context
context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
context.load_cert_chain('cert.pem', 'key.pem')

print(f"Server listening on {HOST}:{PORT}", flush=True)
print("Press Ctrl+C to stop", flush=True)

try:
    while True:
        # Accept new connection
        client_sock, addr = sock.accept()
        print(f"\nConnection from {addr}", flush=True)

        try:
            ssl_sock = context.wrap_socket(client_sock, server_side=True)

            # Receive messages until client disconnects
            while True:
                data = ssl_sock.recv(1024)
                if not data:
                    break
                message = data.decode('utf-8').strip()
                print(f"Received: {message}", flush=True)

            print(f"Client {addr} disconnected", flush=True)
            ssl_sock.close()

        except ssl.SSLError as e:
            print(f"TLS error: {e}", flush=True)
        except ConnectionResetError:
            print(f"Client {addr} disconnected abruptly", flush=True)

except KeyboardInterrupt:
    print("\nShutting down server...", flush=True)
finally:
    sock.close()
