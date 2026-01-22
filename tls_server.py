import ssl
import socket

# Server configuration
HOST = '127.0.0.1'
PORT = 4433

# Create TCP socket
sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
sock.bind((HOST, PORT))
sock.listen(1)

# Wrap socket with TLS
context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
context.load_cert_chain('cert.pem', 'key.pem')

print(f"Server listening on {HOST}:{PORT}")

# Accept connection
client_sock, addr = sock.accept()
ssl_sock = context.wrap_socket(client_sock, server_side=True)

print(f"Connection from {addr}")

# Receive message into variable
message = ssl_sock.recv(1024).decode('utf-8')

print(f"Received: {message}")

# Cleanup
ssl_sock.close()
sock.close()
