/*
 * Lightweight TLS/HTTPS Client
 * gcc tls_client.c -o tls_client.exe -lssl -lcrypto -lws2_32
 * A minimal TLS client that connects to a specified IP/port,
 * prints "Hello World" after establishing a secure connection,
 * then cleanly disconnects.
 *
 * Dependencies: OpenSSL (libssl, libcrypto)
 */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>

/*
 * Platform-specific includes
 * Windows uses Winsock2 for networking, while Unix-like systems
 * use POSIX sockets. We handle both cases here.
 */
#ifdef _WIN32
    /* Windows networking headers */
    #include <winsock2.h>
    #include <ws2tcpip.h>

    /* Link against required Windows libraries */
    #pragma comment(lib, "ws2_32.lib")      /* Winsock library */
    #pragma comment(lib, "libssl.lib")      /* OpenSSL SSL library */
    #pragma comment(lib, "libcrypto.lib")   /* OpenSSL crypto library */
#else
    /* Unix/Linux networking headers */
    #include <unistd.h>          /* For close() */
    #include <arpa/inet.h>       /* For inet_pton() */
    #include <sys/socket.h>      /* For socket(), connect() */

    /* Make Windows closesocket() work on Unix (it's just close()) */
    #define closesocket close
#endif

/* OpenSSL headers for TLS functionality */
#include <openssl/ssl.h>    /* Core SSL/TLS functions */
#include <openssl/err.h>    /* Error handling functions */

int main(int argc, char *argv[]) {
    /*
     * Validate command-line arguments
     * We need exactly 2 arguments: IP address and port number
     */
    if (argc != 3) {
        fprintf(stderr, "Usage: %s <ip> <port>\n", argv[0]);
        return 1;
    }

    /* Store connection parameters from command line */
    const char *ip = argv[1];       /* Target IP address (e.g., "93.184.216.34") */
    int port = atoi(argv[2]);       /* Target port (e.g., 443 for HTTPS) */

#ifdef _WIN32
    /*
     * Windows-specific: Initialize Winsock
     * This must be called before any socket operations on Windows.
     * MAKEWORD(2, 2) requests Winsock version 2.2
     */
    WSADATA wsa;
    if (WSAStartup(MAKEWORD(2, 2), &wsa) != 0) {
        fprintf(stderr, "WSAStartup failed\n");
        return 1;
    }
#endif

    /*
     * Initialize OpenSSL library
     * These calls set up the SSL/TLS infrastructure:
     * - SSL_library_init(): Registers all SSL/TLS ciphers and algorithms
     * - SSL_load_error_strings(): Loads human-readable error messages
     * - OpenSSL_add_all_algorithms(): Registers all available crypto algorithms
     */
    SSL_library_init();
    SSL_load_error_strings();
    OpenSSL_add_all_algorithms();

    /*
     * Create SSL context
     * The context holds configuration that can be shared across multiple connections.
     * TLS_client_method() returns a method that supports all TLS versions
     * and automatically negotiates the highest version supported by both parties.
     */
    const SSL_METHOD *method = TLS_client_method();
    SSL_CTX *ctx = SSL_CTX_new(method);
    if (!ctx) {
        fprintf(stderr, "SSL_CTX_new failed\n");
        return 1;
    }

    /*
     * Limit to TLS 1.2 to avoid TLS 1.3 handshake timing issues on Windows
     */
    SSL_CTX_set_max_proto_version(ctx, TLS1_2_VERSION);

    /*
     * Create TCP socket
     * AF_INET: IPv4 Internet protocols
     * SOCK_STREAM: TCP (reliable, connection-oriented)
     * 0: Let the system choose the appropriate protocol (TCP for SOCK_STREAM)
     */
    int sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) {
        fprintf(stderr, "Socket creation failed\n");
        SSL_CTX_free(ctx);
        return 1;
    }

    /*
     * Set up the server address structure
     * This defines where we want to connect to.
     */
    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));         /* Zero out the structure */
    addr.sin_family = AF_INET;              /* IPv4 address family */
    addr.sin_port = htons(port);            /* Port in network byte order (big-endian) */
    inet_pton(AF_INET, ip, &addr.sin_addr); /* Convert IP string to binary format */

    /*
     * Establish TCP connection to the server
     * This performs the TCP 3-way handshake (SYN, SYN-ACK, ACK)
     * At this point, we have a raw TCP connection but no encryption yet.
     */
    if (connect(sock, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        fprintf(stderr, "Connection failed\n");
        closesocket(sock);
        SSL_CTX_free(ctx);
        return 1;
    }

    /*
     * Skip certificate verification (for testing with self-signed certs)
     * MUST be set before SSL_new() so the SSL object inherits this setting
     */
    SSL_CTX_set_verify(ctx, SSL_VERIFY_NONE, NULL);

    /*
     * Create a new SSL structure for this connection
     * The SSL structure represents a single TLS connection and holds
     * connection-specific state (keys, session info, etc.)
     */
    SSL *ssl = SSL_new(ctx);
    /*
     * Attach the SSL structure to our socket
     * This tells OpenSSL to use our existing TCP socket for the TLS connection.
     * All TLS operations will now read/write through this socket.
     */
    SSL_set_fd(ssl, sock);

    /*
     * Perform TLS handshake
     * This is where the magic happens:
     * 1. Client sends ClientHello (supported TLS versions, cipher suites, etc.)
     * 2. Server responds with ServerHello (chosen version, cipher, certificate)
     * 3. Client verifies server certificate (we skip verification in this minimal example)
     * 4. Key exchange occurs (establishes shared secret)
     * 5. Both sides confirm the handshake
     *
     * After this succeeds, all communication is encrypted.
     */
    if (SSL_connect(ssl) <= 0) {
        fprintf(stderr, "TLS handshake failed\n");
        ERR_print_errors_fp(stderr);    /* Print detailed OpenSSL error info */
        SSL_free(ssl);
        closesocket(sock);
        SSL_CTX_free(ctx);
        return 1;
    }

    /*
     * SUCCESS! We now have an encrypted TLS connection.
     * Print our message to demonstrate the connection worked.
     */
    SSL_write(ssl, "Hello World\n", 12);

    /*
     * Clean shutdown sequence
     * Proper cleanup is important to avoid resource leaks and ensure
     * the connection is closed gracefully.
     */

    /*
     * SSL_shutdown(): Send TLS "close notify" alert
     * This tells the server we're done and allows for a graceful TLS shutdown.
     * A complete shutdown requires calling this twice (send and receive),
     * but for a simple disconnect, one call is sufficient.
     */
    SSL_shutdown(ssl);

    /* SSL_free(): Free the SSL structure and associated resources */
    SSL_free(ssl);

    /* Close the underlying TCP socket */
    closesocket(sock);

    /* SSL_CTX_free(): Free the SSL context */
    SSL_CTX_free(ctx);

#ifdef _WIN32
    /*
     * Windows-specific: Clean up Winsock
     * Must be called when done with all socket operations on Windows.
     */
    WSACleanup();
#endif

    return 0;
}
