/*
 * ============================================================================
 * TLS/HTTPS Client with HTTP Protocol Support
 * ============================================================================
 *
 * COMPILATION:
 *   Windows (MinGW/MSYS2):
 *     gcc tls_client.c -o tls_client.exe -lssl -lcrypto -lws2_32
 *
 *   Linux:
 *     gcc tls_client.c -o tls_client -lssl -lcrypto
 *
 * USAGE:
 *   ./tls_client --ip <addr> --port <num> [options]
 *
 *   Required:
 *     --ip,   -i <addr>    Server IP address
 *     --port, -p <num>     Server port number
 *
 *   Optional:
 *     --host, -h <name>    Hostname for SNI and Host header
 *                          Default: "www.microsoft.com"
 *     --ua,   -u <string>  User-Agent string for HTTP headers
 *                          Default: "Mozilla/5.0 (Windows NT 10.0; Win64; x64)..."
 *     --help               Show help message
 *
 * DEPENDENCIES:
 *   - OpenSSL library (libssl, libcrypto)
 *   - Winsock2 (Windows only, ws2_32.lib)
 *
 * TRAFFIC CHARACTERISTICS:
 *   - Uses TLS 1.2 for encryption
 *   - Sends SNI (Server Name Indication) in ClientHello
 *   - Alternates between HTTP GET and POST requests
 *   - Includes HTTP headers (Host, User-Agent, Content-Type)
 *   - Maintains persistent connection (Connection: keep-alive)
 *
 * ============================================================================
 */

#include <stdio.h>      /* printf, fprintf, snprintf */
#include <string.h>     /* strlen, strchr, memset */
#include <stdlib.h>     /* atoi */

/*
 * ============================================================================
 * PLATFORM-SPECIFIC CONFIGURATION
 * ============================================================================
 *
 * Windows and Unix/Linux have different networking APIs:
 * - Windows uses Winsock2 (ws2_32.dll)
 * - Unix/Linux uses POSIX sockets
 *
 * We use preprocessor directives to include the correct headers and
 * define compatibility macros so the same code works on both platforms.
 */
#ifdef _WIN32
    /*
     * WINDOWS NETWORKING HEADERS
     *
     * winsock2.h - Core Winsock2 API for socket operations
     *   Provides: socket(), connect(), send(), recv(), closesocket()
     *
     * ws2tcpip.h - TCP/IP specific extensions
     *   Provides: inet_pton() for converting IP strings to binary
     */
    #include <winsock2.h>
    #include <ws2tcpip.h>

    /*
     * MSVC PRAGMA FOR AUTOMATIC LIBRARY LINKING
     *
     * These pragmas tell the Microsoft Visual C++ linker to automatically
     * link against these libraries. When using MinGW/GCC, we use -l flags
     * on the command line instead, but these don't hurt to have.
     */
    #pragma comment(lib, "ws2_32.lib")      /* Winsock2 library */
    #pragma comment(lib, "libssl.lib")      /* OpenSSL SSL/TLS library */
    #pragma comment(lib, "libcrypto.lib")   /* OpenSSL cryptography library */
#else
    /*
     * UNIX/LINUX NETWORKING HEADERS
     *
     * unistd.h    - POSIX API, provides close() for sockets
     * arpa/inet.h - Internet address manipulation, provides inet_pton()
     * sys/socket.h - Core socket API: socket(), connect(), send(), recv()
     */
    #include <unistd.h>
    #include <arpa/inet.h>
    #include <sys/socket.h>

    /*
     * COMPATIBILITY MACRO
     *
     * Windows uses closesocket() to close sockets, while Unix uses close().
     * This macro allows us to use closesocket() everywhere in our code.
     */
    #define closesocket close
#endif

/*
 * ============================================================================
 * OPENSSL HEADERS
 * ============================================================================
 *
 * openssl/ssl.h - Core SSL/TLS functionality
 *   Provides: SSL_CTX, SSL, SSL_new(), SSL_connect(), SSL_read(), SSL_write()
 *   These are the main functions for establishing and using TLS connections.
 *
 * openssl/err.h - Error handling and reporting
 *   Provides: ERR_print_errors_fp() for detailed error messages
 *   OpenSSL maintains an error queue; this helps us print meaningful errors.
 */
#include <openssl/ssl.h>
#include <openssl/err.h>

/*
 * ============================================================================
 * HELPER FUNCTION: Print usage information
 * ============================================================================
 */
void print_usage(const char *program_name) {
    fprintf(stderr, "Usage: %s --ip <addr> --port <num> [options]\n", program_name);
    fprintf(stderr, "\nRequired:\n");
    fprintf(stderr, "  --ip,   -i <addr>    Server IP address\n");
    fprintf(stderr, "  --port, -p <num>     Server port number\n");
    fprintf(stderr, "\nOptional:\n");
    fprintf(stderr, "  --host, -h <name>    Hostname for SNI and Host header\n");
    fprintf(stderr, "                       Default: www.microsoft.com\n");
    fprintf(stderr, "  --ua,   -u <string>  User-Agent string\n");
    fprintf(stderr, "                       Default: Mozilla/5.0 (Windows NT 10.0; Win64; x64)...\n");
    fprintf(stderr, "  --help               Show this help message\n");
    fprintf(stderr, "\nExamples:\n");
    fprintf(stderr, "  %s --ip 127.0.0.1 --port 4433\n", program_name);
    fprintf(stderr, "  %s -i 127.0.0.1 -p 443 -h api.github.com\n", program_name);
    fprintf(stderr, "  %s -i 127.0.0.1 -p 443 -u \"curl/8.0.1\"\n", program_name);
    fprintf(stderr, "  %s -i 127.0.0.1 -p 443 -h google.com -u \"Mozilla/5.0 (iPhone)\"\n", program_name);
}

/*
 * ============================================================================
 * MAIN FUNCTION
 * ============================================================================
 */
int main(int argc, char *argv[]) {

    /*
     * ------------------------------------------------------------------------
     * STEP 1: PARSE COMMAND-LINE ARGUMENTS (Named Flags)
     * ------------------------------------------------------------------------
     *
     * We use named flags for flexible argument ordering:
     *   --ip, -i     Server IP address (required)
     *   --port, -p   Server port number (required)
     *   --host, -h   Hostname for SNI/Host header (optional)
     *   --ua, -u     User-Agent string (optional)
     *
     * This allows setting any combination of optional arguments without
     * needing to specify the others. For example:
     *   -i 127.0.0.1 -p 443 -u "curl/8.0"   (custom UA, default host)
     */

    /* Default values - used if not specified on command line */
    const char *ip = NULL;                          /* Required - must be set */
    int port = 0;                                   /* Required - must be set */
    const char *host = "www.microsoft.com";         /* Optional - has default */
    const char *user_agent =                        /* Optional - has default */
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/144.0.0.0 Safari/537.36";

    /*
     * Parse command-line arguments
     *
     * We loop through argv looking for flags (starting with - or --).
     * When we find a flag, we read the next argument as its value.
     *
     * strcmp() returns 0 when strings are equal.
     */
    for (int i = 1; i < argc; i++) {
        /* Check for --help flag */
        if (strcmp(argv[i], "--help") == 0) {
            print_usage(argv[0]);
            return 0;
        }
        /* --ip or -i: Server IP address */
        else if (strcmp(argv[i], "--ip") == 0 || strcmp(argv[i], "-i") == 0) {
            if (i + 1 < argc) {
                ip = argv[++i];     /* Increment i to get the value, then store */
            } else {
                fprintf(stderr, "Error: %s requires a value\n", argv[i]);
                return 1;
            }
        }
        /* --port or -p: Server port number */
        else if (strcmp(argv[i], "--port") == 0 || strcmp(argv[i], "-p") == 0) {
            if (i + 1 < argc) {
                port = atoi(argv[++i]);
            } else {
                fprintf(stderr, "Error: %s requires a value\n", argv[i]);
                return 1;
            }
        }
        /* --host or -h: Hostname for SNI and Host header */
        else if (strcmp(argv[i], "--host") == 0 || strcmp(argv[i], "-h") == 0) {
            if (i + 1 < argc) {
                host = argv[++i];
            } else {
                fprintf(stderr, "Error: %s requires a value\n", argv[i]);
                return 1;
            }
        }
        /* --ua or -u: User-Agent string */
        else if (strcmp(argv[i], "--ua") == 0 || strcmp(argv[i], "-u") == 0) {
            if (i + 1 < argc) {
                user_agent = argv[++i];
            } else {
                fprintf(stderr, "Error: %s requires a value\n", argv[i]);
                return 1;
            }
        }
        /* Unknown flag */
        else {
            fprintf(stderr, "Error: Unknown argument '%s'\n", argv[i]);
            print_usage(argv[0]);
            return 1;
        }
    }

    /*
     * Validate required arguments
     *
     * IP and port are required - if not provided, show usage and exit.
     */
    if (ip == NULL || port == 0) {
        fprintf(stderr, "Error: --ip and --port are required\n\n");
        print_usage(argv[0]);
        return 1;
    }

#ifdef _WIN32
    /*
     * ------------------------------------------------------------------------
     * STEP 2: INITIALIZE WINSOCK (Windows Only)
     * ------------------------------------------------------------------------
     *
     * On Windows, we must initialize the Winsock library before using any
     * socket functions. This loads the ws2_32.dll and sets up internal state.
     *
     * WSADATA - Structure that receives details about the Winsock implementation
     * WSAStartup() - Initializes Winsock
     *   - MAKEWORD(2, 2) requests Winsock version 2.2
     *   - Returns 0 on success, error code on failure
     *
     * Note: We must call WSACleanup() when done to free resources.
     */
    WSADATA wsa;
    if (WSAStartup(MAKEWORD(2, 2), &wsa) != 0) {
        fprintf(stderr, "WSAStartup failed\n");
        return 1;
    }
#endif

    /*
     * ------------------------------------------------------------------------
     * STEP 3: INITIALIZE OPENSSL
     * ------------------------------------------------------------------------
     *
     * OpenSSL requires initialization before use. These functions set up
     * internal data structures and register available algorithms.
     *
     * SSL_library_init() - Registers all SSL/TLS ciphers and digest algorithms
     *   This must be called before any other SSL functions.
     *
     * SSL_load_error_strings() - Loads human-readable error messages
     *   Without this, error messages would just be numeric codes.
     *
     * OpenSSL_add_all_algorithms() - Registers all available algorithms
     *   This includes ciphers (AES, ChaCha20) and digests (SHA256, SHA384).
     *
     * Note: In OpenSSL 1.1.0+, these are called automatically, but calling
     * them explicitly ensures compatibility with older versions.
     */
    SSL_library_init();
    SSL_load_error_strings();
    OpenSSL_add_all_algorithms();

    /*
     * ------------------------------------------------------------------------
     * STEP 4: CREATE SSL CONTEXT
     * ------------------------------------------------------------------------
     *
     * The SSL_CTX (SSL Context) is a factory for creating SSL connections.
     * It holds configuration settings that are shared across all connections:
     * - Supported protocol versions
     * - Certificate verification settings
     * - Cipher suite preferences
     *
     * TLS_client_method() - Returns a method supporting all TLS versions
     *   The actual version is negotiated during the handshake.
     *   For a server, we would use TLS_server_method() instead.
     *
     * SSL_CTX_new() - Creates a new SSL context
     *   Returns NULL on failure (out of memory, etc.)
     */
    const SSL_METHOD *method = TLS_client_method();
    SSL_CTX *ctx = SSL_CTX_new(method);
    if (!ctx) {
        fprintf(stderr, "SSL_CTX_new failed\n");
        return 1;
    }

    /*
     * CONFIGURE TLS VERSION RANGE
     *
     * Support TLS 1.2 and TLS 1.3 to match Chrome browser fingerprint.
     * The supported_versions extension will advertise: TLS 1.3, TLS 1.2
     */
    SSL_CTX_set_min_proto_version(ctx, TLS1_2_VERSION);
    SSL_CTX_set_max_proto_version(ctx, TLS1_3_VERSION);

    /*
     * CONFIGURE CIPHER SUITES (Chrome-like ordering)
     *
     * TLS 1.3 ciphers must be set separately using SSL_CTX_set_ciphersuites()
     * TLS 1.2 ciphers use SSL_CTX_set_cipher_list()
     */

    /* TLS 1.3 ciphersuites */
    if (SSL_CTX_set_ciphersuites(ctx,
            "TLS_AES_128_GCM_SHA256:"
            "TLS_AES_256_GCM_SHA384:"
            "TLS_CHACHA20_POLY1305_SHA256") != 1) {
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }

    /* TLS 1.2 ciphersuites */
    const char *tls12_ciphers =
        "ECDHE-ECDSA-AES128-GCM-SHA256:"
        "ECDHE-RSA-AES128-GCM-SHA256:"
        "ECDHE-ECDSA-AES256-GCM-SHA384:"
        "ECDHE-RSA-AES256-GCM-SHA384:"
        "ECDHE-ECDSA-CHACHA20-POLY1305:"
        "ECDHE-RSA-CHACHA20-POLY1305:"
        "ECDHE-RSA-AES128-SHA:"
        "ECDHE-RSA-AES256-SHA:"
        "AES128-GCM-SHA256:"
        "AES256-GCM-SHA384:"
        "AES128-SHA:"
        "AES256-SHA";
    if (SSL_CTX_set_cipher_list(ctx, tls12_ciphers) != 1) {
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }
    
    /*
     * Set Supported Groups (supported_groups extension)
     *
     * Chrome uses: X25519Kyber768, X25519, P-256, P-384
     * Note: X25519Kyber768 (post-quantum) requires special OpenSSL build
     * We use the standard curves that OpenSSL supports.
     */
    if (SSL_CTX_set1_curves_list(ctx, "X25519:P-256:P-384") != 1) {
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }
    // 4. Enable other common Chrome extensions through options
    // This enables certain behaviors like session ticket support.
    SSL_CTX_set_options(ctx, SSL_OP_NO_SSLv2 | SSL_OP_NO_SSLv3 | SSL_OP_NO_COMPRESSION);

    // 5. Set Signature Algorithms (another critical extension)
    if (SSL_CTX_set1_sigalgs_list(ctx, "ecdsa_secp256r1_sha256:rsa_pss_rsae_sha256:rsa_pkcs1_sha256:ecdsa_secp384r1_sha384:rsa_pss_rsae_sha384:rsa_pkcs1_sha384:rsa_pss_rsae_sha512:rsa_pkcs1_sha512") != 1) {
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }

    /*
     * CONFIGURE ALPN (application_layer_protocol_negotiation extension)
     *
     * Advertises supported application protocols: h2 (HTTP/2), http/1.1
     * Format: length-prefixed strings concatenated together
     */
    static const unsigned char alpn_protos[] = {
        2, 'h', '2',                              /* HTTP/2 */
        8, 'h', 't', 't', 'p', '/', '1', '.', '1' /* HTTP/1.1 */
    };
    SSL_CTX_set_alpn_protos(ctx, alpn_protos, sizeof(alpn_protos));

    /*
     * ENABLE OCSP STAPLING (status_request extension)
     *
     * Requests OCSP response from server during handshake.
     */
    SSL_CTX_set_tlsext_status_type(ctx, TLSEXT_STATUSTYPE_ocsp);

    /*
     * ENABLE CERTIFICATE TRANSPARENCY (signed_certificate_timestamp extension)
     *
     * Requests SCT from server. Extension type 18.
     */
    SSL_CTX_enable_ct(ctx, SSL_CT_VALIDATION_PERMISSIVE);

    /*
     * ENSURE SESSION TICKETS ARE ENABLED (session_ticket extension)
     *
     * Session tickets allow TLS session resumption.
     */
    SSL_CTX_clear_options(ctx, SSL_OP_NO_TICKET);

    /*
     * ------------------------------------------------------------------------
     * STEP 5: CREATE TCP SOCKET
     * ------------------------------------------------------------------------
     *
     * Before we can do TLS, we need a TCP connection. TLS runs on top of
     * a reliable transport protocol (usually TCP).
     *
     * socket() creates an endpoint for communication:
     *   AF_INET     - IPv4 address family
     *   SOCK_STREAM - TCP (reliable, ordered, connection-oriented)
     *   0           - Let the OS choose the protocol (TCP for SOCK_STREAM)
     *
     * Returns: Socket descriptor (positive int) on success, -1 on failure
     */
    int sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) {
        fprintf(stderr, "Socket creation failed\n");
        SSL_CTX_free(ctx);
        return 1;
    }

    /*
     * ------------------------------------------------------------------------
     * STEP 6: CONFIGURE SERVER ADDRESS
     * ------------------------------------------------------------------------
     *
     * struct sockaddr_in holds an IPv4 socket address:
     *   sin_family - Address family (AF_INET for IPv4)
     *   sin_port   - Port number in network byte order (big-endian)
     *   sin_addr   - IPv4 address in binary form
     *
     * htons() - "Host TO Network Short"
     *   Converts port number from host byte order to network byte order.
     *   Network byte order is always big-endian.
     *   Example: port 443 (0x01BB) might become 0xBB01 on little-endian
     *
     * inet_pton() - "Presentation TO Network"
     *   Converts IP address string (e.g., "127.0.0.1") to binary format.
     *   The 'p' stands for presentation (human-readable).
     *   The 'n' stands for network (binary format).
     */
    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));         /* Zero out to avoid garbage */
    addr.sin_family = AF_INET;              /* IPv4 */
    addr.sin_port = htons(port);            /* Convert port to network order */
    inet_pton(AF_INET, ip, &addr.sin_addr); /* Convert IP string to binary */

    /*
     * ------------------------------------------------------------------------
     * STEP 7: ESTABLISH TCP CONNECTION
     * ------------------------------------------------------------------------
     *
     * connect() initiates a connection to the server. For TCP, this performs
     * the three-way handshake:
     *   1. Client sends SYN (synchronize)
     *   2. Server responds with SYN-ACK (synchronize-acknowledge)
     *   3. Client sends ACK (acknowledge)
     *
     * After connect() returns successfully, we have a TCP connection,
     * but NO encryption yet. Data sent now would be in plaintext.
     *
     * Parameters:
     *   sock - Our socket descriptor
     *   (struct sockaddr *)&addr - Server address (cast to generic type)
     *   sizeof(addr) - Size of the address structure
     *
     * Returns: 0 on success, -1 on failure
     */
    if (connect(sock, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        fprintf(stderr, "Connection failed\n");
        closesocket(sock);
        SSL_CTX_free(ctx);
        return 1;
    }

    /*
     * ------------------------------------------------------------------------
     * STEP 8: CONFIGURE CERTIFICATE VERIFICATION
     * ------------------------------------------------------------------------
     *
     * By default, OpenSSL verifies the server's certificate:
     *   - Is it signed by a trusted CA?
     *   - Is it expired?
     *   - Does the hostname match?
     *
     * SSL_VERIFY_NONE disables all verification. This is INSECURE for
     * production use, but necessary for testing with self-signed certificates.
     *
     * For production, you would use:
     *   SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, NULL);
     *   SSL_CTX_load_verify_locations(ctx, "ca-bundle.crt", NULL);
     *
     * This must be set BEFORE SSL_new() so the SSL object inherits it.
     */
    SSL_CTX_set_verify(ctx, SSL_VERIFY_NONE, NULL);

    /*
     * ------------------------------------------------------------------------
     * STEP 9: CREATE SSL CONNECTION OBJECT
     * ------------------------------------------------------------------------
     *
     * SSL_new() creates an SSL structure for a single connection.
     * While SSL_CTX is shared configuration, SSL holds per-connection state:
     *   - Session keys (after handshake)
     *   - Connection state machine
     *   - Buffered data
     *
     * The SSL object inherits settings from the SSL_CTX.
     */
    SSL *ssl = SSL_new(ctx);

    /*
     * ------------------------------------------------------------------------
     * STEP 10: SET SNI (Server Name Indication)
     * ------------------------------------------------------------------------
     *
     * SNI is a TLS extension that allows the client to indicate which
     * hostname it's trying to connect to. This is sent in the ClientHello
     * message, BEFORE encryption begins (so it's visible to network monitors).
     *
     * WHY SNI EXISTS:
     *   One IP address can host multiple HTTPS websites. The server needs
     *   to know which certificate to present before decryption starts.
     *   SNI solves this by having the client specify the desired hostname.
     *
     * The server in our case ignores SNI and always uses the same cert,
     */
    SSL_set_tlsext_host_name(ssl, host);

    /*
     * ------------------------------------------------------------------------
     * STEP 11: BIND SSL TO SOCKET
     * ------------------------------------------------------------------------
     *
     * SSL_set_fd() connects the SSL object to our TCP socket.
     * After this, all SSL_read/SSL_write operations will use this socket.
     *
     * OpenSSL can also work with memory BIOs (buffers) instead of sockets,
     * which is useful for integrating with async I/O frameworks.
     */
    SSL_set_fd(ssl, sock);

    /*
     * ------------------------------------------------------------------------
     * STEP 12: PERFORM TLS HANDSHAKE
     * ------------------------------------------------------------------------
     *
     * SSL_connect() performs the TLS handshake as a client. This is where
     * the cryptographic magic happens:
     *
     * TLS 1.2 HANDSHAKE FLOW:
     *   1. ClientHello (Client -> Server)
     *      - Supported TLS versions
     *      - Random bytes (for key derivation)
     *      - Supported cipher suites
     *      - SNI extension (hostname)
     *      - Other extensions
     *
     *   2. ServerHello (Server -> Client)
     *      - Chosen TLS version
     *      - Random bytes
     *      - Chosen cipher suite
     *      - Session ID
     *
     *   3. Certificate (Server -> Client)
     *      - Server's X.509 certificate
     *      - Certificate chain (intermediate CAs)
     *
     *   4. ServerKeyExchange (Server -> Client) [if needed]
     *      - Key exchange parameters (for DHE/ECDHE)
     *
     *   5. ServerHelloDone (Server -> Client)
     *      - Indicates server is done with hello phase
     *
     *   6. ClientKeyExchange (Client -> Server)
     *      - Client's key exchange data
     *      - For RSA: encrypted pre-master secret
     *      - For ECDHE: client's public key
     *
     *   7. ChangeCipherSpec (Both directions)
     *      - Signals switch to encrypted communication
     *
     *   8. Finished (Both directions)
     *      - Encrypted verification of handshake integrity
     *
     * After this, both sides have:
     *   - Agreed on encryption algorithms
     *   - Derived shared session keys
     *   - Verified each other (optionally)
     *
     * Returns: 1 on success, <=0 on failure
     */
    if (SSL_connect(ssl) <= 0) {
        fprintf(stderr, "TLS handshake failed\n");
        ERR_print_errors_fp(stderr);    /* Print detailed error information */
        SSL_free(ssl);
        closesocket(sock);
        SSL_CTX_free(ctx);
        return 1;
    }

    /*
     * ------------------------------------------------------------------------
     * STEP 13: CONNECTION ESTABLISHED - PRINT STATUS
     * ------------------------------------------------------------------------
     *
     * At this point, we have a fully encrypted TLS connection.
     * All data sent via SSL_write() will be encrypted automatically.
     */
    printf("Connected to %s:%d\n", ip, port);
    printf("Host: %s\n", host);
    printf("User-Agent: %s\n", user_agent);
    printf("Sending HTTP requests every 5 minutes. Press Ctrl+C to stop.\n\n");

    /*
     * ------------------------------------------------------------------------
     * STEP 14: MAIN COMMUNICATION LOOP
     * ------------------------------------------------------------------------
     *
     * We alternate between GET and POST requests to mimic realistic traffic.
     * Real browsers make various types of requests, not just one.
     */
    char request[2048];     /* Buffer for outgoing HTTP request */
    char response[4096];    /* Buffer for incoming HTTP response */
    int request_num = 0;    /* Counter to alternate GET/POST */

    while (1) {
        /*
         * BUILD HTTP REQUEST
         *
         * HTTP/1.1 requests have this structure:
         *   <METHOD> <PATH> HTTP/1.1\r\n
         *   Header-Name: Header-Value\r\n
         *   Header-Name: Header-Value\r\n
         *   \r\n
         *   [Body for POST/PUT]
         *
         * Required headers:
         *   Host - The target hostname (required in HTTP/1.1)
         *
         * Common headers we include:
         *   User-Agent    - Identifies the client software
         *   Accept        - What content types we accept
         *   Content-Type  - Type of data in request body (POST)
         *   Content-Length- Size of request body in bytes (POST)
         *   Connection    - keep-alive maintains the connection
         */
        if (request_num % 2 == 0) {
            /*
             * HTTP GET REQUEST
             *
             * GET requests retrieve data from the server.
             * They have no body - all parameters are in the URL.
             *
             * Example real-world GET requests:
             *   GET /index.html - Fetch a web page
             *   GET /api/users?id=123 - Fetch user data
             *   GET /status - Health check endpoint
             */
            snprintf(request, sizeof(request),
                "GET /api/v1/status HTTP/1.1\r\n"
                "Host: %s\r\n"
                "User-Agent: %s\r\n"
                "Accept: application/json\r\n"
                "Connection: keep-alive\r\n"
                "\r\n",
                host, user_agent);
        } else {
            /*
             * HTTP POST REQUEST
             *
             * POST requests send data to the server.
             * The body contains the data (JSON in this case).
             *
             * Content-Type tells the server how to parse the body:
             *   application/json - JSON data
             *   application/x-www-form-urlencoded - Form data
             *   multipart/form-data - File uploads
             *
             * Content-Length MUST match the actual body size exactly.
             * If wrong, the server may hang waiting for more data or
             * read into the next request.
             */
            const char *body = "{\"status\":\"ok\",\"timestamp\":12345}";
            snprintf(request, sizeof(request),
                "POST /api/v1/telemetry HTTP/1.1\r\n"
                "Host: %s\r\n"
                "User-Agent: %s\r\n"
                "Content-Type: application/json\r\n"
                "Content-Length: %d\r\n"
                "Connection: keep-alive\r\n"
                "\r\n"
                "%s",
                host, user_agent, (int)strlen(body), body);
        }

        /*
         * SEND HTTP REQUEST
         *
         * SSL_write() encrypts and sends data through the TLS connection.
         * It handles all the encryption, MAC computation, and record
         * framing automatically.
         *
         * Returns: Number of bytes written, or <=0 on error
         */
        int bytes = SSL_write(ssl, request, strlen(request));
        if (bytes <= 0) {
            fprintf(stderr, "SSL_write failed\n");
            ERR_print_errors_fp(stderr);
            break;
        }
        printf("Sent: %s request to /api/v1/%s\n",
               (request_num % 2 == 0) ? "GET" : "POST",
               (request_num % 2 == 0) ? "status" : "telemetry");

        /*
         * RECEIVE HTTP RESPONSE
         *
         * SSL_read() receives and decrypts data from the TLS connection.
         * It verifies the MAC and decrypts automatically.
         *
         * We read into a buffer and null-terminate it so we can treat
         * it as a string.
         *
         * Returns: Number of bytes read, 0 on connection close, <0 on error
         */
        int resp_bytes = SSL_read(ssl, response, sizeof(response) - 1);
        if (resp_bytes <= 0) {
            fprintf(stderr, "SSL_read failed\n");
            ERR_print_errors_fp(stderr);
            break;
        }
        response[resp_bytes] = '\0';    /* Null-terminate for string ops */

        /*
         * PARSE AND DISPLAY RESPONSE STATUS LINE
         *
         * HTTP response format:
         *   HTTP/1.1 200 OK\r\n
         *   Headers...\r\n
         *   \r\n
         *   Body...
         *
         * We extract just the first line (status line) for display.
         */
        char *newline = strchr(response, '\r');
        if (newline) *newline = '\0';   /* Truncate at first \r */
        printf("Response: %s\n\n", response);

        request_num++;

        /*
         * SLEEP BETWEEN REQUESTS
         *
         * We wait 5 minutes (300 seconds) between requests.
         *
         * Windows uses Sleep() with milliseconds.
         * Unix uses sleep() with seconds.
         *
         */
#ifdef _WIN32
        Sleep(300000);  /* 300,000 milliseconds = 5 minutes */
#else
        sleep(300);     /* 300 seconds = 5 minutes */
#endif
    }

    /*
     * ------------------------------------------------------------------------
     * STEP 15: CLEANUP AND SHUTDOWN
     * ------------------------------------------------------------------------
     *
     * Proper cleanup is important to:
     *   1. Free allocated memory
     *   2. Close network connections gracefully
     *   3. Release system resources
     */

    /*
     * SSL_shutdown() sends a TLS "close_notify" alert to the server.
     * This tells the server we're done and allows for graceful shutdown.
     *
     * A complete shutdown requires calling this twice:
     *   1. First call sends close_notify
     *   2. Second call waits for server's close_notify
     *
     * For simplicity, we just call it once.
     */
    SSL_shutdown(ssl);

    /*
     * SSL_free() frees the SSL structure and associated resources.
     * This includes session keys and buffers.
     */
    SSL_free(ssl);

    /*
     * closesocket() / close() closes the TCP socket.
     * This sends a TCP FIN to the server.
     */
    closesocket(sock);

    /*
     * SSL_CTX_free() frees the SSL context.
     * Only call this after all SSL objects using it are freed.
     */
    SSL_CTX_free(ctx);

#ifdef _WIN32
    /*
     * WSACleanup() terminates use of Winsock.
     * This must be called once for each successful WSAStartup().
     */
    WSACleanup();
#endif

    return 0;
}
