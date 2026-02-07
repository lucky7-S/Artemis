/*
 * ============================================================================
 * TLS/HTTPS Client with Mesh Network Support (Windows)
 * ============================================================================
 *
 * COMPILATION:
 *   Windows (MinGW/MSYS2):
 *     gcc tls_client_windows.c -o tls_client.exe -lssl -lcrypto -lws2_32
 *
 * USAGE:
 *   ./tls_client.exe --ip <addr> --port <num> [options]
 *
 *   Required (for normal/parent mode):
 *     --ip,   -i <addr>    Server IP address
 *     --port, -p <num>     Server port number
 *
 *   Required (for child mode):
 *     --parent, -P <ip:port>  Connect to parent node instead of server
 *
 *   Optional:
 *     --host, -h <name>    Hostname for SNI and Host header
 *                          Default: "www.microsoft.com"
 *     --ua,   -u <string>  User-Agent string for HTTP headers
 *     --listen, -l <port>  Listen port for child connections (enables parent mode)
 *     --help               Show help message
 *
 * MODES:
 *   Normal Mode: Connect to server, send telemetry
 *   Parent Mode: Connect to server + listen for children + aggregate data
 *   Child Mode:  Connect to parent node, send telemetry
 *
 * ============================================================================
 */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <time.h>

/* Windows networking headers - order matters! */
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>

#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "libssl.lib")
#pragma comment(lib, "libcrypto.lib")

typedef int socklen_t;

/* OpenSSL headers */
#include <openssl/ssl.h>
#include <openssl/err.h>

/*
 * ============================================================================
 * PEER TABLE STRUCTURE FOR MESH NETWORK
 * ============================================================================
 */
#define MAX_PEERS 64
#define INET_ADDRSTRLEN_CUSTOM 16

typedef struct {
    char ip[INET_ADDRSTRLEN_CUSTOM];
    long timestamp;
    int active;
} Peer;

/* Global peer table - maintained by parent node */
Peer peer_table[MAX_PEERS];
int peer_count = 0;

/* Mutex for thread-safe peer table access */
CRITICAL_SECTION peer_table_mutex;
#define MUTEX_INIT() InitializeCriticalSection(&peer_table_mutex)
#define MUTEX_LOCK() EnterCriticalSection(&peer_table_mutex)
#define MUTEX_UNLOCK() LeaveCriticalSection(&peer_table_mutex)
#define MUTEX_DESTROY() DeleteCriticalSection(&peer_table_mutex)

/*
 * ============================================================================
 * GLOBAL STATE FOR MESH NETWORK
 * ============================================================================
 */

/* Mode flags */
int is_parent_mode = 0;
int is_child_mode = 0;
int listen_port = 0;
char parent_ip[64] = "";
int parent_port = 0;
int child_interval = 120;  /* UDP send interval in seconds (default: 120) */

/* Flag to signal listener thread to stop */
volatile int listener_running = 1;

/*
 * ============================================================================
 * HELPER FUNCTION: Add peer to table
 * ============================================================================
 */
void add_peer(const char *ip, long timestamp) {
    MUTEX_LOCK();
    for (int i = 0; i < peer_count; i++) {
        if (strcmp(peer_table[i].ip, ip) == 0) {
            peer_table[i].timestamp = timestamp;
            peer_table[i].active = 1;
            MUTEX_UNLOCK();
            return;
        }
    }
    if (peer_count < MAX_PEERS) {
        strncpy(peer_table[peer_count].ip, ip, INET_ADDRSTRLEN_CUSTOM - 1);
        peer_table[peer_count].ip[INET_ADDRSTRLEN_CUSTOM - 1] = '\0';
        peer_table[peer_count].timestamp = timestamp;
        peer_table[peer_count].active = 1;
        peer_count++;
    }
    MUTEX_UNLOCK();
}

/*
 * ============================================================================
 * HELPER FUNCTION: Build aggregated clients JSON
 * ============================================================================
 */
int build_aggregated_json(char *buffer, size_t bufsize) {
    MUTEX_LOCK();
    int offset = snprintf(buffer, bufsize, "{\"clients\":[");
    for (int i = 0; i < peer_count; i++) {
        if (i > 0) offset += snprintf(buffer + offset, bufsize - offset, ",");
        offset += snprintf(buffer + offset, bufsize - offset,
            "{\"ip\":\"%s\",\"timestamp\":%ld}",
            peer_table[i].ip, peer_table[i].timestamp);
    }
    offset += snprintf(buffer + offset, bufsize - offset, "]}");
    MUTEX_UNLOCK();
    return offset;
}

/*
 * ============================================================================
 * HELPER FUNCTION: Print peer table
 * ============================================================================
 */
void print_peer_table(void) {
    MUTEX_LOCK();
    printf("\n=== Peer Table (%d peers) ===\n", peer_count);
    for (int i = 0; i < peer_count; i++) {
        printf("  %s (timestamp: %ld, active: %d)\n",
               peer_table[i].ip, peer_table[i].timestamp, peer_table[i].active);
    }
    printf("=============================\n\n");
    MUTEX_UNLOCK();
}

/*
 * ============================================================================
 * HELPER FUNCTION: Print usage information
 * ============================================================================
 */
void print_usage(const char *program_name) {
    fprintf(stderr, "Usage: %s --ip <addr> --port <num> [options]\n", program_name);
    fprintf(stderr, "\nRequired (for normal/parent mode):\n");
    fprintf(stderr, "  --ip,   -i <addr>    Server IP address\n");
    fprintf(stderr, "  --port, -p <num>     Server port number\n");
    fprintf(stderr, "\nRequired (for child mode):\n");
    fprintf(stderr, "  --parent, -P <ip:port>  Connect to parent instead of server\n");
    fprintf(stderr, "\nOptional:\n");
    fprintf(stderr, "  --host, -h <name>       Hostname for SNI and Host header\n");
    fprintf(stderr, "  --ua,   -u <string>     User-Agent string\n");
    fprintf(stderr, "  --listen, -l <port>     Listen port for children (enables parent mode)\n");
    fprintf(stderr, "  --interval, -t <secs>   UDP send interval for child mode (default: 120)\n");
    fprintf(stderr, "  --help                  Show this help message\n");
    fprintf(stderr, "\nExamples:\n");
    fprintf(stderr, "  %s --ip 127.0.0.1 --port 4433\n", program_name);
    fprintf(stderr, "  %s -i 127.0.0.1 -p 4433 -l 4434  (parent mode)\n", program_name);
    fprintf(stderr, "  %s -P 127.0.0.1:4434             (child mode, 120s interval)\n", program_name);
    fprintf(stderr, "  %s -P 127.0.0.1:4434 -t 5        (child mode, 5s interval)\n", program_name);
}

/*
 * ============================================================================
 * UDP LISTENER: Receive child telemetry (Parent Mode)
 * ============================================================================
 *
 * Children send simple JSON datagrams:
 *   {"ip":"192.168.1.5","ts":1234567890}
 *
 * No acknowledgment - fire and forget.
 */

/*
 * ============================================================================
 * UDP LISTENER THREAD: Receive child datagrams (Parent Mode)
 * ============================================================================
 */
DWORD WINAPI listener_thread(LPVOID arg) {
    int udp_sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (udp_sock < 0) {
        fprintf(stderr, "Failed to create UDP socket\n");
        return 0;
    }

    struct sockaddr_in listen_addr;
    memset(&listen_addr, 0, sizeof(listen_addr));
    listen_addr.sin_family = AF_INET;
    listen_addr.sin_addr.s_addr = INADDR_ANY;
    listen_addr.sin_port = htons(listen_port);

    if (bind(udp_sock, (struct sockaddr *)&listen_addr, sizeof(listen_addr)) < 0) {
        fprintf(stderr, "Failed to bind UDP on port %d\n", listen_port);
        closesocket(udp_sock);
        return 0;
    }

    printf("[Parent] Listening for UDP datagrams on port %d\n", listen_port);

    char buffer[1024];
    while (listener_running) {
        struct sockaddr_in child_addr;
        socklen_t child_len = sizeof(child_addr);

        int bytes = recvfrom(udp_sock, buffer, sizeof(buffer) - 1, 0,
                             (struct sockaddr *)&child_addr, &child_len);
        if (bytes <= 0) continue;

        buffer[bytes] = '\0';

        char child_ip[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &child_addr.sin_addr, child_ip, sizeof(child_ip));

        /* Parse timestamp from JSON: {"ip":"...","ts":1234567890} */
        char *ts_ptr = strstr(buffer, "\"ts\":");
        long timestamp = (long)time(NULL);
        if (ts_ptr) {
            timestamp = atol(ts_ptr + 5);
        }

        printf("[Parent] UDP from %s: %s\n", child_ip, buffer);
        add_peer(child_ip, timestamp);
        print_peer_table();
    }

    closesocket(udp_sock);
    return 0;
}

/*
 * ============================================================================
 * HELPER FUNCTION: Start UDP listener thread for parent mode
 * ============================================================================
 */
int start_listener_thread(void) {
    HANDLE thread = CreateThread(NULL, 0, listener_thread, NULL, 0, NULL);
    if (thread == NULL) {
        fprintf(stderr, "Failed to create listener thread\n");
        return -1;
    }
    return 0;
}

/*
 * ============================================================================
 * MAIN FUNCTION
 * ============================================================================
 */
int main(int argc, char *argv[]) {
    const char *ip = NULL;
    int port = 0;
    const char *host = "www.microsoft.com";
    const char *user_agent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/144.0.0.0 Safari/537.36";

    /* Parse command-line arguments */
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--help") == 0) {
            print_usage(argv[0]);
            return 0;
        }
        else if (strcmp(argv[i], "--ip") == 0 || strcmp(argv[i], "-i") == 0) {
            if (i + 1 < argc) {
                ip = argv[++i];
            } else {
                fprintf(stderr, "Error: %s requires a value\n", argv[i]);
                return 1;
            }
        }
        else if (strcmp(argv[i], "--port") == 0 || strcmp(argv[i], "-p") == 0) {
            if (i + 1 < argc) {
                port = atoi(argv[++i]);
            } else {
                fprintf(stderr, "Error: %s requires a value\n", argv[i]);
                return 1;
            }
        }
        else if (strcmp(argv[i], "--host") == 0 || strcmp(argv[i], "-h") == 0) {
            if (i + 1 < argc) {
                host = argv[++i];
            } else {
                fprintf(stderr, "Error: %s requires a value\n", argv[i]);
                return 1;
            }
        }
        else if (strcmp(argv[i], "--ua") == 0 || strcmp(argv[i], "-u") == 0) {
            if (i + 1 < argc) {
                user_agent = argv[++i];
            } else {
                fprintf(stderr, "Error: %s requires a value\n", argv[i]);
                return 1;
            }
        }
        else if (strcmp(argv[i], "--listen") == 0 || strcmp(argv[i], "-l") == 0) {
            if (i + 1 < argc) {
                listen_port = atoi(argv[++i]);
                is_parent_mode = 1;
            } else {
                fprintf(stderr, "Error: %s requires a value\n", argv[i]);
                return 1;
            }
        }
        else if (strcmp(argv[i], "--interval") == 0 || strcmp(argv[i], "-t") == 0) {
            if (i + 1 < argc) {
                child_interval = atoi(argv[++i]);
                if (child_interval < 1) child_interval = 1;
            } else {
                fprintf(stderr, "Error: %s requires a value\n", argv[i]);
                return 1;
            }
        }
        else if (strcmp(argv[i], "--parent") == 0 || strcmp(argv[i], "-P") == 0) {
            if (i + 1 < argc) {
                char *parent_arg = argv[++i];
                char *colon = strchr(parent_arg, ':');
                if (colon) {
                    size_t ip_len = colon - parent_arg;
                    if (ip_len >= sizeof(parent_ip)) ip_len = sizeof(parent_ip) - 1;
                    strncpy(parent_ip, parent_arg, ip_len);
                    parent_ip[ip_len] = '\0';
                    parent_port = atoi(colon + 1);
                    is_child_mode = 1;
                } else {
                    fprintf(stderr, "Error: --parent requires ip:port format\n");
                    return 1;
                }
            } else {
                fprintf(stderr, "Error: %s requires a value\n", argv[i]);
                return 1;
            }
        }
        else {
            fprintf(stderr, "Error: Unknown argument '%s'\n", argv[i]);
            print_usage(argv[0]);
            return 1;
        }
    }

    /* Validate required arguments */
    if (!is_child_mode && (ip == NULL || port == 0)) {
        fprintf(stderr, "Error: --ip and --port are required (or use --parent for child mode)\n\n");
        print_usage(argv[0]);
        return 1;
    }

    /* Initialize Winsock */
    WSADATA wsa;
    if (WSAStartup(MAKEWORD(2, 2), &wsa) != 0) {
        fprintf(stderr, "WSAStartup failed\n");
        return 1;
    }

    /*
     * ========================================================================
     * CHILD MODE: Simple UDP sender (no TLS, no HTTP)
     * ========================================================================
     */
    if (is_child_mode) {
        printf("Mode: CHILD (UDP to parent %s:%d)\n", parent_ip, parent_port);
        printf("Sending UDP telemetry every %d seconds. Press Ctrl+C to stop.\n\n", child_interval);

        int udp_sock = socket(AF_INET, SOCK_DGRAM, 0);
        if (udp_sock < 0) {
            fprintf(stderr, "Failed to create UDP socket\n");
            WSACleanup();
            return 1;
        }

        struct sockaddr_in parent_addr;
        memset(&parent_addr, 0, sizeof(parent_addr));
        parent_addr.sin_family = AF_INET;
        parent_addr.sin_port = htons(parent_port);
        inet_pton(AF_INET, parent_ip, &parent_addr.sin_addr);

        /* Get our local IP */
        int temp_sock = socket(AF_INET, SOCK_DGRAM, 0);
        connect(temp_sock, (struct sockaddr *)&parent_addr, sizeof(parent_addr));
        struct sockaddr_in local_addr;
        socklen_t local_len = sizeof(local_addr);
        getsockname(temp_sock, (struct sockaddr *)&local_addr, &local_len);
        char my_ip[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &local_addr.sin_addr, my_ip, sizeof(my_ip));
        closesocket(temp_sock);

        char buffer[256];
        while (1) {
            snprintf(buffer, sizeof(buffer), "{\"ip\":\"%s\",\"ts\":%ld}", my_ip, (long)time(NULL));
            sendto(udp_sock, buffer, strlen(buffer), 0,
                   (struct sockaddr *)&parent_addr, sizeof(parent_addr));
            printf("[Child] Sent: %s\n", buffer);
            Sleep(child_interval * 1000);
        }

        closesocket(udp_sock);
        WSACleanup();
        return 0;
    }

    /*
     * ========================================================================
     * PARENT/NORMAL MODE: TLS connection to server
     * ========================================================================
     */
    MUTEX_INIT();

    /* Initialize OpenSSL */
    SSL_library_init();
    SSL_load_error_strings();
    OpenSSL_add_all_algorithms();

    /* Create SSL context */
    const SSL_METHOD *method = TLS_client_method();
    SSL_CTX *ctx = SSL_CTX_new(method);
    if (!ctx) {
        fprintf(stderr, "SSL_CTX_new failed\n");
        return 1;
    }

    /* Configure TLS */
    SSL_CTX_set_min_proto_version(ctx, TLS1_2_VERSION);
    SSL_CTX_set_max_proto_version(ctx, TLS1_3_VERSION);

    if (SSL_CTX_set_ciphersuites(ctx,
            "TLS_AES_128_GCM_SHA256:"
            "TLS_AES_256_GCM_SHA384:"
            "TLS_CHACHA20_POLY1305_SHA256") != 1) {
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }

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

    if (SSL_CTX_set1_curves_list(ctx, "X25519:P-256:P-384") != 1) {
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }

    SSL_CTX_set_options(ctx, SSL_OP_NO_SSLv2 | SSL_OP_NO_SSLv3 | SSL_OP_NO_COMPRESSION);

    if (SSL_CTX_set1_sigalgs_list(ctx, "ecdsa_secp256r1_sha256:rsa_pss_rsae_sha256:rsa_pkcs1_sha256:ecdsa_secp384r1_sha384:rsa_pss_rsae_sha384:rsa_pkcs1_sha384:rsa_pss_rsae_sha512:rsa_pkcs1_sha512") != 1) {
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }

    static const unsigned char alpn_protos[] = {
        2, 'h', '2',
        8, 'h', 't', 't', 'p', '/', '1', '.', '1'
    };
    SSL_CTX_set_alpn_protos(ctx, alpn_protos, sizeof(alpn_protos));
    SSL_CTX_set_tlsext_status_type(ctx, TLSEXT_STATUSTYPE_ocsp);
    SSL_CTX_enable_ct(ctx, SSL_CT_VALIDATION_PERMISSIVE);
    SSL_CTX_clear_options(ctx, SSL_OP_NO_TICKET);

    /* Create TCP socket */
    int sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) {
        fprintf(stderr, "Socket creation failed\n");
        SSL_CTX_free(ctx);
        return 1;
    }

    /* Configure server address */
    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    inet_pton(AF_INET, ip, &addr.sin_addr);

    /* Connect */
    if (connect(sock, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        fprintf(stderr, "Connection failed\n");
        closesocket(sock);
        SSL_CTX_free(ctx);
        return 1;
    }

    SSL_CTX_set_verify(ctx, SSL_VERIFY_NONE, NULL);

    SSL *ssl = SSL_new(ctx);
    SSL_set_tlsext_host_name(ssl, host);
    SSL_set_fd(ssl, sock);

    if (SSL_connect(ssl) <= 0) {
        fprintf(stderr, "TLS handshake failed\n");
        ERR_print_errors_fp(stderr);
        SSL_free(ssl);
        closesocket(sock);
        SSL_CTX_free(ctx);
        return 1;
    }

    printf("Connected to %s:%d\n", ip, port);
    printf("Host: %s\n", host);
    printf("User-Agent: %s\n", user_agent);
    if (is_parent_mode) {
        printf("Mode: PARENT (will listen for UDP on port %d)\n", listen_port);
    } else {
        printf("Mode: NORMAL\n");
    }
    printf("Sending HTTP requests every 10 seconds. Press Ctrl+C to stop.\n\n");

    /* Get our own IP for peer table */
    struct sockaddr_in local_addr;
    socklen_t local_addr_len = sizeof(local_addr);
    char my_ip[INET_ADDRSTRLEN] = "unknown";
    if (getsockname(sock, (struct sockaddr *)&local_addr, &local_addr_len) == 0) {
        inet_ntop(AF_INET, &local_addr.sin_addr, my_ip, sizeof(my_ip));
    }

    char request[4096];
    char response[4096];
    int request_num = 0;
    int got_parent_role = 0;

    add_peer(my_ip, (long)time(NULL));

    while (1) {
        char body[2048];

        if (is_parent_mode && got_parent_role) {
            /* Parent mode: aggregate child data and forward to server */
            build_aggregated_json(body, sizeof(body));

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

            printf("[Parent] Sending aggregated data to server: %s\n", body);

        } else if (request_num % 2 == 0) {
            /* GET request */
            snprintf(request, sizeof(request),
                "GET /api/v1/status HTTP/1.1\r\n"
                "Host: %s\r\n"
                "User-Agent: %s\r\n"
                "Accept: application/json\r\n"
                "Connection: keep-alive\r\n"
                "\r\n",
                host, user_agent);

        } else {
            /* POST request */
            snprintf(body, sizeof(body),
                "{\"status\":\"ok\",\"timestamp\":%ld,\"client_ip\":\"%s\"}",
                (long)time(NULL), my_ip);

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

        int bytes = SSL_write(ssl, request, strlen(request));
        if (bytes <= 0) {
            fprintf(stderr, "SSL_write failed\n");
            ERR_print_errors_fp(stderr);
            break;
        }

        if (!got_parent_role) {
            printf("Sent: %s request\n", (request_num % 2 == 0) ? "GET" : "POST");
        }

        int resp_bytes = SSL_read(ssl, response, sizeof(response) - 1);
        if (resp_bytes <= 0) {
            fprintf(stderr, "SSL_read failed\n");
            ERR_print_errors_fp(stderr);
            break;
        }
        response[resp_bytes] = '\0';

        /* Parse response - find body first, before modifying buffer */
        char *body_start = strstr(response, "\r\n\r\n");

        /* Check for parent role in body BEFORE we modify the buffer */
        int has_parent_role = 0;
        if (body_start) {
            char *body_content = body_start + 4;
            if (is_parent_mode && !got_parent_role) {
                printf("[Debug] Body: %s\n", body_content);
            }
            if (strstr(body_content, "\"role\":\"parent\"")) {
                has_parent_role = 1;
            }
        }

        /* Now safe to modify for display */
        char *newline = strchr(response, '\r');
        if (newline) *newline = '\0';
        printf("Response: %s\n", response);

        if (is_parent_mode && !got_parent_role && has_parent_role) {
            printf("\n*** ASSIGNED AS PARENT NODE ***\n");
            got_parent_role = 1;

            if (start_listener_thread() < 0) {
                fprintf(stderr, "Failed to start listener thread\n");
            }
        }

        if (is_parent_mode && got_parent_role) {
            print_peer_table();
        }

        printf("\n");
        request_num++;

        Sleep(10000);
    }

    listener_running = 0;
    SSL_shutdown(ssl);
    SSL_free(ssl);
    closesocket(sock);
    SSL_CTX_free(ctx);
    MUTEX_DESTROY();
    WSACleanup();

    return 0;
}
