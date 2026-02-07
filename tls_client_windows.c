/*
 * TLS Mesh Client (Windows)
 * ==========================
 *
 * Modes:
 *   PARENT: Connects to server via TLS, receives commands, listens for children via UDP
 *   CHILD:  Sends telemetry to parent via UDP (fire-and-forget)
 *   NORMAL: Basic TLS client for testing
 *
 * Compilation:
 *   gcc tls_client_windows.c -o tls_client.exe -lssl -lcrypto -lws2_32
 *
 * Usage:
 *   Parent: ./tls_client.exe -i <server_ip> -p <port> -l <udp_port> [-t interval]
 *   Child:  ./tls_client.exe -P <parent_ip:port> [-t interval]
 *   Normal: ./tls_client.exe -i <server_ip> -p <port>
 */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <time.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <openssl/ssl.h>
#include <openssl/err.h>

#pragma comment(lib, "ws2_32.lib")

/* ============================================================================
 * CONFIGURATION
 * ============================================================================ */

#define MAX_PEERS 64
#define BUFFER_SIZE 4096

typedef int socklen_t;

/* ============================================================================
 * PEER TABLE - Tracks all known nodes in the mesh
 * ============================================================================ */

typedef struct {
    char ip[16];
    long timestamp;
    int active;
} Peer;

Peer peer_table[MAX_PEERS];
int peer_count = 0;
CRITICAL_SECTION peer_mutex;

/* Thread-safe peer table operations */
void peer_add(const char *ip, long ts) {
    EnterCriticalSection(&peer_mutex);

    /* Update existing peer */
    for (int i = 0; i < peer_count; i++) {
        if (strcmp(peer_table[i].ip, ip) == 0) {
            peer_table[i].timestamp = ts;
            peer_table[i].active = 1;
            LeaveCriticalSection(&peer_mutex);
            return;
        }
    }

    /* Add new peer */
    if (peer_count < MAX_PEERS) {
        strncpy(peer_table[peer_count].ip, ip, 15);
        peer_table[peer_count].ip[15] = '\0';
        peer_table[peer_count].timestamp = ts;
        peer_table[peer_count].active = 1;
        peer_count++;
    }

    LeaveCriticalSection(&peer_mutex);
}

/* Build JSON payload with all peers */
int peer_build_json(char *buf, size_t len) {
    EnterCriticalSection(&peer_mutex);

    int n = snprintf(buf, len, "{\"clients\":[");
    for (int i = 0; i < peer_count; i++) {
        if (i > 0) n += snprintf(buf + n, len - n, ",");
        n += snprintf(buf + n, len - n, "{\"ip\":\"%s\",\"timestamp\":%ld}",
                      peer_table[i].ip, peer_table[i].timestamp);
    }
    n += snprintf(buf + n, len - n, "]}");

    LeaveCriticalSection(&peer_mutex);
    return n;
}

void peer_print(void) {
    EnterCriticalSection(&peer_mutex);
    printf("\n=== Peers (%d) ===\n", peer_count);
    for (int i = 0; i < peer_count; i++) {
        printf("  %s @ %ld\n", peer_table[i].ip, peer_table[i].timestamp);
    }
    printf("==================\n");
    LeaveCriticalSection(&peer_mutex);
}

/* ============================================================================
 * GLOBAL STATE
 * ============================================================================ */

int is_parent = 0;          /* Parent mode enabled */
int is_child = 0;           /* Child mode enabled */
int listen_port = 0;        /* UDP port for children (parent mode) */
char parent_ip[64] = "";    /* Parent IP (child mode) */
int parent_port = 0;        /* Parent port (child mode) */
int interval = 120;         /* Send interval in seconds */
volatile int running = 1;   /* Thread control flag */

/* ============================================================================
 * UDP LISTENER THREAD (Parent Mode)
 * Receives telemetry from child nodes
 * ============================================================================ */

DWORD WINAPI udp_listener(LPVOID arg) {
    int sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock < 0) return 0;

    struct sockaddr_in addr = {0};
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = INADDR_ANY;
    addr.sin_port = htons(listen_port);

    if (bind(sock, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        printf("[!] UDP bind failed on port %d\n", listen_port);
        closesocket(sock);
        return 0;
    }

    printf("[*] UDP listening on port %d\n", listen_port);

    char buf[1024];
    while (running) {
        struct sockaddr_in src;
        socklen_t srclen = sizeof(src);

        int n = recvfrom(sock, buf, sizeof(buf) - 1, 0, (struct sockaddr *)&src, &srclen);
        if (n <= 0) continue;
        buf[n] = '\0';

        /* Get sender IP */
        char ip[16];
        inet_ntop(AF_INET, &src.sin_addr, ip, sizeof(ip));

        /* Parse timestamp from {"ip":"...","ts":123} */
        long ts = (long)time(NULL);
        char *p = strstr(buf, "\"ts\":");
        if (p) ts = atol(p + 5);

        printf("[UDP] %s: %s\n", ip, buf);
        peer_add(ip, ts);
        peer_print();
    }

    closesocket(sock);
    return 0;
}

/* ============================================================================
 * TLS CONFIGURATION
 * ============================================================================ */

SSL_CTX *create_tls_context(void) {
    SSL_library_init();
    SSL_load_error_strings();
    OpenSSL_add_all_algorithms();

    SSL_CTX *ctx = SSL_CTX_new(TLS_client_method());
    if (!ctx) return NULL;

    /* TLS 1.2/1.3 with modern ciphers */
    SSL_CTX_set_min_proto_version(ctx, TLS1_2_VERSION);
    SSL_CTX_set_max_proto_version(ctx, TLS1_3_VERSION);
    SSL_CTX_set_verify(ctx, SSL_VERIFY_NONE, NULL);

    SSL_CTX_set_ciphersuites(ctx,
        "TLS_AES_128_GCM_SHA256:"
        "TLS_AES_256_GCM_SHA384:"
        "TLS_CHACHA20_POLY1305_SHA256");

    SSL_CTX_set_cipher_list(ctx,
        "ECDHE-RSA-AES128-GCM-SHA256:"
        "ECDHE-RSA-AES256-GCM-SHA384:"
        "ECDHE-RSA-CHACHA20-POLY1305");

    return ctx;
}

/* ============================================================================
 * MAIN
 * ============================================================================ */

void usage(const char *prog) {
    printf("TLS Mesh Client (Windows)\n\n");
    printf("Usage:\n");
    printf("  Parent: %s -i <ip> -p <port> -l <udp_port> [-t secs]\n", prog);
    printf("  Child:  %s -P <ip:port> [-t secs]\n", prog);
    printf("\nOptions:\n");
    printf("  -i, --ip        Server IP (required for parent)\n");
    printf("  -p, --port      Server port (required for parent)\n");
    printf("  -l, --listen    UDP port for children (enables parent mode)\n");
    printf("  -P, --parent    Parent address ip:port (enables child mode)\n");
    printf("  -t, --interval  Send interval in seconds (default: 120)\n");
    printf("  -h, --host      SNI hostname (default: www.microsoft.com)\n");
}

int main(int argc, char *argv[]) {
    const char *server_ip = NULL;
    int server_port = 0;
    const char *host = "www.microsoft.com";
    const char *ua = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120.0.0.0";

    /* Parse arguments */
    for (int i = 1; i < argc; i++) {
        if (!strcmp(argv[i], "-i") || !strcmp(argv[i], "--ip")) {
            server_ip = argv[++i];
        } else if (!strcmp(argv[i], "-p") || !strcmp(argv[i], "--port")) {
            server_port = atoi(argv[++i]);
        } else if (!strcmp(argv[i], "-l") || !strcmp(argv[i], "--listen")) {
            listen_port = atoi(argv[++i]);
            is_parent = 1;
        } else if (!strcmp(argv[i], "-P") || !strcmp(argv[i], "--parent")) {
            char *arg = argv[++i];
            char *colon = strchr(arg, ':');
            if (colon) {
                strncpy(parent_ip, arg, colon - arg);
                parent_port = atoi(colon + 1);
                is_child = 1;
            }
        } else if (!strcmp(argv[i], "-t") || !strcmp(argv[i], "--interval")) {
            interval = atoi(argv[++i]);
        } else if (!strcmp(argv[i], "-h") || !strcmp(argv[i], "--host")) {
            host = argv[++i];
        } else if (!strcmp(argv[i], "--help")) {
            usage(argv[0]);
            return 0;
        }
    }

    /* Validate - must be either parent or child mode */
    if (!is_child && !is_parent) {
        printf("Error: Must specify either parent mode (-l) or child mode (-P)\n\n");
        usage(argv[0]);
        return 1;
    }

    if (is_parent && (!server_ip || !server_port)) {
        printf("Error: Parent mode requires -i and -p\n\n");
        usage(argv[0]);
        return 1;
    }

    /* Initialize Winsock */
    WSADATA wsa;
    WSAStartup(MAKEWORD(2, 2), &wsa);
    InitializeCriticalSection(&peer_mutex);

    /* ========================================================================
     * CHILD MODE: Send UDP telemetry to parent
     * ======================================================================== */
    if (is_child) {
        printf("[CHILD] Target: %s:%d, Interval: %ds\n\n", parent_ip, parent_port, interval);

        int sock = socket(AF_INET, SOCK_DGRAM, 0);
        struct sockaddr_in dest = {0};
        dest.sin_family = AF_INET;
        dest.sin_port = htons(parent_port);
        inet_pton(AF_INET, parent_ip, &dest.sin_addr);

        /* Get our IP */
        int tmp = socket(AF_INET, SOCK_DGRAM, 0);
        connect(tmp, (struct sockaddr *)&dest, sizeof(dest));
        struct sockaddr_in local;
        socklen_t len = sizeof(local);
        getsockname(tmp, (struct sockaddr *)&local, &len);
        char my_ip[16];
        inet_ntop(AF_INET, &local.sin_addr, my_ip, sizeof(my_ip));
        closesocket(tmp);

        char buf[256];
        while (1) {
            snprintf(buf, sizeof(buf), "{\"ip\":\"%s\",\"ts\":%ld}", my_ip, (long)time(NULL));
            sendto(sock, buf, strlen(buf), 0, (struct sockaddr *)&dest, sizeof(dest));
            printf("[>] %s\n", buf);
            Sleep(interval * 1000);
        }
    }

    /* ========================================================================
     * PARENT MODE: TLS to server + UDP from children
     * Each cycle: connect -> POST peers -> GET message -> disconnect
     * ======================================================================== */
    if (is_parent) {
        printf("[PARENT] Server: %s:%d, UDP: %d, Interval: %ds\n\n",
               server_ip, server_port, listen_port, interval);

        SSL_CTX *ctx = create_tls_context();
        CreateThread(NULL, 0, udp_listener, NULL, 0, NULL);

        struct sockaddr_in server = {0};
        server.sin_family = AF_INET;
        server.sin_port = htons(server_port);
        inet_pton(AF_INET, server_ip, &server.sin_addr);

        char req[BUFFER_SIZE], res[BUFFER_SIZE], body[2048];

        while (1) {
            printf("\n--- Cycle ---\n");

            /* Connect */
            int sock = socket(AF_INET, SOCK_STREAM, 0);
            if (connect(sock, (struct sockaddr *)&server, sizeof(server)) < 0) {
                printf("[!] Connect failed\n");
                closesocket(sock);
                Sleep(interval * 1000);
                continue;
            }

            /* Get our IP and add to peers */
            struct sockaddr_in local;
            socklen_t len = sizeof(local);
            char my_ip[16];
            if (getsockname(sock, (struct sockaddr *)&local, &len) == 0) {
                inet_ntop(AF_INET, &local.sin_addr, my_ip, sizeof(my_ip));
                peer_add(my_ip, (long)time(NULL));
            }

            /* TLS handshake */
            SSL *ssl = SSL_new(ctx);
            SSL_set_tlsext_host_name(ssl, host);
            SSL_set_fd(ssl, sock);

            if (SSL_connect(ssl) <= 0) {
                printf("[!] TLS failed\n");
                SSL_free(ssl);
                closesocket(sock);
                Sleep(interval * 1000);
                continue;
            }
            printf("[+] TLS connected\n");

            /* POST peer table */
            peer_build_json(body, sizeof(body));
            snprintf(req, sizeof(req),
                "POST /api/v1/telemetry HTTP/1.1\r\n"
                "Host: %s\r\nUser-Agent: %s\r\n"
                "Content-Type: application/json\r\n"
                "Content-Length: %d\r\nConnection: keep-alive\r\n\r\n%s",
                host, ua, (int)strlen(body), body);

            SSL_write(ssl, req, strlen(req));
            printf("[>] POST %s\n", body);

            int n = SSL_read(ssl, res, sizeof(res) - 1);
            if (n > 0) {
                res[n] = '\0';
                char *end = strchr(res, '\r');
                if (end) *end = '\0';
                printf("[<] %s\n", res);
            }

            /* GET message */
            snprintf(req, sizeof(req),
                "GET /api/v1/message HTTP/1.1\r\n"
                "Host: %s\r\nUser-Agent: %s\r\n"
                "Accept: application/json\r\nConnection: close\r\n\r\n",
                host, ua);

            SSL_write(ssl, req, strlen(req));
            n = SSL_read(ssl, res, sizeof(res) - 1);
            if (n > 0) {
                res[n] = '\0';
                /* Extract message from JSON */
                char *msg = strstr(res, "\"message\":\"");
                if (msg) {
                    msg += 11;
                    char *end = strchr(msg, '"');
                    if (end) *end = '\0';
                    printf("\n========================================\n");
                    printf("  SERVER MESSAGE: %s\n", msg);
                    printf("========================================\n");
                }
            }

            /* Disconnect */
            SSL_shutdown(ssl);
            SSL_free(ssl);
            closesocket(sock);
            printf("[-] Disconnected\n");

            peer_print();
            Sleep(interval * 1000);
        }
    }

    return 0;
}
