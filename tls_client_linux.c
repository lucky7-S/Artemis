/*
 * ============================================================================
 * TLS/HTTPS Client with Mesh Network Support (Linux)
 * ============================================================================
 *
 * COMPILATION:
 *   Linux:
 *     gcc tls_client_linux.c -o tls_client -lssl -lcrypto -lpthread
 *
 * USAGE:
 *   ./tls_client --ip <addr> --port <num> [options]
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
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <pthread.h>

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
pthread_mutex_t peer_table_mutex = PTHREAD_MUTEX_INITIALIZER;
#define MUTEX_INIT() pthread_mutex_init(&peer_table_mutex, NULL)
#define MUTEX_LOCK() pthread_mutex_lock(&peer_table_mutex)
#define MUTEX_UNLOCK() pthread_mutex_unlock(&peer_table_mutex)
#define MUTEX_DESTROY() pthread_mutex_destroy(&peer_table_mutex)

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

/* Global SSL context for parent's child listener */
SSL_CTX *child_listener_ctx = NULL;

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
    fprintf(stderr, "  --host, -h <name>    Hostname for SNI and Host header\n");
    fprintf(stderr, "  --ua,   -u <string>  User-Agent string\n");
    fprintf(stderr, "  --listen, -l <port>  Listen port for children (enables parent mode)\n");
    fprintf(stderr, "  --help               Show this help message\n");
    fprintf(stderr, "\nExamples:\n");
    fprintf(stderr, "  %s --ip 127.0.0.1 --port 4433\n", program_name);
    fprintf(stderr, "  %s -i 127.0.0.1 -p 4433 -l 4434  (parent mode)\n", program_name);
    fprintf(stderr, "  %s -P 127.0.0.1:4434             (child mode)\n", program_name);
}

/*
 * ============================================================================
 * HELPER FUNCTION: Handle a single child connection
 * ============================================================================
 */
void handle_child_connection(SSL *ssl, const char *child_ip) {
    char buffer[4096];
    char response[1024];

    while (listener_running) {
        int bytes = SSL_read(ssl, buffer, sizeof(buffer) - 1);
        if (bytes <= 0) {
            break;
        }
        buffer[bytes] = '\0';

        char *method_end = strchr(buffer, ' ');
        if (!method_end) continue;

        int is_post = (strncmp(buffer, "POST", 4) == 0);
        printf("[Child %s] %s request\n", child_ip, is_post ? "POST" : "GET");

        if (is_post) {
            char *body_start = strstr(buffer, "\r\n\r\n");
            if (body_start) {
                body_start += 4;
                printf("[Child %s] Body: %s\n", child_ip, body_start);

                char *ts_ptr = strstr(body_start, "\"timestamp\":");
                long timestamp = (long)time(NULL);
                if (ts_ptr) {
                    timestamp = atol(ts_ptr + 12);
                }

                add_peer(child_ip, timestamp);
                print_peer_table();
            }
        }

        const char *resp_body = "{\"received\":true}";
        snprintf(response, sizeof(response),
            "HTTP/1.1 200 OK\r\n"
            "Content-Type: application/json\r\n"
            "Content-Length: %d\r\n"
            "Connection: keep-alive\r\n"
            "\r\n"
            "%s",
            (int)strlen(resp_body), resp_body);

        SSL_write(ssl, response, strlen(response));
    }

    SSL_shutdown(ssl);
    SSL_free(ssl);
}

/*
 * ============================================================================
 * LISTENER THREAD: Accept child connections (Parent Mode)
 * ============================================================================
 */
void *listener_thread(void *arg) {
    int listen_sock = socket(AF_INET, SOCK_STREAM, 0);
    if (listen_sock < 0) {
        fprintf(stderr, "Failed to create listener socket\n");
        return NULL;
    }

    int opt = 1;
    setsockopt(listen_sock, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

    struct sockaddr_in listen_addr;
    memset(&listen_addr, 0, sizeof(listen_addr));
    listen_addr.sin_family = AF_INET;
    listen_addr.sin_addr.s_addr = INADDR_ANY;
    listen_addr.sin_port = htons(listen_port);

    if (bind(listen_sock, (struct sockaddr *)&listen_addr, sizeof(listen_addr)) < 0) {
        fprintf(stderr, "Failed to bind listener on port %d\n", listen_port);
        close(listen_sock);
        return NULL;
    }

    if (listen(listen_sock, 5) < 0) {
        fprintf(stderr, "Failed to listen on port %d\n", listen_port);
        close(listen_sock);
        return NULL;
    }

    printf("[Parent] Listening for children on port %d\n", listen_port);

    while (listener_running) {
        struct sockaddr_in child_addr;
        socklen_t child_len = sizeof(child_addr);
        int child_sock = accept(listen_sock, (struct sockaddr *)&child_addr, &child_len);

        if (child_sock < 0) {
            if (listener_running) {
                fprintf(stderr, "Accept failed\n");
            }
            continue;
        }

        char child_ip[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &child_addr.sin_addr, child_ip, sizeof(child_ip));
        printf("[Parent] Child connected from %s\n", child_ip);

        SSL *child_ssl = SSL_new(child_listener_ctx);
        SSL_set_fd(child_ssl, child_sock);

        if (SSL_accept(child_ssl) <= 0) {
            fprintf(stderr, "TLS handshake with child failed\n");
            ERR_print_errors_fp(stderr);
            SSL_free(child_ssl);
            close(child_sock);
            continue;
        }

        handle_child_connection(child_ssl, child_ip);
        close(child_sock);
    }

    close(listen_sock);
    return NULL;
}

/*
 * ============================================================================
 * HELPER FUNCTION: Start listener thread for parent mode
 * ============================================================================
 */
int start_listener_thread(void) {
    child_listener_ctx = SSL_CTX_new(TLS_server_method());
    if (!child_listener_ctx) {
        fprintf(stderr, "Failed to create child listener SSL context\n");
        return -1;
    }

    if (SSL_CTX_use_certificate_file(child_listener_ctx, "cert.pem", SSL_FILETYPE_PEM) <= 0) {
        fprintf(stderr, "Failed to load cert.pem for listener\n");
        ERR_print_errors_fp(stderr);
        return -1;
    }
    if (SSL_CTX_use_PrivateKey_file(child_listener_ctx, "key.pem", SSL_FILETYPE_PEM) <= 0) {
        fprintf(stderr, "Failed to load key.pem for listener\n");
        ERR_print_errors_fp(stderr);
        return -1;
    }

    pthread_t thread;
    if (pthread_create(&thread, NULL, listener_thread, NULL) != 0) {
        fprintf(stderr, "Failed to create listener thread\n");
        return -1;
    }
    pthread_detach(thread);

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
    const char *user_agent = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/144.0.0.0 Safari/537.36";

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
    if (is_child_mode) {
        ip = parent_ip;
        port = parent_port;
    } else if (ip == NULL || port == 0) {
        fprintf(stderr, "Error: --ip and --port are required (or use --parent for child mode)\n\n");
        print_usage(argv[0]);
        return 1;
    }

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
        close(sock);
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
        close(sock);
        SSL_CTX_free(ctx);
        return 1;
    }

    printf("Connected to %s:%d\n", ip, port);
    printf("Host: %s\n", host);
    printf("User-Agent: %s\n", user_agent);
    if (is_child_mode) {
        printf("Mode: CHILD (connecting to parent)\n");
    } else if (is_parent_mode) {
        printf("Mode: PARENT (will listen for children on port %d)\n", listen_port);
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

        if (is_child_mode) {
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

            printf("[Child] Sending telemetry to parent\n");

        } else if (is_parent_mode && got_parent_role) {
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
            snprintf(request, sizeof(request),
                "GET /api/v1/status HTTP/1.1\r\n"
                "Host: %s\r\n"
                "User-Agent: %s\r\n"
                "Accept: application/json\r\n"
                "Connection: keep-alive\r\n"
                "\r\n",
                host, user_agent);

        } else {
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

        if (!is_child_mode && !got_parent_role) {
            printf("Sent: %s request\n", (request_num % 2 == 0) ? "GET" : "POST");
        }

        int resp_bytes = SSL_read(ssl, response, sizeof(response) - 1);
        if (resp_bytes <= 0) {
            fprintf(stderr, "SSL_read failed\n");
            ERR_print_errors_fp(stderr);
            break;
        }
        response[resp_bytes] = '\0';

        char *body_start = strstr(response, "\r\n\r\n");
        char *resp_body = body_start ? body_start + 4 : "";

        char *newline = strchr(response, '\r');
        if (newline) *newline = '\0';
        printf("Response: %s\n", response);

        if (is_parent_mode && !got_parent_role && strstr(resp_body, "\"role\":\"parent\"")) {
            printf("\n*** ASSIGNED AS PARENT NODE ***\n");
            got_parent_role = 1;

            if (start_listener_thread() < 0) {
                fprintf(stderr, "Failed to start listener thread\n");
            }
        }

        if (is_parent_mode && got_parent_role) {
            char *pt_start = strstr(resp_body, "\"peer_table\":");
            if (pt_start) {
                printf("Received peer table from server\n");
                print_peer_table();
            }
        }

        printf("\n");
        request_num++;

        sleep(10);
    }

    listener_running = 0;
    SSL_shutdown(ssl);
    SSL_free(ssl);
    close(sock);
    SSL_CTX_free(ctx);

    if (child_listener_ctx) {
        SSL_CTX_free(child_listener_ctx);
    }

    MUTEX_DESTROY();

    return 0;
}
