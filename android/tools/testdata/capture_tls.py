import socket, threading, subprocess, os, time, sys, json, ssl

OUT = sys.argv[1]
os.makedirs(OUT, exist_ok=True)
tmp = os.path.join(OUT, "_tmp"); os.makedirs(tmp, exist_ok=True)
key = os.path.join(tmp, "k.pem"); crt = os.path.join(tmp, "c.pem")
subprocess.run(["openssl", "req", "-x509", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:prime256v1", "-nodes", "-keyout", key, "-out", crt, "-subj", "/CN=test.local", "-days", "3"], check=True, capture_output=True)

def read_record(sock, timeout=3):
    sock.settimeout(timeout)
    hdr = b""
    while len(hdr) < 5:
        c = sock.recv(5 - len(hdr))
        if not c: return hdr
        hdr += c
    n = int.from_bytes(hdr[3:5], "big"); body = b""
    while len(body) < n:
        c = sock.recv(n - len(body))
        if not c: break
        body += c
    return hdr + body

def capture(name, client_cmd, server_args, port):
    srv = subprocess.Popen(["openssl", "s_server", "-accept", str(port), "-cert", crt, "-key", key, "-quiet", "-www"] + server_args, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    time.sleep(0.6)
    lsock = socket.socket(); lsock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1); lsock.bind(("127.0.0.1", port + 1)); lsock.listen(1)
    cli = subprocess.Popen(client_cmd(port + 1), stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    lsock.settimeout(5); c, _ = lsock.accept()
    up = socket.create_connection(("127.0.0.1", port))
    ch = read_record(c); up.sendall(ch)
    sh = read_record(up)
    try: c.sendall(sh)
    except Exception: pass
    cli.kill(); srv.kill(); c.close(); up.close(); lsock.close()
    open(os.path.join(OUT, name + "_client.hex"), "w").write(ch.hex())
    open(os.path.join(OUT, name + "_server.hex"), "w").write(sh.hex())
    print(name, len(ch), len(sh), ch[:6].hex(), sh[:6].hex())

capture("openssl13", lambda p: ["openssl", "s_client", "-connect", f"127.0.0.1:{p}", "-servername", "example.com", "-alpn", "h2,http/1.1"], [], 18500)
capture("openssl12", lambda p: ["openssl", "s_client", "-connect", f"127.0.0.1:{p}", "-servername", "legacy.example.org", "-tls1_2"], [], 18510)
capture("openssl_nosni", lambda p: ["openssl", "s_client", "-connect", f"127.0.0.1:{p}", "-noservername"], [], 18520)

# Python ssl 클라이언트 (다른 확장 구성)
def py_client(name, port, sni, ctx_setup=None):
    srv = subprocess.Popen(["openssl", "s_server", "-accept", str(port), "-cert", crt, "-key", key, "-quiet", "-www"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    time.sleep(0.6)
    lsock = socket.socket(); lsock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1); lsock.bind(("127.0.0.1", port + 1)); lsock.listen(1)
    def go():
        ctx = ssl.create_default_context(); ctx.check_hostname = False; ctx.verify_mode = ssl.CERT_NONE
        ctx.set_alpn_protocols(["h2", "http/1.1"])
        if ctx_setup: ctx_setup(ctx)
        try:
            s = socket.create_connection(("127.0.0.1", port + 1), timeout=3); w = ctx.wrap_socket(s, server_hostname=sni)
        except Exception: pass
    t = threading.Thread(target=go, daemon=True); t.start()
    lsock.settimeout(5); c, _ = lsock.accept()
    up = socket.create_connection(("127.0.0.1", port))
    ch = read_record(c); up.sendall(ch); sh = read_record(up)
    open(os.path.join(OUT, name + "_client.hex"), "w").write(ch.hex()); open(os.path.join(OUT, name + "_server.hex"), "w").write(sh.hex())
    print(name, len(ch), len(sh)); srv.kill(); c.close(); up.close(); lsock.close()

py_client("python13", 18530, "api.example.org")
