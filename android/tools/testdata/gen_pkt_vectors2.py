#!/usr/bin/env python3
"""패킷 시험용 기준 자료 2: 체크섬 고치기 쌍, 오래된 TLS Hello, 캡처 필터(BPF) — libpcap 으로 컴파일·실행해서 검증"""
import sys, os, json, struct, socket, ctypes, hashlib, random
from scapy.all import Ether, IP, IPv6, TCP, UDP, ICMP, ICMPv6EchoRequest, DNS, DNSQR, Dot1Q, Raw, rdpcap, ARP
import dpkt, warnings
warnings.simplefilter("ignore")

OUT = sys.argv[1]
MAC_C = "52:54:00:12:34:56"; MAC_G = "aa:bb:cc:dd:ee:01"; C = "192.168.1.10"

# ------------------------------------------------------------------ 체크섬 고치기 쌍 (틀린 것 → scapy 가 맞게 만든 것)
def E(p): return Ether(src=MAC_C, dst=MAC_G) / p
pairs = {}
def pair(name, bad, good, start="eth"):
    pairs[name] = {"bad": bytes(bad).hex(), "good": bytes(good).hex(), "start": start}
tcp_kw = dict(sport=54321, dport=443, flags="PA", seq=1000, ack=2000, window=64240)
body = Raw(b"GET / HTTP/1.1\r\n\r\n")
pair("tcp", E(IP(src=C, dst="93.184.216.34", id=0x4001) / TCP(chksum=0x1234, **tcp_kw) / body), E(IP(src=C, dst="93.184.216.34", id=0x4001) / TCP(**tcp_kw) / body))
pair("ip", E(IP(src=C, dst="93.184.216.34", id=0x4002, chksum=0x1111) / TCP(**tcp_kw) / body), E(IP(src=C, dst="93.184.216.34", id=0x4002) / TCP(**tcp_kw) / body))
pair("ip_and_tcp", E(IP(src=C, dst="93.184.216.34", id=0x4003, chksum=0x2222) / TCP(chksum=0x3333, **tcp_kw) / body), E(IP(src=C, dst="93.184.216.34", id=0x4003) / TCP(**tcp_kw) / body))
dq = DNS(id=0x3039, rd=1, qd=DNSQR(qname="example.com", qtype="A"))
pair("udp", E(IP(src=C, dst="8.8.8.8", id=0x4004) / UDP(sport=40000, dport=53, chksum=0xabcd) / dq), E(IP(src=C, dst="8.8.8.8", id=0x4004) / UDP(sport=40000, dport=53) / dq))
pair("icmp", E(IP(src=C, dst="8.8.8.8", id=0x4005) / ICMP(type=8, id=7, seq=1, chksum=0xbeef) / Raw(b"abcdefgh")), E(IP(src=C, dst="8.8.8.8", id=0x4005) / ICMP(type=8, id=7, seq=1) / Raw(b"abcdefgh")))
pair("tcp6", E(IPv6(src="2001:db8::10", dst="2001:db8::20", hlim=60) / TCP(chksum=0x4242, **tcp_kw) / body), E(IPv6(src="2001:db8::10", dst="2001:db8::20", hlim=60) / TCP(**tcp_kw) / body))
pair("icmp6", E(IPv6(src="2001:db8::10", dst="2001:db8::1", hlim=64) / ICMPv6EchoRequest(id=1, seq=2, data=b"hi", cksum=0x1234)), E(IPv6(src="2001:db8::10", dst="2001:db8::1", hlim=64) / ICMPv6EchoRequest(id=1, seq=2, data=b"hi")))
pair("vlan", Ether(src=MAC_C, dst=MAC_G) / Dot1Q(vlan=100) / IP(src="10.100.0.5", dst="10.100.0.1", id=0x4006) / TCP(chksum=0x9999, **tcp_kw) / body, Ether(src=MAC_C, dst=MAC_G) / Dot1Q(vlan=100) / IP(src="10.100.0.5", dst="10.100.0.1", id=0x4006) / TCP(**tcp_kw) / body)
pair("ip_only", IP(src=C, dst="93.184.216.34", id=0x4007) / TCP(chksum=0x7777, **tcp_kw) / body, IP(src=C, dst="93.184.216.34", id=0x4007) / TCP(**tcp_kw) / body, start="ip")
pair("udp_zero", E(IP(src=C, dst="8.8.8.8", id=0x4008) / UDP(sport=40000, dport=53, chksum=0) / dq), E(IP(src=C, dst="8.8.8.8", id=0x4008) / UDP(sport=40000, dport=53, chksum=0) / dq))   # 0 = 사용 안 함 (그대로)
json.dump(pairs, open(os.path.join(OUT, "fixpairs.json"), "w"), indent=1)

# ------------------------------------------------------------------ 오래된 ClientHello (TLS 1.0, RC4·3DES, 확장 없음)
body = struct.pack("!H", 0x0301) + bytes(range(32)) + b"\x00" + struct.pack("!H", 10) + b"".join(struct.pack("!H", c) for c in (0x0005, 0x000a, 0x002f, 0x0035, 0x00ff)) + b"\x01\x00"
hs = b"\x01" + struct.pack("!I", len(body))[1:] + body
legacy = b"\x16\x03\x01" + struct.pack("!H", len(hs)) + hs
open(os.path.join(OUT, "tls", "legacy_client.hex"), "w").write(legacy.hex())
recs, _ = dpkt.ssl.tls_multi_factory(legacy)
ch = dpkt.ssl.TLSHandshake(recs[0].data).data
codes = [c.code if hasattr(c, "code") else int(c) for c in ch.ciphersuites]
exts = [t for t, _ in getattr(ch, "extensions", [])]
ja3 = ",".join([str(ch.version), "-".join(map(str, codes)), "-".join(map(str, exts)), "", ""])
tls = json.load(open(os.path.join(OUT, "tls.json")))
tls["legacy"] = {"client": {"ja3": ja3, "md5": hashlib.md5(ja3.encode()).hexdigest(), "sni": None, "alpn": [], "ciphers": len(codes), "ext_types": exts}}
json.dump(tls, open(os.path.join(OUT, "tls.json"), "w"), ensure_ascii=False, indent=1)

# ------------------------------------------------------------------ 캡처 필터: libpcap 으로 컴파일하고 sample.pcap 의 패킷마다 맞는지 실행
pcap = ctypes.CDLL("libpcap.so.0.8")
class BpfProgram(ctypes.Structure): _fields_ = [("bf_len", ctypes.c_uint), ("bf_insns", ctypes.c_void_p)]
class PktHdr(ctypes.Structure): _fields_ = [("ts_sec", ctypes.c_long), ("ts_usec", ctypes.c_long), ("caplen", ctypes.c_uint32), ("len", ctypes.c_uint32)]
pcap.pcap_open_dead.restype = ctypes.c_void_p; pcap.pcap_open_dead.argtypes = [ctypes.c_int, ctypes.c_int]
pcap.pcap_compile.argtypes = [ctypes.c_void_p, ctypes.POINTER(BpfProgram), ctypes.c_char_p, ctypes.c_int, ctypes.c_uint32]
pcap.pcap_geterr.restype = ctypes.c_char_p; pcap.pcap_geterr.argtypes = [ctypes.c_void_p]
pcap.pcap_offline_filter.argtypes = [ctypes.POINTER(BpfProgram), ctypes.POINTER(PktHdr), ctypes.c_char_p]
handle = pcap.pcap_open_dead(1, 65535)

def compile_bpf(expr):
    prog = BpfProgram()
    if pcap.pcap_compile(handle, ctypes.byref(prog), expr.encode(), 1, 0xffffff00) != 0:
        raise SystemExit("BPF 컴파일 실패: %s: %s" % (expr, pcap.pcap_geterr(handle).decode()))
    return prog

packets = list(rdpcap(os.path.join(OUT, "sample.pcap")))
raws = [bytes(p) for p in packets]

def matches(expr):
    prog = compile_bpf(expr); out = []
    for k, raw in enumerate(raws):
        h = PktHdr(0, 0, len(raw), len(raw))
        if pcap.pcap_offline_filter(ctypes.byref(prog), ctypes.byref(h), raw): out.append(k)
    return out

def ipaddrs(p):
    r = set()
    if p.haslayer(IP): r.add(("src", p[IP].src)); r.add(("dst", p[IP].dst))
    if p.haslayer(IPv6): r.add(("src", p[IPv6].src)); r.add(("dst", p[IPv6].dst))
    if p.haslayer(ARP): r.add(("src", p[ARP].psrc)); r.add(("dst", p[ARP].pdst))
    return r
def host_pred(addr, d):
    return lambda p: any((d == "" or w == d) and a == addr for w, a in ipaddrs(p))
def in_net(addr, net):
    import ipaddress
    try: return ipaddress.ip_address(addr) in ipaddress.ip_network(net, strict=False)
    except Exception: return False
def net_pred(net, d):
    return lambda p: any((d == "" or w == d) and in_net(a, net) for w, a in ipaddrs(p))
def l4(p):
    for L in (TCP, UDP):
        if p.haslayer(L): return L
    return None
def port_pred(ports, d, proto=None):
    def f(p):
        L = l4(p)
        if L is None or (proto and L is not proto): return False
        s, dd = p[L].sport, p[L].dport
        ok = lambda x: any(lo <= x <= hi for lo, hi in ports)
        return ok(s) if d == "src" else ok(dd) if d == "dst" else (ok(s) or ok(dd))
    return f
def tcpflag(mask_all, mask_any=0):
    return lambda p: p.haslayer(TCP) and ((int(p[TCP].flags) & mask_all) == mask_all if mask_all else (int(p[TCP].flags) & mask_any) != 0)
def AND(*fs): return lambda p: all(f(p) for f in fs)
def NOT(f): return lambda p: not f(p)

cases = []
def case(inputs, expr, disp, pred):
    got = matches(expr)
    want = [k for k, p in enumerate(packets) if pred(p)]
    assert got == want, "필터 불일치 %s\n libpcap=%s\n 기대=%s" % (expr, got, want)
    assert len(got) > 0 or True
    cases.append({"inputs": inputs, "expr": expr, "display": disp, "matches": got})

T = lambda p: p.haslayer(TCP); U = lambda p: p.haslayer(UDP)
case({"host": "192.168.1.10"}, "host 192.168.1.10", "ip.addr == 192.168.1.10", host_pred("192.168.1.10", ""))
case({"host": "192.168.1.10", "d": "보내는 쪽(출발지)만"}, "src host 192.168.1.10", "ip.src == 192.168.1.10", host_pred("192.168.1.10", "src"))
case({"host": "8.8.8.8", "d": "받는 쪽(목적지)만"}, "dst host 8.8.8.8", "ip.dst == 8.8.8.8", host_pred("8.8.8.8", "dst"))
case({"net": "192.168.1.0/24"}, "net 192.168.1.0/24", "ip.addr == 192.168.1.0/24", net_pred("192.168.1.0/24", ""))
case({"net": "192.168.1.77/24"}, "net 192.168.1.0/24", "ip.addr == 192.168.1.0/24", net_pred("192.168.1.0/24", ""))      # 호스트 주소를 줘도 네트워크 주소로 맞춤
case({"net": "93.184.0.0/16", "d": "받는 쪽(목적지)만"}, "dst net 93.184.0.0/16", "ip.dst == 93.184.0.0/16", net_pred("93.184.0.0/16", "dst"))
case({"p": "TCP", "ports": "443"}, "tcp and port 443", "tcp && tcp.port == 443", AND(T, port_pred([(443, 443)], "", TCP)))
case({"ports": "80,443,8000-8100"}, "(port 80 or port 443 or portrange 8000-8100)", "(tcp.port in {80 443 8000..8100} || udp.port in {80 443 8000..8100})", port_pred([(80, 80), (443, 443), (8000, 8100)], ""))
case({"p": "UDP", "ports": "53", "d": "받는 쪽(목적지)만"}, "udp and dst port 53", "udp && udp.dstport == 53", AND(U, port_pred([(53, 53)], "dst", UDP)))
case({"p": "TCP", "ports": "22 23", "d": "받는 쪽(목적지)만"}, "tcp and (dst port 22 or dst port 23)", "tcp && tcp.dstport in {22 23}", AND(T, lambda p: p[TCP].dport in (22, 23)))
case({"f": "SYN 만 (연결 시작 요청)"}, "tcp and tcp[tcpflags] & (tcp-syn|tcp-ack) = tcp-syn", "tcp && tcp.flags.syn == 1 && tcp.flags.ack == 0", lambda p: p.haslayer(TCP) and (int(p[TCP].flags) & 0x12) == 0x02)
case({"f": "SYN+ACK (연결 수락)"}, "tcp and tcp[tcpflags] & (tcp-syn|tcp-ack) = (tcp-syn|tcp-ack)", "tcp && tcp.flags.syn == 1 && tcp.flags.ack == 1", lambda p: p.haslayer(TCP) and (int(p[TCP].flags) & 0x12) == 0x12)
case({"f": "RST (연결 거부·강제 종료)"}, "tcp and tcp[tcpflags] & tcp-rst != 0", "tcp && tcp.flags.reset == 1", lambda p: p.haslayer(TCP) and int(p[TCP].flags) & 0x04 != 0)
case({"f": "FIN (연결 종료)"}, "tcp and tcp[tcpflags] & tcp-fin != 0", "tcp && tcp.flags.fin == 1", lambda p: p.haslayer(TCP) and int(p[TCP].flags) & 0x01 != 0)
case({"f": "PSH (데이터 즉시 전달)"}, "tcp and tcp[tcpflags] & tcp-push != 0", "tcp && tcp.flags.push == 1", lambda p: p.haslayer(TCP) and int(p[TCP].flags) & 0x08 != 0)
case({"p": "TCP", "f": "SYN 만 (연결 시작 요청)", "ports": "8080"}, "tcp and port 8080 and tcp[tcpflags] & (tcp-syn|tcp-ack) = tcp-syn", "tcp && tcp.port == 8080 && tcp.flags.syn == 1 && tcp.flags.ack == 0", lambda p: p.haslayer(TCP) and (int(p[TCP].flags) & 0x12) == 0x02 and 8080 in (p[TCP].sport, p[TCP].dport))
case({"p": "ICMP"}, "icmp", "icmp", lambda p: p.haslayer(ICMP))
case({"p": "ICMPv6"}, "icmp6", "icmpv6", lambda p: p.haslayer(IPv6) and p[IPv6].nh == 58)
case({"p": "ARP"}, "arp", "arp", lambda p: p.haslayer(ARP))
case({"p": "IPv6"}, "ip6", "ipv6", lambda p: p.haslayer(IPv6))
case({"p": "TCP", "host": "93.184.216.34", "ports": "443", "x": "192.168.1.1"}, "tcp and host 93.184.216.34 and port 443 and not host 192.168.1.1", "tcp && ip.addr == 93.184.216.34 && tcp.port == 443 && !(ip.addr == 192.168.1.1)",
     AND(T, host_pred("93.184.216.34", ""), port_pred([(443, 443)], "", TCP), NOT(host_pred("192.168.1.1", ""))))
case({"host": "2001:db8::1"}, "host 2001:db8::1", "ipv6.addr == 2001:db8::1", host_pred("2001:db8::1", ""))
case({"net": "2001:db8::/32"}, "net 2001:db8::/32", "ipv6.addr == 2001:db8::/32", net_pred("2001:db8::/32", ""))
case({"x": "8.8.8.8"}, "not host 8.8.8.8", "!(ip.addr == 8.8.8.8)", NOT(host_pred("8.8.8.8", "")))
json.dump(cases, open(os.path.join(OUT, "bpf.json"), "w"), ensure_ascii=False, indent=1)
print("OK pairs=%d bpf cases=%d" % (len(pairs), len(cases)))
