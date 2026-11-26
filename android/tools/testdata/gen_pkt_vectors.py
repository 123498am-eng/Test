#!/usr/bin/env python3
"""패킷 엔진 시험용 기준 자료 만들기.
scapy 로 패킷·pcap 을 만들고(체크섬은 scapy 가 계산), dpkt 로 따로 읽어 기대값을 뽑아요. Kotlin 코드와 무관한 구현이라 서로 교차 검증이 돼요."""
import sys, os, json, struct, hashlib, shutil, random, socket
from scapy.all import (Ether, IP, IPv6, TCP, UDP, ICMP, ICMPv6EchoRequest, ICMPv6EchoReply, ARP, DNS, DNSQR, DNSRR, Dot1Q, BOOTP, DHCP, Raw, Padding, PcapWriter, wrpcap)
from scapy.layers.l2 import CookedLinux
import dpkt

OUT = sys.argv[1]
TLS_SRC = sys.argv[2]
os.makedirs(OUT, exist_ok=True)
random.seed(20231010)

MAC_C = "52:54:00:12:34:56"; MAC_G = "aa:bb:cc:dd:ee:01"
C = "192.168.1.10"; G = "192.168.1.1"

def csum(data, init=0):
    s = init
    if len(data) % 2: data += b"\0"
    for i in range(0, len(data), 2): s += (data[i] << 8) | data[i + 1]
    while s >> 16: s = (s & 0xffff) + (s >> 16)
    return s

def v4_pseudo(src, dst, proto, ln):
    return csum(socket.inet_aton(src) + socket.inet_aton(dst) + bytes([0, proto]) + struct.pack("!H", ln))

def v6_pseudo(src, dst, nxt, ln):
    return csum(socket.inet_pton(socket.AF_INET6, src) + socket.inet_pton(socket.AF_INET6, dst) + struct.pack("!I", ln) + bytes([0, 0, 0, nxt]))

# ------------------------------------------------------------------ 패킷 한 개씩
pk = {}
ip_id = [0x1000]
def nid():
    ip_id[0] += 1; return ip_id[0]

def E(p, src=MAC_C, dst=MAC_G): return Ether(src=src, dst=dst) / p

pk["tcp_syn"] = E(IP(src=C, dst="93.184.216.34", ttl=64, id=0x1c46, flags="DF") / TCP(sport=54321, dport=443, flags="S", seq=1000, window=64240,
                  options=[("MSS", 1460), ("SAckOK", b""), ("Timestamp", (1000, 0)), ("NOP", None), ("WScale", 7)]))
pk["tcp_synack"] = E(IP(src="93.184.216.34", dst=C, ttl=57, id=0x0001, flags="DF") / TCP(sport=443, dport=54321, flags="SA", seq=777000, ack=1001, window=65535, options=[("MSS", 1380), ("NOP", None), ("WScale", 8)]), MAC_G, MAC_C)
pk["tcp_http_get"] = E(IP(src=C, dst="93.184.216.34", ttl=128, id=0x2222, flags="DF") / TCP(sport=54322, dport=80, flags="PA", seq=2001, ack=3001, window=502) / Raw(b"GET /index.html HTTP/1.1\r\nHost: example.com\r\nUser-Agent: test\r\n\r\n"))
pk["tcp_rst"] = E(IP(src="192.168.1.20", dst=C, ttl=64, id=0x0003) / TCP(sport=22, dport=54500, flags="RA", seq=0, ack=1, window=0), MAC_G, MAC_C)
pk["tcp_zero_window"] = E(IP(src="192.168.1.30", dst=C, ttl=64, id=0x0004, flags="DF") / TCP(sport=80, dport=54600, flags="A", seq=9000, ack=5101, window=0), MAC_G, MAC_C)
pk["udp_dns_query"] = E(IP(src=C, dst="8.8.8.8", ttl=64, id=0x3333) / UDP(sport=40000, dport=53) / DNS(id=0x3039, rd=1, qd=DNSQR(qname="example.com", qtype="A")))
pk["udp_dns_response"] = E(IP(src="8.8.8.8", dst=C, ttl=117, id=0x4444) / UDP(sport=53, dport=40000) /
                           DNS(id=0x3039, qr=1, rd=1, ra=1, qd=DNSQR(qname="example.com", qtype="A"), an=DNSRR(rrname="example.com", type="A", ttl=300, rdata="93.184.216.34")), MAC_G, MAC_C)
pk["udp_dns_nxdomain"] = E(IP(src="8.8.8.8", dst=C, ttl=117, id=0x4445) / UDP(sport=53, dport=40001) /
                           DNS(id=0x2222, qr=1, rd=1, ra=1, rcode=3, qd=DNSQR(qname="missing.example.org", qtype="A")), MAC_G, MAC_C)
pk["icmp_echo"] = E(IP(src=C, dst="8.8.8.8", ttl=64, id=0x5555) / ICMP(type=8, code=0, id=0x1234, seq=7) / Raw(bytes(range(32))))
pk["icmp_echo_reply"] = E(IP(src="8.8.8.8", dst=C, ttl=117, id=0x5556) / ICMP(type=0, code=0, id=0x1234, seq=7) / Raw(bytes(range(32))), MAC_G, MAC_C)
orig = bytes(IP(src=C, dst=G, ttl=64, id=0x6666) / UDP(sport=40000, dport=5000) / Raw(b"hello"))
pk["icmp_port_unreach"] = E(IP(src=G, dst=C, ttl=64, id=0x7777) / ICMP(type=3, code=3) / Raw(orig[:28]), MAC_G, MAC_C)
pk["icmp_frag_needed"] = E(IP(src="10.20.0.1", dst=C, ttl=250, id=0x7778) / ICMP(type=3, code=4, nexthopmtu=1400) / Raw(bytes(IP(src=C, dst="93.184.216.34", ttl=64, id=0x1, flags="DF") / TCP(sport=1234, dport=443, flags="PA", seq=1))[:28]), MAC_G, MAC_C)
pk["icmp_ttl_exceeded"] = E(IP(src="10.20.0.1", dst=C, ttl=254, id=0x7779) / ICMP(type=11, code=0) / Raw(bytes(IP(src=C, dst="93.184.216.34", ttl=1, id=0x2) / UDP(sport=33434, dport=33434))[:28]), MAC_G, MAC_C)
pk["arp_request"] = E(ARP(op=1, hwsrc=MAC_C, psrc=C, hwdst="00:00:00:00:00:00", pdst=G), dst="ff:ff:ff:ff:ff:ff") / Padding(b"\0" * 18)
pk["arp_reply"] = E(ARP(op=2, hwsrc=MAC_G, psrc=G, hwdst=MAC_C, pdst=C), MAC_G, MAC_C) / Padding(b"\0" * 18)
pk["arp_gratuitous"] = E(ARP(op=1, hwsrc=MAC_C, psrc=C, hwdst="00:00:00:00:00:00", pdst=C), dst="ff:ff:ff:ff:ff:ff") / Padding(b"\0" * 18)
pk["ipv6_icmp_echo"] = E(IPv6(src="fe80::5054:ff:fe12:3456", dst="2001:db8::1", hlim=64, fl=0x12345, tc=0xb8) / ICMPv6EchoRequest(id=0x4321, seq=3, data=b"ping6"))
pk["ipv6_tcp_syn"] = E(IPv6(src="2001:db8::10", dst="2001:db8::20", hlim=60) / TCP(sport=40000, dport=80, flags="S", seq=4242, window=65000))
pk["vlan_tcp"] = Ether(src=MAC_C, dst=MAC_G) / Dot1Q(vlan=100, prio=5) / IP(src="10.100.0.5", dst="10.100.0.1", ttl=64, id=0x8888) / TCP(sport=1111, dport=22, flags="S", seq=1)
pk["dhcp_discover"] = Ether(src=MAC_C, dst="ff:ff:ff:ff:ff:ff") / IP(src="0.0.0.0", dst="255.255.255.255", id=0x9999) / UDP(sport=68, dport=67) / \
    BOOTP(op=1, chaddr=bytes.fromhex("525400123456"), xid=0x12345678, flags=0x8000) / DHCP(options=[("message-type", "discover"), ("client_id", b"\x01" + bytes.fromhex("525400123456")), ("hostname", "my-phone"), ("param_req_list", [1, 3, 6, 15, 28, 51]), "end"])
pk["dhcp_offer"] = Ether(src=MAC_G, dst=MAC_C) / IP(src=G, dst="192.168.1.50", id=0x9998) / UDP(sport=67, dport=68) / \
    BOOTP(op=2, chaddr=bytes.fromhex("525400123456"), xid=0x12345678, yiaddr="192.168.1.50", siaddr=G) / DHCP(options=[("message-type", "offer"), ("server_id", G), ("lease_time", 86400), ("subnet_mask", "255.255.255.0"), ("router", G), ("name_server", G, "8.8.8.8"), ("domain", "home.lan"), ("renewal_time", 43200), ("rebinding_time", 75600), "end"])
# 체크섬이 틀린 것들
pk["bad_tcp_csum"] = E(IP(src=C, dst="93.184.216.34", ttl=64, id=0x1c47, flags="DF") / TCP(sport=54321, dport=443, flags="S", seq=1000, window=64240, chksum=0x1234))
pk["bad_ip_csum"] = E(IP(src=C, dst="93.184.216.34", ttl=64, id=0x1c48, flags="DF", chksum=0x1111) / TCP(sport=54321, dport=443, flags="S", seq=1000, window=64240))
pk["bad_udp_csum"] = E(IP(src=C, dst="8.8.8.8", ttl=64, id=0x3334) / UDP(sport=40000, dport=53, chksum=0xabcd) / DNS(id=0x3039, rd=1, qd=DNSQR(qname="example.com", qtype="A")))
pk["udp_zero_csum"] = E(IP(src=C, dst="8.8.8.8", ttl=64, id=0x3335) / UDP(sport=40000, dport=53, chksum=0) / DNS(id=0x3039, rd=1, qd=DNSQR(qname="example.com", qtype="A")))
pk["ip_option"] = E(IP(src=C, dst="93.184.216.34", ttl=64, id=0x1c49, options=[b"\x94\x04\x00\x00"]) / ICMP(type=8, id=1, seq=1))     # Router Alert 옵션

raw_of = {k: bytes(v) for k, v in pk.items()}
raw_ip = {k: (bytes(v[IP]) if v.haslayer(IP) else bytes(v[IPv6])) for k, v in pk.items() if v.haslayer(IP) or v.haslayer(IPv6)}

# ------------------------------------------------------------------ dpkt 로 따로 읽은 기대값
def mac(b): return ":".join("%02x" % x for x in b)
def tcp_flags(f):
    names = [(0x80, "CWR"), (0x40, "ECE"), (0x20, "URG"), (0x10, "ACK"), (0x08, "PSH"), (0x04, "RST"), (0x02, "SYN"), (0x01, "FIN")]
    return " ".join(n for m, n in names if f & m)

def facts(raw):
    f = {}
    e = dpkt.ethernet.Ethernet(raw)
    f["eth_dst"] = mac(e.dst); f["eth_src"] = mac(e.src)
    off = 14
    if getattr(e, "vlan_tags", None):
        f["vlan_id"] = e.vlan_tags[0].id; f["vlan_prio"] = e.vlan_tags[0].pri; off += 4 * len(e.vlan_tags)
    f["ethertype"] = e.type
    ip = e.data
    if isinstance(ip, dpkt.ip.IP):
        f["l3"] = "ipv4"; f["src"] = socket.inet_ntoa(ip.src); f["dst"] = socket.inet_ntoa(ip.dst); f["ttl"] = ip.ttl; f["proto"] = ip.p; f["ip_id"] = ip.id; f["ip_len"] = ip.len
        hl = ip.hl * 4
        f["ihl"] = hl
        f["ip_csum_ok"] = csum(raw[off:off + hl]) == 0xffff
        seg = raw[off + hl: off + ip.len]
        if ip.p == 6:
            tcp = dpkt.tcp.TCP(seg); f["sport"] = tcp.sport; f["dport"] = tcp.dport; f["seq"] = tcp.seq; f["ack"] = tcp.ack; f["flags"] = tcp_flags(tcp.flags); f["win"] = tcp.win
            f["payload_len"] = len(tcp.data); f["tcp_hdr"] = tcp.off * 4
            f["l4_csum_ok"] = csum(seg, v4_pseudo(f["src"], f["dst"], 6, len(seg))) == 0xffff
        elif ip.p == 17:
            u = dpkt.udp.UDP(seg); f["sport"] = u.sport; f["dport"] = u.dport; f["udp_len"] = u.ulen; f["udp_csum"] = u.sum
            f["l4_csum_ok"] = (u.sum == 0) or csum(seg[:u.ulen], v4_pseudo(f["src"], f["dst"], 17, u.ulen)) == 0xffff
            if 53 in (u.sport, u.dport):
                d = dpkt.dns.DNS(u.data); f["dns_id"] = d.id; f["dns_qr"] = d.qr; f["dns_rcode"] = d.rcode
                f["dns_q"] = [(q.name, q.type) for q in d.qd]; f["dns_an"] = [(a.name, a.type, a.ttl, socket.inet_ntoa(a.rdata) if a.type == 1 else "") for a in d.an]
        elif ip.p == 1:
            ic = dpkt.icmp.ICMP(seg); f["icmp_type"] = ic.type; f["icmp_code"] = ic.code; f["icmp_csum_ok"] = csum(seg) == 0xffff
            if ic.type in (0, 8): f["icmp_id"] = ic.data.id; f["icmp_seq"] = ic.data.seq
    elif isinstance(ip, dpkt.ip6.IP6):
        f["l3"] = "ipv6"; f["src"] = socket.inet_ntop(socket.AF_INET6, ip.src); f["dst"] = socket.inet_ntop(socket.AF_INET6, ip.dst); f["hlim"] = ip.hlim; f["nxt"] = ip.nxt; f["plen"] = ip.plen
        f["flow"] = ip.flow; f["fc"] = ip.fc
        seg = raw[off + 40: off + 40 + ip.plen]
        if ip.nxt == 58:
            f["l4_csum_ok"] = csum(seg, v6_pseudo(f["src"], f["dst"], 58, len(seg))) == 0xffff; f["icmp_type"] = seg[0]; f["icmp_code"] = seg[1]
        elif ip.nxt == 6:
            tcp = dpkt.tcp.TCP(seg); f["sport"] = tcp.sport; f["dport"] = tcp.dport; f["seq"] = tcp.seq; f["flags"] = tcp_flags(tcp.flags); f["win"] = tcp.win
            f["l4_csum_ok"] = csum(seg, v6_pseudo(f["src"], f["dst"], 6, len(seg))) == 0xffff
    elif isinstance(ip, dpkt.arp.ARP):
        f["l3"] = "arp"; f["arp_op"] = ip.op; f["arp_sha"] = mac(ip.sha); f["arp_spa"] = socket.inet_ntoa(ip.spa); f["arp_tha"] = mac(ip.tha); f["arp_tpa"] = socket.inet_ntoa(ip.tpa)
    return f

packets = {}
for k, raw in raw_of.items():
    packets[k] = {"hex": raw.hex(), "facts": facts(raw)}
    if k in raw_ip: packets[k]["ip_hex"] = raw_ip[k].hex()

# scapy 와 dpkt 두 쪽이 같은 체크섬 판정을 하는지 (기준 자료 자체의 자체 점검)
assert packets["tcp_syn"]["facts"]["l4_csum_ok"] and packets["tcp_syn"]["facts"]["ip_csum_ok"]
assert not packets["bad_tcp_csum"]["facts"]["l4_csum_ok"] and packets["bad_tcp_csum"]["facts"]["ip_csum_ok"]
assert not packets["bad_ip_csum"]["facts"]["ip_csum_ok"]
assert not packets["bad_udp_csum"]["facts"]["l4_csum_ok"] and packets["udp_zero_csum"]["facts"]["l4_csum_ok"]
assert packets["ipv6_icmp_echo"]["facts"]["l4_csum_ok"] and packets["ipv6_tcp_syn"]["facts"]["l4_csum_ok"]

json.dump(packets, open(os.path.join(OUT, "packets.json"), "w"), ensure_ascii=False, indent=1)

# ------------------------------------------------------------------ 패킷 만들기 기준 (같은 입력 → scapy 가 만든 바이트)
build = {}
build["icmp_echo"] = bytes(IP(src="192.168.1.10", dst="8.8.8.8", ttl=64, id=1, flags="DF") / ICMP(type=8, id=0x1234, seq=1) / Raw(b"abcdefgh")).hex()
build["udp"] = bytes(IP(src="192.168.1.10", dst="8.8.8.8", ttl=64, id=1, flags="DF") / UDP(sport=40000, dport=53) / Raw(b"\x12\x34\x01\x00")).hex()
build["tcp_syn"] = bytes(IP(src="192.168.1.10", dst="93.184.216.34", ttl=64, id=1, flags="DF") / TCP(sport=54321, dport=443, flags="S", seq=1000, ack=0, window=64240, options=[("MSS", 1460), ("SAckOK", b""), ("NOP", None), ("WScale", 7), ("NOP", None), ("NOP", None)])).hex()
build["tcp_data"] = bytes(IP(src="192.168.1.10", dst="93.184.216.34", ttl=64, id=1, flags="DF") / TCP(sport=54321, dport=80, flags="PA", seq=5, ack=9, window=64240) / Raw(b"hello")).hex()
build["arp_req"] = bytes(Ether(src="52:54:00:12:34:56", dst="ff:ff:ff:ff:ff:ff") / ARP(op=1, hwsrc="52:54:00:12:34:56", psrc="192.168.1.10", hwdst="00:00:00:00:00:00", pdst="192.168.1.1")).hex()
build["wol"] = (b"\xff" * 6 + bytes.fromhex("aabbccddeeff") * 16).hex()
json.dump(build, open(os.path.join(OUT, "build.json"), "w"), indent=1)

# ------------------------------------------------------------------ DHCP / NTP
dh = {}
for k in ("dhcp_discover", "dhcp_offer"):
    raw = raw_of[k]; e = dpkt.ethernet.Ethernet(raw); b = dpkt.dhcp.DHCP(e.data.data.data)
    opts = {}
    for t, d in b.opts: opts[t] = d.hex()
    dh[k] = {"xid": b.xid, "yiaddr": socket.inet_ntoa(struct.pack("!I", b.yiaddr)) if isinstance(b.yiaddr, int) else socket.inet_ntoa(b.yiaddr), "siaddr": socket.inet_ntoa(struct.pack("!I", b.siaddr)) if isinstance(b.siaddr, int) else socket.inet_ntoa(b.siaddr), "chaddr": b.chaddr[:6].hex(":"), "opts": opts, "udp_payload_hex": bytes(e.data.data.data).hex()}
json.dump(dh, open(os.path.join(OUT, "dhcp.json"), "w"), indent=1)

EPOCH = 2208988800
def ntp_ts(sec_unix, frac):  # (정수초, 2^-32 단위 소수)
    return struct.pack("!II", sec_unix + EPOCH, frac)
# 서버 응답: stratum 2, 기준 192.168.1.1(refid IP), poll 6, precision -23, rootdelay 0.0123, rootdisp 0.0345
T1 = (1700000000, 0x20000000)     # 클라이언트가 보낸 시각 (…, .125)
T2 = (1700000000, 0x20000000 + 0x03000000)
T3 = (1700000000, 0x20000000 + 0x03000000 + 0x00100000)
ntp = bytes([(0 << 6) | (4 << 3) | 4, 2, 6, (-23) & 0xff]) + struct.pack("!II", int(0.0123 * 65536), int(0.0345 * 65536)) + socket.inet_aton("192.168.1.1") + ntp_ts(1699999000, 0) + ntp_ts(*T1) + ntp_ts(*T2) + ntp_ts(*T3)
ntp_gps = bytes([(0 << 6) | (4 << 3) | 4, 1, 3, (-20) & 0xff]) + struct.pack("!II", 0, 0) + b"GPS\0" + ntp_ts(1699999999, 0) + ntp_ts(*T1) + ntp_ts(*T2) + ntp_ts(*T3)
def to_float(ts): return ts[0] + ts[1] / 4294967296.0
json.dump({"hex": ntp.hex(), "gps_hex": ntp_gps.hex(), "t1": to_float(T1), "t2": to_float(T2), "t3": to_float(T3),
           "rootdelay": int(0.0123 * 65536) / 65536.0, "rootdisp": int(0.0345 * 65536) / 65536.0}, open(os.path.join(OUT, "ntp.json"), "w"), indent=1)

# ------------------------------------------------------------------ TLS (JA3 기준: dpkt 로 읽은 값으로 Salesforce JA3 규칙 적용)
GREASE = {0x0a0a, 0x1a1a, 0x2a2a, 0x3a3a, 0x4a4a, 0x5a5a, 0x6a6a, 0x7a7a, 0x8a8a, 0x9a9a, 0xaaaa, 0xbaba, 0xcaca, 0xdada, 0xeaea, 0xfafa}
def code(c): return c.code if hasattr(c, "code") else int(c)

def ja3_of(raw):
    recs, _ = dpkt.ssl.tls_multi_factory(raw)
    hs = dpkt.ssl.TLSHandshake(recs[0].data); ch = hs.data
    ciphers = [code(c) for c in ch.ciphersuites]
    ciphers = [c for c in ciphers if c not in GREASE]
    exts = [t for t, _ in ch.extensions if t not in GREASE]
    curves, fmts = [], []
    for t, d in ch.extensions:
        if t == 10:
            n = struct.unpack("!H", d[:2])[0]; curves = [struct.unpack("!H", d[2 + i:4 + i])[0] for i in range(0, n, 2)]; curves = [c for c in curves if c not in GREASE]
        if t == 11:
            n = d[0]; fmts = list(d[1:1 + n])
    s = ",".join([str(ch.version), "-".join(map(str, ciphers)), "-".join(map(str, exts)), "-".join(map(str, curves)), "-".join(map(str, fmts))])
    sni = None
    for t, d in ch.extensions:
        if t == 0 and len(d) > 5: sni = d[5:5 + struct.unpack("!H", d[3:5])[0]].decode()
    alpn = []
    for t, d in ch.extensions:
        if t == 16:
            i = 2
            while i < len(d): n = d[i]; alpn.append(d[i + 1:i + 1 + n].decode()); i += 1 + n
    return {"ja3": s, "md5": hashlib.md5(s.encode()).hexdigest(), "sni": sni, "alpn": alpn, "ciphers": len(ch.ciphersuites), "ext_types": [t for t, _ in ch.extensions]}

def ja3s_of(raw):
    recs, _ = dpkt.ssl.tls_multi_factory(raw)
    hs = dpkt.ssl.TLSHandshake(recs[0].data); sh = hs.data
    exts = [t for t, _ in sh.extensions]
    cs = code(sh.cipher_suite)
    s = ",".join([str(sh.version), str(cs), "-".join(map(str, exts))])
    return {"ja3s": s, "md5": hashlib.md5(s.encode()).hexdigest(), "cipher": cs}

tls_dir = os.path.join(OUT, "tls"); os.makedirs(tls_dir, exist_ok=True)
tls = {}
for n in ("openssl13", "openssl12", "openssl_nosni", "python13"):
    shutil.copy(os.path.join(TLS_SRC, n + "_client.hex"), tls_dir); shutil.copy(os.path.join(TLS_SRC, n + "_server.hex"), tls_dir)
    c = bytes.fromhex(open(os.path.join(TLS_SRC, n + "_client.hex")).read()); s = bytes.fromhex(open(os.path.join(TLS_SRC, n + "_server.hex")).read())
    tls[n] = {"client": ja3_of(c), "server": ja3s_of(s)}

# GREASE 가 들어간 합성 ClientHello (크롬처럼): GREASE 암호군·확장·그룹·버전을 넣고, JA3 는 GREASE 를 빼야 함
def ext(t, body): return struct.pack("!HH", t, len(body)) + body
def build_grease_hello():
    ciphers = [0x0a0a, 0x1301, 0x1302, 0x1303, 0xc02b, 0xc02f, 0xc02c, 0xc030, 0xcca9, 0xcca8, 0xc013, 0xc014, 0x009c, 0x009d, 0x002f, 0x0035]
    sni = b"www.example.net"
    exts = [
        ext(0x1a1a, b""),
        ext(0, struct.pack("!HBH", len(sni) + 3, 0, len(sni)) + sni),
        ext(23, b""), ext(65281, b"\x00"),
        ext(10, struct.pack("!H", 8) + struct.pack("!HHHH", 0x2a2a, 29, 23, 24)),
        ext(11, b"\x01\x00"),
        ext(35, b""),
        ext(16, struct.pack("!H", 12) + b"\x02h2\x08http/1.1"),
        ext(5, b"\x01\x00\x00\x00\x00"),
        ext(13, struct.pack("!H", 8) + struct.pack("!HHHH", 0x0403, 0x0804, 0x0401, 0x0503)),
        ext(43, b"\x08" + struct.pack("!HHHH", 0x3a3a, 0x0304, 0x0303, 0x0302)),
        ext(51, struct.pack("!H", 4 + 1 + 4) + struct.pack("!HH", 0x4a4a, 1) + b"\x00" + struct.pack("!HH", 29, 32)[:0]),
        ext(0x5a5a, b"\x00"),
    ]
    body = struct.pack("!H", 0x0303) + bytes(range(32)) + b"\x20" + bytes(range(32)) + struct.pack("!H", len(ciphers) * 2) + b"".join(struct.pack("!H", c) for c in ciphers) + b"\x01\x00" + struct.pack("!H", sum(map(len, exts))) + b"".join(exts)
    hs = b"\x01" + struct.pack("!I", len(body))[1:] + body
    return b"\x16\x03\x01" + struct.pack("!H", len(hs)) + hs
g = build_grease_hello()
open(os.path.join(tls_dir, "grease_client.hex"), "w").write(g.hex())
tls["grease"] = {"client": ja3_of(g)}
json.dump(tls, open(os.path.join(OUT, "tls.json"), "w"), indent=1)

# ------------------------------------------------------------------ pcap 시나리오
class Cap:
    def __init__(self, base=1700000000.0):
        self.pkts = []; self.t = base; self.base = base
    def add(self, t_off, pkt):
        pkt.time = self.base + t_off; self.pkts.append(pkt)
cap = Cap()
S = "93.184.216.34"
def seg(src, dst, sport, dport, flags, seq, ack=0, payload=b"", win=64240, ttl=64, msrc=MAC_C, mdst=MAC_G):
    p = Ether(src=msrc, dst=mdst) / IP(src=src, dst=dst, ttl=ttl, id=nid(), flags="DF") / TCP(sport=sport, dport=dport, flags=flags, seq=seq, ack=ack, window=win)
    return p / Raw(payload) if payload else p
def to_srv(*a, **k): return seg(C, a[0], *a[1:], **k)
def from_srv(srv, *a, **k): return seg(srv, C, *a, msrc=MAC_G, mdst=MAC_C, ttl=57, **k)

# 1. ARP
cap.add(0.000, Ether(src=MAC_C, dst="ff:ff:ff:ff:ff:ff") / ARP(op=1, hwsrc=MAC_C, psrc=C, hwdst="00:00:00:00:00:00", pdst=G))
cap.add(0.001, Ether(src=MAC_G, dst=MAC_C) / ARP(op=2, hwsrc=MAC_G, psrc=G, hwdst=MAC_C, pdst=C))
cap.add(0.002, Ether(src=MAC_C, dst="ff:ff:ff:ff:ff:ff") / ARP(op=1, hwsrc=MAC_C, psrc=C, hwdst="00:00:00:00:00:00", pdst="192.168.1.99"))
# 2~4. DNS
def dnsq(t, sport, qid, name): cap.add(t, Ether(src=MAC_C, dst=MAC_G) / IP(src=C, dst="8.8.8.8", id=nid()) / UDP(sport=sport, dport=53) / DNS(id=qid, rd=1, qd=DNSQR(qname=name, qtype="A")))
def dnsr(t, sport, qid, name, rcode=0, ans=None):
    d = DNS(id=qid, qr=1, rd=1, ra=1, rcode=rcode, qd=DNSQR(qname=name, qtype="A"))
    if ans: d = DNS(id=qid, qr=1, rd=1, ra=1, rcode=rcode, qd=DNSQR(qname=name, qtype="A"), an=DNSRR(rrname=name, type="A", ttl=300, rdata=ans))
    cap.add(t, Ether(src=MAC_G, dst=MAC_C) / IP(src="8.8.8.8", dst=C, id=nid(), ttl=117) / UDP(sport=53, dport=sport) / d)
dnsq(0.010, 40001, 0x1111, "example.com"); dnsr(0.030, 40001, 0x1111, "example.com", 0, "93.184.216.34")
dnsq(0.040, 40002, 0x2222, "missing.example.org"); dnsr(0.060, 40002, 0x2222, "missing.example.org", 3)
dnsq(0.070, 40003, 0x3333, "timeout.example.net"); dnsq(1.070, 40004, 0x3334, "timeout.example.net")
dnsq(0.080, 40005, 0x4444, "example.com"); dnsr(0.095, 40005, 0x4444, "example.com", 0, "93.184.216.34")
# 5. TLS 접속 (OpenSSL ClientHello, SNI example.com)
ch1 = bytes.fromhex(open(os.path.join(TLS_SRC, "openssl13_client.hex")).read())
cap.add(0.100, to_srv(S, 54321, 443, "S", 1000)); cap.add(0.140, from_srv(S, 443, 54321, "SA", 777000, 1001)); cap.add(0.141, to_srv(S, 54321, 443, "A", 1001, 777001))
cap.add(0.142, to_srv(S, 54321, 443, "PA", 1001, 777001, ch1)); cap.add(0.180, from_srv(S, 443, 54321, "A", 777001, 1001 + len(ch1)))
# 6. 두 조각으로 나뉜 ClientHello (파이썬, 1540바이트, SNI api.example.org)
ch2 = bytes.fromhex(open(os.path.join(TLS_SRC, "python13_client.hex")).read())
cap.add(0.200, to_srv(S, 54400, 443, "S", 5000)); cap.add(0.240, from_srv(S, 443, 54400, "SA", 888000, 5001)); cap.add(0.241, to_srv(S, 54400, 443, "A", 5001, 888001))
cap.add(0.242, to_srv(S, 54400, 443, "A", 5001, 888001, ch2[:1448])); cap.add(0.243, to_srv(S, 54400, 443, "PA", 5001 + 1448, 888001, ch2[1448:]))
# 7. 대답 없는 SYN 3번 (203.0.113.99:8080)
for k, t in enumerate((0.300, 1.300, 3.300)): cap.add(t, to_srv("203.0.113.99", 54450, 8080, "S", 7000))
# 8. 닫힌 포트: SYN → RST
cap.add(0.400, to_srv("192.168.1.20", 54500, 22, "S", 9000)); cap.add(0.401, from_srv("192.168.1.20", 22, 54500, "RA", 0, 9001, win=0))
# 9. HTTP Basic 인증 (평문)
H = "192.168.1.30"
cap.add(0.500, to_srv(H, 54600, 80, "S", 5000)); cap.add(0.501, from_srv(H, 80, 54600, "SA", 9000, 5001)); cap.add(0.502, to_srv(H, 54600, 80, "A", 5001, 9001))
req = b"GET /admin HTTP/1.1\r\nHost: nas.local\r\nAuthorization: Basic dXNlcjpwYXNz\r\n\r\n"
cap.add(0.503, to_srv(H, 54600, 80, "PA", 5001, 9001, req))
# 11. 재전송: 같은 순서 번호·같은 길이의 데이터를 두 번
data100 = b"x" * 100
cap.add(0.700, to_srv(H, 54600, 80, "PA", 5001 + len(req), 9001, data100)); cap.add(0.900, to_srv(H, 54600, 80, "PA", 5001 + len(req), 9001, data100))
# 12. 제로 윈도
cap.add(0.950, from_srv(H, 80, 54600, "A", 9001, 5001 + len(req) + 100, win=0))
# 10. FTP 평문 로그인
F = "192.0.2.21"
cap.add(0.600, to_srv(F, 54700, 21, "S", 100)); cap.add(0.601, from_srv(F, 21, 54700, "SA", 500, 101)); cap.add(0.602, to_srv(F, 54700, 21, "A", 101, 501))
cap.add(0.603, to_srv(F, 54700, 21, "PA", 101, 501, b"USER anonymous\r\n")); cap.add(0.604, to_srv(F, 54700, 21, "PA", 101 + 16, 501, b"PASS guest@example.com\r\n"))
# 13. ping
cap.add(1.000, Ether(src=MAC_C, dst=MAC_G) / IP(src=C, dst="8.8.8.8", id=nid()) / ICMP(type=8, id=1, seq=1) / Raw(b"abcdefgh"))
cap.add(1.020, Ether(src=MAC_G, dst=MAC_C) / IP(src="8.8.8.8", dst=C, id=nid(), ttl=117) / ICMP(type=0, id=1, seq=1) / Raw(b"abcdefgh"))
# 14. UDP → ICMP 포트 도달 불가
u = IP(src=C, dst=G, ttl=64, id=0x6666) / UDP(sport=40000, dport=5000) / Raw(b"hello")
cap.add(1.100, Ether(src=MAC_C, dst=MAC_G) / u)
cap.add(1.101, Ether(src=MAC_G, dst=MAC_C) / IP(src=G, dst=C, id=nid()) / ICMP(type=3, code=3) / Raw(bytes(u)[:28]))
# 15. IPv6 ping
cap.add(1.200, Ether(src=MAC_C, dst=MAC_G) / IPv6(src="2001:db8::10", dst="2001:db8::1", hlim=64) / ICMPv6EchoRequest(id=1, seq=1, data=b"hi"))
cap.add(1.210, Ether(src=MAC_G, dst=MAC_C) / IPv6(src="2001:db8::1", dst="2001:db8::10", hlim=60) / ICMPv6EchoReply(id=1, seq=1, data=b"hi"))
# 16. Telnet
T = "192.168.1.40"
cap.add(1.300, to_srv(T, 54800, 23, "S", 300)); cap.add(1.301, from_srv(T, 23, 54800, "SA", 600, 301)); cap.add(1.302, to_srv(T, 54800, 23, "A", 301, 601))
cap.add(1.303, from_srv(T, 23, 54800, "PA", 601, 301, b"login: ")); cap.add(1.304, to_srv(T, 54800, 23, "PA", 301, 608, b"root\r\n"))
# 17. QUIC 비슷한 UDP/443
cap.add(1.400, Ether(src=MAC_C, dst=MAC_G) / IP(src=C, dst="142.250.0.1", id=nid()) / UDP(sport=50000, dport=443) / Raw(bytes(random.randrange(256) for _ in range(120))))
# 19. 조각 (첫 조각 아님) + 20. IP 아닌 프레임(LLDP)
cap.add(1.500, Ether(src=MAC_C, dst=MAC_G) / IP(src=C, dst="203.0.113.5", id=nid(), proto=17, frag=100, flags=0) / Raw(b"frag" * 10))
cap.add(1.600, Ether(src=MAC_G, dst="01:80:c2:00:00:0e", type=0x88cc) / Raw(b"\x02\x07\x04" + bytes(6) + b"\x04\x03\x02" + b"1\x06\x02\x00\x78\x00\x00"))
cap.pkts.sort(key=lambda p: p.time)

wrpcap(os.path.join(OUT, "sample.pcap"), cap.pkts)                                  # 마이크로초, 리틀 엔디언
w = PcapWriter(os.path.join(OUT, "sample_nano.pcap"), nano=True)
for p in cap.pkts: w.write(p)
w.close()
w = PcapWriter(os.path.join(OUT, "sample_be.pcap"), endianness=">")
for p in cap.pkts: w.write(p)
w.close()
try:
    from scapy.utils import PcapNgWriter
    w = PcapNgWriter(os.path.join(OUT, "sample.pcapng"))
    for p in cap.pkts: w.write(p)
    w.close()
    NG = True
except Exception as ex:
    print("pcapng 작성 실패", ex); NG = False
# 리눅스 SLL / 순수 IP 링크 형식
sll = []; raw = []
for p in cap.pkts:
    if p.haslayer(IP):
        q = CookedLinux(pkttype=0, lladdrtype=1, lladdrlen=6, src=bytes.fromhex("525400123456") + b"\0\0", proto=0x800) / p[IP].copy(); q.time = p.time; sll.append(q)
        r = p[IP].copy(); r.time = p.time; raw.append(r)
wrpcap(os.path.join(OUT, "sample_sll.pcap"), sll)
wrpcap(os.path.join(OUT, "sample_raw.pcap"), raw)
json.dump({"sll_count": len(sll), "raw_count": len(raw)}, open(os.path.join(OUT, "linktypes.json"), "w"))

# ------------------------------------------------------------------ dpkt 로 읽은 기준 통계
def analyze(path):
    f = open(path, "rb")
    rd = dpkt.pcap.Reader(f)
    total = 0; nbytes = 0; first = None; last = None
    l3 = {}; dns_q = {}; dns_pend = {}; dns_ans = set(); dns_fail = []; sni = {}; http = {}; clear = {}; ja3 = {}
    syn = synack = rst = retrans = zero = 0; synsent = {}; answered = set(); rstfrom = {}; icmp_un = []; arpask = {}; arpis = set(); seen = set(); notip = 0
    talk = {}; protos = {}; pending = {}
    for ts, buf in rd:
        total += 1; nbytes += len(buf); tsu = int(round(ts * 1e6))
        if first is None: first = tsu
        last = tsu
        try: e = dpkt.ethernet.Ethernet(buf)
        except Exception: notip += 1; continue
        ip = e.data
        if isinstance(ip, dpkt.arp.ARP):
            l3["ARP"] = l3.get("ARP", 0) + 1; protos["ARP"] = protos.get("ARP", 0) + 1
            if ip.op == 1: k = (socket.inet_ntoa(ip.tpa), socket.inet_ntoa(ip.spa)); arpask[k] = arpask.get(k, 0) + 1
            elif ip.op == 2: arpis.add(socket.inet_ntoa(ip.spa))
            continue
        v6 = isinstance(ip, dpkt.ip6.IP6)
        if not (v6 or isinstance(ip, dpkt.ip.IP)): notip += 1; continue
        l3["IPv6" if v6 else "IPv4"] = l3.get("IPv6" if v6 else "IPv4", 0) + 1
        if v6: src = socket.inet_ntop(socket.AF_INET6, ip.src); dst = socket.inet_ntop(socket.AF_INET6, ip.dst); proto = ip.nxt; data = bytes(ip.data)
        else:
            src = socket.inet_ntoa(ip.src); dst = socket.inet_ntoa(ip.dst); proto = ip.p; data = bytes(ip.data)
            if ip.off & dpkt.ip.IP_OFFMASK: protos["IP 조각"] = protos.get("IP 조각", 0) + 1; continue
        talk[src] = talk.get(src, 0) + len(buf); talk[dst] = talk.get(dst, 0) + len(buf)
        if proto == 6:
            t = dpkt.tcp.TCP(data); sp, dp = t.sport, t.dport; fl = t.flags
            if fl & 0x12 == 0x02: syn += 1; synsent[(dst, dp)] = synsent.get((dst, dp), 0) + 1
            if fl & 0x12 == 0x12: synack += 1; answered.add((src, sp))
            if fl & 0x04: rst += 1; rstfrom[(src, sp)] = rstfrom.get((src, sp), 0) + 1; answered.add((src, sp))
            if t.win == 0 and not fl & 0x06: zero += 1
            pay = bytes(t.data)
            if pay:
                key = (src, sp, dst, dp, t.seq, len(pay))
                if key in seen: retrans += 1
                seen.add(key)
                text = pay[:300].decode("latin1")
                flow = (src, sp, dst, dp)
                if flow in pending and t.seq == pending[flow][0]:
                    pending[flow][1] += pay; pending[flow][0] += len(pay); pay = bytes(pending[flow][1]); is_tls = True
                    if len(pay) >= 5 + struct.unpack("!H", pay[3:5])[0]: del pending[flow]
                    else: continue
                else: is_tls = pay[0] == 0x16 and len(pay) > 5 and pay[1] == 3
                if is_tls:
                    need = 5 + struct.unpack("!H", pay[3:5])[0]
                    if len(pay) < need and flow not in pending:
                        pending[flow] = [t.seq + len(pay), bytearray(pay)]; continue
                    try: r = ja3_of(pay[:need])
                    except Exception: r = None
                    if r:
                        if r["sni"]: sni[r["sni"]] = sni.get(r["sni"], 0) + 1
                        ja3[r["md5"]] = ja3.get(r["md5"], 0) + 1
                elif text.split(" ")[0] in ("GET", "POST", "PUT", "DELETE", "HEAD", "OPTIONS", "PATCH") and "HTTP/1" in text.split("\r\n")[0]:
                    host = None
                    for ln in text.split("\r\n"):
                        if ln.lower().startswith("host:"): host = ln.split(":", 1)[1].strip()
                    k = "%s %s %s" % (host or dst, text.split(" ")[0], text.split(" ")[1][:40]); http[k] = http.get(k, 0) + 1
                if dp == 21 and text[:5] in ("USER ", "PASS "): clear["FTP 로그인(USER/PASS)"] = clear.get("FTP 로그인(USER/PASS)", 0) + 1
                if dp == 23: clear["Telnet(암호화 없는 원격 접속)"] = clear.get("Telnet(암호화 없는 원격 접속)", 0) + 1
                if dp in (80, 8080) and "\r\nAuthorization: Basic " in text: clear["HTTP Basic 인증"] = clear.get("HTTP Basic 인증", 0) + 1
        elif proto == 17:
            u = dpkt.udp.UDP(data)
            if 53 in (u.sport, u.dport):
                try: d = dpkt.dns.DNS(u.data)
                except Exception: continue
                name = "%s %s" % (d.qd[0].name, {1: "A", 28: "AAAA", 15: "MX"}.get(d.qd[0].type, d.qd[0].type)) if d.qd else None
                if d.qr == 0 and name:
                    dns_q[name] = dns_q.get(name, 0) + 1; dns_pend[(src, dst, d.id)] = name
                elif d.qr == 1:
                    dns_ans.add((dst, src, d.id))
                    if d.rcode != 0 and name: dns_fail.append([name, {2: "SERVFAIL", 3: "NXDOMAIN", 5: "REFUSED"}.get(d.rcode, d.rcode)])
        elif proto == 1:
            ic = dpkt.icmp.ICMP(data)
            if ic.type == 3: icmp_un.append("%s → %s: 목적지 도달 불가 · %s" % (src, dst, {3: "포트 도달 불가(그 포트를 듣는 프로그램이 없음)"}.get(ic.code, "코드 %d" % ic.code)))
    syn_un = sorted([[("%s:%d" % k), v] for k, v in synsent.items() if k not in answered])
    unans = sorted(set(v for k, v in dns_pend.items() if k not in dns_ans))
    arp_un = [k[0] for k in arpask if k[0] not in arpis]
    return {"total": total, "bytes": nbytes, "first": first, "last": last, "l3": l3, "dns_q": dns_q, "dns_unanswered": unans, "dns_fail": dns_fail, "sni": sni, "http": http, "syn": syn, "synack": synack, "rst": rst,
            "retrans": retrans, "zero": zero, "syn_unanswered": syn_un, "rst_from": sorted(["%s:%d" % k for k in rstfrom]), "icmp_unreach": icmp_un, "arp_unanswered": arp_un, "cleartext": clear, "notip": notip, "ja3": ja3, "ip_fragments": protos.get("IP 조각", 0)}

exp = analyze(os.path.join(OUT, "sample.pcap"))
# 만든 순서로 알고 있는 정답과 대조 (기준 자료 점검)
assert exp["syn"] == 9 and exp["synack"] == 5, (exp["syn"], exp["synack"])   # 5 정상 접속 + 닫힌 포트 1 + 대답 없음 3
assert exp["syn_unanswered"] == [["203.0.113.99:8080", 3]], exp["syn_unanswered"]
assert exp["retrans"] == 1 and exp["zero"] == 1 and exp["rst"] == 1
assert exp["dns_unanswered"] == ["timeout.example.net A"], exp["dns_unanswered"]
assert exp["dns_fail"] == [["missing.example.org A", "NXDOMAIN"]]
assert exp["arp_unanswered"] == ["192.168.1.99"]
assert exp["cleartext"] == {"FTP 로그인(USER/PASS)": 2, "HTTP Basic 인증": 1, "Telnet(암호화 없는 원격 접속)": 1}, exp["cleartext"]
assert exp["sni"].get("example.com") == 1
exp["n_written"] = len(cap.pkts)
# 읽은 기준 시각은 scapy 가 쓴 값 그대로 (마이크로초)
json.dump(exp, open(os.path.join(OUT, "pcap_expect.json"), "w"), ensure_ascii=False, indent=1)
# 다른 파일 형식도 같은 패킷 수·바이트·시각이어야 함 (읽는 쪽 점검용 기준)
fmt = {}
for n in ("sample.pcap", "sample_nano.pcap", "sample_be.pcap"):
    r = dpkt.pcap.Reader(open(os.path.join(OUT, n), "rb")); items = [(int(round(float(ts) * 1e6)), len(b)) for ts, b in r]
    fmt[n] = {"count": len(items), "first": items[0][0], "last": items[-1][0], "bytes": sum(x[1] for x in items)}
if NG:
    from scapy.all import rdpcap
    ps = rdpcap(os.path.join(OUT, "sample.pcapng")); fmt["sample.pcapng"] = {"count": len(ps), "first": int(round(float(ps[0].time) * 1e6)), "last": int(round(float(ps[-1].time) * 1e6)), "bytes": sum(len(bytes(p)) for p in ps)}
json.dump(fmt, open(os.path.join(OUT, "pcap_formats.json"), "w"), indent=1)
print("OK", exp["total"], "packets;", {k: v for k, v in fmt.items()})
