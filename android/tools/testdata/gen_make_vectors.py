#!/usr/bin/env python3
"""만들기 도구 시험용 기준 자료: croniter(cron), hashlib·ipaddress(ULA), cryptography(X25519), hashlib.pbkdf2_hmac(WPA)"""
import sys, os, json, hashlib, ipaddress, random, base64, struct
from datetime import datetime
from zoneinfo import ZoneInfo
from croniter import croniter
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
from cryptography.hazmat.primitives import serialization

OUT = sys.argv[1]; random.seed(20240301)
os.makedirs(OUT, exist_ok=True)

# ---- cron: croniter 가 계산한 다음 실행 시각
cases = [
 ("*/15 9-18 * * 1-5", "Asia/Seoul", "2024-03-01 09:30"), ("0 0 * * *", "UTC", "2024-02-27 13:00"), ("30 4 1,15 * 5", "UTC", "2024-01-01 00:00"), ("0 */6 * * *", "Asia/Seoul", "2024-03-01 05:59"),
 ("5 4 * * sun", "UTC", "2024-03-01 00:00"), ("0 12 1 jan,jul *", "Asia/Tokyo", "2023-12-31 23:59"), ("0 0 29 2 *", "UTC", "2023-01-01 00:00"), ("*/7 * * * *", "UTC", "2024-03-01 00:00"),
 ("0 9-17/2 * * mon-fri", "America/New_York", "2024-04-01 08:00"), ("15,45 */2 * * *", "Europe/Berlin", "2024-04-01 00:00"), ("59 23 31 * *", "UTC", "2024-01-15 00:00"), ("0 0 1 */3 *", "UTC", "2024-01-01 00:00"),
 ("0 0 * * 0", "UTC", "2024-03-01 00:00"), ("0 0 * * 7", "UTC", "2024-03-01 00:00"), ("@daily", "Asia/Seoul", "2024-03-01 12:00"), ("@weekly", "UTC", "2024-03-01 12:00"), ("@monthly", "UTC", "2024-03-15 12:00"),
 ("@yearly", "UTC", "2024-03-15 12:00"), ("@hourly", "America/Los_Angeles", "2024-04-01 12:34"), ("0 3 * * 1,3,5", "Europe/London", "2024-04-01 00:00"), ("*/5 0-6 * * *", "UTC", "2024-03-01 05:58"),
 ("10 10 10 10 *", "UTC", "2024-03-01 00:00"), ("0 0 13 * 5", "UTC", "2024-01-01 00:00"), ("0 8 1-7 * 1", "Asia/Seoul", "2024-03-01 00:00"), ("1,2,3,59 23 * * *", "UTC", "2024-03-01 23:02"), ("0 0 1 mar-may *", "UTC", "2024-01-01 00:00"),
 ("30 18 * * fri-sun", "Australia/Sydney", "2024-04-01 00:00"), ("* * * * *", "UTC", "2024-03-01 23:58"), ("0 22 * * 1-5", "Asia/Seoul", "2024-03-01 22:00"), ("0 0 15,L * *", "UTC", "2024-03-01 00:00"),
]
out = []
for expr, tz, start in cases:
    if " L" in expr or "L " in expr: continue         # L 은 Quartz 식: 우리 도구는 오류를 내야 하므로 따로 시험
    z = ZoneInfo(tz); st = datetime.strptime(start, "%Y-%m-%d %H:%M").replace(tzinfo=z)
    it = croniter(expr, st); runs = [it.get_next(datetime).strftime("%Y-%m-%d %H:%M") for _ in range(12)]
    out.append({"expr": expr, "tz": tz, "from": start, "runs": runs})
json.dump(out, open(os.path.join(OUT, "cron_cases.json"), "w"), ensure_ascii=False, indent=1)

# ---- ULA (RFC 4193 3.2.2): SHA-1(NTP 시각 8바이트 + EUI-64 8바이트) 의 아래 40비트
def eui64(mac: bytes) -> bytes: return bytes([mac[0] ^ 2]) + mac[1:3] + b"\xff\xfe" + mac[3:]
ula = []
for k in range(8):
    mac = bytes(random.randrange(256) for _ in range(6)); ntp = random.randrange(1 << 63)
    digest = hashlib.sha1(struct.pack(">Q", ntp) + eui64(mac)).digest(); gid = digest[-5:]
    addr = b"\xfd" + gid + b"\x00" * 10
    net = ipaddress.ip_network((addr, 48))
    subs = [str(ipaddress.ip_network((b"\xfd" + gid + struct.pack(">H", n) + b"\x00" * 8, 64))) for n in (0, 1, 2, 10, 255, 256, 4096, 65535)]
    ula.append({"mac": ":".join("%02x" % b for b in mac), "ntp": ntp, "eui64": eui64(mac).hex(), "gid": gid.hex(), "prefix": str(net), "subnets": subs, "subnet_ns": [0, 1, 2, 10, 255, 256, 4096, 65535]})
json.dump(ula, open(os.path.join(OUT, "ula_cases.json"), "w"), indent=1)

# ---- WireGuard: 임의의 32바이트 비밀키 → 공개키 (cryptography 가 안에서 비트 정리)
wg = []
for k in range(8):
    priv = bytes(random.randrange(256) for _ in range(32)); pub = X25519PrivateKey.from_private_bytes(priv).public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    wg.append({"priv": base64.b64encode(priv).decode(), "pub": base64.b64encode(pub).decode()})
json.dump(wg, open(os.path.join(OUT, "wg_cases.json"), "w"), indent=1)

# ---- WPA PSK: PBKDF2-HMAC-SHA1(passphrase, ssid, 4096, 32)
wpa = [{"ssid": "IEEE", "pass": "password", "psk": hashlib.pbkdf2_hmac("sha1", b"password", b"IEEE", 4096, 32).hex()},
       {"ssid": "ThisIsASSID", "pass": "ThisIsAPassword", "psk": hashlib.pbkdf2_hmac("sha1", b"ThisIsAPassword", b"ThisIsASSID", 4096, 32).hex()}]
alphabet = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!#$%&()*+,-./:;<=>?@[]^_{|}~ "
for k in range(4):
    ssid = "net%d-" % k + "".join(random.choice("abcxyz가나다") for _ in range(random.randrange(1, 6))); pw = "".join(random.choice(alphabet) for _ in range(random.randrange(8, 64)))
    if len(ssid.encode()) <= 32: wpa.append({"ssid": ssid, "pass": pw, "psk": hashlib.pbkdf2_hmac("sha1", pw.encode(), ssid.encode(), 4096, 32).hex()})
json.dump(wpa, open(os.path.join(OUT, "wpa_cases.json"), "w"), ensure_ascii=False, indent=1)
print("OK cron", len(out), "ula", len(ula), "wg", len(wg), "wpa", len(wpa))
