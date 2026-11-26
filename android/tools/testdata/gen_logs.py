import random, json, datetime, collections, os
OUT = os.path.join(os.path.dirname(os.path.abspath(__file__)), '../../app/src/test/resources/netlog')
rnd = random.Random(20231010)
tz = datetime.timezone(datetime.timedelta(hours=9))
MON = ['Jan','Feb','Mar','Apr','May','Jun','Jul','Aug','Sep','Oct','Nov','Dec']
def apache_ts(t): return "%02d/%s/%d:%02d:%02d:%02d +0900" % (t.day, MON[t.month-1], t.year, t.hour, t.minute, t.second)

# ---------------- access.log ----------------
UAS = {
 "chrome": ("Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/118.0.0.0 Safari/537.36", "Chrome"),
 "firefox": ("Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:109.0) Gecko/20100101 Firefox/118.0", "Firefox"),
 "safari": ("Mozilla/5.0 (iPhone; CPU iPhone OS 16_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/16.0 Mobile/15E148 Safari/604.1", "Safari"),
 "googlebot": ("Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)", "Googlebot"),
 "curl": ("curl/8.1.2", "curl"),
 "py": ("python-requests/2.31.0", "python-requests"),
 "none": ("-", "(없음)"),
}
BOT_KEYS = {"googlebot","curl","py","none"}      # 봇·자동 요청으로 세는 것
normal_ips = ["203.0.113.%d" % i for i in range(10, 22)] + ["198.51.100.%d" % i for i in range(30, 36)]
paths = ["/", "/index.html", "/about", "/products?id=%d", "/api/items?page=%d", "/static/app.js", "/static/site.css", "/images/logo.png", "/login", "/contact"]
lines = []; expected = collections.defaultdict(int)
base = datetime.datetime(2023, 10, 10, 9, 0, 0, tzinfo=tz)
events = []       # (time, line, ip, status, bytes, path, method, uakey)
def add(t, ip, method, path, status, size, uakey, ref="-"):
    ua = UAS[uakey][0]
    events.append((t, '%s - - [%s] "%s %s HTTP/1.1" %d %d "%s" "%s"' % (ip, apache_ts(t), method, path, status, size, ref, ua), ip, status, size, path, method, uakey))
for n in range(400):
    t = base + datetime.timedelta(seconds=rnd.randint(0, 3*3600-1))
    ip = rnd.choice(normal_ips); p = rnd.choice(paths)
    if '%d' in p: p = p % rnd.randint(1, 50)
    uak = rnd.choices(["chrome","firefox","safari","googlebot","curl","py","none"], [40,20,20,8,5,4,3])[0]
    st = rnd.choices([200,200,200,301,304,404,500], [60,60,60,10,10,10,2])[0]
    add(t, ip, rnd.choice(["GET","GET","GET","POST"]), p, st, rnd.randint(0, 50000) if st != 304 else 0, uak)
# 심어 둔 공격
A="192.0.2.66"; B="192.0.2.77"; C="192.0.2.88"; D="192.0.2.99"; E="192.0.2.111"
for k in range(3): add(base+datetime.timedelta(minutes=5+k), A, "GET", "/../../etc/passwd", 400, 150, "chrome")
for k in range(5): add(base+datetime.timedelta(minutes=20+k), B, "POST", "/wp-login.php", 200, 5000, "chrome")
for k in range(2): add(base+datetime.timedelta(minutes=40+k), C, "GET", "/.env", 404, 150, "firefox")
for k in range(4): add(base+datetime.timedelta(minutes=60+k), D, "GET", "/index.php?id=%d" % k, 200, 900, "chrome")
events[-1] = None  # placeholder, replaced below
events.pop()
# D 는 도구 User-Agent 로 접속 (sqlmap)
UAS["sqlmap"] = ("sqlmap/1.7.2#stable (https://sqlmap.org)", "sqlmap/1.7.2#stable (https://sqlmap.org)"[:30])
for k in range(4): add(base+datetime.timedelta(minutes=60+k), D, "GET", "/index.php?id=%d" % k, 200, 900, "sqlmap")
for k in range(30): add(base+datetime.timedelta(minutes=100, seconds=k*3), E, "GET", "/p%d.php" % k, 404, 150, "curl")
events = [e for e in events if e is not None]
events.sort(key=lambda e: e[0])
raw = [e[1] for e in events]
raw.insert(100, "this is not a log line"); raw.insert(300, ""); raw.insert(301, "garbage ] [ \" \"")
open(OUT+'/access.log','w',encoding='utf-8').write("\n".join(raw)+"\n")
cnt_ip = collections.Counter(e[2] for e in events); cnt_status = collections.Counter(e[3] for e in events)
cnt_path = collections.Counter(e[5].split('?')[0] for e in events); cnt404 = collections.Counter(e[5].split('?')[0] for e in events if e[3]==404)
cnt_method = collections.Counter(e[6] for e in events)
fam = collections.Counter(UAS[e[7]][1] for e in events)
def top(c, n): return sorted(c.items(), key=lambda kv: (-kv[1], kv[0]))[:n]
per_hour = collections.Counter(e[0].strftime("%Y-%m-%d %H") for e in events)
bots = sum(1 for e in events if e[7] in BOT_KEYS)
exp = {"total": len(events), "skipped": 2, "ips": len(cnt_ip), "status": dict(cnt_status), "methods": dict(cnt_method), "topIps": top(cnt_ip, 10), "topPaths": top(cnt_path, 10), "top404": top(cnt404, 10),
       "agents": dict(fam), "bytes": sum(e[4] for e in events), "perHour": dict(per_hour), "bots": bots, "first": min(e[0] for e in events).strftime("%Y-%m-%d %H:%M:%S +0900"), "last": max(e[0] for e in events).strftime("%Y-%m-%d %H:%M:%S +0900"),
       "planted": {"traversal": [A,3], "wp": [B,5], "env": [C,2], "sqlmap": [D,4], "scanner": [E,30]}}
json.dump(exp, open(OUT+'/access.json','w'), ensure_ascii=False, indent=1)

# ---------------- auth.log ----------------
alines = []; truth = collections.Counter(); users_truth = collections.Counter(); succ = []
t0 = datetime.datetime(2023, 10, 10, 0, 0, 0)
def sys_ts(t): return "%s %2d %02d:%02d:%02d" % (MON[t.month-1], t.day, t.hour, t.minute, t.second)
pid = 1000
def emit(t, msg):
    global pid; pid += 1; alines.append((t, "%s srv sshd[%d]: %s" % (sys_ts(t), pid, msg)))
brute = {"203.0.113.9": 14, "203.0.113.10": 6, "198.51.100.200": 25}
usernames = ["root","admin","test","ubuntu","oracle","postgres","pi"]
t = t0
for ip, n in brute.items():
    for k in range(n):
        t = t + datetime.timedelta(seconds=rnd.randint(1, 30)); u = rnd.choice(usernames); port = rnd.randint(30000, 60000)
        invalid = u not in ("root","ubuntu")
        if invalid: emit(t, "Invalid user %s from %s port %d" % (u, ip, port))
        emit(t, "Failed password for %s%s from %s port %d ssh2" % ("invalid user " if invalid else "", u, ip, port))
        if invalid and k % 2 == 0: emit(t, "Connection closed by invalid user %s %s port %d [preauth]" % (u, ip, port))
        truth[ip] += 1; users_truth[u] += 1
# 스캐너: 인증 전에 끊기만 하는 IP (Failed 줄 없음)
for k in range(8):
    t = t + datetime.timedelta(seconds=7); port = rnd.randint(30000, 60000)
    emit(t, "Connection closed by authenticating user root 192.0.2.5 port %d [preauth]" % port); truth["192.0.2.5"] += 1; users_truth["root"] += 1
# 정상 로그인 두 건 + 많이 실패한 IP 의 성공(침해 의심)
t = t + datetime.timedelta(minutes=3); emit(t, "Accepted publickey for ubuntu from 192.0.2.10 port 40022 ssh2: ED25519 SHA256:abc"); succ.append(("ubuntu","192.0.2.10","publickey"))
t = t + datetime.timedelta(minutes=1); emit(t, "Accepted password for admin from 203.0.113.9 port 51111 ssh2"); succ.append(("admin","203.0.113.9","password"))
alines.append((t, "%s srv sudo: pam_unix(sudo:session): session opened for user root" % sys_ts(t)))
alines.append((t, "%s srv CRON[55]: pam_unix(cron:session): session opened" % sys_ts(t)))
alines.sort(key=lambda x: x[0])
open(OUT+'/auth.log','w',encoding='utf-8').write("\n".join(l for _, l in alines)+"\n")
json.dump({"attempts": dict(truth), "users": dict(users_truth), "success": succ, "total": sum(truth.values())}, open(OUT+'/auth.json','w'), indent=1)

# ---------------- syslog ----------------
progs = {"kernel": 40, "sshd": 30, "CRON": 50, "systemd": 60, "nginx": 20}
slines = []; prog_truth = collections.Counter(); sev = collections.Counter()
t = datetime.datetime(2023, 10, 10, 8, 0, 0)
msgs = {"kernel": ["usb 1-1: new high-speed USB device number %d", "eth0: link up", "Out of memory: Killed process %d (java)", "EXT4-fs error (device sda1): ext4_find_entry: reading directory"],
        "sshd": ["Accepted publickey for ubuntu from 192.0.2.%d port 40022", "error: maximum authentication attempts exceeded for root from 203.0.113.%d port 4000", "Server listening on 0.0.0.0 port %d."],
        "CRON": ["(root) CMD (run-parts /etc/cron.hourly) #%d", "(www-data) CMD (php /var/www/cron.php)"],
        "systemd": ["Started Session %d of user ubuntu.", "Reloading.", "nginx.service: Failed with result 'exit-code'.", "Started Daily apt download activities."],
        "nginx": ["worker process %d exited on signal 11", "open() \"/var/www/x\" failed (2: No such file or directory)", "client sent invalid request while reading client request line"]}
import re
sev_res = [("치명", re.compile(r"\b(panic|fatal|emerg|critical|crit)\b", re.I)), ("오류", re.compile(r"\b(error|err|failed|failure|denied|refused|unreachable|segfault|oom|out of memory|killed process|call trace|i/o error|timeout|timed out)\b", re.I)), ("경고", re.compile(r"\b(warn|warning|deprecated|retry|retrying|throttl)", re.I))]
allmsgs = []
for prog, n in progs.items():
    for k in range(n):
        m = rnd.choice(msgs[prog]); m = m % rnd.randint(1, 99) if '%d' in m else m
        allmsgs.append((prog, m))
rnd.shuffle(allmsgs)
for prog, m in allmsgs:
    t += datetime.timedelta(seconds=rnd.randint(1, 20)); slines.append("%s web1 %s[%d]: %s" % (sys_ts(t), prog, rnd.randint(100, 9999), m)); prog_truth[prog] += 1
    for name, rx in sev_res:
        if rx.search(m): sev[name] += 1; break
slines.insert(50, "-- Logs begin at Tue 2023-10-10 --"); 
open(OUT+'/syslog.txt','w',encoding='utf-8').write("\n".join(slines)+"\n")
json.dump({"total": sum(prog_truth.values()), "progs": dict(prog_truth), "sev": dict(sev)}, open(OUT+'/syslog.json','w'), indent=1)

# ---------------- jsonl ----------------
jl = []; lv = collections.Counter(); users = collections.Counter(); keys = collections.Counter(); ts = []
t = datetime.datetime(2023, 10, 10, 1, 0, 0, tzinfo=datetime.timezone.utc)
for k in range(150):
    t += datetime.timedelta(seconds=rnd.randint(1, 5)); level = rnd.choices(["info","warn","error","debug"], [70,15,10,5])[0]
    o = {"time": t.strftime("%Y-%m-%dT%H:%M:%SZ"), "level": level, "msg": rnd.choice(["user login", "db timeout after %dms" % rnd.randint(100, 9999), "cache miss for key %d" % rnd.randint(1, 500)]), "user": rnd.choice(["kim","lee","park","choi"]), "http": {"status": rnd.choice([200,200,404,500])}}
    if k % 10 == 0: o["extra"] = 1
    jl.append(json.dumps(o, ensure_ascii=False)); lv[level] += 1; users[o["user"]] += 1
    for kk in o: keys[kk] += 1
    ts.append(o["time"])
jl.insert(20, "not json at all"); jl.insert(60, "{broken json")
open(OUT+'/app.jsonl','w',encoding='utf-8').write("\n".join(jl)+"\n")
json.dump({"total": 150, "bad": 2, "levels": dict(lv), "users": dict(users), "keys": dict(keys), "first": ts[0], "last": ts[-1], "errors": lv["error"]}, open(OUT+'/jsonl.json','w'), indent=1)

# ---------------- 시간 간격 ----------------
gl = []; t = datetime.datetime(2023, 10, 10, 10, 0, 0); stamps = []
plan = [(60, 10), (60, 15), (1800, 1), (60, 10), (7200, 1), (30, 8)]
for gap, n in plan:
    for k in range(n):
        t += datetime.timedelta(seconds=gap if k == 0 else 60); stamps.append(t); gl.append("%s INFO tick %d" % (t.strftime("%Y-%m-%d %H:%M:%S"), len(gl)))
# gaps ≥ 600초
expected_gaps = []
for k in range(1, len(stamps)):
    d = (stamps[k]-stamps[k-1]).total_seconds()
    if d >= 600: expected_gaps.append([stamps[k-1].strftime("%Y-%m-%d %H:%M:%S"), stamps[k].strftime("%Y-%m-%d %H:%M:%S"), int(d), k+1])
open(OUT+'/ticks.log','w',encoding='utf-8').write("\n".join(gl)+"\n")
deltas = sorted((stamps[k]-stamps[k-1]).total_seconds() for k in range(1, len(stamps)))
json.dump({"count": len(stamps), "gaps": expected_gaps, "max": deltas[-1], "median": deltas[len(deltas)//2], "first": stamps[0].strftime("%Y-%m-%dT%H:%M:%SZ")}, open(OUT+'/ticks.json','w'), indent=1)

# ---------------- HAR ----------------
entries = []; types = [("text/html", "https://www.shop.example/"), ("application/javascript", "https://www.shop.example/app.js"), ("text/css", "https://www.shop.example/site.css"), ("image/png", "https://www.shop.example/a.png"), ("image/jpeg", "https://cdn.other.net/b.jpg"), ("application/json", "https://api.shop.example/items"), ("application/javascript", "https://www.google-analytics.com/analytics.js")]
tot_t = 0; tot_c = 0; slow = []; failed = 0; sumw = 0; third = 0
for k in range(28):
    mime, url = types[k % len(types)]; url2 = url + ("?v=%d" % k)
    status = 200 if k % 9 != 5 else 404
    transfer = rnd.randint(500, 400000); content = transfer * 3 if mime.startswith(("text","application")) else transfer
    wait = rnd.randint(20, 900); recv = rnd.randint(1, 300); tm = {"blocked": 1.5, "dns": 10, "connect": 20, "ssl": 30, "send": 1, "wait": wait, "receive": recv}
    total = sum(tm.values())
    entries.append({"startedDateTime": "2023-10-10T05:00:%02d.000Z" % k, "time": total, "request": {"method": "GET", "url": url2, "headers": []},
                    "response": {"status": status, "httpVersion": "h2" if k % 2 == 0 else "http/1.1", "headers": ([{"name": "Content-Encoding", "value": "gzip"}] if k % 3 == 0 else []), "content": {"size": content, "mimeType": mime + ("; charset=utf-8" if mime.startswith("text") else "")}, "bodySize": transfer, "headersSize": 200, "_transferSize": transfer + 200},
                    "timings": tm, "serverIPAddress": "93.184.216.34"})
    tot_t += transfer + 200; tot_c += content; slow.append(total); sumw += wait
    if status >= 400: failed += 1
    if "shop.example" not in url2: third += 1
har = {"log": {"version": "1.2", "pages": [{"pageTimings": {"onContentLoad": 1234, "onLoad": 3456}}], "entries": entries}}
open(OUT+'/page.har','w',encoding='utf-8').write(json.dumps(har))
slow_sorted = sorted(slow, reverse=True)
json.dump({"count": 28, "transfer": tot_t, "content": tot_c, "failed": failed, "avgWait": sumw/28, "slowest": slow_sorted[:3], "third": third}, open(OUT+'/har.json','w'), indent=1)
print("generated", sorted(os.listdir(OUT)))
