package com.selfcheck.app

import org.json.JSONException
import java.time.Instant
import java.time.ZoneOffset

/**
 * 로그·출력 분석 도구 12가지: 서버 로그나 명령어 출력(traceroute·ip addr·ss·dig·iptables·tcpdump 등)을 붙여 넣으면
 * 표와 진단으로 풀어 줘요. 붙여 넣은 글(또는 고른 파일)은 폰 안에서만 분석하고, 국가·통신사는 오프라인 자료로 붙여요.
 */
object LogTools {
    private const val L = NetGroups.LOG
    private const val NOTE_LOCAL = "붙여 넣은 글(또는 고른 파일)은 휴대폰 안에서만 분석해요."

    private fun input(host: ToolHost, i: ToolInput): String {
        host.file("f")?.open()?.let { ins -> return ins.use { s -> val b = s.readUpTo(8_000_000); strictUtf8(b) ?: String(b, Charsets.ISO_8859_1) } }
        return i.raw("t")
    }

    private fun logTool(id: String, title: String, desc: String, sample: String, extra: List<Field> = emptyList(), withFile: Boolean = true, run: (String, ToolInput, ToolHost) -> ToolResult) =
        tool(id, L, title, desc, listOf(multi("t", "붙여 넣을 글", "", sample)) + (if (withFile) listOf(file("f", "또는 파일 (선택)")) else emptyList()) + extra, ToolMode.OFFLINE, NOTE_LOCAL, runLabel = "분석") { i, host, _ ->
            val s = input(host, i); if (s.isBlank()) need("글을 붙여 넣거나 파일을 고르세요") else run(s, i, host)
        }

    private fun bar(n: Int, max: Int) = "█".repeat(maxOf(1, n * 20 / maxOf(1, max)))

    private const val SAMPLE_ACCESS = "203.0.113.7 - - [10/Oct/2023:13:55:36 +0900] \"GET /index.html HTTP/1.1\" 200 2326 \"-\" \"Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/118.0 Safari/537.36\"\n" +
        "198.51.100.23 - - [10/Oct/2023:13:55:40 +0900] \"GET /wp-login.php HTTP/1.1\" 404 196 \"-\" \"Mozilla/5.0 zgrab/0.x\"\n" +
        "198.51.100.23 - - [10/Oct/2023:13:55:41 +0900] \"GET /.env HTTP/1.1\" 404 196 \"-\" \"Mozilla/5.0 zgrab/0.x\"\n" +
        "192.0.2.50 - - [10/Oct/2023:14:02:11 +0900] \"GET /api/items?id=1%20union%20select%201 HTTP/1.1\" 500 512 \"-\" \"curl/8.1\"\n" +
        "203.0.113.7 - - [10/Oct/2023:14:10:00 +0900] \"POST /login HTTP/1.1\" 302 0 \"https://example.com/\" \"Mozilla/5.0 (iPhone) Safari/604.1\"\n" +
        "66.249.66.1 - - [10/Oct/2023:14:11:30 +0900] \"GET /robots.txt HTTP/1.1\" 200 98 \"-\" \"Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)\""

    private const val SAMPLE_AUTH = "Oct 10 13:55:36 server sshd[1234]: Invalid user admin from 203.0.113.9 port 51234\n" +
        "Oct 10 13:55:38 server sshd[1234]: Failed password for invalid user admin from 203.0.113.9 port 51234 ssh2\n" +
        "Oct 10 13:55:41 server sshd[1236]: Failed password for root from 203.0.113.9 port 51240 ssh2\n" +
        "Oct 10 13:55:44 server sshd[1238]: Failed password for root from 203.0.113.9 port 51246 ssh2\n" +
        "Oct 10 14:01:02 server sshd[1301]: Accepted publickey for ubuntu from 192.0.2.10 port 40022 ssh2: ED25519 SHA256:abc\n" +
        "Oct 10 14:30:11 server sshd[1402]: Failed password for ubuntu from 198.51.100.5 port 60001 ssh2\n" +
        "Oct 10 14:30:15 server sshd[1402]: Accepted password for ubuntu from 198.51.100.5 port 60002 ssh2"

    private const val SAMPLE_TRACE = "traceroute to example.com (93.184.216.34), 30 hops max, 60 byte packets\n" +
        " 1  _gateway (192.168.0.1)  1.012 ms  0.934 ms  0.921 ms\n" +
        " 2  10.20.0.1 (10.20.0.1)  4.201 ms  4.188 ms  4.150 ms\n" +
        " 3  * * *\n" +
        " 4  112.174.47.9 (112.174.47.9)  5.800 ms  6.020 ms  5.911 ms\n" +
        " 5  ae-1.r01.example.net (203.0.113.5)  160.442 ms  161.021 ms  160.870 ms\n" +
        " 6  93.184.216.34 (93.184.216.34)  162.100 ms  161.900 ms  162.300 ms"

    private const val SAMPLE_IFACE = "1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN group default qlen 1000\n    link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00\n    inet 127.0.0.1/8 scope host lo\n" +
        "2: eth0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc fq_codel state UP group default qlen 1000\n    link/ether 52:54:00:12:34:56 brd ff:ff:ff:ff:ff:ff\n    inet 192.168.1.10/24 brd 192.168.1.255 scope global dynamic eth0\n    inet6 fe80::5054:ff:fe12:3456/64 scope link\n" +
        "3: wlan0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc noqueue state UP group default qlen 1000\n    link/ether aa:bb:cc:dd:ee:ff brd ff:ff:ff:ff:ff:ff\n    inet 169.254.12.7/16 brd 169.254.255.255 scope link wlan0"

    private const val SAMPLE_SOCKETS = "Netid State  Recv-Q Send-Q Local Address:Port Peer Address:Port Process\n" +
        "tcp   LISTEN 0      128    0.0.0.0:22         0.0.0.0:*     users:((\"sshd\",pid=812,fd=3))\n" +
        "tcp   LISTEN 0      511    0.0.0.0:6379       0.0.0.0:*     users:((\"redis-server\",pid=900,fd=6))\n" +
        "tcp   LISTEN 0      4096   127.0.0.1:5432     0.0.0.0:*     users:((\"postgres\",pid=950,fd=5))\n" +
        "tcp   ESTAB  0      0      192.168.1.10:22    203.0.113.9:51234 users:((\"sshd\",pid=2301,fd=4))\n" +
        "tcp   ESTAB  0      0      192.168.1.10:443   8.8.8.8:50111\n" +
        "tcp   TIME-WAIT 0   0      192.168.1.10:80    198.51.100.7:40000\n" +
        "udp   UNCONN 0      0      127.0.0.53%lo:53   0.0.0.0:*"

    private const val SAMPLE_DIG = "; <<>> DiG 9.18.12 <<>> example.com\n;; global options: +cmd\n;; Got answer:\n;; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 4242\n;; flags: qr rd ra; QUERY: 1, ANSWER: 2, AUTHORITY: 0, ADDITIONAL: 1\n\n" +
        ";; QUESTION SECTION:\n;example.com.\t\t\tIN\tA\n\n;; ANSWER SECTION:\nexample.com.\t\t300\tIN\tA\t93.184.216.34\nexample.com.\t\t300\tIN\tA\t93.184.216.35\n\n;; Query time: 231 msec\n;; SERVER: 8.8.8.8#53(8.8.8.8) (UDP)\n;; WHEN: Tue Oct 10 13:55:36 KST 2023\n;; MSG SIZE  rcvd: 72"

    private const val SAMPLE_FW = "-P INPUT ACCEPT\n-P FORWARD DROP\n-P OUTPUT ACCEPT\n-A INPUT -i lo -j ACCEPT\n-A INPUT -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT\n-A INPUT -p tcp -m tcp --dport 22 -j ACCEPT\n-A INPUT -p tcp -m multiport --dports 80,443 -j ACCEPT\n-A INPUT -p tcp -m tcp --dport 3306 -j ACCEPT\n-A INPUT -s 10.0.0.0/8 -j ACCEPT"

    private const val SAMPLE_DUMP = "13:55:36.100000 IP 192.168.1.10.54321 > 93.184.216.34.443: Flags [S], seq 1000, win 64240, length 0\n13:55:37.100000 IP 192.168.1.10.54321 > 93.184.216.34.443: Flags [S], seq 1000, win 64240, length 0\n" +
        "13:55:38.100000 IP 192.168.1.10.54322 > 93.184.216.35.80: Flags [S], seq 2000, win 64240, length 0\n13:55:38.120000 IP 93.184.216.35.80 > 192.168.1.10.54322: Flags [S.], seq 3000, ack 2001, win 65535, length 0\n" +
        "13:55:38.121000 IP 192.168.1.10.54322 > 93.184.216.35.80: Flags [.], ack 3001, win 502, length 0\n13:55:38.130000 IP 192.168.1.10.54322 > 93.184.216.35.80: Flags [P.], seq 2001:2101, ack 3001, win 502, length 100\n" +
        "13:55:38.330000 IP 192.168.1.10.54322 > 93.184.216.35.80: Flags [P.], seq 2001:2101, ack 3001, win 502, length 100\n13:55:39.000000 IP 192.168.1.10.40000 > 8.8.8.8.53: 12345+ A? example.com. (29)\n13:55:39.010000 IP 8.8.8.8.53 > 192.168.1.10.40000: 12345 1/0/0 A 93.184.216.34 (45)\n" +
        "13:55:40.000000 ARP, Request who-has 192.168.1.1 tell 192.168.1.10, length 28"

    private const val SAMPLE_HAR = "{\"log\":{\"version\":\"1.2\",\"pages\":[{\"pageTimings\":{\"onContentLoad\":850,\"onLoad\":2100}}],\"entries\":[" +
        "{\"startedDateTime\":\"2023-10-10T04:55:36.000Z\",\"time\":420,\"request\":{\"method\":\"GET\",\"url\":\"https://www.example.com/\",\"headers\":[]},\"response\":{\"status\":200,\"httpVersion\":\"h2\",\"headers\":[{\"name\":\"Content-Encoding\",\"value\":\"br\"}],\"content\":{\"size\":48000,\"mimeType\":\"text/html\"},\"bodySize\":9000,\"headersSize\":300},\"timings\":{\"blocked\":2,\"dns\":20,\"connect\":30,\"ssl\":40,\"send\":1,\"wait\":300,\"receive\":27}}," +
        "{\"startedDateTime\":\"2023-10-10T04:55:37.000Z\",\"time\":1800,\"request\":{\"method\":\"GET\",\"url\":\"https://cdn.tracker.net/app.js\",\"headers\":[]},\"response\":{\"status\":200,\"httpVersion\":\"http/1.1\",\"headers\":[],\"content\":{\"size\":350000,\"mimeType\":\"application/javascript\"},\"bodySize\":350000,\"headersSize\":250},\"timings\":{\"blocked\":0,\"dns\":0,\"connect\":0,\"ssl\":0,\"send\":1,\"wait\":200,\"receive\":1599}}]}}"

    val ALL: List<NetTool> = listOf(
        logTool("log_access", "웹 접근 로그 분석 (nginx·apache)", "접속 로그에서 많이 오는 IP·주소·응답 코드·시간대·봇 비율을 세고, 공격 시도(경로 탈출·SQL 주입·.env 찾기·스캐너)를 가려내요", SAMPLE_ACCESS) { s, _, host ->
            val r = AccessLog.summarize(s.lines()); val db = host.geoDb()
            if (r.total == 0) return@logTool fail("읽을 수 있는 줄이 없어요. nginx·apache 의 combined/common 형식(IP - - [날짜] \"GET /주소 HTTP/1.1\" 200 123 …)인지 확인하세요")
            result {
                kv("분석한 줄", "${r.total}줄" + if (r.skipped > 0) " (읽지 못한 줄 ${r.skipped})" else ""); r.first?.let { kv("기간", "$it ~ ${r.last}") }; kv("서로 다른 IP", "${r.ips}개"); kv("전송량(응답 크기 합)", LogUtil.bytes(r.bytes)); kv("봇·자동 요청", "${r.botRequests}건 (${LogUtil.pct(r.botRequests, r.total)})")
                head("응답 코드"); header("코드", "건수", "비율")
                for ((code, n) in r.status.entries.sortedByDescending { it.value }.take(8)) row("$code", "$n", LogUtil.pct(n, r.total), level = if (code >= 500) 2 else if (code >= 400) 1 else 0)
                val e5 = r.status.filterKeys { it >= 500 }.values.sum(); if (e5 > 0) note("서버 오류(5xx)가 ${e5}건(${LogUtil.pct(e5, r.total)})이에요. 오류 로그를 같은 시각으로 확인하세요.", if (e5 * 100 >= r.total) 2 else 1)
                head("메서드"); header("메서드", "건수"); for ((m, n) in LogUtil.top(r.methods, 6)) row(m, "$n")
                head("요청이 많은 IP"); header("IP", "요청", "국가·통신사"); for ((ip, n) in r.topIps) row(ip, "$n", LogUtil.where(db, ip))
                head("많이 찾은 주소"); header("주소", "요청"); for ((p, n) in r.topPaths) row(p.take(70), "$n")
                if (r.top404.isNotEmpty()) { head("없는 주소(404)를 많이 찾은 곳"); header("주소", "요청"); for ((p, n) in r.top404) row(p.take(70), "$n", level = 1) }
                head("접속 환경 (User-Agent)"); header("종류", "요청"); for ((u, n) in r.topAgents) row(u, "$n")
                if (r.perHour.isNotEmpty()) { head("시간대별 요청"); header("시간", "요청", "그래프"); val mx = r.perHour.values.max(); for ((h, n) in r.perHour.entries.toList().takeLast(30)) row(h, "$n", bar(n, mx)) }
                head("의심스러운 요청")
                if (r.suspicious.isEmpty()) note("알려진 공격 패턴은 보이지 않아요.", -1)
                else {
                    header("IP", "내용", "건수", "예시", "국가·통신사"); for (x in r.suspicious.take(30)) row(x.ip, x.reason, "${x.count}", x.sample, LogUtil.where(db, x.ip), level = x.level)
                    note("공격 시도 ${r.suspicious.count { it.level == 2 }}종·탐색 ${r.suspicious.count { it.level == 1 }}종이 보여요. 응답 코드가 200 이 아니면 대부분 막힌 것이지만, 200·500 이 섞인 IP 는 로그를 더 살펴보세요. 반복되는 IP 는 방화벽·fail2ban 으로 막고, 관리자 페이지는 접속 IP 를 제한하세요.", if (r.suspicious.any { it.level == 2 }) 2 else 1)
                }
                note("User-Agent·IP 는 쉽게 속일 수 있어서 \"봇\"·국가는 참고용이에요. $NOTE_LOCAL")
            }
        },

        logTool("log_auth", "SSH 로그인 시도 분석 (auth.log)", "auth.log·secure 에서 무차별 대입(brute force) 공격 IP·시도한 계정·성공한 로그인을 찾고, 많이 실패한 IP 에서 로그인에 성공한 위험한 경우를 알려 줘요", SAMPLE_AUTH,
            extra = listOf(choice("th", "공격으로 볼 시도 횟수", listOf("3", "5", "10", "20", "50"), "5"))) { s, i, host ->
            val ev = AuthLog.parse(s.lines()); val db = host.geoDb(); val th = i.str("th").toIntOrNull() ?: 5
            if (ev.isEmpty()) return@logTool fail("SSH 로그인 기록을 찾지 못했어요. \"Failed password for … from IP\", \"Accepted … for … from IP\" 같은 줄이 있는 auth.log(/var/log/auth.log, /var/log/secure)나 journalctl -u ssh 출력을 붙여 넣으세요")
            val r = AuthLog.report(ev, th)
            result {
                kv("실패한 로그인 시도", "${r.failures}번", if (r.failures > 0) 1 else -1); kv("서로 다른 공격 IP", "${r.byIp.size}개 이상"); kv("성공한 로그인", "${r.successes.size}번"); kv("${th}번 이상 시도한 IP", "${r.brute.size}개", if (r.brute.isNotEmpty()) 2 else -1)
                if (r.compromised.isNotEmpty()) { head("⚠ 가장 위험한 경우"); for ((ip, n) in r.compromised) { val ok = r.successes.filter { it.ip == ip }; note("$ip (${LogUtil.where(db, ip)}): ${n}번 실패한 뒤 ${ok.size}번 로그인에 성공했어요 (계정: ${ok.map { it.user }.distinct().joinToString()}). 비밀번호를 알아냈을 가능성이 있어요 — 해당 계정 비밀번호를 바꾸고 로그인 이력·실행 중인 프로세스·cron 을 점검하세요.", 2) } }
                if (r.byIp.isNotEmpty()) { head("시도가 많은 IP"); header("IP", "시도", "국가·통신사"); for ((ip, n) in r.byIp) row(ip, "$n", LogUtil.where(db, ip), level = if (n >= th) 2 else 0) }
                if (r.byUser.isNotEmpty()) { head("공격자가 시도한 계정"); header("계정", "시도"); for ((u, n) in r.byUser) row(u, "$n") }
                if (r.successes.isNotEmpty()) { head("성공한 로그인"); header("시각", "계정", "IP", "방식", "국가·통신사"); for (e in r.successes.takeLast(30)) row(e.time ?: "-", e.user ?: "-", e.ip, e.method ?: "-", LogUtil.where(db, e.ip), level = if (e.user == "root") 1 else 0)
                    if (r.successes.any { it.user == "root" }) note("root 로 직접 로그인한 기록이 있어요. PermitRootLogin no 로 막고 일반 계정 + sudo 를 쓰세요.", 1)
                    if (r.methods["password"] != null) note("비밀번호로 로그인한 기록이 ${r.methods["password"]}번 있어요. 키 인증만 허용(PasswordAuthentication no)하면 무차별 대입이 소용없어져요.", 1) }
                if (r.brute.isNotEmpty()) {
                    head("차단 명령 (상위 10개 IP)"); block(r.brute.take(10).joinToString("\n") { "sudo ufw deny from ${it.first} to any" })
                    head("fail2ban 권장 설정 (/etc/fail2ban/jail.local)"); block("[sshd]\nenabled  = true\nmaxretry = 5\nfindtime = 10m\nbantime  = 1h")
                }
                note("공격 IP 는 계속 바뀌고, VPN·해킹된 기기를 거치기도 해서 IP 차단만으로는 부족해요. 키 인증·포트 제한·fail2ban 을 함께 쓰세요. 국가는 참고용이에요. $NOTE_LOCAL")
            }
        },

        logTool("log_syslog", "syslog·시스템 로그 요약", "syslog·journalctl 출력에서 프로그램별 줄 수, 오류·경고·치명 메시지, 반복되는 메시지 유형을 한눈에", "Oct 10 13:55:36 web1 kernel: [123.4] Out of memory: Killed process 4321 (java)\nOct 10 13:56:01 web1 sshd[812]: error: maximum authentication attempts exceeded for root from 203.0.113.9 port 4000\nOct 10 13:57:10 web1 CRON[900]: (root) CMD (run-parts /etc/cron.hourly)\nOct 10 13:58:20 web1 systemd[1]: Started Session 12 of user ubuntu.") { s, _, _ ->
            val r = SyslogSummary.summarize(s.lines())
            if (r.total == 0) return@logTool fail("읽을 수 있는 줄이 없어요. \"Oct 10 13:55:36 호스트 프로그램[pid]: 메시지\" 또는 ISO 시각(2023-10-10T13:55:36+09:00 …) 형식의 syslog 줄이 필요해요")
            result {
                kv("분석한 줄", "${r.total}줄"); r.first?.let { kv("기간", "$it ~ ${r.last}") }; kv("서로 다른 호스트", "${r.hosts}대")
                head("메시지 심각도"); header("종류", "줄 수"); for ((k, n) in r.severity) row(k, "$n", level = if (n > 0 && k.startsWith("치명")) 2 else if (n > 0 && k.startsWith("오류")) 1 else 0)
                head("프로그램별 줄 수"); header("프로그램", "줄 수"); for ((p, n) in r.byProg) row(p, "$n")
                head("자주 반복되는 메시지 유형 (숫자·IP 는 #·<ip> 로 묶음)"); header("유형", "횟수"); for ((t, n) in r.templates) row(t, "$n")
                if (r.notable.isNotEmpty()) { head("주의할 메시지 (최대 30개)"); header("시각", "프로그램", "내용"); for (l in r.notable) row(l.time ?: "-", l.prog ?: "-", l.msg.take(120), level = 1) }
                if (r.severity.entries.firstOrNull { it.key.startsWith("치명") }?.value ?: 0 > 0) note("치명적 메시지가 있어요. 커널 패닉·메모리 부족(OOM)·디스크 오류는 서비스가 멈추는 원인이 돼요 — 해당 시각 전후를 확인하세요.", 2)
                note("키워드(error·fail 등)로 가린 것이라 정상 메시지가 섞일 수 있어요. $NOTE_LOCAL")
            }
        },

        logTool("log_jsonl", "JSON 줄 로그 요약", "한 줄에 JSON 하나씩 남기는 로그(앱·도커·쿠버네티스)에서 키·로그 수준·자주 나오는 메시지·오류 줄을 집계하고, 원하는 필드의 값을 세요", "{\"time\":\"2023-10-10T13:55:36Z\",\"level\":\"info\",\"msg\":\"user login\",\"user\":\"kim\"}\n{\"time\":\"2023-10-10T13:55:40Z\",\"level\":\"error\",\"msg\":\"db timeout after 3000ms\",\"user\":\"lee\"}\n{\"time\":\"2023-10-10T13:55:41Z\",\"level\":\"info\",\"msg\":\"user login\",\"user\":\"kim\"}",
            extra = listOf(text("field", "값을 셀 필드 (선택)", "예: user 또는 http.status", ""))) { s, i, _ ->
            val r = JsonLogs.summarize(s.lines(), i.str("field"))
            if (r.total == 0) return@logTool fail("JSON 줄을 읽지 못했어요 (읽지 못한 줄 ${r.bad}). 한 줄에 JSON 객체 하나씩인 로그여야 해요")
            result {
                kv("분석한 줄", "${r.total}줄" + if (r.bad > 0) " (JSON 이 아닌 줄 ${r.bad})" else ""); r.first?.let { kv("시각 범위", "$it ~ ${r.last}") }
                head("자주 나오는 키"); header("키", "줄 수"); for ((k, n) in r.keys) row(k, "$n")
                if (r.levels.isNotEmpty()) { head("로그 수준"); header("수준", "줄 수"); for ((k, n) in r.levels) row(k, "$n", level = if (k in listOf("error", "err", "fatal", "critical", "panic")) 2 else if (k.startsWith("warn")) 1 else 0) }
                if (r.messages.isNotEmpty()) { head("자주 나오는 메시지 (숫자는 # 로 묶음)"); header("메시지", "횟수"); for ((m, n) in r.messages) row(m, "$n") }
                if (i.str("field").isNotEmpty()) { head("\"${i.str("field")}\" 값 집계"); if (r.fieldValues.isEmpty()) note("그 필드가 있는 줄이 없어요", 1) else { header("값", "줄 수"); for ((v, n) in r.fieldValues) row(v, "$n") } }
                if (r.errors.isNotEmpty()) { head("오류 줄 (최대 10개)"); block(r.errors.joinToString("\n")) }
                note("키 이름(level·msg·time 등)은 흔한 이름을 자동으로 찾아요. $NOTE_LOCAL")
            }
        },

        logTool("log_time_gaps", "로그 시각 간격 분석 (끊긴 구간 찾기)", "로그 줄의 시각을 읽어 일정 시간 넘게 아무 기록이 없는 구간(서비스 중단·재부팅·크론 누락 의심)과 요청이 몰린 분을 찾아요 (ISO·아파치·syslog·유닉스 시각)", "2023-10-10 13:55:00 job started\n2023-10-10 13:56:00 tick\n2023-10-10 13:57:00 tick\n2023-10-10 14:10:00 tick after restart\n2023-10-10 14:11:00 tick",
            extra = listOf(text("th", "끊김으로 볼 최소 간격 (초)", "", "300"), text("year", "연도 (syslog 형식일 때만)", "", "${java.time.Year.now().value}"))) { s, i, _ ->
            val th = i.long("th")?.takeIf { it > 0 } ?: 300L; val year = i.int("year") ?: java.time.Year.now().value
            val r = LogTime.analyze(s.lines(), th, year)
            if (r.stamped < 2) return@logTool fail("시각을 읽을 수 있는 줄이 ${r.stamped}개뿐이에요. 줄 앞에 2023-10-10 13:55:36 · [10/Oct/2023:13:55:36 +0900] · Oct 10 13:55:36 · 유닉스 시각 같은 시각이 있어야 해요")
            val z = ZoneOffset.UTC
            result {
                kv("전체 줄", "${r.lines}줄 (시각을 읽은 줄 ${r.stamped})"); kv("기간", "${r.first} ~ ${r.last} (UTC 기준)"); kv("줄 사이 간격(중앙값)", "%.2f초".format(r.medianSec)); kv("95% 지점 간격", "%.1f초".format(r.p95Sec)); kv("가장 긴 간격", LogTime.human(r.maxSec.toLong()), if (r.maxSec >= th) 1 else 0)
                r.busiestMinute?.let { kv("가장 몰린 1분", "${it.first.replace('T', ' ')}  ·  ${it.second}줄") }; kv("규칙성(변동계수)", "%.2f  ${if (r.cv < 0.3) "(매우 규칙적)" else if (r.cv < 1.0) "(보통)" else "(들쭉날쭉)"}".format(r.cv)); if (r.outOfOrder > 0) kv("시간 순서가 거꾸로인 줄", "${r.outOfOrder}개", 1)
                head("${LogTime.human(th)} 넘게 기록이 없던 구간 (${r.gaps.size}곳)")
                if (r.gaps.isEmpty()) note("끊긴 구간이 없어요.", -1) else { header("끊기기 전", "다시 시작", "빈 시간", "줄 번호"); for (g in r.gaps) row(g.from.atOffset(z).toLocalDateTime().toString().replace('T', ' '), g.to.atOffset(z).toLocalDateTime().toString().replace('T', ' '), LogTime.human(g.seconds), "${g.line}", level = 1)
                    note("로그가 안 남은 시간이 곧 서비스가 멈춘 시간은 아니에요(한가한 시간대일 수 있어요). 다만 매분 남던 기록이 끊겼다면 프로세스 중단·서버 재부팅·디스크 가득 참을 의심하세요.", 1) }
                note("시각이 시간대 표시 없이 적혀 있으면 UTC 로 보고 간격만 계산해요(간격 계산에는 영향 없어요). 줄은 시간순이라고 가정해요. $NOTE_LOCAL")
            }
        },

        logTool("log_har", "브라우저 HAR 분석 (느린 페이지 원인)", "크롬·엣지·파이어폭스 개발자 도구에서 저장한 HAR 파일로 요청 수·용량·가장 느린/큰 요청·단계별 지연(DNS·연결·TLS·대기·받기)·외부 도메인·압축/캐시 누락을 분석", SAMPLE_HAR) { s, _, _ ->
            val r = try { HarSummary.parse(s) } catch (e: JSONException) { return@logTool fail("HAR 파일(JSON)을 읽지 못했어요. 개발자 도구(F12) → 네트워크 → 우클릭 \"HAR 로 모두 저장\"한 파일이어야 해요") }
            if (r.reqs.isEmpty()) return@logTool fail("요청이 없는 HAR 예요")
            result {
                kv("요청 수", "${r.reqs.size}개"); kv("전송량(네트워크)", LogUtil.bytes(r.transfer)); kv("원본 크기(압축 해제 후)", LogUtil.bytes(r.content)); r.domContentMs?.let { kv("DOM 준비(onContentLoad)", "${it.toLong()}ms") }; r.pageLoadMs?.let { kv("페이지 로드(onLoad)", "${it.toLong()}ms", if (it > 3000) 1 else 0) }
                head("단계별 평균 지연 (요청 1개 기준)"); header("단계", "평균(ms)", "뜻"); val why = listOf("브라우저 대기(연결 수 제한 등)", "도메인 → IP 조회", "TCP 연결", "TLS(https 협상)", "요청 보내기", "서버가 응답하기까지(TTFB)", "응답 받기")
                HarSummary.PHASES.forEachIndexed { k, n -> row(n, LogUtil.ms(r.avgTiming[k]), why[k], level = if (n == "wait" && r.avgTiming[k] > 500) 1 else 0) }
                head("종류별 전송량"); header("종류", "요청", "전송량"); for ((k, n, b) in r.byType) row(k, "$n", LogUtil.bytes(b))
                head("가장 오래 걸린 요청"); header("시간(ms)", "상태", "주소"); for (q in r.slowest) row("${q.timeMs.toLong()}", "${q.status}", q.url.take(80), level = if (q.timeMs > 1500) 1 else 0)
                head("가장 큰 요청"); header("전송량", "형식", "주소"); for (q in r.largest) row(LogUtil.bytes(q.transfer), q.mime.ifEmpty { "-" }, q.url.take(80), level = if (q.transfer > 1_000_000) 1 else 0)
                if (r.failed.isNotEmpty()) { head("실패·오류 요청 (${r.failed.size}개)"); header("상태", "주소"); for (q in r.failed.take(15)) row("${q.status}", q.url.take(90), level = 2) }
                head("연결한 도메인"); header("도메인", "요청", "구분"); val third = r.thirdParty.toMap(); for ((h, n) in r.hosts) row(h, "$n", if (h in third) "외부(제3자)" else "같은 사이트")
                head("프로토콜"); for ((p, n) in r.protocols) kv(p, "${n}개")
                head("개선할 점")
                var tips = 0
                if (r.notCompressed.isNotEmpty()) { tips++; note("압축하지 않은 텍스트 파일이 ${r.notCompressed.size}개예요 (예: ${r.notCompressed.first().url.takeLast(50)}). gzip·Brotli 를 켜면 전송량이 크게 줄어요.", 1) }
                if (r.noCache.isNotEmpty()) { tips++; note("캐시 설정(Cache-Control·Expires)이 없는 이미지·스크립트·스타일·글꼴이 ${r.noCache.size}개예요. 재방문이 느려져요.", 1) }
                if (r.mixed.isNotEmpty()) { tips++; note("https 페이지에서 http 로 불러온 자원이 ${r.mixed.size}개예요(혼합 콘텐츠).", 2) }
                if (r.thirdParty.sumOf { it.second } * 3 > r.reqs.size) { tips++; note("요청의 ${LogUtil.pct(r.thirdParty.sumOf { it.second }, r.reqs.size)} 가 외부 도메인이에요. 광고·분석·글꼴 서비스가 속도를 좌우해요.", 1) }
                if (r.avgTiming[HarSummary.PHASES.indexOf("wait")] > 500) { tips++; note("서버 응답 대기(TTFB) 평균이 ${r.avgTiming[HarSummary.PHASES.indexOf("wait")].toLong()}ms 예요: 서버 처리·DB 쿼리·CDN 을 점검하세요.", 1) }
                if (r.protocols.keys.any { it.startsWith("http/1") } && r.reqs.size > 20) { tips++; note("HTTP/1.1 로 받은 요청이 있고 요청 수가 많아요. HTTP/2 를 켜면 동시에 처리돼 빨라져요.", 0) }
                if (tips == 0) note("눈에 띄는 개선점이 없어요.", -1)
                note("HAR 에는 쿠키·토큰·입력한 내용이 들어 있을 수 있어요. 다른 사람에게 보내기 전에 민감한 헤더를 지우세요(이 도구는 값을 출력하지 않아요). $NOTE_LOCAL")
            }
        },

        logTool("log_traceroute", "traceroute·tracert 결과 해석", "traceroute(리눅스·맥)·tracert(윈도) 출력을 붙여 넣으면 홉별 지연·손실·국가·통신사 경로를 표로 보여 주고, 지연이 갑자기 늘어난 구간과 막힌 곳을 짚어 줘요", SAMPLE_TRACE, withFile = false) { s, _, host ->
            val t = TraceParse.parse(s); val db = host.geoDb()
            if (t.hops.isEmpty()) return@logTool fail("홉 줄을 찾지 못했어요. \" 1  192.168.0.1  1.2 ms …\" 처럼 번호로 시작하는 traceroute/tracert 출력을 붙여 넣으세요")
            fun lab(h: TraceParse.Hop): String? = h.addrs.firstOrNull()?.let { LogUtil.where(db, it) }
            result {
                kv("목적지", if (t.target != null) "${t.target} (${t.targetIp})" else "(헤더 없음)"); kv("홉 수", "${t.hops.size}개"); kv("형식", if (t.windows) "윈도 tracert" else "traceroute")
                header("홉", "주소 (이름)", "평균(ms)", "손실", "국가·통신사")
                for (h in t.hops) { val a = h.addrs; val name = if (a.isEmpty()) "응답 없음 (* * *)" else a.joinToString(", ") { ad -> h.hostOf(ad)?.takeIf { it != ad }?.let { "$ad ($it)" } ?: ad }.take(60)
                    row("${h.n}", name, h.avg?.let { LogUtil.ms(it) } ?: "-", "${h.loss}/${h.probes.size}", if (a.isEmpty()) "-" else lab(h) ?: "-", level = if (a.isEmpty()) 1 else if ((h.avg ?: 0.0) > 150) 1 else 0) }
                head("진단")
                val last = t.hops.last(); val reached = if (t.targetIp != null) t.hops.any { t.targetIp in it.addrs } else last.addrs.isNotEmpty()
                if (reached) note("목적지에 도착했어요 (최종 평균 ${last.avg?.let { LogUtil.ms(it) } ?: "?"}ms).", -1) else note("목적지까지 도착하지 못했어요: 마지막 홉이 ${if (last.addrs.isEmpty()) "응답하지 않아요" else "${last.addrs.first()} 에서 끝났어요"}. 중간 장비·방화벽이 ICMP 를 막았거나 경로가 끊긴 것일 수 있어요.", 2)
                for (h in t.hops) if (h.flags.isNotEmpty()) note("홉 ${h.n}: ${h.flags.distinct().joinToString()} — ${h.flags.joinToString { f -> when (f) { "!H" -> "호스트에 도달할 수 없다는 응답"; "!N" -> "네트워크에 도달할 수 없다는 응답"; "!X" -> "관리자가 통신을 막았다는 응답(방화벽)"; "!P" -> "프로토콜을 쓸 수 없다는 응답"; else -> "도달 불가 응답" } }.take(60)}", 2)
                var prev: TraceParse.Hop? = null
                for (h in t.hops) { val a = h.avg ?: continue; val p = prev?.avg
                    if (p != null && a - p > 40 && a > p * 2) { val chg = if (lab(prev!!) != lab(h)) " (통신사·나라가 바뀌는 지점이에요: ${lab(prev)} → ${lab(h)})" else ""; note("홉 ${prev.n} → ${h.n} 에서 지연이 ${LogUtil.ms(p)}ms → ${LogUtil.ms(a)}ms 로 ${LogUtil.ms(a - p)}ms 늘었어요$chg. 이 구간에 긴 물리 거리(해저 케이블)·혼잡·우회가 있어요.", 1) }
                    prev = h }
                val mid = t.hops.dropLast(1).count { it.addrs.isEmpty() }; if (mid > 0 && reached) note("중간에 응답 없는 홉이 ${mid}개 있지만 그 뒤에도 응답이 이어져요: 장비가 ICMP 응답만 막은 정상적인 경우가 많아요.", 0)
                val path = t.hops.flatMap { h -> h.addrs.take(1) }.mapNotNull { ip -> db?.lookup(ip)?.takeIf { IpUtil.parse(ip)?.let { a -> IpUtil.classify(a) == IpKind.PUBLIC } == true }?.asn?.name?.take(22) }.fold(ArrayList<String>()) { acc, n -> if (acc.lastOrNull() != n) acc.add(n); acc }
                if (path.isNotEmpty()) note("통신사(AS) 경로: ${path.joinToString(" → ")}")
                note("홉마다 3번 보낸 신호의 평균이에요. 중간 홉의 높은 지연은 그 장비가 ICMP 응답을 늦게 처리해서일 수 있어서, 뒤 홉도 같이 느려질 때만 실제 문제로 보세요. $NOTE_LOCAL")
            }
        },

        logTool("log_iface", "네트워크 인터페이스 정보 해석 (ip addr·ifconfig·ipconfig)", "ip addr·ifconfig(리눅스·맥)·ipconfig /all(윈도, 한글판 포함) 출력을 풀어 인터페이스별 주소·MAC·MTU·게이트웨이·DNS를 표로 보고 DHCP 실패(169.254)·MTU·주소 이상을 짚어 줘요", SAMPLE_IFACE, withFile = false) { s, _, _ ->
            val ifs = IfaceParse.parse(s)
            if (ifs.isEmpty()) return@logTool fail("인터페이스를 찾지 못했어요. ip addr, ifconfig, ipconfig /all 의 출력을 처음부터 붙여 넣으세요")
            result {
                kv("인터페이스", "${ifs.size}개 (${ifs.count { it.addrs.any { a -> !a.v6 && !a.ip.startsWith("127.") } }}개가 IPv4 주소를 가짐)")
                for (f in ifs) {
                    head(f.name + (f.state?.let { "  ·  $it" } ?: ""))
                    f.mac?.takeIf { it != "00:00:00:00:00:00" }?.let { kv("MAC", it, 0) }; f.mtu?.let { kv("MTU", "$it", if (it !in listOf(1500, 65536)) 1 else 0) }; f.media?.let { kv("미디어 상태", it, if (it.contains("disconnected", true) || it.contains("끊김")) 1 else 0) }
                    for (a in f.addrs) { val k = IpUtil.parse(a.ip)?.let { IpUtil.classify(it) }; kv(if (a.v6) "IPv6" else "IPv4", a.ip + (a.prefix?.let { "/$it" } ?: "") + (a.scope?.let { "  ($it)" } ?: "") + (k?.takeIf { !a.v6 }?.let { "  → ${it.label.substringBefore(" (")}" } ?: ""), if (k == IpKind.LINK_LOCAL && !a.v6) 2 else 0) }
                    if (f.gateways.isNotEmpty()) kv("게이트웨이", f.gateways.joinToString(", ")); if (f.dns.isNotEmpty()) kv("DNS", f.dns.joinToString(", ")); f.dhcp?.let { kv("DHCP", if (it) "사용" else "고정 주소") }
                    if (f.addrs.any { !it.v6 && it.ip.startsWith("169.254.") }) note("169.254.x.x 는 DHCP 서버에서 주소를 받지 못했을 때 스스로 붙이는 임시 주소(APIPA)예요. 공유기 DHCP 가 꺼졌거나 선·Wi-Fi 연결에 문제가 있어요. 이 주소로는 인터넷이 안 돼요.", 2)
                    if (f.state == "UP" && f.addrs.none { !it.v6 && !it.ip.startsWith("127.") } && f.name != "lo" && !f.name.startsWith("lo")) note("인터페이스는 켜져 있지만 IPv4 주소가 없어요.", 1)
                    if (f.addrs.any { !it.v6 && (IpUtil.parse(it.ip)?.let { a -> IpUtil.classify(a) } == IpKind.CGNAT) }) note("100.64.0.0/10 주소예요: 통신사 공용 주소(CGNAT)·테일스케일 같은 VPN 이에요.", 0)
                    if (f.name.startsWith("docker") || f.name.startsWith("veth") || f.name.startsWith("br-") || f.name.startsWith("virbr")) note("가상 인터페이스(컨테이너·가상머신용)예요.", 0)
                    f.mtu?.let { if (it == 1492) note("MTU 1492 는 PPPoE(일부 인터넷 회선) 값이에요.", 0) else if (it < 1500 && it != 65536) note("MTU $it 는 터널·VPN·PPPoE 를 거치는 값이에요. 큰 패킷이 안 통하면 MTU 를 의심하세요.", 0) else if (it > 1500 && it != 65536) note("MTU $it 는 점보 프레임이에요: 경로의 모든 장비가 지원해야 해요.", 1) }
                }
                note("출력에 보이는 주소만 해석해요. $NOTE_LOCAL")
            }
        },

        logTool("log_sockets", "열린 포트·연결 해석 (ss·netstat)", "ss -tunap · netstat -tulnp · netstat -ano(윈도) 출력에서 외부에 열린 포트·위험한 서비스·연결 상대 IP(국가·통신사)·연결 상태 이상(CLOSE_WAIT 누수 등)을 찾아요", SAMPLE_SOCKETS, withFile = false) { s, _, host ->
            val so = SockParse.parse(s); val db = host.geoDb()
            if (so.isEmpty()) return@logTool fail("소켓 줄을 찾지 못했어요. ss -tunap, netstat -tulnp, netstat -ano 의 출력을 붙여 넣으세요")
            val listen = so.filter { it.state == "LISTEN" || it.state == "UDP" }; val est = so.filter { it.state == "ESTABLISHED" }; val states = so.filter { it.proto == "tcp" }.groupingBy { it.state }.eachCount()
            result {
                kv("전체 소켓", "${so.size}개"); kv("열려 있는(LISTEN·UDP)", "${listen.size}개"); kv("연결됨(ESTABLISHED)", "${est.size}개"); kv("외부에 노출된 포트", "${listen.count { SockParse.exposure(it.local) == 2 }}개", if (listen.any { SockParse.exposure(it.local) == 2 && (Ports.SERVICES[it.lport]?.risk ?: 0) >= 2 }) 2 else 0)
                head("열려 있는 포트"); header("프로토콜", "주소", "포트", "프로그램", "노출", "서비스")
                for (x in listen.sortedWith(compareBy({ -SockParse.exposure(it.local) }, { it.lport }))) { val e = SockParse.exposure(x.local); val info = Ports.SERVICES[x.lport]
                    row(x.proto, x.local, "${x.lport}", x.proc ?: "-", when (e) { 2 -> "모든 곳에서 접속 가능"; 1 -> "특정 주소만"; else -> "이 기기 안에서만" }, info?.name ?: "-", level = if (e == 2 && (info?.risk ?: 0) >= 2) 2 else if (e == 2 && (info?.risk ?: 0) == 1) 1 else 0) }
                for (x in listen.filter { SockParse.exposure(it.local) == 2 }.distinctBy { it.lport }) Ports.SERVICES[x.lport]?.takeIf { it.risk >= 1 && it.advice.isNotEmpty() }?.let { note("${x.lport}번 ${it.name}: ${it.advice}", it.risk) }
                if (states.isNotEmpty()) { head("TCP 연결 상태"); header("상태", "개수"); for ((k, n) in states.entries.sortedByDescending { it.value }) row(k, "$n", level = if ((k == "CLOSE_WAIT" && n >= 20) || (k == "SYN_RECV" && n >= 50)) 2 else 0) }
                if ((states["CLOSE_WAIT"] ?: 0) >= 20) note("CLOSE_WAIT 가 ${states["CLOSE_WAIT"]}개예요: 상대는 연결을 닫았는데 내 프로그램이 소켓을 닫지 않는 누수일 수 있어요(프로그램 버그).", 2)
                if ((states["SYN_RECV"] ?: 0) >= 50) note("SYN_RECV 가 ${states["SYN_RECV"]}개예요: SYN 폭주(DoS) 공격 또는 과부하일 수 있어요.", 2)
                if (est.isNotEmpty()) { head("연결 중인 상대 (IP별)"); header("상대 IP", "연결 수", "내 포트", "국가·통신사")
                    for ((ip, l) in est.groupBy { it.peer }.entries.sortedByDescending { it.value.size }.take(15)) row(ip, "${l.size}", l.map { it.lport }.distinct().take(4).joinToString(","), LogUtil.where(db, ip)) }
                note("프로그램 이름은 sudo 로 실행한 ss -p·netstat -p 출력에만 나와요(윈도는 PID 만). 127.0.0.1 에만 열린 포트는 외부에서 접속할 수 없어요. $NOTE_LOCAL")
            }
        },

        logTool("log_dig", "dig·nslookup 결과 해석", "dig·nslookup 출력을 붙여 넣으면 응답 코드(NOERROR·NXDOMAIN·SERVFAIL)·플래그·답 레코드·응답 시간을 풀고 문제를 짚어 줘요", SAMPLE_DIG, withFile = false) { s, _, _ ->
            val r = DigParse.parse(s)
            if (r.status == null && r.recs.isEmpty()) return@logTool fail("dig/nslookup 출력을 읽지 못했어요 (dig 은 \";; ->>HEADER<<-\" 줄이 있는 전체 출력, nslookup 은 Server·Address 줄이 필요해요)")
            result {
                r.query?.let { kv("질문", it) }; kv("응답 코드", r.status ?: "-", when (r.status) { "NOERROR" -> if (r.recs.any { it.section == "ANSWER" } || r.kind == "nslookup") -1 else 1; "NXDOMAIN" -> 2; "SERVFAIL", "REFUSED" -> 2; else -> 1 })
                r.server?.let { kv("물어본 서버", it + (r.proto?.let { p -> " ($p)" } ?: "")) }; r.queryMs?.let { kv("걸린 시간", "${it}ms", if (it > 200) 1 else 0) }; r.size?.let { kv("응답 크기", "${it}바이트") }
                if (r.kind == "dig") kv("플래그", r.flags.joinToString(" ").ifEmpty { "-" }); if (r.counts.isNotEmpty()) kv("레코드 수", r.counts.entries.joinToString(" · ") { "${it.key} ${it.value}" })
                val answers = r.recs.filter { it.section == "ANSWER" }
                if (answers.isNotEmpty()) { head("답 (ANSWER)"); header("이름", "TTL", "종류", "값"); for (x in answers) row(x.name, if (x.ttl > 0) "${x.ttl}" else "-", x.type, x.data.take(100)) }
                val other = r.recs.filter { it.section != "ANSWER" }; if (other.isNotEmpty()) { head("그 밖의 레코드"); header("구역", "이름", "종류", "값"); for (x in other.take(20)) row(x.section, x.name, x.type, x.data.take(100)) }
                head("진단")
                when (r.status) {
                    "NXDOMAIN" -> note("NXDOMAIN: 그런 도메인이 없어요. 철자·존재 여부를 확인하세요. (방금 만든 도메인은 전파에 시간이 걸릴 수 있어요)", 2)
                    "SERVFAIL" -> note("SERVFAIL: DNS 서버가 답을 만들지 못했어요. 도메인의 네임서버 장애·DNSSEC 검증 실패(서명 만료)가 흔한 원인이에요. 다른 DNS(1.1.1.1·8.8.8.8)로 물어보고, +cd(검증 끄기) 로 DNSSEC 문제인지 가려 보세요.", 2)
                    "REFUSED" -> note("REFUSED: 서버가 이 질문에 답하길 거부했어요. 재귀 조회를 허용하지 않는 서버이거나 접근이 제한된 서버일 수 있어요.", 2)
                    "NOERROR" -> if (answers.isEmpty() && r.kind == "dig") note("도메인은 있지만 물어본 종류의 레코드가 없어요(NODATA).", 1) else note("정상 응답이에요.", -1)
                }
                if ("tc" in r.flags) note("응답이 잘렸어요(tc 플래그): 크기가 커서 UDP 로 다 못 받았어요. +tcp 로 다시 물어보세요.", 1)
                if (r.kind == "dig" && "ra" !in r.flags && r.status == "NOERROR") note("ra(재귀 가능) 플래그가 없어요: 이 서버는 재귀 DNS 가 아닌 권한 서버일 수 있어요. 일반 사용에는 재귀 DNS 를 쓰세요.", 0)
                if ("aa" in r.flags) note("aa 플래그: 이 도메인의 권한 서버가 직접 답했어요 (캐시된 답이 아니에요).", 0)
                if ("ad" in r.flags) note("ad 플래그: DNSSEC 검증을 통과한 답이에요.", -1)
                r.server?.let { sv -> if (sv.startsWith("127.0.0.53") || sv.startsWith("127.0.0.1")) note("이 기기 안의 DNS 캐시(systemd-resolved 등)가 대신 답했어요. 실제 상위 DNS 는 resolvectl status 로 보세요.", 0) }
                answers.minOfOrNull { it.ttl }?.takeIf { it in 1..59 }?.let { note("TTL ${it}초는 매우 짧아요: DNS 서버 부담이 크고, 장애 시 빨리 바꾸려는 설정일 수 있어요.", 0) }
                note("answer 의 값이 둘 이상이면 DNS 라운드 로빈(여러 서버 중 하나로 분산)이에요. $NOTE_LOCAL")
            }
        },

        logTool("log_firewall", "방화벽 규칙 점검 (iptables·ufw)", "iptables -S · iptables-save · ufw status 출력을 읽어 기본 정책·허용된 포트·\"모두 허용\" 규칙·위험한 포트 노출을 점검하고 방화벽이 사실상 꺼져 있는지 알려 줘요", SAMPLE_FW, withFile = false) { s, _, _ ->
            val r = FwParse.parse(s)
            if (r.policies.isEmpty() && r.rules.isEmpty() && r.active == null) return@logTool fail("규칙을 찾지 못했어요. iptables -S(또는 iptables-save)나 ufw status verbose 의 출력을 붙여 넣으세요")
            val inRules = r.rules.filter { it.chain == "INPUT" }
            result {
                kv("종류", if (r.kind == "ufw") "ufw" else "iptables"); r.active?.let { kv("방화벽 상태", if (it) "켜짐(active)" else "꺼짐(inactive)", if (it) -1 else 2) }
                for ((c, p) in r.policies) kv("기본 정책 $c", p, if (c == "INPUT" && p == "ACCEPT") 1 else 0)
                kv("들어오는 규칙(INPUT)", "${inRules.size}개")
                val tail = inRules.lastOrNull { it.proto == null && it.dports.isEmpty() && it.src == null && it.iface == null && it.state == null }
                val policyIn = r.policies["INPUT"]
                val open0 = inRules.filter { it.target == "ACCEPT" }
                val everything = open0.filter { it.proto == null && it.dports.isEmpty() && it.state == null && it.iface == null && (it.src == null || it.src == "0.0.0.0/0") }
                val closed = everything.isEmpty() && (policyIn == "DROP" || policyIn == "REJECT" || (tail != null && (tail.target == "DROP" || tail.target == "REJECT")))
                head("진단")
                if (r.active == false) note("ufw 가 꺼져 있어요(inactive): 방화벽이 동작하지 않아요. sudo ufw enable 로 켜기 전에 SSH 포트(22) 허용부터 하세요.", 2)
                else if (r.kind == "iptables" && !closed) note("INPUT 기본 정책이 ACCEPT 이고 마지막에 전부 DROP 하는 규칙도 없어요: 아래 허용 규칙과 상관없이 모든 포트가 열려 있어요(방화벽이 사실상 꺼진 상태). 기본 정책을 DROP 으로 바꾸고(예: iptables -P INPUT DROP — SSH 허용 규칙을 먼저 넣으세요) 필요한 포트만 허용하세요.", 2)
                else if (closed) note("기본적으로 들어오는 연결을 막고(DROP/REJECT) 허용한 것만 통과시켜요 (좋은 설정이에요).", -1)
                if (r.kind == "iptables" && closed && inRules.none { it.state?.contains("ESTABLISHED") == true } && policyIn == "DROP") note("ESTABLISHED,RELATED 허용 규칙이 없어요: 내가 먼저 연 연결의 응답도 막혀 웹 접속·DNS 가 안 될 수 있어요.", 1)
                val open = open0
                if (everything.isNotEmpty()) note("출발지·포트 조건 없이 모든 것을 허용하는 규칙이 있어요 (${everything.first().raw.take(60)}): 방화벽을 무력화해요.", 2)
                val rows = open.filter { it.dports.isNotEmpty() }
                if (rows.isNotEmpty()) {
                    head("허용된 포트"); header("포트", "프로토콜", "출발지", "서비스")
                    for (x in rows) for (p in x.dports) { val port = p.substringBefore('-').toIntOrNull(); val info = port?.let { Ports.SERVICES[it] }; val anywhere = x.src == null || x.src == "0.0.0.0/0"
                        row(p, x.proto ?: "tcp·udp", x.src ?: "어디서나", info?.name ?: "-", level = if (anywhere && (info?.risk ?: 0) >= 2) 2 else if (anywhere && (info?.risk ?: 0) == 1) 1 else 0) }
                    for (x in rows) for (p in x.dports) { val info = p.substringBefore('-').toIntOrNull()?.let { Ports.SERVICES[it] }; if (info != null && info.risk >= 2 && (x.src == null || x.src == "0.0.0.0/0")) note("${p}번(${info.name})을 어디서나 접속하도록 열었어요: ${info.advice}", 2) }
                }
                if (r.kind == "iptables") note("iptables 는 IPv4 만 보여요. IPv6 는 ip6tables -S 를 따로 확인하세요(IPv6 가 열려 있으면 우회돼요). 도커는 게시한 포트를 iptables 에 직접 추가해서 ufw 규칙을 우회하니 docker -p 포트도 확인하세요.", 0)
                else note("ufw 규칙은 IPv4·IPv6 모두에 적용되지만, 도커가 게시한 포트는 ufw 를 우회해요.", 0)
                note(NOTE_LOCAL)
            }
        },

        logTool("log_tcpdump", "tcpdump 출력 요약 (연결·재전송·차단 찾기)", "tcpdump -nn 으로 뜬 글 출력에서 대화(연결)별 패킷·용량, 응답 없는 접속 시도(SYN), 연결 거부(RST), 재전송, DNS 질문·무응답, ARP 무응답을 가려내요", SAMPLE_DUMP) { s, _, host ->
            val p = TcpdumpParse.parse(s); val db = host.geoDb()
            if (p.isEmpty()) return@logTool fail("패킷 줄을 찾지 못했어요. tcpdump -nn 의 출력(\"13:55:36.1 IP 1.2.3.4.5555 > 5.6.7.8.443: Flags [S], …\")을 붙여 넣으세요")
            val ip = p.filter { it.proto != "ARP" }
            result {
                kv("패킷", "${p.size}개 (TCP ${p.count { it.proto == "TCP" }} · UDP ${p.count { it.proto == "UDP" }} · ICMP ${p.count { it.proto == "ICMP" }} · ARP ${p.count { it.proto == "ARP" }})"); kv("시각 범위", "${p.first().time} ~ ${p.last().time}")
                // 대화(양방향 묶음)
                fun key(x: TcpdumpParse.Pkt): String { val a = "${x.src}:${x.sport ?: ""}"; val b = "${x.dst}:${x.dport ?: ""}"; return x.proto + " " + listOf(a, b).sorted().joinToString(" ↔ ") }
                val conv = ip.groupBy { key(it) }
                head("대화(연결)별 요약 (패킷 많은 순)"); header("대화", "패킷", "바이트", "상대 국가·통신사")
                for ((k, l) in conv.entries.sortedByDescending { it.value.size }.take(12)) { val remote = l.map { if (IpUtil.parse(it.dst)?.let { a -> IpUtil.classify(a) } == IpKind.PUBLIC) it.dst else it.src }.firstOrNull { IpUtil.parse(it)?.let { a -> IpUtil.classify(a) } == IpKind.PUBLIC }; row(k.take(75), "${l.size}", "${l.sumOf { it.len }}", remote?.let { LogUtil.where(db, it) } ?: "내부 주소") }
                head("진단")
                // SYN 만 보내고 응답이 없는 접속
                val tcp = ip.filter { it.proto == "TCP" && it.flags != null }
                val synOnly = tcp.filter { it.flags == "S" }.groupBy { "${it.dst}:${it.dport}" }.filter { (k, v) -> tcp.none { r -> r.flags != null && r.flags.startsWith("S.") && "${r.src}:${r.sport}" == k } && tcp.none { r -> r.flags == "R." && "${r.src}:${r.sport}" == k } }
                if (synOnly.isEmpty()) note("응답 없는 접속 시도(SYN)는 없어요.", -1) else for ((k, v) in synOnly) note("$k 로 SYN 을 ${v.size}번 보냈지만 아무 응답이 없어요 (${LogUtil.where(db, k.substringBeforeLast(':'))}): 방화벽이 조용히 버리거나, 서버·경로가 죽었거나, 주소가 잘못됐어요.", 2)
                val rst = tcp.filter { it.flags != null && (it.flags == "R" || it.flags == "R.") }; if (rst.isNotEmpty()) note("RST(연결 거부·강제 종료)가 ${rst.size}번 보여요: ${rst.groupBy { "${it.src}:${it.sport}" }.entries.sortedByDescending { it.value.size }.take(3).joinToString(", ") { "${it.key}(${it.value.size}번)" }}. 포트가 닫혀 있거나 서버·방화벽이 연결을 끊었어요.", 1)
                val retr = tcp.filter { it.len > 0 && it.seq != null }.groupBy { Triple(it.src + ":" + it.sport, it.dst + ":" + it.dport, it.seq) }.filter { it.value.size > 1 }; if (retr.isNotEmpty()) note("재전송이 ${retr.values.sumOf { it.size - 1 }}번 보여요 (같은 순서 번호 데이터를 다시 보냄): 패킷 손실·혼잡·지연이 있다는 신호예요.", 1)
                val q = ip.filter { it.dnsId != null && !it.dnsResp }; val resp = ip.filter { it.dnsId != null && it.dnsResp }.mapNotNull { it.dnsId }.toSet()
                if (q.isNotEmpty()) { val un = q.filter { it.dnsId !in resp }; if (un.isNotEmpty()) note("DNS 질문 ${q.size}개 중 ${un.size}개가 응답이 없어요 (${un.mapNotNull { it.dnsName }.distinct().take(4).joinToString()}): DNS 서버가 막혔거나 죽었어요.", 2) else note("DNS 질문 ${q.size}개가 모두 응답을 받았어요 (${q.mapNotNull { it.dnsName }.distinct().take(5).joinToString()}).", -1) }
                val arpReq = p.filter { it.proto == "ARP" && it.flags == "who-has" }; val arpOk = p.filter { it.proto == "ARP" && it.flags == "is-at" }.map { it.src }.toSet()
                if (arpReq.isNotEmpty()) { val un = arpReq.filter { it.dst !in arpOk }; if (un.isNotEmpty()) note("ARP \"누가 ${un.first().dst} 인가\" 질문에 답이 없어요 (${un.size}건): 그 기기가 꺼져 있거나 같은 망에 없어요.", 1) }
                val icmpErr = ip.filter { it.proto == "ICMP" && (it.info.contains("unreachable") || it.info.contains("time exceeded")) }; if (icmpErr.isNotEmpty()) note("ICMP 도달 불가·시간 초과 응답이 ${icmpErr.size}번 보여요: ${icmpErr.first().info.take(80)}", 1)
                note("tcpdump 의 TCP 시각·순서는 캡처한 위치 기준이에요. 아주 큰 출력은 앞부분만 보여 주기도 하니 필터(host·port)로 줄여서 캡처하세요. $NOTE_LOCAL")
            }
        },
    )
}
