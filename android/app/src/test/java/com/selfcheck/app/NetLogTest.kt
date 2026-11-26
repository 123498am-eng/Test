package com.selfcheck.app

import org.json.JSONArray
import org.json.JSONObject
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.File
import java.time.Instant

/*
 * 로그·출력 분석 엔진 6종 + 도구 12가지 시험.
 * 큰 로그(웹 접근·SSH 인증·syslog·JSON 줄·시간 간격·HAR)는 파이썬으로 "심어 둔 사건"과 함께 만들고 기대값을 독립적으로 계산했어요
 * (src/test/resources/netlog). 명령어 출력(traceroute·ip addr·ss·dig·iptables·tcpdump)은 실제 형식 그대로의 짧은 글로 시험합니다.
 */
class NetLogTest {
    private fun res(name: String) = File("src/test/resources/netlog/$name").readText()
    private fun json(name: String) = JSONObject(res(name))
    private fun run(id: String, vararg kv: Pair<String, String>, host: ToolHost = FileHost) = runNetTool(id, *kv, host = host)
    private fun pairs(a: JSONArray) = (0 until a.length()).map { a.getJSONArray(it).let { p -> p.getString(0) to p.getInt(1) } }
    private fun intMap(o: JSONObject) = o.keys().asSequence().associateWith { o.getInt(it) }

    // ============================================================ 도우미

    @Test fun logUtilHelpers() {
        assertEquals("33.3%", LogUtil.pct(1, 3)); assertEquals("0%", LogUtil.pct(0, 0)); assertEquals("1.5KB", LogUtil.bytes(1536)); assertEquals("512B", LogUtil.bytes(512)); assertEquals("2.00GB", LogUtil.bytes(2L * 1073741824))
        assertEquals("1.23", LogUtil.ms(1.234)); assertEquals("12.3", LogUtil.ms(12.34)); assertEquals("123", LogUtil.ms(123.4))
        assertEquals(listOf("b" to 3, "a" to 2, "c" to 2), LogUtil.top(mapOf("a" to 2, "b" to 3, "c" to 2), 3))                    // 같은 횟수는 이름 순
        assertEquals("내부 주소", LogUtil.where(FileHost.db, "192.168.1.1")); assertEquals("-", LogUtil.where(FileHost.db, "not an ip")); assertEquals("-", LogUtil.where(null, "8.8.8.8"))
        assertTrue(LogUtil.where(FileHost.db, "8.8.8.8").contains("Google"))
        val data = ByteArray(200_000) { (it % 251).toByte() }; assertEquals(150_000, data.inputStream().readUpTo(150_000).size); assertEquals(200_000, data.inputStream().readUpTo(1_000_000).size)
    }

    // ============================================================ 웹 접근 로그

    @Test fun accessLogMatchesIndependentCounts() {
        val exp = json("access.json"); val r = AccessLog.summarize(res("access.log").lines())
        assertEquals(exp.getInt("total"), r.total); assertEquals(exp.getInt("skipped"), r.skipped); assertEquals(exp.getInt("ips"), r.ips)
        assertEquals(intMap(exp.getJSONObject("status")), r.status.mapKeys { it.key.toString() }); assertEquals(intMap(exp.getJSONObject("methods")), r.methods)
        assertEquals(pairs(exp.getJSONArray("topIps")), r.topIps); assertEquals(pairs(exp.getJSONArray("topPaths")), r.topPaths); assertEquals(pairs(exp.getJSONArray("top404")), r.top404)
        assertEquals(intMap(exp.getJSONObject("agents")), r.topAgents.toMap()); assertEquals(exp.getLong("bytes"), r.bytes); assertEquals(intMap(exp.getJSONObject("perHour")), r.perHour); assertEquals(exp.getInt("bots"), r.botRequests)
        assertEquals(exp.getString("first"), r.first); assertEquals(exp.getString("last"), r.last)
        // 심어 둔 공격이 정확한 횟수로, 다른 IP 는 의심 목록에 없음
        fun susp(ip: String, reason: String) = r.suspicious.firstOrNull { it.ip == ip && it.reason == reason }
        assertEquals(3, susp("192.0.2.66", "경로 탈출 시도(../)")!!.count); assertEquals(5, susp("192.0.2.77", "관리자·로그인 페이지 탐색")!!.count); assertEquals(2, susp("192.0.2.88", "비밀 파일 찾기(.env·.git·키)")!!.count)
        assertEquals(4, susp("192.0.2.99", "공격 도구가 쓰는 User-Agent")!!.count); assertEquals(30, susp("192.0.2.111", "없는 주소를 마구 두드림(스캐너)")!!.count); assertEquals("30건 중 30건이 403·404", susp("192.0.2.111", "없는 주소를 마구 두드림(스캐너)")!!.sample)
        assertEquals(listOf("192.0.2.99", "192.0.2.66", "192.0.2.88", "192.0.2.111", "192.0.2.77"), r.suspicious.map { it.ip })      // 위험 → 횟수 많은 순
        assertEquals(setOf(2, 1), r.suspicious.map { it.level }.toSet()); assertEquals(5, r.suspicious.size)
    }

    @Test fun accessLogLineFormatsAndRules() {
        val e = AccessLog.parse("203.0.113.7 - frank [10/Oct/2023:13:55:36 -0700] \"GET /apache_pb.gif?x=1 HTTP/1.0\" 200 2326 \"http://example.com/start.html\" \"Mozilla/4.08 [en] (Win98; I ;Nav)\"")!!
        assertEquals("203.0.113.7", e.ip); assertEquals("GET", e.method); assertEquals("/apache_pb.gif?x=1", e.path); assertEquals(200, e.status); assertEquals(2326L, e.bytes); assertEquals("http://example.com/start.html", e.referer); assertEquals("Mozilla/4.08 [en] (Win98; I ;Nav)", e.agent)
        assertEquals(Instant.parse("2023-10-10T20:55:36Z"), e.time!!.toInstant())                                              // -0700 → UTC
        val common = AccessLog.parse("2001:db8::1 - - [10/Oct/2023:13:55:36 +0000] \"HEAD / HTTP/1.1\" 304 -")!!                 // common 형식(리퍼러·UA 없음), IPv6, 크기 -
        assertEquals("2001:db8::1", common.ip); assertEquals(0L, common.bytes); assertNull(common.agent); assertNull(common.referer)
        val bad = AccessLog.parse("1.2.3.4 - - [10/Oct/2023:13:55:36 +0000] \"\\x16\\x03\\x01\" 400 0")!!; assertEquals("-", bad.method)    // 이상한 요청 줄
        assertNull(AccessLog.parse("not a log")); assertNull(AccessLog.parse(""))
        assertEquals("Chrome", AccessLog.family("Mozilla/5.0 Chrome/118 Safari/537.36")); assertEquals("Edg", AccessLog.family("Mozilla/5.0 Chrome/118 Safari/537.36 Edg/118.0")); assertEquals("(없음)", AccessLog.family(null)); assertEquals("Googlebot", AccessLog.family("Googlebot/2.1"))
        fun sus(path: String, ua: String = "Mozilla/5.0 Chrome/118") = AccessLog.summarize(listOf("9.9.9.9 - - [10/Oct/2023:13:55:36 +0000] \"GET $path HTTP/1.1\" 200 1 \"-\" \"$ua\"")).suspicious.map { it.reason }
        assertEquals(listOf("SQL 주입 시도"), sus("/a?q=1'%20or%201=1")); assertEquals(listOf("SQL 주입 시도"), sus("/a?q=1+UNION+ALL+SELECT+1,2")); assertEquals(listOf("스크립트 주입(XSS) 시도"), sus("/a?q=%3Cscript%3Ealert(1)"))
        assertEquals(listOf("경로 탈출 시도(../)"), sus("/download?f=..%2f..%2fetc/passwd")); assertEquals(listOf("비밀 파일 찾기(.env·.git·키)"), sus("/.git/config")); assertEquals(listOf("원격 실행 취약점 탐색"), sus("/\${jndi:ldap://x}"))
        assertEquals(listOf("관리자·로그인 페이지 탐색"), sus("/phpmyadmin/index.php")); assertEquals(listOf("공격 도구가 쓰는 User-Agent"), sus("/", "Mozilla/5.00 (Nikto/2.1.6)")); assertTrue(sus("/index.html").isEmpty()); assertTrue(sus("/products?id=12").isEmpty())
    }

    @Test fun toolLogAccess() {
        val r = run("log_access", "t" to res("access.log"))
        assertEquals("447줄 (읽지 못한 줄 2)", r.kv("분석한 줄")); assertEquals("23개", r.kv("서로 다른 IP")); assertEquals("2023-10-10 09:00:08 +0900 ~ 2023-10-10 11:58:35 +0900", r.kv("기간")); assertTrue(r.kv("봇·자동 요청").startsWith("114건"))
        assertTrue(r.hasError); assertTrue(r.text().contains("공격 시도 3종·탐색 2종")); assertTrue(r.rows().any { it[0] == "192.0.2.99" && it[1] == "공격 도구가 쓰는 User-Agent" && it[2] == "4" }); assertEquals(2, r.rowLevel("192.0.2.99"))
        assertTrue(r.rows().any { it[0] == "200" && it[1] == "358" }); assertEquals(2, r.rowLevel("500")); assertEquals(1, r.rowLevel("404")); assertTrue(r.text().contains("서버 오류(5xx)가 5건"))
        val hours = r.rows().filter { it[0].startsWith("2023-10-10 ") && it.size == 3 }; assertEquals(listOf("154", "173", "120"), hours.map { it[1] }); assertTrue(hours[1][2].length == 20)       // 최대 시간대 막대는 20칸
        val def = run("log_access"); assertEquals("6줄", def.kv("분석한 줄")); assertTrue(def.hasError); assertEquals(setOf("관리자·로그인 페이지 탐색", "공격 도구가 쓰는 User-Agent", "비밀 파일 찾기(.env·.git·키)", "SQL 주입 시도"), def.rows().filter { it.size == 5 }.map { it[1] }.toSet())
        assertTrue(run("log_access", "t" to "hello\nworld").hasError); assertTrue(run("log_access", "t" to "").text().contains("붙여 넣거나"))
        val clean = run("log_access", "t" to "1.1.1.1 - - [10/Oct/2023:13:55:36 +0000] \"GET / HTTP/1.1\" 200 5 \"-\" \"Mozilla/5.0 Chrome/118\""); assertFalse(clean.hasError); assertTrue(clean.text().contains("알려진 공격 패턴은 보이지 않아요"))
    }

    // ============================================================ SSH 인증 로그

    @Test fun authLogMatchesGroundTruth() {
        val exp = json("auth.json"); val ev = AuthLog.parse(res("auth.log").lines()); val r = AuthLog.report(ev, 10)
        assertEquals(exp.getInt("total"), r.failures); assertEquals(intMap(exp.getJSONObject("attempts")), r.byIp.toMap()); assertEquals(intMap(exp.getJSONObject("users")), r.byUser.toMap())
        val succ = exp.getJSONArray("success"); assertEquals((0 until succ.length()).map { succ.getJSONArray(it).let { a -> Triple(a.getString(0), a.getString(1), a.getString(2)) } }, r.successes.map { Triple(it.user!!, it.ip, it.method!!) })
        assertEquals(listOf("198.51.100.200" to 25, "203.0.113.9" to 14), r.brute); assertEquals(listOf("203.0.113.9" to 14), r.compromised)                // 많이 실패한 IP 중 성공도 있는 것만
        assertEquals(mapOf("publickey" to 1, "password" to 1), r.methods)
        assertEquals(1, AuthLog.report(ev, 20).brute.size); assertEquals(4, AuthLog.report(ev, 1).brute.size); assertEquals(0, AuthLog.report(ev, 100).brute.size)
    }

    @Test fun authLogLineKinds() {
        val lines = listOf("Oct 10 13:55:36 srv sshd[1]: Failed publickey for ubuntu from 1.2.3.4 port 22 ssh2", "Oct 10 13:55:37 srv sshd[1]: Disconnected from authenticating user root 5.6.7.8 port 22 [preauth]",
            "2023-10-10T13:55:38+09:00 srv sshd[2]: pam_unix(sshd:auth): authentication failure; logname= uid=0 euid=0 tty=ssh ruser= rhost=9.9.9.9  user=admin", "Oct 10 13:55:39 srv sshd[3]: error: maximum authentication attempts exceeded for invalid user x from 7.7.7.7 port 22 ssh2 [preauth]",
            "Oct 10 13:55:40 srv sshd[4]: Accepted keyboard-interactive/pam for kim from 8.8.8.8 port 22 ssh2", "Oct 10 13:55:41 srv sshd[5]: Invalid user  from 6.6.6.6 port 22", "Oct 10 13:55:42 srv CRON[6]: nothing here")
        val ev = AuthLog.parse(lines)
        assertEquals(listOf("fail", "closed", "pam", "maxtries", "accept", "invalid"), ev.map { it.kind }); assertEquals("publickey", ev[0].method); assertEquals("admin", ev[2].user); assertEquals("9.9.9.9", ev[2].ip); assertEquals("2023-10-10T13:55:38", ev[2].time)
        assertEquals("Oct 10 13:55:36", ev[0].time); assertEquals("(빈 이름)", ev[5].user)
        val r = AuthLog.report(ev, 1); assertEquals(4, r.failures)                           // fail·closed·pam·invalid 각 1번 (maxtries·accept 는 세지 않음)
        // 한 번의 시도가 여러 줄이어도 한 번으로: Invalid user + Failed password + Connection closed
        val one = AuthLog.parse(listOf("Oct 10 1:00:00 s sshd[1]: Invalid user bob from 1.1.1.1 port 1", "Oct 10 1:00:01 s sshd[1]: Failed password for invalid user bob from 1.1.1.1 port 1 ssh2", "Oct 10 1:00:02 s sshd[1]: Connection closed by invalid user bob 1.1.1.1 port 1 [preauth]"))
        assertEquals(1, AuthLog.report(one, 1).failures)
    }

    @Test fun toolLogAuth() {
        val r = run("log_auth", "t" to res("auth.log"), "th" to "10")
        assertEquals("53번", r.kv("실패한 로그인 시도")); assertEquals("2개", r.kv("10번 이상 시도한 IP")); assertEquals("2번", r.kv("성공한 로그인")); assertEquals(2, r.kvLevel("10번 이상 시도한 IP")); assertTrue(r.hasError)
        assertTrue(r.text().contains("203.0.113.9 (")); assertTrue(r.text().contains("14번 실패한 뒤 1번 로그인에 성공했어요 (계정: admin)")); assertTrue(r.blocks().contains("sudo ufw deny from 198.51.100.200 to any")); assertTrue(r.blocks().contains("maxretry = 5"))
        assertTrue(r.rows().any { it[0] == "198.51.100.200" && it[1] == "25" }); assertTrue(r.rows().any { it[0] == "root" && it[1] == "11" }); assertTrue(r.text().contains("비밀번호로 로그인한 기록이 1번"))
        val def = run("log_auth"); assertEquals("4번", def.kv("실패한 로그인 시도")); assertEquals("0개", def.kv("5번 이상 시도한 IP")); assertEquals("2번", def.kv("성공한 로그인")); assertFalse(def.hasError)
        assertTrue(run("log_auth", "t" to "nothing about ssh here").hasError)
    }

    // ============================================================ syslog · JSON 줄 · 시간 간격

    @Test fun syslogMatchesIndependentCounts() {
        val exp = json("syslog.json"); val r = SyslogSummary.summarize(res("syslog.txt").lines())
        assertEquals(exp.getInt("total"), r.total); assertEquals(intMap(exp.getJSONObject("progs")), r.byProg.toMap()); assertEquals(1, r.hosts)
        assertEquals(exp.getJSONObject("sev").getInt("오류"), r.severity.entries.first { it.key.startsWith("오류") }.value); assertEquals(0, r.severity.entries.first { it.key.startsWith("치명") }.value); assertEquals(0, r.severity.entries.first { it.key.startsWith("경고") }.value)
        assertEquals(30, r.notable.size); assertTrue(r.notable.all { SyslogSummary.parseLine(it.time + " web1 " + it.prog + ": " + it.msg) != null })
        assertEquals("Accepted publickey for ubuntu from <ip> port #", SyslogSummary.template("Accepted publickey for ubuntu from 192.0.2.17 port 40022")); assertEquals("link <mac> up <hex>", SyslogSummary.template("link aa:bb:cc:dd:ee:ff up 0xdeadbeef"))
        val iso = SyslogSummary.parseLine("2023-10-10T13:55:36.123456+09:00 host sshd[12]: hello world")!!; assertEquals("sshd", iso.prog); assertEquals("hello world", iso.msg); assertEquals("host", iso.host)
        assertNull(SyslogSummary.parseLine("-- Logs begin at Tue --"))
        val d = run("log_syslog"); assertEquals("4줄", d.kv("분석한 줄")); assertTrue(d.rows().any { it[0].startsWith("오류") && it[1] == "2" }); assertTrue(d.text().contains("주의할 메시지")); assertTrue(run("log_syslog", "t" to "hello").hasError)
        assertTrue(run("log_syslog", "t" to "Oct 10 13:55:36 h kernel: Kernel panic - not syncing: Fatal exception").text().contains("치명적 메시지가 있어요"))
    }

    @Test fun jsonLogsMatchIndependentCounts() {
        val exp = json("jsonl.json"); val r = JsonLogs.summarize(res("app.jsonl").lines(), "user")
        assertEquals(exp.getInt("total"), r.total); assertEquals(exp.getInt("bad"), r.bad); assertEquals(intMap(exp.getJSONObject("levels")), r.levels.toMap()); assertEquals(intMap(exp.getJSONObject("keys")), r.keys.toMap()); assertEquals(intMap(exp.getJSONObject("users")), r.fieldValues.toMap())
        assertEquals(exp.getString("first"), r.first); assertEquals(exp.getString("last"), r.last); assertEquals(exp.getInt("errors"), r.errors.size);
        assertEquals(setOf("user login", "db timeout after #ms", "cache miss for key #"), r.messages.map { it.first }.toSet()); assertEquals(150, r.messages.sumOf { it.second })
        assertEquals(404, JsonLogs.get(JSONObject("{\"http\":{\"status\":404}}"), "http.status")); assertEquals(5, JsonLogs.get(JSONObject("{\"a.b\":5}"), "a.b")); assertNull(JsonLogs.get(JSONObject("{\"a\":1}"), "a.b"))
        assertEquals("2023-10-10T04:55:36Z", JsonLogs.timeText(1696913736)); assertEquals("2023-10-10T04:55:36.123Z", JsonLogs.timeText(1696913736123L)); assertEquals("x", JsonLogs.timeText("x")); assertNull(JsonLogs.timeText(null))
        val nested = JsonLogs.summarize(res("app.jsonl").lines(), "http.status"); assertEquals(setOf("200", "404", "500"), nested.fieldValues.map { it.first }.toSet()); assertEquals(150, nested.fieldValues.sumOf { it.second })
        val t = run("log_jsonl", "t" to res("app.jsonl"), "field" to "user"); assertEquals("150줄 (JSON 이 아닌 줄 2)", t.kv("분석한 줄")); assertTrue(t.rows().any { it[0] == "choi" && it[1] == "42" }); assertTrue(t.rows().any { it[0] == "error" && it[1] == "9" }); assertEquals(2, t.rowLevel("error"))
        val d = run("log_jsonl"); assertEquals("3줄", d.kv("분석한 줄")); assertTrue(d.blocks().contains("db timeout")); assertTrue(run("log_jsonl", "t" to "plain text\nmore").hasError); assertTrue(run("log_jsonl", "field" to "nothing").text().contains("그 필드가 있는 줄이 없어요"))
    }

    @Test fun logTimeExtractionAndGaps() {
        val utc = Instant.parse("2023-10-10T04:55:36Z")
        assertEquals(utc, LogTime.extract("2023-10-10T13:55:36+09:00 hello", 2023)); assertEquals(utc, LogTime.extract("1.2.3.4 - - [10/Oct/2023:13:55:36 +0900] \"GET /\"", 2023)); assertEquals(utc, LogTime.extract("1696913736 msg", 2023)); assertEquals(utc, LogTime.extract("1696913736000 msg", 2023))
        assertEquals(Instant.parse("2023-10-10T13:55:36Z"), LogTime.extract("Oct 10 13:55:36 host x", 2023)); assertEquals(Instant.parse("2023-10-10T13:55:36.123Z"), LogTime.extract("2023-10-10 13:55:36,123 INFO", 2023)); assertEquals(Instant.parse("2023-10-10T04:55:36Z"), LogTime.extract("2023-10-10 13:55:36+0900 x", 2023))
        assertNull(LogTime.extract("no time here", 2023)); assertNull(LogTime.extract("2023-13-45 99:99:99", 2023))
        val exp = json("ticks.json"); val r = LogTime.analyze(res("ticks.log").lines(), 600, 2023)
        assertEquals(exp.getInt("count"), r.stamped); assertEquals(exp.getDouble("median"), r.medianSec, 1e-9); assertEquals(exp.getDouble("max"), r.maxSec, 1e-9); assertEquals(Instant.parse(exp.getString("first")), r.first); assertEquals(0, r.outOfOrder)
        val g = exp.getJSONArray("gaps"); assertEquals(g.length(), r.gaps.size)
        for (k in 0 until g.length()) { val x = g.getJSONArray(k); assertEquals(Instant.parse(x.getString(0).replace(' ', 'T') + "Z"), r.gaps[k].from); assertEquals(Instant.parse(x.getString(1).replace(' ', 'T') + "Z"), r.gaps[k].to); assertEquals(x.getLong(2), r.gaps[k].seconds); assertEquals(x.getInt(3), r.gaps[k].line) }
        // 연말 → 새해, 순서가 거꾸로인 줄, 한 분에 몰린 줄
        val ny = LogTime.analyze(listOf("Dec 31 23:59:59 h a", "Jan  1 00:00:05 h b"), 3, 2023); assertEquals(6, ny.gaps.single().seconds); assertEquals(Instant.parse("2024-01-01T00:00:05Z"), ny.last)
        val rev = LogTime.analyze(listOf("2023-10-10 10:00:10 a", "2023-10-10 10:00:05 b", "2023-10-10 10:00:20 c"), 1000, 2023); assertEquals(1, rev.outOfOrder)
        val busy = LogTime.analyze((0 until 5).map { "2023-10-10 10:05:0$it x" } + listOf("2023-10-10 10:09:00 y"), 1000, 2023); assertEquals("2023-10-10T10:05" to 5, busy.busiestMinute)
        assertEquals("45초", LogTime.human(45)); assertEquals("13분 0초", LogTime.human(780)); assertEquals("2시간 0분", LogTime.human(7200)); assertEquals("3일 2시간", LogTime.human(3 * 86400 + 7200))
        val t = run("log_time_gaps", "t" to res("ticks.log"), "th" to "600"); assertTrue(t.text().contains("(2곳)")); assertEquals("2시간 0분", t.kv("가장 긴 간격")); assertEquals(2, t.rows().count { it.size == 4 })
        assertEquals("13분 0초", run("log_time_gaps").kv("가장 긴 간격")); assertTrue(run("log_time_gaps", "t" to "no timestamps\nat all").hasError)
    }

    // ============================================================ HAR

    @Test fun harMatchesIndependentTotals() {
        val exp = json("har.json"); val r = HarSummary.parse(res("page.har"))
        assertEquals(exp.getInt("count"), r.reqs.size); assertEquals(exp.getLong("transfer"), r.transfer); assertEquals(exp.getLong("content"), r.content); assertEquals(exp.getInt("failed"), r.failed.size); assertEquals(exp.getDouble("avgWait"), r.avgTiming[HarSummary.PHASES.indexOf("wait")], 1e-9)
        val slow = exp.getJSONArray("slowest"); assertEquals((0 until 3).map { slow.getDouble(it) }, r.slowest.take(3).map { it.timeMs }); assertEquals(exp.getInt("third"), r.thirdParty.sumOf { it.second }); assertEquals(3456.0, r.pageLoadMs!!, 1e-9); assertEquals(1234.0, r.domContentMs!!, 1e-9)
        assertEquals("www.shop.example", r.firstHost); assertEquals(mapOf("h2" to 14, "http/1.1" to 14), r.protocols); assertTrue(r.byType.map { it.first }.containsAll(listOf("HTML", "스크립트(JS)", "스타일(CSS)", "이미지", "데이터(JSON·XML)")))
        assertEquals(r.transfer, r.byType.sumOf { it.third }); assertEquals(listOf("cdn.other.net", "www.google-analytics.com"), r.thirdParty.map { it.first }.sorted())
        // 작은 HAR: 압축 안 한 텍스트·캐시 없는 정적 파일·혼합 콘텐츠
        val tiny = "{\"log\":{\"entries\":[{\"time\":10,\"request\":{\"method\":\"GET\",\"url\":\"https://a.example/\"},\"response\":{\"status\":200,\"httpVersion\":\"HTTP/2.0\",\"headers\":[],\"content\":{\"size\":9000,\"mimeType\":\"text/html\"},\"bodySize\":9000,\"headersSize\":100},\"timings\":{\"wait\":5}}," +
            "{\"time\":20,\"request\":{\"method\":\"GET\",\"url\":\"http://a.example/x.png\"},\"response\":{\"status\":200,\"httpVersion\":\"http/1.1\",\"headers\":[{\"name\":\"cache-control\",\"value\":\"max-age=3600\"}],\"content\":{\"size\":100,\"mimeType\":\"image/png\"},\"bodySize\":100},\"timings\":{}}," +
            "{\"time\":30,\"request\":{\"method\":\"GET\",\"url\":\"https://a.example/app.js\"},\"response\":{\"status\":200,\"headers\":[],\"content\":{\"size\":5000,\"mimeType\":\"application/javascript\"},\"bodySize\":5000},\"timings\":{}}]}}"
        val t = HarSummary.parse(tiny)
        assertEquals(listOf("https://a.example/"), t.notCompressed.map { it.url }.filter { it.endsWith("/") }); assertEquals(2, t.notCompressed.size); assertEquals(listOf("https://a.example/app.js"), t.noCache.map { it.url }); assertEquals(listOf("http://a.example/x.png"), t.mixed.map { it.url })
        assertEquals("h2", t.reqs[0].http); assertEquals(0.0, t.reqs[0].t[HarSummary.PHASES.indexOf("dns")], 0.0)
        try { HarSummary.parse("not json"); org.junit.Assert.fail() } catch (_: org.json.JSONException) { }
        val tool = run("log_har", "t" to res("page.har")); assertEquals("28개", tool.kv("요청 수")); assertEquals("3456ms", tool.kv("페이지 로드(onLoad)")); assertEquals(1, tool.kvLevel("페이지 로드(onLoad)")); assertTrue(tool.rows().any { it[0] == "wait" && it[2].startsWith("서버가 응답하기까지") })
        assertTrue(tool.rows().any { it[0] == "cdn.other.net" && it[2] == "외부(제3자)" }); assertTrue(tool.rows().any { it[0] == "www.shop.example" && it[2] == "같은 사이트" }); assertEquals(0, tool.cols().first { it.cells[0] == "wait" }.level)                             // 평균 대기 467ms 는 500ms 미만이라 주의 표시 없음
        val d = run("log_har"); assertEquals("2개", d.kv("요청 수")); assertTrue(d.text().contains("압축하지 않은 텍스트 파일이 1개")); assertTrue(d.text().contains("캐시 설정")); assertTrue(d.text().contains("외부 도메인")); assertFalse(d.hasError)
        val mixed = run("log_har", "t" to tiny); assertTrue(mixed.hasError); assertTrue(mixed.text().contains("혼합 콘텐츠")); assertTrue(run("log_har", "t" to "oops").hasError)
    }

    // ============================================================ traceroute

    private val LINUX_TRACE = "traceroute to example.com (93.184.216.34), 30 hops max, 60 byte packets\n 1  _gateway (192.168.0.1)  0.523 ms  0.481 ms  0.465 ms\n 2  10.20.0.1 (10.20.0.1)  4.201 ms  4.188 ms  4.150 ms\n 3  * * *\n" +
        " 4  112.174.47.9 (112.174.47.9)  5.800 ms 112.174.47.10 (112.174.47.10)  6.020 ms  5.911 ms\n 5  ae-1.r01.example.net (203.0.113.5)  160.442 ms  161.021 ms  *\n 6  93.184.216.34 (93.184.216.34)  162.100 ms  161.900 ms  162.300 ms\n" +
        " 7  192.168.9.9 (192.168.9.9)  3000.1 ms !H  3000.2 ms !H  3000.3 ms !H\n 8  r1.example.net (10.0.0.1)  5.0 ms  5.1 ms\n    r2.example.net (10.0.0.2)  6.0 ms\n 9  2001:db8::1 (2001:db8::1)  7.5 ms  7.6 ms  7.7 ms"
    private val WIN_TRACE = "Tracing route to example.com [93.184.216.34]\nover a maximum of 30 hops:\n\n  1    <1 ms    <1 ms    <1 ms  192.168.0.1\n  2     5 ms     4 ms     5 ms  10.20.0.1\n  3     *        *        *     Request timed out.\n  4    12 ms    11 ms    13 ms  host.example.net [203.0.113.5]\n  5   160 ms   161 ms   160 ms  93.184.216.34\n\nTrace complete."

    @Test fun tracerouteParsesLinuxMacAndWindows() {
        val t = TraceParse.parse(LINUX_TRACE)
        assertEquals("example.com", t.target); assertEquals("93.184.216.34", t.targetIp); assertFalse(t.windows); assertEquals(9, t.hops.size)
        val h1 = t.hops[0]; assertEquals(listOf("192.168.0.1"), h1.addrs); assertEquals("_gateway", h1.hostOf("192.168.0.1")); assertEquals(listOf(0.523, 0.481, 0.465), h1.rtts); assertEquals(0.4897, h1.avg!!, 1e-3); assertEquals(0, h1.loss)
        assertTrue(t.hops[2].addrs.isEmpty()); assertEquals(3, t.hops[2].loss); assertNull(t.hops[2].avg)
        assertEquals(listOf("112.174.47.9", "112.174.47.10"), t.hops[3].addrs); assertEquals(listOf(5.8, 6.02, 5.911), t.hops[3].rtts)         // 주소가 바뀐 뒤의 시간은 새 주소 것
        assertEquals(1, t.hops[4].loss); assertEquals(listOf(160.442, 161.021), t.hops[4].rtts); assertEquals("ae-1.r01.example.net", t.hops[4].hostOf("203.0.113.5")); assertEquals(listOf("93.184.216.34"), t.hops[5].addrs)
        assertEquals(listOf("!H", "!H", "!H"), t.hops[6].flags); assertEquals(3000.1, t.hops[6].rtts[0], 1e-9)
        assertEquals(listOf("10.0.0.1", "10.0.0.2"), t.hops[7].addrs); assertEquals(3, t.hops[7].rtts.size)                                      // 같은 홉의 다음 줄
        assertEquals(listOf("2001:db8::1"), t.hops[8].addrs)
        val w = TraceParse.parse(WIN_TRACE); assertTrue(w.windows); assertEquals("example.com", w.target); assertEquals(5, w.hops.size); assertEquals(listOf(0.5, 0.5, 0.5), w.hops[0].rtts); assertEquals(3, w.hops[2].loss); assertTrue(w.hops[2].addrs.isEmpty())
        assertEquals("host.example.net", w.hops[3].hostOf("203.0.113.5")); assertEquals(listOf(12.0, 11.0, 13.0), w.hops[3].rtts); assertEquals(listOf("93.184.216.34"), w.hops[4].addrs)
        val ko = TraceParse.parse("example.com [93.184.216.34](으)로 가는 경로 추적, 최대 홉 수 30:\n\n  1    <1ms    <1ms    <1ms  192.168.0.1\n  2     3ms     2ms     3ms  93.184.216.34\n\n추적을 완료했습니다."); assertEquals("93.184.216.34", ko.targetIp); assertEquals(2, ko.hops.size); assertEquals(listOf(3.0, 2.0, 3.0), ko.hops[1].rtts)
        assertTrue(TraceParse.parse("nothing useful").hops.isEmpty())
    }

    @Test fun toolLogTraceroute() {
        val r = run("log_traceroute")
        assertEquals("example.com (93.184.216.34)", r.kv("목적지")); assertEquals("6개", r.kv("홉 수")); assertEquals("traceroute", r.kv("형식")); assertEquals(6, r.rows().size)
        assertEquals("응답 없음 (* * *)", r.row("3")[1]); assertEquals("3/3", r.row("3")[3]); assertEquals(1, r.rowLevel("3")); assertEquals(1, r.rowLevel("5")); assertTrue(r.row("1")[1].startsWith("192.168.0.1 (_gateway)")); assertEquals("내부 주소", r.row("1")[4]); assertEquals("0/3", r.row("5")[3])
        assertTrue(r.text().contains("목적지에 도착했어요 (최종 평균 162ms)")); assertTrue(r.text().contains("홉 4 → 5 에서 지연이")); assertTrue(r.text().contains("중간에 응답 없는 홉이 1개")); assertFalse(r.hasError)
        val un = run("log_traceroute", "t" to "traceroute to x.example (9.9.9.9), 30 hops max\n 1  192.168.0.1 (192.168.0.1)  1.0 ms  1.0 ms  1.0 ms\n 2  10.0.0.1 (10.0.0.1)  2.0 ms !X  2.0 ms !X  2.0 ms !X\n 3  * * *")
        assertTrue(un.hasError); assertTrue(un.text().contains("목적지까지 도착하지 못했어요")); assertTrue(un.text().contains("방화벽")); assertEquals("윈도 tracert", run("log_traceroute", "t" to WIN_TRACE).kv("형식")); assertTrue(run("log_traceroute", "t" to "hello").hasError)
    }

    // ============================================================ ip addr · ifconfig · ipconfig

    @Test fun interfacesParseAllFormats() {
        val ipa = IfaceParse.parse("1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN group default qlen 1000\n    link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00\n    inet 127.0.0.1/8 scope host lo\n" +
            "2: eth0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc fq_codel state UP group default qlen 1000\n    link/ether 52:54:00:12:34:56 brd ff:ff:ff:ff:ff:ff\n    inet 192.168.1.10/24 brd 192.168.1.255 scope global dynamic eth0\n       valid_lft 85000sec preferred_lft 85000sec\n    inet6 fe80::5054:ff:fe12:3456/64 scope link\n" +
            "3: docker0: <NO-CARRIER,BROADCAST,MULTICAST,UP> mtu 1500 qdisc noqueue state DOWN group default\n    link/ether 02:42:ac:11:00:01 brd ff:ff:ff:ff:ff:ff\n    inet 172.17.0.1/16 brd 172.17.255.255 scope global docker0")
        assertEquals(listOf("lo", "eth0", "docker0"), ipa.map { it.name }); val e = ipa[1]
        assertEquals("UP", e.state); assertEquals("52:54:00:12:34:56", e.mac); assertEquals(1500, e.mtu); assertEquals(2, e.addrs.size)
        assertEquals("192.168.1.10", e.addrs[0].ip); assertEquals(24, e.addrs[0].prefix); assertEquals("global", e.addrs[0].scope); assertFalse(e.addrs[0].v6); assertEquals("fe80::5054:ff:fe12:3456", e.addrs[1].ip); assertEquals(64, e.addrs[1].prefix); assertEquals("link", e.addrs[1].scope); assertTrue(e.addrs[1].v6)
        assertEquals("DOWN", ipa[2].state); assertEquals(16, ipa[2].addrs[0].prefix)
        val ifc = IfaceParse.parse("eth0: flags=4163<UP,BROADCAST,RUNNING,MULTICAST>  mtu 1492\n        inet 192.168.1.10  netmask 255.255.255.0  broadcast 192.168.1.255\n        inet6 fe80::5054:ff:fe12:3456  prefixlen 64  scopeid 0x20<link>\n        ether 52:54:00:12:34:56  txqueuelen 1000  (Ethernet)\n")
        assertEquals(1492, ifc[0].mtu); assertEquals(24, ifc[0].addrs[0].prefix); assertEquals(64, ifc[0].addrs[1].prefix); assertEquals("link", ifc[0].addrs[1].scope); assertEquals("52:54:00:12:34:56", ifc[0].mac)
        val mac = IfaceParse.parse("en0: flags=8863<UP,BROADCAST,SMART,RUNNING,SIMPLEX,MULTICAST> mtu 1500\n\tether aa:bb:cc:dd:ee:ff\n\tinet 192.168.1.5 netmask 0xffffff00 broadcast 192.168.1.255\n"); assertEquals(24, mac[0].addrs[0].prefix); assertEquals("aa:bb:cc:dd:ee:ff", mac[0].mac)
        val old = IfaceParse.parse("eth0      Link encap:Ethernet  HWaddr 00:0c:29:aa:bb:cc\n          inet addr:192.168.1.10  Bcast:192.168.1.255  Mask:255.255.255.0\n          inet6 addr: fe80::20c:29ff:feaa:bbcc/64 Scope:Link\n"); assertEquals("00:0c:29:aa:bb:cc", old[0].mac); assertEquals(24, old[0].addrs[0].prefix); assertEquals(64, old[0].addrs[1].prefix); assertEquals("link", old[0].addrs[1].scope)
        val win = IfaceParse.parse("Windows IP Configuration\n\nEthernet adapter Ethernet:\n\n   Connection-specific DNS Suffix  . : lan\n   Description . . . . . . . . . . . : Intel(R) Ethernet\n   Physical Address. . . . . . . . . : 00-11-22-33-44-55\n   DHCP Enabled. . . . . . . . . . . : Yes\n" +
            "   Link-local IPv6 Address . . . . . : fe80::1234:5678:9abc:def0%12(Preferred)\n   IPv4 Address. . . . . . . . . . . : 192.168.0.5(Preferred)\n   Subnet Mask . . . . . . . . . . . : 255.255.255.0\n   Default Gateway . . . . . . . . . : 192.168.0.1\n   DNS Servers . . . . . . . . . . . : 168.126.63.1\n                                       168.126.63.2\n\n" +
            "Wireless LAN adapter Wi-Fi:\n\n   Media State . . . . . . . . . . . : Media disconnected\n")
        assertEquals(listOf("Ethernet", "Wi-Fi"), win.map { it.name }); val we = win[0]; assertEquals("00:11:22:33:44:55", we.mac); assertEquals(true, we.dhcp); assertEquals(listOf("192.168.0.1"), we.gateways); assertEquals(listOf("168.126.63.1", "168.126.63.2"), we.dns)
        assertEquals("192.168.0.5", we.addrs.first { !it.v6 }.ip); assertEquals(24, we.addrs.first { !it.v6 }.prefix); assertEquals("fe80::1234:5678:9abc:def0", we.addrs.first { it.v6 }.ip); assertEquals("link", we.addrs.first { it.v6 }.scope); assertEquals("Media disconnected", win[1].media)
        val ko = IfaceParse.parse("이더넷 어댑터 이더넷:\n\n   물리적 주소 . . . . . . . . . . . : AA-BB-CC-DD-EE-FF\n   DHCP 사용 . . . . . . . . . . . . : 예\n   IPv4 주소 . . . . . . . . . . . . : 10.0.0.7(기본 설정)\n   서브넷 마스크 . . . . . . . . . . : 255.255.0.0\n   기본 게이트웨이 . . . . . . . . . : 10.0.0.1\n   DNS 서버. . . . . . . . . . . . . : 8.8.8.8\n")
        assertEquals("이더넷", ko[0].name); assertEquals("aa:bb:cc:dd:ee:ff", ko[0].mac); assertEquals(true, ko[0].dhcp); assertEquals(16, ko[0].addrs[0].prefix); assertEquals(listOf("10.0.0.1"), ko[0].gateways); assertEquals(listOf("8.8.8.8"), ko[0].dns)
        assertEquals(24, IfaceParse.maskToPrefix("255.255.255.0")); assertEquals(20, IfaceParse.maskToPrefix("255.255.240.0")); assertEquals(24, IfaceParse.maskToPrefix("0xffffff00")); assertNull(IfaceParse.maskToPrefix("garbage")); assertTrue(IfaceParse.parse("hello").isEmpty())
    }

    @Test fun toolLogIface() {
        val r = run("log_iface"); assertEquals("3개 (2개가 IPv4 주소를 가짐)", r.kv("인터페이스")); assertTrue(r.hasError); assertTrue(r.text().contains("169.254.x.x 는 DHCP")); assertTrue(r.outs.filterIsInstance<Out.Kv>().any { it.label == "IPv4" && it.value.startsWith("169.254.12.7/16") && it.level == 2 })
        assertTrue(r.outs.filterIsInstance<Out.Kv>().any { it.label == "IPv4" && it.value.contains("192.168.1.10/24") && it.value.contains("사설 주소") }); assertTrue(r.outs.filterIsInstance<Out.Head>().any { it.text == "eth0  ·  UP" }); assertEquals("52:54:00:12:34:56", r.kvAll("MAC")[0]); assertFalse(r.kvAll("MAC").contains("00:00:00:00:00:00"))
        val v = run("log_iface", "t" to "5: tun0: <POINTOPOINT,UP,LOWER_UP> mtu 1400 qdisc fq_codel state UNKNOWN\n    inet 100.64.1.2/10 scope global tun0\n6: veth1a2b: <BROADCAST,UP> mtu 9000 state UP\n    inet 10.0.0.2/24 scope global veth1a2b\n7: eth9: <BROADCAST,UP> mtu 1500 state UP\n    link/ether aa:aa:aa:aa:aa:aa brd ff:ff:ff:ff:ff:ff")
        assertTrue(v.text().contains("MTU 1400 는 터널·VPN")); assertTrue(v.text().contains("점보 프레임")); assertTrue(v.text().contains("100.64.0.0/10 주소예요")); assertTrue(v.text().contains("가상 인터페이스")); assertTrue(v.text().contains("인터페이스는 켜져 있지만 IPv4 주소가 없어요")); assertTrue(run("log_iface", "t" to "hello").hasError)
    }

    // ============================================================ ss · netstat

    @Test fun socketsParseSsNetstatAndWindows() {
        assertEquals("::" to 80, SockParse.splitAddr("[::]:80")); assertEquals("::" to 22, SockParse.splitAddr(":::22")); assertEquals("*" to null, SockParse.splitAddr("*:*")); assertEquals("127.0.0.53" to 53, SockParse.splitAddr("127.0.0.53%lo:53")); assertEquals("fe80::1" to 546, SockParse.splitAddr("[fe80::1%eth0]:546")); assertEquals("10.0.0.1" to null, SockParse.splitAddr("10.0.0.1:*"))
        assertEquals(2, SockParse.exposure("0.0.0.0")); assertEquals(2, SockParse.exposure("::")); assertEquals(2, SockParse.exposure("*")); assertEquals(0, SockParse.exposure("127.0.0.1")); assertEquals(0, SockParse.exposure("::1")); assertEquals(1, SockParse.exposure("192.168.1.10"))
        val ss = SockParse.parse("Netid State  Recv-Q Send-Q Local Address:Port Peer Address:Port Process\ntcp   LISTEN 0      128    0.0.0.0:22         0.0.0.0:*     users:((\"sshd\",pid=812,fd=3))\ntcp   ESTAB  0      0      192.168.1.10:22    203.0.113.9:51234 users:((\"sshd\",pid=2301,fd=4))\n" +
            "tcp   TIME-WAIT 0   0      192.168.1.10:80    198.51.100.7:40000\nudp   UNCONN 0      0      127.0.0.53%lo:53   0.0.0.0:*\ntcp   LISTEN 0      4096   [::]:80            [::]:*\n")
        assertEquals(5, ss.size); assertEquals("LISTEN", ss[0].state); assertEquals("sshd (pid 812)", ss[0].proc); assertEquals(22, ss[0].lport); assertEquals("ESTABLISHED", ss[1].state); assertEquals("203.0.113.9", ss[1].peer); assertEquals(51234, ss[1].pport); assertEquals("TIME_WAIT", ss[2].state)
        assertEquals("udp", ss[3].proto); assertEquals("UDP", ss[3].state); assertEquals("127.0.0.53", ss[3].local); assertEquals("::", ss[4].local); assertEquals(80, ss[4].lport)
        val ss2 = SockParse.parse("State  Recv-Q Send-Q Local Address:Port Peer Address:Port\nLISTEN 0 128 0.0.0.0:22 0.0.0.0:*\nESTAB 0 0 10.0.0.1:22 10.0.0.2:5555\nCLOSE-WAIT 1 0 10.0.0.1:80 10.0.0.3:6666"); assertEquals(listOf("LISTEN", "ESTABLISHED", "CLOSE_WAIT"), ss2.map { it.state })
        val ns = SockParse.parse("Proto Recv-Q Send-Q Local Address           Foreign Address         State       PID/Program name\ntcp        0      0 0.0.0.0:22              0.0.0.0:*               LISTEN      812/sshd\ntcp6       0      0 :::80                   :::*                    LISTEN      900/nginx: master\nudp        0      0 0.0.0.0:68              0.0.0.0:*                           611/dhclient\ntcp        0      0 10.0.0.1:22             1.2.3.4:5555            ESTABLISHED -\n")
        assertEquals(4, ns.size); assertEquals("812/sshd", ns[0].proc); assertEquals("::", ns[1].local); assertEquals("udp", ns[2].proto); assertEquals("UDP", ns[2].state); assertEquals(68, ns[2].lport); assertEquals("ESTABLISHED", ns[3].state); assertNull(ns[3].proc)
        val win = SockParse.parse("Active Connections\n\n  Proto  Local Address          Foreign Address        State           PID\n  TCP    0.0.0.0:135            0.0.0.0:0              LISTENING       1012\n  TCP    192.168.0.5:49700      142.250.196.110:443    ESTABLISHED     4120\n  TCP    [::]:445               [::]:0                 LISTENING       4\n  UDP    0.0.0.0:5353           *:*                                    2140\n")
        assertEquals(4, win.size); assertEquals("LISTEN", win[0].state); assertEquals("PID 1012", win[0].proc); assertEquals("142.250.196.110", win[1].peer); assertEquals(443, win[1].pport); assertEquals("::", win[2].local); assertEquals(445, win[2].lport); assertEquals("udp", win[3].proto); assertEquals("PID 2140", win[3].proc)
        assertTrue(SockParse.parse("hello world").isEmpty())
    }

    @Test fun toolLogSockets() {
        val r = run("log_sockets"); assertEquals("7개", r.kv("전체 소켓")); assertEquals("4개", r.kv("열려 있는(LISTEN·UDP)")); assertEquals("2개", r.kv("연결됨(ESTABLISHED)")); assertEquals("2개", r.kv("외부에 노출된 포트")); assertEquals(2, r.kvLevel("외부에 노출된 포트")); assertTrue(r.hasError)
        assertEquals(2, r.cols().first { it.cells[2] == "6379" }.level); assertEquals("Redis (데이터베이스)", r.cols().first { it.cells[2] == "6379" }.cells[5]); assertEquals(1, r.cols().first { it.cells[2] == "22" }.level); assertEquals(0, r.cols().first { it.cells[2] == "5432" }.level); assertEquals("이 기기 안에서만", r.cols().first { it.cells[2] == "5432" }.cells[4])
        assertEquals(listOf("22", "6379"), r.cols().filter { it.cells.size == 6 && it.cells[4] == "모든 곳에서 접속 가능" }.map { it.cells[2] })           // 노출된 것이 먼저, 같으면 포트 번호 순
        assertTrue(r.text().contains("6379번 Redis")); assertTrue(r.rows().any { it[0] == "8.8.8.8" && it[1] == "1" && it[2] == "443" && it[3].contains("Google") }); assertTrue(r.rows().any { it[0] == "TIME_WAIT" && it[1] == "1" })
        val leak = "State Recv-Q Send-Q Local Address:Port Peer Address:Port\n" + (1..25).joinToString("\n") { "CLOSE-WAIT 1 0 10.0.0.1:8080 10.0.1.$it:5000" } + "\n" + (1..60).joinToString("\n") { "SYN-RECV 0 0 10.0.0.1:80 11.0.1.${it % 250}:40$it" }
        val l = run("log_sockets", "t" to leak); assertTrue(l.text().contains("CLOSE_WAIT 가 25개")); assertTrue(l.text().contains("SYN_RECV 가 60개")); assertTrue(l.hasError); assertTrue(run("log_sockets", "t" to "hello").hasError)
    }

    // ============================================================ dig · nslookup

    private val DIG_OK = "; <<>> DiG 9.18.12 <<>> example.com\n;; global options: +cmd\n;; Got answer:\n;; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 4242\n;; flags: qr rd ra; QUERY: 1, ANSWER: 2, AUTHORITY: 0, ADDITIONAL: 1\n\n;; OPT PSEUDOSECTION:\n; EDNS: version: 0, flags:; udp: 65494\n;; QUESTION SECTION:\n;example.com.\t\t\tIN\tA\n\n" +
        ";; ANSWER SECTION:\nexample.com.\t\t300\tIN\tA\t93.184.216.34\nexample.com.\t\t300\tIN\tA\t93.184.216.35\n\n;; Query time: 231 msec\n;; SERVER: 8.8.8.8#53(8.8.8.8) (UDP)\n;; WHEN: Tue Oct 10 13:55:36 KST 2023\n;; MSG SIZE  rcvd: 72"

    @Test fun digAndNslookupParse() {
        val r = DigParse.parse(DIG_OK)
        assertEquals("dig", r.kind); assertEquals("example.com", r.query); assertEquals("NOERROR", r.status); assertEquals(listOf("qr", "rd", "ra"), r.flags); assertEquals(mapOf("QUERY" to 1, "ANSWER" to 2, "AUTHORITY" to 0, "ADDITIONAL" to 1), r.counts)
        assertEquals(231, r.queryMs); assertEquals("8.8.8.8#53", r.server); assertEquals("UDP", r.proto); assertEquals(72, r.size); assertEquals(2, r.recs.size); assertEquals("example.com", r.recs[0].name); assertEquals(300L, r.recs[0].ttl); assertEquals("A", r.recs[0].type); assertEquals("93.184.216.34", r.recs[0].data); assertEquals("ANSWER", r.recs[0].section)
        val auth = DigParse.parse(";; ->>HEADER<<- opcode: QUERY, status: NXDOMAIN, id: 1\n;; flags: qr rd ra; QUERY: 1, ANSWER: 0, AUTHORITY: 1, ADDITIONAL: 1\n\n;; QUESTION SECTION:\n;nope.example.com.\tIN\tA\n\n;; AUTHORITY SECTION:\nexample.com.\t\t900\tIN\tSOA\tns.icann.org. noc.dns.icann.org. 2023100901 7200 3600 1209600 3600\n\n;; Query time: 5 msec\n;; SERVER: 2001:4860:4860::8888#53(2001:4860:4860::8888) (TCP)\n")
        assertEquals("NXDOMAIN", auth.status); assertEquals(1, auth.recs.size); assertEquals("AUTHORITY", auth.recs[0].section); assertEquals("SOA", auth.recs[0].type); assertEquals("2001:4860:4860::8888#53", auth.server); assertEquals("TCP", auth.proto)
        val ns = DigParse.parse("Server:\t\t8.8.8.8\nAddress:\t8.8.8.8#53\n\nNon-authoritative answer:\nName:\texample.com\nAddress: 93.184.216.34\nName:\texample.com\nAddress: 2606:2800:220:1:248:1893:25c8:1946\n")
        assertEquals("nslookup", ns.kind); assertEquals("NOERROR", ns.status); assertEquals(listOf("A", "AAAA"), ns.recs.map { it.type }); assertEquals("8.8.8.8 (8.8.8.8#53)", ns.server); assertTrue(ns.flags.isEmpty()); assertEquals(listOf("93.184.216.34", "2606:2800:220:1:248:1893:25c8:1946"), ns.values)
        val nx = DigParse.parse("Server:\t\t8.8.8.8\nAddress:\t8.8.8.8#53\n\n** server can't find nope.example: NXDOMAIN\n"); assertEquals("NXDOMAIN", nx.status); assertEquals("nope.example", nx.query)
        val mx = DigParse.parse("Server:\t8.8.8.8\nAddress:\t8.8.8.8#53\n\nNon-authoritative answer:\nexample.com\tmail exchanger = 10 mx1.example.com.\nexample.com\ttext = \"v=spf1 -all\"\n"); assertEquals(listOf("MX", "TXT"), mx.recs.map { it.type }); assertEquals("10 mx1.example.com.", mx.recs[0].data)
        assertNull(DigParse.parse("hello").status)
    }

    @Test fun toolLogDig() {
        val r = run("log_dig"); assertEquals("NOERROR", r.kv("응답 코드")); assertEquals(-1, r.kvLevel("응답 코드")); assertEquals("231ms", r.kv("걸린 시간")); assertEquals(1, r.kvLevel("걸린 시간")); assertEquals("8.8.8.8#53 (UDP)", r.kv("물어본 서버")); assertEquals("qr rd ra", r.kv("플래그"))
        assertEquals(listOf("example.com", "300", "A", "93.184.216.34"), r.rows()[0]); assertTrue(r.text().contains("정상 응답이에요")); assertFalse(r.hasError)
        val sf = run("log_dig", "t" to "; <<>> DiG 9.18 <<>> broken.example\n;; ->>HEADER<<- opcode: QUERY, status: SERVFAIL, id: 1\n;; flags: qr rd ra; QUERY: 1, ANSWER: 0, AUTHORITY: 0, ADDITIONAL: 1\n\n;; QUESTION SECTION:\n;broken.example.\t\tIN\tA\n\n;; Query time: 15 msec\n;; SERVER: 127.0.0.53#53(127.0.0.53) (UDP)\n")
        assertEquals(2, sf.kvLevel("응답 코드")); assertTrue(sf.hasError); assertTrue(sf.text().contains("DNSSEC")); assertTrue(sf.text().contains("systemd-resolved"))
        val tc = run("log_dig", "t" to DIG_OK.replace("qr rd ra", "qr aa tc rd ad").replace("300\tIN", "30\tIN")); assertTrue(tc.text().contains("응답이 잘렸어요")); assertTrue(tc.text().contains("aa 플래그")); assertTrue(tc.text().contains("ad 플래그")); assertTrue(tc.text().contains("TTL 30초는 매우 짧아요"))
        val nodata = run("log_dig", "t" to ";; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 1\n;; flags: qr rd ra; QUERY: 1, ANSWER: 0, AUTHORITY: 0, ADDITIONAL: 1\n\n;; QUESTION SECTION:\n;example.com.\tIN\tAAAA\n"); assertTrue(nodata.text().contains("NODATA")); assertEquals(1, nodata.kvLevel("응답 코드"))
        val nx = run("log_dig", "t" to "Server:\t8.8.8.8\nAddress:\t8.8.8.8#53\n\n** server can't find nope.example: NXDOMAIN"); assertTrue(nx.hasError); assertTrue(run("log_dig", "t" to "hello").hasError)
    }

    // ============================================================ 방화벽

    @Test fun firewallParsesIptablesAndUfw() {
        val ip = FwParse.parseIptables("-P INPUT DROP\n-P FORWARD DROP\n-N DOCKER\n-A INPUT -i lo -j ACCEPT\n-A INPUT -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT\n-A INPUT -s 192.168.0.0/16 -p tcp -m tcp --dport 22 -j ACCEPT\n-A INPUT -p tcp -m multiport --dports 80,443,8000:8100 -j ACCEPT\n-A INPUT -j DROP\n-A FORWARD -j DOCKER")
        assertEquals(mapOf("INPUT" to "DROP", "FORWARD" to "DROP"), ip.policies); assertEquals(listOf("DOCKER"), ip.chains); assertEquals(6, ip.rules.size)
        assertEquals("lo", ip.rules[0].iface); assertEquals("RELATED,ESTABLISHED", ip.rules[1].state); assertEquals("192.168.0.0/16", ip.rules[2].src); assertEquals(listOf("22"), ip.rules[2].dports); assertEquals("tcp", ip.rules[2].proto); assertEquals(listOf("80", "443", "8000-8100"), ip.rules[3].dports); assertEquals("DROP", ip.rules[4].target); assertEquals("FORWARD", ip.rules[5].chain)
        val save = FwParse.parseIptables("*filter\n:INPUT DROP [0:0]\n:FORWARD ACCEPT [0:0]\n:MYCHAIN - [0:0]\n-A INPUT -p icmp -j ACCEPT\nCOMMIT\n"); assertEquals(mapOf("INPUT" to "DROP", "FORWARD" to "ACCEPT"), save.policies); assertEquals(listOf("MYCHAIN"), save.chains); assertEquals("icmp", save.rules[0].proto)
        val ufw = FwParse.parse("Status: active\nLogging: on (low)\nDefault: deny (incoming), allow (outgoing), disabled (routed)\n\nTo                         Action      From\n--                         ------      ----\n22/tcp                     ALLOW IN    Anywhere\n80,443/tcp                 ALLOW IN    Anywhere\n3306                       ALLOW IN    192.168.0.0/24\n22/tcp (v6)                ALLOW IN    Anywhere (v6)\n")
        assertEquals("ufw", ufw.kind); assertEquals(true, ufw.active); assertEquals(mapOf("INPUT" to "DROP"), ufw.policies); assertEquals(4, ufw.rules.size); assertEquals(listOf("80", "443"), ufw.rules[1].dports); assertEquals("192.168.0.0/24", ufw.rules[2].src); assertNull(ufw.rules[0].src); assertEquals("ACCEPT", ufw.rules[0].target)
        assertEquals(false, FwParse.parse("Status: inactive").active)
    }

    @Test fun toolLogFirewall() {
        val open = run("log_firewall"); assertTrue(open.hasError); assertTrue(open.text().contains("방화벽이 사실상 꺼진 상태")); assertTrue(open.text().contains("3306번(MySQL (데이터베이스))을 어디서나 접속하도록 열었어요")); assertEquals("ACCEPT", open.kv("기본 정책 INPUT")); assertEquals(1, open.kvLevel("기본 정책 INPUT"))
        assertEquals(listOf("22", "80", "443", "3306"), open.rows().filter { it.size == 4 }.map { it[0] }); assertEquals(2, open.rowLevel("3306")); assertEquals(1, open.rowLevel("22")); assertEquals(0, open.rowLevel("443")); assertEquals("어디서나", open.row("22")[2]); assertTrue(open.text().contains("IPv6 는 ip6tables"))
        val good = run("log_firewall", "t" to "-P INPUT DROP\n-P FORWARD DROP\n-P OUTPUT ACCEPT\n-A INPUT -i lo -j ACCEPT\n-A INPUT -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT\n-A INPUT -p tcp -m tcp --dport 22 -s 192.168.0.0/24 -j ACCEPT\n-A INPUT -p tcp -m tcp --dport 443 -j ACCEPT")
        assertFalse(good.hasError); assertTrue(good.text().contains("좋은 설정이에요")); assertEquals(-1, good.noteWith("좋은 설정")!!.level)
        val noEst = run("log_firewall", "t" to "-P INPUT DROP\n-A INPUT -p tcp --dport 22 -j ACCEPT"); assertTrue(noEst.text().contains("ESTABLISHED,RELATED 허용 규칙이 없어요"))
        val all = run("log_firewall", "t" to "-P INPUT DROP\n-A INPUT -j ACCEPT"); assertTrue(all.hasError); assertTrue(all.text().contains("모든 것을 허용하는 규칙"))
        val ufw = run("log_firewall", "t" to "Status: active\nDefault: deny (incoming), allow (outgoing)\n\nTo Action From\n-- ------ ----\n22/tcp ALLOW IN Anywhere\n6379/tcp ALLOW IN Anywhere\n"); assertEquals("켜짐(active)", ufw.kv("방화벽 상태")); assertTrue(ufw.text().contains("6379번(Redis (데이터베이스))")); assertTrue(ufw.text().contains("도커가 게시한 포트는 ufw 를 우회")); assertTrue(ufw.hasError)
        val off = run("log_firewall", "t" to "Status: inactive"); assertTrue(off.hasError); assertEquals(2, off.kvLevel("방화벽 상태")); assertTrue(off.text().contains("sudo ufw enable")); assertTrue(run("log_firewall", "t" to "hello").hasError)
    }

    // ============================================================ tcpdump

    private val DUMP = "13:55:36.100000 IP 192.168.1.10.54321 > 93.184.216.34.443: Flags [S], seq 1000, win 64240, length 0\n13:55:37.100000 IP 192.168.1.10.54321 > 93.184.216.34.443: Flags [S], seq 1000, win 64240, length 0\n13:55:38.100000 IP 192.168.1.10.54322 > 93.184.216.35.80: Flags [S], seq 2000, win 64240, length 0\n" +
        "13:55:38.120000 IP 93.184.216.35.80 > 192.168.1.10.54322: Flags [S.], seq 3000, ack 2001, win 65535, length 0\n13:55:38.121000 IP 192.168.1.10.54322 > 93.184.216.35.80: Flags [.], ack 3001, win 502, length 0\n13:55:38.130000 IP 192.168.1.10.54322 > 93.184.216.35.80: Flags [P.], seq 2001:2101, ack 3001, win 502, length 100\n" +
        "13:55:38.330000 IP 192.168.1.10.54322 > 93.184.216.35.80: Flags [P.], seq 2001:2101, ack 3001, win 502, length 100\n13:55:39.000000 IP 192.168.1.10.40000 > 8.8.8.8.53: 12345+ A? example.com. (29)\n13:55:39.010000 IP 8.8.8.8.53 > 192.168.1.10.40000: 12345 1/0/0 A 93.184.216.34 (45)\n13:55:40.000000 ARP, Request who-has 192.168.1.1 tell 192.168.1.10, length 28"

    @Test fun tcpdumpParsesPackets() {
        val p = TcpdumpParse.parse(DUMP)
        assertEquals(10, p.size); assertEquals(7, p.count { it.proto == "TCP" }); assertEquals(2, p.count { it.proto == "UDP" }); assertEquals(1, p.count { it.proto == "ARP" })
        assertEquals("192.168.1.10", p[0].src); assertEquals(54321, p[0].sport); assertEquals("93.184.216.34", p[0].dst); assertEquals(443, p[0].dport); assertEquals("S", p[0].flags); assertEquals(1000L, p[0].seq); assertEquals(0, p[0].len); assertEquals("S.", p[3].flags); assertEquals(100, p[5].len); assertEquals(2001L, p[5].seq)
        assertEquals(12345, p[7].dnsId); assertEquals("example.com", p[7].dnsName); assertFalse(p[7].dnsResp); assertEquals(29, p[7].len); assertEquals(12345, p[8].dnsId); assertTrue(p[8].dnsResp); assertNull(p[8].dnsName); assertEquals("who-has", p[9].flags); assertEquals("192.168.1.1", p[9].dst); assertEquals("192.168.1.10", p[9].src)
        assertEquals("2001:db8::1" to 443, TcpdumpParse.hostPort("2001:db8::1.443")); assertEquals("fe80::1" to null, TcpdumpParse.hostPort("fe80::1")); assertEquals("10.0.0.1" to null, TcpdumpParse.hostPort("10.0.0.1")); assertEquals("10.0.0.1" to 8080, TcpdumpParse.hostPort("10.0.0.1.8080"))
        val v6 = TcpdumpParse.parse("13:55:36.1 IP6 2001:db8::2.55555 > 2001:db8::1.443: Flags [S], seq 5, win 1, length 0\n2023-10-10 13:55:37.5 eth0  In  IP 10.0.0.1 > 10.0.0.2: ICMP echo request, id 1, seq 1, length 64\n13:55:38.0 IP 10.0.0.9.5353 > 224.0.0.251.5353: UDP, length 40"); assertEquals(3, v6.size)
        assertEquals("2001:db8::1", v6[0].dst); assertEquals(443, v6[0].dport); assertEquals("ICMP", v6[1].proto); assertEquals(64, v6[1].len); assertEquals("UDP", v6[2].proto); assertEquals(5353, v6[2].sport); assertTrue(TcpdumpParse.parse("garbage line").isEmpty())
    }

    @Test fun toolLogTcpdump() {
        val r = run("log_tcpdump")
        assertEquals("10개 (TCP 7 · UDP 2 · ICMP 0 · ARP 1)", r.kv("패킷")); assertEquals("13:55:36.100000 ~ 13:55:40.000000", r.kv("시각 범위"))
        assertTrue(r.text().contains("93.184.216.34:443 로 SYN 을 2번 보냈지만 아무 응답이 없어요")); assertFalse(r.text().contains("93.184.216.35:80 로 SYN")); assertTrue(r.text().contains("재전송이 1번 보여요")); assertTrue(r.text().contains("DNS 질문 1개가 모두 응답을 받았어요 (example.com)")); assertTrue(r.text().contains("ARP \"누가 192.168.1.1 인가\" 질문에 답이 없어요"))
        assertTrue(r.hasError); val top = r.rows().first(); assertTrue(top[0].startsWith("TCP 192.168.1.10:54322 ↔ 93.184.216.35:80")); assertEquals("5", top[1]); assertEquals("200", top[2])
        val rst = run("log_tcpdump", "t" to "13:00:00.1 IP 10.0.0.1.50000 > 10.0.0.2.22: Flags [S], seq 1, win 1, length 0\n13:00:00.2 IP 10.0.0.2.22 > 10.0.0.1.50000: Flags [R.], seq 0, ack 2, win 0, length 0\n13:00:01.0 IP 10.0.0.1.4000 > 10.0.0.3.53: 777+ A? gone.example. (30)\n")
        assertTrue(rst.text().contains("RST(연결 거부·강제 종료)가 1번")); assertTrue(rst.text().contains("10.0.0.2:22(1번)")); assertTrue(rst.text().contains("DNS 질문 1개 중 1개가 응답이 없어요 (gone.example)")); assertTrue(rst.text().contains("응답 없는 접속 시도(SYN)는 없어요"))             // RST 로라도 답했으니 무응답이 아님; assertTrue(run("log_tcpdump", "t" to "hello").hasError)
    }
}
