package com.selfcheck.app

import org.json.JSONArray
import org.json.JSONObject
import java.time.Instant
import java.time.LocalDateTime
import java.time.OffsetDateTime
import java.time.ZoneOffset
import java.time.format.DateTimeFormatter
import java.util.Locale

/*
 * 로그·출력 분석 엔진 1부: 웹 접근 로그(nginx·apache) · SSH 인증 로그 · syslog · JSON 줄 로그 · 시간 간격(끊김 찾기) · 브라우저 HAR.
 * 모두 붙여 넣은 글(또는 고른 파일)을 폰 안에서만 읽어요. 국가·통신사 표시는 호출하는 쪽이 오프라인 IP 자료로 붙입니다.
 */

/** 최대 max 바이트까지만 읽기 (InputStream.readNBytes 는 안드로이드 13 부터라서 직접 구현) */
fun java.io.InputStream.readUpTo(max: Int): ByteArray {
    val bo = java.io.ByteArrayOutputStream(); val buf = ByteArray(65536); var total = 0
    while (total < max) { val n = read(buf, 0, minOf(buf.size, max - total)); if (n < 0) break; bo.write(buf, 0, n); total += n }
    return bo.toByteArray()
}

object LogUtil {
    fun top(m: Map<String, Int>, n: Int): List<Pair<String, Int>> = m.entries.sortedWith(compareByDescending<Map.Entry<String, Int>> { it.value }.thenBy { it.key }).take(n).map { it.key to it.value }
    fun pct(a: Int, b: Int): String = if (b == 0) "0%" else "%.1f%%".format(a * 100.0 / b)
    fun bytes(n: Long): String = when { n < 1024 -> "${n}B"; n < 1024 * 1024 -> "%.1fKB".format(n / 1024.0); n < 1024L * 1024 * 1024 -> "%.1fMB".format(n / 1048576.0); else -> "%.2fGB".format(n / 1073741824.0) }
    fun ms(v: Double): String = if (v < 10) "%.2f".format(v) else if (v < 100) "%.1f".format(v) else "%.0f".format(v)

    /** "미국 · Google LLC" / "내부 주소" / "-" */
    fun where(db: IpGeoDb?, ip: String): String {
        val a = IpUtil.parse(ip) ?: return "-"
        val k = IpUtil.classify(a)
        if (k == IpKind.PRIVATE || k == IpKind.LOOPBACK || k == IpKind.LINK_LOCAL) return "내부 주소"
        if (k != IpKind.PUBLIC && k != IpKind.CGNAT) return "-"
        val g = db?.lookup(a) ?: return "-"
        return if (g.country == null && g.asn == null) "-" else "${CountryNames.ko(g.country)} · ${g.asn?.name?.take(26) ?: "-"}"
    }
}

// ---------------------------------------------------------------------------------------------
// 웹 접근 로그 (nginx·apache 의 common·combined 형식)

object AccessLog {
    class Entry(val ip: String, val time: OffsetDateTime?, val method: String, val path: String, val status: Int, val bytes: Long, val referer: String?, val agent: String?)
    class Susp(val ip: String, val reason: String, val level: Int, val count: Int, val sample: String)
    class Summary(
        val total: Int, val skipped: Int, val first: String?, val last: String?, val ips: Int, val status: Map<Int, Int>, val methods: Map<String, Int>, val topIps: List<Pair<String, Int>>,
        val topPaths: List<Pair<String, Int>>, val top404: List<Pair<String, Int>>, val topAgents: List<Pair<String, Int>>, val bytes: Long, val perHour: Map<String, Int>, val suspicious: List<Susp>, val botRequests: Int,
    )

    private val LINE = Regex("""^(\S+) \S+ \S+ \[([^\]]+)] "([^"]*)" (\d{3}) (\d+|-)(?: "([^"]*)" "([^"]*)")?""")
    private val TIME = DateTimeFormatter.ofPattern("dd/MMM/yyyy:HH:mm:ss Z", Locale.ENGLISH)

    fun parse(line: String): Entry? {
        val m = LINE.find(line) ?: return null
        val req = m.groupValues[3].split(' ')
        val ok = req.firstOrNull()?.matches(Regex("[A-Za-z]{3,10}")) == true                      // 스캐너가 보내는 바이너리 쓰레기("\x16\x03…")는 메서드로 보지 않음
        val method = if (ok) req[0] else "-"; val path = if (ok) req.getOrNull(1) ?: "-" else "-"
        val t = try { OffsetDateTime.parse(m.groupValues[2], TIME) } catch (_: Exception) { null }
        return Entry(m.groupValues[1], t, method, path, m.groupValues[4].toInt(), m.groupValues[5].toLongOrNull() ?: 0L, m.groups[6]?.value?.takeIf { it != "-" }, m.groups[7]?.value?.takeIf { it != "-" })
    }

    private class Rule(val reason: String, val level: Int, val re: Regex, val onAgent: Boolean = false)

    private val RULES = listOf(
        Rule("경로 탈출 시도(../)", 2, Regex("""(\.\./|%2e%2e|\.\.%2f|%252e)""", RegexOption.IGNORE_CASE)),
        Rule("SQL 주입 시도", 2, Regex("""(union(\+|%20|\s)+(all(\+|%20|\s)+)?select|'(\+|%20|\s)*or(\+|%20|\s)*'?1'?(\+|%20|\s)*=|%27(\+|%20)or|sleep\(\d+\)|information_schema)""", RegexOption.IGNORE_CASE)),
        Rule("스크립트 주입(XSS) 시도", 2, Regex("""(<script|%3cscript|javascript:|onerror=)""", RegexOption.IGNORE_CASE)),
        Rule("비밀 파일 찾기(.env·.git·키)", 2, Regex("""(/\.env|/\.git/|/\.aws/|/\.ssh/|id_rsa|/\.htpasswd|/wp-config\.php|/config\.php\.bak|\.sql(\.gz)?(\?|$)|/backup\.zip)""", RegexOption.IGNORE_CASE)),
        Rule("원격 실행 취약점 탐색", 2, Regex("""(/cgi-bin/|/shell\?|eval-stdin\.php|/vendor/phpunit|/actuator/|/jndi:|\$\{jndi|/boaform/|/HNAP1|/setup\.cgi|cmd=|/manager/html)""", RegexOption.IGNORE_CASE)),
        Rule("관리자·로그인 페이지 탐색", 1, Regex("""(/wp-login\.php|/xmlrpc\.php|/wp-admin|/phpmyadmin|/pma/|/adminer|/administrator/|/admin/login|/user/login)""", RegexOption.IGNORE_CASE)),
        Rule("공격 도구가 쓰는 User-Agent", 2, Regex("""(sqlmap|nikto|masscan|nmap|zgrab|nuclei|wpscan|dirbuster|gobuster|hydra|acunetix|netsparker|havij|fimap)""", RegexOption.IGNORE_CASE), onAgent = true),
    )

    private val BOTS = Regex("""(bot|spider|crawl|slurp|facebookexternalhit|curl/|wget/|python-requests|python-urllib|go-http-client|okhttp|libwww|java/|httpclient|scrapy|headless|monitor|uptime|pingdom)""", RegexOption.IGNORE_CASE)
    private val FAMILIES = listOf("Googlebot", "bingbot", "YandexBot", "Baiduspider", "AhrefsBot", "SemrushBot", "MJ12bot", "facebookexternalhit", "Applebot", "DuckDuckBot", "Yeti", "Daum", "curl", "Wget", "python-requests", "Go-http-client", "okhttp", "Edg/", "OPR/", "Chrome", "Firefox", "Safari", "MSIE", "Trident")

    fun family(ua: String?): String { if (ua == null) return "(없음)"; return FAMILIES.firstOrNull { ua.contains(it, true) }?.removeSuffix("/") ?: ua.take(30) }

    fun summarize(lines: List<String>): Summary {
        val status = HashMap<Int, Int>(); val methods = HashMap<String, Int>(); val ips = HashMap<String, Int>(); val paths = HashMap<String, Int>(); val p404 = HashMap<String, Int>(); val agents = HashMap<String, Int>(); val perHour = java.util.TreeMap<String, Int>()
        var total = 0; var skipped = 0; var bytes = 0L; var bots = 0; var first: OffsetDateTime? = null; var last: OffsetDateTime? = null
        val susp = LinkedHashMap<Pair<String, String>, Susp>(); val perIp = HashMap<String, IntArray>()     // 요청 수, 403·404 수
        for (l in lines) {
            if (l.isBlank()) continue
            val e = parse(l); if (e == null) { skipped++; continue }
            total++; status.merge(e.status, 1, Int::plus); methods.merge(e.method, 1, Int::plus); ips.merge(e.ip, 1, Int::plus); bytes += e.bytes
            val clean = e.path.substringBefore('?'); paths.merge(clean, 1, Int::plus); if (e.status == 404) p404.merge(clean, 1, Int::plus)
            agents.merge(family(e.agent), 1, Int::plus); if (e.agent == null || BOTS.containsMatchIn(e.agent)) bots++
            e.time?.let { t -> if (first == null || t.isBefore(first)) first = t; if (last == null || t.isAfter(last)) last = t; perHour.merge(DateTimeFormatter.ofPattern("yyyy-MM-dd HH").format(t), 1, Int::plus) }
            val c = perIp.getOrPut(e.ip) { IntArray(2) }; c[0]++; if (e.status == 403 || e.status == 404) c[1]++
            for (r in RULES) { val target = if (r.onAgent) e.agent ?: "" else e.path; if (r.re.containsMatchIn(target)) { val k = e.ip to r.reason; val s = susp[k]; susp[k] = if (s == null) Susp(e.ip, r.reason, r.level, 1, target.take(80)) else Susp(e.ip, r.reason, r.level, s.count + 1, s.sample) } }
        }
        for ((ip, c) in perIp) if (c[0] >= 20 && c[1] * 10 >= c[0] * 8) susp[ip to "없는 주소를 마구 두드림(스캐너)"] = Susp(ip, "없는 주소를 마구 두드림(스캐너)", 1, c[1], "${c[0]}건 중 ${c[1]}건이 403·404")
        val fmt = DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss Z")
        return Summary(total, skipped, first?.let { fmt.format(it) }, last?.let { fmt.format(it) }, ips.size, status, methods, LogUtil.top(ips, 10), LogUtil.top(paths, 10), LogUtil.top(p404, 10), LogUtil.top(agents, 8), bytes, perHour,
            susp.values.sortedWith(compareByDescending<Susp> { it.level }.thenByDescending { it.count }.thenBy { it.ip }), bots)
    }
}

// ---------------------------------------------------------------------------------------------
// SSH 인증 로그 (auth.log·secure·journalctl -u ssh)

object AuthLog {
    class Ev(val kind: String, val user: String?, val ip: String, val method: String?, val time: String?)

    private val TIME = Regex("""^(?:(\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})|(\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}))""")
    private val FAILED = Regex("""Failed (\S+) for (?:invalid user )?(\S+) from (\S+) port \d+""")
    private val INVALID = Regex("""Invalid user (\S*) from (\S+)""")
    private val ACCEPT = Regex("""Accepted (\S+) for (\S+) from (\S+) port \d+""")
    private val CLOSED = Regex("""(?:Connection closed by|Disconnected from) (?:authenticating|invalid) user (\S+) (\S+) port \d+""")
    private val MAXTRIES = Regex("""maximum authentication attempts exceeded for (?:invalid user )?(\S+) from (\S+)""")
    private val PAM = Regex("""pam_unix\(sshd:auth\): authentication failure;.*?rhost=(\S+)(?:\s+user=(\S+))?""")

    fun parse(lines: List<String>): List<Ev> {
        val out = ArrayList<Ev>()
        for (l in lines) {
            val t = TIME.find(l)?.let { it.groupValues[1].ifEmpty { it.groupValues[2] } }
            val f = FAILED.find(l); if (f != null) { out += Ev("fail", f.groupValues[2], f.groupValues[3], f.groupValues[1], t); continue }
            val a = ACCEPT.find(l); if (a != null) { out += Ev("accept", a.groupValues[2], a.groupValues[3], a.groupValues[1], t); continue }
            val m = MAXTRIES.find(l); if (m != null) { out += Ev("maxtries", m.groupValues[1], m.groupValues[2], null, t); continue }
            val i = INVALID.find(l); if (i != null) { out += Ev("invalid", i.groupValues[1].ifEmpty { "(빈 이름)" }, i.groupValues[2], null, t); continue }
            val p = PAM.find(l); if (p != null) { out += Ev("pam", p.groupValues[2].ifEmpty { null }, p.groupValues[1], null, t); continue }
            val c = CLOSED.find(l); if (c != null) out += Ev("closed", c.groupValues[1], c.groupValues[2], null, t)
        }
        return out
    }

    class Report(val failures: Int, val successes: List<Ev>, val byIp: List<Pair<String, Int>>, val byUser: List<Pair<String, Int>>, val brute: List<Pair<String, Int>>, val compromised: List<Pair<String, Int>>, val methods: Map<String, Int>)

    /**
     * 한 번의 실패한 시도가 "Invalid user"·"Failed password"·"Connection closed" 처럼 여러 줄로 남아서, (IP, 계정) 한 쌍마다
     * 종류별 줄 수 중 가장 큰 값을 시도 횟수로 봐요 (줄을 모두 더하면 두세 배로 부풀려짐). 그 시도 횟수를 IP별·계정별로 합산해요.
     * brute 는 threshold 번 이상 시도한 IP
     */
    fun report(events: List<Ev>, threshold: Int): Report {
        val bad = events.filter { it.kind != "accept" && it.kind != "maxtries" }
        val pairs = bad.groupBy { it.ip to (it.user ?: "(알 수 없음)") }.mapValues { (_, l) -> l.groupingBy { it.kind }.eachCount().values.max() }
        val byIp = HashMap<String, Int>(); val byUser = HashMap<String, Int>()
        for ((k, n) in pairs) { byIp.merge(k.first, n, Int::plus); byUser.merge(k.second, n, Int::plus) }
        val succ = events.filter { it.kind == "accept" }
        val brute = LogUtil.top(byIp, 1000).filter { it.second >= threshold }
        val comp = brute.filter { b -> succ.any { it.ip == b.first } }
        return Report(byIp.values.sum(), succ, LogUtil.top(byIp, 10), LogUtil.top(byUser, 10), brute, comp, succ.mapNotNull { it.method }.groupingBy { it }.eachCount())
    }
}

// ---------------------------------------------------------------------------------------------
// syslog 요약

object SyslogSummary {
    class Line(val time: String?, val host: String?, val prog: String?, val msg: String)
    class Report(val total: Int, val byProg: List<Pair<String, Int>>, val severity: Map<String, Int>, val templates: List<Pair<String, Int>>, val notable: List<Line>, val first: String?, val last: String?, val hosts: Int)

    private val SYS = Regex("""^(\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+(\S+)\s+([^\s:\[]+)(?:\[\d+])?:\s*(.*)$""")
    private val ISO = Regex("""^(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:\d{2})?)\s+(\S+)\s+([^\s:\[]+)(?:\[\d+])?:\s*(.*)$""")
    private val SEV = listOf("치명(panic·fatal·emerg·crit)" to Regex("""\b(panic|fatal|emerg|critical|crit)\b""", RegexOption.IGNORE_CASE), "오류(error·fail·denied)" to Regex("""\b(error|err|failed|failure|denied|refused|unreachable|segfault|oom|out of memory|killed process|call trace|i/o error|timeout|timed out)\b""", RegexOption.IGNORE_CASE),
        "경고(warn)" to Regex("""\b(warn|warning|deprecated|retry|retrying|throttl)""", RegexOption.IGNORE_CASE))

    fun parseLine(l: String): Line? { val m = ISO.find(l) ?: SYS.find(l) ?: return null; return Line(m.groupValues[1], m.groupValues[2], m.groupValues[3], m.groupValues[4]) }

    fun template(msg: String): String = msg.replace(Regex("""\b\d{1,3}(\.\d{1,3}){3}\b"""), "<ip>").replace(Regex("""\b[0-9a-fA-F]{2}(:[0-9a-fA-F]{2}){5}\b"""), "<mac>").replace(Regex("""\b0x[0-9a-fA-F]+\b"""), "<hex>").replace(Regex("""\b[0-9a-f]{16,}\b"""), "<hex>").replace(Regex("""\d+"""), "#").take(110)

    fun summarize(lines: List<String>): Report {
        val prog = HashMap<String, Int>(); val tpl = HashMap<String, Int>(); val sev = LinkedHashMap<String, Int>().also { m -> SEV.forEach { m[it.first] = 0 } }; val notable = ArrayList<Line>(); val hosts = HashSet<String>()
        var total = 0; var first: String? = null; var last: String? = null
        for (l in lines) {
            val p = parseLine(l) ?: continue
            total++; prog.merge(p.prog ?: "?", 1, Int::plus); tpl.merge(template(p.msg), 1, Int::plus); p.host?.let { hosts += it }
            if (first == null) first = p.time; last = p.time
            val hit = SEV.firstOrNull { it.second.containsMatchIn(p.msg) }
            if (hit != null) { sev.merge(hit.first, 1, Int::plus); if (notable.size < 30) notable += p }
        }
        return Report(total, LogUtil.top(prog, 10), sev, LogUtil.top(tpl, 8), notable, first, last, hosts.size)
    }
}

// ---------------------------------------------------------------------------------------------
// JSON 줄 로그 (한 줄에 JSON 하나)

object JsonLogs {
    class Report(val total: Int, val bad: Int, val keys: List<Pair<String, Int>>, val levels: List<Pair<String, Int>>, val messages: List<Pair<String, Int>>, val fieldValues: List<Pair<String, Int>>, val errors: List<String>, val first: String?, val last: String?)

    private val LEVEL = listOf("level", "severity", "lvl", "loglevel", "log.level", "levelname")
    private val MSG = listOf("msg", "message", "event", "error", "err")
    private val TIME = listOf("time", "timestamp", "ts", "@timestamp", "t", "datetime", "date")

    fun get(o: JSONObject, path: String): Any? {
        if (o.has(path)) return o.get(path)
        var cur: Any? = o
        for (p in path.split('.')) { cur = (cur as? JSONObject)?.opt(p) ?: return null }
        return cur
    }

    fun timeText(v: Any?): String? = when (v) {
        is Number -> { val d = v.toDouble(); val ms = if (d > 1e11) d.toLong() else (d * 1000).toLong(); Instant.ofEpochMilli(ms).toString() }
        is String -> v
        else -> null
    }

    fun summarize(lines: List<String>, field: String): Report {
        val keys = HashMap<String, Int>(); val lv = HashMap<String, Int>(); val msgs = HashMap<String, Int>(); val fv = HashMap<String, Int>(); val errs = ArrayList<String>()
        var total = 0; var bad = 0; var first: String? = null; var last: String? = null
        for (l in lines) {
            val t = l.trim(); if (t.isEmpty()) continue
            val o = try { JSONObject(t) } catch (_: Exception) { bad++; continue }
            total++; o.keys().forEach { keys.merge(it, 1, Int::plus) }
            val level = LEVEL.firstNotNullOfOrNull { k -> get(o, k)?.toString()?.lowercase() }?.also { lv.merge(it, 1, Int::plus) }
            val msg = MSG.firstNotNullOfOrNull { k -> get(o, k)?.toString() }
            if (msg != null) msgs.merge(SyslogSummary.template(msg), 1, Int::plus)
            TIME.firstNotNullOfOrNull { k -> timeText(get(o, k)) }?.let { if (first == null) first = it; last = it }
            if (field.isNotEmpty()) get(o, field)?.let { fv.merge(it.toString().take(60), 1, Int::plus) }
            if (errs.size < 10 && level != null && level in listOf("error", "err", "fatal", "critical", "crit", "panic", "severe", "50", "40") || (level == null && o.has("error") && errs.size < 10)) errs += t.take(220)
        }
        return Report(total, bad, LogUtil.top(keys, 15), LogUtil.top(lv, 8), LogUtil.top(msgs, 8), LogUtil.top(fv, 10), errs, first, last)
    }
}

// ---------------------------------------------------------------------------------------------
// 시간 간격: 로그가 끊긴 구간·몰린 구간 찾기

object LogTime {
    private val ISO = Regex("""(\d{4})-(\d{2})-(\d{2})[T ](\d{2}):(\d{2}):(\d{2})(?:[.,](\d{1,9}))?\s*(Z|[+-]\d{2}:?\d{2})?""")
    private val APACHE = Regex("""(\d{2})/([A-Za-z]{3})/(\d{4}):(\d{2}):(\d{2}):(\d{2}) ([+-]\d{4})""")
    private val SYSLOG = Regex("""\b([A-Z][a-z]{2})\s+(\d{1,2}) (\d{2}):(\d{2}):(\d{2})\b""")
    private val EPOCH = Regex("""^\s*\[?(\d{10}|\d{13})(?:\.(\d+))?\b""")
    private val MONTHS = listOf("Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec")

    private fun zone(s: String?): ZoneOffset = when { s == null || s == "Z" -> ZoneOffset.UTC; else -> ZoneOffset.of(if (':' in s) s else s.substring(0, 3) + ":" + s.substring(3)) }

    /** 한 줄의 첫 시각 (지원: ISO 8601, 아파치 [10/Oct/2023:13:55:36 +0900], syslog Oct 10 13:55:36, 유닉스 초·밀리초). syslog 는 연도가 없어서 year 를 씀 */
    fun extract(line: String, year: Int): Instant? {
        EPOCH.find(line)?.let { m -> val s = m.groupValues[1]; return if (s.length == 13) Instant.ofEpochMilli(s.toLong()) else Instant.ofEpochSecond(s.toLong()) }
        ISO.find(line)?.let { m -> val g = m.groupValues; return try { LocalDateTime.of(g[1].toInt(), g[2].toInt(), g[3].toInt(), g[4].toInt(), g[5].toInt(), g[6].toInt(), (g[7].padEnd(9, '0').take(9).toIntOrNull() ?: 0)).toInstant(zone(g[8].ifEmpty { null })) } catch (_: Exception) { null } }
        APACHE.find(line)?.let { m -> val g = m.groupValues; val mo = MONTHS.indexOfFirst { it.equals(g[2], true) } + 1; if (mo > 0) return try { LocalDateTime.of(g[3].toInt(), mo, g[1].toInt(), g[4].toInt(), g[5].toInt(), g[6].toInt()).toInstant(zone(g[7])) } catch (_: Exception) { null } }
        SYSLOG.find(line)?.let { m -> val g = m.groupValues; val mo = MONTHS.indexOfFirst { it == g[1] } + 1; if (mo > 0) return try { LocalDateTime.of(year, mo, g[2].toInt(), g[3].toInt(), g[4].toInt(), g[5].toInt()).toInstant(ZoneOffset.UTC) } catch (_: Exception) { null } }
        return null
    }

    class Gap(val from: Instant, val to: Instant, val seconds: Long, val line: Int)
    class Report(val lines: Int, val stamped: Int, val first: Instant?, val last: Instant?, val medianSec: Double, val p95Sec: Double, val maxSec: Double, val gaps: List<Gap>, val busiestMinute: Pair<String, Int>?, val cv: Double, val outOfOrder: Int)

    fun analyze(text: List<String>, thresholdSec: Long, year: Int): Report {
        val stamps = ArrayList<Pair<Instant, Int>>(); var prevMonth = -1; var yr = year
        text.forEachIndexed { idx, l ->
            val sys = if (ISO.containsMatchIn(l) || APACHE.containsMatchIn(l) || EPOCH.containsMatchIn(l)) null else SYSLOG.find(l)
            if (sys != null) { val mo = MONTHS.indexOfFirst { it == sys.groupValues[1] } + 1; if (prevMonth in 1..12 && mo > 0 && mo < prevMonth - 6) yr++; if (mo > 0) prevMonth = mo }     // 12월 → 1월 넘어가면 해가 바뀜
            extract(l, yr)?.let { stamps += it to idx + 1 }
        }
        if (stamps.size < 2) return Report(text.size, stamps.size, stamps.firstOrNull()?.first, stamps.lastOrNull()?.first, 0.0, 0.0, 0.0, emptyList(), null, 0.0, 0)
        var ooo = 0; val deltas = ArrayList<Double>(); val gaps = ArrayList<Gap>()
        for (k in 1 until stamps.size) {
            val d = (stamps[k].first.toEpochMilli() - stamps[k - 1].first.toEpochMilli()) / 1000.0
            if (d < 0) { ooo++; continue }
            deltas += d; if (d >= thresholdSec) gaps += Gap(stamps[k - 1].first, stamps[k].first, d.toLong(), stamps[k].second)
        }
        val sorted = deltas.sorted(); val mean = if (deltas.isEmpty()) 0.0 else deltas.average()
        val sd = if (deltas.size < 2) 0.0 else Math.sqrt(deltas.sumOf { (it - mean) * (it - mean) } / deltas.size)
        val perMin = HashMap<String, Int>(); for ((t, _) in stamps) perMin.merge(t.toString().take(16), 1, Int::plus)
        return Report(text.size, stamps.size, stamps.minOf { it.first }, stamps.maxOf { it.first }, if (sorted.isEmpty()) 0.0 else sorted[sorted.size / 2], if (sorted.isEmpty()) 0.0 else sorted[minOf(sorted.size - 1, (sorted.size * 0.95).toInt())], sorted.lastOrNull() ?: 0.0,
            gaps.sortedByDescending { it.seconds }.take(15).sortedBy { it.from }, perMin.maxByOrNull { it.value }?.let { it.key to it.value }, if (mean == 0.0) 0.0 else sd / mean, ooo)
    }

    fun human(sec: Long): String = when { sec < 90 -> "${sec}초"; sec < 5400 -> "${sec / 60}분 ${sec % 60}초"; sec < 172800 -> "${sec / 3600}시간 ${sec % 3600 / 60}분"; else -> "${sec / 86400}일 ${sec % 86400 / 3600}시간" }
}

// ---------------------------------------------------------------------------------------------
// 브라우저 HAR (개발자 도구 → 네트워크 → HAR 저장)

object HarSummary {
    class Req(val url: String, val method: String, val status: Int, val mime: String, val timeMs: Double, val transfer: Long, val content: Long, val http: String, val ip: String?, val encoding: String?, val cache: String?, val t: DoubleArray, val redirect: Boolean)
    class Report(
        val reqs: List<Req>, val pageLoadMs: Double?, val domContentMs: Double?, val transfer: Long, val content: Long, val byType: List<Triple<String, Int, Long>>, val hosts: List<Pair<String, Int>>, val thirdParty: List<Pair<String, Int>>,
        val slowest: List<Req>, val largest: List<Req>, val failed: List<Req>, val avgTiming: DoubleArray, val protocols: Map<String, Int>, val notCompressed: List<Req>, val noCache: List<Req>, val mixed: List<Req>, val firstHost: String,
    )

    val PHASES = listOf("blocked", "dns", "connect", "ssl", "send", "wait", "receive")

    private fun group(mime: String): String = when {
        mime.startsWith("image/") -> "이미지"; mime.contains("javascript") || mime.contains("ecmascript") -> "스크립트(JS)"; mime.contains("css") -> "스타일(CSS)"; mime.contains("html") -> "HTML"; mime.contains("json") || mime.contains("xml") -> "데이터(JSON·XML)"
        mime.startsWith("font/") || mime.contains("woff") || mime.contains("font") -> "글꼴"; mime.startsWith("video/") || mime.startsWith("audio/") -> "미디어"; mime.isEmpty() -> "(알 수 없음)"; else -> "기타"
    }

    private fun header(arr: JSONArray?, name: String): String? { if (arr == null) return null; for (i in 0 until arr.length()) { val h = arr.optJSONObject(i) ?: continue; if (h.optString("name").equals(name, true)) return h.optString("value") }; return null }

    fun parse(json: String): Report {
        val log = JSONObject(json).getJSONObject("log"); val entries = log.getJSONArray("entries")
        val reqs = ArrayList<Req>()
        for (i in 0 until entries.length()) {
            val e = entries.getJSONObject(i); val rq = e.getJSONObject("request"); val rs = e.getJSONObject("response"); val tm = e.optJSONObject("timings"); val content = rs.optJSONObject("content")
            val rh = rs.optJSONArray("headers"); val mime = (content?.optString("mimeType") ?: "").substringBefore(';').trim().lowercase()
            val body = rs.optLong("bodySize", -1).let { if (it < 0) 0 else it }; val hdr = rs.optLong("headersSize", -1).let { if (it < 0) 0 else it }
            val transfer = rs.optLong("_transferSize", -1).let { if (it >= 0) it else body + hdr }
            val t = DoubleArray(PHASES.size) { k -> (tm?.optDouble(PHASES[k], -1.0) ?: -1.0).let { if (it < 0) 0.0 else it } }
            val status = rs.optInt("status", 0)
            reqs += Req(rq.optString("url"), rq.optString("method"), status, mime, e.optDouble("time", 0.0), transfer, maxOf(content?.optLong("size", 0) ?: 0, 0), rs.optString("httpVersion").ifEmpty { e.optString("_protocol") }.lowercase().replace("http/2.0", "h2").replace("http/2", "h2"), e.optString("serverIPAddress").ifEmpty { null },
                header(rh, "Content-Encoding"), header(rh, "Cache-Control") ?: header(rh, "Expires"), t, status in 300..399)
        }
        val firstHost = reqs.firstOrNull()?.let { hostOf(it.url) } ?: ""; val firstBase = EmailHeader.baseDomain(firstHost)
        val pt = log.optJSONArray("pages")?.optJSONObject(0)?.optJSONObject("pageTimings")
        val byType = reqs.groupBy { group(it.mime) }.map { (k, v) -> Triple(k, v.size, v.sumOf { it.transfer }) }.sortedByDescending { it.third }
        val hosts = reqs.groupingBy { hostOf(it.url) }.eachCount(); val third = hosts.filter { EmailHeader.baseDomain(it.key) != firstBase }
        val avg = DoubleArray(PHASES.size) { k -> if (reqs.isEmpty()) 0.0 else reqs.sumOf { it.t[k] } / reqs.size }
        val textual = Regex("""(text/|javascript|json|xml|svg)""")
        return Report(reqs, pt?.optDouble("onLoad", -1.0)?.takeIf { it >= 0 }, pt?.optDouble("onContentLoad", -1.0)?.takeIf { it >= 0 }, reqs.sumOf { it.transfer }, reqs.sumOf { it.content }, byType, LogUtil.top(hosts, 10), LogUtil.top(third, 10),
            reqs.sortedByDescending { it.timeMs }.take(8), reqs.sortedByDescending { it.transfer }.take(8), reqs.filter { it.status >= 400 || it.status == 0 }, avg, reqs.groupingBy { it.http.ifEmpty { "?" } }.eachCount(),
            reqs.filter { it.status in 200..299 && textual.containsMatchIn(it.mime) && it.content > 1500 && it.encoding.isNullOrEmpty() }, reqs.filter { it.status in 200..299 && it.cache == null && (it.mime.startsWith("image/") || it.mime.contains("javascript") || it.mime.contains("css") || it.mime.contains("font")) },
            if (reqs.firstOrNull()?.url?.startsWith("https://") == true) reqs.filter { it.url.startsWith("http://") } else emptyList(), firstHost)
    }

    fun hostOf(url: String): String = try { java.net.URI(url).host ?: url.substringAfter("://").substringBefore('/') } catch (_: Exception) { url.substringAfter("://").substringBefore('/') }
}
