package com.selfcheck.app

import java.time.ZonedDateTime
import java.time.format.DateTimeFormatter
import java.util.Locale

/*
 * 받은 이메일의 전체 헤더를 읽어서 메일이 거쳐 온 서버(Received)와 그 IP, 서버마다 걸린 시간, SPF·DKIM·DMARC 결과를 정리합니다.
 * 인터넷에 접속하지 않고 붙여 넣은 글만 읽습니다. (받은 메일의 헤더에 적힌 것만 보여 주며, 적히지 않은 것은 알 수 없어요.)
 */
object EmailHeader {
    class Hop(val no: Int, val from: String?, val ip: String?, val by: String?, val proto: String?, val time: ZonedDateTime?, val delaySec: Long?, val raw: String)

    /** 접힌 줄(공백으로 시작)을 펴서 (이름, 값) 목록으로. 순서 유지 */
    fun fields(text: String): List<Pair<String, String>> {
        val out = ArrayList<Pair<String, String>>()
        var name: String? = null; val cur = StringBuilder()
        fun flush() { name?.let { out += it to cur.toString().trim().replace(Regex("\\s+"), " ") }; name = null; cur.setLength(0) }
        for (line in text.lines()) {
            if (line.isEmpty()) { if (name != null) flush(); if (out.isNotEmpty()) break else continue }       // 빈 줄: 헤더 끝
            if ((line[0] == ' ' || line[0] == '\t') && name != null) { cur.append(' ').append(line.trim()); continue }
            val i = line.indexOf(':')
            if (i > 0 && line.substring(0, i).all { it.isLetterOrDigit() || it == '-' || it == '_' }) { flush(); name = line.substring(0, i).trim(); cur.append(line.substring(i + 1).trim()) }
        }
        flush()
        return out
    }

    private val FORMATS = listOf(
        DateTimeFormatter.RFC_1123_DATE_TIME,
        DateTimeFormatter.ofPattern("d MMM yyyy HH:mm:ss Z", Locale.ENGLISH),
        DateTimeFormatter.ofPattern("EEE, d MMM yyyy HH:mm:ss z", Locale.ENGLISH),
        DateTimeFormatter.ofPattern("EEE, d MMM yyyy HH:mm Z", Locale.ENGLISH),
    )

    fun parseDate(s: String): ZonedDateTime? {
        val t = s.replace(Regex("\\([^)]*\\)"), " ").replace(Regex("\\s+"), " ").trim()
        for (f in FORMATS) try { return ZonedDateTime.parse(t, f) } catch (_: Exception) {}
        return null
    }

    private val FROM = Regex("""(?i)\bfrom\s+(.+?)(?=\s+by\s|\s+with\s|\s+id\s|\s+for\s|;|$)""")
    private val BY = Regex("""(?i)\bby\s+(.+?)(?=\s+with\s|\s+id\s|\s+for\s|\s+via\s|;|$)""")
    private val WITH = Regex("""(?i)\bwith\s+([A-Za-z0-9_.\-]+)""")
    private val BRACKET_IP = Regex("""[\[(]\s*(?:IPv6:)?([0-9a-fA-F:.]{3,45})\s*[\])]""")

    /** Received 줄들 → 처음 서버부터 순서대로 (위쪽 줄이 가장 최근이라 뒤집음) */
    fun hops(fields: List<Pair<String, String>>): List<Hop> {
        val recvs = fields.filter { it.first.equals("Received", true) }.map { it.second }.reversed()
        val times = recvs.map { r -> r.substringAfterLast(';', "").let { if (it.isBlank()) null else parseDate(it) } }
        return recvs.mapIndexed { i, r ->
            val fromPart = FROM.find(r)?.groupValues?.get(1)?.trim()
            val ip = fromPart?.let { fp -> BRACKET_IP.findAll(fp).mapNotNull { m -> IpUtil.parse(m.groupValues[1])?.let { IpUtil.format(it) } }.lastOrNull() ?: IpText.extract(fp).firstOrNull()?.let { a -> IpUtil.format(a) } }
            val t = times[i]; val prev = times.getOrNull(i - 1)
            Hop(i + 1, fromPart?.substringBefore(' ')?.trim('(', ')', '[', ']'), ip, BY.find(r)?.groupValues?.get(1)?.substringBefore(' ')?.trim(), WITH.find(r)?.groupValues?.get(1), t,
                if (t != null && prev != null) java.time.Duration.between(prev, t).seconds else null, r)
        }
    }

    /** Authentication-Results 의 spf=pass dkim=fail dmarc=pass 같은 결과 (여러 줄이면 먼저 나온 값) */
    fun authResults(fields: List<Pair<String, String>>): Map<String, String> {
        val out = LinkedHashMap<String, String>()
        for ((n, v) in fields) {
            if (n.equals("Authentication-Results", true)) {
                for (m in Regex("""\b(spf|dkim|dmarc|arc|compauth)=([a-z]+)""", RegexOption.IGNORE_CASE).findAll(v)) out.putIfAbsent(m.groupValues[1].lowercase(), m.groupValues[2].lowercase())
            } else if (n.equals("Received-SPF", true)) {
                Regex("""^([a-z]+)""", RegexOption.IGNORE_CASE).find(v)?.let { out.putIfAbsent("spf", it.groupValues[1].lowercase()) }
            }
        }
        return out
    }

    /** 헤더에 따로 적힌 보낸 IP 후보 (X-Originating-IP 등) */
    fun hintIps(fields: List<Pair<String, String>>): List<Pair<String, String>> {
        val out = ArrayList<Pair<String, String>>()
        for ((n, v) in fields) {
            val key = n.lowercase()
            if (key in listOf("x-originating-ip", "x-sender-ip", "x-forwarded-for", "x-real-ip", "x-remote-ip", "x-client-ip") ) IpText.extract(v).forEach { out += n to IpUtil.format(it) }
            if (key == "received-spf") Regex("""client-ip=([0-9a-fA-F:.]+)""").find(v)?.let { out += "Received-SPF client-ip" to it.groupValues[1].trimEnd(';') }
        }
        return out.distinct()
    }

    fun domainOf(addr: String?): String? = addr?.let { a -> Regex("""@([A-Za-z0-9.\-]+)""").findAll(a).lastOrNull()?.groupValues?.get(1)?.lowercase()?.trimEnd('.', '>') }

    /** 도메인의 "등록 가능한 부분"을 간단히 (a.b.example.com → example.com, 한국형 co.kr 등은 세 칸) */
    fun baseDomain(d: String): String {
        if (':' in d || IpUtil.parseV4(d) != null) return d       // IP 주소는 나눌 "도메인"이 없음
        val p = d.split('.'); if (p.size <= 2) return d
        val sld = setOf("co", "or", "go", "ne", "ac", "re", "pe", "com", "org", "net", "gov", "edu")
        return if (p[p.size - 2] in sld && p.last().length == 2) p.takeLast(3).joinToString(".") else p.takeLast(2).joinToString(".")
    }
}
