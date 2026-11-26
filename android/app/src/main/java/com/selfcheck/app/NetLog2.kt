package com.selfcheck.app

/*
 * 로그·출력 분석 엔진 2부: traceroute/tracert · ip addr/ifconfig/ipconfig · ss/netstat · dig/nslookup · iptables/ufw · tcpdump 글 출력.
 * 명령어 출력을 그대로 붙여 넣으면 표와 진단으로 풀어 줘요 (리눅스·맥·윈도 형식, 윈도는 한글판도 읽어요).
 */

// ---------------------------------------------------------------------------------------------
// traceroute / tracert

object TraceParse {
    class Probe(val addr: String?, val host: String?, val rtt: Double?)
    class Hop(val n: Int, val probes: List<Probe>, val flags: List<String>) {
        val addrs: List<String> get() = probes.mapNotNull { it.addr }.distinct()
        val rtts: List<Double> get() = probes.mapNotNull { it.rtt }
        val loss: Int get() = probes.count { it.rtt == null }
        val avg: Double? get() = rtts.takeIf { it.isNotEmpty() }?.average()
        fun hostOf(a: String): String? = probes.firstOrNull { it.addr == a }?.host
    }
    class Trace(val target: String?, val targetIp: String?, val hops: List<Hop>, val windows: Boolean)

    private val IPV4 = Regex("""^\d{1,3}(\.\d{1,3}){3}$""")
    private val IPV6 = Regex("""^[0-9a-fA-F]*:[0-9a-fA-F:.]*$""")
    private fun isIp(s: String) = IPV4.matches(s) || (IPV6.matches(s) && s.count { it == ':' } >= 2)
    private val HEAD = Regex("""(?:traceroute6?|Tracing route) to (\S+) [\[(]([0-9a-fA-F:.]+)[\])]""", RegexOption.IGNORE_CASE)
    private val HEAD_KO = Regex("""(\S+) \[([0-9a-fA-F:.]+)]\(으\)로 가는 경로 추적""")
    private val WIN = Regex("""^\s*(\d+)\s+(<?\d+|\*)(?:\s?ms)?\s+(<?\d+|\*)(?:\s?ms)?\s+(<?\d+|\*)(?:\s?ms)?\s+(\S.*)$""")
    private val NUM = Regex("""\d+(\.\d+)?""")
    private val HOP_START = Regex("""^\s*(\d{1,3})\s+(\S.*)$""")
    private val WIN_HOST = Regex("""^(\S+) \[([^\]]+)]""")

    private fun winRtt(s: String): Double? = if (s == "*") null else if (s.startsWith("<")) 0.5 else s.toDouble()

    private fun readProbes(body: String, into: MutableList<Probe>, flags: MutableList<String>) {
        val toks = body.trim().split(Regex("\\s+")); var i = 0; var addr: String? = null; var host: String? = null
        while (i < toks.size) {
            val t = toks[i]
            when {
                t == "*" -> { into += Probe(addr, host, null); i++ }
                t.startsWith("!") && t.length <= 4 -> { flags += t; i++ }
                NUM.matches(t) && toks.getOrNull(i + 1) == "ms" -> { into += Probe(addr, host, t.toDouble()); i += 2 }
                toks.getOrNull(i + 1)?.let { it.startsWith("(") && it.endsWith(")") } == true -> { host = t; addr = toks[i + 1].trim('(', ')'); i += 2 }
                isIp(t) -> { addr = t; host = null; i++ }
                else -> i++
            }
        }
    }

    fun parse(text: String): Trace {
        val lines = text.lines(); var target: String? = null; var tip: String? = null
        for (l in lines.take(6)) { val m = HEAD.find(l) ?: HEAD_KO.find(l); if (m != null) { target = m.groupValues[1]; tip = m.groupValues[2]; break } }
        val hops = ArrayList<Hop>(); var windows = false
        var cur: ArrayList<Probe>? = null; var curN = 0; var flags = ArrayList<String>()
        fun flush() { val c = cur; if (c != null) hops += Hop(curN, c, flags.toList()); cur = null; flags = ArrayList() }
        for (raw in lines) {
            val l = raw.trimEnd()
            val w = WIN.matchEntire(l)
            if (w != null) {                                                                  // 윈도 tracert: 번호, 시간 3칸, 주소
                windows = true; flush()
                val rest = w.groupValues[5].trim(); val hm = WIN_HOST.find(rest)
                val host = hm?.groupValues?.get(1); val addr = hm?.groupValues?.get(2) ?: rest.takeIf { isIp(it) }
                hops += Hop(w.groupValues[1].toInt(), (2..4).map { Probe(addr, host, winRtt(w.groupValues[it])) }, emptyList())
                continue
            }
            val first = l.trim().substringBefore(' ')
            val hm = HOP_START.matchEntire(l)
            if (hm != null && first.matches(Regex("""\d{1,3}"""))) {                           // 리눅스·맥: " 3  host (ip)  1.2 ms  1.3 ms  1.1 ms"
                val body = hm.groupValues[2]
                if (body.startsWith("*") || " ms" in body || '(' in body || isIp(body.substringBefore(' '))) { flush(); curN = hm.groupValues[1].toInt(); cur = ArrayList(); readProbes(body, cur!!, flags) }
            } else if (cur != null && l.isNotBlank() && l[0].isWhitespace() && (" ms" in l || '(' in l)) readProbes(l, cur!!, flags)      // 같은 홉의 다른 장비 줄
        }
        flush()
        val merged = hops.groupBy { it.n }.toSortedMap().map { (n, hs) -> if (hs.size == 1) hs[0] else Hop(n, hs.flatMap { it.probes }, hs.flatMap { it.flags }) }
        return Trace(target, tip, merged, windows)
    }
}

// ---------------------------------------------------------------------------------------------
// ip addr / ifconfig / ipconfig

object IfaceParse {
    class Addr(val ip: String, val prefix: Int?, val scope: String?, val v6: Boolean)
    class Iface(val name: String) {
        var state: String? = null; var mac: String? = null; var mtu: Int? = null; var dhcp: Boolean? = null; var flags: List<String> = emptyList(); var media: String? = null
        val addrs = ArrayList<Addr>(); val gateways = ArrayList<String>(); val dns = ArrayList<String>()
    }

    fun maskToPrefix(m: String): Int? {
        val v = if (m.startsWith("0x", true)) m.substring(2).toLongOrNull(16) else IpUtil.parseV4(m)?.let { b -> b.fold(0L) { a, x -> (a shl 8) or (x.toLong() and 0xff) } }
        return v?.let { java.lang.Long.bitCount(it) }
    }

    private val KEYS = mapOf(
        "mac" to listOf("Physical Address", "물리적 주소"), "ipv4" to listOf("IPv4 Address", "IPv4 주소", "Autoconfiguration IPv4 Address", "자동 구성 IPv4 주소", "IP Address"), "mask" to listOf("Subnet Mask", "서브넷 마스크"),
        "gw" to listOf("Default Gateway", "기본 게이트웨이"), "dns" to listOf("DNS Servers", "DNS 서버"), "dhcp" to listOf("DHCP Enabled", "DHCP 사용"),
        "ipv6" to listOf("IPv6 Address", "IPv6 주소", "Temporary IPv6 Address", "임시 IPv6 주소", "Link-local IPv6 Address", "링크-로컬 IPv6 주소"), "media" to listOf("Media State", "미디어 상태"),
    )
    private val IPA = Regex("""^\d+:\s+(\S+?)(?:@\S+)?:\s+<([^>]*)>\s+mtu\s+(\d+)(?:.*?\sstate\s+(\w+))?""")
    private val IFCONFIG = Regex("""^(\S+?):\s+flags=\d+<([^>]*)>\s+mtu\s+(\d+)""")
    private val OLD = Regex("""^(\S+)\s+Link encap:(\S+)(?:\s+HWaddr\s+(\S+))?""")
    private val LINK = Regex("""^link/(?:ether|loopback|none)\s*([0-9a-fA-F:]{17})?""")
    private val ETHER = Regex("""^(?:ether|HWaddr)\s+([0-9a-fA-F:]{17})""")
    private val INET = Regex("""^inet\s+(?:addr:)?(\d+\.\d+\.\d+\.\d+)(?:/(\d+))?""")
    private val INET6 = Regex("""^inet6\s+(?:addr:\s*)?([0-9a-fA-F:]+)(?:%\S+)?(?:/(\d+))?(?:\s+prefixlen\s+(\d+))?""")
    private val MASK = Regex("""(?:netmask|Mask:)\s*(\S+)""")
    private val SCOPE = Regex("""(?i)scope(?:id)?:?\s*(?:0x\w+<)?(\w+)""")
    private val KV = Regex("""^(.+?)[\s.]*:\s*(.*)$""")
    private val NOISE = Regex("""\((Preferred|Duplicate|Tentative|Deprecated|기본 설정|선호|사용되지 않음)[^)]*\)""")

    fun parse(text: String): List<Iface> {
        val out = ArrayList<Iface>(); var cur: Iface? = null; var lastKey: String? = null
        for (raw in text.lines()) {
            val l = raw.trimEnd(); val t = l.trim()
            val ipa = IPA.find(l)
            if (ipa != null) { val c0 = Iface(ipa.groupValues[1]); c0.flags = ipa.groupValues[2].split(','); c0.mtu = ipa.groupValues[3].toInt(); c0.state = ipa.groupValues[4].ifEmpty { if ("UP" in c0.flags) "UP" else "DOWN" }; out += c0; cur = c0; lastKey = null; continue }
            val ifc = IFCONFIG.find(l)
            if (ifc != null) { val c0 = Iface(ifc.groupValues[1]); c0.flags = ifc.groupValues[2].split(','); c0.mtu = ifc.groupValues[3].toInt(); c0.state = if ("UP" in c0.flags) "UP" else "DOWN"; out += c0; cur = c0; lastKey = null; continue }
            val old = OLD.find(l)
            if (old != null) { val c0 = Iface(old.groupValues[1]); c0.mac = old.groupValues[3].ifEmpty { null }; c0.state = "?"; out += c0; cur = c0; lastKey = null; continue }
            if (l.isNotEmpty() && !l[0].isWhitespace() && l.endsWith(":") && Regex("(?i)(adapter|어댑터)").containsMatchIn(l)) {
                val title = l.trimEnd(':'); val c0 = Iface(if (title.contains("adapter ", true)) title.substringAfter("adapter ", title) else title.substringAfter("어댑터 ", title)); out += c0; cur = c0; lastKey = null; continue
            }
            val c = cur ?: continue
            val link = LINK.find(t); if (link != null) { c.mac = link.groupValues[1].ifEmpty { null }; continue }
            val eth = ETHER.find(t); if (eth != null) { c.mac = eth.groupValues[1]; continue }
            val v4 = INET.find(t)
            if (v4 != null) { c.addrs += Addr(v4.groupValues[1], v4.groupValues[2].toIntOrNull() ?: MASK.find(t)?.groupValues?.get(1)?.let { maskToPrefix(it) }, SCOPE.find(t)?.groupValues?.get(1), false); continue }
            val v6 = INET6.find(t)
            if (v6 != null) { c.addrs += Addr(v6.groupValues[1], v6.groupValues[2].toIntOrNull() ?: v6.groupValues[3].toIntOrNull(), SCOPE.find(t)?.groupValues?.get(1)?.lowercase(), true); continue }
            val kv = KV.find(l)
            if (kv != null && raw.startsWith(" ")) {                                              // 윈도 "이름 . . . : 값"
                val key = kv.groupValues[1].trim(); val v = kv.groupValues[2].trim().replace(NOISE, "").trim()
                val group = KEYS.entries.firstOrNull { e -> e.value.any { key.equals(it, true) } }?.key; lastKey = group
                when (group) {
                    "mac" -> c.mac = v.replace('-', ':').lowercase().ifEmpty { null }
                    "ipv4" -> if (v.isNotEmpty()) c.addrs += Addr(v, null, if (key.contains("Autoconf", true) || key.contains("자동")) "autoconf" else null, false)
                    "mask" -> { val p = maskToPrefix(v); val idx = c.addrs.indexOfLast { !it.v6 && it.prefix == null }; if (p != null && idx >= 0) c.addrs[idx] = Addr(c.addrs[idx].ip, p, c.addrs[idx].scope, false) }
                    "gw" -> if (v.isNotEmpty()) c.gateways += v
                    "dns" -> if (v.isNotEmpty()) c.dns += v
                    "dhcp" -> c.dhcp = v.equals("Yes", true) || v == "예"
                    "ipv6" -> if (v.isNotEmpty()) c.addrs += Addr(v.substringBefore('%'), null, if (key.contains("Link", true) || key.contains("링크")) "link" else null, true)
                    "media" -> c.media = v
                }
            } else if (t.isNotEmpty() && raw.startsWith("  ") && IpUtil.parse(t.substringBefore('%')) != null) {
                when (lastKey) { "dns" -> c.dns += t; "gw" -> c.gateways += t }                  // 윈도: DNS·게이트웨이가 여러 줄
            }
        }
        return out
    }
}

// ---------------------------------------------------------------------------------------------
// ss / netstat

object SockParse {
    class Sock(val proto: String, val state: String, val local: String, val lport: Int, val peer: String, val pport: Int?, val proc: String?)

    fun splitAddr(a: String): Pair<String, Int?> {
        val s = a.trim().replace(Regex("%[A-Za-z0-9._-]+"), "")
        if (s == "*:*" || s == "*") return "*" to null
        val i = s.lastIndexOf(':'); if (i < 0) return s to null
        val host = s.substring(0, i).removePrefix("[").removeSuffix("]").ifEmpty { "*" }
        return host to s.substring(i + 1).toIntOrNull()
    }

    private fun state(s: String): String = s.uppercase().replace('-', '_').let { when (it) { "ESTAB" -> "ESTABLISHED"; "LISTENING" -> "LISTEN"; "UNCONN" -> "UDP"; else -> it } }

    private val SS = Regex("""^(tcp|udp|raw|tcp6|udp6)\s+([A-Za-z_-]+)\s+\d+\s+\d+\s+(\S+)\s+(\S+)(?:\s+(.*))?$""")
    private val SS_NONETID = Regex("""^(LISTEN|ESTAB|TIME-WAIT|CLOSE-WAIT|SYN-SENT|SYN-RECV|FIN-WAIT-1|FIN-WAIT-2|LAST-ACK|CLOSING|UNCONN)\s+\d+\s+\d+\s+(\S+)\s+(\S+)(?:\s+(.*))?$""")
    private val NETSTAT = Regex("""^(tcp6?|udp6?)\s+\d+\s+\d+\s+(\S+)\s+(\S+)(?:\s+([A-Z_]+))?(?:\s+(\d+/.+?|-))?\s*$""")
    private val WINNET = Regex("""^\s*(TCP|UDP)\s+(\S+)\s+(\S+)\s+(?:([A-Z_]+)\s+)?(\d+)\s*$""")

    private fun proc(s: String?): String? {
        if (s.isNullOrBlank()) return null
        Regex("""\(\("([^"]+)",pid=(\d+)""").find(s)?.let { return "${it.groupValues[1]} (pid ${it.groupValues[2]})" }
        return s.trim().takeIf { it != "-" }
    }

    fun parse(text: String): List<Sock> {
        val out = ArrayList<Sock>()
        for (l in text.lines()) {
            val t = l.trim()
            val ss = SS.matchEntire(t)
            if (ss != null) { val (lh, lp) = splitAddr(ss.groupValues[3]); val (ph, pp) = splitAddr(ss.groupValues[4]); out += Sock(ss.groupValues[1].removeSuffix("6"), state(ss.groupValues[2]), lh, lp ?: 0, ph, pp, proc(ss.groupValues[5])); continue }
            val s2 = SS_NONETID.matchEntire(t)
            if (s2 != null) { val (lh, lp) = splitAddr(s2.groupValues[2]); val (ph, pp) = splitAddr(s2.groupValues[3]); out += Sock(if (s2.groupValues[1] == "UNCONN") "udp" else "tcp", state(s2.groupValues[1]), lh, lp ?: 0, ph, pp, proc(s2.groupValues[4])); continue }
            val ns = NETSTAT.matchEntire(t)
            if (ns != null) { val (lh, lp) = splitAddr(ns.groupValues[2]); val (ph, pp) = splitAddr(ns.groupValues[3]); val proto = ns.groupValues[1].removeSuffix("6"); out += Sock(proto, if (proto == "udp") "UDP" else state(ns.groupValues[4].ifEmpty { "?" }), lh, lp ?: 0, ph, pp, proc(ns.groupValues[5])); continue }
            val wn = WINNET.matchEntire(l)
            if (wn != null) { val (lh, lp) = splitAddr(wn.groupValues[2]); val (ph, pp) = splitAddr(wn.groupValues[3]); val proto = wn.groupValues[1].lowercase(); out += Sock(proto, if (proto == "udp") "UDP" else state(wn.groupValues[4].ifEmpty { "?" }), lh, lp ?: 0, ph, pp, "PID ${wn.groupValues[5]}") }
        }
        return out
    }

    /** 0 이 기기 안에서만, 1 한 주소에만, 2 모든 주소(외부 노출) */
    fun exposure(host: String): Int = when {
        host == "*" || host == "0.0.0.0" || host == "::" || host == "" -> 2
        host.startsWith("127.") || host == "::1" -> 0
        else -> 1
    }
}

// ---------------------------------------------------------------------------------------------
// dig / nslookup

object DigParse {
    class Rec(val name: String, val ttl: Long, val type: String, val data: String, val section: String)
    class Result(val query: String?, val status: String?, val flags: List<String>, val counts: Map<String, Int>, val recs: List<Rec>, val queryMs: Int?, val server: String?, val size: Int?, val proto: String?, val kind: String, val values: List<String>)

    fun parse(text: String): Result {
        val lines = text.lines()
        val isDig = lines.any { it.contains("<<>> DiG") || it.contains(";; ->>HEADER<<-") || it.contains("QUESTION SECTION") }
        if (!isDig) return parseNslookup(lines)
        var status: String? = null; var flags = emptyList<String>(); var counts = emptyMap<String, Int>(); var ms: Int? = null; var server: String? = null; var size: Int? = null; var proto: String? = null; var query: String? = null
        val recs = ArrayList<Rec>(); var section = ""
        for (l in lines) {
            Regex("""<<>> DiG \S+ <<>> (.*)$""").find(l)?.let { query = it.groupValues[1].trim() }
            Regex("""status:\s*(\w+)""").find(l)?.let { status = it.groupValues[1] }
            Regex("""^;; flags:\s*([a-z ]*);\s*QUERY:\s*(\d+),\s*ANSWER:\s*(\d+),\s*AUTHORITY:\s*(\d+),\s*ADDITIONAL:\s*(\d+)""").find(l)?.let { m ->
                flags = m.groupValues[1].trim().split(' ').filter { it.isNotEmpty() }
                counts = mapOf("QUERY" to m.groupValues[2].toInt(), "ANSWER" to m.groupValues[3].toInt(), "AUTHORITY" to m.groupValues[4].toInt(), "ADDITIONAL" to m.groupValues[5].toInt())
            }
            Regex("""Query time:\s*(\d+)\s*msec""").find(l)?.let { ms = it.groupValues[1].toInt() }
            Regex("""SERVER:\s*(\S+?)#(\d+)\(\S*\)(?:\s*\((\w+)\))?""").find(l)?.let { server = it.groupValues[1] + "#" + it.groupValues[2]; proto = it.groupValues[3].ifEmpty { null } }
            Regex("""MSG SIZE\s+rcvd:\s*(\d+)""").find(l)?.let { size = it.groupValues[1].toInt() }
            section = when {
                l.startsWith(";; QUESTION SECTION") -> "QUESTION"; l.startsWith(";; ANSWER SECTION") -> "ANSWER"; l.startsWith(";; AUTHORITY SECTION") -> "AUTHORITY"; l.startsWith(";; ADDITIONAL SECTION") -> "ADDITIONAL"
                l.isBlank() -> ""; else -> section
            }
            if (section == "ANSWER" || section == "AUTHORITY" || section == "ADDITIONAL")
                Regex("""^(\S+)\s+(\d+)\s+IN\s+(\S+)\s+(.*)$""").find(l)?.let { recs += Rec(it.groupValues[1].trimEnd('.'), it.groupValues[2].toLong(), it.groupValues[3], it.groupValues[4].trim(), section) }
        }
        return Result(query, status, flags, counts, recs, ms, server, size, proto, "dig", emptyList())
    }

    private fun parseNslookup(lines: List<String>): Result {
        var server: String? = null; var status: String? = null; var name: String? = null; val recs = ArrayList<Rec>(); var auth = true; var seenName = false; var serverAddr: String? = null
        for (l in lines) {
            val t = l.trim()
            if (Regex("^(Server|서버):").containsMatchIn(t) && server == null) { server = t.substringAfter(':').trim(); continue }
            if (Regex("^(Address|주소):").containsMatchIn(t) && !seenName) { if (serverAddr == null) serverAddr = t.substringAfter(':').trim(); continue }
            if (t.startsWith("Non-authoritative") || t.contains("신뢰할 수 없는 응답")) auth = false
            Regex("""can't find (\S+?):? (\w+)$""").find(t)?.let { name = it.groupValues[1]; status = it.groupValues[2] }
            Regex("""^(Name|이름):\s*(\S+)""").find(t)?.let { name = it.groupValues[2]; seenName = true }
            Regex("""^(Address(?:es)?|주소(?:들)?):\s*(\S.*)$""").find(t)?.takeIf { seenName }?.let { val v = it.groupValues[2].trim(); recs += Rec(name ?: "", 0, if (':' in v && '.' !in v) "AAAA" else "A", v, "ANSWER") }
            Regex("""^(\S+)\s+(?:canonical name|별칭)\s*=\s*(\S+)""").find(t)?.let { recs += Rec(it.groupValues[1], 0, "CNAME", it.groupValues[2].trimEnd('.'), "ANSWER") }
            Regex("""mail exchanger = (\d+)\s+(\S+)""").find(t)?.let { recs += Rec(name ?: "", 0, "MX", "${it.groupValues[1]} ${it.groupValues[2]}", "ANSWER") }
            Regex("""text = (.*)$""").find(t)?.let { recs += Rec(name ?: "", 0, "TXT", it.groupValues[1], "ANSWER") }
        }
        if (status == null && recs.isNotEmpty()) status = "NOERROR"
        return Result(name, status, if (auth) listOf("aa") else emptyList(), mapOf("ANSWER" to recs.size), recs, null, listOfNotNull(server, serverAddr?.let { "($it)" }).joinToString(" ").ifEmpty { null }, null, null, "nslookup", recs.map { it.data })
    }
}

// ---------------------------------------------------------------------------------------------
// iptables / ufw

object FwParse {
    class Rule(val chain: String, val proto: String?, val dports: List<String>, val src: String?, val dst: String?, val iface: String?, val target: String, val state: String?, val raw: String)
    class Result(val kind: String, val policies: Map<String, String>, val rules: List<Rule>, val active: Boolean?, val chains: List<String>)

    private fun tokens(l: String) = Regex("""("[^"]*"|\S+)""").findAll(l).map { it.value.trim('"') }.toList()

    fun parseIptables(text: String): Result {
        val policies = LinkedHashMap<String, String>(); val rules = ArrayList<Rule>(); val chains = ArrayList<String>()
        for (raw in text.lines()) {
            val l = raw.trim()
            Regex("""^:(\S+)\s+(ACCEPT|DROP|REJECT|-)\s""").find(l)?.let { if (it.groupValues[2] != "-") policies[it.groupValues[1]] = it.groupValues[2] else chains += it.groupValues[1] }
            if (l.startsWith("-P ")) { val t = tokens(l); if (t.size >= 3) policies[t[1]] = t[2]; continue }
            if (l.startsWith("-N ")) { chains += l.substringAfter("-N ").trim(); continue }
            if (!l.startsWith("-A ")) continue
            val t = tokens(l)
            fun opt(vararg names: String): String? { for (n in names) { val i = t.indexOf(n); if (i >= 0 && i + 1 < t.size) return t[i + 1] }; return null }
            val dports = (opt("--dport", "--destination-port")?.let { listOf(it) } ?: opt("--dports", "--destination-ports")?.split(',') ?: emptyList()).map { it.replace(':', '-') }
            rules += Rule(t[1], opt("-p", "--protocol"), dports, opt("-s", "--source"), opt("-d", "--destination"), opt("-i", "--in-interface"), opt("-j", "-g") ?: "", opt("--ctstate", "--state"), l)
        }
        return Result("iptables", policies, rules, null, chains)
    }

    fun parseUfw(text: String): Result {
        val rules = ArrayList<Rule>(); var active: Boolean? = null; var defIn: String? = null
        for (raw in text.lines()) {
            val l = raw.trim()
            Regex("""^Status:\s*(\w+)""", RegexOption.IGNORE_CASE).find(l)?.let { active = it.groupValues[1].equals("active", true) }
            Regex("""^Default:\s*(\w+)\s*\(incoming\)""", RegexOption.IGNORE_CASE).find(l)?.let { defIn = it.groupValues[1].uppercase().replace("DENY", "DROP") }
            val m = Regex("""^(\S+?)(?:\s+\(v6\))?\s+(ALLOW|DENY|REJECT|LIMIT)(?:\s+(IN|OUT|FWD))?\s+(.+?)\s*(?:#.*)?$""").find(l) ?: continue
            if (m.groupValues[3] == "OUT") continue
            val spec = m.groupValues[1]; val port = spec.substringBefore('/'); val proto = spec.substringAfter('/', "").ifEmpty { null }
            rules += Rule("INPUT", proto, if (port == "Anywhere" || port.isEmpty()) emptyList() else port.split(',').map { it.replace(':', '-') }, m.groupValues[4].trim().takeIf { !it.startsWith("Anywhere") }, null, null, if (m.groupValues[2] == "ALLOW" || m.groupValues[2] == "LIMIT") "ACCEPT" else "DROP", null, l)
        }
        return Result("ufw", defIn?.let { mapOf("INPUT" to it) } ?: emptyMap(), rules, active, emptyList())
    }

    fun parse(text: String): Result = if (Regex("(?m)^Status:", RegexOption.IGNORE_CASE).containsMatchIn(text) || (text.contains("ALLOW") && !text.contains("-A "))) parseUfw(text) else parseIptables(text)
}

// ---------------------------------------------------------------------------------------------
// tcpdump 글 출력 (-nn)

object TcpdumpParse {
    class Pkt(val time: String, val proto: String, val src: String, val sport: Int?, val dst: String, val dport: Int?, val flags: String?, val len: Int, val seq: Long?, val info: String, val dnsId: Int? = null, val dnsName: String? = null, val dnsResp: Boolean = false)

    private val HEAD = Regex("""^(?:\d{4}-\d{2}-\d{2} )?(\d{2}:\d{2}:\d{2}\.\d+)\s+(?:\S+\s+(?:In|Out)\s+)?(IP6?|ARP)\b,?\s+(.*)$""")
    private val FLOW = Regex("""^(\S+) > (\S+?):(?:\s+(.*))?$""")
    private val DNS_ID = Regex("""^(\d+)[+*-]*\s""")
    private val DNS_NAME = Regex("""\b(?:A|AAAA|MX|TXT|NS|PTR|CNAME|SOA|SRV|HTTPS|ANY)\?\s+(\S+?)\.?\s""")

    fun hostPort(a: String): Pair<String, Int?> {
        if (a.contains(':')) { val i = a.lastIndexOf('.'); return if (i > 0 && i < a.length - 1 && a.substring(i + 1).all { it.isDigit() }) a.substring(0, i) to a.substring(i + 1).toInt() else a to null }
        val parts = a.split('.'); return if (parts.size == 5 && parts.all { p -> p.isNotEmpty() && p.all { it.isDigit() } }) parts.take(4).joinToString(".") to parts[4].toInt() else a to null
    }

    fun parse(text: String): List<Pkt> {
        val out = ArrayList<Pkt>()
        for (l in text.lines()) {
            val h = HEAD.find(l.trim()) ?: continue; val time = h.groupValues[1]; val kind = h.groupValues[2]; val rest = h.groupValues[3]
            if (kind == "ARP") {
                val m = Regex("""^(?:Request who-has (\S+) tell (\S+?),|Reply (\S+) is-at (\S+),)""").find(rest) ?: continue
                out += if (m.groupValues[1].isNotEmpty()) Pkt(time, "ARP", m.groupValues[2], null, m.groupValues[1], null, "who-has", 28, null, rest) else Pkt(time, "ARP", m.groupValues[3], null, "", null, "is-at", 28, null, rest)
                continue
            }
            val f = FLOW.find(rest) ?: continue
            val (sh, sp) = hostPort(f.groupValues[1]); val (dh, dp) = hostPort(f.groupValues[2]); val info = f.groupValues[3]
            val len = Regex("""length (\d+)""").find(info)?.groupValues?.get(1)?.toInt() ?: Regex("""\((\d+)\)\s*$""").find(info)?.groupValues?.get(1)?.toInt() ?: 0
            val flags = Regex("""Flags \[([^\]]+)]""").find(info)?.groupValues?.get(1)
            val seq = Regex("""seq (\d+)""").find(info)?.groupValues?.get(1)?.toLongOrNull()
            val dnsId = if (sp == 53 || dp == 53) DNS_ID.find(info)?.groupValues?.get(1)?.toInt() else null
            val proto = when { flags != null -> "TCP"; info.startsWith("ICMP") -> "ICMP"; info.startsWith("UDP") || dnsId != null || (sp != null && dp != null) -> "UDP"; else -> "기타" }
            out += Pkt(time, proto, sh, sp, dh, dp, flags, len, seq, info, dnsId, if (dnsId != null) DNS_NAME.find(info)?.groupValues?.get(1) else null, dnsId != null && sp == 53)
        }
        return out
    }
}
