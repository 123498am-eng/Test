package com.selfcheck.app

import org.json.JSONObject
import java.io.IOException
import java.net.IDN
import java.net.InetAddress

/*
 * 메일·DNS 점검 엔진: SPF 평가(RFC 7208)·SPF 평탄화·DoH 응답 해석·DNS 존 파일 점검·비슷한 도메인 만들기·이메일 주소 검사·RDAP(도메인).
 * DNS 조회는 SpfDns 로 추상화해서 컴퓨터에서 가짜 DNS 로 시험합니다.
 */

interface SpfDns {
    /** 이름의 TXT 레코드 글자들. 없으면 빈 목록, 조회 실패(시간 초과 등)면 IOException */
    fun txt(name: String): List<String>
    fun addresses(name: String): List<InetAddress>
    fun mx(name: String): List<String>
}

object SpfEval {
    class Result(val verdict: String, val reason: String, val lookups: Int, val trace: List<String>)

    private class State(val dns: SpfDns, val ip: InetAddress) { var lookups = 0; val trace = ArrayList<String>() }
    private class Abort(val verdict: String, val reason: String) : Exception()

    private fun qual(q: Char) = when (q) { '+' -> "pass"; '-' -> "fail"; '~' -> "softfail"; else -> "neutral" }

    private fun inNet(ip: InetAddress, spec: String, defaultPrefix: Int): Boolean {
        val base = spec.substringBefore('/'); val p = spec.substringAfter('/', "").toIntOrNull() ?: defaultPrefix
        val net = IpUtil.parse(base) ?: return false
        if (net.address.size != ip.address.size) return false
        val bits = ip.address.size * 8; if (p !in 0..bits) return false
        val a = V6.toBig(ip); val b = V6.toBig(net); val shift = (if (ip.address.size == 4) 32 else 128) - p
        return a.shiftRight(shift) == b.shiftRight(shift)
    }

    private fun cidrOf(value: String?, v4: Boolean): Int = value?.let { v -> if (v4) v.substringAfter('/', "").substringBefore("//").toIntOrNull() ?: 32 else (if ("//" in v) v.substringAfter("//").toIntOrNull() else null) ?: 128 } ?: (if (v4) 32 else 128)

    /** 도메인 SPF 로 ip 를 평가: pass·fail·softfail·neutral·none·permerror·temperror */
    fun check(dns: SpfDns, ip: InetAddress, domain: String): Result {
        val st = State(dns, ip)
        return try { val (v, why) = eval(st, domain.lowercase().trimEnd('.'), 0); Result(v, why, st.lookups, st.trace) }
        catch (a: Abort) { Result(a.verdict, a.reason, st.lookups, st.trace) }
        catch (e: IOException) { Result("temperror", "DNS 조회에 실패했어요 (${e.message})", st.lookups, st.trace) }
    }

    private fun lookup(st: State, what: String) { st.lookups++; if (st.lookups > 10) throw Abort("permerror", "DNS 조회가 10번을 넘었어요 ($what) — SPF 규격의 한도예요") }

    private fun eval(st: State, domain: String, depth: Int): Pair<String, String> {
        if (depth > 10) throw Abort("permerror", "include/redirect 가 너무 깊어요")
        val txts = st.dns.txt(domain).filter { it.trim().startsWith("v=spf1", true) && (it.trim().length == 6 || it.trim()[6] == ' ') }
        if (txts.isEmpty()) return "none" to "$domain 에 SPF 레코드가 없어요"
        if (txts.size > 1) throw Abort("permerror", "$domain 에 SPF 레코드가 ${txts.size}개예요 (하나만 있어야 해요)")
        st.trace += "$domain: ${txts[0].trim()}"
        val terms = txts[0].trim().split(Regex("\\s+")).drop(1)
        var redirect: String? = null
        for (t in terms) {
            if (t.startsWith("redirect=", true)) { redirect = t.substringAfter('='); continue }
            if (t.startsWith("exp=", true)) continue
            var q = '+'; var term = t
            if (term[0] in "+-~?") { q = term[0]; term = term.substring(1) }
            val name = term.substringBefore(':').substringBefore('/').lowercase(); val value = if (':' in term) term.substringAfter(':') else null
            if (value?.contains("%{") == true) { st.trace += "  $t → 매크로(%{…})는 지원하지 않아서 건너뜀"; continue }
            val matched: Boolean = when (name) {
                "all" -> true
                "ip4", "ip6" -> value != null && inNet(st.ip, value, if (name == "ip4") 32 else 128)
                "a" -> { lookup(st, "a"); val d = (value?.substringBefore('/') ?: domain).ifEmpty { domain }; val v4 = st.ip.address.size == 4; val cidr = if (v4) term.substringAfter('/', "").substringBefore("//").toIntOrNull() ?: 32 else (if ("//" in term) term.substringAfter("//").toIntOrNull() else null) ?: 128
                    st.dns.addresses(d).filter { it.address.size == st.ip.address.size }.any { inNet(st.ip, "${IpUtil.format(it)}/$cidr", cidr) } }
                "mx" -> { lookup(st, "mx"); val d = (value?.substringBefore('/') ?: domain).ifEmpty { domain }; val v4 = st.ip.address.size == 4; val cidr = if (v4) term.substringAfter('/', "").substringBefore("//").toIntOrNull() ?: 32 else (if ("//" in term) term.substringAfter("//").toIntOrNull() else null) ?: 128
                    // RFC 7208 4.6.4: mx 는 조회 1번으로 세고, 그 서버들의 주소는 따로 10개까지만 허용
                    val hosts = st.dns.mx(d).filter { it.isNotBlank() }
                    if (hosts.size > 10) throw Abort("permerror", "$d 의 MX 서버가 ${hosts.size}개예요 — 한 번에 10개까지만 허용돼요 (RFC 7208)")
                    hosts.any { h -> st.dns.addresses(h).filter { it.address.size == st.ip.address.size }.any { inNet(st.ip, "${IpUtil.format(it)}/$cidr", cidr) } } }
                "include" -> { lookup(st, "include"); val d = value ?: throw Abort("permerror", "include 에 도메인이 없어요")
                    val (v, why) = eval(st, d.lowercase().trimEnd('.'), depth + 1)
                    when (v) { "pass" -> true; "fail", "softfail", "neutral" -> false; "none" -> throw Abort("permerror", "include 한 $d 에 SPF 레코드가 없어요"); else -> throw Abort(v, why) } }
                "exists" -> { lookup(st, "exists"); value != null && st.dns.addresses(value).any { it.address.size == 4 } }
                "ptr" -> { st.trace += "  ptr → 지원하지 않는 낡은 방식이라 건너뜀"; false }
                else -> throw Abort("permerror", "알 수 없는 항목: $t")
            }
            st.trace += "  $t → ${if (matched) "일치" else "일치하지 않음"}"
            if (matched) return qual(q) to "$domain 의 \"$t\" 가 일치했어요"
        }
        if (redirect != null) { lookup(st, "redirect"); val (v, why) = eval(st, redirect.lowercase().trimEnd('.'), depth + 1); if (v == "none") throw Abort("permerror", "redirect 한 $redirect 에 SPF 레코드가 없어요"); return v to why }
        return "neutral" to "$domain 의 어떤 항목과도 일치하지 않았어요 (기본값: neutral)"
    }

    /** 평탄화: include·a·mx 를 모두 풀어 ip4/ip6 목록으로. (결과 항목들, 처음 조회 수, 안내) */
    class Flat(val entries: List<String>, val originalLookups: Int, val notes: List<String>, val allQualifier: String)

    fun flatten(dns: SpfDns, domain: String): Flat {
        val out = LinkedHashSet<String>(); val notes = ArrayList<String>(); var lookups = 0; var all = "~all"
        fun walk(d: String, depth: Int, top: Boolean) {
            if (depth > 10) { notes += "include 가 너무 깊어 멈췄어요"; return }
            val txt = dns.txt(d).firstOrNull { it.trim().startsWith("v=spf1", true) } ?: run { notes += "$d 에 SPF 레코드가 없어요"; return }
            val terms = txt.trim().split(Regex("\\s+")).drop(1)
            val hasAll = terms.any { it.trimStart('+', '-', '~', '?').equals("all", true) }     // all 이 있으면 redirect 는 쓰이지 않음 (RFC 7208 6.1)
            for (t in terms) {
                if (t.startsWith("redirect=", true)) { if (!hasAll) { lookups++; walk(t.substringAfter('=').lowercase().trimEnd('.'), depth + 1, top) }; continue }
                if (t.startsWith("exp=", true)) continue
                val term = t.trimStart('+', '-', '~', '?'); val name = term.substringBefore(':').substringBefore('/').lowercase(); val value = if (':' in term) term.substringAfter(':') else null
                when (name) {
                    "ip4", "ip6" -> value?.let { out += "$name:$it" }
                    "include" -> { lookups++; value?.let { walk(it.lowercase().trimEnd('.'), depth + 1, false) } }
                    "a" -> { lookups++; val h = (value?.substringBefore('/') ?: d); val cidr = if ('/' in term) term.substringAfter('/') else null; dns.addresses(h).forEach { out += (if (it.address.size == 4) "ip4:" else "ip6:") + IpUtil.format(it) + (cidr?.let { c -> "/$c" } ?: "") } }
                    "mx" -> { lookups++; val h = (value?.substringBefore('/') ?: d); val cidr = if ('/' in term) term.substringAfter('/') else null; dns.mx(h).filter { it.isNotBlank() }.forEach { m -> dns.addresses(m).forEach { out += (if (it.address.size == 4) "ip4:" else "ip6:") + IpUtil.format(it) + (cidr?.let { c -> "/$c" } ?: "") } } }
                    "all" -> if (top) all = t.let { if (it[0] in "+-~?") "${it[0]}all" else "+all" }.let { if (it.startsWith("+")) "all" else it }
                    "exists", "ptr" -> notes += "$t 는 평탄화할 수 없어서 그대로 남겨야 해요"
                }
            }
        }
        walk(domain.lowercase().trimEnd('.'), 0, true)
        return Flat(out.toList(), lookups, notes, all)
    }

    fun record(f: Flat): String = "v=spf1 " + f.entries.joinToString(" ") + " " + f.allQualifier
}

object Doh {
    class Answer(val name: String, val type: Int, val ttl: Long, val data: String)
    class Reply(val status: Int, val ad: Boolean, val ra: Boolean, val answers: List<Answer>)

    fun url(provider: String, name: String, type: String): String = when (provider) {
        "구글" -> "https://dns.google/resolve?name=${java.net.URLEncoder.encode(name, "UTF-8")}&type=$type"
        else -> "https://cloudflare-dns.com/dns-query?name=${java.net.URLEncoder.encode(name, "UTF-8")}&type=$type"
    }

    fun parse(json: String): Reply {
        val o = JSONObject(json)
        val arr = o.optJSONArray("Answer")
        val answers = (0 until (arr?.length() ?: 0)).mapNotNull { arr!!.optJSONObject(it)?.let { a -> Answer(a.optString("name").trimEnd('.'), a.optInt("type"), a.optLong("TTL"), a.optString("data")) } }
        return Reply(o.optInt("Status", -1), o.optBoolean("AD"), o.optBoolean("RA"), answers)
    }
}

object DomainRdap {
    class Info(val name: String?, val registrar: String?, val created: String?, val expires: String?, val changed: String?, val status: List<String>, val nameservers: List<String>, val dnssec: Boolean?)

    fun parse(text: String): Info {
        val o = JSONObject(text)
        fun ev(action: String): String? { val a = o.optJSONArray("events") ?: return null; for (i in 0 until a.length()) { val e = a.optJSONObject(i) ?: continue; if (e.optString("eventAction").equals(action, true)) return e.optString("eventDate").takeIf { it.isNotBlank() } }; return null }
        var registrar: String? = null
        val ents = o.optJSONArray("entities")
        if (ents != null) for (i in 0 until ents.length()) {
            val e = ents.optJSONObject(i) ?: continue; val roles = e.optJSONArray("roles")
            if ((0 until (roles?.length() ?: 0)).any { roles!!.optString(it) == "registrar" }) { val vc = e.optJSONArray("vcardArray")?.optJSONArray(1); if (vc != null) for (k in 0 until vc.length()) { val p = vc.optJSONArray(k); if (p?.optString(0) == "fn") registrar = p.optString(3) } }
        }
        val ns = o.optJSONArray("nameservers"); val st = o.optJSONArray("status")
        return Info(o.optString("ldhName").ifEmpty { null }, registrar, ev("registration"), ev("expiration"), ev("last changed"), (0 until (st?.length() ?: 0)).map { st!!.optString(it) }, (0 until (ns?.length() ?: 0)).mapNotNull { ns!!.optJSONObject(it)?.optString("ldhName")?.lowercase() },
            o.optJSONObject("secureDNS")?.let { if (it.has("delegationSigned")) it.optBoolean("delegationSigned") else null })
    }
}

object Lookalike {
    class Item(val domain: String, val technique: String, val shown: String = domain)

    private val TLD_SWAPS = listOf("com", "net", "org", "co", "io", "kr", "co.kr", "info", "xyz", "online", "shop", "app")
    private val HOMOGLYPH = mapOf('o' to listOf("0"), 'l' to listOf("1", "i"), 'i' to listOf("1", "l"), 'e' to listOf("3"), 'a' to listOf("4"), 's' to listOf("5"), 'g' to listOf("9"), 'm' to listOf("rn"), 'w' to listOf("vv"), 'd' to listOf("cl"))
    private val CYR = mapOf('a' to 'а', 'e' to 'е', 'o' to 'о', 'p' to 'р', 'c' to 'с', 'x' to 'х', 'y' to 'у', 'i' to 'і')

    /** 도메인(example.com) → 비슷해 보이는 후보 (기술별로 골고루, 최대 limit 개) */
    fun generate(domain: String, limit: Int = 60): List<Item> {
        val d = domain.lowercase().trim().trimEnd('.'); val dot = d.lastIndexOf('.'); if (dot <= 0) return emptyList()
        // co.kr 같은 두 칸 TLD
        val twoPart = Regex("""\.(co|or|ne|go|ac|re|pe|com|org|net|gov|edu)\.[a-z]{2}$""").find(d)
        val tld = twoPart?.value?.drop(1) ?: d.substring(dot + 1); val label = d.removeSuffix(".$tld")
        if (label.isEmpty() || label.contains('.')) return emptyList()
        val by = LinkedHashMap<String, LinkedHashSet<Item>>()
        fun add(tech: String, l: String, t: String = tld, shown: String? = null) {
            if (l.isEmpty() || l.startsWith("-") || l.endsWith("-")) return
            val dom = try { IDN.toASCII("$l.$t", IDN.ALLOW_UNASSIGNED) } catch (_: Exception) { return }
            if (dom == d) return
            by.getOrPut(tech) { LinkedHashSet() }.add(Item(dom, tech, shown ?: "$l.$t"))
        }
        for (i in label.indices) add("글자 빠짐", label.removeRange(i, i + 1))
        for (i in label.indices) add("글자 겹침", label.substring(0, i + 1) + label[i] + label.substring(i + 1))
        for (i in 0 until label.length - 1) if (label[i] != label[i + 1]) add("글자 자리 바뀜", label.substring(0, i) + label[i + 1] + label[i] + label.substring(i + 2))
        for (i in label.indices) HOMOGLYPH[label[i]]?.forEach { add("비슷한 글자(숫자·조합)", label.substring(0, i) + it + label.substring(i + 1)) }
        for (i in 1 until label.length) add("하이픈 넣기", label.substring(0, i) + "-" + label.substring(i))
        for (t in TLD_SWAPS) if (t != tld) add("다른 도메인 끝(TLD)", label, t)
        for (i in label.indices) CYR[label[i]]?.let { add("키릴 글자 위장", label.substring(0, i) + it + label.substring(i + 1), shown = label.substring(0, i) + it + label.substring(i + 1) + ".$tld") }
        add("www 붙임", "www$label"); add("복수형", label + "s"); add("-login 붙임", "$label-login"); add("-support 붙임", "$label-support")
        // 기술마다 번갈아 가며 골고루 뽑기
        val iters = by.values.map { it.iterator() }; val out = ArrayList<Item>(); val seen = HashSet<String>()
        while (out.size < limit && iters.any { it.hasNext() }) for (it in iters) if (it.hasNext() && out.size < limit) { val x = it.next(); if (seen.add(x.domain)) out += x }
        return out
    }
}

object EmailCheck {
    private val SYNTAX = Regex("""^[A-Za-z0-9!#$%&'*+/=?^_`{|}~.-]{1,64}@[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?(?:\.[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?)+$""")
    private val DISPOSABLE = setOf("mailinator.com", "guerrillamail.com", "10minutemail.com", "tempmail.com", "temp-mail.org", "yopmail.com", "trashmail.com", "sharklasers.com", "getnada.com", "maildrop.cc", "dispostable.com", "throwawaymail.com", "fakeinbox.com", "mohmal.com", "emailondeck.com", "mintemail.com", "spamgourmet.com", "tmpmail.org", "burnermail.io", "mailnesia.com")
    private val ROLE = setOf("admin", "administrator", "info", "support", "sales", "contact", "help", "noreply", "no-reply", "postmaster", "webmaster", "abuse", "root", "hostmaster", "billing", "office", "service", "mail", "marketing", "security")

    fun problems(addr: String): List<Pair<String, Int>> = buildList {
        val a = addr.trim()
        if (a.length > 254) add("전체가 254자를 넘어요" to 2)
        if (!SYNTAX.matches(a)) add("형식이 올바르지 않아요 (예: name@example.com)" to 2)
        val local = a.substringBefore('@'); if (local.startsWith(".") || local.endsWith(".") || ".." in local) add("점(.)이 맨 앞·맨 뒤에 있거나 연속돼 있어요" to 2)
    }

    fun domainOf(addr: String) = addr.trim().substringAfterLast('@').lowercase()
    fun isDisposable(domain: String) = domain in DISPOSABLE
    fun isRole(addr: String) = addr.substringBefore('@').lowercase() in ROLE
}

object ZoneLint {
    private val TYPES = setOf("A", "AAAA", "CNAME", "MX", "NS", "TXT", "SOA", "SRV", "PTR", "CAA", "DS", "DNSKEY", "TLSA", "SPF", "NAPTR", "HTTPS", "SVCB", "RRSIG", "NSEC")
    private val COMMON_TLD = Regex("""\.(com|net|org|io|kr|co|info|dev|app|xyz|edu|gov|biz|me|us|uk|jp|cn|de|fr|ru|online|shop|site|cloud)$""", RegexOption.IGNORE_CASE)

    class Rec(val line: Int, val name: String, val ttl: Long?, val type: String, val data: String)

    /** BIND 의 시간 표기: 3600, 1h, 1d12h, 2w … → 초 (읽을 수 없으면 null) */
    internal fun ttlOf(x: String): Long? {
        x.toLongOrNull()?.let { return it }
        if (!Regex("""^(\d+[smhdwSMHDW])+$""").matches(x)) return null
        val unit = mapOf('s' to 1L, 'm' to 60L, 'h' to 3600L, 'd' to 86400L, 'w' to 604800L)
        return Regex("""(\d+)([smhdwSMHDW])""").findAll(x).sumOf { it.groupValues[1].toLong() * unit[it.groupValues[2][0].lowercaseChar()]!! }
    }

    private fun joinParens(text: String): List<Pair<Int, String>> {
        val out = ArrayList<Pair<Int, String>>(); var buf = StringBuilder(); var start = 0; var depth = 0
        text.lines().forEachIndexed { i, raw ->
            // 따옴표 안의 ; 는 주석이 아님
            var inQ = false; var cut = raw.length
            for (k in raw.indices) { if (raw[k] == '"') inQ = !inQ; if (raw[k] == ';' && !inQ) { cut = k; break } }
            val l = raw.substring(0, cut)
            if (depth == 0) { buf = StringBuilder(); start = i + 1 }
            buf.append(l).append(' ')
            depth += l.count { it == '(' } - l.count { it == ')' }
            if (depth <= 0) { depth = 0; if (buf.isNotBlank()) out += start to buf.toString().replace("(", " ").replace(")", " ") }
        }
        return out
    }

    fun lint(text: String): List<Triple<Int, String, Int>> {
        val issues = ArrayList<Triple<Int, String, Int>>()   // (줄, 내용, 심각도 1 주의 2 오류, 0 정보)
        var origin: String? = null; var defTtl: Long? = null; var lastName: String? = null
        val recs = ArrayList<Rec>()
        for ((ln, line) in joinParens(text)) {
            val t = line.trim(); if (t.isEmpty()) continue
            if (t.startsWith("\$ORIGIN", true)) { origin = t.substringAfter(' ').trim().lowercase(); if (!origin!!.endsWith(".")) issues += Triple(ln, "\$ORIGIN 은 점(.)으로 끝나야 해요", 2); continue }
            if (t.startsWith("\$TTL", true)) { defTtl = ttlOf(t.substringAfter(' ').trim()); if (defTtl == null) issues += Triple(ln, "\$TTL 값을 읽지 못했어요", 2); continue }
            if (t.startsWith("\$")) continue
            val toks = t.split(Regex("\\s+")).toMutableList()
            val startsBlank = line[0].isWhitespace()
            var name = if (startsBlank) (lastName ?: "") else toks.removeAt(0)
            if (!startsBlank) lastName = name
            var ttl: Long? = null
            while (toks.isNotEmpty()) { val x = toks[0]; if (x.equals("IN", true) || x.equals("CH", true)) { toks.removeAt(0); continue }; val n = ttlOf(x); if (n != null && x.uppercase() !in TYPES) { ttl = n; toks.removeAt(0) } else break }
            if (toks.isEmpty()) { issues += Triple(ln, "레코드 종류가 없어요", 2); continue }
            val type = toks.removeAt(0).uppercase(); val data = toks.joinToString(" ")
            if (type !in TYPES) { issues += Triple(ln, "알 수 없는 레코드 종류: $type", 2); continue }
            recs += Rec(ln, if (name == "@") (origin ?: "@") else name, ttl ?: defTtl, type, data)
        }
        if (recs.isEmpty()) return listOf(Triple(0, "레코드를 찾지 못했어요", 2))
        val apexNames = setOfNotNull("@", origin, origin?.trimEnd('.'))
        val soa = recs.filter { it.type == "SOA" }
        if (soa.isEmpty()) issues += Triple(0, "SOA 레코드가 없어요 (영역마다 정확히 하나 필요해요)", 2) else if (soa.size > 1) issues += Triple(soa[1].line, "SOA 가 ${soa.size}개예요 (하나만 있어야 해요)", 2)
        soa.firstOrNull()?.let { s -> val f = s.data.split(Regex("\\s+")); if (f.size < 7) issues += Triple(s.line, "SOA 값이 7개(주 서버·담당자·일련번호·갱신·재시도·만료·최소)가 아니에요", 2) else { val serial = f[2]; if (!Regex("""^20\d{8}$""").matches(serial)) issues += Triple(s.line, "SOA 일련번호($serial)가 YYYYMMDDnn 형식이 아니에요 (꼭 필요하진 않지만 관리하기 쉬워요)", 0); if (f[0].isNotEmpty() && !f[0].endsWith(".") && f[0].contains(".")) issues += Triple(s.line, "SOA 주 서버 이름 끝에 점(.)이 없어요", 1) } }
        val ns = recs.filter { it.type == "NS" && it.name in apexNames }; if (ns.size < 2) issues += Triple(0, "영역 최상단(@)의 NS 가 ${ns.size}개예요 (2개 이상 권장)", 1)
        // 같은 이름에 CNAME 과 다른 레코드가 함께 있음
        for ((n, g) in recs.groupBy { it.name }) {
            if (g.any { it.type == "CNAME" } && g.any { it.type !in listOf("CNAME", "RRSIG", "NSEC") }) issues += Triple(g.first { it.type == "CNAME" }.line, "\"$n\" 에 CNAME 과 다른 레코드(${g.filter { it.type != "CNAME" }.map { it.type }.distinct().joinToString()})가 함께 있어요 — CNAME 은 단독이어야 해요", 2)
            if (g.count { it.type == "CNAME" } > 1) issues += Triple(g.last { it.type == "CNAME" }.line, "\"$n\" 에 CNAME 이 여러 개예요", 2)
        }
        recs.filter { it.type == "CNAME" && it.name in apexNames }.forEach { issues += Triple(it.line, "영역 최상단(@)에는 CNAME 을 쓸 수 없어요 (A/ALIAS 를 쓰세요)", 2) }
        val dup = recs.groupBy { listOf(it.name, it.type, it.data) }.filter { it.value.size > 1 }; for ((_, v) in dup) issues += Triple(v[1].line, "똑같은 레코드가 중복돼 있어요: ${v[0].name} ${v[0].type} ${v[0].data.take(40)}", 1)
        for (r in recs) {
            val host = when (r.type) { "NS", "CNAME", "PTR" -> r.data; "MX" -> r.data.substringAfter(' ', ""); else -> null }
            // 이름에 점이 있는데 끝에 점이 없으면 영역 이름이 뒤에 또 붙음: files.example.com → files.example.com.example.com.
            if (host != null && host.isNotEmpty() && !host.endsWith(".") && host.contains('.') && (origin?.let { host.endsWith(it.trimEnd('.')) } == true || COMMON_TLD.containsMatchIn(host))) {
                val expands = if (origin != null) "\"$host.${origin.trimEnd('.')}.\" 로" else "영역 이름이 뒤에 붙어서 엉뚱한 이름으로"
                issues += Triple(r.line, "\"$host\" 끝에 점(.)이 없어요 — 점이 없으면 $expands 해석돼요", 1)
            }
            if (r.type == "A") { val ip = IpUtil.parseV4(r.data.trim()); if (ip == null) issues += Triple(r.line, "A 레코드 값이 IPv4 주소가 아니에요: ${r.data}", 2) else if (IpUtil.classify(InetAddress.getByAddress(ip)).local) issues += Triple(r.line, "A 레코드가 사설·내부 주소(${r.data})예요 — 인터넷에서는 접속할 수 없어요", 1) }
            if (r.type == "AAAA" && IpUtil.parse(r.data.trim())?.address?.size != 16) issues += Triple(r.line, "AAAA 레코드 값이 IPv6 주소가 아니에요: ${r.data}", 2)
            if (r.type == "MX") { val p = r.data.substringBefore(' ').toIntOrNull(); if (p == null) issues += Triple(r.line, "MX 앞의 우선순위가 숫자가 아니에요", 2); if (IpUtil.parse(r.data.substringAfter(' ', "").trim()) != null) issues += Triple(r.line, "MX 는 IP 주소가 아니라 호스트 이름이어야 해요", 2) }
            if (r.type == "TXT") { val strs = Regex("\"([^\"]*)\"").findAll(r.data).map { it.groupValues[1] }.toList().ifEmpty { listOf(r.data) }; if (strs.any { it.toByteArray().size > 255 }) issues += Triple(r.line, "TXT 한 덩어리가 255바이트를 넘어요 — \"앞부분\" \"뒷부분\" 처럼 나눠 써야 해요", 2) }
            r.ttl?.let { if (it < 60) issues += Triple(r.line, "TTL ${it}초는 너무 짧아요 (DNS 서버 부담)", 1) else if (it > 604800) issues += Triple(r.line, "TTL ${it}초(${it / 86400}일)는 너무 길어요 (변경이 늦게 반영돼요)", 1) }
        }
        val spf = recs.filter { it.type == "TXT" && it.data.contains("v=spf1") }.groupBy { it.name }; for ((n, g) in spf) if (g.size > 1) issues += Triple(g[1].line, "\"$n\" 에 SPF 레코드가 ${g.size}개예요 (하나만 있어야 해요)", 2)
        recs.filter { it.type == "SPF" }.forEach { issues += Triple(it.line, "SPF 레코드 종류는 폐기됐어요 — TXT 로 쓰세요", 1) }
        if (recs.none { it.type == "MX" } && recs.any { it.type == "TXT" && it.data.contains("v=spf1") && !it.data.contains("-all") }) issues += Triple(0, "메일을 안 받는 영역이라면 SPF 를 \"v=spf1 -all\" 로 두면 사칭 메일을 막을 수 있어요", 0)
        return issues.sortedWith(compareBy({ it.first }, { -it.third }))
    }
}
