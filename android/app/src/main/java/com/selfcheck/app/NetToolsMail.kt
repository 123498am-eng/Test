package com.selfcheck.app

import org.json.JSONArray
import java.io.IOException
import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.Socket
import java.time.Instant
import java.time.ZonedDateTime

/**
 * 메일·DNS 점검 도구 16가지: DNS 질문(UDP·TCP·TLS·HTTPS)과 공개 레코드만 읽습니다.
 * 이메일 주소 확인은 도메인의 메일 서버(MX)가 있는지만 보고, 그 주소로 메일을 보내거나 받는 사람을 확인하지 않아요.
 */
object MailTools {
    private const val M = NetGroups.MAIL
    private const val NOTE_DNS = "입력한 도메인 이름을 DNS 서버(기본: 지금 연결의 DNS)로 보내요. 인터넷을 사용해요."

    private fun serverFirst(host: ToolHost) = DnsTools.servers(ToolInput(emptyMap()), host)

    /** DNS 에서 SPF 평가에 쓸 조회 함수 */
    private class LiveDns(val servers: List<String>, val host: ToolHost) : SpfDns {
        private fun ask(name: String, t: Int): DnsResponse { val r = DnsTools.ask(servers, name, t, host); if (r.msg.rcode == 2) throw IOException("SERVFAIL ($name)"); return r }
        override fun txt(name: String) = ask(name, DnsType.TXT).msg.answers.filter { it.type == DnsType.TXT }.map { it.text ?: "" }
        override fun addresses(name: String): List<InetAddress> = (ask(name, DnsType.A).msg.answers.filter { it.type == DnsType.A } + runCatching { ask(name, DnsType.AAAA).msg.answers.filter { it.type == DnsType.AAAA } }.getOrDefault(emptyList())).mapNotNull { IpUtil.parse(it.data) }
        override fun mx(name: String): List<String> = ask(name, DnsType.MX).msg.answers.filter { it.type == DnsType.MX }.map { it.data.substringBefore(' ').toInt() to it.data.substringAfter(' ').trimEnd('.') }.sortedBy { it.first }.map { it.second }
    }

    private fun domainIn(i: ToolInput, key: String = "d"): String? = HostInput.host(i.str(key)).ifEmpty { null }?.lowercase()

    private val SELECTORS = listOf("default", "google", "selector1", "selector2", "k1", "k2", "k3", "mail", "dkim", "s1", "s2", "smtp", "mandrill", "mailo", "dk", "m1", "pic", "protonmail", "protonmail2", "protonmail3", "zoho", "fm1", "fm2", "fm3", "mimecast20190104", "sig1", "krs", "cm", "key1", "key2", "mta", "email", "dkim1", "20230601", "scph0123")

    private val HIJACK_SITES = listOf("google.com" to Regex("google", RegexOption.IGNORE_CASE), "cloudflare.com" to Regex("cloudflare", RegexOption.IGNORE_CASE), "wikipedia.org" to Regex("wikimedia", RegexOption.IGNORE_CASE), "github.com" to Regex("github|microsoft", RegexOption.IGNORE_CASE), "microsoft.com" to Regex("microsoft|akamai", RegexOption.IGNORE_CASE))

    private val RESOLVERS = listOf("8.8.8.8" to "구글", "8.8.4.4" to "구글 2", "1.1.1.1" to "클라우드플레어", "1.0.0.1" to "클라우드플레어 2", "9.9.9.9" to "Quad9", "208.67.222.222" to "OpenDNS", "168.126.63.1" to "KT", "210.220.163.82" to "SK브로드밴드", "164.124.101.2" to "LG U+")
    /** 시험에서 바꿀 수 있음 */
    internal var propagationResolvers: List<Pair<String, String>> = RESOLVERS
    /** 시험에서만 씀: 네임서버 이름 → 그 서버가 듣는 포트 (실제로는 항상 53) */
    internal var nsPorts: Map<String, Int> = emptyMap()

    private val TAKEOVER = Regex("""\.(herokuapp\.com|herokudns\.com|github\.io|azurewebsites\.net|cloudapp\.net|trafficmanager\.net|s3[.-][a-z0-9-]*\.amazonaws\.com|s3\.amazonaws\.com|elasticbeanstalk\.com|bitbucket\.io|ghost\.io|netlify\.app|pantheonsite\.io|readme\.io|surge\.sh|wordpress\.com|zendesk\.com|myshopify\.com|unbouncepages\.com|statuspage\.io|helpscoutdocs\.com|webflow\.io|fly\.dev|vercel\.app)\.?$""", RegexOption.IGNORE_CASE)

    val ALL: List<NetTool> = listOf(
        online("dns_doh", M, "DoH 로 DNS 조회 (HTTPS 암호화)", "DNS 질문을 HTTPS 로 암호화해 보내 답을 확인 — 통신사 DNS 가 막거나 바꿔도 진짜 답을 보기", DnsTools.domainField(), choice("t", "레코드 종류", listOf("A", "AAAA", "MX", "TXT", "NS", "CNAME", "SOA", "CAA"), "A"), choice("p", "DoH 서버", listOf("클라우드플레어", "구글")),
            note = "도메인 이름을 선택한 DoH 서버(cloudflare-dns.com 또는 dns.google)에 HTTPS 로 보내요. 인터넷을 사용해요.") { i, _, env ->
            val d = domainIn(i) ?: return@online need("도메인을 입력하세요")
            env.progress("DoH 로 묻는 중...")
            val rep = try { Doh.parse(GeoNet.get(Doh.url(i.str("p"), d, i.str("t")), 9000, 262144, mapOf("Accept" to "application/dns-json"))) } catch (e: IOException) { return@online fail("조회하지 못했어요: ${e.message}") } catch (e: org.json.JSONException) { return@online fail("응답을 읽지 못했어요") }
            result {
                kv("질문", "$d ${i.str("t")}  → ${i.str("p")} (HTTPS)"); kv("응답 코드", "${DnsType.rcode(rep.status)}", if (rep.status == 0) -1 else 2); kv("DNSSEC 검증(AD)", if (rep.ad) "검증됨" else "표시 없음", if (rep.ad) -1 else 0); kv("재귀(RA)", if (rep.ra) "예" else "아니요")
                if (rep.answers.isEmpty()) note(when (rep.status) { 3 -> "NXDOMAIN: 그런 도메인이 없어요."; 0 -> "도메인은 있지만 ${i.str("t")} 레코드가 없어요."; 2 -> "SERVFAIL: DNS 서버가 답을 만들지 못했어요 (DNSSEC 검증 실패일 수 있어요)."; else -> "답이 없어요." }, if (rep.status == 0) 1 else 2)
                else { header("이름", "종류", "TTL", "값"); for (a in rep.answers) row(a.name, DnsType.name(a.type), "${a.ttl}", a.data.take(120)) }
                note("DoH 는 질문을 HTTPS 에 숨겨 보내서 중간(통신사·공용 Wi-Fi)이 볼 수 없어요. 내 DNS 와 결과가 다르면 DNS 변조·차단을 의심할 수 있어요('DNS 변조·가로채기 점검').")
            }
        },

        online("dns_dot", M, "DoT 로 DNS 조회 (TLS 853번 포트)", "DNS 질문을 TLS 로 암호화해 서버의 853번 포트로 보내 — 이 서버가 DoT 를 지원하는지, 인증서는 믿을 만한지", text("s", "DoT 서버 (IP 또는 도메인)", "예: 1.1.1.1", "1.1.1.1", listOf("클라우드플레어" to "1.1.1.1", "구글" to "8.8.8.8", "Quad9" to "9.9.9.9", "dns.google" to "dns.google")),
            DnsTools.domainField(), choice("t", "레코드 종류", listOf("A", "AAAA", "MX", "TXT", "NS"), "A"), note = "그 서버의 853번 포트에 TLS 로 접속해 DNS 질문 1개를 보내요. 인터넷을 사용해요.") { i, host, env ->
            val s = HostInput.host(i.str("s")); if (s.isEmpty()) return@online need("서버를 입력하세요")
            val d = domainIn(i) ?: return@online need("도메인을 입력하세요"); val type = DnsType.parse(i.str("t")) ?: DnsType.A
            val port = i.str("port").toIntOrNull() ?: 853      // 입력 칸은 없고, 시험에서만 다른 포트를 씀
            val a = try { TlsInspect.resolve(s) } catch (_: Exception) { return@online fail("서버 주소를 찾지 못했어요") }
            if (IpUtil.classify(a).blocked) return@online fail("이 주소로는 연결할 수 없어요")
            env.progress("TLS 접속 중...")
            val sock: () -> Socket = if (IpUtil.classify(a).local) host.lanSockets() else ({ Socket() })
            val q = DnsWire.buildQuery(java.security.SecureRandom().nextInt(65536), d, type) ?: return@online fail("도메인 이름이 올바르지 않아요")
            val t0 = System.nanoTime()
            val (msg, tls) = try { ProbeConn(s, port, 6000, sock, tls = true).use { c -> c.sendBytes(byteArrayOf((q.size shr 8).toByte(), q.size.toByte()) + q); val len = c.readExactly(2).let { ((it[0].toInt() and 0xff) shl 8) or (it[1].toInt() and 0xff) }; (DnsWire.parse(c.readExactly(len)) ?: throw IOException("응답을 해석하지 못했어요")) to c.tlsReport } } catch (e: IOException) { return@online fail("접속·조회하지 못했어요: ${e.message} (서버가 DoT 를 지원하지 않거나 853 이 막혔어요)") } catch (e: javax.net.ssl.SSLException) { return@online fail("TLS 연결에 실패했어요: ${e.message?.take(100)}") }
            val ms = (System.nanoTime() - t0) / 1_000_000
            result {
                kv("DoT 서버", "$s:$port (${IpUtil.format(a)})"); tls?.let { kv("TLS", it.protocol, if (it.protocol == "TLSv1.3" || it.protocol == "TLSv1.2") -1 else 2); kv("인증서", if (it.trusted) "믿을 수 있어요" else (it.trustError ?: "믿을 수 없어요"), if (it.trusted) -1 else 1); kv("이름 일치", if (it.hostnameOk) "일치" else "서버 주소와 달라요", if (it.hostnameOk) -1 else 1) }
                DnsTools.summary(this, DnsResponse(msg, ms, s, true), d, type)
                note("DoT 는 DNS 질문을 TLS 로 암호화해요. 안드로이드의 \"비공개 DNS\"(설정 → 네트워크 → 비공개 DNS)에 이 서버의 도메인(예: one.one.one.one, dns.google)을 넣어 쓸 수 있어요.")
            }
        },

        online("dns_hijack", M, "DNS 변조·가로채기 점검", "내 DNS 가 유명 사이트에 엉뚱한(가짜) IP 를 돌려주거나 없는 도메인에 IP 를 주는지, 암호화된 DoH 답과 비교해서 확인", note = "유명 사이트 5곳의 주소를 내 DNS 와 클라우드플레어 DoH 에 묻고, 없는 이름 1개를 내 DNS 에 물어요. 인터넷을 사용해요.") { _, host, env ->
            val servers = serverFirst(host); val db = host.geoDb()
            env.progress("내 DNS 와 DoH 에 묻는 중...")
            val res = Par.map(HIJACK_SITES, 5, 20000) { (d, expect) ->
                val mine = runCatching { DnsTools.ask(servers, d, DnsType.A, host, timeoutMs = 3500).msg.answers.filter { it.type == DnsType.A }.map { it.data } }.getOrNull()
                val doh = runCatching { Doh.parse(GeoNet.get(Doh.url("클라우드플레어", d, "A"), 8000, 65536, mapOf("Accept" to "application/dns-json"))).answers.filter { it.type == 1 }.map { it.data } }.getOrNull()
                Triple(d, mine, doh) to expect
            }
            val nx = runCatching { DnsTools.ask(servers, "selfcheck-" + java.util.UUID.randomUUID().toString().take(10) + ".com", DnsType.A, host, timeoutMs = 3500).msg }.getOrNull()
            var suspicious = 0
            result {
                kv("내 DNS", servers.joinToString(", ")); header("사이트", "내 DNS 의 답", "DoH 의 답", "판정")
                for (r in res) {
                    if (r == null) continue
                    val (d, mine, doh) = r.first; val expect = r.second
                    val bad = mine?.filter { ip -> IpUtil.parse(ip)?.let { a -> IpUtil.classify(a) != IpKind.PUBLIC } == true }.orEmpty()
                    val orgs = mine?.mapNotNull { ip -> IpUtil.parse(ip)?.let { db?.lookup(it)?.asn?.name } }.orEmpty()
                    val overlap = mine != null && doh != null && mine.toSet().intersect(doh.toSet()).isNotEmpty()
                    val verdict = when { mine == null -> "조회 실패" to 1; bad.isNotEmpty() -> "내부·예약 주소를 돌려줘요 (${bad.first()}) — 의심" to 2; orgs.isNotEmpty() && orgs.none { expect.containsMatchIn(it) } && !overlap -> "다른 회사(${orgs.first().take(20)}) 주소 — 의심" to 2; overlap -> "DoH 와 일치" to -1; else -> "주소는 달라도 같은 회사(CDN 정상)" to -1 }
                    if (verdict.second == 2) suspicious++
                    row(d, mine?.take(2)?.joinToString(", ") ?: "-", doh?.take(2)?.joinToString(", ") ?: "-", verdict.first, level = verdict.second)
                }
                val nxHijack = nx != null && nx.rcode == 0 && nx.answers.any { it.type == DnsType.A }
                head("없는 도메인"); kv("무작위 이름 조회", if (nx == null) "응답 없음" else if (nxHijack) "가짜 IP 를 돌려줘요: ${nx.answers.first { it.type == DnsType.A }.data}" else "NXDOMAIN (정상)", if (nxHijack) 2 else -1)
                head("판정")
                if (suspicious > 0 || nxHijack) note("의심스러운 응답이 있어요. 공유기·통신사·공용 Wi-Fi 가 DNS 를 바꿔치거나 광고 페이지로 보내는 것일 수 있어요. 비공개 DNS(DoT)를 켜거나 DNS 를 1.1.1.1/8.8.8.8 로 바꿔 보세요.", 2)
                else note("뚜렷한 변조 신호는 없어요. (주소가 서로 달라도 CDN 이 지역마다 다른 서버를 알려 주는 정상 경우가 많아서, 같은 회사면 문제로 보지 않아요.)", -1)
            }
        },

        online("dns_propagation", M, "DNS 전파 확인 (여러 DNS 서버)", "레코드를 바꾼 뒤 전 세계 DNS 서버 9곳이 새 값을 알려 주는지 — 기대하는 값을 넣으면 일치 여부까지", DnsTools.domainField(), choice("t", "레코드 종류", listOf("A", "AAAA", "MX", "TXT", "NS", "CNAME"), "A"), text("e", "기대하는 값 (선택)", "예: 203.0.113.10 또는 일부 글자", ""),
            note = "도메인을 DNS 서버 9곳(구글·클라우드플레어·Quad9·OpenDNS·KT·SKB·LG U+)에 물어요. 인터넷을 사용해요.") { i, host, env ->
            val d = domainIn(i) ?: return@online need("도메인을 입력하세요"); val type = DnsType.parse(i.str("t")) ?: DnsType.A; val exp = i.str("e")
            val sv = listOf((host.dnsServers().firstOrNull() ?: "8.8.8.8") to "내 DNS") + propagationResolvers
            env.progress("${sv.size}곳에 묻는 중...")
            val res = Par.map(sv, 9, 15000) { (s, _) -> runCatching { DnsTools.ask(listOf(s), d, type, host, timeoutMs = 3000).let { r -> r.msg.rcode to r.msg.answers.filter { it.type == type } } }.getOrNull() }
            var ok = 0; var answered = 0
            // 기대값을 안 적었을 땐 서버끼리 값이 같은지로 판단: 가장 많은 서버가 알려 주는 값 묶음을 "다수"로 봄
            val sets = res.map { r -> r?.second?.map { it.data.trim('"').lowercase() }?.toSet() }
            val majority = sets.filterNotNull().filter { it.isNotEmpty() }.groupingBy { it }.eachCount().maxByOrNull { it.value }?.key
            val consistent = sets.filterNotNull().filter { it.isNotEmpty() }.toSet().size <= 1
            result {
                kv("질문", "$d ${i.str("t")}"); if (exp.isNotEmpty()) kv("기대하는 값", exp)
                header("DNS 서버", "답", "TTL", "판정")
                sv.forEachIndexed { k, (s, name) -> val r = res[k]
                    if (r == null) row("$name ($s)", "응답 없음", "", "", level = 1)
                    else { answered++; val vals = r.second.map { it.data.trim('"') }; val match = if (exp.isEmpty()) vals.isNotEmpty() && sets[k] == majority else vals.any { it.contains(exp, true) }; if (match && vals.isNotEmpty()) ok++
                        row("$name ($s)", if (vals.isEmpty()) (if (r.first == 3) "NXDOMAIN" else "레코드 없음") else vals.take(3).joinToString(", ").take(80), r.second.firstOrNull()?.ttl?.toString() ?: "", if (vals.isEmpty()) "없음" else if (exp.isEmpty()) (if (match) "응답" else "다수와 다름") else if (match) "일치" else "다름", level = if (vals.isEmpty()) 1 else if (match) -1 else 2) } }
                head("요약"); kv("답한 서버", "$answered / ${sv.size}")
                if (exp.isEmpty()) kv("다수와 같은 값", "$ok / $answered", if (answered > 0 && consistent && ok == answered) -1 else 1) else kv("기대값과 일치", "$ok / $answered", if (answered > 0 && ok == answered) -1 else 1)
                val done = answered > 0 && ok == answered && (exp.isNotEmpty() || consistent)
                note(if (answered == 0) "어느 서버도 답하지 않았어요." else if (done) "모든 서버가 같은 값을 알려 줘요 (전파가 끝났어요)." else "서버마다 값이 달라요. 방금 바꿨다면 이전 값의 TTL 이 지날 때까지 기다려야 해요(TTL 이 3600 이면 최대 1시간).", if (done) -1 else 1)
            }
        },

        online("dns_soa_sync", M, "네임서버 간 SOA 일련번호 일치 점검", "도메인의 네임서버(NS)들에게 직접 물어 영역 버전(SOA 일련번호)이 모두 같은지 — 다르면 일부 서버가 옛 설정을 줘요", DnsTools.domainField(), DnsTools.serverField(), note = "도메인의 NS 를 찾고, 각 네임서버에 SOA 질문을 직접 보내요. 인터넷을 사용해요.") { i, host, env ->
            val d = domainIn(i) ?: return@online need("도메인을 입력하세요"); val servers = DnsTools.servers(i, host)
            env.progress("네임서버를 찾는 중...")
            val ns = try { DnsTools.ask(servers, d, DnsType.NS, host).msg.answers.filter { it.type == DnsType.NS }.map { it.data.trimEnd('.') }.distinct() } catch (e: IOException) { return@online fail("조회하지 못했어요: ${e.message}") }
            if (ns.isEmpty()) return@online fail("\"$d\" 의 네임서버를 찾지 못했어요 (등록된 도메인의 최상위 이름인지 확인하세요)")
            val res = Par.map(ns.take(8), 8, 20000) { h ->
                val ip = runCatching { DnsTools.ask(servers, h, DnsType.A, host).msg.answers.firstOrNull { it.type == DnsType.A }?.data }.getOrNull()
                if (ip == null) h to ("주소를 못 찾음" to null) else h to ip.let { a -> runCatching { DnsClient.query(nsPorts[h]?.let { p -> "$a#$p" } ?: a, d, DnsType.SOA, timeoutMs = 3000, rd = false, retries = 1).msg.answers.firstOrNull { it.type == DnsType.SOA }?.data?.split(' ')?.getOrNull(2)?.toLongOrNull().let { s -> a to s } }.getOrElse { a to null } }
            }
            val serials = res.mapNotNull { it?.second?.second }.distinct()
            result {
                kv("도메인", d); kv("네임서버", "${ns.size}개"); header("네임서버", "IP", "SOA 일련번호")
                for (r in res) { if (r == null) continue; val (h, p) = r; row(h, p.first, p.second?.toString() ?: "응답 없음", level = if (p.second == null) 1 else if (serials.size > 1) 2 else -1) }
                if (serials.isEmpty()) note("어느 네임서버에서도 SOA 를 받지 못했어요.", 2) else if (serials.size == 1) note("모든 네임서버의 일련번호가 같아요 (${serials[0]}). 영역이 잘 동기화돼 있어요.", -1) else note("네임서버마다 일련번호가 달라요(${serials.joinToString()}). 일부 서버가 옛 설정을 줘서 사용자마다 다른 결과가 나올 수 있어요. 보조 서버의 영역 전송(AXFR/IXFR)을 점검하세요.", 2)
                if (ns.size < 2) note("네임서버가 1개뿐이에요. 장애에 대비해 서로 다른 네트워크의 서버 2개 이상을 두세요.", 1)
            }
        },

        online("dns_wildcard", M, "와일드카드 DNS 점검", "도메인에 \"아무 이름이나 받아 주는\" 와일드카드(*.example.com) 설정이 있는지 — 없는 이름에도 답하면 오타 도메인이 모두 살아 있어요", DnsTools.domainField(), DnsTools.serverField(), note = NOTE_DNS) { i, host, env ->
            val d = domainIn(i) ?: return@online need("도메인을 입력하세요"); val servers = DnsTools.servers(i, host)
            env.progress("무작위 이름 3개를 묻는 중...")
            val labels = List(3) { "selfcheck-" + java.util.UUID.randomUUID().toString().take(10) }
            val res = Par.map(labels, 3, 12000) { l -> runCatching { DnsTools.ask(servers, "$l.$d", DnsType.A, host, timeoutMs = 3500).msg }.getOrNull() }
            result {
                kv("도메인", d); header("무작위 이름", "결과")
                labels.forEachIndexed { k, l -> val m = res[k]; row("$l.$d", if (m == null) "응답 없음" else if (m.rcode == 3) "NXDOMAIN (없음)" else m.answers.firstOrNull { it.type == DnsType.A }?.data ?: m.answers.firstOrNull()?.data ?: "레코드 없음", level = if (m == null) 1 else if (m.rcode == 3) -1 else 1) }
                val wild = res.count { it != null && it.rcode == 0 && it.answers.isNotEmpty() }
                note(if (wild >= 2) "와일드카드가 있어요: 없는 이름에도 주소를 돌려줘요. 의도한 것(서브도메인을 자동으로 받는 서비스)이면 괜찮지만, 아니라면 *.$d 레코드를 지우세요 (피싱·오타 도메인에 악용될 수 있어요)." else if (res.all { it == null }) "응답이 없어요." else "와일드카드가 없어요 (없는 이름은 NXDOMAIN).", if (wild >= 2) 1 else -1)
            }
        },

        online("dns_cname_chain", M, "CNAME 체인·끊긴 대상 점검", "서브도메인이 가리키는 CNAME 을 끝까지 따라가 최종 주소를 보고, 대상이 사라졌는지(서브도메인 탈취 위험) 확인", text("d", "도메인 (서브도메인)", "예: www.example.com", "www.github.com", listOf("www.github.com" to "www.github.com")), DnsTools.serverField(), note = NOTE_DNS) { i, host, env ->
            val d = domainIn(i) ?: return@online need("도메인을 입력하세요"); val servers = DnsTools.servers(i, host)
            val chain = ArrayList<String>(); var cur = d; var loop = false
            try {
                for (n in 0 until 10) {
                    env.progress("$cur ...")
                    val r = DnsTools.ask(servers, cur, DnsType.CNAME, host).msg.answers.firstOrNull { it.type == DnsType.CNAME } ?: break
                    val next = r.data.trimEnd('.').lowercase(); chain += "$cur → $next"
                    if (chain.any { it.startsWith("$next →") } || next == d) { loop = true; break }
                    cur = next
                }
            } catch (e: IOException) { return@online fail("조회하지 못했어요: ${e.message}") }
            val fin = runCatching { DnsTools.ask(servers, cur, DnsType.A, host).msg }.getOrNull()
            val aAns = fin?.answers?.filter { it.type == DnsType.A }.orEmpty(); val dangling = fin != null && fin.rcode == 3
            val db = host.geoDb()
            result {
                kv("도메인", d)
                if (chain.isEmpty()) kv("CNAME", "없음 (이 이름은 별칭이 아니에요)") else { head("CNAME 체인 (${chain.size}단계)"); chain.forEach { kv("→", it) } }
                if (loop) note("CNAME 이 서로를 가리키는 고리(루프)예요. 이 이름은 해석되지 않아요.", 2)
                kv("최종 이름", cur); kv("최종 주소", if (aAns.isEmpty()) (if (dangling) "NXDOMAIN (없음)" else "A 레코드 없음") else aAns.joinToString(", ") { it.data }, if (aAns.isNotEmpty()) -1 else 2)
                aAns.firstOrNull()?.let { a -> IpUtil.parse(a.data)?.let { ip -> db?.lookup(ip)?.takeIf { it.country != null || it.asn != null }?.let { g -> kv("나라 · 통신사", "${CountryNames.ko(g.country)} · ${g.asn?.name ?: "-"}") } } }
                if (dangling && chain.isNotEmpty()) { val svc = TAKEOVER.find(cur)?.groupValues?.get(1)
                    note("CNAME 이 가리키는 대상($cur)이 사라졌어요(NXDOMAIN). ${if (svc != null) "$svc 같은 외부 서비스는 누군가 같은 이름을 새로 등록해 이 서브도메인을 가로챌 수 있어요(서브도메인 탈취)." else "대상 서비스가 해지됐다면 이 서브도메인을 가로챌 수 있는 위험이 있어요."} 쓰지 않는 CNAME 은 지우세요.", 2) }
                else if (TAKEOVER.containsMatchIn(cur)) note("외부 서비스(${TAKEOVER.find(cur)!!.groupValues[1]})를 가리켜요. 그 서비스에서 이 도메인을 계속 쓰고 있는지 확인하세요.", 0)
                if (chain.size > 3) note("CNAME 단계가 많아요. 단계마다 조회 시간이 늘어요.", 1)
            }
        },

        online("mail_spf_eval", M, "SPF 평가 (이 IP 가 메일을 보내도 되나?)", "도메인의 SPF 규칙으로 특정 IP 가 pass·fail 인지 판정하고, 어떤 항목이 일치했는지·DNS 조회 횟수(10회 한도)를 보여 줘요",
            DnsTools.domainField("gmail.com"), text("ip", "보내는 서버의 IP", "예: 209.85.220.41", "209.85.220.41", listOf("구글 메일" to "209.85.220.41", "내 IP" to "")), DnsTools.serverField(), note = NOTE_DNS + " SPF 에 적힌 include·a·mx 를 따라 여러 번 물어요(최대 10회).") { i, host, env ->
            val d = domainIn(i) ?: return@online need("도메인을 입력하세요"); val ip = IpUtil.parse(i.str("ip")) ?: return@online if (i.str("ip").isEmpty()) need("보내는 서버의 IP 를 입력하세요") else fail("IP 주소를 읽지 못했어요")
            env.progress("SPF 를 평가하는 중...")
            val r = SpfEval.check(LiveDns(DnsTools.servers(i, host), host), ip, d)
            val lv = when (r.verdict) { "pass" -> -1; "fail", "permerror" -> 2; "none" -> 1; else -> 1 }
            result {
                kv("도메인", d); kv("보내는 IP", IpUtil.format(ip)); kv("판정", r.verdict.uppercase(), lv); kv("이유", r.reason); kv("DNS 조회", "${r.lookups} / 10", if (r.lookups > 8) 1 else 0)
                note(when (r.verdict) { "pass" -> "이 IP 는 이 도메인 이름으로 메일을 보내도록 허가됐어요."; "fail" -> "허가되지 않은 IP 예요 (-all). 받는 서버는 보통 이 메일을 거부해요 — 사칭이거나 SPF 에 이 서버를 추가해야 해요."; "softfail" -> "허가되지 않았지만 엄격하지 않아요 (~all). 받는 서버는 스팸으로 분류하는 정도예요."; "neutral" -> "이 IP 에 대해 SPF 가 의견이 없어요 (?all 또는 일치 항목 없음)."; "none" -> "이 도메인에는 SPF 레코드가 없어요. 누구든 이 도메인을 사칭해 메일을 보낼 수 있어요."; "permerror" -> "SPF 규칙 자체에 오류가 있어요. 받는 서버는 SPF 를 실패로 취급해요."; else -> "DNS 조회에 실패해서 판정하지 못했어요." }, lv)
                if (r.trace.isNotEmpty()) { head("평가 과정"); block(r.trace.joinToString("\n")) }
            }
        },

        online("mail_spf_flatten", M, "SPF 평탄화 (조회 10회 한도 줄이기)", "include·a·mx 를 모두 풀어 IP 목록(ip4/ip6)만 남긴 SPF 레코드를 만들어 — DNS 조회가 10회를 넘어 SPF 가 깨질 때", DnsTools.domainField("gmail.com"), DnsTools.serverField(),
            note = NOTE_DNS + " include 를 따라 여러 번 물어요.") { i, host, env ->
            val d = domainIn(i) ?: return@online need("도메인을 입력하세요")
            env.progress("SPF 를 풀어 보는 중...")
            val f = try { SpfEval.flatten(LiveDns(DnsTools.servers(i, host), host), d) } catch (e: IOException) { return@online fail("조회하지 못했어요: ${e.message}") }
            if (f.entries.isEmpty()) return@online result { kv("도메인", d); note("풀어낼 IP 가 없어요 (SPF 가 없거나 ip4/ip6 가 없어요).", 1); f.notes.forEach { note(it, 1) } }
            val rec = SpfEval.record(f); val chunks = rec.chunked(255)
            result {
                kv("도메인", d); kv("원래 DNS 조회 수", "${f.originalLookups}회", if (f.originalLookups > 10) 2 else 0); kv("평탄화 후", "0회 (ip4/ip6 만)", -1); kv("IP 항목", "${f.entries.size}개"); kv("글자 수", "${rec.length}자")
                head("평탄화한 SPF 레코드"); block(rec)
                if (chunks.size > 1) { note("255자를 넘어서 DNS TXT 에는 아래처럼 나눠 넣어야 해요 (${chunks.size}덩어리):", 1); block(chunks.joinToString(" ") { "\"$it\"" }) }
                if (rec.length > 450) note("전체가 450자를 넘으면 UDP 응답이 커져 일부 DNS 에서 문제가 생길 수 있어요. 여러 도메인으로 나누는(서브도메인 include) 방법을 고려하세요.", 1)
                f.notes.forEach { note(it, 1) }
                note("평탄화한 레코드는 IP 가 고정돼서, 메일 서비스(구글·마이크로소프트 등)가 IP 를 바꾸면 SPF 가 틀어져요. 주기적으로 다시 만들어 갱신하거나 평탄화를 자동으로 해 주는 서비스를 쓰세요.", 1)
            }
        },

        online("mail_dkim_selectors", M, "DKIM 선택자 찾기", "자주 쓰는 선택자(default·google·selector1 등 35개)로 도메인의 DKIM 공개키를 찾아 키 길이까지 확인 — 어떤 메일 서비스를 쓰는지도 짐작", DnsTools.domainField("example.com"), DnsTools.serverField(),
            note = "도메인의 _domainkey 이름 35개를 DNS 에 물어요(공개 레코드). 인터넷을 사용해요.") { i, host, env ->
            val d = domainIn(i) ?: return@online need("도메인을 입력하세요"); val servers = DnsTools.servers(i, host)
            env.progress("선택자 ${SELECTORS.size}개를 확인하는 중...")
            val res = Par.map(SELECTORS, 10, 25000) { sel -> sel to runCatching { DnsTools.ask(servers, "$sel._domainkey.$d", DnsType.TXT, host, timeoutMs = 3000).msg.answers }.getOrNull() }
            val hits = res.filterNotNull().mapNotNull { (sel, ans) -> ans?.let { a -> val t = a.firstOrNull { it.type == DnsType.TXT }; val c = a.firstOrNull { it.type == DnsType.CNAME }; if (t != null) Triple(sel, t.text ?: "", c?.data) else if (c != null) Triple(sel, "", c.data) else null } }
            result {
                kv("도메인", d); kv("찾은 선택자", "${hits.size}개 (확인 ${SELECTORS.size}개)", if (hits.isEmpty()) 1 else -1)
                if (hits.isEmpty()) note("자주 쓰는 선택자로는 찾지 못했어요. 메일 서비스마다 선택자 이름이 달라요: 메일의 DKIM-Signature 헤더의 s= 값이 선택자예요('이메일 헤더에서 IP·경로 찾기'에 헤더를 붙여 넣어 보세요).", 1)
                else { header("선택자", "키", "참고"); for ((sel, txt, cname) in hits) { val info = if (txt.isNotEmpty()) DkimParser.parse(txt) else null; row(sel, info?.keyDesc ?: (if (cname != null) "CNAME" else "-"), (cname?.let { "→ ${it.trimEnd('.')}" } ?: "") + (info?.issues?.firstOrNull()?.first?.let { " ${it.take(50)}" } ?: ""), level = info?.issues?.maxOfOrNull { it.second } ?: -1) } }
                val svc = hits.mapNotNull { (_, _, c) -> c }.joinToString(" ").lowercase(); val guess = listOfNotNull(if ("onmicrosoft" in svc || hits.any { it.first.startsWith("selector") }) "마이크로소프트 365" else null, if (hits.any { it.first == "google" }) "구글 워크스페이스" else null, if ("amazonses" in svc) "아마존 SES" else null, if (hits.any { it.first.startsWith("protonmail") }) "프로톤 메일" else null, if (hits.any { it.first in listOf("k1", "k2", "k3") }) "메일침프(Mailchimp)·Sendgrid 류" else null, if (hits.any { it.first == "zoho" }) "조호 메일" else null)
                if (guess.isNotEmpty()) note("선택자 이름으로 짐작한 메일 서비스: ${guess.joinToString(", ")} (확정이 아니에요)", 0)
                if (hits.any { (_, t, _) -> t.isNotEmpty() && (Regex("RSA (\\d+)").find(DkimParser.parse(t).keyDesc ?: "")?.groupValues?.get(1)?.toInt() ?: 2048) < 2048 }) note("2048비트 미만 키가 있어요. 2048비트 이상으로 교체하세요.", 1)
            }
        },

        online("mail_mta_sts", M, "MTA-STS·TLS-RPT·BIMI 점검", "메일 서버끼리 암호화를 강제하는 MTA-STS, 오류 보고(TLS-RPT), 로고 표시(BIMI) 설정을 한꺼번에 점검", DnsTools.domainField("gmail.com"), DnsTools.serverField(), note = NOTE_DNS + " MTA-STS 정책 파일은 https://mta-sts.도메인/.well-known/mta-sts.txt 에서 받아요.") { i, host, env ->
            val d = domainIn(i) ?: return@online need("도메인을 입력하세요"); val servers = DnsTools.servers(i, host)
            fun txt(n: String) = runCatching { DnsTools.ask(servers, n, DnsType.TXT, host).msg.answers.filter { it.type == DnsType.TXT }.map { it.text ?: "" } }.getOrDefault(emptyList())
            env.progress("DNS 확인...")
            val sts = txt("_mta-sts.$d").firstOrNull { it.startsWith("v=STSv1", true) }; val rpt = txt("_smtp._tls.$d").firstOrNull { it.startsWith("v=TLSRPTv1", true) }; val bimi = txt("default._bimi.$d").firstOrNull { it.startsWith("v=BIMI1", true) }
            val policy = if (sts != null) { env.progress("정책 파일..."); runCatching { GeoNet.get("https://mta-sts.$d/.well-known/mta-sts.txt", 8000, 32768) }.getOrNull() } else null
            val pf = policy?.lineSequence()?.mapNotNull { l -> l.indexOf(':').takeIf { it > 0 }?.let { l.substring(0, it).trim().lowercase() to l.substring(it + 1).trim() } }?.toList().orEmpty()
            val mode = pf.firstOrNull { it.first == "mode" }?.second; val maxAge = pf.firstOrNull { it.first == "max_age" }?.second?.toLongOrNull()
            result {
                kv("도메인", d)
                head("MTA-STS (받는 메일 서버에 TLS 강제)"); kv("DNS 레코드", sts ?: "없음", if (sts != null) -1 else 1)
                if (sts != null) { if (policy == null) note("정책 파일(https://mta-sts.$d/.well-known/mta-sts.txt)을 받지 못했어요. DNS 에 레코드가 있어도 정책 파일이 없으면 동작하지 않아요.", 2) else { kv("모드", mode ?: "-", when (mode) { "enforce" -> -1; "testing" -> 1; else -> 1 }); pf.filter { it.first == "mx" }.forEach { kv("허용 MX", it.second) }; maxAge?.let { kv("유효 기간", "${CacheCtl.human(it)} (${it}초)", if (it < 86400) 1 else -1) }
                    note(when (mode) { "enforce" -> "enforce 모드: TLS 로 전달할 수 없으면 메일을 보내지 않아요 (가장 안전해요)."; "testing" -> "testing 모드: 보고만 하고 강제하지 않아요. 문제가 없으면 enforce 로 올리세요."; else -> "모드가 none 이거나 읽지 못했어요." }, if (mode == "enforce") -1 else 1) } }
                else note("MTA-STS 가 없으면 중간 공격자가 메일 서버 사이의 암호화를 끌어내릴 수 있어요(STARTTLS 다운그레이드).", 1)
                head("TLS-RPT (암호화 오류 보고)"); kv("DNS 레코드", rpt ?: "없음", if (rpt != null) -1 else 0); if (rpt != null) Regex("""rua=([^;]+)""").find(rpt)?.let { kv("보고 받을 곳", it.groupValues[1].trim()) }
                head("BIMI (메일 로고 표시)"); kv("DNS 레코드", bimi ?: "없음", 0); if (bimi != null) { Regex("""l=([^;]+)""").find(bimi)?.let { kv("로고 주소", it.groupValues[1].trim()) }; note("BIMI 는 DMARC 가 엄격(p=quarantine 이상)할 때만 동작해요.") }
            }
        },

        online("mail_address_check", M, "이메일 주소 확인 (형식 + 메일 서버)", "주소의 형식이 맞는지, 그 도메인이 메일을 받는 서버(MX)가 있는지, 일회용 메일·역할 주소인지 — 실제로 메일을 보내지 않아요", text("a", "이메일 주소", "예: name@example.com", "name@gmail.com", listOf("예시" to "name@gmail.com")), DnsTools.serverField(),
            note = "주소의 도메인 부분만 DNS 에 물어요(MX·A). 메일 서버에 접속하거나 그 주소로 메일을 보내지 않아요.") { i, host, env ->
            val a = i.str("a"); if (a.isEmpty()) return@online need("이메일 주소를 입력하세요")
            val prob = EmailCheck.problems(a); val d = EmailCheck.domainOf(a)
            val servers = DnsTools.servers(i, host)
            val mx = if (prob.none { it.second == 2 }) { env.progress("메일 서버를 찾는 중..."); runCatching { DnsTools.ask(servers, d, DnsType.MX, host).msg.answers.filter { it.type == DnsType.MX }.map { it.data.substringBefore(' ').toInt() to it.data.substringAfter(' ').trimEnd('.') }.sortedBy { it.first } }.getOrNull() } else null
            val hasA = if (mx != null && mx.isEmpty()) runCatching { DnsTools.ask(servers, d, DnsType.A, host).msg.answers.any { it.type == DnsType.A } }.getOrDefault(false) else false
            val nullMx = mx?.size == 1 && mx[0].second.isEmpty()
            result {
                kv("주소", a); kv("도메인", d); kv("형식", if (prob.isEmpty()) "올바른 형식이에요" else prob.first().first, if (prob.isEmpty()) -1 else 2)
                if (mx != null) { kv("메일 서버(MX)", if (nullMx) "받지 않는 도메인(Null MX)" else if (mx.isNotEmpty()) mx.take(3).joinToString(", ") { it.second } else if (hasA) "MX 없음 (A 레코드로 받아요)" else "없음 — 이 도메인은 메일을 받을 수 없어요", if (mx.isNotEmpty() && !nullMx || hasA) -1 else 2) }
                kv("일회용 메일", if (EmailCheck.isDisposable(d)) "예 (임시 주소 서비스)" else "아니요(알려진 목록 기준)", if (EmailCheck.isDisposable(d)) 1 else -1); kv("역할 주소", if (EmailCheck.isRole(a)) "예 (info·admin 처럼 사람이 아닌 공용 주소)" else "아니요")
                note(when { prob.isNotEmpty() -> "형식이 틀려서 메일을 받을 수 없어요."; mx != null && (nullMx || (mx.isEmpty() && !hasA)) -> "이 도메인은 메일을 받지 않아요."; mx == null -> "DNS 조회에 실패해서 메일 서버를 확인하지 못했어요."; else -> "주소 형식과 도메인의 메일 서버는 정상이에요. 단, 사서함(@ 앞부분)이 실제로 있는지는 확인할 수 없어요 (메일을 보내 보는 방법밖에 없어요)." }, if (prob.isEmpty() && mx != null && (mx.isNotEmpty() || hasA) && !nullMx) -1 else 2)
            }
        },

        online("mail_fcrdns", M, "역방향·정방향 DNS 일치 확인 (FCrDNS)", "메일 서버 IP 의 역방향 이름(PTR)이 있고, 그 이름이 다시 같은 IP 로 돌아오는지 — 메일 수신 서버가 스팸 판단에 쓰는 기본 점검", text("ip", "메일 서버 IP", "예: 209.85.220.41", "209.85.220.41", listOf("구글 메일" to "209.85.220.41")), DnsTools.serverField(), note = NOTE_DNS + " (역방향 PTR 과 정방향 A 조회)") { i, host, env ->
            val ip = IpUtil.parse(i.str("ip")) ?: return@online if (i.str("ip").isEmpty()) need("IP 주소를 입력하세요") else fail("IP 주소를 읽지 못했어요"); val servers = DnsTools.servers(i, host)
            env.progress("PTR 조회...")
            val ptrs = try { DnsTools.ask(servers, Ptr.name(ip), DnsType.PTR, host).msg.answers.filter { it.type == DnsType.PTR }.map { it.data.trimEnd('.') } } catch (e: IOException) { return@online fail("조회하지 못했어요: ${e.message}") }
            val fwd = ptrs.take(3).map { h -> h to runCatching { (DnsTools.ask(servers, h, DnsType.A, host).msg.answers + DnsTools.ask(servers, h, DnsType.AAAA, host).msg.answers).filter { it.type == DnsType.A || it.type == DnsType.AAAA }.mapNotNull { IpUtil.parse(it.data) } }.getOrDefault(emptyList()) }
            val ok = fwd.any { (_, l) -> l.any { it.hostAddress == ip.hostAddress } }
            val generic = ptrs.any { Regex("""(\d{1,3}[.-]\d{1,3}[.-]\d{1,3}[.-]\d{1,3}|dynamic|dhcp|pool|cable|dsl|adsl|ppp|customer|broadband)""", RegexOption.IGNORE_CASE).containsMatchIn(it) }
            result {
                kv("IP", IpUtil.format(ip)); kv("역방향 이름(PTR)", if (ptrs.isEmpty()) "없음" else ptrs.joinToString(", "), if (ptrs.isEmpty()) 2 else -1)
                if (ptrs.isNotEmpty()) { header("PTR 이름", "다시 조회한 주소", "일치"); for ((h, l) in fwd) row(h, l.take(3).joinToString(", ") { IpUtil.format(it) }.ifEmpty { "없음" }, if (l.any { it.hostAddress == ip.hostAddress }) "예" else "아니요", level = if (l.any { it.hostAddress == ip.hostAddress }) -1 else 2) }
                kv("FCrDNS 일치", if (ok) "예" else "아니요", if (ok) -1 else 2); if (generic) kv("가정·유동 IP 형태의 이름", "예", 1)
                note(when { ptrs.isEmpty() -> "역방향 이름이 없어요. 많은 메일 서버가 PTR 이 없는 IP 의 메일을 거부해요. IP 를 빌려 준 통신사·호스팅에 PTR 등록을 요청하세요."; !ok -> "PTR 이름을 다시 조회해도 이 IP 가 나오지 않아요. 메일 서버의 호스트 이름(HELO)과 A 레코드, PTR 을 서로 맞춰야 해요."; generic -> "일치하지만 이름이 가정용·유동 IP 형태예요. 메일 서버라면 mail.내도메인 같은 이름으로 바꾸세요."; else -> "PTR 과 A 가 서로 일치해요 (좋아요)." }, if (ok && !generic) -1 else 1)
            }
        },

        online("domain_rdap", M, "도메인 등록·만료일 확인 (RDAP)", "도메인의 등록일·만료일·상태·등록 기관·네임서버를 공식 등록 정보(RDAP)에서 — 만료 전에 갱신했는지 점검", DnsTools.domainField("example.com"), note = "도메인 이름을 rdap.org 로 보내 담당 등록 기관(레지스트리)의 RDAP 서버에서 조회해요. 일부 국가 도메인(.kr 등)은 RDAP 를 지원하지 않을 수 있어요.") { i, _, env ->
            val d = domainIn(i) ?: return@online need("도메인을 입력하세요"); if (!HostInput.isPlausibleDomain(d)) return@online fail("도메인 형식이 아니에요")
            env.progress("등록 정보를 받는 중...")
            val r = try { DomainRdap.parse(GeoNet.get("https://rdap.org/domain/${java.net.IDN.toASCII(d)}", 10000, 600_000, mapOf("Accept" to "application/rdap+json, application/json"))) } catch (e: IOException) { return@online fail("조회하지 못했어요: ${e.message} (이 도메인의 최상위(TLD)가 RDAP 를 지원하지 않을 수 있어요. '도메인 등록 정보(WHOIS)' 도구를 써 보세요)") } catch (e: org.json.JSONException) { return@online fail("응답을 읽지 못했어요") }
            val exp = r.expires?.let { runCatching { ZonedDateTime.parse(it).toInstant() }.getOrNull() ?: runCatching { Instant.parse(it) }.getOrNull() }
            val days = exp?.let { java.time.Duration.between(Instant.now(), it).toDays() }
            result {
                kv("도메인", r.name ?: d); r.registrar?.let { kv("등록 기관", it) }; r.created?.let { kv("등록일", it.take(10)) }; r.changed?.let { kv("마지막 변경", it.take(10)) }
                kv("만료일", r.expires?.take(10) ?: "알 수 없음", if (days == null) 0 else if (days < 0) 2 else if (days < 30) 2 else if (days < 90) 1 else -1)
                days?.let { kv("남은 기간", if (it < 0) "${-it}일 전에 만료됨" else "${it}일 남음", if (it < 30) 2 else if (it < 90) 1 else -1) }
                if (r.status.isNotEmpty()) kv("상태", r.status.joinToString(", ")); if (r.nameservers.isNotEmpty()) kv("네임서버", r.nameservers.joinToString(", ")); r.dnssec?.let { kv("DNSSEC", if (it) "서명됨" else "서명 안 됨") }
                if (days != null && days < 30) note(if (days < 0) "도메인이 만료됐어요! 즉시 갱신하지 않으면 다른 사람이 가져갈 수 있어요." else "만료가 한 달도 안 남았어요. 자동 갱신을 켜거나 지금 갱신하세요.", 2)
                if (r.status.any { it.contains("clientTransferProhibited") || it.contains("transfer prohibited", true) }) note("이전 잠금이 걸려 있어요 (도메인 탈취를 막는 좋은 설정이에요).", -1)
                note("개인 연락처(등록자 이름·메일·전화)는 표시하지 않아요.")
            }
        },

        calc("dns_zone_lint", M, "DNS 존 파일 점검 (문법·실수 찾기)", "BIND 영역(zone) 파일 내용을 붙여 넣으면 SOA·NS·CNAME 충돌·점 빠짐·TXT 길이·중복 같은 흔한 실수를 찾아줘요 (폰 안에서만 읽어요)",
            multi("z", "영역 파일 내용", "BIND 형식 (\$ORIGIN, \$TTL, SOA, NS, A, MX …)", "\$ORIGIN example.com.\n\$TTL 3600\n@ IN SOA ns1.example.com. admin.example.com. ( 2024010101 7200 3600 1209600 3600 )\n@ IN NS ns1.example.com.\n@ IN MX 10 mail.example.com.\nwww IN CNAME example.com.\nwww IN A 203.0.113.10\nmail IN A 192.168.1.5\nftp IN CNAME files.example.com\n@ IN TXT \"v=spf1 mx -all\"")) { i ->
            val z = i.raw("z"); if (z.isBlank()) return@calc need("영역 파일 내용을 붙여 넣으세요")
            val issues = ZoneLint.lint(z)
            result {
                kv("줄 수", "${z.lines().size}줄"); kv("발견한 항목", "${issues.size}개 (오류 ${issues.count { it.third == 2 }} · 주의 ${issues.count { it.third == 1 }} · 참고 ${issues.count { it.third == 0 }})", if (issues.any { it.third == 2 }) 2 else if (issues.any { it.third == 1 }) 1 else -1)
                if (issues.isEmpty()) note("눈에 띄는 문제가 없어요.", -1)
                else { header("줄", "내용"); for ((ln, msg, lv) in issues) row(if (ln == 0) "전체" else "$ln", msg, level = if (lv == 2) 2 else if (lv == 1) 1 else 0) }
                note("자주 하는 실수를 찾는 간단한 점검이에요. 실제 적용 전에는 named-checkzone(BIND) 같은 공식 도구로도 확인하세요.")
            }
        },

        online("dns_lookalike", M, "비슷한 도메인 찾기 (피싱·사칭 대비)", "내 도메인과 철자가 비슷한 주소(글자 빠짐·숫자 바꿈·다른 끝·키릴 글자 위장 등) 최대 60개 중 실제로 등록돼 쓰이는 것을 찾기", DnsTools.domainField("example.com", "내 도메인"), DnsTools.serverField(),
            note = "비슷한 이름 최대 60개를 DNS 에 물어요(공개 조회). 등록된 도메인이 있어도 반드시 악의적인 것은 아니에요 — 직접 확인하세요.") { i, host, env ->
            val typed = domainIn(i) ?: return@online need("도메인을 입력하세요"); val servers = DnsTools.servers(i, host)
            val d = EmailHeader.baseDomain(typed)        // www.example.com 처럼 앞에 붙은 이름은 떼고 등록한 이름(example.com)만 씀
            val cands = Lookalike.generate(d, 60); if (cands.isEmpty()) return@online fail("도메인 형식을 읽지 못했어요 (예: example.com)")
            env.progress("${cands.size}개를 확인하는 중...")
            val res = Par.map(cands, 10, 40000) { c -> runCatching { DnsTools.ask(servers, c.domain, DnsType.A, host, timeoutMs = 2500).msg.answers.filter { it.type == DnsType.A }.map { it.data } }.getOrNull() }
            val db = host.geoDb()
            val live = cands.indices.filter { !res[it].isNullOrEmpty() }
            result {
                kv("내 도메인", d); kv("확인한 후보", "${cands.size}개"); kv("실제로 쓰이는(IP 가 있는) 도메인", "${live.size}개", if (live.isEmpty()) -1 else 1)
                if (live.isNotEmpty()) { header("도메인", "방식", "IP", "나라 · 통신사"); for (k in live) { val c = cands[k]; val ip = res[k]!!.first(); val g = IpUtil.parse(ip)?.let { db?.lookup(it) }; row(c.shown.let { if (it != c.domain) "$it (${c.domain})" else it }, c.technique, ip, if (g == null || (g.country == null && g.asn == null)) "-" else "${CountryNames.ko(g.country)} · ${g.asn?.name?.take(24) ?: "-"}", level = if (c.technique.contains("키릴")) 2 else 1) } }
                else note("비슷한 이름 중 IP 가 연결된 도메인이 없어요.", -1)
                note("등록돼 있다고 모두 피싱은 아니에요(주차된 도메인·무관한 회사). 내 브랜드를 흉내 내는 사이트가 보이면 열어서 로그인 정보를 입력하지 말고, 도메인 등록 기관·호스팅에 신고하거나 법적 대응을 검토하세요. 미리 주요 비슷한 도메인을 직접 등록해 두는 방법도 있어요.", 1)
            }
        },
    )
}
