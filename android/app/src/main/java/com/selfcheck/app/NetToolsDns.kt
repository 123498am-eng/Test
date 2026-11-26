package com.selfcheck.app

import java.io.IOException
import java.net.InetAddress

/** DNS·도메인 조회 도구 (인터넷 사용): DNS 서버에 직접 질문을 보내 레코드를 읽고, 메일 보안 레코드를 점검해요 */
object DnsTools {
    private const val D = NetGroups.DNS
    private const val NOTE = "입력한 도메인 이름이 DNS 서버(기본: 지금 연결의 DNS)로 전송돼요. 질문은 운영체제를 거치지 않고 이 앱이 직접 보내요."

    private val SERVER_CHIPS = listOf("내 DNS" to "", "구글" to "8.8.8.8", "클라우드플레어" to "1.1.1.1", "Quad9" to "9.9.9.9", "KT" to "168.126.63.1", "SKB" to "210.220.163.82", "LG U+" to "164.124.101.2")
    private val PUBLIC_SERVERS = listOf("8.8.8.8" to "구글", "1.1.1.1" to "클라우드플레어", "9.9.9.9" to "Quad9", "168.126.63.1" to "KT", "210.220.163.82" to "SK브로드밴드", "164.124.101.2" to "LG U+", "208.67.222.222" to "OpenDNS")

    internal fun serverField() = text("server", "DNS 서버 (비우면 내 DNS)", "예: 8.8.8.8", "", SERVER_CHIPS)
    internal fun domainField(def: String = "example.com", label: String = "도메인", hint: String = "예: example.com") =
        text("d", label, hint, def, listOf("example.com" to "example.com", "google.com" to "google.com", "naver.com" to "naver.com", "github.com" to "github.com"))

    /** 쓸 DNS 서버 목록: 직접 입력한 것 > 지금 연결의 DNS > 8.8.8.8 */
    internal fun servers(i: ToolInput, host: ToolHost): List<String> =
        i.str("server").takeIf { it.isNotEmpty() }?.let { listOf(it) } ?: host.dnsServers().ifEmpty { listOf("8.8.8.8") }

    private fun isLocal(server: String) = IpUtil.parse(server.substringBefore('#'))?.let { IpUtil.classify(it).local } == true

    /** 서버를 차례로 시도해 처음 성공한 응답. 내 망 안 DNS 는 Wi-Fi 망에 묶어서 물음 */
    internal fun ask(srvs: List<String>, name: String, type: Int, host: ToolHost, dnssec: Boolean = false, timeoutMs: Int = 3000): DnsResponse {
        var last: IOException? = null
        for (s in srvs) try {
            val local = isLocal(s)
            return DnsClient.query(s, name, type, timeoutMs = timeoutMs, dnssec = dnssec, bind = { if (local) host.bindDatagram(it) }, newSocket = if (local) host.lanSockets() else ({ java.net.Socket() }))
        } catch (e: IOException) { last = e }
        throw last ?: IOException("응답이 없어요")
    }

    private fun flags(m: DnsMessage) = listOfNotNull(if (m.aa) "AA" else null, if (m.ra) "RA" else null, if (m.ad) "AD(DNSSEC 검증됨)" else null, if (m.tc) "TC" else null).joinToString(" ").ifEmpty { "-" }

    internal fun summary(rb: Rb, r: DnsResponse, qname: String, qtype: Int) {
        val m = r.msg
        rb.kv("질문", "$qname  ${DnsType.name(qtype)}")
        rb.kv("응답한 서버", r.server + if (r.viaTcp) " (TCP)" else ""); rb.kv("걸린 시간", "${r.ms}ms")
        rb.kv("응답 코드", DnsType.rcode(m.rcode), if (m.rcode == 0) -1 else 2); rb.kv("플래그", flags(m))
        if (m.answers.isEmpty()) {
            rb.note(when (m.rcode) {
                3 -> "NXDOMAIN: 그런 도메인이 없어요 (오타이거나 아직 등록·전파되지 않았을 수 있어요)."
                0 -> "도메인은 있지만 ${DnsType.name(qtype)} 레코드는 없어요 (NODATA)."
                2 -> "SERVFAIL: DNS 서버가 답을 만들지 못했어요 (도메인의 네임서버 문제나 DNSSEC 검증 실패일 수 있어요)."
                5 -> "REFUSED: 이 DNS 서버가 질문을 거부했어요 (허용된 사용자만 쓰는 서버일 수 있어요)."
                else -> "답이 없어요."
            }, if (m.rcode == 0) 1 else 2)
            m.authority.firstOrNull { it.type == DnsType.SOA }?.let { rb.kv("상위 SOA", it.data) }
        } else { rb.header("이름", "종류", "TTL", "값"); for (a in m.answers) rb.row(a.name, a.typeName, "${a.ttl}", a.data) }
    }

    private fun typeTool(id: String, title: String, desc: String, type: Int, hint: String = "예: example.com", def: String = "example.com") =
        online(id, D, title, desc, domainField(def, hint = hint), serverField(), note = NOTE) { i, host, _ ->
            val d = HostInput.host(i.str("d")); if (d.isEmpty()) return@online need("도메인을 입력하세요")
            val r = try { ask(servers(i, host), d, type, host) } catch (e: IOException) { return@online fail("조회하지 못했어요: ${e.message}") }
            result { summary(this, r, d, type) }
        }

    /** TXT 레코드들의 글자 */
    private fun txtOf(r: DnsResponse) = r.msg.answers.filter { it.type == DnsType.TXT }.mapNotNull { it.text }

    private fun qualifierText(q: Char) = when (q) { '+' -> "허용"; '-' -> "거부"; '~' -> "의심"; else -> "중립" }

    internal fun renderSpf(rb: Rb, spfs: List<String>) {
        if (spfs.size > 1) rb.note("SPF 레코드가 ${spfs.size}개예요. 하나만 있어야 하고, 여러 개면 SPF 가 무효예요.", 2)
        val info = SpfParser.parse(spfs[0])
        rb.block(spfs[0]); rb.kv("DNS 조회 횟수", "${info.lookups} / 10", if (info.lookups > 10) 2 else if (info.lookups > 8) 1 else -1)
        if (info.terms.isNotEmpty()) { rb.head("허용 목록"); rb.header("처리", "종류", "값"); for (t in info.terms) rb.row(qualifierText(t.qualifier), t.mech, t.value ?: "") }
        info.redirect?.let { rb.kv("redirect", it) }
        rb.head("점검"); for ((m, l) in info.issues) rb.note(m, l)
    }

    internal fun renderDmarc(rb: Rb, txt: String) {
        val info = DmarcParser.parse(txt)
        rb.block(txt); rb.head("항목"); for ((k, v) in info.tags) rb.kv(k, v)
        rb.head("점검"); for ((m, l) in info.issues) rb.note(m, l)
    }

    private val TYPE_CHOICES = listOf("A", "AAAA", "MX", "TXT", "NS", "CNAME", "SOA", "SRV", "CAA", "DS", "DNSKEY", "HTTPS", "ANY")

    val ALL: List<NetTool> = listOf(
        online("dns_query", D, "DNS 직접 조회 (모든 종류)", "도메인·레코드 종류·DNS 서버를 골라 직접 질문 (A·AAAA·MX·TXT·NS·SOA·CAA·DS·DNSKEY …)",
            domainField(), choice("t", "레코드 종류", TYPE_CHOICES), serverField(), note = NOTE) { i, host, _ ->
            val d = HostInput.host(i.str("d")); if (d.isEmpty()) return@online need("도메인을 입력하세요")
            val type = DnsType.parse(i.str("t")) ?: DnsType.A
            val r = try { ask(servers(i, host), d, type, host, dnssec = type == DnsType.DS || type == DnsType.DNSKEY) } catch (e: IOException) { return@online fail("조회하지 못했어요: ${e.message}") }
            result { summary(this, r, d, type) }
        },
        typeTool("dns_a", "A 레코드 조회 (IPv4)", "도메인의 IPv4 주소와 TTL", DnsType.A),
        typeTool("dns_aaaa", "AAAA 레코드 조회 (IPv6)", "도메인의 IPv6 주소", DnsType.AAAA),
        typeTool("dns_mx", "MX 레코드 조회 (메일 서버)", "메일을 받는 서버와 우선순위", DnsType.MX),
        typeTool("dns_txt", "TXT 레코드 조회", "SPF·DKIM·도메인 소유 확인 등 글자 레코드", DnsType.TXT),
        typeTool("dns_ns", "NS 레코드 조회 (네임서버)", "도메인을 관리하는 DNS 서버", DnsType.NS),
        typeTool("dns_cname", "CNAME 조회 (별칭)", "다른 이름으로 연결된 별칭", DnsType.CNAME, "예: www.example.com", "www.example.com"),
        typeTool("dns_soa", "SOA 조회 (영역 정보)", "주 네임서버·관리자·일련번호·갱신 주기", DnsType.SOA),
        typeTool("dns_srv", "SRV 조회 (서비스 위치)", "서비스의 서버·포트 (예: _sip._tcp.example.com)", DnsType.SRV, "예: _sip._tcp.example.com", "_sip._tcp.example.com"),
        typeTool("dns_caa", "CAA 조회 (인증서 발급 허용 기관)", "이 도메인의 인증서를 발급해도 되는 CA", DnsType.CAA),

        online("dns_ptr", D, "PTR 조회 (IP → 이름)", "IP 주소에 등록된 도메인 이름 (역방향 조회)", text("ip", "IP 주소", "예: 8.8.8.8", "8.8.8.8", listOf("8.8.8.8" to "8.8.8.8", "1.1.1.1" to "1.1.1.1")), serverField(), note = NOTE) { i, host, _ ->
            val a = IpUtil.parse(i.str("ip")) ?: return@online if (i.str("ip").isEmpty()) need("IP 주소를 입력하세요") else fail("IP 주소를 읽지 못했어요")
            val name = Ptr.name(a)
            val r = try { ask(servers(i, host), name, DnsType.PTR, host) } catch (e: IOException) { return@online fail("조회하지 못했어요: ${e.message}") }
            result { kv("조회한 이름", name); summary(this, r, name, DnsType.PTR) }
        },

        online("dns_all", D, "DNS 레코드 한꺼번에", "A·AAAA·MX·NS·TXT·SOA·CAA 를 차례로 조회해 도메인 설정을 한눈에", domainField(), serverField(), note = NOTE) { i, host, env ->
            val d = HostInput.host(i.str("d")); if (d.isEmpty()) return@online need("도메인을 입력하세요")
            val srv = servers(i, host)
            result {
                kv("도메인", d)
                for (t in listOf(DnsType.A, DnsType.AAAA, DnsType.MX, DnsType.NS, DnsType.TXT, DnsType.SOA, DnsType.CAA)) {
                    if (env.cancel.get()) break
                    env.progress("${DnsType.name(t)} 조회 중...")
                    head(DnsType.name(t))
                    val r = try { ask(srv, d, t, host) } catch (e: IOException) { note("조회 실패: ${e.message}", 2); continue }
                    if (r.msg.answers.isEmpty()) note(if (r.msg.rcode == 3) "도메인이 없어요 (NXDOMAIN)" else "없어요", if (r.msg.rcode == 3) 2 else 0)
                    else for (a in r.msg.answers) row(a.typeName, "${a.ttl}", a.data)
                }
            }
        },

        online("dns_spf", D, "SPF 점검", "도메인의 SPF(메일 발신 허용 목록)를 읽고 위험한 설정·DNS 조회 한도를 점검", domainField(), serverField(), note = NOTE) { i, host, _ ->
            val d = HostInput.host(i.str("d")); if (d.isEmpty()) return@online need("도메인을 입력하세요")
            val r = try { ask(servers(i, host), d, DnsType.TXT, host) } catch (e: IOException) { return@online fail("조회하지 못했어요: ${e.message}") }
            val spfs = SpfParser.find(txtOf(r))
            result {
                kv("도메인", d); kv("응답 코드", DnsType.rcode(r.msg.rcode), if (r.msg.rcode == 0) -1 else 2)
                if (spfs.isEmpty()) note("SPF 레코드(v=spf1 로 시작하는 TXT)를 찾지 못했어요. 누구나 이 도메인 이름으로 메일을 보낼 수 있다는 뜻이라 스팸·사칭에 쓰일 수 있어요. '설정 만들기'의 SPF 만들기로 만들어 보세요.", 2)
                else renderSpf(this, spfs)
            }
        },

        online("dns_dmarc", D, "DMARC 점검", "_dmarc 레코드의 정책·보고서 주소를 읽고 약한 설정을 점검", domainField(), serverField(), note = NOTE) { i, host, _ ->
            val d = HostInput.host(i.str("d")); if (d.isEmpty()) return@online need("도메인을 입력하세요")
            val r = try { ask(servers(i, host), "_dmarc.$d", DnsType.TXT, host) } catch (e: IOException) { return@online fail("조회하지 못했어요: ${e.message}") }
            val found = DmarcParser.find(txtOf(r))
            result {
                kv("조회한 이름", "_dmarc.$d")
                if (found.isEmpty()) note("DMARC 레코드가 없어요. SPF·DKIM 이 있어도 실패한 메일을 어떻게 처리할지 정해 두지 않았다는 뜻이에요. '설정 만들기'의 DMARC 만들기를 써 보세요.", 2)
                else { if (found.size > 1) note("DMARC 레코드가 ${found.size}개예요. 하나만 있어야 해요.", 2); renderDmarc(this, found[0]) }
            }
        },

        online("dns_dkim", D, "DKIM 점검", "선택자(selector)로 DKIM 공개키를 읽고 키 길이를 점검", text("sel", "선택자 (selector)", "예: google, selector1, default", "google", listOf("google" to "google", "selector1" to "selector1", "default" to "default", "k1" to "k1")),
            domainField(), serverField(), note = NOTE) { i, host, _ ->
            val d = HostInput.host(i.str("d")); val sel = i.str("sel"); if (d.isEmpty() || sel.isEmpty()) return@online need("선택자와 도메인을 입력하세요")
            val name = "$sel._domainkey.$d"
            val r = try { ask(servers(i, host), name, DnsType.TXT, host) } catch (e: IOException) { return@online fail("조회하지 못했어요: ${e.message}") }
            val found = DkimParser.find(txtOf(r))
            result {
                kv("조회한 이름", name)
                if (found.isEmpty()) note("이 선택자의 DKIM 레코드가 없어요. 선택자는 메일 서비스마다 달라요 (메일 원문 헤더의 DKIM-Signature 안 s= 값을 보세요).", 1)
                else { val info = DkimParser.parse(found[0]); block(found[0].take(400)); info.keyDesc?.let { kv("키", it) }; for ((k, v) in info.tags.filterKeys { it != "p" }) kv(k, v); head("점검"); for ((m, l) in info.issues) note(m, l) }
            }
        },

        online("dns_mail", D, "이메일 보안 종합 점검", "MX·SPF·DMARC 가 모두 설정돼 있는지 한 번에 점검하고 점수로", domainField(), serverField(), note = NOTE) { i, host, env ->
            val d = HostInput.host(i.str("d")); if (d.isEmpty()) return@online need("도메인을 입력하세요")
            val srv = servers(i, host)
            fun q(name: String, t: Int, label: String): DnsResponse? { env.progress("$label 조회 중..."); return try { ask(srv, name, t, host) } catch (_: IOException) { null } }
            val mx = q(d, DnsType.MX, "MX"); val txt = q(d, DnsType.TXT, "SPF"); val dm = q("_dmarc.$d", DnsType.TXT, "DMARC")
            if (mx == null && txt == null && dm == null) return@online fail("DNS 서버에 닿지 못했어요")
            val mxs = mx?.msg?.answers?.filter { it.type == DnsType.MX }.orEmpty(); val spf = SpfParser.find(txt?.let { txtOf(it) }.orEmpty()); val dmarc = DmarcParser.find(dm?.let { txtOf(it) }.orEmpty())
            var score = 0
            result {
                kv("도메인", d)
                head("메일 서버 (MX)")
                if (mxs.isEmpty()) note("MX 가 없어요. 이 도메인으로는 메일을 받지 않거나(정상일 수 있어요) 설정이 빠진 거예요.", 1) else { score++; for (m in mxs.sortedBy { it.data.substringBefore(' ').toIntOrNull() ?: 0 }) kv("MX", m.data) }
                head("SPF")
                if (spf.isEmpty()) note("SPF 없음 — 누구나 이 도메인 이름으로 메일을 보낼 수 있어요", 2)
                else { val info = SpfParser.parse(spf[0]); score++; kv("레코드", spf[0].take(120)); if (info.allQualifier == '-' || info.allQualifier == '~') score++; for ((m, l) in info.issues.filter { it.second >= 1 }) note(m, l) }
                head("DMARC")
                if (dmarc.isEmpty()) note("DMARC 없음 — 실패한 메일을 어떻게 처리할지 정해져 있지 않아요", 2)
                else { val info = DmarcParser.parse(dmarc[0]); score++; kv("레코드", dmarc[0].take(120)); val p = info.tags["p"]?.lowercase(); if (p == "quarantine" || p == "reject") score++; for ((m, l) in info.issues.filter { it.second >= 1 }) note(m, l) }
                head("종합")
                kv("점수", "$score / 5", if (score >= 4) -1 else if (score >= 2) 1 else 2)
                note(when { score >= 5 -> "메일 위조·사칭을 막는 기본 설정이 잘 되어 있어요."; score >= 3 -> "기본 설정은 있지만 정책을 더 엄격하게(SPF -all, DMARC quarantine/reject) 올릴 여지가 있어요."; else -> "메일 보안 설정이 부족해요. 도메인 사칭 메일에 쓰이기 쉬워요." }, if (score >= 4) -1 else if (score >= 2) 1 else 2)
                note("DKIM 은 선택자를 알아야 해서 여기서는 확인하지 못해요. 'DKIM 점검'에서 선택자를 넣어 확인하세요.")
            }
        },

        online("dns_dnssec", D, "DNSSEC 사용 여부", "DNS 응답에 전자서명(DNSSEC)이 쓰이는지, 상위 영역에 등록돼 있는지", domainField("cloudflare.com"), serverField(), note = NOTE) { i, host, _ ->
            val d = HostInput.host(i.str("d")); if (d.isEmpty()) return@online need("도메인을 입력하세요")
            val srv = servers(i, host)
            val ds = try { ask(srv, d, DnsType.DS, host, dnssec = true) } catch (e: IOException) { return@online fail("조회하지 못했어요: ${e.message}") }
            val key = try { ask(srv, d, DnsType.DNSKEY, host, dnssec = true) } catch (e: IOException) { return@online fail("조회하지 못했어요: ${e.message}") }
            val dsN = ds.msg.answers.count { it.type == DnsType.DS }; val keyN = key.msg.answers.count { it.type == DnsType.DNSKEY }
            result {
                kv("도메인", d); kv("DS (상위 영역에 등록된 지문)", if (dsN > 0) "${dsN}개" else "없음", if (dsN > 0) -1 else 0); kv("DNSKEY (공개키)", if (keyN > 0) "${keyN}개" else "없음", if (keyN > 0) -1 else 0)
                kv("리졸버의 검증(AD)", if (ds.msg.ad || key.msg.ad) "검증됨" else "표시 없음 (이 DNS 서버가 검증하지 않을 수 있어요)")
                for (a in key.msg.answers.filter { it.type == DnsType.DNSKEY }.take(4)) kv("키", a.data)
                note(when { dsN > 0 && keyN > 0 -> "DNSSEC 가 사용 중이에요. 이 도메인의 DNS 응답이 위조되지 않았는지 검증할 수 있어요."; keyN > 0 -> "공개키는 있지만 상위 영역에 DS 가 등록되지 않아 신뢰 사슬이 끊겨 있어요(사실상 무효)."; else -> "DNSSEC 를 쓰지 않아요 (대부분의 도메인이 그래요)." }, if (dsN > 0 && keyN > 0) -1 else 0)
            }
        },

        online("dns_compare", D, "DNS 서버별 응답 비교", "내 DNS·구글·클라우드플레어·Quad9 가 같은 답을 주는지 (DNS 변조·전파 확인)", domainField(), choice("t", "레코드 종류", listOf("A", "AAAA", "MX", "TXT", "NS")), note = NOTE) { i, host, env ->
            val d = HostInput.host(i.str("d")); if (d.isEmpty()) return@online need("도메인을 입력하세요")
            val type = DnsType.parse(i.str("t")) ?: DnsType.A
            val mine = host.dnsServers().firstOrNull()
            val list = (listOfNotNull(mine?.let { it to "내 DNS" }) + listOf("8.8.8.8" to "구글", "1.1.1.1" to "클라우드플레어", "9.9.9.9" to "Quad9")).distinctBy { it.first }
            val out = java.util.Collections.synchronizedMap(LinkedHashMap<String, Pair<DnsResponse?, String?>>())
            env.progress("${list.size}곳에 질문 중...")
            list.map { (ip, _) -> Thread { out[ip] = try { ask(listOf(ip), d, type, host, timeoutMs = 2500) to null } catch (e: IOException) { null to e.message } }.also { it.start() } }.forEach { it.join(6000) }
            result {
                header("DNS 서버", "시간", "답")
                val sets = ArrayList<Set<String>>()
                for ((ip, label) in list) {
                    val (r, err) = out[ip] ?: (null to "응답 없음")
                    if (r == null) row("$label ($ip)", "-", err ?: "실패", level = 2)
                    else { val ans = r.msg.answers.filter { it.type == type }.map { it.data }.sorted(); sets += ans.toSet(); row("$label ($ip)", "${r.ms}ms", if (ans.isEmpty()) DnsType.rcode(r.msg.rcode) else ans.joinToString(", ")) }
                }
                kv("비교 결과", if (sets.size < 2) "비교할 응답이 부족해요" else if (sets.distinct().size == 1) "모두 같은 답이에요" else "서버마다 답이 달라요", if (sets.size < 2) 1 else if (sets.distinct().size == 1) -1 else 1)
                note("CDN·지역별 DNS 를 쓰는 사이트는 서버마다 답이 다른 것이 정상이에요. 그러나 평소와 다른 엉뚱한 주소가 나오면 내 DNS 가 변조됐을 수 있어요.")
            }
        },

        online("dns_speed", D, "DNS 서버 속도 비교", "내 DNS·구글·클라우드플레어·Quad9·국내 통신사 DNS 의 응답 속도를 재서 가장 빠른 곳 찾기", domainField("www.google.com"), choice("n", "횟수", listOf("5", "10")), note = NOTE) { i, host, env ->
            val d = HostInput.host(i.str("d")); if (d.isEmpty()) return@online need("도메인을 입력하세요")
            val n = i.str("n").toIntOrNull() ?: 5
            val mine = host.dnsServers().firstOrNull()
            val list = (listOfNotNull(mine?.let { it to "내 DNS" }) + PUBLIC_SERVERS).distinctBy { it.first }
            class Stat(val ip: String, val name: String, val first: Long?, val times: List<Long>, val lost: Int)
            val stats = java.util.Collections.synchronizedList(ArrayList<Stat>())
            env.progress("${list.size}곳에 $n 번씩 질문 중...")
            list.map { (ip, name) ->
                Thread {
                    val t = ArrayList<Long>(); var lost = 0; var first: Long? = null
                    for (k in 0 until n) {
                        if (env.cancel.get()) break
                        try { val r = DnsClient.query(ip, d, DnsType.A, timeoutMs = 1500, retries = 0, bind = { if (isLocal(ip)) host.bindDatagram(it) }); if (k == 0) first = r.ms else t += r.ms } catch (_: IOException) { lost++ }
                    }
                    stats += Stat(ip, name, first, t, lost)
                }.also { it.start() }
            }.forEach { it.join(20000) }
            val sorted = stats.sortedBy { if (it.times.isEmpty()) Double.MAX_VALUE else it.times.average() }
            result {
                kv("도메인", d); kv("횟수", "$n 번 (첫 번째는 캐시 없는 처음 응답, 나머지는 평균)")
                header("순위", "DNS 서버", "처음", "평균", "손실")
                sorted.forEachIndexed { idx, s -> row("${idx + 1}", "${s.name} (${s.ip})", s.first?.let { "${it}ms" } ?: "-", if (s.times.isEmpty()) "-" else "%.0fms".format(s.times.average()), "${s.lost}/$n", level = if (s.lost == n) 2 else if (idx == 0 && s.times.isNotEmpty()) -1 else 0) }
                sorted.firstOrNull { it.times.isNotEmpty() }?.let { note("가장 빠른 DNS: ${it.name} (${it.ip}) — 평균 ${"%.0f".format(it.times.average())}ms. 이 DNS 로 바꾸면 접속이 조금 빨라질 수 있어요 (입력한 도메인이 그 DNS 운영자에게 보여요).", -1) }
            }
        },

        online("dns_trace", D, "DNS 위임 추적 (루트부터)", "dig +trace 처럼 루트 서버부터 .com → 네임서버까지 따라가며 질문 (DNS 가 어떻게 풀리는지)", domainField("www.example.com"), choice("t", "레코드 종류", listOf("A", "AAAA", "MX", "NS", "TXT")), note = NOTE) { i, host, env ->
            val d = HostInput.host(i.str("d")); if (d.isEmpty()) return@online need("도메인을 입력하세요")
            val type = DnsType.parse(i.str("t")) ?: DnsType.A
            val roots = listOf("198.41.0.4" to "a.root-servers.net", "193.0.14.129" to "k.root-servers.net", "192.203.230.10" to "e.root-servers.net", "199.7.83.42" to "l.root-servers.net")
            result {
                kv("질문", "$d  ${DnsType.name(type)}")
                var cands: List<Pair<String, String>> = roots; var step = 0; var done = false
                while (!done && step < 10 && !env.cancel.get()) {
                    step++
                    env.progress("$step 단계 ...")
                    var resp: DnsResponse? = null; var used: Pair<String, String>? = null
                    for (c in cands.take(4)) { try { resp = DnsClient.query(c.first, d, type, rd = false, timeoutMs = 2500, retries = 0); used = c; break } catch (_: IOException) {} }
                    if (resp == null || used == null) { note("$step 단계: 응답하는 서버가 없어요", 2); break }
                    val m = resp.msg
                    head("$step 단계 — ${used.second} (${used.first}) ${resp.ms}ms")
                    if (m.answers.isNotEmpty()) {
                        for (a in m.answers) row(a.name, a.typeName, "${a.ttl}", a.data)
                        if (m.answers.any { it.type == type } || m.answers.none { it.type == DnsType.CNAME }) { done = true; note("최종 답을 받았어요 (권한 있는 서버: ${if (m.aa) "예" else "아니요"}).", -1); break }
                    }
                    val ns = m.authority.filter { it.type == DnsType.NS }.map { it.data.trimEnd('.') }
                    if (ns.isEmpty()) { note(if (m.rcode == 3) "NXDOMAIN: 그런 도메인이 없어요." else "더 내려갈 위임이 없어요 (${DnsType.rcode(m.rcode)}).", if (m.rcode == 3) 2 else 1); break }
                    kv("위임된 네임서버", ns.take(6).joinToString(", ") + if (ns.size > 6) " 외 ${ns.size - 6}개" else "")
                    val glue = ns.mapNotNull { n -> m.additional.firstOrNull { it.type == DnsType.A && it.name.trimEnd('.').equals(n, true) }?.let { it.data to n } }
                    cands = glue.ifEmpty { ns.take(3).mapNotNull { n -> Dns.resolve(n, 3000).firstOrNull { it.address.size == 4 }?.let { IpUtil.format(it) to n } } }
                    if (cands.isEmpty()) { note("다음 네임서버의 주소를 찾지 못했어요", 2); break }
                }
            }
        },

        online("asn_lookup", D, "IP → ASN·통신사 (네트워크 소유 기관)", "IP 가 속한 주소 블록과 이를 운영하는 통신사·기관(ASN) — 개인이 아니라 기관 단위 정보예요",
            text("ip", "IP 주소", "예: 8.8.8.8", "8.8.8.8", listOf("8.8.8.8" to "8.8.8.8", "1.1.1.1" to "1.1.1.1", "168.126.63.1" to "168.126.63.1")), serverField(),
            note = "IP 주소가 DNS 서버(Team Cymru 의 공개 ASN 조회 서비스)로 전송돼요. 결과는 주소 블록을 가진 기관(통신사 등)이며, 사용자의 위치·신원이 아니에요.") { i, host, _ ->
            val a = IpUtil.parse(i.str("ip")) ?: return@online if (i.str("ip").isEmpty()) need("IP 주소를 입력하세요") else fail("IP 주소를 읽지 못했어요")
            val kind = IpUtil.classify(a); if (kind != IpKind.PUBLIC) return@online fail("공인 IP 만 조회할 수 있어요 (${kind.label})")
            val srv = servers(i, host)
            val o = try { ask(srv, Cymru.originName(a), DnsType.TXT, host) } catch (e: IOException) { return@online fail("조회하지 못했어요: ${e.message}") }
            val txt = o.msg.answers.firstOrNull { it.type == DnsType.TXT }?.text ?: return@online fail("이 주소의 ASN 정보를 찾지 못했어요")
            val (asn, prefix, rest) = Cymru.parseOrigin(txt) ?: return@online fail("응답을 해석하지 못했어요: $txt")
            val nm = try { ask(srv, "AS$asn.asn.cymru.com", DnsType.TXT, host).msg.answers.firstOrNull { it.type == DnsType.TXT }?.text?.let { Cymru.parseName(it) } } catch (_: IOException) { null }
            result { kv("IP", IpUtil.format(a)); kv("ASN", "AS$asn"); kv("기관 이름", nm ?: "알 수 없음"); kv("주소 블록", prefix); kv("할당 국가 코드", rest.getOrElse(0) { "-" }); kv("등록 기관", rest.getOrElse(1) { "-" }); kv("할당일", rest.getOrElse(2) { "-" }); note("이 정보는 주소 블록을 관리하는 기관(통신사·클라우드·회사)이에요. 이 IP 를 쓰는 사람의 위치나 신원을 알려 주지 않아요.") }
        },
    )
}
