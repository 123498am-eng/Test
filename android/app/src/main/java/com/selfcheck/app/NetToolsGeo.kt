package com.selfcheck.app

import java.io.IOException
import java.net.InetAddress
import java.time.Instant
import java.time.ZoneId
import java.time.ZonedDateTime
import java.time.format.DateTimeFormatter

/**
 * IP 위치·IP 찾기 도구 39가지.
 * 폰 안의 자료(국가·통신사)로 조회하는 도구는 IP 를 어디로도 보내지 않고, 인터넷 제공처에 묻는 도구는 무엇이 나가는지 안내를 보여 줍니다.
 * 이 묶음에는 "상대방이 모르게 IP 를 알아내는 링크(IP 로거)"나 "사람을 찾아내는" 기능은 없습니다.
 */
object GeoTools {
    private const val G = NetGroups.GEO
    private const val NO_DB = "폰 안의 IP 자료를 읽지 못했어요 (설치 파일이 손상됐을 수 있어요)"
    private const val ACCURACY = "IP 위치는 통신사가 등록한 주소 블록을 바탕으로 짐작한 값이에요. 같은 통신사 안에서도 도시가 자주 틀리고, 사람이나 집의 위치와는 상관이 없어요."
    private const val SENT = "입력한 IP 를 위치 제공처(ipwho.is·ipapi.co·ipinfo.io·ip.guide·ipapi.is)에 보내 조회해요. 인터넷을 사용해요."
    private const val SENT_ME = "내 공인 IP 는 어차피 접속하는 서버에 보이는 값이에요. 위치 제공처(ipwho.is·ipapi.co·ipinfo.io·ip.guide·ipapi.is) 5곳에 한 번씩 물어요."

    /** 시험에서 인터넷 대신 컴퓨터 안의 가짜 서버를 가리키게 바꾸는 값들 */
    internal var stunServers: List<Pair<String, Int>> = listOf("stun.l.google.com" to 19302, "stun1.l.google.com" to 19302, "stun.cloudflare.com" to 3478)
    internal var publicResolvers: List<Pair<String, String>> = listOf("8.8.8.8" to "구글", "1.1.1.1" to "클라우드플레어", "9.9.9.9" to "Quad9", "208.67.222.222" to "OpenDNS")
    /** (OpenDNS 의 myip 서버, 구글 DNS 서버) */
    internal var myIpDnsServers: Pair<String, String> = "208.67.222.222" to "216.239.32.10"
    internal var ssdpTarget: java.net.InetSocketAddress = java.net.InetSocketAddress("239.255.255.250", 1900)
    internal var mdnsTarget: java.net.InetSocketAddress = Mdns.GROUP
    internal var ssdpWaitMs = 4000
    internal var mdnsWaitMs = 3000

    private val IP_CHIPS = listOf("구글 DNS" to "8.8.8.8", "클라우드플레어" to "1.1.1.1", "KT DNS" to "168.126.63.1", "SK브로드밴드 DNS" to "210.220.163.82", "IPv6" to "2001:4860:4860::8888")
    private fun ipField(key: String = "ip", label: String = "IP 주소", def: String = "8.8.8.8") = text(key, label, "예: 8.8.8.8 또는 2001:4860:4860::8888", def, IP_CHIPS)

    private fun fmtDate(z: ZonedDateTime) = DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm").format(z)

    /** 입력한 IP 가 공인 주소가 아니면 이유를 돌려줌 (인터넷 제공처에는 공인 주소만 보냄) */
    private fun notPublic(a: InetAddress): String? { val k = IpUtil.classify(a); return if (k == IpKind.PUBLIC) null else "${k.label}: 위치 정보가 없는 주소예요. ${k.note}" }

    private fun readIp(i: ToolInput, key: String = "ip"): Pair<InetAddress?, ToolResult?> {
        val t = i.str(key)
        if (t.isEmpty()) return null to need("IP 주소를 입력하세요")
        return (IpUtil.parse(t) ?: return null to fail("IP 주소를 읽지 못했어요 (\"$t\")")) to null
    }

    private fun db(host: ToolHost): IpGeoDb? = host.geoDb()

    // ---------------------------------------------------------------- 위치 결과 그리기
    private fun renderConsensus(rb: Rb, c: GeoConsensus, results: List<GeoResult>, db: IpGeoDb?, ip: InetAddress?) {
        val levelText = when (c.level) { -1 -> "높음 (제공처가 나라·도시·좌표에 모두 동의)"; 0 -> "보통 (나라는 같지만 도시나 좌표가 다름)"; else -> "낮음 (제공처끼리 의견이 갈리거나 한 곳뿐)" }
        rb.kv("나라", CountryNames.label(c.countryCode ?: c.country).let { if (c.countryCode == null) (c.country ?: "-") else it }, if (c.agree == c.total) -1 else 1)
        c.region?.let { rb.kv("지역", it) }
        rb.kv("도시", c.city ?: "-", if (c.cityAgree >= 2) 0 else 1)
        if (c.lat != null && c.lon != null) rb.kv("대략적 좌표", "${Geo.dec(c.lat)}, ${Geo.dec(c.lon)}  (${Geo.dms(c.lat, 'N', 'S')} ${Geo.dms(c.lon, 'E', 'W')})")
        c.timezone?.let { tz -> rb.kv("시간대", tz + runCatching { "  ·  현지 ${fmtDate(ZonedDateTime.now(ZoneId.of(tz)))}" }.getOrDefault("")) }
        c.org?.let { rb.kv("통신사·소유", it + (c.asn?.let { a -> " ($a)" } ?: "")) }
        rb.kv("신뢰도", levelText, c.level)
        c.spreadKm?.let { rb.kv("제공처 간 좌표 차이", "최대 ${"%.0f".format(it)} km") }
        rb.kv("일치한 제공처", "${c.agree} / ${c.total}")
        if (db != null && ip != null) {
            val g = db.lookup(ip)
            rb.head("폰 안 자료와 비교"); rb.kv("국가(폰 안 자료)", g.countryLabel); rb.kv("통신사(폰 안 자료)", g.orgLabel)
            if (g.country != null && c.countryCode != null && g.country != c.countryCode) rb.note("폰 안 자료와 인터넷 제공처의 나라가 달라요. 최근에 주소 블록이 다른 나라로 옮겨졌거나 해외에서 쓰는 주소(로밍·VPN·해외 서버)일 수 있어요.", 1)
        }
        val tbl = results
        rb.head("제공처별 답")
        rb.header("제공처", "위치", "통신사")
        for (r in tbl) { if (r.error != null) rb.row(r.provider, r.error, "", level = 1) else rb.row(r.provider, r.place + (if (r.lat != null && r.lon != null) "  (${"%.2f".format(r.lat)}, ${"%.2f".format(r.lon)})" else ""), r.org ?: "") }
        c.lat?.let { la -> c.lon?.let { lo -> rb.head("지도로 보기 (대략적인 위치예요)"); for ((n, u) in Geo.mapLinks(la, lo)) rb.kv(n, u) } }
        rb.note(ACCURACY, 1)
    }

    // ---------------------------------------------------------------- 방화벽 규칙 (국가·ASN 대역 목록 → 설정)
    private val RULE_FORMATS = listOf("대역 목록만(CIDR)", "iptables + ipset", "nftables", "nginx geo", "Apache(.htaccess)")
    private const val MAX_CIDRS = 20000

    private fun toCidrs(ranges: List<Pair<Long, Long>>): List<Cidr4> = ranges.flatMap { Cidr.rangeToCidrs(it.first, it.second) }

    private fun rules(fmt: String, cidrsAll: List<Cidr4>, label: String, allowOnly: Boolean): String {
        val cidrs = cidrsAll.take(MAX_CIDRS).map { it.toString() }
        val head = "# $label — ${cidrsAll.size}개 대역" + if (cidrsAll.size > MAX_CIDRS) " (너무 많아서 앞 $MAX_CIDRS 개만)" else ""
        return when (fmt) {
            "iptables + ipset" -> buildString {
                val set = if (allowOnly) "geo_allow" else "geo_block"
                appendLine(head)
                appendLine("sudo ipset create $set hash:net family inet hashsize 4096 maxelem ${maxOf(65536, cidrs.size * 2)} -exist")
                for (c in cidrs) appendLine("sudo ipset add $set $c -exist")
                if (allowOnly) {
                    appendLine("# 아래는 목록 밖의 모든 접속을 막아요. 지금 쓰는 SSH 접속 주소가 목록에 있는지 꼭 먼저 확인하세요 (없으면 접속이 끊겨요)")
                    appendLine("sudo iptables -A INPUT -i lo -j ACCEPT"); appendLine("sudo iptables -A INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT")
                    appendLine("sudo iptables -A INPUT -m set --match-set $set src -j ACCEPT"); appendLine("sudo iptables -A INPUT -j DROP")
                } else appendLine("sudo iptables -I INPUT 1 -m set --match-set $set src -j DROP")
            }
            "nftables" -> buildString {
                appendLine(head)
                appendLine("table inet geo {")
                appendLine("  set geo_list {\n    type ipv4_addr\n    flags interval\n    auto-merge\n    elements = {\n      ${cidrs.joinToString(",\n      ")}\n    }\n  }")
                if (allowOnly) appendLine("  chain input {\n    type filter hook input priority -10; policy accept;\n    iif lo accept\n    ct state established,related accept\n    ip saddr @geo_list accept\n    drop     # 목록 밖은 모두 거부 (SSH 접속 주소가 목록에 있는지 먼저 확인!)\n  }")
                else appendLine("  chain input {\n    type filter hook input priority -10; policy accept;\n    ip saddr @geo_list drop\n  }")
                appendLine("}")
            }
            "nginx geo" -> buildString {
                appendLine(head); appendLine("# http { } 블록 안에 넣고, server { } 안에서 if (\$geo_blocked) { return 403; } 로 막아요")
                appendLine("geo \$geo_blocked {"); appendLine("    default ${if (allowOnly) 1 else 0};")
                for (c in cidrs) appendLine("    $c ${if (allowOnly) 0 else 1};")
                appendLine("}")
            }
            "Apache(.htaccess)" -> buildString {
                appendLine(head)
                if (allowOnly) { appendLine("Require ip ${cidrs.joinToString(" ")}") }
                else { appendLine("<RequireAll>"); appendLine("    Require all granted"); cidrs.chunked(50).forEach { appendLine("    Require not ip ${it.joinToString(" ")}") }; appendLine("</RequireAll>") }
            }
            else -> head + "\n" + cidrs.joinToString("\n")
        }
    }

    private fun readCountries(text: String, db: IpGeoDb): Pair<List<String>, List<String>> {
        val ok = ArrayList<String>(); val bad = ArrayList<String>()
        for (t in text.split(',', ' ', '\n', ';').map { it.trim() }.filter { it.isNotEmpty() }) {
            val code = CountryNames.find(t)
            if (code != null && code in db.countryCodes) ok += code else bad += t
        }
        return ok.distinct() to bad
    }

    // ---------------------------------------------------------------- 도구 목록
    val ALL: List<NetTool> = listOf(
        // ===== 폰 안의 자료로 조회 (인터넷에 묻지 않음)
        tool("geo_country", G, "IP 국가·통신사 조회 (폰 안에서)", "IP 가 어느 나라·어느 통신사(ASN)의 주소 블록인지 — 인터넷에 묻지 않고 폰에 들어 있는 자료로 조회",
            listOf(ipField()), ToolMode.OFFLINE, "폰 안의 자료(DB-IP Lite)만 쓰고, 입력한 IP 는 어디로도 보내지 않아요.", live = true) { i, host, _ ->
            val db = db(host) ?: return@tool fail(NO_DB)
            val (a, err) = readIp(i); if (a == null) return@tool err!!
            val kind = IpUtil.classify(a); val g = db.lookup(a)
            result {
                kv("IP", IpUtil.format(a)); kv("주소 종류", kind.label)
                if (kind != IpKind.PUBLIC) note(kind.note, 1)
                kv("나라", g.countryLabel, if (g.country != null) 0 else 1); kv("통신사(ASN)", g.orgLabel)
                CloudDetect.label(g.asn?.name)?.let { kv("서비스 종류", it) }
                note("나라는 \"그 주소 블록이 쓰이는 나라\" 수준이에요. $ACCURACY")
                note("자료: ${db.sourceNote}")
            }
        },

        tool("geo_country_bulk", G, "IP 목록 국가·통신사 일괄 조회", "IP 여러 개(최대 500개)를 한꺼번에 — 폰 안의 자료로 조회해서 표로",
            listOf(multi("ips", "IP 목록 (한 줄에 하나, 글 속에 섞여 있어도 돼요)", "예: 8.8.8.8", "8.8.8.8\n1.1.1.1\n168.126.63.1\n210.220.163.82\n2001:4860:4860::8888\n192.168.0.1")), ToolMode.OFFLINE,
            "폰 안의 자료만 쓰고 입력한 IP 는 어디로도 보내지 않아요.") { i, host, _ ->
            val db = db(host) ?: return@tool fail(NO_DB)
            val ips = IpText.extract(i.raw("ips")).distinctBy { IpUtil.format(it) }.take(500)
            if (ips.isEmpty()) return@tool need("IP 주소를 한 줄에 하나씩 입력하세요")
            result {
                header("IP", "나라", "통신사")
                for (a in ips) { val g = db.lookup(a); val k = IpUtil.classify(a); row(IpUtil.format(a), if (k != IpKind.PUBLIC && g.country == null) k.label.substringBefore(" (") else g.countryLabel, g.orgLabel, level = if (g.country == null) 1 else 0) }
                note("${ips.size}개 조회. 자료: ${db.sourceNote}")
            }
        },

        tool("geo_country_stats", G, "IP 목록 국가별·통신사별 집계", "접속 IP 목록을 나라별·통신사별로 세어 순위로 (어느 나라에서 많이 들어오는지)",
            listOf(multi("ips", "IP 목록 (같은 IP 가 여러 번 나와도 돼요)", "한 줄에 하나", "8.8.8.8\n8.8.4.4\n1.1.1.1\n168.126.63.1\n168.126.63.1\n210.220.163.82\n210.220.163.82\n210.220.163.82\n113.226.115.168\n52.95.110.1")), ToolMode.OFFLINE,
            "폰 안의 자료만 쓰고 입력한 IP 는 어디로도 보내지 않아요.") { i, host, _ ->
            val db = db(host) ?: return@tool fail(NO_DB)
            val all = IpText.extract(i.raw("ips")); if (all.isEmpty()) return@tool need("IP 주소를 입력하세요")
            val pub = all.filter { IpUtil.classify(it) == IpKind.PUBLIC }
            val byCountry = pub.groupBy { db.country(it) ?: "?" }.map { (c, l) -> Triple(c, l.size, l.map { IpUtil.format(it) }.distinct().size) }.sortedByDescending { it.second }
            val byAsn = pub.groupBy { db.asn(it)?.let { a -> "AS${a.asn} ${a.name}" } ?: "자료 없음" }.map { (n, l) -> n to l.size }.sortedByDescending { it.second }
            result {
                kv("전체", "${all.size}건 (공인 ${pub.size}건, 사설·예약 ${all.size - pub.size}건)")
                head("나라별"); header("나라", "건수", "비율", "서로 다른 IP")
                for ((c, n, u) in byCountry.take(30)) row(if (c == "?") "자료 없음" else CountryNames.label(c), "$n", "${"%.1f".format(n * 100.0 / pub.size)}%", "$u")
                head("통신사별 상위"); header("통신사(ASN)", "건수")
                for ((n, c) in byAsn.take(15)) row(n, "$c")
                note("자료: ${db.sourceNote}")
            }
        },

        tool("geo_asn_org", G, "ASN 번호로 통신사·IP 대역 찾기", "ASN(AS 번호)이 쓰는 IPv4 대역 목록과 이름 — 폰 안의 자료",
            listOf(text("asn", "ASN 번호", "예: 4766 또는 AS4766", "4766", listOf("KT" to "4766", "SK브로드밴드" to "9318", "LG U+" to "3786", "구글" to "15169", "클라우드플레어" to "13335"))), ToolMode.OFFLINE,
            "폰 안의 자료만 쓰고 어디로도 보내지 않아요.", live = true) { i, host, _ ->
            val db = db(host) ?: return@tool fail(NO_DB)
            val n = i.str("asn").removePrefix("AS").removePrefix("as").trim().toIntOrNull() ?: return@tool if (i.str("asn").isEmpty()) need("ASN 번호를 입력하세요") else fail("ASN 은 숫자예요 (예: 4766). 이름으로 찾으려면 '통신사 이름으로 ASN 찾기'를 쓰세요")
            val name = db.asnName(n) ?: return@tool fail("AS$n 은(는) 자료에 없어요")
            val ranges = db.asnRanges(n); val cidrs = Cidr.merge(toCidrs(ranges))
            result {
                kv("ASN", "AS$n"); kv("이름", name); kv("IPv4 주소 수", "%,d개".format(ranges.sumOf { it.second - it.first + 1 })); kv("범위 / 대역 수", "${ranges.size}개 범위 · ${cidrs.size}개 CIDR")
                if (cidrs.isNotEmpty()) { head("대역 (앞 60개)"); block(cidrs.take(60).joinToString("\n")) }
                if (cidrs.size > 60) note("나머지 ${cidrs.size - 60}개는 'ASN 기준 방화벽 규칙 만들기'로 전체를 받을 수 있어요.")
                note("자료: ${db.sourceNote}")
            }
        },

        tool("geo_find_org", G, "통신사·회사 이름으로 ASN 찾기", "이름 일부(예: korea telecom, amazon, naver)로 ASN 번호와 주소 수를 찾기 — 폰 안의 자료",
            listOf(text("q", "이름 (영어)", "예: korea telecom, amazon, naver", "korea telecom", listOf("KT" to "korea telecom", "SK" to "sk broadband", "아마존" to "amazon", "네이버" to "naver", "카카오" to "kakao"))), ToolMode.OFFLINE,
            "폰 안의 자료만 쓰고 어디로도 보내지 않아요.") { i, host, _ ->
            val db = db(host) ?: return@tool fail(NO_DB)
            val q = i.str("q"); if (q.length < 2) return@tool need("이름을 두 글자 이상 입력하세요 (영어로: 자료의 이름이 영어예요)")
            val hits = db.searchAsn(q, 40)
            if (hits.isEmpty()) return@tool result { note("\"$q\" 가 들어간 이름이 없어요. 영어 철자를 바꿔 보세요 (예: korea, kt, sk).", 1) }
            result {
                kv("찾은 수", "${hits.size}개" + if (hits.size >= 40) " (앞 40개만)" else "")
                header("ASN", "이름", "IPv4 주소 수")
                for (h in hits) row("AS${h.asn}", h.name, "%,d".format(db.asnRanges(h.asn).sumOf { it.second - it.first + 1 }))
                note("주소 수가 0 이면 IPv6 만 쓰거나 지금은 쓰이지 않는 ASN 이에요. 자료: ${db.sourceNote}")
            }
        },

        tool("geo_cloud_check", G, "클라우드·CDN·호스팅 IP 판별", "IP 가 아마존·구글·마이크로소프트·클라우드플레어·네이버 클라우드 같은 데이터센터 주소인지 (가정 회선이 아닌지)",
            listOf(ipField()), ToolMode.OFFLINE, "폰 안의 자료만 쓰고 입력한 IP 는 어디로도 보내지 않아요.", live = true) { i, host, _ ->
            val db = db(host) ?: return@tool fail(NO_DB)
            val (a, err) = readIp(i); if (a == null) return@tool err!!
            val g = db.lookup(a); val label = CloudDetect.label(g.asn?.name)
            result {
                kv("IP", IpUtil.format(a)); kv("통신사(ASN)", g.orgLabel); kv("나라", g.countryLabel)
                if (label != null) { kv("판별", label, 1); note("클라우드·호스팅 업체의 주소예요. 이 주소에서 오는 접속은 서버·봇·VPN·프록시일 가능성이 있고, 가정집 사용자의 직접 접속은 아닐 가능성이 커요.", 1) }
                else { kv("판별", "알려진 클라우드·CDN 이름과 일치하지 않아요", -1); note("가정·회사·통신사 회선일 수도, 목록에 없는 호스팅 업체일 수도 있어요. 이름으로 짐작하는 방식이라 완벽하지 않아요.") }
            }
        },

        tool("geo_country_cidrs", G, "국가별 IP 대역(CIDR) 목록", "한 나라에 속한 모든 IPv4 대역을 CIDR 목록으로 (방화벽·허용 목록용) — 폰 안의 자료",
            listOf(text("c", "나라 (이름 또는 코드)", "예: KR, 한국, 일본", "KR", listOf("한국" to "KR", "일본" to "JP", "미국" to "US", "중국" to "CN", "싱가포르" to "SG"))), ToolMode.OFFLINE,
            "폰 안의 자료만 쓰고 어디로도 보내지 않아요.") { i, host, _ ->
            val db = db(host) ?: return@tool fail(NO_DB)
            val code = CountryNames.find(i.str("c"))?.takeIf { it in db.countryCodes } ?: return@tool if (i.str("c").isEmpty()) need("나라를 입력하세요 (예: KR)") else fail("\"${i.str("c")}\" 나라를 찾지 못했어요. 두 글자 코드(KR)나 한국어 이름을 쓰세요")
            val ranges = db.countryRanges(code); val cidrs = toCidrs(ranges); val total = ranges.sumOf { it.second - it.first + 1 }
            result {
                kv("나라", CountryNames.label(code)); kv("IPv4 주소 수", "%,d개 (전체의 %.2f%%)".format(total, total * 100.0 / 4294967296.0)); kv("대역 수", "${cidrs.size}개 CIDR")
                block(cidrs.take(MAX_CIDRS).joinToString("\n")); if (cidrs.size > MAX_CIDRS) note("너무 많아서 앞 $MAX_CIDRS 개만 보여요.", 1)
                note("이 자료는 \"주소 블록이 쓰이는 나라\"예요. 해외 서버·VPN·로밍은 다른 나라로 나올 수 있어서, 국가 기준 차단은 완벽하지 않아요. 자료: ${db.sourceNote}")
            }
        },

        tool("geo_country_blocklist", G, "국가 기준 방화벽 규칙 만들기", "나라(여러 개 가능)의 IP 대역으로 차단·허용 규칙 만들기 — iptables·nftables·nginx·Apache",
            listOf(text("c", "나라 (쉼표로 여러 개)", "예: CN, RU", "CN,RU", listOf("중국·러시아" to "CN,RU", "한국만" to "KR")), choice("act", "동작", listOf("이 나라들을 차단", "이 나라들만 허용")), choice("fmt", "형식", RULE_FORMATS, "iptables + ipset")),
            ToolMode.OFFLINE, "폰 안의 자료로 규칙 글만 만들어요. 아무것도 적용하지 않아요.") { i, host, _ ->
            val db = db(host) ?: return@tool fail(NO_DB)
            val (codes, bad) = readCountries(i.str("c"), db)
            if (codes.isEmpty()) return@tool if (i.str("c").isEmpty()) need("나라를 입력하세요 (예: CN,RU)") else fail("나라를 찾지 못했어요: ${bad.joinToString()}")
            val allow = i.str("act").contains("만 허용"); val cidrs = Cidr.merge(toCidrs(codes.flatMap { db.countryRanges(it) }))
            result {
                kv("나라", codes.joinToString(", ") { CountryNames.ko(it) }); kv("동작", if (allow) "목록의 나라만 허용 (나머지는 거부)" else "목록의 나라를 차단"); kv("대역 수", "${cidrs.size}개")
                if (bad.isNotEmpty()) note("찾지 못한 나라: ${bad.joinToString()}", 1)
                block(rules(i.str("fmt"), cidrs, codes.joinToString(",") + if (allow) " 허용" else " 차단", allow))
                if (allow) note("\"만 허용\"은 위험해요: 내 접속 주소가 목록 밖이면 서버에 다시 못 들어가요. 콘솔(직접 접속) 수단이 있을 때만 적용하세요.", 1)
                note("국가 기준 차단은 VPN·해외 서버를 거치면 우회돼요. 그리고 주소 블록의 나라가 실제 사용자의 나라와 다를 수 있어요(오차 있음). 적용하기 전에 규칙을 읽어 보세요.")
            }
        },

        tool("geo_asn_blocklist", G, "ASN 기준 방화벽 규칙 만들기", "통신사·호스팅(ASN)의 IP 대역으로 차단·허용 규칙 만들기 — 클라우드 봇 차단 등",
            listOf(text("asn", "ASN 번호 (쉼표로 여러 개)", "예: 4766, 9318", "9318", listOf("KT" to "4766", "SK브로드밴드" to "9318")), choice("act", "동작", listOf("이 ASN 들을 차단", "이 ASN 들만 허용")), choice("fmt", "형식", RULE_FORMATS, "nginx geo")),
            ToolMode.OFFLINE, "폰 안의 자료로 규칙 글만 만들어요. 아무것도 적용하지 않아요.") { i, host, _ ->
            val db = db(host) ?: return@tool fail(NO_DB)
            val nums = i.str("asn").split(',', ' ', '\n').map { it.trim().removePrefix("AS").removePrefix("as") }.filter { it.isNotEmpty() }
            val ids = nums.mapNotNull { it.toIntOrNull() }; if (ids.isEmpty()) return@tool if (nums.isEmpty()) need("ASN 번호를 입력하세요") else fail("ASN 은 숫자예요")
            val known = ids.filter { db.asnName(it) != null }; if (known.isEmpty()) return@tool fail("자료에 없는 ASN 이에요")
            val allow = i.str("act").contains("만 허용"); val cidrs = Cidr.merge(toCidrs(known.flatMap { db.asnRanges(it) }))
            result {
                kv("ASN", known.joinToString(", ") { "AS$it ${db.asnName(it)}" }); kv("동작", if (allow) "목록만 허용" else "목록을 차단"); kv("대역 수", "${cidrs.size}개")
                if (known.size < ids.size) note("자료에 없는 ASN: ${(ids - known.toSet()).joinToString { "AS$it" }}", 1)
                if (cidrs.isEmpty()) note("이 ASN 은 IPv4 대역이 없어요.", 1) else block(rules(i.str("fmt"), cidrs, known.joinToString(",") { "AS$it" }, allow))
                if (allow) note("\"만 허용\"은 내 접속 주소가 목록 밖이면 서버에 다시 못 들어가는 위험이 있어요.", 1)
            }
        },

        tool("geo_log_countries", G, "접속 로그의 국가·통신사 통계", "웹·SSH 접속 로그를 붙여 넣으면 어느 나라·통신사에서 얼마나 들어왔는지 (로그는 폰 밖으로 나가지 않아요)",
            listOf(multi("log", "로그 (아무 형식이나, IP 가 들어 있으면 돼요)", "예: 203.0.113.5 - - [10/Oct/2026] \"GET / HTTP/1.1\" 200", "8.8.8.8 - - [10/Oct/2026:13:55:36] \"GET / HTTP/1.1\" 200 612\n168.126.63.1 - - [10/Oct/2026:13:55:40] \"GET /login HTTP/1.1\" 200 512\n113.226.115.168 - - [10/Oct/2026:13:56:01] \"GET /wp-login.php HTTP/1.1\" 404 0\n113.226.115.168 - - [10/Oct/2026:13:56:02] \"GET /.env HTTP/1.1\" 404 0\n52.95.110.1 - - [10/Oct/2026:13:57:11] \"GET /robots.txt HTTP/1.1\" 200 80\n192.168.0.5 - - [10/Oct/2026:13:58:00] \"GET /admin HTTP/1.1\" 200 99")), ToolMode.OFFLINE,
            "폰 안의 자료만 쓰고 로그는 어디로도 보내지 않아요.") { i, host, _ ->
            val db = db(host) ?: return@tool fail(NO_DB)
            val lines = i.raw("log").lines().filter { it.isNotBlank() }
            val perLine = lines.mapNotNull { l -> IpText.extract(l).firstOrNull()?.takeIf { IpUtil.classify(it) == IpKind.PUBLIC } }
            if (perLine.isEmpty()) return@tool need("공인 IP 가 들어 있는 로그 줄을 붙여 넣으세요")
            val byIp = perLine.groupBy { IpUtil.format(it) }.map { (ip, l) -> Triple(ip, l.size, db.lookup(l[0])) }.sortedByDescending { it.second }
            val byCountry = byIp.groupBy { it.third.country }.map { (c, l) -> Triple(c, l.sumOf { it.second }, l.size) }.sortedByDescending { it.second }
            result {
                kv("로그 줄", "${lines.size}줄 (공인 IP 가 있는 줄 ${perLine.size}줄, 서로 다른 IP ${byIp.size}개)")
                head("나라별"); header("나라", "요청 수", "비율", "IP 수")
                for ((c, n, u) in byCountry.take(20)) row(CountryNames.label(c), "$n", "${"%.1f".format(n * 100.0 / perLine.size)}%", "$u")
                head("요청이 많은 IP"); header("IP", "요청", "나라 · 통신사")
                for ((ip, n, g) in byIp.take(15)) row(ip, "$n", "${CountryNames.ko(g.country)} · ${g.asn?.name ?: "자료 없음"}")
                note("자료: ${db.sourceNote}")
            }
        },

        // ===== 인터넷 제공처에 묻는 위치 조회
        online("geo_ip", G, "IP 위치 조회 (여러 제공처 합의)", "IP 의 대략적인 위치(나라·지역·도시)·통신사·시간대를 5곳에 물어 다수결로 — 서로 얼마나 다른지도 보여 줘요",
            ipField(), note = SENT) { i, host, env ->
            val (a, err) = readIp(i); if (a == null) return@online err!!
            notPublic(a)?.let { return@online fail(it) }
            env.progress("제공처 5곳에 묻는 중...")
            val rs = GeoNet.lookupAll(GeoProviders.DEFAULT, IpUtil.format(a))
            val c = GeoMerge.merge(rs) ?: return@online result { kv("IP", IpUtil.format(a)); header("제공처", "결과"); for (r in rs) row(r.provider, r.error ?: "-", level = 1); note("어느 제공처에서도 위치를 얻지 못했어요. 인터넷 연결을 확인하거나 잠시 뒤 다시 해 보세요.", 2) }
            result { kv("IP", IpUtil.format(a)); renderConsensus(this, c, rs, db(host), a) }
        },

        online("geo_providers", G, "제공처별 위치 비교 (7곳)", "같은 IP 를 7개 제공처에 물어 답을 나란히 — IP 위치가 얼마나 들쭉날쭉한지 직접 확인",
            ipField(), note = "입력한 IP 를 위치 제공처 7곳(ipwho.is·ipapi.co·ipinfo.io·ip.guide·geojs.io·ipapi.is·ip-api.com)에 보내요. ip-api.com 은 암호화(https)를 지원하지 않아 http 로 물어요.") { i, _, env ->
            val (a, err) = readIp(i); if (a == null) return@online err!!
            notPublic(a)?.let { return@online fail(it) }
            env.progress("제공처 7곳에 묻는 중...")
            val rs = GeoNet.lookupAll(GeoProviders.ALL, IpUtil.format(a))
            val pts = rs.filter { it.ok && it.lat != null && it.lon != null }
            var spread = 0.0; for (x in pts.indices) for (y in x + 1 until pts.size) spread = maxOf(spread, Geo.distanceKm(pts[x].lat!!, pts[x].lon!!, pts[y].lat!!, pts[y].lon!!))
            result {
                kv("IP", IpUtil.format(a)); kv("답한 제공처", "${rs.count { it.ok }} / ${rs.size}")
                if (pts.size >= 2) kv("좌표가 가장 많이 다른 두 곳", "${"%.0f".format(spread)} km", if (spread > 100) 1 else -1)
                header("제공처", "나라 · 지역 · 도시", "좌표", "통신사")
                for (r in rs) if (r.error != null) row(r.provider, r.error, "", "", level = 1) else row(r.provider, r.place, if (r.lat != null && r.lon != null) "${"%.2f".format(r.lat)}, ${"%.2f".format(r.lon)}" else "-", r.org ?: "")
                note("제공처마다 쓰는 자료가 달라서 도시가 다르거나 수십~수백 km 차이가 나는 것이 정상이에요. 그래서 IP 로는 \"어느 도시쯤\" 이상을 알 수 없어요.", 1)
            }
        },

        online("geo_my_ip", G, "내 공인 IP와 대략적인 위치", "지금 인터넷에서 보이는 내 IP 와 위치·통신사 (VPN·모바일 데이터를 켠 상태도 확인)", note = SENT_ME) { _, host, env ->
            env.progress("제공처 5곳에 묻는 중...")
            val rs = GeoNet.lookupAll(GeoProviders.DEFAULT, "")
            val ip = rs.firstNotNullOfOrNull { it.ip }
            val c = GeoMerge.merge(rs) ?: return@online result { header("제공처", "결과"); for (r in rs) row(r.provider, r.error ?: "-", level = 1); note("위치를 얻지 못했어요. 인터넷 연결을 확인하세요.", 2) }
            result {
                kv("내 공인 IP", ip ?: "-", -1)
                host.lanIp()?.let { kv("Wi-Fi 안의 내 IP", it.first) }
                renderConsensus(this, c, rs, db(host), ip?.let { IpUtil.parse(it) })
            }
        },

        online("geo_batch", G, "IP 여러 개 위치 일괄 조회 (최대 20개)", "IP 목록의 대략적인 위치·통신사를 표로 (제공처 1~2곳에 하나씩 물어요)",
            multi("ips", "IP 목록 (한 줄에 하나)", "예: 8.8.8.8", "8.8.8.8\n1.1.1.1\n168.126.63.1"), note = "입력한 IP 하나하나를 위치 제공처(ipwho.is, 실패하면 ipapi.is)에 보내 조회해요. 인터넷을 사용해요.") { i, _, env ->
            val ips = IpText.extract(i.raw("ips")).filter { IpUtil.classify(it) == IpKind.PUBLIC }.distinctBy { IpUtil.format(it) }.take(20)
            if (ips.isEmpty()) return@online need("공인 IP 를 한 줄에 하나씩 입력하세요")
            val rows = ArrayList<Pair<String, GeoResult>>()
            for ((k, a) in ips.withIndex()) {
                if (env.cancel.get()) break
                env.progress("${k + 1} / ${ips.size} 조회 중...")
                var r = GeoNet.lookup(GeoProviders.IPWHO, IpUtil.format(a)); if (!r.ok) r = GeoNet.lookup(GeoProviders.IPAPI_IS, IpUtil.format(a))
                rows += IpUtil.format(a) to r; if (k < ips.size - 1) Thread.sleep(150)
            }
            result {
                header("IP", "위치", "통신사")
                for ((ip, r) in rows) if (r.ok) row(ip, r.place, r.org ?: "") else row(ip, r.error ?: "-", "", level = 1)
                note("제공처 한 곳의 답이라 틀릴 수 있어요. 한 IP 를 정확히 보려면 'IP 위치 조회(여러 제공처 합의)'를 쓰세요. $ACCURACY", 1)
            }
        },

        online("geo_distance", G, "두 IP 사이의 대략적인 거리", "두 IP 의 위치를 조회해 직선거리(km)와 빛의 속도로 본 최소 왕복 시간을 계산 — 핑이 왜 느린지 짐작할 때",
            ipField("a", "첫째 IP", "8.8.8.8"), ipField("b", "둘째 IP", "168.126.63.1"), note = SENT) { i, _, env ->
            val a = IpUtil.parse(i.str("a")) ?: return@online fail("첫째 IP 를 읽지 못했어요"); val b = IpUtil.parse(i.str("b")) ?: return@online fail("둘째 IP 를 읽지 못했어요")
            notPublic(a)?.let { return@online fail("첫째 IP: $it") }; notPublic(b)?.let { return@online fail("둘째 IP: $it") }
            env.progress("두 IP 의 위치를 묻는 중...")
            val ca = GeoMerge.merge(GeoNet.lookupAll(GeoProviders.DEFAULT, IpUtil.format(a))); val cb = GeoMerge.merge(GeoNet.lookupAll(GeoProviders.DEFAULT, IpUtil.format(b)))
            if (ca?.lat == null || cb?.lat == null) return@online fail("위치(좌표)를 얻지 못했어요")
            val km = Geo.distanceKm(ca.lat, ca.lon!!, cb.lat, cb.lon!!)
            result {
                kv("첫째", "${ca.city ?: "-"}, ${CountryNames.ko(ca.countryCode)}"); kv("둘째", "${cb.city ?: "-"}, ${CountryNames.ko(cb.countryCode)}")
                kv("직선거리", "${"%.0f".format(km)} km  (${"%.0f".format(km / 1.609344)} mi)"); kv("방향", "첫째에서 둘째 쪽: ${Geo.compass(Geo.bearing(ca.lat, ca.lon, cb.lat, cb.lon))}쪽")
                kv("이론상 최소 왕복 시간", "약 ${"%.1f".format(Geo.minRttMs(km))} ms")
                note("실제 핑은 광섬유가 직선이 아니라서 보통 이론값의 1.5~3배예요. 위치가 수십~수백 km 틀릴 수 있어서 거리도 대략적인 값이에요. $ACCURACY", 1)
            }
        },

        online("geo_timezone", G, "IP 의 시간대·현지 시각", "IP 가 있는 곳의 시간대와 지금 현지 시각, 내 폰과의 시차", ipField(), note = SENT) { i, _, env ->
            val (a, err) = readIp(i); if (a == null) return@online err!!
            notPublic(a)?.let { return@online fail(it) }
            env.progress("제공처에 묻는 중...")
            val c = GeoMerge.merge(GeoNet.lookupAll(GeoProviders.DEFAULT, IpUtil.format(a))) ?: return@online fail("시간대를 얻지 못했어요")
            val tz = c.timezone ?: return@online fail("제공처가 시간대를 알려 주지 않았어요")
            val zone = try { ZoneId.of(tz) } catch (_: Exception) { return@online fail("알 수 없는 시간대예요: $tz") }
            val now = ZonedDateTime.now(zone); val mine = ZonedDateTime.now(ZoneId.systemDefault())
            val diff = (now.offset.totalSeconds - mine.offset.totalSeconds) / 3600.0
            result {
                kv("IP", IpUtil.format(a)); kv("시간대", tz); kv("현지 시각", fmtDate(now) + "  (UTC${now.offset.id.replace("Z", "+00:00")})"); kv("내 폰 시각", fmtDate(mine) + "  (${ZoneId.systemDefault()})")
                kv("시차", if (diff == 0.0) "같은 시간대" else "${if (diff > 0) "+" else ""}${"%.1f".format(diff).removeSuffix(".0")}시간 (그곳이 ${if (diff > 0) "앞서요" else "늦어요"})")
                note(ACCURACY, 1)
            }
        },

        online("geo_vpn_check", G, "VPN·프록시·데이터센터 IP 점검", "IP 가 VPN·프록시·Tor·데이터센터로 알려져 있는지 (로그인 이상 접속·사기 점검용)", ipField(),
            note = "입력한 IP 를 ipapi.is·ip-api.com(http)에 보내고, Tor 프로젝트의 출구 노드 목록(공개 목록)을 받아 비교해요. 인터넷을 사용해요.") { i, host, env ->
            val (a, err) = readIp(i); if (a == null) return@online err!!
            notPublic(a)?.let { return@online fail(it) }
            val ip = IpUtil.format(a)
            env.progress("조회 중...")
            val jobs = Par.map(listOf("is", "api", "tor"), 3, 12000) { k ->
                when (k) { "is" -> GeoNet.lookup(GeoProviders.IPAPI_IS, ip) as Any; "api" -> GeoNet.lookup(GeoProviders.IPAPI_COM, ip) as Any; else -> runCatching { ip in TorList.parse(GeoNet.get("https://check.torproject.org/torbulkexitlist", 8000, 1_000_000)) }.getOrNull() ?: "?" }
            }
            val isR = jobs[0] as? GeoResult; val apiR = jobs[1] as? GeoResult; val tor = jobs[2] as? Boolean
            val org = db(host)?.lookup(a)?.asn?.name ?: isR?.org ?: apiR?.org; val cloud = CloudDetect.label(org)
            val signals = ArrayList<String>()
            if (isR?.vpn == true) signals += "VPN 으로 알려진 주소 (ipapi.is)"; if (isR?.proxy == true || apiR?.proxy == true) signals += "프록시로 알려진 주소"; if (isR?.tor == true || tor == true) signals += "Tor 출구 노드"
            if (isR?.hosting == true || apiR?.hosting == true) signals += "데이터센터·호스팅 주소"; if (isR?.abuser == true) signals += "악용 신고가 많은 주소 (ipapi.is)"; if (cloud != null) signals += "클라우드 업체 이름과 일치: $cloud"
            result {
                kv("IP", ip); kv("통신사", org ?: "-")
                header("점검", "결과")
                row("ipapi.is", if (isR?.ok == true || isR?.error == null) "VPN ${yn(isR?.vpn)} · 프록시 ${yn(isR?.proxy)} · Tor ${yn(isR?.tor)} · 데이터센터 ${yn(isR?.hosting)}" else (isR?.error ?: "응답 없음"), level = if (isR?.error != null) 1 else 0)
                row("ip-api.com", if (apiR?.error == null) "프록시 ${yn(apiR?.proxy)} · 호스팅 ${yn(apiR?.hosting)} · 모바일망 ${yn(apiR?.mobile)}" else (apiR?.error ?: "응답 없음"), level = if (apiR?.error != null) 1 else 0)
                row("Tor 출구 목록", when (tor) { true -> "목록에 있어요"; false -> "목록에 없어요"; null -> "목록을 받지 못했어요" }, level = if (tor == true) 2 else 0)
                head("판정")
                if (signals.isEmpty()) note("VPN·프록시·데이터센터로 알려진 신호가 없어요 (일반 회선으로 보여요). 목록에 없는 VPN 도 있어서 \"아니다\"를 보장하지는 않아요.", -1)
                else { for (s in signals) note(s, 1); note("${signals.size}가지 신호가 있어요. 로그인 보호 등에서는 추가 인증을 요구하는 정도로 쓰고, 이것만으로 사람을 판단하지는 마세요.", 1) }
            }
        },

        online("geo_tor_check", G, "Tor 출구 노드인지 확인", "IP 가 Tor 네트워크의 출구 노드 목록에 있는지 (Tor 프로젝트의 공개 목록과 비교)", ipField(),
            note = "Tor 프로젝트의 공개 출구 노드 목록(check.torproject.org)을 받아서 폰 안에서 비교해요. 입력한 IP 는 보내지 않아요.") { i, _, env ->
            val (a, err) = readIp(i); if (a == null) return@online err!!
            env.progress("출구 노드 목록 받는 중...")
            val list = try { TorList.parse(GeoNet.get("https://check.torproject.org/torbulkexitlist", 9000, 2_000_000)) } catch (e: IOException) { return@online fail("목록을 받지 못했어요: ${e.message}") }
            val hit = IpUtil.format(a) in list
            result { kv("IP", IpUtil.format(a)); kv("출구 노드 수(지금 목록)", "${list.size}개"); kv("결과", if (hit) "Tor 출구 노드예요" else "목록에 없어요", if (hit) 1 else -1)
                note(if (hit) "이 주소에서 오는 접속은 Tor 브라우저 사용자가 익명으로 접속한 것일 수 있어요." else "지금 목록에 없다고 해서 Tor 를 안 쓴다는 보장은 아니에요 (다리(bridge)·입구 노드는 목록에 없어요).") }
        },

        online("geo_dnsbl", G, "스팸·악성 IP 목록(DNSBL) 점검", "메일 서버·내 IP 가 스팸·악성 목록(Spamhaus·SpamCop 등 7곳)에 올라 있는지", DnsTools.serverField(), ipField(def = "127.0.0.2", label = "IPv4 주소 (127.0.0.2 는 시험용: 항상 \"있음\"으로 나와요)"),
            note = "조회할 IP 를 거꾸로 쓴 이름을 각 목록의 DNS 서버에 물어요(예: 2.0.0.127.zen.spamhaus.org). 공용 DNS(8.8.8.8 등)로는 Spamhaus 가 거절할 수 있어요.") { i, host, env ->
            val a = IpUtil.parse(i.str("ip")) ?: return@online if (i.str("ip").isEmpty()) need("IPv4 주소를 입력하세요") else fail("IP 주소를 읽지 못했어요")
            if (a.address.size != 4) return@online fail("IPv4 주소만 점검해요")
            val servers = DnsTools.servers(i, host); val rev = Dnsbl.reverseV4(IpUtil.format(a))
            env.progress("목록 ${Dnsbl.ZONES.size}곳에 묻는 중...")
            val res = Par.map(Dnsbl.ZONES, 7, 14000) { z ->
                try { val r = DnsTools.ask(servers, "$rev.${z.zone}", DnsType.A, host, timeoutMs = 3500); Dnsbl.interpret(z.zone, r.msg.answers.filter { it.type == DnsType.A }.map { it.data }) }
                catch (e: IOException) { 0 to "조회하지 못했어요 (${e.message})" }
            }
            result {
                kv("IP", IpUtil.format(a)); kv("사용한 DNS", servers.first())
                header("목록", "결과", "설명")
                var listed = 0
                Dnsbl.ZONES.forEachIndexed { k, z -> val (lv, msg) = res[k] ?: (0 to "응답 없음"); if (lv == 2) listed++; row(z.label, when (lv) { 2 -> "올라 있음"; -1 -> "깨끗함"; else -> "판정 불가" }, msg, level = lv) }
                head("판정")
                if (listed > 0) note("${listed}곳에 올라 있어요. 이 주소로 메일을 보내면 스팸으로 분류될 수 있어요. 각 목록 사이트에서 삭제를 요청할 수 있어요.", 2)
                else note("조회된 목록 중에는 올라 있지 않아요 (판정 불가인 곳은 제외).", -1)
            }
        },

        online("geo_rdap", G, "IP 등록 정보 (RDAP)", "IP 가 속한 주소 블록의 범위·이름·종류·소유 기관·신고 접수 연락처 — 등록 기관(RIR)의 공식 조회",
            ipField(), note = "입력한 IP 를 rdap.org 로 보내 담당 등록 기관(ARIN·RIPE·APNIC·KRNIC 등)의 RDAP 서버로 연결돼요. 인터넷을 사용해요.") { i, _, env ->
            val (a, err) = readIp(i); if (a == null) return@online err!!
            notPublic(a)?.let { return@online fail(it) }
            env.progress("등록 정보를 받는 중...")
            val r = try { Rdap.parseIp(GeoNet.get("https://rdap.org/ip/${IpUtil.format(a)}", 9000, 600_000, mapOf("Accept" to "application/rdap+json, application/json"))) } catch (e: IOException) { return@online fail("조회하지 못했어요: ${e.message}") } catch (e: org.json.JSONException) { return@online fail("응답을 읽지 못했어요") }
            result {
                kv("IP", IpUtil.format(a)); r.name?.let { kv("블록 이름", it) }; r.handle?.let { kv("등록 번호", it) }
                if (r.start != null) kv("범위", "${r.start} ~ ${r.end}"); if (r.cidrs.isNotEmpty()) kv("CIDR", r.cidrs.joinToString(", "))
                r.type?.let { kv("종류", it) }; r.country?.let { kv("나라(등록)", CountryNames.label(it)) }
                r.org?.let { kv("소유 기관", it) }; r.abuse?.let { kv("신고 접수(기관 연락처)", it) }
                if (r.status.isNotEmpty()) kv("상태", r.status.joinToString(", ")); r.changed?.let { kv("마지막 변경", it.take(10)) }
                note("이 정보는 \"주소 블록을 관리하는 기관\"이에요. 이 IP 를 쓰는 사람의 이름·위치를 알려 주지 않아요. 개인 명의로 등록된 항목은 표시하지 않아요.")
            }
        },

        online("geo_asn_routes", G, "ASN 이 알리는 IP 대역 (실시간 라우팅)", "ASN 이 지금 인터넷에 광고하는 IPv4·IPv6 대역 목록 (RIPEstat 공개 자료)",
            text("asn", "ASN 번호", "예: 4766 또는 AS4766", "4766", listOf("KT" to "4766", "구글" to "15169", "클라우드플레어" to "13335")), note = "ASN 번호를 RIPEstat(stat.ripe.net)에 보내 조회해요. 인터넷을 사용해요.") { i, host, env ->
            val n = i.str("asn").removePrefix("AS").removePrefix("as").trim().toIntOrNull() ?: return@online if (i.str("asn").isEmpty()) need("ASN 번호를 입력하세요") else fail("ASN 은 숫자예요")
            env.progress("라우팅 정보를 받는 중...")
            val pre = try { Rdap.parsePrefixes(GeoNet.get("https://stat.ripe.net/data/announced-prefixes/data.json?resource=AS$n", 12000, 4_000_000)) } catch (e: IOException) { return@online fail("조회하지 못했어요: ${e.message}") } catch (e: org.json.JSONException) { return@online fail("응답을 읽지 못했어요") }
            val v4 = pre.filter { ':' !in it }; val v6 = pre.filter { ':' in it }
            result {
                kv("ASN", "AS$n" + (db(host)?.asnName(n)?.let { "  $it" } ?: "")); kv("광고 중인 대역", "IPv4 ${v4.size}개 · IPv6 ${v6.size}개")
                if (pre.isEmpty()) note("광고 중인 대역이 없어요 (사용하지 않는 ASN 이거나 번호가 틀렸어요).", 1)
                else { block((v4.take(150) + v6.take(50)).joinToString("\n")); if (pre.size > 200) note("앞 200개만 보여요.", 1) }
            }
        },

        // ===== 도메인·URL·메일 서버의 IP 와 위치 (DNS 와 폰 안의 자료로: 위치 제공처에는 묻지 않음)
        online("geo_domain_server", G, "웹사이트 서버는 어디에 있나요?", "도메인의 서버 IP 와 그 IP 가 있는 나라·통신사(클라우드) — DNS 와 폰 안의 자료로 알아봐요",
            DnsTools.domainField("naver.com"), DnsTools.serverField(), note = "입력한 도메인을 DNS 서버에 물어요. 나라·통신사는 폰 안의 자료로 찾아서 IP 를 따로 보내지 않아요.") { i, host, env ->
            val d = HostInput.host(i.str("d")); if (d.isEmpty()) return@online need("도메인을 입력하세요")
            val servers = DnsTools.servers(i, host); env.progress("IP 를 찾는 중...")
            val recs = ArrayList<DnsRecord>(); var cname: List<String> = emptyList()
            for (t in listOf(DnsType.A, DnsType.AAAA)) try { val r = DnsTools.ask(servers, d, t, host); recs += r.msg.answers.filter { it.type == t }; cname = cname + r.msg.answers.filter { it.type == DnsType.CNAME }.map { "${it.name} → ${it.data}" } } catch (_: IOException) {}
            if (recs.isEmpty()) return@online fail("\"$d\" 의 IP 를 찾지 못했어요 (없는 도메인이거나 DNS 문제예요)")
            val db = db(host)
            result {
                kv("도메인", d); cname.distinct().forEach { kv("별칭(CNAME)", it) }
                header("IP", "나라", "통신사 · 종류")
                for (r in recs.distinctBy { it.data }) { val g = db?.let { x -> IpUtil.parse(r.data)?.let { a -> x.lookup(a) } }; row(r.data, g?.countryLabel ?: "-", (g?.orgLabel ?: "-") + (CloudDetect.label(g?.asn?.name)?.let { " · $it" } ?: "")) }
                val countries = recs.mapNotNull { r -> IpUtil.parse(r.data)?.let { db?.country(it) } }.distinct()
                if (countries.size > 1) note("서버가 여러 나라(${countries.joinToString { CountryNames.ko(it) }})에 걸쳐 있어요. CDN 이거나 지역별로 다른 서버로 연결해 주는 구성이에요.")
                note("CDN(클라우드플레어 등) 뒤에 있으면 실제 서버가 아니라 CDN 의 주소가 보여요. 서버의 진짜 위치를 뜻하지는 않아요.")
            }
        },

        online("geo_domain_ips", G, "도메인의 모든 IP (여러 DNS 로 비교)", "내 DNS·구글·클라우드플레어·Quad9·OpenDNS 5곳에 물어 나온 IP 를 모두 모아서 (지역별로 다른 서버를 알려 주는지)",
            DnsTools.domainField("google.com"), note = "도메인을 DNS 서버 5곳(내 DNS, 8.8.8.8, 1.1.1.1, 9.9.9.9, 208.67.222.222)에 물어요. 나라·통신사는 폰 안의 자료로 찾아요.") { i, host, env ->
            val d = HostInput.host(i.str("d")); if (d.isEmpty()) return@online need("도메인을 입력하세요")
            val sv = listOf((host.dnsServers().firstOrNull() ?: "8.8.8.8") to "내 DNS") + publicResolvers
            env.progress("DNS 서버 5곳에 묻는 중...")
            val tasks = sv.flatMap { s -> listOf(DnsType.A, DnsType.AAAA).map { s to it } }
            val res = Par.map(tasks, 8, 14000) { (s, t) -> s.second to runCatching { DnsTools.ask(listOf(s.first), d, t, host, timeoutMs = 3000).msg.answers.filter { it.type == t }.map { it.data } }.getOrDefault(emptyList()) }
            val who = LinkedHashMap<String, MutableList<String>>()
            for (r in res) if (r != null) for (ip in r.second) who.getOrPut(ip) { ArrayList() }.let { if (r.first !in it) it += r.first }
            if (who.isEmpty()) return@online fail("IP 를 찾지 못했어요")
            val db = db(host)
            result {
                kv("도메인", d); kv("찾은 IP", "${who.size}개")
                header("IP", "나라 · 통신사", "알려 준 DNS")
                for ((ip, by) in who) { val g = db?.lookup(ip); row(ip, if (g == null) "-" else "${CountryNames.ko(g.country)} · ${g.asn?.name ?: "-"}", by.joinToString(", ")) }
                if (who.values.any { it.size < sv.size } && who.size > 1) note("DNS 마다 다른 IP 를 알려 줬어요. 사용자 위치에 가까운 서버로 연결해 주는 방식(지역 DNS)이거나, 주소가 돌아가며 나오는 라운드 로빈이에요.")
            }
        },

        online("geo_url_hops", G, "링크가 거치는 서버들의 IP·나라", "짧은 주소·광고 링크가 어느 서버를 거쳐 어디로 가는지 — 단계마다 서버 IP 와 나라·통신사", text("u", "주소 (URL)", "예: http://github.com", "http://github.com", listOf("github.com" to "http://github.com", "example.com" to "http://example.com")),
            note = "그 주소에 웹 요청(GET)을 보내 이동 경로를 따라가요(최대 8번). 나라·통신사는 폰 안의 자료로 찾아요. 의심스러운 링크는 열어서 로그인 정보를 입력하지 마세요.") { i, host, env ->
            val u = i.str("u"); if (u.isEmpty()) return@online need("주소를 입력하세요")
            val chain = try { MiniHttp.follow(u, 8) { n, c -> env.progress("$n 번째: $c") } } catch (e: IOException) { return@online fail("접속하지 못했어요: ${e.message}") }
            val db = db(host)
            result {
                header("단계", "주소", "서버 IP", "나라 · 통신사")
                chain.forEachIndexed { k, c -> val g = db?.lookup(c.remoteIp); row("${k + 1}", c.url, c.remoteIp, if (g == null) "-" else "${CountryNames.ko(g.country)} · ${g.asn?.name ?: "-"}") }
                val ips = chain.map { it.remoteIp }.distinct(); kv("거친 서버", "${ips.size}곳"); kv("최종 주소", chain.last().url)
                if (chain.last().isRedirect) note("이동이 너무 많아 중간에 멈췄어요 (반복일 수 있어요).", 1)
            }
        },

        online("geo_mail_servers", G, "메일 서버(MX)의 IP·나라·통신사", "도메인의 메일을 받는 서버(MX)와 그 IP, 어느 나라·어느 회사(구글·마이크로소프트 등)인지", DnsTools.domainField("naver.com"), DnsTools.serverField(),
            note = "도메인의 MX 레코드와 서버 주소를 DNS 에 물어요. 나라·통신사는 폰 안의 자료로 찾아요.") { i, host, env ->
            val d = HostInput.host(i.str("d")); if (d.isEmpty()) return@online need("도메인을 입력하세요")
            val servers = DnsTools.servers(i, host); env.progress("MX 를 찾는 중...")
            val mx = try { DnsTools.ask(servers, d, DnsType.MX, host).msg.answers.filter { it.type == DnsType.MX }.map { it.data.substringBefore(' ').toInt() to it.data.substringAfter(' ').trimEnd('.') }.sortedBy { it.first } } catch (e: IOException) { return@online fail("조회하지 못했어요: ${e.message}") }
            if (mx.isEmpty()) return@online result { kv("도메인", d); note("MX 레코드가 없어요. 이 도메인은 메일을 받지 않거나 A 레코드로 받아요.", 1) }
            val db = db(host)
            val ips = Par.map(mx, 6, 12000) { (_, h) -> runCatching { DnsTools.ask(servers, h, DnsType.A, host, timeoutMs = 3000).msg.answers.firstOrNull { it.type == DnsType.A }?.data }.getOrNull() }
            result {
                kv("도메인", d); header("우선순위", "메일 서버", "IP", "나라 · 통신사")
                mx.forEachIndexed { k, (p, h) -> val ip = ips[k]; val g = ip?.let { db?.lookup(it) }; row("$p", h, ip ?: "-", if (g == null) "-" else "${CountryNames.ko(g.country)} · ${g.asn?.name ?: "-"}" + (CloudDetect.label(g.asn?.name)?.let { " · $it" } ?: "")) }
                note("우선순위 숫자가 작은 서버가 먼저 받아요. 구글·마이크로소프트 같은 클라우드 메일이면 회사 메일을 그곳이 맡고 있다는 뜻이에요.")
            }
        },

        online("geo_traceroute", G, "경로 추적 + 구간별 나라·통신사", "목적지까지 가는 길의 각 장비가 어느 나라·어느 통신사인지 — 해외로 돌아가는지, 어디서 느려지는지", DnsTools.domainField("www.google.com", "목적지 (도메인 또는 IP)"), choice("max", "최대 홉", listOf("15", "20", "30"), "20"),
            note = "TTL 을 1부터 늘려 가며 기기의 ping 으로 경로를 알아내요(시간이 걸려요). 나라·통신사는 폰 안의 자료로 찾아요.") { i, host, env ->
            val h = HostInput.host(i.str("d")); if (h.isEmpty()) return@online need("목적지를 입력하세요")
            val dest = try { TlsInspect.resolve(h) } catch (_: Exception) { return@online fail("\"$h\" 의 주소를 찾지 못했어요") }
            val hops = Trace.run(IpUtil.format(dest), i.str("max").toInt(), env.cancel) { env.progress(it) }
            val db = db(host)
            result {
                kv("목적지", "$h (${IpUtil.format(dest)})"); header("홉", "주소", "시간", "나라 · 통신사")
                var prev: String? = null; val path = ArrayList<String>()
                for (hp in hops) { val g = hp.ip?.let { ip -> if (IpUtil.parse(ip)?.let { IpUtil.classify(it) } == IpKind.PUBLIC) db?.lookup(ip) else null }
                    val loc = when { hp.ip == null -> "-"; g != null -> "${CountryNames.ko(g.country)} · ${g.asn?.name ?: "-"}"; else -> IpUtil.parse(hp.ip)?.let { IpUtil.classify(it).label.substringBefore(" (") } ?: "-" }
                    row("${hp.ttl}", hp.ip ?: "*", hp.ms?.let { "%.0f ms".format(it) } ?: "응답 없음", loc, level = if (hp.ip == null) 1 else 0)
                    g?.country?.let { c -> if (c != prev) { path += c; prev = c } } }
                if (path.isNotEmpty()) kv("지나간 나라", path.joinToString(" → ") { CountryNames.ko(it) })
                note("'*' 는 그 장비가 응답하지 않는다는 뜻(정상인 경우가 많아요). 사설 주소는 통신사 내부 장비라 나라를 알 수 없어요. 나라는 주소 블록 기준이라 실제 장비 위치와 다를 수 있어요.")
            }
        },

        tool("geo_email_header", G, "이메일 헤더에서 IP·경로 찾기", "받은 메일의 전체 헤더를 붙여 넣으면 메일이 거쳐 온 서버와 IP, 서버마다 걸린 시간, SPF·DKIM·DMARC 결과를 정리 (피싱·스팸 점검)",
            listOf(multi("h", "메일 전체 헤더", "Gmail: 메일 열기 → ⋮ → \"원본 보기\"에서 복사", "Received: from mail-wm1-f45.google.com (mail-wm1-f45.google.com [209.85.128.45])\n by mx.example.net (Postfix) with ESMTPS id 4F2D1A0123\n for <me@example.net>; Tue, 14 Nov 2023 10:00:05 +0900 (KST)\nReceived: by mail-wm1-f45.google.com with SMTP id 5b1f17b1804b1-40a4a4d3a14so1234567f8f.0\n for <me@example.net>; Mon, 13 Nov 2023 17:00:00 -0800 (PST)\nReceived: from [10.0.0.5] (unknown [203.0.113.77])\n by smtp.gmail.com with ESMTPSA id abc; Mon, 13 Nov 2023 16:59:58 -0800 (PST)\nAuthentication-Results: mx.example.net; spf=pass smtp.mailfrom=sender@gmail.com; dkim=pass header.d=gmail.com; dmarc=pass header.from=gmail.com\nReturn-Path: <sender@gmail.com>\nFrom: Sender <sender@gmail.com>\nX-Originating-IP: [203.0.113.77]\nSubject: hello")), ToolMode.OFFLINE,
            "붙여 넣은 헤더를 폰 안에서만 읽어요. 어디로도 보내지 않아요. (헤더에 적힌 것만 알 수 있어요)") { i, host, _ ->
            val fields = EmailHeader.fields(i.raw("h")); if (fields.isEmpty()) return@tool need("메일의 전체 헤더를 붙여 넣으세요 (Received: 줄들이 있어야 경로를 볼 수 있어요)")
            val hops = EmailHeader.hops(fields); val auth = EmailHeader.authResults(fields); val hints = EmailHeader.hintIps(fields); val db = db(host)
            fun loc(ip: String?): String { if (ip == null) return "-"; val a = IpUtil.parse(ip) ?: return "-"; val k = IpUtil.classify(a); if (k != IpKind.PUBLIC) return k.label.substringBefore(" ("); val g = db?.lookup(a); return if (g == null) "-" else "${CountryNames.ko(g.country)} · ${g.asn?.name ?: "-"}" }
            result {
                fields.firstOrNull { it.first.equals("From", true) }?.let { kv("보낸 사람(From)", it.second) }; fields.firstOrNull { it.first.equals("Return-Path", true) }?.let { kv("반송 주소(Return-Path)", it.second) }
                fields.firstOrNull { it.first.equals("Reply-To", true) }?.let { kv("답장 주소(Reply-To)", it.second) }; fields.firstOrNull { it.first.equals("Subject", true) }?.let { kv("제목", it.second.take(100)) }
                if (hops.isEmpty()) note("Received 줄이 없어요. 메일의 \"전체 헤더(원본)\"를 붙여 넣어야 경로를 알 수 있어요.", 1)
                else {
                    head("메일이 거쳐 온 서버 (처음 → 받는 쪽)"); header("순서", "서버 · IP", "나라 · 통신사", "걸린 시간")
                    for (h in hops) row("${h.no}", (h.from ?: "-") + (h.ip?.let { "  $it" } ?: ""), loc(h.ip), h.delaySec?.let { d -> if (d < 0) "시계 차이" else if (d < 120) "${d}초" else "${d / 60}분" } ?: "-", level = if ((h.delaySec ?: 0) > 3600) 1 else 0)
                    val firstPublic = hops.firstOrNull { h -> h.ip?.let { IpUtil.parse(it)?.let { a -> IpUtil.classify(a) == IpKind.PUBLIC } } == true }
                    firstPublic?.let { kv("처음 공인 IP 서버", "${it.ip}  (${loc(it.ip)})") }
                    if (hops.any { (it.delaySec ?: 0) > 3600 }) note("한 구간에서 1시간 넘게 걸렸어요. 메일 서버 지연이거나 스팸 필터가 오래 붙잡아 둔 것일 수 있어요.", 1)
                }
                if (hints.isNotEmpty()) { head("헤더에 따로 적힌 IP"); for ((n, ip) in hints) kv(n, "$ip  (${loc(ip)})") }
                head("인증 결과")
                if (auth.isEmpty()) note("SPF·DKIM·DMARC 결과 줄(Authentication-Results)이 없어요.", 1)
                else for ((k, v) in auth) kv(k.uppercase(), v, if (v == "pass") -1 else if (v in listOf("none", "neutral", "softfail", "temperror")) 1 else 2)
                val from = EmailHeader.domainOf(fields.firstOrNull { it.first.equals("From", true) }?.second); val rp = EmailHeader.domainOf(fields.firstOrNull { it.first.equals("Return-Path", true) }?.second)
                val reply = EmailHeader.domainOf(fields.firstOrNull { it.first.equals("Reply-To", true) }?.second)
                if (from != null && rp != null && EmailHeader.baseDomain(from) != EmailHeader.baseDomain(rp)) note("보낸 사람($from)과 반송 주소($rp)의 도메인이 달라요. 대량 메일 서비스를 쓰면 흔하지만, 주소를 속인 메일일 수도 있어요.", 1)
                if (from != null && reply != null && EmailHeader.baseDomain(from) != EmailHeader.baseDomain(reply)) note("답장 주소($reply)가 보낸 사람 도메인($from)과 달라요. 답장하면 다른 곳으로 가요 — 피싱에서 자주 쓰는 방식이에요.", 1)
                if (auth["spf"] == "fail" || auth["dkim"] == "fail" || auth["dmarc"] == "fail") note("인증에 실패한 항목이 있어요. 보낸 사람을 사칭한 메일일 가능성이 있으니 링크·첨부를 열지 마세요.", 2)
                note("헤더 윗줄일수록 최근(받는 쪽) 서버예요. 가장 아랫줄(처음 서버)의 IP 가 보낸 쪽에 가장 가깝지만, 웹메일(Gmail 등)은 사용자의 IP 를 숨기고 서비스 서버 IP 만 보여 줘요.")
            }
        },

        // ===== 내 IP 알아내기 (여러 방법)
        online("geo_my_ip_multi", G, "내 공인 IP 여러 곳에서 확인", "서로 다른 5개 서비스가 보는 내 IP 를 비교 — VPN·프록시·이중 회선·통신사 NAT 진단", note = "공개 IP 확인 서비스 5곳(ipify·icanhazip·ifconfig.me·checkip.amazonaws.com·ident.me)에 접속해요. 내 IP 는 어차피 접속하는 서버에 보이는 값이에요.") { _, host, env ->
            val sv = listOf("ipify" to "https://api.ipify.org", "icanhazip" to "https://icanhazip.com", "ifconfig.me" to "https://ifconfig.me/ip", "AWS checkip" to "https://checkip.amazonaws.com", "ident.me" to "https://ident.me")
            env.progress("5곳에 묻는 중...")
            val res = Par.map(sv, 5, 12000) { (n, u) -> n to runCatching { GeoNet.get(u, 6000, 256).trim().lineSequence().first().trim() }.getOrElse { "!" + (it.message ?: "실패") } }
            val got = sv.mapIndexed { k, s -> s.first to (res[k]?.second ?: "!응답 없음") }
            val ok = got.filter { !it.second.startsWith("!") && IpUtil.parse(it.second) != null }
            if (ok.isEmpty()) return@online fail("내 IP 를 확인하지 못했어요. 인터넷 연결을 확인하세요")
            val distinct = ok.map { it.second }.distinct(); val db = db(host)
            result {
                header("서비스", "보이는 내 IP", "나라 · 통신사")
                for ((n, v) in got) if (v.startsWith("!")) row(n, v.drop(1), "", level = 1) else { val g = db?.lookup(v); row(n, v, if (g == null) "-" else "${CountryNames.ko(g.country)} · ${g.asn?.name ?: "-"}") }
                if (distinct.size == 1) { kv("내 공인 IP", distinct[0], -1); note("모든 서비스가 같은 IP 를 봐요.", -1) }
                else { kv("서로 다른 IP", "${distinct.size}개: ${distinct.joinToString()}", 1); note("서비스마다 다른 IP 가 보여요. VPN·프록시를 일부 앱에만 적용했거나(분할 터널), 회선이 둘이라 번갈아 나가거나, IPv4·IPv6 를 섞어서 보는 경우예요.", 1) }
                host.lanIp()?.let { (ip, _) -> if (ip in distinct) note("Wi-Fi 안의 내 IP 가 공인 IP 와 같아요: 공유기 없이 인터넷에 직접 연결된 상태예요.") }
            }
        },

        online("geo_my_ip_dns", G, "DNS 로 내 공인 IP 알아내기 + DNS 누수 점검", "웹이 아니라 DNS 질문으로 내 IP 를 알아내고, 내 DNS 서버가 어느 회사 것인지 확인 (VPN 을 켰는데 DNS 가 새는지)",
            note = "OpenDNS(myip.opendns.com)·구글(o-o.myaddr.l.google.com)·아카마이(whoami.akamai.net)에 DNS 질문을 보내요. 질문 내용은 특별한 이름일 뿐 내 정보가 담기지 않아요.") { _, host, env ->
            val sys = host.dnsServers().ifEmpty { listOf("8.8.8.8") }
            data class Q(val label: String, val server: List<String>, val name: String, val type: Int, val meaning: String)
            val qs = listOf(
                Q("OpenDNS 에 직접 물음", listOf(myIpDnsServers.first), "myip.opendns.com", DnsType.A, "me"),
                Q("구글 DNS 서버에 직접 물음", listOf(myIpDnsServers.second), "o-o.myaddr.l.google.com", DnsType.TXT, "me"),
                Q("내 DNS 를 거쳐 구글에 물음", sys, "o-o.myaddr.l.google.com", DnsType.TXT, "resolver"),
                Q("내 DNS 를 거쳐 아카마이에 물음", sys, "whoami.akamai.net", DnsType.A, "resolver"),
            )
            env.progress("DNS 질문 4개를 보내는 중...")
            val res = Par.map(qs, 4, 12000) { q -> runCatching { val r = DnsTools.ask(q.server, q.name, q.type, host, timeoutMs = 3500); r.msg.answers.filter { it.type == q.type }.flatMap { rec -> if (q.type == DnsType.TXT) IpText.extract(rec.text ?: "").map { IpUtil.format(it) } else listOf(rec.data) }.distinct() }.getOrNull() }
            val db = db(host)
            result {
                kv("내가 쓰는 DNS", sys.joinToString(", ")); header("방법", "알아낸 IP", "나라 · 통신사")
                qs.forEachIndexed { k, q -> val ips = res[k]; if (ips.isNullOrEmpty()) row(q.label, "응답 없음", "", level = 1) else for (ip in ips) { val g = db?.lookup(ip); row(q.label, ip, if (g == null) "-" else "${CountryNames.ko(g.country)} · ${g.asn?.name ?: "-"}") } }
                val mine = qs.indices.filter { qs[it].meaning == "me" }.flatMap { res[it].orEmpty() }.distinct(); val resolver = qs.indices.filter { qs[it].meaning == "resolver" }.flatMap { res[it].orEmpty() }.distinct()
                if (mine.isNotEmpty()) { head("내 공인 IP"); kv("DNS 로 알아낸 내 IP", mine.joinToString()) }
                if (resolver.isNotEmpty()) { head("내 DNS 서버가 인터넷에 나가는 주소"); kv("DNS 서버의 공인 IP", resolver.joinToString()); val org = resolver.firstNotNullOfOrNull { ip -> db?.lookup(ip)?.asn?.name }; if (org != null) kv("운영 회사", org) }
                note("VPN 을 켰는데 \"DNS 서버의 공인 IP\"가 내 통신사(예: KT·SKB·LG U+)로 나오면 DNS 질문이 VPN 밖으로 새고 있다는 뜻이에요. VPN 회사나 구글·클라우드플레어로 나오면 정상이에요.")
            }
        },

        online("geo_my_ip_stun", G, "STUN 으로 내 공인 IP·포트·NAT 유형", "화상통화·게임이 쓰는 STUN 방식으로 내 IP:포트를 알아내고, 서버마다 포트가 같은지로 NAT 종류를 짐작 (P2P 연결이 잘 되는지)",
            note = "STUN 서버 3곳(stun.l.google.com, stun1.l.google.com, stun.cloudflare.com)에 UDP 패킷 1개씩 보내요. 내 IP·포트 외에 보내는 정보는 없어요.") { _, host, env ->
            val sv = stunServers
            env.progress("STUN 서버 ${stunServers.size}곳에 묻는 중...")
            val res = Par.map(sv, 3, 9000) { (h, p) -> runCatching { Stun.query(h, p, 2500) { host.bindDatagram(it) } }.getOrNull() }
            val ok = sv.indices.filter { res[it] != null }
            if (ok.isEmpty()) return@online fail("STUN 응답이 없어요. UDP 가 막힌 망(회사·학교·일부 Wi-Fi)이거나 인터넷 연결이 없어요")
            val db = db(host)
            result {
                header("서버", "내 공인 IP : 포트", "시간")
                sv.forEachIndexed { k, s -> val r = res[k]; if (r == null) row(s.first, "응답 없음", "", level = 1) else row(s.first, "${IpUtil.format(r.first)}:${r.second}", "${r.third}ms") }
                val ips = ok.map { IpUtil.format(res[it]!!.first) }.distinct(); val ports = ok.map { res[it]!!.second }
                kv("내 공인 IP", ips.joinToString(), -1); db?.lookup(ips[0])?.let { kv("나라 · 통신사", "${CountryNames.ko(it.country)} · ${it.asn?.name ?: "-"}") }
                if (ok.size >= 2) {
                    if (ports.distinct().size == 1) { kv("NAT 포트 매핑", "서버가 달라도 같은 포트 (${ports[0]})", -1); note("서버가 달라도 같은 포트를 써요(\"엔드포인트 독립 매핑\"). 화상통화·게임에서 상대와 직접(P2P) 연결이 잘 되는 편이에요.", -1) }
                    else { kv("NAT 포트 매핑", "서버마다 다른 포트 (${ports.joinToString()})", 1); note("서버마다 포트가 달라요(\"대칭 NAT\" 가능성). 이런 망(특히 일부 모바일 통신사 NAT)에서는 P2P 연결이 어렵고 중계 서버를 거쳐 느려질 수 있어요.", 1) }
                } else note("응답한 서버가 하나뿐이라 NAT 종류는 판단하지 못했어요.", 1)
                if (ips.size > 1) note("서버마다 다른 IP 가 보여요. 회선이 둘이거나 로드밸런싱 NAT 일 수 있어요.", 1)
            }
        },

        online("geo_my_ip_dual", G, "IPv4·IPv6 공인 주소 각각 확인", "내 인터넷이 IPv4·IPv6 둘 다 되는지, 각각의 공인 주소와 나라·통신사", note = "ipify(api.ipify.org 와 api6.ipify.org)에 접속해요. 내 IP 는 어차피 접속하는 서버에 보이는 값이에요.") { _, host, env ->
            env.progress("IPv4·IPv6 를 확인하는 중...")
            val sv = listOf("IPv4" to "https://api.ipify.org", "IPv6" to "https://api6.ipify.org")
            val res = Par.map(sv, 2, 11000) { (_, u) -> runCatching { GeoNet.get(u, 6000, 256).trim() }.getOrNull() }
            val db = db(host)
            result {
                header("종류", "공인 주소", "나라 · 통신사")
                sv.forEachIndexed { k, s -> val v = res[k]?.takeIf { IpUtil.parse(it) != null }; if (v == null) row(s.first, "안 돼요 (또는 응답 없음)", "", level = 1) else { val g = db?.lookup(v); row(s.first, v, if (g == null) "-" else "${CountryNames.ko(g.country)} · ${g.asn?.name ?: "-"}") } }
                val v4 = res[0] != null && IpUtil.parse(res[0]!!) != null; val v6 = res[1] != null && IpUtil.parse(res[1]!!) != null
                note(when { v4 && v6 -> "IPv4·IPv6 둘 다 돼요 (듀얼 스택)."; v4 -> "IPv4 만 돼요. IPv6 는 통신사·공유기 설정에서 꺼져 있거나 지원하지 않아요."; v6 -> "IPv6 만 돼요 (IPv4 는 번역 방식일 수 있어요)."; else -> "둘 다 확인하지 못했어요. 인터넷 연결을 확인하세요." }, if (v4 && v6) -1 else 0)
            }
        },

        online("geo_cf_trace", G, "클라우드플레어가 본 내 연결 정보", "내 IP·나라·가까운 클라우드플레어 서버 위치(공항 코드)·HTTP/TLS 버전·WARP 사용 여부", note = "cloudflare.com 의 /cdn-cgi/trace 주소 하나에 접속해요. 내 IP 는 어차피 접속하는 서버에 보이는 값이에요.") { _, host, env ->
            env.progress("접속 중...")
            val text = try { GeoNet.get("https://www.cloudflare.com/cdn-cgi/trace", 7000, 4096) } catch (e: IOException) { return@online fail("접속하지 못했어요: ${e.message}") }
            val m = text.lineSequence().mapNotNull { l -> l.indexOf('=').takeIf { it > 0 }?.let { l.substring(0, it) to l.substring(it + 1) } }.toMap()
            val colo = m["colo"]
            val db = db(host); val ip = m["ip"]
            result {
                ip?.let { kv("내 IP", it, -1); db?.lookup(it)?.let { g -> kv("나라 · 통신사 (폰 안 자료)", "${CountryNames.ko(g.country)} · ${g.asn?.name ?: "-"}") } }
                m["loc"]?.let { kv("나라 (클라우드플레어 판단)", CountryNames.label(it)) }
                colo?.let { kv("가장 가까운 서버", "$it ${COLO[it]?.let { c -> "($c)" } ?: ""}") }
                m["http"]?.let { kv("HTTP 버전", it) }; m["tls"]?.let { kv("TLS 버전", it) }; m["kex"]?.let { kv("키 교환", it) }; m["sni"]?.let { kv("SNI", it) }
                m["warp"]?.let { kv("WARP(클라우드플레어 VPN)", if (it == "off") "꺼짐" else "켜짐($it)", if (it == "off") 0 else 1) }; m["gateway"]?.let { kv("Gateway", it) }
                m["visit_scheme"]?.let { kv("접속 방식", it) }
                if (m.isEmpty()) note("예상한 형식의 응답이 아니에요.", 1)
                note("가까운 서버는 인터넷 경로 기준이라 실제 거리와 다를 수 있어요. (공항 코드: ICN 인천, NRT 도쿄 등)")
            }
        },

        lanTool("geo_upnp_wan", G, "공유기가 받은 WAN IP 와 CGNAT 판별", "공유기(UPnP)에게 바깥쪽 IP 를 직접 물어서, 인터넷에서 보이는 IP 와 비교 — 이중 NAT·통신사 공용 주소(CGNAT)인지",
            note = "같은 망에 SSDP 방송을 보내 공유기를 찾고, 공유기에 \"WAN IP 가 뭐야?\" 하고 물어요(내 망 안). 비교를 위해 ipify 에도 한 번 접속해요. UPnP 가 꺼진 공유기는 답하지 않아요.") { _, host, env ->
            env.progress("공유기를 찾는 중... (4초)")
            val devs = try { Ssdp.discover(ssdpWaitMs, "urn:schemas-upnp-org:device:InternetGatewayDevice:1", ssdpTarget, bind = { host.bindDatagram(it) }) } catch (e: IOException) { return@lanTool fail("방송을 보내지 못했어요: ${e.message}. Wi-Fi 에 연결돼 있는지 확인하세요") }
            val gw = devs.filter { it.location != null }.distinctBy { it.ip }
            if (gw.isEmpty()) return@lanTool result { note("UPnP 로 답하는 공유기를 찾지 못했어요. 공유기에서 UPnP 가 꺼져 있거나 게스트 Wi-Fi 일 수 있어요.", 1) }
            env.progress("WAN IP 를 묻는 중...")
            val wan = gw.firstNotNullOfOrNull { Igd.externalIp(it, host.lanSockets()) }
            val pub = runCatching { GeoNet.get("https://api.ipify.org", 6000, 256).trim() }.getOrNull()?.takeIf { IpUtil.parse(it) != null }
            result {
                kv("공유기", gw.joinToString { it.ip })
                if (wan == null) note("공유기가 WAN IP 를 알려 주지 않았어요 (지원하지 않거나 UPnP 제어가 꺼져 있어요).", 1)
                else {
                    kv("공유기가 받은 WAN IP", wan); pub?.let { kv("인터넷에서 보이는 내 IP", it) }
                    val k = IpUtil.parse(wan)?.let { IpUtil.classify(it) }
                    when {
                        k == IpKind.PRIVATE -> note("WAN IP 가 사설 주소($wan)예요: 공유기 앞에 또 다른 공유기(이중 NAT)가 있어요. 포트 포워딩·서버 운영·일부 게임 연결이 안 될 수 있어요.", 2)
                        k == IpKind.CGNAT -> note("WAN IP 가 통신사 공용 주소(100.64.x.x, CGNAT)예요: 여러 가입자가 주소를 나눠 써서 외부에서 내 집으로 직접 접속하는 서버 운영·포트 포워딩이 안 돼요. 통신사에 공인 IP 를 요청해야 해요.", 2)
                        pub != null && pub != wan -> note("공유기의 WAN IP 와 인터넷에서 보이는 IP 가 달라요. VPN·프록시를 쓰고 있거나, 통신사가 한 번 더 주소를 바꾸는(NAT) 구성이에요.", 1)
                        else -> note("공유기의 WAN IP 가 곧 공인 IP 예요 (공인 IP 를 직접 받고 있어요). 외부에서 접속하는 서버 운영이 가능한 구성이에요.", -1)
                    }
                }
            }
        },

        lanTool("geo_mdns", G, "같은 망 기기 이름·IP 찾기 (mDNS·Bonjour)", "프린터·TV·크롬캐스트·애플 기기·NAS 가 스스로 알리는 이름과 IP·서비스를 찾기 (공유기에 안 보이는 기기도)",
            note = "같은 망에 mDNS 질문(UDP 5353)을 16개 보내고 2.5초 동안 답을 모아요. 내 집·내 사무실 망에서만 쓰세요.") { _, host, env ->
            val types = listOf("_http._tcp", "_https._tcp", "_ipp._tcp", "_printer._tcp", "_airplay._tcp", "_raop._tcp", "_googlecast._tcp", "_hap._tcp", "_smb._tcp", "_ssh._tcp", "_workstation._tcp", "_device-info._tcp", "_spotify-connect._tcp", "_companion-link._tcp", "_afpovertcp._tcp")
            val qs = listOf("_services._dns-sd._udp.local" to DnsType.PTR) + types.map { "$it.local" to DnsType.PTR }
            env.progress("기기들의 답을 모으는 중... (3초)")
            val msgs = try { Mdns.query(qs, mdnsWaitMs, mdnsTarget, bind = { host.bindDatagram(it) }) } catch (e: IOException) { return@lanTool fail("질문을 보내지 못했어요: ${e.message}. Wi-Fi 에 연결돼 있는지 확인하세요") }
            // 서비스 인스턴스 이름을 알았으니 SRV·TXT·A 를 한 번 더 물어 완성
            val first = Mdns.instances(msgs)
            val ptrs = msgs.flatMap { it.answers + it.additional }.filter { it.type == DnsType.PTR && !it.name.startsWith("_services") }.map { it.data.trimEnd('.') }.distinct().take(40)
            val extra = if (ptrs.isEmpty()) emptyList() else try { Mdns.query(ptrs.flatMap { listOf(it to DnsType.SRV, it to DnsType.TXT) }, mdnsWaitMs, mdnsTarget, bind = { host.bindDatagram(it) }) } catch (_: IOException) { emptyList() }
            val inst = Mdns.instances(msgs + extra); val svcTypes = Mdns.serviceTypes(msgs)
            if (msgs.isEmpty()) return@lanTool result { note("응답한 기기가 없어요. 게스트 Wi-Fi·AP 격리이거나 이 기기에서 멀티캐스트가 막혀 있을 수 있어요.", 1) }
            result {
                kv("찾은 기기·서비스", "${inst.size}개" + if (first.isEmpty() && inst.isNotEmpty()) "" else "")
                if (inst.isNotEmpty()) { header("이름", "서비스", "IP : 포트"); for (x in inst.sortedBy { it.name }.take(80)) row(x.name, x.service.removeSuffix("._tcp").removeSuffix("._udp").removePrefix("_").ifEmpty { "-" }, (x.ips.firstOrNull() ?: "-") + (x.port?.let { ":$it" } ?: "")) }
                if (svcTypes.isNotEmpty()) { head("이 망에 알려진 서비스 종류"); block(svcTypes.joinToString("\n")) }
                note("기기 이름이 \"홍길동의 아이폰\"처럼 사람 이름을 담고 있을 수 있어요. 결과를 공유할 때 주의하세요.", 1)
            }
        },

        lanTool("geo_mdns_resolve", G, "기기 이름(.local)으로 IP 찾기", "프린터·NAS·라즈베리파이 같은 기기의 이름(예: printer.local)으로 같은 망 안의 IP 를 알아내기", text("n", "기기 이름", "예: printer.local 또는 raspberrypi", "raspberrypi.local"),
            note = "같은 망에 mDNS 질문(UDP 5353)을 보내요. 내 망 안에서만 동작해요.") { i, host, env ->
            val raw = i.str("n").lowercase().removeSuffix("."); if (raw.isEmpty()) return@lanTool need("기기 이름을 입력하세요")
            val name = if (raw.endsWith(".local")) raw else "$raw.local"
            if (!name.all { it.isLetterOrDigit() || it == '-' || it == '.' || it == '_' }) return@lanTool fail("이름에 쓸 수 없는 글자가 있어요")
            env.progress("$name 을 찾는 중...")
            val msgs = try { Mdns.query(listOf(name to DnsType.A, name to DnsType.AAAA), mdnsWaitMs, mdnsTarget, bind = { host.bindDatagram(it) }) } catch (e: IOException) { return@lanTool fail("질문을 보내지 못했어요: ${e.message}") }
            val ips = msgs.flatMap { it.answers + it.additional }.filter { (it.type == DnsType.A || it.type == DnsType.AAAA) && it.name.trimEnd('.').equals(name, true) }.map { it.data }.distinct()
            result { kv("이름", name); if (ips.isEmpty()) note("응답이 없어요. 이름이 틀렸거나, 그 기기가 mDNS 를 지원하지 않거나, 같은 망에 없어요.", 1) else { for (ip in ips) kv(if (':' in ip) "IPv6" else "IPv4", ip, -1) } }
        },

        online("geo_ptr_sweep", G, "IP 대역의 이름(역방향 DNS) 일괄 조회", "CIDR 안의 IP(최대 64개) 각각의 역방향 DNS 이름 — 내 IP 대역에 어떤 서버·기기 이름이 등록돼 있는지", DnsTools.serverField(), text("cidr", "IP 대역 (/26 ~ /32)", "예: 192.168.0.0/26 또는 8.8.8.0/28", "8.8.8.0/28"),
            note = "대역 안의 IP 마다 DNS 서버에 역방향 이름(PTR)을 물어요(최대 64개). 내 대역 점검용이에요.") { i, host, env ->
            val c = Cidr4.parse(i.str("cidr")) ?: return@online if (i.str("cidr").isEmpty()) need("IP 대역을 입력하세요") else fail("IP 대역을 읽지 못했어요 (예: 192.168.0.0/26)")
            if (c.size > 64) return@online fail("최대 64개(/26)까지만 조회해요")
            val ips = (c.first..c.last).map { IpUtil.v4Text(it) }; val servers = DnsTools.servers(i, host)
            env.progress("${ips.size}개 조회 중...")
            val res = Par.map(ips, 8, 20000) { ip -> runCatching { DnsTools.ask(servers, Ptr.name(InetAddress.getByAddress(IpUtil.longToV4(IpUtil.v4ToLong(IpUtil.parseV4(ip)!!)))), DnsType.PTR, host, timeoutMs = 2500).msg.answers.filter { it.type == DnsType.PTR }.map { it.data.trimEnd('.') } }.getOrNull() }
            val named = ips.indices.filter { !res[it].isNullOrEmpty() }
            result {
                kv("대역", c.toString()); kv("이름이 있는 IP", "${named.size} / ${ips.size}")
                if (named.isNotEmpty()) { header("IP", "역방향 이름"); for (k in named) row(ips[k], res[k]!!.joinToString(", ")) }
                else note("등록된 역방향 이름이 없어요 (대부분의 가정용 대역은 비어 있거나 통신사가 자동 생성한 이름이에요).", 1)
            }
        },

        // ===== 좌표 도구 (인터넷 없이)
        calc("geo_coord_map", G, "좌표 → 지도 링크 만들기", "위도·경도로 OpenStreetMap·구글·카카오 지도 링크 만들기 (IP 위치 조회 결과의 좌표를 붙여 넣어 보세요)",
            text("c", "좌표", "예: 37.5665, 126.9780", "37.5665, 126.9780", listOf("서울시청" to "37.5665, 126.9780", "도쿄" to "35.6762, 139.6503", "싱가포르" to "1.3521, 103.8198")), live = true) { i ->
            val p = Geo.parseCoord(i.str("c")) ?: return@calc if (i.str("c").isEmpty()) need("좌표를 입력하세요") else fail("좌표를 읽지 못했어요 (예: 37.5665, 126.9780 또는 37°33′59″N 126°58′41″E)")
            result { kv("위도, 경도", "${Geo.dec(p.first)}, ${Geo.dec(p.second)}"); kv("도분초", "${Geo.dms(p.first, 'N', 'S')} ${Geo.dms(p.second, 'E', 'W')}"); head("지도 링크 (눌러서 복사)"); for ((n, u) in Geo.mapLinks(p.first, p.second)) kv(n, u) }
        },

        calc("geo_haversine", G, "두 좌표 사이 거리·방향", "위도·경도 두 곳의 직선거리(km·mi)·방향·중간 지점 (대원 거리)",
            text("a", "첫째 좌표", "예: 37.5665, 126.9780", "37.5665, 126.9780", listOf("서울" to "37.5665, 126.9780")), text("b", "둘째 좌표", "예: 35.6762, 139.6503", "35.6762, 139.6503", listOf("도쿄" to "35.6762, 139.6503", "뉴욕" to "40.7128, -74.0060")), live = true) { i ->
            val a = Geo.parseCoord(i.str("a")) ?: return@calc fail("첫째 좌표를 읽지 못했어요"); val b = Geo.parseCoord(i.str("b")) ?: return@calc fail("둘째 좌표를 읽지 못했어요")
            val km = Geo.distanceKm(a.first, a.second, b.first, b.second); val br = Geo.bearing(a.first, a.second, b.first, b.second); val mid = Geo.midpoint(a.first, a.second, b.first, b.second)
            result { kv("직선거리", "${"%.1f".format(km)} km  (${"%.1f".format(km / 1.609344)} mi · ${"%.1f".format(km / 1.852)} 해리)"); kv("방향", "${"%.1f".format(br)}° (${Geo.compass(br)}쪽)"); kv("중간 지점", "${Geo.dec(mid.first)}, ${Geo.dec(mid.second)}"); kv("이론상 최소 왕복 시간(광섬유)", "${"%.1f".format(Geo.minRttMs(km))} ms") }
        },

        calc("geo_coord_convert", G, "좌표 형식 변환 (십진수 ↔ 도분초)", "37.5665 ↔ 37°33′59.4″N 처럼 좌표를 여러 형식으로",
            text("c", "좌표 (아무 형식)", "예: 37°33'59.4\"N 126°58'40.8\"E", "37°33'59.4\"N 126°58'40.8\"E", listOf("십진수" to "37.5665, 126.9780", "도분초" to "37°33'59.4\"N 126°58'40.8\"E", "도·분" to "N37 33.99 E126 58.68")), live = true) { i ->
            val p = Geo.parseCoord(i.str("c")) ?: return@calc if (i.str("c").isEmpty()) need("좌표를 입력하세요") else fail("좌표를 읽지 못했어요. 십진수(37.5665, 126.9780), 도분초(37°33′59.4″N 126°58′40.8″E), 도·분(N37 33.99 E126 58.68) 형식을 쓰세요")
            fun ddm(v: Double, pos: Char, neg: Char): String { val a = Math.abs(v); val d = a.toInt(); return "%c%d %06.3f".format(if (v >= 0) pos else neg, d, (a - d) * 60) }
            result { kv("십진수", "${Geo.dec(p.first)}, ${Geo.dec(p.second)}"); kv("도분초", "${Geo.dms(p.first, 'N', 'S')} ${Geo.dms(p.second, 'E', 'W')}"); kv("도·분", "${ddm(p.first, 'N', 'S')}  ${ddm(p.second, 'E', 'W')}"); kv("geo URI", "geo:${"%.6f".format(p.first)},${"%.6f".format(p.second)}") }
        },
    )

    private fun yn(b: Boolean?) = when (b) { true -> "예"; false -> "아니요"; null -> "?" }

    /** 클라우드플레어 서버 위치(공항 코드) 일부 */
    private val COLO = mapOf("ICN" to "서울 인천", "GMP" to "서울 김포", "PUS" to "부산", "NRT" to "도쿄 나리타", "HND" to "도쿄 하네다", "KIX" to "오사카", "FUK" to "후쿠오카", "HKG" to "홍콩", "SIN" to "싱가포르", "TPE" to "타이베이", "KHH" to "가오슝",
        "LAX" to "로스앤젤레스", "SJC" to "새너제이", "SEA" to "시애틀", "SFO" to "샌프란시스코", "ORD" to "시카고", "DFW" to "댈러스", "IAD" to "워싱턴", "EWR" to "뉴어크", "MIA" to "마이애미", "YYZ" to "토론토", "LHR" to "런던", "FRA" to "프랑크푸르트",
        "AMS" to "암스테르담", "CDG" to "파리", "MAD" to "마드리드", "MXP" to "밀라노", "SYD" to "시드니", "MEL" to "멜버른", "BOM" to "뭄바이", "DEL" to "델리", "BKK" to "방콕", "KUL" to "쿠알라룸푸르", "CGK" to "자카르타", "MNL" to "마닐라", "DXB" to "두바이", "GRU" to "상파울루")
}

/** 경로 추적: 기기의 ping 으로 TTL 을 1부터 늘려 가며 각 장비의 주소와 응답 시간을 얻음 */
object Trace {
    class Hop(val ttl: Int, val ip: String?, val ms: Double?)

    fun run(dest: String, max: Int, cancel: java.util.concurrent.atomic.AtomicBoolean, progress: (String) -> Unit = {}): List<Hop> {
        val hops = ArrayList<Hop>()
        for (ttl in 1..max) {
            if (cancel.get()) break
            progress("$ttl 번째 홉 확인 중...")
            val t0 = System.nanoTime()
            val lines = try { SystemPing.run(dest, 1, 2, ttl, cancel) } catch (_: IOException) { break }
            val wall = (System.nanoTime() - t0) / 1e6
            val p = lines.mapNotNull { SystemPing.parseLine(it) }.firstOrNull { it.kind == "reply" || it.kind == "exceeded" || it.kind == "unreachable" }
            hops += Hop(ttl, p?.from, p?.ms ?: if (p != null) wall else null)
            if (p?.kind == "reply") break
        }
        return hops
    }
}
