package com.selfcheck.app

import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Before
import org.junit.Test
import java.io.Closeable
import java.io.IOException
import java.net.IDN
import java.net.InetAddress
import java.time.Instant

/*
 * 메일·DNS 점검 엔진(SPF 평가·평탄화, DoH 해석, RDAP, 비슷한 도메인, 이메일 주소, DNS 영역 파일 점검)과 메일·DNS 도구 16가지 시험.
 * 가짜 DNS 서버(UDP)·가짜 DoT 서버(TLS)·가짜 인터넷 응답(GeoNet.fetcher)으로 도구를 끝까지 실행합니다.
 * 규격 예시(RFC 7208 의 SPF 규칙 등)와 직접 계산한 값으로 비교했고, 실제 인터넷과는 연결하지 않았어요.
 */
class NetMailTest {
    private val closers = ArrayList<Closeable>()
    private fun <T : Closeable> T.track(): T { closers += this; return this }
    private var savedResolvers: List<Pair<String, String>> = emptyList()

    @Before fun setUp() { savedResolvers = MailTools.propagationResolvers; MailTools.nsPorts = emptyMap(); GeoNet.fetcher = null }
    @After fun tearDown() {
        closers.forEach { runCatching { it.close() } }; closers.clear()
        GeoNet.fetcher = null; MailTools.propagationResolvers = savedResolvers; MailTools.nsPorts = emptyMap()
    }

    private fun run(id: String, vararg kv: Pair<String, String>, host: ToolHost = FileHost) = runNetTool(id, *kv, host = host)
    private fun fakeDns(z: FakeZone, custom: ((String, Int) -> Pair<Int, List<DnsAns>>?)? = null) = TestDns { n, t -> custom?.invoke(n, t) ?: z.answer(n, t) }.track()

    /** SPF 엔진 시험용: 이름 → 답을 map 으로 정해 두는 가짜 DNS */
    private class MapDns(
        val txt: Map<String, List<String>> = emptyMap(), val a: Map<String, List<String>> = emptyMap(),
        val mx: Map<String, List<String>> = emptyMap(), val fail: Set<String> = emptySet(),
    ) : SpfDns {
        override fun txt(name: String): List<String> { if (name in fail) throw IOException("시간 초과"); return txt[name] ?: emptyList() }
        override fun addresses(name: String): List<InetAddress> = (a[name] ?: emptyList()).map { InetAddress.getByName(it) }
        override fun mx(name: String): List<String> = mx[name] ?: emptyList()
    }

    private fun spf(dns: SpfDns, ip: String, domain: String = "example.com") = SpfEval.check(dns, InetAddress.getByName(ip), domain)
    private fun spfOf(record: String, vararg more: Pair<String, String>) = MapDns(txt = mapOf("example.com" to listOf(record)) + more.associate { it.first to listOf(it.second) })

    // ============================================================ 엔진: SPF

    @Test fun spfEvaluatesIpRangesAndQualifiers() {
        val dns = spfOf("v=spf1 ip4:192.0.2.0/24 ip6:2001:db8::/32 -all")
        assertEquals("pass", spf(dns, "192.0.2.77").verdict)
        assertEquals("pass", spf(dns, "2001:db8::1").verdict)
        assertEquals("fail", spf(dns, "192.0.3.1").verdict)
        assertEquals("fail", spf(dns, "2001:db9::1").verdict)
        val r = spf(dns, "192.0.2.77"); assertTrue(r.reason.contains("ip4:192.0.2.0/24")); assertEquals(0, r.lookups)
        val q = spfOf("v=spf1 ~ip4:10.0.0.0/8 ?ip4:11.0.0.0/8 +ip4:12.0.0.0/8 -all")
        assertEquals("softfail", spf(q, "10.1.1.1").verdict); assertEquals("neutral", spf(q, "11.1.1.1").verdict); assertEquals("pass", spf(q, "12.1.1.1").verdict); assertEquals("fail", spf(q, "13.1.1.1").verdict)
        assertEquals("neutral", spf(spfOf("v=spf1 ip4:1.1.1.0/24"), "8.8.8.8").verdict)         // 끝에 all 이 없으면 neutral
        assertEquals("neutral", spf(spfOf("v=spf1 ?all"), "8.8.8.8").verdict)
        val one = spfOf("v=spf1 ip4:192.0.2.5 -all")                                           // 접두사가 없으면 그 주소 하나만
        assertEquals("pass", spf(one, "192.0.2.5").verdict); assertEquals("fail", spf(one, "192.0.2.6").verdict)
        assertEquals("fail", spf(one, "2001:db8::5").verdict)                                  // IPv6 는 ip4 항목과 비교하지 않음
        val cidr = spfOf("v=spf1 ip4:192.0.2.0/31 -all")                                       // 경계: /31 은 주소 2개
        assertEquals("pass", spf(cidr, "192.0.2.1").verdict); assertEquals("fail", spf(cidr, "192.0.2.2").verdict)
    }

    @Test fun spfAMxMechanismsWithCidr() {
        val dns = MapDns(
            txt = mapOf("example.com" to listOf("v=spf1 a mx:mail.example.com/30 a:other.example.net/24 -all")),
            a = mapOf("example.com" to listOf("198.51.100.10"), "mx1.example.com" to listOf("203.0.113.5"), "other.example.net" to listOf("192.0.2.200")),
            mx = mapOf("mail.example.com" to listOf("mx1.example.com")))
        val a = spf(dns, "198.51.100.10"); assertEquals("pass", a.verdict); assertEquals(1, a.lookups)
        val m = spf(dns, "203.0.113.6"); assertEquals("pass", m.verdict); assertEquals(2, m.lookups)       // a(1) + mx(1): mx 서버의 주소 조회는 따로 세지 않음 (RFC 7208 4.6.4)
        val o = spf(dns, "192.0.2.7"); assertEquals("pass", o.verdict); assertEquals(3, o.lookups)
        val f = spf(dns, "8.8.8.8"); assertEquals("fail", f.verdict); assertEquals(3, f.lookups)
        assertEquals("fail", spf(dns, "203.0.113.8").verdict)                                              // /30 밖 (.4~.7 만)
        // mx 서버가 11개면 permerror
        val many = MapDns(txt = mapOf("example.com" to listOf("v=spf1 mx -all")), mx = mapOf("example.com" to (1..11).map { "mx$it.example.com" }))
        val e = spf(many, "8.8.8.8"); assertEquals("permerror", e.verdict); assertTrue(e.reason.contains("11개"))
        // Null MX(빈 이름)는 건너뜀
        val nullMx = MapDns(txt = mapOf("example.com" to listOf("v=spf1 mx -all")), mx = mapOf("example.com" to listOf("")))
        assertEquals("fail", spf(nullMx, "8.8.8.8").verdict)
    }

    @Test fun spfIncludeChainsDoNotLeakQualifiers() {
        val dns = MapDns(txt = mapOf(
            "example.com" to listOf("v=spf1 include:_spf.a.net include:_spf.b.net -all"),
            "_spf.a.net" to listOf("v=spf1 ip4:192.0.2.0/25 ~all"),
            "_spf.b.net" to listOf("v=spf1 ip4:198.51.100.0/24 -all")))
        val p = spf(dns, "198.51.100.9"); assertEquals("pass", p.verdict); assertEquals(2, p.lookups); assertTrue(p.trace.any { it.startsWith("_spf.b.net:") })
        val a = spf(dns, "192.0.2.9"); assertEquals("pass", a.verdict); assertEquals(1, a.lookups)
        assertEquals("fail", spf(dns, "8.8.8.8").verdict)            // 포함된 쪽의 ~all·-all 은 바깥으로 새지 않고 바깥의 -all 이 적용됨
        val e = spf(spfOf("v=spf1 include:nospf.example.org -all"), "8.8.8.8"); assertEquals("permerror", e.verdict); assertTrue(e.reason.contains("nospf.example.org"))
    }

    @Test fun spfTenLookupLimit() {
        fun chain(n: Int): MapDns {
            val inc = (1..n).joinToString(" ") { "include:i$it.example.net" }
            val txt = mutableMapOf("example.com" to listOf("v=spf1 $inc -all"))
            for (k in 1..n) txt["i$k.example.net"] = listOf("v=spf1 ip4:10.$k.0.0/16 -all")
            return MapDns(txt = txt)
        }
        val ten = spf(chain(10), "8.8.8.8"); assertEquals("fail", ten.verdict); assertEquals(10, ten.lookups)
        val eleven = spf(chain(11), "8.8.8.8"); assertEquals("permerror", eleven.verdict); assertTrue(eleven.reason.contains("10번")); assertEquals(11, eleven.lookups)
        // 안쪽 include 에서 쓴 조회도 같은 한도에 합쳐짐 (바깥 6 + 안쪽 6)
        val txt = mutableMapOf("example.com" to listOf("v=spf1 " + (1..5).joinToString(" ") { "include:a$it.example.net" } + " include:big.example.net -all"), "big.example.net" to listOf("v=spf1 " + (1..6).joinToString(" ") { "include:j$it.example.net" } + " -all"))
        for (k in 1..5) txt["a$k.example.net"] = listOf("v=spf1 -all"); for (k in 1..6) txt["j$k.example.net"] = listOf("v=spf1 -all")
        assertEquals("permerror", spf(MapDns(txt = txt), "8.8.8.8").verdict)
        // include 고리(서로 포함)도 끝나야 함
        val loop = MapDns(txt = mapOf("example.com" to listOf("v=spf1 include:b.example.net -all"), "b.example.net" to listOf("v=spf1 include:example.com -all")))
        assertEquals("permerror", spf(loop, "8.8.8.8").verdict)
    }

    @Test fun spfRedirectExistsMacroPtrAndErrors() {
        val red = spfOf("v=spf1 redirect=_spf.example.net", "_spf.example.net" to "v=spf1 ip4:192.0.2.0/24 -all")
        val p = spf(red, "192.0.2.9"); assertEquals("pass", p.verdict); assertEquals(1, p.lookups); assertEquals("fail", spf(red, "8.8.8.8").verdict)
        assertEquals("fail", spf(spfOf("v=spf1 -all redirect=_spf.example.net", "_spf.example.net" to "v=spf1 +all"), "8.8.8.8").verdict)    // all 이 먼저 일치하면 redirect 는 무시
        assertEquals("permerror", spf(spfOf("v=spf1 redirect=gone.example.net"), "8.8.8.8").verdict)
        val ex = MapDns(txt = mapOf("example.com" to listOf("v=spf1 exists:check.example.net -all")), a = mapOf("check.example.net" to listOf("127.0.0.2")))
        val e = spf(ex, "8.8.8.8"); assertEquals("pass", e.verdict); assertEquals(1, e.lookups)
        assertEquals("fail", spf(spfOf("v=spf1 exists:check.example.net -all"), "8.8.8.8").verdict)
        val mac = spf(spfOf("v=spf1 exists:%{i}._spf.example.net -all"), "8.8.8.8"); assertEquals("fail", mac.verdict); assertEquals(0, mac.lookups); assertTrue(mac.trace.any { "매크로" in it })
        val ptr = spf(spfOf("v=spf1 ptr -all"), "8.8.8.8"); assertEquals("fail", ptr.verdict); assertTrue(ptr.trace.any { "ptr" in it })
        val unk = spf(spfOf("v=spf1 foo:bar -all"), "8.8.8.8"); assertEquals("permerror", unk.verdict); assertTrue(unk.reason.contains("foo:bar"))
        val two = spf(MapDns(txt = mapOf("example.com" to listOf("v=spf1 -all", "v=spf1 +all"))), "8.8.8.8"); assertEquals("permerror", two.verdict); assertTrue(two.reason.contains("2개"))
        assertEquals("none", spf(MapDns(txt = mapOf("example.com" to listOf("google-site-verification=abc", "v=spf10 -all"))), "8.8.8.8").verdict)   // v=spf10 은 SPF 가 아님
        assertEquals("temperror", spf(MapDns(fail = setOf("example.com")), "8.8.8.8").verdict)
        assertEquals("pass", spf(spfOf("V=SPF1 IP4:192.0.2.0/24 -ALL"), "192.0.2.1").verdict)           // 버전 글자·항목 이름은 대소문자 무시
    }

    @Test fun spfFlattenExpandsEverythingToIpEntries() {
        val dns = MapDns(
            txt = mapOf("example.com" to listOf("v=spf1 mx a:relay.example.com include:_spf.mailer.net ip4:192.0.2.5 ~all"), "_spf.mailer.net" to listOf("v=spf1 ip4:198.51.100.0/24 ip6:2001:db8::/32 -all")),
            a = mapOf("relay.example.com" to listOf("203.0.113.80"), "mx1.example.com" to listOf("203.0.113.25", "2001:db8:1::25")),
            mx = mapOf("example.com" to listOf("mx1.example.com")))
        val f = SpfEval.flatten(dns, "example.com")
        assertEquals(listOf("ip4:203.0.113.25", "ip6:2001:db8:1::25", "ip4:203.0.113.80", "ip4:198.51.100.0/24", "ip6:2001:db8::/32", "ip4:192.0.2.5"), f.entries)
        assertEquals(3, f.originalLookups); assertEquals("~all", f.allQualifier); assertTrue(f.notes.isEmpty())
        assertEquals("v=spf1 ip4:203.0.113.25 ip6:2001:db8:1::25 ip4:203.0.113.80 ip4:198.51.100.0/24 ip6:2001:db8::/32 ip4:192.0.2.5 ~all", SpfEval.record(f))
        // 같은 규칙을 평탄화 결과로 평가해도 같은 판정
        val flatDns = MapDns(txt = mapOf("example.com" to listOf(SpfEval.record(f))))
        for (ip in listOf("203.0.113.25", "198.51.100.77", "192.0.2.5", "2001:db8:ffff::1", "8.8.8.8")) assertEquals(ip, spf(dns, ip).verdict.replace("softfail", "x"), spf(flatDns, ip).verdict.replace("softfail", "x"))
        // all 한정자: -all·?all·+all(all)
        assertEquals("-all", SpfEval.flatten(MapDns(txt = mapOf("example.com" to listOf("v=spf1 ip4:1.2.3.4 -all"))), "example.com").allQualifier)
        assertEquals("?all", SpfEval.flatten(MapDns(txt = mapOf("example.com" to listOf("v=spf1 ip4:1.2.3.4 ?all"))), "example.com").allQualifier)
        assertEquals("all", SpfEval.flatten(MapDns(txt = mapOf("example.com" to listOf("v=spf1 ip4:1.2.3.4 all"))), "example.com").allQualifier)
        // redirect 는 따라가고, mx/24 같은 접두사는 이어 붙임, exists·ptr 는 풀 수 없다고 알림
        val rd = SpfEval.flatten(MapDns(txt = mapOf("example.com" to listOf("v=spf1 redirect=_spf.example.net"), "_spf.example.net" to listOf("v=spf1 mx/24 exists:x.example.net -all")), a = mapOf("mx1.example.net" to listOf("203.0.113.25")), mx = mapOf("_spf.example.net" to listOf("mx1.example.net"))), "example.com")
        assertEquals(listOf("ip4:203.0.113.25/24"), rd.entries); assertEquals("-all", rd.allQualifier); assertTrue(rd.notes.any { it.contains("exists:x.example.net") })
        val none = SpfEval.flatten(MapDns(), "example.com"); assertTrue(none.entries.isEmpty()); assertTrue(none.notes.single().contains("SPF 레코드가 없어요"))
    }

    // ============================================================ 엔진: DoH·RDAP·비슷한 도메인·이메일·영역 파일

    @Test fun dohReplyParsingAndUrls() {
        val ok = Doh.parse("""{"Status":0,"TC":false,"RD":true,"RA":true,"AD":true,"CD":false,"Question":[{"name":"example.com","type":1}],"Answer":[{"name":"example.com.","type":1,"TTL":300,"data":"93.184.216.34"},{"name":"example.com","type":16,"TTL":3600,"data":"\"v=spf1 -all\""}]}""")
        assertEquals(0, ok.status); assertTrue(ok.ad); assertTrue(ok.ra); assertEquals(2, ok.answers.size)
        assertEquals("example.com", ok.answers[0].name); assertEquals(1, ok.answers[0].type); assertEquals(300L, ok.answers[0].ttl); assertEquals("93.184.216.34", ok.answers[0].data)
        assertEquals("\"v=spf1 -all\"", ok.answers[1].data)
        val nx = Doh.parse("""{"Status":3,"RA":true,"Authority":[{"name":"com.","type":6,"TTL":900,"data":"a.gtld-servers.net. nstld.verisign-grs.com. 1 1800 900 604800 86400"}]}""")
        assertEquals(3, nx.status); assertTrue(nx.answers.isEmpty()); assertFalse(nx.ad); assertTrue(nx.ra)
        assertEquals(-1, Doh.parse("{}").status)
        try { Doh.parse("<html>blocked</html>"); fail("JSON 이 아니면 예외여야 해요") } catch (_: org.json.JSONException) { }
        assertEquals("https://cloudflare-dns.com/dns-query?name=example.com&type=A", Doh.url("클라우드플레어", "example.com", "A"))
        assertEquals("https://dns.google/resolve?name=a+b.com&type=TXT", Doh.url("구글", "a b.com", "TXT"))
    }

    @Test fun domainRdapParsesDatesStatusAndRegistrarOnly() {
        val i = DomainRdap.parse(rdapJson("2099-08-13T04:00:00Z"))
        assertEquals("EXAMPLE.COM", i.name); assertEquals("Example Registrar, Inc.", i.registrar)
        assertEquals("1995-08-14T04:00:00Z", i.created); assertEquals("2099-08-13T04:00:00Z", i.expires); assertEquals("2024-08-14T07:01:34Z", i.changed)
        assertEquals(listOf("client transfer prohibited", "client update prohibited"), i.status); assertEquals(listOf("a.iana-servers.net", "b.iana-servers.net"), i.nameservers); assertEquals(true, i.dnssec)
        val empty = DomainRdap.parse("{}"); assertNull(empty.name); assertNull(empty.registrar); assertNull(empty.expires); assertTrue(empty.status.isEmpty()); assertNull(empty.dnssec)
    }

    private fun rdapJson(expires: String) = """{"objectClassName":"domain","ldhName":"EXAMPLE.COM","status":["client transfer prohibited","client update prohibited"],
        "events":[{"eventAction":"registration","eventDate":"1995-08-14T04:00:00Z"},{"eventAction":"expiration","eventDate":"$expires"},{"eventAction":"last changed","eventDate":"2024-08-14T07:01:34Z"}],
        "nameservers":[{"objectClassName":"nameserver","ldhName":"A.IANA-SERVERS.NET"},{"objectClassName":"nameserver","ldhName":"B.IANA-SERVERS.NET"}],"secureDNS":{"delegationSigned":true},
        "entities":[{"objectClassName":"entity","roles":["registrar"],"vcardArray":["vcard",[["version",{},"text","4.0"],["fn",{},"text","Example Registrar, Inc."]]]},
        {"objectClassName":"entity","roles":["registrant"],"vcardArray":["vcard",[["version",{},"text","4.0"],["fn",{},"text","Jane Doe"],["email",{},"text","jane.doe@example.org"],["tel",{},"uri","tel:+1.5555550100"]]]}]}"""

    @Test fun lookalikeGeneratesTypoHomoglyphAndTldVariants() {
        val all = Lookalike.generate("example.com", 1000)
        val doms = all.map { it.domain }.toSet()
        assertEquals(all.size, doms.size); assertFalse("example.com" in doms)
        for (d in listOf("xample.com", "exmple.com", "exampl.com", "eexample.com", "examlpe.com", "examp1e.com", "exampie.com", "exarnple.com", "ex4mple.com", "3xample.com", "e-xample.com",
            "example.net", "example.org", "example.co.kr", "wwwexample.com", "examples.com", "example-login.com", "example-support.com")) assertTrue("$d 가 없음", d in doms)
        val cyr = IDN.toASCII("еxample.com")                                                // 첫 글자만 키릴 문자 е(U+0435)
        assertTrue(cyr.startsWith("xn--")); val item = all.first { it.domain == cyr }; assertEquals("еxample.com", item.shown); assertEquals("키릴 글자 위장", item.technique)
        val natural = Lookalike.generate("example.com")
        assertEquals(52, natural.size); assertEquals(11, natural.map { it.technique }.toSet().size)     // 후보가 60개보다 적으면 전부 (7+7+6+6+6+11+5+4)
        val capped = Lookalike.generate("networktoolbox.com")
        assertEquals(60, capped.size); assertEquals(11, capped.map { it.technique }.toSet().size)       // 많으면 60개로 줄이되 11가지 방식이 골고루
        val kr = Lookalike.generate("naver.co.kr", 1000).map { it.domain }
        assertTrue("naver.com" in kr); assertTrue("nver.co.kr" in kr); assertFalse("naver.co.kr" in kr)
        assertTrue(Lookalike.generate("localhost").isEmpty()); assertTrue(Lookalike.generate("www.example.com").isEmpty()); assertTrue(Lookalike.generate("").isEmpty())
    }

    @Test fun emailCheckFormatDisposableAndRole() {
        assertTrue(EmailCheck.problems("name@example.com").isEmpty()); assertTrue(EmailCheck.problems("first.last+tag@sub.example.co.kr").isEmpty())
        for (bad in listOf("name@example", "na me@example.com", "name@exa_mple.com", "name@@example.com", "@example.com", "name@.com", "사용자@example.com", "name@example..com", "not-an-email")) assertTrue("$bad 는 오류여야 해요", EmailCheck.problems(bad).any { it.second == 2 })
        assertTrue(EmailCheck.problems(".name@example.com").any { it.first.contains("점(.)") }); assertTrue(EmailCheck.problems("na..me@example.com").any { it.first.contains("점(.)") })
        assertTrue(EmailCheck.problems("a".repeat(65) + "@example.com").isNotEmpty())                // 앞부분은 64자까지
        assertTrue(EmailCheck.problems("a".repeat(64) + "@" + ("b".repeat(60) + ".").repeat(4) + "com").any { it.first.contains("254자") })
        assertEquals("example.com", EmailCheck.domainOf(" Name@Example.COM ")); assertTrue(EmailCheck.isDisposable("mailinator.com")); assertFalse(EmailCheck.isDisposable("gmail.com"))
        assertTrue(EmailCheck.isRole("Admin@x.com")); assertTrue(EmailCheck.isRole("no-reply@x.com")); assertFalse(EmailCheck.isRole("john@x.com"))
    }

    @Test fun zoneLintTtlNotation() {
        assertEquals(3600L, ZoneLint.ttlOf("3600")); assertEquals(3600L, ZoneLint.ttlOf("1h")); assertEquals(129600L, ZoneLint.ttlOf("1d12h")); assertEquals(1209600L, ZoneLint.ttlOf("2W"))
        assertEquals(90L, ZoneLint.ttlOf("90s")); assertEquals(5400L, ZoneLint.ttlOf("1h30m"))
        for (bad in listOf("", "abc", "A", "MX", "1x", "h1")) assertNull("$bad", ZoneLint.ttlOf(bad))
    }

    private fun lint(vararg lines: String) = ZoneLint.lint(lines.joinToString("\n"))
    private fun List<Triple<Int, String, Int>>.has(line: Int, fragment: String, level: Int) = any { it.first == line && fragment in it.second && it.third == level }

    @Test fun zoneLintFindsTheClassicMistakes() {
        val sample = lint("\$ORIGIN example.com.", "\$TTL 3600", "@ IN SOA ns1.example.com. admin.example.com. ( 2024010101 7200 3600 1209600 3600 )", "@ IN NS ns1.example.com.", "@ IN MX 10 mail.example.com.",
            "www IN CNAME example.com.", "www IN A 203.0.113.10", "mail IN A 192.168.1.5", "ftp IN CNAME files.example.com", "@ IN TXT \"v=spf1 mx -all\"")
        assertEquals(4, sample.size)
        assertTrue(sample.has(0, "NS 가 1개예요", 1))
        assertTrue(sample.has(6, "\"www\" 에 CNAME 과 다른 레코드(A)가 함께 있어요", 2))
        assertTrue(sample.has(8, "사설·내부 주소(192.168.1.5)", 1))
        assertTrue(sample.has(9, "\"files.example.com\" 끝에 점(.)이 없어요 — 점이 없으면 \"files.example.com.example.com.\" 로 해석돼요", 1))
        assertEquals(listOf(0, 6, 8, 9), sample.map { it.first })                                  // 줄 번호 순서

        val z = listOf(
            "; zone for test", "\$ORIGIN example.org.", "\$TTL 1h",
            "@   IN  SOA ns1.example.org. hostmaster.example.org. (", "        1          ; serial", "        7200       ; refresh", "        3600       ; retry", "        1209600    ; expire", "        300 )      ; minimum",
            "    IN  NS  ns1.example.org.", "    IN  NS  ns2.example.org.",
            "@   IN  CNAME other.example.net.",                              // 12
            "@   30  IN  A   999.1.1.1",                                     // 13
            "@   IN  AAAA 192.0.2.1",                                        // 14
            "@   IN  MX  mail.example.org.",                                 // 15
            "@   IN  MX  10 192.0.2.5",                                      // 16
            "@   IN  TXT \"v=spf1 a -all\"",                                 // 17
            "@   IN  TXT \"v=spf1 mx -all\"",                                // 18
            "long IN TXT \"${"a".repeat(300)}\"",                            // 19
            "joined IN TXT \"k=v; not a comment\"",                          // 20
            "dup IN A 1.2.3.4", "dup IN A 1.2.3.4",                          // 21, 22
            "obs IN SPF \"v=spf1 -all\"",                                    // 23
            "x IN FOO bar",                                                  // 24
            "old 99999999 IN A 5.6.7.8",                                     // 25
            "mail IN MX 10 mx.example.org")                                  // 26
        val r = ZoneLint.lint(z.joinToString("\n"))
        assertTrue(r.has(4, "SOA 일련번호(1)가 YYYYMMDDnn 형식이 아니에요", 0))          // 여러 줄로 나눠 쓴 SOA 는 시작 줄 번호로, 괄호 안 주석(;)은 무시
        assertTrue(r.has(12, "영역 최상단(@)에는 CNAME 을 쓸 수 없어요", 2)); assertTrue(r.has(12, "CNAME 과 다른 레코드(SOA, NS, A, AAAA, MX, TXT)", 2))
        assertTrue(r.has(13, "A 레코드 값이 IPv4 주소가 아니에요: 999.1.1.1", 2)); assertTrue(r.has(13, "TTL 30초는 너무 짧아요", 1))
        assertTrue(r.has(14, "AAAA 레코드 값이 IPv6 주소가 아니에요: 192.0.2.1", 2))
        assertTrue(r.has(15, "MX 앞의 우선순위가 숫자가 아니에요", 2)); assertTrue(r.has(16, "MX 는 IP 주소가 아니라 호스트 이름이어야 해요", 2))
        assertTrue(r.has(18, "SPF 레코드가 2개예요", 2)); assertTrue(r.has(19, "255바이트를 넘어요", 2))
        assertTrue(r.has(22, "똑같은 레코드가 중복돼 있어요: dup A 1.2.3.4", 1)); assertTrue(r.has(23, "SPF 레코드 종류는 폐기됐어요", 1)); assertTrue(r.has(24, "알 수 없는 레코드 종류: FOO", 2))
        assertTrue(r.has(25, "TTL 99999999초(1157일)는 너무 길어요", 1)); assertTrue(r.has(26, "\"mx.example.org\" 끝에 점(.)이 없어요", 1))
        assertTrue("따옴표 안의 ; 는 주석이 아니고 \$TTL 1h 는 올바른 표기", r.none { it.first == 20 || it.first == 3 })
        assertTrue("NS 가 둘이면 NS 개수 안내가 없어야 해요", r.none { "NS 가" in it.second })
        assertEquals(r.sortedWith(compareBy({ it.first }, { -it.third })), r)                           // 줄 번호 순, 같은 줄은 심각한 것 먼저

        assertEquals(listOf(Triple(0, "레코드를 찾지 못했어요", 2)), ZoneLint.lint("; 비어 있음\n\n"))
        val noDot = lint("\$ORIGIN example.com", "@ IN SOA ns1.example.com. h.example.com. 2024010101 1 1 1 1", "@ IN NS ns1.example.com.")
        assertTrue(noDot.has(1, "\$ORIGIN 은 점(.)으로 끝나야 해요", 2))
        assertTrue(lint("@ IN NS ns1.example.com.", "@ IN NS ns2.example.com.").has(0, "SOA 레코드가 없어요", 2))
        val noMail = lint("@ IN SOA ns1.x. h.x. 2024010101 1 1 1 1", "@ IN NS a.x.", "@ IN NS b.x.", "@ IN TXT \"v=spf1 ~all\"")
        assertTrue(noMail.has(0, "메일을 안 받는 영역이라면", 0))
        assertTrue(lint("@ IN SOA ns1.x. h.x. 2024010101 1 1", "@ IN NS a.x.", "@ IN NS b.x.").has(1, "SOA 값이 7개", 2))
        assertTrue(lint("@ IN SOA ns1.x. h.x. 2024010101 1 1 1 1", "@ IN SOA ns2.x. h.x. 2024010102 1 1 1 1", "@ IN NS a.x.", "@ IN NS b.x.").has(2, "SOA 가 2개예요", 2))
        assertTrue(lint("@ IN SOA ns1.x. h.x. 2024010101 1 1 1 1", "@ IN NS a.x.", "@ IN NS b.x.", "www IN CNAME a", "www IN CNAME b").has(5, "CNAME 이 여러 개예요", 2))
    }

    // ============================================================ 도구: DoH·DoT

    @Test fun toolDnsDohReadsJsonFromProviders() {
        val urls = ArrayList<String>()
        GeoNet.fetcher = { u -> urls += u; """{"Status":0,"RA":true,"AD":true,"Answer":[{"name":"example.com.","type":1,"TTL":300,"data":"93.184.216.34"}]}""" }
        val r = run("dns_doh", "d" to "https://Example.com/path", "t" to "A", "p" to "클라우드플레어")
        assertEquals("https://cloudflare-dns.com/dns-query?name=example.com&type=A", urls.single())
        assertEquals(listOf("example.com", "A", "300", "93.184.216.34"), r.rows().single()); assertEquals("검증됨", r.kv("DNSSEC 검증(AD)")); assertEquals(DnsType.rcode(0), r.kv("응답 코드")); assertEquals(-1, r.kvLevel("응답 코드"))
        urls.clear(); run("dns_doh", "d" to "example.com", "t" to "MX", "p" to "구글"); assertEquals("https://dns.google/resolve?name=example.com&type=MX", urls.single())
        GeoNet.fetcher = { """{"Status":3}""" }; val nx = run("dns_doh", "d" to "nope.example.com", "t" to "A", "p" to "구글"); assertTrue(nx.hasError); assertTrue(nx.text().contains("NXDOMAIN: 그런 도메인이 없어요"))
        GeoNet.fetcher = { """{"Status":0}""" }; val nodata = run("dns_doh", "d" to "example.com", "t" to "TXT", "p" to "구글"); assertFalse(nodata.hasError); assertEquals(1, nodata.noteWith("TXT 레코드가 없어요")?.level)
        GeoNet.fetcher = { """{"Status":2}""" }; assertTrue(run("dns_doh", "d" to "example.com", "t" to "A", "p" to "구글").text().contains("SERVFAIL"))
        GeoNet.fetcher = { throw IOException("서버가 503 으로 답했어요") }; val e = run("dns_doh", "d" to "example.com", "t" to "A", "p" to "구글"); assertTrue(e.hasError); assertTrue(e.text().contains("503"))
        GeoNet.fetcher = { "<html>blocked</html>" }; assertTrue(run("dns_doh", "d" to "example.com", "t" to "A", "p" to "구글").text().contains("응답을 읽지 못했어요"))
        assertTrue(run("dns_doh", "d" to "", "t" to "A", "p" to "구글").text().contains("도메인을 입력하세요"))
    }

    private fun dotServer(answer: (ByteArray) -> ByteArray?) = TestTcp { c0 ->
        val ssl = upgradeServerTls(c0); val ins = ssl.inputStream
        val len = (ins.read() shl 8) or ins.read()
        val q = ByteArray(len); var got = 0
        while (got < len) { val r = ins.read(q, got, len - got); if (r < 0) break; got += r }
        val resp = answer(q) ?: return@TestTcp
        ssl.outputStream.write(byteArrayOf((resp.size shr 8).toByte(), resp.size.toByte()) + resp); ssl.outputStream.flush()
    }.track()

    @Test fun toolDnsDotAsksOverTls() {
        val seen = java.util.concurrent.CopyOnWriteArrayList<Pair<String, Int>>()
        val s = dotServer { q -> val (n, p) = DnsWire.readName(q, 12); seen += n to (((q[p].toInt() and 0xff) shl 8) or (q[p + 1].toInt() and 0xff)); dnsReply(q, 0, listOf(DnsAns.A("93.184.216.34"))) }
        val r = run("dns_dot", "s" to "127.0.0.1", "d" to "Example.com", "t" to "A", "port" to s.port.toString())
        assertTrue(r.kv("DoT 서버"), r.kv("DoT 서버").startsWith("127.0.0.1:${s.port} (127.0.0.1)")); assertEquals("TLSv1.3", r.kv("TLS")); assertEquals(-1, r.kvLevel("TLS"))
        assertEquals(1, r.kvLevel("인증서")); assertFalse(r.kv("인증서").contains("믿을 수 있어요")); assertEquals("일치", r.kv("이름 일치"))        // 시험용 자체 서명 인증서
        assertTrue(r.text().contains("93.184.216.34")); assertEquals(listOf("example.com" to DnsType.A), seen.toList())
        // 서버가 답 없이 닫음, TLS 가 아닌 서버
        val silent = dotServer { null }
        assertTrue(run("dns_dot", "s" to "127.0.0.1", "d" to "example.com", "t" to "A", "port" to silent.port.toString()).hasError)
        val plain = TestTcp { c -> c.getOutputStream().write("hello\r\n".toByteArray()) }.track()
        val pr = run("dns_dot", "s" to "127.0.0.1", "d" to "example.com", "t" to "A", "port" to plain.port.toString()); assertTrue(pr.hasError); assertTrue(pr.text().contains("접속·조회하지 못했어요"))
        assertTrue(run("dns_dot", "s" to "", "d" to "example.com", "t" to "A").text().contains("서버를 입력하세요"))
        assertTrue(run("dns_dot", "s" to "224.0.0.1", "d" to "example.com", "t" to "A").hasError)                                              // 멀티캐스트 주소는 연결 불가
    }

    // ============================================================ 도구: DNS 변조·전파·SOA·와일드카드·CNAME

    @Test fun toolDnsHijackComparesWithDohAndFindsFakeAnswers() {
        val dohAnswers = mapOf("google.com" to "8.8.8.8", "cloudflare.com" to "1.1.1.1", "wikipedia.org" to "208.80.154.224", "github.com" to "140.82.112.3", "microsoft.com" to "20.70.246.20")
        GeoNet.fetcher = { url -> val name = Regex("name=([^&]+)").find(url)!!.groupValues[1]; """{"Status":0,"RA":true,"Answer":[{"name":"$name.","type":1,"TTL":60,"data":"${dohAnswers[name]}"}]}""" }
        val honest = FakeZone().a("google.com", "8.8.8.8").a("cloudflare.com", "1.1.1.1").a("wikipedia.org", "208.80.154.224").a("github.com", "140.82.112.3").a("microsoft.com", "20.70.246.20")
        val ok = run("dns_hijack", host = TestHost(dns = listOf(fakeDns(honest).server)))
        assertEquals(5, ok.rows().size); assertTrue(ok.rows().all { it[3] == "DoH 와 일치" }); assertEquals("google.com", ok.rows()[0][0]); assertEquals("8.8.8.8", ok.rows()[0][1]); assertEquals("8.8.8.8", ok.rows()[0][2])
        assertEquals("NXDOMAIN (정상)", ok.kv("무작위 이름 조회")); assertTrue(ok.text().contains("뚜렷한 변조 신호는 없어요")); assertFalse(ok.hasError)

        // 변조: github.com 은 사설 주소, microsoft.com 은 엉뚱한 회사(구글) 주소, 없는 이름에도 가짜 IP
        val bad = FakeZone().a("google.com", "8.8.8.8").a("cloudflare.com", "1.1.1.1").a("wikipedia.org", "208.80.154.224").a("github.com", "192.168.1.1").a("microsoft.com", "8.8.8.8")
        val badDns = fakeDns(bad) { n, t -> if (n.startsWith("selfcheck-") && t == DnsType.A) 0 to listOf<DnsAns>(DnsAns.A("198.51.100.77")) else null }
        val h = run("dns_hijack", host = TestHost(dns = listOf(badDns.server)))
        assertEquals("내부·예약 주소를 돌려줘요 (192.168.1.1) — 의심", h.row("github.com")[3]); assertEquals(2, h.rowLevel("github.com"))
        assertEquals("다른 회사(Google LLC) 주소 — 의심", h.row("microsoft.com")[3]); assertEquals(2, h.rowLevel("microsoft.com"))
        assertEquals("DoH 와 일치", h.row("google.com")[3]); assertEquals("가짜 IP 를 돌려줘요: 198.51.100.77", h.kv("무작위 이름 조회")); assertEquals(2, h.kvLevel("무작위 이름 조회"))
        assertTrue(h.hasError); assertTrue(h.text().contains("의심스러운 응답이 있어요"))

        // CDN: 주소는 달라도 같은 회사(구글)면 정상
        val cdn = FakeZone().a("google.com", "142.250.196.110").a("cloudflare.com", "1.1.1.1").a("wikipedia.org", "208.80.154.224").a("github.com", "140.82.112.3").a("microsoft.com", "20.70.246.20")
        val c = run("dns_hijack", host = TestHost(dns = listOf(fakeDns(cdn).server)))
        assertEquals("주소는 달라도 같은 회사(CDN 정상)", c.row("google.com")[3]); assertEquals(-1, c.rowLevel("google.com")); assertFalse(c.hasError)
    }

    @Test fun toolDnsPropagationComparesServers() {
        val a = fakeDns(FakeZone().a("example.com", "93.184.216.34")); val b = fakeDns(FakeZone().a("example.com", "93.184.216.34")); val c = fakeDns(FakeZone().a("example.com", "93.184.216.35"))
        MailTools.propagationResolvers = listOf(b.server to "B서버", c.server to "C서버")
        val host = TestHost(dns = listOf(a.server))
        val r = run("dns_propagation", "d" to "example.com", "t" to "A", "e" to "93.184.216.34", host = host)
        assertEquals("3 / 3", r.kv("답한 서버")); assertEquals("2 / 3", r.kv("기대값과 일치")); assertEquals(1, r.kvLevel("기대값과 일치"))
        assertEquals(listOf("일치", "일치", "다름"), r.rows().map { it[3] }); assertEquals(listOf("내 DNS (${a.server})", "B서버 (${b.server})", "C서버 (${c.server})"), r.rows().map { it[0] }); assertEquals("60", r.rows()[0][2])
        assertTrue(r.text().contains("서버마다 값이 달라요")); assertEquals(2, r.rowLevel("C서버 (${c.server})"))
        // 기대값 없이: 다수와 다른 서버를 표시
        val r2 = run("dns_propagation", "d" to "example.com", "t" to "A", host = host)
        assertEquals("2 / 3", r2.kv("다수와 같은 값")); assertEquals(listOf("응답", "응답", "다수와 다름"), r2.rows().map { it[3] }); assertTrue(r2.text().contains("서버마다 값이 달라요")); assertFalse(r2.text().contains("전파가 끝났어요"))
        // 모두 같으면 끝난 것
        MailTools.propagationResolvers = listOf(b.server to "B서버")
        val r3 = run("dns_propagation", "d" to "example.com", "t" to "A", host = host); assertEquals("2 / 2", r3.kv("다수와 같은 값")); assertTrue(r3.text().contains("전파가 끝났어요")); assertEquals(-1, r3.kvLevel("다수와 같은 값"))
        // 없는 이름
        val nx = run("dns_propagation", "d" to "nope.example.org", "t" to "A", host = host); assertTrue(nx.rows().all { it[1] == "NXDOMAIN" }); assertEquals("0 / 2", nx.kv("다수와 같은 값"))
    }

    @Test fun toolDnsSoaSyncComparesSerialsOfEachNameserver() {
        val s1 = fakeDns(FakeZone().raw("example.com", DnsType.SOA, soaData(2024010101))); val s2 = fakeDns(FakeZone().raw("example.com", DnsType.SOA, soaData(2024010102)))
        val resolver = fakeDns(FakeZone().ns("example.com", "ns1.example.net").ns("example.com", "ns2.example.net").ns("example.com", "ns3.example.net").a("ns1.example.net", "127.0.0.1").a("ns2.example.net", "127.0.0.1"))
        MailTools.nsPorts = mapOf("ns1.example.net" to s1.port, "ns2.example.net" to s2.port)
        val r = run("dns_soa_sync", "d" to "example.com", "server" to resolver.server)
        assertEquals(listOf(listOf("ns1.example.net", "127.0.0.1", "2024010101"), listOf("ns2.example.net", "127.0.0.1", "2024010102"), listOf("ns3.example.net", "주소를 못 찾음", "응답 없음")), r.rows())
        assertEquals("3개", r.kv("네임서버")); assertTrue(r.hasError); assertTrue(r.text().contains("네임서버마다 일련번호가 달라요(2024010101, 2024010102)")); assertEquals(2, r.rowLevel("ns1.example.net")); assertEquals(1, r.rowLevel("ns3.example.net"))
        // 서버에 SOA 질문이 정말 도착했는지 (재귀 요청 없이 권한 서버에 직접)
        assertTrue(s1.queries.any { it == ("example.com" to DnsType.SOA) }); assertTrue(s2.queries.any { it == ("example.com" to DnsType.SOA) })
        // 일련번호가 모두 같고 서버가 1개뿐
        val only = fakeDns(FakeZone().ns("example.org", "ns1.example.net").a("ns1.example.net", "127.0.0.1"))
        val same = fakeDns(FakeZone().raw("example.org", DnsType.SOA, soaData(7)))
        MailTools.nsPorts = mapOf("ns1.example.net" to same.port)
        val o = run("dns_soa_sync", "d" to "example.org", "server" to only.server); assertFalse(o.hasError); assertEquals(7L.toString(), o.rows()[0][2]); assertTrue(o.text().contains("일련번호가 같아요 (7)")); assertEquals(1, o.noteWith("네임서버가 1개뿐이에요")?.level)
        assertTrue(run("dns_soa_sync", "d" to "nodomain.example", "server" to only.server).hasError)                                       // NS 가 없는 이름
    }

    @Test fun toolDnsWildcardDetectsCatchAll() {
        val wild = fakeDns(FakeZone()) { n, t -> if (n.endsWith(".wild.example") && t == DnsType.A) 0 to listOf<DnsAns>(DnsAns.A("203.0.113.9")) else null }
        val r = run("dns_wildcard", "d" to "wild.example", "server" to wild.server)
        assertEquals(3, r.rows().size); assertTrue(r.rows().all { it[0].startsWith("selfcheck-") && it[0].endsWith(".wild.example") && it[1] == "203.0.113.9" })
        assertEquals(1, r.noteWith("와일드카드가 있어요")?.level); assertEquals(3, wild.queries.count { it.second == DnsType.A && it.first.startsWith("selfcheck-") })
        val plain = fakeDns(FakeZone().a("www.plain.example", "203.0.113.5"))
        val p = run("dns_wildcard", "d" to "plain.example", "server" to plain.server)
        assertTrue(p.rows().all { it[1] == "NXDOMAIN (없음)" }); assertEquals(-1, p.noteWith("와일드카드가 없어요")?.level)
    }

    @Test fun toolDnsCnameChainFollowsAndWarnsAboutDanglingTargets() {
        // 사라진 외부 서비스를 가리키는 CNAME → 서브도메인 탈취 위험
        val dangling = fakeDns(FakeZone().cname("www.example.com", "shop.herokuapp.com")) { n, _ -> if (n == "shop.herokuapp.com") 3 to emptyList<DnsAns>() else null }
        val d = run("dns_cname_chain", "d" to "www.example.com", "server" to dangling.server)
        assertEquals(listOf("www.example.com → shop.herokuapp.com"), d.kvAll("→")); assertEquals("shop.herokuapp.com", d.kv("최종 이름")); assertEquals("NXDOMAIN (없음)", d.kv("최종 주소")); assertEquals(2, d.kvLevel("최종 주소"))
        assertTrue(d.hasError); assertTrue(d.text().contains("서브도메인 탈취")); assertTrue(d.text().contains("herokuapp.com"))
        // 정상: 두 단계 뒤 구글 주소
        val ok = fakeDns(FakeZone().cname("blog.example.com", "ghs.example.net").cname("ghs.example.net", "edge.example.org").a("edge.example.org", "8.8.8.8"))
        val r = run("dns_cname_chain", "d" to "blog.example.com", "server" to ok.server)
        assertEquals(listOf("blog.example.com → ghs.example.net", "ghs.example.net → edge.example.org"), r.kvAll("→")); assertTrue(r.text().contains("CNAME 체인 (2단계)")); assertEquals("edge.example.org", r.kv("최종 이름")); assertEquals("8.8.8.8", r.kv("최종 주소"))
        assertTrue(r.kv("나라 · 통신사").contains("Google LLC")); assertTrue(r.kv("나라 · 통신사").contains(CountryNames.ko("US"))); assertFalse(r.hasError)
        // 고리
        val loop = fakeDns(FakeZone().cname("a.example.com", "b.example.com").cname("b.example.com", "a.example.com"))
        val l = run("dns_cname_chain", "d" to "a.example.com", "server" to loop.server); assertTrue(l.hasError); assertTrue(l.text().contains("고리(루프)"))
        // 별칭이 아님 / 살아 있는 외부 서비스
        val plain = fakeDns(FakeZone().a("plain.example.com", "8.8.8.8")); val pr = run("dns_cname_chain", "d" to "plain.example.com", "server" to plain.server)
        assertEquals("없음 (이 이름은 별칭이 아니에요)", pr.kv("CNAME")); assertEquals("8.8.8.8", pr.kv("최종 주소"))
        val ext = fakeDns(FakeZone().cname("docs.example.com", "myorg.github.io").a("myorg.github.io", "185.199.108.153"))
        val er = run("dns_cname_chain", "d" to "docs.example.com", "server" to ext.server); assertEquals(0, er.noteWith("외부 서비스(github.io)를 가리켜요")?.level); assertFalse(er.hasError)
    }

    // ============================================================ 도구: SPF·DKIM·MTA-STS·주소·FCrDNS

    @Test fun toolMailSpfEvalUsesLiveDnsChain() {
        val dns = fakeDns(FakeZone().txt("example.com", "v=spf1 ip4:192.0.2.0/24 include:_spf.mailer.net -all").txt("_spf.mailer.net", "v=spf1 ip4:198.51.100.0/24 ~all"))
        val pass = run("mail_spf_eval", "d" to "example.com", "ip" to "198.51.100.7", "server" to dns.server)
        assertEquals("PASS", pass.kv("판정")); assertEquals(-1, pass.kvLevel("판정")); assertEquals("1 / 10", pass.kv("DNS 조회")); assertTrue(pass.blocks().contains("_spf.mailer.net: v=spf1")); assertTrue(pass.text().contains("허가됐어요"))
        val direct = run("mail_spf_eval", "d" to "example.com", "ip" to "192.0.2.50", "server" to dns.server); assertEquals("PASS", direct.kv("판정")); assertEquals("0 / 10", direct.kv("DNS 조회"))
        val fail = run("mail_spf_eval", "d" to "example.com", "ip" to "203.0.113.9", "server" to dns.server)
        assertEquals("FAIL", fail.kv("판정")); assertEquals(2, fail.kvLevel("판정")); assertTrue(fail.hasError); assertTrue(fail.text().contains("허가되지 않은 IP"))
        val none = run("mail_spf_eval", "d" to "nospf.example.net", "ip" to "198.51.100.7", "server" to dns.server); assertEquals("NONE", none.kv("판정")); assertTrue(none.text().contains("SPF 레코드가 없어요"))
        val servfail = fakeDns(FakeZone()) { n, _ -> if (n == "broken.example.net") 2 to emptyList<DnsAns>() else null }
        assertEquals("TEMPERROR", run("mail_spf_eval", "d" to "broken.example.net", "ip" to "198.51.100.7", "server" to servfail.server).kv("판정"))
        assertTrue(run("mail_spf_eval", "d" to "example.com", "ip" to "", "server" to dns.server).text().contains("IP 를 입력하세요")); assertTrue(run("mail_spf_eval", "d" to "example.com", "ip" to "x", "server" to dns.server).hasError)
        // 11번째 조회에서 permerror
        val z = FakeZone().txt("big.example.com", "v=spf1 " + (1..11).joinToString(" ") { "include:i$it.example.net" } + " -all"); for (k in 1..11) z.txt("i$k.example.net", "v=spf1 ip4:10.$k.0.0/16 -all")
        val big = run("mail_spf_eval", "d" to "big.example.com", "ip" to "8.8.8.8", "server" to fakeDns(z).server); assertEquals("PERMERROR", big.kv("판정")); assertTrue(big.text().contains("10번을 넘었어요")); assertTrue(big.hasError)
    }

    @Test fun toolMailSpfFlattenBuildsIpOnlyRecord() {
        val z = FakeZone().txt("example.com", "v=spf1 mx a:relay.example.com include:_spf.mailer.net ip4:192.0.2.5 ~all").txt("_spf.mailer.net", "v=spf1 ip4:198.51.100.0/24 ip6:2001:db8::/32 -all")
            .mx("example.com", 10, "mx1.example.com").a("mx1.example.com", "203.0.113.25").a("relay.example.com", "203.0.113.80")
        val r = run("mail_spf_flatten", "d" to "example.com", "server" to fakeDns(z).server)
        assertEquals("v=spf1 ip4:203.0.113.25 ip4:203.0.113.80 ip4:198.51.100.0/24 ip6:2001:db8::/32 ip4:192.0.2.5 ~all", r.blocks().lines().first { it.startsWith("v=spf1") })
        assertEquals("3회", r.kv("원래 DNS 조회 수")); assertEquals("5개", r.kv("IP 항목")); assertEquals("0회 (ip4/ip6 만)", r.kv("평탄화 후")); assertFalse(r.hasError)
        // 255자가 넘으면 TXT 를 나눠 넣는 방법도 알려 줌
        val many = FakeZone().txt("big.example.com", "v=spf1 " + (1..40).joinToString(" ") { "ip4:198.51.100.$it" } + " -all")
        val m = run("mail_spf_flatten", "d" to "big.example.com", "server" to fakeDns(many).server)
        assertTrue(m.text().contains("255자를 넘어서")); assertTrue(m.blocks().lines().any { it.startsWith("\"v=spf1 ") && it.contains("\" \"") })
        assertTrue(run("mail_spf_flatten", "d" to "nospf.example.net", "server" to fakeDns(FakeZone()).server).text().contains("풀어낼 IP 가 없어요"))
    }

    private val key2048 = "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAo16JLaVv4sX8RyDgkINgG9iP8OZ09ij9EYB5J9uXgPO2xQmaqFBrMo9PqRIBIZEsE6FY9brIqR7tTvaFDINvYWY6Z36fQdY5C7pfQ1PlaKiKDI8EclTJw+nv6WltRS0k1zRSmwGPH0SxV/0NwbCl9iSzRYETAnaKh37MIqSoen7Hh3ht4wceBIYlQyCQZjgjAykRO9PDYVGmGgrPsXO5it1k4ULrWf9vJizPuoVMJ+nS6Uq33Cd6NirmR/ccxYyzNVXRoIbErqMT+GwTyp7qqIwZjz38inLGebDcDq8Lu3kMVyKUarbJkQ+9NTTA8wUtBmdQ1dChU2J83Y/25r6uIwIDAQAB"
    private val key1024 = "MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDUDR4Lp90ro9hstWlC6P9DpHs7T5l7GNWZtltARdZfw1lC1fZgblFjm36Jti+nktZ6a/HZHdZdSasjnHqFpt99sfipefJQjVhh7PjGq9F1xqSXZhve8GBj4cuq1ytssepKOD7WVHDCbawjSxbeff2Dphb2OloKP0ZQ3gqfCqASNwIDAQAB"

    @Test fun toolMailDkimSelectorsFindsKeysAndGuessesProviders() {
        val z = FakeZone().txt("google._domainkey.example.com", "v=DKIM1; k=rsa; p=$key2048")
            .cname("selector1._domainkey.example.com", "selector1-example-com._domainkey.example.onmicrosoft.com")
            .txt("k1._domainkey.example.com", "v=DKIM1; k=rsa; t=y; p=$key1024")
        val dns = fakeDns(z)
        val r = run("mail_dkim_selectors", "d" to "example.com", "server" to dns.server)
        assertEquals("3개 (확인 35개)", r.kv("찾은 선택자")); assertEquals(-1, r.kvLevel("찾은 선택자"))
        assertEquals(listOf("google", "selector1", "k1"), r.rows().map { it[0] })                       // 선택자 목록의 순서대로
        assertEquals("RSA 2048비트", r.row("google")[1]); assertTrue(r.row("google")[2].contains("키 길이가 충분해요")); assertEquals(-1, r.rowLevel("google"))
        assertEquals("CNAME", r.row("selector1")[1]); assertEquals("→ selector1-example-com._domainkey.example.onmicrosoft.com", r.row("selector1")[2])
        assertEquals("RSA 1024비트", r.row("k1")[1]); assertEquals(1, r.rowLevel("k1"))
        val guess = r.noteWith("선택자 이름으로 짐작한 메일 서비스")!!.text; assertTrue(guess.contains("마이크로소프트 365")); assertTrue(guess.contains("구글 워크스페이스")); assertTrue(guess.contains("메일침프"))
        assertEquals(1, r.noteWith("2048비트 미만 키가 있어요")?.level)
        assertEquals(35, dns.queries.count { it.second == DnsType.TXT && it.first.endsWith("._domainkey.example.com") })
        val none = run("mail_dkim_selectors", "d" to "example.net", "server" to fakeDns(FakeZone()).server); assertEquals("0개 (확인 35개)", none.kv("찾은 선택자")); assertEquals(1, none.kvLevel("찾은 선택자")); assertTrue(none.text().contains("자주 쓰는 선택자로는 찾지 못했어요"))
    }

    @Test fun toolMailMtaStsReadsPolicyAndRelatedRecords() {
        val z = FakeZone().txt("_mta-sts.example.com", "v=STSv1; id=20240101T000000").txt("_smtp._tls.example.com", "v=TLSRPTv1; rua=mailto:tls-reports@example.com").txt("default._bimi.example.com", "v=BIMI1; l=https://example.com/logo.svg")
        val dns = fakeDns(z)
        val urls = ArrayList<String>()
        GeoNet.fetcher = { u -> urls += u; "version: STSv1\nmode: enforce\nmx: *.example.com\nmx: mail.example.net\nmax_age: 604800\n" }
        val r = run("mail_mta_sts", "d" to "example.com", "server" to dns.server)
        assertEquals(listOf("https://mta-sts.example.com/.well-known/mta-sts.txt"), urls)
        assertEquals(listOf("v=STSv1; id=20240101T000000", "v=TLSRPTv1; rua=mailto:tls-reports@example.com", "v=BIMI1; l=https://example.com/logo.svg"), r.kvAll("DNS 레코드"))
        assertEquals("enforce", r.kv("모드")); assertEquals(-1, r.kvLevel("모드")); assertEquals(listOf("*.example.com", "mail.example.net"), r.kvAll("허용 MX")); assertEquals("7일 (604800초)", r.kv("유효 기간"))
        assertEquals("mailto:tls-reports@example.com", r.kv("보고 받을 곳")); assertEquals("https://example.com/logo.svg", r.kv("로고 주소")); assertTrue(r.text().contains("enforce 모드")); assertFalse(r.hasError)
        GeoNet.fetcher = { "version: STSv1\nmode: testing\nmx: mail.example.net\nmax_age: 3600\n" }
        val t = run("mail_mta_sts", "d" to "example.com", "server" to dns.server); assertEquals(1, t.kvLevel("모드")); assertEquals(1, t.noteWith("testing 모드")?.level); assertEquals(1, t.kvLevel("유효 기간"))
        GeoNet.fetcher = { throw IOException("서버가 404 로 답했어요") }
        val missing = run("mail_mta_sts", "d" to "example.com", "server" to dns.server); assertTrue(missing.hasError); assertTrue(missing.text().contains("정책 파일(https://mta-sts.example.com/.well-known/mta-sts.txt)을 받지 못했어요"))
        urls.clear(); GeoNet.fetcher = { u -> urls += u; "" }
        val bare = run("mail_mta_sts", "d" to "example.net", "server" to dns.server); assertEquals("없음", bare.kv("DNS 레코드")); assertEquals(1, bare.kvLevel("DNS 레코드")); assertTrue(bare.text().contains("MTA-STS 가 없으면")); assertTrue(urls.isEmpty())   // DNS 에 없으면 정책 파일을 받으러 가지 않음
    }

    @Test fun toolMailAddressCheckLooksAtDomainOnly() {
        val z = FakeZone().mx("example.com", 20, "mx2.example.com").mx("example.com", 10, "mx1.example.com").a("bare.example.org", "192.0.2.1").mx("nullmx.example.net", 0, ".").mx("mailinator.com", 10, "mx.mailinator.com")
        val dns = fakeDns(z)
        val ok = run("mail_address_check", "a" to "Name@Example.com", "server" to dns.server)
        assertEquals("올바른 형식이에요", ok.kv("형식")); assertEquals("mx1.example.com, mx2.example.com", ok.kv("메일 서버(MX)")); assertEquals(-1, ok.kvLevel("메일 서버(MX)")); assertEquals("아니요(알려진 목록 기준)", ok.kv("일회용 메일")); assertEquals("아니요", ok.kv("역할 주소"))
        assertTrue(ok.text().contains("주소 형식과 도메인의 메일 서버는 정상이에요")); assertTrue(ok.text().contains("사서함(@ 앞부분)이 실제로 있는지는 확인할 수 없어요")); assertFalse(ok.hasError)
        assertTrue(run("mail_address_check", "a" to "info@example.com", "server" to dns.server).kv("역할 주소").startsWith("예"))
        val disp = run("mail_address_check", "a" to "x@mailinator.com", "server" to dns.server); assertTrue(disp.kv("일회용 메일").startsWith("예")); assertEquals(1, disp.kvLevel("일회용 메일"))
        val bare = run("mail_address_check", "a" to "user@bare.example.org", "server" to dns.server); assertEquals("MX 없음 (A 레코드로 받아요)", bare.kv("메일 서버(MX)")); assertEquals(-1, bare.kvLevel("메일 서버(MX)"))
        val nul = run("mail_address_check", "a" to "user@nullmx.example.net", "server" to dns.server); assertEquals("받지 않는 도메인(Null MX)", nul.kv("메일 서버(MX)")); assertTrue(nul.hasError); assertTrue(nul.text().contains("이 도메인은 메일을 받지 않아요"))
        val gone = run("mail_address_check", "a" to "user@nowhere.example.org", "server" to dns.server); assertEquals("없음 — 이 도메인은 메일을 받을 수 없어요", gone.kv("메일 서버(MX)")); assertTrue(gone.hasError)
        val badFmt = run("mail_address_check", "a" to "not-an-email", "server" to dns.server); assertEquals(2, badFmt.kvLevel("형식")); assertFalse(badFmt.hasKv("메일 서버(MX)")); assertTrue(badFmt.hasError); assertTrue(badFmt.text().contains("형식이 틀려서 메일을 받을 수 없어요"))
        assertTrue(run("mail_address_check", "a" to "", "server" to dns.server).text().contains("이메일 주소를 입력하세요"))
        // 메일 서버에는 접속하지 않음: DNS 질문(MX·A)만 갔는지
        assertTrue(dns.queries.all { it.second == DnsType.MX || it.second == DnsType.A })
    }

    @Test fun toolMailFcrdnsMatchesReverseAndForward() {
        val z = FakeZone().ptr("41.220.85.209.in-addr.arpa", "mail-sor-f41.google.com").a("mail-sor-f41.google.com", "209.85.220.41")
            .ptr("9.2.0.192.in-addr.arpa", "192-0-2-9.dynamic.example.net").a("192-0-2-9.dynamic.example.net", "192.0.2.9")
        val dns = fakeDns(z)
        val ok = run("mail_fcrdns", "ip" to "209.85.220.41", "server" to dns.server)
        assertEquals("mail-sor-f41.google.com", ok.kv("역방향 이름(PTR)")); assertEquals("예", ok.kv("FCrDNS 일치")); assertEquals(listOf("mail-sor-f41.google.com", "209.85.220.41", "예"), ok.rows().single())
        assertTrue(ok.text().contains("PTR 과 A 가 서로 일치해요 (좋아요)")); assertFalse(ok.hasKv("가정·유동 IP 형태의 이름"))
        val generic = run("mail_fcrdns", "ip" to "192.0.2.9", "server" to dns.server); assertEquals("예", generic.kv("FCrDNS 일치")); assertEquals("예", generic.kv("가정·유동 IP 형태의 이름")); assertEquals(1, generic.noteWith("가정용·유동 IP 형태예요")?.level)
        val mismatch = run("mail_fcrdns", "ip" to "198.51.100.77", "server" to dns.server)              // PTR 이 없는 주소
        assertEquals("없음", mismatch.kv("역방향 이름(PTR)")); assertEquals(2, mismatch.kvLevel("역방향 이름(PTR)")); assertTrue(mismatch.text().contains("역방향 이름이 없어요"))
        val wrong = fakeDns(FakeZone().ptr("5.100.51.198.in-addr.arpa", "mail.example.com").a("mail.example.com", "198.51.100.1"))
        val w = run("mail_fcrdns", "ip" to "198.51.100.5", "server" to wrong.server); assertEquals("아니요", w.kv("FCrDNS 일치")); assertEquals(2, w.kvLevel("FCrDNS 일치")); assertTrue(w.text().contains("PTR 이름을 다시 조회해도 이 IP 가 나오지 않아요"))
        assertTrue(run("mail_fcrdns", "ip" to "x", "server" to dns.server).hasError); assertTrue(run("mail_fcrdns", "ip" to "", "server" to dns.server).text().contains("IP 주소를 입력하세요"))
    }

    // ============================================================ 도구: 도메인 정보·영역 파일·비슷한 도메인

    @Test fun toolDomainRdapShowsDatesButNoPersonalContacts() {
        val urls = ArrayList<String>()
        GeoNet.fetcher = { u -> urls += u; rdapJson("2099-08-13T04:00:00Z") }
        val r = run("domain_rdap", "d" to "https://Example.com/x")
        assertEquals(listOf("https://rdap.org/domain/example.com"), urls)
        assertEquals("EXAMPLE.COM", r.kv("도메인")); assertEquals("Example Registrar, Inc.", r.kv("등록 기관")); assertEquals("1995-08-14", r.kv("등록일")); assertEquals("2024-08-14", r.kv("마지막 변경")); assertEquals("2099-08-13", r.kv("만료일")); assertEquals(-1, r.kvLevel("만료일"))
        assertTrue(r.kv("남은 기간").endsWith("일 남음")); assertEquals("a.iana-servers.net, b.iana-servers.net", r.kv("네임서버")); assertEquals("서명됨", r.kv("DNSSEC")); assertTrue(r.kv("상태").contains("client transfer prohibited"))
        assertTrue(r.text().contains("이전 잠금이 걸려 있어요")); assertTrue(r.text().contains("개인 연락처")); assertFalse(r.hasError)
        for (secret in listOf("Jane Doe", "jane.doe@example.org", "5555550100")) assertFalse("개인 정보($secret)가 결과에 나오면 안 돼요", r.text().contains(secret))
        // 만료 임박·지남
        GeoNet.fetcher = { rdapJson(Instant.now().plusSeconds(10L * 86400).toString()) }
        val soon = run("domain_rdap", "d" to "example.com"); assertEquals(2, soon.kvLevel("만료일")); assertEquals(2, soon.kvLevel("남은 기간")); assertTrue(soon.hasError); assertTrue(soon.text().contains("만료가 한 달도 안 남았어요"))
        GeoNet.fetcher = { rdapJson(Instant.now().plusSeconds(60L * 86400).toString()) }
        val sixty = run("domain_rdap", "d" to "example.com"); assertEquals(1, sixty.kvLevel("만료일")); assertFalse(sixty.hasError)
        GeoNet.fetcher = { rdapJson("2001-01-01T00:00:00Z") }
        val past = run("domain_rdap", "d" to "example.com"); assertTrue(past.kv("남은 기간").contains("일 전에 만료됨")); assertTrue(past.hasError); assertTrue(past.text().contains("도메인이 만료됐어요"))
        // 한글 도메인은 punycode 로, 오류들
        urls.clear(); GeoNet.fetcher = { u -> urls += u; "{}" }
        run("domain_rdap", "d" to "한국.kr"); assertEquals(listOf("https://rdap.org/domain/" + IDN.toASCII("한국.kr")), urls); assertTrue(urls[0].contains("xn--"))
        GeoNet.fetcher = { throw IOException("서버가 404 로 답했어요") }; val e = run("domain_rdap", "d" to "example.kr"); assertTrue(e.hasError); assertTrue(e.text().contains("RDAP 를 지원하지 않을 수 있어요"))
        GeoNet.fetcher = { "<html>x</html>" }; assertTrue(run("domain_rdap", "d" to "example.com").text().contains("응답을 읽지 못했어요"))
        assertTrue(run("domain_rdap", "d" to "not a domain").hasError); assertTrue(run("domain_rdap", "d" to "").text().contains("도메인을 입력하세요"))
    }

    @Test fun toolDnsZoneLintRunsOnPastedText() {
        val r = run("dns_zone_lint")                                                                    // 기본 예시 그대로
        assertEquals("4개 (오류 1 · 주의 3 · 참고 0)", r.kv("발견한 항목")); assertEquals(2, r.kvLevel("발견한 항목")); assertEquals("10줄", r.kv("줄 수"))
        assertEquals(listOf("전체", "6", "8", "9"), r.rows().map { it[0] }); assertTrue(r.rows()[1][1].contains("CNAME 과 다른 레코드(A)")); assertTrue(r.rows()[3][1].contains("files.example.com.example.com."))
        assertEquals(listOf(1, 2, 1, 1), r.cols().map { it.level })
        val clean = run("dns_zone_lint", "z" to "\$ORIGIN example.net.\n@ IN SOA ns1.example.net. h.example.net. 2024010101 7200 3600 1209600 300\n@ IN NS ns1.example.net.\n@ IN NS ns2.example.net.\nwww IN A 8.8.8.8")
        assertEquals("0개 (오류 0 · 주의 0 · 참고 0)", clean.kv("발견한 항목")); assertEquals(-1, clean.kvLevel("발견한 항목")); assertTrue(clean.text().contains("눈에 띄는 문제가 없어요"))
        assertTrue(run("dns_zone_lint", "z" to "").text().contains("영역 파일 내용을 붙여 넣으세요"))
    }

    @Test fun toolDnsLookalikeFindsRegisteredNamesAndFlagsCyrillic() {
        val cyr = IDN.toASCII("еxample.com")
        val dns = fakeDns(FakeZone().a("exmple.com", "198.51.100.7").a(cyr, "198.51.100.8").a("example.net", "8.8.8.8"))
        val r = run("dns_lookalike", "d" to "www.Example.com", "server" to dns.server)                      // www. 는 떼고 example.com 으로 검사
        assertEquals("example.com", r.kv("내 도메인")); assertEquals("52개", r.kv("확인한 후보")); assertEquals("3개", r.kv("실제로 쓰이는(IP 가 있는) 도메인")); assertEquals(1, r.kvLevel("실제로 쓰이는(IP 가 있는) 도메인"))
        assertEquals(52, dns.queries.size); assertTrue(dns.queries.all { it.second == DnsType.A })
        val typo = r.rows().first { it[0] == "exmple.com" }; assertEquals(listOf("exmple.com", "글자 빠짐", "198.51.100.7", "-"), typo)
        val cyrRow = r.rows().first { it[0].startsWith("еxample.com") }; assertEquals("еxample.com ($cyr)", cyrRow[0]); assertEquals("키릴 글자 위장", cyrRow[1]); assertEquals(2, r.cols().first { it.cells == cyrRow }.level)
        val net = r.rows().first { it[0] == "example.net" }; assertEquals("다른 도메인 끝(TLD)", net[1]); assertTrue(net[3].contains("Google LLC")); assertTrue(net[3].contains(CountryNames.ko("US")))
        assertTrue(r.text().contains("등록돼 있다고 모두 피싱은 아니에요"))
        val none = run("dns_lookalike", "d" to "example.com", "server" to fakeDns(FakeZone()).server); assertEquals("0개", none.kv("실제로 쓰이는(IP 가 있는) 도메인")); assertEquals(-1, none.kvLevel("실제로 쓰이는(IP 가 있는) 도메인")); assertTrue(none.text().contains("IP 가 연결된 도메인이 없어요"))
        assertTrue(run("dns_lookalike", "d" to "localhost", "server" to dns.server).text().contains("도메인 형식을 읽지 못했어요"))
    }
}
