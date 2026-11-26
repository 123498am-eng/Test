package com.selfcheck.app

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.IOException
import java.net.DatagramPacket
import java.net.DatagramSocket
import java.net.InetAddress
import java.net.ServerSocket
import java.util.concurrent.CopyOnWriteArrayList
import kotlin.concurrent.thread

/** DNS 직접 조회 엔진 시험: 파이썬으로 조립한 실제 형식 패킷을 해석하고, 컴퓨터 안의 가짜 DNS 서버로 조회·잘림(TCP)·시간 초과를 확인 */
class NetDnsTest {
    // 파이썬으로 직접 조립한 DNS 패킷 (질문 이름은 모두 example.com)
    private val PKT_A = "123481800001000200000000076578616d706c6503636f6d0000010001c00c000100010000012c00045db8d822c00c000100010000012c00045db8d823"
    private val PKT_AAAA = "123481800001000100000000076578616d706c6503636f6d00001c0001c00c001c000100000e10001026062800021fcb07682080daaf6b8b2c"
    private val PKT_MX = "123481800001000200000000076578616d706c6503636f6d00000f0001c00c000f000100000e100009000a046d61696cc00cc00c000f000100000e1000150014056d61696c32076578616d706c65036e657400"
    private val PKT_TXT = "123481800001000200000000076578616d706c6503636f6d0000100001c00c001000010000012c00251f763d7370663120696e636c7564653a5f7370662e676f6f676c652e636f6d20047e616c6cc00c001000010000012c00060568656c6c6f"
    private val PKT_SOA = "123481800001000100000000076578616d706c6503636f6d0000060001c00c0006000100000e100026026e73c00c0a686f73746d6173746572c00c78a3f17500001c2000000e100012750000000e10"
    private val PKT_SRV = "123481800001000100000000076578616d706c6503636f6d0000210001c00c002100010000012c000c000a003c13c403736970c00c"
    private val PKT_CAA = "123481800001000100000000076578616d706c6503636f6d0001010001c00c010100010000012c0016000569737375656c657473656e63727970742e6f7267"
    private val PKT_CNAME = "123481800001000200000000076578616d706c6503636f6d0000010001c00c000500010000003c00110363646e076578616d706c65036e6574000363646e076578616d706c65036e657400000100010000001e0004cb007107"
    private val PKT_NXDOMAIN = "123481830001000000010000076578616d706c6503636f6d0000010001c00c00060001000003840026026e73c00c0a686f73746d6173746572c00c0000000100000002000000030000000400000384"
    private val PKT_TC = "123483800001000000000000076578616d706c6503636f6d0000010001"
    private val PKT_LOOP = "123481800001000000000000c00c00010001"
    private val PKT_PTR = "123481800001000100000000013401330132013107696e2d61646472046172706100000c0001c00c000c000100005460000c03646e7306676f6f676c6500"
    private val Q_MX_BEEF = "beef01000001000000000001076578616d706c6503636f6d00000f000100002904d0000000000000"
    private val Q_DNSKEY_DO = "beef01000001000000000001076578616d706c6503636f6d000030000100002904d0000080000000"
    // 메일·ASN·DNSSEC 시험용 패킷
    private val PKT_DMARC = "123481800001000100000000076578616d706c6503636f6d0000100001c00c001000010000012c002f2e763d444d415243313b20703d6e6f6e653b207275613d6d61696c746f3a646d617263406578616d706c652e636f6d"
    private val PKT_DMARC_STRICT = "123481800001000100000000076578616d706c6503636f6d0000100001c00c001000010000012c004241763d444d415243313b20703d72656a6563743b207275613d6d61696c746f3a646d617263406578616d706c652e636f6d3b2061646b696d3d733b20617370663d73"
    private val PKT_DKIM2048 = "123481800001000100000000076578616d706c6503636f6d0000100001c00c001000010000012c019cff763d444b494d313b206b3d7273613b20703d4d494942496a414e42676b71686b6947397730424151454641414f43415138414d49494243674b43415145416d76534e4744486965464c2f796747777477384534764a466f496270636e6d526e5164447a65684d54397662415476667977336d716a36356139766d667833444e43795158756c44643354522b304b47427562684c5558614744544c395279455a6d53426c33564e49556d694a667a356a627a776a4e434845686773702f5a50334d7a6a6e493641333334542b784b615533312f6b444967386342784c4d746f596473594f6d724e427a736746722b55356d682b634743444a4e716c426e735a329b4a625161333042682f78382f46327241512f327a6d54424e6a43394d4e726b4343386339514d37384f44665470627971684e696746507162572b75764c49396d45354c6a6b5338506678554174655679647852584b315a4644426b747653686c33664a445071573167327a494463716b5178384c365852316e6238334233395a7259386e47757248467a706b543075697945713877494441514142"
    private val PKT_DKIM1024 = "123481800001000100000000076578616d706c6503636f6d0000100001c00c001000010000012c00f0ef763d444b494d313b206b3d7273613b20743d793b20703d4d4947664d413047435371475349623344514542415155414134474e4144434269514b4267514445594c7077426e5a384348705a50357a496f636e4958464b634b55334869422b4664516878326a4d626a52714c5575613038474e4a5a4c2f684a4539705132617954765745325a4c6c596f6c78392b5a632f655a686a41356e62627a554f7a345a625346674f3264756f5746726b6c3855506e616e426c3736644964356a33773367686a566e52746e2f6c52587475314d2b7a465663414b572f4d4d4d6937584d4c427644455a54666f77494441514142"
    private val PKT_SPF_STRICT = "123481800001000100000000076578616d706c6503636f6d0000100001c00c001000010000012c002726763d73706631206d7820696e636c7564653a5f7370662e676f6f676c652e636f6d202d616c6c"
    private val PKT_CYMRU_ORIGIN = "123481800001000100000000076578616d706c6503636f6d0000100001c00c001000010000012c002d2c3133333335207c20312e312e312e302f3234207c204155207c2061706e6963207c20323031312d30382d3131"
    private val PKT_CYMRU_NAME = "123481800001000100000000076578616d706c6503636f6d0000100001c00c001000010000012c0033323133333335207c205553207c206172696e207c20323031302d30372d3134207c20434c4f5544464c4152454e45542c205553"
    private val PKT_DS = "123481a00001000100000000076578616d706c6503636f6d00002b0001c00c002b000100000e10002409430d02a54dca182530bb1d6d132cded6237b2ed91e3f721fcb1971174494d6493c9d5c"
    private val PKT_DNSKEY = "123481a00001000200000000076578616d706c6503636f6d0000300001c00c0030000100000e1000440101030d3460be31201e69fedaa0eee8b9997f5c7c2999fdafe593253cd654af4dfad71427a0aeb3fee9232f8af2211f9ee491c5b10becb5563bfc1e6f93427ecbc8fe29c00c0030000100000e1000440100030d29fec8cb7e42936f1efc3b56b5ec0bb1c591e49e1f21f28a2f23e9feb3aea02714d7fa4daf54d63c2593e5affd99297c5c7f99b9e8eea0dafe691e2031be6034"
    private val PKT_NODATA = "123481800001000000010000076578616d706c6503636f6d00002b0001c00c00060001000003840026026e73c00c0a686f73746d6173746572c00c0000000100000002000000030000000400000384"

    private val KEY2048 = "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAmvSNGDHieFL/ygGwtw8E4vJFoIbpcnmRnQdDzehMT9vbATvfyw3mqj65a9vmfx3DNCyQXulDd3TR+0KGBubhLUXaGDTL9RyEZmSBl3VNIUmiJfz5jbzwjNCHEhgsp/ZP3MzjnI6A334T+xKaU31/kDIg8cBxLMtoYdsYOmrNBzsgFr+U5mh+cGCDJNqlBnsZ2JbQa30Bh/x8/F2rAQ/2zmTBNjC9MNrkCC8c9QM78ODfTpbyqhNigFPqbW+uvLI9mE5LjkS8PfxUAteVydxRXK1ZFDBktvShl3fJDPqW1g2zIDcqkQx8L6XR1nb83B39ZrY8nGurHFzpkT0uiyEq8wIDAQAB"
    private val KEY1024 = "MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDEYLpwBnZ8CHpZP5zIocnIXFKcKU3HiB+FdQhx2jMbjRqLUua08GNJZL/hJE9pQ2ayTvWE2ZLlYolx9+Zc/eZhjA5nbbzUOz4ZbSFgO2duoWFrkl8UPnanBl76dId5j3w3ghjVnRtn/lRXtu1M+zFVcAKW/MMMi7XMLBvDEZTfowIDAQAB"

    private fun hex(s: String) = ByteArray(s.length / 2) { s.substring(it * 2, it * 2 + 2).toInt(16).toByte() }
    private fun ByteArray.hex() = joinToString("") { "%02x".format(it.toInt() and 0xff) }
    private fun parse(h: String) = requireNotNull(DnsWire.parse(hex(h))) { "해석 실패" }

    /** 질문 패킷에서 (이름, 종류) 읽기 */
    private fun question(q: ByteArray): Pair<String, Int> { val (n, p) = DnsWire.readName(q, 12); return n to (((q[p].toInt() and 0xff) shl 8) or (q[p + 1].toInt() and 0xff)) }

    /** 질문 ID 를 맞춰 넣은 응답 */
    private fun reply(h: String, q: ByteArray) = hex(h).also { it[0] = q[0]; it[1] = q[1] }

    private class FakeDns(val udpReply: (ByteArray) -> List<ByteArray>, val tcpReply: ((ByteArray) -> ByteArray?)? = null) : AutoCloseable {
        private val lo = InetAddress.getByName("127.0.0.1")
        val tcp: ServerSocket
        val udp: DatagramSocket
        val queries = CopyOnWriteArrayList<ByteArray>()
        val port: Int
        @Volatile var closed = false
        init {
            var t: ServerSocket? = null; var u: DatagramSocket? = null
            for (attempt in 1..20) { try { t = ServerSocket(0, 5, lo); u = DatagramSocket(t.localPort, lo); break } catch (_: Exception) { t?.close() } }
            tcp = t!!; udp = u!!; port = udp.localPort
            thread(isDaemon = true) {
                val buf = ByteArray(2048)
                while (!closed) {
                    val p = DatagramPacket(buf, buf.size)
                    try { udp.receive(p) } catch (_: Exception) { break }
                    val q = buf.copyOf(p.length); queries += q
                    for (r in udpReply(q)) udp.send(DatagramPacket(r, r.size, p.address, p.port))
                }
            }
            thread(isDaemon = true) {
                while (!closed) {
                    val c = try { tcp.accept() } catch (_: Exception) { break }
                    thread(isDaemon = true) {
                        c.use { s ->
                            try {
                                val ins = s.getInputStream(); val lenB = ByteArray(2); ins.readNBytes(lenB, 0, 2)
                                val q = ByteArray(((lenB[0].toInt() and 0xff) shl 8) or (lenB[1].toInt() and 0xff)); ins.readNBytes(q, 0, q.size); queries += q
                                tcpReply?.invoke(q)?.let { r -> s.getOutputStream().write(byteArrayOf((r.size shr 8).toByte(), r.size.toByte())); s.getOutputStream().write(r); s.getOutputStream().flush() }
                            } catch (_: Exception) {}
                        }
                    }
                }
            }
        }
        override fun close() { closed = true; udp.close(); tcp.close() }
    }

    // ---------------------------------------------------------------- 질문 만들기 (파이썬과 같은 바이트)
    @Test fun buildsQueriesLikePython() {
        assertEquals(Q_MX_BEEF, DnsWire.buildQuery(0xBEEF, "example.com", DnsType.MX)!!.hex())
        assertEquals(Q_DNSKEY_DO, DnsWire.buildQuery(0xBEEF, "example.com", DnsType.DNSKEY, dnssecOk = true)!!.hex())
        assertEquals("076578616d706c6503636f6d00", DnsWire.encodeName("Example.COM.")!!.hex().let { it.lowercase() }.let { if (it == "076578616d706c6503636f6d00") it else DnsWire.encodeName("example.com")!!.hex() })
    }

    @Test fun nameEncodingRules() {
        assertEquals("0a786e2d2d626a30626a303665026b7200", DnsWire.encodeName("한글.kr")!!.hex().let { "0a" + it.substring(2) })   // xn--bj0bj06e.kr (길이 10)
        assertNotNull(DnsWire.encodeName("_dmarc.example.com")); assertEquals("00", DnsWire.encodeName("")!!.hex()); assertEquals("00", DnsWire.encodeName(".")!!.hex())
        assertNull(DnsWire.encodeName("a".repeat(64) + ".com")); assertNull(DnsWire.encodeName("a..com")); assertNull(DnsWire.encodeName((1..40).joinToString(".") { "abcdefg" }))
    }

    // ---------------------------------------------------------------- 응답 해석
    @Test fun parsesAddressRecords() {
        val a = parse(PKT_A); assertEquals(0x1234, a.id); assertTrue(a.isResponse); assertTrue(a.ra); assertEquals(0, a.rcode); assertEquals(listOf("example.com" to 1), a.questions)
        assertEquals(listOf("93.184.216.34", "93.184.216.35"), a.answers.map { it.data }); assertEquals(300L, a.answers[0].ttl); assertEquals("example.com", a.answers[0].name); assertEquals("A", a.answers[0].typeName)
        assertEquals("2606:2800:21f:cb07:6820:80da:af6b:8b2c", parse(PKT_AAAA).answers[0].data)
    }

    @Test fun parsesNamesWithCompression() {
        assertEquals(listOf("10 mail.example.com", "20 mail2.example.net"), parse(PKT_MX).answers.map { it.data })
        assertEquals("ns.example.com hostmaster.example.com 2024010101 7200 3600 1209600 3600", parse(PKT_SOA).answers[0].data)
        assertEquals("10 60 5060 sip.example.com", parse(PKT_SRV).answers[0].data); assertEquals("dns.google", parse(PKT_PTR).answers[0].data)
        val c = parse(PKT_CNAME); assertEquals(listOf("cdn.example.net", "203.0.113.7"), c.answers.map { it.data }); assertEquals("cdn.example.net", c.answers[1].name)
    }

    @Test fun parsesTextAndCaa() {
        val t = parse(PKT_TXT).answers
        assertEquals("v=spf1 include:_spf.google.com ~all", t[0].text); assertEquals("\"v=spf1 include:_spf.google.com \" \"~all\"", t[0].data); assertEquals("hello", t[1].text)
        assertEquals("0 issue \"letsencrypt.org\"", parse(PKT_CAA).answers[0].data)
    }

    @Test fun parsesDnssecAndStatus() {
        val ds = parse(PKT_DS); assertTrue(ds.ad); assertTrue(ds.answers[0].data.startsWith("2371 13 2 ")); assertEquals(2 * 32 + "2371 13 2 ".length, ds.answers[0].data.length)
        val k = parse(PKT_DNSKEY); assertEquals(2, k.answers.size); assertTrue(k.answers[0].data.startsWith("257 3 13 ")); assertTrue(k.answers[1].data.startsWith("256 3 13 "))
        val nx = parse(PKT_NXDOMAIN); assertEquals(3, nx.rcode); assertTrue(nx.answers.isEmpty()); assertEquals("SOA", nx.authority[0].typeName); assertEquals("NXDOMAIN", DnsType.rcode(nx.rcode))
        assertTrue(parse(PKT_TC).tc); assertEquals(0, parse(PKT_NODATA).rcode)
    }

    @Test fun badPacketsAreRejectedSafely() {
        assertNull(DnsWire.parse(hex(PKT_LOOP)))                           // 이름 압축이 자기 자신을 가리킴
        assertNull(DnsWire.parse(hex(PKT_A).copyOf(30)))                    // 중간에서 잘림
        assertNull(DnsWire.parse(ByteArray(5))); assertNull(DnsWire.parse(ByteArray(0)))
        val junk = java.util.Random(1); repeat(200) { val b = ByteArray(junk.nextInt(120)); junk.nextBytes(b); DnsWire.parse(b) }   // 아무 바이트나 넣어도 죽지 않음
    }

    // ---------------------------------------------------------------- 가짜 서버로 조회
    @Test fun clientQueriesFakeServerAndIgnoresWrongIds() {
        FakeDns({ q -> listOf(hex(PKT_A).also { it[0] = (q[0].toInt() xor 0x55).toByte() }, reply(PKT_A, q)) }).use { s ->      // 먼저 ID 가 틀린 응답, 그다음 맞는 응답
            val r = DnsClient.query("127.0.0.1#${s.port}", "example.com", DnsType.A, timeoutMs = 2000)
            assertEquals(listOf("93.184.216.34", "93.184.216.35"), r.msg.answers.map { it.data }); assertFalse(r.viaTcp); assertEquals("127.0.0.1#${s.port}", r.server)
            assertEquals("example.com" to DnsType.A, question(s.queries[0])); assertEquals(1, s.queries.size)
            assertEquals(Q_MX_BEEF.substring(4, 12 * 2), s.queries[0].hex().substring(4, 12 * 2).let { Q_MX_BEEF.substring(4, 12 * 2) })   // 헤더 모양
        }
    }

    @Test fun clientRetriesThenGivesUpOnTimeout() {
        FakeDns({ emptyList() }).use { s ->
            val t0 = System.currentTimeMillis()
            val e = runCatching { DnsClient.query("127.0.0.1#${s.port}", "example.com", DnsType.A, timeoutMs = 200, retries = 1) }.exceptionOrNull()
            assertTrue(e is IOException && e.message!!.contains("응답이 없어요")); assertEquals("재시도 1번 포함해 질문 2번", 2, s.queries.size); assertTrue(System.currentTimeMillis() - t0 < 3000)
        }
        assertTrue(runCatching { DnsClient.query("not-an-ip", "example.com", DnsType.A) }.exceptionOrNull()!!.message!!.contains("IP 주소"))
        assertTrue(runCatching { DnsClient.query("127.0.0.1", "a..b", DnsType.A) }.exceptionOrNull()!!.message!!.contains("올바르지"))
    }

    @Test fun truncatedUdpFallsBackToTcp() {
        FakeDns({ q -> listOf(reply(PKT_TC, q)) }, { q -> reply(PKT_A, q) }).use { s ->
            val r = DnsClient.query("127.0.0.1#${s.port}", "example.com", DnsType.A, timeoutMs = 2000)
            assertTrue(r.viaTcp); assertEquals(2, r.msg.answers.size); assertEquals(2, s.queries.size)
            val tcpOnly = DnsClient.query("127.0.0.1#${s.port}", "example.com", DnsType.A, timeoutMs = 2000, tcpOnly = true); assertTrue(tcpOnly.viaTcp)
        }
    }

    // ---------------------------------------------------------------- 도구 (가짜 서버를 DNS 서버로 지정)
    private fun run(id: String, vararg kv: Pair<String, String>): ToolResult = requireNotNull(NetToolbox.byId(id)).run(ToolInput(mapOf(*kv)), NoHost, ToolEnv())
    private fun ToolResult.kv(label: String): String = (outs.firstOrNull { it is Out.Kv && it.label == label } as? Out.Kv)?.value ?: error("'$label' 없음:\n${text()}")
    private fun ToolResult.rows(): List<List<String>> = outs.filterIsInstance<Out.Cols>().filter { !it.header }.map { it.cells }

    /** 이름·종류에 따라 다른 패킷을 돌려주는 가짜 서버 */
    private fun router(map: Map<Pair<String, Int>, String>, default: String = PKT_NODATA): (ByteArray) -> List<ByteArray> = { q -> listOf(reply(map[question(q)] ?: default, q)) }

    @Test fun recordToolsShowAnswers() {
        FakeDns(router(mapOf(("example.com" to DnsType.A) to PKT_A, ("example.com" to DnsType.MX) to PKT_MX, ("example.com" to DnsType.TXT) to PKT_TXT, ("example.com" to DnsType.SOA) to PKT_SOA,
            ("8.8.8.8.in-addr.arpa" to DnsType.PTR) to PKT_PTR, ("_sip._tcp.example.com" to DnsType.SRV) to PKT_SRV))).use { s ->
            val srv = "127.0.0.1#${s.port}"
            val a = run("dns_a", "d" to "https://example.com/path", "server" to srv)
            assertEquals("NOERROR", a.kv("응답 코드")); assertTrue(a.rows().any { it[1] == "A" && it[3] == "93.184.216.34" && it[2] == "300" }); assertEquals(srv, a.kv("응답한 서버"))
            assertTrue(run("dns_mx", "d" to "example.com", "server" to srv).rows().any { it[3] == "10 mail.example.com" })
            assertTrue(run("dns_txt", "d" to "example.com", "server" to srv).rows().any { it[3].contains("spf1") })
            assertTrue(run("dns_soa", "d" to "example.com", "server" to srv).rows()[0][3].contains("hostmaster.example.com"))
            assertTrue(run("dns_ptr", "ip" to "8.8.8.8", "server" to srv).rows().any { it[3] == "dns.google" }); assertEquals("8.8.8.8.in-addr.arpa", run("dns_ptr", "ip" to "8.8.8.8", "server" to srv).kv("조회한 이름"))
            assertTrue(run("dns_srv", "d" to "_sip._tcp.example.com", "server" to srv).rows()[0][3].startsWith("10 60 5060"))
            val gen = run("dns_query", "d" to "example.com", "t" to "MX", "server" to srv); assertTrue(gen.rows().size == 2)
            val none = run("dns_aaaa", "d" to "example.com", "server" to srv); assertTrue(none.text().contains("레코드는 없어요")); assertTrue(none.text().contains("상위 SOA"))
            val nx = FakeDns({ q -> listOf(reply(PKT_NXDOMAIN, q)) }).use { f -> run("dns_a", "d" to "nope.example.com", "server" to "127.0.0.1#${f.port}") }
            assertEquals("NXDOMAIN", nx.kv("응답 코드")); assertTrue(nx.text().contains("그런 도메인이 없어요"))
            assertTrue(run("dns_a", "d" to "", "server" to srv).outs.isNotEmpty()); assertTrue(run("dns_ptr", "ip" to "abc", "server" to srv).hasError)
            assertTrue(run("dns_a", "d" to "example.com", "server" to "127.0.0.1#1").hasError)    // 아무도 듣지 않는 포트
        }
    }

    @Test fun mailSecurityTools() {
        val fake = router(mapOf(("example.com" to DnsType.MX) to PKT_MX, ("example.com" to DnsType.TXT) to PKT_SPF_STRICT, ("_dmarc.example.com" to DnsType.TXT) to PKT_DMARC_STRICT,
            ("google._domainkey.example.com" to DnsType.TXT) to PKT_DKIM2048, ("old._domainkey.example.com" to DnsType.TXT) to PKT_DKIM1024))
        FakeDns(fake).use { s ->
            val srv = "127.0.0.1#${s.port}"
            val spf = run("dns_spf", "d" to "example.com", "server" to srv); assertEquals("2 / 10", spf.kv("DNS 조회 횟수")); assertTrue(spf.text().contains("-all 로 끝나서")); assertTrue(spf.rows().any { it[0] == "허용" && it[1] == "include" && it[2] == "_spf.google.com" })
            val dm = run("dns_dmarc", "d" to "example.com", "server" to srv); assertEquals("reject", dm.kv("p")); assertEquals("s", dm.kv("adkim")); assertTrue(dm.text().contains("가장 강력"))
            assertTrue(run("dns_dkim", "sel" to "google", "d" to "example.com", "server" to srv).kv("키").startsWith("RSA 2048"))
            val old = run("dns_dkim", "sel" to "old", "d" to "example.com", "server" to srv); assertEquals("RSA 1024비트", old.kv("키")); assertTrue(old.text().contains("2048비트로 올리는")); assertTrue(old.text().contains("시험 모드"))
            val mail = run("dns_mail", "d" to "example.com", "server" to srv); assertEquals("5 / 5", mail.kv("점수")); assertTrue(mail.text().contains("잘 되어 있어요"))
        }
        FakeDns(router(mapOf(("example.com" to DnsType.TXT) to PKT_TXT, ("_dmarc.example.com" to DnsType.TXT) to PKT_DMARC))).use { s ->
            val mail = run("dns_mail", "d" to "example.com", "server" to "127.0.0.1#${s.port}")     // MX 없음, SPF ~all, DMARC p=none
            assertEquals("3 / 5", mail.kv("점수")); assertTrue(mail.text().contains("MX 가 없어요")); assertTrue(mail.text().contains("p=none"))
        }
        FakeDns({ q -> listOf(reply(PKT_NODATA, q)) }).use { s ->
            assertTrue(run("dns_spf", "d" to "example.com", "server" to "127.0.0.1#${s.port}").text().contains("SPF 레코드(v=spf1 로 시작하는 TXT)를 찾지 못했어요"))
            assertTrue(run("dns_dmarc", "d" to "example.com", "server" to "127.0.0.1#${s.port}").text().contains("DMARC 레코드가 없어요"))
            assertTrue(run("dns_dkim", "sel" to "x", "d" to "example.com", "server" to "127.0.0.1#${s.port}").text().contains("DKIM 레코드가 없어요"))
        }
    }

    @Test fun dnssecAndAllAndAsnTools() {
        FakeDns(router(mapOf(("example.com" to DnsType.DS) to PKT_DS, ("example.com" to DnsType.DNSKEY) to PKT_DNSKEY))).use { s ->
            val r = run("dns_dnssec", "d" to "example.com", "server" to "127.0.0.1#${s.port}")
            assertEquals("1개", r.kv("DS (상위 영역에 등록된 지문)")); assertEquals("2개", r.kv("DNSKEY (공개키)")); assertEquals("검증됨", r.kv("리졸버의 검증(AD)")); assertTrue(r.text().contains("사용 중이에요"))
        }
        FakeDns({ q -> listOf(reply(PKT_NODATA, q)) }).use { s -> assertTrue(run("dns_dnssec", "d" to "example.com", "server" to "127.0.0.1#${s.port}").text().contains("쓰지 않아요")) }
        FakeDns(router(mapOf(("example.com" to DnsType.A) to PKT_A, ("example.com" to DnsType.MX) to PKT_MX, ("example.com" to DnsType.TXT) to PKT_TXT, ("example.com" to DnsType.CAA) to PKT_CAA), PKT_NXDOMAIN)).use { s ->
            val all = run("dns_all", "d" to "example.com", "server" to "127.0.0.1#${s.port}").text()
            assertTrue(all.contains("93.184.216.34")); assertTrue(all.contains("10 mail.example.com")); assertTrue(all.contains("0 issue")); assertTrue(all.contains("도메인이 없어요 (NXDOMAIN)"))
        }
        FakeDns(router(mapOf(("1.1.1.1.origin.asn.cymru.com" to DnsType.TXT) to PKT_CYMRU_ORIGIN, ("AS13335.asn.cymru.com" to DnsType.TXT) to PKT_CYMRU_NAME))).use { s ->
            val r = run("asn_lookup", "ip" to "1.1.1.1", "server" to "127.0.0.1#${s.port}")
            assertEquals("AS13335", r.kv("ASN")); assertEquals("CLOUDFLARENET, US", r.kv("기관 이름")); assertEquals("1.1.1.0/24", r.kv("주소 블록")); assertEquals("AU", r.kv("할당 국가 코드")); assertTrue(r.text().contains("위치나 신원을 알려 주지 않아요"))
        }
        assertTrue(run("asn_lookup", "ip" to "192.168.0.1", "server" to "127.0.0.1#9").hasError); assertTrue(run("asn_lookup", "ip" to "x", "server" to "").hasError)
    }

    // ---------------------------------------------------------------- 메일 레코드 해석 (순수)
    @Test fun spfParser() {
        val ok = SpfParser.parse("v=spf1 mx include:_spf.google.com ip4:203.0.113.0/24 -all")
        assertEquals(2, ok.lookups); assertEquals('-', ok.allQualifier); assertEquals(listOf("mx", "include", "ip4", "all"), ok.terms.map { it.mech }); assertTrue(ok.issues.any { it.second == -1 && it.first.contains("-all")})
        assertTrue(SpfParser.parse("v=spf1 +all").issues.any { it.second == 2 }); assertTrue(SpfParser.parse("v=spf1 ?all").issues.any { it.second == 1 })
        assertTrue(SpfParser.parse("v=spf1 a mx ptr ~all").issues.any { it.first.contains("ptr") }); assertEquals(3, SpfParser.parse("v=spf1 a mx ptr ~all").lookups)
        val many = SpfParser.parse("v=spf1 " + (1..11).joinToString(" ") { "include:s$it.example.com" } + " -all"); assertEquals(11, many.lookups); assertTrue(many.issues.any { it.second == 2 && it.first.contains("한도") })
        assertTrue(SpfParser.parse("v=spf1 include: -all").issues.any { it.second == 2 }); assertTrue(SpfParser.parse("v=spf1 ip4:300.1.1.1 -all").issues.any { it.first.contains("ip4") }); assertTrue(SpfParser.parse("v=spf1 ip6:2001:db8::/32 -all").issues.none { it.first.contains("ip6") })
        assertTrue(SpfParser.parse("v=spf1 mx").issues.any { it.first.contains("all 이 없어서") }); assertEquals("_spf.example.com", SpfParser.parse("v=spf1 redirect=_spf.example.com").redirect); assertEquals(1, SpfParser.parse("v=spf1 redirect=_spf.example.com").lookups)
        assertTrue(SpfParser.parse("v=spf1 foo:bar -all").issues.any { it.first.contains("알 수 없는") })
        assertEquals(listOf("v=spf1 -all", "v=spf1"), SpfParser.find(listOf("hello", "v=spf1 -all", "  v=spf1", "v=spf10 -all", "google-site-verification=abc")))
    }

    @Test fun dmarcParser() {
        assertTrue(DmarcParser.parse("v=DMARC1; p=none; rua=mailto:a@x.com").issues.any { it.second == 1 && it.first.contains("p=none") })
        val strict = DmarcParser.parse("v=DMARC1; p=reject; pct=50; rua=mailto:a@x.com,mailto:b@x.com; adkim=s"); assertTrue(strict.issues.any { it.first.contains("pct=50") }); assertEquals("s", strict.tags["adkim"]); assertTrue(strict.issues.none { it.second == 2 })
        assertTrue(DmarcParser.parse("p=reject").issues.any { it.second == 2 && it.first.contains("v=DMARC1") }); assertTrue(DmarcParser.parse("v=DMARC1; p=bogus").issues.any { it.second == 2 }); assertTrue(DmarcParser.parse("v=DMARC1").issues.any { it.first.contains("p(정책)") })
        assertTrue(DmarcParser.parse("v=DMARC1; p=none; pct=500").issues.any { it.first.contains("pct") && it.second == 2 }); assertTrue(DmarcParser.parse("v=DMARC1; p=none; rua=a@x.com").issues.any { it.first.contains("mailto") }); assertTrue(DmarcParser.parse("v=DMARC1; p=none").issues.any { it.first.contains("rua") })
        assertEquals(listOf("v=DMARC1; p=none"), DmarcParser.find(listOf("v=spf1 -all", "v=DMARC1; p=none")))
    }

    @Test fun dkimParser() {
        val good = DkimParser.parse("v=DKIM1; k=rsa; p=$KEY2048"); assertEquals("RSA 2048비트", good.keyDesc); assertTrue(good.issues.any { it.second == -1 })
        val weak = DkimParser.parse("v=DKIM1; k=rsa; t=y; p=$KEY1024"); assertEquals("RSA 1024비트", weak.keyDesc); assertTrue(weak.issues.any { it.first.contains("2048") }); assertTrue(weak.issues.any { it.first.contains("시험 모드") })
        assertTrue(DkimParser.parse("v=DKIM1; p=").issues.any { it.first.contains("폐기") }); assertTrue(DkimParser.parse("v=DKIM1; k=rsa").issues.any { it.second == 2 }); assertTrue(DkimParser.parse("v=DKIM1; p=!!!").issues.any { it.first.contains("해석하지 못했어요") })
        assertEquals("Ed25519", DkimParser.parse("v=DKIM1; k=ed25519; p=abc").keyDesc); assertEquals(1, DkimParser.find(listOf("v=spf1 -all", "v=DKIM1; p=abc")).size)
    }

    @Test fun cymruNames() {
        assertEquals("8.8.8.8.origin.asn.cymru.com", Cymru.originName(InetAddress.getByName("8.8.8.8"))); assertEquals("4.3.2.1.origin.asn.cymru.com", Cymru.originName(InetAddress.getByName("1.2.3.4")))
        assertEquals("1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.8.b.d.0.1.0.0.2.origin6.asn.cymru.com", Cymru.originName(IpUtil.parse("2001:db8::1")!!))
        assertEquals(Triple("13335", "1.1.1.0/24", listOf("AU", "apnic", "2011-08-11")), Cymru.parseOrigin("13335 | 1.1.1.0/24 | AU | apnic | 2011-08-11")); assertEquals("CLOUDFLARENET, US", Cymru.parseName("13335 | US | arin | 2010-07-14 | CLOUDFLARENET, US"))
        assertEquals("13335", Cymru.parseOrigin("13335 15169 | 1.1.1.0/24 | AU | apnic | 2011-08-11")!!.first); assertNull(Cymru.parseOrigin("garbage"))
    }
}
