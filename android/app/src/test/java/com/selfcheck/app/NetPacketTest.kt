package com.selfcheck.app

import org.json.JSONArray
import org.json.JSONObject
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.File

/*
 * 패킷 해석 엔진·도구 10가지 시험.
 * 기준 자료(src/test/resources/netpkt)는 scapy 로 패킷·pcap 을 만들고(체크섬은 scapy 가 계산), dpkt·libpcap·실제 OpenSSL 로 따로 읽어서 뽑은 값이에요.
 * 이 코드(Kotlin)와 무관한 구현이라 서로 교차 검증이 돼요. TLS Hello 는 로컬 openssl s_client / 파이썬 ssl 이 실제로 보낸 바이트를 받아 온 거예요.
 */
class NetPacketTest {
    private val dir = "src/test/resources/netpkt"
    private fun file(name: String) = File("$dir/$name")
    private fun json(name: String) = JSONObject(file(name).readText())
    private fun hexBytes(h: String): ByteArray = ByteArray(h.length / 2) { h.substring(it * 2, it * 2 + 2).toInt(16).toByte() }
    private val packets by lazy { json("packets.json") }
    private fun raw(name: String) = hexBytes(packets.getJSONObject(name).getString("hex"))
    private fun facts(name: String) = packets.getJSONObject(name).getJSONObject("facts")
    private fun tlsBytes(name: String, side: String = "client") = hexBytes(file("tls/${name}_$side.hex").readText().trim())
    private fun run(id: String, vararg kv: Pair<String, String>, host: ToolHost = FileHost) = runNetTool(id, *kv, host = host)
    private fun intMap(o: JSONObject) = o.keys().asSequence().associateWith { o.getInt(it) }
    private fun strList(a: JSONArray) = (0 until a.length()).map { a.getString(it) }
    private fun hostWith(vararg files: Pair<String, File>) = object : TestHost() {
        override fun file(key: String) = files.firstOrNull { it.first == key }?.second?.let { f -> FileRef(f.name, f.length()) { f.inputStream() } }
    }
    private fun PacketDecode.Layer.f(label: String): String = fields.firstOrNull { it.first == label }?.second ?: error("'$label' 칸이 없음: ${fields.map { it.first }}")
    private fun PacketDecode.Decoded.layer(name: String) = layers.firstOrNull { it.name == name } ?: error("'$name' 층이 없음: ${layers.map { it.name }}")
    private fun PacketDecode.Layer.hasNote(fragment: String) = notes.any { fragment in it.first }
    private fun PacketDecode.Layer.noteLevel(fragment: String) = notes.first { fragment in it.first }.second
    private fun hex(b: ByteArray) = b.joinToString("") { "%02x".format(it.toInt() and 0xff) }

    // ============================================================ 16진수 붙여넣기 형식

    private fun ascii(b: ByteArray, from: Int, to: Int) = (from until to).joinToString("") { val c = b[it].toInt() and 0xff; if (c in 32..126) c.toChar().toString() else "." }
    private fun spaced(b: ByteArray, from: Int, to: Int) = (from until to).joinToString(" ") { "%02x".format(b[it].toInt() and 0xff) }
    private fun lines(b: ByteArray, f: (Int, Int) -> String) = (b.indices step 16).joinToString("\n") { f(it, minOf(b.size, it + 16)) }
    private fun asTcpdumpXX(b: ByteArray) = lines(b) { s, e -> "\t0x%04x:  ".format(s) + (s until e step 2).joinToString(" ") { j -> spaced(b, j, minOf(j + 2, e)).replace(" ", "") } }
    private fun asTcpdumpX(b: ByteArray) = lines(b) { s, e -> "\t0x%04x:  ".format(s) + (s until e step 2).joinToString(" ") { j -> spaced(b, j, minOf(j + 2, e)).replace(" ", "") }.padEnd(39) + "  " + ascii(b, s, e) }
    private fun asHexdumpC(b: ByteArray) = lines(b) { s, e -> "%08x  ".format(s) + spaced(b, s, minOf(e, s + 8)).padEnd(23) + "  " + (if (e > s + 8) spaced(b, s + 8, e) else "").padEnd(23) + "  |" + ascii(b, s, e) + "|" }
    private fun asXxd(b: ByteArray) = lines(b) { s, e -> "%08x: ".format(s) + (s until e step 2).joinToString(" ") { j -> spaced(b, j, minOf(j + 2, e)).replace(" ", "") }.padEnd(39) + "  " + ascii(b, s, e) }
    private fun asWireshark(b: ByteArray) = lines(b) { s, e -> "%04x  ".format(s) + spaced(b, s, minOf(e, s + 8)).padEnd(23) + "  " + (if (e > s + 8) spaced(b, s + 8, e) else "").padEnd(23) + "   " + ascii(b, s, e) }
    private fun asScapy(b: ByteArray) = lines(b) { s, e -> "%04x  ".format(s).uppercase() + spaced(b, s, e).uppercase().padEnd(47) + "  " + ascii(b, s, e) }
    private fun asText2pcap(b: ByteArray) = lines(b) { s, e -> "%06x ".format(s) + spaced(b, s, e) }

    @Test fun hexPasteFormatsAllRoundTrip() {
        val samples = listOf(raw("tcp_syn"), tlsBytes("openssl13"), hexBytes(json("ntp.json").getString("hex")), raw("arp_request"), byteArrayOf(0x45, 0x00, 0x7f), ByteArray(16) { (it * 17).toByte() }, ByteArray(33) { 0x20 })
        val formats = mapOf<String, (ByteArray) -> String>("tcpdump -xx" to this::asTcpdumpXX, "tcpdump -X" to this::asTcpdumpX, "hexdump -C" to this::asHexdumpC, "xxd" to this::asXxd, "wireshark" to this::asWireshark, "scapy hexdump" to this::asScapy, "text2pcap" to this::asText2pcap,
            "한 줄" to { b -> hex(b) }, "공백" to { b -> spaced(b, 0, b.size) }, "0x 붙임" to { b -> b.joinToString(", ") { "0x%02x".format(it.toInt() and 0xff) } }, "C 배열" to { b -> "{" + b.joinToString(", ") { "0x%02X".format(it.toInt() and 0xff) } + "};" },
            "\\x 이스케이프" to { b -> b.joinToString("") { "\\x%02x".format(it.toInt() and 0xff) } }, "콜론" to { b -> spaced(b, 0, b.size).replace(' ', ':') }, "하이픈" to { b -> spaced(b, 0, b.size).replace(' ', '-') }, "대문자·줄바꿈" to { b -> lines(b) { s, e -> spaced(b, s, e).uppercase() } })
        for ((n, b) in samples.withIndex()) for ((fmt, f) in formats) assertArrayEquals("샘플 $n ($fmt 형식)\n${f(b)}", b, PacketHex.parse(f(b)))
        assertNull(PacketHex.parse("")); assertNull(PacketHex.parse("   \n ")); assertNull(PacketHex.parse("abc")); assertNull(PacketHex.parse("zz 00")); assertNull(PacketHex.parse("45 00 0"))
        assertArrayEquals(byteArrayOf(0, 0, 0, 1, 0, 2), PacketHex.parse("0000 0001 0002"))                              // 오프셋처럼 보여도 한 칸 띄어 쓴 평범한 글은 그대로
        assertArrayEquals(byteArrayOf(0x45, 0x00), PacketHex.parse("\r\n 45 00 \r\n"))
    }

    // ============================================================ 체크섬 (RFC 1071)

    @Test fun internetChecksumMatchesRfcAndReferenceHeaders() {
        val rfc = hexBytes("0001f203f4f5f6f7")                                                                          // RFC 1071 3절의 예
        assertEquals(0xddf2L, InetChecksum.sum(rfc)); assertEquals(0x220d, InetChecksum.checksum(rfc))
        assertEquals(0x0402L, InetChecksum.sum(hexBytes("010203"))); assertEquals(0xfbfd, InetChecksum.checksum(hexBytes("010203")))                       // 홀수 길이는 뒤에 0 을 붙여 계산
        assertTrue(InetChecksum.valid(rfc + byteArrayOf(0x22, 0x0d), 0, 10)); assertEquals(0xffff, InetChecksum.checksum(ByteArray(0)))
        for (name in packets.keys()) {
            val f = facts(name); if (f.getString("l3") != "ipv4") continue
            val b = raw(name); val off = 14 + (if (f.has("vlan_id")) 4 else 0)
            assertEquals(name, f.getBoolean("ip_csum_ok"), InetChecksum.valid(b, off, off + f.getInt("ihl")))
        }
    }

    // ============================================================ 계층별 해석 (scapy 가 만들고 dpkt 가 읽은 값과 대조)

    private fun checkFacts(name: String) {
        val f = facts(name); val d = PacketDecode.decode(raw(name), "eth"); val msg = "패킷 $name"
        val eth = d.layer("이더넷")
        assertEquals(msg, f.getString("eth_dst"), eth.f("목적지 MAC").substringBefore("  ")); assertEquals(msg, f.getString("eth_src"), eth.f("출발지 MAC").substringBefore("  "))
        if (f.has("vlan_id")) assertTrue(msg, eth.f("VLAN 태그").startsWith("VLAN ID ${f.getInt("vlan_id")} · 우선순위 ${f.getInt("vlan_prio")}"))
        when (f.getString("l3")) {
            "arp" -> {
                val a = d.layer("ARP"); assertTrue(msg, a.f("동작").startsWith("${f.getInt("arp_op")} ")); assertEquals(msg, f.getString("arp_sha"), a.f("보내는 MAC")); assertEquals(msg, f.getString("arp_spa"), a.f("보내는 IP"))
                assertEquals(msg, f.getString("arp_tha"), a.f("대상 MAC")); assertEquals(msg, f.getString("arp_tpa"), a.f("대상 IP"))
            }
            "ipv4" -> {
                val ip = d.layer("IPv4")
                assertEquals(msg, f.getString("src"), ip.f("출발지 IP").substringBefore("  (")); assertEquals(msg, f.getString("dst"), ip.f("목적지 IP").substringBefore("  ("))
                assertEquals(msg, "${f.getInt("ttl")}", ip.f("TTL")); assertTrue(msg, ip.f("프로토콜").startsWith("${f.getInt("proto")} ")); assertEquals(msg, "0x%04x".format(f.getInt("ip_id")), ip.f("식별자(ID)"))
                assertEquals(msg, "${f.getInt("ip_len")}바이트", ip.f("전체 길이")); assertEquals(msg, "4 · ${f.getInt("ihl")}바이트", ip.f("버전·헤더 길이"))
                assertEquals(msg, f.getBoolean("ip_csum_ok"), ip.f("머리글 체크섬").endsWith("(맞아요)")); assertEquals(msg, !f.getBoolean("ip_csum_ok"), ip.hasNote("머리글 체크섬이 맞지 않아요"))
                when (f.getInt("proto")) {
                    6 -> {
                        val t = d.layer("TCP")
                        assertEquals(msg, "${f.getInt("sport")}", t.f("출발지 포트").substringBefore(' ')); assertEquals(msg, "${f.getInt("dport")}", t.f("목적지 포트").substringBefore(' '))
                        assertEquals(msg, "${f.getLong("seq")}", t.f("순서 번호(seq)")); assertEquals(msg, "${f.getLong("ack")}", t.f("확인 번호(ack)")); assertEquals(msg, f.getString("flags"), t.f("플래그"))
                        assertEquals(msg, "${f.getInt("win")}", t.f("윈도 크기")); assertEquals(msg, "${f.getInt("payload_len")}바이트", t.f("데이터 길이")); assertEquals(msg, "${f.getInt("tcp_hdr")}바이트", t.f("헤더 길이"))
                        assertEquals(msg, !f.getBoolean("l4_csum_ok"), t.hasNote("체크섬이 맞지 않아요"))
                    }
                    17 -> {
                        val u = d.layer("UDP")
                        assertEquals(msg, "${f.getInt("sport")}", u.f("출발지 포트").substringBefore(' ')); assertEquals(msg, "${f.getInt("dport")}", u.f("목적지 포트").substringBefore(' ')); assertEquals(msg, "${f.getInt("udp_len")}바이트", u.f("길이"))
                        assertEquals(msg, !f.getBoolean("l4_csum_ok"), u.hasNote("체크섬이 맞지 않아요")); assertEquals(msg, f.getInt("udp_csum") == 0, u.hasNote("체크섬이 0 이에요"))
                        if (f.has("dns_id")) {
                            val dns = d.layer("DNS"); assertEquals(msg, "0x%04x".format(f.getInt("dns_id")), dns.f("ID")); assertEquals(msg, if (f.getInt("dns_qr") == 1) "응답" else "질문", dns.f("종류"))
                            assertEquals(msg, DnsType.rcode(f.getInt("dns_rcode")), dns.f("응답 코드")); val q = f.getJSONArray("dns_q").getJSONArray(0)
                            assertEquals(msg, "${q.getString(0).trimEnd('.')} ${DnsType.name(q.getInt(1))}", dns.f("질문")); assertEquals(msg, "${f.getJSONArray("dns_an").length()}", dns.f("답 수"))
                        }
                    }
                    1 -> {
                        val c = d.layer("ICMP"); assertTrue(msg, c.f("종류").startsWith("${f.getInt("icmp_type")} ")); assertTrue(msg, c.f("코드").startsWith("${f.getInt("icmp_code")}"))
                        assertEquals(msg, !f.getBoolean("icmp_csum_ok"), c.hasNote("ICMP 체크섬이 맞지 않아요"))
                        if (f.has("icmp_id")) { assertEquals(msg, "${f.getInt("icmp_id")}", c.f("식별자(id)")); assertEquals(msg, "${f.getInt("icmp_seq")}", c.f("순서(seq)")) }
                    }
                }
            }
            "ipv6" -> {
                val ip = d.layer("IPv6")
                assertEquals(msg, f.getString("src"), ip.f("출발지 IP")); assertEquals(msg, f.getString("dst"), ip.f("목적지 IP")); assertEquals(msg, "${f.getInt("hlim")}", ip.f("홉 제한")); assertEquals(msg, "${f.getInt("plen")}바이트", ip.f("페이로드 길이"))
                assertEquals(msg, "0x%02x".format(f.getInt("fc")), ip.f("트래픽 클래스")); assertEquals(msg, "0x%05x".format(f.getInt("flow")), ip.f("플로 레이블")); assertTrue(msg, ip.f("다음 헤더").startsWith("${f.getInt("nxt")} "))
                val l4 = d.layers.first { it.name == "ICMPv6" || it.name == "TCP" }; assertEquals(msg, !f.getBoolean("l4_csum_ok"), l4.hasNote("체크섬이 맞지 않아요"))
                if (f.has("icmp_type")) assertTrue(msg, l4.f("종류").startsWith("${f.getInt("icmp_type")} "))
                if (f.has("sport")) { assertEquals(msg, "${f.getInt("sport")}", l4.f("출발지 포트").substringBefore(' ')); assertEquals(msg, f.getString("flags"), l4.f("플래그")) }
            }
        }
    }

    @Test fun decodeMatchesIndependentReferenceForEveryPacket() {
        assertTrue(packets.length() >= 25)
        for (name in packets.keys()) checkFacts(name)
    }

    @Test fun decodeSummariesAndSpecialCases() {
        val syn = PacketDecode.decode(raw("tcp_syn")); assertEquals("192.168.1.10 → 93.184.216.34 TCP 54321 → 443 [SYN] 0바이트", syn.summary); assertFalse(syn.truncated)
        assertTrue(syn.layer("TCP").f("옵션").contains("MSS 1460") && syn.layer("TCP").f("옵션").contains("SACK 허용") && syn.layer("TCP").f("옵션").contains("윈도 배율 7 (×128)") && syn.layer("TCP").f("옵션").contains("타임스탬프 1000/0"))
        assertTrue(syn.layer("TCP").hasNote("SYN: 연결 시작")); assertTrue(syn.layer("IPv4").f("플래그").startsWith("DF")); assertEquals(0, syn.layer("IPv4").noteLevel("TTL 64"))
        assertTrue(syn.layer("IPv4").hasNote("처음 값이 64 이라면 0개")); assertTrue(syn.layer("IPv4").f("목적지 IP").contains("공인"))
        // 자동 판별: 이더넷 / IP 부터 둘 다 같은 결과
        val ipOnly = hexBytes(packets.getJSONObject("tcp_syn").getString("ip_hex")); assertTrue(PacketDecode.looksLikeIp(ipOnly)); assertFalse(PacketDecode.looksLikeIp(raw("tcp_syn")))
        assertEquals(syn.summary, PacketDecode.decode(ipOnly).summary); assertEquals(syn.summary, PacketDecode.decode(ipOnly, "ip").summary); assertEquals(syn.summary, PacketDecode.decode(raw("tcp_syn"), "eth").summary)
        assertTrue(PacketDecode.looksLikeIp(hexBytes(packets.getJSONObject("ipv6_tcp_syn").getString("ip_hex")))); assertFalse(PacketDecode.looksLikeIp(raw("ipv6_tcp_syn")))
        // 응답·RST·제로 윈도
        assertTrue(PacketDecode.decode(raw("tcp_synack")).layer("TCP").hasNote("SYN+ACK: 서버가")); val rst = PacketDecode.decode(raw("tcp_rst")).layer("TCP"); assertTrue(rst.hasNote("RST")); assertEquals(1, rst.noteLevel("RST"))
        assertTrue(PacketDecode.decode(raw("tcp_zero_window")).layer("TCP").hasNote("윈도 크기가 0")); assertTrue(PacketDecode.decode(raw("tcp_synack")).layer("IPv4").hasNote("처음 값이 64 이라면 7개"))
        // 체크섬 틀림 (IP·TCP·UDP) 은 경고, 정상은 없음
        assertEquals(1, PacketDecode.decode(raw("bad_tcp_csum")).layer("TCP").noteLevel("체크섬이 맞지 않아요")); assertTrue(PacketDecode.decode(raw("bad_ip_csum")).layer("IPv4").hasNote("머리글 체크섬이 맞지 않아요")); assertTrue(PacketDecode.decode(raw("bad_udp_csum")).layer("UDP").hasNote("체크섬이 맞지 않아요"))
        assertTrue(PacketDecode.decode(raw("udp_zero_csum")).layer("UDP").hasNote("체크섬이 0 이에요")); assertFalse(PacketDecode.decode(raw("tcp_syn")).layer("TCP").hasNote("체크섬"))
        // IP 옵션, VLAN, MAC 종류
        assertTrue(PacketDecode.decode(raw("ip_option")).layer("IPv4").hasNote("IP 옵션이 있어요(4바이트)")); val vlan = PacketDecode.decode(raw("vlan_tcp")); assertTrue(vlan.layer("이더넷").f("EtherType").contains("IPv4")); assertEquals("10.100.0.5 → 10.100.0.1 TCP 1111 → 22 [SYN] 0바이트", vlan.summary)
        assertTrue(PacketDecode.decode(raw("arp_request")).layer("이더넷").f("목적지 MAC").endsWith("(브로드캐스트)")); assertTrue(PacketDecode.decode(raw("dhcp_discover")).layer("이더넷").f("목적지 MAC").endsWith("(브로드캐스트)"))
        val priv = PacketDecode.decode(hexBytes("aabbccddee01" + "02aabbccddee" + "0806" + "0001080006040001" + "02aabbccddee" + "c0a8010a" + "000000000000" + "c0a80101")); assertTrue(priv.layer("이더넷").hasNote("로컬 관리"))
        // ARP
        assertEquals("ARP: 누가 192.168.1.1 인가? (192.168.1.10 가 물음)", PacketDecode.decode(raw("arp_request")).summary); assertEquals("ARP: 192.168.1.1 는 aa:bb:cc:dd:ee:01", PacketDecode.decode(raw("arp_reply")).summary)
        assertTrue(PacketDecode.decode(raw("arp_gratuitous")).layer("ARP").hasNote("gratuitous ARP")); assertTrue(PacketDecode.decode(raw("arp_request")).layer("ARP").f("동작").contains("누가 192.168.1.1 인가?"))
        // ICMP
        val echo = PacketDecode.decode(raw("icmp_echo")); assertEquals("192.168.1.10 → 8.8.8.8 ICMP Echo 요청(ping)", echo.summary); assertEquals("32바이트", echo.layer("ICMP").f("데이터"))
        val un = PacketDecode.decode(raw("icmp_port_unreach")).layer("ICMP"); assertTrue(un.f("코드").contains("포트 도달 불가")); assertEquals("192.168.1.10 → 192.168.1.1 (UDP)", un.f("원래 패킷")); assertEquals(1, un.noteLevel("전달하지 못했다"))
        assertEquals("1400", PacketDecode.decode(raw("icmp_frag_needed")).layer("ICMP").f("다음 홉 MTU")); assertTrue(PacketDecode.decode(raw("icmp_frag_needed")).layer("ICMP").f("코드").contains("MTU 문제"))
        assertTrue(PacketDecode.decode(raw("icmp_ttl_exceeded")).layer("ICMP").hasNote("traceroute"))
        // IPv6
        assertEquals("fe80::5054:ff:fe12:3456 → 2001:db8::1 ICMPv6 Echo 요청(ping)", PacketDecode.decode(raw("ipv6_icmp_echo")).summary); assertEquals("2001:db8::10 → 2001:db8::20 TCP 40000 → 80 [SYN] 0바이트", PacketDecode.decode(raw("ipv6_tcp_syn")).summary)
        // DNS·HTTP·DHCP·NTP 응용 계층
        assertEquals("192.168.1.10 → 8.8.8.8 UDP 40000 → 53 29바이트 · DNS 질문 example.com A", PacketDecode.decode(raw("udp_dns_query")).summary); assertEquals("DNS 응답 example.com A", PacketDecode.decode(raw("udp_dns_response")).summary.substringAfter("· "))
        val http = PacketDecode.decode(raw("tcp_http_get")); assertEquals("GET /index.html HTTP/1.1", http.layer("HTTP").f("첫 줄")); assertEquals("example.com", http.layer("HTTP").f("Host")); assertEquals(1, http.layer("HTTP").noteLevel("암호화되지 않은"))
        assertTrue(PacketDecode.decode(raw("dhcp_offer")).layers.any { it.name == "DHCP" })
        // 짧거나 잘린 데이터
        val cut = PacketDecode.decode(raw("tcp_syn").copyOf(54 + 8)); assertTrue(cut.truncated); assertTrue(cut.layer("TCP").hasNote("체크섬을 확인할 수 없어요") || cut.layer("TCP").hasNote("짧아요"))
        assertTrue(PacketDecode.decode(byteArrayOf(1, 2, 3), "eth").layers[0].hasNote("14바이트보다 짧아서")); assertTrue(PacketDecode.decode(raw("tcp_syn").copyOf(20), "eth").layers.any { it.hasNote("짧아요") })
        assertTrue(PacketDecode.decode(hexBytes("ffffffffffff" + "aabbccddeeff" + "88cc" + "00".repeat(20))).layers.any { it.name == "알 수 없는 상위 프로토콜" })
    }

    // ============================================================ 체크섬 고치기

    @Test fun checksumFixerProducesTheSameBytesAsScapy() {
        val pairs = json("fixpairs.json")
        for (name in pairs.keys()) {
            val p = pairs.getJSONObject(name); val bad = hexBytes(p.getString("bad")); val good = hexBytes(p.getString("good")); val start = p.getString("start")
            val r = ChecksumFix.analyze(bad, start); assertNull(name, r.problem)
            assertArrayEquals("$name: 고친 결과가 scapy 가 계산한 올바른 패킷과 같아야 해요", good, r.fixed)
            assertTrue("$name: 고친 결과는 모두 맞아야 해요", ChecksumFix.analyze(r.fixed, start).allOk); assertEquals("$name: 틀렸는지 여부", !bad.contentEquals(good), !r.allOk)
        }
        // 구체적인 판정
        val tcp = ChecksumFix.analyze(hexBytes(pairs.getJSONObject("tcp").getString("bad")), "eth").items; assertEquals(listOf("IPv4 머리글" to true, "TCP" to false), tcp.map { it.layer to it.ok }); assertEquals(0x1234, tcp[1].stored)
        assertEquals(listOf(false, false), ChecksumFix.analyze(hexBytes(pairs.getJSONObject("ip_and_tcp").getString("bad")), "eth").items.map { it.ok }); assertEquals(0x1111, ChecksumFix.analyze(hexBytes(pairs.getJSONObject("ip").getString("bad")), "eth").items[0].stored)
        assertEquals(listOf("IPv6 머리글" to true, "TCP" to false), ChecksumFix.analyze(hexBytes(pairs.getJSONObject("tcp6").getString("bad")), "eth").items.map { it.layer to it.ok }); assertEquals("ICMPv6", ChecksumFix.analyze(hexBytes(pairs.getJSONObject("icmp6").getString("bad")), "eth").items[1].layer)
        assertTrue(ChecksumFix.analyze(hexBytes(pairs.getJSONObject("udp_zero").getString("bad")), "eth").items.any { it.layer == "UDP" && it.ok && it.note!!.contains("사용 안 함") })
        // 맞는 패킷은 그대로, 틀린 패킷은 이름대로
        for (name in packets.keys()) {
            if (facts(name).getString("l3") == "arp") continue
            val r = ChecksumFix.analyze(raw(name), "eth"); assertEquals(name, !name.startsWith("bad_"), r.allOk)
            if (r.allOk) assertArrayEquals(name, raw(name), r.fixed) else assertTrue(name, ChecksumFix.analyze(r.fixed, "eth").allOk)
        }
        assertEquals("IPv4·IPv6 패킷이 아니에요 (EtherType 0x0806)", ChecksumFix.analyze(raw("arp_request"), "eth").problem!!.substringBefore(")") + ")"); assertNotNull(ChecksumFix.analyze(ByteArray(5), "eth").problem); assertNotNull(ChecksumFix.analyze(ByteArray(0), "ip").problem)
        val cut = ChecksumFix.analyze(raw("tcp_syn").copyOf(54 + 8), "eth"); assertTrue(cut.items.any { it.note?.contains("잘려서") == true })
        val frag = hexBytes(packets.getJSONObject("tcp_syn").getString("ip_hex")).also { it[6] = 0x20; it[7] = 0x00 }; assertTrue(ChecksumFix.analyze(frag, "ip").items.any { it.note?.contains("조각난") == true })
    }

    // ============================================================ TLS Hello · JA3

    @Test fun tlsHelloMatchesDpktAndRealOpenSslBytes() {
        val ref = json("tls.json")
        for (name in listOf("openssl13", "openssl12", "openssl_nosni", "python13", "grease", "legacy")) {
            val exp = ref.getJSONObject(name).getJSONObject("client"); val h = TlsHello.parse(hexBytes(file("tls/${name}_client.hex").readText().trim()))!!
            assertTrue(name, h.client); assertEquals("$name JA3", exp.getString("ja3"), h.ja3); assertEquals("$name JA3 해시", exp.getString("md5"), h.ja3Hash); assertEquals("$name SNI", (if (exp.isNull("sni")) null else exp.getString("sni")), h.sni)
            assertEquals(name, strList(exp.getJSONArray("alpn")), h.alpn); assertEquals(name, exp.getInt("ciphers"), h.ciphers.size); assertEquals(name, exp.getJSONArray("ext_types").let { a -> (0 until a.length()).map { a.getInt(it) } }, h.exts.map { it.type }); assertTrue(name, h.complete)
        }
        for (name in listOf("openssl13", "openssl12", "openssl_nosni", "python13")) {
            val exp = ref.getJSONObject(name).getJSONObject("server"); val s = TlsHello.parse(tlsBytes(name, "server"))!!
            assertFalse(name, s.client); assertEquals("$name JA3S", exp.getString("ja3s"), s.ja3); assertEquals("$name JA3S 해시", exp.getString("md5"), s.ja3Hash); assertEquals(name, exp.getInt("cipher"), s.ciphers[0])
        }
        // 알려진 사실: OpenSSL 3 의 TLS 1.3 ClientHello
        val o13 = TlsHello.parse(tlsBytes("openssl13"))!!; assertEquals(0x0303, o13.version); assertTrue(0x0304 in o13.supportedVersions); assertEquals("example.com", o13.sni); assertEquals(listOf("h2", "http/1.1"), o13.alpn); assertTrue(29 in o13.groups && 23 in o13.groups); assertEquals(listOf(29), o13.keyShareGroups)
        assertEquals(32, o13.sessionId.size); assertEquals(0x0301, o13.recordVersion); assertEquals(listOf(0), o13.compression)
        // GREASE 는 JA3 에서 빠지고 원래 값으로는 남아 있음
        val g = TlsHello.parse(hexBytes(file("tls/grease_client.hex").readText().trim()))!!; assertTrue(0x0a0a in g.ciphers); assertTrue(0x1a1a in g.exts.map { it.type }); assertFalse(g.ja3.contains("2570")); assertFalse(g.ja3.contains("6682")); assertEquals("www.example.net", g.sni)
        // 이더넷·IP·TCP 머리글이 붙은 패킷 안에서도 찾음
        val hello = tlsBytes("openssl13"); val sip = byteArrayOf(192.toByte(), 168.toByte(), 1, 10); val dip = byteArrayOf(93, 184.toByte(), 216.toByte(), 34)
        val frame = PacketBuild.ether(ByteArray(6) { 1 }, ByteArray(6) { 2 }, 0x0800, PacketBuild.ipv4(sip, dip, 6, PacketBuild.tcp(sip, dip, 54321, 443, 1, 1, 0x18, 1000, hello)))
        assertEquals(o13.ja3Hash, TlsHello.parse(frame)!!.ja3Hash); assertTrue(PacketDecode.decode(frame).layers.any { it.name == "TLS" && it.f("서버 이름(SNI)") == "example.com" })
        // 조각난 Hello 는 표시
        val big = TlsHello.parse(tlsBytes("python13").copyOf(1448))!!; assertFalse(big.complete); assertNull(TlsHello.parse(tlsBytes("openssl13").copyOf(30))); assertNull(TlsHello.parse(ByteArray(100) { 7 })); assertNull(TlsHello.parse(ByteArray(0)))
        // 약한 암호군 판별
        assertTrue(TlsHello.isWeakCipher(0x0005) && TlsHello.isWeakCipher(0x000a) && TlsHello.isWeakCipher(0xc011) && TlsHello.isWeakCipher(0x0001)); assertFalse(TlsHello.isWeakCipher(0x1301) || TlsHello.isWeakCipher(0xc02f) || TlsHello.isWeakCipher(0x1234))
    }

    // ============================================================ DHCP · NTP

    @Test fun dhcpMatchesDpkt() {
        val ref = json("dhcp.json")
        for (name in listOf("dhcp_discover", "dhcp_offer")) {
            val exp = ref.getJSONObject(name); val m = DhcpParse.parse(hexBytes(exp.getString("udp_payload_hex")))!!
            assertEquals(name, exp.getLong("xid"), m.xid); assertEquals(name, exp.getString("yiaddr"), m.yiaddr); assertEquals(name, exp.getString("siaddr"), m.siaddr); assertEquals(name, exp.getString("chaddr"), m.chaddr)
            val opts = exp.getJSONObject("opts"); assertEquals(name, opts.keys().asSequence().map { it.toInt() }.filter { it != 255 && it != 0 }.sorted().toList(), m.options.map { it.code }.sorted())
        }
        val o = DhcpParse.parse(hexBytes(ref.getJSONObject("dhcp_offer").getString("udp_payload_hex")))!!; fun v(c: Int) = o.options.first { it.code == c }.value
        assertEquals("OFFER(주소 제안)", o.msgType); assertEquals(2, o.op); assertEquals("255.255.255.0", v(1)); assertEquals("192.168.1.1", v(3)); assertEquals("192.168.1.1, 8.8.8.8", v(6)); assertEquals("home.lan", v(15)); assertEquals("86400초 (24시간)", v(51)); assertEquals("43200초 (12시간)", v(58)); assertEquals("75600초 (21시간)", v(59)); assertEquals("192.168.1.1", v(54))
        val d = DhcpParse.parse(hexBytes(ref.getJSONObject("dhcp_discover").getString("udp_payload_hex")))!!; assertEquals("DISCOVER(주소 찾기)", d.msgType); assertEquals("my-phone", d.hostname); assertTrue(d.broadcast); assertEquals(1, d.op)
        assertEquals("서브넷 마스크, 라우터(게이트웨이), DNS 서버, 도메인 이름, 브로드캐스트 주소, 임대 시간", d.options.first { it.code == 55 }.value); assertNull(DhcpParse.parse(ByteArray(300))); assertNull(DhcpParse.parse(ByteArray(10)))
    }

    @Test fun ntpMatchesIndependentTimestamps() {
        val exp = json("ntp.json"); val m = NtpDecode.parse(hexBytes(exp.getString("hex")))!!
        assertEquals(0, m.li); assertEquals(4, m.vn); assertEquals(4, m.mode); assertEquals(2, m.stratum); assertEquals(6, m.poll); assertEquals(-23, m.precision); assertEquals("192.168.1.1", m.refId)
        assertEquals(exp.getDouble("rootdelay"), m.rootDelay, 1e-9); assertEquals(exp.getDouble("rootdisp"), m.rootDisp, 1e-9); assertEquals(exp.getDouble("t1"), m.orig, 1e-6); assertEquals(exp.getDouble("t2"), m.recv, 1e-6); assertEquals(exp.getDouble("t3"), m.xmit, 1e-6)
        assertEquals("2023-11-14T22:13:20.125 UTC", NtpDecode.fmt(m.orig)); assertEquals("(0, 값 없음)", NtpDecode.fmt(0.0))
        val gps = NtpDecode.parse(hexBytes(exp.getString("gps_hex")))!!; assertEquals(1, gps.stratum); assertEquals("GPS", gps.refId); assertNull(NtpDecode.parse(ByteArray(47)))
        // 시계 오차·왕복 지연 공식: 서버가 +50ms 앞서 있고 한쪽 지연이 10ms 인 상황을 만들어 놓고 거꾸로 계산
        val (off, delay) = NtpDecode.offsetDelay(100.0, 100.060, 100.061, 100.021); assertEquals(0.050, off, 1e-9); assertEquals(0.020, delay, 1e-9)
        val (off2, delay2) = NtpDecode.offsetDelay(100.0, 100.010, 100.011, 100.021); assertEquals(0.0, off2, 1e-9); assertEquals(0.020, delay2, 1e-9)
        val (off3, _) = NtpDecode.offsetDelay(100.0, 99.960, 99.961, 100.021); assertEquals(-0.050, off3, 1e-9)
    }

    // ============================================================ pcap · pcapng 읽기와 통계

    @Test fun captureFormatsAllReadIdentically() {
        val fmt = json("pcap_formats.json")
        for (name in fmt.keys()) {
            val exp = fmt.getJSONObject(name); val cap = PcapRead.read(file(name).readBytes()); val tol = if (name.contains("nano")) 1L else 0L
            assertEquals(name, exp.getInt("count"), cap.packets.size); assertEquals(name, exp.getLong("bytes"), cap.packets.sumOf { it.data.size.toLong() }); assertFalse(name, cap.truncatedFile)
            assertEquals(name, exp.getLong("first").toDouble(), cap.packets.first().tsMicros.toDouble(), tol.toDouble()); assertEquals(name, exp.getLong("last").toDouble(), cap.packets.last().tsMicros.toDouble(), tol.toDouble())
        }
        assertTrue(PcapRead.read(file("sample.pcap").readBytes()).format.startsWith("pcap (마이크로초")); assertTrue(PcapRead.read(file("sample_nano.pcap").readBytes()).format.startsWith("pcap (나노초")); assertEquals("pcapng", PcapRead.read(file("sample.pcapng").readBytes()).format)
        val lt = json("linktypes.json"); val sll = PcapRead.read(file("sample_sll.pcap").readBytes()); val rawIp = PcapRead.read(file("sample_raw.pcap").readBytes())
        assertEquals(lt.getInt("sll_count"), sll.packets.size); assertEquals(113, sll.packets[0].link); assertEquals(lt.getInt("raw_count"), rawIp.packets.size); assertTrue(rawIp.packets[0].link in setOf(101, 228))
        // 링크 종류가 달라도 같은 접속 통계 (SLL·순수 IP 에는 IPv4 패킷만 담아 둠)
        val base = PcapStats.analyze(PcapRead.read(file("sample.pcap").readBytes()))
        for (c in listOf(sll, rawIp)) { val r = PcapStats.analyze(c); assertEquals(base.syn, r.syn); assertEquals(base.synAck, r.synAck); assertEquals(base.rst, r.rst); assertEquals(base.retrans, r.retrans); assertEquals(base.zeroWin, r.zeroWin); assertEquals(base.synUnanswered, r.synUnanswered); assertEquals(base.sni, r.sni); assertEquals(base.dnsQueries, r.dnsQueries); assertEquals(base.cleartext, r.cleartext); assertEquals(46, r.l3["IPv4"]) }
        // pcapng 도 같은 통계
        val ng = PcapStats.analyze(PcapRead.read(file("sample.pcapng").readBytes())); assertEquals(base.protos, ng.protos); assertEquals(base.dnsQueries, ng.dnsQueries); assertEquals(base.sni, ng.sni); assertEquals(base.first, ng.first); assertEquals(base.last, ng.last)
        // 빅 엔디언 pcap 도 같은 통계
        val be = PcapStats.analyze(PcapRead.read(file("sample_be.pcap").readBytes())); assertEquals(base.protos, be.protos); assertEquals(base.first, be.first)
    }

    @Test fun captureReaderHandlesDamagedAndWrongFiles() {
        val b = file("sample.pcap").readBytes()
        val cut = PcapRead.read(b.copyOf(b.size - 10)); assertTrue(cut.truncatedFile); assertEquals(51, cut.packets.size)
        val cutNg = PcapRead.read(file("sample.pcapng").readBytes().let { it.copyOf(it.size - 7) }); assertTrue(cutNg.truncatedFile); assertTrue(cutNg.packets.size in 40..51)
        val junk = PcapRead.read(ByteArray(100) { 9 }); assertTrue(junk.packets.isEmpty()); assertEquals("알 수 없음", junk.format); assertTrue(junk.notes[0].contains("pcap")); assertTrue(PcapRead.read(ByteArray(3)).packets.isEmpty())
        assertTrue(PcapRead.read(b.copyOf(24)).packets.isEmpty())                                                                  // 머리글만 있는 파일
        val capped = PcapRead.read(b, maxPackets = 10); assertEquals(10, capped.packets.size); assertTrue(capped.notes.any { it.contains("10개") })
    }

    @Test fun captureStatisticsMatchIndependentAnalysis() {
        val exp = json("pcap_expect.json"); val r = PcapStats.analyze(PcapRead.read(file("sample.pcap").readBytes()))
        assertEquals(exp.getInt("total"), r.total); assertEquals(exp.getLong("bytes"), r.bytes); assertEquals(exp.getLong("first"), r.first); assertEquals(exp.getLong("last"), r.last); assertEquals(intMap(exp.getJSONObject("l3")), r.l3)
        assertEquals(intMap(exp.getJSONObject("dns_q")), r.dnsQueries.toMap()); assertEquals(strList(exp.getJSONArray("dns_unanswered")), r.dnsUnanswered)
        assertEquals((0 until exp.getJSONArray("dns_fail").length()).map { exp.getJSONArray("dns_fail").getJSONArray(it).let { p -> p.getString(0) to p.getString(1) } }, r.dnsFail)
        assertEquals(intMap(exp.getJSONObject("sni")), r.sni.toMap()); assertEquals(intMap(exp.getJSONObject("http")), r.http.toMap()); assertEquals(intMap(exp.getJSONObject("cleartext")), r.cleartext.toMap()); assertEquals(intMap(exp.getJSONObject("ja3")), r.ja3.toMap())
        assertEquals(exp.getInt("syn"), r.syn); assertEquals(exp.getInt("synack"), r.synAck); assertEquals(exp.getInt("rst"), r.rst); assertEquals(exp.getInt("retrans"), r.retrans); assertEquals(exp.getInt("zero"), r.zeroWin)
        assertEquals((0 until exp.getJSONArray("syn_unanswered").length()).map { exp.getJSONArray("syn_unanswered").getJSONArray(it).let { p -> p.getString(0) to p.getInt(1) } }, r.synUnanswered)
        assertEquals(strList(exp.getJSONArray("rst_from")), r.rstFrom.map { it.first }.sorted()); assertEquals(strList(exp.getJSONArray("icmp_unreach")), r.icmpUnreach); assertEquals(strList(exp.getJSONArray("arp_unanswered")), r.arpUnanswered)
        assertEquals(exp.getInt("notip"), r.notIp); assertEquals(exp.getInt("ip_fragments"), r.fragments)
        // 만든 순서로 알고 있는 사실 (접속 대상·프로토콜 분포)
        assertEquals(mapOf("example.com" to listOf("93.184.216.34")), r.dnsAnswers); assertEquals(mapOf("example.com" to listOf("93.184.216.34"), "api.example.org" to listOf("93.184.216.34")), r.sniIps); assertEquals(mapOf("nas.local" to listOf("192.168.1.30")), r.httpHostIps)
        assertEquals(3, r.protos["ARP"]); assertEquals(2, r.protos["ICMPv6"]); assertEquals(3, r.protos["ICMP"]); assertEquals(8, r.protos["UDP · DNS"]); assertEquals(1, r.protos["UDP · QUIC(HTTP/3)"]); assertEquals(1, r.protos["IP 조각"]); assertEquals(10, r.protos["TCP · HTTPS"])
        assertTrue(r.flows.size <= 20 && r.flows.isNotEmpty()); assertTrue(r.flows.zipWithNext().all { (a, b) -> a.packets >= b.packets }); assertTrue(r.talkers.size <= 10); assertTrue(r.talkers.zipWithNext().all { (a, b) -> a.second >= b.second })
        assertEquals(r.protos.values.sum() - r.protos["IP 조각"]!! - r.protos["ARP"]!!, r.l3["IPv4"]!! + r.l3["IPv6"]!! - r.fragments)                           // 분류된 패킷 수가 맞아떨어짐
    }

    @Test fun clientHelloSplitAcrossSegmentsIsReassembledOnlyInOrder() {
        val sip = byteArrayOf(10, 0, 0, 2); val dip = byteArrayOf(10, 0, 0, 3); val hello = tlsBytes("python13")
        fun pkt(seq: Long, data: ByteArray) = PcapRead.Pkt(0, 101, PacketBuild.ipv4(sip, dip, 6, PacketBuild.tcp(sip, dip, 40000, 443, seq, 1, 0x18, 1000, data)), 0)
        fun stats(vararg p: PcapRead.Pkt) = PcapStats.analyze(PcapRead.Capture(p.toList(), "x", false, emptyList()))
        assertEquals(listOf("api.example.org" to 1), stats(pkt(100, hello.copyOf(1000)), pkt(1100, hello.copyOfRange(1000, hello.size))).sni)
        assertEquals(listOf("api.example.org" to 1), stats(pkt(100, hello.copyOf(500)), pkt(600, hello.copyOfRange(500, 1000)), pkt(1100, hello.copyOfRange(1000, hello.size))).sni)               // 세 조각
        assertTrue(stats(pkt(100, hello.copyOf(1000)), pkt(5000, hello.copyOfRange(1000, hello.size))).sni.isEmpty())                                         // 이어지지 않으면 읽지 않음
        assertEquals(listOf("api.example.org" to 1), stats(pkt(0xfffffff0L, hello.copyOf(32)), pkt(0x10L, hello.copyOfRange(32, hello.size))).sni)             // 순서 번호가 한 바퀴 돌아도 이어붙임
    }

    // ============================================================ 패킷 만들기

    @Test fun packetBuilderMatchesScapyByteForByte() {
        val ref = json("build.json"); val sip = byteArrayOf(192.toByte(), 168.toByte(), 1, 10); val google = byteArrayOf(8, 8, 8, 8); val web = byteArrayOf(93, 184.toByte(), 216.toByte(), 34)
        assertEquals(ref.getString("icmp_echo"), hex(PacketBuild.ipv4(sip, google, 1, PacketBuild.icmpEcho(0x1234, 1, "abcdefgh".toByteArray()))))
        assertEquals(ref.getString("udp"), hex(PacketBuild.ipv4(sip, google, 17, PacketBuild.udp(sip, google, 40000, 53, hexBytes("12340100")))))
        assertEquals(ref.getString("tcp_syn"), hex(PacketBuild.ipv4(sip, web, 6, PacketBuild.tcp(sip, web, 54321, 443, 1000, 0, 0x02, 64240, ByteArray(0), synOptions = true))))
        assertEquals(ref.getString("tcp_data"), hex(PacketBuild.ipv4(sip, web, 6, PacketBuild.tcp(sip, web, 54321, 80, 5, 9, 0x18, 64240, "hello".toByteArray()))))
        val mac = Bx.parseMac("52:54:00:12:34:56")!!
        assertEquals(ref.getString("arp_req"), hex(PacketBuild.ether(ByteArray(6) { 0xff.toByte() }, mac, 0x0806, PacketBuild.arp(1, mac, sip, ByteArray(6), byteArrayOf(192.toByte(), 168.toByte(), 1, 1)))))
        assertEquals(ref.getString("wol"), hex(PacketBuild.wol(Bx.parseMac("aa-bb-cc-dd-ee-ff")!!))); assertEquals(48, PacketBuild.ntpRequest().size); assertEquals(0x1b, PacketBuild.ntpRequest()[0].toInt())
        assertNull(Bx.parseMac("aa:bb:cc")); assertNull(Bx.parseMac("zz:bb:cc:dd:ee:ff")); assertNull(Bx.parseMac("aabbccddeeff")); assertEquals("aa:bb:cc:dd:ee:ff", Bx.mac(Bx.parseMac("AA-BB-CC-DD-EE-FF")!!, 0))
        // 만든 패킷은 우리 해석기로 다시 읽어도 체크섬이 모두 맞음
        for (p in listOf(PacketBuild.ipv4(sip, google, 1, PacketBuild.icmpEcho(1, 1, ByteArray(40))), PacketBuild.ipv4(sip, google, 17, PacketBuild.udp(sip, google, 1, 2, ByteArray(33))), PacketBuild.ipv4(sip, web, 6, PacketBuild.tcp(sip, web, 1, 2, 3, 4, 0x10, 5, ByteArray(7))))) assertTrue(ChecksumFix.analyze(p, "ip").allOk)
    }

    // ============================================================ 도구 (화면에 보이는 값)

    @Test fun toolPktDecode() {
        val r = run("pkt_decode"); assertEquals("192.168.1.10 → 93.184.216.34 TCP 54321 → 443 [SYN] 0바이트", r.kv("요약")); assertEquals("74바이트", r.kv("전체 크기")); assertEquals("64", r.kv("TTL")); assertEquals("1000", r.kv("순서 번호(seq)")); assertFalse(r.hasError)
        for (fmt in listOf(this::asTcpdumpX, this::asHexdumpC, this::asWireshark, this::asScapy, this::asText2pcap)) assertEquals(r.kv("요약"), run("pkt_decode", "h" to fmt(raw("tcp_syn"))).kv("요약"))
        assertEquals(r.kv("요약"), run("pkt_decode", "h" to hex(hexBytes(packets.getJSONObject("tcp_syn").getString("ip_hex"))), "s" to "IP 부터").kv("요약"))
        assertTrue(run("pkt_decode", "h" to hex(raw("bad_tcp_csum"))).text().contains("체크섬이 맞지 않아요")); assertTrue(run("pkt_decode", "h" to hex(raw("tcp_syn").copyOf(60))).text().contains("잘려 있어요"))
        assertTrue(run("pkt_decode", "h" to "").notes().any { it.level == 1 }); assertFalse(run("pkt_decode", "h" to "").hasError); assertTrue(run("pkt_decode", "h" to "xyz").hasError); assertTrue(run("pkt_decode", "h" to "45 00 0").hasError)
        for (n in listOf("dhcp_offer", "icmp_port_unreach", "arp_request", "ipv6_icmp_echo", "vlan_tcp")) assertFalse(n, run("pkt_decode", "h" to hex(raw(n))).hasError)
    }

    @Test fun toolPktChecksum() {
        val r = run("pkt_checksum"); val rows = r.rows(); assertEquals(listOf("IPv4 머리글", "맞아요"), listOf(rows[0][0], rows[0][3])); assertEquals(listOf("TCP", "0x1234", "틀려요"), listOf(rows[1][0], rows[1][1], rows[1][3])); assertEquals(2, r.rowLevel("TCP"))
        val fixed = hexBytes(r.kv("고친 패킷(16진수)")); assertTrue(ChecksumFix.analyze(fixed, "eth").allOk); assertEquals(rows[1][2], "0x%04x".format(Bx.u16(fixed, 14 + 20 + 16)))
        val pairs = json("fixpairs.json"); for (n in listOf("tcp", "udp", "icmp", "tcp6", "icmp6", "vlan", "ip_and_tcp")) { val p = pairs.getJSONObject(n); assertEquals(n, p.getString("good"), run("pkt_checksum", "h" to p.getString("bad")).kv("고친 패킷(16진수)")) }
        assertEquals(hex(hexBytes(pairs.getJSONObject("ip_only").getString("good"))), run("pkt_checksum", "h" to pairs.getJSONObject("ip_only").getString("bad"), "s" to "IP 부터").kv("고친 패킷(16진수)"))
        val ok = run("pkt_checksum", "h" to hex(raw("tcp_syn"))); assertFalse(ok.hasKv("고친 패킷(16진수)")); assertTrue(ok.notes().any { it.level == -1 && "모두 맞아요" in it.text })
        val calc = run("pkt_checksum", "h" to "00 01 f2 03 f4 f5 f6 f7", "m" to "바이트 열의 체크섬만 계산 (RFC 1071)"); assertEquals("0xddf2", calc.kv("16비트 합(올림 접기)")); assertEquals("0x220d", calc.kv("체크섬(합의 보수)")); assertEquals("22 0d", calc.kv("체크섬 바이트")); assertTrue(calc.kv("이미 들어 있는 체크섬 검증").startsWith("맞지 않거나"))
        assertTrue(run("pkt_checksum", "h" to "00 01 f2 03 f4 f5 f6 f7 22 0d", "m" to "바이트 열의 체크섬만 계산 (RFC 1071)").kv("이미 들어 있는 체크섬 검증").startsWith("맞아요")); assertTrue(run("pkt_checksum", "h" to "01 02 03", "m" to "바이트 열의 체크섬만 계산 (RFC 1071)").text().contains("홀수"))
        assertTrue(run("pkt_checksum", "h" to hex(raw("arp_request"))).hasError); assertTrue(run("pkt_checksum", "h" to "qq").hasError)
    }

    @Test fun toolPktPcap() {
        val host = hostWith("f" to file("sample.pcap")); val r = run("pkt_pcap", host = host)
        assertEquals("52개", r.kv("패킷 수")); assertEquals("5.2KB", r.kv("전체 크기")); assertEquals("2023-11-14 22:13:20.000 UTC ~ 2023-11-14 22:13:23.300 UTC", r.kv("기간")); assertEquals("3.300초", r.kv("길이")); assertTrue(r.kv("파일 형식").startsWith("pcap (마이크로초"));
        val t = r.text(); assertTrue(t.contains("TCP · HTTPS")); assertTrue(r.rows().any { it[0] == "UDP · DNS" && it[1] == "8" })
        // 문제 신호가 빠짐없이 나오고, 위험도 단계가 맞음
        fun note(fragment: String) = r.noteWith(fragment) ?: error("'$fragment' 안내가 없음:\n$t")
        assertEquals(2, note("203.0.113.99:8080 로 연결(SYN)을 3번").level); assertEquals(1, note("연결 거부·강제 종료(RST) 1번: 192.168.1.20:22(1번)").level); assertEquals(1, note("재전송으로 보이는 패킷이 1개").level); assertEquals(1, note("TCP 윈도 크기 0 이 1번").level)
        assertEquals(2, note("답이 없는 DNS 질문: timeout.example.net A").level); assertEquals(1, note("DNS 실패 응답: missing.example.org A → NXDOMAIN").level); assertEquals(1, note("ICMP 오류: 192.168.1.1 → 192.168.1.10: 목적지 도달 불가 · 포트 도달 불가").level)
        assertEquals(1, note("192.168.1.99").level); assertEquals(2, note("FTP 로그인(USER/PASS) 2번").level); assertEquals(2, note("HTTP Basic 인증 1번").level); assertEquals(2, note("Telnet(암호화 없는 원격 접속) 1번").level)
        assertFalse(t.contains("dXNlcjpwYXNz")); assertFalse(t.contains("guest@example.com")); assertFalse(t.contains("anonymous"))                                    // 평문 로그인 내용은 보여 주지 않음
        assertEquals(0, note("IP 조각(fragment) 1개").level); assertEquals(0, note("IP 가 아닌 프레임 1개").level)
        assertTrue(r.rows().any { it[0] == "192.168.1.10" && it[2] == "내부 주소" }); assertTrue(r.rows().any { it[0] == "93.184.216.34" && it[2].isNotEmpty() })
        // 파일 없음 / 잘못된 파일 / 빈 캡처
        val none = run("pkt_pcap"); assertFalse(none.hasError); assertTrue(none.notes().single().text.contains("캡처 파일")); val bad = File.createTempFile("bad", ".pcap").also { it.writeBytes(ByteArray(64) { 1 }); it.deleteOnExit() }
        assertTrue(run("pkt_pcap", host = hostWith("f" to bad)).notes().single().text.contains("pcap")); assertEquals("52개", run("pkt_pcap", host = hostWith("f" to file("sample.pcapng"))).kv("패킷 수"))
        // 평범한 캡처: ARP 응답·DNS 응답이 모두 있으면 "문제 없음"
        val clean = File.createTempFile("clean", ".pcap").also { f -> f.writeBytes(file("sample.pcap").readBytes().copyOf(24 + 16 + 42)); f.deleteOnExit() }       // 첫 ARP 요청 한 개만
        assertTrue(run("pkt_pcap", host = hostWith("f" to clean)).notes().any { it.text.contains("ARP 로 물었는데") })
    }

    @Test fun toolPktPcapSites() {
        val r = run("pkt_pcap_sites", host = hostWith("f" to file("sample.pcap"))); val rows = r.rows().associateBy { it[0] }
        assertEquals("5개", r.kv("이름 수")); assertEquals("DNS×2 TLS×1", rows.getValue("example.com")[1]); assertTrue(rows.getValue("example.com")[2].startsWith("93.184.216.34 (")); assertEquals("TLS×1", rows.getValue("api.example.org")[1]); assertTrue(rows.getValue("api.example.org")[2].startsWith("93.184.216.34"))
        assertEquals("HTTP×1", rows.getValue("nas.local")[1]); assertEquals("192.168.1.30 (내부 주소)", rows.getValue("nas.local")[2]); assertEquals("DNS×2", rows.getValue("timeout.example.net")[1]); assertEquals("-", rows.getValue("timeout.example.net")[2]); assertEquals("DNS×1", rows.getValue("missing.example.org")[1])
        assertEquals(listOf("example.com", "timeout.example.net"), r.rows().map { it[0] }.take(2)); assertTrue(r.noteWith("답을 못 받은 DNS 이름: timeout.example.net A") != null); assertTrue(r.noteWith("몰래 캡처")!!.level == 1)
        assertTrue(run("pkt_pcap_sites").notes().single().text.contains("캡처 파일"))
        val onlyArp = File.createTempFile("arp", ".pcap").also { f -> f.writeBytes(file("sample.pcap").readBytes().copyOf(24 + 16 + 42)); f.deleteOnExit() }
        assertTrue(run("pkt_pcap_sites", host = hostWith("f" to onlyArp)).notes().any { it.text.contains("찾지 못했어요") })
    }

    @Test fun toolPktJa3() {
        val ref = json("tls.json"); val r = run("pkt_ja3")
        assertEquals("ClientHello (클라이언트 → 서버)", r.kv("종류")); assertEquals(ref.getJSONObject("openssl13").getJSONObject("client").getString("md5"), r.kv("JA3 해시(MD5)")); assertEquals(ref.getJSONObject("openssl13").getJSONObject("client").getString("ja3"), r.kv("JA3 문자열")); assertEquals("example.com", r.kv("서버 이름(SNI)"))
        assertEquals("h2, http/1.1", r.kv("ALPN")); assertEquals("TLS 1.2", r.kv("핸드셰이크 버전")); assertTrue(r.kv("지원 버전(확장)").contains("TLS 1.3") && r.kv("지원 버전(확장)").contains("TLS 1.2")); assertEquals("32바이트", r.kv("세션 ID")); assertTrue(r.kv("지원 그룹(곡선)").contains("x25519"))
        assertTrue(r.rows().any { it[1].contains("TLS_AES_256_GCM_SHA384") }); assertTrue(r.rows().any { it[1].contains("server_name(SNI)") }); assertTrue(r.noteWith("TLS 1.3 을 지원해요")!!.level == -1); assertNull(r.noteWith("약한 암호군")); assertNull(r.noteWith("오래된 프로토콜")); assertNull(r.noteWith("SNI 가 없어요"))
        // 오래된 클라이언트: 낮은 버전·RC4·3DES·SNI 없음·전방 비밀성 없음
        val old = run("pkt_ja3", "h" to file("tls/legacy_client.hex").readText()); assertEquals(ref.getJSONObject("legacy").getJSONObject("client").getString("md5"), old.kv("JA3 해시(MD5)")); assertEquals(2, old.noteWith("오래된 프로토콜 버전")!!.level); assertTrue(old.noteWith("오래된 프로토콜 버전")!!.text.contains("TLS 1.0"))
        assertEquals(2, old.noteWith("약한 암호군 2개")!!.level); assertTrue(old.noteWith("약한 암호군")!!.text.contains("RC4-SHA") && old.noteWith("약한 암호군")!!.text.contains("DES-CBC3-SHA")); assertEquals(1, old.noteWith("SNI 가 없어요")!!.level); assertEquals(2, old.noteWith("전방 비밀성")!!.level); assertEquals(1, old.noteWith("TLS 1.3 을 제시하지 않았어요")!!.level)
        assertEquals("없음", old.kv("서버 이름(SNI)")); assertEquals(1, old.kvLevel("서버 이름(SNI)")); assertTrue(old.rows().any { it[1].contains("RC4-SHA") && old.rowLevel(it[0]) == 2 })
        // 서버 Hello
        val s = run("pkt_ja3", "h" to file("tls/openssl13_server.hex").readText()); assertEquals("ServerHello (서버 → 클라이언트)", s.kv("종류")); assertEquals(ref.getJSONObject("openssl13").getJSONObject("server").getString("md5"), s.kv("JA3S 해시(MD5)")); assertTrue(s.kv("고른 버전(확장)").contains("TLS 1.3")); assertTrue(s.noteWith("서버가 고른 버전: TLS 1.3")!!.level == -1)
        // GREASE·조각난 Hello·패킷 전체
        assertTrue(run("pkt_ja3", "h" to file("tls/grease_client.hex").readText()).noteWith("GREASE 값이 3개")!!.text.contains("JA3")); assertEquals(1, run("pkt_ja3", "h" to hex(tlsBytes("python13").copyOf(1448))).noteWith("한 패킷에 다 들어 있지 않아요")!!.level)
        assertEquals(r.kv("JA3 해시(MD5)"), run("pkt_ja3", "h" to hex(PacketBuild.ether(ByteArray(6), ByteArray(6), 0x0800, PacketBuild.ipv4(byteArrayOf(1, 1, 1, 1), byteArrayOf(2, 2, 2, 2), 6, PacketBuild.tcp(byteArrayOf(1, 1, 1, 1), byteArrayOf(2, 2, 2, 2), 1, 443, 1, 1, 0x18, 1, tlsBytes("openssl13")))))).kv("JA3 해시(MD5)"))
        assertTrue(run("pkt_ja3", "h" to "45 00 00 00 11 22").hasError); assertTrue(run("pkt_ja3", "h" to "qq").hasError); assertFalse(run("pkt_ja3", "h" to "").hasError)
    }

    @Test fun toolPktDnsDecode() {
        val r = run("pkt_dns_decode"); assertEquals("0x3039", r.kv("ID")); assertEquals("응답", r.kv("종류")); assertEquals("NOERROR", r.kv("응답 코드")); assertEquals("질문 1 · 답 1 · 권한 0 · 추가 0", r.kv("개수")); assertEquals("RD(재귀 요청) · RA(재귀 가능)", r.kv("플래그")); assertEquals("0 (표준 질의)", r.kv("opcode"))
        assertTrue(r.rows().any { it == listOf("example.com", "A", "300초", "93.184.216.34") }); assertTrue(r.rows().any { it == listOf("example.com", "A") })
        // 패킷 전체(UDP)·NXDOMAIN·질문·TCP 길이 접두사
        val full = run("pkt_dns_decode", "h" to hex(raw("udp_dns_response"))); assertEquals(r.kv("ID"), full.kv("ID")); assertTrue(full.rows().any { it.size == 4 && it[3] == "93.184.216.34" })
        val nx = run("pkt_dns_decode", "h" to hex(raw("udp_dns_nxdomain"))); assertEquals("NXDOMAIN", nx.kv("응답 코드")); assertEquals(1, nx.kvLevel("응답 코드")); assertTrue(nx.noteWith("NXDOMAIN")!!.text.contains("그런 이름이 없어요")); assertTrue(nx.noteWith("NODATA") == null)
        val q = run("pkt_dns_decode", "h" to hex(raw("udp_dns_query"))); assertEquals("질문", q.kv("종류")); assertEquals("RD(재귀 요청)", q.kv("플래그")); assertTrue(q.rows().any { it == listOf("example.com", "A") }); assertEquals(0, q.kvLevel("응답 코드"))
        val dnsOnly = PacketDecode.payloadOf(raw("udp_dns_response"), setOf(53))!!; val tcp = run("pkt_dns_decode", "h" to hex(Bx.be16(dnsOnly.size) + dnsOnly)); assertEquals("0x3039", tcp.kv("ID")); assertEquals("1", tcp.kv("개수").substringAfter("답 ").substringBefore(" "))
        val tc = dnsOnly.copyOf().also { it[2] = (it[2].toInt() or 0x02).toByte() }; assertEquals(1, run("pkt_dns_decode", "h" to hex(tc)).noteWith("잘렸어요(TC)")!!.level)
        val servfail = dnsOnly.copyOf().also { it[3] = ((it[3].toInt() and 0xf0) or 2).toByte() }; assertEquals(2, run("pkt_dns_decode", "h" to hex(servfail)).noteWith("SERVFAIL")!!.level)
        val ad = dnsOnly.copyOf().also { it[3] = (it[3].toInt() or 0x20).toByte() }; assertTrue(run("pkt_dns_decode", "h" to hex(ad)).kv("플래그").contains("AD(DNSSEC 검증됨)")); assertTrue(run("pkt_dns_decode", "h" to hex(ad)).noteWith("AD 표시") != null)
        assertTrue(run("pkt_dns_decode", "h" to "01 02 03").hasError); assertTrue(run("pkt_dns_decode", "h" to "zz").hasError); assertFalse(run("pkt_dns_decode", "h" to "").hasError)
    }

    @Test fun toolPktDhcpDecode() {
        val r = run("pkt_dhcp_decode"); assertEquals("OFFER(주소 제안)", r.kv("메시지 종류")); assertEquals("서버 → 클라이언트 (BOOTREPLY)", r.kv("방향")); assertEquals("0x12345678", r.kv("거래 ID(xid)")); assertEquals("192.168.1.50", r.kv("제안·할당된 IP (yiaddr)")); assertEquals("52:54:00:12:34:56", r.kv("클라이언트 MAC")); assertEquals("192.168.1.1", r.kv("다음 서버 (siaddr)"))
        assertTrue(r.rows().any { it[1] == "임대 시간" && it[2] == "86400초 (24시간)" }); assertTrue(r.rows().any { it[1] == "DNS 서버" && it[2] == "192.168.1.1, 8.8.8.8" }); assertTrue(r.rows().any { it[1] == "도메인 이름" && it[2] == "home.lan" })
        assertEquals(-1, r.noteWith("순서가 올바른 값")!!.level); assertTrue(r.noteWith("DNS 서버: 192.168.1.1, 8.8.8.8 (공인 DNS")!!.level == 0); assertTrue(r.noteWith("게이트웨이 192.168.1.1 · DHCP 서버 192.168.1.1")!!.text.contains("게이트웨이")); assertNull(r.noteWith("WPAD"))
        val full = run("pkt_dhcp_decode", "h" to hex(raw("dhcp_offer"))); assertEquals(r.kv("거래 ID(xid)"), full.kv("거래 ID(xid)")); val d = run("pkt_dhcp_decode", "h" to hex(raw("dhcp_discover")))
        assertEquals("DISCOVER(주소 찾기)", d.kv("메시지 종류")); assertEquals("my-phone", d.kv("호스트 이름")); assertEquals("예", d.kv("브로드캐스트로 답해 주세요")); assertTrue(d.rows().any { it[1] == "요청한 옵션 목록" && it[2].contains("DNS 서버") }); assertTrue(d.noteWith("rogue") != null); assertFalse(d.hasKv("제안·할당된 IP (yiaddr)"))
        // WPAD(옵션 252) 는 경고, T1·T2 가 이상하면 오류
        val offer = hexBytes(json("dhcp.json").getJSONObject("dhcp_offer").getString("udp_payload_hex")); val end = offer.indexOfLast { it == 0xff.toByte() }
        val wpad = offer.copyOf(end) + byteArrayOf(252.toByte(), 4) + "x.pa".toByteArray() + byteArrayOf(0xff.toByte()); assertEquals(1, run("pkt_dhcp_decode", "h" to hex(wpad)).noteWith("WPAD")!!.level)
        val t1 = offer.copyOf().also { var p = 240; while (p < it.size && it[p] != 0xff.toByte()) { if (it[p].toInt() == 58) { it[p + 2] = 0xff.toByte() }; p += 2 + (it[p + 1].toInt() and 0xff) } }; assertEquals(2, run("pkt_dhcp_decode", "h" to hex(t1)).noteWith("T1·T2 값의 순서가 이상해요")!!.level)
        assertTrue(run("pkt_dhcp_decode", "h" to hex(ByteArray(300))).hasError); assertTrue(run("pkt_dhcp_decode", "h" to "zz").hasError); assertFalse(run("pkt_dhcp_decode", "h" to "").hasError)
    }

    @Test fun toolPktNtpDecode() {
        val exp = json("ntp.json"); val r = run("pkt_ntp_decode")
        assertEquals("4 (서버(시간 응답))", r.kv("모드")); assertEquals("2 (1단계 위의 서버에서 받음)", r.kv("계층(stratum)")); assertEquals("192.168.1.1 (동기 대상 서버)", r.kv("기준 ID")); assertEquals("2^6 = 64초", r.kv("폴 간격")); assertTrue(r.kv("정밀도").startsWith("2^-23 초")); assertEquals("12.3 ms", r.kv("루트 지연")); assertEquals("34.5 ms", r.kv("루트 분산"))
        assertEquals("2023-11-14T22:13:20.125 UTC", r.kv("T1 원래 보낸 시각(orig)")); assertEquals("없음", r.kv("윤초 표시(LI)")); assertEquals("0.244 ms", r.kv("서버 처리 시간(T3−T2)")); assertFalse(r.hasKv("시계 오차(θ)"))
        // T4 를 주면 오차·지연 계산 (공식을 따로 다시 계산한 값과 대조)
        val t1 = exp.getDouble("t1"); val t2 = exp.getDouble("t2"); val t3 = exp.getDouble("t3"); val t4 = t3 + 0.0050
        val c = run("pkt_ntp_decode", "t4" to "%.6f".format(t4)); val theta = (((t2 - t1) + (t3 - t4)) / 2) * 1000; val delta = ((t4 - t1) - (t3 - t2)) * 1000
        assertEquals("%+.3f ms".format(theta), c.kv("시계 오차(θ)")); assertEquals("%.3f ms".format(delta), c.kv("왕복 지연(δ)")); assertTrue(c.noteWith(if (theta > 0) "느려요" else "빨라요") != null)
        val iso = run("pkt_ntp_decode", "t4" to "2023-11-14T22:13:20.142Z"); assertEquals("%+.3f ms".format(((exp.getDouble("t2") - t1) + (t3 - 1700000000.142)) / 2 * 1000), iso.kv("시계 오차(θ)"))
        assertTrue(run("pkt_ntp_decode", "t4" to "내일").notes().any { it.level == 2 && "T4 형식" in it.text }); assertTrue(run("pkt_ntp_decode", "t4" to "1700000000.0").noteWith("왕복 지연이 음수") != null)
        val gps = run("pkt_ntp_decode", "h" to exp.getString("gps_hex")); assertTrue(gps.kv("계층(stratum)").startsWith("1 (원자시계·GPS")); assertEquals("GPS (기준 시계 종류)", gps.kv("기준 ID"))
        val req = run("pkt_ntp_decode", "h" to hex(PacketBuild.ntpRequest())); assertTrue(req.kv("모드").startsWith("3 (클라이언트")); assertTrue(req.noteWith("클라이언트가 보낸 요청") != null)
        val kod = hexBytes(exp.getString("hex")).also { it[1] = 0; "RATE".toByteArray().copyInto(it, 12) }; val k = run("pkt_ntp_decode", "h" to hex(kod)); assertEquals(2, k.noteWith("계층 0")!!.level); assertTrue(k.kv("기준 ID").startsWith("RATE"))
        val unsynced = hexBytes(exp.getString("hex")).also { it[0] = (it[0].toInt() or 0xc0).toByte(); it[1] = 16 }; val u = run("pkt_ntp_decode", "h" to hex(unsynced)); assertEquals(2, u.kvLevel("윤초 표시(LI)")); assertEquals(2, u.kvLevel("계층(stratum)"))
        val udpFrame = PacketBuild.ether(ByteArray(6), ByteArray(6), 0x0800, PacketBuild.ipv4(byteArrayOf(1, 1, 1, 1), byteArrayOf(2, 2, 2, 2), 17, PacketBuild.udp(byteArrayOf(1, 1, 1, 1), byteArrayOf(2, 2, 2, 2), 123, 40000, hexBytes(exp.getString("hex"))))); assertEquals(r.kv("T3 서버가 보낸 시각"), run("pkt_ntp_decode", "h" to hex(udpFrame)).kv("T3 서버가 보낸 시각"))
        assertTrue(run("pkt_ntp_decode", "h" to "01 02").hasError); assertTrue(run("pkt_ntp_decode", "h" to "zz").hasError)
    }

    @Test fun toolPktBuild() {
        val ref = json("build.json")
        fun build(t: String, vararg kv: Pair<String, String>) = run("pkt_build", "t" to t, *kv)
        val ping = build("ICMP Echo 요청 (ping)", "data" to "abcdefgh", "dip" to "8.8.8.8"); assertEquals(ref.getString("icmp_echo"), ping.kv("IP 패킷(16진수)")); assertEquals("192.168.1.10 → 8.8.8.8 ICMP Echo 요청(ping)", ping.kv("이 패킷을 다시 해석하면")); assertEquals("이더넷 프레임 50바이트 · IP 패킷 36바이트", ping.kv("크기"))
        val udp = build("UDP 데이터", "dip" to "8.8.8.8", "data" to "hex:12340100"); assertEquals(ref.getString("udp"), udp.kv("IP 패킷(16진수)"))
        val syn = build("TCP SYN (연결 시작)", "dip" to "93.184.216.34", "sport" to "54321", "dport" to "443", "seq" to "1000,0"); assertEquals(ref.getString("tcp_syn"), syn.kv("IP 패킷(16진수)"))
        val data = build("TCP 데이터 (PSH+ACK)", "dip" to "93.184.216.34", "sport" to "54321", "dport" to "80", "seq" to "5, 9", "data" to "hello"); assertEquals(ref.getString("tcp_data"), data.kv("IP 패킷(16진수)"))
        val arp = build("ARP 요청 (누가 이 IP 인가?)"); assertEquals(ref.getString("arp_req"), arp.kv("이더넷 프레임(16진수)")); assertFalse(arp.hasKv("IP 패킷(16진수)")); assertEquals("ARP: 누가 192.168.1.1 인가? (192.168.1.10 가 물음)", arp.kv("이 패킷을 다시 해석하면"))
        val reply = build("ARP 응답", "dmac" to "aa:bb:cc:dd:ee:01"); assertEquals("ARP: 192.168.1.10 는 52:54:00:12:34:56", reply.kv("이 패킷을 다시 해석하면"))
        val wol = build("Wake-on-LAN (매직 패킷)", "dmac" to "aa:bb:cc:dd:ee:ff"); val wf = hexBytes(wol.kv("이더넷 프레임(16진수)")); assertEquals(ref.getString("wol"), hex(PacketDecode.payloadOf(wf, setOf(9))!!)); assertEquals("ff:ff:ff:ff:ff:ff", Bx.mac(wf, 0)); assertTrue(wol.kv("이 패킷을 다시 해석하면").contains("255.255.255.255"))
        val ntp = build("NTP 요청", "dip" to "162.159.200.1"); assertTrue(ntp.kv("이 패킷을 다시 해석하면").contains("UDP 40000 → 123")); val rstp = build("TCP RST (연결 끊기)", "dport" to "22"); assertTrue(rstp.kv("이 패킷을 다시 해석하면").contains("[ACK RST]"))
        // 만든 패킷은 해석기로 읽어도 문제 없고, 체크섬은 모두 맞음. 보내지 않는다고 알림
        for (r in listOf(ping, udp, syn, data, arp, reply, wol, ntp, rstp)) { assertTrue(ChecksumFix.analyze(hexBytes(r.kv("이더넷 프레임(16진수)")), "eth").allOk || r.kv("종류").startsWith("ARP")); assertFalse(r.hasError); assertTrue(r.text().contains("Import from Hex Dump")); assertTrue(r.text().contains("전송하는 기능은 없어요")) }
        assertTrue(ping.blocks().contains("000000 ")); assertTrue(ping.blocks().lines().first { it.isNotBlank() }.split(" ").size >= 16)
        // 입력 확인
        assertTrue(build("UDP 데이터", "smac" to "zz").hasError); assertTrue(build("UDP 데이터", "dmac" to "1:2:3").hasError); assertTrue(build("UDP 데이터", "sip" to "300.1.1.1").hasError); assertTrue(build("UDP 데이터", "dip" to "::1").hasError); assertTrue(build("UDP 데이터", "dport" to "70000").hasError)
        assertTrue(build("UDP 데이터", "ttl" to "0").hasError); assertTrue(build("UDP 데이터", "data" to "hex:xyz").hasError); assertTrue(build("UDP 데이터", "data" to "a".repeat(1401)).hasError); assertFalse(build("UDP 데이터", "data" to "").hasError); assertFalse(build("UDP 데이터", "data" to "한글 데이터").hasError)
    }

    @Test fun toolPktBpfAgreesWithLibpcapVerifiedExpressions() {
        val cases = JSONArray(file("bpf.json").readText()); assertTrue(cases.length() >= 20)
        for (k in 0 until cases.length()) {
            val c = cases.getJSONObject(k); val inp = c.getJSONObject("inputs"); val r = run("pkt_bpf", *inp.keys().asSequence().map { it to inp.getString(it) }.toList().toTypedArray())
            assertEquals("입력 $inp", c.getString("expr"), r.kv("캡처 필터 (tcpdump·tshark -f, BPF)")); assertEquals("입력 $inp", c.getString("display"), r.kv("표시 필터 (와이어샤크 화면 위쪽 칸)"))
            assertTrue(r.blocks().contains("sudo tcpdump -i any -nn -s 0 -w capture.pcap '${c.getString("expr")}'")); assertTrue(r.blocks().contains("tshark -i any -f '${c.getString("expr")}'"))
        }
        val r = run("pkt_bpf", "host" to "192.168.1.10", "p" to "TCP", "ports" to "80,443", "f" to "SYN 만 (연결 시작 요청)", "x" to "192.168.1.1")
        assertEquals("tcp and host 192.168.1.10 and (port 80 or port 443) and tcp[tcpflags] & (tcp-syn|tcp-ack) = tcp-syn and not host 192.168.1.1", r.kv("캡처 필터 (tcpdump·tshark -f, BPF)")); assertTrue(r.noteWith("잡는 패킷:")!!.text.contains("연결을 시작하는 SYN"))
        // 입력 확인
        assertTrue(run("pkt_bpf", "host" to "example").hasError); assertTrue(run("pkt_bpf", "net" to "10.0.0.0").hasError); assertTrue(run("pkt_bpf", "net" to "10.0.0.0/33").hasError); assertTrue(run("pkt_bpf", "net" to "2001:db8::/129").hasError); assertTrue(run("pkt_bpf", "net" to "2001:db8::/32").let { !it.hasError })
        assertTrue(run("pkt_bpf", "ports" to "80,abc").hasError); assertTrue(run("pkt_bpf", "ports" to "70000").hasError); assertTrue(run("pkt_bpf", "ports" to "2000-1000").hasError); assertTrue(run("pkt_bpf", "x" to "nope").hasError)
        assertTrue(run("pkt_bpf", "p" to "UDP", "f" to "SYN 만 (연결 시작 요청)").hasError); assertEquals(1, run("pkt_bpf").notes().single().level); assertFalse(run("pkt_bpf").hasError)
    }

    @Test fun everyPacketToolRunsWithItsDefaults() {
        val ids = PktTools.ALL.map { it.id }; assertEquals(listOf("pkt_decode", "pkt_checksum", "pkt_pcap", "pkt_pcap_sites", "pkt_ja3", "pkt_dns_decode", "pkt_dhcp_decode", "pkt_ntp_decode", "pkt_build", "pkt_bpf"), ids)
        for (t in PktTools.ALL) {
            assertEquals(NetGroups.PACKET, t.group); assertEquals(ToolMode.OFFLINE, t.mode); assertTrue(t.note!!.contains("어디로도") || t.note!!.contains("보내지")); assertTrue(t.desc.length > 20)
            val r = runNetTool(t.id, host = hostWith("f" to file("sample.pcap"))); assertTrue(t.id, r.outs.isNotEmpty())
            if (t.id != "pkt_bpf" && t.id != "pkt_pcap") assertFalse("${t.id}\n${r.text()}", r.hasError)       // 예제 캡처에는 일부러 문제 신호를 많이 심어 둠
        }
    }
}
