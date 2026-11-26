package com.selfcheck.app

import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

class NetToolsTest {
    private fun kind(s: String) = IpUtil.classify(requireNotNull(IpUtil.parse(s)) { "해석 실패: $s" })
    private fun v4(s: String) = IpUtil.v4ToLong(IpUtil.parseV4(s)!!)

    @Test fun parsesIpv4AndRejectsLookalikes() {
        assertArrayEquals(byteArrayOf(192.toByte(), 168.toByte(), 0, 1), IpUtil.parseV4("192.168.0.1"))
        assertArrayEquals(byteArrayOf(0, 0, 0, 0), IpUtil.parseV4(" 0.0.0.0 "))
        // 8진수·16진수·줄임 표기, 범위 밖, 군더더기는 모두 거부 (주소를 잘못 읽어 엉뚱한 곳을 검사하지 않도록)
        for (bad in listOf("", "1.2.3", "1.2.3.4.5", "256.1.1.1", "1.2.3.-4", "a.b.c.d", "01.2.3.4", "1.2.3.04", "0x7f.0.0.1", "192.168.0.1/24", "1..3.4", "1.2.3.4 5", "1.2.3.1000", "٣.٣.٣.٣"))
            assertNull(bad, IpUtil.parseV4(bad))
    }

    @Test fun parseNeverDoesDnsLookups() {
        assertNull(IpUtil.parse("example.com")); assertNull(IpUtil.parse("localhost")); assertNull(IpUtil.parse("1.2.3"))
        assertNull(IpUtil.parse("12:34")); assertNull(IpUtil.parse("gggg::1"))
        assertEquals("::1", IpUtil.format(IpUtil.parse("::1")!!))
        assertEquals("::1", IpUtil.format(IpUtil.parse("[::1]")!!))
        assertEquals("2001:db8::1", IpUtil.format(IpUtil.parse("2001:0db8:0000:0000:0000:0000:0000:0001")!!))
        assertEquals("fe80::", IpUtil.format(IpUtil.parse("fe80:0:0:0:0:0:0:0")!!))
        assertEquals("::", IpUtil.format(IpUtil.parse("::")!!))
        assertEquals("1:0:0:2::3", IpUtil.format(IpUtil.parse("1:0:0:2:0:0:0:3")!!)) // 가장 긴 0 구간을 ::
        assertEquals("1:2:3:4:5:6:7:8", IpUtil.format(IpUtil.parse("1:2:3:4:5:6:7:8")!!))
        assertEquals("1:0:3:4:5:6:7:8", IpUtil.format(IpUtil.parse("1:0:3:4:5:6:7:8")!!)) // 0 한 칸은 :: 로 줄이지 않음
        assertEquals("203.0.113.7", IpUtil.format(IpUtil.parse("203.0.113.7")!!))
    }

    @Test fun classifiesAddressKinds() {
        val cases = mapOf(
            "192.168.0.1" to IpKind.PRIVATE, "10.1.2.3" to IpKind.PRIVATE, "172.16.0.1" to IpKind.PRIVATE, "172.31.255.255" to IpKind.PRIVATE,
            "172.15.255.255" to IpKind.PUBLIC, "172.32.0.1" to IpKind.PUBLIC, "192.169.0.1" to IpKind.PUBLIC, "11.0.0.1" to IpKind.PUBLIC,
            "127.0.0.1" to IpKind.LOOPBACK, "127.255.255.254" to IpKind.LOOPBACK,
            "169.254.10.10" to IpKind.LINK_LOCAL,
            "100.64.0.1" to IpKind.CGNAT, "100.127.255.255" to IpKind.CGNAT, "100.128.0.1" to IpKind.PUBLIC, "100.63.255.255" to IpKind.PUBLIC,
            "8.8.8.8" to IpKind.PUBLIC, "1.1.1.1" to IpKind.PUBLIC, "211.234.100.1" to IpKind.PUBLIC,
            "224.0.0.251" to IpKind.MULTICAST, "239.255.255.250" to IpKind.MULTICAST,
            "255.255.255.255" to IpKind.BROADCAST, "0.0.0.0" to IpKind.UNSPECIFIED, "0.1.2.3" to IpKind.RESERVED,
            "240.0.0.1" to IpKind.RESERVED, "192.0.2.5" to IpKind.RESERVED, "198.51.100.7" to IpKind.RESERVED, "203.0.113.9" to IpKind.RESERVED,
            "198.18.0.1" to IpKind.RESERVED, "198.19.255.255" to IpKind.RESERVED, "198.20.0.1" to IpKind.PUBLIC,
            "::1" to IpKind.LOOPBACK, "::" to IpKind.UNSPECIFIED, "fe80::1" to IpKind.LINK_LOCAL, "fd12:3456::1" to IpKind.PRIVATE, "fc00::1" to IpKind.PRIVATE,
            "ff02::1" to IpKind.MULTICAST, "2001:db8::5" to IpKind.RESERVED, "2606:4700:4700::1111" to IpKind.PUBLIC, "2400:cb00::1" to IpKind.PUBLIC,
            "::ffff:192.168.0.5" to IpKind.PRIVATE, "::ffff:8.8.8.8" to IpKind.PUBLIC,
        )
        for ((ip, k) in cases) assertEquals(ip, k, kind(ip))
    }

    @Test fun consentRulesFollowTheKind() {
        for (k in listOf(IpKind.PRIVATE, IpKind.LOOPBACK, IpKind.LINK_LOCAL)) { assertTrue(k.local); assertFalse(k.needsConsent); assertFalse(k.blocked) }
        // 인터넷 주소와 통신사 공용 주소는 "내 장비이거나 허락받았음"을 확인받아야 함
        for (k in listOf(IpKind.PUBLIC, IpKind.CGNAT)) { assertTrue(k.needsConsent); assertFalse(k.blocked) }
        for (k in listOf(IpKind.MULTICAST, IpKind.BROADCAST, IpKind.UNSPECIFIED, IpKind.RESERVED)) { assertTrue(k.blocked); assertFalse(k.needsConsent) }
        assertTrue(IpKind.values().all { it.label.isNotBlank() && it.note.isNotBlank() })
    }

    @Test fun v4Forms() {
        val f = IpUtil.v4Forms(v4("192.168.0.1")).toMap()
        assertEquals("3232235521", f["십진수"]); assertEquals("0xC0A80001", f["16진수"])
        assertEquals("11000000.10101000.00000000.00000001", f["2진수"]); assertEquals("1.0.168.192.in-addr.arpa", f["역방향 조회 이름"])
    }

    @Test fun subnetMath() {
        val s = Subnet.parse("192.168.0.77/24")!!
        assertEquals("192.168.0.0", IpUtil.v4Text(s.network)); assertEquals("255.255.255.0", IpUtil.v4Text(s.mask)); assertEquals("0.0.0.255", IpUtil.v4Text(s.wildcard))
        assertEquals("192.168.0.255", IpUtil.v4Text(s.broadcast)); assertEquals("192.168.0.1", IpUtil.v4Text(s.first)); assertEquals("192.168.0.254", IpUtil.v4Text(s.last))
        assertEquals(254L, s.hostCount)

        val t = Subnet.parse("10.1.2.3/255.255.0.0")!!
        assertEquals(16, t.prefix); assertEquals("10.1.0.0", IpUtil.v4Text(t.network)); assertEquals(65534L, t.hostCount)

        val q = Subnet.parse("192.168.1.5/30")!!
        assertEquals("192.168.1.4", IpUtil.v4Text(q.network)); assertEquals("192.168.1.5", IpUtil.v4Text(q.first)); assertEquals("192.168.1.6", IpUtil.v4Text(q.last))
        assertEquals("192.168.1.7", IpUtil.v4Text(q.broadcast)); assertEquals(2L, q.hostCount)

        val p2p = Subnet.parse("10.0.0.1/31")!!
        assertEquals(2L, p2p.hostCount); assertEquals("10.0.0.0", IpUtil.v4Text(p2p.first)); assertEquals("10.0.0.1", IpUtil.v4Text(p2p.last))
        val one = Subnet.parse("10.0.0.1/32")!!
        assertEquals(1L, one.hostCount); assertEquals(one.first, one.last)
        val all = Subnet.parse("1.2.3.4/0")!!
        assertEquals("0.0.0.0", IpUtil.v4Text(all.network)); assertEquals(4294967294L, all.hostCount); assertEquals("0.0.0.0", IpUtil.v4Text(all.mask))

        for (bad in listOf("1.2.3.4", "1.2.3.4/33", "1.2.3.4/-1", "1.2.3.4/255.0.255.0", "1.2.3.4/abc", "x/24", "1.2.3.4/", "1.2.3/24", "1.2.3.4/255.255.255.256"))
            assertNull(bad, Subnet.parse(bad))
    }

    @Test fun lanRangeStaysSmall() {
        val (s, trimmed) = Lan.range(v4("192.168.0.12"), 24)
        assertFalse(trimmed); assertEquals(254, Lan.addresses(s).size); assertEquals("192.168.0.1", IpUtil.v4Text(Lan.addresses(s).first()))
        // 큰 망(/16)은 내 주소가 속한 /24 만, 줄였다고 알림
        val (big, t2) = Lan.range(v4("10.20.30.40"), 16)
        assertTrue(t2); assertEquals("10.20.30.0", IpUtil.v4Text(big.network)); assertEquals(254, Lan.addresses(big).size)
        val (small, t3) = Lan.range(v4("192.168.0.12"), 26)
        assertFalse(t3); assertEquals(62, Lan.addresses(small).size)
        assertEquals(24, Lan.range(v4("192.168.0.12"), 32).first.prefix) // 이상한 값은 /24
    }

    @Test fun arpTableParsing() {
        val text = """
            IP address       HW type     Flags       HW address            Mask     Device
            192.168.0.1      0x1         0x2         A4:2B:B0:11:22:33     *        wlan0
            192.168.0.20     0x1         0x0         00:00:00:00:00:00     *        wlan0
            192.168.0.31     0x1         0x2         da:a1:19:00:11:22     *        wlan0
            garbage line
        """.trimIndent()
        val e = Arp.parse(text)
        assertEquals(listOf("192.168.0.1", "192.168.0.31"), e.map { it.ip })
        assertEquals("a4:2b:b0:11:22:33", e[0].mac); assertEquals("wlan0", e[0].device)
        assertFalse(Arp.isRandomMac(e[0].mac)); assertTrue(Arp.isRandomMac(e[1].mac)) // 두 번째는 임의(랜덤) MAC
        assertTrue(Arp.parse("").isEmpty())
    }

    @Test fun hostInputPicksTheHostPart() {
        assertEquals("Example.com", HostInput.host("https://user:pw@Example.com:8443/a/b?q=1#x"))
        assertEquals("192.168.0.1", HostInput.host(" 192.168.0.1:8080 "))
        assertEquals("2001:db8::1", HostInput.host("[2001:db8::1]:443"))
        assertEquals("2001:db8::1", HostInput.host("2001:db8::1"))
        assertEquals("example.com", HostInput.host("example.com."))
        assertEquals("example.com", HostInput.host("example.com/path"))
        for (ok in listOf("example.com", "localhost", "예시.한국", "a-b.c_d.example.co.kr")) assertTrue(ok, HostInput.isPlausibleDomain(ok))
        for (bad in listOf("", "192.168.1", "123", "a b.com", "exa\$mple.com", "-a.com", "a-.com", "a..com", "x".repeat(64), "http://x.com")) assertFalse(bad, HostInput.isPlausibleDomain(bad))
    }

    @Test fun portSpecParsing() {
        assertEquals(listOf(22, 80, 443, 8000, 8001, 8002), Ports.parse("443, 22 80;8000-8002 80", 100).ports)
        val well = Ports.parse("1-1024", Ports.MAX_REMOTE)
        assertNull(well.error); assertEquals(1024, well.ports.size)
        assertEquals(65535, Ports.parse("1-65535", Ports.MAX_ALL).ports.size)
        for (bad in listOf("", "  ", "abc", "0", "65536", "100-50", "1-70000", "22-", "-22", "22,x", "1-3000"))
            assertNotNull(bad, Ports.parse(bad, Ports.MAX_REMOTE).error)
        assertNotNull(Ports.parse("22,23", 1).error) // 한 번에 허용하는 수를 넘음
        assertNotNull(Ports.parse("1-65535", Ports.MAX_REMOTE).error) // 내 망 밖 주소는 전체 포트 검사 불가
        assertTrue(Ports.parse("abc", 10).ports.isEmpty())
    }

    @Test fun describedPortsAreConsistent() {
        assertTrue(Ports.QUICK.size >= 60)
        assertEquals(Ports.QUICK, Ports.QUICK.sorted())
        for ((p, i) in Ports.SERVICES) {
            assertTrue("포트 $p", p in 1..65535); assertTrue(i.name.isNotBlank()); assertTrue(i.risk in 0..2)
            if (i.risk >= 1) assertTrue("포트 $p 는 위험·주의인데 설명이 없음", i.advice.isNotBlank())
        }
        assertTrue(Ports.HTTP.intersect(Ports.TLS).isEmpty())
        assertEquals(2, Ports.describe(23)!!.risk); assertEquals(2, Ports.describe(3389)!!.risk); assertEquals(0, Ports.describe(443)!!.risk)
        assertNull(Ports.describe(54321))
    }
}
