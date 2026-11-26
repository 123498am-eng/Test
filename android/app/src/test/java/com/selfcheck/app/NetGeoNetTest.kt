package com.selfcheck.app

import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Test
import java.io.IOException
import java.net.DatagramPacket
import java.net.InetAddress
import java.net.InetSocketAddress
import java.nio.ByteBuffer

/*
 * IP 위치·IP 찾기 엔진 시험: 좌표 계산(파이썬 정답), 제공처 응답 해석·다수결, STUN(RFC 5769 형식), UPnP WAN IP, mDNS(파이썬으로 만든 패킷),
 * DNSBL, RDAP, 이메일 헤더 — 그리고 그 위에 만든 도구들을 가짜 서버·가짜 응답으로 끝까지.
 * 실제 인터넷의 위치 제공처와는 연결하지 않았어요: 제공처 응답 모양은 공개 문서에 나온 형식을 바탕으로 직접 적은 샘플이에요.
 */
class NetGeoNetTest {
    @After fun reset() {
        GeoNet.fetcher = null
        GeoTools.stunServers = listOf("stun.l.google.com" to 19302, "stun1.l.google.com" to 19302, "stun.cloudflare.com" to 3478)
        GeoTools.publicResolvers = listOf("8.8.8.8" to "구글", "1.1.1.1" to "클라우드플레어", "9.9.9.9" to "Quad9", "208.67.222.222" to "OpenDNS")
        GeoTools.myIpDnsServers = "208.67.222.222" to "216.239.32.10"
        GeoTools.ssdpTarget = InetSocketAddress("239.255.255.250", 1900); GeoTools.mdnsTarget = Mdns.GROUP
        GeoTools.ssdpWaitMs = 4000; GeoTools.mdnsWaitMs = 3000
    }

    @org.junit.Before fun fast() { GeoTools.ssdpWaitMs = 500; GeoTools.mdnsWaitMs = 500 }

    private fun hex(s: String) = ByteArray(s.length / 2) { s.substring(it * 2, it * 2 + 2).toInt(16).toByte() }
    private fun text(r: ToolResult) = r.text()

    // ================================================================ 좌표
    @Test fun geoMath_matchesPython() {
        assertEquals(1149.3589233998575, Geo.distanceKm(37.5665, 126.9780, 35.6762, 139.6503), 0.001)
        assertEquals(11052.592094422282, Geo.distanceKm(37.5665, 126.9780, 40.7128, -74.0060), 0.01)
        assertEquals(0.0, Geo.distanceKm(37.5665, 126.9780, 37.5665, 126.9780), 1e-9)
        assertEquals(96.6960907678685, Geo.bearing(37.5665, 126.9780, 35.6762, 139.6503), 0.001)
        val m = Geo.midpoint(37.5665, 126.9780, 35.6762, 139.6503); assertEquals(36.789549757337994, m.first, 1e-6); assertEquals(133.39215985448777, m.second, 1e-6)
        assertEquals("37°33′59.4″N", Geo.dms(37.5665, 'N', 'S')); assertEquals("126°58′40.8″E", Geo.dms(126.9780, 'E', 'W')); assertEquals("0°00′00.0″N", Geo.dms(0.0, 'N', 'S'))
        assertEquals("60°00′00.0″S", Geo.dms(-59.99999, 'N', 'S'))                          // 59.9999… → 60 으로 올림 (60.0 초가 나오지 않음)
        assertEquals("동", Geo.compass(90.0)); assertEquals("북", Geo.compass(359.0)); assertEquals("남서", Geo.compass(225.0))
        assertEquals(11.5, Geo.minRttMs(1149.0), 0.1)
    }

    @Test fun parseCoord_formats() {
        fun eq(a: Double, b: Double, p: Pair<Double, Double>?) { assertNotNull(p); assertEquals(a, p!!.first, 1e-3); assertEquals(b, p.second, 1e-3) }
        eq(37.5665, 126.978, Geo.parseCoord("37.5665, 126.9780")); eq(-33.8688, 151.2093, Geo.parseCoord("-33.8688 151.2093")); eq(37.5665, 126.978, Geo.parseCoord("37.5665;126.978"))
        eq(37.5665, 126.978, Geo.parseCoord("37°33′59.4″N 126°58′40.8″E")); eq(37.5665, 126.978, Geo.parseCoord("37°33'59.4\"N, 126°58'40.8\"E"))
        eq(37.5665, 126.978, Geo.parseCoord("N37 33.99 E126 58.68")); eq(-33.8688, 151.2093, Geo.parseCoord("33°52'7.68\"S 151°12'33.48\"E")); eq(37.5665, -122.0, Geo.parseCoord("37.5665N 122W"))
        eq(37.5665, 126.978, Geo.parseCoord("E126.978 N37.5665"))                                // 경도를 먼저 써도 방향 글자로 구별
        assertNull(Geo.parseCoord("")); assertNull(Geo.parseCoord("91, 10")); assertNull(Geo.parseCoord("10, 181")); assertNull(Geo.parseCoord("1 2 3 4 5 6 7")); assertNull(Geo.parseCoord("서울"))
        assertEquals("geo:37.56650,126.97800", Geo.mapLinks(37.5665, 126.978).last().second); assertTrue(Geo.mapLinks(37.5665, 126.978).any { it.second.startsWith("https://www.openstreetmap.org/") })
    }

    // ================================================================ 제공처 응답 해석
    private val J_IPWHO = """{"ip":"168.126.63.1","success":true,"type":"IPv4","continent":"Asia","country":"South Korea","country_code":"KR","region":"Seoul","region_code":"11","city":"Seoul","latitude":37.5665,"longitude":126.978,"postal":"04524","connection":{"asn":4766,"org":"Korea Telecom","isp":"Korea Telecom","domain":"kt.com"},"timezone":{"id":"Asia/Seoul","abbr":"KST","offset":32400,"utc":"+09:00"}}"""
    private val J_IPAPI = """{"ip":"168.126.63.1","version":"IPv4","city":"Seoul","region":"Seoul","region_code":"11","country":"KR","country_name":"South Korea","country_code":"KR","latitude":37.5665,"longitude":126.978,"timezone":"Asia/Seoul","org":"KT Corporation","asn":"AS4766"}"""
    private val J_IPINFO = """{"ip":"168.126.63.1","hostname":"kns.kornet.net","city":"Seoul","region":"Seoul","country":"KR","loc":"37.5660,126.9784","org":"AS4766 Korea Telecom","postal":"03141","timezone":"Asia/Seoul"}"""
    private val J_GUIDE = """{"ip":"168.126.63.1","network":{"cidr":"168.126.0.0/16","autonomous_system":{"asn":4766,"name":"KIXS-AS-KR","organization":"Korea Telecom","country":"KR","rir":"APNIC"}},"location":{"city":"Seoul","country":"South Korea","timezone":"Asia/Seoul","latitude":37.5660,"longitude":126.9784}}"""
    private val J_IPAPIS = """{"ip":"168.126.63.1","rir":"APNIC","is_bogon":false,"is_mobile":false,"is_datacenter":false,"is_tor":false,"is_proxy":false,"is_vpn":true,"is_abuser":false,"company":{"name":"Korea Telecom","type":"isp"},"asn":{"asn":4766,"org":"Korea Telecom"},"location":{"country":"South Korea","country_code":"KR","state":"Seoul","city":"Seoul","latitude":37.566,"longitude":126.9784,"timezone":"Asia/Seoul"}}"""
    private val J_GEOJS = """{"organization_name":"KIXS-AS-KR Korea Telecom","country_code":"KR","ip":"168.126.63.1","region":"Seoul","latitude":"37.5660","longitude":"126.9784","accuracy":5,"timezone":"Asia/Seoul","city":"Seoul","asn":4766,"country":"South Korea"}"""
    private val J_IPAPICOM = """{"status":"success","country":"South Korea","countryCode":"KR","regionName":"Seoul","city":"Seoul","lat":37.5663,"lon":126.9779,"timezone":"Asia/Seoul","isp":"Korea Telecom","org":"Korea Telecom","as":"AS4766 Korea Telecom","mobile":false,"proxy":false,"hosting":true,"query":"168.126.63.1"}"""

    @Test fun providerParsers_extractFields() {
        val r = GeoProviders.IPWHO.parse(J_IPWHO); assertTrue(r.ok); assertEquals("KR", r.countryCode); assertEquals("Seoul", r.city); assertEquals(37.5665, r.lat!!, 1e-6); assertEquals("Korea Telecom", r.org); assertEquals("AS4766", r.asn); assertEquals("Asia/Seoul", r.timezone)
        GeoProviders.IPAPI_CO.parse(J_IPAPI).let { assertEquals("KR", it.countryCode); assertEquals("AS4766", it.asn); assertEquals("KT Corporation", it.org); assertEquals("South Korea", it.country) }
        GeoProviders.IPINFO.parse(J_IPINFO).let { assertEquals("KR", it.countryCode); assertEquals(37.566, it.lat!!, 1e-6); assertEquals(126.9784, it.lon!!, 1e-6); assertEquals("Korea Telecom", it.org); assertEquals("AS4766", it.asn) }
        GeoProviders.IPGUIDE.parse(J_GUIDE).let { assertEquals("South Korea", it.country); assertNull(it.countryCode); assertEquals("AS4766", it.asn); assertEquals("Korea Telecom", it.org); assertEquals("Seoul", it.city) }
        GeoProviders.IPAPI_IS.parse(J_IPAPIS).let { assertEquals(true, it.vpn); assertEquals(false, it.proxy); assertEquals("KR", it.countryCode); assertEquals("Seoul", it.region); assertEquals("Korea Telecom", it.org) }
        GeoProviders.GEOJS.parse(J_GEOJS).let { assertEquals(37.566, it.lat!!, 1e-6); assertEquals("AS4766", it.asn); assertEquals("KIXS-AS-KR Korea Telecom", it.org) }
        GeoProviders.IPAPI_COM.parse(J_IPAPICOM).let { assertEquals(true, it.hosting); assertEquals(false, it.proxy); assertEquals("AS4766", it.asn); assertEquals("Seoul", it.city) }
        assertFalse(GeoProviders.IPAPI_COM.https); assertTrue(GeoProviders.DEFAULT.all { it.https })
    }

    @Test fun providerParsers_errorsAndNulls() {
        assertEquals("Invalid IP address", GeoProviders.IPWHO.parse("""{"success":false,"message":"Invalid IP address"}""").error)
        assertEquals("RateLimited", GeoProviders.IPAPI_CO.parse("""{"error":true,"reason":"RateLimited","message":"x"}""").error)
        assertEquals("사설·예약 주소예요", GeoProviders.IPINFO.parse("""{"ip":"192.168.0.1","bogon":true}""").error)
        assertEquals("fail", GeoProviders.IPAPI_COM.parse("""{"status":"fail","message":"fail","query":"x"}""").error ?: "fail")
        assertTrue(GeoProviders.IPAPI_IS.parse("""{"ip":"10.0.0.1","is_bogon":true}""").error!!.contains("사설"))
        val sparse = GeoProviders.IPWHO.parse("""{"ip":"1.2.3.4","success":true,"country_code":"US","city":null,"latitude":null,"connection":{}}""")
        assertTrue(sparse.ok); assertNull(sparse.city); assertNull(sparse.lat); assertEquals("US", sparse.place)
        assertEquals("http://ip-api.com/json/1.2.3.4?fields=status,message,country,countryCode,regionName,city,lat,lon,timezone,isp,org,as,mobile,proxy,hosting,query".substringBefore('?'), GeoProviders.IPAPI_COM.urlFor("1.2.3.4").substringBefore('?'))
        assertEquals("https://ipwho.is/", GeoProviders.IPWHO.urlFor("")); assertEquals("https://ipapi.co/json/", GeoProviders.IPAPI_CO.urlFor("")); assertEquals("https://ipapi.co/8.8.8.8/json/", GeoProviders.IPAPI_CO.urlFor("8.8.8.8"))
    }

    @Test fun consensus_levels() {
        val all = listOf(GeoProviders.IPWHO.parse(J_IPWHO), GeoProviders.IPAPI_CO.parse(J_IPAPI), GeoProviders.IPINFO.parse(J_IPINFO), GeoProviders.IPGUIDE.parse(J_GUIDE), GeoProviders.IPAPI_IS.parse(J_IPAPIS))
        val c = GeoMerge.merge(all)!!
        assertEquals("KR", c.countryCode); assertEquals("Seoul", c.city); assertEquals(5, c.agree); assertEquals(5, c.total); assertEquals(-1, c.level); assertTrue(c.spreadKm!! < 5)
        assertEquals("Asia/Seoul", c.timezone); assertEquals(37.566, c.lat!!, 0.01)
        // 한 곳이 다른 나라
        val us = GeoResult("x", countryCode = "US", country = "United States", city = "Ashburn", lat = 39.04, lon = -77.49)
        GeoMerge.merge(all + us)!!.let { assertEquals("KR", it.countryCode); assertEquals(5, it.agree); assertEquals(6, it.total); assertEquals(0, it.level) }
        // 나라는 같은데 도시·좌표가 멀리 떨어짐
        val busan = GeoResult("y", countryCode = "KR", country = "South Korea", city = "Busan", lat = 35.18, lon = 129.07)
        GeoMerge.merge(listOf(all[0], busan))!!.let { assertEquals(2, it.agree); assertTrue(it.spreadKm!! > 300); assertEquals(1, it.level) }
        // 한 곳뿐, 모두 실패
        assertEquals(1, GeoMerge.merge(listOf(all[0]))!!.level)
        assertNull(GeoMerge.merge(listOf(GeoResult("e", error = "실패"), GeoResult("f", error = "실패"))))
        assertNull(GeoMerge.merge(emptyList()))
    }

    // ================================================================ 내려받기
    @Test fun geoNetGet_followsRedirectsAndReportsStatus() {
        TestHttp { req, out ->
            when (req.path) {
                "/a" -> out.respond("302 Found", "Location: /b")
                "/b" -> out.respond("200 OK", "Content-Type: application/json", body = """{"ok":1}""".toByteArray())
                "/boom" -> out.respond("503 Service Unavailable")
                else -> out.respond("404 Not Found")
            }
        }.use { srv ->
            assertEquals("""{"ok":1}""", GeoNet.get(srv.url("/a")))
            try { GeoNet.get(srv.url("/boom")); fail() } catch (e: IOException) { assertTrue(e.message!!, e.message!!.contains("503")) }
            assertTrue(srv.requests.first().headers["accept"]!!.contains("json"))
        }
        // lookup 은 실패를 예외 대신 결과로
        GeoNet.fetcher = { throw IOException("접속 실패") }
        assertEquals("접속 실패", GeoNet.lookup(GeoProviders.IPWHO, "8.8.8.8").error)
        GeoNet.fetcher = { "이건 JSON 이 아님" }
        assertEquals("응답을 읽지 못했어요", GeoNet.lookup(GeoProviders.IPWHO, "8.8.8.8").error)
    }

    // ================================================================ STUN
    private val STUN_TX = hex("b7e7a701bc34d686fa87dfae")
    private val STUN4 = "010100242112a442b7e7a701bc34d686fa87dfae8022000b7465737420766563746f7200002000080001a147e112a64380280004c07d4c96"
    private val STUN6 = "010100302112a442b7e7a701bc34d686fa87dfae8022000b7465737420766563746f7200002000140002a1470113a9faa5d3f179bc25f4b5bed2b9d980280004c07d4c96"
    private val STUN_PLAIN = "0101000c2112a442b7e7a701bc34d686fa87dfae0001000800013039cb007109"

    @Test fun stun_parsesRfcStyleResponses() {
        assertEquals("000100002112a442b7e7a701bc34d686fa87dfae", Stun.request(STUN_TX).joinToString("") { "%02x".format(it) })
        Stun.parse(hex(STUN4), hex(STUN4).size, STUN_TX)!!.let { assertEquals("192.0.2.1", IpUtil.format(it.first)); assertEquals(32853, it.second) }
        Stun.parse(hex(STUN6), hex(STUN6).size, STUN_TX)!!.let { assertEquals("2001:db8:1234:5678:11:2233:4455:6677", IpUtil.format(it.first)); assertEquals(32853, it.second) }
        Stun.parse(hex(STUN_PLAIN), hex(STUN_PLAIN).size, STUN_TX)!!.let { assertEquals("203.0.113.9", IpUtil.format(it.first)); assertEquals(12345, it.second) }       // 옛 MAPPED-ADDRESS
        assertNull("다른 요청의 응답", Stun.parse(hex(STUN4), hex(STUN4).size, ByteArray(12))); assertNull(Stun.parse(hex(STUN4), 10, STUN_TX))
        assertNull(Stun.parse(hex(STUN4).also { it[0] = 0x01; it[1] = 0x11 }, hex(STUN4).size, STUN_TX))               // 오류 응답 종류
    }

    /** 보낸 사람 주소를 XOR-MAPPED-ADDRESS 로 되돌려 주는 가짜 STUN 서버 (mappedPort 가 있으면 그 포트로) */
    private fun fakeStun(mappedPort: Int? = null, mappedIp: String? = null) = TestUdp { p, sock ->
        val req = p.data.copyOf(p.length); val tx = req.copyOfRange(8, 20)
        val ip = (mappedIp?.let { InetAddress.getByName(it) } ?: p.address).address; val port = mappedPort ?: p.port
        val cookie = 0x2112A442
        val attr = ByteBuffer.allocate(8).apply { put(0); put(1); putShort((port xor (cookie ushr 16)).toShort()); putInt(java.nio.ByteBuffer.wrap(ip).int xor cookie) }.array()
        val body = ByteBuffer.allocate(4 + 8).apply { putShort(0x0020); putShort(8); put(attr) }.array()
        val resp = ByteBuffer.allocate(20 + body.size).apply { putShort(0x0101); putShort(body.size.toShort()); putInt(cookie); put(tx); put(body) }.array()
        sock.send(DatagramPacket(resp, resp.size, p.socketAddress))
    }

    @Test fun stun_queryAndTool() {
        fakeStun().use { s ->
            val r = Stun.query("127.0.0.1", s.port, 1500)
            assertEquals("127.0.0.1", IpUtil.format(r.first)); assertTrue(r.second in 1024..65535); assertEquals(20, s.received.single().size)
        }
        // 서버가 달라도 같은 포트 → 엔드포인트 독립 매핑
        fakeStun(40000, "203.0.113.9").use { a -> fakeStun(40000, "203.0.113.9").use { b ->
            GeoTools.stunServers = listOf("127.0.0.1" to a.port, "127.0.0.1" to b.port)
            val t = text(runNetTool("geo_my_ip_stun")); assertTrue(t, t.contains("203.0.113.9") && t.contains("서버가 달라도 같은 포트 (40000)") && t.contains("P2P"))
        } }
        // 서버마다 다른 포트 → 대칭 NAT 가능성
        fakeStun(40001, "203.0.113.9").use { a -> fakeStun(50002, "203.0.113.9").use { b ->
            GeoTools.stunServers = listOf("127.0.0.1" to a.port, "127.0.0.1" to b.port)
            val t = text(runNetTool("geo_my_ip_stun")); assertTrue(t, t.contains("서버마다 다른 포트 (40001, 50002)") && t.contains("대칭 NAT"))
        } }
        // 응답 없음
        TestUdp().use { silent -> GeoTools.stunServers = listOf("127.0.0.1" to silent.port); assertTrue(runNetTool("geo_my_ip_stun").hasError) }
    }

    // ================================================================ UPnP 공유기 WAN IP
    private val IGD_XML = """<?xml version="1.0"?><root xmlns="urn:schemas-upnp-org:device-1-0"><URLBase>@BASE@</URLBase><device><deviceType>urn:schemas-upnp-org:device:InternetGatewayDevice:1</deviceType><friendlyName>Router</friendlyName>
        <deviceList><device><deviceType>urn:schemas-upnp-org:device:WANDevice:1</deviceType><deviceList><device><deviceType>urn:schemas-upnp-org:device:WANConnectionDevice:1</deviceType><serviceList>
        <service><serviceType>urn:schemas-upnp-org:service:WANCommonInterfaceConfig:1</serviceType><controlURL>/ctl/CmnIfCfg</controlURL></service>
        <service><serviceType>urn:schemas-upnp-org:service:WANIPConnection:1</serviceType><serviceId>urn:upnp-org:serviceId:WANIPConn1</serviceId><controlURL>/ctl/IPConn</controlURL><eventSubURL>/evt/IPConn</eventSubURL></service>
        </serviceList></device></deviceList></device></deviceList></device></root>"""

    @Test fun igd_parsesDescriptionAndSoap() {
        val svc = Igd.parseDescription(IGD_XML.replace("@BASE@", "http://192.168.0.1:5000/"), "http://192.168.0.1:5000/rootDesc.xml")
        assertEquals(1, svc.size); assertEquals("urn:schemas-upnp-org:service:WANIPConnection:1", svc[0].type); assertEquals("http://192.168.0.1:5000/ctl/IPConn", svc[0].controlUrl)
        // URLBase 가 없으면 장치 설명 주소를 기준으로
        assertEquals("http://192.168.0.1:49152/ctl/IPConn", Igd.parseDescription(IGD_XML.replace("<URLBase>@BASE@</URLBase>", ""), "http://192.168.0.1:49152/desc.xml")[0].controlUrl)
        assertEquals("203.0.113.7", Igd.parseExternalIp("<s:Envelope><s:Body><u:GetExternalIPAddressResponse><NewExternalIPAddress>203.0.113.7</NewExternalIPAddress></u:GetExternalIPAddressResponse></s:Body></s:Envelope>"))
        assertNull(Igd.parseExternalIp("<x/>")); assertNull(Igd.parseExternalIp("<NewExternalIPAddress></NewExternalIPAddress>"))
        assertTrue(String(Igd.soapBody("urn:schemas-upnp-org:service:WANIPConnection:1", "GetExternalIPAddress")).contains("<u:GetExternalIPAddress xmlns:u=\"urn:schemas-upnp-org:service:WANIPConnection:1\"/>"))
    }

    private fun withFakeRouter(wan: String, publicIp: String?, body: (TestHttp) -> Unit) {
        lateinit var http: TestHttp
        http = TestHttp { req, out ->
            when {
                req.path == "/rootDesc.xml" -> out.respond("200 OK", "Content-Type: text/xml", body = IGD_XML.replace("@BASE@", "http://127.0.0.1:${http.port}/").toByteArray())
                req.path == "/ctl/IPConn" && req.method == "POST" -> out.respond("200 OK", "Content-Type: text/xml", body = "<s:Envelope><s:Body><u:GetExternalIPAddressResponse><NewExternalIPAddress>$wan</NewExternalIPAddress></u:GetExternalIPAddressResponse></s:Body></s:Envelope>".toByteArray())
                else -> out.respond("404 Not Found")
            }
        }
        http.use { h ->
            TestUdp { p, sock -> val d = "HTTP/1.1 200 OK\r\nST: urn:schemas-upnp-org:device:InternetGatewayDevice:1\r\nUSN: uuid:router::urn:schemas-upnp-org:device:InternetGatewayDevice:1\r\nLOCATION: http://127.0.0.1:${h.port}/rootDesc.xml\r\nSERVER: Linux UPnP/1.1\r\n\r\n".toByteArray(); sock.send(DatagramPacket(d, d.size, p.socketAddress)) }.use { ssdp ->
                GeoTools.ssdpTarget = InetSocketAddress(LOOP, ssdp.port)
                GeoNet.fetcher = { url -> if (url.contains("ipify") && publicIp != null) publicIp else throw IOException("접속 실패") }
                body(h)
            }
        }
    }

    @Test fun upnpWanTool_detectsDoubleNatAndCgnat() {
        withFakeRouter("203.0.113.7", "203.0.113.7") { h ->
            val t = text(runNetTool("geo_upnp_wan")); assertTrue(t, t.contains("공유기가 받은 WAN IP: 203.0.113.7") && t.contains("공인 IP 를 직접 받고 있어요"))
            val post = h.requests.first { it.method == "POST" }
            assertTrue(post.headers["soapaction"]!!.contains("WANIPConnection:1#GetExternalIPAddress")); assertTrue(post.bodyText.contains("GetExternalIPAddress")); assertTrue(post.headers["content-type"]!!.startsWith("text/xml"))
        }
        withFakeRouter("192.168.1.2", "203.0.113.7") { _ -> assertTrue(text(runNetTool("geo_upnp_wan")).contains("이중 NAT")); assertTrue(runNetTool("geo_upnp_wan").hasError) }
        withFakeRouter("100.64.12.34", "203.0.113.7") { _ -> assertTrue(text(runNetTool("geo_upnp_wan")).contains("CGNAT")) }
        withFakeRouter("203.0.113.7", "198.51.100.9") { _ -> assertTrue(text(runNetTool("geo_upnp_wan")).contains("달라요")) }
        // 공유기를 못 찾음
        GeoTools.ssdpTarget = InetSocketAddress(LOOP, TestUdp().use { it.port })
        assertTrue(text(runNetTool("geo_upnp_wan")).contains("찾지 못했어요"))
    }

    // ================================================================ mDNS
    private val MDNS_PKT = "000084000000000200000004095f7365727669636573075f646e732d7364045f756470056c6f63616c00000c0001000011940015085f616972706c6179045f746370056c6f63616c00085f616972706c6179045f746370056c6f63616c00000c00010000119400240e4c6976696e6720526f6f6d205456085f616972706c6179045f746370056c6f63616c000e4c6976696e6720526f6f6d205456085f616972706c6179045f746370056c6f63616c000021800100000078001c000000001b580e4c6976696e672d526f6f6d2d5456056c6f63616c000e4c6976696e6720526f6f6d205456085f616972706c6179045f746370056c6f63616c0000108001000011940011106d6f64656c3d4170706c655456362c320e4c6976696e672d526f6f6d2d5456056c6f63616c0000018001000000780004c0a800140e4c6976696e672d526f6f6d2d5456056c6f63616c00001c8001000000780010fe800000000000000000000000001234"

    @Test fun mdns_parsesPythonPacket() {
        val m = DnsWire.parse(hex(MDNS_PKT))!!
        assertTrue(m.isResponse); assertEquals(2, m.answers.size); assertEquals(4, m.additional.size)
        assertEquals(listOf("_airplay._tcp.local"), Mdns.serviceTypes(listOf(m)))
        val inst = Mdns.instances(listOf(m)); assertEquals(1, inst.size)
        inst[0].let { assertEquals("Living Room TV", it.name); assertEquals("_airplay._tcp", it.service); assertEquals(7000, it.port); assertEquals("Living-Room-TV.local", it.host); assertEquals(listOf("192.168.0.20", "fe80::1234"), it.ips); assertTrue(it.txt[0].contains("model=AppleTV6,2")) }
        // 질문 패킷: ID·플래그·QU 비트
        val q = Mdns.buildQuery(7, "_http._tcp.local", DnsType.PTR)!!
        assertEquals(7, ((q[0].toInt() and 0xff) shl 8) or (q[1].toInt() and 0xff)); assertEquals(0, q[2].toInt()); assertEquals(0x80, q[q.size - 2].toInt() and 0xff); assertEquals(1, q[q.size - 1].toInt())
    }

    @Test fun mdnsTools_endToEnd() {
        TestUdp { p, sock -> val d = hex(MDNS_PKT); sock.send(DatagramPacket(d, d.size, p.socketAddress)) }.use { srv ->
            GeoTools.mdnsTarget = InetSocketAddress(LOOP, srv.port)
            val t = text(runNetTool("geo_mdns")); assertTrue(t, t.contains("Living Room TV") && t.contains("airplay") && t.contains("192.168.0.20:7000") && t.contains("_airplay._tcp.local"))
            val r = text(runNetTool("geo_mdns_resolve", "n" to "living-room-tv")); assertTrue(r, r.contains("192.168.0.20") && r.contains("fe80::1234") && r.contains("living-room-tv.local"))
        }
    }

    @Test fun mdnsResolve_ignoresOtherNames() {
        TestUdp { p, sock -> val d = hex(MDNS_PKT); sock.send(DatagramPacket(d, d.size, p.socketAddress)) }.use { srv ->
            GeoTools.mdnsTarget = InetSocketAddress(LOOP, srv.port)
            assertTrue(text(runNetTool("geo_mdns_resolve", "n" to "someone-else.local")).contains("응답이 없어요"))
        }
        TestUdp().use { silent -> GeoTools.mdnsTarget = InetSocketAddress(LOOP, silent.port); assertTrue(text(runNetTool("geo_mdns")).contains("응답한 기기가 없어요")) }
        assertTrue(runNetTool("geo_mdns_resolve", "n" to "bad name!").hasError)
    }

    // ================================================================ DNSBL · RDAP · Tor · 클라우드
    @Test fun dnsbl_interpretation() {
        assertEquals("2.1.168.192", Dnsbl.reverseV4("192.168.1.2"))
        assertEquals(-1, Dnsbl.interpret("bl.spamcop.net", emptyList()).first)
        assertTrue(Dnsbl.interpret("zen.spamhaus.org", listOf("127.0.0.2")).second.contains("SBL")); assertTrue(Dnsbl.interpret("zen.spamhaus.org", listOf("127.0.0.11")).second.contains("PBL"))
        assertTrue(Dnsbl.interpret("zen.spamhaus.org", listOf("127.0.0.4")).second.contains("XBL")); assertEquals(2, Dnsbl.interpret("bl.spamcop.net", listOf("127.0.0.2")).first)
        Dnsbl.interpret("zen.spamhaus.org", listOf("127.255.255.254")).let { assertEquals(0, it.first); assertTrue(it.second.contains("거절")) }
    }

    @Test fun dnsblTool_withFakeDns() {
        TestDns { name, type ->
            when {
                type != DnsType.A -> 0 to emptyList()
                name == "2.0.0.127.zen.spamhaus.org" -> 0 to listOf(DnsAns.A("127.0.0.2"))
                name == "2.0.0.127.bl.spamcop.net" -> 0 to listOf(DnsAns.A("127.0.0.2"))
                name.endsWith(".psbl.surriel.com") -> 0 to listOf(DnsAns.A("127.255.255.254"))
                else -> 3 to emptyList()
            }
        }.use { dns ->
            val r = runNetTool("geo_dnsbl", "ip" to "127.0.0.2", host = TestHost(listOf(dns.server))); val t = text(r)
            assertTrue(t, t.contains("Spamhaus ZEN") && t.contains("SBL (스팸 발송지)") && t.contains("2곳에 올라 있어요") && t.contains("판정 불가") && t.contains("깨끗함"))
            assertTrue(r.hasError); assertEquals(7, dns.queries.size)
            val clean = text(runNetTool("geo_dnsbl", "ip" to "203.0.113.50", host = TestHost(listOf(dns.server)))); assertTrue(clean, clean.contains("올라 있지 않아요"))
        }
        assertTrue(runNetTool("geo_dnsbl", "ip" to "2001:db8::1").hasError)
    }

    private val RDAP = """{"objectClassName":"ip network","handle":"NET-8-8-8-0-2","startAddress":"8.8.8.0","endAddress":"8.8.8.255","ipVersion":"v4","name":"GOGL","type":"DIRECT ALLOCATION","country":"US","status":["active"],
      "entities":[{"objectClassName":"entity","handle":"GOGL","roles":["registrant"],"vcardArray":["vcard",[["version",{},"text","4.0"],["fn",{},"text","Google LLC"],["kind",{},"text","org"]]],
        "entities":[{"objectClassName":"entity","handle":"ABUSE5250-ARIN","roles":["abuse"],"vcardArray":["vcard",[["version",{},"text","4.0"],["fn",{},"text","Abuse"],["email",{},"text","network-abuse@google.com"],["kind",{},"text","group"]]]}]},
        {"handle":"PERSON1","roles":["technical"],"vcardArray":["vcard",[["fn",{},"text","Hong Gildong"],["kind",{},"text","individual"],["email",{},"text","hong@example.com"]]]}],
      "events":[{"eventAction":"registration","eventDate":"2014-03-14T16:52:05-04:00"},{"eventAction":"last changed","eventDate":"2023-12-28T17:24:56-05:00"}],
      "cidr0_cidrs":[{"v4prefix":"8.8.8.0","length":24}]}"""

    @Test fun rdap_parsesAndHidesIndividuals() {
        val r = Rdap.parseIp(RDAP)
        assertEquals("GOGL", r.name); assertEquals("8.8.8.0", r.start); assertEquals("8.8.8.255", r.end); assertEquals("US", r.country); assertEquals("Google LLC", r.org); assertEquals("network-abuse@google.com", r.abuse)
        assertEquals(listOf("8.8.8.0/24"), r.cidrs); assertEquals("2023-12-28T17:24:56-05:00", r.changed); assertEquals(listOf("active"), r.status)
        val person = Rdap.parseIp(RDAP.replace("\"kind\",{},\"text\",\"org\"", "\"kind\",{},\"text\",\"individual\"").replace("Google LLC", "Hong Gildong"))
        assertEquals("개인 명의 (표시하지 않아요)", person.org); assertFalse(person.org!!.contains("Hong"))
        assertEquals(listOf("8.8.8.0/24", "2001:4860::/32"), Rdap.parsePrefixes("""{"data":{"prefixes":[{"prefix":"8.8.8.0/24"},{"prefix":"2001:4860::/32"},{"x":1}]}}"""))
        assertTrue(Rdap.parsePrefixes("""{"data":{}}""").isEmpty())
        assertEquals(setOf("1.2.3.4", "5.6.7.8"), TorList.parse("# comment\n1.2.3.4\n\n5.6.7.8 \n"))
    }

    @Test fun cloudDetect_labels() {
        assertEquals("아마존 클라우드(AWS)", CloudDetect.label("Amazon.com, Inc.")); assertEquals("클라우드플레어(CDN·보안)", CloudDetect.label("Cloudflare, Inc.")); assertEquals("구글 (클라우드·서비스)", CloudDetect.label("Google LLC"))
        assertEquals("마이크로소프트(Azure)", CloudDetect.label("Microsoft Corporation")); assertEquals("네이버 (클라우드·서비스)", CloudDetect.label("NAVER Cloud Corp.")); assertNull(CloudDetect.label("Korea Telecom")); assertNull(CloudDetect.label(null))
    }

    // ================================================================ 이메일 헤더
    private val HEADER = """Received: from mail-wm1-f45.google.com (mail-wm1-f45.google.com [209.85.128.45])
 by mx.example.net (Postfix) with ESMTPS id 4F2D1A0123
 for <me@example.net>; Tue, 14 Nov 2023 10:00:05 +0900 (KST)
Received: by mail-wm1-f45.google.com with SMTP id 5b1f17b1804b1-40a4a4d3a14so1234567f8f.0
 for <me@example.net>; Mon, 13 Nov 2023 17:00:00 -0800 (PST)
Received: from [10.0.0.5] (unknown [203.0.113.77])
 by smtp.gmail.com with ESMTPSA id abc; Mon, 13 Nov 2023 16:59:58 -0800 (PST)
Authentication-Results: mx.example.net; spf=pass smtp.mailfrom=sender@gmail.com; dkim=pass header.d=gmail.com; dmarc=pass header.from=gmail.com
Return-Path: <sender@gmail.com>
From: Sender <sender@gmail.com>
Reply-To: boss@evil-example.org
X-Originating-IP: [203.0.113.77]
Subject: hello

본문은 헤더가 아니라서 읽지 않아요.
Received: from fake.example (fake [198.51.100.1]) by nowhere with SMTP; Mon, 13 Nov 2023 10:00:00 +0000"""

    @Test fun emailHeader_hopsDelaysAndAuth() {
        val f = EmailHeader.fields(HEADER)
        assertEquals(3, f.count { it.first == "Received" }); assertTrue("본문 뒤의 줄은 무시", f.none { it.second.contains("fake.example") })
        val hops = EmailHeader.hops(f)
        assertEquals(3, hops.size)
        assertEquals("203.0.113.77", hops[0].ip); assertEquals(1, hops[0].no); assertNull(hops[0].delaySec); assertEquals("smtp.gmail.com", hops[0].by); assertEquals("ESMTPSA", hops[0].proto)
        assertNull(hops[1].ip); assertEquals(2L, hops[1].delaySec)                                  // Gmail 내부 전달 (from 없음)
        assertEquals("209.85.128.45", hops[2].ip); assertEquals(5L, hops[2].delaySec); assertEquals("mx.example.net", hops[2].by)
        assertEquals(mapOf("spf" to "pass", "dkim" to "pass", "dmarc" to "pass"), EmailHeader.authResults(f))
        assertEquals(listOf("X-Originating-IP" to "203.0.113.77"), EmailHeader.hintIps(f))
        assertEquals("gmail.com", EmailHeader.domainOf("Sender <sender@gmail.com>")); assertEquals("example.co.kr", EmailHeader.baseDomain("mail.example.co.kr")); assertEquals("example.com", EmailHeader.baseDomain("a.b.example.com"))
        assertNotNull(EmailHeader.parseDate("Tue, 14 Nov 2023 10:00:05 +0900 (KST)")); assertNotNull(EmailHeader.parseDate("14 Nov 2023 10:00:05 +0000")); assertNull(EmailHeader.parseDate("어제 오후"))
    }

    @Test fun emailHeaderTool_summarizes() {
        val r = runNetTool("geo_email_header", "h" to HEADER); val t = text(r)
        assertTrue(t, t.contains("203.0.113.77") && t.contains("209.85.128.45") && t.contains("5초") && t.contains("SPF: pass") && t.contains("DMARC: pass"))
        assertTrue(t, t.contains("Reply-To") || t.contains("답장 주소(evil-example.org)") || t.contains("답장 주소"))                   // 답장 주소 도메인이 다름
        assertTrue(t.contains("미국"))                                                                                              // 구글 서버는 폰 안 자료로 미국
        assertFalse(r.hasError)
        val bad = runNetTool("geo_email_header", "h" to HEADER.replace("spf=pass", "spf=fail")); assertTrue(bad.hasError && text(bad).contains("사칭"))
        assertTrue(text(runNetTool("geo_email_header", "h" to "Subject: hi\nFrom: a@b.com")).contains("Received 줄이 없어요"))
        assertTrue(text(runNetTool("geo_email_header", "h" to "")).contains("전체 헤더"))
    }

    // ================================================================ 오프라인 조회 도구 (폰 안 자료)
    @Test fun offlineGeoTools() {
        text(runNetTool("geo_country", "ip" to "8.8.8.8")).let { assertTrue(it, it.contains("미국 (US)") && it.contains("AS15169 Google LLC") && it.contains("구글 (클라우드·서비스)") && it.contains("DB-IP")) }
        text(runNetTool("geo_country", "ip" to "192.168.0.1")).let { assertTrue(it, it.contains("사설") && it.contains("자료 없음")) }
        assertTrue(runNetTool("geo_country", "ip" to "abc").hasError); assertTrue(text(runNetTool("geo_country", "ip" to "")).contains("입력하세요"))
        assertTrue(runNetTool("geo_country", host = NoHost).hasError)                                                // 자료를 못 읽으면 안내
        val bulk = text(runNetTool("geo_country_bulk")); assertTrue(bulk, bulk.contains("대한민국 (KR)") && bulk.contains("미국 (US)") && bulk.contains("AS4766 Korea Telecom") && bulk.contains("6개 조회"))
        val stats = text(runNetTool("geo_country_stats")); assertTrue(stats, stats.contains("전체: 10건") && stats.contains("대한민국 (KR)") && stats.contains("50.0%") && stats.contains("호주 (AU)"))
        val asn = text(runNetTool("geo_asn_org", "asn" to "AS4766")); assertTrue(asn, asn.contains("Korea Telecom") && asn.contains("46,352,224") && asn.contains("1563개 범위") && asn.contains("5410개 CIDR") && asn.contains("1.96.0.0/12"))
        assertTrue(runNetTool("geo_asn_org", "asn" to "99999999").hasError); assertTrue(runNetTool("geo_asn_org", "asn" to "korea").hasError)
        val org = text(runNetTool("geo_find_org", "q" to "korea telecom")); assertTrue(org, org.contains("AS4766")); assertTrue(text(runNetTool("geo_find_org", "q" to "zzzzqqqq")).contains("가 들어간 이름이 없어요"))
        assertTrue(text(runNetTool("geo_cloud_check", "ip" to "52.95.110.1")).contains("아마존 클라우드(AWS)")); assertTrue(text(runNetTool("geo_cloud_check", "ip" to "168.126.63.1")).contains("일치하지 않아요"))
    }

    @Test fun countryCidrsAndRules() {
        val kr = text(runNetTool("geo_country_cidrs", "c" to "한국")); assertTrue(kr, kr.contains("대한민국 (KR)") && kr.contains("3547개 CIDR") && kr.contains("116,081,260") && kr.contains("1.11.0.0/16\n1.16.0.0/18\n1.18.116.0/22"))
        assertTrue(runNetTool("geo_country_cidrs", "c" to "없는나라").hasError)
        val asnRules = text(runNetTool("geo_asn_blocklist", "asn" to "9318", "fmt" to "nginx geo", "act" to "이 ASN 들을 차단"))
        assertTrue(asnRules, asnRules.contains("2484개") && asnRules.contains("geo \$geo_blocked {") && asnRules.contains("default 0;") && asnRules.contains("    1.224.48.0/20 1;") && asnRules.contains("    1.224.64.0/18 1;"))
        assertEquals(2484, Regex("""^\s+\d+\.\d+\.\d+\.\d+/\d+ 1;$""", RegexOption.MULTILINE).findAll(asnRules).count())
        val allow = text(runNetTool("geo_asn_blocklist", "asn" to "9318", "fmt" to "nginx geo", "act" to "이 ASN 들만 허용")); assertTrue(allow, allow.contains("default 1;") && allow.contains("1.224.48.0/20 0;") && allow.contains("목록 밖이면"))
        val ipset = text(runNetTool("geo_country_blocklist", "c" to "KR", "fmt" to "iptables + ipset", "act" to "이 나라들을 차단"))
        assertTrue(ipset, ipset.contains("ipset create geo_block hash:net family inet") && ipset.contains("sudo ipset add geo_block 1.11.0.0/16 -exist") && ipset.contains("iptables -I INPUT 1 -m set --match-set geo_block src -j DROP"))
        assertEquals(3547, Regex("sudo ipset add geo_block").findAll(ipset).count())
        val keep = text(runNetTool("geo_country_blocklist", "c" to "KR", "fmt" to "iptables + ipset", "act" to "이 나라들만 허용")); assertTrue(keep, keep.contains("-j DROP") && keep.contains("SSH 접속 주소가 목록에 있는지") && keep.contains("ESTABLISHED,RELATED"))
        assertTrue(text(runNetTool("geo_country_blocklist", "c" to "KR", "fmt" to "nftables")).contains("table inet geo")); assertTrue(text(runNetTool("geo_country_blocklist", "c" to "KR", "fmt" to "Apache(.htaccess)")).contains("<RequireAll>"))
        assertTrue(text(runNetTool("geo_country_blocklist", "c" to "KR", "fmt" to "대역 목록만(CIDR)")).contains("1.11.0.0/16"))
        // 너무 큰 목록은 잘라서 알림
        val big = text(runNetTool("geo_country_blocklist", "c" to "CN,RU", "fmt" to "대역 목록만(CIDR)")); assertTrue(big.contains("21054개") && big.contains("너무 많아서 앞 20000 개만"))
        assertTrue(runNetTool("geo_country_blocklist", "c" to "").text().contains("입력하세요")); assertTrue(runNetTool("geo_country_blocklist", "c" to "없는나라").hasError)
    }

    @Test fun logCountriesTool() {
        val r = text(runNetTool("geo_log_countries"))
        assertTrue(r, r.contains("공인 IP 가 있는 줄 5줄") && r.contains("서로 다른 IP 4개") && r.contains("중국 (CN)") && r.contains("40.0%") && r.contains("113.226.115.168"))
        assertTrue(text(runNetTool("geo_log_countries", "log" to "192.168.0.1 only private")).contains("공인 IP"))
    }

    // ================================================================ 인터넷 제공처 도구 (가짜 응답)
    private fun fakeProviders(overrides: Map<String, String> = emptyMap(), failing: Set<String> = emptySet()) {
        GeoNet.fetcher = { url ->
            val key = when { "ipwho.is" in url -> "ipwho"; "ipapi.co" in url -> "ipapico"; "ipinfo.io" in url -> "ipinfo"; "ip.guide" in url -> "guide"; "api.ipapi.is" in url -> "ipapiis"; "geojs.io" in url -> "geojs"; "ip-api.com" in url -> "ipapicom"; else -> "other" }
            if (key in failing) throw IOException("연결 시간 초과")
            overrides[key] ?: when (key) { "ipwho" -> J_IPWHO; "ipapico" -> J_IPAPI; "ipinfo" -> J_IPINFO; "guide" -> J_GUIDE; "ipapiis" -> J_IPAPIS; "geojs" -> J_GEOJS; "ipapicom" -> J_IPAPICOM; else -> throw IOException("알 수 없는 주소: $url") }
        }
    }

    @Test fun geoIpTools() {
        fakeProviders()
        val t = text(runNetTool("geo_ip", "ip" to "168.126.63.1"))
        assertTrue(t, t.contains("대한민국 (KR)") && t.contains("Seoul") && t.contains("신뢰도: 높음") && t.contains("5 / 5") && t.contains("폰 안 자료와 비교") && t.contains("AS4766 Korea Telecom") && t.contains("openstreetmap.org") && t.contains("사람이나 집의 위치"))
        assertFalse(runNetTool("geo_ip", "ip" to "168.126.63.1").hasError)
        // 일부 제공처 실패 → 나머지로 계산하고 실패는 표시
        fakeProviders(failing = setOf("ipwho", "guide")); text(runNetTool("geo_ip", "ip" to "168.126.63.1")).let { assertTrue(it, it.contains("3 / 3") && it.contains("연결 시간 초과")) }
        // 전부 실패 → 오류
        fakeProviders(failing = setOf("ipwho", "ipapico", "ipinfo", "guide", "ipapiis")); assertTrue(runNetTool("geo_ip", "ip" to "168.126.63.1").hasError)
        // 사설 주소는 제공처에 보내지 않음
        var called = false; GeoNet.fetcher = { called = true; "{}" }
        assertTrue(runNetTool("geo_ip", "ip" to "192.168.0.1").hasError); assertTrue(runNetTool("geo_ip", "ip" to "127.0.0.1").hasError); assertFalse(called)
        assertTrue(text(runNetTool("geo_ip", "ip" to "")).contains("입력하세요"))
    }

    @Test fun geoProvidersAndMyIp() {
        fakeProviders(overrides = mapOf("geojs" to J_GEOJS.replace("37.5660", "35.18").replace("126.9784", "129.07").replace("\"Seoul\"", "\"Busan\"")))
        text(runNetTool("geo_providers", "ip" to "168.126.63.1")).let { assertTrue(it, it.contains("7 / 7") && it.contains("geojs.io") && it.contains("ip-api.com") && it.contains("3") && it.contains("km")) }
        fakeProviders(failing = setOf("ipapicom")); text(runNetTool("geo_providers", "ip" to "168.126.63.1")).let { assertTrue(it, it.contains("6 / 7") && it.contains("연결 시간 초과")) }
        fakeProviders()
        val me = text(runNetTool("geo_my_ip", host = TestHost(lan = "192.168.0.12" to 24))); assertTrue(me, me.contains("내 공인 IP: 168.126.63.1") && me.contains("Wi-Fi 안의 내 IP: 192.168.0.12") && me.contains("대한민국 (KR)"))
    }

    @Test fun geoBatchDistanceTimezone() {
        fakeProviders(overrides = mapOf("ipwho" to J_IPWHO))
        val b = text(runNetTool("geo_batch", "ips" to "168.126.63.1\n168.126.63.2\n192.168.0.1")); assertTrue(b, b.contains("Seoul, South Korea") && b.lines().count { it.contains("Seoul, South Korea") } == 2 && !b.contains("192.168.0.1"))
        assertTrue(text(runNetTool("geo_batch", "ips" to "192.168.0.1")).contains("공인 IP"))
        // 두 IP 사이 거리: 주소에 따라 다른 제공처 응답
        val tokyo = """{"ip":"x","success":true,"country":"Japan","country_code":"JP","region":"Tokyo","city":"Tokyo","latitude":35.6762,"longitude":139.6503,"connection":{"asn":2516,"isp":"KDDI"},"timezone":{"id":"Asia/Tokyo"}}"""
        GeoNet.fetcher = { url -> if ("168.126.63.1" in url) when { "ipwho.is" in url -> J_IPWHO.replace("37.5665", "37.5665"); "ipapi.co" in url -> J_IPAPI; "ipinfo" in url -> J_IPINFO; "ip.guide" in url -> J_GUIDE; else -> J_IPAPIS } else when { "ipwho.is" in url -> tokyo; "ipapi.co" in url -> tokyo.replace("\"success\":true,", "").replace("country_code", "country_code"); else -> throw IOException("없음") } }
        val d = text(runNetTool("geo_distance", "a" to "168.126.63.1", "b" to "8.8.4.4")); assertTrue(d, Regex("직선거리: 11[0-9]{2} km").containsMatchIn(d) && d.contains("이론상 최소 왕복 시간") && d.contains("동쪽"))
        fakeProviders()
        val tz = text(runNetTool("geo_timezone", "ip" to "168.126.63.1")); assertTrue(tz, tz.contains("Asia/Seoul") && tz.contains("현지 시각") && tz.contains("시차"))
        fakeProviders(overrides = mapOf("ipwho" to J_IPWHO.replace("Asia/Seoul", "Mars/Olympus"), "ipapico" to J_IPAPI.replace("Asia/Seoul", "Mars/Olympus"), "ipinfo" to J_IPINFO.replace("Asia/Seoul", "Mars/Olympus"), "guide" to J_GUIDE.replace("Asia/Seoul", "Mars/Olympus"), "ipapiis" to J_IPAPIS.replace("Asia/Seoul", "Mars/Olympus")))
        assertTrue(runNetTool("geo_timezone", "ip" to "168.126.63.1").hasError)
    }

    @Test fun vpnTorRdapRoutes() {
        GeoNet.fetcher = { url ->
            when {
                "check.torproject.org" in url -> "9.9.9.9\n149.154.167.50\n"
                "api.ipapi.is" in url -> J_IPAPIS.replace("\"is_datacenter\":false", "\"is_datacenter\":true")
                "ip-api.com" in url -> J_IPAPICOM
                "rdap.org" in url -> RDAP
                "stat.ripe.net" in url && "AS4766" in url -> """{"data":{"prefixes":[{"prefix":"1.96.0.0/12"},{"prefix":"2001:4860::/32"}]}}"""
                else -> throw IOException("없음")
            }
        }
        val v = runNetTool("geo_vpn_check", "ip" to "9.9.9.9"); val t = text(v)
        assertTrue(t, t.contains("VPN 으로 알려진 주소") && t.contains("Tor 출구 노드") && t.contains("데이터센터·호스팅 주소") && t.contains("목록에 있어요") && t.contains("신호가 있어요")); assertTrue(v.hasError.not())
        val calm = text(runNetTool("geo_vpn_check", "ip" to "168.126.63.1")); assertTrue(calm, calm.contains("VPN 으로 알려진 주소"))                    // ipapi.is 샘플이 vpn=true 라서
        assertTrue(text(runNetTool("geo_tor_check", "ip" to "149.154.167.50")).contains("Tor 출구 노드예요")); assertTrue(text(runNetTool("geo_tor_check", "ip" to "1.0.0.1")).contains("목록에 없어요"))
        val rd = text(runNetTool("geo_rdap", "ip" to "8.8.8.8")); assertTrue(rd, rd.contains("Google LLC") && rd.contains("8.8.8.0/24") && rd.contains("network-abuse@google.com") && rd.contains("GOGL") && !rd.contains("Hong") && rd.contains("개인 명의로 등록된 항목은 표시하지 않아요"))
        val rt = text(runNetTool("geo_asn_routes", "asn" to "4766")); assertTrue(rt, rt.contains("IPv4 1개 · IPv6 1개") && rt.contains("1.96.0.0/12") && rt.contains("Korea Telecom"))
        assertTrue(runNetTool("geo_asn_routes", "asn" to "abc").hasError); assertTrue(runNetTool("geo_rdap", "ip" to "10.0.0.1").hasError)
    }

    @Test fun myIpEchoTools() {
        GeoNet.fetcher = { url -> when { "ipify.org" in url && "api6" !in url && "api64" !in url -> "203.0.113.9"; "icanhazip" in url -> "203.0.113.9\n"; "ifconfig.me" in url -> "203.0.113.9"; "amazonaws" in url -> "198.51.100.7\n"; "ident.me" in url -> "203.0.113.9"; "api6" in url -> throw IOException("IPv6 없음"); else -> throw IOException("없음") } }
        val m = text(runNetTool("geo_my_ip_multi")); assertTrue(m, m.contains("서로 다른 IP: 2개") && m.contains("198.51.100.7") && m.contains("분할 터널"))
        val same = run { GeoNet.fetcher = { "203.0.113.9\n" }; text(runNetTool("geo_my_ip_multi", host = TestHost(lan = "203.0.113.9" to 24))) }; assertTrue(same, same.contains("내 공인 IP: 203.0.113.9") && same.contains("모든 서비스가 같은 IP") && same.contains("공유기 없이 인터넷에 직접"))
        GeoNet.fetcher = { throw IOException("끊김") }; assertTrue(runNetTool("geo_my_ip_multi").hasError)
        GeoNet.fetcher = { url -> if ("api6" in url) throw IOException("없음") else "168.126.63.9" }
        val d = text(runNetTool("geo_my_ip_dual")); assertTrue(d, d.contains("IPv4") && d.contains("168.126.63.9") && d.contains("대한민국") && d.contains("IPv4 만 돼요"))
        GeoNet.fetcher = { url -> if ("api6" in url) "2001:4860:4860::8888" else "8.8.8.8" }; assertTrue(text(runNetTool("geo_my_ip_dual")).contains("듀얼 스택"))
        GeoNet.fetcher = { "fl=1a2\nh=www.cloudflare.com\nip=168.126.63.9\nts=1\nvisit_scheme=https\nuag=x\ncolo=ICN\nsliver=none\nhttp=http/2\nloc=KR\ntls=TLSv1.3\nsni=plaintext\nwarp=off\ngateway=off\nrbi=off\nkex=X25519MLKEM768\n" }
        val c = text(runNetTool("geo_cf_trace")); assertTrue(c, c.contains("내 IP: 168.126.63.9") && c.contains("ICN (서울 인천)") && c.contains("대한민국 (KR)") && c.contains("TLSv1.3") && c.contains("WARP(클라우드플레어 VPN): 꺼짐"))
        GeoNet.fetcher = { "이상한 응답" }; assertTrue(text(runNetTool("geo_cf_trace")).contains("예상한 형식의 응답이 아니에요"))
    }

    // ================================================================ DNS 로 알아내는 도구 (가짜 DNS 서버)
    @Test fun dnsBasedGeoTools() {
        TestDns { name, type ->
            when {
                name == "naver.com" && type == DnsType.A -> 0 to listOf(DnsAns.A("168.126.63.1"), DnsAns.A("8.8.8.8"))
                name == "naver.com" && type == DnsType.MX -> 0 to listOf(DnsAns.MX(20, "mx2.example.com"), DnsAns.MX(10, "mx1.example.com"))
                name == "mx1.example.com" && type == DnsType.A -> 0 to listOf(DnsAns.A("168.126.63.1"))
                name == "mx2.example.com" && type == DnsType.A -> 0 to listOf(DnsAns.A("52.95.110.1"))
                name == "cname.example.com" && type == DnsType.A -> 0 to listOf(DnsAns.CNAME("target.example.com"), DnsAns.A("1.1.1.1"))
                name.endsWith("in-addr.arpa") && type == DnsType.PTR -> if (name.startsWith("1.2.0.192")) 0 to listOf(DnsAns.PTR("gw.example.net")) else 3 to emptyList()
                else -> 3 to emptyList()
            }
        }.use { dns ->
            val host = TestHost(listOf(dns.server))
            val s = text(runNetTool("geo_domain_server", "d" to "naver.com", host = host)); assertTrue(s, s.contains("168.126.63.1") && s.contains("대한민국 (KR)") && s.contains("미국 (US)") && s.contains("AS15169 Google LLC") && s.contains("여러 나라") && s.contains("대한민국, 미국"))
            val cn = text(runNetTool("geo_domain_server", "d" to "cname.example.com", host = host)); assertTrue(cn, cn.contains("cname.example.com → target.example.com") && cn.contains("호주 (AU)"))
            assertTrue(runNetTool("geo_domain_server", "d" to "nothing.example.com", host = host).hasError)
            val mx = text(runNetTool("geo_mail_servers", "d" to "naver.com", host = host)); assertTrue(mx, mx.indexOf("mx1.example.com") < mx.indexOf("mx2.example.com") && mx.contains("대한민국 · Korea Telecom") && mx.contains("미국 · Amazon.com, Inc. · 아마존 클라우드(AWS)"))
            assertTrue(text(runNetTool("geo_mail_servers", "d" to "nomx.example.com", host = host)).contains("MX 레코드가 없어요"))
            val sweep = text(runNetTool("geo_ptr_sweep", "cidr" to "192.0.2.0/30", host = host)); assertTrue(sweep, sweep.contains("이름이 있는 IP: 1 / 4") && sweep.contains("192.0.2.1") && sweep.contains("gw.example.net"))
            assertTrue(runNetTool("geo_ptr_sweep", "cidr" to "10.0.0.0/24", host = host).hasError); assertTrue(runNetTool("geo_ptr_sweep", "cidr" to "x", host = host).hasError)
            // 도메인의 모든 IP: 내 DNS + 공용 DNS(가짜 둘)
            TestDns { name, type -> if (name == "naver.com" && type == DnsType.A) 0 to listOf(DnsAns.A("168.126.63.1"), DnsAns.A("210.220.163.82")) else 3 to emptyList() }.use { other ->
                GeoTools.publicResolvers = listOf(other.server to "둘째")
                val all = text(runNetTool("geo_domain_ips", "d" to "naver.com", host = host)); assertTrue(all, all.contains("찾은 IP: 3개") && all.contains("210.220.163.82") && all.contains("내 DNS, 둘째") && all.contains("SK Broadband") && true)
                assertTrue(all, all.contains("DNS 마다 다른 IP"))
            }
        }
    }

    @Test fun myIpDnsTool() {
        TestDns { name, type -> if (name == "myip.opendns.com" && type == DnsType.A) 0 to listOf(DnsAns.A("203.0.113.9")) else 3 to emptyList() }.use { open ->
            TestDns { name, type -> if (name == "o-o.myaddr.l.google.com" && type == DnsType.TXT) 0 to listOf(DnsAns.TXT("203.0.113.9")) else 3 to emptyList() }.use { goog ->
                TestDns { name, type ->
                    when { name == "o-o.myaddr.l.google.com" && type == DnsType.TXT -> 0 to listOf(DnsAns.TXT("168.126.63.100"), DnsAns.TXT("edns0-client-subnet 203.0.113.0/24")); name == "whoami.akamai.net" && type == DnsType.A -> 0 to listOf(DnsAns.A("168.126.63.100")); else -> 3 to emptyList() }
                }.use { sys ->
                    GeoTools.myIpDnsServers = open.server to goog.server
                    val t = text(runNetTool("geo_my_ip_dns", host = TestHost(listOf(sys.server))))
                    assertTrue(t, t.contains("DNS 로 알아낸 내 IP: 203.0.113.9") && t.contains("DNS 서버의 공인 IP: 168.126.63.100") && t.contains("운영 회사: Korea Telecom") && t.contains("DNS 질문이 VPN 밖으로 새고 있다는"))
                }
            }
        }
    }

    @Test fun registry_geoGroupIsBigAndGuarded() {
        val geo = NetToolbox.ALL.filter { it.group == NetGroups.GEO }
        println("GEO tools: ${geo.size}")
        assertTrue("IP 위치·IP 찾기 도구 수 ${geo.size}", geo.size >= 30)
        for (t in geo) if (t.mode != ToolMode.OFFLINE) assertFalse("${t.id}: 무엇이 나가는지 안내", t.note.isNullOrBlank())
        // 몰래 IP 를 알아내는 도구(IP 로거·추적 링크 등)나 사람을 찾는 도구는 없음
        val text = geo.joinToString(" ") { it.id + " " + it.title + " " + it.desc }.lowercase()
        for (bad in listOf("logger", "grabber", "로거", "추적 링크", "몰래", "상대방 ip", "휴대폰 위치", "전화번호")) assertFalse("금지된 도구 이름: $bad", text.contains(bad) && !text.contains("몰래 ip 를 알아내는 링크"))
    }
}
