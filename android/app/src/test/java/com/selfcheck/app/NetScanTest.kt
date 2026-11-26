package com.selfcheck.app

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Assume.assumeTrue
import org.junit.Test
import java.io.IOException
import java.net.ConnectException
import java.net.InetAddress
import java.net.ServerSocket
import java.net.Socket
import java.net.SocketAddress
import java.net.SocketTimeoutException
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicInteger
import kotlin.concurrent.thread

/** 컴퓨터 안(127.0.0.1)의 가짜 서버로 포트 검사·기기 찾기 엔진을 시험 (밖으로는 아무것도 보내지 않음) */
class NetScanTest {
    private val lo: InetAddress = InetAddress.getByName("127.0.0.1")

    /** 접속하면 인사말(또는 요청에 대한 응답)을 보내는 시험용 서버. received = 클라이언트가 먼저 보낸 글자 수 */
    private class Server(private val greeting: String? = null, private val reply: ((String) -> String)? = null) : AutoCloseable {
        private val server = ServerSocket(0, 50, InetAddress.getByName("127.0.0.1"))
        val port: Int get() = server.localPort
        @Volatile var received = 0
        @Volatile var lastRequest = ""

        init {
            thread(isDaemon = true) {
                while (!server.isClosed) {
                    val c = try { server.accept() } catch (_: IOException) { break }
                    thread(isDaemon = true) {
                        c.use {
                            try {
                                if (greeting != null) { it.getOutputStream().write(greeting.toByteArray()); it.getOutputStream().flush() }
                                it.soTimeout = 900
                                val buf = ByteArray(2048)
                                val n = try { it.getInputStream().read(buf) } catch (_: IOException) { -1 }
                                if (n > 0) {
                                    received += n; lastRequest = String(buf, 0, n)
                                    reply?.let { r -> it.getOutputStream().write(r(lastRequest).toByteArray()); it.getOutputStream().flush() }
                                }
                            } catch (_: IOException) {}
                        }
                    }
                }
            }
        }

        override fun close() { server.close() }
    }

    /** 방금까지 쓰이다 닫힌 포트 = 연결하면 거부(RST)될 가능성이 높은 포트 */
    private fun closedPort(): Int = ServerSocket(0, 1, lo).use { it.localPort }

    @Test fun findsOpenAndClosedPortsAndReadsTheGreeting() {
        Server(greeting = "SSH-2.0-TestServer_1.0\r\n").use { srv ->
            val closed = closedPort()
            val rep = PortScanner.scan(lo, listOf(closed, srv.port), ScanOptions(timeoutMs = 1500, threads = 4))
            val open = rep.results.first { it.port == srv.port }; val shut = rep.results.first { it.port == closed }
            assertEquals(PortState.OPEN, open.state); assertEquals("SSH-2.0-TestServer_1.0", open.banner)
            assertEquals(PortState.CLOSED, shut.state); assertNull(shut.banner)
            assertEquals(listOf(srv.port), rep.open.map { it.port })
            assertTrue(rep.hostAlive); assertEquals(1, rep.closedCount); assertEquals(0, rep.noReplyCount); assertFalse(rep.cancelled)
            assertEquals(rep.results.map { it.port }, rep.results.map { it.port }.sorted()) // 결과는 포트 번호순
            assertEquals(0, rep.worstRisk) // 설명이 없는 포트는 보통으로
        }
    }

    @Test fun readsWebServerNameWithOneHeadRequest() {
        Server(reply = { _ -> "HTTP/1.0 200 OK\r\nServer: TestSrv/1.0\r\nContent-Length: 0\r\n\r\n" }).use { srv ->
            val rep = PortScanner.scan(lo, listOf(srv.port), ScanOptions(timeoutMs = 1500, httpPorts = setOf(srv.port)))
            assertEquals("HTTP/1.0 200 OK · Server: TestSrv/1.0", rep.results[0].banner)
            assertTrue(srv.lastRequest.startsWith("HEAD / HTTP/1.0\r\nHost: 127.0.0.1\r\n"))
            assertTrue(srv.lastRequest.contains("SelfCheck-PortCheck"))
        }
    }

    @Test fun sendsNothingToNonWebPorts() {
        Server().use { srv ->
            val rep = PortScanner.scan(lo, listOf(srv.port), ScanOptions(timeoutMs = 1500))
            assertEquals(PortState.OPEN, rep.results[0].state); assertNull(rep.results[0].banner)
            Thread.sleep(300)
            assertEquals("웹 포트가 아니면 연결만 확인하고 아무것도 보내지 않아야 함", 0, srv.received)
        }
    }

    @Test fun bannerReadingCanBeTurnedOff() {
        Server(greeting = "220 hello\r\n").use { srv ->
            val rep = PortScanner.scan(lo, listOf(srv.port), ScanOptions(banner = false))
            assertEquals(PortState.OPEN, rep.results[0].state); assertNull(rep.results[0].banner)
        }
    }

    @Test fun reportsProgressForEveryPortOnce() {
        val ports = (30000..30049).toList()
        val seen = java.util.Collections.synchronizedList(ArrayList<Int>())
        val total = AtomicInteger()
        val rep = PortScanner.scan(lo, ports, ScanOptions(timeoutMs = 500, threads = 8, banner = false)) { done, t, _ -> seen += done; total.set(t) }
        assertEquals(50, total.get()); assertEquals((1..50).toList(), seen.sorted()); assertEquals(50, rep.results.size); assertFalse(rep.cancelled)
    }

    @Test fun cancelStopsBeforeTheRemainingPorts() {
        val ports = (31000..31199).toList()
        val cancel = AtomicBoolean(false)
        val rep = PortScanner.scan(lo, ports, ScanOptions(timeoutMs = 500, threads = 1, banner = false), cancel) { done, _, _ -> if (done >= 5) cancel.set(true) }
        assertTrue(rep.cancelled); assertEquals(5, rep.results.size)
        // 시작하기 전에 취소하면 아무것도 검사하지 않음
        val pre = PortScanner.scan(lo, ports, ScanOptions(threads = 4), AtomicBoolean(true))
        assertTrue(pre.cancelled); assertTrue(pre.results.isEmpty())
        // 빈 목록은 바로 끝남
        assertEquals(0, PortScanner.scan(lo, emptyList()).results.size)
    }

    @Test fun reportTextListsOpenPortsWithRisk() {
        Server(greeting = "220 ready\r\n").use { srv ->
            val rep = PortScanner.scan(lo, listOf(srv.port), ScanOptions(timeoutMs = 1500))
            val text = rep.toText()
            assertTrue(text.startsWith("포트 검사 결과 · 127.0.0.1")); assertTrue(text.contains("열림 1")); assertTrue(text.contains("- ${srv.port}")); assertTrue(text.contains("220 ready"))
        }
        val none = ScanReport("10.0.0.1", 3, listOf(PortResult(22, PortState.NO_REPLY, 500)), true, 1500)
        assertTrue(none.toText().contains("열린 포트 없음")); assertTrue(none.toText().contains("중간에 멈춤")); assertFalse(none.hostAlive)
        val danger = ScanReport("10.0.0.1", 2, listOf(PortResult(23, PortState.OPEN, 3, "login:"), PortResult(80, PortState.OPEN, 3)), false, 100)
        assertEquals(2, danger.worstRisk); assertTrue(danger.toText().contains("[위험]"))
    }

    @Test fun failureMessagesAreClassifiedOnAndroidAndJvm() {
        fun st(e: IOException) = classifyFailure(e).first
        assertEquals(PortState.CLOSED, st(ConnectException("Connection refused (Connection refused)")))
        assertEquals(PortState.CLOSED, st(ConnectException("failed to connect to /192.168.0.1 (port 23) from /192.168.0.5 (port 40000) after 700ms: isConnected failed: ECONNREFUSED (Connection refused)")))
        assertEquals(PortState.NO_REPLY, st(SocketTimeoutException("failed to connect to /192.168.0.9 (port 80) after 700ms")))
        assertEquals(PortState.NO_REPLY, st(ConnectException("Connection timed out")))
        assertEquals(PortState.NO_REPLY, st(ConnectException("isConnected failed: EHOSTUNREACH (No route to host)")))
        assertEquals(PortState.ERROR, st(ConnectException("isConnected failed: ENETUNREACH (Network is unreachable)")))
        assertEquals(PortState.ERROR, st(java.net.SocketException("socket failed: EACCES (Permission denied)")))
        assertEquals(PortState.ERROR, st(IOException("뭔가 이상한 오류")))
    }

    @Test fun bannerTextFromOtherMachinesIsCleaned() {
        fun sum(s: String, http: Boolean = false) = summarizeBanner(s.toByteArray(Charsets.ISO_8859_1), s.length, http)
        assertEquals("SSH-2.0-OpenSSH_9.6", sum("SSH-2.0-OpenSSH_9.6\r\nsecond line"))
        assertEquals("220 ProFTPD ready", sum("\u001B[31m220 ProFTPD\u0007 ready\u0000"))   // 제어 문자(색 코드·벨)는 지움
        assertEquals("HTTP/1.1 401 Unauthorized · www-authenticate: Basic realm=\"TP-LINK Router\" · Server: lighttpd",
            sum("HTTP/1.1 401 Unauthorized\r\nContent-Type: text/html\r\nwww-authenticate: Basic realm=\"TP-LINK Router\"\r\nServer: lighttpd\r\n\r\n", true))
        assertEquals("(바이너리 응답 5바이트)", summarizeBanner(byteArrayOf(0xff.toByte(), 0xfd.toByte(), 0x18, 0xff.toByte(), 0xfb.toByte()), 5, false)) // 텔넷 협상 데이터
        assertNull(sum("\r\n\r\n"))
        assertNull(summarizeBanner(ByteArray(4), 0, false))
        assertTrue(sum("A".repeat(500))!!.length <= 140)
    }

    // ---- 같은 망 기기 찾기

    @Test fun lanProbeFindsAHostThatRefusesAndCollectsItsOpenPorts() {
        Server().use { srv ->
            val closed = closedPort()
            // 먼저 본 포트가 "연결 거부" 응답 → 살아 있음, 이어서 다른 포트에서 열린 포트를 모음
            val h = LanScanner.probe(lo, livePorts = intArrayOf(closed), morePorts = intArrayOf(srv.port), icmp = false, tcpMs = 500)
            assertNotNull(h); assertEquals("127.0.0.1", h!!.ip); assertEquals("연결 거부 응답", h.how); assertEquals(listOf(srv.port), h.openPorts)
        }
    }

    @Test fun lanProbeFindsAHostByAnOpenPort() {
        Server().use { srv ->
            val h = LanScanner.probe(lo, livePorts = intArrayOf(srv.port), morePorts = intArrayOf(), icmp = false, tcpMs = 500)!!
            assertEquals("포트 ${srv.port} 응답", h.how); assertEquals(listOf(srv.port), h.openPorts)
        }
    }

    private class FailingSocket(private val err: IOException) : Socket() {
        override fun connect(endpoint: SocketAddress?, timeout: Int) { throw err }
    }

    @Test fun lanProbeReturnsNullWhenNothingAnswers() {
        for (err in listOf(SocketTimeoutException("timeout"), ConnectException("isConnected failed: EHOSTUNREACH (No route to host)"), ConnectException("ENETUNREACH (Network is unreachable)"))) {
            val h = LanScanner.probe(lo, icmp = false, newSocket = { FailingSocket(err) })
            assertNull(err.message, h)
        }
    }

    @Test fun lanSweepFindsLoopbackAndSkipsDeadAddresses() {
        assumeTrue("이 환경에서는 핑이 통하지 않음", runCatching { lo.isReachable(500) }.getOrDefault(false))
        val found = LanScanner.sweep(listOf(lo), threads = 2)
        assertEquals(1, found.size); assertEquals("127.0.0.1", found[0].ip)
        // 모든 연결이 시간 초과되고 핑도 끈 경우: 아무것도 찾지 못함
        val none = LanScanner.sweep(listOf(lo, lo), icmp = false, newSocket = { FailingSocket(SocketTimeoutException("t")) })
        assertTrue(none.isEmpty())
        val cancelled = LanScanner.sweep(listOf(lo, lo), cancel = AtomicBoolean(true))
        assertTrue(cancelled.isEmpty())
    }

    // ---- 이름 풀이

    @Test fun dnsResolvesLocalhostAndGivesUpOnMissingNames() {
        val a = Dns.resolve("localhost", 4000)
        assertTrue(a.isNotEmpty()); assertTrue(a.all { IpUtil.classify(it) == IpKind.LOOPBACK })
        assertTrue(Dns.resolve("no-such-host.invalid", 3000).isEmpty())
        assertEquals(42, Dns.withTimeout(1000) { 42 })
        assertNull(Dns.withTimeout(100) { Thread.sleep(2000); 1 })     // 시간 안에 못 끝나면 null
        assertNull(Dns.withTimeout(1000) { error("실패") })              // 예외도 null
    }
}
