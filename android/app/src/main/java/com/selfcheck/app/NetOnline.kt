package com.selfcheck.app

import java.io.BufferedInputStream
import java.io.ByteArrayOutputStream
import java.io.IOException
import java.io.InputStream
import java.net.DatagramPacket
import java.net.DatagramSocket
import java.net.IDN
import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.Socket
import java.net.SocketTimeoutException
import java.net.URI
import java.nio.ByteBuffer
import java.security.KeyStore
import java.security.cert.X509Certificate
import javax.net.ssl.SSLContext
import javax.net.ssl.SSLSocket
import javax.net.ssl.TrustManager
import javax.net.ssl.TrustManagerFactory
import javax.net.ssl.X509TrustManager

/*
 * 접속 진단 엔진 (화면과 분리, 컴퓨터 안의 가짜 서버로 시험):
 *  MiniHttp(웹 응답·시간 분석) · TlsInspect(인증서) · NtpClient(시계) · SystemPing(핑·경로 추적 해석)
 *  Ssdp(UPnP 기기 찾기) · Wol(원격 켜기) · Nbns(윈도 이름) · Whois · SpeedTest(속도 측정)
 * 모두 평범한 접속·질문만 하고, 조회한 상대에게 무엇이 전달되는지는 각 도구 화면에 안내합니다.
 */

/** 인증서 이름 검사 (SAN 우선, 없으면 CN). 와일드카드는 맨 앞 한 칸만 */
object HostMatch {
    private fun cn(c: X509Certificate): String? = Regex("""(?:^|,)\s*CN=([^,]+)""").find(c.subjectX500Principal.name)?.groupValues?.get(1)?.trim()

    private fun matchName(host: String, pattern: String): Boolean {
        val h = host.lowercase().trimEnd('.'); val p = pattern.lowercase().trimEnd('.')
        if (!p.startsWith("*.")) return h == p
        val hl = h.split('.'); val pl = p.split('.')
        return pl.size >= 3 && hl.size == pl.size && hl.drop(1) == pl.drop(1)
    }

    fun matches(host: String, c: X509Certificate): Boolean {
        val ip = IpUtil.parse(host)
        val sans = runCatching { c.subjectAlternativeNames?.toList() }.getOrNull().orEmpty()
        if (ip != null) {
            val norm = IpUtil.format(ip)
            return sans.any { (it[0] as? Int) == 7 && IpUtil.parse(it[1].toString())?.let { a -> IpUtil.format(a) } == norm }
        }
        val dns = sans.filter { (it[0] as? Int) == 2 }.map { it[1].toString() }
        if (dns.isNotEmpty()) return dns.any { matchName(host, it) }
        return cn(c)?.let { matchName(host, it) } == true
    }
}

class TlsReport(
    val host: String, val port: Int, val protocol: String, val cipher: String, val chain: List<X509Certificate>,
    val trustError: String?, val hostnameOk: Boolean, val ms: Long,
) {
    val trusted: Boolean get() = trustError == null
}

object TlsInspect {
    private class Recording : X509TrustManager {
        @Volatile var chain: List<X509Certificate> = emptyList()
        override fun checkClientTrusted(c: Array<X509Certificate>, a: String) {}
        override fun checkServerTrusted(c: Array<X509Certificate>, a: String) { chain = c.toList() }
        override fun getAcceptedIssuers(): Array<X509Certificate> = emptyArray()
    }

    /** 시스템이 믿는 발급 기관으로 이어지는지. null = 믿을 수 있음, 아니면 이유 */
    fun trustCheck(chain: List<X509Certificate>): String? {
        if (chain.isEmpty()) return "인증서가 없어요"
        val leaf = chain[0]
        return try {
            val tmf = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm()).apply { init(null as KeyStore?) }
            tmf.trustManagers.filterIsInstance<X509TrustManager>().first().checkServerTrusted(chain.toTypedArray(), "RSA")
            null
        } catch (e: java.security.cert.CertificateExpiredException) { "인증서가 만료됐어요"
        } catch (e: Exception) {
            val m = e.message ?: ""
            when {
                chain.size == 1 && leaf.subjectX500Principal == leaf.issuerX500Principal -> "자체 서명 인증서예요 (공인 인증 기관이 발급하지 않았어요)"
                m.contains("expired", true) || CertInfo.daysLeft(leaf) < 0 -> "인증서가 만료됐어요"
                m.contains("not yet valid", true) -> "인증서가 아직 유효하지 않아요 (시작 전이거나 폰 시계가 틀림)"
                else -> "신뢰할 수 있는 발급 기관으로 이어지지 않아요 (${m.take(80)})"
            }
        }
    }

    fun resolve(host: String): InetAddress = IpUtil.parse(host) ?: InetAddress.getAllByName(IDN.toASCII(host, IDN.ALLOW_UNASSIGNED)).sortedBy { if (it.address.size == 4) 0 else 1 }.first()

    fun inspect(host: String, port: Int = 443, timeoutMs: Int = 8000, protocols: Array<String>? = null, newSocket: () -> Socket = { Socket() }): TlsReport {
        val t0 = System.nanoTime()
        val addr = resolve(host)
        val raw = newSocket()
        try {
            raw.connect(InetSocketAddress(addr, port), timeoutMs); raw.soTimeout = timeoutMs
            val rec = Recording()
            val ctx = SSLContext.getInstance("TLS").apply { init(null, arrayOf<TrustManager>(rec), null) }
            val ssl = ctx.socketFactory.createSocket(raw, host, port, true) as SSLSocket
            if (protocols != null) ssl.enabledProtocols = protocols
            ssl.startHandshake()
            val s = ssl.session
            val chain = rec.chain.ifEmpty { s.peerCertificates.filterIsInstance<X509Certificate>() }
            val rep = TlsReport(host, port, s.protocol, s.cipherSuite, chain, trustCheck(chain), chain.isNotEmpty() && HostMatch.matches(host, chain[0]), (System.nanoTime() - t0) / 1_000_000)
            runCatching { ssl.close() }
            return rep
        } catch (e: Exception) { runCatching { raw.close() }; throw e }
    }

    /** 이 기기가 지원하는 TLS 버전 목록 */
    fun supportedProtocols(): List<String> = SSLContext.getInstance("TLS").apply { init(null, null, null) }.supportedSSLParameters.protocols.toList()
}

// ---------------------------------------------------------------------------------------------
// 웹 응답 분석 (직접 소켓으로 HTTP/1.1: 안드로이드의 http:// 차단 정책과 무관하고, 단계별 시간을 잴 수 있음)

class HttpTimings(val dnsMs: Long, val connectMs: Long, val tlsMs: Long?, val ttfbMs: Long, val totalMs: Long)

class HttpResult(
    val url: String, val status: Int, val statusLine: String, val headers: List<Pair<String, String>>, val body: String?,
    val remoteIp: String, val timings: HttpTimings, val tls: TlsReport?,
) {
    fun header(name: String): String? = headers.firstOrNull { it.first.equals(name, true) }?.second
    fun all(name: String): List<String> = headers.filter { it.first.equals(name, true) }.map { it.second }
    val isRedirect get() = status in listOf(301, 302, 303, 307, 308) && header("Location") != null
}

class ParsedUrl(val scheme: String, val host: String, val port: Int, val path: String) {
    val isHttps get() = scheme == "https"
    override fun toString() = "$scheme://${if (':' in host) "[$host]" else host}${if (port == (if (isHttps) 443 else 80)) "" else ":$port"}$path"
}

object MiniHttp {
    private val URL_RE = Regex("""^(https?)://(\[[^\]]+\]|[^/:?#]+)(?::(\d+))?([^#]*)(?:#.*)?$""", RegexOption.IGNORE_CASE)

    fun parseUrl(raw: String): ParsedUrl? {
        var u = raw.trim(); if ("://" !in u) u = "https://$u"
        val m = URL_RE.matchEntire(u) ?: return null
        val scheme = m.groupValues[1].lowercase(); val host = m.groupValues[2].removePrefix("[").removeSuffix("]")
        val port = m.groupValues[3].toIntOrNull() ?: if (scheme == "https") 443 else 80
        if (port !in 1..65535 || host.isEmpty()) return null
        var path = m.groupValues[4]; if (path.isEmpty()) path = "/" else if (!path.startsWith("/")) path = "/$path"
        return ParsedUrl(scheme, host, port, path)
    }

    /** 머리글 한 줄 "이름: 값" */
    internal fun parseHeaderLine(l: String): Pair<String, String>? { val i = l.indexOf(':'); return if (i <= 0) null else l.substring(0, i).trim() to l.substring(i + 1).trim() }

    private fun readLine(ins: InputStream, limit: Int = 16384): String? {
        val bo = ByteArrayOutputStream()
        while (true) {
            val c = ins.read()
            if (c < 0) return if (bo.size() == 0) null else bo.toString("ISO-8859-1")
            if (c == '\n'.code) return bo.toString("ISO-8859-1").trimEnd('\r')
            bo.write(c); if (bo.size() > limit) throw IOException("머리글이 너무 길어요")
        }
    }

    /** chunked 본문 풀기 (maxBody 바이트까지) */
    internal fun readChunked(ins: InputStream, maxBody: Int): ByteArray {
        val out = ByteArrayOutputStream()
        while (out.size() < maxBody) {
            val size = readLine(ins)?.substringBefore(';')?.trim()?.toIntOrNull(16) ?: break
            if (size == 0) break
            val buf = ByteArray(minOf(size, maxBody - out.size())); var got = 0
            while (got < buf.size) { val r = ins.read(buf, got, buf.size - got); if (r < 0) break; got += r }
            out.write(buf, 0, got)
            if (got < size) break
            readLine(ins)
        }
        return out.toByteArray()
    }

    fun request(
        url: String, method: String = "GET", headers: Map<String, String> = emptyMap(), maxBody: Int = 0, timeoutMs: Int = 8000, insecure: Boolean = false,
        userAgent: String = "SelfCheck-NetTools/1.0", newSocket: () -> Socket = { Socket() },
    ): HttpResult {
        val u = parseUrl(url) ?: throw IOException("URL 형식이 올바르지 않아요")
        val t0 = System.nanoTime(); fun ms(from: Long = t0) = (System.nanoTime() - from) / 1_000_000
        val addr = try { TlsInspect.resolve(u.host) } catch (e: Exception) { throw IOException("도메인을 찾지 못했어요 (${u.host})") }
        val dnsMs = ms()
        val tc = System.nanoTime()
        var sock = newSocket()
        try {
            sock.connect(InetSocketAddress(addr, u.port), timeoutMs); sock.soTimeout = timeoutMs
            val connectMs = ms(tc)
            var tlsMs: Long? = null; var tls: TlsReport? = null
            if (u.isHttps) {
                val tt = System.nanoTime()
                val rec = object : X509TrustManager {
                    @Volatile var chain: List<X509Certificate> = emptyList()
                    override fun checkClientTrusted(c: Array<X509Certificate>, a: String) {}
                    override fun checkServerTrusted(c: Array<X509Certificate>, a: String) { chain = c.toList() }
                    override fun getAcceptedIssuers(): Array<X509Certificate> = emptyArray()
                }
                val ctx = SSLContext.getInstance("TLS").apply { init(null, arrayOf<TrustManager>(rec), null) }
                val ssl = ctx.socketFactory.createSocket(sock, u.host, u.port, true) as SSLSocket
                sock = ssl
                try { ssl.startHandshake() } catch (e: javax.net.ssl.SSLException) { throw IOException("TLS 연결에 실패했어요: ${e.message?.take(100)}") }
                tlsMs = ms(tt)
                val s = ssl.session; val chain = rec.chain.ifEmpty { s.peerCertificates.filterIsInstance<X509Certificate>() }
                tls = TlsReport(u.host, u.port, s.protocol, s.cipherSuite, chain, TlsInspect.trustCheck(chain), chain.isNotEmpty() && HostMatch.matches(u.host, chain[0]), tlsMs)
                if (!insecure) {
                    if (tls.trustError != null) throw IOException("인증서를 믿을 수 없어요: ${tls.trustError}")
                    if (!tls.hostnameOk) throw IOException("인증서 이름이 접속한 주소(${u.host})와 달라요")
                }
            }
            val req = StringBuilder("$method ${u.path} HTTP/1.1\r\nHost: ${if (':' in u.host) "[${u.host}]" else u.host}${if (u.port == (if (u.isHttps) 443 else 80)) "" else ":${u.port}"}\r\n")
            req.append("User-Agent: $userAgent\r\nAccept: */*\r\nAccept-Encoding: identity\r\nConnection: close\r\n")
            for ((k, v) in headers) req.append("$k: $v\r\n")
            req.append("\r\n")
            sock.getOutputStream().apply { write(req.toString().toByteArray(Charsets.ISO_8859_1)); flush() }
            val ins = BufferedInputStream(sock.getInputStream())
            val tr = System.nanoTime()
            val first = readLine(ins) ?: throw IOException("서버가 아무 응답 없이 연결을 닫았어요")
            val ttfb = ms(tr) + connectMs + dnsMs + (tlsMs ?: 0)
            val status = Regex("""^HTTP/\d(?:\.\d)?\s+(\d{3})""").find(first)?.groupValues?.get(1)?.toInt() ?: throw IOException("HTTP 응답이 아니에요: ${first.take(60)}")
            val hs = ArrayList<Pair<String, String>>()
            while (true) { val l = readLine(ins) ?: break; if (l.isEmpty()) break; parseHeaderLine(l)?.let { hs += it } }
            var body: String? = null
            val noBody = method == "HEAD" || status in 100..199 || status == 204 || status == 304
            if (maxBody > 0 && !noBody) {
                val te = hs.firstOrNull { it.first.equals("Transfer-Encoding", true) }?.second ?: ""
                val cl = hs.firstOrNull { it.first.equals("Content-Length", true) }?.second?.toLongOrNull()
                val bytes = try {
                    if (te.contains("chunked", true)) readChunked(ins, maxBody)
                    else {
                        val want = minOf(cl ?: Long.MAX_VALUE, maxBody.toLong()).toInt(); val bo = ByteArrayOutputStream(); val buf = ByteArray(8192)
                        while (bo.size() < want) { val r = ins.read(buf, 0, minOf(buf.size, want - bo.size())); if (r < 0) break; bo.write(buf, 0, r) }
                        bo.toByteArray()
                    }
                } catch (_: SocketTimeoutException) { ByteArray(0) }
                body = strictUtf8(bytes) ?: String(bytes, Charsets.ISO_8859_1)
            }
            return HttpResult(u.toString(), status, first, hs, body, IpUtil.format(addr), HttpTimings(dnsMs, connectMs, tlsMs, ttfb, ms()), tls)
        } finally { runCatching { sock.close() } }
    }

    /** 리다이렉트를 따라가며 모든 단계의 응답을 돌려줌 (최대 maxHops 번) */
    fun follow(url: String, maxHops: Int = 10, insecure: Boolean = false, timeoutMs: Int = 8000, newSocket: () -> Socket = { Socket() }, onStep: (Int, String) -> Unit = { _, _ -> }): List<HttpResult> {
        val out = ArrayList<HttpResult>(); var cur = url
        for (hop in 1..maxHops + 1) {
            onStep(hop, cur)
            val r = request(cur, "GET", maxBody = 0, timeoutMs = timeoutMs, insecure = insecure, newSocket = newSocket)
            out += r
            if (!r.isRedirect) break
            cur = try { URI(r.url).resolve(r.header("Location")!!.trim()).toString() } catch (_: Exception) { break }
        }
        return out
    }
}

// ---------------------------------------------------------------------------------------------
// NTP (시계 확인)

class NtpResult(val server: String, val offsetMs: Double, val delayMs: Double, val stratum: Int, val refId: String)

object NtpClient {
    private const val EPOCH_DIFF = 2208988800L

    private fun toNtp(ms: Double): Long { val sec = Math.floor(ms / 1000).toLong() + EPOCH_DIFF; val frac = ((ms / 1000 - Math.floor(ms / 1000)) * 4294967296.0).toLong(); return (sec shl 32) or (frac and 0xFFFFFFFFL) }
    private fun fromNtp(v: Long): Double { val sec = (v ushr 32) and 0xFFFFFFFFL; val frac = v and 0xFFFFFFFFL; return (sec - EPOCH_DIFF) * 1000.0 + frac * 1000.0 / 4294967296.0 }

    /** 요청 패킷 (48바이트, 버전 3, 클라이언트 모드, 보내는 시각을 마지막 8바이트에) */
    fun request(nowMs: Double): ByteArray = ByteBuffer.allocate(48).also { it.put(0, 0x1B); it.putLong(40, toNtp(nowMs)) }.array()

    /** 응답 해석: T1(보낸 시각) T4(받은 시각)로 시계 차이와 왕복 지연을 계산 */
    fun parse(server: String, resp: ByteArray, t1Ms: Double, t4Ms: Double): NtpResult {
        if (resp.size < 48) throw IOException("NTP 응답이 너무 짧아요")
        val bb = ByteBuffer.wrap(resp)
        val mode = resp[0].toInt() and 7; val stratum = resp[1].toInt() and 0xff
        if (mode != 4 && mode != 5) throw IOException("NTP 서버 응답이 아니에요")
        val refId = if (stratum <= 1) String(resp, 12, 4, Charsets.US_ASCII).trim('\u0000', ' ') else (12..15).joinToString(".") { (resp[it].toInt() and 0xff).toString() }
        if (stratum == 0) throw IOException("서버가 요청을 거절했어요 (Kiss-o'-Death: $refId)")
        if (Math.abs(fromNtp(bb.getLong(24)) - t1Ms) > 5.0) throw IOException("응답이 내 요청과 맞지 않아요")
        val t2 = fromNtp(bb.getLong(32)); val t3 = fromNtp(bb.getLong(40))
        return NtpResult(server, ((t2 - t1Ms) + (t3 - t4Ms)) / 2, (t4Ms - t1Ms) - (t3 - t2), stratum, refId)
    }

    fun query(server: String, port: Int = 123, timeoutMs: Int = 3000, now: () -> Double = { System.currentTimeMillis().toDouble() }, bind: (DatagramSocket) -> Unit = {}): NtpResult {
        val addr = IpUtil.parse(server.substringBefore('#')) ?: try { TlsInspect.resolve(server.substringBefore('#')) } catch (_: Exception) { throw IOException("서버 주소를 찾지 못했어요") }
        val p = server.substringAfter('#', "").toIntOrNull() ?: port
        DatagramSocket().use { s ->
            bind(s); s.soTimeout = timeoutMs
            val t1 = now(); val req = request(t1)
            s.send(DatagramPacket(req, req.size, addr, p))
            val buf = ByteArray(128); val pk = DatagramPacket(buf, buf.size)
            try { s.receive(pk) } catch (_: SocketTimeoutException) { throw IOException("응답이 없어요 (UDP 123 번이 막혀 있을 수 있어요)") }
            return parse(server, buf.copyOf(pk.length), t1, now())
        }
    }
}

// ---------------------------------------------------------------------------------------------
// 시스템 ping 출력 해석 (안드로이드에는 ICMP 소켓 API 가 없어서 기기의 ping 명령을 씀)

class PingLine(val kind: String, val from: String?, val seq: Int?, val ttl: Int?, val ms: Double?)

object SystemPing {
    // 주소는 "1.2.3.4" 또는 "이름 (1.2.3.4)" 두 모양 모두 받음 (기기마다 ping 출력이 다름)
    private const val ADDR = """(?:\S+\s+\(([0-9a-fA-F:.]+)\)|([0-9a-fA-F:.]+))"""
    private val REPLY = Regex("""(\d+) bytes from $ADDR:?.*?(?:icmp_)?seq=(\d+)(?:.*?ttl=(\d+))?(?:.*?time[=<]([\d.]+)\s*ms)?""")
    private val EXCEEDED = Regex("""(?i)^from\s+$ADDR[:\s].*?(time to live exceeded|ttl exceeded|hop limit exceeded|ttl expired)""")
    private val UNREACH = Regex("""(?i)^from\s+$ADDR[:\s].*?(unreachable|prohibited)""")
    private val SEQ = Regex("""(?:icmp_)?seq=(\d+)""")

    /** 주소 뒤에 붙은 ':' 는 ping 이 붙이는 구분 글자일 수 있어서, 주소로 읽히지 않을 때만 떼어 냄 */
    private fun addr(named: String, plain: String): String {
        val s = named.ifEmpty { plain }
        return if (IpUtil.parse(s) == null && s.endsWith(":")) s.dropLast(1) else s
    }

    /** ping 출력 한 줄 → 종류(reply · exceeded · unreachable) / 아니면 null */
    fun parseLine(line: String): PingLine? {
        val l = line.trim()
        REPLY.find(l)?.let { m -> return PingLine("reply", addr(m.groupValues[2], m.groupValues[3]), m.groupValues[4].toIntOrNull(), m.groupValues[5].toIntOrNull(), m.groupValues[6].toDoubleOrNull()) }
        EXCEEDED.find(l)?.let { m -> return PingLine("exceeded", addr(m.groupValues[1], m.groupValues[2]), SEQ.find(l)?.groupValues?.get(1)?.toIntOrNull(), null, null) }
        UNREACH.find(l)?.let { m -> return PingLine("unreachable", addr(m.groupValues[1], m.groupValues[2]), SEQ.find(l)?.groupValues?.get(1)?.toIntOrNull(), null, null) }
        return null
    }

    /** 요약 줄: "3 packets transmitted, 3 received, 0% packet loss" → (보냄, 받음) */
    fun parseSummary(text: String): Pair<Int, Int>? =
        Regex("""(\d+) packets transmitted, (\d+)(?: packets)? received""").find(text)?.let { it.groupValues[1].toInt() to it.groupValues[2].toInt() }

    /** 기기의 ping 으로 실행해 출력 줄을 돌려줌. 명령이 없으면 IOException */
    fun run(host: String, count: Int, waitSec: Int = 2, ttl: Int? = null, cancel: java.util.concurrent.atomic.AtomicBoolean? = null): List<String> {
        val cmd = ArrayList<String>()
        val bin = listOf("/system/bin/ping", "/system/xbin/ping", "ping").firstOrNull { it == "ping" || java.io.File(it).exists() } ?: "ping"
        cmd += bin; cmd += listOf("-c", "$count", "-W", "$waitSec"); if (ttl != null) cmd += listOf("-t", "$ttl"); cmd += host
        val p = try { ProcessBuilder(cmd).redirectErrorStream(true).start() } catch (e: IOException) { throw IOException("이 기기에는 ping 명령이 없어요") }
        val out = ArrayList<String>()
        val deadline = System.currentTimeMillis() + (count * (waitSec + 1) + 3) * 1000L
        val reader = p.inputStream.bufferedReader()
        try {
            while (System.currentTimeMillis() < deadline && cancel?.get() != true) {
                if (reader.ready()) { val l = reader.readLine() ?: break; out += l } else { if (!p.isAlive) { while (reader.ready()) out += reader.readLine() ?: break; break }; Thread.sleep(20) }
            }
        } finally { p.destroy() }
        return out
    }
}

// ---------------------------------------------------------------------------------------------
// UPnP 기기 찾기 (SSDP), 원격 켜기 (Wake-on-LAN), 윈도 이름 조회 (NetBIOS)

class SsdpDevice(val ip: String, val st: String, val usn: String, val server: String?, val location: String?)

object Ssdp {
    fun search(st: String = "ssdp:all", mx: Int = 2): ByteArray =
        "M-SEARCH * HTTP/1.1\r\nHOST: 239.255.255.250:1900\r\nMAN: \"ssdp:discover\"\r\nMX: $mx\r\nST: $st\r\n\r\n".toByteArray(Charsets.US_ASCII)

    /** 응답(HTTP/1.1 200 OK) 또는 알림(NOTIFY)의 머리글을 대문자 이름으로 */
    fun parse(payload: String): Map<String, String>? {
        val lines = payload.split("\r\n", "\n"); val first = lines.firstOrNull() ?: return null
        if (!first.startsWith("HTTP/1.1 200") && !first.startsWith("NOTIFY")) return null
        return lines.drop(1).mapNotNull { MiniHttp.parseHeaderLine(it) }.associate { it.first.uppercase() to it.second }
    }

    fun discover(timeoutMs: Int = 3000, st: String = "ssdp:all", target: InetSocketAddress = InetSocketAddress("239.255.255.250", 1900), bind: (DatagramSocket) -> Unit = {}): List<SsdpDevice> {
        val found = LinkedHashMap<String, SsdpDevice>()
        DatagramSocket().use { s ->
            bind(s); val req = search(st)
            repeat(2) { s.send(DatagramPacket(req, req.size, target)) }
            val deadline = System.currentTimeMillis() + timeoutMs
            val buf = ByteArray(4096)
            while (true) {
                val left = (deadline - System.currentTimeMillis()).toInt(); if (left <= 0) break
                s.soTimeout = left
                val p = DatagramPacket(buf, buf.size)
                try { s.receive(p) } catch (_: SocketTimeoutException) { break }
                val h = parse(String(buf, 0, p.length, Charsets.UTF_8)) ?: continue
                val ip = IpUtil.format(p.address); val usn = h["USN"] ?: h["LOCATION"] ?: continue
                found.putIfAbsent("$ip|$usn", SsdpDevice(ip, h["ST"] ?: h["NT"] ?: "", usn, h["SERVER"], h["LOCATION"]))
            }
        }
        return found.values.toList()
    }

    /** 장치 설명(XML)에서 이름·제조사·모델. 응답한 기기 자신의 내부망 주소일 때만 가져옴 */
    fun describe(d: SsdpDevice, newSocket: () -> Socket = { Socket() }): Triple<String?, String?, String?>? {
        val loc = d.location ?: return null
        val u = MiniHttp.parseUrl(loc) ?: return null
        if (u.host != d.ip || IpUtil.parse(u.host)?.let { IpUtil.classify(it).local } != true || u.isHttps) return null
        val body = try { MiniHttp.request(loc, maxBody = 16384, timeoutMs = 2500, newSocket = newSocket).body } catch (_: IOException) { null } ?: return null
        fun tag(n: String) = Regex("<$n>([^<]{1,80})</$n>", RegexOption.IGNORE_CASE).find(body)?.groupValues?.get(1)?.trim()
        return Triple(tag("friendlyName"), tag("manufacturer"), tag("modelName"))
    }
}

object Wol {
    /** 매직 패킷: FF 6개 + MAC 16번 반복 (102바이트) */
    fun packet(mac: ByteArray): ByteArray = ByteArray(6) { 0xFF.toByte() } + ByteArray(16 * 6) { mac[it % 6] }

    fun send(mac: ByteArray, target: InetAddress, port: Int = 9, bind: (DatagramSocket) -> Unit = {}) {
        DatagramSocket().use { s -> bind(s); s.broadcast = true; val p = packet(mac); s.send(DatagramPacket(p, p.size, target, port)) }
    }
}

class NbName(val name: String, val suffix: Int, val group: Boolean)
class NbResult(val names: List<NbName>, val mac: String?)

object Nbns {
    /** NBSTAT 질문: 이름 "*" 를 NetBIOS 방식으로 인코딩(CKAAAA…) */
    fun query(id: Int = 0x4242): ByteArray {
        val name = "CK" + "A".repeat(30)
        return ByteBuffer.allocate(50).apply { putShort(id.toShort()); putShort(0); putShort(1); putShort(0); putShort(0); putShort(0); put(0x20); put(name.toByteArray(Charsets.US_ASCII)); put(0); putShort(0x21); putShort(1) }.array()
    }

    /** NBSTAT 응답 해석. 규격상 응답에는 질문이 없고(0개) 일부 기기는 질문을 되돌려 보내므로 헤더의 개수만큼 건너뜀 */
    fun parse(b: ByteArray, id: Int? = null): NbResult? = try {
        fun u16(o: Int) = ((b[o].toInt() and 0xff) shl 8) or (b[o + 1].toInt() and 0xff)
        val isResponse = (b[2].toInt() and 0x80) != 0
        val qd = u16(4); val an = u16(6)
        if (!isResponse || an < 1 || qd > 1 || (id != null && u16(0) != id)) null else {
            var pos = 12
            repeat(qd) { val (_, p1) = DnsWire.readName(b, pos); pos = p1 + 4 }
            val (_, p2) = DnsWire.readName(b, pos)                           // 답의 이름
            if (u16(p2) != 0x0021) null else {                               // 종류가 NBSTAT(33)인 답만
                val rd = p2 + 10
                val n = b[rd].toInt() and 0xff
                val names = (0 until n).map { k ->
                    val o = rd + 1 + k * 18
                    NbName(String(b, o, 15, Charsets.ISO_8859_1).trim(), b[o + 15].toInt() and 0xff, ((b[o + 16].toInt() and 0xff) and 0x80) != 0)
                }
                val macOff = rd + 1 + n * 18
                val mac = if (macOff + 6 <= b.size && b.copyOfRange(macOff, macOff + 6).any { it.toInt() != 0 }) Mac.hex(b.copyOfRange(macOff, macOff + 6)) else null
                NbResult(names, mac)
            }
        }
    } catch (_: Exception) { null }

    fun ask(ip: InetAddress, port: Int = 137, timeoutMs: Int = 1500, bind: (DatagramSocket) -> Unit = {}): NbResult? {
        DatagramSocket().use { s ->
            bind(s); s.soTimeout = timeoutMs
            s.connect(InetSocketAddress(ip, port))                            // 이 주소가 아닌 곳에서 온 응답은 받지 않음
            val q = query(); s.send(DatagramPacket(q, q.size))
            val buf = ByteArray(1024); val p = DatagramPacket(buf, buf.size)
            return try { s.receive(p); parse(buf.copyOf(p.length), 0x4242) } catch (_: SocketTimeoutException) { null } catch (_: java.net.PortUnreachableException) { null }
        }
    }
}

// ---------------------------------------------------------------------------------------------
// WHOIS

object Whois {
    fun query(server: String, q: String, port: Int = 43, timeoutMs: Int = 7000, newSocket: () -> Socket = { Socket() }): String {
        newSocket().use { s ->
            s.connect(InetSocketAddress(TlsInspect.resolve(server.substringBefore('#')), server.substringAfter('#', "").toIntOrNull() ?: port), timeoutMs); s.soTimeout = timeoutMs
            s.getOutputStream().apply { write((q + "\r\n").toByteArray()); flush() }
            val bo = ByteArrayOutputStream(); val buf = ByteArray(4096)
            try { while (bo.size() < 65536) { val r = s.getInputStream().read(buf); if (r < 0) break; bo.write(buf, 0, r) } } catch (_: SocketTimeoutException) {}
            val bytes = bo.toByteArray()
            val utf = String(bytes, Charsets.UTF_8)
            return if (utf.count { it == '�' } > 3) String(bytes, java.nio.charset.Charset.forName("EUC-KR")) else utf
        }
    }

    /** IANA 응답의 "refer:" 또는 "whois:" 줄 */
    fun referOf(text: String): String? = text.lines().firstNotNullOfOrNull { l ->
        val k = l.substringBefore(':', "").trim().lowercase(); if (k == "refer" || k == "whois") l.substringAfter(':').trim().takeIf { it.isNotEmpty() } else null
    }

    /** 원문에서 알고 싶은 항목만 (대소문자 무시, 같은 항목이 여러 번이면 모두) */
    fun keyLines(text: String, keys: List<String>): List<Pair<String, String>> {
        val ks = keys.map { it.lowercase() }
        return text.lines().mapNotNull { l ->
            val k = l.substringBefore(':', "").trim(); val v = l.substringAfter(':', "").trim()
            if (k.lowercase() in ks && v.isNotEmpty()) k to v else null
        }.distinct()
    }

    private val PERSONAL = Regex("""(?i)(registrant|admin|tech|billing|contact|person|e-?mail|phone|fax|address|street|city|postal|zip|abuse|nic-hdl|등록인|담당자|연락처|전화|주소|우편|전자우편|이메일|이름)""")

    /** 개인 연락처(이름·메일·전화·주소·담당자) 줄을 지움: 도메인·주소 블록을 가진 "기관"의 기술 정보만 보여 주기 위해 */
    fun redact(text: String): String = text.lines().filterNot { l -> ':' in l && PERSONAL.containsMatchIn(l.substringBefore(':')) }.joinToString("\n")
}

// ---------------------------------------------------------------------------------------------
// 인터넷 속도 측정 (Cloudflare 의 공개 측정 주소를 사용. base 를 바꿔 시험)

class SpeedResult(val latencyMs: Double?, val downMbps: Double?, val upMbps: Double?, val downBytes: Long, val upBytes: Long)

object SpeedTest {
    const val CLOUDFLARE = "https://speed.cloudflare.com"

    private fun open(url: String, post: Boolean = false): java.net.HttpURLConnection = (URI(url).toURL().openConnection() as java.net.HttpURLConnection).apply {
        connectTimeout = 6000; readTimeout = 8000; useCaches = false; setRequestProperty("User-Agent", "SelfCheck-NetTools/1.0"); setRequestProperty("Accept-Encoding", "identity")
        if (post) { requestMethod = "POST"; doOutput = true }
    }

    fun latency(base: String, n: Int = 5): Double? {
        val t = ArrayList<Double>()
        repeat(n) { try { val c = open("$base/__down?bytes=0"); val t0 = System.nanoTime(); c.inputStream.use { it.readBytes() }; t += (System.nanoTime() - t0) / 1e6; c.disconnect() } catch (_: IOException) {} }
        return t.sorted().let { if (it.isEmpty()) null else it[it.size / 2] }
    }

    /** 속도 측정이 쓸 수 있는 데이터 상한 (빠른 회선에서 모바일 데이터를 한꺼번에 쓰지 않도록) */
    const val DOWN_CAP = 250_000_000L
    const val UP_CAP = 60_000_000L

    /** 여러 연결로 limitMs 동안 (또는 maxBytes 까지) 내려받아 Mbps (첫 0.7초는 속도 올리는 구간이라 제외) */
    fun download(base: String, threads: Int = 4, limitMs: Long = 7000, chunk: Int = 25_000_000, cancel: java.util.concurrent.atomic.AtomicBoolean = java.util.concurrent.atomic.AtomicBoolean(false), maxBytes: Long = DOWN_CAP): Pair<Double, Long>? {
        val total = java.util.concurrent.atomic.AtomicLong(); val warm = java.util.concurrent.atomic.AtomicLong(); val start = System.nanoTime(); val warmMs = 700L
        val ths = (1..threads).map { Thread {
            try {
                while (!cancel.get() && (System.nanoTime() - start) / 1_000_000 < limitMs && total.get() < maxBytes) {
                    val c = open("$base/__down?bytes=$chunk"); val buf = ByteArray(65536)
                    c.inputStream.use { ins -> while (!cancel.get() && (System.nanoTime() - start) / 1_000_000 < limitMs && total.get() < maxBytes) { val r = ins.read(buf); if (r < 0) break; total.addAndGet(r.toLong()); if ((System.nanoTime() - start) / 1_000_000 < warmMs) warm.addAndGet(r.toLong()) } }
                    c.disconnect()
                }
            } catch (_: IOException) {}
        }.also { it.isDaemon = true; it.start() } }
        ths.forEach { it.join(limitMs + 6000) }
        val elapsed = (System.nanoTime() - start) / 1e9
        val sec = elapsed - warmMs / 1000.0
        val bytes = total.get() - warm.get()
        // 너무 빨라서 올리는 구간 안에 상한에 닿았다면, 전체 시간으로 평균을 냄
        return when {
            bytes > 0 && sec >= 0.3 -> (bytes * 8 / sec / 1e6) to total.get()
            total.get() > 0 && elapsed > 0 -> (total.get() * 8 / elapsed / 1e6) to total.get()
            else -> null
        }
    }

    fun upload(base: String, threads: Int = 3, limitMs: Long = 5000, chunk: Int = 4_000_000, cancel: java.util.concurrent.atomic.AtomicBoolean = java.util.concurrent.atomic.AtomicBoolean(false), maxBytes: Long = UP_CAP): Pair<Double, Long>? {
        val total = java.util.concurrent.atomic.AtomicLong(); val start = System.nanoTime()
        val ths = (1..threads).map { Thread {
            try {
                val data = ByteArray(65536).also { java.util.Random().nextBytes(it) }
                while (!cancel.get() && (System.nanoTime() - start) / 1_000_000 < limitMs && total.get() < maxBytes) {
                    val c = open("$base/__up", post = true); c.setFixedLengthStreamingMode(chunk)
                    c.outputStream.use { out -> var sent = 0; while (sent < chunk) { val n = minOf(data.size, chunk - sent); out.write(data, 0, n); sent += n; total.addAndGet(n.toLong()) } }
                    c.responseCode; c.inputStream.use { it.readBytes() }; c.disconnect()
                }
            } catch (_: IOException) {}
        }.also { it.isDaemon = true; it.start() } }
        ths.forEach { it.join(limitMs + 6000) }
        val sec = (System.nanoTime() - start) / 1e9
        return if (total.get() <= 0) null else (total.get() * 8 / sec / 1e6) to total.get()
    }
}
