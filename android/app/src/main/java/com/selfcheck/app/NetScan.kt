package com.selfcheck.app

import java.io.IOException
import java.net.ConnectException
import java.net.IDN
import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.NoRouteToHostException
import java.net.Socket
import java.net.SocketTimeoutException
import java.util.concurrent.Callable
import java.util.concurrent.ConcurrentLinkedQueue
import java.util.concurrent.CountDownLatch
import java.util.concurrent.Executors
import java.util.concurrent.ThreadFactory
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicInteger

/*
 * 포트 검사 · 같은 망 기기 찾기 엔진 (안드로이드 화면과 분리, 컴퓨터에서 시험 가능).
 *
 * 검사 방식은 "TCP 연결 시도" 하나뿐입니다 (운영체제가 하는 평범한 연결과 똑같음):
 *   연결됨 = 열림, 연결 거부(RST) = 닫힘, 대답 없음 = 방화벽이 숨겼거나 장비가 없음.
 * 몰래 하는 방식(SYN 만 보내기·주소 위조·조각 패킷)이나 암호·취약점 시도는 하지 않습니다.
 */

enum class PortState(val label: String) { OPEN("열림"), CLOSED("닫힘"), NO_REPLY("응답 없음"), ERROR("오류") }

class PortResult(val port: Int, val state: PortState, val ms: Int, val banner: String? = null, val detail: String? = null)

class ScanOptions(
    val timeoutMs: Int = 1000,
    val threads: Int = 48,
    /** 열린 포트에서 서비스 인사말(SSH·FTP·웹 서버 이름 등)을 읽을지 */
    val banner: Boolean = true,
    val bannerWaitMs: Int = 400,
    val httpPorts: Set<Int> = Ports.HTTP,
    /** 소켓을 만드는 방법 (안드로이드에서는 Wi-Fi 망에 묶은 소켓을 넘김) */
    val newSocket: () -> Socket = { Socket() },
)

class ScanReport(
    val target: String,
    val requested: Int,
    val results: List<PortResult>,
    val cancelled: Boolean,
    val elapsedMs: Long,
) {
    val open: List<PortResult> get() = results.filter { it.state == PortState.OPEN }
    val closedCount: Int get() = results.count { it.state == PortState.CLOSED }
    val noReplyCount: Int get() = results.count { it.state == PortState.NO_REPLY }
    val errorCount: Int get() = results.count { it.state == PortState.ERROR }

    /** 장비가 켜져 있는 것으로 보이는가 (열림 또는 닫힘 응답이 하나라도 있음) */
    val hostAlive: Boolean get() = results.any { it.state == PortState.OPEN || it.state == PortState.CLOSED }

    /** 가장 위험한 열린 포트의 위험도 (없으면 -1) */
    val worstRisk: Int get() = open.maxOfOrNull { Ports.describe(it.port)?.risk ?: 0 } ?: -1

    fun toText(): String = buildString {
        appendLine("포트 검사 결과 · $target")
        appendLine("검사 ${results.size}/${requested}개 · 열림 ${open.size} · 닫힘 $closedCount · 응답 없음 $noReplyCount · ${"%.1f".format(elapsedMs / 1000.0)}초" + if (cancelled) " (중간에 멈춤)" else "")
        for (r in open.sortedBy { it.port }) {
            val info = Ports.describe(r.port)
            appendLine("- ${r.port}  ${info?.name ?: "알 수 없음"}" + (info?.takeIf { it.risk > 0 }?.let { "  [${if (it.risk == 2) "위험" else "주의"}]" } ?: "") + (r.banner?.let { "  : $it" } ?: ""))
        }
        if (open.isEmpty()) appendLine("- 열린 포트 없음")
    }
}

/** 연결 실패를 열림/닫힘/응답 없음으로 나눔. 안드로이드와 컴퓨터(JVM)의 오류 글이 달라서 글자로 판단 */
internal fun classifyFailure(e: IOException): Pair<PortState, String?> {
    val m = e.message ?: ""
    return when {
        e is SocketTimeoutException -> PortState.NO_REPLY to null
        m.contains("refused", true) || m.contains("ECONNREFUSED") -> PortState.CLOSED to null
        m.contains("timed out", true) || m.contains("ETIMEDOUT") -> PortState.NO_REPLY to null
        e is NoRouteToHostException || m.contains("EHOSTUNREACH") || m.contains("No route to host", true) ->
            PortState.NO_REPLY to "경로 없음 (장비가 꺼졌거나 같은 망이 아니에요)"
        m.contains("ENETUNREACH") || m.contains("unreachable", true) -> PortState.ERROR to "네트워크에 연결되어 있지 않아요"
        m.contains("EPERM") || m.contains("EACCES") || m.contains("Permission denied", true) -> PortState.ERROR to "권한이 없어요 (방화벽·VPN 이 막았을 수 있어요)"
        e is ConnectException -> PortState.ERROR to m.take(80)
        else -> PortState.ERROR to m.take(80)
    }
}

internal fun daemonFactory(name: String): ThreadFactory {
    val n = AtomicInteger()
    return ThreadFactory { r -> Thread(r, "$name-${n.incrementAndGet()}").apply { isDaemon = true } }
}

object PortScanner {
    /**
     * host 의 ports 를 동시에 여러 개 검사합니다 (한 번에 opt.threads 개까지만).
     * cancel 을 true 로 바꾸면 아직 시작하지 않은 포트는 건너뛰고 곧 끝납니다.
     * onProgress 는 검사 스레드에서 불립니다 (화면 갱신은 호출하는 쪽에서 메인 스레드로 옮기세요).
     */
    fun scan(
        host: InetAddress,
        ports: List<Int>,
        opt: ScanOptions = ScanOptions(),
        cancel: AtomicBoolean = AtomicBoolean(false),
        onProgress: (done: Int, total: Int, found: PortResult?) -> Unit = { _, _, _ -> },
    ): ScanReport {
        val t0 = System.nanoTime()
        val total = ports.size
        val results = ConcurrentLinkedQueue<PortResult>()
        val done = AtomicInteger()
        if (total > 0) {
            val pool = Executors.newFixedThreadPool(opt.threads.coerceIn(1, 256).coerceAtMost(total), daemonFactory("portscan"))
            val latch = CountDownLatch(total)
            try {
                for (p in ports) pool.execute {
                    try {
                        if (!cancel.get()) {
                            val r = probe(host, p, opt, cancel)
                            results.add(r)
                            onProgress(done.incrementAndGet(), total, if (r.state == PortState.OPEN) r else null)
                        }
                    } catch (_: Throwable) {
                    } finally { latch.countDown() }
                }
                latch.await()
            } finally { pool.shutdownNow() }
        }
        val sorted = results.sortedBy { it.port }
        return ScanReport(IpUtil.format(host), total, sorted, sorted.size < total, (System.nanoTime() - t0) / 1_000_000)
    }

    internal fun probe(host: InetAddress, port: Int, opt: ScanOptions, cancel: AtomicBoolean): PortResult {
        val s = try { opt.newSocket() } catch (e: IOException) { return PortResult(port, PortState.ERROR, 0, null, e.message?.take(80)) }
        val t = System.nanoTime()
        fun ms() = ((System.nanoTime() - t) / 1_000_000).toInt()
        try {
            s.connect(InetSocketAddress(host, port), opt.timeoutMs)
            val connectMs = ms()
            val banner = if (opt.banner && !cancel.get()) readBanner(s, host, port, opt) else null
            return PortResult(port, PortState.OPEN, connectMs, banner)
        } catch (e: IOException) {
            val (st, d) = classifyFailure(e)
            return PortResult(port, st, ms(), null, d)
        } catch (e: SecurityException) {
            return PortResult(port, PortState.ERROR, ms(), null, "권한이 없어요")
        } finally {
            runCatching { s.close() }
        }
    }

    /** 열린 포트의 인사말을 조금만 읽음. 웹 포트는 "HEAD /" 한 번만 보내서 서버 이름을 읽음 (그 외에는 아무것도 보내지 않음) */
    private fun readBanner(s: Socket, host: InetAddress, port: Int, opt: ScanOptions): String? {
        if (port in Ports.TLS) return null
        return try {
            s.soTimeout = opt.bannerWaitMs
            val http = port in opt.httpPorts
            if (http) {
                val req = "HEAD / HTTP/1.0\r\nHost: ${IpUtil.format(host)}\r\nUser-Agent: SelfCheck-PortCheck\r\nConnection: close\r\n\r\n"
                s.getOutputStream().apply { write(req.toByteArray(Charsets.US_ASCII)); flush() }
            }
            val buf = ByteArray(1024)
            var n = 0
            val ins = s.getInputStream()
            while (n < buf.size) {
                val r = try { ins.read(buf, n, buf.size - n) } catch (_: SocketTimeoutException) { -2 }
                if (r <= 0) break
                n += r
                if (!http || hasHeaderEnd(buf, n)) break
            }
            summarizeBanner(buf, n, http)
        } catch (_: IOException) { null }
    }

    private fun hasHeaderEnd(b: ByteArray, n: Int): Boolean {
        for (i in 0..n - 4) if (b[i] == '\r'.code.toByte() && b[i + 1] == '\n'.code.toByte() && b[i + 2] == '\r'.code.toByte() && b[i + 3] == '\n'.code.toByte()) return true
        return false
    }
}

/** 받은 글(남의 장비가 보낸 것)을 화면에 안전하게 보여 줄 한 줄로: 보이는 영문·숫자·기호만, 길이 제한 */
internal fun summarizeBanner(raw: ByteArray, len: Int, http: Boolean): String? {
    if (len <= 0) return null
    var printable = 0
    for (i in 0 until len) { val c = raw[i].toInt() and 0xff; if (c in 0x20..0x7e || c == 0x0d || c == 0x0a || c == 0x09) printable++ }
    if (printable * 2 < len) return "(바이너리 응답 ${len}바이트)"
    // 터미널 색 코드(ESC[31m 같은 것)는 통째로 지우고, 보이는 글자만 남김
    val text = String(raw, 0, len, Charsets.ISO_8859_1).replace(Regex("\u001B\\[[0-9;?]*[ -/]*[@-~]"), "")
    val lines = text.split("\r\n", "\n").map { l -> l.filter { it in ' '..'~' }.trim() }.filter { it.isNotEmpty() }
    if (lines.isEmpty()) return null
    val out = ArrayList<String>()
    out += lines[0]
    if (http) for (l in lines.drop(1)) {
        val k = l.substringBefore(':', "").lowercase()
        if (k == "server" || k == "www-authenticate" || k == "x-powered-by") out += l
    }
    return out.joinToString(" · ").take(140)
}

// ---------------------------------------------------------------------------------------------
// 같은 망 기기 찾기

class LanHost(
    val ip: String,
    val hostName: String?,
    /** 처음 응답이 온 데까지 걸린 시간(ms) */
    val ms: Int,
    val openPorts: List<Int>,
    /** 어떻게 알아냈는지 (핑·포트 응답·연결 거부 응답) */
    val how: String,
    val mac: String? = null,
)

object LanScanner {
    /** 살아 있는지 보는 포트: 켜져 있으면 닫힌 포트도 "거부" 응답을 하므로 하나만 맞아도 알 수 있음 */
    val LIVE_PORTS = intArrayOf(80, 443, 445, 22, 8080, 62078, 53)
    /** 살아 있는 기기에서만 더 살펴보는 포트 (무슨 기기인지 짐작하는 단서) */
    val MORE_PORTS = intArrayOf(139, 7000, 8008, 554, 9100, 5000)

    /**
     * 주소 하나가 살아 있는지 확인합니다 (아무 응답이 없으면 null).
     * 핑(ICMP/TCP 에코) → 포트 몇 개 연결 시도 순서. 방화벽이 전부 막는 기기는 찾을 수 없습니다.
     */
    fun probe(
        addr: InetAddress,
        livePorts: IntArray = LIVE_PORTS,
        morePorts: IntArray = MORE_PORTS,
        icmp: Boolean = true,
        pingMs: Int = 400,
        tcpMs: Int = 250,
        newSocket: () -> Socket = { Socket() },
        cancel: AtomicBoolean = AtomicBoolean(false),
    ): LanHost? {
        val t0 = System.nanoTime()
        fun ms() = ((System.nanoTime() - t0) / 1_000_000).toInt()
        var how: String? = null
        var firstMs = 0
        val open = ArrayList<Int>()
        if (icmp && !cancel.get()) {
            val ok = try { addr.isReachable(pingMs) } catch (_: IOException) { false }
            if (ok) { how = "핑 응답"; firstMs = ms() }
        }
        fun tryPort(p: Int) {
            if (cancel.get()) return
            val s = try { newSocket() } catch (_: IOException) { return }
            try {
                s.connect(InetSocketAddress(addr, p), tcpMs)
                open += p
                if (how == null) { how = "포트 $p 응답"; firstMs = ms() }
            } catch (e: IOException) {
                if (classifyFailure(e).first == PortState.CLOSED && how == null) { how = "연결 거부 응답"; firstMs = ms() }
            } finally { runCatching { s.close() } }
        }
        val tried = HashSet<Int>()
        // 1) 살아 있는지: 핑으로 이미 알았으면 건너뛰고, 아니면 포트를 하나씩 시도하다 첫 응답에서 멈춤
        if (how == null) for (p in livePorts) { tryPort(p); tried += p; if (how != null) break }
        if (how == null) return null
        // 2) 살아 있는 기기: 아직 안 본 포트들에서 열린 포트(무슨 기기인지 짐작하는 단서) 모으기
        for (p in (livePorts.toList() + morePorts.toList()).distinct()) if (p !in tried) { tryPort(p); tried += p }
        return LanHost(IpUtil.format(addr), null, firstMs, open.sorted(), how!!)
    }

    /**
     * 여러 주소를 동시에 확인합니다. 찾은 기기는 이름(역방향 DNS)도 알아봅니다.
     * onProgress 는 검사 스레드에서 불립니다.
     */
    fun sweep(
        addrs: List<InetAddress>,
        threads: Int = 96,
        icmp: Boolean = true,
        newSocket: () -> Socket = { Socket() },
        cancel: AtomicBoolean = AtomicBoolean(false),
        onProgress: (done: Int, total: Int, found: LanHost?) -> Unit = { _, _, _ -> },
    ): List<LanHost> {
        val total = addrs.size
        val found = ConcurrentLinkedQueue<LanHost>()
        val done = AtomicInteger()
        if (total == 0) return emptyList()
        val pool = Executors.newFixedThreadPool(threads.coerceIn(1, 256).coerceAtMost(total), daemonFactory("lanscan"))
        val latch = CountDownLatch(total)
        try {
            for (a in addrs) pool.execute {
                try {
                    if (!cancel.get()) {
                        var h = probe(a, icmp = icmp, newSocket = newSocket, cancel = cancel)
                        if (h != null) {
                            val name = Dns.reverse(a, 800)
                            if (name != null) h = LanHost(h.ip, name, h.ms, h.openPorts, h.how, h.mac)
                            found.add(h)
                        }
                        onProgress(done.incrementAndGet(), total, h)
                    }
                } catch (_: Throwable) {
                } finally { latch.countDown() }
            }
            latch.await()
        } finally { pool.shutdownNow() }
        return found.sortedBy { h -> IpUtil.parseV4(h.ip)?.let { IpUtil.v4ToLong(it) } ?: Long.MAX_VALUE }
    }
}

// ---------------------------------------------------------------------------------------------
// 이름 풀이 (DNS): 오래 걸리는 조회는 시간을 정해 두고 기다림

object Dns {
    private val pool = Executors.newCachedThreadPool(daemonFactory("dns"))

    fun <T> withTimeout(ms: Long, block: () -> T): T? {
        val f = pool.submit(Callable { runCatching(block).getOrNull() })
        return try { f.get(ms, TimeUnit.MILLISECONDS) } catch (_: Exception) { f.cancel(true); null }
    }

    /** 도메인 → IP 목록 (IPv4 먼저). 못 찾으면 빈 목록. 한글 도메인도 받음 */
    fun resolve(host: String, timeoutMs: Long = 6000): List<InetAddress> {
        val ascii = runCatching { IDN.toASCII(host, IDN.ALLOW_UNASSIGNED) }.getOrDefault(host)
        val all = withTimeout(timeoutMs) { InetAddress.getAllByName(ascii).toList() } ?: return emptyList()
        return all.distinct().sortedBy { if (it.address.size == 4) 0 else 1 }
    }

    /** IP → 이름 (역방향 조회). 이름이 없으면(결과가 IP 글자 그대로면) null */
    fun reverse(addr: InetAddress, timeoutMs: Long = 2000): String? =
        withTimeout(timeoutMs) { addr.canonicalHostName }?.takeIf { it.isNotBlank() && it != addr.hostAddress && it != IpUtil.format(addr) }
}
