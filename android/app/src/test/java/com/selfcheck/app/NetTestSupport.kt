package com.selfcheck.app

import java.io.BufferedInputStream
import java.io.BufferedOutputStream
import java.io.Closeable
import java.io.File
import java.io.IOException
import java.io.InputStream
import java.io.OutputStream
import java.net.DatagramPacket
import java.net.DatagramSocket
import java.net.InetAddress
import java.net.ServerSocket
import java.net.Socket
import java.nio.ByteBuffer
import java.util.concurrent.CopyOnWriteArrayList
import kotlin.concurrent.thread

/** 시험에서 쓰는 휴대폰 흉내: 오프라인 IP 자료를 assets 폴더에서 바로 읽고, DNS 서버를 지정할 수 있음 */
open class TestHost(private val dns: List<String> = emptyList(), private val lan: Pair<String, Int>? = null, private val gw: String? = null) : ToolHost {
    override fun geoDb(): IpGeoDb? = FileHost.db
    override fun dnsServers(): List<String> = dns
    override fun lanIp(): Pair<String, Int>? = lan
    override fun gateway(): String? = gw
}

object FileHost : TestHost() {
    val db: IpGeoDb by lazy { IpGeoDb.ofAssetsDir(File("src/main/assets")) }
}

/** 도구 id 와 입력(기본값에 덮어씀)으로 도구를 실행 */
fun runNetTool(id: String, vararg kv: Pair<String, String>, host: ToolHost = FileHost): ToolResult {
    val t = NetToolbox.byId(id) ?: throw AssertionError("도구가 없어요: $id")
    val values = t.fields.associate { it.key to it.default } + kv
    return t.run(ToolInput(values), host, ToolEnv())
}

val LOOP: InetAddress = InetAddress.getByName("127.0.0.1")

class TestReq(val method: String, val target: String, val headers: Map<String, String>, val body: ByteArray) {
    val path: String get() = target.substringBefore('?')
    val query: String get() = target.substringAfter('?', "")
    val bodyText: String get() = String(body, Charsets.UTF_8)
}

fun OutputStream.respond(status: String, vararg headers: String, body: ByteArray = ByteArray(0), length: Boolean = true) {
    val sb = StringBuilder("HTTP/1.1 $status\r\n")
    for (h in headers) sb.append(h).append("\r\n")
    if (length) sb.append("Content-Length: ${body.size}\r\n")
    sb.append("Connection: close\r\n\r\n")
    write(sb.toString().toByteArray(Charsets.ISO_8859_1)); write(body); flush()
}

/** 127.0.0.1 에 열리는 가짜 웹 서버. 요청마다 handler 가 직접 응답 바이트를 씀 */
class TestHttp(private val handler: (TestReq, OutputStream) -> Unit) : Closeable {
    private val ss = ServerSocket(0, 50, LOOP)
    val port: Int = ss.localPort
    val requests = CopyOnWriteArrayList<TestReq>()

    init {
        thread(isDaemon = true) {
            while (true) {
                val c = try { ss.accept() } catch (_: IOException) { break }
                thread(isDaemon = true) { serve(c) }
            }
        }
    }

    private fun readLine(ins: InputStream): String? {
        val sb = StringBuilder()
        while (true) { val c = ins.read(); if (c < 0) return if (sb.isEmpty()) null else sb.toString(); if (c == '\n'.code) return sb.toString().trimEnd('\r'); sb.append(c.toChar()) }
    }

    private fun serve(c: Socket) {
        try {
            c.soTimeout = 5000
            val ins = BufferedInputStream(c.getInputStream()); val out = BufferedOutputStream(c.getOutputStream())
            val first = readLine(ins) ?: return
            val parts = first.split(' ')
            val hs = LinkedHashMap<String, String>()
            while (true) { val l = readLine(ins) ?: break; if (l.isEmpty()) break; hs[l.substringBefore(':').trim().lowercase()] = l.substringAfter(':').trim() }
            val len = hs["content-length"]?.toIntOrNull() ?: 0
            val body = ByteArray(len); var got = 0
            while (got < len) { val r = ins.read(body, got, len - got); if (r < 0) break; got += r }
            val req = TestReq(parts[0], parts.getOrElse(1) { "/" }, hs, body); requests += req
            handler(req, out); out.flush()
        } catch (_: Throwable) {
        } finally { runCatching { c.close() } }
    }

    fun url(path: String = "/") = "http://127.0.0.1:$port$path"
    override fun close() { runCatching { ss.close() } }
}

/** 127.0.0.1 TCP 가짜 서버: 연결되면 script 가 입출력을 직접 다룸 (SMTP·IMAP·FTP·SSH 같은 글 주고받기 서버 흉내) */
class TestTcp(private val script: (Socket) -> Unit) : Closeable {
    private val ss = ServerSocket(0, 50, LOOP)
    val port: Int = ss.localPort
    val connections = java.util.concurrent.atomic.AtomicInteger()

    init {
        thread(isDaemon = true) {
            while (true) {
                val c = try { ss.accept() } catch (_: IOException) { break }
                connections.incrementAndGet()
                thread(isDaemon = true) { try { c.soTimeout = 5000; script(c) } catch (_: Throwable) {} finally { runCatching { c.close() } } }
            }
        }
    }

    override fun close() { runCatching { ss.close() } }
}

/** 127.0.0.1 UDP 가짜 서버: 받은 글을 기록하고 reply 가 원하는 대로 답함 */
class TestUdp(private val reply: (DatagramPacket, DatagramSocket) -> Unit = { _, _ -> }) : Closeable {
    val sock = DatagramSocket(0, LOOP)
    val port: Int = sock.localPort
    val received = CopyOnWriteArrayList<ByteArray>()

    init {
        thread(isDaemon = true) {
            val buf = ByteArray(4096)
            while (true) {
                val p = DatagramPacket(buf, buf.size)
                try { sock.receive(p) } catch (_: IOException) { break }
                received += buf.copyOf(p.length)
                try { reply(p, sock) } catch (_: IOException) {}
            }
        }
    }

    fun send(p: DatagramPacket, data: ByteArray) = sock.send(DatagramPacket(data, data.size, p.socketAddress))
    override fun close() { sock.close() }
}

// ---------------------------------------------------------------------------------------------
// 가짜 DNS 서버 (UDP): 질문 이름·종류에 따라 시험이 정한 답을 조립해서 돌려줌

sealed class DnsAns {
    class A(val ip: String) : DnsAns()
    class AAAA(val ip: String) : DnsAns()
    class MX(val pref: Int, val host: String) : DnsAns()
    class PTR(val host: String) : DnsAns()
    class TXT(val text: String) : DnsAns()
    class CNAME(val target: String) : DnsAns()
    class NS(val host: String) : DnsAns()
    class RAW(val type: Int, val data: ByteArray) : DnsAns()
}

fun dnsName(n: String): ByteArray {
    val out = java.io.ByteArrayOutputStream()
    for (l in n.trim('.').split('.')) if (l.isNotEmpty()) { out.write(l.length); out.write(l.toByteArray()) }
    out.write(0); return out.toByteArray()
}

fun dnsReply(q: ByteArray, rcode: Int, answers: List<DnsAns>, flagsExtra: Int = 0): ByteArray {
    val (_, p) = DnsWire.readName(q, 12); val qEnd = p + 4
    val bo = java.io.ByteArrayOutputStream()
    val head = ByteBuffer.allocate(12).apply { put(q[0]); put(q[1]); putShort((0x8180 or rcode or flagsExtra).toShort()); putShort(1); putShort(answers.size.toShort()); putShort(0); putShort(0) }.array()
    bo.write(head); bo.write(q, 12, qEnd - 12)
    for (a in answers) {
        val (type, rdata) = when (a) {
            is DnsAns.A -> 1 to java.net.InetAddress.getByName(a.ip).address
            is DnsAns.AAAA -> 28 to java.net.InetAddress.getByName(a.ip).address
            is DnsAns.MX -> 15 to (byteArrayOf((a.pref shr 8).toByte(), a.pref.toByte()) + dnsName(a.host))
            is DnsAns.PTR -> 12 to dnsName(a.host)
            is DnsAns.NS -> 2 to dnsName(a.host)
            is DnsAns.CNAME -> 5 to dnsName(a.target)
            is DnsAns.TXT -> { val b = a.text.toByteArray(); val chunks = b.toList().chunked(255).map { c -> byteArrayOf(c.size.toByte()) + c.toByteArray() }; 16 to chunks.fold(ByteArray(0)) { x, y -> x + y } }
            is DnsAns.RAW -> a.type to a.data
        }
        bo.write(byteArrayOf(0xC0.toByte(), 0x0C)); bo.write(ByteBuffer.allocate(10).apply { putShort(type.toShort()); putShort(1); putInt(60); putShort(rdata.size.toShort()) }.array()); bo.write(rdata)
    }
    return bo.toByteArray()
}

/** handler(이름, 종류) → (rcode, 답) 을 돌려주는 가짜 DNS. server 는 "127.0.0.1#포트" 로 씀 */
class TestDns(private val extraFlags: (String) -> Int = { 0 }, private val handler: (String, Int) -> Pair<Int, List<DnsAns>>) : Closeable {
    private val udp = TestUdp { p, sock ->
        val q = p.data.copyOf(p.length)
        val (name, pos) = DnsWire.readName(q, 12)
        val type = ((q[pos].toInt() and 0xff) shl 8) or (q[pos + 1].toInt() and 0xff)
        val (rc, ans) = handler(name.lowercase(), type)
        val r = dnsReply(q, rc, ans, extraFlags(name.lowercase())); sock.send(DatagramPacket(r, r.size, p.socketAddress))
    }
    val port: Int get() = udp.port
    val server: String get() = "127.0.0.1#$port"
    val queries: List<Pair<String, Int>> get() = udp.received.map { q -> val (n, p) = DnsWire.readName(q, 12); n.lowercase() to (((q[p].toInt() and 0xff) shl 8) or (q[p + 1].toInt() and 0xff)) }
    override fun close() = udp.close()
}


/** 시험용 TLS 서버 키 저장소 (keytool 로 만든 시험 전용, 비밀번호 changeit, CN=localhost, SAN localhost·127.0.0.1) */
const val TEST_SRV_P12 = "MIIEOgIBAzCCA+QGCSqGSIb3DQEHAaCCA9UEggPRMIIDzTCCASQGCSqGSIb3DQEHAaCCARUEggERMIIBDTCCAQkGCyqGSIb3" +
    "DQEMCgECoIG9MIG6MGYGCSqGSIb3DQEFDTBZMDgGCSqGSIb3DQEFDDArBBREC1Pd4+UKWIKeYHj5H3BjUhYtVAICJxACASAw" +
    "DAYIKoZIhvcNAgkFADAdBglghkgBZQMEASoEEJQuElJ9fvjFHGGIerAcRlAEUJFztwLf+WmL3WWWmgh5WMIGwELUPlB1UKqc" +
    "IzzZ/JTCuqUgKuW3CjpsMaXIv9o/Id8C7toq45zvH4rx/naM97IX7bm/F3l79r6HCHUI+iGsMTowFQYJKoZIhvcNAQkUMQge" +
    "BgBzAHIAdjAhBgkqhkiG9w0BCRUxFAQSVGltZSAxNzk1NjgzMDczNjMyMIICoQYJKoZIhvcNAQcGoIICkjCCAo4CAQAwggKH" +
    "BgkqhkiG9w0BBwEwZgYJKoZIhvcNAQUNMFkwOAYJKoZIhvcNAQUMMCsEFJkreWEA8j5+wjCbNeO8VqcbLzGgAgInEAIBIDAM" +
    "BggqhkiG9w0CCQUAMB0GCWCGSAFlAwQBKgQQmGYNCAldvpvawO8uNN6TTICCAhBVwjkmVGy3gskPcnLNhhW778nFmq0NTzoj" +
    "IKV5Sk1lccoFE5+sBqz5qNg803z/qlc3DeDYgeCCvl0Bcjj9q0yMC1roiOeFVIExcriqupM/VMjtMypJSIOjz76RXvG/wJmf" +
    "yoeOrX3iXZkz6v7j6AqNKZGf5obB/jogueoE8oMdYPDLCHwqSfjKI3PY1IZC2hkoeJalztD9pjQysg8IDQWv94oLwPkqZKpu" +
    "DMT2Cv0pSmEh7R3NyfY8kEgu1zsLzal8DnrOKkNwDkh+/9/hIoiOWdtodznxLiJI/0rgbgEodvpnYz0V2sFko1sdRHU0io2v" +
    "cNkt1qgUONDO3D3mLX0rKKqnFgwgQHLEiyiE+2MMdNcm51zABcBSYxIlhjZ78E4MbpLoa3m0SiDDtoWknF9rGEPxs/DvvjJO" +
    "nKLavhDy7ENbQkMg6eTaQX6U4MA8MvTZh8sWn7DKpGE7LlkFwzdrrMvv96D0SHDfofF5iyivTfGMkU0VMC9XG7defLNz5IXj" +
    "RvI4jAEi44qdRO9vh8JRZ6anWE4qMZm/VtzJ5lYNXf0KpSA3vPETWNKBtTu1wg7mnbsFQQhu5Nds7uuFCLgJ6nwLNOYwE+8W" +
    "LTE++u4Jwze/1yS2gFBvphdfsP5gLoxG29uQZaOpAaUXTiBbrcIcygpdOBSbvN8L6NfxzCgGoQX6wBxxDAGsGFYMFbgm9GIw" +
    "TTAxMA0GCWCGSAFlAwQCAQUABCCKrJDk8DNMKv51eqOR4M526kNZ4i5spUk0AqyjZOTnAAQURnbTI6xefCt1p8FuvYgxuyDI" +
    "7oECAicQ"

fun testServerTls(): javax.net.ssl.SSLContext {
    val pw = "changeit".toCharArray()
    val ks = java.security.KeyStore.getInstance("PKCS12").apply { load(java.io.ByteArrayInputStream(java.util.Base64.getDecoder().decode(TEST_SRV_P12)), pw) }
    val kmf = javax.net.ssl.KeyManagerFactory.getInstance(javax.net.ssl.KeyManagerFactory.getDefaultAlgorithm()).apply { init(ks, pw) }
    return javax.net.ssl.SSLContext.getInstance("TLS").apply { init(kmf.keyManagers, null, null) }
}

/** 이미 연결된 소켓을 TLS 서버 쪽으로 바꿈 (STARTTLS 시험용) */
fun upgradeServerTls(s: java.net.Socket, ctx: javax.net.ssl.SSLContext = testServerTls()): javax.net.ssl.SSLSocket =
    (ctx.socketFactory.createSocket(s, null, s.port, true) as javax.net.ssl.SSLSocket).apply { useClientMode = false; startHandshake() }

/** 줄바꿈까지 한 줄 읽기 (버퍼 없이 한 바이트씩: TLS 로 바꿀 때 데이터가 남지 않게) */
fun readLineRaw(ins: java.io.InputStream): String? {
    val sb = StringBuilder()
    while (true) { val c = ins.read(); if (c < 0) return if (sb.isEmpty()) null else sb.toString(); if (c == '\n'.code) return sb.toString().trimEnd('\r'); sb.append(c.toChar()) }
}

// NTP 시각 변환 (1900-01-01 기준 초 + 2^-32 초 단위)
private const val NTP_EPOCH_T = 2208988800L
fun ntpMsOf(b: ByteArray, off: Int): Double { val v = ByteBuffer.wrap(b).getLong(off); return (((v ushr 32) and 0xFFFFFFFFL) - NTP_EPOCH_T) * 1000.0 + (v and 0xFFFFFFFFL) * 1000.0 / 4294967296.0 }
fun ntpOfMs(ms: Double): Long { val sec = Math.floor(ms / 1000.0).toLong(); val frac = ((ms / 1000.0 - sec) * 4294967296.0).toLong(); return ((sec + NTP_EPOCH_T) shl 32) or (frac and 0xFFFFFFFFL) }

/** 실제 시계보다 offsetMs 만큼 앞선 시각을 알려 주는 가짜 NTP 서버 */
class TestNtp(val offsetMs: Double = 0.0, val stratum: Int = 2) : Closeable {
    private val sock = DatagramSocket(0, LOOP)
    val port: Int = sock.localPort
    init {
        thread(isDaemon = true) {
            val buf = ByteArray(128)
            while (true) {
                val p = DatagramPacket(buf, buf.size)
                try { sock.receive(p) } catch (_: IOException) { break }
                if (p.length < 48) continue
                val req = buf.copyOf(p.length); val t1 = ntpMsOf(req, 40)
                val resp = ByteArray(48); resp[0] = 0x1C; resp[1] = stratum.toByte(); resp[12] = 10; resp[15] = 1
                System.arraycopy(req, 40, resp, 24, 8)
                val t2 = t1 + 5.0 + offsetMs
                ByteBuffer.wrap(resp).putLong(32, ntpOfMs(t2)).putLong(40, ntpOfMs(t2))
                try { sock.send(DatagramPacket(resp, resp.size, p.socketAddress)) } catch (_: IOException) {}
            }
        }
    }
    override fun close() { sock.close() }
}
