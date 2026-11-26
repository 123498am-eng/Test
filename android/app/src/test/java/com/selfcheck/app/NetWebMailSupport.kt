package com.selfcheck.app

import java.io.ByteArrayOutputStream
import java.io.Closeable
import java.io.IOException
import java.io.OutputStream
import java.net.ServerSocket
import java.net.Socket
import java.nio.ByteBuffer
import java.util.concurrent.CopyOnWriteArrayList
import java.util.concurrent.atomic.AtomicInteger
import java.util.zip.GZIPOutputStream
import javax.net.ssl.SSLSocket
import kotlin.concurrent.thread

/*
 * 웹·메일 도구 시험용 공용 도구: 결과 읽기 도우미, 자체 서명 인증서를 쓰는 가짜 HTTPS 서버(ALPN 선택 가능),
 * 이름·종류별로 답을 만들어 주는 가짜 DNS 영역(FakeZone).
 */

// ---------------------------------------------------------------------------------------------
// 도구 결과 읽기

fun ToolResult.kv(label: String): String = (outs.firstOrNull { it is Out.Kv && it.label == label } as? Out.Kv)?.value ?: error("'$label' 줄이 없음:\n${text()}")
fun ToolResult.kvLevel(label: String): Int = (outs.firstOrNull { it is Out.Kv && it.label == label } as? Out.Kv)?.level ?: error("'$label' 줄이 없음:\n${text()}")
fun ToolResult.kvAll(label: String): List<String> = outs.filterIsInstance<Out.Kv>().filter { it.label == label }.map { it.value }
fun ToolResult.hasKv(label: String): Boolean = outs.any { it is Out.Kv && it.label == label }
fun ToolResult.cols(): List<Out.Cols> = outs.filterIsInstance<Out.Cols>().filter { !it.header }
fun ToolResult.rows(): List<List<String>> = cols().map { it.cells }
fun ToolResult.row(first: String): List<String> = rows().firstOrNull { it[0] == first } ?: error("'$first' 행이 없음:\n${text()}")
fun ToolResult.rowLevel(first: String): Int = cols().firstOrNull { it.cells[0] == first }?.level ?: error("'$first' 행이 없음:\n${text()}")
fun ToolResult.notes(): List<Out.Note> = outs.filterIsInstance<Out.Note>()
fun ToolResult.noteWith(fragment: String): Out.Note? = notes().firstOrNull { fragment in it.text }
fun ToolResult.blocks(): String = outs.filterIsInstance<Out.Block>().joinToString("\n") { it.text }

// ---------------------------------------------------------------------------------------------
// 가짜 HTTPS 서버

/**
 * 127.0.0.1 에 열리는 가짜 HTTPS 서버. 인증서는 시험용 자체 서명이라 "믿을 수 없는 인증서"로 보임.
 * alpn 을 주면 TLS 협상에서 그 프로토콜들(서버 선호 순서)을 알려 줌.
 */
class TestHttps(private val alpn: List<String> = emptyList(), private val handler: (TestReq, OutputStream) -> Unit = { _, out -> out.respond("200 OK", body = "ok".toByteArray()) }) : Closeable {
    private val ss = ServerSocket(0, 50, LOOP)
    private val ctx = testServerTls()
    val port: Int = ss.localPort
    val handshakes = AtomicInteger()
    val requests = CopyOnWriteArrayList<TestReq>()

    init {
        thread(isDaemon = true) {
            while (true) {
                val c = try { ss.accept() } catch (_: IOException) { break }
                thread(isDaemon = true) { serve(c) }
            }
        }
    }

    private fun serve(c: Socket) {
        try {
            c.soTimeout = 5000
            val ssl = ctx.socketFactory.createSocket(c, null, c.port, true) as SSLSocket
            ssl.useClientMode = false
            if (alpn.isNotEmpty()) ssl.sslParameters = ssl.sslParameters.also { it.applicationProtocols = alpn.toTypedArray() }
            ssl.startHandshake(); handshakes.incrementAndGet()
            val ins = ssl.inputStream
            val first = readLineRaw(ins) ?: return                 // 핸드셰이크만 하고 닫는 손님(ALPN 시험)은 여기서 끝
            val parts = first.split(' ')
            val hs = LinkedHashMap<String, String>()
            while (true) { val l = readLineRaw(ins) ?: break; if (l.isEmpty()) break; hs[l.substringBefore(':').trim().lowercase()] = l.substringAfter(':').trim() }
            val req = TestReq(parts[0], parts.getOrElse(1) { "/" }, hs, ByteArray(0)); requests += req
            handler(req, ssl.outputStream); ssl.outputStream.flush()
        } catch (_: Throwable) {
        } finally { runCatching { c.close() } }
    }

    override fun close() { runCatching { ss.close() } }
}

fun gzipOf(b: ByteArray): ByteArray { val bo = ByteArrayOutputStream(); GZIPOutputStream(bo).use { it.write(b) }; return bo.toByteArray() }

// ---------------------------------------------------------------------------------------------
// 가짜 DNS 영역

/**
 * 이름·종류별 답을 모아 둔 가짜 영역. TestDns 의 handler 로 씀.
 * - 이름이 있고 그 종류가 있으면 그 답
 * - 이름이 CNAME 이면 (CNAME 이 아닌 질문에는) 진짜 DNS 처럼 CNAME 을 답
 * - 이름은 있는데 그 종류가 없으면 NODATA(코드 0, 답 없음), 이름이 아예 없으면 NXDOMAIN(코드 3)
 */
class FakeZone {
    private val recs = ArrayList<Triple<String, Int, DnsAns>>()
    fun a(n: String, ip: String) = apply { recs += Triple(n, DnsType.A, DnsAns.A(ip)) }
    fun aaaa(n: String, ip: String) = apply { recs += Triple(n, DnsType.AAAA, DnsAns.AAAA(ip)) }
    fun mx(n: String, pref: Int, h: String) = apply { recs += Triple(n, DnsType.MX, DnsAns.MX(pref, h)) }
    fun txt(n: String, t: String) = apply { recs += Triple(n, DnsType.TXT, DnsAns.TXT(t)) }
    fun cname(n: String, t: String) = apply { recs += Triple(n, DnsType.CNAME, DnsAns.CNAME(t)) }
    fun ptr(n: String, h: String) = apply { recs += Triple(n, DnsType.PTR, DnsAns.PTR(h)) }
    fun ns(n: String, h: String) = apply { recs += Triple(n, DnsType.NS, DnsAns.NS(h)) }
    fun raw(n: String, type: Int, data: ByteArray) = apply { recs += Triple(n, type, DnsAns.RAW(type, data)) }

    fun answer(name: String, type: Int): Pair<Int, List<DnsAns>> {
        val hits = recs.filter { it.first == name && it.second == type }.map { it.third }
        if (hits.isNotEmpty()) return 0 to hits
        if (type != DnsType.CNAME) recs.firstOrNull { it.first == name && it.second == DnsType.CNAME }?.let { return 0 to listOf(it.third) }
        return (if (recs.any { it.first == name }) 0 else 3) to emptyList()
    }
}

/** SOA 레코드 데이터 (주 서버, 담당자, 일련번호, 갱신 7200, 재시도 3600, 만료 1209600, 최소 300) */
fun soaData(serial: Long, mname: String = "ns1.example.net", rname: String = "hostmaster.example.net"): ByteArray =
    dnsName(mname) + dnsName(rname) + ByteBuffer.allocate(20).apply { putInt(serial.toInt()); putInt(7200); putInt(3600); putInt(1209600); putInt(300) }.array()
