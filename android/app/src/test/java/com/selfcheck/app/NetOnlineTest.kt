package com.selfcheck.app

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Test
import java.io.BufferedInputStream
import java.io.BufferedOutputStream
import java.io.ByteArrayInputStream
import java.io.Closeable
import java.io.IOException
import java.io.InputStream
import java.io.OutputStream
import java.net.DatagramPacket
import java.net.DatagramSocket
import java.net.InetAddress
import java.net.ServerSocket
import java.net.Socket
import java.nio.ByteBuffer
import java.security.KeyStore
import java.security.cert.CertificateFactory
import java.security.cert.X509Certificate
import java.util.Base64
import java.util.concurrent.CopyOnWriteArrayList
import java.util.concurrent.atomic.AtomicBoolean
import javax.net.ssl.KeyManagerFactory
import javax.net.ssl.SSLContext
import javax.net.ssl.SSLServerSocket
import kotlin.concurrent.thread

/*
 * 접속 진단 엔진 시험. 컴퓨터 안(127.0.0.1)에 가짜 서버를 열어 두고
 * MiniHttp · TLS · NTP · 핑 해석 · SSDP · WoL · NetBIOS · WHOIS · 속도 측정과, 그 위에 만든 도구들을 확인합니다.
 * 인터넷에는 접속하지 않아요. (진짜 인터넷 서버와의 동작은 휴대폰에서만 확인할 수 있어요.)
 */

private val LO: InetAddress = InetAddress.getByName("127.0.0.1")

// 시험용 인증서 (openssl / keytool 로 만든 시험 전용. 비밀번호 changeit)
private const val SRV_P12 = "MIIEOgIBAzCCA+QGCSqGSIb3DQEHAaCCA9UEggPRMIIDzTCCASQGCSqGSIb3DQEHAaCCARUEggERMIIBDTCCAQkGCyqGSIb3" +
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
private const val OLD_P12 = "MIID+gIBAzCCA6QGCSqGSIb3DQEHAaCCA5UEggORMIIDjTCCASQGCSqGSIb3DQEHAaCCARUEggERMIIBDTCCAQkGCyqGSIb3" +
    "DQEMCgECoIG9MIG6MGYGCSqGSIb3DQEFDTBZMDgGCSqGSIb3DQEFDDArBBQHx9agl4njO1xVOXwyFmQ45MxdyAICJxACASAw" +
    "DAYIKoZIhvcNAgkFADAdBglghkgBZQMEASoEEGT5lhx3VQ/CgWwSfz1AM7MEUFTkS9A8NxqmMu6l0tDkbO1P1QX9+tO3C/iK" +
    "abMswYdSK1ECwGTh9Sn/0mPMBNh6a9lWQoLnF4NyeUQKUejBAHMQ3oMyN5u3rwVFTJ//3oI0MTowFQYJKoZIhvcNAQkUMQge" +
    "BgBvAGwAZDAhBgkqhkiG9w0BCRUxFAQSVGltZSAxNzk1NjgzMDc0MDE5MIICYQYJKoZIhvcNAQcGoIICUjCCAk4CAQAwggJH" +
    "BgkqhkiG9w0BBwEwZgYJKoZIhvcNAQUNMFkwOAYJKoZIhvcNAQUMMCsEFBgS7DzeKslrFTy1DFuw+OMedvdUAgInEAIBIDAM" +
    "BggqhkiG9w0CCQUAMB0GCWCGSAFlAwQBKgQQ5JPvM0dbfFq8jy7Llme9rYCCAdCGyoPkMEgls908KwsDLpWcMjDlQTM74C9g" +
    "h0qRYyHhTmgd8KilOE/cWuEHEmJoVLfNPbwcGwraq+9TdK+tyO4cnanOGEqkyl+I5gi3rPvbgE6AV5u7gAmX49vZ8Bmdk+9R" +
    "Cs/vDe1FUV7Mi7sDLeSkn6dZV7WKqqQ2hUd+A1jpnX9VhlBgPEE6QyQ8i2X8mrRbAeRKiqeGZLzVBvds5m8fAcJ0LO7pOjrx" +
    "YjMJtMVu5aqdDz1oxjXdQFFiRmyTpqkntbGezpybfeXBBncFb+PycEulpRIhcf9vziLx5RPamd3ySBPieI9uWOg4c/yW1VBH" +
    "sJGNj9FzUty93flD2XbtYtYSYEZv/w/jJe4nDSFKDKUM1LDj//cFadqburKEb2egC5+tbWNalvtW3V00qgxhkymzTNqrZVf6" +
    "kkt/T0W4QlwqEtZWRIJsjJM7AHcev9XqxS3fHN86HMxeHtdDsgPYj/GHTGviyn6T+ET6NRMLA1vXu7YsaL+ZxTJci/hm4LDK" +
    "XlyM8j3avpnY1i08QbfTce80vTZgkWqHjNu4iAsYDqiD5DKzKwlEscLvHxmv69PxSBQGJMClq0DAhBbXzKp6+BwwHc3hNkRN" +
    "JY+aPFWEFjBNMDEwDQYJYIZIAWUDBAIBBQAEIPQIDVxS6XzVOxDay9YmAGUpzYc4vHTLDy4PkXE6iVMYBBTI/3kLMaLAaTcr" +
    "KbSQRy1FwV7uOAICJxA="
private const val WILD_PEM = "-----BEGIN CERTIFICATE-----\n" +
    "MIIB0TCCAXagAwIBAgIUd3zd6p6TelrqDhrESswMMxinntAwCgYIKoZIzj0EAwIw\n" +
    "KTEUMBIGA1UEAwwLZXhhbXBsZS5jb20xETAPBgNVBAoMCFRlc3QgT3JnMCAXDTI2\n" +
    "MTEyNjA4NTExM1oYDzIxMjYxMTAyMDg1MTEzWjApMRQwEgYDVQQDDAtleGFtcGxl\n" +
    "LmNvbTERMA8GA1UECgwIVGVzdCBPcmcwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNC\n" +
    "AAQjNVrMma+Zfk79BpSnlcbQS2pH6wATG+nfDd11mllVJIHRceZum275GGHzPqDa\n" +
    "p7mzA7J/ABXyXp6tZ4QXbAjuo3oweDAdBgNVHQ4EFgQUrW+NY2BlfaicD8S+CvBv\n" +
    "bX6QyYgwHwYDVR0jBBgwFoAUrW+NY2BlfaicD8S+CvBvbX6QyYgwDwYDVR0TAQH/\n" +
    "BAUwAwEB/zAlBgNVHREEHjAcgg0qLmV4YW1wbGUuY29tggtleGFtcGxlLmNvbTAK\n" +
    "BggqhkjOPQQDAgNJADBGAiEA1QtMQXmuEQpzPuJVz298G0lrFCp+O9Gqz1bY6ltt\n" +
    "etQCIQC25jhQP+U0dAv7Vx7heqqtF2J/o69BFRVVKMNSNtQ+dw==\n" +
    "-----END CERTIFICATE-----\n"
private const val CNONLY_PEM = "-----BEGIN CERTIFICATE-----\n" +
    "MIIBkDCCATegAwIBAgIUd6MK2T3KHCz4s7Z6HufrfWmHOCYwCgYIKoZIzj0EAwIw\n" +
    "HTEbMBkGA1UEAwwSbGVnYWN5LmV4YW1wbGUub3JnMCAXDTI2MTEyNjA4NTExM1oY\n" +
    "DzIxMjYxMTAyMDg1MTEzWjAdMRswGQYDVQQDDBJsZWdhY3kuZXhhbXBsZS5vcmcw\n" +
    "WTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAATXfwm6T9pfoGa7Ae/InS9PSk7sHHu2\n" +
    "IH+7UhQv+w+w4QSPBsK+bpK+Nfn/uxRAqXvYMgLsfGDItBTgcCe/uf8Go1MwUTAd\n" +
    "BgNVHQ4EFgQUorWbIj5qFCN0Nu1XCcwBMrVZIE8wHwYDVR0jBBgwFoAUorWbIj5q\n" +
    "FCN0Nu1XCcwBMrVZIE8wDwYDVR0TAQH/BAUwAwEB/zAKBggqhkjOPQQDAgNHADBE\n" +
    "AiBkuwUu2VHt7iA6EMI711ft1N5KgXKmsKF6aCwSBNjnkgIgNTKR57emD5V7Pft8\n" +
    "R7aBfZ60M8P/FTRa79FNE7TMWPk=\n" +
    "-----END CERTIFICATE-----\n"
private const val IP_PEM = "-----BEGIN CERTIFICATE-----\n" +
    "MIIBrDCCAVKgAwIBAgIUGIdDqxt5nz4Su/l6Oq95suKNKdswCgYIKoZIzj0EAwIw\n" +
    "ETEPMA0GA1UEAwwGcm91dGVyMCAXDTI2MTEyNjA4NTExM1oYDzIxMjYxMTAyMDg1\n" +
    "MTEzWjARMQ8wDQYDVQQDDAZyb3V0ZXIwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNC\n" +
    "AATvAkX/ymRKrFoYgXMcN++p+v34+6nnbQ/GCXmOL0t56CNOmQw3hQfzdVI1btDU\n" +
    "SXWU+MIkrmb/9pXFiEYxHHFpo4GFMIGCMB0GA1UdDgQWBBSM8FOCcpZfbjxxc1Rl\n" +
    "h6Uzl+yzODAfBgNVHSMEGDAWgBSM8FOCcpZfbjxxc1Rlh6Uzl+yzODAPBgNVHRMB\n" +
    "Af8EBTADAQH/MC8GA1UdEQQoMCaHBMCoAAGHECABDbgAAAAAAAAAAAAAAAGCDHJv\n" +
    "dXRlci5sb2NhbDAKBggqhkjOPQQDAgNIADBFAiEAueA9UwRBj+itm6WG28vbq43b\n" +
    "rctdYSZ7Kf72vysSSlQCIF+F0dDfPrYTUppE1viEoSyJMOSmpk72XWDBgE7htU6c\n" +
    "-----END CERTIFICATE-----\n"

// Python 으로 직접 만든 NetBIOS 이름 응답 (질문 0개 / 질문 되돌려 보내는 1개)
private const val NB0 = "42428400000000010000000020434b4141414141414141414141414141414141414141414141414141414141410000210001000000000077044d5950432020202020202020202020000400574f524b47524f55502020202020200084004d5950432020202020202020202020200400574f524b47524f55502020202020201e8400aabbccddeeff00000000000000000000000000000000000000000000000000000000000000000000000000000000"
private const val NB1 = "42428400000100010000000020434b414141414141414141414141414141414141414141414141414141414141000021000120434b4141414141414141414141414141414141414141414141414141414141410000210001000000000077044d5950432020202020202020202020000400574f524b47524f55502020202020200084004d5950432020202020202020202020200400574f524b47524f55502020202020201e8400aabbccddeeff00000000000000000000000000000000000000000000000000000000000000000000000000000000"

private fun hex(s: String): ByteArray = ByteArray(s.length / 2) { s.substring(it * 2, it * 2 + 2).toInt(16).toByte() }

private fun serverTls(b64: String): SSLContext {
    val pw = "changeit".toCharArray()
    val ks = KeyStore.getInstance("PKCS12").apply { load(ByteArrayInputStream(Base64.getDecoder().decode(b64)), pw) }
    val kmf = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm()).apply { init(ks, pw) }
    return SSLContext.getInstance("TLS").apply { init(kmf.keyManagers, null, null) }
}

private fun pem(s: String): X509Certificate = CertificateFactory.getInstance("X.509").generateCertificate(ByteArrayInputStream(s.toByteArray())) as X509Certificate

private class NetReq(val method: String, val target: String, val headers: Map<String, String>, val body: ByteArray) {
    val path: String get() = target.substringBefore('?')
    val query: String get() = target.substringAfter('?', "")
}

private fun OutputStream.reply(status: String, vararg headers: String, body: ByteArray = ByteArray(0), length: Boolean = true) {
    val sb = StringBuilder("HTTP/1.1 $status\r\n")
    for (h in headers) sb.append(h).append("\r\n")
    if (length) sb.append("Content-Length: ${body.size}\r\n")
    sb.append("Connection: close\r\n\r\n")
    write(sb.toString().toByteArray(Charsets.ISO_8859_1)); write(body); flush()
}

/** 127.0.0.1 에 열리는 가짜 웹 서버 (TLS 도 가능). 요청마다 handler 가 직접 응답 바이트를 씀 */
private class NetFakeHttp(tls: SSLContext? = null, protocols: Array<String>? = null, private val handler: (NetReq, OutputStream) -> Unit) : Closeable {
    private val ss: ServerSocket =
        if (tls != null) (tls.serverSocketFactory.createServerSocket(0, 50, LO) as SSLServerSocket).also { s -> protocols?.let { s.enabledProtocols = it } }
        else ServerSocket(0, 50, LO)
    val port: Int = ss.localPort
    val requests = CopyOnWriteArrayList<NetReq>()

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
            val req = NetReq(parts[0], parts.getOrElse(1) { "/" }, hs, body); requests += req
            handler(req, out); out.flush()
        } catch (_: Throwable) {
        } finally { runCatching { c.close() } }
    }

    fun url(path: String = "/") = "http://127.0.0.1:$port$path"
    override fun close() { runCatching { ss.close() } }
}

/** 127.0.0.1 UDP 가짜 서버: 받은 글을 기록하고 reply 가 원하는 대로 답함 */
private class NetFakeUdp(private val reply: (DatagramPacket, DatagramSocket) -> Unit = { _, _ -> }) : Closeable {
    val sock = DatagramSocket(0, LO)
    val port: Int = sock.localPort
    val received = CopyOnWriteArrayList<ByteArray>()

    init {
        thread(isDaemon = true) {
            val buf = ByteArray(2048)
            while (true) {
                val p = DatagramPacket(buf, buf.size)
                try { sock.receive(p) } catch (_: IOException) { break }
                received += buf.copyOf(p.length)
                try { reply(p, sock) } catch (_: IOException) {}
            }
        }
    }

    override fun close() { sock.close() }
}

/** 한 줄 질문에 글로 답하는 가짜 WHOIS 서버 (TCP 43 번 대신) */
private class NetFakeWhois(private val answer: (String) -> ByteArray) : Closeable {
    private val ss = ServerSocket(0, 10, LO)
    val port: Int = ss.localPort
    val queries = CopyOnWriteArrayList<String>()

    init {
        thread(isDaemon = true) {
            while (true) {
                val c = try { ss.accept() } catch (_: IOException) { break }
                thread(isDaemon = true) {
                    try {
                        c.use { s ->
                            s.soTimeout = 3000
                            val line = s.getInputStream().bufferedReader(Charsets.ISO_8859_1).readLine() ?: return@use
                            queries += line
                            s.getOutputStream().apply { write(answer(line)); flush() }
                        }
                    } catch (_: Throwable) {}
                }
            }
        }
    }

    override fun close() { runCatching { ss.close() } }
}

// NTP 시각 변환 (시험 쪽에서 따로 구현: 1900-01-01 기준 초 + 2^-32 초 단위 소수)
private const val NTP_EPOCH = 2208988800L
private fun ntpToMs(b: ByteArray, off: Int): Double {
    val v = ByteBuffer.wrap(b).getLong(off)
    return (((v ushr 32) and 0xFFFFFFFFL) - NTP_EPOCH) * 1000.0 + (v and 0xFFFFFFFFL) * 1000.0 / 4294967296.0
}
private fun msToNtp(ms: Double): Long {
    val sec = Math.floor(ms / 1000.0).toLong()
    val frac = ((ms / 1000.0 - sec) * 4294967296.0).toLong()
    return ((sec + NTP_EPOCH) shl 32) or (frac and 0xFFFFFFFFL)
}

private class NetFakeNtp(
    val offsetMs: Double = 0.0, val stratum: Int = 2, val mode: Int = 4, val refId: ByteArray = byteArrayOf(10, 0, 0, 1), val oneWayMs: Double = 10.0,
    val badOriginate: Boolean = false, val shortReply: Boolean = false, val silent: Boolean = false,
) : Closeable {
    private val sock = DatagramSocket(0, LO)
    val port: Int = sock.localPort

    init {
        thread(isDaemon = true) {
            val buf = ByteArray(128)
            while (true) {
                val p = DatagramPacket(buf, buf.size)
                try { sock.receive(p) } catch (_: IOException) { break }
                if (silent || p.length < 48) continue
                val req = buf.copyOf(p.length); val t1 = ntpToMs(req, 40)
                val resp = ByteArray(48)
                resp[0] = ((3 shl 3) or mode).toByte(); resp[1] = stratum.toByte(); for (k in 0 until 4) resp[12 + k] = refId[k]
                System.arraycopy(req, 40, resp, 24, 8)                                    // 내가 보낸 시각을 되돌려 줌
                if (badOriginate) ByteBuffer.wrap(resp).putLong(24, msToNtp(t1 + 60000.0))
                val t2 = t1 + oneWayMs + offsetMs
                ByteBuffer.wrap(resp).putLong(32, msToNtp(t2)).putLong(40, msToNtp(t2))
                val out = if (shortReply) resp.copyOf(20) else resp
                try { sock.send(DatagramPacket(out, out.size, p.socketAddress)) } catch (_: IOException) {}
            }
        }
    }

    override fun close() { sock.close() }
}

private fun runTool(id: String, vararg kv: Pair<String, String>, host: ToolHost = NoHost): ToolResult {
    val t = NetToolbox.byId(id) ?: throw AssertionError("도구가 없어요: $id")
    val values = t.fields.associate { it.key to it.default } + kv
    return t.run(ToolInput(values), host, ToolEnv())
}

class NetOnlineTest {

    // ------------------------------------------------------------------------------ 주소 읽기

    @Test fun parseUrl_variants() {
        val a = MiniHttp.parseUrl("example.com")!!
        assertEquals("https", a.scheme); assertEquals(443, a.port); assertEquals("/", a.path)
        val b = MiniHttp.parseUrl("http://Example.com:8080/a/b?x=1#frag")!!
        assertEquals("http", b.scheme); assertEquals("Example.com", b.host); assertEquals(8080, b.port); assertEquals("/a/b?x=1", b.path)
        assertEquals("http://Example.com:8080/a/b?x=1", b.toString())
        val c = MiniHttp.parseUrl("https://[2001:db8::1]:8443/x")!!
        assertEquals("2001:db8::1", c.host); assertEquals(8443, c.port); assertEquals("https://[2001:db8::1]:8443/x", c.toString())
        assertEquals("/?q=1", MiniHttp.parseUrl("http://example.com?q=1")!!.path)
        assertNull(MiniHttp.parseUrl("http://")); assertNull(MiniHttp.parseUrl("http://example.com:99999/")); assertNull(MiniHttp.parseUrl("ftp://example.com"))
        assertEquals("a" to "b c", MiniHttp.parseHeaderLine("a:  b c "))
        assertNull(MiniHttp.parseHeaderLine(":bad")); assertNull(MiniHttp.parseHeaderLine("nocolon"))
    }

    @Test fun hostPort_variants() {
        assertEquals("example.com" to 443, DiagTools.hostPort("example.com"))
        assertEquals("example.com" to 8443, DiagTools.hostPort("https://example.com:8443/path?x#y"))
        assertEquals("example.com" to 8443, DiagTools.hostPort("example.com:8443"))
        assertEquals("::1" to 8443, DiagTools.hostPort("[::1]:8443"))
        assertEquals("2001:db8::1" to 443, DiagTools.hostPort("[2001:db8::1]"))
        assertEquals("2001:db8::1" to 443, DiagTools.hostPort("2001:db8::1"))
        assertEquals("host" to 443, DiagTools.hostPort("user@host:99999"))
        assertEquals("Example.COM" to 443, DiagTools.hostPort("Example.COM."))
        assertEquals("a.b" to 25, DiagTools.hostPort("a.b", 25))
    }

    // ------------------------------------------------------------------------------ MiniHttp

    @Test fun miniHttp_basicResponse() {
        val body = "<html><head><title>  테스트   페이지 </title></head><body>안녕</body></html>".toByteArray()
        NetFakeHttp { _, out -> out.reply("200 OK", "Content-Type: text/html; charset=utf-8", "Server: nginx/1.18.0", body = body) }.use { srv ->
            val r = MiniHttp.request(srv.url("/hello?x=1"), maxBody = 4096, headers = mapOf("X-Test" to "1"))
            assertEquals(200, r.status); assertEquals("HTTP/1.1 200 OK", r.statusLine)
            assertEquals("nginx/1.18.0", r.header("server")); assertEquals(String(body), r.body)
            assertEquals("테스트 페이지", DiagTools.titleOf(r.body))
            assertEquals("127.0.0.1", r.remoteIp); assertNull(r.tls); assertFalse(r.isRedirect)
            assertTrue(r.timings.totalMs >= 0 && r.timings.ttfbMs >= r.timings.connectMs && r.timings.totalMs + 2 >= r.timings.ttfbMs)
            val q = srv.requests.single()
            assertEquals("GET", q.method); assertEquals("/hello?x=1", q.target); assertEquals("127.0.0.1:${srv.port}", q.headers["host"])
            assertTrue(q.headers["user-agent"]!!.startsWith("SelfCheck")); assertEquals("1", q.headers["x-test"]); assertEquals("close", q.headers["connection"])
        }
    }

    @Test fun miniHttp_chunkedBody() {
        NetFakeHttp { _, out ->
            out.write(("HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n" + "5;ext=1\r\nhello\r\n" + "A\r\n, chunked!\r\n" + "0\r\n\r\n").toByteArray()); out.flush()
        }.use { srv ->
            assertEquals("hello, chunked!", MiniHttp.request(srv.url(), maxBody = 4096).body)
            assertEquals("hello, ch", MiniHttp.request(srv.url(), maxBody = 9).body)       // 상한에서 자름
        }
    }

    @Test fun miniHttp_headNoBodyAnd204() {
        NetFakeHttp { req, out ->
            if (req.method == "HEAD") out.reply("200 OK", "Content-Length: 1234", length = false)
            else out.reply("204 No Content", length = false)
        }.use { srv ->
            val h = MiniHttp.request(srv.url(), "HEAD", maxBody = 100)
            assertEquals(200, h.status); assertNull(h.body); assertEquals("1234", h.header("Content-Length"))
            assertEquals(204, MiniHttp.request(srv.url(), "GET", maxBody = 100).status)
        }
    }

    @Test fun miniHttp_bodyCappedAndMultiHeaders() {
        NetFakeHttp { _, out -> out.reply("200 OK", "Set-Cookie: a=1; Secure; HttpOnly", "Set-Cookie: b=2", body = ByteArray(100000) { 'a'.code.toByte() }) }.use { srv ->
            val r = MiniHttp.request(srv.url(), maxBody = 1000)
            assertEquals(1000, r.body!!.length)
            assertEquals(listOf("a=1; Secure; HttpOnly", "b=2"), r.all("set-cookie"))
        }
    }

    @Test fun miniHttp_timingReflectsSlowServer() {
        NetFakeHttp { _, out -> Thread.sleep(300); out.reply("200 OK", body = "ok".toByteArray()) }.use { srv ->
            val r = MiniHttp.request(srv.url(), maxBody = 10)
            assertTrue("TTFB ${r.timings.ttfbMs}", r.timings.ttfbMs in 250..3000)
            assertTrue(r.timings.connectMs < 250)
        }
    }

    @Test fun miniHttp_followRedirects() {
        lateinit var base: String
        NetFakeHttp { req, out ->
            when (req.path) {
                "/a" -> out.reply("301 Moved Permanently", "Location: /b")
                "/b" -> out.reply("302 Found", "Location: $base/c")
                "/d" -> out.reply("307 Temporary Redirect", "Location: e?x=1")
                "/e" -> out.reply("200 OK", body = "e".toByteArray())
                "/loop" -> out.reply("302 Found", "Location: /loop")
                "/nolocation" -> out.reply("302 Found")
                else -> out.reply("200 OK", body = "final".toByteArray())
            }
        }.use { srv ->
            base = srv.url("").trimEnd('/')
            val steps = ArrayList<Pair<Int, String>>()
            val chain = MiniHttp.follow(srv.url("/a")) { n, u -> steps += n to u }
            assertEquals(listOf(301, 302, 200), chain.map { it.status })
            assertTrue(chain[0].isRedirect && chain[1].isRedirect && !chain[2].isRedirect)
            assertEquals(srv.url("/c"), chain.last().url)
            assertEquals(listOf(1, 2, 3), steps.map { it.first }); assertEquals(srv.url("/b"), steps[1].second)
            // 상대 주소(쿼리 포함)도 올바르게 이어짐
            assertEquals(srv.url("/e?x=1"), MiniHttp.follow(srv.url("/d")).last().url)
            // 끝없는 반복: maxHops + 1 번에서 멈춤
            val loop = MiniHttp.follow(srv.url("/loop"), maxHops = 3)
            assertEquals(4, loop.size); assertTrue(loop.last().isRedirect)
            // Location 이 없는 3xx 는 이동하지 않음
            val nl = MiniHttp.follow(srv.url("/nolocation")); assertEquals(1, nl.size); assertFalse(nl[0].isRedirect)
        }
    }

    @Test fun miniHttp_errors() {
        NetFakeHttp { req, out -> if (req.path == "/ssh") { out.write("SSH-2.0-OpenSSH_8.9\r\n".toByteArray()); out.flush() } }.use { srv ->
            try { MiniHttp.request(srv.url("/empty")); fail() } catch (e: IOException) { assertTrue(e.message!!, e.message!!.contains("아무 응답")) }
            try { MiniHttp.request(srv.url("/ssh")); fail() } catch (e: IOException) { assertTrue(e.message!!, e.message!!.contains("HTTP 응답이 아니에요")) }
        }
        val closed = ServerSocket(0, 1, LO).use { it.localPort }
        try { MiniHttp.request("http://127.0.0.1:$closed/", timeoutMs = 1500); fail() } catch (_: IOException) {}
        try { MiniHttp.request("http://"); fail() } catch (e: IOException) { assertTrue(e.message!!.contains("URL")) }
    }

    // ------------------------------------------------------------------------------ 인증서 이름 검사

    @Test fun hostMatch_wildcardCnAndIp() {
        val wild = pem(WILD_PEM)
        assertTrue(HostMatch.matches("example.com", wild)); assertTrue(HostMatch.matches("www.example.com", wild)); assertTrue(HostMatch.matches("EXAMPLE.com.", wild))
        assertFalse("와일드카드는 한 칸만", HostMatch.matches("a.b.example.com", wild))
        assertFalse(HostMatch.matches("notexample.com", wild)); assertFalse(HostMatch.matches("example.org", wild)); assertFalse(HostMatch.matches("192.168.0.1", wild))
        val cnOnly = pem(CNONLY_PEM)
        assertTrue(HostMatch.matches("legacy.example.org", cnOnly)); assertFalse(HostMatch.matches("other.example.org", cnOnly))
        val ip = pem(IP_PEM)
        assertTrue(HostMatch.matches("192.168.0.1", ip)); assertTrue(HostMatch.matches("2001:db8::1", ip)); assertTrue(HostMatch.matches("[2001:db8::1]", ip))
        assertFalse(HostMatch.matches("192.168.0.2", ip)); assertTrue(HostMatch.matches("router.local", ip))
        assertFalse("SAN 이 있으면 CN 은 보지 않음", HostMatch.matches("router", ip))
    }

    // ------------------------------------------------------------------------------ TLS

    @Test fun tlsInspect_selfSigned() {
        NetFakeHttp(tls = serverTls(SRV_P12)) { _, out -> out.reply("200 OK", body = "secure".toByteArray()) }.use { srv ->
            val rep = TlsInspect.inspect("127.0.0.1", srv.port, 5000)
            assertTrue(rep.protocol, rep.protocol.startsWith("TLSv1")); assertEquals(1, rep.chain.size)
            assertFalse(rep.trusted); assertTrue(rep.trustError!!, rep.trustError!!.contains("자체 서명"))
            assertTrue("IP SAN 127.0.0.1", rep.hostnameOk)
            assertTrue(CertInfo.daysLeft(rep.chain[0]) > 30000)
            assertTrue(TlsInspect.inspect("localhost", srv.port, 5000).hostnameOk)
            assertFalse(HostMatch.matches("evil.example.com", rep.chain[0]))
        }
    }

    @Test fun tlsInspect_expiredAndProtocolChoice() {
        NetFakeHttp(tls = serverTls(OLD_P12)) { _, out -> out.reply("200 OK") }.use { srv ->
            val rep = TlsInspect.inspect("127.0.0.1", srv.port, 5000)
            assertTrue(CertInfo.daysLeft(rep.chain[0]) < 0); assertFalse(rep.trusted)
        }
        NetFakeHttp(tls = serverTls(SRV_P12), protocols = arrayOf("TLSv1.2")) { _, out -> out.reply("200 OK") }.use { srv ->
            assertEquals("TLSv1.2", TlsInspect.inspect("127.0.0.1", srv.port, 5000, arrayOf("TLSv1.2")).protocol)
            try { TlsInspect.inspect("127.0.0.1", srv.port, 5000, arrayOf("TLSv1.3")); fail("서버가 1.2 만 받는데 1.3 으로 접속됨") } catch (_: Exception) {}
        }
        assertTrue(TlsInspect.supportedProtocols().any { it == "TLSv1.2" })
    }

    @Test fun miniHttp_httpsNeedsTrustUnlessInsecure() {
        NetFakeHttp(tls = serverTls(SRV_P12)) { _, out -> out.reply("200 OK", "Server: fake", body = "secure".toByteArray()) }.use { srv ->
            val url = "https://127.0.0.1:${srv.port}/"
            try { MiniHttp.request(url, maxBody = 100); fail("자체 서명 인증서는 거절돼야 해요") } catch (e: IOException) { assertTrue(e.message!!, e.message!!.contains("인증서를 믿을 수 없어요")) }
            val r = MiniHttp.request(url, maxBody = 100, insecure = true)
            assertEquals(200, r.status); assertEquals("secure", r.body); assertNotNull(r.tls); assertFalse(r.tls!!.trusted); assertNotNull(r.timings.tlsMs)
        }
    }

    // ------------------------------------------------------------------------------ NTP

    @Test fun ntp_requestPacketAndOffset() {
        val req = NtpClient.request(1704067200000.0)            // 2024-01-01 00:00:00 UTC → NTP 초 3913056000 = 0xE93C7F00
        assertEquals(48, req.size); assertEquals(0x1B, req[0].toInt())
        assertEquals("e93c7f0000000000", req.copyOfRange(40, 48).joinToString("") { "%02x".format(it) })
        val t1 = 1_700_000_000_000.0
        fun clock(): () -> Double { var n = 0; return { if (n++ == 0) t1 else t1 + 20.0 } }          // 왕복 20ms
        NetFakeNtp(offsetMs = 2500.0).use { s ->
            val r = NtpClient.query("127.0.0.1#${s.port}", timeoutMs = 1000, now = clock())
            assertEquals(2500.0, r.offsetMs, 0.01); assertEquals(20.0, r.delayMs, 0.01); assertEquals(2, r.stratum); assertEquals("10.0.0.1", r.refId)
        }
        NetFakeNtp(offsetMs = -1234.5, stratum = 1, refId = byteArrayOf('G'.code.toByte(), 'P'.code.toByte(), 'S'.code.toByte(), 0)).use { s ->
            val r = NtpClient.query("127.0.0.1#${s.port}", timeoutMs = 1000, now = clock())
            assertEquals(-1234.5, r.offsetMs, 0.01); assertEquals("GPS", r.refId); assertEquals(1, r.stratum)
        }
        NetFakeNtp(offsetMs = 3.0).use { s ->       // 실제 시계로도 동작 (시계 차이는 몇 ms 안쪽)
            val r = NtpClient.query("127.0.0.1#${s.port}", timeoutMs = 1000)
            assertTrue("offset ${r.offsetMs}", Math.abs(r.offsetMs - 3.0) < 300); assertTrue(r.delayMs in 0.0..300.0)
        }
    }

    @Test fun ntp_badReplies() {
        fun expect(server: NetFakeNtp, part: String, timeout: Int = 500) = server.use { s ->
            try { NtpClient.query("127.0.0.1#${s.port}", timeoutMs = timeout); fail("오류여야 해요: $part") } catch (e: IOException) { assertTrue("${e.message} ⊅ $part", e.message!!.contains(part)) }
        }
        expect(NetFakeNtp(stratum = 0, refId = "RATE".toByteArray()), "거절")
        expect(NetFakeNtp(mode = 3), "서버 응답이 아니에요")
        expect(NetFakeNtp(badOriginate = true), "요청과 맞지 않아요")
        expect(NetFakeNtp(shortReply = true), "너무 짧")
        expect(NetFakeNtp(silent = true), "응답이 없어요", timeout = 200)
    }

    // ------------------------------------------------------------------------------ 핑 출력 해석

    @Test fun systemPing_parseLines() {
        fun p(l: String) = SystemPing.parseLine(l)
        p("64 bytes from 142.250.196.196: icmp_seq=1 ttl=117 time=12.3 ms")!!.let { assertEquals("reply", it.kind); assertEquals("142.250.196.196", it.from); assertEquals(1, it.seq); assertEquals(117, it.ttl); assertEquals(12.3, it.ms!!, 0.001) }
        p("64 bytes from lax17s55-in-f4.1e100.net (142.250.196.196): icmp_seq=7 ttl=117 time=0.456 ms")!!.let { assertEquals("142.250.196.196", it.from); assertEquals(7, it.seq); assertEquals(0.456, it.ms!!, 0.0001) }
        p("64 bytes from 2001:4860:4860::8888: icmp_seq=2 ttl=117 time=10.1 ms")!!.let { assertEquals("2001:4860:4860::8888", it.from); assertEquals(10.1, it.ms!!, 0.001) }
        p("64 bytes from 8.8.8.8: seq=0 ttl=117 time=12.3 ms")!!.let { assertEquals("8.8.8.8", it.from); assertEquals(0, it.seq) }        // BusyBox 모양
        p("From 192.168.0.1 icmp_seq=1 Time to live exceeded")!!.let { assertEquals("exceeded", it.kind); assertEquals("192.168.0.1", it.from); assertEquals(1, it.seq) }
        p("From 10.0.0.1: icmp_seq=1 Time to live exceeded")!!.let { assertEquals("exceeded", it.kind); assertEquals("10.0.0.1", it.from) }
        p("From gateway.lan (192.168.0.1) icmp_seq=1 Time to live exceeded")!!.let { assertEquals("exceeded", it.kind); assertEquals("192.168.0.1", it.from) }
        p("From 192.168.0.5 icmp_seq=1 Destination Host Unreachable")!!.let { assertEquals("unreachable", it.kind); assertEquals("192.168.0.5", it.from) }
        assertNull(p("PING google.com (142.250.196.196) 56(84) bytes of data."))
        assertNull(p("--- google.com ping statistics ---")); assertNull(p("")); assertNull(p("rtt min/avg/max/mdev = 11.1/12.2/13.3/0.9 ms"))
        assertEquals(4 to 4, SystemPing.parseSummary("4 packets transmitted, 4 received, 0% packet loss, time 3004ms"))
        assertEquals(4 to 3, SystemPing.parseSummary("4 packets transmitted, 3 packets received, 25% packet loss"))
        assertEquals(4 to 0, SystemPing.parseSummary("4 packets transmitted, 0 received, +4 errors, 100% packet loss, time 3070ms"))
        assertNull(SystemPing.parseSummary("nothing here"))
    }

    // ------------------------------------------------------------------------------ SSDP · WoL · NetBIOS

    @Test fun ssdp_parseAndDiscover() {
        val ok = "HTTP/1.1 200 OK\r\nCACHE-CONTROL: max-age=1800\r\nEXT:\r\nLOCATION: http://192.168.0.1:5000/rootDesc.xml\r\nSERVER: Linux/4.4 UPnP/1.1 MiniUPnPd/2.1\r\nST: upnp:rootdevice\r\nUSN: uuid:abc::upnp:rootdevice\r\n\r\n"
        val m = Ssdp.parse(ok)!!
        assertEquals("http://192.168.0.1:5000/rootDesc.xml", m["LOCATION"]); assertEquals("upnp:rootdevice", m["ST"]); assertEquals("", m["EXT"])
        assertNotNull(Ssdp.parse("NOTIFY * HTTP/1.1\r\nNT: upnp:rootdevice\r\nUSN: uuid:x\r\n\r\n"))
        assertNull(Ssdp.parse("M-SEARCH * HTTP/1.1\r\nST: ssdp:all\r\n\r\n")); assertNull(Ssdp.parse("HTTP/1.1 404 Not Found\r\n\r\n")); assertNull(Ssdp.parse("hello"))
        val q = String(Ssdp.search(), Charsets.US_ASCII)
        assertTrue(q.startsWith("M-SEARCH * HTTP/1.1\r\n") && q.contains("MAN: \"ssdp:discover\"") && q.contains("ST: ssdp:all") && q.endsWith("\r\n\r\n"))

        val a = "HTTP/1.1 200 OK\r\nLOCATION: http://127.0.0.1:1/a.xml\r\nSERVER: A/1.0 UPnP/1.0\r\nST: upnp:rootdevice\r\nUSN: uuid:aaa::upnp:rootdevice\r\n\r\n"
        val b = "HTTP/1.1 200 OK\r\nSERVER: B/2.0\r\nST: urn:schemas-upnp-org:device:MediaServer:1\r\nUSN: uuid:bbb\r\n\r\n"
        NetFakeUdp { p, sock ->
            for (msg in listOf(a, b, "garbage", a)) { val d = msg.toByteArray(); sock.send(DatagramPacket(d, d.size, p.socketAddress)) }
        }.use { srv ->
            val found = Ssdp.discover(700, target = java.net.InetSocketAddress(LO, srv.port))
            assertEquals("같은 USN 은 한 번만", 2, found.size)
            assertTrue(found.all { it.ip == "127.0.0.1" })
            assertEquals("A/1.0 UPnP/1.0", found.first { it.usn.startsWith("uuid:aaa") }.server)
            assertEquals("urn:schemas-upnp-org:device:MediaServer:1", found.first { it.usn == "uuid:bbb" }.st)
            assertTrue(String(srv.received.first(), Charsets.US_ASCII).startsWith("M-SEARCH"))
        }
    }

    @Test fun ssdp_describeOnlyOwnLocalDevice() {
        val xml = "<?xml version=\"1.0\"?><root><device><friendlyName>거실 TV</friendlyName><manufacturer>ACME</manufacturer><modelName>X-1000</modelName></device></root>"
        NetFakeHttp { _, out -> out.reply("200 OK", "Content-Type: text/xml", body = xml.toByteArray()) }.use { srv ->
            val ok = Ssdp.describe(SsdpDevice("127.0.0.1", "upnp:rootdevice", "uuid:1", null, "http://127.0.0.1:${srv.port}/desc.xml"))
            assertEquals(Triple("거실 TV", "ACME", "X-1000"), ok)
            assertEquals(1, srv.requests.size)
            // 기기가 알려 준 주소가 그 기기 자신이 아니거나, 내부망이 아니거나, https 면 요청하지 않음 (엉뚱한 곳으로 요청을 보내게 만드는 것 방지)
            assertNull(Ssdp.describe(SsdpDevice("127.0.0.1", "x", "u", null, "http://127.0.0.2:${srv.port}/desc.xml")))
            assertNull(Ssdp.describe(SsdpDevice("8.8.8.8", "x", "u", null, "http://8.8.8.8/desc.xml")))
            assertNull(Ssdp.describe(SsdpDevice("127.0.0.1", "x", "u", null, "https://127.0.0.1:${srv.port}/desc.xml")))
            assertNull(Ssdp.describe(SsdpDevice("127.0.0.1", "x", "u", null, null)))
            assertEquals(1, srv.requests.size)
        }
    }

    @Test fun wol_packetAndSend() {
        val mac = byteArrayOf(0x00, 0x1A, 0x2B, 0x3C, 0x4D, 0x5E)
        val p = Wol.packet(mac)
        assertEquals(102, p.size)
        for (i in 0 until 6) assertEquals(0xFF, p[i].toInt() and 0xFF)
        for (rep in 0 until 16) for (k in 0 until 6) assertEquals(mac[k], p[6 + rep * 6 + k])
        NetFakeUdp().use { srv ->
            Wol.send(mac, LO, srv.port)
            val deadline = System.currentTimeMillis() + 2000
            while (srv.received.isEmpty() && System.currentTimeMillis() < deadline) Thread.sleep(20)
            assertEquals(1, srv.received.size); assertTrue(p.contentEquals(srv.received[0]))
        }
    }

    @Test fun nbns_queryParseAndAsk() {
        val q = Nbns.query()
        assertEquals(50, q.size)
        assertEquals(0x4242, ((q[0].toInt() and 0xff) shl 8) or (q[1].toInt() and 0xff)); assertEquals(1, q[5].toInt())                        // 질문 1개
        assertEquals(0x20, q[12].toInt()); assertEquals("CK" + "A".repeat(30), String(q, 13, 32, Charsets.US_ASCII)); assertEquals(0, q[45].toInt())   // 이름 "*" 의 NetBIOS 인코딩
        assertEquals(0x0021, ((q[46].toInt() and 0xff) shl 8) or (q[47].toInt() and 0xff)); assertEquals(1, q[49].toInt())                       // 종류 NBSTAT, 분류 IN
        for (raw in listOf(NB0, NB1)) {
            val r = Nbns.parse(hex(raw), 0x4242)!!
            assertEquals(listOf("MYPC" to 0x00, "WORKGROUP" to 0x00, "MYPC" to 0x20, "WORKGROUP" to 0x1E), r.names.map { it.name to it.suffix })
            assertEquals(listOf(false, true, false, true), r.names.map { it.group })
            assertEquals(Mac.hex(byteArrayOf(0xAA.toByte(), 0xBB.toByte(), 0xCC.toByte(), 0xDD.toByte(), 0xEE.toByte(), 0xFF.toByte())), r.mac)
        }
        assertNull("다른 요청의 응답", Nbns.parse(hex(NB0), 0x1111))
        assertNull(Nbns.parse(hex(NB0).copyOf(60)))
        assertNull(Nbns.parse(hex(NB0).also { it[2] = 0 }))                               // 응답 표시가 없음
        assertNull(Nbns.parse(hex(NB0).also { it[12 + 34 + 1] = 0x20 }))                  // 종류가 NBSTAT 이 아님
        assertNull(Nbns.parse(ByteArray(0)))

        NetFakeUdp { p, sock -> val d = hex(NB0); sock.send(DatagramPacket(d, d.size, p.socketAddress)) }.use { srv ->
            val r = Nbns.ask(LO, srv.port, 1000)!!
            assertEquals(4, r.names.size); assertTrue(Nbns.query().contentEquals(srv.received.single()))
        }
        NetFakeUdp { p, _ -> DatagramSocket(0, LO).use { other -> val d = hex(NB0); other.send(DatagramPacket(d, d.size, p.socketAddress)) } }.use { srv ->
            assertNull("다른 곳에서 온 응답은 무시", Nbns.ask(LO, srv.port, 400))
        }
        NetFakeUdp().use { srv -> assertNull(Nbns.ask(LO, srv.port, 300)) }
    }

    // ------------------------------------------------------------------------------ WHOIS

    @Test fun whois_queryReferAndKeys() {
        val iana = "% IANA WHOIS server\n\nrefer:        whois.verisign-grs.com\n\ndomain:       COM\n\nwhois:        whois.verisign-grs.com\n\nstatus:       ACTIVE\n"
        NetFakeWhois { iana.toByteArray() }.use { srv ->
            val t = Whois.query("127.0.0.1#${srv.port}", "com")
            assertEquals(listOf("com"), srv.queries); assertEquals("whois.verisign-grs.com", Whois.referOf(t))
        }
        assertEquals("whois.kr", Whois.referOf("domain: KR\nwhois: whois.kr\nstatus: ACTIVE"))
        assertNull(Whois.referOf("domain: XX\nstatus: ACTIVE")); assertNull(Whois.referOf("refer:   \n"))
        // 한글 WHOIS 는 EUC-KR 로 오는 경우가 있음
        val kr = "도메인 이름 : 테스트사이트.kr\n등록일 : 2020. 01. 01.\n등록 대행자 : 한국인터넷진흥원\n"
        NetFakeWhois { kr.toByteArray(charset("EUC-KR")) }.use { srv -> assertEquals(kr, Whois.query("127.0.0.1#${srv.port}", "x.kr")) }
        NetFakeWhois { kr.toByteArray(Charsets.UTF_8) }.use { srv -> assertEquals(kr, Whois.query("127.0.0.1#${srv.port}", "x.kr")) }
        val text = "Domain Name: EXAMPLE.COM\nRegistrar: Example Registrar, Inc.\nName Server: NS1.EXAMPLE.COM\nname server: NS2.EXAMPLE.COM\nName Server: NS1.EXAMPLE.COM\nCreation Date: 1995-08-14T04:00:00Z\nUpdated Date:\nDNSSEC: unsigned"
        assertEquals(listOf("Domain Name" to "EXAMPLE.COM", "Name Server" to "NS1.EXAMPLE.COM", "name server" to "NS2.EXAMPLE.COM", "Creation Date" to "1995-08-14T04:00:00Z"),
            Whois.keyLines(text, listOf("domain name", "NAME SERVER", "Creation Date", "Updated Date")))
    }

    @Test fun whois_redactsPersonalContacts() {
        val raw = """
            Domain Name: EXAMPLE.COM
            Registrar: MarkMonitor Inc.
            Registrar Abuse Contact Email: abuse@example.net
            Registrant Name: Hong Gildong
            Registrant Email: hong@example.com
            Admin Phone: +82.21234567
            Tech Email: tech@example.com
            Name Server: NS1.EXAMPLE.COM
            person:  John Doe
            address: 1 Main St
            e-mail:  john@example.org
            phone:   +1 555 0100
            nic-hdl: JD1-RIPE
            admin-c: JD1-RIPE
            inetnum: 203.0.113.0 - 203.0.113.255
            netname: EXAMPLE-NET
            descr:   Example ISP
            OrgAbusePhone: +1-555-0100
            주소 : 서울특별시
            전화번호 : 02-123-4567
            기관명 : 예시 통신
            >>> Last update of WHOIS database: 2026-01-01T00:00:00Z <<<
        """.trimIndent()
        val out = Whois.redact(raw)
        for (gone in listOf("Hong Gildong", "hong@example.com", "+82.21234567", "tech@example.com", "John Doe", "1 Main St", "john@example.org", "+1 555 0100", "JD1-RIPE", "abuse@example.net", "서울특별시", "02-123-4567", "+1-555-0100"))
            assertFalse("지워져야 함: $gone", out.contains(gone))
        for (kept in listOf("EXAMPLE.COM", "MarkMonitor Inc.", "NS1.EXAMPLE.COM", "203.0.113.0 - 203.0.113.255", "EXAMPLE-NET", "Example ISP", "예시 통신", "Last update of WHOIS database"))
            assertTrue("남아야 함: $kept", out.contains(kept))
    }

    // ------------------------------------------------------------------------------ 속도 측정 (가짜 측정 서버)

    private fun speedServer(throttleMsPer16k: Long = 0): NetFakeHttp = NetFakeHttp { req, out ->
        when (req.path) {
            "/__down" -> {
                val n = req.query.substringAfter("bytes=").toLongOrNull() ?: 0L
                out.reply("200 OK", "Content-Type: application/octet-stream", "Content-Length: $n", length = false)
                val block = ByteArray(16384); var sent = 0L
                while (sent < n) { val k = minOf(block.size.toLong(), n - sent).toInt(); out.write(block, 0, k); out.flush(); sent += k; if (throttleMsPer16k > 0) Thread.sleep(throttleMsPer16k) }
            }
            "/__up" -> out.reply("200 OK", body = "ok".toByteArray())
            else -> out.reply("404 Not Found")
        }
    }

    @Test fun speedTest_latencyDownloadUploadAndCaps() {
        speedServer(throttleMsPer16k = 1).use { srv ->
            val base = srv.url("").trimEnd('/')
            val lat = SpeedTest.latency(base, 3)!!
            assertTrue("latency $lat", lat in 0.0..2000.0)
            val down = SpeedTest.download(base, threads = 2, limitMs = 1800, chunk = 5_000_000)!!
            assertTrue("down ${down.first} Mbps", down.first in 5.0..20000.0); assertTrue(down.second in 1_000_000L..250_000_000L)
            // 상한: 이 데이터 이상은 받지 않음 (스레드마다 읽는 한 덩어리 정도만 넘을 수 있음)
            val capped = SpeedTest.download(base, threads = 2, limitMs = 5000, chunk = 5_000_000, maxBytes = 3_000_000)!!
            assertTrue("capped ${capped.second}", capped.second in 3_000_000L..3_000_000L + 2 * 65536 + 1)
            val up = SpeedTest.upload(base, threads = 2, limitMs = 1500, chunk = 1_000_000, maxBytes = 10_000_000)!!
            assertTrue("up ${up.first} Mbps", up.first > 1.0); assertTrue("up bytes ${up.second}", up.second in 10_000_000L..12_000_000L)
        }
        // 이미 취소했다면 서버에 요청하지 않음
        speedServer().use { srv ->
            val base = srv.url("").trimEnd('/'); val cancel = AtomicBoolean(true)
            assertNull(SpeedTest.download(base, cancel = cancel)); assertNull(SpeedTest.upload(base, cancel = cancel))
            assertTrue(srv.requests.isEmpty())
        }
        // 응답하지 않는 서버: 모두 null
        val closed = ServerSocket(0, 1, LO).use { it.localPort }
        assertNull(SpeedTest.latency("http://127.0.0.1:$closed", 2))
    }

    // ------------------------------------------------------------------------------ 머리글 해석

    @Test fun cdnDetect_andHints() {
        fun names(vararg h: Pair<String, String>) = CdnDetect.detect(h.toList()).map { it.service }
        assertEquals(listOf("Cloudflare"), names("CF-Ray" to "8a1b2c-ICN", "Server" to "cloudflare"))
        val cf = CdnDetect.detect(listOf("Via" to "1.1 abcd.cloudfront.net (CloudFront)", "X-Amz-Cf-Id" to "xyz", "X-Amz-Cf-Pop" to "ICN57-C1"))
        assertEquals("Amazon CloudFront", cf.single().service); assertTrue(cf.single().evidence.contains("ICN57-C1"))
        assertEquals(listOf("Fastly"), names("X-Served-By" to "cache-icn1234-ICN"))
        assertEquals(listOf("Google 서버"), names("Server" to "gws"))
        assertEquals(listOf("Vercel"), names("X-Vercel-Id" to "icn1::abc"))
        assertTrue(names("Server" to "nginx/1.18.0", "X-Powered-By" to "PHP/7.4").isEmpty())
        val hints = CdnDetect.hints(listOf("Server" to "nginx/1.18.0", "X-Powered-By" to "PHP/7.4", "X-Cache" to "HIT", "Age" to "120"))
        assertEquals(listOf("웹 서버", "만든 기술", "캐시 상태", "캐시된 지 (초)"), hints.map { it.first })
    }

    @Test fun secHeaders_gradeLeaksCookies() {
        val good = listOf("Strict-Transport-Security" to "max-age=31536000; includeSubDomains", "Content-Security-Policy" to "default-src 'self'", "X-Content-Type-Options" to "nosniff",
            "X-Frame-Options" to "DENY", "Referrer-Policy" to "strict-origin-when-cross-origin", "Permissions-Policy" to "camera=()")
        val g = SecHeaders.grade(good, true)
        assertEquals(6, g.size); assertTrue(g.all { it.level == -1 })
        val none = SecHeaders.grade(emptyList(), true)
        assertEquals(6, none.size); assertTrue(none.all { it.level == 2 && it.advice.isNotEmpty() })
        assertEquals(1, SecHeaders.grade(emptyList(), false).first { it.name == "HSTS" }.level)                       // http 로는 확인 불가
        assertEquals(1, SecHeaders.grade(listOf("Strict-Transport-Security" to "max-age=100"), true).first { it.name == "HSTS" }.level)
        assertEquals(1, SecHeaders.grade(listOf("Content-Security-Policy" to "script-src 'unsafe-inline'"), true).first { it.name == "CSP" }.level)
        assertEquals(1, SecHeaders.grade(listOf("Referrer-Policy" to "unsafe-url"), true).first { it.name == "Referrer-Policy" }.level)
        assertEquals(-1, SecHeaders.grade(listOf("Content-Security-Policy" to "frame-ancestors 'self'"), true).first { it.name == "클릭재킹 방어" }.level)
        assertEquals(2, SecHeaders.leaks(listOf("Server" to "Apache/2.4.41 (Ubuntu)", "X-Powered-By" to "PHP/7.4", "X-AspNet-Version" to "4.0")).size.let { it - 1 })
        assertTrue(SecHeaders.leaks(listOf("Server" to "nginx")).isEmpty())
        val ck = SecHeaders.cookies(listOf("sid=abc; Path=/; Secure; HttpOnly; SameSite=Lax", "track=1"))
        assertEquals("sid", ck[0].name); assertTrue(ck[0].secure && ck[0].httpOnly); assertEquals("Lax", ck[0].sameSite)
        assertEquals("track", ck[1].name); assertFalse(ck[1].secure || ck[1].httpOnly); assertNull(ck[1].sameSite)
    }

    @Test fun robots_parse() {
        val r = Robots.parse("# comment\nUser-agent: *\nDisallow: /admin\nDisallow: /private # inline\nDisallow:\nAllow: /public\nUser-agent: Bingbot\nSitemap: https://example.com/sitemap.xml\nSitemap: https://example.com/news.xml")
        assertEquals(2, r.userAgents); assertEquals(2, r.disallow); assertEquals(1, r.allow)
        assertEquals(listOf("https://example.com/sitemap.xml", "https://example.com/news.xml"), r.sitemaps)
    }

    // ------------------------------------------------------------------------------ 도구 (화면이 부르는 함수) — 가짜 서버로 끝까지

    @Test fun tools_httpFamily() {
        val body = "<html><head><title>내 사이트</title></head><body>hello</body></html>".toByteArray()
        lateinit var base: String
        NetFakeHttp { req, out ->
            when (req.path) {
                "/" -> out.reply("200 OK", "Content-Type: text/html; charset=utf-8", "Server: nginx/1.18.0", "CF-Ray: 8a1b2c-ICN", "Set-Cookie: sid=1; Secure; HttpOnly; SameSite=Lax", "X-Powered-By: PHP/7.4", body = if (req.method == "HEAD") ByteArray(0) else body)
                "/robots.txt" -> out.reply("200 OK", "Content-Type: text/plain", body = "User-agent: *\nDisallow: /admin\nSitemap: $base/sitemap.xml\n".toByteArray())
                "/short" -> out.reply("301 Moved Permanently", "Location: /final")
                "/final" -> out.reply("200 OK", body = "x".toByteArray())
                "/nohead" -> if (req.method == "HEAD") out.reply("405 Method Not Allowed", "Allow: GET") else out.reply("200 OK", "X-Fallback: yes", body = "x".toByteArray())
                else -> out.reply("404 Not Found")
            }
        }.use { srv ->
            base = srv.url("").trimEnd('/')
            val u = srv.url("/")
            runTool("http_check", "u" to u, "follow" to "따라가지 않음", "ins" to "인증서 검사함").text().let { t ->
                for (w in listOf("200", "내 사이트", "nginx/1.18.0", "127.0.0.1", "첫 응답까지(TTFB)", "text/html")) assertTrue("$w ∉ $t", t.contains(w))
            }
            runTool("http_check", "u" to srv.url("/short"), "follow" to "따라감", "ins" to "인증서 검사함").text().let { t -> assertTrue(t, t.contains("리다이렉트 1번") && t.contains("/final")) }
            runTool("http_headers", "u" to u).text().let { t -> assertTrue(t, t.contains("Server") && t.contains("nginx/1.18.0") && t.contains("200")) }
            runTool("http_headers", "u" to srv.url("/nohead")).text().let { t -> assertTrue("HEAD 가 막히면 GET 으로: $t", t.contains("X-Fallback")) }
            runTool("redirect_trace", "u" to srv.url("/short"), "ins" to "인증서 검사함").text().let { t -> assertTrue(t, t.contains("이동 횟수: 1번") && t.contains(srv.url("/final"))) }
            runTool("site_timing", "u" to u, "n" to "1").text().let { t -> assertTrue(t, t.contains("TCP 연결") && t.contains("첫 응답까지") && t.contains("1번 평균")) }
            runTool("sec_headers", "u" to u).text().let { t -> assertTrue(t, t.contains("0 / 6") && t.contains("X-Powered-By") && t.contains("sid") && t.contains("Server 머리글이 버전까지")) }
            runTool("cdn_detect", "u" to u).text().let { t -> assertTrue(t, t.contains("Cloudflare") && t.contains("웹 서버") && t.contains("PHP/7.4")) }
            runTool("robots_fetch", "u" to u).text().let { t -> assertTrue(t, t.contains("Disallow(막은 경로): 1개") && t.contains("$base/sitemap.xml")) }
            val bulk = runTool("url_bulk", "urls" to "${srv.url("/")}\n${srv.url("/missing")}\nhttp://127.0.0.1:${ServerSocket(0, 1, LO).use { it.localPort }}/").text()
            assertTrue(bulk, bulk.contains("200") && bulk.contains("404"))
            assertTrue(bulk.lines().count { it.contains("127.0.0.1") } == 3)
            // 입력이 비었을 때
            assertFalse(runTool("http_check", "u" to "").hasError); assertTrue(runTool("http_check", "u" to "").text().contains("주소를 입력"))
        }
    }

    @Test fun tools_tlsCertAndPings() {
        NetFakeHttp(tls = serverTls(SRV_P12)) { _, out -> out.reply("200 OK") }.use { srv ->
            val t = runTool("tls_cert", "h" to "127.0.0.1:${srv.port}").text()
            assertTrue(t, t.contains("자체 서명") && t.contains("TLSv1") && t.contains("127.0.0.1:${srv.port}") && t.contains("남은 기간"))
        }
        NetFakeHttp { _, out -> out.reply("200 OK") }.use { srv ->
            val t = runTool("ping_tcp", "h" to "127.0.0.1", "port" to "${srv.port}", "n" to "5", "gap" to "0.3초").text()
            assertTrue(t, t.contains("성공 / 시도: 5 / 5") && t.contains("손실: 0.0%"))
            val open = srv.port; val closed = ServerSocket(0, 1, LO).use { it.localPort }
            val pc = runTool("port_check", "h" to "127.0.0.1", "ports" to "$open,$closed").text()
            assertTrue(pc, pc.contains("$open") && pc.contains("열림") && pc.contains("$closed") && pc.contains("닫힘"))
        }
        val closed = ServerSocket(0, 1, LO).use { it.localPort }
        runTool("ping_tcp", "h" to "127.0.0.1", "port" to "$closed", "n" to "5", "gap" to "0.3초").let { r -> assertTrue(r.text(), r.text().contains("모든 연결이 실패") && r.hasError) }
        assertTrue(runTool("port_check", "h" to "127.0.0.1", "ports" to "1-11").text().contains("최대 10"))
    }

    @Test fun tools_guardrailsAndEmptyInputs() {
        // 내 망 점검 도구는 내 망 안(사설·루프백) 주소만 받음
        assertTrue(runTool("nbns_name", "ip" to "8.8.8.8").hasError)
        assertTrue(runTool("router_info", "gw" to "8.8.8.8").hasError)
        assertTrue(runTool("whois_ip", "ip" to "192.168.0.1").hasError); assertTrue(runTool("whois_ip", "ip" to "127.0.0.1").hasError)
        assertTrue(runTool("whois_ip", "ip" to "abc").hasError)
        assertTrue(runTool("port_check", "h" to "224.0.0.1", "ports" to "80").hasError)              // 멀티캐스트 거절
        assertTrue(runTool("ping_tcp", "h" to "127.0.0.1", "port" to "0").hasError)
        // Wake-on-LAN: MAC 검사, 내 망 밖 브로드캐스트 거절
        assertTrue(runTool("wol_send", "mac" to "zz").hasError); assertTrue(runTool("wol_send", "mac" to "01:00:5e:00:00:01").hasError)
        assertTrue(runTool("wol_send", "mac" to "aa:bb:cc:dd:ee:ff", "bc" to "8.8.8.255").hasError)
        runTool("wol_send", "mac" to "aa:bb:cc:dd:ee:ff", "bc" to "127.0.0.1", "port" to "9").let { r -> assertFalse(r.text(), r.hasError); assertTrue(r.text().contains("102바이트")) }
        // 휴대폰 정보가 없으면 안내만
        assertTrue(runTool("net_info").hasError); assertTrue(runTool("wifi_info").hasError)
        // 루프백 공유기 점검은 끝까지 실행됨
        assertTrue(runTool("router_info", "gw" to "127.0.0.1").text().contains("공유기: 127.0.0.1"))
        // 빈 입력
        for (id in listOf("tls_cert", "ping_tcp", "port_check", "ping_icmp", "traceroute", "robots_fetch", "sec_headers", "cdn_detect", "redirect_trace", "http_headers", "site_timing", "tls_versions", "whois_domain"))
            runTool(id, "h" to "", "u" to "", "d" to "").let { r -> assertFalse("$id 는 빈 입력에 오류 대신 안내만: ${r.text()}", r.hasError); assertTrue("$id: ${r.text()}", r.text().isNotBlank()) }
        runTool("url_bulk", "urls" to "").let { assertFalse(it.hasError); assertTrue(it.text().contains("한 줄에 하나씩")) }
        runTool("cert_expiry", "hosts" to "").let { assertFalse(it.hasError); assertTrue(it.text().contains("한 줄에 하나씩")) }
    }

    @Test fun registry_hasGuardrailsAndCounts() {
        val all = NetToolbox.ALL
        assertEquals(all.size, all.map { it.id }.toSet().size)
        for (t in all) {
            assertTrue("${t.id} 제목·설명", t.title.isNotBlank() && t.desc.isNotBlank())
            assertTrue("${t.id} 묶음 ${t.group}", t.group in NetGroups.ALL)
            if (t.mode != ToolMode.OFFLINE) assertTrue("${t.id}: 무엇을 보내는지 안내가 있어야 해요", !t.note.isNullOrBlank())
        }
        // 데이터를 많이 쓰거나 남의 서버에 접속을 시도하는 도구는 실행 전에 한 번 더 확인
        for (id in listOf("speed_test", "port_check")) assertNotNull("$id 확인창", NetToolbox.byId(id)!!.confirm)
        val byGroup = all.groupBy { it.group }.mapValues { it.value.size }
        println("NET-TOOLS total=${all.size} " + NetGroups.ALL.joinToString(" ") { "$it=${byGroup[it] ?: 0}" })
        assertTrue("도구 수 ${all.size}", all.size >= 170)
        assertTrue(byGroup[NetGroups.DIAG]!! >= 20); assertTrue(byGroup[NetGroups.LAN]!! >= 6); assertTrue(byGroup[NetGroups.DNS]!! >= 23)
    }
}
