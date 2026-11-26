package com.selfcheck.app

import org.json.JSONArray
import org.json.JSONObject
import java.io.BufferedInputStream
import java.io.ByteArrayOutputStream
import java.io.Closeable
import java.io.IOException
import java.io.InputStream
import java.io.OutputStream
import java.net.DatagramPacket
import java.net.DatagramSocket
import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.Socket
import java.net.SocketTimeoutException
import java.nio.ByteBuffer
import java.security.MessageDigest
import java.util.Base64

/*
 * 서버·서비스 점검 엔진: 메일(SMTP·IMAP·POP3)·FTP·SSH·MQTT·RTSP·SIP·WebSocket·게임 서버(마인크래프트·Source) 등
 * 서버가 먼저 알려 주는 인사말과 공개된 "상태 질문"에 대한 답만 읽습니다. 로그인 시도·취약점 공격·대량 접속은 하지 않아요.
 * 화면과 분리해서 컴퓨터 안의 가짜 서버로 시험합니다.
 */

/** 글줄 기반 프로토콜용 연결 (TLS 로 바꾸는 STARTTLS 지원). 시간이 지나면 IOException */
class ProbeConn(host: String, port: Int, timeoutMs: Int = 6000, newSocket: () -> Socket = { Socket() }, tls: Boolean = false) : Closeable {
    var socket: Socket
    var tlsReport: TlsReport? = null
    private var ins: InputStream
    private var out: OutputStream

    init {
        val addr = try { TlsInspect.resolve(host) } catch (e: Exception) { throw IOException("도메인을 찾지 못했어요 ($host)") }
        var s = newSocket()
        try {
            s.connect(InetSocketAddress(addr, port), timeoutMs); s.soTimeout = timeoutMs
            if (tls) { val (ssl, rep) = TlsInspect.wrap(s, host, port); s = ssl; tlsReport = rep }
        } catch (e: IOException) { runCatching { s.close() }; throw e }
        socket = s; ins = BufferedInputStream(s.getInputStream()); out = s.getOutputStream()
    }

    /** 이미 연결된 소켓을 TLS 로 바꿈 (STARTTLS) */
    fun upgrade(host: String, port: Int): TlsReport {
        val (ssl, rep) = TlsInspect.wrap(socket, host, port)
        socket = ssl; ins = BufferedInputStream(ssl.getInputStream()); out = ssl.getOutputStream(); tlsReport = rep
        return rep
    }

    fun send(text: String) { out.write(text.toByteArray(Charsets.ISO_8859_1)); out.flush() }
    fun sendBytes(b: ByteArray) { out.write(b); out.flush() }
    val input: InputStream get() = ins

    /** 한 줄 (줄바꿈 제외). 연결이 닫히면 null. 8KB 를 넘으면 오류 */
    fun line(): String? {
        val bo = ByteArrayOutputStream()
        while (true) {
            val c = try { ins.read() } catch (_: SocketTimeoutException) { throw IOException("응답이 없어요 (시간 초과)") }
            if (c < 0) return if (bo.size() == 0) null else bo.toString("ISO-8859-1")
            if (c == '\n'.code) return bo.toString("ISO-8859-1").trimEnd('\r')
            bo.write(c); if (bo.size() > 8192) throw IOException("줄이 너무 길어요")
        }
    }

    fun readExactly(n: Int): ByteArray {
        val b = ByteArray(n); var o = 0
        while (o < n) { val r = try { ins.read(b, o, n - o) } catch (_: SocketTimeoutException) { throw IOException("응답이 없어요 (시간 초과)") }; if (r < 0) throw IOException("서버가 연결을 닫았어요"); o += r }
        return b
    }

    /** 오는 대로 최대 max 바이트까지, waitMs 동안 더 안 오면 멈춤 (인사말 읽기용) */
    fun readSome(max: Int, waitMs: Int): ByteArray {
        val bo = ByteArrayOutputStream(); val buf = ByteArray(2048)
        val old = socket.soTimeout
        try {
            socket.soTimeout = waitMs
            while (bo.size() < max) { val r = try { ins.read(buf, 0, minOf(buf.size, max - bo.size())) } catch (_: SocketTimeoutException) { -2 }; if (r < 0) break; bo.write(buf, 0, r) }
        } finally { runCatching { socket.soTimeout = old } }
        return bo.toByteArray()
    }

    override fun close() { runCatching { socket.close() } }
}

/** 메일·FTP 같은 서버 점검 결과 */
class MailReport(val banner: String, val caps: List<String>, val starttls: Boolean, val tls: TlsReport?, val capsAfterTls: List<String>, val implicit: Boolean)

object Smtp {
    /** 250-... 줄들을 "250 ..." 줄이 올 때까지 모음 */
    internal fun reply(c: ProbeConn, proto: String = "SMTP"): Pair<Int, List<String>> {
        val lines = ArrayList<String>(); var code = 0
        while (lines.size < 200) {
            val l = c.line() ?: throw IOException("서버가 연결을 닫았어요"); lines += l
            if (l.length >= 3 && l.substring(0, 3).all { it.isDigit() }) { code = l.substring(0, 3).toInt(); if (l.length == 3 || l[3] == ' ') break }
            else if (lines.size == 1) throw IOException("$proto 서버의 인사말이 아니에요: ${l.take(80)}")
        }
        return code to lines
    }

    private fun caps(lines: List<String>) = lines.drop(1).map { it.drop(4).trim() }

    fun probe(host: String, port: Int, implicit: Boolean, timeoutMs: Int = 6000, newSocket: () -> Socket = { Socket() }): MailReport {
        ProbeConn(host, port, timeoutMs, newSocket, tls = implicit).use { c ->
            val (code, banner) = reply(c)
            if (code != 220) throw IOException("SMTP 서버의 인사말이 아니에요: ${banner.firstOrNull()?.take(80) ?: ""}")
            c.send("EHLO selfcheck.invalid\r\n"); val (ec, el) = reply(c)
            val caps = if (ec == 250) caps(el) else emptyList()
            val starttls = caps.any { it.equals("STARTTLS", true) }
            var tls = c.tlsReport; var capsTls = emptyList<String>()
            if (!implicit && starttls) {
                c.send("STARTTLS\r\n")
                if (reply(c).first == 220) { tls = c.upgrade(host, port); c.send("EHLO selfcheck.invalid\r\n"); val (e2, l2) = reply(c); capsTls = if (e2 == 250) caps(l2) else emptyList() }
            }
            runCatching { c.send("QUIT\r\n") }
            return MailReport(banner.first().drop(4), caps, starttls, tls, capsTls, implicit)
        }
    }
}

object Imap {
    private fun caps(c: ProbeConn, tag: String): List<String> {
        c.send("$tag CAPABILITY\r\n"); val caps = ArrayList<String>()
        for (n in 0 until 100) { val l = c.line() ?: break; if (l.startsWith("* CAPABILITY", true)) caps += l.substring(12).trim().split(' ').filter { it.isNotEmpty() }; if (l.startsWith("$tag ")) break }
        return caps
    }

    fun probe(host: String, port: Int, implicit: Boolean, timeoutMs: Int = 6000, newSocket: () -> Socket = { Socket() }): MailReport {
        ProbeConn(host, port, timeoutMs, newSocket, tls = implicit).use { c ->
            val banner = c.line() ?: throw IOException("서버가 연결을 닫았어요")
            if (!banner.startsWith("* OK") && !banner.startsWith("* PREAUTH")) throw IOException("IMAP 서버의 인사말이 아니에요: ${banner.take(80)}")
            val caps = caps(c, "a1"); val starttls = caps.any { it.equals("STARTTLS", true) }
            var tls = c.tlsReport; var capsTls = emptyList<String>()
            if (!implicit && starttls) {
                c.send("a2 STARTTLS\r\n"); var ok = false
                for (n in 0 until 20) { val l = c.line() ?: break; if (l.startsWith("a2 ")) { ok = l.startsWith("a2 OK"); break } }
                if (ok) { tls = c.upgrade(host, port); capsTls = caps(c, "a3") }
            }
            runCatching { c.send("a9 LOGOUT\r\n") }
            return MailReport(banner.removePrefix("* OK").removePrefix("* PREAUTH").trim(), caps, starttls, tls, capsTls, implicit)
        }
    }
}

object Pop3 {
    private fun caps(c: ProbeConn): List<String> {
        c.send("CAPA\r\n"); val first = c.line() ?: return emptyList()
        if (!first.startsWith("+OK")) return emptyList()
        val out = ArrayList<String>()
        for (n in 0 until 100) { val l = c.line() ?: break; if (l == ".") break; out += l.trim() }
        return out
    }

    fun probe(host: String, port: Int, implicit: Boolean, timeoutMs: Int = 6000, newSocket: () -> Socket = { Socket() }): MailReport {
        ProbeConn(host, port, timeoutMs, newSocket, tls = implicit).use { c ->
            val banner = c.line() ?: throw IOException("서버가 연결을 닫았어요")
            if (!banner.startsWith("+OK")) throw IOException("POP3 서버의 인사말이 아니에요: ${banner.take(80)}")
            val caps = caps(c); val starttls = caps.any { it.equals("STLS", true) }
            var tls = c.tlsReport; var capsTls = emptyList<String>()
            if (!implicit && starttls) { c.send("STLS\r\n"); if ((c.line() ?: "").startsWith("+OK")) { tls = c.upgrade(host, port); capsTls = caps(c) } }
            runCatching { c.send("QUIT\r\n") }
            return MailReport(banner.removePrefix("+OK").trim(), caps, starttls, tls, capsTls, implicit)
        }
    }
}

class FtpReport(val banner: String, val features: List<String>, val tls: TlsReport?, val anonymous: Boolean?)

object Ftp {
    fun probe(host: String, port: Int, tryAnonymous: Boolean, timeoutMs: Int = 6000, newSocket: () -> Socket = { Socket() }): FtpReport {
        ProbeConn(host, port, timeoutMs, newSocket).use { c ->
            val (code, banner) = Smtp.reply(c, "FTP")
            if (code != 220) throw IOException("FTP 서버의 인사말이 아니에요: ${banner.firstOrNull()?.take(80) ?: ""}")
            c.send("FEAT\r\n"); val (fc, fl) = Smtp.reply(c)
            val feats = if (fc == 211) fl.drop(1).dropLast(1).map { it.trim() } else emptyList()
            var tls: TlsReport? = null
            if (feats.any { it.equals("AUTH TLS", true) || it.startsWith("AUTH TLS", true) }) { c.send("AUTH TLS\r\n"); if (Smtp.reply(c).first == 234) tls = c.upgrade(host, port) }
            var anon: Boolean? = null
            if (tryAnonymous) {
                c.send("USER anonymous\r\n"); val (uc, _) = Smtp.reply(c)
                anon = when (uc) { 230 -> true; 331 -> { c.send("PASS selfcheck@example.invalid\r\n"); Smtp.reply(c).first == 230 }; else -> false }
            }
            runCatching { c.send("QUIT\r\n") }
            return FtpReport(banner.joinToString(" ") { it.drop(4) }.trim(), feats, tls, anon)
        }
    }
}

// ---------------------------------------------------------------------------------------------
// SSH: 서버가 연결하자마자 알려 주는 버전과 지원 암호 목록(KEXINIT)만 읽음 (로그인 시도 없음)

object Ssh {
    class Kex(val kex: List<String>, val hostKeys: List<String>, val ciphers: List<String>, val macs: List<String>, val compression: List<String>)
    class Report(val banner: String, val kex: Kex?)

    /** KEXINIT 본문(종류 20) → 알고리즘 목록 */
    fun parseKexInit(payload: ByteArray): Kex? {
        if (payload.size < 22 || payload[0].toInt() != 20) return null
        val bb = ByteBuffer.wrap(payload); bb.position(17)
        val lists = ArrayList<List<String>>()
        try { repeat(10) { val n = bb.int; if (n < 0 || n > bb.remaining()) return null; val b = ByteArray(n); bb.get(b); lists += String(b, Charsets.US_ASCII).split(',').filter { it.isNotEmpty() } } } catch (_: Exception) { return null }
        if (lists.size < 8) return null
        return Kex(lists[0], lists[1], (lists[2] + lists[3]).distinct(), (lists[4] + lists[5]).distinct(), (lists[6] + lists[7]).distinct())
    }

    private val WEAK_KEX = mapOf("diffie-hellman-group1-sha1" to "1024비트 DH + SHA-1: 매우 약해요", "diffie-hellman-group-exchange-sha1" to "SHA-1 기반이라 약해요", "diffie-hellman-group14-sha1" to "SHA-1 기반이라 낡았어요")
    private val WEAK_HOSTKEY = mapOf("ssh-dss" to "DSA 키는 1024비트로 제한돼 약해요", "ssh-rsa" to "SHA-1 서명을 쓰는 옛 방식이에요 (rsa-sha2-256/512 가 안전해요)")
    private val WEAK_CIPHER = Regex("""(?i)^(3des-cbc|arcfour.*|blowfish-cbc|cast128-cbc|des-cbc.*|rijndael-cbc.*)$""")
    private val CBC = Regex("""(?i)^aes(128|192|256)-cbc$""")
    private val WEAK_MAC = Regex("""(?i)^(hmac-md5.*|hmac-sha1-96.*|umac-64.*|hmac-ripemd160.*|none)$""")

    /** (알고리즘, 이유, 심각도 1=낡음 2=약함) */
    fun weaknesses(k: Kex): List<Triple<String, String, Int>> = buildList {
        for (a in k.kex) WEAK_KEX[a]?.let { add(Triple(a, it, if (a.contains("group1-")) 2 else 1)) }
        for (a in k.hostKeys) WEAK_HOSTKEY[a]?.let { add(Triple(a, it, if (a == "ssh-dss") 2 else 1)) }
        for (a in k.ciphers) { if (WEAK_CIPHER.matches(a)) add(Triple(a, "약한 암호", 2)) else if (CBC.matches(a)) add(Triple(a, "CBC 방식은 낡았어요 (GCM·CTR·chacha20 이 안전해요)", 1)) }
        for (a in k.macs) if (WEAK_MAC.matches(a)) add(Triple(a, "약한 무결성 검사", 2)) else if (a.equals("hmac-sha1", true)) add(Triple(a, "SHA-1 기반이라 낡았어요", 1))
    }

    fun probe(host: String, port: Int, timeoutMs: Int = 6000, newSocket: () -> Socket = { Socket() }): Report {
        ProbeConn(host, port, timeoutMs, newSocket).use { c ->
            var banner: String? = null
            for (n in 0 until 20) { val l = c.line() ?: break; if (l.startsWith("SSH-")) { banner = l; break } }
            banner ?: throw IOException("SSH 서버의 인사말(SSH-2.0-…)을 받지 못했어요")
            c.send("SSH-2.0-SelfCheck_1.0\r\n")
            val head = c.readExactly(5)
            val len = ByteBuffer.wrap(head).int; val pad = head[4].toInt() and 0xFF
            if (len < 6 || len > 35000) return Report(banner, null)
            val body = c.readExactly(len - 1)
            val payload = body.copyOf(body.size - pad)
            return Report(banner, parseKexInit(payload))
        }
    }
}

// ---------------------------------------------------------------------------------------------
// MQTT 브로커: CONNECT 한 번 보내고 CONNACK 의 허용 여부만 읽음 (구독·발행 안 함)

object Mqtt {
    fun remainingLength(n: Int): ByteArray {
        val out = ByteArrayOutputStream(); var x = n
        do { var d = x % 128; x /= 128; if (x > 0) d = d or 128; out.write(d) } while (x > 0)
        return out.toByteArray()
    }

    fun connectPacket(clientId: String, keepAlive: Int = 10): ByteArray {
        val body = ByteArrayOutputStream()
        body.write(byteArrayOf(0, 4, 'M'.code.toByte(), 'Q'.code.toByte(), 'T'.code.toByte(), 'T'.code.toByte(), 4, 2, (keepAlive shr 8).toByte(), keepAlive.toByte()))
        val cid = clientId.toByteArray(); body.write(byteArrayOf((cid.size shr 8).toByte(), cid.size.toByte())); body.write(cid)
        return byteArrayOf(0x10) + remainingLength(body.size()) + body.toByteArray()
    }

    /** CONNACK(20 02 플래그 코드)의 반환 코드. 아니면 null */
    fun parseConnack(b: ByteArray): Int? = if (b.size >= 4 && (b[0].toInt() and 0xFF) == 0x20 && b[1].toInt() == 2) b[3].toInt() and 0xFF else null

    val CODES = mapOf(0 to "접속을 허용했어요 (인증 없이)", 1 to "프로토콜 버전(3.1.1)을 거부했어요", 2 to "클라이언트 ID 를 거부했어요", 3 to "서버를 지금 쓸 수 없어요", 4 to "사용자 이름·암호가 필요해요 (인증을 요구해요)", 5 to "접속 권한이 없어요 (인증을 요구해요)")

    fun probe(host: String, port: Int, tls: Boolean, timeoutMs: Int = 6000, newSocket: () -> Socket = { Socket() }): Pair<Int, TlsReport?> {
        ProbeConn(host, port, timeoutMs, newSocket, tls).use { c ->
            c.sendBytes(connectPacket("selfcheck-" + java.util.UUID.randomUUID().toString().take(8)))
            val ack = c.readExactly(4)
            val rc = parseConnack(ack) ?: throw IOException("MQTT 서버의 응답이 아니에요")
            runCatching { c.sendBytes(byteArrayOf(0xE0.toByte(), 0)) }
            return rc to c.tlsReport
        }
    }
}

// ---------------------------------------------------------------------------------------------
// RTSP(IP 카메라) · SIP(인터넷 전화): "어떤 서버예요?" 질문(OPTIONS/DESCRIBE)에 대한 답만 읽음

class RtspReply(val status: Int, val statusLine: String, val headers: Map<String, String>)

object Rtsp {
    fun parse(text: String): RtspReply? {
        val lines = text.split("\r\n", "\n"); val first = lines.firstOrNull() ?: return null
        val m = Regex("""^RTSP/\d\.\d\s+(\d{3})\s*(.*)$""").find(first) ?: return null
        val hs = LinkedHashMap<String, String>()
        for (l in lines.drop(1)) { if (l.isEmpty()) break; val i = l.indexOf(':'); if (i > 0) hs[l.substring(0, i).trim().lowercase()] = l.substring(i + 1).trim() }
        return RtspReply(m.groupValues[1].toInt(), first, hs)
    }

    private fun exchange(c: ProbeConn, req: String): RtspReply {
        c.send(req)
        val bo = ByteArrayOutputStream()
        while (bo.size() < 16384) { val b = c.input.read(); if (b < 0) break; bo.write(b); val n = bo.size(); if (n >= 4 && bo.toByteArray().let { it[n - 4] == 13.toByte() && it[n - 3] == 10.toByte() && it[n - 2] == 13.toByte() && it[n - 1] == 10.toByte() }) break }
        return parse(bo.toString("ISO-8859-1")) ?: throw IOException("RTSP 서버의 응답이 아니에요")
    }

    fun probe(host: String, port: Int, timeoutMs: Int = 5000, newSocket: () -> Socket = { Socket() }): Pair<RtspReply, RtspReply?> {
        ProbeConn(host, port, timeoutMs, newSocket).use { c ->
            val url = "rtsp://$host:$port/"
            val opt = try { exchange(c, "OPTIONS $url RTSP/1.0\r\nCSeq: 1\r\nUser-Agent: SelfCheck\r\n\r\n") } catch (e: SocketTimeoutException) { throw IOException("응답이 없어요") }
            val desc = runCatching { exchange(c, "DESCRIBE $url RTSP/1.0\r\nCSeq: 2\r\nUser-Agent: SelfCheck\r\nAccept: application/sdp\r\n\r\n") }.getOrNull()
            return opt to desc
        }
    }
}

object Sip {
    fun optionsRequest(host: String, port: Int, callId: String, branch: String, tag: String): String =
        "OPTIONS sip:$host SIP/2.0\r\nVia: SIP/2.0/UDP selfcheck.invalid:5060;branch=z9hG4bK$branch;rport\r\nMax-Forwards: 70\r\nFrom: <sip:selfcheck@selfcheck.invalid>;tag=$tag\r\nTo: <sip:$host>\r\nCall-ID: $callId@selfcheck.invalid\r\nCSeq: 1 OPTIONS\r\nUser-Agent: SelfCheck\r\nAccept: application/sdp\r\nContent-Length: 0\r\n\r\n"

    /** 응답 → (상태 줄, 머리글(소문자 이름)) */
    fun parse(text: String): Pair<String, Map<String, String>>? {
        val lines = text.split("\r\n", "\n"); val first = lines.firstOrNull() ?: return null
        if (!first.startsWith("SIP/2.0")) return null
        val hs = LinkedHashMap<String, String>()
        for (l in lines.drop(1)) { if (l.isEmpty()) break; val i = l.indexOf(':'); if (i > 0) hs[l.substring(0, i).trim().lowercase()] = l.substring(i + 1).trim() }
        return first to hs
    }

    fun probe(host: String, port: Int, timeoutMs: Int = 4000, bind: (DatagramSocket) -> Unit = {}): Pair<String, Map<String, String>> {
        val addr = try { TlsInspect.resolve(host) } catch (_: Exception) { throw IOException("서버 주소를 찾지 못했어요 ($host)") }
        val rnd = java.util.UUID.randomUUID().toString().replace("-", "")
        val req = optionsRequest(host, port, rnd.take(16), rnd.take(12), rnd.takeLast(8)).toByteArray()
        DatagramSocket().use { s ->
            bind(s); s.soTimeout = timeoutMs
            s.send(DatagramPacket(req, req.size, addr, port))
            val buf = ByteArray(4096); val p = DatagramPacket(buf, buf.size)
            val deadline = System.currentTimeMillis() + timeoutMs
            while (true) {
                val left = (deadline - System.currentTimeMillis()).toInt(); if (left <= 0) throw IOException("응답이 없어요 (UDP 5060 이 막혔거나 SIP 서버가 아니에요)")
                s.soTimeout = left
                try { s.receive(p) } catch (_: SocketTimeoutException) { throw IOException("응답이 없어요 (UDP 5060 이 막혔거나 SIP 서버가 아니에요)") }
                parse(String(buf, 0, p.length, Charsets.UTF_8))?.let { if (it.second["call-id"]?.startsWith(rnd.take(16)) == true) return it }
            }
        }
    }
}

// ---------------------------------------------------------------------------------------------
// WebSocket

object WebSocketProbe {
    const val GUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"
    class Report(val statusLine: String, val headers: Map<String, String>, val acceptOk: Boolean, val message: String?, val tls: TlsReport?)

    fun acceptFor(key: String): String = Base64.getEncoder().encodeToString(MessageDigest.getInstance("SHA-1").digest((key + GUID).toByteArray(Charsets.US_ASCII)))

    /** 클라이언트가 보내는 프레임은 반드시 마스크해야 함 (RFC 6455) */
    fun maskedFrame(opcode: Int, payload: ByteArray, mask: ByteArray = ByteArray(4).also { java.security.SecureRandom().nextBytes(it) }): ByteArray {
        val bo = ByteArrayOutputStream(); bo.write(0x80 or opcode)
        when { payload.size < 126 -> bo.write(0x80 or payload.size); payload.size < 65536 -> { bo.write(0x80 or 126); bo.write(payload.size shr 8); bo.write(payload.size and 0xFF) }; else -> throw IllegalArgumentException("너무 길어요") }
        bo.write(mask); for (i in payload.indices) bo.write(payload[i].toInt() xor mask[i % 4].toInt())
        return bo.toByteArray()
    }

    /** 서버가 보낸 프레임 하나 → (종류, 내용). 4KB 넘는 내용은 앞부분만 */
    fun readFrame(ins: InputStream): Pair<Int, ByteArray>? {
        val b0 = ins.read(); if (b0 < 0) return null; val b1 = ins.read(); if (b1 < 0) return null
        var len = b1 and 0x7F
        if (len == 126) len = (ins.read() shl 8) or ins.read() else if (len == 127) { var l = 0L; repeat(8) { l = (l shl 8) or ins.read().toLong() }; len = minOf(l, 1_000_000L).toInt() }
        val masked = (b1 and 0x80) != 0; val mask = if (masked) ByteArray(4).also { var o = 0; while (o < 4) { val r = ins.read(); if (r < 0) return null; it[o++] = r.toByte() } } else null
        val keep = minOf(len, 4096); val data = ByteArray(keep); var o = 0
        while (o < keep) { val r = ins.read(data, o, keep - o); if (r < 0) break; o += r }
        if (mask != null) for (i in 0 until o) data[i] = (data[i].toInt() xor mask[i % 4].toInt()).toByte()
        return (b0 and 0x0F) to data.copyOf(o)
    }

    fun probe(url: String, message: String?, timeoutMs: Int = 6000, newSocket: () -> Socket = { Socket() }): Report {
        val u = MiniHttp.parseUrl(url.replaceFirst(Regex("^ws", RegexOption.IGNORE_CASE), "http")) ?: throw IOException("주소 형식이 올바르지 않아요 (예: wss://example.com/socket)")
        ProbeConn(u.host, u.port, timeoutMs, newSocket, tls = u.isHttps).use { c ->
            val key = Base64.getEncoder().encodeToString(ByteArray(16).also { java.security.SecureRandom().nextBytes(it) })
            c.send("GET ${u.path} HTTP/1.1\r\nHost: ${u.host}${if (u.port == (if (u.isHttps) 443 else 80)) "" else ":${u.port}"}\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: $key\r\nSec-WebSocket-Version: 13\r\nUser-Agent: SelfCheck-NetTools/1.0\r\n\r\n")
            val first = c.line() ?: throw IOException("서버가 아무 응답 없이 연결을 닫았어요")
            val hs = LinkedHashMap<String, String>()
            for (n in 0 until 100) { val l = c.line() ?: break; if (l.isEmpty()) break; val i = l.indexOf(':'); if (i > 0) hs[l.substring(0, i).trim().lowercase()] = l.substring(i + 1).trim() }
            val ok = first.contains(" 101") && hs["sec-websocket-accept"] == acceptFor(key)
            var got: String? = null
            if (first.contains(" 101")) {
                if (message != null) c.sendBytes(maskedFrame(1, message.toByteArray()))
                got = try { readFrame(c.input)?.let { (op, d) -> if (op == 1) String(d, Charsets.UTF_8) else if (op == 2) "(이진 ${d.size}바이트)" else null } } catch (_: IOException) { null }
                runCatching { c.sendBytes(maskedFrame(8, byteArrayOf(0x03, 0xE8.toByte()))) }
            }
            return Report(first, hs, ok, got, c.tlsReport)
        }
    }
}

// ---------------------------------------------------------------------------------------------
// 게임 서버 상태 (공개된 상태 질문에 대한 답: 이름·인원·버전)

object Minecraft {
    fun varInt(v: Int): ByteArray { val o = ByteArrayOutputStream(); var x = v; while (true) { if (x and 0x7F.inv() == 0) { o.write(x); break }; o.write((x and 0x7F) or 0x80); x = x ushr 7 }; return o.toByteArray() }

    fun readVarInt(ins: InputStream): Int {
        var r = 0; var shift = 0
        while (true) { val b = ins.read(); if (b < 0) throw IOException("서버가 연결을 닫았어요"); r = r or ((b and 0x7F) shl shift); if (b and 0x80 == 0) return r; shift += 7; if (shift > 35) throw IOException("VarInt 가 너무 길어요") }
    }

    private fun frame(id: Int, body: ByteArray): ByteArray { val inner = varInt(id) + body; return varInt(inner.size) + inner }

    /** 핸드셰이크(다음 상태=상태 조회) + 상태 요청 */
    fun request(host: String, port: Int, protocol: Int = 765): ByteArray {
        val h = host.toByteArray()
        val hs = varInt(protocol) + varInt(h.size) + h + byteArrayOf((port shr 8).toByte(), port.toByte()) + varInt(1)
        return frame(0, hs) + frame(0, ByteArray(0))
    }

    class Status(val version: String?, val protocol: Int?, val online: Int?, val max: Int?, val motd: String, val pingMs: Long?)

    /** MOTD 는 글자 또는 {"text":..,"extra":[..]} 구조 → 글로 이어 붙이고 색 코드(§a)는 지움 */
    fun flatten(d: Any?): String = when (d) {
        null, JSONObject.NULL -> ""
        is String -> d
        is JSONArray -> (0 until d.length()).joinToString("") { flatten(d.opt(it)) }
        is JSONObject -> d.optString("text", "") + flatten(d.opt("extra"))
        else -> d.toString()
    }.replace(Regex("§[0-9a-fk-orA-FK-OR]"), "")

    fun parseStatus(json: String): Status {
        val o = JSONObject(json); val v = o.optJSONObject("version"); val p = o.optJSONObject("players")
        return Status(v?.optString("name")?.ifEmpty { null }, v?.let { if (it.has("protocol")) it.optInt("protocol") else null }, p?.let { if (it.has("online")) it.optInt("online") else null }, p?.let { if (it.has("max")) it.optInt("max") else null }, flatten(o.opt("description")).trim().replace(Regex("\\s*\\n\\s*"), " / "), null)
    }

    fun probe(host: String, port: Int, timeoutMs: Int = 5000, newSocket: () -> Socket = { Socket() }): Status {
        ProbeConn(host, port, timeoutMs, newSocket).use { c ->
            c.sendBytes(request(host, port))
            val len = readVarInt(c.input); if (len < 2 || len > 1_000_000) throw IOException("마인크래프트 서버의 응답이 아니에요")
            val body = c.readExactly(len); val bin = java.io.ByteArrayInputStream(body)
            if (readVarInt(bin) != 0) throw IOException("마인크래프트 서버의 응답이 아니에요")
            val sl = readVarInt(bin); val js = ByteArray(minOf(sl, bin.available())); bin.read(js)
            val st = try { parseStatus(String(js, Charsets.UTF_8)) } catch (_: org.json.JSONException) { throw IOException("상태 응답을 읽지 못했어요") }
            // 응답 시간: 핑 패킷(id 1 + 8바이트)을 되돌려 받는 시간
            var ping: Long? = null
            runCatching {
                val payload = System.nanoTime().let { ByteBuffer.allocate(8).putLong(it).array() }
                val t0 = System.nanoTime(); c.sendBytes(frame(1, payload))
                val pl = readVarInt(c.input); val pr = c.readExactly(pl); if (pr[0].toInt() == 1) ping = (System.nanoTime() - t0) / 1_000_000
            }
            return Status(st.version, st.protocol, st.online, st.max, st.motd, ping)
        }
    }
}

object SourceQuery {
    private val HEADER = byteArrayOf(-1, -1, -1, -1)
    val REQUEST: ByteArray = HEADER + byteArrayOf(0x54) + "Source Engine Query".toByteArray() + byteArrayOf(0)

    class Info(val protocol: Int, val name: String, val map: String, val folder: String, val game: String, val appId: Int, val players: Int, val max: Int, val bots: Int, val type: Char, val env: Char, val visibility: Int, val vac: Int)

    /** 응답이 챌린지(0x41)면 그 4바이트 */
    fun challenge(b: ByteArray): ByteArray? = if (b.size >= 9 && b.copyOfRange(0, 4).contentEquals(HEADER) && b[4].toInt() == 0x41) b.copyOfRange(5, 9) else null

    fun parseInfo(b: ByteArray): Info? {
        if (b.size < 6 || !b.copyOfRange(0, 4).contentEquals(HEADER) || b[4].toInt() != 0x49) return null
        var pos = 5
        fun cstr(): String { val s = pos; while (pos < b.size && b[pos].toInt() != 0) pos++; val r = String(b, s, pos - s, Charsets.UTF_8); pos++; return r }
        return try {
            val proto = b[pos++].toInt() and 0xFF
            val name = cstr(); val map = cstr(); val folder = cstr(); val game = cstr()
            val id = (b[pos].toInt() and 0xFF) or ((b[pos + 1].toInt() and 0xFF) shl 8); pos += 2
            val players = b[pos++].toInt() and 0xFF; val max = b[pos++].toInt() and 0xFF; val bots = b[pos++].toInt() and 0xFF
            val type = (b[pos++].toInt() and 0xFF).toChar(); val env = (b[pos++].toInt() and 0xFF).toChar(); val vis = b[pos++].toInt() and 0xFF; val vac = b[pos++].toInt() and 0xFF
            Info(proto, name, map, folder, game, id, players, max, bots, type, env, vis, vac)
        } catch (_: IndexOutOfBoundsException) { null }
    }

    fun query(host: String, port: Int, timeoutMs: Int = 3000, bind: (DatagramSocket) -> Unit = {}): Info {
        val addr = try { TlsInspect.resolve(host) } catch (_: Exception) { throw IOException("서버 주소를 찾지 못했어요 ($host)") }
        DatagramSocket().use { s ->
            bind(s)
            fun ask(req: ByteArray): ByteArray {
                s.soTimeout = timeoutMs; s.send(DatagramPacket(req, req.size, addr, port))
                val buf = ByteArray(1400); val p = DatagramPacket(buf, buf.size)
                try { s.receive(p) } catch (_: SocketTimeoutException) { throw IOException("응답이 없어요 (게임 서버의 조회 포트(UDP)가 닫혔거나 Source 계열 서버가 아니에요)") }
                return buf.copyOf(p.length)
            }
            var resp = ask(REQUEST)
            challenge(resp)?.let { resp = ask(REQUEST + it) }
            return parseInfo(resp) ?: throw IOException("지원하지 않는 응답이에요 (옛 GoldSource 서버이거나 Source 서버가 아니에요)")
        }
    }
}

/** Syslog (RFC 5424) 시험 메시지 한 줄 */
object Syslog {
    val FACILITIES = listOf("kern", "user", "mail", "daemon", "auth", "syslog", "lpr", "news", "uucp", "cron", "authpriv", "ftp", "ntp", "audit", "alert", "clock", "local0", "local1", "local2", "local3", "local4", "local5", "local6", "local7")
    val SEVERITIES = listOf("emerg", "alert", "crit", "err", "warning", "notice", "info", "debug")

    fun pri(facility: Int, severity: Int) = facility * 8 + severity
    fun message(pri: Int, timestampIso: String, hostname: String, app: String, text: String): String = "<$pri>1 $timestampIso $hostname $app - - - $text"
}
