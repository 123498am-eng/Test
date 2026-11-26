package com.selfcheck.app

import java.io.ByteArrayOutputStream
import java.io.IOException
import java.net.DatagramPacket
import java.net.DatagramSocket
import java.net.IDN
import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.Socket
import java.net.SocketTimeoutException
import java.nio.ByteBuffer
import java.security.KeyFactory
import java.security.interfaces.RSAPublicKey
import java.security.spec.X509EncodedKeySpec
import java.time.Instant
import java.time.ZoneOffset
import java.time.format.DateTimeFormatter
import java.util.Base64

/*
 * DNS 직접 조회 엔진: 운영체제의 이름 풀이를 거치지 않고 DNS 서버에 UDP(잘리면 TCP)로 질문을 보내 모든 종류의 레코드를 읽습니다.
 * (안드로이드는 MX·TXT 같은 레코드를 조회하는 기본 기능이 없어서 직접 만들었어요.)
 * 질문·응답 해석은 화면과 분리해 컴퓨터에서 시험합니다.
 */

object DnsType {
    const val A = 1; const val NS = 2; const val CNAME = 5; const val SOA = 6; const val PTR = 12; const val MX = 15; const val TXT = 16; const val AAAA = 28
    const val SRV = 33; const val NAPTR = 35; const val OPT = 41; const val DS = 43; const val RRSIG = 46; const val NSEC = 47; const val DNSKEY = 48; const val NSEC3 = 50
    const val TLSA = 52; const val SVCB = 64; const val HTTPS = 65; const val ANY = 255; const val CAA = 257

    val NAMES = mapOf(A to "A", NS to "NS", CNAME to "CNAME", SOA to "SOA", PTR to "PTR", MX to "MX", TXT to "TXT", AAAA to "AAAA", SRV to "SRV", NAPTR to "NAPTR", OPT to "OPT",
        DS to "DS", RRSIG to "RRSIG", NSEC to "NSEC", DNSKEY to "DNSKEY", NSEC3 to "NSEC3", TLSA to "TLSA", SVCB to "SVCB", HTTPS to "HTTPS", ANY to "ANY", CAA to "CAA")

    fun name(t: Int) = NAMES[t] ?: "TYPE$t"
    fun parse(s: String): Int? = NAMES.entries.firstOrNull { it.value.equals(s.trim(), true) }?.key

    val RCODES = mapOf(0 to "NOERROR", 1 to "FORMERR", 2 to "SERVFAIL", 3 to "NXDOMAIN", 4 to "NOTIMP", 5 to "REFUSED", 6 to "YXDOMAIN", 7 to "YXRRSET", 8 to "NXRRSET", 9 to "NOTAUTH", 10 to "NOTZONE")
    fun rcode(c: Int) = RCODES[c] ?: "RCODE$c"
}

class DnsRecord(val name: String, val type: Int, val cls: Int, val ttl: Long, val data: String, val text: String? = null) {
    val typeName get() = DnsType.name(type)
}

class DnsMessage(val id: Int, val flags: Int, val questions: List<Pair<String, Int>>, val answers: List<DnsRecord>, val authority: List<DnsRecord>, val additional: List<DnsRecord>) {
    val isResponse get() = flags and 0x8000 != 0
    val aa get() = flags and 0x0400 != 0
    val tc get() = flags and 0x0200 != 0
    val rd get() = flags and 0x0100 != 0
    val ra get() = flags and 0x0080 != 0
    val ad get() = flags and 0x0020 != 0
    val rcode get() = flags and 0xF
}

object DnsWire {
    /** 도메인 → DNS 이름(길이+글자 …, 0). 한글 도메인은 퓨니코드로. 올바르지 않으면 null */
    fun encodeName(name: String): ByteArray? {
        val n = name.trim().trimEnd('.')
        if (n.isEmpty()) return byteArrayOf(0)
        val ascii = try { IDN.toASCII(n, IDN.ALLOW_UNASSIGNED) } catch (_: Exception) { return null }
        val out = ByteArrayOutputStream()
        for (label in ascii.split('.')) {
            val b = label.toByteArray(Charsets.ISO_8859_1)
            if (b.isEmpty() || b.size > 63) return null
            out.write(b.size); out.write(b)
        }
        out.write(0)
        return if (out.size() > 255) null else out.toByteArray()
    }

    /** 질문 패킷: 헤더 + 질문 1개 + EDNS0(OPT, UDP 크기 광고, dnssecOk 면 DO 비트) */
    fun buildQuery(id: Int, name: String, type: Int, rd: Boolean = true, dnssecOk: Boolean = false, udpSize: Int = 1232): ByteArray? {
        val q = encodeName(name) ?: return null
        val bb = ByteBuffer.allocate(12 + q.size + 4 + 11)
        bb.putShort(id.toShort()); bb.putShort((if (rd) 0x0100 else 0).toShort()); bb.putShort(1); bb.putShort(0); bb.putShort(0); bb.putShort(1)
        bb.put(q); bb.putShort(type.toShort()); bb.putShort(1)
        bb.put(0); bb.putShort(DnsType.OPT.toShort()); bb.putShort(udpSize.toShort()); bb.putInt(if (dnssecOk) 0x8000 else 0); bb.putShort(0)
        return bb.array()
    }

    private fun u8(b: ByteArray, o: Int): Int { if (o >= b.size) throw IllegalArgumentException("패킷이 잘렸어요"); return b[o].toInt() and 0xff }
    private fun u16(b: ByteArray, o: Int) = (u8(b, o) shl 8) or u8(b, o + 1)
    private fun u32(b: ByteArray, o: Int) = (u16(b, o).toLong() shl 16) or u16(b, o + 2).toLong()

    /** 압축 포인터를 따라 이름 읽기: (이름, 다음 읽을 위치) */
    fun readName(b: ByteArray, start: Int): Pair<String, Int> {
        val sb = StringBuilder(); var pos = start; var next = -1; var jumps = 0
        while (true) {
            val l = u8(b, pos)
            when {
                l == 0 -> { if (next < 0) next = pos + 1; break }
                l and 0xC0 == 0xC0 -> {
                    val ptr = ((l and 0x3F) shl 8) or u8(b, pos + 1)
                    if (next < 0) next = pos + 2
                    if (++jumps > 64) throw IllegalArgumentException("이름 압축이 반복돼요")
                    pos = ptr
                }
                l > 63 -> throw IllegalArgumentException("이름 길이가 이상해요")
                else -> { if (pos + 1 + l > b.size) throw IllegalArgumentException("이름이 잘렸어요"); sb.append(String(b, pos + 1, l, Charsets.ISO_8859_1)).append('.'); pos += 1 + l }
            }
            if (sb.length > 255) throw IllegalArgumentException("이름이 너무 길어요")
        }
        return (if (sb.isEmpty()) "." else sb.toString().trimEnd('.')) to next
    }

    fun parse(b: ByteArray, len: Int = b.size): DnsMessage? = try {
        val buf = if (len == b.size) b else b.copyOf(len)
        parseOrThrow(buf)
    } catch (_: IllegalArgumentException) { null } catch (_: IndexOutOfBoundsException) { null }

    private fun parseOrThrow(b: ByteArray): DnsMessage {
        if (b.size < 12) throw IllegalArgumentException("너무 짧아요")
        val id = u16(b, 0); val flags = u16(b, 2); val qd = u16(b, 4); val an = u16(b, 6); val ns = u16(b, 8); val ar = u16(b, 10)
        var pos = 12
        val qs = ArrayList<Pair<String, Int>>()
        repeat(qd) { val (n, p) = readName(b, pos); qs += n to u16(b, p); pos = p + 4 }
        fun section(count: Int): List<DnsRecord> {
            val out = ArrayList<DnsRecord>()
            repeat(count) {
                val (n, p) = readName(b, pos)
                val type = u16(b, p); val cls = u16(b, p + 2); val ttl = u32(b, p + 4); val rdlen = u16(b, p + 8); val rd = p + 10
                if (rd + rdlen > b.size) throw IllegalArgumentException("레코드가 잘렸어요")
                pos = rd + rdlen
                if (type != DnsType.OPT) out += decode(b, n, type, cls, ttl, rd, rdlen)
            }
            return out
        }
        val answers = section(an); val auth = section(ns); val add = section(ar)
        return DnsMessage(id, flags, qs, answers, auth, add)
    }

    private fun hex(b: ByteArray, off: Int, len: Int) = (off until off + len).joinToString("") { "%02x".format(b[it].toInt() and 0xff) }
    private fun date(sec: Long) = DateTimeFormatter.ofPattern("yyyy-MM-dd").withZone(ZoneOffset.UTC).format(Instant.ofEpochSecond(sec))

    private fun decode(b: ByteArray, name: String, type: Int, cls: Int, ttl: Long, o: Int, len: Int): DnsRecord {
        fun r(data: String, text: String? = null) = DnsRecord(name, type, cls, ttl, data, text)
        return when (type) {
            DnsType.A -> if (len == 4) r(IpUtil.v4Text(IpUtil.v4ToLong(b.copyOfRange(o, o + 4)))) else r(hex(b, o, len))
            DnsType.AAAA -> if (len == 16) r(IpUtil.format(InetAddress.getByAddress(b.copyOfRange(o, o + 16)))) else r(hex(b, o, len))
            DnsType.NS, DnsType.CNAME, DnsType.PTR -> r(readName(b, o).first)
            DnsType.MX -> r("${u16(b, o)} ${readName(b, o + 2).first}")
            DnsType.TXT -> {
                val parts = ArrayList<String>(); var p = o
                while (p < o + len) { val l = u8(b, p); parts += String(b, p + 1, minOf(l, o + len - p - 1), Charsets.UTF_8); p += 1 + l }
                r(parts.joinToString(" ") { "\"$it\"" }, parts.joinToString(""))
            }
            DnsType.SOA -> {
                val (m, p1) = readName(b, o); val (rn, p2) = readName(b, p1)
                r("$m $rn ${u32(b, p2)} ${u32(b, p2 + 4)} ${u32(b, p2 + 8)} ${u32(b, p2 + 12)} ${u32(b, p2 + 16)}")
            }
            DnsType.SRV -> r("${u16(b, o)} ${u16(b, o + 2)} ${u16(b, o + 4)} ${readName(b, o + 6).first}")
            DnsType.CAA -> { val tl = u8(b, o + 1); r("${u8(b, o)} ${String(b, o + 2, tl, Charsets.US_ASCII)} \"${String(b, o + 2 + tl, len - 2 - tl, Charsets.UTF_8)}\"") }
            DnsType.DS -> r("${u16(b, o)} ${u8(b, o + 2)} ${u8(b, o + 3)} ${hex(b, o + 4, len - 4)}")
            DnsType.DNSKEY -> r("${u16(b, o)} ${u8(b, o + 2)} ${u8(b, o + 3)} " + Base64.getEncoder().encodeToString(b.copyOfRange(o + 4, o + len)).let { if (it.length > 40) it.take(40) + "…" else it })
            DnsType.RRSIG -> {
                val (signer, _) = readName(b, o + 18)
                r("${DnsType.name(u16(b, o))} alg=${u8(b, o + 2)} 서명기간 ${date(u32(b, o + 8))}~${date(u32(b, o + 12))} 키태그=${u16(b, o + 16)} $signer")
            }
            DnsType.HTTPS, DnsType.SVCB -> r("${u16(b, o)} ${readName(b, o + 2).let { it.first }} (매개변수 ${len} 바이트 중 일부 생략)")
            else -> r(hex(b, o, minOf(len, 32)) + if (len > 32) "…" else "")
        }
    }
}

class DnsResponse(val msg: DnsMessage, val ms: Long, val server: String, val viaTcp: Boolean)

object DnsClient {
    private val rnd = java.security.SecureRandom()

    /**
     * server(IP 주소)에 질문을 보내고 응답을 받음. UDP 로 보내고 잘림(TC)이면 TCP 로 다시 물음.
     * 시간 초과는 retries 만큼 다시 시도. 실패하면 IOException.
     */
    fun query(
        server: String, name: String, type: Int, port: Int = 53, timeoutMs: Int = 3000, rd: Boolean = true, dnssec: Boolean = false,
        retries: Int = 1, tcpOnly: Boolean = false, bind: (DatagramSocket) -> Unit = {}, newSocket: () -> Socket = { Socket() },
    ): DnsResponse {
        // "8.8.8.8" 또는 dig 처럼 "8.8.8.8#5353" (포트 지정)
        val addr = IpUtil.parse(server.substringBefore('#')) ?: throw IOException("DNS 서버는 IP 주소로 입력하세요 (예: 8.8.8.8)")
        val port = server.substringAfter('#', "").toIntOrNull() ?: port
        val id = rnd.nextInt(65536)
        val q = DnsWire.buildQuery(id, name, type, rd, dnssec) ?: throw IOException("도메인 이름이 올바르지 않아요")
        val t0 = System.nanoTime()
        fun ms() = (System.nanoTime() - t0) / 1_000_000
        if (!tcpOnly) {
            var last: IOException? = null
            for (attempt in 0..retries) {
                try {
                    val raw = udp(addr, port, q, id, timeoutMs, bind)
                    val m = DnsWire.parse(raw) ?: throw IOException("응답을 해석하지 못했어요")
                    return if (!m.tc) DnsResponse(m, ms(), server, false) else tcp(addr, port, q, timeoutMs, newSocket).let { DnsResponse(it, ms(), server, true) }
                } catch (e: SocketTimeoutException) { last = IOException("응답이 없어요 (${timeoutMs}ms 초과)") }
            }
            throw last ?: IOException("응답이 없어요")
        }
        return DnsResponse(tcp(addr, port, q, timeoutMs, newSocket), ms(), server, true)
    }

    private fun udp(addr: InetAddress, port: Int, q: ByteArray, id: Int, timeoutMs: Int, bind: (DatagramSocket) -> Unit): ByteArray {
        DatagramSocket().use { s ->
            bind(s); s.soTimeout = timeoutMs
            s.send(DatagramPacket(q, q.size, addr, port))
            val buf = ByteArray(4096); val p = DatagramPacket(buf, buf.size)
            val deadline = System.currentTimeMillis() + timeoutMs
            while (true) {
                val left = (deadline - System.currentTimeMillis()).toInt()
                if (left <= 0) throw SocketTimeoutException()
                s.soTimeout = left
                s.receive(p)
                if (p.address == addr && p.length >= 12 && ((buf[0].toInt() and 0xff) shl 8 or (buf[1].toInt() and 0xff)) == id) return buf.copyOf(p.length)
            }
        }
    }

    private fun tcp(addr: InetAddress, port: Int, q: ByteArray, timeoutMs: Int, newSocket: () -> Socket): DnsMessage {
        newSocket().use { s ->
            s.connect(InetSocketAddress(addr, port), timeoutMs); s.soTimeout = timeoutMs
            val out = s.getOutputStream(); out.write(byteArrayOf((q.size shr 8).toByte(), q.size.toByte())); out.write(q); out.flush()
            val ins = s.getInputStream()
            fun readFully(n: Int): ByteArray { val b = ByteArray(n); var o = 0; while (o < n) { val r = ins.read(b, o, n - o); if (r < 0) throw IOException("연결이 끊겼어요"); o += r }; return b }
            val len = readFully(2).let { ((it[0].toInt() and 0xff) shl 8) or (it[1].toInt() and 0xff) }
            return DnsWire.parse(readFully(len)) ?: throw IOException("응답을 해석하지 못했어요")
        }
    }
}

// ---------------------------------------------------------------------------------------------
// 메일 보안 레코드 해석 (SPF · DMARC · DKIM)

class SpfTerm(val qualifier: Char, val mech: String, val value: String?)
class SpfInfo(val terms: List<SpfTerm>, val redirect: String?, val lookups: Int, val allQualifier: Char?, val issues: List<Pair<String, Int>>)

object SpfParser {
    /** TXT 값들 중 SPF 레코드(v=spf1 로 시작)만 */
    fun find(txts: List<String>): List<String> = txts.map { it.trim() }.filter { it.startsWith("v=spf1", true) && (it.length == 6 || it[6] == ' ') }

    fun parse(txt: String): SpfInfo {
        val terms = ArrayList<SpfTerm>(); var redirect: String? = null; var all: Char? = null; var lookups = 0
        val issues = ArrayList<Pair<String, Int>>()
        for (tok in txt.trim().split(Regex("\\s+")).drop(1)) {
            if (tok.contains('=') && !tok.contains(':')) {
                val (k, v) = tok.split('=', limit = 2)
                when (k.lowercase()) { "redirect" -> { redirect = v; lookups++ }; "exp" -> {}; else -> issues += "알 수 없는 항목 \"$tok\"" to 1 }
                continue
            }
            val q = if (tok[0] in "+-~?") tok[0] else '+'
            val body = tok.removePrefix(q.toString()).takeIf { tok[0] in "+-~?" } ?: tok
            val name = body.substringBefore(':').substringBefore('/').lowercase(); val value = if (':' in body) body.substringAfter(':') else if ('/' in body) body.substring(body.indexOf('/')) else null
            when (name) {
                "all" -> all = q
                "include", "exists" -> { lookups++; if (value.isNullOrEmpty()) issues += "$name 에 도메인이 없어요" to 2 }
                "a", "mx" -> lookups++
                "ptr" -> { lookups++; issues += "ptr 는 느리고 폐기 예정이라 쓰지 않는 게 좋아요" to 1 }
                "ip4" -> if (value == null || Cidr4.parse(value) == null) issues += "ip4 값이 올바르지 않아요: ${value ?: ""}" to 2
                "ip6" -> if (value == null || V6.parseCidr(value) == null) issues += "ip6 값이 올바르지 않아요: ${value ?: ""}" to 2
                else -> issues += "알 수 없는 항목 \"$tok\"" to 1
            }
            terms += SpfTerm(q, name, value)
        }
        when (all) {
            '+' -> issues += "+all 은 모든 서버가 이 도메인 이름으로 메일을 보낼 수 있다는 뜻이라 SPF 가 아무 보호도 못 해요" to 2
            '?' -> issues += "?all 은 판단하지 않겠다는 뜻이라 보호 효과가 없어요" to 1
            '~' -> issues += "~all(softfail)은 허용되지 않은 서버의 메일을 의심 표시만 해요. 설정이 안정되면 -all 로 올리세요" to 0
            '-' -> issues += "-all 로 끝나서 허용하지 않은 서버의 메일을 거부해요 (가장 엄격)" to -1
            null -> if (redirect == null) issues += "끝에 all 이 없어서 나머지 서버를 어떻게 다룰지 정해지지 않았어요" to 1
        }
        if (lookups > 10) issues += "DNS 조회가 ${lookups}번이라 한도(10번)를 넘었어요. 이러면 SPF 가 오류(permerror)로 처리돼요" to 2
        else if (lookups > 8) issues += "DNS 조회가 ${lookups}번으로 한도(10번)에 가까워요" to 1
        return SpfInfo(terms, redirect, lookups, all, issues)
    }
}

class DmarcInfo(val tags: LinkedHashMap<String, String>, val issues: List<Pair<String, Int>>)

object DmarcParser {
    fun find(txts: List<String>): List<String> = txts.map { it.trim() }.filter { it.startsWith("v=DMARC1", true) }

    fun parse(txt: String): DmarcInfo {
        val tags = LinkedHashMap<String, String>()
        for (part in txt.split(';')) { val t = part.trim(); if (t.isEmpty()) continue; val k = t.substringBefore('=').trim().lowercase(); tags[k] = t.substringAfter('=', "").trim() }
        val issues = ArrayList<Pair<String, Int>>()
        if (tags.keys.firstOrNull() != "v" || !tags["v"].equals("DMARC1", true)) issues += "v=DMARC1 이 맨 앞에 있어야 해요" to 2
        val p = tags["p"]?.lowercase()
        when (p) {
            null -> issues += "p(정책)가 없어요. 필수 항목이에요" to 2
            "none" -> issues += "p=none: 보고서만 받고 아무것도 막지 않아요. 정상 메일이 모두 통과하면 quarantine → reject 로 올리세요" to 1
            "quarantine" -> issues += "p=quarantine: 인증에 실패한 메일을 스팸함으로 보내요" to -1
            "reject" -> issues += "p=reject: 인증에 실패한 메일을 거부해요 (가장 강력)" to -1
            else -> issues += "p 값이 올바르지 않아요 (none · quarantine · reject)" to 2
        }
        tags["pct"]?.let { v -> val n = v.toIntOrNull(); if (n == null || n !in 0..100) issues += "pct 는 0~100 이어야 해요" to 2 else if (n < 100) issues += "pct=$n: 정책을 메일의 ${n}%에만 적용해요" to 1 }
        tags["sp"]?.let { if (it.lowercase() !in listOf("none", "quarantine", "reject")) issues += "sp 값이 올바르지 않아요" to 2 }
        for (k in listOf("adkim", "aspf")) tags[k]?.let { if (it.lowercase() !in listOf("r", "s")) issues += "$k 는 r(느슨) 또는 s(엄격)이어야 해요" to 2 }
        if (tags["rua"].isNullOrEmpty()) issues += "rua(집계 보고서 주소)가 없어서 누가 내 도메인으로 메일을 보내는지 볼 수 없어요" to 1
        else if (!tags["rua"]!!.split(',').all { it.trim().startsWith("mailto:", true) }) issues += "rua 는 mailto:주소 형식이어야 해요" to 2
        return DmarcInfo(tags, issues)
    }
}

class DkimInfo(val tags: LinkedHashMap<String, String>, val keyDesc: String?, val issues: List<Pair<String, Int>>)

object DkimParser {
    fun find(txts: List<String>): List<String> = txts.map { it.trim() }.filter { it.contains("p=") || it.startsWith("v=DKIM1", true) }

    fun parse(txt: String): DkimInfo {
        val tags = LinkedHashMap<String, String>()
        for (part in txt.split(';')) { val t = part.trim(); if (t.isEmpty()) continue; tags[t.substringBefore('=').trim().lowercase()] = t.substringAfter('=', "").trim().replace(" ", "") }
        val issues = ArrayList<Pair<String, Int>>()
        val k = (tags["k"] ?: "rsa").lowercase(); val p = tags["p"]
        var desc: String? = null
        when {
            p == null -> issues += "p(공개키)가 없어요" to 2
            p.isEmpty() -> issues += "p 가 비어 있어요: 이 키는 폐기(revoked)됐어요" to 1
            k == "ed25519" -> desc = "Ed25519"
            else -> try {
                val key = KeyFactory.getInstance("RSA").generatePublic(X509EncodedKeySpec(Base64.getDecoder().decode(p))) as RSAPublicKey
                val bits = key.modulus.bitLength(); desc = "RSA ${bits}비트"
                if (bits < 1024) issues += "키가 ${bits}비트라 너무 약해요 (2048비트 권장)" to 2 else if (bits < 2048) issues += "키가 ${bits}비트예요. 2048비트로 올리는 것을 권장해요" to 1 else issues += "키 길이가 충분해요 (${bits}비트)" to -1
            } catch (_: Exception) { issues += "공개키(p)를 해석하지 못했어요" to 2 }
        }
        if (tags["t"]?.contains("y") == true) issues += "t=y: 시험 모드예요. 운영 중이라면 제거하세요" to 1
        return DkimInfo(tags, desc, issues)
    }
}

/** Team Cymru 의 IP→ASN DNS 응답 해석: "13335 | 1.1.1.0/24 | AU | apnic | 2011-08-11" */
class AsnInfo(val asn: String, val prefix: String, val country: String, val registry: String, val allocated: String, val name: String?)

object Cymru {
    fun parseOrigin(txt: String): Triple<String, String, List<String>>? {
        val f = txt.split('|').map { it.trim() }
        return if (f.size >= 5) Triple(f[0].split(' ').first(), f[1], f.drop(2)) else null
    }

    fun parseName(txt: String): String? = txt.split('|').map { it.trim() }.getOrNull(4)

    fun originName(a: InetAddress): String =
        if (a.address.size == 4) Ptr.name(a).removeSuffix(".in-addr.arpa") + ".origin.asn.cymru.com"
        else Ptr.name(a).removeSuffix(".ip6.arpa") + ".origin6.asn.cymru.com"
}

