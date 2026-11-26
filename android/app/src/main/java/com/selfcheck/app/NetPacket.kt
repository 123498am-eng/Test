package com.selfcheck.app

import java.net.InetAddress
import java.security.MessageDigest

/*
 * 패킷 해석 엔진: 16진수 글 → 바이트, 인터넷 체크섬(RFC 1071), 이더넷·VLAN·IPv4·IPv6·TCP·UDP·ICMP·ICMPv6·ARP 디코더(체크섬 검증 포함),
 * DNS·TLS·HTTP·DHCP·NTP 응용 계층 풀이, TLS ClientHello/ServerHello(JA3), pcap/pcapng 읽기, 패킷 만들기.
 * 모두 붙여 넣은 바이트나 고른 파일만 읽고, 어디로도 보내지 않아요. 안드로이드가 못 읽는 최신 자바 API 는 쓰지 않았어요.
 */

object Bx {
    fun u8(b: ByteArray, i: Int) = b[i].toInt() and 0xff
    fun u16(b: ByteArray, i: Int) = (u8(b, i) shl 8) or u8(b, i + 1)
    fun u32(b: ByteArray, i: Int) = (u16(b, i).toLong() shl 16) or u16(b, i + 2).toLong()
    fun hex(b: ByteArray, from: Int = 0, to: Int = b.size, sep: String = " ") = (from until to).joinToString(sep) { "%02x".format(b[it].toInt() and 0xff) }
    fun mac(b: ByteArray, i: Int) = (0 until 6).joinToString(":") { "%02x".format(u8(b, i + it)) }
    fun ip4(b: ByteArray, i: Int) = "${u8(b, i)}.${u8(b, i + 1)}.${u8(b, i + 2)}.${u8(b, i + 3)}"
    fun ip6(b: ByteArray, i: Int): String = IpUtil.format(InetAddress.getByAddress(b.copyOfRange(i, i + 16)))
    fun printable(b: ByteArray, from: Int, to: Int) = (from until to).joinToString("") { val c = u8(b, it); if (c in 32..126) c.toChar().toString() else "·" }
    fun be16(v: Int) = byteArrayOf((v ushr 8).toByte(), v.toByte())
    fun be32(v: Long) = byteArrayOf((v ushr 24).toByte(), (v ushr 16).toByte(), (v ushr 8).toByte(), v.toByte())
    fun parseMac(s: String): ByteArray? { val t = s.trim().replace('-', ':').split(':'); if (t.size != 6 || t.any { it.length !in 1..2 || it.toIntOrNull(16) == null }) return null; return ByteArray(6) { t[it].toInt(16).toByte() } }
}

/**
 * 붙여 넣은 16진수 글 → 바이트. 공백·콜론·쉼표·0x·\x·{} 를 허용하고, 덤프 형식의 줄 앞 오프셋과 뒤쪽 글자 칸은 걷어 내요:
 * tcpdump -x/-xx/-X(0x0000:), hexdump -C·xxd(8자리 오프셋), 와이어샤크·scapy(4자리), text2pcap(6자리).
 */
object PacketHex {
    private val TCPDUMP = Regex("^0x([0-9a-fA-F]{2,}):\\s*(.*)$")
    private val OFF8 = Regex("^([0-9a-fA-F]{8})(?::\\s+|\\s{2,})(.*)$")
    private val OFF4 = Regex("^([0-9a-fA-F]{4})\\s{2,}(.*)$")
    private val OFF6 = Regex("^([0-9a-fA-F]{6})\\s+(.*)$")
    private fun isHex(c: Char) = c in '0'..'9' || c in 'a'..'f' || c in 'A'..'F'

    /** 오프셋 뒤의 한 줄에서 16진수 칸만 (3칸 이상 띄어지거나 16바이트를 채우거나 | 를 만나면 글자 칸으로 보고 끝) */
    private fun hexPart(s: String): String {
        val sb = StringBuilder(); var bytes = 0; var i = 0
        while (i < s.length && bytes < 16) {
            var sp = 0; while (i < s.length && s[i] == ' ') { sp++; i++ }
            if (i >= s.length || (sp >= 3 && bytes > 0)) break
            var j = i; while (j < s.length && isHex(s[j])) j++
            val tok = s.substring(i, j)
            if (tok.isEmpty() || tok.length % 2 != 0 || tok.length > 8 || (j < s.length && s[j] != ' ' && s[j] != '|')) break
            sb.append(tok); bytes += tok.length / 2; i = j
            if (i < s.length && s[i] == '|') break
        }
        return sb.toString()
    }

    fun parse(text: String): ByteArray? {
        val sb = StringBuilder(); var total = 0
        for (raw in text.lines()) {
            val line = raw.replace('\r', ' ').replace('\t', ' ').trim(); if (line.isEmpty()) continue
            var part: String? = null
            TCPDUMP.find(line)?.let { part = hexPart(it.groupValues[2]) }
            if (part == null) OFF8.find(line)?.let { part = hexPart(it.groupValues[2]) }
            if (part == null) OFF4.find(line)?.let { m -> if (m.groupValues[1].toInt(16) == total) part = hexPart(m.groupValues[2]) }
            if (part == null) OFF6.find(line)?.let { m -> if (m.groupValues[1].toInt(16) == total) part = hexPart(m.groupValues[2]) }
            val p = part ?: line
            sb.append(p); if (part != null) total += p.length / 2
        }
        val h = sb.toString().replace(Regex("(?i)\\\\x|0x"), "").filter { !it.isWhitespace() && it !in ":,-{}[];" }
        if (h.isEmpty() || h.length % 2 != 0 || !h.all { isHex(it) }) return null
        return ByteArray(h.length / 2) { h.substring(it * 2, it * 2 + 2).toInt(16).toByte() }
    }
}

/** 인터넷 체크섬 (RFC 1071) */
object InetChecksum {
    /** 16비트 덧셈(올림 접기) — 보수를 취하기 전 값. init 은 의사 머리글 합 */
    fun sum(data: ByteArray, from: Int = 0, to: Int = data.size, init: Long = 0): Long {
        var s = init; var i = from
        while (i + 1 < to) { s += ((data[i].toInt() and 0xff) shl 8) or (data[i + 1].toInt() and 0xff); i += 2 }
        if (i < to) s += (data[i].toInt() and 0xff) shl 8
        while (s ushr 16 != 0L) s = (s and 0xffff) + (s ushr 16)
        return s
    }
    fun checksum(data: ByteArray, from: Int = 0, to: Int = data.size, init: Long = 0): Int = (sum(data, from, to, init).inv() and 0xffff).toInt()
    fun valid(data: ByteArray, from: Int, to: Int, init: Long = 0): Boolean = sum(data, from, to, init) == 0xffffL
    fun pseudoV4(src: ByteArray, dst: ByteArray, proto: Int, len: Int): Long = sum(src + dst + byteArrayOf(0, proto.toByte()) + Bx.be16(len))
    fun pseudoV6(src: ByteArray, dst: ByteArray, next: Int, len: Int): Long = sum(src + dst + Bx.be32(len.toLong()) + byteArrayOf(0, 0, 0, next.toByte()))
}

object PacketNames {
    val PROTO = mapOf(1 to "ICMP", 2 to "IGMP", 4 to "IP-in-IP", 6 to "TCP", 17 to "UDP", 41 to "IPv6 캡슐", 47 to "GRE", 50 to "ESP(IPsec)", 51 to "AH(IPsec)", 58 to "ICMPv6", 89 to "OSPF", 103 to "PIM", 112 to "VRRP", 132 to "SCTP")
    val ETHER = mapOf(0x0800 to "IPv4", 0x86DD to "IPv6", 0x0806 to "ARP", 0x8100 to "VLAN(802.1Q)", 0x88A8 to "VLAN(802.1ad)", 0x8847 to "MPLS", 0x88CC to "LLDP", 0x8863 to "PPPoE 탐색", 0x8864 to "PPPoE 세션", 0x0842 to "Wake-on-LAN")
    val ICMP_TYPE = mapOf(0 to "Echo 응답(ping 답)", 3 to "목적지 도달 불가", 4 to "Source Quench(폐기됨)", 5 to "경로 재지정(Redirect)", 8 to "Echo 요청(ping)", 9 to "라우터 광고", 10 to "라우터 요청", 11 to "시간 초과(TTL 만료)", 12 to "매개변수 오류", 13 to "타임스탬프 요청", 14 to "타임스탬프 응답")
    val ICMP_UNREACH = mapOf(0 to "네트워크 도달 불가", 1 to "호스트 도달 불가", 2 to "프로토콜 도달 불가", 3 to "포트 도달 불가(그 포트를 듣는 프로그램이 없음)", 4 to "조각화가 필요하지만 DF 가 켜져 있음(MTU 문제)", 5 to "소스 라우트 실패", 9 to "목적지 네트워크 관리상 금지", 10 to "목적지 호스트 관리상 금지", 13 to "관리자가 통신을 막음(방화벽)")
    val ICMP6_TYPE = mapOf(1 to "목적지 도달 불가", 2 to "패킷이 너무 큼(MTU)", 3 to "시간 초과(Hop Limit 만료)", 4 to "매개변수 오류", 128 to "Echo 요청(ping)", 129 to "Echo 응답(ping 답)", 133 to "라우터 요청(RS)", 134 to "라우터 광고(RA)", 135 to "이웃 요청(NS)", 136 to "이웃 광고(NA)", 137 to "재지정")
    val SERVICE = mapOf(20 to "FTP 데이터", 21 to "FTP", 22 to "SSH", 23 to "Telnet", 25 to "SMTP", 53 to "DNS", 67 to "DHCP 서버", 68 to "DHCP 클라이언트", 80 to "HTTP", 110 to "POP3", 123 to "NTP", 143 to "IMAP", 161 to "SNMP", 389 to "LDAP", 443 to "HTTPS", 445 to "SMB", 465 to "SMTPS", 514 to "Syslog", 587 to "SMTP 제출", 993 to "IMAPS", 995 to "POP3S", 1883 to "MQTT", 1900 to "SSDP", 3306 to "MySQL", 3389 to "RDP", 5353 to "mDNS", 5432 to "PostgreSQL", 6379 to "Redis", 8080 to "HTTP 대체", 8443 to "HTTPS 대체")
}

// ---------------------------------------------------------------------------------------------
// TLS ClientHello / ServerHello

object TlsHello {
    class Ext(val type: Int, val data: ByteArray)
    class Hello(val client: Boolean, val recordVersion: Int?, val version: Int, val random: ByteArray, val sessionId: ByteArray, val ciphers: List<Int>, val compression: List<Int>, val exts: List<Ext>, val sni: String?, val alpn: List<String>,
                val groups: List<Int>, val ecFormats: List<Int>, val sigAlgs: List<Int>, val supportedVersions: List<Int>, val keyShareGroups: List<Int>, val ja3: String, val ja3Hash: String, val complete: Boolean = true)

    val GREASE: Set<Int> = (0..15).map { ((it * 0x10 + 0x0a) shl 8) or (it * 0x10 + 0x0a) }.toSet()
    fun isGrease(v: Int) = v in GREASE

    val VERSIONS = mapOf(0x0300 to "SSL 3.0", 0x0301 to "TLS 1.0", 0x0302 to "TLS 1.1", 0x0303 to "TLS 1.2", 0x0304 to "TLS 1.3")
    val CIPHERS = mapOf(0x1301 to "TLS_AES_128_GCM_SHA256", 0x1302 to "TLS_AES_256_GCM_SHA384", 0x1303 to "TLS_CHACHA20_POLY1305_SHA256", 0xc02b to "ECDHE-ECDSA-AES128-GCM-SHA256", 0xc02c to "ECDHE-ECDSA-AES256-GCM-SHA384", 0xc02f to "ECDHE-RSA-AES128-GCM-SHA256",
        0xc030 to "ECDHE-RSA-AES256-GCM-SHA384", 0xcca8 to "ECDHE-RSA-CHACHA20-POLY1305", 0xcca9 to "ECDHE-ECDSA-CHACHA20-POLY1305", 0xc009 to "ECDHE-ECDSA-AES128-SHA", 0xc00a to "ECDHE-ECDSA-AES256-SHA", 0xc013 to "ECDHE-RSA-AES128-SHA", 0xc014 to "ECDHE-RSA-AES256-SHA",
        0x009c to "AES128-GCM-SHA256", 0x009d to "AES256-GCM-SHA384", 0x002f to "AES128-SHA", 0x0035 to "AES256-SHA", 0x003c to "AES128-SHA256", 0x003d to "AES256-SHA256", 0x000a to "DES-CBC3-SHA(3DES, 약함)", 0x0005 to "RC4-SHA(RC4, 약함)", 0x0004 to "RC4-MD5(RC4, 약함)",
        0x0009 to "DES-CBC-SHA(DES, 약함)", 0x0003 to "EXP-RC4-MD5(수출용, 약함)", 0x0001 to "NULL-MD5(암호화 없음)", 0x0002 to "NULL-SHA(암호화 없음)", 0x00ff to "TLS_EMPTY_RENEGOTIATION_INFO_SCSV", 0x5600 to "TLS_FALLBACK_SCSV", 0x009e to "DHE-RSA-AES128-GCM-SHA256", 0x009f to "DHE-RSA-AES256-GCM-SHA384", 0x0033 to "DHE-RSA-AES128-SHA", 0x0039 to "DHE-RSA-AES256-SHA",
        0x0006 to "EXP-RC2-CBC-MD5(수출용, 약함)", 0x0008 to "EXP-DES-CBC-SHA(수출용, 약함)", 0x0013 to "DHE-DSS-DES-CBC3-SHA(3DES, 약함)", 0x0015 to "DHE-RSA-DES-CBC-SHA(DES, 약함)", 0x0016 to "DHE-RSA-DES-CBC3-SHA(3DES, 약함)", 0x0018 to "ADH-RC4-MD5(인증 없음, 약함)",
        0x0034 to "ADH-AES128-SHA(인증 없음, 약함)", 0x003a to "ADH-AES256-SHA(인증 없음, 약함)", 0xc007 to "ECDHE-ECDSA-RC4-SHA(RC4, 약함)", 0xc008 to "ECDHE-ECDSA-DES-CBC3-SHA(3DES, 약함)", 0xc011 to "ECDHE-RSA-RC4-SHA(RC4, 약함)", 0xc012 to "ECDHE-RSA-DES-CBC3-SHA(3DES, 약함)")
    val EXTENSIONS = mapOf(0 to "server_name(SNI)", 5 to "status_request(OCSP)", 10 to "supported_groups", 11 to "ec_point_formats", 13 to "signature_algorithms", 14 to "use_srtp", 16 to "ALPN", 18 to "signed_certificate_timestamp", 21 to "padding", 23 to "extended_master_secret",
        27 to "compress_certificate", 28 to "record_size_limit", 35 to "session_ticket", 41 to "pre_shared_key", 42 to "early_data", 43 to "supported_versions", 44 to "cookie", 45 to "psk_key_exchange_modes", 49 to "post_handshake_auth", 50 to "signature_algorithms_cert", 51 to "key_share",
        13172 to "next_protocol_negotiation", 17513 to "application_settings", 65037 to "encrypted_client_hello(ECH)", 65281 to "renegotiation_info")
    val GROUPS = mapOf(23 to "secp256r1", 24 to "secp384r1", 25 to "secp521r1", 29 to "x25519", 30 to "x448", 256 to "ffdhe2048", 257 to "ffdhe3072", 258 to "ffdhe4096", 0x6399 to "X25519Kyber768(양자 내성)", 0x11ec to "X25519MLKEM768(양자 내성)")
    val SIGS = mapOf(0x0401 to "rsa_pkcs1_sha256", 0x0501 to "rsa_pkcs1_sha384", 0x0601 to "rsa_pkcs1_sha512", 0x0403 to "ecdsa_secp256r1_sha256", 0x0503 to "ecdsa_secp384r1_sha384", 0x0603 to "ecdsa_secp521r1_sha512", 0x0804 to "rsa_pss_rsae_sha256", 0x0805 to "rsa_pss_rsae_sha384",
        0x0806 to "rsa_pss_rsae_sha512", 0x0807 to "ed25519", 0x0808 to "ed448", 0x0201 to "rsa_pkcs1_sha1(약함)", 0x0203 to "ecdsa_sha1(약함)")

    fun name(m: Map<Int, String>, v: Int): String = if (isGrease(v)) "GREASE(무작위 자리표시)" else m[v] ?: "0x%04x".format(v)

    /** 이름에 "약함"·"암호화 없음"이 붙은 암호군 (RC4·3DES·DES·수출용·NULL·인증 없음) */
    fun isWeakCipher(c: Int): Boolean = CIPHERS[c]?.let { it.contains("약함") || it.contains("암호화 없음") } ?: false

    private fun list16(d: ByteArray, off: Int, step: Int): List<Int> { val n = Bx.u16(d, off); return (0 until n / step).map { k -> if (step == 2) Bx.u16(d, off + 2 + k * 2) else Bx.u8(d, off + 2 + k) } }

    /** TLS 기록(0x16 03 0x …)·핸드셰이크 본문(01/02 …)·그 앞에 이더넷/IP/TCP 가 붙은 패킷 어디서든 첫 Hello 를 찾음 */
    fun parse(bytes: ByteArray): Hello? {
        for (start in 0 until minOf(bytes.size - 9, 200)) {
            if (Bx.u8(bytes, start) == 0x16 && Bx.u8(bytes, start + 1) == 3 && Bx.u8(bytes, start + 2) in 0..4 && Bx.u8(bytes, start + 5) in 1..2) {
                parseHandshake(bytes, start + 5, Bx.u16(bytes, start + 1))?.let { return it }
            }
        }
        return if (bytes.size > 4 && Bx.u8(bytes, 0) in 1..2) parseHandshake(bytes, 0, null) else null
    }

    private fun parseHandshake(b: ByteArray, off0: Int, recVer: Int?): Hello? = try {
        var p = off0; val type = Bx.u8(b, p); require(type == 1 || type == 2); val len = (Bx.u8(b, p + 1) shl 16) or Bx.u16(b, p + 2); p += 4; val end = minOf(b.size, p + len)
        val ver = Bx.u16(b, p); p += 2; val random = b.copyOfRange(p, p + 32); p += 32
        val sid = b.copyOfRange(p + 1, p + 1 + Bx.u8(b, p)); p += 1 + sid.size
        val ciphers: List<Int>; val comp: List<Int>
        if (type == 1) { ciphers = list16(b, p, 2); p += 2 + Bx.u16(b, p); val cn = Bx.u8(b, p); comp = (0 until cn).map { Bx.u8(b, p + 1 + it) }; p += 1 + cn }
        else { ciphers = listOf(Bx.u16(b, p)); p += 2; comp = listOf(Bx.u8(b, p)); p += 1 }
        val exts = ArrayList<Ext>()
        if (p + 2 <= end) { val el = Bx.u16(b, p); p += 2; val ee = minOf(end, p + el); while (p + 4 <= ee) { val t = Bx.u16(b, p); val l = Bx.u16(b, p + 2); exts += Ext(t, b.copyOfRange(p + 4, minOf(ee, p + 4 + l))); p += 4 + l } }
        fun ext(t: Int) = exts.firstOrNull { it.type == t }?.data
        val sni = ext(0)?.let { d -> if (d.size > 5) String(d, 5, minOf(Bx.u16(d, 3), d.size - 5), Charsets.ISO_8859_1) else null }
        val alpn = ext(16)?.let { d -> val out = ArrayList<String>(); var q = 2; while (q < d.size) { val l = Bx.u8(d, q); if (q + 1 + l > d.size) break; out += String(d, q + 1, l, Charsets.ISO_8859_1); q += 1 + l }; out } ?: emptyList()
        val groups = ext(10)?.let { list16(it, 0, 2) } ?: emptyList(); val ecf = ext(11)?.let { d -> (0 until Bx.u8(d, 0)).map { Bx.u8(d, 1 + it) } } ?: emptyList(); val sigs = ext(13)?.let { list16(it, 0, 2) } ?: emptyList()
        val sv = ext(43)?.let { d -> if (type == 1) (0 until Bx.u8(d, 0) / 2).map { Bx.u16(d, 1 + it * 2) } else listOf(Bx.u16(d, 0)) } ?: emptyList()
        val ks = ext(51)?.let { d -> if (type == 1) { val out = ArrayList<Int>(); var q = 2; while (q + 4 <= d.size) { out += Bx.u16(d, q); q += 4 + Bx.u16(d, q + 2) }; out } else listOf(Bx.u16(d, 0)) } ?: emptyList()
        val ja3 = if (type == 1) listOf(ver.toString(), ciphers.filter { !isGrease(it) }.joinToString("-"), exts.map { it.type }.filter { !isGrease(it) }.joinToString("-"), groups.filter { !isGrease(it) }.joinToString("-"), ecf.joinToString("-")).joinToString(",")
                  else listOf(ver.toString(), ciphers.first().toString(), exts.map { it.type }.joinToString("-")).joinToString(",")
        Hello(type == 1, recVer, ver, random, sid, ciphers, comp, exts, sni, alpn, groups, ecf, sigs, sv, ks, ja3, MessageDigest.getInstance("MD5").digest(ja3.toByteArray()).joinToString("") { "%02x".format(it.toInt() and 0xff) }, off0 + 4 + len <= b.size)
    } catch (_: Exception) { null }
}

// ---------------------------------------------------------------------------------------------
// 계층별 디코더

object PacketDecode {
    class Layer(val name: String, val fields: List<Pair<String, String>>, val notes: List<Pair<String, Int>> = emptyList())
    class Decoded(val layers: List<Layer>, val summary: String, val truncated: Boolean)

    private class Ctx(val src: ByteArray, val dst: ByteArray, val v6: Boolean)

    /** 이더넷 머리글 없이 IP 머리글부터 시작하는 데이터인지 (tcpdump -x 는 IP 부터, 와이어샤크 복사는 보통 이더넷부터) */
    fun looksLikeIp(b: ByteArray): Boolean {
        if (b.size < 20) return false
        val v = Bx.u8(b, 0) shr 4
        if (v == 4) {
            val ihl = (Bx.u8(b, 0) and 15) * 4
            if (ihl < 20 || ihl > b.size) return false
            val total = Bx.u16(b, 2)
            if (total < ihl) return false
            return InetChecksum.valid(b, 0, ihl) || (Bx.u16(b, 10) == 0 && total <= b.size)
        }
        if (v == 6) return b.size >= 40 && Bx.u8(b, 6) in setOf(0, 4, 6, 17, 41, 43, 44, 47, 50, 51, 58, 60, 132) && Bx.u16(b, 4) + 40 <= b.size + 1500
        return false
    }

    fun decode(b: ByteArray, start: String = "auto"): Decoded {
        val layers = ArrayList<Layer>(); var trunc = false
        val mode = when (start) { "eth" -> "eth"; "ip" -> "ip"; else -> if (looksLikeIp(b)) "ip" else "eth" }
        var etherType: Int; var off = 0
        if (mode == "eth") {
            if (b.size < 14) return Decoded(listOf(Layer("이더넷", emptyList(), listOf("14바이트보다 짧아서 이더넷 머리글을 읽을 수 없어요" to 2))), "너무 짧은 데이터", true)
            val notes = ArrayList<Pair<String, Int>>(); val dst = Bx.mac(b, 0); val srcM = Bx.mac(b, 6); etherType = Bx.u16(b, 12); off = 14
            val f = arrayListOf("목적지 MAC" to dst + macKind(b[0].toInt()), "출발지 MAC" to srcM + macKind(b[6].toInt()))
            while ((etherType == 0x8100 || etherType == 0x88A8) && off + 4 <= b.size) { val tci = Bx.u16(b, off); f += "VLAN 태그" to "VLAN ID ${tci and 0xfff} · 우선순위 ${tci shr 13}${if (tci and 0x1000 != 0) " · DEI" else ""}"; etherType = Bx.u16(b, off + 2); off += 4 }
            f += "EtherType" to "0x%04x (%s)".format(etherType, PacketNames.ETHER[etherType] ?: "알 수 없음")
            if (b[6].toInt() and 2 != 0) notes += "출발지 MAC 의 '로컬 관리' 비트가 켜져 있어요: 제조사가 붙인 주소가 아니에요. 폰·PC 의 임의(무작위) MAC 기능일 수도, 가상 머신·컨테이너(52:54:00 은 QEMU/KVM, 02:42 는 Docker 기본값)일 수도, 관리자가 정한 주소일 수도 있어요" to 0
            layers += Layer("이더넷", f, notes)
        } else { etherType = if (Bx.u8(b, 0) shr 4 == 6) 0x86DD else 0x0800 }
        var summary = ""
        when (etherType) {
            0x0800 -> summary = ipv4(b, off, layers).also { trunc = it.second }.first
            0x86DD -> summary = ipv6(b, off, layers).also { trunc = it.second }.first
            0x0806 -> summary = arp(b, off, layers)
            else -> layers += Layer("알 수 없는 상위 프로토콜", listOf("데이터(처음 32바이트)" to Bx.hex(b, off, minOf(b.size, off + 32))), listOf("EtherType 0x%04x 는 이 도구가 풀지 못해요".format(etherType) to 1))
        }
        return Decoded(layers, summary, trunc)
    }

    private fun macKind(first: Int): String = when { first and 0xff == 0xff -> "  (브로드캐스트)"; first and 1 != 0 -> "  (멀티캐스트)"; else -> "" }

    private fun ipv4(b: ByteArray, off: Int, layers: ArrayList<Layer>): Pair<String, Boolean> {
        if (b.size < off + 20) { layers += Layer("IPv4", emptyList(), listOf("IPv4 머리글(20바이트)보다 짧아요" to 2)); return "잘린 IPv4" to true }
        val ihl = (Bx.u8(b, off) and 15) * 4; val total = Bx.u16(b, off + 2); val proto = Bx.u8(b, off + 9); val ttl = Bx.u8(b, off + 8); val fl = Bx.u16(b, off + 6)
        val src = b.copyOfRange(off + 12, off + 16); val dst = b.copyOfRange(off + 16, off + 20); val notes = ArrayList<Pair<String, Int>>()
        val hdrOk = ihl >= 20 && off + ihl <= b.size && InetChecksum.valid(b, off, off + ihl)
        if (Bx.u8(b, off) shr 4 != 4) notes += "버전 칸이 4 가 아니에요" to 2
        if (ihl > 20) notes += "IP 옵션이 있어요(${ihl - 20}바이트): 소스 라우팅 같은 옵션은 보안상 막는 곳이 많아요" to 1
        if (!hdrOk) notes += "머리글 체크섬이 맞지 않아요(저장된 값 0x%04x, 계산한 값 0x%04x). 손상됐거나 NIC 가 보내는 쪽에서 나중에 채우는 오프로드일 수 있어요".format(Bx.u16(b, off + 10), InetChecksum.checksum(b.copyOf().also { it[off + 10] = 0; it[off + 11] = 0 }, off, off + ihl)) to 1
        if (fl and 0x2000 != 0 || fl and 0x1fff != 0) notes += "조각난(fragment) 패킷이에요: 첫 조각이 아니면 TCP/UDP 머리글이 없어요" to 1
        notes += ttlNote(ttl)
        val sk = IpUtil.classify(InetAddress.getByAddress(src)).label.substringBefore(" ("); val dk = IpUtil.classify(InetAddress.getByAddress(dst)).label.substringBefore(" (")
        layers += Layer("IPv4", listOf("버전·헤더 길이" to "4 · ${ihl}바이트", "DSCP/ECN" to "0x%02x".format(Bx.u8(b, off + 1)), "전체 길이" to "${total}바이트", "식별자(ID)" to "0x%04x".format(Bx.u16(b, off + 4)),
            "플래그" to (listOfNotNull(if (fl and 0x4000 != 0) "DF(조각내지 말 것)" else null, if (fl and 0x2000 != 0) "MF(뒤에 조각 있음)" else null).joinToString(" · ").ifEmpty { "없음" }), "조각 오프셋" to "${(fl and 0x1fff) * 8}바이트", "TTL" to "$ttl",
            "프로토콜" to "$proto (${PacketNames.PROTO[proto] ?: "알 수 없음"})", "머리글 체크섬" to "0x%04x (%s)".format(Bx.u16(b, off + 10), if (hdrOk) "맞아요" else "틀려요"), "출발지 IP" to "${Bx.ip4(src, 0)}  ($sk)", "목적지 IP" to "${Bx.ip4(dst, 0)}  ($dk)"), notes)
        val end = minOf(b.size, off + total.coerceAtLeast(ihl)); val trunc = off + total > b.size
        val body = off + ihl
        val ctx = Ctx(src, dst, false)
        val head = "${Bx.ip4(src, 0)} → ${Bx.ip4(dst, 0)}"
        if (fl and 0x1fff != 0) return "$head 조각" to trunc
        return (l4(b, body, end, proto, ctx, total - ihl, trunc, layers, head)) to trunc
    }

    private fun ttlNote(ttl: Int): Pair<String, Int> {
        val init = listOf(32, 64, 128, 255).first { it >= ttl }
        return "TTL $ttl → 처음 값이 $init 이라면 ${init - ttl}개의 장비(홉)를 지나왔어요 (64 는 리눅스·맥·안드로이드·iOS, 128 은 윈도, 255 는 네트워크 장비가 흔해요)" to 0
    }

    private fun ipv6(b: ByteArray, off: Int, layers: ArrayList<Layer>): Pair<String, Boolean> {
        if (b.size < off + 40) { layers += Layer("IPv6", emptyList(), listOf("IPv6 머리글(40바이트)보다 짧아요" to 2)); return "잘린 IPv6" to true }
        val pl = Bx.u16(b, off + 4); var next = Bx.u8(b, off + 6); val hop = Bx.u8(b, off + 7); val src = b.copyOfRange(off + 8, off + 24); val dst = b.copyOfRange(off + 24, off + 40)
        val tcls = ((Bx.u8(b, off) and 15) shl 4) or (Bx.u8(b, off + 1) shr 4); val flow = ((Bx.u8(b, off + 1) and 15) shl 16) or Bx.u16(b, off + 2)
        val f = arrayListOf("버전" to "6", "트래픽 클래스" to "0x%02x".format(tcls), "플로 레이블" to "0x%05x".format(flow), "페이로드 길이" to "${pl}바이트", "홉 제한" to "$hop", "출발지 IP" to Bx.ip6(src, 0), "목적지 IP" to Bx.ip6(dst, 0))
        var p = off + 40; val ext = ArrayList<String>()
        while (next in listOf(0, 43, 44, 60) && p + 8 <= b.size) { ext += PacketNames.PROTO[next] ?: when (next) { 0 -> "Hop-by-Hop"; 43 -> "라우팅"; 44 -> "조각(Fragment)"; else -> "목적지 옵션" }; val nn = Bx.u8(b, p); p += if (next == 44) 8 else (Bx.u8(b, p + 1) + 1) * 8; next = nn }
        f += "다음 헤더" to "$next (${PacketNames.PROTO[next] ?: "알 수 없음"})"; if (ext.isNotEmpty()) f += "확장 헤더" to ext.joinToString(" → ")
        layers += Layer("IPv6", f)
        val end = minOf(b.size, off + 40 + pl); val trunc = off + 40 + pl > b.size
        val head = "${Bx.ip6(src, 0)} → ${Bx.ip6(dst, 0)}"
        return l4(b, p, end, next, Ctx(src, dst, true), off + 40 + pl - p, trunc, layers, head) to trunc
    }

    private fun l4(b: ByteArray, p: Int, end: Int, proto: Int, ctx: Ctx, declaredLen: Int, trunc: Boolean, layers: ArrayList<Layer>, head: String): String = when (proto) {
        6 -> tcp(b, p, end, ctx, declaredLen, trunc, layers, head)
        17 -> udp(b, p, end, ctx, trunc, layers, head)
        1 -> icmp(b, p, end, trunc, layers, head)
        58 -> icmp6(b, p, end, ctx, declaredLen, trunc, layers, head)
        else -> { layers += Layer(PacketNames.PROTO[proto] ?: "프로토콜 $proto", listOf("데이터(처음 32바이트)" to Bx.hex(b, p, minOf(end, p + 32))), listOf("이 도구가 상세히 풀지 않는 프로토콜이에요" to 0)); "$head ${PacketNames.PROTO[proto] ?: proto}" }
    }

    private fun checksumNote(b: ByteArray, p: Int, end: Int, ctx: Ctx, proto: Int, declaredLen: Int, trunc: Boolean, csumPos: Int, zeroOk: Boolean = false): Pair<String, Int>? {
        val stored = Bx.u16(b, p + csumPos)
        if (zeroOk && stored == 0) return "체크섬이 0 이에요: IPv4 의 UDP 는 체크섬을 안 쓸 수 있어요" to 0
        if (trunc || end - p < declaredLen) return "캡처가 잘려서(snaplen) 체크섬을 확인할 수 없어요" to 0
        val init = if (ctx.v6) InetChecksum.pseudoV6(ctx.src, ctx.dst, proto, declaredLen) else InetChecksum.pseudoV4(ctx.src, ctx.dst, proto, declaredLen)
        return if (InetChecksum.valid(b, p, p + declaredLen, init)) null else {
            val z = b.copyOf(); z[p + csumPos] = 0; z[p + csumPos + 1] = 0
            "체크섬이 맞지 않아요(저장된 값 0x%04x, 계산한 값 0x%04x). 이 기기가 보낸 패킷을 그 기기에서 캡처했다면 NIC 가 체크섬을 나중에 채워서(오프로드) 틀리게 보이는 게 정상이에요. 다른 곳에서 캡처했는데도 틀리면 중간에 손상됐어요".format(stored, InetChecksum.checksum(z, p, p + declaredLen, init)) to 1
        }
    }

    private fun tcp(b: ByteArray, p: Int, end: Int, ctx: Ctx, declaredLen: Int, trunc: Boolean, layers: ArrayList<Layer>, head: String): String {
        if (end - p < 20) { layers += Layer("TCP", emptyList(), listOf("TCP 머리글(20바이트)보다 짧아요" to 2)); return "$head 잘린 TCP" }
        val sp = Bx.u16(b, p); val dp = Bx.u16(b, p + 2); val seq = Bx.u32(b, p + 4); val ack = Bx.u32(b, p + 8); val doff = (Bx.u8(b, p + 12) shr 4) * 4; val fl = Bx.u8(b, p + 13) or ((Bx.u8(b, p + 12) and 1) shl 8); val win = Bx.u16(b, p + 14)
        val names = listOf(0x80 to "CWR", 0x40 to "ECE", 0x20 to "URG", 0x10 to "ACK", 0x08 to "PSH", 0x04 to "RST", 0x02 to "SYN", 0x01 to "FIN")
        val flags = names.filter { fl and it.first != 0 }.map { it.second }; val notes = ArrayList<Pair<String, Int>>()
        checksumNote(b, p, end, ctx, 6, declaredLen, trunc, 16)?.let { notes += it }
        if (fl and 0x02 != 0 && fl and 0x10 == 0) notes += "SYN: 연결 시작 요청이에요" to 0 else if (fl and 0x12 == 0x12) notes += "SYN+ACK: 서버가 연결 요청을 받아들였어요" to 0
        if (fl and 0x04 != 0) notes += "RST: 연결을 거부하거나 강제로 끊어요 (포트가 닫혀 있거나 방화벽·서버가 끊은 경우)" to 1
        if (win == 0 && fl and 0x04 == 0) notes += "윈도 크기가 0 이에요: 받는 쪽 버퍼가 가득 차서 보내지 말라는 뜻(제로 윈도)" to 1
        val opts = ArrayList<String>(); var q = p + 20; val oe = minOf(end, p + doff)
        while (q < oe) { val k = Bx.u8(b, q); if (k == 0) break; if (k == 1) { q++; continue }; if (q + 1 >= oe) break; val l = Bx.u8(b, q + 1); if (l < 2 || q + l > oe) break
            opts += when (k) { 2 -> "MSS ${Bx.u16(b, q + 2)}"; 3 -> "윈도 배율 ${Bx.u8(b, q + 2)} (×${1 shl Bx.u8(b, q + 2)})"; 4 -> "SACK 허용"; 5 -> "SACK 블록 ${(l - 2) / 8}개"; 8 -> "타임스탬프 ${Bx.u32(b, q + 2)}/${Bx.u32(b, q + 6)}"; 34 -> "TCP Fast Open"; else -> "옵션 $k" }; q += l }
        val payStart = p + doff; val pay = if (payStart < end) end - payStart else 0
        layers += Layer("TCP", listOf("출발지 포트" to portName(sp), "목적지 포트" to portName(dp), "순서 번호(seq)" to "$seq", "확인 번호(ack)" to "$ack", "헤더 길이" to "${doff}바이트", "플래그" to flags.joinToString(" ").ifEmpty { "없음" }, "윈도 크기" to "$win",
            "체크섬" to "0x%04x".format(Bx.u16(b, p + 16)), "긴급 포인터" to "${Bx.u16(b, p + 18)}") + (if (opts.isNotEmpty()) listOf("옵션" to opts.joinToString(", ")) else emptyList()) + listOf("데이터 길이" to "${pay}바이트"), notes)
        var summ = "$head TCP $sp → $dp [${flags.joinToString(" ")}] ${pay}바이트"
        if (pay > 0) app(b, payStart, end, sp, dp, true, layers)?.let { summ += " · $it" }
        return summ
    }

    private fun udp(b: ByteArray, p: Int, end: Int, ctx: Ctx, trunc: Boolean, layers: ArrayList<Layer>, head: String): String {
        if (end - p < 8) { layers += Layer("UDP", emptyList(), listOf("UDP 머리글(8바이트)보다 짧아요" to 2)); return "$head 잘린 UDP" }
        val sp = Bx.u16(b, p); val dp = Bx.u16(b, p + 2); val len = Bx.u16(b, p + 4); val notes = ArrayList<Pair<String, Int>>()
        checksumNote(b, p, end, ctx, 17, len, trunc, 6, zeroOk = !ctx.v6)?.let { notes += it }
        if (len < 8) notes += "UDP 길이 칸이 8 보다 작아요" to 2
        layers += Layer("UDP", listOf("출발지 포트" to portName(sp), "목적지 포트" to portName(dp), "길이" to "${len}바이트", "체크섬" to "0x%04x".format(Bx.u16(b, p + 6)), "데이터 길이" to "${maxOf(0, len - 8)}바이트"), notes)
        var summ = "$head UDP $sp → $dp ${maxOf(0, len - 8)}바이트"
        if (end - p > 8) app(b, p + 8, minOf(end, p + maxOf(len, 8)), sp, dp, false, layers)?.let { summ += " · $it" }
        return summ
    }

    private fun icmp(b: ByteArray, p: Int, end: Int, trunc: Boolean, layers: ArrayList<Layer>, head: String): String {
        if (end - p < 8) { layers += Layer("ICMP", emptyList(), listOf("ICMP 머리글(8바이트)보다 짧아요" to 2)); return "$head 잘린 ICMP" }
        val type = Bx.u8(b, p); val code = Bx.u8(b, p + 1); val notes = ArrayList<Pair<String, Int>>(); val f = ArrayList<Pair<String, String>>()
        f += "종류" to "$type (${PacketNames.ICMP_TYPE[type] ?: "알 수 없음"})"
        f += "코드" to if (type == 3) "$code (${PacketNames.ICMP_UNREACH[code] ?: "기타"})" else "$code"
        f += "체크섬" to "0x%04x".format(Bx.u16(b, p + 2))
        if (!trunc && !InetChecksum.valid(b, p, end)) notes += "ICMP 체크섬이 맞지 않아요" to 1
        if (type == 8 || type == 0) { f += "식별자(id)" to "${Bx.u16(b, p + 4)}"; f += "순서(seq)" to "${Bx.u16(b, p + 6)}"; f += "데이터" to "${end - p - 8}바이트" }
        if (type == 3 && code == 4) f += "다음 홉 MTU" to "${Bx.u16(b, p + 6)}"
        if (type == 3 || type == 11) { if (end - p >= 8 + 20) { val ip = p + 8; f += "원래 패킷" to "${Bx.ip4(b, ip + 12)} → ${Bx.ip4(b, ip + 16)} (${PacketNames.PROTO[Bx.u8(b, ip + 9)] ?: "프로토콜 ${Bx.u8(b, ip + 9)}"})" } }
        if (type == 3) notes += "이 패킷은 \"전달하지 못했다\"는 보고예요: 원래 패킷을 보낸 쪽으로 돌아가요" to 1
        if (type == 11 && code == 0) notes += "TTL 이 0 이 돼서 버려졌다는 보고예요 (traceroute 가 경로를 알아내는 데 쓰는 응답이에요)" to 0
        layers += Layer("ICMP", f, notes)
        return "$head ICMP ${PacketNames.ICMP_TYPE[type] ?: type}"
    }

    private fun icmp6(b: ByteArray, p: Int, end: Int, ctx: Ctx, declaredLen: Int, trunc: Boolean, layers: ArrayList<Layer>, head: String): String {
        if (end - p < 4) { layers += Layer("ICMPv6", emptyList(), listOf("ICMPv6 머리글보다 짧아요" to 2)); return "$head 잘린 ICMPv6" }
        val type = Bx.u8(b, p); val code = Bx.u8(b, p + 1); val notes = ArrayList<Pair<String, Int>>()
        checksumNote(b, p, end, ctx, 58, declaredLen, trunc, 2)?.let { notes += it }
        val f = arrayListOf("종류" to "$type (${PacketNames.ICMP6_TYPE[type] ?: "알 수 없음"})", "코드" to "$code", "체크섬" to "0x%04x".format(Bx.u16(b, p + 2)))
        if ((type == 128 || type == 129) && end - p >= 8) { f += "식별자(id)" to "${Bx.u16(b, p + 4)}"; f += "순서(seq)" to "${Bx.u16(b, p + 6)}" }
        if (type == 2 && end - p >= 8) f += "MTU" to "${Bx.u32(b, p + 4)}"
        if ((type == 135 || type == 136) && end - p >= 24) f += "대상 주소" to Bx.ip6(b, p + 8)
        layers += Layer("ICMPv6", f, notes)
        return "$head ICMPv6 ${PacketNames.ICMP6_TYPE[type] ?: type}"
    }

    private fun arp(b: ByteArray, p: Int, layers: ArrayList<Layer>): String {
        if (b.size < p + 28) { layers += Layer("ARP", emptyList(), listOf("ARP(28바이트)보다 짧아요" to 2)); return "잘린 ARP" }
        val op = Bx.u16(b, p + 6); val sm = Bx.mac(b, p + 8); val sip = Bx.ip4(b, p + 14); val tm = Bx.mac(b, p + 18); val tip = Bx.ip4(b, p + 24); val notes = ArrayList<Pair<String, Int>>()
        if (sip == tip && op == 1) notes += "출발지·대상 IP 가 같아요: 자기 주소를 알리는 gratuitous ARP 예요 (IP 충돌 확인이나 이전 알림)" to 0
        if (sip == "0.0.0.0") notes += "출발지 IP 가 0.0.0.0 이에요: 이 주소를 써도 되는지 확인하는 ARP probe(주소 충돌 검사)예요" to 0
        layers += Layer("ARP", listOf("하드웨어 종류" to "${Bx.u16(b, p)} (${if (Bx.u16(b, p) == 1) "이더넷" else "기타"})", "프로토콜" to "0x%04x".format(Bx.u16(b, p + 2)), "동작" to "$op (${when (op) { 1 -> "요청 \"누가 $tip 인가?\""; 2 -> "응답 \"$sip 는 $sm 이에요\""; else -> "기타" }})",
            "보내는 MAC" to sm, "보내는 IP" to sip, "대상 MAC" to tm, "대상 IP" to tip), notes)
        return if (op == 1) "ARP: 누가 $tip 인가? ($sip 가 물음)" else "ARP: $sip 는 $sm"
    }

    fun portName(p: Int): String = PacketNames.SERVICE[p]?.let { "$p ($it)" } ?: "$p"

    /** 응용 계층: 알아본 게 있으면 한 줄 요약을 돌려주고 layers 에 풀이를 추가 */
    private fun app(b: ByteArray, s: Int, e: Int, sp: Int, dp: Int, tcp: Boolean, layers: ArrayList<Layer>): String? {
        if (e - s <= 0) return null
        val port = if (PacketNames.SERVICE.containsKey(dp)) dp else sp
        if (port == 53) {
            val raw = if (tcp && e - s > 2 && Bx.u16(b, s) == e - s - 2) b.copyOfRange(s + 2, e) else b.copyOfRange(s, e)
            val m = DnsWire.parse(raw)
            if (m != null) {
                val q = m.questions.firstOrNull()?.let { "${it.first} ${DnsType.name(it.second)}" } ?: "-"
                layers += Layer("DNS", listOf("ID" to "0x%04x".format(m.id), "종류" to (if (m.isResponse) "응답" else "질문"), "응답 코드" to DnsType.rcode(m.rcode), "질문" to q, "답 수" to "${m.answers.size}") + m.answers.take(6).map { "답" to "${it.name} ${it.typeName} ${it.data.take(60)}" }, emptyList())
                return "DNS ${if (m.isResponse) "응답" else "질문"} $q"
            }
        }
        if (Bx.u8(b, s) == 0x16 && e - s >= 6 && Bx.u8(b, s + 1) == 3) {
            val hs = if (Bx.u8(b, s + 5) == 1) "ClientHello" else if (Bx.u8(b, s + 5) == 2) "ServerHello" else "핸드셰이크 ${Bx.u8(b, s + 5)}"
            val h = TlsHello.parse(b.copyOfRange(s, e)); val f = arrayListOf("기록 종류" to "핸드셰이크(22)", "기록 버전" to "0x%04x".format(Bx.u16(b, s + 1)), "메시지" to hs)
            h?.sni?.let { f += "서버 이름(SNI)" to it }; h?.let { f += "JA3" to it.ja3Hash }
            layers += Layer("TLS", f, listOf("내용은 암호화돼 있어 SNI 말고는 알 수 없어요" to 0)); return "TLS $hs${h?.sni?.let { " ($it)" } ?: ""}"
        }
        if (tcp && Bx.u8(b, s) in 0x14..0x17 && e - s >= 5 && Bx.u8(b, s + 1) == 3) { layers += Layer("TLS", listOf("기록 종류" to when (Bx.u8(b, s)) { 20 -> "ChangeCipherSpec"; 21 -> "Alert"; 22 -> "핸드셰이크"; else -> "암호화된 응용 데이터" }, "길이" to "${Bx.u16(b, s + 3)}바이트")); return "TLS 기록" }
        val text = String(b, s, minOf(e - s, 16), Charsets.ISO_8859_1)
        if (tcp && Regex("^(GET|POST|PUT|DELETE|HEAD|OPTIONS|PATCH) /").containsMatchIn(text) || text.startsWith("HTTP/1.")) {
            val line = String(b, s, minOf(e - s, 200), Charsets.ISO_8859_1).lineSequence().first().take(120); val host = Regex("(?i)\r\nHost:\\s*(\\S+)").find(String(b, s, minOf(e - s, 1000), Charsets.ISO_8859_1))?.groupValues?.get(1)
            layers += Layer("HTTP", listOfNotNull("첫 줄" to line, host?.let { "Host" to it }), listOf("암호화되지 않은 HTTP 예요: 내용을 중간에서 읽고 바꿀 수 있어요" to 1)); return "HTTP $line"
        }
        if (!tcp && (sp == 123 || dp == 123) && e - s >= 48) { val mode = Bx.u8(b, s) and 7; layers += Layer("NTP", listOf("버전" to "${(Bx.u8(b, s) shr 3) and 7}", "모드" to "$mode (${ntpMode(mode)})", "계층(stratum)" to "${Bx.u8(b, s + 1)}")); return "NTP ${ntpMode(mode)}" }
        if (!tcp && (sp == 67 || sp == 68 || dp == 67 || dp == 68) && e - s >= 240) { layers += Layer("DHCP", listOf("메시지" to (DhcpParse.parse(b.copyOfRange(s, e))?.msgType ?: "?")), listOf("자세히 보려면 'DHCP 메시지 해석' 도구에 이 패킷을 붙여 넣으세요" to 0)); return "DHCP" }
        layers += Layer("데이터", listOf("처음 ${minOf(48, e - s)}바이트" to Bx.hex(b, s, minOf(e, s + 48)), "글자로" to Bx.printable(b, s, minOf(e, s + 48))))
        return null
    }

    fun ntpMode(m: Int) = when (m) { 1 -> "대칭 능동"; 2 -> "대칭 수동"; 3 -> "클라이언트(시간 요청)"; 4 -> "서버(시간 응답)"; 5 -> "브로드캐스트"; 6 -> "제어"; else -> "기타" }

    /** 패킷 안의 UDP/TCP 데이터 부분과 프로토콜 번호(17=UDP, 6=TCP). 포트가 wantPorts 에 없거나 UDP/TCP 가 아니면 null (이더넷 유무는 자동 판별) */
    fun transportPayload(b: ByteArray, wantPorts: Set<Int>): Pair<ByteArray, Int>? {
        if (b.size < 28) return null
        val ip = looksLikeIp(b); var off = if (ip) 0 else 14
        if (!ip && b.size < 34) return null
        var type = if (ip) (if (Bx.u8(b, 0) shr 4 == 6) 0x86DD else 0x0800) else Bx.u16(b, 12)
        while ((type == 0x8100 || type == 0x88A8) && off + 4 <= b.size) { type = Bx.u16(b, off + 2); off += 4 }
        val proto: Int; var p: Int
        if (type == 0x0800) {
            if (b.size < off + 20) return null
            val ihl = (Bx.u8(b, off) and 15) * 4; proto = Bx.u8(b, off + 9); p = off + ihl
            if (Bx.u16(b, off + 6) and 0x1fff != 0) return null
        } else if (type == 0x86DD) {
            if (b.size < off + 40) return null
            var nh = Bx.u8(b, off + 6); p = off + 40
            while (nh in listOf(0, 43, 44, 60) && p + 8 <= b.size) { val nn = Bx.u8(b, p); p += if (nh == 44) 8 else (Bx.u8(b, p + 1) + 1) * 8; nh = nn }
            proto = nh
        } else return null
        if (proto == 17 && b.size >= p + 8 && (Bx.u16(b, p) in wantPorts || Bx.u16(b, p + 2) in wantPorts)) return b.copyOfRange(p + 8, minOf(b.size, p + maxOf(8, Bx.u16(b, p + 4)))) to 17
        if (proto == 6 && b.size >= p + 20 && (Bx.u16(b, p) in wantPorts || Bx.u16(b, p + 2) in wantPorts)) return b.copyOfRange(minOf(b.size, p + (Bx.u8(b, p + 12) shr 4) * 4), b.size) to 6
        return null
    }

    fun payloadOf(b: ByteArray, wantPorts: Set<Int>): ByteArray? = transportPayload(b, wantPorts)?.first
}

// ---------------------------------------------------------------------------------------------
// DHCP

object DhcpParse {
    class Opt(val code: Int, val name: String, val value: String)
    class Msg(val op: Int, val msgType: String?, val xid: Long, val secs: Int, val broadcast: Boolean, val ciaddr: String, val yiaddr: String, val siaddr: String, val giaddr: String, val chaddr: String, val hostname: String?, val options: List<Opt>)

    private val TYPES = mapOf(1 to "DISCOVER(주소 찾기)", 2 to "OFFER(주소 제안)", 3 to "REQUEST(주소 요청)", 4 to "DECLINE(주소 거절)", 5 to "ACK(승인)", 6 to "NAK(거부)", 7 to "RELEASE(주소 반납)", 8 to "INFORM(정보 요청)")
    private val NAMES = mapOf(1 to "서브넷 마스크", 3 to "라우터(게이트웨이)", 6 to "DNS 서버", 12 to "호스트 이름", 15 to "도메인 이름", 26 to "MTU", 28 to "브로드캐스트 주소", 42 to "NTP 서버", 43 to "벤더 정보", 50 to "요청한 IP", 51 to "임대 시간", 53 to "메시지 종류",
        54 to "DHCP 서버 ID", 55 to "요청한 옵션 목록", 57 to "최대 메시지 크기", 58 to "갱신 시간(T1)", 59 to "재결합 시간(T2)", 60 to "벤더 클래스", 61 to "클라이언트 ID", 66 to "TFTP 서버", 67 to "부트 파일", 82 to "릴레이 에이전트 정보", 119 to "검색 도메인", 121 to "클래스 없는 경로", 252 to "WPAD 주소")

    fun parse(raw: ByteArray): Msg? {
        var base = -1
        for (i in 236..minOf(raw.size - 4, 300)) if (raw[i] == 0x63.toByte() && raw[i + 1] == 0x82.toByte() && raw[i + 2] == 0x53.toByte() && raw[i + 3] == 0x63.toByte()) { base = i - 236; break }
        if (base < 0 || raw.size < base + 240) return null
        val b = raw.copyOfRange(base, raw.size); val hl = Bx.u8(b, 2)
        val opts = ArrayList<Opt>(); var p = 240; var msgType: String? = null; var hostname: String? = null
        while (p < b.size) {
            val c = Bx.u8(b, p); if (c == 255) break; if (c == 0) { p++; continue }; if (p + 1 >= b.size) break; val l = Bx.u8(b, p + 1); if (p + 2 + l > b.size) break; val d = b.copyOfRange(p + 2, p + 2 + l)
            val v = when (c) {
                1, 3, 6, 28, 42, 50, 54, 252 -> if (c in listOf(3, 6, 42)) (0 until l / 4).joinToString(", ") { Bx.ip4(d, it * 4) } else if (c == 252) String(d) else Bx.ip4(d, 0)
                12, 15, 60, 66, 67, 119 -> String(d, Charsets.ISO_8859_1)
                51, 58, 59 -> "${Bx.u32(d, 0)}초 (${Bx.u32(d, 0) / 3600}시간)"
                26, 57 -> "${Bx.u16(d, 0)}"
                53 -> TYPES[d[0].toInt()] ?: "${d[0]}"
                55 -> d.joinToString(", ") { (NAMES[it.toInt() and 0xff] ?: "${it.toInt() and 0xff}") }
                61 -> Bx.hex(d, 0, d.size, ":")
                else -> Bx.hex(d, 0, minOf(d.size, 24))
            }
            if (c == 53) msgType = v; if (c == 12) hostname = v
            opts += Opt(c, NAMES[c] ?: "옵션 $c", v); p += 2 + l
        }
        return Msg(Bx.u8(b, 0), msgType, Bx.u32(b, 4), Bx.u16(b, 8), Bx.u16(b, 10) and 0x8000 != 0, Bx.ip4(b, 12), Bx.ip4(b, 16), Bx.ip4(b, 20), Bx.ip4(b, 24), Bx.hex(b, 28, 28 + minOf(hl, 16), ":"), hostname, opts)
    }
}

// ---------------------------------------------------------------------------------------------
// NTP

object NtpDecode {
    private const val EPOCH = 2208988800L
    class Msg(val li: Int, val vn: Int, val mode: Int, val stratum: Int, val poll: Int, val precision: Int, val rootDelay: Double, val rootDisp: Double, val refId: String, val ref: Double, val orig: Double, val recv: Double, val xmit: Double)

    private fun ts(b: ByteArray, i: Int): Double { val s = Bx.u32(b, i); val f = Bx.u32(b, i + 4); return if (s == 0L && f == 0L) 0.0 else (s - EPOCH) + f / 4294967296.0 }
    /** t1=내가 보낸 시각, t2=서버가 받은 시각, t3=서버가 보낸 시각, t4=내가 받은 시각 (모두 UNIX 초). 오차(내 시계에 더해야 할 값)와 왕복 지연 */
    fun offsetDelay(t1: Double, t2: Double, t3: Double, t4: Double): Pair<Double, Double> = (((t2 - t1) + (t3 - t4)) / 2.0) to ((t4 - t1) - (t3 - t2))

    fun fmt(t: Double): String = if (t == 0.0) "(0, 값 없음)" else java.time.Instant.ofEpochMilli((t * 1000).toLong()).toString().replace("Z", "") + " UTC"

    fun parse(b: ByteArray): Msg? {
        if (b.size < 48) return null
        val stratum = Bx.u8(b, 1); val vn = (Bx.u8(b, 0) shr 3) and 7
        val refId = if (stratum <= 1) String(b, 12, 4, Charsets.ISO_8859_1).trimEnd('\u0000').filter { it.code in 32..126 } else Bx.ip4(b, 12)
        return Msg(Bx.u8(b, 0) shr 6, vn, Bx.u8(b, 0) and 7, stratum, Bx.u8(b, 2).toByte().toInt(), Bx.u8(b, 3).toByte().toInt(), Bx.u32(b, 4) / 65536.0, Bx.u32(b, 8) / 65536.0, refId, ts(b, 16), ts(b, 24), ts(b, 32), ts(b, 40))
    }
}

// ---------------------------------------------------------------------------------------------
// pcap / pcapng

object PcapRead {
    class Pkt(val tsMicros: Long, val link: Int, val data: ByteArray, val origLen: Int)
    class Capture(val packets: List<Pkt>, val format: String, val truncatedFile: Boolean, val notes: List<String>)

    private fun rd(b: ByteArray, i: Int, le: Boolean): Long = if (le) (b[i].toLong() and 0xff) or ((b[i + 1].toLong() and 0xff) shl 8) or ((b[i + 2].toLong() and 0xff) shl 16) or ((b[i + 3].toLong() and 0xff) shl 24) else Bx.u32(b, i)
    private fun rd16(b: ByteArray, i: Int, le: Boolean): Int = if (le) (b[i].toInt() and 0xff) or ((b[i + 1].toInt() and 0xff) shl 8) else Bx.u16(b, i)

    fun read(b: ByteArray, maxPackets: Int = 300_000): Capture {
        if (b.size < 24) return Capture(emptyList(), "알 수 없음", false, listOf("파일이 너무 짧아요"))
        val m = Bx.u32(b, 0)
        return when (m) {
            0xa1b2c3d4L, 0xd4c3b2a1L, 0xa1b23c4dL, 0x4d3cb2a1L -> classic(b, maxPackets)
            0x0a0d0d0aL -> pcapng(b, maxPackets)
            else -> Capture(emptyList(), "알 수 없음", false, listOf("pcap(.pcap)·pcapng(.pcapng) 파일이 아니에요 (처음 4바이트 ${Bx.hex(b, 0, 4)})"))
        }
    }

    private fun classic(b: ByteArray, max: Int): Capture {
        val m = Bx.u32(b, 0); val le = m == 0xd4c3b2a1L || m == 0x4d3cb2a1L; val nano = m == 0xa1b23c4dL || m == 0x4d3cb2a1L
        val link = rd(b, 20, le).toInt() and 0x0fffffff; var p = 24; val out = ArrayList<Pkt>(); var cut = false; val notes = ArrayList<String>()
        while (p + 16 <= b.size) {
            val sec = rd(b, p, le); val frac = rd(b, p + 4, le); val cap = rd(b, p + 8, le).toInt(); val orig = rd(b, p + 12, le).toInt()
            if (cap < 0 || cap > 262144 || p + 16 + cap > b.size) { cut = true; break }
            out += Pkt(sec * 1_000_000 + (if (nano) frac / 1000 else frac), link, b.copyOfRange(p + 16, p + 16 + cap), orig); p += 16 + cap
            if (out.size >= max) { notes += "패킷이 ${max}개를 넘어서 앞의 ${max}개만 분석했어요"; break }
        }
        return Capture(out, "pcap (${if (nano) "나노초" else "마이크로초"}, 링크 $link)", cut, notes)
    }

    private val POW10 = LongArray(19).also { var v = 1L; for (k in it.indices) { it[k] = v; v *= 10 } }

    /** pcapng 의 if_tsresol(10 의 거듭제곱 또는 2 의 거듭제곱) 값으로 만든 시각 → 마이크로초 */
    private fun toMicros(ts: Long, resol: Int): Long = if (resol and 0x80 != 0) (ts.toDouble() * 1e6 / Math.pow(2.0, (resol and 0x7f).toDouble())).toLong()
        else if (resol == 6) ts else if (resol > 6) ts / POW10[minOf(18, resol - 6)] else ts * POW10[6 - resol]

    private fun pcapng(b: ByteArray, max: Int): Capture {
        var p = 0; var le = true; val links = ArrayList<Int>(); val resols = ArrayList<Int>(); val out = ArrayList<Pkt>(); var cut = false; val notes = ArrayList<String>()
        while (p + 12 <= b.size) {
            val type = if (p == 0) Bx.u32(b, 0) else rd(b, p, le)
            if (type == 0x0a0d0d0aL) { le = Bx.u32(b, p + 8) != 0x1a2b3c4dL; links.clear(); resols.clear() }
            val len = rd(b, p + 4, le).toInt(); if (len < 12 || p + len > b.size) { cut = true; break }
            when (type) {
                1L -> {                                                   // 인터페이스 설명 블록: 링크 종류와 시각 단위
                    links += rd16(b, p + 8, le); var q = p + 16; var res = 6
                    while (q + 4 <= p + len - 4) { val oc = rd16(b, q, le); val ol = rd16(b, q + 2, le); if (oc == 0) break; if (oc == 9 && ol >= 1) res = b[q + 4].toInt() and 0xff; q += 4 + ((ol + 3) / 4) * 4 }
                    resols += res
                }
                6L -> {                                                   // 확장 패킷 블록
                    val id = rd(b, p + 8, le).toInt(); val ts = (rd(b, p + 12, le) shl 32) or rd(b, p + 16, le); val cap = rd(b, p + 20, le).toInt(); val orig = rd(b, p + 24, le).toInt()
                    if (cap >= 0 && p + 28 + cap <= b.size) out += Pkt(toMicros(ts, resols.getOrElse(id) { 6 }), links.getOrElse(id) { 1 }, b.copyOfRange(p + 28, p + 28 + cap), orig)
                }
                3L -> { val orig = rd(b, p + 8, le).toInt(); val cap = minOf(orig, len - 16); if (cap >= 0) out += Pkt(0, links.getOrElse(0) { 1 }, b.copyOfRange(p + 12, p + 12 + cap), orig) }
            }
            p += len
            if (out.size >= max) { notes += "패킷이 ${max}개를 넘어서 앞의 ${max}개만 분석했어요"; break }
        }
        return Capture(out, "pcapng", cut, notes)
    }

    /** 링크 계층 머리글을 떼고 IP 패킷부터 돌려줌 (이더넷·VLAN·리눅스 SLL·Raw IP). 알 수 없으면 null */
    fun ipPacket(p: Pkt): Triple<Int, ByteArray, Int>? {      // (EtherType 0x0800/0x86DD/0x0806, 데이터, 시작 위치)
        val d = p.data
        when (p.link) {
            1 -> { if (d.size < 14) return null; var off = 14; var t = Bx.u16(d, 12); while ((t == 0x8100 || t == 0x88A8) && off + 4 <= d.size) { t = Bx.u16(d, off + 2); off += 4 }; return Triple(t, d, off) }
            101, 228, 229 -> return if (d.isEmpty()) null else Triple(if (Bx.u8(d, 0) shr 4 == 6) 0x86DD else 0x0800, d, 0)
            113 -> return if (d.size < 16) null else Triple(Bx.u16(d, 14), d, 16)
            276 -> return if (d.size < 20) null else Triple(Bx.u16(d, 0), d, 20)
            0 -> return if (d.size < 4) null else Triple(if (Bx.u8(d, 4) shr 4 == 6) 0x86DD else 0x0800, d, 4)
        }
        return null
    }
}

// ---------------------------------------------------------------------------------------------
// pcap 요약: 패킷마다 가볍게 읽어 대화·DNS·TLS SNI·HTTP·재전송·무응답 접속을 모음

object PcapStats {
    class Flow(val proto: String, val a: String, val b: String, var packets: Int = 0, var bytes: Long = 0, var firstUs: Long = 0, var lastUs: Long = 0)
    class Report(
        val total: Int, val bytes: Long, val first: Long, val last: Long, val l3: Map<String, Int>, val protos: Map<String, Int>, val flows: List<Flow>, val talkers: List<Pair<String, Long>>,
        val dnsQueries: List<Pair<String, Int>>, val dnsUnanswered: List<String>, val dnsFail: List<Pair<String, String>>, val dnsAnswers: Map<String, List<String>>,
        val sni: List<Pair<String, Int>>, val sniIps: Map<String, List<String>>, val http: List<Pair<String, Int>>, val httpHostIps: Map<String, List<String>>,
        val syn: Int, val synAck: Int, val rst: Int, val retrans: Int, val zeroWin: Int, val synUnanswered: List<Pair<String, Int>>, val rstFrom: List<Pair<String, Int>>, val icmpUnreach: List<String>, val arpUnanswered: List<String>,
        val cleartext: List<Pair<String, Int>>, val notIp: Int, val fragments: Int, val ja3: List<Pair<String, Int>>,
    )

    private val FTP_POP_LOGIN = Regex("^(USER|PASS) \\S")
    private val HTTP_BASIC = Regex("(?i)\\r\\nAuthorization: Basic ")
    private val HTTP_REQ = Regex("^(GET|POST|PUT|DELETE|HEAD|OPTIONS|PATCH) (\\S+) HTTP/1")
    private val IMAP_LOGIN = Regex("(?i)^\\S+ LOGIN \\S+ \\S+")
    private val SMTP_AUTH = Regex("(?i)^AUTH (LOGIN|PLAIN)")

    private class Pending(var next: Long, val buf: java.io.ByteArrayOutputStream, val need: Int)

    private fun service(proto: String, a: Int, b: Int): String {
        if (proto == "UDP" && (a == 443 || b == 443)) return "UDP · QUIC(HTTP/3)"
        val s = PacketNames.SERVICE[minOf(a, b)] ?: PacketNames.SERVICE[maxOf(a, b)]
        return if (s != null) "$proto · $s" else proto
    }

    fun analyze(cap: PcapRead.Capture): Report {
        val l3 = HashMap<String, Int>(); val protos = HashMap<String, Int>(); val flows = LinkedHashMap<String, Flow>(); val talk = HashMap<String, Long>()
        val dnsQ = HashMap<String, Int>(); val dnsPending = HashMap<String, String>(); val dnsAns = HashSet<String>(); val dnsFail = ArrayList<Pair<String, String>>(); val dnsAnswers = LinkedHashMap<String, LinkedHashSet<String>>()
        val sni = HashMap<String, Int>(); val sniIps = LinkedHashMap<String, LinkedHashSet<String>>(); val http = HashMap<String, Int>(); val hostIps = LinkedHashMap<String, LinkedHashSet<String>>()
        val ja3 = HashMap<String, Int>(); val clear = HashMap<String, Int>()
        var syn = 0; var synAck = 0; var rst = 0; var retrans = 0; var zero = 0; var notIp = 0; var frags = 0
        val synSent = HashMap<String, Int>(); val answered = HashSet<String>(); val rstFrom = HashMap<String, Int>(); val icmpUn = LinkedHashSet<String>()
        val arpAsk = LinkedHashMap<String, Int>(); val arpIs = HashSet<String>(); val seen = HashSet<String>(); var bytes = 0L
        val pendingTls = HashMap<String, Pending>()
        for (pk in cap.packets) {
            bytes += pk.origLen
            val ip = PcapRead.ipPacket(pk)
            if (ip == null) { notIp++; continue }
            val (et, d, off) = ip
            if (et == 0x0806) {
                l3.merge("ARP", 1, Int::plus); protos.merge("ARP", 1, Int::plus)
                if (d.size >= off + 28) { val op = Bx.u16(d, off + 6); if (op == 1) arpAsk.merge("${Bx.ip4(d, off + 24)}|${Bx.ip4(d, off + 14)}", 1, Int::plus) else if (op == 2) arpIs += Bx.ip4(d, off + 14) }
                continue
            }
            val v6 = et == 0x86DD
            if (!v6 && et != 0x0800) { notIp++; continue }
            val src: String; val dst: String; var proto: Int; var p: Int
            if (!v6) {
                if (d.size < off + 20) { notIp++; continue }
                val ihl = (Bx.u8(d, off) and 15) * 4; src = Bx.ip4(d, off + 12); dst = Bx.ip4(d, off + 16); proto = Bx.u8(d, off + 9); p = off + ihl
                l3.merge("IPv4", 1, Int::plus)
                if (Bx.u16(d, off + 6) and 0x1fff != 0) { frags++; protos.merge("IP 조각", 1, Int::plus); continue }
            } else {
                if (d.size < off + 40) { notIp++; continue }
                src = Bx.ip6(d, off + 8); dst = Bx.ip6(d, off + 24); proto = Bx.u8(d, off + 6); p = off + 40
                l3.merge("IPv6", 1, Int::plus)
                while (proto in listOf(0, 43, 44, 60) && p + 8 <= d.size) { val nn = Bx.u8(d, p); p += if (proto == 44) 8 else (Bx.u8(d, p + 1) + 1) * 8; proto = nn }
            }
            talk.merge(src, pk.origLen.toLong(), Long::plus); talk.merge(dst, pk.origLen.toLong(), Long::plus)
            var sp = -1; var dp = -1; var label = PacketNames.PROTO[proto] ?: "IP 프로토콜 $proto"
            if (proto == 6 && d.size >= p + 20) {
                sp = Bx.u16(d, p); dp = Bx.u16(d, p + 2); val fl = Bx.u8(d, p + 13); val seq = Bx.u32(d, p + 4); val doff = (Bx.u8(d, p + 12) shr 4) * 4
                val pay = d.size - (p + doff)
                if (fl and 0x12 == 0x02) { syn++; synSent.merge("$dst:$dp", 1, Int::plus) }
                if (fl and 0x12 == 0x12) { synAck++; answered += "$src:$sp" }
                if (fl and 0x04 != 0) { rst++; rstFrom.merge("$src:$sp", 1, Int::plus); answered += "$src:$sp" }
                if (Bx.u16(d, p + 14) == 0 && fl and 0x06 == 0) zero++
                if (pay > 0 && doff >= 20 && p + doff < d.size) {
                    val key = "$src:$sp>$dst:$dp"
                    if (!seen.add("$key|$seq|$pay")) retrans++
                    val payload = d.copyOfRange(p + doff, d.size); val text = String(payload, 0, minOf(payload.size, 400), Charsets.ISO_8859_1)
                    // TLS ClientHello: 한 패킷에 다 안 들어가면 같은 방향으로 순서대로 이어지는 조각을 모아서 읽음
                    var hello: ByteArray? = null; val pend = pendingTls[key]
                    if (pend != null && seq == pend.next) {
                        pend.buf.write(payload); pend.next = (seq + payload.size) and 0xffffffffL
                        if (pend.buf.size() >= pend.need) { hello = pend.buf.toByteArray().copyOf(pend.need); pendingTls.remove(key) }
                    } else if (payload.size > 9 && Bx.u8(payload, 0) == 0x16 && Bx.u8(payload, 1) == 3 && Bx.u8(payload, 5) == 1) {
                        val need = 5 + Bx.u16(payload, 3)
                        if (need <= 20000) { if (payload.size >= need) hello = payload.copyOf(need) else if (pendingTls.size < 2000) pendingTls[key] = Pending((seq + payload.size) and 0xffffffffL, java.io.ByteArrayOutputStream().also { it.write(payload) }, need) }
                    }
                    if (hello != null) TlsHello.parse(hello)?.takeIf { it.client }?.let { h ->
                        h.sni?.let { sni.merge(it, 1, Int::plus); sniIps.getOrPut(it) { LinkedHashSet() } += dst }
                        ja3.merge(h.ja3Hash, 1, Int::plus)
                    }
                    HTTP_REQ.find(text)?.let { m ->
                        val host = Regex("(?i)\\r\\nHost:\\s*(\\S+)").find(text)?.groupValues?.get(1)
                        http.merge("${host ?: dst} ${m.groupValues[1]} ${m.groupValues[2].take(40)}", 1, Int::plus); hostIps.getOrPut(host ?: dst) { LinkedHashSet() } += dst
                    }
                    if (dp == 21 && FTP_POP_LOGIN.containsMatchIn(text)) clear.merge("FTP 로그인(USER/PASS)", 1, Int::plus)
                    if (dp == 110 && FTP_POP_LOGIN.containsMatchIn(text)) clear.merge("POP3 로그인(USER/PASS)", 1, Int::plus)
                    if (dp == 23) clear.merge("Telnet(암호화 없는 원격 접속)", 1, Int::plus)
                    if ((dp == 80 || dp == 8080) && HTTP_BASIC.containsMatchIn(text)) clear.merge("HTTP Basic 인증", 1, Int::plus)
                    if (dp == 143 && IMAP_LOGIN.containsMatchIn(text)) clear.merge("IMAP 로그인", 1, Int::plus)
                    if ((dp == 25 || dp == 587) && SMTP_AUTH.containsMatchIn(text)) clear.merge("SMTP 인증(AUTH LOGIN/PLAIN)", 1, Int::plus)
                    if ((sp == 53 || dp == 53) && payload.size > 14) dnsOf(payload.copyOfRange(2, payload.size), src, dst, dnsQ, dnsPending, dnsAns, dnsFail, dnsAnswers)
                }
                label = service("TCP", sp, dp)
            } else if (proto == 17 && d.size >= p + 8) {
                sp = Bx.u16(d, p); dp = Bx.u16(d, p + 2)
                if ((sp == 53 || dp == 53) && d.size > p + 20) dnsOf(d.copyOfRange(p + 8, d.size), src, dst, dnsQ, dnsPending, dnsAns, dnsFail, dnsAnswers)
                label = service("UDP", sp, dp)
            } else if (proto == 1 && d.size >= p + 8) {
                label = "ICMP"; val t = Bx.u8(d, p)
                if (t == 3 || t == 11) icmpUn += "$src → $dst: ${PacketNames.ICMP_TYPE[t]}${if (t == 3) " · " + (PacketNames.ICMP_UNREACH[Bx.u8(d, p + 1)] ?: "코드 ${Bx.u8(d, p + 1)}") else ""}"
            }
            protos.merge(label, 1, Int::plus)
            val ka = if (sp >= 0) "$src:$sp" else src; val kb = if (dp >= 0) "$dst:$dp" else dst
            val key = "$proto|" + listOf(ka, kb).sorted().joinToString("|")
            val f = flows.getOrPut(key) { Flow(label, ka, kb, 0, 0, pk.tsMicros, pk.tsMicros) }; f.packets++; f.bytes += pk.origLen; f.lastUs = pk.tsMicros
        }
        val first = cap.packets.firstOrNull()?.tsMicros ?: 0; val last = cap.packets.lastOrNull()?.tsMicros ?: 0
        val synUn = synSent.filter { it.key !in answered }.entries.sortedWith(compareByDescending<Map.Entry<String, Int>> { it.value }.thenBy { it.key }).map { it.key to it.value }
        val unanswered = dnsPending.filter { it.key !in dnsAns }.values.distinct()
        return Report(cap.packets.size, bytes, first, last, l3, protos, flows.values.sortedByDescending { it.packets }.take(20), talk.entries.sortedByDescending { it.value }.take(10).map { it.key to it.value },
            LogUtil.top(dnsQ, 30), unanswered, dnsFail, dnsAnswers.mapValues { it.value.toList() }, LogUtil.top(sni, 30), sniIps.mapValues { it.value.toList() }, LogUtil.top(http, 30), hostIps.mapValues { it.value.toList() },
            syn, synAck, rst, retrans, zero, synUn, LogUtil.top(rstFrom, 10), icmpUn.take(10), arpAsk.filter { it.key.substringBefore('|') !in arpIs }.keys.map { it.substringBefore('|') },
            clear.entries.sortedByDescending { it.value }.map { it.key to it.value }, notIp, frags, LogUtil.top(ja3, 10))
    }

    private fun dnsOf(raw: ByteArray, src: String, dst: String, q: HashMap<String, Int>, pending: HashMap<String, String>, answered: HashSet<String>, fail: ArrayList<Pair<String, String>>, answers: LinkedHashMap<String, LinkedHashSet<String>>) {
        val m = DnsWire.parse(raw) ?: return
        val id = "%04x".format(m.id)
        val name = m.questions.firstOrNull()?.let { "${it.first} ${DnsType.name(it.second)}" }
        if (!m.isResponse) { if (name == null) return; q.merge(name, 1, Int::plus); pending["$src>$dst:$id"] = name }
        else {
            answered += "$dst>$src:$id"
            if (m.rcode != 0 && name != null) fail += name to DnsType.rcode(m.rcode)
            for (a in m.answers) if (a.type == DnsType.A || a.type == DnsType.AAAA) answers.getOrPut(a.name.lowercase()) { LinkedHashSet() } += a.data
        }
    }
}

// ---------------------------------------------------------------------------------------------
// 체크섬 검사·고치기: IPv4 머리글, TCP·UDP·ICMP(IPv4), TCP·UDP·ICMPv6(IPv6)

object ChecksumFix {
    class Item(val layer: String, val stored: Int, val computed: Int, val ok: Boolean, val note: String? = null)
    class Result(val items: List<Item>, val fixed: ByteArray, val problem: String? = null) { val allOk get() = problem == null && items.all { it.ok } }

    fun analyze(b: ByteArray, start: String = "auto"): Result {
        val d = b.copyOf(); val items = ArrayList<Item>()
        val mode = when (start) { "eth" -> "eth"; "ip" -> "ip"; else -> if (PacketDecode.looksLikeIp(b)) "ip" else "eth" }
        var off = 0; var et: Int
        if (mode == "eth") {
            if (b.size < 14) return Result(items, d, "이더넷 머리글(14바이트)보다 짧아요")
            et = Bx.u16(b, 12); off = 14
            while ((et == 0x8100 || et == 0x88A8) && off + 4 <= b.size) { et = Bx.u16(b, off + 2); off += 4 }
        } else {
            if (b.isEmpty()) return Result(items, d, "내용이 없어요")
            et = if (Bx.u8(b, 0) shr 4 == 6) 0x86DD else 0x0800
        }
        when (et) {
            0x0800 -> v4(b, d, off, items)
            0x86DD -> v6(b, d, off, items)
            else -> return Result(items, d, "IPv4·IPv6 패킷이 아니에요 (EtherType 0x%04x)".format(et))
        }
        return Result(items, d)
    }

    /** 체크섬 칸을 0 으로 두고 다시 계산해서 채움. (저장돼 있던 값, 계산한 값) */
    private fun redo(d: ByteArray, from: Int, to: Int, pos: Int, init: Long): Pair<Int, Int> {
        val stored = Bx.u16(d, pos); d[pos] = 0; d[pos + 1] = 0
        val c = InetChecksum.checksum(d, from, to, init)
        Bx.be16(c).copyInto(d, pos)
        return stored to c
    }

    private fun l4(b: ByteArray, d: ByteArray, p: Int, to: Int, cut: Boolean, name: String, pos: Int, minLen: Int, init: Long, items: ArrayList<Item>, zeroOk: Boolean = false) {
        if (to - p < minLen) { items += Item(name, 0, 0, false, "$name 머리글($minLen 바이트)보다 짧아요"); return }
        val stored = Bx.u16(b, p + pos)
        if (cut) { items += Item(name, stored, stored, true, "캡처가 잘려서(snaplen) 끝까지 계산할 수 없어요"); return }
        if (zeroOk && stored == 0) { items += Item(name, 0, 0, true, "체크섬 0 = 사용 안 함 (IPv4 의 UDP 는 허용돼요)"); return }
        val (s, c) = redo(d, p, to, p + pos, init)
        var cc = c
        if (name == "UDP" && c == 0) { cc = 0xffff; Bx.be16(0xffff).copyInto(d, p + pos) }       // UDP 는 계산 결과가 0 이면 0xffff 로 보내요
        items += Item(name, s, cc, s == cc)
    }

    private fun v4(b: ByteArray, d: ByteArray, off: Int, items: ArrayList<Item>) {
        if (b.size < off + 20) { items += Item("IPv4 머리글", 0, 0, false, "IPv4 머리글(20바이트)보다 짧아요"); return }
        val ihl = (Bx.u8(b, off) and 15) * 4
        if (ihl < 20 || off + ihl > b.size) { items += Item("IPv4 머리글", 0, 0, false, "머리글 길이 칸($ihl)이 이상해요"); return }
        val (s0, c0) = redo(d, off, off + ihl, off + 10, 0)
        items += Item("IPv4 머리글", s0, c0, s0 == c0)
        val total = Bx.u16(b, off + 2); val proto = Bx.u8(b, off + 9); val fl = Bx.u16(b, off + 6)
        if (total < ihl) { items += Item("IPv4 전체 길이", total, ihl, false, "전체 길이 칸($total)이 머리글 길이($ihl)보다 작아요"); return }
        val cut = off + total > b.size; val end = minOf(b.size, off + total); val p = off + ihl
        if (fl and 0x2000 != 0 || fl and 0x1fff != 0) { items += Item("TCP·UDP·ICMP", 0, 0, true, "조각난 패킷이라 조각을 다 모아야 체크섬을 계산할 수 있어요"); return }
        val src = b.copyOfRange(off + 12, off + 16); val dst = b.copyOfRange(off + 16, off + 20)
        when (proto) {
            6 -> l4(b, d, p, end, cut, "TCP", 16, 20, InetChecksum.pseudoV4(src, dst, 6, end - p), items)
            17 -> { val ul = if (end - p >= 8) Bx.u16(b, p + 4) else 0; val len = if (ul in 8..(end - p)) ul else end - p; l4(b, d, p, p + len, cut, "UDP", 6, 8, InetChecksum.pseudoV4(src, dst, 17, len), items, zeroOk = true) }
            1 -> l4(b, d, p, end, cut, "ICMP", 2, 8, 0, items)
            else -> items += Item(PacketNames.PROTO[proto] ?: "프로토콜 $proto", 0, 0, true, "이 프로토콜은 체크섬을 따로 계산하지 않아요")
        }
    }

    private fun v6(b: ByteArray, d: ByteArray, off: Int, items: ArrayList<Item>) {
        if (b.size < off + 40) { items += Item("IPv6 머리글", 0, 0, false, "IPv6 머리글(40바이트)보다 짧아요"); return }
        val plen = Bx.u16(b, off + 4); var next = Bx.u8(b, off + 6); var p = off + 40
        val src = b.copyOfRange(off + 8, off + 24); val dst = b.copyOfRange(off + 24, off + 40)
        while (next in listOf(0, 43, 44, 60) && p + 8 <= b.size) { val nn = Bx.u8(b, p); p += if (next == 44) 8 else (Bx.u8(b, p + 1) + 1) * 8; next = nn }
        val cut = off + 40 + plen > b.size; val end = minOf(b.size, off + 40 + plen); val len = off + 40 + plen - p
        items += Item("IPv6 머리글", 0, 0, true, "IPv6 에는 머리글 체크섬이 없어요")
        when (next) {
            6 -> l4(b, d, p, end, cut, "TCP", 16, 20, InetChecksum.pseudoV6(src, dst, 6, len), items)
            17 -> l4(b, d, p, end, cut, "UDP", 6, 8, InetChecksum.pseudoV6(src, dst, 17, len), items)
            58 -> l4(b, d, p, end, cut, "ICMPv6", 2, 4, InetChecksum.pseudoV6(src, dst, 58, len), items)
            else -> items += Item(PacketNames.PROTO[next] ?: "프로토콜 $next", 0, 0, true, "이 프로토콜은 체크섬을 따로 계산하지 않아요")
        }
    }
}

// ---------------------------------------------------------------------------------------------
// 패킷 만들기

object PacketBuild {
    fun ipv4(src: ByteArray, dst: ByteArray, proto: Int, payload: ByteArray, ttl: Int = 64, id: Int = 1, df: Boolean = true, tos: Int = 0): ByteArray {
        val h = ByteArray(20); h[0] = 0x45; h[1] = tos.toByte(); Bx.be16(20 + payload.size).copyInto(h, 2); Bx.be16(id).copyInto(h, 4); Bx.be16(if (df) 0x4000 else 0).copyInto(h, 6); h[8] = ttl.toByte(); h[9] = proto.toByte(); src.copyInto(h, 12); dst.copyInto(h, 16)
        Bx.be16(InetChecksum.checksum(h)).copyInto(h, 10); return h + payload
    }
    fun icmpEcho(id: Int, seq: Int, data: ByteArray, reply: Boolean = false): ByteArray { val m = byteArrayOf(if (reply) 0 else 8, 0, 0, 0) + Bx.be16(id) + Bx.be16(seq) + data; Bx.be16(InetChecksum.checksum(m)).copyInto(m, 2); return m }
    fun udp(src: ByteArray, dst: ByteArray, sport: Int, dport: Int, data: ByteArray): ByteArray {
        val u = Bx.be16(sport) + Bx.be16(dport) + Bx.be16(8 + data.size) + byteArrayOf(0, 0) + data
        var c = InetChecksum.checksum(u, init = InetChecksum.pseudoV4(src, dst, 17, u.size)); if (c == 0) c = 0xffff; Bx.be16(c).copyInto(u, 6); return u
    }
    fun tcp(src: ByteArray, dst: ByteArray, sport: Int, dport: Int, seq: Long, ack: Long, flags: Int, win: Int, data: ByteArray, synOptions: Boolean = false): ByteArray {
        val opt = if (synOptions) byteArrayOf(2, 4, 0x05, 0xb4.toByte(), 4, 2, 1, 3, 3, 7, 1, 1) else ByteArray(0)       // MSS 1460, SACK 허용, 윈도 배율 7, 채움
        val t = Bx.be16(sport) + Bx.be16(dport) + Bx.be32(seq) + Bx.be32(ack) + byteArrayOf((((20 + opt.size) / 4) shl 4).toByte(), flags.toByte()) + Bx.be16(win) + byteArrayOf(0, 0, 0, 0) + opt + data
        Bx.be16(InetChecksum.checksum(t, init = InetChecksum.pseudoV4(src, dst, 6, t.size))).copyInto(t, 16); return t
    }
    fun ether(dst: ByteArray, src: ByteArray, type: Int, payload: ByteArray) = dst + src + Bx.be16(type) + payload
    fun arp(op: Int, smac: ByteArray, sip: ByteArray, tmac: ByteArray, tip: ByteArray) = Bx.be16(1) + Bx.be16(0x0800) + byteArrayOf(6, 4) + Bx.be16(op) + smac + sip + tmac + tip
    fun wol(mac: ByteArray) = ByteArray(6) { 0xff.toByte() } + (1..16).flatMap { mac.toList() }.toByteArray()
    fun ntpRequest(): ByteArray = ByteArray(48).also { it[0] = 0x1b }
}
