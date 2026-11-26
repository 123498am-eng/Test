package com.selfcheck.app

import java.nio.ByteBuffer
import java.nio.charset.CharacterCodingException
import java.nio.charset.CodingErrorAction
import java.security.MessageDigest
import java.security.cert.X509Certificate
import java.time.Instant
import java.time.LocalDate
import java.time.LocalDateTime
import java.time.ZoneId
import java.time.ZonedDateTime
import java.time.format.DateTimeFormatter
import javax.crypto.Mac as JMac
import javax.crypto.spec.SecretKeySpec

/*
 * 변환·인코딩·해시 계산 엔진 (화면과 분리, 컴퓨터에서 표준 시험 값으로 확인)
 */

object Base32 {
    private const val ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"

    fun encode(data: ByteArray, pad: Boolean = true): String {
        val sb = StringBuilder()
        var buffer = 0; var bits = 0
        for (b in data) {
            buffer = (buffer shl 8) or (b.toInt() and 0xff); bits += 8
            while (bits >= 5) { sb.append(ALPHABET[(buffer shr (bits - 5)) and 31]); bits -= 5 }
        }
        if (bits > 0) sb.append(ALPHABET[(buffer shl (5 - bits)) and 31])
        if (pad) while (sb.length % 8 != 0) sb.append('=')
        return sb.toString()
    }

    /** 공백·하이픈·= 는 무시, 소문자 허용. 틀린 글자가 있으면 null */
    fun decode(s: String): ByteArray? {
        val clean = s.uppercase().filter { it != ' ' && it != '-' && it != '=' && it != '\n' && it != '\r' && it != '\t' }
        val out = java.io.ByteArrayOutputStream()
        var buffer = 0; var bits = 0
        for (c in clean) {
            val v = ALPHABET.indexOf(c)
            if (v < 0) return null
            buffer = (buffer shl 5) or v; bits += 5
            if (bits >= 8) { out.write((buffer shr (bits - 8)) and 0xff); bits -= 8 }
        }
        return out.toByteArray()
    }
}

object Percent {
    private const val UNRESERVED = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~"

    /** RFC 3986 퍼센트 인코딩 (UTF-8). formStyle 이면 공백을 + 로 */
    fun encode(s: String, formStyle: Boolean = false): String {
        val sb = StringBuilder()
        for (b in s.toByteArray(Charsets.UTF_8)) {
            val c = (b.toInt() and 0xff).toChar()
            when {
                c in UNRESERVED -> sb.append(c)
                c == ' ' && formStyle -> sb.append('+')
                else -> sb.append('%').append("%02X".format(b.toInt() and 0xff))
            }
        }
        return sb.toString()
    }

    /** 퍼센트 디코딩. 잘못된 %XX 가 있으면 null */
    fun decode(s: String, plusIsSpace: Boolean = false): String? {
        val out = java.io.ByteArrayOutputStream()
        var i = 0
        while (i < s.length) {
            val c = s[i]
            when {
                c == '%' -> {
                    if (i + 3 > s.length) return null
                    val h = s.substring(i + 1, i + 3).toIntOrNull(16) ?: return null
                    out.write(h); i += 3
                }
                c == '+' && plusIsSpace -> { out.write(' '.code); i++ }
                else -> { out.write(c.toString().toByteArray(Charsets.UTF_8)); i++ }
            }
        }
        return String(out.toByteArray(), Charsets.UTF_8)
    }
}

object Html {
    private val NAMED = mapOf(
        "amp" to "&", "lt" to "<", "gt" to ">", "quot" to "\"", "apos" to "'", "nbsp" to " ", "copy" to "©", "reg" to "®", "trade" to "™",
        "hellip" to "…", "mdash" to "—", "ndash" to "–", "lsquo" to "‘", "rsquo" to "’", "ldquo" to "“", "rdquo" to "”", "bull" to "•",
        "middot" to "·", "euro" to "€", "yen" to "¥", "pound" to "£", "cent" to "¢", "laquo" to "«", "raquo" to "»", "times" to "×",
        "divide" to "÷", "deg" to "°", "plusmn" to "±",
    )

    fun encode(s: String, allNonAscii: Boolean = false): String {
        val sb = StringBuilder()
        var i = 0
        while (i < s.length) {
            val cp = s.codePointAt(i); i += Character.charCount(cp)
            when {
                cp == '&'.code -> sb.append("&amp;"); cp == '<'.code -> sb.append("&lt;"); cp == '>'.code -> sb.append("&gt;")
                cp == '"'.code -> sb.append("&quot;"); cp == '\''.code -> sb.append("&#39;")
                allNonAscii && cp > 127 -> sb.append("&#x").append(cp.toString(16).uppercase()).append(';')
                else -> sb.appendCodePoint(cp)
            }
        }
        return sb.toString()
    }

    private val ENTITY = Regex("&(#[xX][0-9A-Fa-f]+|#\\d+|[A-Za-z][A-Za-z0-9]*);")

    fun decode(s: String): String = ENTITY.replace(s) { m ->
        val g = m.groupValues[1]
        when {
            g.startsWith("#x") || g.startsWith("#X") -> g.substring(2).toIntOrNull(16)?.takeIf { Character.isValidCodePoint(it) }?.let { String(Character.toChars(it)) } ?: m.value
            g.startsWith("#") -> g.substring(1).toIntOrNull()?.takeIf { Character.isValidCodePoint(it) }?.let { String(Character.toChars(it)) } ?: m.value
            else -> NAMED[g] ?: m.value
        }
    }
}

object Totp {
    fun hmac(alg: String, key: ByteArray, data: ByteArray): ByteArray = JMac.getInstance(alg).run { init(SecretKeySpec(key, alg)); doFinal(data) }

    /** RFC 6238/4226: counter 하나에 대한 일회용 코드 */
    fun code(secret: ByteArray, counter: Long, digits: Int = 6, alg: String = "HmacSHA1"): String {
        val h = hmac(alg, secret, ByteBuffer.allocate(8).putLong(counter).array())
        val off = h.last().toInt() and 0x0f
        val bin = ((h[off].toInt() and 0x7f) shl 24) or ((h[off + 1].toInt() and 0xff) shl 16) or ((h[off + 2].toInt() and 0xff) shl 8) or (h[off + 3].toInt() and 0xff)
        var mod = 1L; repeat(digits) { mod *= 10 }
        return (bin.toLong() % mod).toString().padStart(digits, '0')
    }

    fun at(secret: ByteArray, epochSec: Long, period: Int, digits: Int, alg: String) = code(secret, epochSec / period, digits, alg)
}

object Hashes {
    fun hex(b: ByteArray) = b.joinToString("") { "%02x".format(it.toInt() and 0xff) }
    fun digest(alg: String, data: ByteArray): ByteArray = MessageDigest.getInstance(alg).digest(data)
    val ALGS = listOf("MD5", "SHA-1", "SHA-256", "SHA-384", "SHA-512")

    /** 인터넷 체크섬 (RFC 1071): 16비트 합의 1의 보수 */
    fun internetChecksum(b: ByteArray): Int {
        var sum = 0L
        var i = 0
        while (i < b.size) {
            val hi = b[i].toInt() and 0xff
            val lo = if (i + 1 < b.size) b[i + 1].toInt() and 0xff else 0
            sum += (hi shl 8) or lo; i += 2
        }
        while (sum shr 16 != 0L) sum = (sum and 0xffff) + (sum shr 16)
        return (sum.inv() and 0xffff).toInt()
    }
}

object Epoch {
    val KST: ZoneId = ZoneId.of("Asia/Seoul")
    private val FMT = DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss")

    /** 숫자의 크기로 단위 추정: 초 / 밀리초 / 마이크로초 / 나노초 */
    fun fromNumber(n: Long): Pair<Instant, String> {
        val a = Math.abs(n)
        return when {
            a >= 100_000_000_000_000_000L -> Instant.ofEpochSecond(n / 1_000_000_000, n % 1_000_000_000) to "나노초"
            a >= 100_000_000_000_000L -> Instant.ofEpochSecond(n / 1_000_000, (n % 1_000_000) * 1000) to "마이크로초"
            a >= 100_000_000_000L -> Instant.ofEpochMilli(n) to "밀리초"
            else -> Instant.ofEpochSecond(n) to "초"
        }
    }

    fun fmt(i: Instant, zone: ZoneId): String = FMT.format(ZonedDateTime.ofInstant(i, zone)) + " (${zone.id.let { if (it == "Z") "UTC" else it }})"

    /** "2025-01-31 12:30:00", "2025-01-31T12:30:00Z", "2025-01-31T12:30:00+09:00", "2025/01/31", "2025.01.31" */
    fun parseDate(s: String, zone: ZoneId): Instant? {
        val t = s.trim().replace('/', '-').replace('.', '-')
        runCatching { return Instant.parse(t) }
        runCatching { return ZonedDateTime.parse(t).toInstant() }
        runCatching { return java.time.OffsetDateTime.parse(t).toInstant() }
        for (p in listOf("yyyy-MM-dd HH:mm:ss", "yyyy-MM-dd'T'HH:mm:ss", "yyyy-MM-dd HH:mm", "yyyy-MM-dd'T'HH:mm"))
            runCatching { return LocalDateTime.parse(t, DateTimeFormatter.ofPattern(p)).atZone(zone).toInstant() }
        runCatching { return LocalDate.parse(t).atStartOfDay(zone).toInstant() }
        return null
    }
}

/** 인증서 한 장을 사람이 읽는 줄로 (PEM 해석·TLS 점검에서 함께 씀) */
object CertInfo {
    private fun dn(x: String) = x.replace(", ", ",").replace(",", ", ")

    fun fingerprint(c: X509Certificate, alg: String): String =
        Hashes.hex(MessageDigest.getInstance(alg).digest(c.encoded)).chunked(2).joinToString(":").uppercase()

    fun daysLeft(c: X509Certificate, now: Long = System.currentTimeMillis()): Long = Math.floorDiv(c.notAfter.time - now, 86_400_000L)

    fun keyDesc(c: X509Certificate): String {
        val k = c.publicKey
        return when (k) {
            is java.security.interfaces.RSAPublicKey -> "RSA ${k.modulus.bitLength()}비트"
            is java.security.interfaces.ECPublicKey -> "EC ${k.params.order.bitLength()}비트"
            else -> k.algorithm
        }
    }

    fun sans(c: X509Certificate): List<String> = runCatching {
        c.subjectAlternativeNames?.mapNotNull { e ->
            val v = e[1]?.toString() ?: return@mapNotNull null
            when (e[0] as? Int) { 2 -> v; 7 -> "IP $v"; 1 -> "메일 $v"; 6 -> "URI $v"; else -> v }
        }
    }.getOrNull() ?: emptyList()

    fun describe(c: X509Certificate): List<Pair<String, String>> {
        val left = daysLeft(c)
        val fmt = DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm").withZone(ZoneId.of("UTC"))
        return listOf(
            "주체(Subject)" to dn(c.subjectX500Principal.name), "발급자(Issuer)" to dn(c.issuerX500Principal.name),
            "일련번호" to c.serialNumber.toString(16).uppercase(),
            "유효 시작" to fmt.format(c.notBefore.toInstant()) + " UTC", "유효 끝" to fmt.format(c.notAfter.toInstant()) + " UTC",
            "남은 기간" to if (left < 0) "${-left}일 전에 만료됨" else "${left}일 남음",
            "서명 알고리즘" to c.sigAlgName, "공개키" to keyDesc(c),
            "CA 인증서" to if (c.basicConstraints >= 0) "예" else "아니요",
            "SHA-256 지문" to fingerprint(c, "SHA-256"), "SHA-1 지문" to fingerprint(c, "SHA-1"),
        ) + sans(c).let { if (it.isEmpty()) emptyList() else listOf("대체 이름(SAN)" to it.take(12).joinToString(", ") + if (it.size > 12) " 외 ${it.size - 12}개" else "") }
    }
}

/** 글(UTF-8) → 바이트가 올바른 UTF-8 이면 글, 아니면 null */
fun strictUtf8(b: ByteArray): String? = try {
    Charsets.UTF_8.newDecoder().onMalformedInput(CodingErrorAction.REPORT).onUnmappableCharacter(CodingErrorAction.REPORT).decode(ByteBuffer.wrap(b)).toString()
} catch (_: CharacterCodingException) { null }

fun hexDump(b: ByteArray, limit: Int = 256): String {
    val sb = StringBuilder()
    for (off in 0 until minOf(b.size, limit) step 16) {
        val chunk = b.copyOfRange(off, minOf(off + 16, b.size))
        sb.append("%04x  ".format(off)).append(chunk.joinToString(" ") { "%02x".format(it.toInt() and 0xff) }.padEnd(47)).append("  ")
            .append(chunk.map { val c = it.toInt() and 0xff; if (c in 32..126) c.toChar() else '.' }.joinToString("")).append('\n')
    }
    if (b.size > limit) sb.append("… (${b.size - limit}바이트 더)")
    return sb.toString().trimEnd()
}

