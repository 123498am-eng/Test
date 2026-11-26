package com.selfcheck.app

import org.json.JSONObject
import java.math.BigInteger
import java.net.IDN
import java.security.MessageDigest
import java.security.SecureRandom
import java.util.Base64
import javax.crypto.Cipher
import javax.crypto.Mac
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.IvParameterSpec
import javax.crypto.spec.SecretKeySpec
import kotlin.math.ceil
import kotlin.math.floor
import kotlin.math.ln
import kotlin.math.log2
import kotlin.math.pow
import kotlin.math.roundToLong

/*
 * 보안 도구 엔진: 모두 휴대폰 안에서만 계산하고 비밀번호·키를 밖으로 보내지 않아요.
 * PBKDF2·WPA PSK·htpasswd(MD5-crypt·SHA-crypt)·X25519·Ed25519·SSH 지문·CVSS·CSP·URL 점검·비밀 검사·AES 상자·JWT 서명 확인·비밀번호 강도.
 * 규격 예시(RFC 6070·7748·8032·7515, IEEE 802.11i)와 openssl·파이썬 cryptography 로 만든 값으로 시험합니다.
 */

object Pbkdf2 {
    /** PBKDF2 (RFC 8018). hmacAlg 는 "HmacSHA1" 같은 JCA 이름 */
    fun derive(hmacAlg: String, password: ByteArray, salt: ByteArray, iterations: Int, dkLen: Int): ByteArray {
        require(iterations >= 1 && dkLen >= 1)
        val mac = Mac.getInstance(hmacAlg)
        mac.init(SecretKeySpec(if (password.isEmpty()) ByteArray(1) else password, hmacAlg))     // 빈 키는 0 하나와 같은 HMAC (키는 0 으로 채워지므로)
        val hLen = mac.macLength; val blocks = (dkLen + hLen - 1) / hLen
        val out = ByteArray(dkLen)
        for (b in 1..blocks) {
            mac.update(salt); mac.update(byteArrayOf((b ushr 24).toByte(), (b ushr 16).toByte(), (b ushr 8).toByte(), b.toByte()))
            var u = mac.doFinal(); val t = u.copyOf()
            for (i in 2..iterations) { u = mac.doFinal(u); for (k in t.indices) t[k] = (t[k].toInt() xor u[k].toInt()).toByte() }
            System.arraycopy(t, 0, out, (b - 1) * hLen, minOf(hLen, dkLen - (b - 1) * hLen))
        }
        return out
    }
}

object WpaPsk {
    /** WPA/WPA2 개인용 PSK: PBKDF2-HMAC-SHA1(암호, SSID, 4096번, 32바이트) — IEEE 802.11i 부록 H.4 */
    fun psk(passphrase: String, ssid: String): ByteArray = Pbkdf2.derive("HmacSHA1", passphrase.toByteArray(Charsets.UTF_8), ssid.toByteArray(Charsets.UTF_8), 4096, 32)

    /** 규격 위반·주의 (내용, 심각도) */
    fun problems(passphrase: String, ssid: String): List<Pair<String, Int>> = buildList {
        val pb = passphrase.toByteArray(Charsets.UTF_8).size; val sb = ssid.toByteArray(Charsets.UTF_8).size
        if (sb !in 1..32) add("SSID 는 1~32바이트여야 해요 (지금 ${sb}바이트)" to 2)
        if (passphrase.length !in 8..63) add("암호는 8~63글자여야 해요 (지금 ${passphrase.length}글자). 64자리 16진수라면 그 값이 이미 PSK 예요" to 2)
        else if (passphrase.any { it.code !in 32..126 }) add("암호에 ASCII 가 아닌 글자가 있어요. 규격은 ASCII 만 허용하고, 기기마다 글자 인코딩이 달라 접속이 안 될 수 있어요 (${pb}바이트)" to 1)
        if (passphrase.length in 8..11) add("암호가 짧아요. 12글자 이상을 권장해요 (PSK 는 오프라인으로 무차별 대입이 가능해요)" to 1)
    }
}

// ---------------------------------------------------------------------------------------------
// 비밀번호 강도

object PasswordStrength {
    class Report(val length: Int, val classes: List<String>, val pool: Int, val naiveBits: Double, val bits: Double, val patterns: List<String>, val level: Int, val label: String)

    private val ROWS = listOf("qwertyuiop", "asdfghjkl", "zxcvbnm", "1234567890", "ㅂㅈㄷㄱㅅㅛㅕㅑㅐㅔ", "ㅁㄴㅇㄹㅎㅗㅓㅏㅣ", "ㅋㅌㅊㅍㅠㅜㅡ")

    private fun poolOf(pw: String): Pair<Int, List<String>> {
        var pool = 0; val c = ArrayList<String>()
        if (pw.any { it in 'a'..'z' }) { pool += 26; c += "소문자" }
        if (pw.any { it in 'A'..'Z' }) { pool += 26; c += "대문자" }
        if (pw.any { it in '0'..'9' }) { pool += 10; c += "숫자" }
        if (pw.any { it.code in 32..126 && !it.isLetterOrDigit() }) { pool += 33; c += "기호" }
        if (pw.any { it.code > 126 }) { pool += 128; c += "한글·기타 글자" }
        return pool to c
    }

    private fun sameRun(s: String, i: Int): Int { var k = i; while (k + 1 < s.length && s[k + 1] == s[i]) k++; return k - i + 1 }
    private fun stepRun(s: String, i: Int): Int {
        if (i + 1 >= s.length) return 1
        val d = s[i + 1].code - s[i].code; if (d != 1 && d != -1) return 1
        var k = i + 1; while (k + 1 < s.length && s[k + 1].code - s[k].code == d) k++; return k - i + 1
    }
    private fun rowRun(s: String, i: Int): Int {
        var best = 1
        for (row in ROWS) for (rev in listOf(false, true)) {
            val r = if (rev) row.reversed() else row
            val start = r.indexOf(s[i].lowercaseChar()); if (start < 0) continue
            var k = 1; while (i + k < s.length && start + k < r.length && s[i + k].lowercaseChar() == r[start + k]) k++
            best = maxOf(best, k)
        }
        return best
    }
    private fun blockRepeat(s: String, i: Int): Pair<Int, Int>? {       // (덩어리 길이, 반복 횟수)
        for (p in 2..(s.length - i) / 2) {
            if (s.regionMatches(i, s, i + p, p) && s.substring(i, i + p).toSet().size > 1) { var reps = 2; while (i + (reps + 1) * p <= s.length && s.regionMatches(i, s, i + reps * p, p)) reps++; if (p * reps >= 6) return p to reps }
        }
        return null
    }

    fun analyze(pw: String): Report {
        if (pw.isEmpty()) return Report(0, emptyList(), 0, 0.0, 0.0, emptyList(), 0, "비어 있어요")
        val (pool, classes) = poolOf(pw); val per = log2(pool.toDouble()); val naive = pw.length * per
        var bits = 0.0; val patterns = ArrayList<String>(); var i = 0
        while (i < pw.length) {
            val run = sameRun(pw, i); if (run >= 3) { bits += per + log2(run.toDouble()); patterns += "같은 글자 반복(${pw[i]} × $run)"; i += run; continue }
            val br = blockRepeat(pw, i)
            if (br != null) { bits += br.first * per + log2(br.second.toDouble()); patterns += "같은 덩어리 반복(\"${pw.substring(i, i + br.first)}\" × ${br.second})"; i += br.first * br.second; continue }
            val seq = stepRun(pw, i); if (seq >= 3) { bits += per + 1 + log2(seq.toDouble()); patterns += "연속된 글자(${pw.substring(i, i + seq)})"; i += seq; continue }
            val row = rowRun(pw, i); if (row >= 3) { bits += per + 1 + log2(row.toDouble()); patterns += "키보드 줄 그대로(${pw.substring(i, i + row)})"; i += row; continue }
            if (i + 4 <= pw.length && Regex("(19|20)\\d\\d").matches(pw.substring(i, i + 4))) { bits += log2(120.0); patterns += "연도(${pw.substring(i, i + 4)})"; i += 4; continue }
            bits += per; i++
        }
        val level = when { bits < 28 -> 0; bits < 36 -> 1; bits < 60 -> 2; bits < 80 -> 3; else -> 4 }
        return Report(pw.length, classes, pool, naive, bits, patterns, level, listOf("매우 약함", "약함", "보통", "강함", "매우 강함")[level])
    }

    /** 평균적으로 맞히는 데 걸리는 시간(초): 가능한 경우의 절반을 시도 */
    fun seconds(bits: Double, guessesPerSecond: Double): Double = 2.0.pow(bits - 1) / guessesPerSecond

    fun human(sec: Double): String {
        if (sec < 1) return "1초도 안 걸려요"
        if (sec < 60) return "${sec.roundToLong()}초"
        if (sec < 3600) return "${(sec / 60).roundToLong()}분"
        if (sec < 86400) return "${(sec / 3600).roundToLong()}시간"
        val days = sec / 86400
        if (days < 365) return "${days.roundToLong()}일"
        val years = days / 365.25
        return when {
            years < 1e4 -> "${"%,d".format(years.roundToLong())}년"
            years < 1e8 -> "${"%.1f".format(years / 1e4)}만 년"
            years < 1e12 -> "${"%.1f".format(years / 1e8)}억 년"
            years < 1e16 -> "${"%.1f".format(years / 1e12)}조 년"
            else -> "사실상 불가능 (우주 나이 138억 년보다 훨씬 길어요)"
        }
    }
}

object Hibp {
    fun sha1Hex(pw: String): String = MessageDigest.getInstance("SHA-1").digest(pw.toByteArray(Charsets.UTF_8)).joinToString("") { "%02X".format(it.toInt() and 0xff) }

    /** 응답("해시뒷부분:횟수" 줄들)에서 내 뒷부분을 찾음. 없거나 가짜 채움(횟수 0)이면 null */
    fun count(body: String, suffix: String): Long? {
        for (l in body.lineSequence()) { val t = l.trim(); if (t.length > 36 && t.substring(0, 35).equals(suffix, true) && t[35] == ':') return t.substring(36).trim().toLongOrNull()?.takeIf { it > 0 } }
        return null
    }
}

// ---------------------------------------------------------------------------------------------
// htpasswd 용 해시: MD5-crypt($1$·$apr1$) · SHA-crypt($5$·$6$)

object UnixCrypt {
    private const val ITOA64 = "./0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
    const val SALT_CHARS = ITOA64

    private fun to64(v: Int, n: Int, sb: StringBuilder) { var x = v; repeat(n) { sb.append(ITOA64[x and 0x3f]); x = x ushr 6 } }
    private fun b24(b: ByteArray, x: Int, y: Int, z: Int, n: Int, sb: StringBuilder) = to64(((b[x].toInt() and 0xff) shl 16) or ((b[y].toInt() and 0xff) shl 8) or (b[z].toInt() and 0xff), n, sb)

    fun randomSalt(n: Int, rnd: SecureRandom = SecureRandom()): String = (1..n).map { ITOA64[rnd.nextInt(64)] }.joinToString("")

    /** magic 은 "$1$"(리눅스 shadow) 또는 "$apr1$"(아파치 htpasswd) */
    fun md5(pw: ByteArray, salt: String, magic: String = "\$1\$"): String {
        val s = salt.removePrefix(magic).substringBefore('$').take(8).toByteArray()
        val md = MessageDigest.getInstance("MD5")
        md.update(pw); md.update(s); md.update(pw); val alt = md.digest()
        md.reset(); md.update(pw); md.update(magic.toByteArray()); md.update(s)
        var pl = pw.size; while (pl > 0) { md.update(alt, 0, minOf(16, pl)); pl -= 16 }
        var i = pw.size; while (i > 0) { if (i and 1 != 0) md.update(0.toByte()) else md.update(pw[0]); i = i ushr 1 }
        var fin = md.digest()
        for (r in 0 until 1000) {
            md.reset()
            if (r and 1 != 0) md.update(pw) else md.update(fin)
            if (r % 3 != 0) md.update(s)
            if (r % 7 != 0) md.update(pw)
            if (r and 1 != 0) md.update(fin) else md.update(pw)
            fin = md.digest()
        }
        val sb = StringBuilder(magic).append(String(s)).append('$')
        b24(fin, 0, 6, 12, 4, sb); b24(fin, 1, 7, 13, 4, sb); b24(fin, 2, 8, 14, 4, sb); b24(fin, 3, 9, 15, 4, sb); b24(fin, 4, 10, 5, 4, sb)
        to64(fin[11].toInt() and 0xff, 2, sb)
        return sb.toString()
    }

    /** SHA-crypt (Drepper). sha512 = true 면 $6$, 아니면 $5$. rounds 가 null 이면 기본 5000번 */
    fun sha(pw: ByteArray, salt: String, sha512: Boolean, rounds: Int? = null): String {
        val magic = if (sha512) "\$6\$" else "\$5\$"
        var body = salt.removePrefix(magic); var custom = false; var n = 5000
        if (body.startsWith("rounds=")) { body.substringAfter("rounds=").substringBefore('$').toIntOrNull()?.let { n = it.coerceIn(1000, 999_999_999); custom = true }; body = body.substringAfter('$') }
        rounds?.let { n = it.coerceIn(1000, 999_999_999); custom = true }
        val s = body.substringBefore('$').take(16).toByteArray()
        val md = MessageDigest.getInstance(if (sha512) "SHA-512" else "SHA-256"); val hl = md.digestLength
        md.update(pw); md.update(s); md.update(pw); val b = md.digest()
        md.reset(); md.update(pw); md.update(s)
        var cnt = pw.size; while (cnt > hl) { md.update(b); cnt -= hl }; md.update(b, 0, cnt)
        cnt = pw.size; while (cnt > 0) { if (cnt and 1 != 0) md.update(b) else md.update(pw); cnt = cnt ushr 1 }
        var a = md.digest()
        md.reset(); repeat(pw.size) { md.update(pw) }; val dp = md.digest()
        val p = ByteArray(pw.size) { dp[it % hl] }
        md.reset(); repeat(16 + (a[0].toInt() and 0xff)) { md.update(s) }; val ds = md.digest()
        val sq = ByteArray(s.size) { ds[it % hl] }
        for (r in 0 until n) {
            md.reset()
            if (r and 1 != 0) md.update(p) else md.update(a)
            if (r % 3 != 0) md.update(sq)
            if (r % 7 != 0) md.update(p)
            if (r and 1 != 0) md.update(a) else md.update(p)
            a = md.digest()
        }
        val sb = StringBuilder(magic); if (custom) sb.append("rounds=").append(n).append('$'); sb.append(String(s)).append('$')
        if (sha512) {
            val t = listOf(0, 21, 42, 22, 43, 1, 44, 2, 23, 3, 24, 45, 25, 46, 4, 47, 5, 26, 6, 27, 48, 28, 49, 7, 50, 8, 29, 9, 30, 51, 31, 52, 10, 53, 11, 32, 12, 33, 54, 34, 55, 13, 56, 14, 35, 15, 36, 57, 37, 58, 16, 59, 17, 38, 18, 39, 60, 40, 61, 19, 62, 20, 41)
            for (k in t.indices step 3) b24(a, t[k], t[k + 1], t[k + 2], 4, sb)
            to64(a[63].toInt() and 0xff, 2, sb)
        } else {
            val t = listOf(0, 10, 20, 21, 1, 11, 12, 22, 2, 3, 13, 23, 24, 4, 14, 15, 25, 5, 6, 16, 26, 27, 7, 17, 18, 28, 8, 9, 19, 29)
            for (k in t.indices step 3) b24(a, t[k], t[k + 1], t[k + 2], 4, sb)
            to64(((a[31].toInt() and 0xff) shl 8) or (a[30].toInt() and 0xff), 3, sb)
        }
        return sb.toString()
    }

    /** htpasswd 의 {SHA} 형식: Base64(SHA-1(비밀번호)) — 오래됐고 약해서 권장하지 않음 */
    fun htpasswdSha1(pw: ByteArray): String = "{SHA}" + Base64.getEncoder().encodeToString(MessageDigest.getInstance("SHA-1").digest(pw))
}

// ---------------------------------------------------------------------------------------------
// 곡선 암호: X25519 (RFC 7748) · Ed25519 공개키 (RFC 8032)

object X25519 {
    private val P = BigInteger.ONE.shiftLeft(255).subtract(BigInteger.valueOf(19))
    private val A24 = BigInteger.valueOf(121665)
    val BASE = ByteArray(32).also { it[0] = 9 }

    private fun decodeLE(b: ByteArray): BigInteger = BigInteger(1, b.reversedArray())
    private fun encodeLE(x: BigInteger): ByteArray {
        val be = x.toByteArray(); val out = ByteArray(32)
        for (i in 0 until minOf(32, be.size)) out[i] = be[be.size - 1 - i]
        return out
    }

    /** 개인키 비트 정리: 아래 3비트 0, 맨 위 비트 0, 그 아래 비트 1 */
    fun clamp(k: ByteArray): ByteArray = k.copyOf().also { it[0] = (it[0].toInt() and 248).toByte(); it[31] = ((it[31].toInt() and 127) or 64).toByte() }

    fun scalarMult(k: ByteArray, u: ByteArray): ByteArray {
        require(k.size == 32 && u.size == 32)
        val kk = decodeLE(clamp(k)); val x1 = decodeLE(u.copyOf().also { it[31] = (it[31].toInt() and 127).toByte() }).mod(P)
        var x2 = BigInteger.ONE; var z2 = BigInteger.ZERO; var x3 = x1; var z3 = BigInteger.ONE; var swap = false
        for (t in 254 downTo 0) {
            val bit = kk.testBit(t)
            if (swap != bit) { var tmp = x2; x2 = x3; x3 = tmp; tmp = z2; z2 = z3; z3 = tmp }
            swap = bit
            val a = x2.add(z2).mod(P); val aa = a.multiply(a).mod(P); val b = x2.subtract(z2).mod(P); val bb = b.multiply(b).mod(P); val e = aa.subtract(bb).mod(P)
            val c = x3.add(z3).mod(P); val d = x3.subtract(z3).mod(P); val da = d.multiply(a).mod(P); val cb = c.multiply(b).mod(P)
            x3 = da.add(cb).mod(P).pow(2).mod(P); z3 = x1.multiply(da.subtract(cb).mod(P).pow(2)).mod(P)
            x2 = aa.multiply(bb).mod(P); z2 = e.multiply(aa.add(A24.multiply(e)).mod(P)).mod(P)
        }
        if (swap) { var tmp = x2; x2 = x3; x3 = tmp; tmp = z2; z2 = z3; z3 = tmp }
        return encodeLE(x2.multiply(z2.modPow(P.subtract(BigInteger.valueOf(2)), P)).mod(P))
    }

    fun publicKey(priv: ByteArray): ByteArray = scalarMult(priv, BASE)

    /** 새 키쌍: (정리된 개인키, 공개키) — WireGuard 의 wg genkey / wg pubkey 와 같은 결과 */
    fun generate(rnd: SecureRandom = SecureRandom()): Pair<ByteArray, ByteArray> { val k = clamp(ByteArray(32).also { rnd.nextBytes(it) }); return k to publicKey(k) }
}

object Ed25519 {
    private val P = BigInteger.ONE.shiftLeft(255).subtract(BigInteger.valueOf(19))
    private val D = BigInteger.valueOf(-121665).multiply(BigInteger.valueOf(121666).modInverse(P)).mod(P)
    private val SQRT_M1 = BigInteger.valueOf(2).modPow(P.subtract(BigInteger.ONE).shiftRight(2), P)
    private class Pt(val x: BigInteger, val y: BigInteger, val z: BigInteger, val t: BigInteger)

    private fun recoverX(y: BigInteger, sign: Int): BigInteger? {
        val x2 = y.multiply(y).subtract(BigInteger.ONE).multiply(D.multiply(y).multiply(y).add(BigInteger.ONE).modInverse(P)).mod(P)
        if (x2.signum() == 0) return if (sign == 0) BigInteger.ZERO else null
        var x = x2.modPow(P.add(BigInteger.valueOf(3)).shiftRight(3), P)
        if (x.multiply(x).subtract(x2).mod(P).signum() != 0) x = x.multiply(SQRT_M1).mod(P)
        if (x.multiply(x).subtract(x2).mod(P).signum() != 0) return null
        if (x.testBit(0) != (sign == 1)) x = P.subtract(x)
        return x
    }

    private val G: Pt by lazy {
        val gy = BigInteger.valueOf(4).multiply(BigInteger.valueOf(5).modInverse(P)).mod(P); val gx = recoverX(gy, 0)!!
        Pt(gx, gy, BigInteger.ONE, gx.multiply(gy).mod(P))
    }

    private fun add(p: Pt, q: Pt): Pt {
        val a = p.y.subtract(p.x).multiply(q.y.subtract(q.x)).mod(P); val b = p.y.add(p.x).multiply(q.y.add(q.x)).mod(P)
        val c = BigInteger.valueOf(2).multiply(p.t).multiply(q.t).multiply(D).mod(P); val d = BigInteger.valueOf(2).multiply(p.z).multiply(q.z).mod(P)
        val e = b.subtract(a); val f = d.subtract(c); val g = d.add(c); val h = b.add(a)
        return Pt(e.multiply(f).mod(P), g.multiply(h).mod(P), f.multiply(g).mod(P), e.multiply(h).mod(P))
    }

    private fun mul(s: BigInteger, p: Pt): Pt {
        var q = Pt(BigInteger.ZERO, BigInteger.ONE, BigInteger.ONE, BigInteger.ZERO); var pp = p
        for (i in 0 until s.bitLength()) { if (s.testBit(i)) q = add(q, pp); pp = add(pp, pp) }
        return q
    }

    private fun encode(p: Pt): ByteArray {
        val zi = p.z.modInverse(P); val x = p.x.multiply(zi).mod(P); val y = p.y.multiply(zi).mod(P)
        val v = y.or(if (x.testBit(0)) BigInteger.ONE.shiftLeft(255) else BigInteger.ZERO)
        val be = v.toByteArray(); val out = ByteArray(32); for (i in 0 until minOf(32, be.size)) out[i] = be[be.size - 1 - i]; return out
    }

    /** 32바이트 시드 → 공개키 32바이트 (RFC 8032 5.1.5) */
    fun publicKey(seed: ByteArray): ByteArray {
        require(seed.size == 32)
        val h = MessageDigest.getInstance("SHA-512").digest(seed)
        val a = h.copyOf(32); a[0] = (a[0].toInt() and 248).toByte(); a[31] = ((a[31].toInt() and 127) or 64).toByte()
        return encode(mul(BigInteger(1, a.reversedArray()), G))
    }
}

// ---------------------------------------------------------------------------------------------
// SSH 공개키 지문과 OpenSSH 키 파일 모양

object SshKey {
    class Info(val type: String, val bits: String, val sha256: String, val md5: String, val comment: String, val options: String)

    private class Reader(val b: ByteArray) {
        var p = 0
        fun u32(): Int { if (p + 4 > b.size) throw IllegalArgumentException("키가 중간에 끝났어요"); val v = ((b[p].toInt() and 0xff) shl 24) or ((b[p + 1].toInt() and 0xff) shl 16) or ((b[p + 2].toInt() and 0xff) shl 8) or (b[p + 3].toInt() and 0xff); p += 4; return v }
        fun str(): ByteArray { val n = u32(); if (n < 0 || p + n > b.size) throw IllegalArgumentException("키가 중간에 끝났어요"); val r = b.copyOfRange(p, p + n); p += n; return r }
    }

    private val TYPES = setOf("ssh-rsa", "ssh-dss", "ssh-ed25519", "ecdsa-sha2-nistp256", "ecdsa-sha2-nistp384", "ecdsa-sha2-nistp521", "sk-ssh-ed25519@openssh.com", "sk-ecdsa-sha2-nistp256@openssh.com", "ssh-ed448", "rsa-sha2-256", "rsa-sha2-512")

    /** "ssh-ed25519 AAAA… 주석" 한 줄 (앞에 옵션이 있어도 됨, known_hosts 의 호스트 이름 앞부분도 건너뜀) */
    fun parse(line: String): Info {
        val toks = line.trim().split(Regex("\\s+"))
        val ti = toks.indexOfFirst { it in TYPES }; if (ti < 0 || ti + 1 >= toks.size) throw IllegalArgumentException("ssh-ed25519·ssh-rsa·ecdsa-sha2-… 로 시작하는 공개키 한 줄을 붙여 넣으세요")
        val blob = try { Base64.getDecoder().decode(toks[ti + 1]) } catch (_: Exception) { throw IllegalArgumentException("Base64 부분을 읽지 못했어요") }
        val r = Reader(blob); val type = String(r.str())
        if (type != toks[ti]) throw IllegalArgumentException("앞의 종류(${toks[ti]})와 키 안의 종류($type)가 달라요")
        val bits = when {
            type == "ssh-rsa" -> { r.str(); "RSA ${BigInteger(1, r.str()).bitLength()}비트" }
            type == "ssh-dss" -> "DSA ${BigInteger(1, run { r.str(); r.str() }).bitLength()}비트 (낡은 방식)"
            type.contains("ed25519") -> { if (r.str().size != 32) throw IllegalArgumentException("Ed25519 공개키는 32바이트여야 해요"); "Ed25519 (256비트)" }
            type.startsWith("ecdsa") || type.startsWith("sk-ecdsa") -> { r.str(); if (r.str().isEmpty()) throw IllegalArgumentException("타원곡선 점이 비어 있어요"); when { "nistp256" in type -> "ECDSA P-256"; "nistp384" in type -> "ECDSA P-384"; else -> "ECDSA P-521" } }
            else -> type
        }
        val sha = Base64.getEncoder().withoutPadding().encodeToString(MessageDigest.getInstance("SHA-256").digest(blob))
        val md5 = MessageDigest.getInstance("MD5").digest(blob).joinToString(":") { "%02x".format(it.toInt() and 0xff) }
        return Info(type, bits, "SHA256:$sha", "MD5:$md5", toks.drop(ti + 2).joinToString(" "), toks.take(ti).joinToString(" "))
    }

    private fun ByteArrayBuilder.str(b: ByteArray) { u32(b.size); write(b) }
    private class ByteArrayBuilder { val o = java.io.ByteArrayOutputStream(); fun write(b: ByteArray) = o.write(b); fun u32(v: Int) { o.write(byteArrayOf((v ushr 24).toByte(), (v ushr 16).toByte(), (v ushr 8).toByte(), v.toByte())) }; fun bytes() = o.toByteArray() }

    fun ed25519PublicBlob(pub: ByteArray): ByteArray = ByteArrayBuilder().also { it.str("ssh-ed25519".toByteArray()); it.str(pub) }.bytes()

    fun ed25519PublicLine(pub: ByteArray, comment: String): String = "ssh-ed25519 " + Base64.getEncoder().encodeToString(ed25519PublicBlob(pub)) + (if (comment.isNotEmpty()) " $comment" else "")

    /** 암호를 걸지 않은 OpenSSH 개인키 파일(-----BEGIN OPENSSH PRIVATE KEY-----) */
    fun ed25519PrivatePem(seed: ByteArray, pub: ByteArray, comment: String, rnd: SecureRandom = SecureRandom()): String {
        val check = rnd.nextInt()
        val priv = ByteArrayBuilder().also { b ->
            b.u32(check); b.u32(check); b.str("ssh-ed25519".toByteArray()); b.str(pub); b.str(seed + pub); b.str(comment.toByteArray())
            var pad = 1; while (b.o.size() % 8 != 0) b.o.write(pad++)
        }.bytes()
        val out = ByteArrayBuilder().also { b ->
            b.write("openssh-key-v1\u0000".toByteArray()); b.str("none".toByteArray()); b.str("none".toByteArray()); b.str(ByteArray(0)); b.u32(1); b.str(ed25519PublicBlob(pub)); b.str(priv)
        }.bytes()
        return "-----BEGIN OPENSSH PRIVATE KEY-----\n" + Base64.getEncoder().encodeToString(out).chunked(70).joinToString("\n") + "\n-----END OPENSSH PRIVATE KEY-----\n"
    }
}

// ---------------------------------------------------------------------------------------------
// CVSS 3.0 / 3.1 기본 점수

object Cvss {
    class Result(val version: String, val score: Double, val severity: String, val impact: Double, val exploitability: Double, val scopeChanged: Boolean, val parts: List<Pair<String, String>>)

    private val AV = mapOf("N" to (0.85 to "네트워크"), "A" to (0.62 to "인접 네트워크"), "L" to (0.55 to "로컬"), "P" to (0.20 to "물리적"))
    private val AC = mapOf("L" to (0.77 to "낮음"), "H" to (0.44 to "높음"))
    private val UI = mapOf("N" to (0.85 to "필요 없음"), "R" to (0.62 to "사용자 동작 필요"))
    private val CIA = mapOf("H" to (0.56 to "높음"), "L" to (0.22 to "낮음"), "N" to (0.0 to "없음"))
    private val PR_U = mapOf("N" to 0.85, "L" to 0.62, "H" to 0.27)
    private val PR_C = mapOf("N" to 0.85, "L" to 0.68, "H" to 0.50)
    private val PR_NAME = mapOf("N" to "필요 없음", "L" to "낮은 권한", "H" to "높은 권한")

    /** CVSS 3.1 의 올림: 부동소수점 오차를 피하려고 정수로 계산 */
    fun roundUp31(x: Double): Double { val i = (x * 100000).roundToLong(); return if (i % 10000 == 0L) i / 100000.0 else (floor(i / 10000.0) + 1) / 10.0 }
    private fun roundUp30(x: Double): Double = ceil(x * 10) / 10

    fun severity(score: Double) = when { score == 0.0 -> "없음"; score < 4.0 -> "낮음"; score < 7.0 -> "보통"; score < 9.0 -> "높음"; else -> "치명적" }

    fun parse(vector: String): Result {
        val v = vector.trim(); val head = Regex("^CVSS:(3\\.[01])/").find(v)?.groupValues?.get(1) ?: throw IllegalArgumentException("CVSS:3.1/AV:N/AC:L/… 처럼 CVSS:3.0 또는 3.1 로 시작하는 벡터여야 해요")
        val m = v.removePrefix("CVSS:$head/").split('/').associate { it.substringBefore(':') to it.substringAfter(':', "") }
        for (k in listOf("AV", "AC", "PR", "UI", "S", "C", "I", "A")) if (k !in m) throw IllegalArgumentException("$k 항목이 없어요")
        val av = AV[m["AV"]] ?: throw IllegalArgumentException("AV 값은 N·A·L·P 중 하나예요"); val ac = AC[m["AC"]] ?: throw IllegalArgumentException("AC 값은 L·H 예요")
        val ui = UI[m["UI"]] ?: throw IllegalArgumentException("UI 값은 N·R 이에요"); val scope = m["S"]; if (scope != "U" && scope != "C") throw IllegalArgumentException("S 값은 U·C 예요")
        val changed = scope == "C"
        val pr = (if (changed) PR_C else PR_U)[m["PR"]] ?: throw IllegalArgumentException("PR 값은 N·L·H 예요")
        val c = CIA[m["C"]] ?: throw IllegalArgumentException("C 값은 H·L·N 이에요"); val i = CIA[m["I"]] ?: throw IllegalArgumentException("I 값은 H·L·N 이에요"); val a = CIA[m["A"]] ?: throw IllegalArgumentException("A 값은 H·L·N 이에요")
        val iss = 1 - (1 - c.first) * (1 - i.first) * (1 - a.first)
        val impact = if (changed) 7.52 * (iss - 0.029) - 3.25 * (iss - 0.02).pow(15) else 6.42 * iss
        val expl = 8.22 * av.first * ac.first * pr * ui.first
        val round = if (head == "3.1") ::roundUp31 else ::roundUp30
        val base = if (impact <= 0) 0.0 else if (changed) round(minOf(1.08 * (impact + expl), 10.0)) else round(minOf(impact + expl, 10.0))
        val parts = listOf("공격 경로(AV)" to av.second, "공격 복잡도(AC)" to ac.second, "필요한 권한(PR)" to PR_NAME.getValue(m["PR"]!!), "사용자 동작(UI)" to ui.second, "영향 범위(S)" to (if (changed) "바뀜(다른 구성요소까지 영향)" else "그대로"),
            "기밀성(C)" to c.second, "무결성(I)" to i.second, "가용성(A)" to a.second)
        return Result(head, base, severity(base), impact, expl, changed, parts)
    }
}

// ---------------------------------------------------------------------------------------------
// Content-Security-Policy 점검

object CspCheck {
    class Finding(val level: Int, val text: String)

    private val KNOWN = setOf("default-src", "script-src", "script-src-elem", "script-src-attr", "style-src", "style-src-elem", "style-src-attr", "img-src", "font-src", "connect-src", "media-src", "object-src", "frame-src", "child-src", "worker-src", "manifest-src", "prefetch-src",
        "base-uri", "form-action", "frame-ancestors", "sandbox", "report-uri", "report-to", "upgrade-insecure-requests", "block-all-mixed-content", "require-trusted-types-for", "trusted-types", "navigate-to", "plugin-types", "referrer", "require-sri-for")

    fun parse(policy: String): LinkedHashMap<String, List<String>> {
        val m = LinkedHashMap<String, List<String>>()
        for (d in policy.trim().removePrefix("Content-Security-Policy:").removePrefix("Content-Security-Policy-Report-Only:").split(';')) {
            val t = d.trim().split(Regex("\\s+")).filter { it.isNotEmpty() }; if (t.isEmpty()) continue
            m.putIfAbsent(t[0].lowercase(), t.drop(1))       // 같은 지시어가 또 나오면 첫 번째만 쓰임 (CSP 규격)
        }
        return m
    }

    fun analyze(policy: String): List<Finding> {
        val p = parse(policy); val out = ArrayList<Finding>()
        if (p.isEmpty()) return listOf(Finding(2, "읽을 수 있는 지시어가 없어요"))
        fun eff(name: String): List<String>? = p[name] ?: p["default-src"]
        for (k in p.keys) if (k !in KNOWN) out += Finding(1, "알 수 없는 지시어 \"$k\" — 오타일 수 있어요 (브라우저는 무시해요)")
        for (k in listOf("plugin-types", "referrer", "require-sri-for", "block-all-mixed-content")) if (k in p) out += Finding(0, "\"$k\" 는 더는 쓰지 않는 지시어예요")
        val script = eff("script-src")
        if (script == null) out += Finding(2, "script-src 도 default-src 도 없어요: 어떤 스크립트든 실행돼서 XSS 를 막지 못해요")
        else {
            val lower = script.map { it.lowercase() }
            val strict = lower.any { it == "'strict-dynamic'" }; val hasNonce = lower.any { it.startsWith("'nonce-") || it.startsWith("'sha256-") || it.startsWith("'sha384-") || it.startsWith("'sha512-") }
            if ("'unsafe-inline'" in lower && !hasNonce && !strict) out += Finding(2, "스크립트에 'unsafe-inline' 이 허용돼 있어요: 주입된 <script> 가 그대로 실행돼서 CSP 의 효과가 거의 없어요. nonce 나 해시를 쓰세요")
            else if ("'unsafe-inline'" in lower) out += Finding(0, "'unsafe-inline' 이 있지만 nonce·해시가 함께 있어서 최신 브라우저는 무시해요 (구형 브라우저용)")
            if ("'unsafe-eval'" in lower) out += Finding(1, "'unsafe-eval' 이 허용돼 있어요: eval() 로 문자열을 코드로 실행할 수 있어요")
            if (lower.any { it == "*" }) out += Finding(2, "스크립트 출처에 * 가 있어요: 어느 사이트의 스크립트든 불러올 수 있어요")
            if (!strict && lower.any { it == "https:" || it == "http:" || it == "data:" }) out += Finding(2, "스크립트 출처에 https:/http:/data: 처럼 넓은 범위가 있어요: 아무 https 사이트나 data: 주소의 스크립트를 불러올 수 있어요")
            if (lower.any { it.startsWith("http://") }) out += Finding(1, "스크립트 출처에 http:// 주소가 있어요: 중간에서 바꿔치기될 수 있어요")
            if (lower.any { it.startsWith("*.") || it.contains("://*.") }) out += Finding(1, "와일드카드 서브도메인(*.)이 있어요: 그 아래 어느 서브도메인이든 탈취되거나 사용자 콘텐츠를 올릴 수 있으면 우회돼요")
        }
        val obj = eff("object-src"); if (obj == null || obj.none { it == "'none'" }) out += Finding(1, "object-src 가 'none' 이 아니에요: 플러그인(<object>·<embed>)으로 우회할 수 있어요. object-src 'none' 을 추가하세요")
        if ("base-uri" !in p) out += Finding(1, "base-uri 가 없어요: 주입된 <base> 태그로 상대 주소 스크립트를 공격자 서버로 돌릴 수 있어요. base-uri 'self' 또는 'none' 을 추가하세요")
        if ("frame-ancestors" !in p) out += Finding(1, "frame-ancestors 가 없어요: 다른 사이트가 이 페이지를 iframe 에 넣어 클릭재킹을 할 수 있어요 (X-Frame-Options 를 따로 쓰고 있다면 괜찮아요)")
        if ("form-action" !in p) out += Finding(0, "form-action 이 없어요: 주입된 폼이 데이터를 아무 서버로나 보낼 수 있어요")
        val dflt = p["default-src"]
        if (dflt != null && dflt.any { it == "*" }) out += Finding(1, "default-src 에 * 가 있어요: 지시어를 따로 안 적은 모든 자원이 어디서든 올 수 있어요")
        val allSrc = p.filterKeys { it != "report-uri" && it != "form-action" && it != "base-uri" && it != "frame-ancestors" }.values.flatten()
        if (allSrc.any { it.startsWith("http://") && !it.startsWith("http://localhost") }) out += Finding(1, "http:// 출처가 있어요: https 페이지에서는 혼합 콘텐츠가 되고 중간에서 바꿔치기될 수 있어요")
        if ("upgrade-insecure-requests" !in p && "block-all-mixed-content" !in p) out += Finding(0, "upgrade-insecure-requests 가 없어요: http 자원을 https 로 자동 승격하지 않아요")
        if ("report-uri" !in p && "report-to" !in p) out += Finding(0, "report-uri/report-to 가 없어요: 위반이 일어나도 알림을 받지 못해요 (처음에는 Content-Security-Policy-Report-Only 로 시험하세요)")
        if (out.none { it.level >= 1 }) out += Finding(-1, "눈에 띄는 약점이 없어요")
        return out
    }
}

// ---------------------------------------------------------------------------------------------
// URL 안전 점검 (피싱·사칭 주소의 흔한 수법)

object UrlInspect {
    class Part(val scheme: String, val userinfo: String?, val host: String, val port: Int?, val path: String, val query: String?, val fragment: String?)
    class Finding(val level: Int, val text: String)

    fun parse(raw: String): Part? {
        var u = raw.trim(); if (u.isEmpty()) return null
        if (!Regex("^[a-zA-Z][a-zA-Z0-9+.-]*:").containsMatchIn(u) || u.startsWith("//")) u = (if (u.startsWith("//")) "https:" else "https://") + u
        val m = Regex("^([a-zA-Z][a-zA-Z0-9+.-]*):(?://([^/?#]*))?([^?#]*)(?:\\?([^#]*))?(?:#(.*))?$").matchEntire(u) ?: return null
        val scheme = m.groupValues[1].lowercase(); val auth = m.groupValues[2]
        val userinfo = if ('@' in auth) auth.substringBeforeLast('@') else null; var hp = auth.substringAfterLast('@')
        var port: Int? = null
        if (hp.startsWith("[")) { port = hp.substringAfter("]:", "").toIntOrNull(); hp = hp.substringBefore(']').removePrefix("[") }
        else if (hp.count { it == ':' } == 1) { port = hp.substringAfter(':').toIntOrNull(); hp = hp.substringBefore(':') }
        return Part(scheme, userinfo, hp.lowercase().trimEnd('.'), port, m.groupValues[3], m.groups[4]?.value, m.groups[5]?.value)
    }

    /** inet_aton 방식으로 읽히는 IPv4 (정수 3232235777, 16진수 0xC0A80001, 8진수 0300.0250.0.1 등) → 점으로 나눈 모양 */
    fun legacyIpv4(host: String): String? {
        val parts = host.split('.'); if (parts.size !in 1..4 || parts.any { it.isEmpty() }) return null
        val nums = parts.map { p -> try { when { p.startsWith("0x", true) -> p.substring(2).toLong(16); p.length > 1 && p.startsWith("0") -> p.toLong(8); else -> p.toLong() } } catch (_: NumberFormatException) { return null } }
        if (nums.any { it < 0 }) return null
        var v = 0L; for ((i, n) in nums.withIndex()) { val last = i == nums.size - 1; val maxv = if (last) (1L shl (8 * (5 - nums.size))) - 1 else 255L; if (n > maxv) return null; v = if (last) v or n else v or (n shl (8 * (3 - i))) }
        return "${(v shr 24) and 255}.${(v shr 16) and 255}.${(v shr 8) and 255}.${v and 255}"
    }

    private val SHORTENERS = setOf("bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd", "buff.ly", "rebrand.ly", "cutt.ly", "me2.do", "vo.la", "url.kr", "han.gl", "naver.me", "kko.to", "t.ly", "shorturl.at", "s.id", "lnkd.in", "bitly.com", "tiny.cc", "rb.gy")
    private val BAD_TLDS = setOf("zip", "mov", "top", "xyz", "tk", "gq", "cf", "ml", "ga", "click", "country", "kim", "loan", "work", "men", "date", "download", "racing", "review", "stream", "science", "party", "icu", "cyou", "buzz", "monster", "rest")
    private val BRANDS = listOf("google", "gmail", "youtube", "apple", "icloud", "microsoft", "outlook", "office365", "paypal", "amazon", "facebook", "instagram", "whatsapp", "netflix", "naver", "kakao", "daum", "coupang", "toss", "shinhan", "kbstar", "wooribank", "hanabank", "nonghyup", "kakaobank", "samsung", "binance", "coinbase", "upbit", "bithumb", "telegram", "github", "dropbox", "linkedin", "twitter", "steam", "discord", "yahoo")
    private val BAIT = Regex("(login|signin|sign-in|verify|verification|secure|security|account|update|confirm|password|wallet|bank|billing|support|helpdesk|recover|unlock|suspend)", RegexOption.IGNORE_CASE)
    /** 라틴 글자와 똑같이 보이는 키릴·그리스 글자 → 그 라틴 글자 */
    private val CONFUSABLE = mapOf('а' to 'a', 'е' to 'e', 'о' to 'o', 'р' to 'p', 'с' to 'c', 'х' to 'x', 'у' to 'y', 'і' to 'i', 'ј' to 'j', 'ѕ' to 's', 'ԁ' to 'd', 'ԛ' to 'q', 'ԝ' to 'w', 'ɡ' to 'g',
        'Α' to 'a', 'Β' to 'b', 'Ε' to 'e', 'Ζ' to 'z', 'Η' to 'h', 'Ι' to 'i', 'Κ' to 'k', 'Μ' to 'm', 'Ν' to 'n', 'Ο' to 'o', 'Ρ' to 'p', 'Τ' to 't', 'Χ' to 'x', 'Υ' to 'y', 'α' to 'a', 'ο' to 'o', 'ι' to 'i', 'ν' to 'v', 'ρ' to 'p', 'τ' to 't', 'υ' to 'u')
    private val CYR_LOOK = CONFUSABLE.keys.joinToString("")

    private fun lev(a: String, b: String): Int { val d = IntArray(b.length + 1) { it }; for (i in 1..a.length) { var prev = d[0]; d[0] = i; for (j in 1..b.length) { val t = d[j]; d[j] = minOf(d[j] + 1, d[j - 1] + 1, prev + if (a[i - 1] == b[j - 1]) 0 else 1); prev = t } }; return d[b.length] }

    fun analyze(raw: String): Pair<Part?, List<Finding>> {
        val p = parse(raw) ?: return null to listOf(Finding(2, "주소를 읽지 못했어요"))
        val f = ArrayList<Finding>()
        if (p.scheme !in listOf("http", "https")) return p to listOf(Finding(2, "\"${p.scheme}:\" 는 웹 주소가 아니에요. javascript:·data: 주소는 링크로 열면 코드가 실행될 수 있어서 위험해요"))
        if (p.scheme == "http") f += Finding(if (BAIT.containsMatchIn(p.path + (p.query ?: "")) || p.userinfo != null) 2 else 1, "https 가 아닌 http 라서 입력한 내용이 암호화되지 않아요${if (BAIT.containsMatchIn(p.path)) " — 로그인·결제 페이지로 보이는데 http 예요" else ""}")
        if (p.userinfo != null) f += Finding(2, "주소 앞에 \"${p.userinfo}@\" 가 붙어 있어요: @ 앞은 아이디일 뿐이고 실제로 가는 곳은 \"${p.host}\" 예요. 앞부분을 그럴듯한 사이트 이름으로 꾸미는 수법이에요")
        val legacy = legacyIpv4(p.host)
        if (legacy != null) { val plain = Regex("^\\d{1,3}(\\.\\d{1,3}){3}$").matches(p.host); f += Finding(if (plain) 1 else 2, if (plain) "도메인 이름이 아니라 IP 주소(${p.host})예요: 정상 서비스는 보통 도메인을 써요" else "IP 주소를 숫자·16진수·8진수로 숨겨 썼어요 (${p.host} = $legacy): 눈속임 수법이에요") }
        else if (':' in p.host) f += Finding(1, "도메인 이름이 아니라 IPv6 주소예요")
        else {
            val hostA = try { IDN.toASCII(p.host, IDN.ALLOW_UNASSIGNED) } catch (_: Exception) { p.host }        // 유니코드로 적었어도 실제 접속 이름(punycode)으로 맞춰 봄
            val labels = hostA.split('.'); val tld = labels.last()
            val uni = try { IDN.toUnicode(hostA, IDN.ALLOW_UNASSIGNED) } catch (_: Exception) { hostA }
            if (labels.any { it.startsWith("xn--") }) {
                val scripts = uni.split('.').map { l -> l.filter { it.isLetter() }.map { Character.UnicodeScript.of(it.code) }.toSet() }
                val mixed = scripts.any { it.size > 1 }; val confus = uni.any { it in CYR_LOOK }
                if (mixed || confus) f += Finding(2, "국제화 도메인(\"$uni\")인데 라틴 글자와 똑같이 생긴 다른 문자(키릴·그리스 등)가 ${if (mixed) "섞여" else "들어"} 있어요: 눈으로는 같아 보이지만 다른 사이트예요 (실제 주소: $hostA)")
                else f += Finding(0, "국제화(한글 등) 도메인이에요: 화면에는 \"$uni\", 실제로는 $hostA 로 접속해요")
                val skelLabel = EmailHeader.baseDomain(uni.map { CONFUSABLE[it] ?: it }.joinToString("")).substringBefore('.')
                BRANDS.firstOrNull { it == skelLabel }?.let { f += Finding(2, "\"$uni\" 은 \"$it\" 의 글자를 비슷하게 생긴 다른 문자로 바꿔친 주소예요") }
            }
            if (tld in BAD_TLDS) f += Finding(1, "도메인 끝(.$tld)이 스팸·피싱에 많이 쓰이는 값싼 도메인이에요")
            if (labels.size >= 5) f += Finding(1, "서브도메인이 ${labels.size - 2}단계로 길어요: 진짜 도메인은 맨 뒤 두 칸(${EmailHeader.baseDomain(hostA)})이에요")
            if (hostA.length > 45) f += Finding(1, "도메인이 ${hostA.length}글자로 아주 길어요")
            if (hostA.count { it == '-' } >= 3) f += Finding(1, "도메인에 하이픈(-)이 많아요: 브랜드 이름을 억지로 끼워 넣은 주소에서 흔해요")
            val base = EmailHeader.baseDomain(hostA); val baseLabel = base.substringBefore('.'); val subs = hostA.removeSuffix(base).trimEnd('.')
            for (b in BRANDS) {
                val inSub = subs.isNotEmpty() && subs.contains(b); val inBase = baseLabel.contains(b)
                if (inSub && baseLabel != b) f += Finding(2, "\"$b\" 이름이 앞쪽 칸에 있지만 진짜 도메인은 \"$base\" 예요: ${b} 와 무관한 사이트일 가능성이 커요")
                else if (inBase && baseLabel != b) f += Finding(if (BAIT.containsMatchIn(baseLabel)) 2 else 1, "도메인 \"$base\" 에 \"$b\" 가 들어 있지만 정식 도메인이 아니에요${if (BAIT.containsMatchIn(baseLabel)) " (login·secure·verify 같은 낚시 단어까지 붙었어요)" else ""}")
                else if (!inBase && baseLabel.length >= 5 && b.length >= 5 && lev(baseLabel, b) == 1) f += Finding(2, "\"$baseLabel\" 은 \"$b\" 와 한 글자 차이예요: 철자를 살짝 바꾼 사칭 도메인일 수 있어요")
                else if (!inBase && baseLabel.length >= 5 && baseLabel.replace('0', 'o').replace('1', 'l').replace('3', 'e').replace('4', 'a').replace('5', 's').replace("rn", "m").replace("vv", "w") == b) f += Finding(2, "\"$baseLabel\" 은 숫자·글자를 바꿔서 \"$b\" 처럼 보이게 한 주소예요")
            }
            if (hostA in SHORTENERS || base in SHORTENERS) f += Finding(1, "단축 주소예요: 실제 목적지를 알 수 없어요. '리다이렉트 추적' 도구로 도착지를 먼저 확인하세요")
        }
        val q = p.query ?: ""
        if (Regex("(?i)(url|redirect|next|goto|return|continue|dest|target|link)=https?(%3a|:)").containsMatchIn(q)) f += Finding(1, "주소 안에 또 다른 주소가 들어 있어요(redirect 값): 정상 사이트를 거쳐 엉뚱한 곳으로 보내는 수법에 쓰여요")
        if (p.path.contains("//") && p.path.indexOf("//") > 0 && Regex("https?:/").containsMatchIn(p.path)) f += Finding(1, "경로 안에 http:// 가 또 들어 있어요")
        if (Regex("%[0-9a-fA-F]{2}").findAll(p.host + p.path).count() >= 6) f += Finding(1, "%로 가린 글자가 많아요: 내용을 숨기려는 주소일 수 있어요")
        if (p.port != null && p.port !in listOf(80, 443)) f += Finding(1, "기본이 아닌 포트(${p.port})를 써요")
        if (f.none { it.level >= 1 }) f += Finding(-1, "흔한 속임수 징후는 보이지 않아요 (그렇다고 안전하다는 뜻은 아니에요)")
        return p to f.sortedByDescending { it.level }
    }
}

// ---------------------------------------------------------------------------------------------
// 글 속에 섞인 비밀(키·토큰·비밀번호) 찾기

object SecretScan {
    class Hit(val line: Int, val kind: String, val level: Int, val preview: String, val advice: String)

    private class Rule(val kind: String, val level: Int, val re: Regex, val advice: String, val group: Int = 0)

    private val RULES = listOf(
        Rule("개인키(PEM·OpenSSH)", 2, Regex("-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP |ENCRYPTED )?PRIVATE KEY(?: BLOCK)?-----"), "개인키는 절대 공유하면 안 돼요. 노출됐다면 키를 폐기하고 새로 만드세요"),
        Rule("AWS 액세스 키 ID", 2, Regex("\\b(?:AKIA|ASIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA)[A-Z0-9]{16}\\b"), "AWS 콘솔에서 해당 키를 비활성화·삭제하고 사용 기록을 확인하세요"),
        Rule("AWS 비밀 키", 2, Regex("(?i)aws.{0,20}?(?:secret|private).{0,20}?[=:]\\s*[\"']?([A-Za-z0-9/+=]{40})\\b", RegexOption.IGNORE_CASE), "AWS 키는 쌍으로 폐기하세요", 1),
        Rule("GitHub 토큰", 2, Regex("\\b(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{36,}\\b|\\bgithub_pat_[A-Za-z0-9_]{50,}\\b"), "GitHub 설정에서 토큰을 취소하고 새로 만드세요"),
        Rule("Slack 토큰", 2, Regex("\\bxox[baprs]-[A-Za-z0-9-]{10,}\\b"), "Slack 앱 설정에서 토큰을 재발급하세요"),
        Rule("Slack 웹훅 주소", 2, Regex("https://hooks\\.slack\\.com/services/T[A-Za-z0-9]+/B[A-Za-z0-9]+/[A-Za-z0-9]+"), "웹훅 주소를 아는 사람은 누구나 메시지를 보낼 수 있어요. 재발급하세요"),
        Rule("Discord 웹훅 주소", 2, Regex("https://(?:ptb\\.|canary\\.)?discord(?:app)?\\.com/api/webhooks/\\d+/[A-Za-z0-9_-]+"), "웹훅을 삭제하고 새로 만드세요"),
        Rule("Google API 키", 1, Regex("\\bAIza[0-9A-Za-z_-]{35}\\b"), "Google Cloud 콘솔에서 키를 제한(앱·IP)하거나 재발급하세요"),
        Rule("Stripe 비밀 키", 2, Regex("\\b[sr]k_live_[0-9a-zA-Z]{20,}\\b"), "Stripe 대시보드에서 키를 롤(roll)하세요"),
        Rule("SendGrid 키", 2, Regex("\\bSG\\.[A-Za-z0-9_-]{20,}\\.[A-Za-z0-9_-]{30,}\\b"), "SendGrid 에서 키를 삭제하세요"),
        Rule("npm 토큰", 2, Regex("\\bnpm_[A-Za-z0-9]{36}\\b"), "npm 에서 토큰을 취소하세요"),
        Rule("텔레그램 봇 토큰", 2, Regex("\\b\\d{8,10}:[A-Za-z0-9_-]{35}\\b"), "BotFather 에서 /revoke 로 토큰을 새로 받으세요"),
        Rule("JWT", 1, Regex("\\beyJ[A-Za-z0-9_-]{10,}\\.eyJ[A-Za-z0-9_-]{10,}\\.[A-Za-z0-9_-]{10,}\\b"), "로그인 토큰이 노출됐어요. 만료되기 전에 서버에서 폐기(로그아웃·키 교체)하세요"),
        Rule("주소에 들어 있는 아이디:비밀번호", 2, Regex("\\b[a-zA-Z][a-zA-Z0-9+.-]*://[^\\s/:@]+:([^\\s/@]{3,})@[^\\s/]+"), "주소에 비밀번호를 적으면 로그·기록에 그대로 남아요. 비밀번호를 바꾸고 별도 설정으로 옮기세요", 1),
        Rule("비밀번호·토큰 설정값", 1, Regex("(?i)\\b[A-Za-z0-9_.-]*(?:password|passwd|passphrase|pwd|secret|token|api[_-]?key|access[_-]?key|private[_-]?key|auth[_-]?key)[A-Za-z0-9_.-]*[\"']?\\s*[:=]\\s*[\"']?([^\\s\"',;]{6,})"), "코드·설정 파일에 직접 적지 말고 환경 변수나 비밀 저장소를 쓰세요", 1),
    )

    private val PLACEHOLDER = Regex("(?i)^(?:x{4,}|\\*{3,}|<.*>|\\$\\{.*\\}|\\{\\{.*\\}\\}|your[_-].*|example.*|changeme|change[_-]me|password|secret|token|null|none|true|false|string|todo|redacted|dummy|test)$")

    fun entropy(s: String): Double { if (s.isEmpty()) return 0.0; return s.groupingBy { it }.eachCount().values.sumOf { c -> val p = c.toDouble() / s.length; p * (ln(1.0 / p) / ln(2.0)) } }

    fun mask(s: String): String = if (s.length <= 8) "*".repeat(s.length) else s.take(4) + "…" + "*".repeat(minOf(6, s.length - 6)) + s.takeLast(2)

    fun scan(text: String): List<Hit> {
        val out = ArrayList<Hit>()
        text.lines().forEachIndexed { idx, line ->
            val covered = ArrayList<IntRange>()
            for (r in RULES) for (m in r.re.findAll(line)) {
                val g = if (r.group > 0) m.groups[r.group] ?: continue else m.groups[0]!!
                val v = g.value
                if (r.kind == "비밀번호·토큰 설정값" && (PLACEHOLDER.matches(v) || (entropy(v) < 2.5 && v.length < 12))) continue
                if (covered.any { it.first <= g.range.first && g.range.last <= it.last }) continue       // 더 구체적인 규칙이 이미 잡은 자리
                covered += g.range
                out += Hit(idx + 1, r.kind, r.level, if (r.kind.startsWith("개인키")) "-----BEGIN … PRIVATE KEY-----" else mask(v), r.advice)
            }
        }
        return out
    }
}

// ---------------------------------------------------------------------------------------------
// 비밀번호로 글 암호화 (AES-256-GCM 은 이 앱 형식, CBC 는 openssl enc 와 호환)

object AesBox {
    private val rnd = SecureRandom()
    private fun b64u(b: ByteArray) = Base64.getUrlEncoder().withoutPadding().encodeToString(b)
    private fun unb64u(s: String) = Base64.getUrlDecoder().decode(s)
    private fun random(n: Int) = ByteArray(n).also { rnd.nextBytes(it) }

    /** scbox1.반복횟수.솔트.논스.암호문(+태그) — 키는 PBKDF2-HMAC-SHA256 으로 비밀번호에서 만듦 */
    fun encryptGcm(password: String, plain: ByteArray, iterations: Int = 200_000, salt: ByteArray = random(16), nonce: ByteArray = random(12)): String {
        val key = Pbkdf2.derive("HmacSHA256", password.toByteArray(Charsets.UTF_8), salt, iterations, 32)
        val c = Cipher.getInstance("AES/GCM/NoPadding"); c.init(Cipher.ENCRYPT_MODE, SecretKeySpec(key, "AES"), GCMParameterSpec(128, nonce))
        return "scbox1.$iterations.${b64u(salt)}.${b64u(nonce)}.${b64u(c.doFinal(plain))}"
    }

    fun decryptGcm(password: String, token: String): ByteArray {
        val p = token.trim().split('.'); if (p.size != 5 || p[0] != "scbox1") throw IllegalArgumentException("scbox1 로 시작하는 암호문이 아니에요")
        val it = p[1].toIntOrNull()?.takeIf { it in 1000..10_000_000 } ?: throw IllegalArgumentException("반복 횟수를 읽지 못했어요")
        val key = Pbkdf2.derive("HmacSHA256", password.toByteArray(Charsets.UTF_8), unb64u(p[2]), it, 32)
        val c = Cipher.getInstance("AES/GCM/NoPadding"); c.init(Cipher.DECRYPT_MODE, SecretKeySpec(key, "AES"), GCMParameterSpec(128, unb64u(p[3])))
        return c.doFinal(unb64u(p[4]))
    }

    private fun opensslKeyIv(password: String, salt: ByteArray, iterations: Int): Pair<SecretKeySpec, IvParameterSpec> {
        val d = Pbkdf2.derive("HmacSHA256", password.toByteArray(Charsets.UTF_8), salt, iterations, 48)
        return SecretKeySpec(d.copyOf(32), "AES") to IvParameterSpec(d.copyOfRange(32, 48))
    }

    /** openssl enc -aes-256-cbc -pbkdf2 -iter N -a 와 같은 모양 ("Salted__" + 솔트 8바이트 + 암호문, Base64) */
    fun encryptOpenssl(password: String, plain: ByteArray, iterations: Int = 10_000, salt: ByteArray = random(8)): String {
        val (k, iv) = opensslKeyIv(password, salt, iterations)
        val c = Cipher.getInstance("AES/CBC/PKCS5Padding"); c.init(Cipher.ENCRYPT_MODE, k, iv)
        return Base64.getEncoder().encodeToString("Salted__".toByteArray() + salt + c.doFinal(plain))
    }

    fun decryptOpenssl(password: String, b64: String, iterations: Int = 10_000): ByteArray {
        val raw = Base64.getMimeDecoder().decode(b64.trim()); if (raw.size < 32 || String(raw, 0, 8) != "Salted__") throw IllegalArgumentException("\"Salted__\" 로 시작하는 openssl 암호문이 아니에요")
        val (k, iv) = opensslKeyIv(password, raw.copyOfRange(8, 16), iterations)
        val c = Cipher.getInstance("AES/CBC/PKCS5Padding"); c.init(Cipher.DECRYPT_MODE, k, iv)
        return c.doFinal(raw, 16, raw.size - 16)
    }
}

// ---------------------------------------------------------------------------------------------
// JWT 서명 확인 (HS256/384/512 · RS256/384/512 · ES256/384/512)

object JwtVerify {
    class Result(val ok: Boolean, val detail: String)

    private fun unb64u(s: String): ByteArray = Base64.getUrlDecoder().decode(s.trim().trimEnd('='))

    /** JOSE 의 ECDSA 서명(R||S)을 자바가 읽는 DER 모양으로 */
    fun joseToDer(raw: ByteArray): ByteArray {
        fun int(b: ByteArray): ByteArray { var x = b.dropWhile { it == 0.toByte() }.toByteArray(); if (x.isEmpty()) x = byteArrayOf(0); if (x[0] < 0) x = byteArrayOf(0) + x; return byteArrayOf(0x02, x.size.toByte()) + x }
        val h = raw.size / 2; val body = int(raw.copyOf(h)) + int(raw.copyOfRange(h, raw.size))
        return byteArrayOf(0x30) + (if (body.size < 128) byteArrayOf(body.size.toByte()) else byteArrayOf(0x81.toByte(), body.size.toByte())) + body
    }

    /** 공개키 글 → 키: PEM(PUBLIC KEY·CERTIFICATE) 또는 JWK(JSON) */
    fun publicKey(text: String, alg: String): java.security.PublicKey {
        val t = text.trim()
        if (t.startsWith("{")) {
            val j = JSONObject(t)
            return when (j.optString("kty")) {
                "RSA" -> java.security.KeyFactory.getInstance("RSA").generatePublic(java.security.spec.RSAPublicKeySpec(BigInteger(1, unb64u(j.getString("n"))), BigInteger(1, unb64u(j.getString("e")))))
                "EC" -> {
                    val name = when (j.optString("crv")) { "P-256" -> "secp256r1"; "P-384" -> "secp384r1"; "P-521" -> "secp521r1"; else -> throw IllegalArgumentException("지원하지 않는 곡선: ${j.optString("crv")}") }
                    val ap = java.security.AlgorithmParameters.getInstance("EC").apply { init(java.security.spec.ECGenParameterSpec(name)) }
                    val spec = ap.getParameterSpec(java.security.spec.ECParameterSpec::class.java)
                    java.security.KeyFactory.getInstance("EC").generatePublic(java.security.spec.ECPublicKeySpec(java.security.spec.ECPoint(BigInteger(1, unb64u(j.getString("x"))), BigInteger(1, unb64u(j.getString("y")))), spec))
                }
                else -> throw IllegalArgumentException("JWK 의 kty 는 RSA 또는 EC 여야 해요")
            }
        }
        if ("BEGIN CERTIFICATE" in t) return java.security.cert.CertificateFactory.getInstance("X.509").generateCertificate(t.byteInputStream()).publicKey
        val der = Base64.getMimeDecoder().decode(t.lines().filter { !it.startsWith("-----") }.joinToString(""))
        return java.security.KeyFactory.getInstance(if (alg.startsWith("ES")) "EC" else "RSA").generatePublic(java.security.spec.X509EncodedKeySpec(der))
    }

    fun verify(token: String, keyText: String): Result {
        val parts = token.trim().removePrefix("Bearer ").trim().split('.'); if (parts.size != 3) return Result(false, "JWT 는 점(.)으로 나뉜 세 부분이어야 해요")
        val header = try { JSONObject(String(unb64u(parts[0]))) } catch (_: Exception) { return Result(false, "헤더를 읽지 못했어요") }
        val alg = header.optString("alg"); val input = (parts[0] + "." + parts[1]).toByteArray(); val sig = try { unb64u(parts[2]) } catch (_: Exception) { return Result(false, "서명 부분을 읽지 못했어요") }
        return try {
            when {
                alg.equals("none", true) -> Result(false, "alg=none: 서명이 없는 토큰이에요")
                alg in listOf("HS256", "HS384", "HS512") -> {
                    val secret = if (keyText.trim().startsWith("{")) unb64u(JSONObject(keyText).getString("k")) else keyText.toByteArray()
                    val mac = Totp.hmac("Hmac" + alg.replace("HS", "SHA"), secret, input)
                    Result(MessageDigest.isEqual(mac, sig), alg)
                }
                alg in listOf("RS256", "RS384", "RS512") -> Result(java.security.Signature.getInstance("SHA${alg.substring(2)}withRSA").apply { initVerify(publicKey(keyText, alg)); update(input) }.verify(sig), alg)
                alg in listOf("ES256", "ES384", "ES512") -> {
                    val need = mapOf("ES256" to 64, "ES384" to 96, "ES512" to 132)[alg]!!
                    if (sig.size != need) Result(false, "$alg 서명은 ${need}바이트여야 해요 (지금 ${sig.size}바이트)")
                    else Result(java.security.Signature.getInstance("SHA${alg.substring(2)}withECDSA").apply { initVerify(publicKey(keyText, alg)); update(input) }.verify(joseToDer(sig)), alg)
                }
                else -> Result(false, "이 도구는 HS·RS·ES 256/384/512 만 확인해요 (alg=$alg)")
            }
        } catch (e: IllegalArgumentException) { Result(false, e.message ?: "키를 읽지 못했어요") } catch (e: Exception) { Result(false, "키를 읽거나 확인하지 못했어요: ${e.javaClass.simpleName}") }
    }
}
