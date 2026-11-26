package com.selfcheck.app

import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Before
import org.junit.Test
import java.io.IOException
import java.security.MessageDigest
import java.security.SecureRandom
import java.util.Base64

/*
 * 보안 점검 엔진과 도구 14가지 시험. 기준값은 모두 "다른 구현"이 만든 값이에요:
 * RFC 6070·7748·8032 와 IEEE 802.11i·Drepper(SHA-crypt) 공개 시험값, openssl 3.0(passwd·enc), 파이썬 cryptography(X25519·Ed25519·RSA·ECDSA·AES-GCM·OpenSSH 키),
 * hashlib(PBKDF2), CVSS 공식의 독립 계산. 실제 인터넷과는 연결하지 않았어요(유출 확인은 가짜 응답으로 시험).
 */
class NetSecTest {
    private fun hexb(s: String) = ByteArray(s.length / 2) { s.substring(2 * it, 2 * it + 2).toInt(16).toByte() }
    private fun hx(b: ByteArray) = b.joinToString("") { "%02x".format(it.toInt() and 0xff) }
    private fun sha256(s: String) = MessageDigest.getInstance("SHA-256").digest(s.toByteArray())
    private fun run(id: String, vararg kv: Pair<String, String>, host: ToolHost = FileHost) = runNetTool(id, *kv, host = host)

    @Before fun setUp() { GeoNet.fetcher = null }
    @After fun tearDown() { GeoNet.fetcher = null }

    // ============================================================ PBKDF2·WPA

    @Test fun pbkdf2MatchesRfc6070AndHashlib() {
        fun sha1(pw: String, salt: String, c: Int, n: Int) = hx(Pbkdf2.derive("HmacSHA1", pw.toByteArray(), salt.toByteArray(), c, n))
        assertEquals("0c60c80f961f0e71f3a9b524af6012062fe037a6", sha1("password", "salt", 1, 20))
        assertEquals("ea6c014dc72d6f8ccd1ed92ace1d41f0d8de8957", sha1("password", "salt", 2, 20))
        assertEquals("4b007901b765489abead49d926f721d065a429c1", sha1("password", "salt", 4096, 20))
        assertEquals("3d2eec4fe41c849b80c8d83662c0e44a8b291a964cf2f07038", sha1("passwordPASSWORDpassword", "saltSALTsaltSALTsaltSALTsaltSALTsalt", 4096, 25))
        assertEquals("56fa6aa75548099dcc37d7f03425e0c3", sha1("pass\u0000word", "sa\u0000lt", 4096, 16))
        for ((alg, pw, salt, c, n, expect) in SecVectors.pbkdf2.map { it.toVec() })
            assertEquals("$alg $c", expect, hx(Pbkdf2.derive("Hmac" + alg.uppercase(), hexb(pw), hexb(salt), c.toInt(), n.toInt())))
    }
    private data class Vec(val a: String, val b: String, val c: String, val d: String, val e: String, val f: String)
    private fun List<String>.toVec() = Vec(this[0], this[1], this[2], this[3].toString(), this[4].toString(), this[5])

    @Test fun wpaPskMatchesIeee80211iVectors() {
        assertEquals(SecVectors.WPA_IEEE, hx(WpaPsk.psk("password", "IEEE")))                                       // 규격 부록 H.4.1
        assertEquals("f42c6fc52df0ebef9ebb4b90b38a5f902e83fe1b135a70e23aed762e9710a12e", SecVectors.WPA_IEEE)
        assertEquals("0dc0d6eb90555ed6419756b9a15ec3e3209b63df707dd508d14581f8982721af", hx(WpaPsk.psk("ThisIsAPassword", "ThisIsASSID")))   // H.4.2
        assertEquals(SecVectors.WPA_LONG, hx(WpaPsk.psk("a".repeat(63), "Z".repeat(32))))                           // 길이 한계
        assertTrue(WpaPsk.problems("password123", "Home").none { it.second == 2 })
        assertTrue(WpaPsk.problems("short", "Home").any { it.second == 2 && "8~63" in it.first })
        assertTrue(WpaPsk.problems("a".repeat(64), "Home").any { it.second == 2 })
        assertTrue(WpaPsk.problems("goodpassword", "").any { it.second == 2 && "SSID" in it.first })
        assertTrue(WpaPsk.problems("goodpassword", "x".repeat(33)).any { it.second == 2 })
        assertTrue(WpaPsk.problems("비밀번호입니다만열두글자", "Home").any { it.second == 1 && "ASCII" in it.first })
        assertTrue(WpaPsk.problems("abcdefgh", "Home").any { it.second == 1 && "짧아요" in it.first })
    }

    // ============================================================ 비밀번호 강도·유출 확인

    @Test fun passwordStrengthPatternsAndCrackTimes() {
        assertEquals("비어 있어요", PasswordStrength.analyze("").label)
        val rep = PasswordStrength.analyze("aaaaaaaa")
        assertEquals(0, rep.level); assertEquals(26, rep.pool); assertEquals(log2(26.0) + log2(8.0), rep.bits, 1e-9); assertTrue(rep.patterns.single().contains("같은 글자 반복(a × 8)"))
        assertEquals(log2(26.0) + 1 + log2(8.0), PasswordStrength.analyze("abcdefgh").bits, 1e-9)                      // 연속
        assertTrue(PasswordStrength.analyze("abcdefgh").patterns.single().contains("연속된 글자(abcdefgh)"))
        assertTrue(PasswordStrength.analyze("987654").patterns.single().contains("연속된 글자(987654)"))                 // 내림차순
        assertTrue(PasswordStrength.analyze("qwertyuiop").patterns.single().contains("키보드 줄 그대로(qwertyuiop)"))
        assertTrue(PasswordStrength.analyze("poiuy").patterns.single().contains("키보드 줄 그대로"))                     // 거꾸로
        assertTrue(PasswordStrength.analyze("ㅂㅈㄷㄱㅅ").patterns.single().contains("키보드 줄 그대로"))                 // 한글 자판
        val block = PasswordStrength.analyze("abcabcabc"); assertEquals(3 * log2(26.0) + log2(3.0), block.bits, 1e-9); assertTrue(block.patterns.single().contains("같은 덩어리 반복(\"abc\" × 3)"))
        val year = PasswordStrength.analyze("x1999y"); assertTrue(year.patterns.single().contains("연도(1999)")); assertEquals(2 * log2(36.0) + log2(120.0), year.bits, 1e-9)
        val good = PasswordStrength.analyze("Tr0ub4dor&3")                                                              // 패턴 없음: 11 × log2(95)
        assertEquals(95, good.pool); assertEquals(11 * log2(95.0), good.bits, 1e-9); assertEquals(good.naiveBits, good.bits, 1e-9); assertEquals(3, good.level); assertEquals("강함", good.label); assertTrue(good.patterns.isEmpty())
        assertEquals(listOf("소문자", "대문자", "숫자", "기호"), good.classes)
        assertEquals(4, PasswordStrength.analyze("correct-horse-battery-staple-Xk9#").level)
        assertEquals(138, PasswordStrength.analyze("비밀번호123").pool)                                                  // 숫자 10 + 한글 등 128
        assertEquals(2.0.pow(39) / 10, PasswordStrength.seconds(40.0, 10.0), 1.0)
        assertEquals("1초도 안 걸려요", PasswordStrength.human(0.4)); assertEquals("30초", PasswordStrength.human(30.0)); assertEquals("2시간", PasswordStrength.human(7200.0)); assertEquals("3일", PasswordStrength.human(3 * 86400.0))
        assertEquals("5,000년", PasswordStrength.human(5000 * 365.25 * 86400)); assertEquals("30.0만 년", PasswordStrength.human(3e5 * 365.25 * 86400)); assertTrue(PasswordStrength.human(1e30).startsWith("사실상 불가능"))
    }
    private fun log2(x: Double) = kotlin.math.log2(x)
    private fun Double.pow(n: Int) = Math.pow(this, n.toDouble())

    @Test fun hibpKAnonymityHelpers() {
        assertEquals("5BAA61E4C9B93F3F0682250B6CF8331B7EE68FD8", Hibp.sha1Hex("password"))
        val suffix = "1E4C9B93F3F0682250B6CF8331B7EE68FD8"
        val body = "0018A45C4D1DEF81644B54AB7F969B88D65:1\r\n$suffix:10434004\r\n011053FD0102E94D6AE2F8B83D76FAF94F6:0\r\n"
        assertEquals(10434004L, Hibp.count(body, suffix)); assertEquals(10434004L, Hibp.count(body, suffix.lowercase()))
        assertNull(Hibp.count(body, "011053FD0102E94D6AE2F8B83D76FAF94F6"))                  // 가짜 채움(횟수 0)은 없는 것
        assertNull(Hibp.count(body, "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF")); assertNull(Hibp.count("", suffix))
    }

    @Test fun toolSecPasswordCheckAndWpa() {
        val w = run("sec_wpa_psk")                                                                 // 기본값이 IEEE 규격 예시
        assertEquals(SecVectors.WPA_IEEE, w.kv("PSK (64자리 16진수)")); assertTrue(w.blocks().contains("psk=${SecVectors.WPA_IEEE}")); assertTrue(w.blocks().contains("wpa_psk=${SecVectors.WPA_IEEE}")); assertFalse(w.hasError)
        assertTrue(run("sec_wpa_psk", "pass" to "short").hasError); assertTrue(run("sec_wpa_psk", "ssid" to "", "pass" to "x").text().contains("입력하세요"))
        val weak = run("sec_password_check", "pw" to "aaaaaaaa"); assertEquals("매우 약함", weak.kv("강도")); assertEquals(2, weak.kvLevel("강도")); assertTrue(weak.text().contains("같은 글자 반복")); assertEquals(3, weak.rows().size)
        assertEquals("10초", weak.rows()[0][1]); assertEquals("1초도 안 걸려요", weak.rows()[1][1]); assertTrue(weak.text().contains("12글자 이상"))
        val strong = run("sec_password_check", "pw" to "correct-horse-battery-staple-Xk9#"); assertEquals("매우 강함", strong.kv("강도")); assertEquals(-1, strong.kvLevel("강도")); assertFalse(strong.text().contains("12글자 이상으로"))
        assertTrue(strong.rows()[2][1].contains("년")); assertTrue(run("sec_password_check", "pw" to "").text().contains("입력하세요"))
    }

    @Test fun toolSecPwnedRangeSendsOnlyHashPrefix() {
        val seen = ArrayList<String>()
        val body = "0018A45C4D1DEF81644B54AB7F969B88D65:1\n1E4C9B93F3F0682250B6CF8331B7EE68FD8:10434004\n011053FD0102E94D6AE2F8B83D76FAF94F6:0\n"
        GeoNet.fetcher = { u -> seen += u; body }
        val hit = run("sec_pwned_range", "pw" to "password")
        assertEquals(listOf("https://api.pwnedpasswords.com/range/5BAA6"), seen); assertEquals(5, seen.single().substringAfterLast('/').length); assertFalse(seen.single().contains("1E4C9B93F3F0682250B6CF8331B7EE68FD8"))     // 해시 앞 5글자만 나감
        assertEquals("5BAA6", hit.kv("보낸 해시 앞부분")); assertEquals("3개", hit.kv("받은 후보 수")); assertEquals("10,434,004번 유출된 비밀번호예요", hit.kv("결과")); assertEquals(2, hit.kvLevel("결과")); assertTrue(hit.hasError)
        val miss = run("sec_pwned_range", "pw" to "this-one-is-not-in-the-list-9f3k"); assertEquals("유출 목록에서 찾지 못했어요", miss.kv("결과")); assertFalse(miss.hasError)
        GeoNet.fetcher = { throw IOException("서버가 503 으로 답했어요") }; val e = run("sec_pwned_range", "pw" to "x"); assertTrue(e.hasError); assertTrue(e.text().contains("503"))
        assertTrue(run("sec_pwned_range", "pw" to "").text().contains("입력하세요"))
    }

    @Test fun toolSecPbkdf2() {
        val r = run("sec_pbkdf2", "alg" to "HMAC-SHA256", "pw" to "password", "salt" to "salt", "iter" to "4096", "len" to "32")
        assertEquals("c5e478d59288c841aa530db6845c4c8d962893a001ce4e11a4963873aa98134a", r.kv("16진수")); assertEquals(Base64.getEncoder().encodeToString(hexb(r.kv("16진수"))), r.kv("Base64"))
        assertEquals("0c60c80f961f0e71f3a9b524af6012062fe037a6", run("sec_pbkdf2", "alg" to "HMAC-SHA1", "pw" to "password", "salt" to "salt", "iter" to "1", "len" to "20").kv("16진수"))
        val h = run("sec_pbkdf2", "alg" to "HMAC-SHA256", "pw" to "한글 비번", "salt" to "00 ff 10", "fmt" to "16진수", "iter" to "777", "len" to "40")      // 한글 비밀번호(UTF-8)·16진수 솔트
        assertEquals("5f348642d99dfd3abb934f1eefaa817bc29eb7deac608844166eab45b2e9facbf9a7c558b39fdd49", h.kv("16진수"))
        assertTrue(run("sec_pbkdf2", "iter" to "0").hasError); assertTrue(run("sec_pbkdf2", "iter" to "9999999").text().contains("2,000,000")); assertTrue(run("sec_pbkdf2", "len" to "500").hasError); assertTrue(run("sec_pbkdf2", "fmt" to "16진수", "salt" to "xyz").hasError)
    }

    // ============================================================ htpasswd (openssl passwd 와 비교)

    @Test fun unixCryptMatchesOpensslAndDrepperVectors() {
        for ((kind, pw, salt, expect) in SecVectors.crypt.map { Quad(it[0], it[1], it[2], it[3]) }) {
            val got = when (kind) { "apr1" -> UnixCrypt.md5(pw.toByteArray(), salt, "\$apr1\$"); "1" -> UnixCrypt.md5(pw.toByteArray(), salt, "\$1\$"); "5" -> UnixCrypt.sha(pw.toByteArray(), salt, false); else -> UnixCrypt.sha(pw.toByteArray(), salt, true) }
            assertEquals("$kind '$pw' $salt", expect, got)
        }
        assertEquals("\$6\$saltstring\$svn8UoSVapNtMuq1ukKS4tPQd8iKwSMHWjl/O817G3uBnIFNjnQJuesI68u4OTLiBFdcbYEdFCoEOfaS35inz1", UnixCrypt.sha("Hello world!".toByteArray(), "saltstring", true))
        assertEquals("\$5\$saltstring\$5B8vYYiY.CVt1RlTTf8KbXBH3hsxY/GNooZaBBGWEc5", UnixCrypt.sha("Hello world!".toByteArray(), "saltstring", false))
        assertEquals("\$6\$rounds=10000\$saltstringsaltst\$OW1/O6BYHV6BcXZu8QVeXbDWra3Oeqh0sbHbbMCVNSnCM/UrjmM0Dp8vOuZeHBy/YTBmSK6H9qs/y3RnOaw5v.", UnixCrypt.sha("Hello world!".toByteArray(), "\$6\$rounds=10000\$saltstringsaltstring", true))   // 솔트는 16글자까지
        // 이미 만들어진 해시를 솔트 자리에 넣으면 같은 해시가 다시 나옴 (비밀번호 확인용)
        val known = SecVectors.crypt[0][3]; assertEquals(known, UnixCrypt.md5("a".toByteArray(), known, "\$apr1\$"))
        assertEquals("{SHA}W6ph5Mm5Pz8GgiULbPgzG37mj9g=", UnixCrypt.htpasswdSha1("password".toByteArray()))
        assertEquals(8, UnixCrypt.randomSalt(8).length); assertTrue(UnixCrypt.randomSalt(16).all { it in UnixCrypt.SALT_CHARS }); assertNotEquals(UnixCrypt.randomSalt(16), UnixCrypt.randomSalt(16))
    }
    private data class Quad(val a: String, val b: String, val c: String, val d: String)

    @Test fun toolSecHtpasswd() {
        assertEquals("admin:${SecVectors.crypt[5][3]}", run("sec_htpasswd", "user" to "admin", "pw" to "secret", "fmt" to "Apache MD5 (apr1)", "salt" to "abcdefgh").blocks().lines().first { it.startsWith("admin:") })
        val s6 = run("sec_htpasswd", "user" to "u", "pw" to "secret", "fmt" to "SHA-512 crypt (\$6\$)", "salt" to "0123456789abcdef"); assertEquals("u:${SecVectors.crypt[8][3]}", s6.blocks().lines().first { it.startsWith("u:") }); assertTrue(s6.blocks().contains("auth_basic_user_file"))
        assertEquals("u:{SHA}W6ph5Mm5Pz8GgiULbPgzG37mj9g=", run("sec_htpasswd", "user" to "u", "pw" to "password", "fmt" to "{SHA} (약함, 비권장)").blocks().lines().first { it.startsWith("u:") })
        assertTrue(run("sec_htpasswd", "user" to "u", "pw" to "password", "fmt" to "{SHA} (약함, 비권장)").hasError)                // 약한 방식은 경고
        val rnd1 = run("sec_htpasswd", "user" to "u", "pw" to "x").kv("해시"); val rnd2 = run("sec_htpasswd", "user" to "u", "pw" to "x").kv("해시"); assertNotEquals(rnd1, rnd2); assertTrue(rnd1.startsWith("\$apr1\$"))   // 솔트를 안 주면 무작위
        assertTrue(run("sec_htpasswd", "user" to "a:b", "pw" to "x").hasError); assertTrue(run("sec_htpasswd", "user" to "u", "pw" to "x", "salt" to "bad salt!").hasError); assertTrue(run("sec_htpasswd", "user" to "", "pw" to "x").text().contains("입력하세요"))
    }

    // ============================================================ X25519 · Ed25519 · SSH

    @Test fun x25519MatchesRfc7748AndCryptography() {
        assertEquals(SecVectors.RFC7748_OUT, hx(X25519.scalarMult(hexb(SecVectors.RFC7748_SCALAR), hexb(SecVectors.RFC7748_U))))
        assertEquals(SecVectors.ALICE_PUB, hx(X25519.publicKey(hexb(SecVectors.ALICE_PRIV)))); assertEquals(SecVectors.BOB_PUB, hx(X25519.publicKey(hexb(SecVectors.BOB_PRIV))))
        assertEquals(SecVectors.DH_SHARED, hx(X25519.scalarMult(hexb(SecVectors.ALICE_PRIV), hexb(SecVectors.BOB_PUB)))); assertEquals(SecVectors.DH_SHARED, hx(X25519.scalarMult(hexb(SecVectors.BOB_PRIV), hexb(SecVectors.ALICE_PUB))))
        for ((k, u, shared, pub) in SecVectors.x25519.map { Quad(it[0], it[1], it[2], it[3]) }) { assertEquals(shared, hx(X25519.scalarMult(hexb(k), hexb(u)))); assertEquals(pub, hx(X25519.publicKey(hexb(k)))) }
        val (privA, pubA) = X25519.generate(); val (privB, pubB) = X25519.generate()
        assertEquals(0, privA[0].toInt() and 7); assertEquals(0, privA[31].toInt() and 0x80); assertEquals(0x40, privA[31].toInt() and 0x40); assertEquals(hx(pubA), hx(X25519.publicKey(privA)))
        assertEquals(hx(X25519.scalarMult(privA, pubB)), hx(X25519.scalarMult(privB, pubA)))                    // 두 쪽이 같은 공유 비밀
        assertNotEquals(hx(privA), hx(privB))
    }

    @Test fun ed25519PublicKeysMatchRfc8032AndCryptography() {
        assertEquals(SecVectors.RFC8032_PUB, hx(Ed25519.publicKey(hexb(SecVectors.RFC8032_SEED))))
        for ((seed, pub) in SecVectors.ed25519.map { it[0] to it[1] }) assertEquals(pub, hx(Ed25519.publicKey(hexb(seed))))
    }

    @Test fun sshFingerprintsMatchOpensshSerialization() {
        for (row in SecVectors.ssh) {
            val k = SshKey.parse(row[1])
            assertEquals(row[0], row[2], k.sha256); assertEquals(row[0], row[3], k.md5); assertEquals("me@host", k.comment)
            assertEquals(when (row[0]) { "ed25519" -> "Ed25519 (256비트)"; "rsa2048" -> "RSA 2048비트"; "rsa1024" -> "RSA 1024비트"; "p256" -> "ECDSA P-256"; else -> "ECDSA P-384" }, k.bits)
        }
        // 앞에 옵션·호스트 이름이 붙어도 읽음
        val line = SecVectors.ssh[0][1]; val withOpt = "from=\"10.0.0.0/8\",no-pty $line"; assertEquals(SecVectors.ssh[0][2], SshKey.parse(withOpt).sha256); assertTrue(SshKey.parse(withOpt).options.contains("no-pty"))
        // GitHub 이 공개한 ed25519 호스트 키 지문
        assertEquals("SHA256:+DiY3wvvV6TuJJhbpZisF/zLDA0zPMSvHdkr4UvCOqU", SshKey.parse("github.com ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqKLsabgH5C9okWi0dh2l9GKJl").sha256)
        // 우리가 만든 공개키 줄이 OpenSSH 가 만든 줄과 글자까지 같음
        val pub = Ed25519.publicKey(sha256("sshed")); assertEquals(SecVectors.ssh[0][1], SshKey.ed25519PublicLine(pub, "me@host"))
        for (bad in listOf("hello world", "ssh-ed25519", "ssh-ed25519 !!!notbase64", "ssh-rsa " + SecVectors.ssh[0][1].split(' ')[1], "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAA")) try { SshKey.parse(bad); fail("읽히면 안 돼요: $bad") } catch (_: IllegalArgumentException) { }
    }

    private class Rd(val b: ByteArray, var p: Int = 0) {
        fun u32(): Int { val v = ((b[p].toInt() and 0xff) shl 24) or ((b[p + 1].toInt() and 0xff) shl 16) or ((b[p + 2].toInt() and 0xff) shl 8) or (b[p + 3].toInt() and 0xff); p += 4; return v }
        fun str(): ByteArray { val n = u32(); val r = b.copyOfRange(p, p + n); p += n; return r }
    }

    @Test fun opensshPrivateKeyFileStructure() {
        val seed = sha256("pem-seed"); val pub = Ed25519.publicKey(seed)
        val pem = SshKey.ed25519PrivatePem(seed, pub, "me@host", SecureRandom())
        assertTrue(pem.startsWith("-----BEGIN OPENSSH PRIVATE KEY-----\n")); assertTrue(pem.endsWith("-----END OPENSSH PRIVATE KEY-----\n")); assertTrue(pem.lines().all { it.length <= 70 || it.startsWith("-----") })
        val raw = Base64.getDecoder().decode(pem.lines().filter { !it.startsWith("-----") }.joinToString(""))
        assertEquals("openssh-key-v1\u0000", String(raw, 0, 15))
        val r = Rd(raw, 15)
        assertEquals("none", String(r.str())); assertEquals("none", String(r.str())); assertEquals(0, r.str().size); assertEquals(1, r.u32())      // 암호 없음·키 1개
        assertEquals(hx(SshKey.ed25519PublicBlob(pub)), hx(r.str()))
        val priv = r.str(); assertEquals(raw.size, r.p); assertEquals(0, priv.size % 8)                                                           // 뒤에 남는 바이트 없음, 8바이트 단위
        val q = Rd(priv); val c1 = q.u32(); val c2 = q.u32(); assertEquals(c1, c2)                                                                // 확인 값 두 개가 같아야 해독이 성공한 것으로 봄
        assertEquals("ssh-ed25519", String(q.str())); assertEquals(hx(pub), hx(q.str())); assertEquals(hx(seed + pub), hx(q.str())); assertEquals("me@host", String(q.str()))
        val pad = priv.copyOfRange(q.p, priv.size); assertEquals((1..pad.size).map { it.toByte() }, pad.toList())                                // 채움은 1,2,3…
    }

    // ============================================================ CVSS · CSP · URL · 비밀 검사

    @Test fun cvssScoresMatchIndependentCalculation() {
        for ((vec, score, sev) in listOf(
            Triple("AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H", 10.0, "치명적"), Triple("AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", 9.8, "치명적"), Triple("AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N", 7.5, "높음"),
            Triple("AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N", 6.1, "보통"), Triple("AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H", 7.8, "높음"), Triple("AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H", 8.1, "높음"),
            Triple("AV:N/AC:L/PR:L/UI:R/S:U/C:L/I:N/A:N", 3.5, "낮음"), Triple("AV:P/AC:H/PR:H/UI:R/S:U/C:N/I:N/A:N", 0.0, "없음"), Triple("AV:A/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H", 6.5, "보통"),
            Triple("AV:N/AC:L/PR:H/UI:N/S:C/C:H/I:H/A:H", 9.1, "치명적"))) {
            for (ver in listOf("3.1", "3.0")) { val r = Cvss.parse("CVSS:$ver/$vec"); assertEquals("$ver $vec", score, r.score, 1e-9); assertEquals(sev, r.severity); assertEquals(ver, r.version) }
        }
        val r = Cvss.parse("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"); assertEquals(3.887, r.exploitability, 0.001); assertEquals(5.873, r.impact, 0.001); assertFalse(r.scopeChanged); assertEquals(8, r.parts.size)
        assertEquals(1.0, Cvss.roundUp31(0.95), 1e-9); assertEquals(4.0, Cvss.roundUp31(4.0), 1e-9); assertEquals(4.0, Cvss.roundUp31(4.000001), 1e-9); assertEquals(4.1, Cvss.roundUp31(4.00002), 1e-9); assertEquals(4.9, Cvss.roundUp31(4.9000000000000004), 1e-9)
        for (bad in listOf("", "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", "CVSS:4.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H", "CVSS:3.1/AV:X/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:Z/C:H/I:H/A:H")) try { Cvss.parse(bad); fail("읽히면 안 돼요: $bad") } catch (_: IllegalArgumentException) { }
        val t = run("sec_cvss"); assertEquals("9.8 / 10  (치명적)", t.kv("기본 점수")); assertEquals(2, t.kvLevel("기본 점수")); assertEquals(8, t.rows().size); assertEquals("네트워크", t.row("공격 경로(AV)")[1])
        assertEquals("0.0 / 10  (없음)", run("sec_cvss", "v" to "CVSS:3.1/AV:P/AC:H/PR:H/UI:R/S:U/C:N/I:N/A:N").kv("기본 점수")); assertTrue(run("sec_cvss", "v" to "CVSS:3.1/AV:Q").hasError); assertTrue(run("sec_cvss", "v" to "").text().contains("입력하세요"))
    }

    @Test fun cspAnalysisFlagsWeakPolicies() {
        val strong = "default-src 'none'; script-src 'self' 'nonce-abc123'; style-src 'self'; img-src 'self' data:; connect-src 'self'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'; object-src 'none'; upgrade-insecure-requests; report-uri /csp"
        assertTrue(CspCheck.analyze(strong).all { it.level <= 0 }); assertEquals(-1, CspCheck.analyze(strong).single { it.level == -1 }.level)
        val weak = CspCheck.analyze("default-src * 'unsafe-inline' 'unsafe-eval'; img-src * data:")
        assertTrue(weak.any { it.level == 2 && "'unsafe-inline'" in it.text }); assertTrue(weak.any { it.level == 2 && "* 가 있어요" in it.text }); assertTrue(weak.any { it.level == 1 && "'unsafe-eval'" in it.text })
        assertTrue(weak.any { "object-src" in it.text }); assertTrue(weak.any { "base-uri" in it.text }); assertTrue(weak.any { "frame-ancestors" in it.text })
        assertTrue(CspCheck.analyze("img-src 'self'").any { it.level == 2 && "script-src 도 default-src 도 없어요" in it.text })
        assertTrue(CspCheck.analyze("scrpt-src 'self'; default-src 'self'").any { it.level == 1 && "알 수 없는 지시어 \"scrpt-src\"" in it.text })
        assertTrue(CspCheck.analyze("default-src 'self'; script-src 'self' https: data:").any { it.level == 2 && "https:/http:/data:" in it.text })
        assertTrue(CspCheck.analyze("default-src 'self'; script-src 'nonce-x' 'strict-dynamic' https: 'unsafe-inline'").none { it.level == 2 })      // strict-dynamic 이면 넓은 범위·unsafe-inline 은 구형 브라우저용
        assertTrue(CspCheck.analyze("default-src 'self'; script-src 'self' *.cdn.example.com http://x.example.com").let { f -> f.any { "와일드카드 서브도메인" in it.text } && f.any { "http:// 주소" in it.text } })
        assertTrue(CspCheck.analyze("default-src 'self'; plugin-types application/pdf").any { it.level == 0 && "더는 쓰지 않는" in it.text })
        val p = CspCheck.parse("Content-Security-Policy: default-src 'self'; default-src *; img-src 'self' data:"); assertEquals(listOf("'self'"), p["default-src"]); assertEquals(listOf("default-src", "img-src"), p.keys.toList())      // 같은 지시어는 첫 번째만
        assertTrue(CspCheck.analyze(";;").single().level == 2)
        val t = run("sec_csp_check"); assertTrue(t.hasError); assertEquals("4개", t.kv("지시어")); assertTrue(t.kv("점검 결과").startsWith("위험 ")); assertTrue(t.rows().any { it[0] == "object-src" && it[1] == "'none'" })
    }

    private fun urlFindings(u: String) = UrlInspect.analyze(u).second
    private fun List<UrlInspect.Finding>.has(level: Int, fragment: String) = any { it.level == level && fragment in it.text }

    @Test fun urlInspectFindsCommonPhishingTricks() {
        assertTrue(urlFindings("https://paypal.com@evil.example/login").has(2, "실제로 가는 곳은 \"evil.example\""))
        val dec = urlFindings("http://3232235777/login"); assertTrue(dec.has(2, "숫자·16진수·8진수로 숨겨")); assertTrue(dec.has(2, "192.168.1.1")); assertTrue(dec.has(2, "https 가 아닌 http"))
        assertEquals("192.168.0.1", UrlInspect.legacyIpv4("0xC0A80001")); assertEquals("192.168.0.1", UrlInspect.legacyIpv4("0300.0250.0.1")); assertEquals("127.0.0.1", UrlInspect.legacyIpv4("2130706433")); assertEquals("10.0.0.1", UrlInspect.legacyIpv4("10.1")); assertEquals("192.168.1.1", UrlInspect.legacyIpv4("192.168.257"))
        assertNull(UrlInspect.legacyIpv4("example.com")); assertNull(UrlInspect.legacyIpv4("256.1.1.1")); assertNull(UrlInspect.legacyIpv4("1.2.3.4.5")); assertNull(UrlInspect.legacyIpv4("4294967296"))
        assertTrue(urlFindings("http://192.168.0.1/").has(1, "IP 주소(192.168.0.1)"))
        val sub = urlFindings("https://www.paypal.com.secure-login.example.xyz/verify"); assertTrue(sub.has(2, "\"paypal\" 이름이 앞쪽 칸에 있지만 진짜 도메인은 \"example.xyz\"")); assertTrue(sub.has(1, ".xyz")); assertTrue(sub.has(1, "서브도메인이 4단계"))
        assertTrue(urlFindings("https://paypa1.com").has(2, "\"paypa1\" 은 \"paypal\" 와 한 글자 차이"))
        assertTrue(urlFindings("https://rnicrosoft.com").has(2, "\"rnicrosoft\" 은 숫자·글자를 바꿔서 \"microsoft\" 처럼 보이게"))
        assertTrue(urlFindings("https://paypal-login.com").has(2, "낚시 단어"))
        val cyr = "аpple.com"                                                                                         // 첫 글자만 키릴 а
        assertTrue(urlFindings("https://$cyr/").has(2, "라틴 글자와 똑같이 생긴 다른 문자")); assertTrue(urlFindings("https://$cyr/").has(2, "\"apple\" 의 글자를 비슷하게 생긴 다른 문자로 바꿔친"))
        assertTrue(urlFindings("https://" + java.net.IDN.toASCII(cyr) + "/").has(2, "라틴 글자와 똑같이 생긴 다른 문자"))     // punycode 로 붙여도 같음
        assertTrue(urlFindings("https://한국.kr/").has(0, "국제화(한글 등) 도메인")); assertFalse(urlFindings("https://한국.kr/").any { it.level == 2 })
        assertTrue(urlFindings("https://bit.ly/3abc").has(1, "단축 주소"))
        assertTrue(urlFindings("https://example.com/go?url=https://evil.example").has(1, "redirect 값"))
        assertTrue(urlFindings("javascript:alert(1)").single().let { it.level == 2 && "웹 주소가 아니에요" in it.text }); assertTrue(urlFindings("data:text/html;base64,PGgxPg==").single().level == 2)
        assertTrue(urlFindings("https://example.com:8443/").has(1, "포트(8443)")); assertTrue(urlFindings("https://a-b-c-d.example.com").has(1, "하이픈"))
        assertEquals(-1, urlFindings("https://www.naver.com/").single().level); assertEquals(-1, urlFindings("https://m.naver.com/news").single().level); assertEquals(-1, urlFindings("evil.example.org/login").single().level)
        assertEquals("evil.example", UrlInspect.parse("//evil.example/x")!!.host); assertEquals(8080, UrlInspect.parse("http://[::1]:8080/a?b=1#c")!!.port); assertEquals("b=1", UrlInspect.parse("http://[::1]:8080/a?b=1#c")!!.query); assertEquals("c", UrlInspect.parse("http://[::1]:8080/a?b=1#c")!!.fragment)
        // 도구: 한 개는 자세히, 여러 개는 표
        val one = run("sec_url_inspect", "u" to "https://paypal.com@evil.example/login"); assertEquals("evil.example", one.kv("접속하는 곳(호스트)")); assertEquals("paypal.com", one.kv("@ 앞부분")); assertTrue(one.hasError)
        val many = run("sec_url_inspect"); assertEquals(3, many.rows().size); assertEquals(listOf("위험", "위험", "특이점 없음"), many.rows().map { it[1] }); assertTrue(run("sec_url_inspect", "u" to "").text().contains("입력하세요"))
    }

    private val aws = "AK" + "IA" + "IOSFODNN7EXAMPLE"
    private val gh = "gh" + "p_" + "abcdefghijklmnopqrstuvwxyz0123456789"
    private val slack = "xo" + "xb-" + "1234567890-abcdefghijkl"
    private val pemHead = "-----BEGIN " + "RSA PRIVATE KEY-----"
    private val jwt = "eyJhbGciOiJIUzI1NiJ9" + "." + "eyJzdWIiOiIxMjM0NTY3ODkwIn0" + "." + "abcdefghijklmnop"
    private val tg = "123456789" + ":" + "AAAAAAAAAABBBBBBBBBBCCCCCCCCCCDDDDD"
    private val stripe = "sk_" + "live_" + "a".repeat(24)

    @Test fun secretScanFindsKnownFormatsAndSkipsPlaceholders() {
        val text = listOf("# config", "aws = $aws", "GITHUB_TOKEN=$gh", "slack: \"$slack\"", pemHead, "auth: $jwt", "bot=$tg", "stripe_key = \"$stripe\"", "db = postgres://admin:Sup3rS3cret@db.example.com:5432/app",
            "db_password = \"hunter2hunter2\"", "password = \"changeme\"", "token: \${TOKEN}", "secret = \"<your-secret>\"", "api_key = \"aaaaaaaa\"", "api_key = \"x7Fq9Zk2Lm\"", "just a normal line").joinToString("\n")
        val hits = SecretScan.scan(text)
        fun kind(line: Int) = hits.filter { it.line == line }.map { it.kind }
        assertEquals(listOf("AWS 액세스 키 ID"), kind(2)); assertEquals(listOf("GitHub 토큰"), kind(3)); assertEquals(listOf("Slack 토큰"), kind(4)); assertEquals(listOf("개인키(PEM·OpenSSH)"), kind(5)); assertEquals(listOf("JWT"), kind(6))
        assertEquals(listOf("텔레그램 봇 토큰"), kind(7)); assertEquals(listOf("Stripe 비밀 키"), kind(8)); assertEquals(listOf("주소에 들어 있는 아이디:비밀번호"), kind(9)); assertEquals(listOf("비밀번호·토큰 설정값"), kind(10))
        assertTrue("자리표시자·낮은 엔트로피 값은 건너뜀", (11..14).all { kind(it).isEmpty() }); assertEquals(listOf("비밀번호·토큰 설정값"), kind(15)); assertTrue(kind(16).isEmpty())
        assertEquals(2, hits.first { it.line == 2 }.level); assertEquals(1, hits.first { it.line == 6 }.level); assertEquals(1, hits.first { it.line == 10 }.level)
        for (h in hits) for (secret in listOf(aws, gh, slack, jwt, tg, stripe, "Sup3rS3cret", "hunter2hunter2")) assertFalse("원문이 그대로 보이면 안 돼요: ${h.kind}", h.preview.contains(secret))
        assertEquals("AKIA…******LE", SecretScan.mask(aws)); assertEquals("****", SecretScan.mask("abcd")); assertEquals(0.0, SecretScan.entropy("aaaa"), 1e-9); assertEquals(2.0, SecretScan.entropy("abcd"), 1e-9)
        // 도구
        val r = run("sec_secret_scan", "t" to text); assertEquals("16줄 · ${"%,d".format(text.length)}글자", r.kv("검사한 글")); assertTrue(r.kv("발견").startsWith("${hits.size}건")); assertEquals(2, r.kvLevel("발견")); assertTrue(r.hasError); assertTrue(r.text().contains("저장소(Git)에 이미 올렸다면"))
        assertEquals(hits.size, r.rows().size); assertEquals("2", r.rows()[0][0]); assertFalse(r.text().contains(gh)); assertFalse(r.text().contains(aws))
        val clean = run("sec_secret_scan", "t" to "hello world\nnothing here"); assertEquals("없음", clean.kv("발견")); assertEquals(-1, clean.kvLevel("발견")); assertTrue(run("sec_secret_scan", "t" to "").text().contains("붙여 넣거나"))
        val fh = object : TestHost() { override fun file(key: String) = if (key == "f") FileRef("leak.env", 100) { "TOKEN_X=$gh\n".byteInputStream() } else null }
        val fr = run("sec_secret_scan", host = fh); assertEquals(1, fr.rows().size); assertEquals("GitHub 토큰", fr.rows()[0][1])
    }

    // ============================================================ AES 상자 · JWT · 기타

    @Test fun aesBoxMatchesPythonGcmAndOpensslEnc() {
        val plain = "비밀 메모 secret note 🙂".toByteArray()
        val gcm = SecVectors.gcm[0]
        assertEquals(gcm[2], AesBox.encryptGcm(gcm[0], plain, 1000, ByteArray(16) { it.toByte() }, ByteArray(12) { (100 + it).toByte() }))     // 파이썬 AESGCM 과 글자까지 같음
        assertEquals(String(plain), String(AesBox.decryptGcm(gcm[0], gcm[2])))
        try { AesBox.decryptGcm("wrong", gcm[2]); fail("틀린 비밀번호는 거부해야 해요") } catch (_: javax.crypto.AEADBadTagException) { }
        val parts = gcm[2].split('.'); val flipped = (parts.take(4) + listOf(parts[4].replaceFirst(parts[4][0], if (parts[4][0] == 'A') 'B' else 'A'))).joinToString(".")
        try { AesBox.decryptGcm(gcm[0], flipped); fail("바뀐 암호문은 거부해야 해요") } catch (_: javax.crypto.AEADBadTagException) { }
        for (bad in listOf("nonsense", "scbox1.x.a.b.c", "scbox1.5.a.b.c", "scbox2.1000.a.b.c")) try { AesBox.decryptGcm("x", bad); fail("읽히면 안 돼요: $bad") } catch (_: IllegalArgumentException) { }
        val a = AesBox.encryptGcm("pw", plain, 1000); val b = AesBox.encryptGcm("pw", plain, 1000); assertNotEquals(a, b); assertEquals(String(plain), String(AesBox.decryptGcm("pw", b)))   // 솔트·논스가 무작위
        // openssl enc -aes-256-cbc -pbkdf2 -iter 1234 -S … -a -A : -S 로 솔트를 주면 openssl 은 "Salted__"+솔트 머리글을 출력하지 않아서, 앞에 붙여 완성한 값과 비교
        val cbc = SecVectors.cbc[0]; val salt = hexb(cbc[2]); val full = Base64.getEncoder().encodeToString("Salted__".toByteArray() + salt + Base64.getDecoder().decode(cbc[3]))
        assertEquals(full, AesBox.encryptOpenssl(cbc[0], plain, 1234, salt))
        assertEquals(String(plain), String(AesBox.decryptOpenssl(cbc[0], full, 1234)))
        assertTrue(runCatching { String(AesBox.decryptOpenssl("wrong", full, 1234)) }.getOrNull() != String(plain))                           // 틀린 비밀번호로는 원문이 나오지 않음
        try { AesBox.decryptOpenssl("x", "aGVsbG8gd29ybGQgaGVsbG8gd29ybGQgaGVsbG8gd29ybGQ=", 1000); fail() } catch (_: IllegalArgumentException) { }
    }

    @Test fun toolSecAesBoxRoundTrips() {
        val enc = run("sec_aes_box", "m" to "암호화 (AES-GCM, 권장)", "pw" to "pw-1234", "t" to "안녕 secret"); val token = enc.blocks().lines().first { it.startsWith("scbox1.") }
        assertEquals("안녕 secret", run("sec_aes_box", "m" to "복호화 (AES-GCM)", "pw" to "pw-1234", "t" to token).blocks().lines().single())
        val wrong = run("sec_aes_box", "m" to "복호화 (AES-GCM)", "pw" to "nope", "t" to token); assertTrue(wrong.hasError); assertTrue(wrong.text().contains("비밀번호가 틀렸거나"))
        val cbc = run("sec_aes_box", "m" to "암호화 (openssl 호환 CBC)", "pw" to "pw-1234", "t" to "hello", "iter" to "5000"); val b64 = cbc.blocks().lines().first { it.startsWith("U2FsdGVkX1") }
        assertTrue(cbc.blocks().contains("openssl enc -d -aes-256-cbc -pbkdf2 -iter 5000 -a -A")); assertEquals("hello", run("sec_aes_box", "m" to "복호화 (openssl 호환 CBC)", "pw" to "pw-1234", "t" to b64, "iter" to "5000").blocks().lines().single())
        assertTrue(run("sec_aes_box", "m" to "복호화 (AES-GCM)", "pw" to "x", "t" to "garbage").hasError); assertTrue(run("sec_aes_box", "pw" to "", "t" to "x").text().contains("입력하세요"))
    }

    private fun parts(t: String) = t.split('.')

    @Test fun jwtSignaturesVerifyForAllAlgorithms() {
        for ((alg, key, token) in SecVectors.jwtHs.map { Triple(it[0], it[1], it[2]) }) {
            assertTrue(alg, JwtVerify.verify(token, key).ok); assertEquals(alg, JwtVerify.verify(token, key).detail)
            assertFalse(JwtVerify.verify(token, "other-key").ok)
            val tampered = parts(token).let { listOf(it[0], Base64.getUrlEncoder().withoutPadding().encodeToString("{\"sub\":\"evil\"}".toByteArray()), it[2]) }.joinToString("."); assertFalse(JwtVerify.verify(tampered, key).ok)
            assertTrue(JwtVerify.verify("Bearer $token", key).ok)
        }
        assertTrue(JwtVerify.verify(SecVectors.jwtHs[0][2], "{\"kty\":\"oct\",\"k\":\"${Base64.getUrlEncoder().withoutPadding().encodeToString("super-secret-key".toByteArray())}\"}").ok)     // JWK 로 비밀키 주기
        for ((alg, token) in SecVectors.jwtRs.map { it[0] to it[1] }) { assertTrue(alg, JwtVerify.verify(token, SecVectors.rsaPem).ok); assertTrue(JwtVerify.verify(token, SecVectors.rsaJwk).ok) }
        assertFalse(JwtVerify.verify(SecVectors.jwtRs[0][1], SecVectors.jwtEs[0][3]).ok)                                       // RS 토큰에 EC 키
        for ((alg, token, jwk, pem) in SecVectors.jwtEs.map { Quad(it[0], it[1], it[2], it[3]) }) {
            assertTrue(alg, JwtVerify.verify(token, jwk).ok); assertTrue(JwtVerify.verify(token, pem).ok)
            val bad = parts(token).let { it[0] + "." + it[1] + "." + it[2].reversed() }; assertFalse(JwtVerify.verify(bad, jwk).ok)
        }
        val none = parts(SecVectors.jwtHs[0][2]).let { Base64.getUrlEncoder().withoutPadding().encodeToString("{\"alg\":\"none\"}".toByteArray()) + "." + it[1] + "." }; assertTrue(JwtVerify.verify(none, "x").detail.contains("alg=none")); assertFalse(JwtVerify.verify(none, "x").ok)
        assertFalse(JwtVerify.verify("a.b", "x").ok); assertFalse(JwtVerify.verify("not.a.jwt", "x").ok); assertFalse(JwtVerify.verify(SecVectors.jwtHs[0][2], "").ok)
        val ps = Base64.getUrlEncoder().withoutPadding().encodeToString("{\"alg\":\"PS256\"}".toByteArray()) + ".e30.c2ln"; assertTrue(JwtVerify.verify(ps, "x").detail.contains("PS256"))
        // 도구
        val ok = run("sec_jwt_verify", "t" to SecVectors.jwtHs[0][2], "k" to "super-secret-key"); assertTrue(ok.kv("서명").startsWith("올바른")); assertEquals("HS256", ok.kv("알고리즘")); assertFalse(ok.hasError); assertTrue(ok.kv("만료(exp)").contains("까지"))
        val no = run("sec_jwt_verify", "t" to SecVectors.jwtHs[0][2], "k" to "wrong"); assertEquals(2, no.kvLevel("서명")); assertTrue(no.hasError)
        assertTrue(run("sec_jwt_verify", "t" to "", "k" to "x").text().contains("입력하세요")); assertTrue(run("sec_jwt_verify", "t" to SecVectors.jwtHs[0][2], "k" to "").text().contains("입력하세요"))
    }

    @Test fun toolSecSshFingerprintReadsKeys() {
        val r = run("sec_ssh_fingerprint"); assertEquals("SHA256:+DiY3wvvV6TuJJhbpZisF/zLDA0zPMSvHdkr4UvCOqU", r.kv("SHA256 지문")); assertEquals("Ed25519 (256비트)", r.kv("크기")); assertEquals(-1, r.kvLevel("크기")); assertFalse(r.hasError)
        val multi = SecVectors.ssh.filter { it[0] == "rsa1024" || it[0] == "rsa2048" || it[0] == "p256" }.joinToString("\n") { it[1] } + "\n# 주석 줄\nnot a key"
        val m = run("sec_ssh_fingerprint", "k" to multi)
        assertEquals(listOf("RSA 2048비트", "RSA 1024비트", "ECDSA P-256"), m.kvAll("크기")); assertEquals(0, m.outs.filterIsInstance<Out.Kv>().first { it.value == "RSA 2048비트" }.level); assertEquals(2, m.outs.filterIsInstance<Out.Kv>().first { it.value == "RSA 1024비트" }.level)
        assertTrue(m.hasError); assertTrue(m.text().contains("읽지 못한 줄: not a key")); assertTrue(m.text().contains("이 키는 약해서")); assertEquals(3, m.kvAll("SHA256 지문").size)
        assertTrue(run("sec_ssh_fingerprint", "k" to "").text().contains("붙여 넣으세요"))
    }

    @Test fun toolSecEntropyAndOtpauth() {
        assertEquals("0.000 비트/바이트 (최대 8)", run("sec_entropy", "t" to "a".repeat(100)).kv("엔트로피")); assertEquals(1, run("sec_entropy", "t" to "a".repeat(100)).kvLevel("판단"))
        val rnd = ByteArray(4096).also { SecureRandom().nextBytes(it) }; val fh = object : TestHost() { override fun file(key: String) = if (key == "f") FileRef("r.bin", rnd.size.toLong()) { rnd.inputStream() } else null }
        val e = run("sec_entropy", host = fh); assertTrue(e.kv("엔트로피"), e.kv("엔트로피").substringBefore(' ').toDouble() > 7.9); assertTrue(e.kv("판단").startsWith("거의 완전한 무작위")); assertEquals("4,096바이트", e.kv("크기"))
        assertEquals("8.000 비트/바이트 (최대 8)", run("sec_entropy", host = object : TestHost() { override fun file(key: String) = if (key == "f") FileRef("u.bin", 256) { ByteArray(256) { it.toByte() }.inputStream() } else null }).kv("엔트로피"))
        assertTrue(run("sec_entropy", "t" to "짧음").kv("판단").contains("너무 짧아서"))
        val o = run("sec_otpauth"); assertEquals("Example", o.kv("발급처")); assertEquals("alice@example.com", o.kv("계정")); assertEquals("JBSWY3DPEHPK3PXP", o.kv("비밀키(Base32)")); assertEquals("TOTP (시간 기반)", o.kv("종류")); assertEquals("30초", o.kv("주기"))
        val now = System.currentTimeMillis() / 1000; val key = Base32.decode("JBSWY3DPEHPK3PXP")!!; assertTrue(o.kv("지금 코드") in listOf(now - 1, now, now + 1).map { Totp.at(key, it, 30, 6, "HmacSHA1") })
        val custom = run("sec_otpauth", "u" to "otpauth://totp/Corp%3Abob?secret=jbsw y3dp ehpk 3pxp&issuer=Corp&algorithm=SHA256&digits=8&period=60"); assertEquals("Corp", custom.kv("발급처")); assertEquals("bob", custom.kv("계정")); assertEquals("SHA256", custom.kv("알고리즘")); assertEquals(8, custom.kv("지금 코드").length); assertTrue(custom.text().contains("기본값(SHA1·6자리·30초)이 아니에요"))
        val hotp = run("sec_otpauth", "u" to "otpauth://hotp/Svc:me?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ&counter=3&issuer=Svc"); assertEquals("HOTP (횟수 기반)", hotp.kv("종류")); assertEquals("969429", hotp.kv("코드(카운터 3)"))          // RFC 4226 부록 D (카운터 3)
        assertTrue(run("sec_otpauth", "u" to "otpauth://totp/x?secret=!!!").hasError); assertTrue(run("sec_otpauth", "u" to "https://example.com").hasError); assertTrue(run("sec_otpauth", "u" to "otpauth://totp/x?secret=JBSWY3DPEHPK3PXP&algorithm=MD5").hasError)
    }
}
