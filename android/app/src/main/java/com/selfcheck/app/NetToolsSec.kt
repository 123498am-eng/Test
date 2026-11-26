package com.selfcheck.app

import org.json.JSONObject
import java.io.IOException
import java.net.URLDecoder
import java.time.Instant
import java.util.Base64

/**
 * 보안 점검 도구 14가지: 비밀번호·키·토큰·주소·설정 글을 휴대폰 안에서만 계산해요.
 * (비밀번호 유출 확인만 인터넷을 쓰고, 비밀번호 자체가 아니라 SHA-1 해시 앞 5글자만 보내요.)
 */
object SecTools {
    private const val S = NetGroups.SEC

    /** 글자를 바꿀 때마다 돌리지 않고 버튼으로만 실행 (시간이 걸리거나 무작위가 들어가는 도구) */
    private fun NetTool.manual(label: String = "계산") = NetTool(id, group, title, desc, fields, mode, note, confirm, false, false, label, run)

    private fun hex(b: ByteArray) = Hashes.hex(b)
    private const val NOTE_LOCAL = "입력한 내용은 휴대폰 밖으로 나가지 않아요."

    private val CVSS_CHIPS = listOf(
        "10.0 치명적 (Log4Shell)" to "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H", "9.8 원격 코드 실행" to "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        "7.5 정보 유출 (Heartbleed)" to "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N", "6.1 반사형 XSS" to "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N", "7.8 로컬 권한 상승" to "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H")

    private fun fileText(host: ToolHost, key: String, max: Int = 5_000_000): String? {
        val f = host.file(key) ?: return null
        val ins = f.open() ?: return null
        return ins.use { s -> val b = s.readNBytes(max); strictUtf8(b) ?: String(b, Charsets.ISO_8859_1) }
    }

    val ALL: List<NetTool> = listOf(
        calc("sec_wpa_psk", S, "Wi-Fi 암호 → WPA PSK (64자리 키)", "Wi-Fi 이름(SSID)과 암호로 WPA/WPA2 가 실제로 쓰는 256비트 키(PSK)를 계산해요 — 공유기·wpa_supplicant 설정에 그대로 넣을 수 있어요",
            text("ssid", "Wi-Fi 이름 (SSID)", "예: MyHome", "IEEE"), text("pass", "Wi-Fi 암호", "8~63글자", "password")) { i ->
            val ssid = i.raw("ssid"); val pass = i.raw("pass")
            if (ssid.isEmpty() || pass.isEmpty()) return@calc need("Wi-Fi 이름과 암호를 입력하세요")
            val probs = WpaPsk.problems(pass, ssid)
            if (probs.any { it.second == 2 }) return@calc result { probs.forEach { note(it.first, it.second) } }
            val psk = hex(WpaPsk.psk(pass, ssid))
            result {
                kv("SSID", ssid); kv("PSK (64자리 16진수)", psk, -1)
                head("wpa_supplicant.conf"); block("network={\n    ssid=\"$ssid\"\n    psk=$psk\n}")
                head("hostapd.conf"); block("ssid=$ssid\nwpa=2\nwpa_psk=$psk")
                probs.forEach { note(it.first, it.second) }
                note("PBKDF2-HMAC-SHA1 을 4096번 돌린 값이에요(IEEE 802.11i). SSID 가 솔트라서 같은 암호라도 이름이 다르면 키가 달라요. 키를 아는 사람은 암호 없이도 접속할 수 있으니 암호처럼 다루세요. $NOTE_LOCAL")
            }
        }.manual(),

        calc("sec_password_check", S, "비밀번호 강도 점검 (예상 해독 시간)", "비밀번호의 글자 종류·반복·연속·키보드 패턴을 보고 복잡도(비트)와 공격자가 맞히는 데 걸리는 평균 시간을 계산해요",
            text("pw", "비밀번호", "입력한 글자는 휴대폰 밖으로 나가지 않아요", "")) { i ->
            val pw = i.raw("pw"); if (pw.isEmpty()) return@calc need("비밀번호를 입력하세요")
            val r = PasswordStrength.analyze(pw)
            result {
                kv("강도", r.label, listOf(2, 2, 1, -1, -1)[r.level]); kv("길이", "${r.length}글자"); kv("쓴 글자 종류", r.classes.joinToString(" · ")); kv("예상 복잡도", "%.0f비트 (패턴을 고려하기 전 %.0f비트)".format(r.bits, r.naiveBits))
                if (r.patterns.isNotEmpty()) { head("추측하기 쉬운 패턴"); r.patterns.forEach { note(it, 1) } }
                head("평균 해독 시간 (가능한 경우의 절반을 시도)"); header("공격 상황", "걸리는 시간")
                row("로그인 창에 초당 10번 대입", PasswordStrength.human(PasswordStrength.seconds(r.bits, 10.0)))
                row("느린 해시(bcrypt 등)가 유출 · 초당 1만 번", PasswordStrength.human(PasswordStrength.seconds(r.bits, 1e4)))
                row("약한 해시(MD5·SHA-1)가 유출 · GPU 초당 100억 번", PasswordStrength.human(PasswordStrength.seconds(r.bits, 1e10)))
                if (r.length < 12) note("12글자 이상으로 늘리는 것이 가장 효과적이에요. 길이가 1글자 늘 때마다 대략 ${"%.1f".format(kotlin.math.log2(maxOf(r.pool, 2).toDouble()))}비트씩 늘어요.", 1)
                note("이 점수는 글자 구조만 본 추정이에요. 사람이 흔히 쓰는 단어·이름·생일 같은 건 구조가 복잡해도 사전 공격에 빨리 뚫려요 — 실제로 유출된 적이 있는지는 '유출 비밀번호 확인' 으로 확인하세요. 같은 비밀번호를 여러 사이트에 쓰지 않는 것도 중요해요. $NOTE_LOCAL")
            }
        },

        online("sec_pwned_range", S, "유출 비밀번호 확인 (Have I Been Pwned)", "이 비밀번호가 지금까지 알려진 유출 사고에 나온 적이 있는지 — 비밀번호 자체는 보내지 않고 해시 앞 5글자만 보내는 방식(k-익명성)",
            text("pw", "확인할 비밀번호", "", ""),
            note = "비밀번호의 SHA-1 해시 앞 5글자만 api.pwnedpasswords.com 에 보내요. 서버는 그 5글자로 시작하는 수백 개 후보를 돌려주고, 일치 여부는 이 폰에서 가려내요. 인터넷을 사용해요.") { i, _, env ->
            val pw = i.raw("pw"); if (pw.isEmpty()) return@online need("비밀번호를 입력하세요")
            val sha = Hibp.sha1Hex(pw); val prefix = sha.take(5); val suffix = sha.drop(5)
            env.progress("조회하는 중...")
            val body = try { GeoNet.get("https://api.pwnedpasswords.com/range/$prefix", 9000, 400_000, mapOf("Add-Padding" to "true")) } catch (e: IOException) { return@online fail("조회하지 못했어요: ${e.message}") }
            val n = Hibp.count(body, suffix)
            result {
                kv("보낸 해시 앞부분", prefix); kv("받은 후보 수", "${body.lines().count { it.contains(':') }}개")
                if (n == null) { kv("결과", "유출 목록에서 찾지 못했어요", -1); note("목록에 없다고 안전한 비밀번호라는 뜻은 아니에요. 길고 무작위한 비밀번호를 비밀번호 관리자로 만들어 쓰고, 사이트마다 다르게 쓰세요.", 0) }
                else { kv("결과", "${"%,d".format(n)}번 유출된 비밀번호예요", 2); note("공격자들의 사전에 들어 있는 비밀번호라서 몇 초 안에 뚫려요. 이 비밀번호를 쓰는 모든 계정에서 바꾸세요.", 2) }
            }
        },

        calc("sec_pbkdf2", S, "PBKDF2 키 만들기", "비밀번호와 솔트로 키를 늘려 만드는 PBKDF2 (RFC 8018) — 비밀번호 저장·키 유도 설정 확인·다른 프로그램 결과와 비교할 때",
            choice("alg", "해시", listOf("HMAC-SHA256", "HMAC-SHA1", "HMAC-SHA512"), "HMAC-SHA256"), text("pw", "비밀번호", "", "password"), text("salt", "솔트", "", "salt"), choice("fmt", "솔트 형식", listOf("글자", "16진수")),
            text("iter", "반복 횟수", "1 ~ 2,000,000", "100000"), text("len", "만들 키 길이(바이트)", "1 ~ 128", "32")) { i ->
            val iter = i.int("iter") ?: return@calc fail("반복 횟수를 숫자로 입력하세요"); val len = i.int("len") ?: return@calc fail("키 길이를 숫자로 입력하세요")
            if (iter !in 1..2_000_000) return@calc fail("반복 횟수는 1 ~ 2,000,000 이에요 (휴대폰이 오래 멈추지 않게 제한했어요)"); if (len !in 1..128) return@calc fail("키 길이는 1 ~ 128 바이트예요")
            val salt = if (i.str("fmt") == "16진수") (ServerTools.parseHex(i.str("salt")) ?: return@calc fail("솔트가 16진수가 아니에요 (0-9, a-f 로 짝수 글자)")) else i.raw("salt").toByteArray()
            val alg = "Hmac" + i.str("alg").removePrefix("HMAC-").replace("SHA", "SHA")
            val t0 = System.nanoTime(); val dk = Pbkdf2.derive(alg, i.raw("pw").toByteArray(), salt, iter, len); val ms = (System.nanoTime() - t0) / 1_000_000
            result { kv("16진수", hex(dk), -1); kv("Base64", Base64.getEncoder().encodeToString(dk)); kv("걸린 시간", "${ms}ms"); note("같은 입력이면 어느 프로그램에서든 같은 값이 나와야 해요(RFC 6070 등 시험값으로 확인했어요). 비밀번호 저장에는 반복 횟수를 크게(SHA-256 기준 60만 번 이상 권장, OWASP) 하고 솔트는 사용자마다 무작위로 쓰세요. $NOTE_LOCAL") }
        }.manual(),

        calc("sec_htpasswd", S, "htpasswd 비밀번호 줄 만들기", "아파치·nginx 기본 인증(.htpasswd)에 넣을 \"아이디:해시\" 줄 — Apache MD5(apr1)·SHA-512/256 crypt·{SHA}",
            text("user", "아이디", "", "admin"), text("pw", "비밀번호", "", "secret"),
            choice("fmt", "해시 방식", listOf("Apache MD5 (apr1)", "SHA-512 crypt (\$6\$)", "SHA-256 crypt (\$5\$)", "MD5 crypt (\$1\$, 낡음)", "{SHA} (약함, 비권장)")), text("salt", "솔트 (선택)", "비우면 무작위", "")) { i ->
            val user = i.str("user"); val pw = i.raw("pw"); if (user.isEmpty() || pw.isEmpty()) return@calc need("아이디와 비밀번호를 입력하세요")
            if (':' in user) return@calc fail("아이디에는 콜론(:)을 쓸 수 없어요")
            val f = i.choice("fmt", listOf("Apache MD5 (apr1)", "SHA-512 crypt (\$6\$)", "SHA-256 crypt (\$5\$)", "MD5 crypt (\$1\$, 낡음)", "{SHA} (약함, 비권장)"))
            val salt = i.str("salt").takeIf { it.isNotEmpty() }
            if (salt != null && salt.any { it !in UnixCrypt.SALT_CHARS }) return@calc fail("솔트는 영문·숫자·점(.)·슬래시(/) 만 쓸 수 있어요")
            val bytes = pw.toByteArray()
            val h = when (f) {
                0 -> UnixCrypt.md5(bytes, salt ?: UnixCrypt.randomSalt(8), "\$apr1\$")
                1 -> UnixCrypt.sha(bytes, salt ?: UnixCrypt.randomSalt(16), true)
                2 -> UnixCrypt.sha(bytes, salt ?: UnixCrypt.randomSalt(16), false)
                3 -> UnixCrypt.md5(bytes, salt ?: UnixCrypt.randomSalt(8), "\$1\$")
                else -> UnixCrypt.htpasswdSha1(bytes)
            }
            result {
                head(".htpasswd 에 넣을 줄"); block("$user:$h")
                kv("아이디", user); kv("해시", h)
                if (f == 4) note("{SHA} 는 솔트가 없는 SHA-1 이라 같은 비밀번호는 같은 값이고 사전 공격에 약해요. 가능하면 apr1 이나 bcrypt(htpasswd -B)를 쓰세요.", 2)
                else if (f == 0 || f == 3) note("MD5 기반 해시는 1000번 반복이라 요즘 GPU 에는 약해요. 서버에서 htpasswd -B(bcrypt)를 쓸 수 있으면 그쪽이 더 안전해요.", 1)
                else note("SHA-crypt 는 기본 5000번 반복이에요. 아파치 htpasswd 는 apr1·bcrypt 만 받으므로, 이 해시는 nginx·리눅스 crypt() 를 쓰는 서버에서 쓰세요.", 0)
                head("nginx 설정"); block("auth_basic \"Restricted\";\nauth_basic_user_file /etc/nginx/.htpasswd;")
                note("같은 비밀번호도 솔트가 무작위라 만들 때마다 다른 줄이 나와요(모두 맞는 값). $NOTE_LOCAL")
            }
        }.manual("만들기"),

        calc("sec_jwt_verify", S, "JWT 서명 확인", "HS256/384/512(공유 비밀키)·RS256/384/512(RSA 공개키)·ES256/384/512(타원곡선 공개키)로 JWT 서명이 맞는지 확인",
            multi("t", "JWT", "xxxxx.yyyyy.zzzzz", ""), multi("k", "비밀키 또는 공개키", "HS 는 비밀키 글자, RS·ES 는 PEM(PUBLIC KEY·CERTIFICATE) 또는 JWK(JSON)", "")) { i ->
            val t = i.str("t"); val k = i.raw("k"); if (t.isEmpty()) return@calc need("JWT 를 입력하세요"); if (k.isBlank()) return@calc need("비밀키 또는 공개키를 입력하세요")
            val r = JwtVerify.verify(t, k)
            val payload = runCatching { JSONObject(String(Base64.getUrlDecoder().decode(t.removePrefix("Bearer ").trim().split('.')[1].trimEnd('=')))) }.getOrNull()
            result {
                kv("알고리즘", r.detail.takeIf { r.ok } ?: "-"); kv("서명", if (r.ok) "올바른 서명이에요 ✔" else "확인하지 못했어요 ✘", if (r.ok) -1 else 2)
                if (!r.ok) note(if (r.detail.length > 4 && !r.detail.startsWith("HS") && !r.detail.startsWith("RS") && !r.detail.startsWith("ES")) r.detail else "서명이 맞지 않아요: 키가 다르거나, 헤더·내용이 바뀌었거나, 위조된 토큰일 수 있어요. 공백·줄바꿈이 키에 섞이지 않았는지도 확인하세요.", 2)
                val now = System.currentTimeMillis() / 1000
                payload?.optLong("exp", 0)?.takeIf { it > 0 }?.let { kv("만료(exp)", if (it < now) "이미 만료됨 (${Instant.ofEpochSecond(it)})" else "${Instant.ofEpochSecond(it)} 까지", if (it < now) 2 else -1) }
                payload?.optLong("nbf", 0)?.takeIf { it > 0 }?.let { if (it > now) kv("사용 시작(nbf)", "아직 유효하지 않음 (${Instant.ofEpochSecond(it)})", 1) }
                note("서명이 맞다는 것은 \"이 키를 가진 쪽이 만들었다\"는 뜻일 뿐이에요. 서버는 alg 를 토큰이 아니라 서버 설정으로 고정하고, exp·aud·iss 도 함께 확인해야 해요. $NOTE_LOCAL")
            }
        },

        calc("sec_ssh_fingerprint", S, "SSH 공개키 지문 확인", "authorized_keys·known_hosts·id_*.pub 의 공개키 줄로 지문(SHA256·MD5)·종류·키 길이를 보고, 약한 키(짧은 RSA·DSA)를 찾아요",
            multi("k", "공개키 (여러 줄 가능)", "ssh-ed25519 AAAA… 주석", "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqKLsabgH5C9okWi0dh2l9GKJl github.com")) { i ->
            val lines = i.lines("k").filter { !it.startsWith("#") }; if (lines.isEmpty()) return@calc need("공개키를 붙여 넣으세요")
            val bad = ArrayList<String>(); var n = 0
            result {
                for (l in lines.take(50)) {
                    val k = try { SshKey.parse(l) } catch (e: IllegalArgumentException) { bad += "${l.take(40)}… → ${e.message}"; continue }
                    n++; head("키 $n${if (k.comment.isNotEmpty()) " · ${k.comment}" else ""}")
                    val weak = when { k.type == "ssh-dss" -> 2; k.bits.startsWith("RSA") && (Regex("(\\d+)").find(k.bits)?.value?.toInt() ?: 0) < 2048 -> 2; k.bits.startsWith("RSA") && (Regex("(\\d+)").find(k.bits)?.value?.toInt() ?: 0) < 3072 -> 0; else -> -1 }
                    kv("종류", k.type); kv("크기", k.bits, weak); kv("SHA256 지문", k.sha256); kv("MD5 지문", k.md5); if (k.options.isNotEmpty()) kv("옵션", k.options.take(120))
                    if (weak == 2) note("이 키는 약해서 쓰면 안 돼요. Ed25519 키로 바꾸세요 (ssh-keygen -t ed25519).", 2)
                }
                bad.forEach { note("읽지 못한 줄: $it", 2) }
                if (n == 0 && bad.isEmpty()) note("공개키를 찾지 못했어요", 1)
                note("서버에 처음 접속할 때 나오는 지문(SHA256:…)을 서버 관리자가 알려 준 값과 비교하세요. 다르면 중간자 공격일 수 있으니 접속하지 마세요. $NOTE_LOCAL")
            }
        },

        calc("sec_cvss", S, "CVSS 취약점 점수 계산 (3.0·3.1)", "CVSS 벡터(CVSS:3.1/AV:N/AC:L/…)로 기본 점수와 위험도를 계산하고 항목마다 뜻을 풀어 줘요 — 보안 공지의 점수를 직접 확인할 때",
            text("v", "CVSS 벡터", "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", CVSS_CHIPS)) { i ->
            val v = i.str("v"); if (v.isEmpty()) return@calc need("CVSS 벡터를 입력하세요")
            val r = try { Cvss.parse(v) } catch (e: IllegalArgumentException) { return@calc fail(e.message ?: "벡터를 읽지 못했어요") }
            result {
                kv("기본 점수", "%.1f / 10  (${r.severity})".format(r.score), when { r.score >= 9.0 -> 2; r.score >= 7.0 -> 2; r.score >= 4.0 -> 1; r.score > 0 -> 0; else -> -1 })
                kv("버전", "CVSS ${r.version}"); kv("악용 용이성 점수", "%.1f".format(r.exploitability)); kv("영향 점수", "%.1f".format(r.impact))
                head("항목 풀이"); header("항목", "값"); for ((k, d) in r.parts) row(k, d)
                note("기본(Base) 점수는 취약점 자체의 심각도만 나타내요. 우리 시스템에서의 실제 위험은 노출 여부·패치 여부·악용 코드 존재 여부(Temporal·Environmental)에 따라 달라서, 점수가 높아도 외부에 안 열려 있으면 급하지 않을 수 있고 점수가 중간이어도 인터넷에 노출돼 있으면 서둘러야 해요.")
            }
        },

        calc("sec_csp_check", S, "Content-Security-Policy 점검", "CSP 헤더를 붙여 넣으면 unsafe-inline·와일드카드·누락된 object-src/base-uri/frame-ancestors 같은 약점을 찾아 줘요",
            multi("p", "CSP 정책", "default-src 'self'; script-src 'self' …", "default-src 'self'; script-src 'self' 'unsafe-inline' https://cdn.example.com; img-src * data:; object-src 'none'")) { i ->
            val p = i.raw("p"); if (p.isBlank()) return@calc need("CSP 정책을 붙여 넣으세요")
            val dirs = CspCheck.parse(p); val f = CspCheck.analyze(p)
            result {
                kv("지시어", "${dirs.size}개"); kv("점검 결과", "위험 ${f.count { it.level == 2 }} · 주의 ${f.count { it.level == 1 }} · 참고 ${f.count { it.level == 0 }}", if (f.any { it.level == 2 }) 2 else if (f.any { it.level == 1 }) 1 else -1)
                head("지시어"); header("지시어", "허용 출처"); for ((k, v) in dirs) row(k, v.joinToString(" ").ifEmpty { "(값 없음)" }.take(120))
                head("점검"); for (x in f.sortedByDescending { it.level }) note(x.text, x.level)
                note("CSP 는 XSS 피해를 줄여 주는 두 번째 방어선이에요. 처음에는 Content-Security-Policy-Report-Only 로 위반 보고만 받아 보고, 문제없을 때 강제로 바꾸세요. $NOTE_LOCAL")
            }
        },

        calc("sec_url_inspect", S, "수상한 주소(URL) 점검", "문자 메시지·메일의 링크가 피싱 수법을 쓰는지 — @ 속임수·IP 숨김·한 글자 차이 도메인·키릴 문자 위장·브랜드 이름 끼워넣기·단축 주소 (링크를 열지 않고 글자만 분석)",
            multi("u", "주소 (한 줄에 하나, 최대 30개)", "https://…", "https://www.paypal.com.secure-login.example.xyz/verify?next=http://x.example\nhttp://3232235777/login\nhttps://naver.com")) { i ->
            val urls = i.lines("u").take(30); if (urls.isEmpty()) return@calc need("주소를 입력하세요")
            result {
                if (urls.size == 1) {
                    val (p, f) = UrlInspect.analyze(urls[0])
                    if (p != null) { kv("방식", p.scheme); kv("접속하는 곳(호스트)", p.host.ifEmpty { "-" }, if (p.userinfo != null) 2 else 0); p.userinfo?.let { kv("@ 앞부분", it, 2) }; p.port?.let { kv("포트", "$it") }; kv("경로", p.path.ifEmpty { "/" }.take(100)); p.query?.let { kv("쿼리", it.take(100)) } }
                    head("점검"); f.forEach { note(it.text, it.level) }
                } else {
                    header("주소", "판정", "가장 큰 이유")
                    for (u in urls) { val (_, f) = UrlInspect.analyze(u); val w = f.first(); row(u.take(60), when (w.level) { 2 -> "위험"; 1 -> "주의"; -1 -> "특이점 없음"; else -> "참고" }, w.text.take(80), level = w.level) }
                }
                note("글자만 분석해요: 주소로 접속하지 않아서 사이트가 실제로 안전한지는 알 수 없어요. \"특이점 없음\"이어도 모르는 사람이 보낸 링크는 열지 말고, 은행·택배는 앱이나 직접 입력한 주소로 확인하세요. $NOTE_LOCAL")
            }
        },

        tool("sec_secret_scan", S, "비밀 노출 검사 (키·토큰·비밀번호)", "코드·설정·로그·메모에 AWS/GitHub/Slack 키, 개인키, 주소 속 비밀번호, password= 설정값이 섞여 있는지 찾아 — 값은 가려서(앞 4글자만) 보여 줘요",
            listOf(multi("t", "검사할 글", "코드·설정 파일 내용을 붙여 넣으세요", ""), file("f", "또는 파일 (선택)")), ToolMode.OFFLINE, NOTE_LOCAL, runLabel = "검사") { i, host, _ ->
            val text = fileText(host, "f") ?: i.raw("t"); if (text.isBlank()) return@tool need("글을 붙여 넣거나 파일을 고르세요")
            val hits = SecretScan.scan(text)
            result {
                kv("검사한 글", "${text.lines().size}줄 · ${"%,d".format(text.length)}글자"); kv("발견", if (hits.isEmpty()) "없음" else "${hits.size}건 (위험 ${hits.count { it.level == 2 }} · 주의 ${hits.count { it.level == 1 }})", if (hits.any { it.level == 2 }) 2 else if (hits.isNotEmpty()) 1 else -1)
                if (hits.isEmpty()) note("알려진 키·토큰 모양을 찾지 못했어요. (모든 종류를 찾는 건 아니에요 — 회사 내부 형식·무작위 문자열은 놓칠 수 있어요.)", -1)
                else {
                    header("줄", "종류", "내용(가림)"); for (h in hits.take(200)) row("${h.line}", h.kind, h.preview, level = h.level)
                    head("조치"); for ((k, hs) in hits.groupBy { it.kind }) note("$k ${hs.size}건: ${hs.first().advice}", hs.maxOf { it.level })
                    note("저장소(Git)에 이미 올렸다면 지워도 기록에 남아 있어요: 값을 폐기·재발급하는 것이 먼저예요. 이후에는 .env·비밀 저장소(Secrets Manager 등)로 옮기세요.", 1)
                }
            }
        },

        calc("sec_aes_box", S, "비밀번호로 글 암호화·복호화 (AES-256)", "민감한 메모를 비밀번호로 암호화해서 메신저·메일에 붙여 보내고, 받은 쪽이 같은 비밀번호로 풀기 — AES-256-GCM(권장) 또는 openssl 과 호환되는 CBC",
            choice("m", "동작", listOf("암호화 (AES-GCM, 권장)", "복호화 (AES-GCM)", "암호화 (openssl 호환 CBC)", "복호화 (openssl 호환 CBC)")), text("pw", "비밀번호", "길고 무작위할수록 안전해요", ""), multi("t", "글 또는 암호문", "", ""),
            text("iter", "반복 횟수 (CBC 일 때, openssl -iter 값)", "", "10000")) { i ->
            val m = i.choice("m", listOf("암호화 (AES-GCM, 권장)", "복호화 (AES-GCM)", "암호화 (openssl 호환 CBC)", "복호화 (openssl 호환 CBC)")); val pw = i.raw("pw"); val t = i.raw("t")
            if (pw.isEmpty() || t.isBlank()) return@calc need("비밀번호와 글(또는 암호문)을 입력하세요")
            val iter = i.int("iter")?.takeIf { it in 1000..1_000_000 } ?: 10000
            try {
                when (m) {
                    0 -> { val tk = AesBox.encryptGcm(pw, t.toByteArray(Charsets.UTF_8)); result { head("암호문 (이 줄 전체를 보내세요)"); block(tk); note("AES-256-GCM · 키는 PBKDF2-HMAC-SHA256 200,000번으로 비밀번호에서 만들어요. 내용이 한 글자라도 바뀌면 복호화가 거부돼요. 비밀번호는 메신저로 같이 보내지 말고 따로 알려 주세요. $NOTE_LOCAL") } }
                    1 -> { val p = AesBox.decryptGcm(pw, t); result { head("복호화한 글"); block(String(p, Charsets.UTF_8), false); note("비밀번호가 맞고 내용이 바뀌지 않았어요 ✔", -1) } }
                    2 -> { val b = AesBox.encryptOpenssl(pw, t.toByteArray(Charsets.UTF_8), iter); result { head("암호문 (Base64 한 줄)"); block(b); head("컴퓨터에서 풀기"); block("echo '$b' | openssl enc -d -aes-256-cbc -pbkdf2 -iter $iter -a -A"); note("openssl enc 형식(AES-256-CBC, PBKDF2-SHA256)이라 컴퓨터에서 바로 풀 수 있어요. 다만 CBC 는 내용이 바뀌었는지 확인해 주지 못해요(무결성 없음) — 가능하면 GCM 을 쓰세요. $NOTE_LOCAL", 1) } }
                    else -> { val p = AesBox.decryptOpenssl(pw, t, iter); result { head("복호화한 글"); block(String(p, Charsets.UTF_8), false); note("복호화됐어요. CBC 는 비밀번호가 틀려도 깨진 글이 나올 수 있으니 내용이 정상인지 직접 확인하세요.", 1) } }
                }
            } catch (e: javax.crypto.AEADBadTagException) { fail("복호화하지 못했어요: 비밀번호가 틀렸거나 암호문이 바뀌었어요")
            } catch (e: javax.crypto.BadPaddingException) { fail("복호화하지 못했어요: 비밀번호나 반복 횟수가 맞지 않아요")
            } catch (e: IllegalArgumentException) { fail(e.message ?: "암호문을 읽지 못했어요")
            } catch (e: Exception) { fail("처리하지 못했어요: ${e.javaClass.simpleName}") }
        }.manual("실행"),

        tool("sec_entropy", S, "무작위 정도(엔트로피) 측정", "글이나 파일이 얼마나 무작위처럼 보이는지 — 암호화·압축된 데이터와 평범한 글을 구분하고, 키·토큰이 충분히 무작위인지 확인",
            listOf(multi("t", "글", "", ""), file("f", "또는 파일 (선택)")), ToolMode.OFFLINE, NOTE_LOCAL, live = true, runLabel = "측정") { i, host, _ ->
            val f = host.file("f")
            val data: ByteArray = if (f != null) (f.open()?.use { it.readNBytes(8_000_000) } ?: return@tool fail("파일을 열 수 없어요")) else i.raw("t").toByteArray(Charsets.UTF_8)
            if (data.isEmpty()) return@tool need("글을 입력하거나 파일을 고르세요")
            val counts = IntArray(256); for (b in data) counts[b.toInt() and 0xff]++
            val h = counts.filter { it > 0 }.sumOf { c -> val p = c.toDouble() / data.size; p * kotlin.math.log2(1.0 / p) }
            val unique = counts.count { it > 0 }
            result {
                kv("크기", "%,d바이트".format(data.size)); kv("서로 다른 바이트", "$unique 가지"); kv("엔트로피", "%.3f 비트/바이트 (최대 8)".format(h)); kv("총 정보량(이론상 최대)", "%,.0f비트".format(h * data.size))
                val (label, lv) = when { data.size < 32 -> "너무 짧아서 판단하기 어려워요" to 0; h >= 7.5 -> "거의 완전한 무작위 (암호화·압축된 데이터, 또는 무작위 키)" to -1; h >= 6.0 -> "꽤 무작위 (Base64·압축 일부·바이너리)" to 0; h >= 3.5 -> "일반적인 글·프로그램 코드 수준" to 0; else -> "반복이 많은 단순한 데이터" to 1 }
                kv("판단", label, lv)
                note("이 값은 \"글자가 얼마나 고르게 나오는가\"만 보는 통계예요. 엔트로피가 높다고 안전한 비밀번호라는 뜻은 아니에요(예측 가능한 규칙으로 만든 값도 높게 나올 수 있어요). 짧은 글은 오차가 커요. $NOTE_LOCAL")
            }
        },

        calc("sec_otpauth", S, "otpauth:// 주소 해석 (2단계 인증 QR 내용)", "2단계 인증 QR 코드에 담긴 otpauth://totp/… 주소를 풀어 발급처·계정·비밀키·알고리즘·주기를 보고 지금 코드까지 확인",
            text("u", "otpauth 주소", "otpauth://totp/Example:alice@example.com?secret=JBSWY3DPEHPK3PXP&issuer=Example", "otpauth://totp/Example:alice@example.com?secret=JBSWY3DPEHPK3PXP&issuer=Example")) { i ->
            val u = i.str("u"); if (u.isEmpty()) return@calc need("otpauth:// 주소를 입력하세요")
            val m = Regex("^otpauth://(totp|hotp)/([^?]*)\\?(.*)$", RegexOption.IGNORE_CASE).matchEntire(u) ?: return@calc fail("otpauth://totp/라벨?secret=… 형식이 아니에요")
            val q = m.groupValues[3].split('&').filter { '=' in it }.associate { URLDecoder.decode(it.substringBefore('='), "UTF-8").lowercase() to URLDecoder.decode(it.substringAfter('='), "UTF-8") }
            val label = URLDecoder.decode(m.groupValues[2], "UTF-8"); val type = m.groupValues[1].lowercase()
            val secret = q["secret"] ?: return@calc fail("secret 이 없어요"); val key = Base32.decode(secret.replace(" ", "").uppercase()) ?: return@calc fail("secret 이 Base32(A-Z, 2-7)가 아니에요")
            val alg = (q["algorithm"] ?: "SHA1").uppercase(); if (alg !in listOf("SHA1", "SHA256", "SHA512")) return@calc fail("알고리즘은 SHA1·SHA256·SHA512 만 지원해요 (받은 값: $alg)")
            val digits = q["digits"]?.toIntOrNull()?.takeIf { it in 6..8 } ?: 6; val period = q["period"]?.toIntOrNull()?.takeIf { it in 5..300 } ?: 30
            val issuer = q["issuer"] ?: label.substringBefore(':', "").ifEmpty { "-" }; val account = label.substringAfter(':', label).trim()
            result {
                kv("종류", if (type == "totp") "TOTP (시간 기반)" else "HOTP (횟수 기반)"); kv("발급처", issuer); kv("계정", account); kv("비밀키(Base32)", secret.uppercase(), 1); kv("알고리즘", alg); kv("자릿수", "$digits"); kv(if (type == "totp") "주기" else "카운터", if (type == "totp") "${period}초" else (q["counter"] ?: "0"))
                if (type == "totp") { val now = System.currentTimeMillis() / 1000; kv("지금 코드", Totp.at(key, now, period, digits, "Hmac$alg"), -1); kv("남은 시간", "${period - now % period}초") }
                else kv("코드(카운터 ${q["counter"] ?: "0"})", Totp.code(key, (q["counter"] ?: "0").toLongOrNull() ?: 0L, digits, "Hmac$alg"), -1)
                if (alg != "SHA1" || digits != 6 || period != 30) note("기본값(SHA1·6자리·30초)이 아니에요: 일부 인증 앱(구글 인증기 등)은 알고리즘·자릿수·주기를 무시하고 기본값으로 계산해서 코드가 달라질 수 있어요.", 1)
                note("비밀키를 아는 사람은 누구나 같은 코드를 만들 수 있어요. 이 주소·QR 을 화면 캡처나 메신저로 남기지 마세요. $NOTE_LOCAL", 1)
            }
        },
    )
}
