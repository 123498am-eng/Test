package com.selfcheck.app

import java.math.BigDecimal
import java.math.BigInteger
import java.net.IDN
import java.security.SecureRandom
import java.security.cert.CertificateFactory
import java.security.cert.X509Certificate
import java.time.Instant
import java.time.ZoneId
import java.time.ZoneOffset
import java.util.Base64
import java.util.UUID

/** 변환·인코딩 20가지 + 해시·토큰 11가지 (모두 오프라인) */
object ConvertTools {
    private const val C = NetGroups.CONVERT
    private const val H = NetGroups.HASH

    private fun b64Decode(s: String): ByteArray? = try {
        var t = s.filter { !it.isWhitespace() }.replace('-', '+').replace('_', '/')
        while (t.length % 4 != 0) t += "="
        Base64.getDecoder().decode(t)
    } catch (_: IllegalArgumentException) { null }

    private fun decodedText(b: ByteArray, rb: Rb) {
        val txt = strictUtf8(b)
        if (txt != null) rb.block(txt, mono = false) else { rb.note("글자(UTF-8)로 읽을 수 없는 데이터예요. 16진수로 보여 드릴게요.", 1); rb.block(hexDump(b)) }
    }

    private val sampleText = "안녕하세요 hello & 世界?q=a b"

    /** 스크립트 혼용(라틴+키릴 등) 검사: 겉보기가 같은 다른 글자로 속이는 도메인 */
    internal fun mixedScript(label: String): Boolean {
        val scripts = label.codePoints().toArray().map { Character.UnicodeScript.of(it) }
            .filter { it != Character.UnicodeScript.COMMON && it != Character.UnicodeScript.INHERITED }.toSet()
        return scripts.size > 1 && scripts.any { it == Character.UnicodeScript.CYRILLIC || it == Character.UnicodeScript.GREEK } && Character.UnicodeScript.LATIN in scripts
    }

    private val URL_RE = Regex("""^([A-Za-z][A-Za-z0-9+.\-]*):\/\/(?:([^@\/?#]*)@)?(\[[^\]]+\]|[^:\/?#]*)(?::(\d*))?([^?#]*)(?:\?([^#]*))?(?:#(.*))?$""")
    private val DEFAULT_PORT = mapOf("http" to 80, "https" to 443, "ftp" to 21, "ssh" to 22, "ws" to 80, "wss" to 443, "ftps" to 990)

    internal fun parseQuery(q: String): List<Pair<String, String>> = q.removePrefix("?").split('&').filter { it.isNotEmpty() }.map {
        val k = it.substringBefore('='); val v = if ('=' in it) it.substringAfter('=') else ""
        (Percent.decode(k, true) ?: k) to (Percent.decode(v, true) ?: v)
    }

    private val ALL_BASES = listOf(2, 8, 10, 16, 36)

    private val BYTE_UNITS = listOf("B" to BigDecimal(1), "KB" to BigDecimal(1000), "MB" to BigDecimal(1_000_000), "GB" to BigDecimal(1_000_000_000), "TB" to BigDecimal(1_000_000_000_000L),
        "KiB" to BigDecimal(1024), "MiB" to BigDecimal(1_048_576), "GiB" to BigDecimal(1_073_741_824L), "TiB" to BigDecimal(1_099_511_627_776L),
        "bit" to BigDecimal("0.125"), "Kb" to BigDecimal(125), "Mb" to BigDecimal(125_000), "Gb" to BigDecimal(125_000_000))
    private val RATE_UNITS = listOf("bps" to BigDecimal(1), "Kbps" to BigDecimal(1000), "Mbps" to BigDecimal(1_000_000), "Gbps" to BigDecimal(1_000_000_000),
        "B/s" to BigDecimal(8), "KB/s" to BigDecimal(8000), "MB/s" to BigDecimal(8_000_000), "GB/s" to BigDecimal(8_000_000_000L),
        "KiB/s" to BigDecimal(8192), "MiB/s" to BigDecimal(8_388_608))

    private fun fmtNum(d: BigDecimal): String {
        return if (d.abs() >= BigDecimal(1_000_000_000_000_000L) || (d.signum() != 0 && d.abs() < BigDecimal("0.000001"))) String.format("%.6e", d)
        else d.setScale(9, java.math.RoundingMode.HALF_UP).stripTrailingZeros().toPlainString()
    }

    private val JWT_TIMES = listOf("exp" to "만료(exp)", "nbf" to "이 시각 이후 유효(nbf)", "iat" to "발급(iat)")

    val ALL: List<NetTool> = listOf(
        // ------------------------------------------------------------ 변환·인코딩
        calc("url_encode", C, "URL 인코딩", "글자를 주소창에 쓸 수 있는 %XX 형태로 (한글·공백·특수문자)",
            choice("mode", "공백 처리", listOf("%20 (주소·경로)", "+ (폼 데이터)")), multi("t", "바꿀 글", "", sampleText)) { i ->
            val s = i.raw("t"); if (s.isEmpty()) return@calc need("바꿀 글을 입력하세요")
            result { block(Percent.encode(s, i.choice("mode", listOf("%20 (주소·경로)", "+ (폼 데이터)")) == 1)); note("알파벳·숫자와 - . _ ~ 만 그대로 두고 나머지는 UTF-8 바이트를 %XX 로 바꿔요.") }
        },
        calc("url_decode", C, "URL 디코딩", "%EC%95%88%EB%85%95 같은 퍼센트 인코딩을 읽을 수 있는 글로",
            choice("mode", "+ 기호", listOf("공백으로 (폼 데이터)", "그대로")), multi("t", "바꿀 글", "", "%EC%95%88%EB%85%95%ED%95%98%EC%84%B8%EC%9A%94+hello%20%26+%E4%B8%96%E7%95%8C")) { i ->
            val s = i.raw("t"); if (s.isBlank()) return@calc need("바꿀 글을 입력하세요")
            val r = Percent.decode(s.trim(), i.choice("mode", listOf("공백으로 (폼 데이터)", "그대로")) == 0) ?: return@calc fail("%XX 모양이 올바르지 않아요 (% 뒤에 16진수 두 자리)")
            result { block(r, mono = false) }
        },
        calc("base64_encode", C, "Base64 인코딩", "글자(UTF-8)를 Base64 로 (표준·URL 안전·패딩 없음)",
            choice("mode", "방식", listOf("표준", "URL 안전 (-_)", "URL 안전·패딩 없음")), multi("t", "바꿀 글", "", sampleText)) { i ->
            val s = i.raw("t"); if (s.isEmpty()) return@calc need("바꿀 글을 입력하세요")
            val m = i.choice("mode", listOf("표준", "URL 안전 (-_)", "URL 안전·패딩 없음"))
            val e = when (m) { 0 -> Base64.getEncoder(); 1 -> Base64.getUrlEncoder(); else -> Base64.getUrlEncoder().withoutPadding() }
            result { block(e.encodeToString(s.toByteArray())); kv("원본 길이", "${s.toByteArray().size}바이트") }
        },
        calc("base64_decode", C, "Base64 디코딩", "Base64(표준·URL 안전) 문자열을 원래 글로 (줄바꿈·패딩 생략도 OK)",
            multi("t", "Base64", "", "7JWI64WV7ZWY7IS47JqUIGhlbGxvICYg5LiW55WM")) { i ->
            val s = i.raw("t"); if (s.isBlank()) return@calc need("Base64 문자열을 입력하세요")
            val b = b64Decode(s) ?: return@calc fail("Base64 가 아니에요 (A-Z a-z 0-9 + / = 만 쓸 수 있어요)")
            result { decodedText(b, this); kv("바이트 수", "${b.size}") }
        },
        calc("base32_encode", C, "Base32 인코딩", "글자를 Base32 로 (2단계 인증 키 등에서 씀)", multi("t", "바꿀 글", "", "foobar")) { i ->
            val s = i.raw("t"); if (s.isEmpty()) return@calc need("바꿀 글을 입력하세요")
            result { block(Base32.encode(s.toByteArray())); kv("패딩 없이", Base32.encode(s.toByteArray(), false)) }
        },
        calc("base32_decode", C, "Base32 디코딩", "Base32 문자열(공백·하이픈·소문자 OK)을 원래 글로", multi("t", "Base32", "", "MZXW6YTBOI======")) { i ->
            val s = i.raw("t"); if (s.isBlank()) return@calc need("Base32 문자열을 입력하세요")
            val b = Base32.decode(s) ?: return@calc fail("Base32 가 아니에요 (A-Z 와 2-7 만 쓸 수 있어요)")
            result { decodedText(b, this); kv("바이트 수", "${b.size}") }
        },
        calc("hex_encode", C, "16진수(Hex) 인코딩", "글자를 UTF-8 바이트의 16진수로", choice("sep", "구분", listOf("공백", "없음", "콜론")), multi("t", "바꿀 글", "", "Hello 안녕")) { i ->
            val s = i.raw("t"); if (s.isEmpty()) return@calc need("바꿀 글을 입력하세요")
            val sep = when (i.choice("sep", listOf("공백", "없음", "콜론"))) { 0 -> " "; 1 -> ""; else -> ":" }
            result { block(s.toByteArray().joinToString(sep) { "%02x".format(it.toInt() and 0xff) }) }
        },
        calc("hex_decode", C, "16진수(Hex) 디코딩", "16진수 바이트(공백·콜론·0x 허용)를 글로", multi("t", "16진수", "", "48 65 6c 6c 6f 20 ec 95 88 eb 85 95")) { i ->
            val s = i.raw("t"); if (s.isBlank()) return@calc need("16진수를 입력하세요")
            val h = s.replace("0x", "", true).filter { it.isLetterOrDigit() }
            if (h.length % 2 != 0 || !h.all { it in '0'..'9' || it in 'a'..'f' || it in 'A'..'F' }) return@calc fail("16진수(0-9 a-f)를 두 자리씩 입력하세요")
            val b = ByteArray(h.length / 2) { h.substring(it * 2, it * 2 + 2).toInt(16).toByte() }
            result { decodedText(b, this); kv("바이트 수", "${b.size}") }
        },
        calc("html_encode", C, "HTML 엔티티 인코딩", "< > & \" ' 를 HTML 에 안전한 &lt; 등으로 (XSS 막기 기본)",
            choice("all", "한글 등", listOf("그대로", "모두 &#x…; 로")), multi("t", "바꿀 글", "", "<a href=\"x\">내 & 네 'quote'</a>")) { i ->
            val s = i.raw("t"); if (s.isEmpty()) return@calc need("바꿀 글을 입력하세요")
            result { block(Html.encode(s, i.choice("all", listOf("그대로", "모두 &#x…; 로")) == 1)) }
        },
        calc("html_decode", C, "HTML 엔티티 디코딩", "&amp; &lt; &#39; &#x1F600; 같은 엔티티를 글자로", multi("t", "HTML", "", "&lt;b&gt;안녕&lt;/b&gt; &amp; &copy; &#39;hi&#39; &#x1F600;")) { i ->
            val s = i.raw("t"); if (s.isEmpty()) return@calc need("HTML 을 입력하세요")
            result { block(Html.decode(s), mono = false) }
        },
        calc("punycode_encode", C, "한글 도메인 → 퓨니코드", "한글·유니코드 도메인을 xn-- 형태(DNS 에서 쓰는 모양)로, 혼용 문자 사칭도 검사",
            text("d", "도메인", "예: 한글.kr, 한국도메인.한국", "한글.kr", listOf("예시" to "예시.한국", "사칭 예" to "аpple.com"))) { i ->
            val s = HostInput.host(i.str("d")); if (s.isEmpty()) return@calc need("도메인을 입력하세요")
            val ascii = try { IDN.toASCII(s, IDN.ALLOW_UNASSIGNED) } catch (e: IllegalArgumentException) { return@calc fail("변환할 수 없는 도메인이에요: ${e.message}") }
            result {
                kv("원래", s); kv("퓨니코드", ascii)
                val bad = s.split('.').filter { mixedScript(it) }
                if (bad.isNotEmpty()) note("⚠ ${bad.joinToString(", ")} 에 라틴 문자와 키릴·그리스 문자가 섞여 있어요. 겉모습이 똑같은 다른 글자로 진짜 사이트를 흉내 내는 피싱 수법일 수 있어요.", 2)
                else if (ascii != s.lowercase()) note("브라우저는 이 도메인을 내부적으로 위 퓨니코드로 바꿔 접속해요.")
            }
        },
        calc("punycode_decode", C, "퓨니코드 → 한글 도메인", "xn-- 도메인을 원래 글자로 (링크가 어디로 가는지 확인)",
            text("d", "도메인", "예: xn--bj0bj06e.kr", "xn--bj0bj06e.kr")) { i ->
            val s = HostInput.host(i.str("d")); if (s.isEmpty()) return@calc need("도메인을 입력하세요")
            val u = try { IDN.toUnicode(s, IDN.ALLOW_UNASSIGNED) } catch (e: Exception) { return@calc fail("읽을 수 없는 퓨니코드예요") }
            result {
                kv("퓨니코드", s); kv("원래 글자", u)
                val bad = u.split('.').filter { mixedScript(it) }
                if (bad.isNotEmpty()) note("⚠ ${bad.joinToString(", ")} 에 라틴 문자와 키릴·그리스 문자가 섞여 있어요. 진짜 사이트를 흉내 내는 주소일 수 있으니 조심하세요.", 2)
            }
        },
        calc("url_parse", C, "URL 분해 (피싱 점검)", "주소를 스킴·호스트·포트·경로·쿼리로 나누고 속임수 주소 신호를 알려 줘요",
            text("u", "URL", "예: https://user@example.com:8443/a/b?x=1#top", "https://login.example.com@203.0.113.9:8443/a/b?next=%2Fhome&x=1#top", listOf("정상" to "https://www.example.com/path?q=1", "숫자 주소" to "http://3232235521/login"))) { i ->
            var u = i.str("u"); if (u.isEmpty()) return@calc need("URL 을 입력하세요")
            val added = "://" !in u; if (added) u = "http://$u"
            val m = URL_RE.matchEntire(u) ?: return@calc fail("URL 을 읽지 못했어요")
            val (scheme, user, host, port, path, query, frag) = m.destructured
            result {
                if (added) note("스킴이 없어 http:// 를 붙여서 해석했어요.")
                kv("스킴", scheme.lowercase()); if (user.isNotEmpty()) kv("사용자 정보", user, 2)
                kv("호스트", host); kv("포트", port.ifEmpty { DEFAULT_PORT[scheme.lowercase()]?.let { "$it (기본)" } ?: "-" })
                kv("경로", path.ifEmpty { "/" }); if (query.isNotEmpty()) kv("쿼리", query); if (frag.isNotEmpty()) kv("조각(#)", frag)
                val q = parseQuery(query)
                if (q.isNotEmpty()) { head("쿼리 값"); for ((k, v) in q) kv(k, v) }
                head("점검")
                var flags = 0
                fun warn(t: String) { flags++; note(t, 1) }
                if (user.isNotEmpty()) warn("주소에 '@' 가 있어요. 진짜 목적지는 @ 뒤의 '$host' 예요. \"login.example.com@…\" 처럼 앞부분으로 속이는 피싱에 자주 쓰여요.")
                val ip = IpUtil.parse(host.removePrefix("[").removeSuffix("]"))
                if (ip != null) warn("호스트가 IP 주소예요(${IpUtil.format(ip)}). 일반 사이트는 도메인을 써요.")
                else if (host.all { it.isDigit() } || host.startsWith("0x", true)) warn("호스트가 숫자·16진수 주소예요. 브라우저가 IP 로 읽을 수 있어서 목적지를 숨기는 수법으로 쓰여요 (IPv4 진법 변환 도구로 확인).")
                if (host.contains("xn--")) warn("퓨니코드(xn--) 도메인이에요. 원래 글자: ${runCatching { IDN.toUnicode(host) }.getOrDefault(host)}")
                if (host.split('.').any { mixedScript(it) }) warn("라틴 문자와 키릴·그리스 문자가 섞인 호스트예요. 진짜 사이트를 흉내 내는 글자일 수 있어요.")
                if (host.count { it == '.' } >= 4) warn("하위 도메인이 아주 많아요. 진짜 도메인은 맨 뒤 두세 칸(예: example.com)이에요.")
                if (scheme.lowercase() == "http") warn("암호화되지 않은 http 예요. 로그인·결제는 https 에서만 하세요.")
                if (Regex("%[0-9A-Fa-f]{2}").containsMatchIn(host)) warn("호스트에 %XX 가 들어 있어요. 일반 주소에서는 보기 어려운 모양이에요.")
                if (flags == 0) note("눈에 띄는 속임수 신호는 없어요. (그래도 내용까지 안전하다는 뜻은 아니에요.)", -1)
            }
        },
        calc("query_parse", C, "쿼리 문자열 분석", "URL 의 ?a=1&b=2 부분을 항목별로 풀고 디코딩 (중복 키 표시)",
            text("q", "URL 또는 쿼리", "예: https://x.com/s?q=%ED%95%9C&lang=ko", "https://x.com/search?q=%ED%95%9C%EA%B8%80+test&lang=ko&lang=en&page=2")) { i ->
            val s = i.str("q"); if (s.isEmpty()) return@calc need("URL 이나 쿼리를 입력하세요")
            val q = parseQuery(s.substringAfter('?', s).substringBefore('#'))
            if (q.isEmpty()) return@calc fail("쿼리(?뒤의 key=value)를 찾지 못했어요")
            val dup = q.groupBy { it.first }.filter { it.value.size > 1 }.keys
            result { header("키", "값"); for ((k, v) in q) row(k, v, level = if (k in dup) 1 else 0); kv("항목 수", "${q.size}개"); if (dup.isNotEmpty()) note("같은 키가 여러 번 나와요: ${dup.joinToString(", ")}", 1) }
        },
        calc("query_build", C, "쿼리 문자열 만들기", "key=value 줄들을 주소에 붙일 쿼리 문자열로 (값은 자동 인코딩)",
            text("base", "기본 주소 (선택)", "예: https://example.com/search", "https://example.com/search"), multi("kv", "항목", "한 줄에 key=value", "q=한글 검색\nlang=ko\npage=2")) { i ->
            val pairs = i.lines("kv").map { it.substringBefore('=').trim() to it.substringAfter('=', "").trim() }.filter { it.first.isNotEmpty() }
            if (pairs.isEmpty()) return@calc need("key=value 를 한 줄에 하나씩 입력하세요")
            val qs = pairs.joinToString("&") { Percent.encode(it.first) + "=" + Percent.encode(it.second) }
            result { block((if (i.str("base").isEmpty()) "" else i.str("base") + "?") + qs); kv("항목 수", "${pairs.size}개") }
        },
        calc("base_convert", C, "진법 변환 (2~36진수)", "큰 수도 2·8·10·16·36 진수로 한꺼번에",
            choice("from", "입력 진법", listOf("10", "2", "8", "16", "36")), text("n", "수", "예: 255, 11111111, ff", "3232235521")) { i ->
            val s = i.str("n").replace("_", "").replace(" ", "").removePrefix("0x").removePrefix("0b"); if (s.isEmpty()) return@calc need("수를 입력하세요")
            val from = i.str("from").toInt()
            val v = try { BigInteger(s, from) } catch (_: NumberFormatException) { return@calc fail("${from}진수로 읽을 수 없어요") }
            result {
                for (b in ALL_BASES) kv("${b}진수", v.toString(b).uppercase().let { if (b == 2) it.reversed().chunked(4).joinToString(" ").reversed() else it })
                kv("비트 수", "${v.bitLength()}비트")
            }
        },
        calc("epoch_convert", C, "유닉스 시간 ↔ 날짜", "초·밀리초 숫자 ↔ 날짜 (비워 두면 지금 시각), 한국(KST)·UTC 동시 표시",
            choice("tz", "날짜 입력 시 기준", listOf("한국 KST", "UTC")), text("v", "숫자 또는 날짜", "예: 1700000000 · 2025-01-31 12:30:00", "1700000000", listOf("지금" to ""))) { i ->
            val s = i.str("v"); val zone = if (i.choice("tz", listOf("한국 KST", "UTC")) == 0) Epoch.KST else ZoneOffset.UTC
            val inst: Instant; var unit = ""
            if (s.isEmpty()) { inst = Instant.now(); unit = "지금" }
            else if (s.toLongOrNull() != null) { val (a, u) = Epoch.fromNumber(s.toLong()); inst = a; unit = u }
            else inst = Epoch.parseDate(s, zone) ?: return@calc fail("읽지 못했어요. 예: 1700000000 또는 2025-01-31 12:30:00 또는 2025-01-31T12:30:00Z")
            result {
                if (unit.isNotEmpty()) kv("입력 단위", unit)
                kv("한국(KST)", Epoch.fmt(inst, Epoch.KST)); kv("UTC", Epoch.fmt(inst, ZoneOffset.UTC)); kv("ISO 8601", inst.toString())
                kv("초", inst.epochSecond.toString()); kv("밀리초", inst.toEpochMilli().toString())
                val d = Instant.now().epochSecond - inst.epochSecond
                kv("지금과의 차이", if (Math.abs(d) < 5) "지금" else (if (d > 0) "${rel(d)} 전" else "${rel(-d)} 후"))
            }
        },
        calc("unit_bytes", C, "데이터 크기 단위 변환", "B·KB·MB·GB·TB(1000 단위)와 KiB·MiB·GiB·TiB(1024 단위), 비트 단위까지 한꺼번에",
            text("v", "값", "예: 1.5", "1.5"), choice("u", "단위", BYTE_UNITS.map { it.first }, "GB")) { i ->
            val v = i.double("v") ?: return@calc if (i.str("v").isEmpty()) need("값을 입력하세요") else fail("숫자로 입력하세요")
            val bytes = BigDecimal(v.toString()).multiply(BYTE_UNITS.first { it.first == i.str("u") }.second)
            result { for ((u, f) in BYTE_UNITS) kv(u, fmtNum(bytes.divide(f, 12, java.math.RoundingMode.HALF_UP))); note("KB·MB 는 1000 배, KiB·MiB 는 1024 배예요. 윈도는 1024 배를 KB 로 부르고, 저장장치 제조사는 1000 배를 써서 용량이 다르게 보여요.") }
        },
        calc("unit_rate", C, "전송 속도 단위 변환", "Mbps ↔ MB/s 같은 속도 단위 (통신사는 비트, 다운로드 창은 바이트)",
            text("v", "값", "예: 500", "500"), choice("u", "단위", RATE_UNITS.map { it.first }, "Mbps")) { i ->
            val v = i.double("v") ?: return@calc if (i.str("v").isEmpty()) need("값을 입력하세요") else fail("숫자로 입력하세요")
            val bps = BigDecimal(v.toString()).multiply(RATE_UNITS.first { it.first == i.str("u") }.second)
            result { for ((u, f) in RATE_UNITS) kv(u, fmtNum(bps.divide(f, 12, java.math.RoundingMode.HALF_UP))); note("1 바이트 = 8 비트라서 500 Mbps 회선의 다운로드는 최대 약 62.5 MB/s 예요.") }
        },
        calc("hostname_check", C, "호스트명·도메인 규칙 검사", "RFC 1123 규칙(글자·길이·하이픈)에 맞는지, 어디가 틀렸는지",
            text("h", "호스트명 또는 도메인", "예: my-server.example.com", "my-server.example.com", listOf("밑줄 예" to "my_server.example.com", "하이픈 예" to "-bad-.com"))) { i ->
            val h = i.str("h").trimEnd('.'); if (h.isEmpty()) return@calc need("이름을 입력하세요")
            val issues = ArrayList<String>()
            if (h.length > 253) issues += "전체 길이가 253자를 넘어요 (${h.length}자)"
            val labels = h.split('.')
            for (l in labels) {
                if (l.isEmpty()) issues += "빈 칸이 있어요 (점이 연속됨)"
                else {
                    if (l.length > 63) issues += "\"${l.take(12)}…\" 는 63자를 넘어요 (${l.length}자)"
                    if (l.startsWith("-") || l.endsWith("-")) issues += "\"$l\" 는 하이픈으로 시작하거나 끝날 수 없어요"
                    val badc = l.filter { !(it in 'a'..'z' || it in 'A'..'Z' || it in '0'..'9' || it == '-') }.toSet()
                    if (badc.isNotEmpty()) issues += "\"$l\" 에 쓸 수 없는 글자가 있어요: ${badc.joinToString(" ")}" + if ('_' in badc) " (밑줄은 호스트명에 쓸 수 없지만 일부 DNS 레코드 이름에는 쓰여요)" else ""
                }
            }
            if (labels.size > 1 && labels.last().all { it.isDigit() }) issues += "맨 끝(최상위) 칸이 숫자뿐이에요"
            result {
                kv("이름", h); kv("전체 길이", "${h.length}자 (최대 253)"); kv("칸 수", "${labels.size}")
                if (issues.isEmpty()) note("규칙에 맞는 이름이에요.", -1) else { note("고칠 점 ${issues.size}가지", 2); issues.forEach { note("• $it", 1) } }
            }
        },

        // ------------------------------------------------------------ 해시·토큰
        calc("hash_text", H, "해시 계산 (MD5·SHA)", "글자의 MD5·SHA-1·SHA-256·SHA-384·SHA-512 해시",
            choice("alg", "알고리즘", Hashes.ALGS, "SHA-256"), multi("t", "글", "", "hello")) { i ->
            val s = i.raw("t"); if (s.isEmpty()) return@calc need("글을 입력하세요")
            val d = Hashes.digest(i.str("alg"), s.toByteArray())
            result {
                kv("알고리즘", i.str("alg")); kv("16진수", Hashes.hex(d)); kv("16진수(대문자)", Hashes.hex(d).uppercase()); kv("Base64", Base64.getEncoder().encodeToString(d)); kv("글자 → 바이트", "${s.toByteArray().size}바이트 (UTF-8)")
                if (i.str("alg") in listOf("MD5", "SHA-1")) note("MD5·SHA-1 은 충돌 공격이 가능해서 보안 용도(서명·비밀번호 저장)에는 쓰면 안 돼요. 파일 무결성 확인용으로만 쓰세요.", 1)
            }
        },
        calc("hash_all", H, "해시 한꺼번에 (5종)", "같은 글의 MD5·SHA-1·SHA-256·SHA-384·SHA-512 를 한 번에", multi("t", "글", "", "hello")) { i ->
            val s = i.raw("t"); if (s.isEmpty()) return@calc need("글을 입력하세요")
            result { for (a in Hashes.ALGS) kv(a, Hashes.hex(Hashes.digest(a, s.toByteArray()))) }
        },
        calc("hmac_text", H, "HMAC 계산", "비밀키로 만든 메시지 인증 코드 (웹훅 서명 검증에 씀)",
            choice("alg", "알고리즘", listOf("HmacSHA256", "HmacSHA1", "HmacSHA512", "HmacMD5")), text("k", "비밀키", "", "key"), multi("t", "메시지", "", "The quick brown fox jumps over the lazy dog")) { i ->
            if (i.raw("k").isEmpty() || i.raw("t").isEmpty()) return@calc need("비밀키와 메시지를 입력하세요")
            val d = Totp.hmac(i.str("alg"), i.raw("k").toByteArray(), i.raw("t").toByteArray())
            result { kv("알고리즘", i.str("alg")); kv("16진수", Hashes.hex(d)); kv("Base64", Base64.getEncoder().encodeToString(d)); note("비밀키는 휴대폰 밖으로 나가지 않아요.") }
        },
        tool("hash_file", H, "파일 해시·무결성 확인", "파일의 MD5·SHA-1·SHA-256 을 계산하고 내려받은 해시와 비교 (변조·손상 확인)",
            listOf(file("f", "파일"), text("exp", "비교할 해시 (선택)", "배포 사이트에 적힌 값")), ToolMode.OFFLINE, "파일은 휴대폰 안에서만 읽어요. 큰 파일은 시간이 걸려요.", runLabel = "계산") { i, host, env ->
            val f = host.file("f") ?: return@tool need("파일을 고르세요")
            val ins = f.open() ?: return@tool fail("파일을 열 수 없어요")
            val md = listOf("MD5", "SHA-1", "SHA-256").map { java.security.MessageDigest.getInstance(it) }
            var total = 0L
            ins.use { s -> val buf = ByteArray(64 * 1024); while (true) { if (env.cancel.get()) break; val n = s.read(buf); if (n < 0) break; md.forEach { it.update(buf, 0, n) }; total += n; if (f.size > 0) env.progress("읽는 중 ${total * 100 / f.size}%") } }
            if (env.cancel.get()) return@tool need("중간에 멈췄어요")
            val hex = md.map { Hashes.hex(it.digest()) }
            val exp = i.str("exp").lowercase().filter { it.isLetterOrDigit() }
            result {
                kv("파일", f.name); kv("크기", "%,d바이트".format(total))
                kv("MD5", hex[0]); kv("SHA-1", hex[1]); kv("SHA-256", hex[2])
                if (exp.isNotEmpty()) { val hit = hex.indexOfFirst { it == exp }; if (hit >= 0) note("일치해요 ✔ (${listOf("MD5", "SHA-1", "SHA-256")[hit]})", -1) else note("일치하지 않아요 ✘ 파일이 바뀌었거나 다른 파일일 수 있어요.", 2) }
            }
        },
        calc("uuid_gen", H, "UUID 만들기", "무작위 UUID v4 (고유 ID)", choice("n", "개수", listOf("1", "5", "10", "20")), choice("fmt", "모양", listOf("소문자", "대문자", "하이픈 없음"))) { i ->
            val n = i.str("n").toIntOrNull() ?: 1; val f = i.choice("fmt", listOf("소문자", "대문자", "하이픈 없음"))
            val list = (1..n).map { UUID.randomUUID().toString().let { u -> when (f) { 1 -> u.uppercase(); 2 -> u.replace("-", ""); else -> u } } }
            result { block(list.joinToString("\n")); note("버튼을 누를 때마다 새로 만들어져요.") }
        }.let { NetTool(it.id, it.group, it.title, it.desc, it.fields, it.mode, it.note, it.confirm, false, false, "만들기", it.run) },
        calc("token_gen", H, "무작위 토큰·API 키 만들기", "예측할 수 없는 토큰 (16진수·Base64URL·영문+숫자)",
            choice("fmt", "모양", listOf("16진수", "Base64URL", "영문+숫자")), choice("len", "길이 (바이트 / 글자 수)", listOf("16", "24", "32", "48", "64"), "32"), choice("n", "개수", listOf("1", "3", "5", "10"))) { i ->
            val len = i.str("len").toInt(); val n = i.str("n").toInt(); val f = i.choice("fmt", listOf("16진수", "Base64URL", "영문+숫자")); val rnd = SecureRandom()
            val alpha = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"
            val list = (1..n).map {
                when (f) {
                    0 -> ByteArray(len).also { b -> rnd.nextBytes(b) }.let { b -> Hashes.hex(b) }
                    1 -> ByteArray(len).also { b -> rnd.nextBytes(b) }.let { b -> Base64.getUrlEncoder().withoutPadding().encodeToString(b) }
                    else -> (1..len).map { alpha[rnd.nextInt(alpha.length)] }.joinToString("")
                }
            }
            result { block(list.joinToString("\n")); note("보안 난수(SecureRandom)로 만들어요. 한 번 만든 값은 저장되지 않으니 필요하면 복사해 두세요.") }
        }.let { NetTool(it.id, it.group, it.title, it.desc, it.fields, it.mode, it.note, it.confirm, false, false, "만들기", it.run) },
        calc("totp_code", H, "TOTP 인증 코드 계산", "2단계 인증(OTP) 비밀키(Base32)로 지금 코드를 계산 — 앱이 맞는지 확인할 때",
            text("s", "비밀키 (Base32)", "예: JBSWY3DPEHPK3PXP", "JBSWY3DPEHPK3PXP"), choice("d", "자릿수", listOf("6", "8")), choice("p", "주기(초)", listOf("30", "60")),
            choice("a", "알고리즘", listOf("SHA1", "SHA256", "SHA512")), text("t", "기준 시각 (선택, 유닉스 초)", "비우면 지금")) { i ->
            val key = Base32.decode(i.str("s")) ?: return@calc fail("Base32 비밀키가 아니에요 (A-Z 와 2-7)")
            if (key.isEmpty()) return@calc need("비밀키를 입력하세요")
            val now = i.long("t") ?: (System.currentTimeMillis() / 1000)
            val period = i.str("p").toInt(); val digits = i.str("d").toInt(); val alg = "Hmac" + i.str("a")
            result {
                kv("지금 코드", Totp.at(key, now, period, digits, alg), -1); kv("남은 시간", "${period - now % period}초")
                kv("이전 코드", Totp.at(key, now - period, period, digits, alg)); kv("다음 코드", Totp.at(key, now + period, period, digits, alg))
                note("비밀키는 휴대폰 밖으로 나가지 않아요. 다른 사람에게 알려 주면 계정이 위험해져요.")
            }
        },
        calc("jwt_decode", H, "JWT 해석", "JWT 의 헤더·페이로드를 풀어 보기 (만료 여부와 위험한 설정 표시, 서명은 확인하지 않음)",
            multi("t", "JWT", "xxxxx.yyyyy.zzzzz", "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyLCJleHAiOjQxMDI0NDQ4MDB9.signature")) { i ->
            val parts = i.str("t").removePrefix("Bearer ").trim().split('.')
            if (i.str("t").isEmpty()) return@calc need("JWT 를 입력하세요")
            if (parts.size != 3) return@calc fail("JWT 는 점(.)으로 나뉜 세 부분(헤더.내용.서명)이에요")
            fun js(p: String): org.json.JSONObject? = b64Decode(p)?.let { strictUtf8(it) }?.let { runCatching { org.json.JSONObject(it) }.getOrNull() }
            val h = js(parts[0]) ?: return@calc fail("헤더를 읽지 못했어요"); val p = js(parts[1]) ?: return@calc fail("내용(payload)을 읽지 못했어요")
            result {
                head("헤더"); block(h.toString(2)); head("내용(payload)"); block(p.toString(2))
                head("점검")
                val alg = h.optString("alg")
                kv("알고리즘", alg.ifEmpty { "?" }, if (alg.equals("none", true)) 2 else 0)
                if (alg.equals("none", true)) note("alg=none 은 서명이 없다는 뜻이에요. 서버가 이런 토큰을 받아들이면 누구나 위조할 수 있어요.", 2)
                else if (alg.startsWith("HS")) note("HS 계열은 서버와 공유하는 비밀키로 서명해요. 이 도구는 서명을 확인하지 않아요.")
                for ((k, label) in JWT_TIMES) if (p.has(k)) {
                    val t = p.optLong(k); val now = System.currentTimeMillis() / 1000
                    val state = when { k == "exp" && t < now -> "이미 만료됨" to 2; k == "exp" -> "${rel(t - now)} 후 만료" to -1; k == "nbf" && t > now -> "아직 유효하지 않음" to 1; else -> "" to 0 }
                    kv(label, Epoch.fmt(Instant.ofEpochSecond(t), Epoch.KST) + (if (state.first.isNotEmpty()) "  → ${state.first}" else ""), state.second)
                }
                if (!p.has("exp")) note("만료(exp)가 없는 토큰이에요. 유출되면 계속 쓸 수 있어서 위험해요.", 1)
                note("JWT 의 내용은 암호화가 아니라 Base64 라서 누구나 읽을 수 있어요. 비밀번호 같은 민감한 정보를 넣으면 안 돼요.")
            }
        },
        calc("basic_auth", H, "Basic 인증 헤더 만들기·해석", "아이디:비밀번호 ↔ Authorization: Basic …  (자동으로 방향을 알아봐요)",
            text("v", "아이디:비밀번호 또는 헤더 값", "예: admin:secret 또는 Basic YWRtaW46c2VjcmV0", "admin:secret")) { i ->
            val s = i.str("v"); if (s.isEmpty()) return@calc need("값을 입력하세요")
            val enc = s.removePrefix("Authorization:").trim()
            val looksHeader = enc.startsWith("Basic ", true)
            if (!looksHeader && ':' in s) {
                result { kv("헤더", "Authorization: Basic " + Base64.getEncoder().encodeToString(s.toByteArray())); note("Basic 인증은 암호화가 아니라 Base64 일 뿐이에요. 반드시 https 에서만 쓰세요.", 1) }
            } else {
                val b = b64Decode(if (looksHeader) enc.substring(6) else enc)?.let { strictUtf8(it) } ?: return@calc fail("Base64 로 읽을 수 없어요")
                result { kv("아이디", b.substringBefore(':')); kv("비밀번호", b.substringAfter(':', "")); note("Base64 는 누구나 풀 수 있어요. 이 헤더가 노출됐다면 비밀번호를 바꾸세요.", 1) }
            }
        },
        calc("cert_pem", H, "인증서(PEM) 해석", "-----BEGIN CERTIFICATE----- 인증서를 붙여 넣으면 주체·발급자·유효기간·지문·SAN 을 풀어 줘요",
            multi("pem", "PEM 인증서", "-----BEGIN CERTIFICATE----- … -----END CERTIFICATE-----")) { i ->
            val txt = i.raw("pem"); if (txt.isBlank()) return@calc need("PEM 인증서를 붙여 넣으세요")
            val certs = try { CertificateFactory.getInstance("X.509").generateCertificates(txt.byteInputStream()).filterIsInstance<X509Certificate>() } catch (e: Exception) { return@calc fail("인증서를 읽지 못했어요: ${e.message?.take(80)}") }
            if (certs.isEmpty()) return@calc fail("인증서를 찾지 못했어요. -----BEGIN CERTIFICATE----- 줄부터 붙여 넣었는지 확인하세요")
            result {
                certs.forEachIndexed { idx, c ->
                    head("인증서 ${idx + 1}")
                    for ((k, v) in CertInfo.describe(c)) kv(k, v, if (k == "남은 기간") (if (CertInfo.daysLeft(c) < 0) 2 else if (CertInfo.daysLeft(c) < 30) 1 else -1) else 0)
                }
            }
        },
        calc("crc_checksum", H, "체크섬 (CRC32·Adler32·인터넷)", "CRC-32, CRC-32C, Adler-32, 인터넷 체크섬(RFC 1071) 한꺼번에",
            choice("mode", "입력 방식", listOf("글자(UTF-8)", "16진수 바이트")), multi("t", "입력", "", "123456789")) { i ->
            val s = i.raw("t"); if (s.isEmpty()) return@calc need("값을 입력하세요")
            val b = if (i.choice("mode", listOf("글자(UTF-8)", "16진수 바이트")) == 1) {
                val h = s.replace("0x", "", true).filter { it.isLetterOrDigit() }
                if (h.length % 2 != 0 || !h.all { it in '0'..'9' || it in 'a'..'f' || it in 'A'..'F' }) return@calc fail("16진수를 두 자리씩 입력하세요")
                ByteArray(h.length / 2) { h.substring(it * 2, it * 2 + 2).toInt(16).toByte() }
            } else s.toByteArray()
            val crc = java.util.zip.CRC32().also { it.update(b) }; val crcc = java.util.zip.CRC32C().also { it.update(b) }; val ad = java.util.zip.Adler32().also { it.update(b) }
            result {
                kv("바이트 수", "${b.size}"); kv("CRC-32", "%08x".format(crc.value)); kv("CRC-32C (iSCSI·SCTP)", "%08x".format(crcc.value)); kv("Adler-32", "%08x".format(ad.value)); kv("인터넷 체크섬", "%04x".format(Hashes.internetChecksum(b)))
            }
        },
    )

    private fun rel(sec: Long): String = when {
        sec < 60 -> "${sec}초"; sec < 3600 -> "${sec / 60}분"; sec < 86400 -> "${sec / 3600}시간 ${sec % 3600 / 60}분"; sec < 86400 * 365 -> "${sec / 86400}일"; else -> "${sec / 86400 / 365}년 ${sec / 86400 % 365}일"
    }
}
