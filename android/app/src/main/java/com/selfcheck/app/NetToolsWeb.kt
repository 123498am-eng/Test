package com.selfcheck.app

import org.json.JSONArray
import java.io.IOException
import java.net.InetSocketAddress
import java.net.Socket
import java.time.Instant
import java.time.ZoneId
import java.time.ZonedDateTime
import java.time.format.DateTimeFormatter
import javax.net.ssl.SSLSocket
import javax.net.ssl.SSLSocketFactory

/**
 * 웹사이트 점검 도구 18가지: 주소에 일반 웹 요청(GET·HEAD·OPTIONS)을 보내 응답 헤더와 HTML 을 읽고 해석합니다.
 * 로그인·입력 양식 제출·취약점 공격은 하지 않아요. (링크 점검은 최대 20개 주소에 HEAD 요청만 보내요.)
 */
object WebTools {
    private const val W = NetGroups.WEB
    private const val NOTE_WEB = "입력한 주소의 서버에 일반 웹 요청(GET)을 보내요. 인터넷을 사용해요."
    private val URL_CHIPS = listOf("example.com" to "https://example.com", "github.com" to "https://github.com", "naver.com" to "https://www.naver.com", "google.com" to "https://www.google.com")

    private fun urlField(def: String = "https://example.com", label: String = "주소 (URL)") = text("u", label, "예: https://example.com", def, URL_CHIPS)
    private fun hostField(def: String = "example.com", label: String = "도메인 (포트는 :8443 처럼)") = text("h", label, "예: example.com", def, URL_CHIPS.map { it.first to it.second.substringAfter("://") })

    private fun page(u: String, maxBody: Int = 524288, headers: Map<String, String> = emptyMap()): HttpResult = Web.get(u, maxBody, headers = headers)

    private fun fail(e: Exception) = fail("접속하지 못했어요: ${e.message}")

    private fun lv(status: Int) = when (status) { in 200..299 -> -1; in 300..399 -> 0; in 400..499 -> 1; else -> 2 }

    val ALL: List<NetTool> = listOf(
        online("web_http2", W, "HTTP/2·HTTP/3 지원 확인", "사이트가 HTTP/2 를 쓰는지(TLS ALPN 협상), HTTP/3(QUIC)를 광고하는지 확인 — 웹 속도 설정 점검", hostField("www.google.com"), note = "서버에 TLS 접속 1번과 웹 요청 1번을 보내요. 인터넷을 사용해요.") { i, _, env ->
            val (h, port) = DiagTools.hostPort(i.str("h")); if (h.isEmpty()) return@online need("도메인을 입력하세요")
            env.progress("TLS 협상 중...")
            val a = try { Alpn.negotiate(h, port) } catch (e: Exception) { return@online fail("TLS 접속에 실패했어요: ${e.message?.take(100) ?: e.javaClass.simpleName}") }
            val r = runCatching { MiniHttp.request("https://$h${if (port == 443) "" else ":$port"}/", "GET", maxBody = 0, insecure = true) }.getOrNull()
            val alt = r?.header("Alt-Svc")
            result {
                kv("서버", "$h:$port"); kv("TLS", a.tlsVersion, if (a.tlsVersion == "TLSv1.3" || a.tlsVersion == "TLSv1.2") -1 else 2)
                if (!a.supported) note("이 기기(안드로이드 9 이하)에서는 HTTP/2 협상 결과를 읽을 수 없어요. 안드로이드 10 이상에서 확인하세요.", 1)
                else kv("협상된 프로토콜(ALPN)", a.protocol ?: "없음(HTTP/1.1)", if (a.protocol == "h2") -1 else 0)
                kv("HTTP/3(QUIC) 광고", alt?.let { s -> if (Regex("""\bh3(-\d+)?=""").containsMatchIn(s)) "예 ($s)".take(100) else "아니요 (Alt-Svc: ${s.take(60)})" } ?: "아니요 (Alt-Svc 없음)", if (alt != null && Regex("""\bh3(-\d+)?=""").containsMatchIn(alt)) -1 else 0)
                r?.let { kv("응답", it.statusLine.substringAfter(' ')); it.header("Server")?.let { s -> kv("Server", s) } }
                if (a.supported) note(when (a.protocol) { "h2" -> "HTTP/2 를 지원해요 (한 연결로 여러 요청을 동시에 처리해 빨라요)."; null -> "HTTP/2 를 협상하지 않았어요. 서버 설정에서 http2 를 켜면 여러 파일을 불러올 때 빨라져요."; else -> "${a.protocol} 로 협상됐어요." }, if (a.protocol == "h2") -1 else 1)
                note("HTTP/3 는 UDP 443 번을 쓰는 방식이에요. 이 도구는 서버가 광고하는지(Alt-Svc)만 확인하고 실제 UDP 연결은 시험하지 않아요.")
            }
        },

        online("web_compress", W, "압축(gzip·br) 지원과 절감 효과", "서버가 gzip·Brotli 압축을 쓰는지, 압축하면 전송 크기가 얼마나 줄어드는지", urlField(), note = "같은 주소를 압축 요청 방식을 바꿔 3번 받아요(최대 2MB). 인터넷을 사용해요.") { i, _, env ->
            val u = i.str("u"); if (u.isEmpty()) return@online need("주소를 입력하세요")
            val modes = listOf("압축 안 함(identity)" to "identity", "gzip" to "gzip", "br(Brotli)·gzip" to "br, gzip")
            val rs = ArrayList<Triple<String, String, HttpResult>>()
            for ((label, enc) in modes) { env.progress("$label 로 받는 중..."); try { rs += Triple(label, enc, Web.get(u, 2_000_000, headers = mapOf("Accept-Encoding" to enc))) } catch (e: IOException) { return@online fail(e) } }
            fun size(r: HttpResult): Long? = r.header("Content-Length")?.toLongOrNull() ?: r.body?.length?.toLong()
            val base = size(rs[0].third)
            result {
                kv("주소", rs[0].third.url); header("요청 방식", "받은 Content-Encoding", "전송 크기", "절감")
                for ((label, _, r) in rs) { val sz = size(r); val enc = r.header("Content-Encoding") ?: "없음"; row(label, enc, sz?.let { "%,d 바이트".format(it) } ?: "알 수 없음", if (sz != null && base != null && base > 0 && r !== rs[0].third) "${"%.0f".format((1 - sz.toDouble() / base) * 100)}% 줄어듦" else "-", level = if (enc != "없음") -1 else 0) }
                val gz = rs[1].third.header("Content-Encoding"); val br = rs[2].third.header("Content-Encoding")
                note(when { br?.contains("br") == true -> "Brotli 를 지원해요 (gzip 보다 보통 15~20% 더 작아요)."; gz?.contains("gzip") == true -> "gzip 을 지원해요. Brotli 까지 켜면 더 줄일 수 있어요."; else -> "압축을 쓰지 않아요. 텍스트(HTML·CSS·JS·JSON)는 압축하면 70% 안팎 줄어서 속도와 데이터 비용이 크게 좋아져요." }, if (gz != null || br != null) -1 else 1)
                if ((base ?: 0) in 1..800) note("응답이 작아서(800바이트 이하) 압축 효과를 판단하기 어려워요.")
                rs[0].third.header("Content-Type")?.let { kv("Content-Type", it) }
            }
        },

        online("web_cache", W, "캐시 설정 분석", "Cache-Control·ETag·Last-Modified 를 해석하고, 조건부 요청(304)이 실제로 동작하는지 시험", urlField("https://example.com/"), note = NOTE_WEB + " 캐시 시험을 위해 같은 주소에 한두 번 더 요청해요.") { i, _, env ->
            val u = i.str("u"); if (u.isEmpty()) return@online need("주소를 입력하세요")
            val r = try { page(u, 4096) } catch (e: IOException) { return@online fail(e) }
            val cc = CacheCtl.parse(r.header("Cache-Control")); val etag = r.header("ETag"); val lm = r.header("Last-Modified")
            val cond = ArrayList<Pair<String, HttpResult?>>()
            if (etag != null) { env.progress("If-None-Match 시험..."); cond += "If-None-Match" to runCatching { MiniHttp.request(r.url, "GET", mapOf("If-None-Match" to etag), 0) }.getOrNull() }
            if (lm != null) { env.progress("If-Modified-Since 시험..."); cond += "If-Modified-Since" to runCatching { MiniHttp.request(r.url, "GET", mapOf("If-Modified-Since" to lm), 0) }.getOrNull() }
            val type = r.header("Content-Type")?.substringBefore(';')?.trim() ?: ""
            val isStatic = type.startsWith("image/") || type.startsWith("font/") || type in listOf("text/css", "application/javascript", "text/javascript", "application/font-woff2", "application/wasm")
            result {
                kv("주소", r.url); kv("상태", r.statusLine.substringAfter(' '), lv(r.status)); kv("종류", type.ifEmpty { "-" })
                head("캐시 설정"); kv("Cache-Control", r.header("Cache-Control") ?: "없음", if (r.header("Cache-Control") == null) 1 else 0)
                CacheCtl.seconds(cc, "max-age")?.let { kv("브라우저 보관 시간", CacheCtl.human(it)) }; CacheCtl.seconds(cc, "s-maxage")?.let { kv("CDN·프록시 보관 시간", CacheCtl.human(it)) }
                val flags = listOfNotNull(if ("no-store" in cc) "저장 금지(no-store)" else null, if ("no-cache" in cc) "쓸 때마다 재확인(no-cache)" else null, if ("private" in cc) "개인용(private)" else null, if ("public" in cc) "공용 캐시 허용(public)" else null, if ("immutable" in cc) "변하지 않음(immutable)" else null, if ("must-revalidate" in cc) "만료 후 재확인(must-revalidate)" else null, if ("stale-while-revalidate" in cc) "만료 뒤에도 먼저 보여 주고 갱신(stale-while-revalidate)" else null)
                if (flags.isNotEmpty()) kv("지시어", flags.joinToString(" · "))
                r.header("Expires")?.let { kv("Expires", it) }; r.header("Age")?.let { kv("CDN 에서 보관된 시간(Age)", "${it}초") }; r.header("Vary")?.let { kv("Vary", it) }; etag?.let { kv("ETag", it.take(60)) }; lm?.let { kv("Last-Modified", it) }
                if (cond.isNotEmpty()) { head("조건부 요청 시험 (바뀐 게 없으면 304 로 본문 없이 답해야 해요)"); for ((n, c) in cond) kv(n, c?.statusLine?.substringAfter(' ') ?: "응답 없음", if (c?.status == 304) -1 else 1) }
                head("진단")
                when {
                    "no-store" in cc -> note("저장을 금지했어요: 매번 전체를 다시 받아요. 로그인 정보 같은 민감한 페이지에는 맞지만, 공개 파일에는 느려요.", if (isStatic) 1 else 0)
                    isStatic && CacheCtl.seconds(cc, "max-age") == null && "immutable" !in cc -> note("정적 파일(${type})인데 캐시 시간이 없어요. 파일 이름에 해시를 붙이고 Cache-Control: public, max-age=31536000, immutable 을 주면 재방문이 빨라져요.", 1)
                    isStatic && (CacheCtl.seconds(cc, "max-age") ?: 0) >= 86400 -> note("정적 파일을 오래 캐시해요 (좋아요).", -1)
                    type == "text/html" && (CacheCtl.seconds(cc, "max-age") ?: 0) > 3600 -> note("HTML 을 오래 캐시하면 수정해도 사용자가 옛 페이지를 볼 수 있어요. HTML 은 짧게(또는 no-cache + ETag) 두세요.", 1)
                    r.header("Cache-Control") == null && etag == null && lm == null -> note("캐시 관련 머리글이 전혀 없어요. 브라우저가 알아서 짐작해서 캐시해요(비효율적일 수 있어요).", 1)
                    else -> note("캐시 설정이 있어요.", -1)
                }
                if (cond.any { it.second?.status == 304 }) note("조건부 요청이 304 로 동작해요 (바뀌지 않았으면 본문을 다시 보내지 않아요).", -1)
            }
        },

        online("web_cors", W, "CORS 설정 점검", "다른 사이트의 스크립트가 이 서버의 데이터를 읽을 수 있는지 (잘못된 CORS 설정은 로그인 상태 데이터 유출로 이어져요)", urlField("https://example.com/api"), note = "같은 주소에 Origin 을 바꿔 가며 요청 3번(GET 2번, 사전 확인 OPTIONS 1번)을 보내요. 인터넷을 사용해요.") { i, _, env ->
            val u = i.str("u"); if (u.isEmpty()) return@online need("주소를 입력하세요")
            val evil = "https://selfcheck-test.invalid"
            fun acx(r: HttpResult?, n: String) = r?.header(n)
            env.progress("Origin 시험...")
            val a = try { MiniHttp.request(u, "GET", mapOf("Origin" to evil), 0) } catch (e: IOException) { return@online fail(e) }
            val pre = runCatching { MiniHttp.request(u, "OPTIONS", mapOf("Origin" to evil, "Access-Control-Request-Method" to "GET", "Access-Control-Request-Headers" to "authorization"), 0) }.getOrNull()
            val nul = runCatching { MiniHttp.request(u, "GET", mapOf("Origin" to "null"), 0) }.getOrNull()
            val acao = acx(a, "Access-Control-Allow-Origin"); val acac = acx(a, "Access-Control-Allow-Credentials")?.equals("true", true) == true
            result {
                kv("주소", u); header("요청", "Allow-Origin", "Allow-Credentials", "Allow-Methods", "Allow-Headers")
                row("GET (Origin: 낯선 사이트)", acao ?: "-", acx(a, "Access-Control-Allow-Credentials") ?: "-", acx(a, "Access-Control-Allow-Methods") ?: "-", acx(a, "Access-Control-Allow-Headers") ?: "-")
                row("OPTIONS(사전 확인)", acx(pre, "Access-Control-Allow-Origin") ?: "-", acx(pre, "Access-Control-Allow-Credentials") ?: "-", acx(pre, "Access-Control-Allow-Methods") ?: "-", acx(pre, "Access-Control-Allow-Headers") ?: "-")
                row("GET (Origin: null)", acx(nul, "Access-Control-Allow-Origin") ?: "-", acx(nul, "Access-Control-Allow-Credentials") ?: "-", "-", "-")
                head("진단")
                var any = false
                if (acao == "*" && acac) { note("Allow-Origin: * 와 Allow-Credentials: true 를 함께 쓰는 것은 규격에 어긋나요(브라우저가 무시해요). 설정 실수예요.", 2); any = true }
                if (acao == evil && acac) { note("아무 사이트(Origin)나 그대로 허용하면서 쿠키까지 허용해요: 악성 사이트가 방문자의 로그인 상태로 이 서버의 데이터를 읽어 갈 수 있어요. 허용할 Origin 목록(화이트리스트)으로 제한하세요.", 2); any = true }
                else if (acao == evil) { note("아무 Origin 이나 그대로 허용해요(쿠키는 불허). 공개 API 가 아니라면 허용 목록으로 제한하세요.", 1); any = true }
                if (acx(nul, "Access-Control-Allow-Origin") == "null") { note("Origin: null 을 허용해요. 샌드박스 iframe·로컬 파일에서도 접근할 수 있어서 위험해요.", 2); any = true }
                if (acao == "*" && !acac) { note("모든 사이트에서 읽을 수 있어요 (공개 API 라면 정상이에요).", 1); any = true }
                if (acao == null) { note("CORS 허용 머리글이 없어요: 다른 사이트의 스크립트는 응답을 읽을 수 없어요 (기본적으로 안전한 상태예요).", -1); any = true }
                if (acao != null && acao != "*" && !(a.header("Vary")?.contains("Origin", true) ?: false)) { note("Allow-Origin 이 요청마다 달라질 수 있는데 Vary: Origin 이 없어요. CDN 이 다른 사용자에게 잘못된 값을 줄 수 있어요.", 1); any = true }
                if (!any) note("특별한 문제가 보이지 않아요.", -1)
            }
        },

        online("web_cookies", W, "쿠키 보안 점검", "서버가 심는 쿠키마다 Secure·HttpOnly·SameSite·범위·수명을 점검하고 고칠 점을 알려 줘요", urlField(), note = NOTE_WEB) { i, _, _ ->
            val u = i.str("u"); if (u.isEmpty()) return@online need("주소를 입력하세요")
            val r = try { page(u, 4096) } catch (e: IOException) { return@online fail(e) }
            val cookies = r.all("Set-Cookie").map { CookieParse.parse(it) }; val https = r.url.startsWith("https://")
            result {
                kv("주소", r.url); kv("쿠키 수", "${cookies.size}개")
                if (cookies.isEmpty()) return@result note("이 응답에서는 쿠키를 심지 않아요 (로그인이나 설정 페이지에서만 심는 사이트도 많아요).", 0)
                header("이름", "Secure", "HttpOnly", "SameSite", "범위", "수명")
                for (c in cookies) { val iss = CookieParse.issues(c, https); row(c.name.take(28), if (c.secure) "예" else "아니요", if (c.httpOnly) "예" else "아니요", c.sameSite ?: "없음", (c.domain ?: "이 호스트") + (c.path?.let { " $it" } ?: ""), c.maxAge?.let { CacheCtl.human(it) } ?: (c.expires?.let { "만료일 지정" } ?: "세션(브라우저 닫으면 삭제)"), level = iss.maxOfOrNull { it.second } ?: -1) }
                val all = cookies.flatMap { c -> CookieParse.issues(c, https).map { "${c.name}: ${it.first}" to it.second } }
                if (all.isEmpty()) note("모든 쿠키가 안전한 속성을 갖고 있어요.", -1) else { head("고칠 점"); for ((m, l) in all) note(m, l) }
                if (!https) note("http 로 접속했어요: https 로 접속해야 Secure 속성을 제대로 판단할 수 있어요.", 1)
            }
        },

        online("web_methods", W, "허용 HTTP 메서드와 TRACE 점검", "서버가 어떤 요청 방식(GET·POST·PUT·DELETE 등)을 받는지 확인하고, 위험한 TRACE 가 켜져 있는지 시험", urlField(),
            note = "OPTIONS 요청 1번과 TRACE 요청 1번을 보내요(내용을 바꾸지 않는 요청이에요). 내가 관리하는 서버나 공개 사이트에만 쓰세요.") { i, _, env ->
            val u = i.str("u"); if (u.isEmpty()) return@online need("주소를 입력하세요")
            env.progress("OPTIONS...")
            val o = try { MiniHttp.request(u, "OPTIONS", maxBody = 0) } catch (e: IOException) { return@online fail(e) }
            env.progress("TRACE...")
            val t = runCatching { MiniHttp.request(u, "TRACE", mapOf("X-SelfCheck-Probe" to "trace-test"), 2048) }.getOrNull()
            val allow = (o.header("Allow") ?: o.header("Access-Control-Allow-Methods"))?.split(',')?.map { it.trim().uppercase() } ?: emptyList()
            result {
                kv("주소", u); kv("OPTIONS 응답", o.statusLine.substringAfter(' ')); kv("허용 메서드(Allow)", if (allow.isEmpty()) "알려 주지 않음" else allow.joinToString(", "))
                val traceOn = t != null && t.status == 200 && (t.body?.contains("trace-test") == true)
                kv("TRACE", when { t == null -> "응답 없음"; traceOn -> "켜져 있어요 (위험)"; else -> "꺼져 있어요 (${t.status})" }, if (traceOn) 2 else -1)
                if (traceOn) note("TRACE 가 켜져 있어요: 요청 내용을 그대로 되돌려 줘서 쿠키·인증 헤더가 노출되는 공격(XST)에 쓰일 수 있어요. 서버 설정에서 끄세요(Apache: TraceEnable off).", 2)
                val risky = allow.filter { it in listOf("PUT", "DELETE", "PATCH", "CONNECT") }
                if (risky.isNotEmpty()) note("${risky.joinToString(", ")} 도 허용해요. 공개 웹사이트가 아니라 API 라면 정상이지만, 일반 웹 페이지라면 불필요한 메서드는 막는 것이 좋아요.", 1)
                if (allow.isEmpty()) note("서버가 Allow 목록을 알려 주지 않았어요 (일부 서버는 OPTIONS 에 답하지 않아요).", 0)
            }
        },

        online("web_security_txt", W, "security.txt 확인", "사이트가 보안 문제 신고 창구(security.txt)를 공개했는지 확인하고 연락처·만료일을 검사", text("u", "도메인 또는 주소", "예: example.com", "github.com", URL_CHIPS.map { it.first to it.second.substringAfter("://") }), note = NOTE_WEB + " (/.well-known/security.txt 와 /security.txt)") { i, _, env ->
            val o = Web.origin(MiniHttp.parseUrl(i.str("u").ifEmpty { return@online need("도메인을 입력하세요") })?.toString() ?: return@online fail("주소를 읽지 못했어요")) ?: return@online fail("주소를 읽지 못했어요")
            var found: HttpResult? = null; var where = ""
            for (p in listOf("/.well-known/security.txt", "/security.txt")) { env.progress("$p ..."); val r = runCatching { page(o + p, 65536) }.getOrNull(); if (r != null && r.status == 200 && (r.header("Content-Type") ?: "").lowercase().let { it.isEmpty() || "text/plain" in it || "text/" in it } && !r.body.isNullOrBlank() && !r.body!!.trimStart().startsWith("<")) { found = r; where = p; break } }
            if (found == null) return@online result { kv("사이트", o); note("security.txt 가 없어요. 보안 취약점을 발견한 사람이 신고할 곳을 알려 주는 표준 파일이에요(RFC 9116). /.well-known/security.txt 에 Contact·Expires 를 적어 두는 것이 좋아요.", 1) }
            val info = SecurityTxt.parse(found.body!!); val contacts = SecurityTxt.field(info, "Contact"); val expires = SecurityTxt.field(info, "Expires").firstOrNull()
            val exp = expires?.let { runCatching { ZonedDateTime.parse(it) }.getOrNull() ?: runCatching { Instant.parse(it).atZone(ZoneId.of("UTC")) }.getOrNull() }
            result {
                kv("사이트", o); kv("위치", where, -1); kv("서명(PGP)", if (info.signed) "있어요" else "없어요")
                header("항목", "값"); for ((k, v) in info.fields) row(k, v.take(90))
                head("점검")
                if (contacts.isEmpty()) note("Contact 가 없어요 (필수 항목이에요).", 2) else note("Contact ${contacts.size}개: ${contacts.first().take(60)}", -1)
                if (expires == null) note("Expires 가 없어요 (필수 항목이에요).", 2) else if (exp == null) note("Expires 형식을 읽지 못했어요: $expires", 1) else if (exp.isBefore(ZonedDateTime.now())) note("Expires 가 지났어요(${exp.toLocalDate()}). 갱신하세요.", 2) else note("유효기간: ${exp.toLocalDate()} 까지", -1)
                if (!found.url.startsWith("https://")) note("https 로 제공해야 해요.", 1)
                if (contacts.any { it.startsWith("mailto:") || it.contains("@") }) note("연락처에 메일 주소가 보여요: 스팸이 올 수 있으니 전용 주소를 쓰세요.", 0)
            }
        },

        online("web_sitemap", W, "사이트맵 읽기", "robots.txt 와 /sitemap.xml 에서 사이트맵을 찾아 등록된 주소 수·최근 수정일·앞부분 목록을 보여 줘요", text("u", "도메인 또는 주소", "예: example.com", "www.google.com", URL_CHIPS.map { it.first to it.second.substringAfter("://") }), note = NOTE_WEB + " (robots.txt 와 사이트맵 파일)") { i, _, env ->
            val o = Web.origin(MiniHttp.parseUrl(i.str("u").ifEmpty { return@online need("도메인을 입력하세요") })?.toString() ?: return@online fail("주소를 읽지 못했어요")) ?: return@online fail("주소를 읽지 못했어요")
            env.progress("robots.txt ...")
            val robots = runCatching { page("$o/robots.txt", 65536).takeIf { it.status == 200 }?.body }.getOrNull()
            val listed = robots?.lineSequence()?.mapNotNull { l -> if (l.trim().startsWith("sitemap:", true)) l.substringAfter(':').trim() else null }?.toList() ?: emptyList()
            val urls = (listed.ifEmpty { listOf("$o/sitemap.xml") }).take(3)
            result {
                kv("사이트", o); kv("robots.txt 의 사이트맵", if (listed.isEmpty()) "없음 (/sitemap.xml 을 시도)" else "${listed.size}개")
                for (su in urls) {
                    env.progress("$su ...")
                    val r = runCatching { page(su, 2_000_000) }.getOrNull()
                    head(su)
                    if (r == null) { note("접속하지 못했어요.", 1); continue }
                    if (r.status != 200 || r.body.isNullOrBlank()) { note("${r.statusLine.substringAfter(' ')} — 사이트맵이 없어요.", 1); continue }
                    val xml = r.body!!; val locs = Sitemap.locs(xml); val mods = Sitemap.lastmods(xml).sortedDescending()
                    kv("종류", if (Sitemap.isIndex(xml)) "사이트맵 목록(index)" else "주소 목록(urlset)"); kv(if (Sitemap.isIndex(xml)) "하위 사이트맵" else "등록된 주소", "${locs.size}개", if (locs.isEmpty()) 2 else -1)
                    if (mods.isNotEmpty()) kv("가장 최근 수정일", mods.first())
                    if (locs.isNotEmpty()) block(locs.take(25).joinToString("\n") + if (locs.size > 25) "\n… 외 ${locs.size - 25}개" else "")
                    if (locs.size >= 50000) note("사이트맵 하나에는 최대 50,000개 주소만 넣을 수 있어요.", 1)
                    if (locs.any { it.startsWith("http://") } && o.startsWith("https://")) note("https 사이트인데 http 주소가 섞여 있어요.", 1)
                }
            }
        },

        online("web_links", W, "페이지 링크 추출·깨진 링크 점검", "페이지의 링크를 모아 내부·외부로 나누고, 일부(최대 20개)가 살아 있는지 HEAD 요청으로 확인", urlField(), note = "페이지를 받은 뒤, 링크 최대 20개에 HEAD 요청을 보내요(다른 사이트에도 요청이 가요). 내 사이트나 공개 페이지에만 쓰세요.") { i, _, env ->
            val u = i.str("u"); if (u.isEmpty()) return@online need("주소를 입력하세요")
            val r = try { page(u) } catch (e: IOException) { return@online fail(e) }
            val html = r.body ?: ""; val els = HtmlDoc.elements(html); val base = HtmlDoc.elements(html).firstOrNull { it.name == "base" }?.attrs?.get("href")?.let { HtmlDoc.abs(r.url, it) } ?: r.url
            val links = HtmlDoc.anchors(els, base).map { it.substringBefore('#') }.distinct(); val host = HtmlDoc.hostOf(r.url)
            val internal = links.filter { HtmlDoc.hostOf(it) == host }; val external = links.filter { HtmlDoc.hostOf(it) != host }
            val pick = (internal.take(12) + external.take(8)).take(20)
            env.progress("${pick.size}개 확인 중...")
            val res = Par.map(pick, 6, 25000) { l -> runCatching { var x = MiniHttp.request(l, "HEAD", maxBody = 0, timeoutMs = 6000); if (x.status == 405 || x.status == 501 || x.status == 403) x = MiniHttp.request(l, "GET", maxBody = 0, timeoutMs = 6000); x.status.toString() }.getOrElse { "오류: ${it.message?.take(40)}" } }
            result {
                kv("페이지", r.url); kv("상태", r.statusLine.substringAfter(' '), lv(r.status)); kv("링크", "${links.size}개 (내부 ${internal.size} · 외부 ${external.size})"); kv("확인한 링크", "${pick.size}개")
                if (pick.isNotEmpty()) { header("상태", "주소"); pick.forEachIndexed { k, l -> val s = res[k] ?: "응답 없음"; val code = s.toIntOrNull(); row(s, l.take(90), level = if (code == null) 2 else if (code in 200..399) -1 else if (code in 400..499) 2 else 1) }
                    val bad = pick.indices.count { k -> val c = res[k]?.toIntOrNull(); c == null || c >= 400 }
                    note(if (bad == 0) "확인한 링크는 모두 정상이에요." else "${bad}개가 열리지 않아요(4xx·5xx·오류). 깨진 링크는 사용자와 검색 순위에 나빠요. 일부 사이트는 자동 요청(HEAD)을 막아 정상 링크가 403 으로 나올 수 있어요.", if (bad == 0) -1 else 1) }
                else note("확인할 링크가 없어요. 링크가 스크립트로 만들어지는 페이지는 읽을 수 없어요.", 1)
                if (links.size > pick.size) note("나머지 ${links.size - pick.size}개는 확인하지 않았어요.")
            }
        },

        online("web_seo", W, "페이지 기본 정보(SEO) 점검", "제목·설명·canonical·robots·viewport·언어·Open Graph·h1·이미지 대체 글을 읽고 검색·공유에 필요한 것이 있는지 점검", urlField(), note = NOTE_WEB) { i, _, _ ->
            val u = i.str("u"); if (u.isEmpty()) return@online need("주소를 입력하세요")
            val r = try { page(u) } catch (e: IOException) { return@online fail(e) }
            val html = r.body ?: ""; val els = HtmlDoc.elements(html); val meta = HtmlDoc.metas(els)
            val title = HtmlDoc.title(html); val desc = meta["description"]; val canon = HtmlDoc.linkRel(els, "canonical").firstOrNull(); val lang = els.firstOrNull { it.name == "html" }?.attrs?.get("lang")
            val h1 = els.count { it.name == "h1" }; val imgs = els.filter { it.name == "img" }; val noAlt = imgs.count { it.attrs["alt"] == null }; val words = HtmlDoc.visibleText(html).let { t -> t.split(' ').count { it.isNotBlank() } }
            val robots = meta["robots"]?.lowercase() ?: ""
            result {
                kv("페이지", r.url); kv("상태", r.statusLine.substringAfter(' '), lv(r.status)); kv("HTML 크기", "%,d 바이트".format(r.body?.length ?: 0)); kv("응답 시간", "${r.timings.totalMs}ms", if (r.timings.totalMs > 1500) 1 else 0)
                header("항목", "값", "평가")
                row("제목", title ?: "없음", if (title == null) "필수" else "${title.length}자" + if (title.length in 15..60) " (좋아요)" else " (30~60자 권장)", level = if (title == null) 2 else if (title.length in 15..60) -1 else 1)
                row("설명(description)", desc?.take(60) ?: "없음", if (desc == null) "검색 결과 요약에 쓰여요" else "${desc.length}자" + if (desc.length in 70..170) " (좋아요)" else " (70~160자 권장)", level = if (desc == null) 1 else if (desc.length in 70..170) -1 else 1)
                row("canonical", canon ?: "없음", if (canon == null) "중복 주소 정리에 필요" else "있어요", level = if (canon == null) 1 else -1)
                row("robots 메타", meta["robots"] ?: "없음", if ("noindex" in robots) "검색 제외(noindex)!" else "색인 허용", level = if ("noindex" in robots) 2 else 0)
                row("viewport", meta["viewport"]?.take(40) ?: "없음", if (meta["viewport"] == null) "모바일 화면이 깨질 수 있어요" else "있어요", level = if (meta["viewport"] == null) 2 else -1)
                row("언어(html lang)", lang ?: "없음", if (lang == null) "접근성·번역에 필요" else "있어요", level = if (lang == null) 1 else -1)
                row("h1 제목", "${h1}개", if (h1 == 1) "좋아요" else if (h1 == 0) "없어요" else "여러 개예요", level = if (h1 == 1) -1 else 1)
                row("이미지", "${imgs.size}개", if (noAlt == 0) "모두 alt 가 있어요" else "alt 없는 이미지 ${noAlt}개", level = if (noAlt == 0) -1 else 1)
                row("본문 단어 수", "$words", if (words < 100) "내용이 적어요" else "충분해요", level = if (words < 100) 1 else -1)
                val og = listOf("og:title", "og:description", "og:image").filter { meta[it] != null }
                row("공유 미리보기(Open Graph)", og.joinToString(", ").ifEmpty { "없음" }, if (og.size == 3) "제목·설명·이미지 모두 있어요" else "카톡·SNS 공유 시 미리보기가 빈약해요", level = if (og.size == 3) -1 else 1)
                row("트위터 카드", meta["twitter:card"] ?: "없음", "", level = 0)
                row("구조화 데이터(JSON-LD)", if (html.contains("application/ld+json", true)) "있어요" else "없어요", "", level = 0)
                row("https", if (r.url.startsWith("https://")) "예" else "아니요", if (r.url.startsWith("https://")) "" else "http 는 검색·브라우저가 안전하지 않다고 표시해요", level = if (r.url.startsWith("https://")) -1 else 2)
            }
        },

        online("web_external", W, "외부 리소스·추적기·혼합 콘텐츠 점검", "페이지가 불러오는 외부 도메인(광고·분석 추적기 포함)을 모아 보여 주고, https 페이지에 http 자원이 섞였는지 점검", urlField("https://www.naver.com"), note = NOTE_WEB) { i, _, _ ->
            val u = i.str("u"); if (u.isEmpty()) return@online need("주소를 입력하세요")
            val r = try { page(u) } catch (e: IOException) { return@online fail(e) }
            val res = HtmlDoc.resources(HtmlDoc.elements(r.body ?: ""), r.url); val host = HtmlDoc.hostOf(r.url) ?: ""; val site = EmailHeader.baseDomain(host)
            val ext = res.filter { HtmlDoc.hostOf(it.second)?.let { h -> EmailHeader.baseDomain(h) != site } == true }
            val byHost = ext.groupBy { HtmlDoc.hostOf(it.second)!! }.map { (h, l) -> Triple(h, l.size, l.map { it.first }.distinct()) }.sortedByDescending { it.second }
            val mixed = if (r.url.startsWith("https://")) res.filter { it.second.startsWith("http://") } else emptyList()
            val trackers = byHost.mapNotNull { (h, _, _) -> Trackers.match(h)?.let { h to it } }
            result {
                kv("페이지", r.url); kv("불러오는 리소스", "${res.size}개 (같은 사이트 ${res.size - ext.size} · 외부 ${ext.size})"); kv("외부 도메인", "${byHost.size}곳"); kv("추적·광고 의심", "${trackers.size}곳", if (trackers.isEmpty()) -1 else 1)
                if (byHost.isNotEmpty()) { head("외부 도메인"); header("도메인", "개수", "종류", "분류"); for ((h, n, k) in byHost.take(40)) row(h, "$n", k.joinToString(","), Trackers.match(h) ?: "-", level = if (Trackers.match(h) != null) 1 else 0) }
                head("혼합 콘텐츠")
                if (mixed.isEmpty()) note(if (r.url.startsWith("https://")) "https 페이지에 http 자원이 없어요 (좋아요)." else "http 페이지라 혼합 콘텐츠를 판단하지 않아요.", if (r.url.startsWith("https://")) -1 else 0)
                else { for ((k, m) in mixed.take(15)) note("$k: $m", if (k in listOf("script", "css", "iframe")) 2 else 1); note("스크립트·CSS·iframe 이 http 면 브라우저가 차단하고 사이트 일부가 깨져요. 이미지·미디어는 경고만 떠요.", 1) }
                if (trackers.isNotEmpty()) note("광고·분석 서비스가 방문자의 정보를 외부로 보내요. 개인정보 처리방침에 알리고 동의 절차를 갖췄는지 확인하세요.", 1)
            }
        },

        online("web_stack", W, "사용 기술 추정 (웹 서버·CMS·프레임워크)", "응답 헤더·쿠키·HTML 단서로 웹 서버·워드프레스·React 등 사이트가 쓰는 기술을 추정", urlField(), note = NOTE_WEB) { i, _, _ ->
            val u = i.str("u"); if (u.isEmpty()) return@online need("주소를 입력하세요")
            val r = try { page(u) } catch (e: IOException) { return@online fail(e) }
            val found = StackDetect.detect(r.headers, r.body)
            result { kv("주소", r.url); kv("상태", r.statusLine.substringAfter(' '), lv(r.status)); r.remoteIp.let { kv("서버 IP", it) }
                if (found.isEmpty()) note("알려진 기술의 흔적을 찾지 못했어요. 헤더를 숨기거나 스크립트로 만들어지는 페이지일 수 있어요.", 1)
                else { header("기술", "근거"); for ((n, e) in found) row(n, e) }
                note("공개된 흔적으로 짐작한 것이라 틀릴 수 있어요. 내 사이트라면 서버 버전·제작 도구 표시를 숨기면 공격자가 취약점을 고르기 어려워요.") }
        },

        online("web_robots_test", W, "robots.txt 로 이 주소가 허용되는지 시험", "검색 로봇(구글·네이버 등)이 특정 주소를 수집해도 되는지 robots.txt 규칙(Allow·Disallow·*·$)으로 판정", urlField("https://example.com/admin/page"),
            choice("ua", "로봇", listOf("Googlebot", "Bingbot", "Yeti (네이버)", "Daumoa (다음)", "* (그 밖의 모든 로봇)")), note = NOTE_WEB + " (그 사이트의 /robots.txt)") { i, _, env ->
            val u = i.str("u"); val p = MiniHttp.parseUrl(u.ifEmpty { return@online need("주소를 입력하세요") }) ?: return@online fail("주소를 읽지 못했어요")
            val o = Web.origin(p.toString())!!; env.progress("robots.txt ...")
            val r = try { page("$o/robots.txt", 524288) } catch (e: IOException) { return@online fail(e) }
            val ua = i.str("ua").substringBefore(' ').let { if (it == "*") "*" else it }
            result {
                kv("검사한 주소", p.toString()); kv("로봇", i.str("ua")); kv("robots.txt", r.statusLine.substringAfter(' '), if (r.status == 200) -1 else 1)
                if (r.status != 200 || r.body.isNullOrBlank()) return@result note("robots.txt 가 없어서 모든 로봇이 모든 주소를 수집할 수 있어요.", 0)
                val (ok, rule) = RobotsMatcher.allowed(r.body!!, ua, p.path)
                kv("결과", if (ok) "수집 허용" else "수집 금지", if (ok) -1 else 2); kv("적용된 규칙", rule ?: "해당 규칙 없음 (기본 허용)")
                note("robots.txt 는 \"하지 말아 주세요\"라는 부탁일 뿐 접근을 막는 보안 장치가 아니에요. 숨기고 싶은 페이지는 로그인·접근 제한을 거세요. (이 판정은 robots.txt 규칙만 해석한 것이고 각 검색 엔진의 최종 동작과 다를 수 있어요.)")
            }
        },

        online("web_server_time", W, "웹서버 시각 확인 (내 시계 오차)", "웹서버가 응답에 담아 보내는 Date 로 내 폰 시계가 얼마나 틀렸는지 확인 — NTP(UDP 123)가 막힌 망에서도 가능", urlField("https://www.google.com"), note = NOTE_WEB) { i, _, _ ->
            val u = i.str("u"); if (u.isEmpty()) return@online need("주소를 입력하세요")
            val before = System.currentTimeMillis()
            val r = try { MiniHttp.request(u, "HEAD", maxBody = 0) } catch (e: IOException) { return@online fail(e) }
            val after = System.currentTimeMillis()
            val d = r.header("Date") ?: return@online fail("서버가 Date 머리글을 보내지 않았어요")
            val t = EmailHeader.parseDate(d) ?: return@online fail("Date 를 읽지 못했어요: $d")
            val phone = (before + after) / 2; val diff = phone - t.toInstant().toEpochMilli()
            result {
                kv("서버 시각", d); kv("내 폰 시각", DateTimeFormatter.RFC_1123_DATE_TIME.format(Instant.ofEpochMilli(phone).atZone(ZoneId.of("GMT")))); kv("왕복 시간", "${after - before}ms")
                kv("내 시계 오차", if (Math.abs(diff) < 1500) "±1초 이내" else "${if (diff > 0) "폰이 ${diff / 1000}초 빨라요" else "폰이 ${-diff / 1000}초 느려요"}", if (Math.abs(diff) < 2000) -1 else if (Math.abs(diff) < 30000) 1 else 2)
                note("웹서버 Date 는 1초 단위라 정밀도가 낮아요(정밀한 확인은 'NTP 시간 서버 비교'). 오차가 수십 초 이상이면 \"날짜 및 시간 자동 설정\"을 켜세요 — HTTPS 인증서·OTP 코드 오류의 원인이에요.")
            }
        },

        online("web_download_speed", W, "파일 다운로드 속도 시험 (내가 고른 주소)", "내가 고른 파일 주소에서 일정 용량을 받아 실제 다운로드 속도를 측정 — 특정 서버·CDN 까지의 속도 확인", urlField("https://speed.cloudflare.com/__down?bytes=25000000", "파일 주소"), choice("max", "최대로 받을 용량", listOf("5MB", "20MB", "50MB"), "20MB"),
            note = "입력한 주소에서 파일을 받아 용량만큼에서 멈춰요(저장하지 않아요). 모바일 데이터는 선택한 용량만큼 써요.") { i, _, env ->
            val u = i.str("u"); if (u.isEmpty()) return@online need("파일 주소를 입력하세요")
            val max = i.str("max").removeSuffix("MB").toLong() * 1_000_000
            env.progress("받는 중...")
            val d = try { Downloader.measure(u, max, 9000, env.cancel) { env.progress("%.1f MB 받음".format(it / 1e6)) } } catch (e: IOException) { return@online fail("받지 못했어요: ${e.message}") } catch (e: javax.net.ssl.SSLException) { return@online fail("TLS 오류: ${e.message?.take(100)}") }
            result {
                kv("주소", u.take(90)); kv("응답", d.statusLine.substringAfter(' '), lv(d.status)); kv("첫 바이트까지", "${d.ttfbMs}ms"); kv("받은 용량", "%.2f MB".format(d.bytes / 1e6)); d.contentLength?.let { kv("파일 크기(Content-Length)", "%.2f MB".format(it / 1e6)) }
                if (d.bodyMs >= 80 && d.bytes > 0) { val mbps = d.bytes * 8.0 / (d.bodyMs / 1000.0) / 1e6; kv("다운로드 속도", "%.1f Mbps  (%.1f MB/s)".format(mbps, mbps / 8), -1) } else note("받은 시간이 너무 짧아서(0.1초 미만) 속도를 정확히 잴 수 없어요. 더 큰 용량을 선택하세요.", 1)
                note("서버·경로(CDN)·시간대에 따라 달라지는 값이에요. 여러 번 재 보세요.")
            }
        },

        online("web_ipv6", W, "사이트의 IPv6 지원 점검", "도메인에 IPv6(AAAA) 주소가 있는지, 그 주소로 실제 접속이 되는지 (내 기기가 IPv6 를 쓸 수 있을 때)", hostField("www.google.com", "도메인"), note = "도메인의 AAAA 레코드를 DNS 에 묻고, 있으면 그 주소의 443 포트에 연결을 시도해요. 인터넷을 사용해요.") { i, host, env ->
            val h = HostInput.host(i.str("h")); if (h.isEmpty()) return@online need("도메인을 입력하세요")
            val servers = DnsTools.servers(i, host); env.progress("AAAA 조회...")
            val aaaa = try { DnsTools.ask(servers, h, DnsType.AAAA, host).msg.answers.filter { it.type == DnsType.AAAA }.map { it.data } } catch (e: IOException) { return@online fail("조회하지 못했어요: ${e.message}") }
            val a = runCatching { DnsTools.ask(servers, h, DnsType.A, host).msg.answers.filter { it.type == DnsType.A }.map { it.data } }.getOrDefault(emptyList())
            val conn = aaaa.firstOrNull()?.let { ip -> runCatching { val t0 = System.nanoTime(); Socket().use { it.connect(InetSocketAddress(IpUtil.parse(ip), 443), 4000) }; (System.nanoTime() - t0) / 1_000_000 }.getOrNull() }
            result {
                kv("도메인", h); kv("IPv4(A)", if (a.isEmpty()) "없음" else a.take(4).joinToString(", ")); kv("IPv6(AAAA)", if (aaaa.isEmpty()) "없음" else aaaa.take(3).joinToString(", "), if (aaaa.isEmpty()) 1 else -1)
                if (aaaa.isNotEmpty()) kv("IPv6 로 접속", if (conn != null) "됐어요 (${conn}ms)" else "안 됐어요", if (conn != null) -1 else 1)
                note(when { aaaa.isEmpty() -> "이 도메인은 IPv6 주소가 없어요. IPv6 만 쓰는 망(일부 이동통신·해외)에서는 NAT64 를 거쳐야 하거나 접속이 어려워요. DNS 에 AAAA 레코드를 추가하면 지원할 수 있어요."; conn != null -> "IPv6 로 접속돼요."; else -> "AAAA 는 있지만 접속에 실패했어요. 내 기기·망이 IPv6 를 못 쓰거나 서버의 IPv6 방화벽 설정 문제일 수 있어요(내 망의 IPv6 는 'IPv4·IPv6 공인 주소 확인'으로 확인하세요)." }, if (aaaa.isNotEmpty() && conn != null) -1 else 1)
            }
        },

        online("web_ct_logs", W, "인증서 투명성 로그 조회 (발급된 인증서·서브도메인)", "내 도메인에 지금까지 발급된 HTTPS 인증서를 공개 로그(crt.sh)에서 찾아 — 모르는 인증서나 잊은 서브도메인 점검", hostField("example.com", "도메인"),
            note = "도메인 이름을 crt.sh(인증서 투명성 로그 검색)에 보내 조회해요. 공개된 정보만 나오고, 느리거나 실패할 수 있어요.") { i, _, env ->
            val d = HostInput.host(i.str("h")).removePrefix("*.").removePrefix("www."); if (d.isEmpty() || !HostInput.isPlausibleDomain(d)) return@online need("도메인을 입력하세요 (예: example.com)")
            env.progress("crt.sh 에서 찾는 중... (최대 20초)")
            val arr = try { JSONArray(GeoNet.get("https://crt.sh/?q=%25.$d&output=json", 22000, 6_000_000)) } catch (e: IOException) { return@online fail("조회하지 못했어요: ${e.message} (crt.sh 가 바쁠 때 자주 실패해요. 잠시 뒤 다시 해 보세요)") } catch (e: org.json.JSONException) { return@online fail("응답을 읽지 못했어요") }
            class E(val id: Long, val names: List<String>, val issuer: String, val before: String, val after: String, val logged: String)
            val es = (0 until arr.length()).mapNotNull { k -> arr.optJSONObject(k)?.let { o -> E(o.optLong("id"), o.optString("name_value").split('\n').map { it.trim().lowercase() }.filter { it.isNotEmpty() }, o.optString("issuer_name").let { s -> Regex("""CN=([^,]+)""").find(s)?.groupValues?.get(1) ?: s }, o.optString("not_before").take(10), o.optString("not_after").take(10), o.optString("entry_timestamp").take(10)) } }.distinctBy { it.id }
            if (es.isEmpty()) return@online result { kv("도메인", d); note("발급 기록이 없어요.", 1) }
            val names = es.flatMap { it.names }.distinct().sorted(); val today = java.time.LocalDate.now().toString()
            val active = es.filter { it.after >= today }
            result {
                kv("도메인", d); kv("발급 기록", "${es.size}건 (아직 유효 ${active.size}건)"); kv("서로 다른 이름", "${names.size}개"); kv("와일드카드(*.)", "${names.count { it.startsWith("*.") }}개")
                head("최근 발급 20건"); header("발급일", "이름", "발급 기관", "만료일")
                for (e in es.sortedByDescending { it.before }.take(20)) row(e.before, e.names.take(2).joinToString(", ") + if (e.names.size > 2) " 외 ${e.names.size - 2}" else "", e.issuer.take(30), e.after, level = if (e.after < today) 0 else -1)
                head("발견된 이름 (${names.size}개)"); block(names.take(150).joinToString("\n") + if (names.size > 150) "\n… 외 ${names.size - 150}개" else "")
                note("모르는 서브도메인이나 내가 발급하지 않은 인증서가 보이면 점검하세요(해킹·사칭·잊은 서비스일 수 있어요). 공개 로그에는 비밀 서브도메인 이름도 남으니, 숨기고 싶은 이름은 와일드카드 인증서를 쓰는 방법이 있어요.", 1)
            }
        },

        online("web_https_grade", W, "HTTPS 설정 종합 점검 (A~F 등급)", "TLS 버전·인증서·낡은 TLS 허용 여부·HSTS·http→https 이동을 모아 점수와 등급으로", hostField("example.com"), note = "서버에 TLS 접속 여러 번(버전별)과 웹 요청 1~2번을 보내요. 인터넷을 사용해요.") { i, _, env ->
            val (h, port) = DiagTools.hostPort(i.str("h")); if (h.isEmpty()) return@online need("도메인을 입력하세요")
            env.progress("TLS 접속...")
            val rep = try { TlsInspect.inspect(h, port, 7000) } catch (e: Exception) { return@online fail("TLS 접속에 실패했어요: ${e.message?.take(100) ?: e.javaClass.simpleName}") }
            val mine = runCatching { TlsInspect.supportedProtocols() }.getOrDefault(emptyList())
            fun accepts(p: String): Boolean? = if (p !in mine) null else try { TlsInspect.inspect(h, port, 5000, arrayOf(p)); true } catch (_: Exception) { false }
            env.progress("낡은 TLS 확인...")
            val old = listOf("TLSv1.1", "TLSv1").map { it to accepts(it) }; val tls13 = accepts("TLSv1.3")
            env.progress("웹 응답 확인...")
            val web = runCatching { MiniHttp.request("https://$h${if (port == 443) "" else ":$port"}/", "GET", maxBody = 0, insecure = true) }.getOrNull()
            val redirect = if (port == 443) runCatching { MiniHttp.request("http://$h/", "GET", maxBody = 0, timeoutMs = 5000) }.getOrNull() else null
            val hsts = web?.header("Strict-Transport-Security"); val age = hsts?.let { Regex("""max-age=(\d+)""", RegexOption.IGNORE_CASE).find(it)?.groupValues?.get(1)?.toLongOrNull() }
            val leaf = rep.chain.firstOrNull(); val days = leaf?.let { CertInfo.daysLeft(it) } ?: 0
            val ded = ArrayList<Triple<String, Int, String>>()
            if (!rep.trusted) ded += Triple("인증서를 믿을 수 없어요", 100, rep.trustError ?: ""); if (!rep.hostnameOk) ded += Triple("인증서 이름이 달라요", 100, "접속한 주소가 인증서에 없어요")
            if (days < 0) ded += Triple("인증서가 만료됐어요", 100, "${-days}일 전")
            else if (days < 14) ded += Triple("인증서 만료가 임박했어요", 15, "${days}일 남음") else if (days < 30) ded += Triple("인증서 만료가 가까워요", 5, "${days}일 남음")
            for ((p, ok) in old) if (ok == true) ded += Triple("낡은 $p 를 허용해요", 20, "TLS 1.2 이상만 켜세요")
            if (rep.protocol == "TLSv1.2" && tls13 == false) ded += Triple("TLS 1.3 을 지원하지 않아요", 5, "1.3 이 더 빠르고 안전해요")
            if (web != null) { if (hsts == null) ded += Triple("HSTS 가 없어요", 10, "Strict-Transport-Security 로 https 만 쓰도록 강제") else if ((age ?: 0) < 15552000) ded += Triple("HSTS 기간이 짧아요", 5, "max-age 180일 이상 권장") }
            if (redirect != null) { val toHttps = redirect.isRedirect && (redirect.header("Location") ?: "").startsWith("https://"); if (!toHttps) ded += Triple("http 접속이 https 로 이동하지 않아요", 10, "80번 포트 접속을 https 로 보내세요") }
            val score = (100 - ded.sumOf { it.second }).coerceAtLeast(0); val cap = ded.any { it.second >= 100 }
            val grade = when { cap -> "F"; score >= 95 -> "A+"; score >= 90 -> "A"; score >= 80 -> "B"; score >= 70 -> "C"; score >= 60 -> "D"; else -> "F" }
            result {
                kv("서버", "$h:$port"); kv("등급", "$grade  ($score 점)", if (grade.startsWith("A")) -1 else if (grade == "B" || grade == "C") 1 else 2)
                kv("TLS 버전", rep.protocol); kv("TLS 1.3", when (tls13) { true -> "지원"; false -> "미지원"; null -> "이 기기가 확인할 수 없어요" }); old.forEach { (p, ok) -> kv(p, when (ok) { true -> "허용해요 (위험)"; false -> "거부해요"; null -> "이 기기가 확인할 수 없어요" }, if (ok == true) 2 else 0) }
                kv("인증서", if (rep.trusted) "믿을 수 있어요" else (rep.trustError ?: "믿을 수 없어요"), if (rep.trusted) -1 else 2); kv("인증서 만료", if (days < 0) "${-days}일 전 만료" else "${days}일 남음", if (days < 14) 2 else if (days < 30) 1 else -1)
                kv("HSTS", hsts?.take(80) ?: if (web == null) "확인 못 함" else "없음", if (hsts != null) -1 else 1); redirect?.let { kv("http → https", if (it.isRedirect && (it.header("Location") ?: "").startsWith("https://")) "이동해요" else "이동하지 않아요 (${it.status})", if (it.isRedirect && (it.header("Location") ?: "").startsWith("https://")) -1 else 1) }
                if (port != 443) note("443 이 아닌 포트라서 http → https 이동은 확인하지 않았어요.")
                if (ded.isEmpty()) note("감점 항목이 없어요. 잘 설정돼 있어요.", -1) else { head("감점 항목"); header("항목", "감점", "설명"); for ((n, p, d) in ded) row(n, if (p >= 100) "치명적" else "-$p", d, level = if (p >= 15) 2 else 1) }
                note("이 점수는 이 도구가 확인한 몇 가지 기준만으로 낸 간단한 등급이에요 (암호 스위트 세부·OCSP·인증서 체인 품질은 보지 않아요).")
            }
        },
    )
}

/** 파일을 받아 크기만큼만 읽고 버리면서 속도를 잼 (저장하지 않음). https 는 시스템 인증서로 검증 */
object Downloader {
    class Result(val statusLine: String, val status: Int, val ttfbMs: Long, val bodyMs: Long, val bytes: Long, val contentLength: Long?)

    fun measure(url: String, maxBytes: Long, timeoutMs: Int, cancel: java.util.concurrent.atomic.AtomicBoolean = java.util.concurrent.atomic.AtomicBoolean(false), newSocket: () -> Socket = { Socket() }, progress: (Long) -> Unit = {}): Result {
        val u = MiniHttp.parseUrl(url) ?: throw IOException("주소 형식이 올바르지 않아요")
        val addr = try { TlsInspect.resolve(u.host) } catch (_: Exception) { throw IOException("도메인을 찾지 못했어요 (${u.host})") }
        if (IpUtil.classify(addr).blocked) throw IOException("이 주소로는 받을 수 없어요")
        var sock = newSocket(); val t0 = System.nanoTime()
        try {
            sock.connect(InetSocketAddress(addr, u.port), timeoutMs); sock.soTimeout = timeoutMs
            if (u.isHttps) { val ssl = (SSLSocketFactory.getDefault() as SSLSocketFactory).createSocket(sock, u.host, u.port, true) as SSLSocket; ssl.sslParameters = ssl.sslParameters.also { it.endpointIdentificationAlgorithm = "HTTPS" }; ssl.startHandshake(); sock = ssl }
            sock.getOutputStream().apply { write("GET ${u.path} HTTP/1.1\r\nHost: ${u.host}\r\nUser-Agent: SelfCheck-NetTools/1.0\r\nAccept: */*\r\nAccept-Encoding: identity\r\nConnection: close\r\n\r\n".toByteArray()); flush() }
            val ins = java.io.BufferedInputStream(sock.getInputStream(), 65536)
            fun line(): String? { val sb = StringBuilder(); while (true) { val c = ins.read(); if (c < 0) return if (sb.isEmpty()) null else sb.toString(); if (c == '\n'.code) return sb.toString().trimEnd('\r'); sb.append(c.toChar()); if (sb.length > 16384) throw IOException("머리글이 너무 길어요") } }
            val first = line() ?: throw IOException("서버가 아무 응답 없이 연결을 닫았어요"); val ttfb = (System.nanoTime() - t0) / 1_000_000
            val status = Regex("""^HTTP/\d(?:\.\d)?\s+(\d{3})""").find(first)?.groupValues?.get(1)?.toInt() ?: throw IOException("HTTP 응답이 아니에요")
            var cl: Long? = null; var chunked = false
            while (true) { val l = line() ?: break; if (l.isEmpty()) break; val k = l.substringBefore(':').lowercase(); val v = l.substringAfter(':').trim(); if (k == "content-length") cl = v.toLongOrNull(); if (k == "transfer-encoding" && v.contains("chunked", true)) chunked = true }
            val buf = ByteArray(65536); var total = 0L; val t1 = System.nanoTime(); var lastReport = 0L
            while (total < maxBytes && !cancel.get()) { val r = try { ins.read(buf, 0, minOf(buf.size.toLong(), maxBytes - total).toInt()) } catch (_: java.net.SocketTimeoutException) { break }; if (r < 0) break; total += r; if (total - lastReport > 1_000_000) { lastReport = total; progress(total) } }
            return Result(first, status, ttfb, (System.nanoTime() - t1) / 1_000_000, total, if (chunked) null else cl)
        } finally { runCatching { sock.close() } }
    }
}
