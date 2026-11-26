package com.selfcheck.app

import java.io.IOException
import java.net.InetSocketAddress
import java.net.Socket
import java.net.URI
import java.security.cert.X509Certificate
import javax.net.ssl.SSLContext
import javax.net.ssl.SSLParameters
import javax.net.ssl.SSLSocket
import javax.net.ssl.TrustManager
import javax.net.ssl.X509TrustManager

/*
 * 웹사이트 점검 엔진: HTML 읽기(제목·메타·링크·리소스), 캐시·쿠키·CORS·security.txt·사이트맵·robots 규칙 해석,
 * 사용 기술 추정, 추적기 도메인, HTTP/2(ALPN) 협상. 화면·인터넷과 분리해서 컴퓨터에서 시험합니다.
 */

object Web {
    /** 리다이렉트를 따라가며 마지막 응답의 본문까지 받음 (최대 hops 번 이동) */
    fun get(url: String, maxBody: Int = 524288, insecure: Boolean = false, headers: Map<String, String> = emptyMap(), hops: Int = 5, timeoutMs: Int = 9000, newSocket: () -> Socket = { Socket() }): HttpResult {
        var cur = url
        for (n in 0..hops) {
            val r = MiniHttp.request(cur, "GET", headers, maxBody, timeoutMs, insecure, newSocket = newSocket)
            if (r.isRedirect && n < hops) { cur = try { URI(r.url).resolve(r.header("Location")!!.trim()).toString() } catch (_: Exception) { return r }; continue }
            return r
        }
        throw IOException("이동이 너무 많아요")
    }

    /** "https://example.com/a/b?x" → "https://example.com" */
    fun origin(url: String): String? = MiniHttp.parseUrl(url)?.let { u -> "${u.scheme}://${if (':' in u.host) "[${u.host}]" else u.host}${if (u.port == (if (u.isHttps) 443 else 80)) "" else ":${u.port}"}" }
}

object HtmlDoc {
    private val TAG = Regex("""<(a|link|meta|script|img|iframe|form|source|video|audio|h1|html|base|embed|object|input)\b([^>]*)>""", RegexOption.IGNORE_CASE)
    private val ATTR = Regex("""([a-zA-Z_:][-a-zA-Z0-9_:.]*)\s*(?:=\s*(?:"([^"]*)"|'([^']*)'|([^\s"'>]+)))?""")

    class El(val name: String, val attrs: Map<String, String>)

    fun attrs(body: String): Map<String, String> {
        val m = LinkedHashMap<String, String>()
        for (a in ATTR.findAll(body)) { val k = a.groupValues[1].lowercase(); val v = a.groupValues[2].ifEmpty { a.groupValues[3].ifEmpty { a.groupValues[4] } }; m.putIfAbsent(k, decode(v)) }
        return m
    }

    private val COMMENT = Regex("<!--.*?-->", RegexOption.DOT_MATCHES_ALL)
    private val SCRIPT_BODY = Regex("""(<script\b[^>]*>).*?(</script\s*>)""", setOf(RegexOption.IGNORE_CASE, RegexOption.DOT_MATCHES_ALL))
    private val STYLE_BODY = Regex("""(<style\b[^>]*>).*?(</style\s*>)""", setOf(RegexOption.IGNORE_CASE, RegexOption.DOT_MATCHES_ALL))

    /** 주석·스크립트·스타일 안의 글은 태그가 아니라서 빼고 읽음 (스크립트가 만드는 HTML 조각이 링크로 잡히지 않게) */
    fun elements(html: String): List<El> {
        val clean = html.replace(COMMENT, " ").replace(SCRIPT_BODY, "$1$2").replace(STYLE_BODY, "$1$2")
        return TAG.findAll(clean).map { El(it.groupValues[1].lowercase(), attrs(it.groupValues[2])) }.toList()
    }

    fun decode(s: String): String = s.replace("&amp;", "&").replace("&quot;", "\"").replace("&#39;", "'").replace("&lt;", "<").replace("&gt;", ">").replace("&#x2F;", "/")

    fun title(html: String): String? = Regex("""<title[^>]*>(.*?)</title>""", setOf(RegexOption.IGNORE_CASE, RegexOption.DOT_MATCHES_ALL)).find(html)?.groupValues?.get(1)?.let { decode(it).trim().replace(Regex("\\s+"), " ") }?.takeIf { it.isNotEmpty() }

    /** <meta name|property=... content=...> 를 이름(소문자) → 값 으로 */
    fun metas(els: List<El>): Map<String, String> {
        val m = LinkedHashMap<String, String>()
        for (e in els) if (e.name == "meta") { val k = (e.attrs["name"] ?: e.attrs["property"] ?: e.attrs["http-equiv"])?.lowercase() ?: continue; e.attrs["content"]?.let { m.putIfAbsent(k, it) } }
        return m
    }

    fun linkRel(els: List<El>, rel: String): List<String> = els.filter { it.name == "link" && it.attrs["rel"]?.lowercase()?.split(' ')?.contains(rel) == true }.mapNotNull { it.attrs["href"] }

    /** 본문에서 보이는 글자 수준의 텍스트 (스크립트·스타일·태그 제거) */
    fun visibleText(html: String): String = html.replace(Regex("""<(script|style|noscript)\b.*?</\1>""", setOf(RegexOption.IGNORE_CASE, RegexOption.DOT_MATCHES_ALL)), " ").replace(Regex("<!--.*?-->", RegexOption.DOT_MATCHES_ALL), " ").replace(Regex("<[^>]+>"), " ").let { decode(it) }.replace(Regex("\\s+"), " ").trim()

    /** 페이지가 불러오는 리소스: (종류, 절대 주소) */
    fun resources(els: List<El>, base: String): List<Pair<String, String>> {
        val out = ArrayList<Pair<String, String>>()
        fun add(kind: String, ref: String?) { if (ref.isNullOrBlank() || ref.startsWith("data:") || ref.startsWith("javascript:") || ref.startsWith("#") || ref.startsWith("mailto:") || ref.startsWith("tel:")) return; abs(base, ref)?.let { out += kind to it } }
        for (e in els) when (e.name) {
            "script" -> add("script", e.attrs["src"]); "img" -> add("img", e.attrs["src"]); "iframe" -> add("iframe", e.attrs["src"]); "source", "video", "audio", "embed" -> add("media", e.attrs["src"])
            "link" -> if (e.attrs["rel"]?.lowercase()?.let { "stylesheet" in it || "preload" in it || "icon" in it } == true) add("css", e.attrs["href"])
            "form" -> add("form", e.attrs["action"])
        }
        return out
    }

    fun anchors(els: List<El>, base: String): List<String> = els.filter { it.name == "a" }.mapNotNull { it.attrs["href"] }.filter { it.isNotBlank() && !it.startsWith("#") && !it.startsWith("javascript:") && !it.startsWith("mailto:") && !it.startsWith("tel:") }.mapNotNull { abs(base, it) }

    fun abs(base: String, ref: String): String? = try { URI(base).resolve(ref.trim().replace(" ", "%20")).toString().takeIf { it.startsWith("http://") || it.startsWith("https://") } } catch (_: Exception) { null }

    fun hostOf(url: String): String? = try { URI(url).host?.lowercase() } catch (_: Exception) { null }
}

/** Cache-Control 지시어와 해석 */
object CacheCtl {
    fun parse(cc: String?): Map<String, String?> = cc?.split(',')?.map { it.trim() }?.filter { it.isNotEmpty() }?.associate { d -> d.substringBefore('=').lowercase().trim() to d.substringAfter('=', "").trim().trim('"').ifEmpty { null } } ?: emptyMap()

    fun seconds(d: Map<String, String?>, key: String): Long? = d[key]?.toLongOrNull()

    fun human(sec: Long): String = when { sec <= 0 -> "0초"; sec < 120 -> "${sec}초"; sec < 7200 -> "${sec / 60}분"; sec < 172800 -> "${sec / 3600}시간"; else -> "${sec / 86400}일" }
}

object CookieParse {
    class Cookie(val name: String, val valueLen: Int, val secure: Boolean, val httpOnly: Boolean, val sameSite: String?, val domain: String?, val path: String?, val expires: String?, val maxAge: Long?, val prefix: String?)

    fun parse(setCookie: String): Cookie {
        val parts = setCookie.split(';').map { it.trim() }
        val nv = parts[0]; val name = nv.substringBefore('='); val value = nv.substringAfter('=', "")
        fun attr(n: String) = parts.drop(1).firstOrNull { it.startsWith("$n=", true) }?.substringAfter('=')?.trim()
        return Cookie(name, value.length, parts.any { it.equals("Secure", true) }, parts.any { it.equals("HttpOnly", true) }, attr("SameSite"), attr("Domain"), attr("Path"), attr("Expires"), attr("Max-Age")?.toLongOrNull(),
            if (name.startsWith("__Host-")) "__Host-" else if (name.startsWith("__Secure-")) "__Secure-" else null)
    }

    private val SESSION_NAMES = Regex("""(?i)(sess|sid|token|auth|login|jwt|csrf|xsrf)""")

    /** 쿠키마다 지적할 점: (내용, 심각도 1 주의 2 위험) */
    fun issues(c: Cookie, https: Boolean): List<Pair<String, Int>> = buildList {
        val sensitive = SESSION_NAMES.containsMatchIn(c.name)
        if (!c.secure && https) add("Secure 가 없어서 http 로도 전송될 수 있어요" to (if (sensitive) 2 else 1))
        if (!c.httpOnly && sensitive) add("HttpOnly 가 없어서 스크립트(XSS)가 읽을 수 있어요" to 2)
        if (c.sameSite == null) add("SameSite 가 없어요 (브라우저 기본값은 Lax 지만 명시하는 것이 좋아요)" to 1)
        else if (c.sameSite.equals("None", true) && !c.secure) add("SameSite=None 은 Secure 와 함께 써야 해요" to 2)
        if (c.prefix == "__Host-" && (c.domain != null || c.path != "/" || !c.secure)) add("__Host- 쿠키는 Secure·Path=/ 이고 Domain 이 없어야 해요" to 2)
        if (c.maxAge != null && c.maxAge > 31536000 || (c.maxAge == null && c.expires != null && sensitive && false)) add("유효기간이 1년을 넘어요" to 1)
    }
}

object SecurityTxt {
    class Info(val fields: List<Pair<String, String>>, val signed: Boolean)

    fun parse(text: String): Info {
        val signed = text.contains("-----BEGIN PGP SIGNED MESSAGE-----")
        val fields = text.lineSequence().map { it.trim() }.filter { it.isNotEmpty() && !it.startsWith("#") && !it.startsWith("-----") && it.contains(':') && !it.startsWith("Hash:") }
            .map { it.substringBefore(':').trim() to it.substringAfter(':').trim() }.filter { it.first.matches(Regex("[A-Za-z-]+")) }.toList()
        return Info(fields, signed)
    }

    fun field(i: Info, name: String) = i.fields.filter { it.first.equals(name, true) }.map { it.second }
}

object Sitemap {
    private val LOC = Regex("""<loc>\s*(?:<!\[CDATA\[)?\s*([^<\]\s]+)\s*(?:\]\]>)?\s*</loc>""", RegexOption.IGNORE_CASE)
    fun isIndex(xml: String) = xml.contains("<sitemapindex", true)
    fun locs(xml: String): List<String> = LOC.findAll(xml).map { HtmlDoc.decode(it.groupValues[1]) }.toList()
    fun lastmods(xml: String): List<String> = Regex("""<lastmod>\s*([^<\s]+)\s*</lastmod>""", RegexOption.IGNORE_CASE).findAll(xml).map { it.groupValues[1] }.toList()
}

object StackDetect {
    /** (기술, 근거) 목록 */
    fun detect(headers: List<Pair<String, String>>, html: String?): List<Pair<String, String>> {
        val out = LinkedHashMap<String, String>()
        fun h(n: String) = headers.firstOrNull { it.first.equals(n, true) }?.second
        h("Server")?.let { s -> val l = s.lowercase()
            when { "nginx" in l -> out["Nginx"] = "Server: $s"; "apache" in l -> out["Apache"] = "Server: $s"; "microsoft-iis" in l -> out["Microsoft IIS"] = "Server: $s"; "litespeed" in l -> out["LiteSpeed"] = "Server: $s"; "cloudflare" in l -> out["Cloudflare"] = "Server: $s"; "caddy" in l -> out["Caddy"] = "Server: $s"; "gws" == l -> out["Google 웹 서버"] = "Server: $s"; else -> out["웹 서버: $s"] = "Server 머리글" } }
        h("X-Powered-By")?.let { v -> val l = v.lowercase(); when { "php" in l -> out["PHP"] = "X-Powered-By: $v"; "asp.net" in l -> out["ASP.NET"] = "X-Powered-By: $v"; "express" in l -> out["Express(Node.js)"] = "X-Powered-By: $v"; "next.js" in l -> out["Next.js"] = "X-Powered-By: $v"; else -> out["기술: $v"] = "X-Powered-By" } }
        h("X-AspNet-Version")?.let { out["ASP.NET"] = "X-AspNet-Version: $it" }
        if (h("X-Drupal-Cache") != null || h("X-Generator")?.contains("Drupal", true) == true) out["Drupal"] = "응답 머리글"
        if (h("X-Shopify-Stage") != null || h("X-ShopId") != null) out["Shopify"] = "X-Shopify 머리글"
        if (h("CF-Ray") != null) out["Cloudflare(CDN)"] = "CF-Ray 머리글"
        if (h("X-Vercel-Id") != null) out["Vercel"] = "X-Vercel-Id"; if (h("X-Nf-Request-Id") != null) out["Netlify"] = "X-Nf-Request-Id"; if (h("X-Amz-Cf-Id") != null) out["Amazon CloudFront"] = "X-Amz-Cf-Id"
        if (h("Link")?.contains("wp-json", true) == true) out["WordPress"] = "Link 머리글(wp-json)"
        for ((k, v) in headers) if (k.equals("Set-Cookie", true)) { val n = v.substringBefore('=')
            when { n == "PHPSESSID" -> out.putIfAbsent("PHP", "쿠키 PHPSESSID"); n == "JSESSIONID" -> out.putIfAbsent("Java 서버(Tomcat 등)", "쿠키 JSESSIONID"); n.startsWith("ASP.NET_SessionId") -> out.putIfAbsent("ASP.NET", "쿠키 ASP.NET_SessionId"); n == "laravel_session" -> out.putIfAbsent("Laravel(PHP)", "쿠키 laravel_session"); n == "connect.sid" -> out.putIfAbsent("Express(Node.js)", "쿠키 connect.sid"); n == "csrftoken" -> out.putIfAbsent("Django(Python)", "쿠키 csrftoken"); n == "_rails_session" || n.endsWith("_session") && "rails" in v.lowercase() -> out.putIfAbsent("Ruby on Rails", "쿠키 $n") } }
        val b = html ?: return out.map { it.key to it.value }
        val l = b.lowercase()
        Regex("""<meta[^>]+name=["']generator["'][^>]+content=["']([^"']+)""", RegexOption.IGNORE_CASE).find(b)?.let { out["제작 도구: ${it.groupValues[1]}"] = "meta generator" }
        val rules = listOf(
            "wp-content/" to "WordPress", "wp-includes/" to "WordPress", "/_next/static" to "Next.js", "__next_data__" to "Next.js", "window.__nuxt__" to "Nuxt(Vue)", "ng-version=" to "Angular", "data-reactroot" to "React", "react-dom" to "React",
            "vue.js" to "Vue.js", "vue.min.js" to "Vue.js", "jquery" to "jQuery", "bootstrap" to "Bootstrap", "tailwind" to "Tailwind CSS", "cdn.shopify.com" to "Shopify", "static.wixstatic.com" to "Wix", "squarespace" to "Squarespace",
            "googletagmanager.com" to "Google 태그 관리자", "google-analytics.com" to "Google 애널리틱스", "gtag(" to "Google 애널리틱스(gtag)", "connect.facebook.net" to "Facebook 픽셀·SDK", "wcs.naver.net" to "네이버 애널리틱스", "t1.daumcdn.net/kas" to "카카오 애드핏",
            "cafe24" to "카페24", "makeshop" to "메이크샵", "tistory" to "티스토리", "joomla" to "Joomla", "drupal.settings" to "Drupal", "gatsby" to "Gatsby", "hugo" to "Hugo(정적 사이트)", "recaptcha" to "reCAPTCHA",
        )
        for ((needle, name) in rules) if (needle in l) out.putIfAbsent(name, "HTML 안의 \"${needle.trim('/')}\"")
        return out.map { it.key to it.value }
    }
}

object RobotsMatcher {
    private class Rule(val allow: Boolean, val pattern: String)

    private fun regexOf(p: String): Regex {
        val anchored = p.endsWith("$"); val body = if (anchored) p.dropLast(1) else p
        return Regex("^" + body.split('*').joinToString(".*") { Regex.escape(it) } + (if (anchored) "$" else ""))
    }

    /** (허용 여부, 적용된 규칙) — 가장 구체적(긴) 규칙이 이기고, 같으면 Allow 가 이김. 규칙이 없으면 허용 */
    fun allowed(robots: String, ua: String, path: String): Pair<Boolean, String?> {
        data class Group(val agents: MutableList<String> = ArrayList(), val rules: MutableList<Rule> = ArrayList())
        val groups = ArrayList<Group>(); var cur: Group? = null; var lastWasAgent = false
        for (raw in robots.lines()) {
            val l = raw.substringBefore('#').trim(); val k = l.substringBefore(':', "").trim().lowercase(); val v = l.substringAfter(':', "").trim()
            when (k) {
                "user-agent" -> { if (!lastWasAgent || cur == null) { cur = Group().also { groups += it } }; cur!!.agents += v.lowercase(); lastWasAgent = true }
                "allow", "disallow" -> { lastWasAgent = false; cur?.rules?.add(Rule(k == "allow", v)) }
                else -> if (k.isNotEmpty() && k != "sitemap") lastWasAgent = false
            }
        }
        val u = ua.lowercase()
        // 이름이 가장 길게 들어맞는 그룹, 없으면 *
        val best = groups.filter { g -> g.agents.any { it != "*" && it.isNotEmpty() && u.contains(it) } }.maxByOrNull { g -> g.agents.filter { it != "*" && u.contains(it) }.maxOf { it.length } } ?: groups.firstOrNull { "*" in it.agents } ?: return true to null
        var win: Rule? = null; var winLen = -1
        for (r in best.rules) {
            if (r.pattern.isEmpty()) continue
            if (regexOf(r.pattern).containsMatchIn(path)) { val len = r.pattern.length; if (len > winLen || (len == winLen && r.allow)) { win = r; winLen = len } }
        }
        return if (win == null) true to null else win.allow to "${if (win.allow) "Allow" else "Disallow"}: ${win.pattern}"
    }
}

object Trackers {
    private val LIST = mapOf(
        "google-analytics.com" to "Google 애널리틱스", "googletagmanager.com" to "Google 태그 관리자", "doubleclick.net" to "Google 광고(DoubleClick)", "googlesyndication.com" to "Google 애드센스", "googleadservices.com" to "Google 광고",
        "connect.facebook.net" to "Facebook(Meta) 픽셀·SDK", "facebook.com" to "Facebook(Meta)", "hotjar.com" to "Hotjar(화면 녹화·분석)", "clarity.ms" to "Microsoft Clarity(화면 녹화)", "mixpanel.com" to "Mixpanel", "segment.com" to "Segment", "segment.io" to "Segment",
        "amplitude.com" to "Amplitude", "criteo.com" to "Criteo 광고", "taboola.com" to "Taboola 광고", "outbrain.com" to "Outbrain 광고", "adnxs.com" to "Xandr 광고", "scorecardresearch.com" to "Comscore", "linkedin.com" to "LinkedIn 인사이트",
        "tiktok.com" to "TikTok 픽셀", "twitter.com" to "X(트위터) 위젯", "ads-twitter.com" to "X 광고", "wcs.naver.net" to "네이버 애널리틱스", "wcs.naver.com" to "네이버 애널리틱스", "daumcdn.net" to "카카오(다음) 광고·분석", "kakao.com" to "카카오 SDK", "criteo.net" to "Criteo 광고",
    )
    fun match(host: String): String? { val h = host.lowercase(); return LIST.entries.firstOrNull { h == it.key || h.endsWith("." + it.key) }?.value }
}

/** ALPN(HTTP/2 협상): 안드로이드 10 이상·JDK 9 이상에서만 협상 결과를 읽을 수 있음 (없으면 null) */
object Alpn {
    private class Recording : X509TrustManager {
        @Volatile var chain: List<X509Certificate> = emptyList()
        override fun checkClientTrusted(c: Array<X509Certificate>, a: String) {}
        override fun checkServerTrusted(c: Array<X509Certificate>, a: String) { chain = c.toList() }
        override fun getAcceptedIssuers(): Array<X509Certificate> = emptyArray()
    }

    class Result(val protocol: String?, val supported: Boolean, val tlsVersion: String)

    fun negotiate(host: String, port: Int = 443, offered: List<String> = listOf("h2", "http/1.1"), timeoutMs: Int = 7000, newSocket: () -> Socket = { Socket() }): Result {
        val addr = TlsInspect.resolve(host)
        val raw = newSocket()
        try {
            raw.connect(InetSocketAddress(addr, port), timeoutMs); raw.soTimeout = timeoutMs
            val ctx = SSLContext.getInstance("TLS").apply { init(null, arrayOf<TrustManager>(Recording()), null) }
            val ssl = ctx.socketFactory.createSocket(raw, host, port, true) as SSLSocket
            var supported = true
            try { val sp = ssl.sslParameters; SSLParameters::class.java.getMethod("setApplicationProtocols", Array<String>::class.java).invoke(sp, offered.toTypedArray()); ssl.sslParameters = sp } catch (_: ReflectiveOperationException) { supported = false } catch (_: UnsupportedOperationException) { supported = false }
            ssl.startHandshake()
            val proto = try { SSLSocket::class.java.getMethod("getApplicationProtocol").invoke(ssl) as? String } catch (_: ReflectiveOperationException) { supported = false; null }
            val ver = ssl.session.protocol
            runCatching { ssl.close() }
            return Result(proto?.takeIf { it.isNotEmpty() }, supported, ver)
        } catch (e: Exception) { runCatching { raw.close() }; throw e }
    }
}
