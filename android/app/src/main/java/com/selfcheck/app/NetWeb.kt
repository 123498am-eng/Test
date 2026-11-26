package com.selfcheck.app

/** 웹 응답 머리글 해석 (CDN 판별 · 보안 헤더 점검 · 쿠키 · robots.txt) — 화면과 인터넷 없이 시험 */

class CdnHit(val service: String, val evidence: String)

object CdnDetect {
    private fun h(headers: List<Pair<String, String>>, name: String) = headers.firstOrNull { it.first.equals(name, true) }?.second

    fun detect(headers: List<Pair<String, String>>): List<CdnHit> {
        val out = ArrayList<CdnHit>()
        val server = h(headers, "Server")?.lowercase() ?: ""; val via = h(headers, "Via")?.lowercase() ?: ""; val xcache = h(headers, "X-Cache")?.lowercase() ?: ""
        fun has(n: String) = h(headers, n) != null
        if (has("CF-Ray") || server.contains("cloudflare")) out += CdnHit("Cloudflare", h(headers, "CF-Ray")?.let { "cf-ray: $it" } ?: "Server: cloudflare")
        if (has("X-Amz-Cf-Id") || via.contains("cloudfront") || xcache.contains("cloudfront")) out += CdnHit("Amazon CloudFront", h(headers, "X-Amz-Cf-Pop")?.let { "POP $it" } ?: "x-amz-cf-id / via cloudfront")
        if (has("X-Fastly-Request-Id") || (h(headers, "X-Served-By")?.lowercase()?.contains("cache-") == true)) out += CdnHit("Fastly", h(headers, "X-Served-By") ?: "x-fastly-request-id")
        if (server.contains("akamai") || headers.any { it.first.lowercase().startsWith("x-akamai") } || has("Akamai-GRN")) out += CdnHit("Akamai", "Server/x-akamai 머리글")
        if (has("X-Azure-Ref") || has("X-MSEdge-Ref")) out += CdnHit("Microsoft Azure (Front Door/Edge)", "x-azure-ref")
        if (has("X-Vercel-Id") || server.contains("vercel")) out += CdnHit("Vercel", h(headers, "X-Vercel-Id") ?: "Server: Vercel")
        if (has("X-Nf-Request-Id") || server.contains("netlify")) out += CdnHit("Netlify", "x-nf-request-id")
        if (has("X-GitHub-Request-Id") || server == "github.com") out += CdnHit("GitHub Pages", "x-github-request-id")
        if (server in listOf("gws", "gse", "esf", "google frontend", "sffe") || via.contains("google")) out += CdnHit("Google 서버", "Server: ${h(headers, "Server") ?: "Via google"}")
        if (has("X-Sucuri-Id")) out += CdnHit("Sucuri", "x-sucuri-id")
        if (has("X-Iinfo") || has("X-CDN") && h(headers, "X-CDN")!!.lowercase().contains("imperva")) out += CdnHit("Imperva", "x-iinfo")
        return out
    }

    /** CDN 은 아니지만 알 수 있는 정보: 웹 서버·기술·캐시 */
    fun hints(headers: List<Pair<String, String>>): List<Pair<String, String>> = buildList {
        h(headers, "Server")?.let { add("웹 서버" to it) }; h(headers, "X-Powered-By")?.let { add("만든 기술" to it) }; h(headers, "Via")?.let { add("중간 프록시(Via)" to it) }
        h(headers, "X-Cache")?.let { add("캐시 상태" to it) }; h(headers, "Age")?.let { add("캐시된 지 (초)" to it) }; h(headers, "Alt-Svc")?.let { add("HTTP/3 광고(Alt-Svc)" to it.take(80)) }
    }
}

class SecCheck(val name: String, val level: Int, val detail: String, val advice: String)

object SecHeaders {
    private fun h(headers: List<Pair<String, String>>, name: String) = headers.firstOrNull { it.first.equals(name, true) }?.second

    /** 6가지 핵심 보안 헤더 점검. level: -1 좋음, 1 주의, 2 부족 */
    fun grade(headers: List<Pair<String, String>>, https: Boolean): List<SecCheck> {
        val out = ArrayList<SecCheck>()
        val hsts = h(headers, "Strict-Transport-Security")
        out += when {
            !https -> SecCheck("HSTS", 1, "http 로 접속했어요", "https 로 접속해야 HSTS 를 확인할 수 있어요")
            hsts == null -> SecCheck("HSTS", 2, "없음", "Strict-Transport-Security: max-age=31536000; includeSubDomains")
            else -> { val age = Regex("""max-age=(\d+)""", RegexOption.IGNORE_CASE).find(hsts)?.groupValues?.get(1)?.toLongOrNull() ?: 0
                if (age >= 15552000) SecCheck("HSTS", -1, hsts, "") else SecCheck("HSTS", 1, hsts, "max-age 를 최소 15552000(180일) 이상으로") }
        }
        val csp = h(headers, "Content-Security-Policy")
        out += when {
            csp == null -> SecCheck("CSP", 2, "없음", "Content-Security-Policy: default-src 'self' (사이트에 맞게 조정)")
            csp.contains("unsafe-inline") || Regex("""(^|;|\s)\*(\s|;|$)""").containsMatchIn(csp) -> SecCheck("CSP", 1, csp.take(100), "'unsafe-inline' 이나 * 허용은 XSS 방어를 약하게 해요")
            else -> SecCheck("CSP", -1, csp.take(100), "")
        }
        val xcto = h(headers, "X-Content-Type-Options")
        out += if (xcto?.equals("nosniff", true) == true) SecCheck("X-Content-Type-Options", -1, "nosniff", "") else SecCheck("X-Content-Type-Options", 2, xcto ?: "없음", "X-Content-Type-Options: nosniff")
        val xfo = h(headers, "X-Frame-Options")
        out += when {
            xfo != null && xfo.uppercase().let { it.startsWith("DENY") || it.startsWith("SAMEORIGIN") } -> SecCheck("클릭재킹 방어", -1, "X-Frame-Options: $xfo", "")
            csp?.contains("frame-ancestors", true) == true -> SecCheck("클릭재킹 방어", -1, "CSP frame-ancestors", "")
            else -> SecCheck("클릭재킹 방어", 2, "없음", "X-Frame-Options: SAMEORIGIN 또는 CSP frame-ancestors 'self'")
        }
        val rp = h(headers, "Referrer-Policy")
        out += if (rp != null) SecCheck("Referrer-Policy", if (rp.lowercase() in listOf("unsafe-url", "no-referrer-when-downgrade")) 1 else -1, rp, if (rp.lowercase() in listOf("unsafe-url", "no-referrer-when-downgrade")) "strict-origin-when-cross-origin 을 권장해요" else "") else SecCheck("Referrer-Policy", 2, "없음", "Referrer-Policy: strict-origin-when-cross-origin")
        val pp = h(headers, "Permissions-Policy") ?: h(headers, "Feature-Policy")
        out += if (pp != null) SecCheck("Permissions-Policy", -1, pp.take(100), "") else SecCheck("Permissions-Policy", 2, "없음", "Permissions-Policy: camera=(), microphone=(), geolocation=()")
        return out
    }

    /** 정보 노출 점검 */
    fun leaks(headers: List<Pair<String, String>>): List<String> = buildList {
        h(headers, "Server")?.takeIf { Regex("""\d+\.\d+""").containsMatchIn(it) }?.let { add("Server 머리글이 버전까지 알려 줘요 ($it). 버전을 숨기면 공격자가 알려진 취약점을 고르기 어려워요.") }
        h(headers, "X-Powered-By")?.let { add("X-Powered-By 가 사용 기술을 알려 줘요 ($it). 제거하는 것이 좋아요.") }
        h(headers, "X-AspNet-Version")?.let { add("X-AspNet-Version 이 .NET 버전을 알려 줘요 ($it).") }
    }

    class CookieInfo(val name: String, val secure: Boolean, val httpOnly: Boolean, val sameSite: String?)

    fun cookies(setCookies: List<String>): List<CookieInfo> = setCookies.map { c ->
        val parts = c.split(';').map { it.trim() }
        CookieInfo(parts[0].substringBefore('='), parts.any { it.equals("Secure", true) }, parts.any { it.equals("HttpOnly", true) }, parts.firstOrNull { it.startsWith("SameSite=", true) }?.substringAfter('='))
    }
}

class RobotsInfo(val userAgents: Int, val disallow: Int, val allow: Int, val sitemaps: List<String>)

object Robots {
    fun parse(text: String): RobotsInfo {
        var ua = 0; var dis = 0; var al = 0; val maps = ArrayList<String>()
        for (raw in text.lines()) {
            val l = raw.substringBefore('#').trim(); val k = l.substringBefore(':', "").trim().lowercase(); val v = l.substringAfter(':', "").trim()
            when (k) { "user-agent" -> ua++; "disallow" -> if (v.isNotEmpty()) dis++; "allow" -> if (v.isNotEmpty()) al++; "sitemap" -> if (v.isNotEmpty()) maps += v }
        }
        return RobotsInfo(ua, dis, al, maps)
    }
}
