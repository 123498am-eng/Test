package com.selfcheck.app

import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import java.io.Closeable
import java.io.IOException
import java.time.Instant
import java.time.ZoneId
import java.time.format.DateTimeFormatter

/*
 * 웹사이트 점검 엔진(HTML 읽기·캐시·쿠키·robots·사이트맵·기술 추정·ALPN)과 웹 도구 18가지 시험.
 * 컴퓨터 안(127.0.0.1)에 가짜 웹 서버(HTTP·자체 서명 HTTPS)와 가짜 DNS 를 열어 놓고 도구를 끝까지 실행합니다.
 * 실제 인터넷 사이트와는 연결하지 않았어요.
 */
class NetWebTest {
    private val closers = ArrayList<Closeable>()
    private fun <T : Closeable> T.track(): T { closers += this; return this }

    @Before fun setUp() { GeoNet.fetcher = null }
    @After fun tearDown() { closers.forEach { runCatching { it.close() } }; closers.clear(); GeoNet.fetcher = null }

    private fun run(id: String, vararg kv: Pair<String, String>, host: ToolHost = FileHost) = runNetTool(id, *kv, host = host)
    private fun page(html: String, vararg headers: String) = TestHttp { _, out -> out.respond("200 OK", "Content-Type: text/html; charset=utf-8", *headers, body = html.toByteArray()) }.track()

    // ============================================================ 엔진: HTML·캐시·쿠키·robots 등

    @Test fun htmlDocReadsElementsTitleMetaAndResources() {
        val html = """
            <!DOCTYPE html><html lang="ko"><head><meta charset="utf-8">
            <title>  Hello &amp; 안녕
               World </title>
            <meta name="Description" content="A &quot;test&quot; page">
            <meta property="og:title" content='OG Title'>
            <meta http-equiv=refresh content=5>
            <!-- <a href="/commented">old</a> -->
            <link rel="canonical" href="https://example.com/a">
            <link rel="stylesheet" href="/s.css">
            <link rel="icon" href="favicon.ico">
            <link rel="alternate stylesheet" href="x.css">
            <script src="app.js"></script>
            <script>var s = "<a href='/hidden'>x</a>"; document.write('<img src="/inline.png">');</script>
            <style>a { content: "<a href='/css-hidden'>"; }</style>
            </head><body>
            <h1>One</h1>
            <a href="/about">About</a> <a href='contact.html'>Contact</a> <a href="#top">top</a> <a href="mailto:a@b.c">mail</a> <a href="javascript:void(0)">js</a> <a href="https://other.com/x y">sp</a>
            <img src="data:image/png;base64,AAAA"> <img src="/logo.png" alt="logo"> <img src=/nq.png>
            <iframe src="//ads.example.net/frame"></iframe>
            <form action="/submit"></form>
            <video src="v.mp4"></video>
            </body></html>
        """.trimIndent()
        val els = HtmlDoc.elements(html)
        assertEquals("Hello & 안녕 World", HtmlDoc.title(html))
        val meta = HtmlDoc.metas(els)
        assertEquals("A \"test\" page", meta["description"])
        assertEquals("OG Title", meta["og:title"])
        assertEquals("5", meta["refresh"])
        assertNull(meta["charset"])
        assertEquals(listOf("https://example.com/a"), HtmlDoc.linkRel(els, "canonical"))
        assertEquals(listOf("/s.css", "x.css"), HtmlDoc.linkRel(els, "stylesheet"))
        assertEquals("ko", els.first { it.name == "html" }.attrs["lang"])
        assertEquals(1, els.count { it.name == "h1" })
        // 스크립트·스타일·주석 안의 글은 태그로 읽지 않음
        val base = "https://example.com/dir/page.html"
        val anchors = HtmlDoc.anchors(els, base)
        assertFalse(anchors.any { "hidden" in it || "commented" in it })
        assertFalse(els.any { it.name == "img" && it.attrs["src"] == "/inline.png" })
        assertEquals(listOf("https://example.com/about", "https://example.com/dir/contact.html", "https://other.com/x%20y"), anchors)
        val res = HtmlDoc.resources(els, base)
        assertTrue("script" to "https://example.com/dir/app.js" in res)
        assertTrue("css" to "https://example.com/s.css" in res)
        assertTrue("css" to "https://example.com/dir/favicon.ico" in res)
        assertTrue("css" to "https://example.com/dir/x.css" in res)
        assertTrue("img" to "https://example.com/logo.png" in res)
        assertTrue("img" to "https://example.com/nq.png" in res)
        assertTrue("iframe" to "https://ads.example.net/frame" in res)
        assertTrue("form" to "https://example.com/submit" in res)
        assertTrue("media" to "https://example.com/dir/v.mp4" in res)
        assertFalse(res.any { it.second.startsWith("data:") })
        assertEquals("https://example.com", Web.origin("https://example.com/a/b?x=1"))
        assertEquals("http://127.0.0.1:8080", Web.origin("http://127.0.0.1:8080/x"))
        assertEquals("https://example.com:8443", Web.origin("https://example.com:8443/"))
        assertEquals("example.com", HtmlDoc.hostOf("https://Example.com/x"))
    }

    @Test fun htmlVisibleTextDropsScriptsStylesAndDecodesEntities() {
        assertEquals("Hi there & you", HtmlDoc.visibleText("<p>Hi <b>there</b> &amp; <script>x()</script>you</p><!-- c --><style>p{}</style>"))
        assertEquals("", HtmlDoc.visibleText("<script>alert(1)</script><noscript>x</noscript>"))
        assertEquals("a b", HtmlDoc.visibleText("<div>a</div>\n\n<div>   b  </div>"))
    }

    @Test fun cacheControlParsingAndHumanTimes() {
        val d = CacheCtl.parse("public, max-age=31536000, immutable, s-maxage=\"600\"")
        assertEquals("31536000", d["max-age"]); assertTrue(d.containsKey("immutable")); assertNull(d["immutable"]); assertEquals(600L, CacheCtl.seconds(d, "s-maxage"))
        assertTrue(CacheCtl.parse(null).isEmpty()); assertTrue(CacheCtl.parse(" , ,").isEmpty())
        assertEquals("0초", CacheCtl.human(0)); assertEquals("90초", CacheCtl.human(90)); assertEquals("10분", CacheCtl.human(600)); assertEquals("2시간", CacheCtl.human(7200))
        assertEquals("2일", CacheCtl.human(172800)); assertEquals("365일", CacheCtl.human(31536000))
    }

    @Test fun cookieParsingAndIssues() {
        val good = CookieParse.parse("__Host-id=abc; Path=/; Secure; HttpOnly; SameSite=Strict")
        assertEquals("__Host-", good.prefix); assertTrue(good.secure && good.httpOnly); assertEquals("Strict", good.sameSite); assertEquals("/", good.path); assertNull(good.domain); assertEquals(3, good.valueLen)
        assertTrue(CookieParse.issues(good, true).isEmpty())

        val bad = CookieParse.parse("SID=1; Domain=.example.com; Path=/a; SameSite=None")
        val bi = CookieParse.issues(bad, true)
        assertEquals(3, bi.size); assertTrue(bi.all { it.second == 2 })
        assertTrue(bi.any { it.first.startsWith("Secure 가 없어서") }); assertTrue(bi.any { it.first.startsWith("HttpOnly 가 없어서") }); assertTrue(bi.any { it.first.startsWith("SameSite=None") })
        assertEquals(2, CookieParse.issues(bad, false).size)                 // http 로 받았으면 Secure 는 따지지 않음

        val plain = CookieParse.parse("theme=dark; Max-Age=40000000")
        assertEquals(40000000L, plain.maxAge)
        val pi = CookieParse.issues(plain, true)
        assertEquals(3, pi.size); assertTrue(pi.all { it.second == 1 }); assertTrue(pi.any { it.first.contains("1년") })

        val host = CookieParse.parse("__Host-x=1; Domain=example.com; Secure; Path=/; SameSite=Lax")
        assertTrue(CookieParse.issues(host, true).any { it.first.startsWith("__Host-") && it.second == 2 })
        assertEquals("__Secure-", CookieParse.parse("__Secure-a=1; Secure").prefix)
        val exp = CookieParse.parse("a=b; secure; httponly; Expires=Wed, 21 Oct 2099 07:28:00 GMT; Max-Age=60")
        assertTrue(exp.secure && exp.httpOnly); assertEquals("Wed, 21 Oct 2099 07:28:00 GMT", exp.expires); assertEquals(60L, exp.maxAge)
    }

    @Test fun securityTxtParsing() {
        val signed = """
            -----BEGIN PGP SIGNED MESSAGE-----
            Hash: SHA512

            # Our security policy
            Contact: mailto:security@example.com
            Contact: https://example.com/security/report
            Expires: 2099-01-01T00:00:00.000Z
            Preferred-Languages: en, ko
            Canonical: https://example.com/.well-known/security.txt
            -----BEGIN PGP SIGNATURE-----

            iQIzBAEBCgAdFiEEabcdef
            =Ab12
            -----END PGP SIGNATURE-----
        """.trimIndent()
        val info = SecurityTxt.parse(signed)
        assertTrue(info.signed)
        assertEquals(listOf("mailto:security@example.com", "https://example.com/security/report"), SecurityTxt.field(info, "contact"))
        assertEquals(listOf("2099-01-01T00:00:00.000Z"), SecurityTxt.field(info, "Expires"))
        assertEquals(listOf("https://example.com/.well-known/security.txt"), SecurityTxt.field(info, "canonical"))
        assertEquals(5, info.fields.size)
        assertFalse(SecurityTxt.parse("Contact: a@b.c").signed)
        assertTrue(SecurityTxt.parse("<html>not found: 404</html>").fields.isEmpty())
    }

    @Test fun sitemapParsing() {
        val urlset = """<?xml version="1.0"?>
            <urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">
             <url><loc>https://example.com/</loc><lastmod>2024-05-01</lastmod></url>
             <url><loc> https://example.com/a?x=1&amp;y=2 </loc><lastmod>2024-06-15T10:00:00+09:00</lastmod></url>
             <url><loc><![CDATA[https://example.com/c?z=3&w=4]]></loc></url>
            </urlset>"""
        assertFalse(Sitemap.isIndex(urlset))
        assertEquals(listOf("https://example.com/", "https://example.com/a?x=1&y=2", "https://example.com/c?z=3&w=4"), Sitemap.locs(urlset))
        assertEquals(listOf("2024-05-01", "2024-06-15T10:00:00+09:00"), Sitemap.lastmods(urlset))
        val index = "<SitemapIndex><sitemap><loc>https://example.com/s1.xml</loc></sitemap><sitemap><loc>https://example.com/s2.xml</loc></sitemap></SitemapIndex>"
        assertTrue(Sitemap.isIndex(index)); assertEquals(2, Sitemap.locs(index).size)
        assertTrue(Sitemap.locs("<html>404</html>").isEmpty())
    }

    @Test fun stackDetectionFromHeadersCookiesAndHtml() {
        val headers = listOf("Server" to "nginx/1.24.0", "X-Powered-By" to "PHP/8.2.1", "Set-Cookie" to "PHPSESSID=abc; path=/", "CF-Ray" to "8a1b2c-ICN", "Link" to "<https://x.example/wp-json/>; rel=\"https://api.w.org/\"")
        val html = """<html><head><meta name="generator" content="WordPress 6.4"><script src="/wp-content/themes/a.js"></script><script src="https://www.googletagmanager.com/gtm.js"></script><script src="/js/jquery.min.js"></script><script>gtag('js', new Date())</script></head></html>"""
        val found = StackDetect.detect(headers, html).toMap()
        assertEquals("Server: nginx/1.24.0", found["Nginx"]); assertEquals("X-Powered-By: PHP/8.2.1", found["PHP"]); assertNotNull(found["Cloudflare(CDN)"])
        assertEquals("Link 머리글(wp-json)", found["WordPress"]); assertNotNull(found["제작 도구: WordPress 6.4"])
        assertNotNull(found["Google 태그 관리자"]); assertNotNull(found["Google 애널리틱스(gtag)"]); assertNotNull(found["jQuery"])
        // 쿠키만으로도 짐작
        assertNotNull(StackDetect.detect(listOf("Set-Cookie" to "JSESSIONID=1; Path=/"), null).toMap()["Java 서버(Tomcat 등)"])
        assertNotNull(StackDetect.detect(listOf("Set-Cookie" to "csrftoken=abc"), null).toMap()["Django(Python)"])
        assertEquals("Server: gws", StackDetect.detect(listOf("Server" to "gws"), null).toMap()["Google 웹 서버"])
        assertNotNull(StackDetect.detect(listOf("Server" to "Kestrel"), null).toMap()["웹 서버: Kestrel"])
        assertTrue(StackDetect.detect(emptyList(), "<html><body>hi</body></html>").isEmpty())
    }

    @Test fun robotsMatcherFollowsLongestMatchAndGroupRules() {
        val robots = """
            # crawl rules
            User-agent: *
            Disallow: /private/
            Disallow: /*.pdf$
            Allow: /private/open/
            Disallow: /tmp

            User-agent: Googlebot
            User-agent: Googlebot-Image
            Disallow: /nogoogle/
            Allow: /nogoogle/ok.html
            Sitemap: https://example.com/sitemap.xml
        """.trimIndent()
        fun ok(ua: String, path: String) = RobotsMatcher.allowed(robots, ua, path)
        assertEquals(false to "Disallow: /private/", ok("bingbot", "/private/x"))
        assertEquals(true to "Allow: /private/open/", ok("bingbot", "/private/open/doc"))          // 더 긴(구체적인) 규칙이 이김
        assertEquals(false to "Disallow: /*.pdf\$", ok("bingbot", "/files/a.pdf"))
        assertEquals(true to null, ok("bingbot", "/files/a.pdf?x=1"))                               // $ 는 주소의 끝을 뜻함
        assertEquals(false to "Disallow: /tmp", ok("bingbot", "/tmpfile"))
        assertEquals(true to null, ok("Googlebot/2.1", "/private/x"))                               // 이름이 맞는 그룹이 * 그룹을 대신함
        assertEquals(false to "Disallow: /nogoogle/", ok("Googlebot-Image/1.0", "/nogoogle/a"))
        assertEquals(true to "Allow: /nogoogle/ok.html", ok("Googlebot", "/nogoogle/ok.html"))
        assertEquals(true to "Allow: /page", RobotsMatcher.allowed("User-agent: *\nDisallow: /page\nAllow: /page", "x", "/page"))   // 길이가 같으면 Allow
        assertEquals(true to null, RobotsMatcher.allowed("User-agent: *\nDisallow:", "x", "/anything"))                          // 빈 Disallow = 모두 허용
        assertEquals(true to null, RobotsMatcher.allowed("User-agent: onlybot\nDisallow: /", "x", "/a"))                         // 맞는 그룹이 없으면 허용
        assertEquals(false to "Disallow: /a", RobotsMatcher.allowed("User-agent: *\r\nDisallow: /a # note\r\n", "x", "/a/b"))   // CRLF·주석
        assertEquals(false to "Disallow: /z", RobotsMatcher.allowed("User-agent: a\nSitemap: https://x/s.xml\nUser-agent: b\nDisallow: /z", "a", "/z"))   // Sitemap 줄은 그룹을 끊지 않음
        val longer = "User-agent: google\nDisallow: /g/\n\nUser-agent: googlebot\nDisallow: /gb/\n"
        assertEquals(true to null, RobotsMatcher.allowed(longer, "Googlebot/2.1", "/g/x"))                                       // 이름이 더 길게 맞는 그룹을 고름
        assertEquals(false to "Disallow: /gb/", RobotsMatcher.allowed(longer, "Googlebot/2.1", "/gb/x"))
        assertEquals(true to null, RobotsMatcher.allowed("", "x", "/a"))
    }

    @Test fun trackerMatching() {
        assertEquals("Google 애널리틱스", Trackers.match("www.google-analytics.com"))
        assertEquals("Google 애널리틱스", Trackers.match("GOOGLE-ANALYTICS.COM"))
        assertNull(Trackers.match("notgoogle-analytics.com")); assertNull(Trackers.match("example.com"))
        assertEquals("Google 광고(DoubleClick)", Trackers.match("stats.g.doubleclick.net"))
        assertEquals("네이버 애널리틱스", Trackers.match("wcs.naver.net"))
        assertEquals("Facebook(Meta) 픽셀·SDK", Trackers.match("connect.facebook.net"))
    }

    @Test fun alpnNegotiationAgainstLocalTlsServer() {
        TestHttps(alpn = listOf("h2", "http/1.1")).use { s ->
            val r = Alpn.negotiate("127.0.0.1", s.port)
            assertEquals("h2", r.protocol); assertTrue(r.supported); assertTrue(r.tlsVersion.startsWith("TLSv1"))
        }
        TestHttps(alpn = listOf("http/1.1")).use { s -> assertEquals("http/1.1", Alpn.negotiate("127.0.0.1", s.port).protocol) }
        TestHttps().use { s -> assertNull(Alpn.negotiate("127.0.0.1", s.port).protocol) }        // ALPN 을 안 쓰는 서버
        // 내가 http/1.1 만 제안하면 서버가 h2 를 좋아해도 http/1.1
        TestHttps(alpn = listOf("h2", "http/1.1")).use { s -> assertEquals("http/1.1", Alpn.negotiate("127.0.0.1", s.port, offered = listOf("http/1.1")).protocol) }
    }

    @Test fun baseDomainKeepsIpAddressesWhole() {
        assertEquals("example.com", EmailHeader.baseDomain("a.b.example.com"))
        assertEquals("naver.co.kr", EmailHeader.baseDomain("mail.naver.co.kr"))
        assertEquals("127.0.0.1", EmailHeader.baseDomain("127.0.0.1"))
        assertEquals("192.168.0.1", EmailHeader.baseDomain("192.168.0.1"))
        assertEquals("2001:db8::1", EmailHeader.baseDomain("2001:db8::1"))
    }

    // ============================================================ 도구: 웹 서버에 요청 보내는 것들

    @Test fun toolWebHttp2ReadsAlpnAndAltSvc() {
        TestHttps(alpn = listOf("h2", "http/1.1")) { _, out -> out.respond("200 OK", "Server: gws", "Alt-Svc: h3=\":443\"; ma=2592000", body = ByteArray(0)) }.track().let { s ->
            val r = run("web_http2", "h" to "127.0.0.1:${s.port}")
            assertEquals("h2", r.kv("협상된 프로토콜(ALPN)")); assertEquals(-1, r.kvLevel("협상된 프로토콜(ALPN)"))
            assertTrue(r.kv("HTTP/3(QUIC) 광고").startsWith("예")); assertEquals("TLSv1.3", r.kv("TLS")); assertEquals("200 OK", r.kv("응답")); assertEquals("gws", r.kv("Server"))
            assertTrue(r.text().contains("HTTP/2 를 지원해요")); assertFalse(r.hasError)
        }
        TestHttps(alpn = listOf("http/1.1")) { _, out -> out.respond("200 OK", body = ByteArray(0)) }.track().let { s ->
            val r = run("web_http2", "h" to "127.0.0.1:${s.port}")
            assertEquals("http/1.1", r.kv("협상된 프로토콜(ALPN)")); assertEquals(0, r.kvLevel("협상된 프로토콜(ALPN)"))
            assertTrue(r.kv("HTTP/3(QUIC) 광고").startsWith("아니요")); assertTrue(r.text().contains("http/1.1 로 협상됐어요"))
        }
        TestHttps { _, out -> out.respond("200 OK", body = ByteArray(0)) }.track().let { s ->
            val r = run("web_http2", "h" to "127.0.0.1:${s.port}")
            assertEquals("없음(HTTP/1.1)", r.kv("협상된 프로토콜(ALPN)")); assertTrue(r.text().contains("HTTP/2 를 협상하지 않았어요"))
        }
        assertTrue(run("web_http2", "h" to "127.0.0.1:1").hasError)                    // 아무도 안 듣는 포트
        assertTrue(run("web_http2", "h" to "").text().contains("도메인을 입력하세요"))
    }

    @Test fun toolWebCompressComparesEncodings() {
        val html = ("<html><body>" + "<p>hello selfcheck network tools</p>\n".repeat(200) + "</body></html>").toByteArray()
        TestHttp { req, out ->
            if ("gzip" in (req.headers["accept-encoding"] ?: "")) out.respond("200 OK", "Content-Type: text/html", "Content-Encoding: gzip", body = gzipOf(html))
            else out.respond("200 OK", "Content-Type: text/html", body = html)
        }.track().let { s ->
            val r = run("web_compress", "u" to s.url("/"))
            val rows = r.rows()
            assertEquals(3, rows.size)
            assertEquals("없음", rows[0][1]); assertEquals("gzip", rows[1][1]); assertEquals("gzip", rows[2][1])
            assertEquals("%,d 바이트".format(html.size), rows[0][2])
            assertTrue(rows[1][3].endsWith("% 줄어듦")); val pct = rows[1][3].substringBefore('%').toInt(); assertTrue("압축으로 90% 넘게 줄어야 해요: $pct", pct > 90)
            assertTrue(r.text().contains("gzip 을 지원해요")); assertFalse(r.text().contains("Brotli 를 지원해요"))
            assertEquals(listOf("identity", "gzip", "br, gzip"), s.requests.map { it.headers["accept-encoding"] })     // 서버가 받은 요청이 방식대로인지
        }
        TestHttp { req, out ->
            if ("br" in (req.headers["accept-encoding"] ?: "")) out.respond("200 OK", "Content-Type: text/html", "Content-Encoding: br", body = ByteArray(300) { 7 })
            else out.respond("200 OK", "Content-Type: text/html", body = html)
        }.track().let { s -> val r = run("web_compress", "u" to s.url("/")); assertEquals("br", r.rows()[2][1]); assertTrue(r.text().contains("Brotli 를 지원해요")) }
        TestHttp { _, out -> out.respond("200 OK", "Content-Type: text/html", body = html) }.track().let { s ->
            val r = run("web_compress", "u" to s.url("/")); assertEquals(1, r.noteWith("압축을 쓰지 않아요")?.level)
        }
    }

    @Test fun toolWebCacheAnalyzesHeadersAndConditionalRequests() {
        val etag = "\"v1-abc\""; val lm = "Wed, 21 Oct 2015 07:28:00 GMT"
        TestHttp { req, out ->
            when (req.path) {
                "/" -> if (req.headers["if-none-match"] == etag || req.headers["if-modified-since"] == lm) out.respond("304 Not Modified", "ETag: $etag", "Cache-Control: public, max-age=7200")
                       else out.respond("200 OK", "Content-Type: text/html; charset=utf-8", "Cache-Control: public, max-age=7200", "ETag: $etag", "Last-Modified: $lm", "Age: 120", "Vary: Accept-Encoding", body = "<html>hi</html>".toByteArray())
                "/style.css" -> out.respond("200 OK", "Content-Type: text/css", body = "a{}".toByteArray())
                "/app.abc123.js" -> out.respond("200 OK", "Content-Type: application/javascript", "Cache-Control: public, max-age=31536000, immutable", body = "x".toByteArray())
                "/secret" -> out.respond("200 OK", "Content-Type: text/html", "Cache-Control: no-store", body = "x".toByteArray())
                else -> out.respond("200 OK", "Content-Type: text/html", body = "x".toByteArray())
            }
        }.track().let { s ->
            val r = run("web_cache", "u" to s.url("/"))
            assertEquals("public, max-age=7200", r.kv("Cache-Control")); assertEquals("2시간", r.kv("브라우저 보관 시간"))
            assertTrue(r.kv("지시어").contains("공용 캐시 허용(public)")); assertEquals("120초", r.kv("CDN 에서 보관된 시간(Age)")); assertEquals("Accept-Encoding", r.kv("Vary")); assertEquals(etag, r.kv("ETag")); assertEquals(lm, r.kv("Last-Modified"))
            assertTrue(r.kv("If-None-Match").startsWith("304")); assertEquals(-1, r.kvLevel("If-None-Match")); assertTrue(r.kv("If-Modified-Since").startsWith("304"))
            assertTrue(r.text().contains("HTML 을 오래 캐시하면")); assertTrue(r.text().contains("조건부 요청이 304 로 동작해요"))
            // 서버가 조건부 요청 머리글을 실제로 받았는지
            assertTrue(s.requests.any { it.headers["if-none-match"] == etag }); assertTrue(s.requests.any { it.headers["if-modified-since"] == lm })

            val css = run("web_cache", "u" to s.url("/style.css"))
            assertEquals("없음", css.kv("Cache-Control")); assertEquals(1, css.kvLevel("Cache-Control")); assertTrue(css.text().contains("정적 파일(text/css)인데 캐시 시간이 없어요")); assertFalse(css.hasKv("If-None-Match"))
            assertTrue(run("web_cache", "u" to s.url("/app.abc123.js")).text().contains("정적 파일을 오래 캐시해요 (좋아요)"))
            assertTrue(run("web_cache", "u" to s.url("/secret")).text().contains("저장을 금지했어요"))
            assertEquals(1, run("web_cache", "u" to s.url("/other")).noteWith("캐시 관련 머리글이 전혀 없어요")?.level)
        }
        assertTrue(run("web_cache", "u" to "http://127.0.0.1:1/").hasError)
    }

    private fun corsServer(mode: String) = TestHttp { req, out ->
        val o = req.headers["origin"]
        val h = ArrayList<String>(); h += "Content-Type: application/json"
        when (mode) {
            "reflect-cred" -> if (o != null) { h += "Access-Control-Allow-Origin: $o"; h += "Access-Control-Allow-Credentials: true"; h += "Vary: Origin" }
            "star" -> h += "Access-Control-Allow-Origin: *"
            "star-cred" -> { h += "Access-Control-Allow-Origin: *"; h += "Access-Control-Allow-Credentials: true" }
            "fixed" -> h += "Access-Control-Allow-Origin: https://app.example.com"
            "fixed-vary" -> { h += "Access-Control-Allow-Origin: https://app.example.com"; h += "Vary: Origin" }
        }
        out.respond("200 OK", *h.toTypedArray(), body = "{}".toByteArray())
    }.track()

    @Test fun toolWebCorsFlagsDangerousSetups() {
        val reflect = corsServer("reflect-cred")
        val r = run("web_cors", "u" to reflect.url("/api"))
        assertTrue(r.hasError); assertTrue(r.text().contains("아무 사이트(Origin)나 그대로 허용하면서 쿠키까지")); assertTrue(r.text().contains("Origin: null 을 허용해요"))
        assertEquals("https://selfcheck-test.invalid", r.row("GET (Origin: 낯선 사이트)")[1]); assertEquals("true", r.row("GET (Origin: 낯선 사이트)")[2])
        // 서버가 받은 Origin 이 의도한 값인지
        assertTrue(reflect.requests.any { it.headers["origin"] == "https://selfcheck-test.invalid" && it.method == "GET" })
        assertTrue(reflect.requests.any { it.method == "OPTIONS" && it.headers["access-control-request-method"] == "GET" })
        assertTrue(reflect.requests.any { it.headers["origin"] == "null" })

        val star = run("web_cors", "u" to corsServer("star").url("/api"))
        assertEquals("*", star.row("GET (Origin: 낯선 사이트)")[1]); assertTrue(star.text().contains("모든 사이트에서 읽을 수 있어요")); assertFalse(star.hasError)
        assertTrue(run("web_cors", "u" to corsServer("star-cred").url("/api")).hasError)                                       // * + 쿠키 허용은 규격 위반
        val fixed = run("web_cors", "u" to corsServer("fixed").url("/api")); assertTrue(fixed.text().contains("Vary: Origin 이 없어요")); assertFalse(fixed.hasError)
        assertTrue(run("web_cors", "u" to corsServer("fixed-vary").url("/api")).text().contains("특별한 문제가 보이지 않아요"))
        val none = run("web_cors", "u" to corsServer("none").url("/api")); assertTrue(none.text().contains("CORS 허용 머리글이 없어요")); assertFalse(none.hasError)
    }

    @Test fun toolWebCookiesFlagsWeakCookies() {
        TestHttp { _, out -> out.respond("200 OK", "Set-Cookie: sessionid=abcdef123456; Path=/", "Set-Cookie: theme=dark; Path=/; SameSite=Lax; Max-Age=600", "Set-Cookie: tracker=1; SameSite=None; Path=/", body = "ok".toByteArray()) }.track().let { s ->
            val r = run("web_cookies", "u" to s.url("/"))
            assertEquals("3개", r.kv("쿠키 수"))
            val sid = r.row("sessionid"); assertEquals("아니요", sid[1]); assertEquals("아니요", sid[2]); assertEquals("없음", sid[3]); assertEquals("이 호스트 /", sid[4]); assertEquals("세션(브라우저 닫으면 삭제)", sid[5]); assertEquals(2, r.rowLevel("sessionid"))
            assertEquals("Lax", r.row("theme")[3]); assertEquals("10분", r.row("theme")[5]); assertEquals(-1, r.rowLevel("theme"))
            assertEquals(2, r.rowLevel("tracker"))                                 // SameSite=None 인데 Secure 없음
            assertTrue(r.hasError); assertTrue(r.text().contains("sessionid: HttpOnly 가 없어서")); assertTrue(r.text().contains("tracker: SameSite=None 은 Secure 와 함께"))
            assertTrue(r.text().contains("http 로 접속했어요"))
        }
        TestHttp { _, out -> out.respond("200 OK", body = "ok".toByteArray()) }.track().let { s ->
            val r = run("web_cookies", "u" to s.url("/")); assertEquals("0개", r.kv("쿠키 수")); assertTrue(r.text().contains("쿠키를 심지 않아요")); assertFalse(r.hasError)
        }
    }

    @Test fun toolWebMethodsDetectsTrace() {
        TestHttp { req, out ->
            when (req.method) {
                "OPTIONS" -> out.respond("204 No Content", "Allow: GET, HEAD, POST, PUT, DELETE, OPTIONS")
                "TRACE" -> out.respond("200 OK", "Content-Type: message/http", body = ("TRACE / HTTP/1.1\r\n" + req.headers.entries.joinToString("\r\n") { "${it.key}: ${it.value}" }).toByteArray())
                else -> out.respond("200 OK", body = "x".toByteArray())
            }
        }.track().let { s ->
            val r = run("web_methods", "u" to s.url("/"))
            assertEquals("204 No Content", r.kv("OPTIONS 응답")); assertEquals("GET, HEAD, POST, PUT, DELETE, OPTIONS", r.kv("허용 메서드(Allow)"))
            assertTrue(r.kv("TRACE").startsWith("켜져 있어요")); assertEquals(2, r.kvLevel("TRACE")); assertTrue(r.hasError); assertTrue(r.text().contains("PUT, DELETE 도 허용해요"))
            assertTrue(s.requests.any { it.method == "TRACE" && it.headers["x-selfcheck-probe"] == "trace-test" })
        }
        TestHttp { req, out -> if (req.method == "TRACE") out.respond("405 Method Not Allowed") else out.respond("200 OK", body = "x".toByteArray()) }.track().let { s ->
            val r = run("web_methods", "u" to s.url("/"))
            assertEquals("꺼져 있어요 (405)", r.kv("TRACE")); assertEquals("알려 주지 않음", r.kv("허용 메서드(Allow)")); assertFalse(r.hasError); assertTrue(r.text().contains("서버가 Allow 목록을 알려 주지 않았어요"))
        }
        TestHttp { req, out -> if (req.method == "OPTIONS") out.respond("200 OK", "Access-Control-Allow-Methods: GET,post") else out.respond("405 Method Not Allowed") }.track().let { s ->
            assertEquals("GET, POST", run("web_methods", "u" to s.url("/")).kv("허용 메서드(Allow)"))
        }
    }

    private fun secTxtServer(body: String?, ct: String = "text/plain; charset=utf-8", path: String = "/.well-known/security.txt") =
        TestHttp { req, out -> if (body != null && req.path == path) out.respond("200 OK", "Content-Type: $ct", body = body.toByteArray()) else out.respond("404 Not Found", body = "nope".toByteArray()) }.track()

    @Test fun toolWebSecurityTxtChecksContactAndExpiry() {
        val good = secTxtServer("# policy\nContact: mailto:security@example.com\nContact: https://example.com/report\nExpires: 2099-12-31T23:59:59.000Z\nPreferred-Languages: ko, en\n")
        val r = run("web_security_txt", "u" to good.url(""))
        assertEquals("/.well-known/security.txt", r.kv("위치")); assertEquals("없어요", r.kv("서명(PGP)"))
        assertTrue(r.rows().any { it[0] == "Contact" && it[1] == "mailto:security@example.com" }); assertTrue(r.text().contains("Contact 2개")); assertTrue(r.text().contains("유효기간: 2099-12-31"))
        assertTrue(r.text().contains("https 로 제공해야 해요")); assertTrue(r.text().contains("연락처에 메일 주소가 보여요")); assertFalse(r.hasError)

        assertTrue(run("web_security_txt", "u" to secTxtServer("Contact: https://example.com/r\nExpires: 2020-01-01T00:00:00Z\n").url("")).text().contains("Expires 가 지났어요(2020-01-01)"))
        assertTrue(run("web_security_txt", "u" to secTxtServer("Contact: https://example.com/r\nExpires: 2020-01-01T00:00:00Z\n").url("")).hasError)
        val noContact = run("web_security_txt", "u" to secTxtServer("Expires: 2099-12-31T23:59:59Z\n").url("")); assertTrue(noContact.hasError); assertTrue(noContact.text().contains("Contact 가 없어요"))
        val noExpires = run("web_security_txt", "u" to secTxtServer("Contact: https://example.com/r\n").url("")); assertTrue(noExpires.hasError); assertTrue(noExpires.text().contains("Expires 가 없어요"))
        assertEquals("/security.txt", run("web_security_txt", "u" to secTxtServer("Contact: https://e.example/r\nExpires: 2099-01-01T00:00:00Z\n", path = "/security.txt").url("")).kv("위치"))   // 예전 위치
        val none = run("web_security_txt", "u" to secTxtServer(null).url("")); assertEquals(1, none.noteWith("security.txt 가 없어요")?.level); assertFalse(none.hasError)
        // 없는 주소에 HTML 오류 페이지를 200 으로 주는 사이트는 파일이 있는 것으로 보지 않음
        val soft = run("web_security_txt", "u" to secTxtServer("<!doctype html><html><body>Not found</body></html>", ct = "text/html").url("")); assertTrue(soft.text().contains("security.txt 가 없어요"))
    }

    @Test fun toolWebSitemapFollowsRobotsAndSitemapIndex() {
        lateinit var base: String
        val s = TestHttp { req, out ->
            when (req.path) {
                "/robots.txt" -> out.respond("200 OK", "Content-Type: text/plain", body = "User-agent: *\nDisallow: /private\nSitemap: $base/sitemap-index.xml\n".toByteArray())
                "/sitemap-index.xml" -> out.respond("200 OK", "Content-Type: application/xml", body = ("""<?xml version="1.0"?><sitemapindex xmlns="http://www.sitemaps.org/schemas/sitemap/0.9"><sitemap><loc>$base/s1.xml</loc><lastmod>2024-05-01</lastmod></sitemap><sitemap><loc>$base/s2.xml</loc><lastmod>2024-05-20</lastmod></sitemap></sitemapindex>""").toByteArray())
                else -> out.respond("404 Not Found", body = "no".toByteArray())
            }
        }.track()
        base = s.url("").trimEnd('/')
        val r = run("web_sitemap", "u" to s.url(""))
        assertEquals("1개", r.kv("robots.txt 의 사이트맵")); assertEquals("사이트맵 목록(index)", r.kv("종류")); assertEquals("2개", r.kv("하위 사이트맵")); assertEquals("2024-05-20", r.kv("가장 최근 수정일"))
        assertTrue(r.blocks().contains("$base/s1.xml")); assertTrue(s.requests.any { it.path == "/sitemap-index.xml" })

        val s2 = TestHttp { req, out ->
            if (req.path == "/sitemap.xml") out.respond("200 OK", "Content-Type: application/xml", body = """<urlset><url><loc>https://example.com/</loc><lastmod>2024-05-01</lastmod></url><url><loc>https://example.com/a?x=1&amp;y=2</loc><lastmod>2024-06-15T10:00:00+09:00</lastmod></url><url><loc><![CDATA[https://example.com/c?z=3&w=4]]></loc></url></urlset>""".toByteArray())
            else out.respond("404 Not Found", body = "no".toByteArray())
        }.track()
        val r2 = run("web_sitemap", "u" to s2.url(""))
        assertEquals("없음 (/sitemap.xml 을 시도)", r2.kv("robots.txt 의 사이트맵")); assertEquals("주소 목록(urlset)", r2.kv("종류")); assertEquals("3개", r2.kv("등록된 주소")); assertEquals("2024-06-15T10:00:00+09:00", r2.kv("가장 최근 수정일"))
        assertTrue(r2.blocks().contains("https://example.com/a?x=1&y=2")); assertTrue(r2.blocks().contains("https://example.com/c?z=3&w=4"))

        val none = TestHttp { _, out -> out.respond("404 Not Found", body = "no".toByteArray()) }.track()
        assertTrue(run("web_sitemap", "u" to none.url("")).text().contains("404 Not Found — 사이트맵이 없어요"))
    }

    @Test fun toolWebLinksSplitsInternalExternalAndFallsBackToGet() {
        lateinit var self: TestHttp
        val s = TestHttp { req, out ->
            when (req.path) {
                "/" -> out.respond("200 OK", "Content-Type: text/html", body = """<html><head><title>t</title></head><body>
                    <a href="/ok">ok</a> <a href="/ok#top">ok again</a> <a href="/gone">gone</a> <a href="/nohead">nohead</a> <a href="sub/page.html">rel</a>
                    <a href="http://localhost:${self.port}/ext-ok">ext</a> <a href="#frag">f</a> <a href="mailto:x@y.z">m</a> <a href="javascript:void(0)">j</a></body></html>""".toByteArray())
                "/gone" -> out.respond("404 Not Found", body = "x".toByteArray())
                "/nohead" -> if (req.method == "HEAD") out.respond("405 Method Not Allowed", "Allow: GET") else out.respond("200 OK", body = "x".toByteArray())
                else -> out.respond("200 OK", body = "x".toByteArray())
            }
        }.track(); self = s
        val r = run("web_links", "u" to s.url("/"))
        assertEquals("5개 (내부 4 · 외부 1)", r.kv("링크")); assertEquals("5개", r.kv("확인한 링크"))
        fun status(suffix: String) = r.rows().first { it[1].endsWith(suffix) }[0]
        assertEquals("200", status("/ok")); assertEquals("404", status("/gone")); assertEquals("200", status("/nohead")); assertEquals("200", status("/sub/page.html")); assertEquals("200", status("/ext-ok"))
        assertEquals(2, r.cols().first { it.cells[1].endsWith("/gone") }.level); assertEquals(-1, r.cols().first { it.cells[1].endsWith("/ok") }.level)
        assertTrue(r.text().contains("1개가 열리지 않아요"))
        assertTrue(s.requests.any { it.method == "HEAD" && it.path == "/nohead" }); assertTrue(s.requests.any { it.method == "GET" && it.path == "/nohead" })    // HEAD 를 막으면 GET 으로 다시
        assertEquals(1, s.requests.count { it.path == "/ok" && it.method == "HEAD" })                                                                  // #top 은 같은 링크로 합침

        val b = TestHttp { req, out ->
            if (req.path == "/") out.respond("200 OK", "Content-Type: text/html", body = """<html><head><base href="/docs/"></head><body><a href="guide.html">g</a></body></html>""".toByteArray()) else out.respond("200 OK", body = "x".toByteArray())
        }.track()
        run("web_links", "u" to b.url("/"))
        assertTrue(b.requests.any { it.path == "/docs/guide.html" })                  // <base href> 기준으로 상대 링크 풀기
        assertTrue(run("web_links", "u" to page("<html><body>no links</body></html>").url("/")).text().contains("확인할 링크가 없어요"))
    }

    @Test fun toolWebSeoScoresPages() {
        val title = "셀프체크 네트워크 도구 모음 — 휴대폰으로 하는 점검"
        val desc = "이 페이지는 네트워크 점검 도구 모음을 소개합니다. ".repeat(3).trim()
        val words = (1..120).joinToString(" ") { "단어$it" }
        val rich = """<!doctype html><html lang="ko"><head><meta charset="utf-8"><title>$title</title>
            <meta name="description" content="$desc"><link rel="canonical" href="https://example.com/">
            <meta name="viewport" content="width=device-width, initial-scale=1">
            <meta property="og:title" content="t"><meta property="og:description" content="d"><meta property="og:image" content="https://example.com/i.png">
            <meta name="twitter:card" content="summary"><script type="application/ld+json">{"@type":"WebSite"}</script></head>
            <body><h1>제목</h1><img src="a.png" alt="가"><img src="b.png" alt=""><p>$words</p></body></html>"""
        val r = run("web_seo", "u" to page(rich).url("/"))
        assertEquals("200 OK", r.kv("상태"))
        assertEquals(title, r.row("제목")[1]); assertEquals("${title.length}자 (좋아요)", r.row("제목")[2]); assertEquals(-1, r.rowLevel("제목"))
        assertEquals(desc.take(60), r.row("설명(description)")[1]); assertEquals("${desc.length}자 (좋아요)", r.row("설명(description)")[2]); assertEquals(-1, r.rowLevel("설명(description)"))
        assertEquals("https://example.com/", r.row("canonical")[1]); assertEquals("ko", r.row("언어(html lang)")[1]); assertEquals("1개", r.row("h1 제목")[1]); assertEquals(-1, r.rowLevel("h1 제목"))
        assertEquals("2개", r.row("이미지")[1]); assertEquals("모두 alt 가 있어요", r.row("이미지")[2]); assertEquals("충분해요", r.row("본문 단어 수")[2]); assertEquals(-1, r.rowLevel("viewport"))
        assertEquals("제목·설명·이미지 모두 있어요", r.row("공유 미리보기(Open Graph)")[2]); assertEquals("summary", r.row("트위터 카드")[1]); assertEquals("있어요", r.row("구조화 데이터(JSON-LD)")[1])
        assertEquals("아니요", r.row("https")[1]); assertEquals(2, r.rowLevel("https"))                  // 시험 서버는 http

        val poor = run("web_seo", "u" to page("<html><body>hi</body></html>").url("/"))
        assertEquals("없음", poor.row("제목")[1]); assertEquals(2, poor.rowLevel("제목")); assertEquals(2, poor.rowLevel("viewport")); assertEquals(1, poor.rowLevel("설명(description)")); assertEquals(1, poor.rowLevel("canonical"))
        assertEquals("0개", poor.row("h1 제목")[1]); assertEquals(1, poor.rowLevel("h1 제목")); assertEquals("1", poor.row("본문 단어 수")[1]); assertEquals("내용이 적어요", poor.row("본문 단어 수")[2])
        val noindex = run("web_seo", "u" to page("""<html><head><meta name="robots" content="noindex, nofollow"></head><body>x</body></html>""").url("/"))
        assertEquals("noindex, nofollow", noindex.row("robots 메타")[1]); assertEquals("검색 제외(noindex)!", noindex.row("robots 메타")[2]); assertEquals(2, noindex.rowLevel("robots 메타"))
    }

    @Test fun toolWebExternalListsThirdPartyAndTrackers() {
        val html = """<html><head><script src="https://www.google-analytics.com/analytics.js"></script>
            <script src="https://connect.facebook.net/en_US/fbevents.js"></script>
            <link rel="stylesheet" href="https://cdn.example.net/x.css"></head>
            <body><img src="/logo.png"><script src="/app.js"></script></body></html>"""
        val r = run("web_external", "u" to page(html).url("/"))
        assertEquals("5개 (같은 사이트 2 · 외부 3)", r.kv("불러오는 리소스")); assertEquals("3곳", r.kv("외부 도메인")); assertEquals("2곳", r.kv("추적·광고 의심")); assertEquals(1, r.kvLevel("추적·광고 의심"))
        assertEquals(listOf("www.google-analytics.com", "1", "script", "Google 애널리틱스"), r.row("www.google-analytics.com")); assertEquals(1, r.rowLevel("www.google-analytics.com"))
        assertEquals("Facebook(Meta) 픽셀·SDK", r.row("connect.facebook.net")[3])
        assertEquals(listOf("cdn.example.net", "1", "css", "-"), r.row("cdn.example.net")); assertEquals(0, r.rowLevel("cdn.example.net"))
        assertTrue(r.text().contains("http 페이지라 혼합 콘텐츠를 판단하지 않아요")); assertTrue(r.text().contains("광고·분석 서비스가 방문자의 정보를 외부로 보내요"))
        val clean = run("web_external", "u" to page("<html><body><img src=\"/a.png\"></body></html>").url("/"))
        assertEquals("0곳", clean.kv("추적·광고 의심")); assertEquals(-1, clean.kvLevel("추적·광고 의심"))
    }

    @Test fun toolWebStackGuessesTechnologies() {
        val html = """<html><head><meta name="generator" content="WordPress 6.4"><script src="/wp-content/themes/a.js"></script><script src="https://www.googletagmanager.com/gtm.js"></script><script src="/js/jquery.min.js"></script></head></html>"""
        val r = run("web_stack", "u" to page(html, "Server: nginx/1.24.0", "X-Powered-By: PHP/8.2.1", "Set-Cookie: PHPSESSID=abc; path=/", "CF-Ray: 8a1b2c-ICN").url("/"))
        val names = r.rows().map { it[0] }
        for (n in listOf("Nginx", "PHP", "Cloudflare(CDN)", "제작 도구: WordPress 6.4", "WordPress", "Google 태그 관리자", "jQuery")) assertTrue("$n 가 없음: $names", n in names)
        assertEquals("127.0.0.1", r.kv("서버 IP")); assertEquals("200 OK", r.kv("상태"))
        val bare = run("web_stack", "u" to TestHttp { _, out -> out.respond("200 OK", body = "hi".toByteArray()) }.track().url("/"))
        assertEquals(1, bare.noteWith("알려진 기술의 흔적을 찾지 못했어요")?.level)
    }

    @Test fun toolWebRobotsTestAppliesRulesPerBot() {
        val robots = "User-agent: *\nDisallow: /admin/\nAllow: /admin/public/\n\nUser-agent: Googlebot\nDisallow: /nogoogle/\n"
        val s = TestHttp { req, out -> if (req.path == "/robots.txt") out.respond("200 OK", "Content-Type: text/plain", body = robots.toByteArray()) else out.respond("404 Not Found") }.track()
        val star = run("web_robots_test", "u" to s.url("/admin/secret"), "ua" to "* (그 밖의 모든 로봇)")
        assertEquals("수집 금지", star.kv("결과")); assertEquals(2, star.kvLevel("결과")); assertEquals("Disallow: /admin/", star.kv("적용된 규칙")); assertEquals("200 OK", star.kv("robots.txt"))
        val allow = run("web_robots_test", "u" to s.url("/admin/public/x"), "ua" to "* (그 밖의 모든 로봇)"); assertEquals("수집 허용", allow.kv("결과")); assertEquals("Allow: /admin/public/", allow.kv("적용된 규칙"))
        val g = run("web_robots_test", "u" to s.url("/admin/secret"), "ua" to "Googlebot"); assertEquals("수집 허용", g.kv("결과")); assertEquals("해당 규칙 없음 (기본 허용)", g.kv("적용된 규칙")); assertEquals("Googlebot", g.kv("로봇"))
        assertEquals("수집 금지", run("web_robots_test", "u" to s.url("/admin/secret"), "ua" to "Yeti (네이버)").kv("결과"))     // 이름이 없는 로봇은 * 규칙
        assertEquals("수집 금지", run("web_robots_test", "u" to s.url("/nogoogle/a"), "ua" to "Googlebot").kv("결과"))
        val none = TestHttp { _, out -> out.respond("404 Not Found") }.track()
        val nr = run("web_robots_test", "u" to none.url("/a"), "ua" to "Googlebot"); assertTrue(nr.text().contains("robots.txt 가 없어서 모든 로봇이 모든 주소를 수집할 수 있어요")); assertEquals(1, nr.kvLevel("robots.txt"))
    }

    @Test fun toolWebServerTimeMeasuresClockOffset() {
        fun dateHeader(ms: Long) = "Date: " + DateTimeFormatter.RFC_1123_DATE_TIME.format(Instant.ofEpochMilli(ms).atZone(ZoneId.of("GMT")))
        TestHttp { _, out -> out.respond("200 OK", dateHeader(System.currentTimeMillis())) }.track().let { s ->
            val r = run("web_server_time", "u" to s.url("/")); assertEquals("±1초 이내", r.kv("내 시계 오차")); assertEquals(-1, r.kvLevel("내 시계 오차")); assertTrue(r.kv("서버 시각").endsWith("GMT")); assertTrue(s.requests.all { it.method == "HEAD" })
        }
        TestHttp { _, out -> out.respond("200 OK", dateHeader(System.currentTimeMillis() + 300_000)) }.track().let { s ->
            val r = run("web_server_time", "u" to s.url("/")); assertTrue(r.kv("내 시계 오차"), Regex("폰이 (299|300)초 느려요").matches(r.kv("내 시계 오차"))); assertEquals(2, r.kvLevel("내 시계 오차"))
        }
        TestHttp { _, out -> out.respond("200 OK", dateHeader(System.currentTimeMillis() - 10_000)) }.track().let { s ->
            val r = run("web_server_time", "u" to s.url("/")); assertTrue(r.kv("내 시계 오차"), Regex("폰이 (9|10)초 빨라요").matches(r.kv("내 시계 오차"))); assertEquals(1, r.kvLevel("내 시계 오차"))
        }
        val noDate = run("web_server_time", "u" to TestHttp { _, out -> out.respond("200 OK") }.track().url("/")); assertTrue(noDate.hasError); assertTrue(noDate.text().contains("Date 머리글을 보내지 않았어요"))
    }

    @Test fun toolWebDownloadSpeedMeasuresThroughputAndStopsAtLimit() {
        fun throttled(total: Int) = TestHttp { _, out ->
            val body = ByteArray(150_000) { (it % 251).toByte() }
            out.write("HTTP/1.1 200 OK\r\nContent-Type: application/octet-stream\r\nContent-Length: $total\r\nConnection: close\r\n\r\n".toByteArray())
            var sent = 0; while (sent < total) { val n = minOf(body.size, total - sent); out.write(body, 0, n); out.flush(); sent += n; Thread.sleep(8) }
        }.track()
        val r = run("web_download_speed", "u" to throttled(3_000_000).url("/big"), "max" to "5MB")
        assertEquals("200 OK", r.kv("응답")); assertEquals("3.00 MB", r.kv("받은 용량")); assertEquals("3.00 MB", r.kv("파일 크기(Content-Length)"))
        assertTrue(r.kv("다운로드 속도"), Regex("""\d+\.\d Mbps {2}\(\d+\.\d MB/s\)""").matches(r.kv("다운로드 속도"))); assertTrue(r.kv("첫 바이트까지").endsWith("ms"))
        val capped = run("web_download_speed", "u" to throttled(12_000_000).url("/big"), "max" to "5MB")
        assertEquals("5.00 MB", capped.kv("받은 용량")); assertEquals("12.00 MB", capped.kv("파일 크기(Content-Length)"))       // 용량 한도에서 멈춤
        val notFound = run("web_download_speed", "u" to TestHttp { _, out -> out.respond("404 Not Found", body = "no".toByteArray()) }.track().url("/x"), "max" to "5MB")
        assertEquals("404 Not Found", notFound.kv("응답")); assertEquals(1, notFound.kvLevel("응답")); assertTrue(notFound.text().contains("받은 시간이 너무 짧아서"))
        assertTrue(run("web_download_speed", "u" to "http://127.0.0.1:1/x", "max" to "5MB").hasError)
        assertTrue(run("web_download_speed", "u" to "", "max" to "5MB").text().contains("파일 주소를 입력하세요"))
    }

    @Test fun toolWebIpv6ReadsAaaaRecordsAndTriesToConnect() {
        val dns = TestDns { name, type ->
            when {
                name == "v6.example.com" && type == DnsType.AAAA -> 0 to listOf(DnsAns.AAAA("::1"))
                name == "v6.example.com" && type == DnsType.A -> 0 to listOf(DnsAns.A("93.184.216.34"))
                name == "v4only.example.com" && type == DnsType.A -> 0 to listOf(DnsAns.A("93.184.216.35"))
                else -> 0 to emptyList()
            }
        }.track()
        val host = TestHost(dns = listOf(dns.server))
        val r = run("web_ipv6", "h" to "v6.example.com", host = host)
        assertEquals("93.184.216.34", r.kv("IPv4(A)")); assertEquals("::1", r.kv("IPv6(AAAA)")); assertEquals("안 됐어요", r.kv("IPv6 로 접속"))      // 이 시험 환경에는 [::1]:443 서버가 없음
        val v4 = run("web_ipv6", "h" to "https://v4only.example.com/path", host = host)
        assertEquals("없음", v4.kv("IPv6(AAAA)")); assertEquals(1, v4.kvLevel("IPv6(AAAA)")); assertTrue(v4.text().contains("IPv6 주소가 없어요")); assertFalse(v4.hasKv("IPv6 로 접속"))
        assertTrue(dns.queries.any { it == ("v4only.example.com" to DnsType.AAAA) })
    }

    @Test fun toolWebCtLogsListsCertificatesAndNames() {
        val seen = ArrayList<String>()
        val sample = """[{"issuer_ca_id":183267,"issuer_name":"C=US, O=Let's Encrypt, CN=R3","common_name":"example.com","name_value":"example.com\nwww.example.com","id":111,"entry_timestamp":"2024-01-02T03:04:05.123","not_before":"2024-01-02T02:00:00","not_after":"2099-04-01T02:00:00","serial_number":"aa"},
            {"issuer_name":"C=US, O=DigiCert Inc, CN=DigiCert TLS RSA SHA256 2020 CA1","name_value":"*.example.com","id":222,"entry_timestamp":"2019-01-02T03:04:05","not_before":"2019-01-01T00:00:00","not_after":"2020-01-01T00:00:00"},
            {"issuer_name":"C=US, O=Let's Encrypt, CN=R3","name_value":"example.com\nwww.example.com","id":111,"not_before":"2024-01-02T02:00:00","not_after":"2099-04-01T02:00:00"}]"""
        GeoNet.fetcher = { u -> seen += u; sample }
        val r = run("web_ct_logs", "h" to "https://www.example.com/path")
        assertTrue(seen.single().contains("crt.sh/?q=%25.example.com") && seen.single().contains("output=json"))
        assertEquals("example.com", r.kv("도메인")); assertEquals("2건 (아직 유효 1건)", r.kv("발급 기록")); assertEquals("3개", r.kv("서로 다른 이름")); assertEquals("1개", r.kv("와일드카드(*.)"))
        assertEquals(listOf("2024-01-02", "example.com, www.example.com", "R3", "2099-04-01"), r.rows()[0]); assertEquals(-1, r.cols()[0].level)
        assertTrue(r.rows()[1][2].startsWith("DigiCert")); assertEquals(0, r.cols()[1].level)                               // 만료된 인증서는 level 0
        assertEquals("*.example.com\nexample.com\nwww.example.com", r.blocks())
        GeoNet.fetcher = { "[]" }; assertTrue(run("web_ct_logs", "h" to "example.com").text().contains("발급 기록이 없어요"))
        GeoNet.fetcher = { throw IOException("서버가 503 으로 답했어요") }; val e = run("web_ct_logs", "h" to "example.com"); assertTrue(e.hasError); assertTrue(e.text().contains("503"))
        GeoNet.fetcher = { "<html>busy</html>" }; assertTrue(run("web_ct_logs", "h" to "example.com").text().contains("응답을 읽지 못했어요"))
        assertTrue(run("web_ct_logs", "h" to "!!").text().contains("도메인을 입력하세요"))
    }

    @Test fun toolWebHttpsGradeFailsUntrustedCertificate() {
        TestHttps { _, out -> out.respond("200 OK", "Strict-Transport-Security: max-age=31536000; includeSubDomains", body = "ok".toByteArray()) }.track().let { s ->
            val r = run("web_https_grade", "h" to "127.0.0.1:${s.port}")
            assertTrue(r.kv("등급"), r.kv("등급").startsWith("F")); assertEquals(2, r.kvLevel("등급"))
            assertEquals("TLSv1.3", r.kv("TLS 버전")); assertEquals("지원", r.kv("TLS 1.3")); assertTrue(r.kv("HSTS").startsWith("max-age=31536000")); assertEquals(-1, r.kvLevel("HSTS"))
            assertFalse(r.kv("TLSv1.1").contains("허용")); assertFalse(r.kv("TLSv1").contains("허용"))             // 낡은 TLS 는 이 JDK 도 서버도 끄고 있음
            assertTrue(r.rows().any { it[0] == "인증서를 믿을 수 없어요" && it[1] == "치명적" }); assertTrue(r.text().contains("443 이 아닌 포트라서"))
            assertTrue(s.handshakes.get() >= 3)                                                                       // 버전별 접속 + 웹 요청
        }
        assertTrue(run("web_https_grade", "h" to "127.0.0.1:1").hasError)
    }
}
