package com.selfcheck.app

import android.content.Context
import org.json.JSONArray
import java.io.IOException
import java.io.InputStream
import java.net.HttpURLConnection
import java.net.URL
import java.util.concurrent.ExecutorCompletionService
import java.util.concurrent.Executors

data class SiteResult(
    val username: String,
    val site: String,
    val url: String,
    val status: String, // found / possible / not_found / blocked / error
    val http: Int?,
    val note: String,
    val avatar: String?,
    var faceScore: Double? = null,
)

/**
 * 내 아이디를 사이트마다 확인합니다. 사이트별 규칙 없이, 존재하지 않을 무작위
 * 아이디의 응답과 비교해서 판별합니다 (파이썬 버전과 같은 방식).
 */
object UsernameChecker {
    private const val UA = "Mozilla/5.0 (Linux; Android 14) AppleWebKit/537.36 " +
        "(KHTML, like Gecko) Chrome/130.0 Mobile Safari/537.36"
    private val MISSING = setOf(404, 410)
    private val BLOCKED = setOf(401, 403, 429, 503)

    class Resp(val code: Int, val finalUrl: String, val body: String)

    fun loadSites(ctx: Context): List<Pair<String, String>> {
        val arr = JSONArray(ctx.assets.open("sites.json").bufferedReader().readText())
        return (0 until arr.length()).map { arr.getJSONArray(it).let { p -> p.getString(0) to p.getString(1) } }
    }

    fun fetch(url: String, timeoutMs: Int, maxBody: Int = 300_000): Resp {
        var current = url
        for (hop in 0..6) {
            val c = (URL(current).openConnection() as HttpURLConnection).apply {
                instanceFollowRedirects = false
                connectTimeout = timeoutMs
                readTimeout = timeoutMs
                setRequestProperty("User-Agent", UA)
                setRequestProperty("Accept-Language", "ko,en-US;q=0.8")
            }
            try {
                val code = c.responseCode
                val loc = c.getHeaderField("Location")
                if (code in 300..399 && loc != null) {
                    current = URL(URL(current), loc).toString()
                    continue
                }
                val stream = if (code >= 400) c.errorStream else c.inputStream
                val body = stream?.use { readLimited(it, maxBody) } ?: ""
                return Resp(code, current, body)
            } finally {
                c.disconnect()
            }
        }
        throw IOException("리다이렉트가 너무 많음")
    }

    fun fetchBytes(url: String, timeoutMs: Int, maxBytes: Int = 8_000_000): ByteArray {
        val c = (URL(url).openConnection() as HttpURLConnection).apply {
            connectTimeout = timeoutMs; readTimeout = timeoutMs
            setRequestProperty("User-Agent", UA)
        }
        try {
            return c.inputStream.use { readBytes(it, maxBytes) }
        } finally {
            c.disconnect()
        }
    }

    private fun readBytes(input: InputStream, limit: Int): ByteArray {
        val out = java.io.ByteArrayOutputStream()
        val buf = ByteArray(16 * 1024)
        while (out.size() < limit) {
            val n = input.read(buf)
            if (n < 0) break
            out.write(buf, 0, n)
        }
        return out.toByteArray()
    }

    private fun readLimited(input: InputStream, limit: Int) = String(readBytes(input, limit), Charsets.UTF_8)

    private fun randName(): String {
        val chars = "abcdefghijklmnopqrstuvwxyz0123456789"
        return "zq" + (1..14).map { chars.random() }.joinToString("")
    }

    private val OG1 = Regex("""<meta[^>]+(?:property|name)=["'](?:og:image|twitter:image)["'][^>]+content=["']([^"']+)""", RegexOption.IGNORE_CASE)
    private val OG2 = Regex("""<meta[^>]+content=["']([^"']+)["'][^>]+(?:property|name)=["'](?:og:image|twitter:image)""", RegexOption.IGNORE_CASE)

    private fun ogImage(html: String): String? =
        (OG1.find(html) ?: OG2.find(html))?.groupValues?.get(1)?.replace("&amp;", "&")

    private fun containsName(url: String, name: String): Boolean {
        val u = URL(url)
        return u.host.lowercase().contains(name) || u.path.lowercase().contains(name)
    }

    fun checkSite(site: String, template: String, username: String, timeoutMs: Int): SiteResult {
        val url = template.replace("{}", username)
        fun r(status: String, http: Int?, note: String = "", avatar: String? = null) =
            SiteResult(username, site, url, status, http, note, avatar)

        val real = try { fetch(url, timeoutMs) } catch (e: Exception) {
            return r("error", null, e.javaClass.simpleName)
        }
        val code = real.code
        if (code in MISSING) return r("not_found", code)
        if (code in BLOCKED) return r("blocked", code, "봇 차단 또는 로그인 필요")
        if (code >= 400) return r("error", code)

        val fakeName = randName()
        val fake = try { fetch(template.replace("{}", fakeName), timeoutMs) } catch (e: Exception) { null }
        val avatar = ogImage(real.body)
        if (fake == null) return r("possible", code, "비교 요청 실패", avatar)
        if (fake.code >= 400) return r("found", code, "", avatar)

        val name = username.lowercase()
        val nameInReal = containsName(real.finalUrl, name)
        val nameInFake = containsName(fake.finalUrl, fakeName)
        if (nameInReal && !nameInFake) return r("found", code, "없는 아이디는 다른 페이지로 이동", avatar)
        if (!nameInReal) return r("not_found", code, "다른 페이지로 이동됨")

        val bodyReal = real.body.lowercase().contains(name)
        val bodyFake = fake.body.lowercase().contains(fakeName)
        val lr = real.body.length; val lf = fake.body.length
        val differ = Math.abs(lr - lf) > maxOf(500.0, 0.15 * maxOf(lr, lf, 1))
        if (bodyReal && !bodyFake) return r("found", code, "본문에 아이디 있음", avatar)
        if (differ) return r("possible", code, "응답 내용이 다름", avatar)
        return r("not_found", code, "없는 아이디와 응답이 같음")
    }

    fun checkAll(
        sites: List<Pair<String, String>>,
        username: String,
        workers: Int = 16,
        timeoutMs: Int = 15_000,
        progress: (done: Int, total: Int, r: SiteResult) -> Unit = { _, _, _ -> },
    ): List<SiteResult> {
        val pool = Executors.newFixedThreadPool(workers)
        try {
            val cs = ExecutorCompletionService<SiteResult>(pool)
            sites.forEach { (n, t) -> cs.submit { checkSite(n, t, username, timeoutMs) } }
            val out = ArrayList<SiteResult>(sites.size)
            for (i in 1..sites.size) {
                val res = cs.take().get()
                out += res
                progress(i, sites.size, res)
            }
            return out
        } finally {
            pool.shutdownNow()
        }
    }

    val ORDER = mapOf("found" to 0, "possible" to 1, "blocked" to 2, "error" to 3, "not_found" to 4)
    val LABEL = mapOf("found" to "있음", "possible" to "있을 수도", "blocked" to "확인 불가(차단)",
        "error" to "오류", "not_found" to "없음")
}
