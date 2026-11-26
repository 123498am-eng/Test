package com.selfcheck.app

import org.json.JSONObject
import java.io.IOException
import java.net.DatagramPacket
import java.net.DatagramSocket
import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.SocketTimeoutException
import java.nio.ByteBuffer
import java.util.concurrent.Callable
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit
import kotlin.math.abs
import kotlin.math.asin
import kotlin.math.atan2
import kotlin.math.cos
import kotlin.math.floor
import kotlin.math.min
import kotlin.math.pow
import kotlin.math.sin
import kotlin.math.sqrt

/*
 * IP 위치·IP 찾기 도구의 엔진 (화면과 분리해서 컴퓨터에서 시험):
 *  Geo(좌표 계산) · GeoProviders(IP 위치 제공처 응답 해석·합의) · Stun · Igd(UPnP 공유기 WAN IP) · Mdns · Dnsbl · Rdap · CloudDetect
 * IP 위치는 통신사가 등록한 주소 블록을 바탕으로 짐작하는 값이라, 도시 수준에서도 자주 틀리고 사람·집의 위치와는 무관합니다.
 */

// ---------------------------------------------------------------------------------------------
// 좌표 계산

object Geo {
    private const val R = 6371.0088

    fun distanceKm(lat1: Double, lon1: Double, lat2: Double, lon2: Double): Double {
        val p1 = Math.toRadians(lat1); val p2 = Math.toRadians(lat2)
        val dp = p2 - p1; val dl = Math.toRadians(lon2 - lon1)
        val a = sin(dp / 2).pow(2) + cos(p1) * cos(p2) * sin(dl / 2).pow(2)
        return 2 * R * asin(min(1.0, sqrt(a)))
    }

    /** 첫째 점에서 둘째 점으로 가는 처음 방위 (0=북, 90=동) */
    fun bearing(lat1: Double, lon1: Double, lat2: Double, lon2: Double): Double {
        val p1 = Math.toRadians(lat1); val p2 = Math.toRadians(lat2); val dl = Math.toRadians(lon2 - lon1)
        val y = sin(dl) * cos(p2); val x = cos(p1) * sin(p2) - sin(p1) * cos(p2) * cos(dl)
        return (Math.toDegrees(atan2(y, x)) + 360.0) % 360.0
    }

    fun midpoint(lat1: Double, lon1: Double, lat2: Double, lon2: Double): Pair<Double, Double> {
        val p1 = Math.toRadians(lat1); val l1 = Math.toRadians(lon1); val p2 = Math.toRadians(lat2); val dl = Math.toRadians(lon2 - lon1)
        val bx = cos(p2) * cos(dl); val by = cos(p2) * sin(dl)
        val p3 = atan2(sin(p1) + sin(p2), sqrt((cos(p1) + bx).pow(2) + by.pow(2)))
        val l3 = l1 + atan2(by, cos(p1) + bx)
        return Math.toDegrees(p3) to ((Math.toDegrees(l3) + 540.0) % 360.0 - 180.0)
    }

    private val COMPASS = listOf("북", "북북동", "북동", "동북동", "동", "동남동", "남동", "남남동", "남", "남남서", "남서", "서남서", "서", "서북서", "북서", "북북서")
    fun compass(deg: Double): String = COMPASS[((deg / 22.5) + 0.5).toInt() % 16]

    /** 빛이 광섬유에서 가는 속도(약 20만 km/s)로 이론상 가장 짧은 왕복 시간(ms) */
    fun minRttMs(km: Double): Double = km / 100.0

    /** 37.5665 → 37°33′59.4″N */
    fun dms(v: Double, pos: Char, neg: Char): String {
        val h = if (v >= 0) pos else neg
        val total = Math.round(abs(v) * 36000.0) / 10.0           // 0.1초 단위로 반올림해서 60.0초가 나오지 않게
        val d = (total / 3600).toInt(); val rem = total - d * 3600.0
        val m = (rem / 60).toInt(); val s = rem - m * 60.0
        return "%d°%02d′%04.1f″%c".format(d, m, s, h)
    }

    /** 십진수 도 (37.56650) 로 보이기 */
    fun dec(v: Double) = "%.5f".format(v)

    private val PART = Regex("""([NSEWnsew])?\s*([+-]?\d+(?:\.\d+)?)\s*[°º d]?\s*(?:(\d+(?:\.\d+)?)\s*['′’m]?\s*(?:(\d+(?:\.\d+)?)\s*["″”s]?)?)?\s*([NSEWnsew])?""")

    /** "37.5665, 126.9780" · "37°33′59.4″N 126°58′40.8″E" · "N37 33.99 E126 58.68" 등을 (위도, 경도)로. 읽지 못하면 null */
    fun parseCoord(text: String): Pair<Double, Double>? {
        val t = text.trim()
        if (t.isEmpty()) return null
        Regex("""^([+-]?\d+(?:\.\d+)?)\s*[,;/\s]\s*([+-]?\d+(?:\.\d+)?)$""").find(t)?.let { m ->
            val a = m.groupValues[1].toDouble(); val b = m.groupValues[2].toDouble()
            return if (abs(a) <= 90 && abs(b) <= 180) a to b else null
        }
        val parts = ArrayList<Triple<Char?, Double, Boolean>>()          // (방향, 값, 방향이 있었나)
        for (m in PART.findAll(t)) {
            val hemi = (m.groupValues[1].ifEmpty { m.groupValues[5] }).uppercase().firstOrNull()
            val deg = m.groupValues[2].toDoubleOrNull() ?: continue
            val min = m.groupValues[3].toDoubleOrNull() ?: 0.0; val sec = m.groupValues[4].toDoubleOrNull() ?: 0.0
            if (min >= 60 || sec >= 60) return null
            var v = abs(deg) + min / 60 + sec / 3600
            if (deg < 0) v = -v
            if (hemi == 'S' || hemi == 'W') v = -abs(v)
            parts += Triple(hemi, v, hemi != null)
        }
        if (parts.size != 2) return null
        var (lat, lon) = parts[0].second to parts[1].second
        if (parts[0].first == 'E' || parts[0].first == 'W' || parts[1].first == 'N' || parts[1].first == 'S') { lat = parts[1].second; lon = parts[0].second }
        return if (abs(lat) <= 90 && abs(lon) <= 180) lat to lon else null
    }

    fun mapLinks(lat: Double, lon: Double): List<Pair<String, String>> {
        val la = "%.5f".format(lat); val lo = "%.5f".format(lon)
        return listOf(
            "OpenStreetMap" to "https://www.openstreetmap.org/?mlat=$la&mlon=$lo#map=11/$la/$lo",
            "구글 지도" to "https://www.google.com/maps?q=$la,$lo",
            "카카오맵" to "https://map.kakao.com/link/map/위치,$la,$lo",
            "geo 주소(지도 앱)" to "geo:$la,$lo",
        )
    }
}

// ---------------------------------------------------------------------------------------------
// 병렬 실행 도우미 (제공처·서버 여러 곳에 한꺼번에 물어봄)

object Par {
    fun <T, R> map(items: List<T>, threads: Int = 8, timeoutMs: Long = 15000, f: (T) -> R): List<R?> {
        if (items.isEmpty()) return emptyList()
        val pool = Executors.newFixedThreadPool(min(threads, items.size), daemonFactory("par"))
        try {
            val futures = items.map { pool.submit(Callable { try { f(it) } catch (_: Throwable) { null } }) }
            val deadline = System.currentTimeMillis() + timeoutMs
            @Suppress("UNCHECKED_CAST")
            return futures.map { fu -> try { fu.get(maxOf(1L, deadline - System.currentTimeMillis()), TimeUnit.MILLISECONDS) as R? } catch (_: Exception) { null } }
        } finally { pool.shutdownNow() }
    }
}

// ---------------------------------------------------------------------------------------------
// IP 위치 제공처

class GeoResult(
    val provider: String, val ip: String? = null, val countryCode: String? = null, val country: String? = null, val region: String? = null, val city: String? = null,
    val lat: Double? = null, val lon: Double? = null, val timezone: String? = null, val org: String? = null, val asn: String? = null,
    val proxy: Boolean? = null, val vpn: Boolean? = null, val tor: Boolean? = null, val hosting: Boolean? = null, val mobile: Boolean? = null, val abuser: Boolean? = null,
    val error: String? = null,
) {
    val ok: Boolean get() = error == null && (countryCode != null || country != null)
    val place: String get() = listOfNotNull(city, region, country ?: countryCode).distinct().joinToString(", ").ifEmpty { "-" }
}

class GeoProvider(val id: String, val https: Boolean, val urlFor: (String) -> String, val parse: (String) -> GeoResult)

object GeoProviders {
    private fun JSONObject.s(k: String): String? = if (!has(k) || isNull(k)) null else optString(k).trim().takeIf { it.isNotEmpty() && it != "null" }
    private fun JSONObject.d(k: String): Double? = if (!has(k) || isNull(k)) null else optString(k).trim().toDoubleOrNull()
    private fun JSONObject.b(k: String): Boolean? = if (!has(k) || isNull(k)) null else when (val v = opt(k)) { is Boolean -> v; is String -> v.equals("true", true); else -> null }
    private fun asnText(v: String?): String? = v?.trim()?.let { if (it.all { c -> c.isDigit() }) "AS$it" else it.uppercase().takeIf { u -> u.startsWith("AS") } ?: it }
    private fun err(p: String, m: String) = GeoResult(p, error = m)

    private fun ipwho(t: String): GeoResult {
        val o = JSONObject(t)
        if (!o.optBoolean("success", true)) return err("ipwho.is", o.s("message") ?: "조회 실패")
        val c = o.optJSONObject("connection"); val tz = o.optJSONObject("timezone")
        return GeoResult("ipwho.is", o.s("ip"), o.s("country_code"), o.s("country"), o.s("region"), o.s("city"), o.d("latitude"), o.d("longitude"), tz?.s("id"), c?.s("isp") ?: c?.s("org"), asnText(c?.s("asn")))
    }

    private fun ipapiCo(t: String): GeoResult {
        val o = JSONObject(t)
        if (o.optBoolean("error", false)) return err("ipapi.co", o.s("reason") ?: o.s("message") ?: "조회 실패")
        return GeoResult("ipapi.co", o.s("ip"), o.s("country_code") ?: o.s("country"), o.s("country_name"), o.s("region"), o.s("city"), o.d("latitude"), o.d("longitude"), o.s("timezone"), o.s("org"), asnText(o.s("asn")))
    }

    private fun ipinfo(t: String): GeoResult {
        val o = JSONObject(t)
        if (o.b("bogon") == true) return err("ipinfo.io", "사설·예약 주소예요")
        if (o.has("error") && !o.has("ip")) return err("ipinfo.io", o.optJSONObject("error")?.s("message") ?: o.s("error") ?: "조회 실패")
        val loc = o.s("loc")?.split(',')
        val orgFull = o.s("org")
        val asn = orgFull?.takeIf { it.startsWith("AS", true) }?.substringBefore(' ')?.uppercase()
        return GeoResult("ipinfo.io", o.s("ip"), o.s("country"), null, o.s("region"), o.s("city"), loc?.getOrNull(0)?.toDoubleOrNull(), loc?.getOrNull(1)?.toDoubleOrNull(), o.s("timezone"), if (asn != null) orgFull.substringAfter(' ', "").ifEmpty { null } else orgFull, asn)
    }

    private fun ipGuide(t: String): GeoResult {
        val o = JSONObject(t)
        o.s("error")?.let { return err("ip.guide", it) }
        val loc = o.optJSONObject("location"); val net = o.optJSONObject("network"); val asn = net?.optJSONObject("autonomous_system")
        return GeoResult("ip.guide", o.s("ip"), null, loc?.s("country"), null, loc?.s("city"), loc?.d("latitude"), loc?.d("longitude"), loc?.s("timezone"), asn?.s("organization") ?: asn?.s("name"), asnText(asn?.s("asn")))
    }

    private fun geojs(t: String): GeoResult {
        val o = JSONObject(t)
        return GeoResult("geojs.io", o.s("ip"), o.s("country_code"), o.s("country"), o.s("region"), o.s("city"), o.d("latitude"), o.d("longitude"), o.s("timezone"), o.s("organization_name") ?: o.s("organization"), asnText(o.s("asn")))
    }

    private fun ipApi(t: String): GeoResult {
        val o = JSONObject(t)
        if (o.s("status") != "success") return err("ip-api.com", o.s("message") ?: "조회 실패")
        return GeoResult("ip-api.com", o.s("query"), o.s("countryCode"), o.s("country"), o.s("regionName"), o.s("city"), o.d("lat"), o.d("lon"), o.s("timezone"), o.s("isp") ?: o.s("org"), asnText(o.s("as")?.substringBefore(' ')),
            proxy = o.b("proxy"), hosting = o.b("hosting"), mobile = o.b("mobile"))
    }

    private fun ipapiIs(t: String): GeoResult {
        val o = JSONObject(t)
        o.s("error")?.let { return err("ipapi.is", it) }
        if (o.b("is_bogon") == true) return err("ipapi.is", "사설·예약 주소예요")
        val loc = o.optJSONObject("location"); val asn = o.optJSONObject("asn"); val co = o.optJSONObject("company")
        return GeoResult("ipapi.is", o.s("ip"), loc?.s("country_code"), loc?.s("country"), loc?.s("state"), loc?.s("city"), loc?.d("latitude"), loc?.d("longitude"), loc?.s("timezone"), co?.s("name") ?: asn?.s("org"), asnText(asn?.s("asn")),
            proxy = o.b("is_proxy"), vpn = o.b("is_vpn"), tor = o.b("is_tor"), hosting = o.b("is_datacenter"), mobile = o.b("is_mobile"), abuser = o.b("is_abuser"))
    }

    val IPWHO = GeoProvider("ipwho.is", true, { ip -> if (ip.isEmpty()) "https://ipwho.is/" else "https://ipwho.is/$ip" }, ::ipwho)
    val IPAPI_CO = GeoProvider("ipapi.co", true, { ip -> if (ip.isEmpty()) "https://ipapi.co/json/" else "https://ipapi.co/$ip/json/" }, ::ipapiCo)
    val IPINFO = GeoProvider("ipinfo.io", true, { ip -> if (ip.isEmpty()) "https://ipinfo.io/json" else "https://ipinfo.io/$ip/json" }, ::ipinfo)
    val IPGUIDE = GeoProvider("ip.guide", true, { ip -> if (ip.isEmpty()) "https://ip.guide/" else "https://ip.guide/$ip" }, ::ipGuide)
    val GEOJS = GeoProvider("geojs.io", true, { ip -> if (ip.isEmpty()) "https://get.geojs.io/v1/ip/geo.json" else "https://get.geojs.io/v1/ip/geo/$ip.json" }, ::geojs)
    val IPAPI_IS = GeoProvider("ipapi.is", true, { ip -> if (ip.isEmpty()) "https://api.ipapi.is/" else "https://api.ipapi.is/?q=$ip" }, ::ipapiIs)
    /** 무료 주소는 https 를 지원하지 않아서 http (결과가 암호화되지 않고, 누구나 중간에서 바꿀 수 있음) */
    val IPAPI_COM = GeoProvider("ip-api.com", false, { ip -> "http://ip-api.com/json/$ip?fields=status,message,country,countryCode,regionName,city,lat,lon,timezone,isp,org,as,mobile,proxy,hosting,query" }, ::ipApi)

    /** 기본으로 묻는 제공처 (모두 https) */
    val DEFAULT = listOf(IPWHO, IPAPI_CO, IPINFO, IPGUIDE, IPAPI_IS)
    val ALL = DEFAULT + listOf(GEOJS, IPAPI_COM)
}

object GeoNet {
    /** 시험에서 인터넷 대신 쓰는 가짜 응답 함수 (주소 → 본문) */
    @Volatile var fetcher: ((String) -> String)? = null

    /** 주소에서 글을 받아옴 (리다이렉트 4번까지 따라감). 200번대가 아니면 IOException */
    fun get(url: String, timeoutMs: Int = 7000, maxBody: Int = 262144, headers: Map<String, String> = emptyMap()): String {
        fetcher?.let { return it(url) }
        var cur = url
        for (hop in 0..4) {
            val r = MiniHttp.request(cur, "GET", mapOf("Accept" to "application/json, text/plain, */*") + headers, maxBody, timeoutMs)
            if (r.isRedirect) { cur = java.net.URI(r.url).resolve(r.header("Location")!!.trim()).toString(); continue }
            if (r.status !in 200..299) throw IOException("서버가 ${r.statusLine.substringAfter(' ')} 로 답했어요")
            return r.body ?: ""
        }
        throw IOException("이동이 너무 많아요")
    }

    fun lookup(p: GeoProvider, ip: String, timeoutMs: Int = 7000): GeoResult =
        try { p.parse(get(p.urlFor(ip), timeoutMs)) } catch (e: IOException) { GeoResult(p.id, error = e.message ?: "접속하지 못했어요") } catch (e: org.json.JSONException) { GeoResult(p.id, error = "응답을 읽지 못했어요") } catch (e: Exception) { GeoResult(p.id, error = e.message ?: e.javaClass.simpleName) }

    fun lookupAll(providers: List<GeoProvider>, ip: String, timeoutMs: Int = 7000): List<GeoResult> =
        Par.map(providers, 8, timeoutMs + 3000L) { lookup(it, ip, timeoutMs) }.mapIndexed { i, r -> r ?: GeoResult(providers[i].id, error = "응답이 없어요") }
}

/** 여러 제공처의 답을 하나로: 나라는 다수결, 도시·좌표는 그 나라 안에서 모음 */
class GeoConsensus(
    val countryCode: String?, val country: String?, val city: String?, val region: String?, val lat: Double?, val lon: Double?, val timezone: String?, val org: String?, val asn: String?,
    val agree: Int, val total: Int, val spreadKm: Double?, val cityAgree: Int, val level: Int,
)

object GeoMerge {
    fun merge(all: List<GeoResult>): GeoConsensus? {
        val ok = all.filter { it.ok }
        if (ok.isEmpty()) return null
        // 나라 코드 없이 이름만 주는 제공처(ip.guide 등)는, 다른 제공처가 준 (이름, 코드) 쌍이나 한국어 표로 코드를 맞춰서 같은 나라끼리 묶음
        val learned = ok.filter { it.countryCode != null && it.country != null }.associate { it.country!!.trim().lowercase() to it.countryCode!!.trim().uppercase() }
        fun key(r: GeoResult): String? = r.countryCode?.trim()?.uppercase() ?: r.country?.trim()?.let { n -> learned[n.lowercase()] ?: CountryNames.find(n) ?: n.uppercase() }
        val groups = ok.groupBy { key(it) }
        val top = groups.maxByOrNull { it.value.size }!!
        val inCountry = top.value
        val cityGroups = inCountry.filter { !it.city.isNullOrBlank() }.groupBy { it.city!!.trim().lowercase() }
        val cityTop = cityGroups.maxByOrNull { it.value.size }?.value
        val pts = inCountry.filter { it.lat != null && it.lon != null }
        var spread = 0.0
        for (i in pts.indices) for (j in i + 1 until pts.size) spread = maxOf(spread, Geo.distanceKm(pts[i].lat!!, pts[i].lon!!, pts[j].lat!!, pts[j].lon!!))
        val near = (cityTop ?: inCountry).filter { it.lat != null && it.lon != null }
        val lat = if (near.isEmpty()) null else near.map { it.lat!! }.sorted().let { it[it.size / 2] }
        val lon = if (near.isEmpty()) null else near.map { it.lon!! }.sorted().let { it[it.size / 2] }
        fun mostCommon(f: (GeoResult) -> String?) = inCountry.mapNotNull(f).groupingBy { it.lowercase() }.eachCount().maxByOrNull { it.value }?.key?.let { k -> inCountry.mapNotNull(f).first { it.lowercase() == k } }
        val agree = top.value.size; val total = ok.size
        val level = when {
            total >= 2 && agree == total && (pts.size < 2 || spread < 30) && (cityTop?.size ?: 0) >= 2 -> -1
            agree * 2 > total && (pts.size < 2 || spread < 200) && total >= 2 -> 0
            else -> 1
        }
        return GeoConsensus(top.key?.takeIf { it.length == 2 }, inCountry.firstNotNullOfOrNull { it.country }, mostCommon { it.city }, mostCommon { it.region }, lat, lon, mostCommon { it.timezone }, mostCommon { it.org }, mostCommon { it.asn },
            agree, total, if (pts.size >= 2) spread else null, cityTop?.size ?: 0, level)
    }
}

// ---------------------------------------------------------------------------------------------
// STUN (내 공인 IP·포트 알아내기)

object Stun {
    private const val COOKIE = 0x2112A442

    fun request(txid: ByteArray): ByteArray = ByteBuffer.allocate(20).apply { putShort(0x0001); putShort(0); putInt(COOKIE); put(txid) }.array()

    /** 응답에서 (공인 주소, 포트). 내 요청(txid)의 응답이 아니면 null */
    fun parse(b: ByteArray, len: Int, txid: ByteArray): Pair<InetAddress, Int>? {
        if (len < 20) return null
        val bb = ByteBuffer.wrap(b, 0, len)
        if ((bb.getShort(0).toInt() and 0xFFFF) != 0x0101 || bb.getInt(4) != COOKIE) return null
        if (!(0 until 12).all { b[8 + it] == txid[it] }) return null
        val total = (bb.getShort(2).toInt() and 0xFFFF).coerceAtMost(len - 20)
        var pos = 20; var plain: Pair<InetAddress, Int>? = null
        while (pos + 4 <= 20 + total) {
            val type = bb.getShort(pos).toInt() and 0xFFFF; val alen = bb.getShort(pos + 2).toInt() and 0xFFFF; val v = pos + 4
            if (v + alen > len) break
            if ((type == 0x0020 || type == 0x0001) && alen >= 8) {
                val fam = b[v + 1].toInt() and 0xFF
                val xor = type == 0x0020
                var port = ((b[v + 2].toInt() and 0xFF) shl 8) or (b[v + 3].toInt() and 0xFF)
                val size = if (fam == 1) 4 else if (fam == 2) 16 else 0
                if (size > 0 && alen >= 4 + size) {
                    val addr = b.copyOfRange(v + 4, v + 4 + size)
                    if (xor) {
                        port = port xor (COOKIE ushr 16)
                        val mask = ByteBuffer.allocate(16).putInt(COOKIE).put(txid).array()
                        for (i in addr.indices) addr[i] = (addr[i].toInt() xor mask[i].toInt()).toByte()
                    }
                    val r = InetAddress.getByAddress(addr) to port
                    if (xor) return r else plain = r
                }
            }
            pos = v + ((alen + 3) and 3.inv())
        }
        return plain
    }

    /** server:port 에 UDP 로 물어서 (공인 주소, 공인 포트, 걸린 시간 ms) */
    fun query(server: String, port: Int = 3478, timeoutMs: Int = 2500, bind: (DatagramSocket) -> Unit = {}): Triple<InetAddress, Int, Long> {
        val addr = IpUtil.parse(server) ?: try { TlsInspect.resolve(server) } catch (_: Exception) { throw IOException("서버 주소를 찾지 못했어요 ($server)") }
        val txid = ByteArray(12).also { java.security.SecureRandom().nextBytes(it) }
        DatagramSocket().use { s ->
            bind(s); s.soTimeout = timeoutMs
            val q = request(txid); val t0 = System.nanoTime()
            s.send(DatagramPacket(q, q.size, addr, port))
            val buf = ByteArray(512); val p = DatagramPacket(buf, buf.size)
            val deadline = System.currentTimeMillis() + timeoutMs
            while (true) {
                val left = (deadline - System.currentTimeMillis()).toInt()
                if (left <= 0) throw IOException("응답이 없어요 (UDP 가 막혀 있을 수 있어요)")
                s.soTimeout = left
                try { s.receive(p) } catch (_: SocketTimeoutException) { throw IOException("응답이 없어요 (UDP 가 막혀 있을 수 있어요)") }
                parse(buf, p.length, txid)?.let { return Triple(it.first, it.second, (System.nanoTime() - t0) / 1_000_000) }
            }
        }
    }
}

// ---------------------------------------------------------------------------------------------
// UPnP 공유기(IGD) 에서 WAN IP 읽기

object Igd {
    class Service(val type: String, val controlUrl: String)

    private fun tag(s: String, name: String) = Regex("<$name>\\s*([^<]*?)\\s*</$name>", RegexOption.IGNORE_CASE).find(s)?.groupValues?.get(1)

    /** 장치 설명 XML 에서 WAN IP/PPP 연결 서비스와 제어 주소(절대 주소) */
    fun parseDescription(xml: String, location: String): List<Service> {
        val base = tag(xml, "URLBase")?.takeIf { it.startsWith("http") } ?: location
        val out = ArrayList<Service>()
        for (m in Regex("<service>(.*?)</service>", setOf(RegexOption.DOT_MATCHES_ALL, RegexOption.IGNORE_CASE)).findAll(xml)) {
            val type = tag(m.groupValues[1], "serviceType") ?: continue
            val ctl = tag(m.groupValues[1], "controlURL") ?: continue
            if (!(type.contains("WANIPConnection") || type.contains("WANPPPConnection"))) continue
            val abs = try { java.net.URI(base).resolve(ctl).toString() } catch (_: Exception) { continue }
            out += Service(type, abs)
        }
        return out
    }

    fun soapBody(serviceType: String, action: String): ByteArray =
        ("<?xml version=\"1.0\"?><s:Envelope xmlns:s=\"http://schemas.xmlsoap.org/soap/envelope/\" s:encodingStyle=\"http://schemas.xmlsoap.org/soap/encoding/\"><s:Body><u:$action xmlns:u=\"$serviceType\"/></s:Body></s:Envelope>").toByteArray()

    fun parseExternalIp(xml: String): String? = tag(xml, "NewExternalIPAddress")?.takeIf { it.isNotEmpty() }

    /** 공유기에게 "바깥쪽(WAN) IP 가 뭐야?" 하고 물음. 응답한 기기 자신의 내부 주소일 때만 요청함 */
    fun externalIp(device: SsdpDevice, newSocket: () -> java.net.Socket = { java.net.Socket() }): String? {
        val loc = device.location ?: return null
        val u = MiniHttp.parseUrl(loc) ?: return null
        if (u.host != device.ip || IpUtil.parse(u.host)?.let { IpUtil.classify(it).local } != true || u.isHttps) return null
        val xml = try { MiniHttp.request(loc, maxBody = 65536, timeoutMs = 2500, newSocket = newSocket).body } catch (_: IOException) { null } ?: return null
        for (s in parseDescription(xml, loc)) {
            val cu = MiniHttp.parseUrl(s.controlUrl) ?: continue
            if (cu.host != device.ip) continue
            val hdr = mapOf("Content-Type" to "text/xml; charset=\"utf-8\"", "SOAPAction" to "\"${s.type}#GetExternalIPAddress\"")
            val r = try { MiniHttp.request(s.controlUrl, "POST", hdr, 8192, 2500, newSocket = newSocket, body = soapBody(s.type, "GetExternalIPAddress")) } catch (_: IOException) { continue }
            parseExternalIp(r.body ?: "")?.let { return it }
        }
        return null
    }
}

// ---------------------------------------------------------------------------------------------
// mDNS (Bonjour): 같은 망 기기가 스스로 알리는 이름·서비스·IP 를 읽음

object Mdns {
    val GROUP = InetSocketAddress("224.0.0.251", 5353)

    class Instance(val name: String, val service: String, val host: String?, val port: Int?, val ips: List<String>, val txt: List<String>)

    fun buildQuery(id: Int, name: String, type: Int): ByteArray? {
        val n = DnsWire.encodeName(name) ?: return null
        return ByteBuffer.allocate(12 + n.size + 4).apply { putShort(id.toShort()); putShort(0); putShort(1); putShort(0); putShort(0); putShort(0); put(n); putShort(type.toShort()); putShort(0x8001.toShort()) }.array()
    }

    /** 질문마다 따로 보냄 (출발 포트가 5353 이 아니면 기기가 나에게만 직접 답해 줌: 멀티캐스트를 받을 필요가 없음) */
    fun query(questions: List<Pair<String, Int>>, timeoutMs: Int = 2500, target: InetSocketAddress = GROUP, bind: (DatagramSocket) -> Unit = {}): List<DnsMessage> {
        val out = ArrayList<DnsMessage>()
        DatagramSocket().use { s ->
            bind(s)
            for ((k, q) in questions.withIndex()) { val pkt = buildQuery(k + 1, q.first, q.second) ?: continue; s.send(DatagramPacket(pkt, pkt.size, target)) }
            val deadline = System.currentTimeMillis() + timeoutMs
            val buf = ByteArray(9000)
            while (true) {
                val left = (deadline - System.currentTimeMillis()).toInt(); if (left <= 0) break
                s.soTimeout = left
                val p = DatagramPacket(buf, buf.size)
                try { s.receive(p) } catch (_: SocketTimeoutException) { break }
                DnsWire.parse(buf, p.length)?.takeIf { it.isResponse }?.let { out += it }
            }
        }
        return out
    }

    /** 응답들에서 서비스(SRV)·문구(TXT)·주소(A/AAAA)를 이어 붙여 기기별 정보로 */
    fun instances(msgs: List<DnsMessage>): List<Instance> {
        val recs = msgs.flatMap { it.answers + it.additional }
        val a = HashMap<String, MutableSet<String>>()
        for (r in recs) if (r.type == DnsType.A || r.type == DnsType.AAAA) a.getOrPut(r.name.lowercase().trimEnd('.')) { LinkedHashSet() } += r.data
        val txt = HashMap<String, List<String>>()
        for (r in recs) if (r.type == DnsType.TXT) txt[r.name.lowercase().trimEnd('.')] = (r.text ?: "").let { listOf(it) }
        val out = ArrayList<Instance>(); val seen = HashSet<String>()
        for (r in recs) if (r.type == DnsType.SRV) {
            val key = r.name.lowercase().trimEnd('.'); if (!seen.add(key)) continue
            val f = r.data.split(' '); val host = f.getOrNull(3)?.trimEnd('.'); val port = f.getOrNull(2)?.toIntOrNull()
            val inst = r.name.trimEnd('.'); val svc = Regex("(_[^.]+\\._(?:tcp|udp))").find(inst)?.groupValues?.get(1) ?: ""
            out += Instance(inst.substringBefore("._").ifEmpty { inst }, svc, host, port, host?.let { a[it.lowercase()]?.toList() } ?: emptyList(), txt[key] ?: emptyList())
        }
        // SRV 없이 주소만 알려 준 기기
        val used = out.mapNotNull { it.host?.lowercase() }.toSet()
        for ((host, ips) in a) if (host !in used) out += Instance(host, "", host, null, ips.toList(), emptyList())
        return out
    }

    /** _services._dns-sd._udp 응답의 서비스 종류 목록 */
    fun serviceTypes(msgs: List<DnsMessage>): List<String> =
        msgs.flatMap { it.answers + it.additional }.filter { it.type == DnsType.PTR && it.name.startsWith("_services._dns-sd._udp", true) }.map { it.data.trimEnd('.') }.distinct().sorted()
}

// ---------------------------------------------------------------------------------------------
// 스팸 목록(DNSBL)

object Dnsbl {
    class Zone(val zone: String, val label: String)

    val ZONES = listOf(
        Zone("zen.spamhaus.org", "Spamhaus ZEN"), Zone("bl.spamcop.net", "SpamCop"), Zone("psbl.surriel.com", "PSBL"),
        Zone("dnsbl-1.uceprotect.net", "UCEPROTECT 1단계"), Zone("ix.dnsbl.manitu.net", "manitu"), Zone("dnsbl.dronebl.org", "DroneBL"), Zone("all.s5h.net", "S5H"),
    )

    fun reverseV4(ip: String): String = ip.split('.').reversed().joinToString(".")

    /** 판정: -1 목록에 없음, 2 목록에 있음, 0 알 수 없음(조회 제한 등) */
    fun interpret(zone: String, answers: List<String>): Pair<Int, String> {
        if (answers.isEmpty()) return -1 to "목록에 없어요"
        if (answers.any { it.startsWith("127.255.255.") }) return 0 to "조회를 거절했어요 (공용 DNS·조회 횟수 제한). 다른 DNS 서버로 다시 해 보세요"
        val code = answers.first()
        val meaning = if (zone.startsWith("zen.spamhaus")) when (code.substringAfterLast('.')) {
            "2" -> "SBL (스팸 발송지)"; "3" -> "SBL CSS (스팸 발송 의심 대역)"; "4", "5", "6", "7" -> "XBL (감염된 기기·악성코드)"; "9" -> "DROP (범죄 조직 대역)"; "10", "11" -> "PBL (일반 가정 회선: 메일 서버로 쓰면 안 되는 주소)"; else -> "목록에 있어요"
        } else "목록에 있어요"
        return 2 to "$meaning ($code)"
    }
}

// ---------------------------------------------------------------------------------------------
// RDAP (IP 등록 정보) · RIPEstat · Tor 출구 목록

class RdapIp(val name: String?, val handle: String?, val start: String?, val end: String?, val type: String?, val country: String?, val status: List<String>, val org: String?, val abuse: String?, val changed: String?, val cidrs: List<String>)

object Rdap {
    private fun JSONObject.s(k: String): String? = if (!has(k) || isNull(k)) null else optString(k).trim().takeIf { it.isNotEmpty() }

    private fun vcardField(e: JSONObject, field: String): String? {
        val arr = e.optJSONArray("vcardArray")?.optJSONArray(1) ?: return null
        for (i in 0 until arr.length()) { val p = arr.optJSONArray(i) ?: continue; if (p.optString(0) == field) return p.opt(3)?.toString()?.takeIf { it.isNotBlank() } }
        return null
    }

    /** 개인이 아니라 "기관" 이름일 때만 소유 기관으로 보여 줌 (kind 가 individual 이면 숨김) */
    fun parseIp(text: String): RdapIp {
        val o = JSONObject(text)
        var org: String? = null; var abuse: String? = null
        val ents = o.optJSONArray("entities")
        fun scan(arr: org.json.JSONArray?) {
            if (arr == null) return
            for (i in 0 until arr.length()) {
                val e = arr.optJSONObject(i) ?: continue
                val roles = (0 until (e.optJSONArray("roles")?.length() ?: 0)).map { e.optJSONArray("roles")!!.optString(it) }
                val kind = vcardField(e, "kind")
                if ("registrant" in roles && org == null) org = if (kind == "individual") "개인 명의 (표시하지 않아요)" else vcardField(e, "fn") ?: e.s("handle")
                if ("abuse" in roles && abuse == null && kind != "individual") abuse = vcardField(e, "email")
                scan(e.optJSONArray("entities"))
            }
        }
        scan(ents)
        val ev = o.optJSONArray("events")
        var changed: String? = null
        if (ev != null) for (i in 0 until ev.length()) { val e = ev.optJSONObject(i) ?: continue; if (e.optString("eventAction").contains("last changed")) changed = e.s("eventDate") }
        val st = o.optJSONArray("status"); val status = (0 until (st?.length() ?: 0)).map { st!!.optString(it) }
        val cidr = o.optJSONArray("cidr0_cidrs"); val cidrs = (0 until (cidr?.length() ?: 0)).mapNotNull { i -> cidr!!.optJSONObject(i)?.let { c -> (c.s("v4prefix") ?: c.s("v6prefix"))?.let { p -> "$p/${c.optInt("length")}" } } }
        return RdapIp(o.s("name"), o.s("handle"), o.s("startAddress"), o.s("endAddress"), o.s("type"), o.s("country"), status, org, abuse, changed, cidrs)
    }

    fun parsePrefixes(text: String): List<String> {
        val arr = JSONObject(text).optJSONObject("data")?.optJSONArray("prefixes") ?: return emptyList()
        return (0 until arr.length()).mapNotNull { arr.optJSONObject(it)?.optString("prefix")?.takeIf { p -> p.isNotEmpty() } }
    }
}

object TorList {
    fun parse(text: String): Set<String> = text.lineSequence().map { it.trim() }.filter { it.isNotEmpty() && !it.startsWith("#") }.toSet()
}

// ---------------------------------------------------------------------------------------------
// 클라우드·CDN 판별 (통신사 이름 기준의 짐작)

object CloudDetect {
    private val RULES = listOf(
        Regex("amazon|aws", RegexOption.IGNORE_CASE) to "아마존 클라우드(AWS)", Regex("google (llc|cloud)|google-cloud|googleusercontent", RegexOption.IGNORE_CASE) to "구글 (클라우드·서비스)",
        Regex("microsoft|azure", RegexOption.IGNORE_CASE) to "마이크로소프트(Azure)", Regex("cloudflare", RegexOption.IGNORE_CASE) to "클라우드플레어(CDN·보안)",
        Regex("akamai", RegexOption.IGNORE_CASE) to "아카마이(CDN)", Regex("fastly", RegexOption.IGNORE_CASE) to "패스틀리(CDN)", Regex("oracle", RegexOption.IGNORE_CASE) to "오라클 클라우드",
        Regex("digitalocean", RegexOption.IGNORE_CASE) to "디지털오션", Regex("linode|akamai connected", RegexOption.IGNORE_CASE) to "리노드", Regex("vultr|choopa|the constant company", RegexOption.IGNORE_CASE) to "벌터(Vultr)",
        Regex("hetzner", RegexOption.IGNORE_CASE) to "헤츠너", Regex("\\bovh", RegexOption.IGNORE_CASE) to "OVH", Regex("alibaba|aliyun|hangzhou alibaba", RegexOption.IGNORE_CASE) to "알리바바 클라우드",
        Regex("tencent", RegexOption.IGNORE_CASE) to "텐센트 클라우드", Regex("naver cloud|naver business platform|naver corp", RegexOption.IGNORE_CASE) to "네이버 (클라우드·서비스)", Regex("kakao", RegexOption.IGNORE_CASE) to "카카오 (클라우드·서비스)",
        Regex("nhn|toast", RegexOption.IGNORE_CASE) to "NHN 클라우드", Regex("kt ?cloud|kt corp.*idc|korea telecom.*idc", RegexOption.IGNORE_CASE) to "KT 클라우드·IDC", Regex("samsung sds", RegexOption.IGNORE_CASE) to "삼성 SDS 클라우드",
        Regex("leaseweb", RegexOption.IGNORE_CASE) to "리스웹", Regex("scaleway|online s\\.a\\.s", RegexOption.IGNORE_CASE) to "스케일웨이", Regex("contabo", RegexOption.IGNORE_CASE) to "콘타보",
        Regex("m247|datacamp|cdn77|packet host|equinix|cogent|colocrossing|quadranet|psychz", RegexOption.IGNORE_CASE) to "데이터센터·호스팅 업체 (VPN 서버로도 자주 쓰임)",
    )

    fun label(org: String?): String? = org?.let { o -> RULES.firstOrNull { it.first.containsMatchIn(o) }?.second }
}
