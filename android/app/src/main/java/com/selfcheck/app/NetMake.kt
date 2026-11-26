package com.selfcheck.app

import java.security.MessageDigest
import java.time.LocalDate
import java.time.LocalDateTime
import java.time.ZoneId
import java.time.ZonedDateTime
import java.time.temporal.ChronoUnit

/*
 * 만들기 도구의 계산 엔진: cron 식 해석·다음 실행 시각·systemd OnCalendar 변환, IPv6 ULA(RFC 4193), tc(netem·tbf) 명령.
 * 설정 파일 생성기는 NetMakeCfg.kt. 모든 계산은 폰 안에서만 하고 어디로도 보내지 않아요.
 */

object Cron {
    class Spec(val minute: BooleanArray, val hour: BooleanArray, val dom: BooleanArray, val month: BooleanArray, val dow: BooleanArray, val domStar: Boolean, val dowStar: Boolean, val fields: List<String>) {
        fun values(a: BooleanArray, lo: Int): List<Int> = (lo until a.size).filter { a[it] }
        val minutes get() = values(minute, 0); val hours get() = values(hour, 0); val doms get() = values(dom, 1); val months get() = values(month, 1); val dows get() = values(dow, 0)
        val allDom get() = doms.size == 31; val allMonth get() = months.size == 12; val allDow get() = dows.size == 7
        /** 일과 요일을 둘 다 제한했으면 "둘 중 하나만 맞아도"(OR) 실행돼요 (Vixie cron). 한쪽이 * 로 시작하면 둘 다 맞아야 해요 */
        val orSemantics get() = !domStar && !dowStar
    }

    private val ALIASES = mapOf("@yearly" to "0 0 1 1 *", "@annually" to "0 0 1 1 *", "@monthly" to "0 0 1 * *", "@weekly" to "0 0 * * 0", "@daily" to "0 0 * * *", "@midnight" to "0 0 * * *", "@hourly" to "0 * * * *")
    private val MONTHS = listOf("JAN", "FEB", "MAR", "APR", "MAY", "JUN", "JUL", "AUG", "SEP", "OCT", "NOV", "DEC")
    private val DAYS = listOf("SUN", "MON", "TUE", "WED", "THU", "FRI", "SAT")
    val DAY_KO = listOf("일", "월", "화", "수", "목", "금", "토")

    private fun value(tok: String, names: List<String>?, nameBase: Int, label: String): Int {
        tok.toIntOrNull()?.let { return it }
        if (Regex("(?i)^\\d*[LW]$|#").containsMatchIn(tok)) throw IllegalArgumentException("$label 칸의 \"$tok\" 는 Quartz/스프링 식(L·W·#)이에요. 일반 cron 은 지원하지 않아요")
        names?.indexOf(tok.uppercase())?.takeIf { it >= 0 }?.let { return it + nameBase }
        throw IllegalArgumentException("$label 칸의 \"$tok\" 를 숫자나 이름으로 읽지 못했어요")
    }

    private fun field(text: String, lo: Int, hi: Int, names: List<String>?, nameBase: Int, label: String): BooleanArray {
        val set = BooleanArray(hi + 1)
        for (part in text.split(',')) {
            if (part.isEmpty()) throw IllegalArgumentException("$label 칸에 빈 항목이 있어요 (쉼표가 겹쳤나요?)")
            val range = part.substringBefore('/'); val stepText = if (part.contains('/')) part.substringAfter('/') else null
            val step = stepText?.let { it.toIntOrNull() ?: throw IllegalArgumentException("$label 칸의 간격 \"$it\" 이 숫자가 아니에요") } ?: 1
            if (step <= 0) throw IllegalArgumentException("$label 칸의 간격은 1 이상이어야 해요: $part")
            val (a, b) = when {
                range == "*" || range == "?" -> lo to hi
                range.contains('-') -> {
                    val from = value(range.substringBefore('-'), names, nameBase, label); var to = value(range.substringAfter('-'), names, nameBase, label)
                    if (names === DAYS && to == 0 && from > 0) to = 7                      // fri-sun · mon-sun 처럼 일요일로 끝나는 요일 범위는 7(일요일)로 봐요
                    from to to
                }
                else -> { val v = value(range, names, nameBase, label); if (stepText != null) v to hi else v to v }
            }
            if (a < lo || b > hi || a > b) throw IllegalArgumentException("$label 칸의 값은 $lo~$hi 여야 해요: $part")
            var v = a; while (v <= b) { set[v] = true; v += step }
        }
        return set
    }

    /** "분 시 일 월 요일" 5칸 (또는 @daily 같은 별칭). 틀리면 IllegalArgumentException(한국어 설명) */
    fun parse(expr: String): Spec {
        val t = expr.trim()
        if (t.isEmpty()) throw IllegalArgumentException("cron 식을 입력하세요 (예: */15 9-18 * * 1-5)")
        if (t.lowercase() == "@reboot") throw IllegalArgumentException("@reboot 는 \"부팅할 때 한 번\"이라 실행 시각이 없어요")
        val src = ALIASES[t.lowercase()] ?: t
        val f = src.split(Regex("\\s+"))
        if (f.size == 6 || f.size == 7) throw IllegalArgumentException("칸이 ${f.size}개예요. 리눅스 cron 은 5칸(분 시 일 월 요일)이에요. 맨 앞이 초인 Quartz·스프링 식은 지원하지 않아요")
        if (f.size != 5) throw IllegalArgumentException("칸이 ${f.size}개예요. 분 시 일 월 요일, 5칸을 공백으로 나눠 쓰세요")
        val dow = field(f[4], 0, 7, DAYS, 0, "요일").also { if (it[7]) { it[0] = true; it[7] = false } }.copyOf(7)
        val month = field(f[3], 1, 12, MONTHS, 1, "월")
        return Spec(field(f[0], 0, 59, null, 0, "분"), field(f[1], 0, 23, null, 0, "시"), field(f[2], 1, 31, null, 0, "일"), month, dow, f[2].startsWith("*") || f[2].startsWith("?"), f[4].startsWith("*") || f[4].startsWith("?"), f)
    }

    fun dayMatches(s: Spec, d: LocalDate): Boolean {
        val domOk = s.dom[d.dayOfMonth]; val dowOk = s.dow[d.dayOfWeek.value % 7]
        return if (s.domStar || s.dowStar) domOk && dowOk else domOk || dowOk
    }

    /** from 이후(같은 시각은 제외)의 다음 실행 시각 count 개. 최대 limitYears 년 안에서만 찾음 */
    fun nextRuns(s: Spec, from: ZonedDateTime, count: Int, limitYears: Long = 100): List<ZonedDateTime> {
        val zone: ZoneId = from.zone
        var t = from.toLocalDateTime().truncatedTo(ChronoUnit.MINUTES).plusMinutes(1)
        val end = t.plusYears(limitYears); val out = ArrayList<ZonedDateTime>()
        while (out.size < count && t.isBefore(end)) {
            if (!s.month[t.monthValue]) { t = t.toLocalDate().withDayOfMonth(1).plusMonths(1).atStartOfDay(); continue }
            if (!dayMatches(s, t.toLocalDate())) { t = t.toLocalDate().plusDays(1).atStartOfDay(); continue }
            if (!s.hour[t.hour]) { t = t.withMinute(0).plusHours(1); continue }
            if (!s.minute[t.minute]) { t = t.plusMinutes(1); continue }
            val z = ZonedDateTime.ofLocal(t, zone, null)
            if (out.isEmpty() || out.last().toInstant() != z.toInstant()) out += z
            t = t.plusMinutes(1)
        }
        return out
    }

    private fun stepOf(v: List<Int>, size: Int): Int? {
        if (v.size < 2 || v[0] != 0) return null
        val n = v[1] - v[0]; if (n <= 0 || size % n != 0 || v.size != size / n) return null
        return if (v.indices.all { v[it] == it * n }) n else null
    }

    private fun runs(v: List<Int>): List<Pair<Int, Int>> {
        val out = ArrayList<Pair<Int, Int>>(); var i = 0
        while (i < v.size) { var j = i; while (j + 1 < v.size && v[j + 1] == v[j] + 1) j++; out += v[i] to v[j]; i = j + 1 }
        return out
    }

    private fun hoursText(h: List<Int>): String {
        stepOf(h, 24)?.let { return "${it}시간마다" }
        val r = runs(h)
        return r.joinToString("·") { (a, b) -> if (a == b) "${a}시" else if (b - a == 1) "${a}시·${b}시" else "${a}~${b}시" }
    }

    private fun weekdayText(d: List<Int>): String = when {
        d == listOf(1, 2, 3, 4, 5) -> "평일(월~금)"
        d == listOf(0, 6) -> "주말(토·일)"
        else -> "매주 " + d.joinToString("·") { DAY_KO[it] } + "요일"
    }

    private fun domText(d: List<Int>): String = "매월 " + runs(d).joinToString("·") { (a, b) -> if (a == b) "${a}일" else if (b - a == 1) "${a}일·${b}일" else "${a}~${b}일" }

    /** 사람이 읽는 설명: "평일(월~금) 9~18시 사이 15분마다 실행" */
    fun describe(s: Spec): String {
        val m = s.minutes; val h = s.hours; val allMin = m.size == 60; val allHour = h.size == 24
        fun minText(): String = if (m.size == 1) (if (m[0] == 0) "정각" else "${m[0]}분") else m.joinToString("·") { "${it}분" }
        val time = when {
            allMin && allHour -> "매분"
            allHour && stepOf(m, 60) != null -> "${stepOf(m, 60)}분마다"
            allHour && m.size == 1 -> if (m[0] == 0) "매시 정각" else "매시 ${m[0]}분"
            allHour -> "매시 " + minText()
            h.size == 1 && m.size == 1 -> "%02d:%02d".format(h[0], m[0])
            allMin -> hoursText(h) + " 동안 매분"
            stepOf(m, 60) != null -> "${hoursText(h)} 사이 ${stepOf(m, 60)}분마다"
            else -> hoursText(h) + " " + minText()
        }
        val day = when {
            s.allDom && s.allDow -> "매일"
            s.allDom -> weekdayText(s.dows)
            s.allDow -> domText(s.doms)
            s.orSemantics -> domText(s.doms) + " 또는 " + weekdayText(s.dows)
            else -> domText(s.doms) + "이면서 " + weekdayText(s.dows)
        }
        val month = if (s.allMonth) "" else s.months.joinToString("·") { "${it}월" } + "에 "
        return "$month$day $time 실행"
    }

    /** 값 목록 → systemd 표기 (전부면 *, 이어지는 3개 이상은 a..b, pad 면 두 자리로) */
    private fun sd(v: List<Int>, total: Int, pad: Boolean = false): String {
        if (v.size == total) return "*"
        fun f(n: Int) = if (pad) "%02d".format(n) else "$n"
        return runs(v).joinToString(",") { (a, b) -> if (a == b) f(a) else if (b - a == 1) "${f(a)},${f(b)}" else "${f(a)}..${f(b)}" }
    }

    /** systemd 타이머의 OnCalendar 식으로 바꿈. (일·요일을 둘 다 제한하면 systemd 는 "둘 다 맞아야" 해서 cron 과 달라요) */
    fun onCalendar(s: Spec): String {
        val names = listOf("Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat")
        val dows = s.dows
        val dowPart = if (s.allDow) "" else runs(dows).joinToString(",") { (a, b) -> if (a == b) names[a] else if (b - a == 1) "${names[a]},${names[b]}" else "${names[a]}..${names[b]}" } + " "
        val months = sd(s.months, 12); val doms = sd(s.doms, 31); val hours = sd(s.hours, 24, true); val minutes = sd(s.minutes, 60, true)
        return "$dowPart*-$months-$doms $hours:$minutes:00"
    }

    /** 이 식이 평소 쓰는 cron 과 systemd 가 다르게 해석하는 부분 */
    fun caveats(s: Spec): List<String> = buildList {
        if (s.orSemantics) add("일과 요일을 둘 다 정했어요. cron 은 \"둘 중 하나만 맞아도\" 실행하지만 systemd 타이머는 \"둘 다 맞아야\" 실행해서 OnCalendar 로 바꾸면 결과가 달라져요.")
        if (!s.allDom && s.doms.any { it == 31 } && s.months.any { it in listOf(2, 4, 6, 9, 11) }) add("31일이 들어 있어요. 31일이 없는 달에는 그 달에 실행되지 않아요.")
        if (!s.allDom && s.doms.any { it >= 29 } && 2 in s.months) add("2월에는 29일(윤년에만)·30일·31일이 없어요.")
    }
}

// ---------------------------------------------------------------------------------------------
// IPv6 고유 로컬 주소 (ULA, RFC 4193)

object Ula {
    private const val NTP_EPOCH = 2208988800L

    /** MAC 6바이트 → EUI-64: 가운데에 ff:fe 를 끼우고 첫 바이트의 U/L 비트를 뒤집음 */
    fun eui64(mac: ByteArray): ByteArray {
        require(mac.size == 6)
        return byteArrayOf((mac[0].toInt() xor 2).toByte(), mac[1], mac[2], 0xff.toByte(), 0xfe.toByte(), mac[3], mac[4], mac[5])
    }

    /** 64비트 NTP 시각(위 32비트 초, 아래 32비트 소수) */
    fun ntpTime(unixMillis: Long): Long { val sec = Math.floorDiv(unixMillis, 1000L) + NTP_EPOCH; val frac = (Math.floorMod(unixMillis, 1000L) * 4294967296L) / 1000L; return (sec shl 32) or frac }

    /** RFC 4193 3.2.2: SHA-1(NTP 시각 8바이트 + EUI-64 8바이트) 의 맨 아래 40비트가 전역 ID */
    fun globalId(ntp64: Long, eui: ByteArray): ByteArray {
        require(eui.size == 8)
        val input = ByteArray(16); for (i in 0 until 8) input[i] = (ntp64 ushr (56 - 8 * i)).toByte(); eui.copyInto(input, 8)
        return MessageDigest.getInstance("SHA-1").digest(input).copyOfRange(15, 20)
    }

    private fun hextet(a: Int, b: Int) = Integer.toHexString(((a and 0xff) shl 8) or (b and 0xff))

    /** fdXX:XXXX:XXXX::/48 */
    fun prefix(gid: ByteArray): String { require(gid.size == 5); return "fd" + "%02x".format(gid[0].toInt() and 0xff) + ":" + hextet(gid[1].toInt(), gid[2].toInt()) + ":" + hextet(gid[3].toInt(), gid[4].toInt()) + "::/48" }

    /** 이 /48 안의 /64 서브넷 n 번째 (0~65535) */
    fun subnet(gid: ByteArray, n: Int): String {
        require(n in 0..65535)
        val p = prefix(gid).removeSuffix("::/48")
        return if (n == 0) "$p::/64" else "$p:${Integer.toHexString(n)}::/64"
    }
}

// ---------------------------------------------------------------------------------------------
// tc (트래픽 컨트롤): netem 으로 지연·손실을 흉내 내고 tbf 로 속도를 제한

object TcCmd {
    class Netem(val delayMs: Double, val jitterMs: Double, val dist: String, val lossPct: Double, val dupPct: Double, val corruptPct: Double, val reorderPct: Double, val rateBps: Long)

    fun num(v: Double): String = if (v == Math.floor(v) && v < 1e9) "${v.toLong()}" else "%.3f".format(v).trimEnd('0').trimEnd('.')

    /** "10", "10m", "10mbit", "10Mbps", "512kbit", "1gbit" → bit/s. 읽지 못하면 null */
    fun parseRate(text: String): Long? {
        val m = Regex("^([0-9]+(?:\\.[0-9]+)?)\\s*([kmgKMG]?)(?:bit|bps)?(?:/s)?$").find(text.trim().replace(" ", "").lowercase()) ?: return null
        val n = m.groupValues[1].toDouble(); val mul = when (m.groupValues[2]) { "k" -> 1e3; "m" -> 1e6; "g" -> 1e9; else -> 1e6 }
        val v = (n * mul).toLong(); return if (v in 1000L..100_000_000_000L) v else null
    }

    /** tc 가 알아듣는 속도 글자: 12.5 → "12500kbit" 처럼 정수 kbit/mbit/gbit 로 */
    fun rateText(bps: Long): String = when { bps % 1_000_000_000L == 0L -> "${bps / 1_000_000_000L}gbit"; bps % 1_000_000L == 0L -> "${bps / 1_000_000L}mbit"; bps % 1000L == 0L -> "${bps / 1000L}kbit"; else -> "${bps}bit" }

    /** tc qdisc add ... netem ... (한 줄). 지연·손실·중복·손상·재정렬·속도를 하나의 netem 에 */
    fun netem(dev: String, n: Netem, parent: String = "root", handle: String? = null): String {
        val sb = StringBuilder("tc qdisc add dev $dev $parent")
        if (handle != null) sb.append(" handle $handle")
        sb.append(" netem")
        if (n.delayMs > 0) { sb.append(" delay ${num(n.delayMs)}ms"); if (n.jitterMs > 0) { sb.append(" ${num(n.jitterMs)}ms"); if (n.dist != "") sb.append(" distribution ${n.dist}") } }
        if (n.lossPct > 0) sb.append(" loss ${num(n.lossPct)}%")
        if (n.dupPct > 0) sb.append(" duplicate ${num(n.dupPct)}%")
        if (n.corruptPct > 0) sb.append(" corrupt ${num(n.corruptPct)}%")
        if (n.reorderPct > 0) sb.append(" reorder ${num(n.reorderPct)}% 50%")
        if (n.rateBps > 0) sb.append(" rate ${rateText(n.rateBps)}")
        return sb.toString()
    }

    /** tbf 가 정해진 속도를 내려면 버킷(burst)이 최소 rate/HZ 바이트는 있어야 해요(HZ=250 기준). 2배 여유를 두고 KB 로 올림, 최소 MTU 2개 */
    fun tbfBurstBytes(rateBps: Long, hz: Int = 250, mtu: Int = 1514): Long {
        val min = Math.ceil(rateBps / 8.0 / hz).toLong() * 2; return maxOf(min, 2L * mtu).let { (it + 1023) / 1024 * 1024 }
    }

    /** tbf 큐 길이(limit, 바이트) = 속도(바이트/초) × 대기 허용 시간 + burst */
    fun tbfLimitBytes(rateBps: Long, latencyMs: Int, burst: Long): Long = (rateBps / 8.0 * latencyMs / 1000.0).toLong() + burst

    fun tbf(dev: String, rateBps: Long, latencyMs: Int, parent: String = "root", handle: String? = null): String =
        "tc qdisc add dev $dev $parent" + (if (handle != null) " handle $handle" else "") + " tbf rate ${rateText(rateBps)} burst ${tbfBurstBytes(rateBps) / 1024}kb latency ${latencyMs}ms"
}
