package com.selfcheck.app

import kotlin.math.abs
import kotlin.math.ceil
import kotlin.math.exp
import kotlin.math.floor
import kotlin.math.ln
import kotlin.math.max
import kotlin.math.pow
import kotlin.math.sqrt

/*
 * 용량·전력·품질 계산 엔진: RAID, PoE 전력(케이블 손실 포함), UPS 가동 시간(페우케르트), VoIP 통화 품질(E-model), CGNAT 포트 블록,
 * 광링크 손실 예산, 이더넷 와이어 스피드, Erlang B/C, 95% 요금 계산. 순수 계산이라 컴퓨터에서 파이썬 기준값과 대조해 시험해요.
 */

object Raid {
    class Plan(val name: String, val minDisks: Int, val usableDisks: Int, val faultText: String, val guaranteed: Int, val writePenalty: Int, val readX: Double, val writeX: Double, val rebuildReadDisks: Int)

    val LEVELS = listOf("RAID 0 (줄 세우기)", "RAID 1 (미러)", "RAID 5", "RAID 6", "RAID 10", "RAID 50", "RAID 60", "JBOD (이어 붙이기)")

    /** n: 디스크 수, g: RAID 50·60 의 그룹 수. 조건에 안 맞으면 IllegalArgumentException(한국어 안내) */
    fun plan(level: String, n: Int, g: Int): Plan {
        fun need(ok: Boolean, msg: String) { if (!ok) throw IllegalArgumentException(msg) }
        return when (LEVELS.indexOf(level)) {
            0 -> { need(n >= 2, "RAID 0 은 디스크가 2개 이상 필요해요"); Plan(level, 2, n, "없음 (디스크 1개만 고장 나도 모든 데이터를 잃어요)", 0, 1, n.toDouble(), n.toDouble(), 0) }
            1 -> { need(n >= 2, "RAID 1 은 디스크가 2개 이상 필요해요"); Plan(level, 2, 1, "디스크 ${n - 1}개까지 고장 나도 돼요 (전부 같은 내용의 복사본)", n - 1, 2, n.toDouble(), 1.0, 1) }
            2 -> { need(n >= 3, "RAID 5 는 디스크가 3개 이상 필요해요"); Plan(level, 3, n - 1, "디스크 1개까지", 1, 4, (n - 1).toDouble(), (n - 1).toDouble(), n - 1) }
            3 -> { need(n >= 4, "RAID 6 은 디스크가 4개 이상 필요해요"); Plan(level, 4, n - 2, "디스크 2개까지", 2, 6, (n - 2).toDouble(), (n - 2).toDouble(), n - 1) }
            4 -> { need(n >= 4 && n % 2 == 0, "RAID 10 은 짝수 개(4개 이상)의 디스크가 필요해요"); Plan(level, 4, n / 2, "짝 중 한 쪽만 고장 나면 최대 ${n / 2}개까지, 같은 짝 둘이 고장 나면 데이터를 잃어요 (확실히 견디는 건 1개)", 1, 2, n.toDouble(), n / 2.0, 1) }
            5 -> { need(g >= 2, "RAID 50 은 그룹이 2개 이상 필요해요"); need(n % g == 0 && n / g >= 3, "RAID 50 은 디스크 수가 그룹 수로 나누어떨어지고 그룹마다 3개 이상이어야 해요 (지금 ${n}개 ÷ ${g}그룹)"); Plan(level, 6, n - g, "그룹마다 1개씩, 같은 그룹에서 2개가 고장 나면 데이터를 잃어요 (확실히 견디는 건 1개)", 1, 4, (n - g).toDouble(), (n - g).toDouble(), n / g - 1) }
            6 -> { need(g >= 2, "RAID 60 은 그룹이 2개 이상 필요해요"); need(n % g == 0 && n / g >= 4, "RAID 60 은 디스크 수가 그룹 수로 나누어떨어지고 그룹마다 4개 이상이어야 해요 (지금 ${n}개 ÷ ${g}그룹)"); Plan(level, 8, n - 2 * g, "그룹마다 2개씩, 같은 그룹에서 3개가 고장 나면 데이터를 잃어요 (확실히 견디는 건 2개)", 2, 6, (n - 2 * g).toDouble(), (n - 2 * g).toDouble(), n / g - 1) }
            else -> { need(n >= 1, "디스크가 1개 이상 필요해요"); Plan(level, 1, n, "없음 (고장 난 디스크의 데이터만 잃어요)", 0, 1, 1.0, 1.0, 0) }
        }
    }

    /** 복구하다가 읽기 오류(URE)를 만날 확률: 읽어야 하는 비트 수 × 비트당 오류율 의 푸아송 근사 1 − e^(−λ) */
    fun ureProbability(readBytes: Double, perBit: Double): Double = 1 - exp(-(readBytes * 8.0) * perBit)
}

object Poe {
    /** 규격별 (이름, PSE 최소 출력전압 V, 케이블 100m 루프 저항 Ω, 포트 공급 한도 W(PSE), 기기 사용 한도 W(PD)) — IEEE 802.3af/at/bt 규격값 */
    class Std(val name: String, val volts: Double, val loopOhm100m: Double, val psePort: Double, val pdMax: Double)
    val STANDARDS = listOf(Std("IEEE 802.3af (PoE, 15.4W)", 44.0, 20.0, 15.4, 12.95), Std("IEEE 802.3at (PoE+, 30W)", 50.0, 12.5, 30.0, 25.5), Std("IEEE 802.3bt Type 3 (PoE++, 60W)", 50.0, 6.25, 60.0, 51.0), Std("IEEE 802.3bt Type 4 (PoE++, 90W)", 52.5, 6.25, 90.0, 71.3))

    /** 기기가 pdW 를 쓰려면 스위치(PSE)가 내보내야 하는 전력: V·I − I²·R = pdW 를 풀어서 I 를 얻고 P = V·I. 공급할 수 없으면 null */
    fun pseWatts(pdW: Double, volts: Double, loopOhm: Double): Double? {
        if (pdW <= 0) return 0.0
        val disc = volts * volts - 4 * loopOhm * pdW
        if (disc < 0) return null
        val i = (volts - sqrt(disc)) / (2 * loopOhm)
        return volts * i
    }
    fun loopOhm(std: Std, meters: Double) = std.loopOhm100m * meters / 100.0
}

object Ups {
    /** 단순 계산: 배터리 에너지(Wh) × 방전 한도 × 노후 × 인버터 효율 ÷ 부하 → 시간 */
    fun simpleHours(batteryWh: Double, dod: Double, aging: Double, eff: Double, loadW: Double): Double = batteryWh * dod * aging * eff / loadW

    /** 페우케르트 보정: 방전 전류가 클수록 쓸 수 있는 용량이 줄어요. t = H·(C/(I·H))^k (C: H시간율 용량 Ah, I: 방전 전류 A) */
    fun peukertHours(totalVolts: Double, ah: Double, rateHours: Double, k: Double, eff: Double, loadW: Double, dod: Double, aging: Double): Double {
        val current = loadW / (totalVolts * eff)
        return rateHours * (ah * dod * aging / (current * rateHours)).pow(k)
    }
}

object Voip {
    class Codec(val name: String, val ie: Double, val bpl: Double, val delayMs: Double)
    val CODECS = listOf(Codec("G.711 (PLC 없음)", 0.0, 4.3, 20.0), Codec("G.711 (PLC 있음)", 0.0, 25.1, 20.0), Codec("G.729A", 11.0, 19.0, 35.0), Codec("G.723.1 (6.3k)", 15.0, 16.1, 67.5))

    /** 지연 손상(Id): 단순화한 E-model (Cole·Rosenbluth). d = 입에서 귀까지 한 방향 지연(ms) */
    fun delayImpairment(d: Double): Double = 0.024 * d + (if (d > 177.3) 0.11 * (d - 177.3) else 0.0)

    /** 손실 손상: Ie_eff = Ie + (95 − Ie)·Ppl / (Ppl/BurstR + Bpl) (Ppl: 손실 %) */
    fun effectiveIe(ie: Double, bpl: Double, lossPct: Double, burstR: Double): Double = if (lossPct <= 0) ie else ie + (95 - ie) * lossPct / (lossPct / burstR + bpl)

    fun rFactor(d: Double, ieEff: Double): Double = 93.2 - delayImpairment(d) - ieEff

    /** R → MOS (ITU-T G.107 부록): 1 + 0.035R + R(R−60)(100−R)·7e-6 */
    fun mos(r: Double): Double = when { r < 0 -> 1.0; r > 100 -> 4.5; else -> 1 + 0.035 * r + r * (r - 60) * (100 - r) * 7e-6 }

    fun category(r: Double) = when { r >= 90 -> "매우 만족 (모두 만족)"; r >= 80 -> "만족"; r >= 70 -> "일부 사용자가 불만"; r >= 60 -> "많은 사용자가 불만"; r >= 50 -> "거의 모든 사용자가 불만"; else -> "통화로 쓰기 어려움" }
}

object Cgnat {
    /** 공인 주소 하나에서 가입자 하나에 주는 포트 묶음(블록)을 몇 명에게 줄 수 있나 */
    fun subsPerIp(portStart: Int, portEnd: Int, block: Int): Int = ((portEnd - portStart + 1) / block)

    class Mapping(val outsideIndex: Long, val slot: Int, val first: Int, val last: Int)

    /** 결정적(deterministic) NAT 방식(RFC 7422): 안쪽 주소의 순번 i → 공인 주소 순번과 포트 범위. 기록(로그) 없이도 계산으로 가입자를 찾을 수 있어요 */
    fun map(insideIndex: Long, subsPerIp: Int, portStart: Int, block: Int): Mapping {
        val out = insideIndex / subsPerIp; val slot = (insideIndex % subsPerIp).toInt()
        val first = portStart + slot * block
        return Mapping(out, slot, first, first + block - 1)
    }
}

object Fiber {
    class Type(val name: String, val dbPerKm: Double)
    val TYPES = listOf(Type("단일모드 1310nm (OS2)", 0.35), Type("단일모드 1550nm (OS2)", 0.22), Type("멀티모드 850nm (OM3·OM4)", 3.0), Type("멀티모드 1300nm (OM3·OM4)", 1.0), Type("멀티모드 850nm (OM1·OM2)", 3.5), Type("직접 입력 (dB/km)", 0.0))

    class Result(val fiberLoss: Double, val connLoss: Double, val spliceLoss: Double, val totalLoss: Double, val rxDbm: Double, val marginDb: Double, val marginAfterSafety: Double, val maxKm: Double?)

    fun budget(txDbm: Double, sensDbm: Double, dbPerKm: Double, km: Double, connectors: Int, connDb: Double, splices: Int, spliceDb: Double, safetyDb: Double): Result {
        val fl = dbPerKm * km; val cl = connectors * connDb; val sl = splices * spliceDb; val total = fl + cl + sl; val rx = txDbm - total; val margin = rx - sensDbm
        val maxKm = if (dbPerKm > 0) (txDbm - sensDbm - safetyDb - cl - sl) / dbPerKm else null
        return Result(fl, cl, sl, total, rx, margin, margin - safetyDb, maxKm)
    }
}

object WireSpeed {
    const val OVERHEAD = 20      // 프리앰블 7 + SFD 1 + 프레임 간 간격(IFG) 12 바이트

    /** 한 초에 보낼 수 있는 프레임 수: 속도 ÷ ((프레임 + 20)·8). frame 은 FCS 까지 포함한 이더넷 프레임 크기 */
    fun pps(bitsPerSec: Double, frameBytes: Int): Double = bitsPerSec / ((frameBytes + OVERHEAD) * 8.0)
}

object Erlang {
    /** 막힌 호 비율(Erlang B): 회선 n 개, 부하 a 얼랑. 안정적인 점화식 B(k) = a·B(k−1) / (k + a·B(k−1)) */
    fun b(n: Int, a: Double): Double { var inv = 1.0; for (k in 1..n) inv = 1 + inv * k / a; return 1 / inv }

    /** 기다릴 확률(Erlang C): 상담원 n 명, 부하 a 얼랑 (n > a) */
    fun c(n: Int, a: Double): Double { if (n <= a) return 1.0; val bb = b(n, a); return bb / (1 - a / n * (1 - bb)) }

    /** 서비스 수준: t 초 안에 연결될 비율, aht: 평균 통화 시간(초) */
    fun serviceLevel(n: Int, a: Double, ahtSec: Double, tSec: Double): Double = if (n <= a) 0.0 else 1 - c(n, a) * exp(-(n - a) * tSec / ahtSec)

    /** 평균 대기 시간(ASA): 전체 호 기준 */
    fun avgWait(n: Int, a: Double, ahtSec: Double): Double = if (n <= a) Double.POSITIVE_INFINITY else c(n, a) * ahtSec / (n - a)

    fun linesFor(a: Double, maxBlocking: Double, limit: Int = 100_000): Int { var n = max(1, ceil(a).toInt() - 1); while (n < limit && b(n, a) > maxBlocking) n++; while (n > 1 && b(n - 1, a) <= maxBlocking) n--; return n }
    fun agentsFor(a: Double, ahtSec: Double, tSec: Double, targetSl: Double, limit: Int = 100_000): Int { var n = floor(a).toInt() + 1; while (n < limit && serviceLevel(n, a, ahtSec, tSec) < targetSl) n++; return n }
}

object Pctl {
    /** 95% 요금 방식(가장 가까운 순위): 작은 값부터 늘어놓고 ceil(n·p) 번째 값. 위쪽 (1−p) 만큼은 버려요 */
    fun nearestRank(samples: List<Double>, p: Double): Double { val s = samples.sorted(); val k = ceil(s.size * p / 100.0 - 1e-9).toInt().coerceIn(1, s.size); return s[k - 1] }
    fun rank(n: Int, p: Double): Int = ceil(n * p / 100.0 - 1e-9).toInt().coerceIn(1, n)
}
