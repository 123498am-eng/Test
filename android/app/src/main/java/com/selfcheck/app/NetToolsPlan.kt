package com.selfcheck.app

import java.time.Instant
import java.time.LocalDateTime
import java.time.ZoneOffset
import kotlin.math.abs
import kotlin.math.ceil
import kotlin.math.floor
import kotlin.math.max
import kotlin.math.min
import kotlin.math.pow

/**
 * 용량·전력·품질 계산 도구 10가지: RAID, PoE 전력 예산, UPS 가동 시간, NTP 시계 오차, VoIP 통화 품질, CGNAT 포트 계획,
 * 광링크 손실 예산, 이더넷 와이어 스피드, Erlang B/C, 95% 요금. 입력하면 바로 계산하고 어디로도 보내지 않아요.
 */
object PlanTools {
    private const val G = NetGroups.PLAN

    private fun d(v: Double, digits: Int = 2) = "%.${digits}f".format(v)
    private fun n(v: Long) = "%,d".format(v)
    private fun num(i: ToolInput, k: String): Double? = i.double(k)?.takeIf { !it.isNaN() && !it.isInfinite() }

    /** 줄마다 "이름, 값, 개수" (쉼표 또는 공백) */
    private fun parseDevices(text: String): List<Triple<String, Double, Int>>? {
        val out = ArrayList<Triple<String, Double, Int>>()
        for (line in text.lines().map { it.trim() }.filter { it.isNotEmpty() }) {
            val parts = if (line.contains(',') || line.contains(';') || line.contains('\t')) line.split(',', ';', '\t').map { it.trim() }.filter { it.isNotEmpty() } else {
                val w = line.split(Regex("\\s+")); if (w.size >= 3 && w[w.size - 1].toIntOrNull() != null && w[w.size - 2].removeSuffix("W").removeSuffix("w").toDoubleOrNull() != null) listOf(w.dropLast(2).joinToString(" "), w[w.size - 2], w.last()) else if (w.size >= 2) listOf(w.dropLast(1).joinToString(" "), w.last()) else return null }
            if (parts.size < 2) return null
            val watts = parts[1].removeSuffix("W").removeSuffix("w").trim().toDoubleOrNull() ?: return null
            val count = if (parts.size >= 3) parts[2].removePrefix("x").removePrefix("×").trim().toIntOrNull() ?: return null else 1
            if (watts <= 0 || count <= 0 || count > 10000) return null
            out += Triple(parts[0], watts, count)
        }
        return out
    }

    private fun parseTime(s: String): Double? {
        val t = s.trim(); if (t.isEmpty()) return null
        t.toDoubleOrNull()?.let { return it }
        try { return Instant.parse(t).let { it.epochSecond + it.nano / 1e9 } } catch (_: Exception) {}
        for (p in listOf("yyyy-MM-dd HH:mm:ss.SSS", "yyyy-MM-dd HH:mm:ss", "yyyy-MM-dd'T'HH:mm:ss.SSS", "yyyy-MM-dd'T'HH:mm:ss")) try { return LocalDateTime.parse(t, java.time.format.DateTimeFormatter.ofPattern(p)).toInstant(ZoneOffset.UTC).let { it.epochSecond + it.nano / 1e9 } } catch (_: Exception) {}
        return null
    }

    private val UNITS = listOf("TB", "GB")
    private val URE = listOf("1 / 10^14 (일반 하드디스크)", "1 / 10^15 (고급 하드디스크)", "1 / 10^16 (SSD·엔터프라이즈)")
    private val UPS_CHEM = listOf("납축전지 (VRLA)", "리튬인산철 (LiFePO4)")
    private val SPEEDS = listOf("10 Mbps", "100 Mbps", "1 Gbps", "2.5 Gbps", "5 Gbps", "10 Gbps", "25 Gbps", "40 Gbps", "100 Gbps", "400 Gbps")
    private val SPEED_BPS = listOf(10e6, 100e6, 1e9, 2.5e9, 5e9, 10e9, 25e9, 40e9, 100e9, 400e9)
    private val VLAN = listOf("없음", "VLAN 태그(4바이트) 있음")
    private val ERLANG = listOf("Erlang B — 필요한 통화로(회선) 수", "Erlang B — 회선 수에 따른 통화 실패율", "Erlang C — 필요한 상담원 수", "Erlang C — 상담원 수에 따른 대기·서비스 수준")
    private val PCTL = listOf("95", "90", "99", "99.9")
    private val PCT_UNIT = listOf("Mbps", "kbps", "Gbps")

    val ALL: List<NetTool> = listOf(
        // 1
        calc("calc_raid", G, "RAID 용량·내결함성·복구 위험 계산", "RAID 0·1·5·6·10·50·60·JBOD 의 쓸 수 있는 용량·효율·견디는 고장 수·읽기/쓰기 배수·쓰기 페널티와, 디스크 하나를 복구할 때 걸리는 시간·복구 중 읽기 오류(URE)를 만날 확률을 계산해요",
            choice("lv", "RAID 종류", Raid.LEVELS, "RAID 5"), text("n", "디스크 개수", "", "4"), text("size", "디스크 하나의 크기", "", "8"), choice("unit", "단위", UNITS), text("g", "그룹 수 (RAID 50·60)", "", "2"), text("rb", "복구 속도 (MB/s)", "고장 난 디스크를 다시 채우는 속도", "100"), choice("ure", "읽기 오류율(URE)", URE)) { i ->
            val nDisks = i.int("n") ?: return@calc fail("디스크 개수를 숫자로 적어 주세요"); val size = num(i, "size")?.takeIf { it > 0 } ?: return@calc fail("디스크 크기를 0 보다 큰 숫자로 적어 주세요")
            val g = i.int("g") ?: 2; val rb = num(i, "rb")?.takeIf { it > 0 } ?: return@calc fail("복구 속도(MB/s)를 0 보다 큰 숫자로 적어 주세요"); if (nDisks > 1000) return@calc fail("디스크는 1000개까지 계산해요")
            val plan = try { Raid.plan(i.str("lv"), nDisks, g) } catch (e: IllegalArgumentException) { return@calc fail(e.message ?: "조건이 맞지 않아요") }
            val diskBytes = size * if (i.choice("unit", UNITS) == 0) 1e12 else 1e9; val raw = nDisks * diskBytes; val usable = plan.usableDisks * diskBytes
            fun tb(b: Double): String { return if (b >= 1e12) "${d(b / 1e12)} TB" else "${d(b / 1e9)} GB" }
            val tib = usable / 2.0.pow(40)
            val p = listOf(1e-14, 1e-15, 1e-16)[i.choice("ure", URE)]; val rebuildH = diskBytes / (rb * 1e6) / 3600
            result {
                kv("전체 용량(디스크 합계)", tb(raw)); kv("쓸 수 있는 용량", "${tb(usable)}  (≈ ${d(tib)} TiB)"); kv("효율", "${d(usable / raw * 100, 1)}%"); kv("견디는 디스크 고장", plan.faultText); kv("최소 디스크 수", "${plan.minDisks}개")
                kv("순차 읽기 속도", "디스크 1개의 약 ${d(plan.readX, 1)}배"); kv("순차 쓰기 속도", "디스크 1개의 약 ${d(plan.writeX, 1)}배"); kv("임의 쓰기 비용", "쓰기 1번이 디스크 입출력 ${plan.writePenalty}번 (쓰기 페널티)")
                if (plan.rebuildReadDisks > 0) {
                    val prob = Raid.ureProbability(plan.rebuildReadDisks * diskBytes, p); val protectedAgainst = Raid.LEVELS.indexOf(i.str("lv")) in listOf(3, 6)
                    head("디스크 1개가 고장 나서 복구할 때"); kv("복구 시간", "${d(rebuildH, 1)}시간 (디스크 ${tb(diskBytes)} ÷ ${d(rb, 0)} MB/s, 쉬지 않고 쓸 때 기준 — 실제로는 서비스와 겹쳐 더 걸려요)")
                    kv("읽어야 하는 양", tb(plan.rebuildReadDisks * diskBytes)); kv("복구 중 읽기 오류를 만날 확률", "${d(prob * 100, 2)}%", level = if (protectedAgainst) 0 else if (prob >= 0.2) 2 else if (prob >= 0.05) 1 else 0)
                    if (protectedAgainst) note("RAID 6·60 은 복구 중에 읽기 오류가 한 번 나도 두 번째 패리티로 복구돼서 데이터를 잃지 않아요.", -1)
                    else if (Raid.LEVELS.indexOf(i.str("lv")) in listOf(2, 5)) note(if (prob >= 0.05) "복구하다가 오류를 만나면 그 데이터를 잃거나 복구가 멈출 수 있어요. 디스크가 크고 많을수록 위험해서, 큰 디스크에는 RAID 6 이나 RAID 10 을 권해요." else "복구 중 읽기 오류 위험이 낮은 편이에요. 그래도 복구하는 동안은 한 번 더 고장 나면 끝이라 백업이 꼭 필요해요.", if (prob >= 0.05) 1 else 0)
                    if (rebuildH > 24) note("복구에 하루 넘게 걸려요. 그동안 두 번째 고장이 날 위험이 커져요(같은 시기에 산 디스크는 비슷하게 늙어요).", 1)
                }
                note("RAID 는 \"디스크 고장\"을 견디는 장치지 백업이 아니에요. 실수로 지운 파일·랜섬웨어·화재·컨트롤러 고장은 막지 못해요.", 1)
                note("읽기·쓰기 배수는 이론적인 대략값이에요(컨트롤러·캐시·파일 크기에 따라 달라요). 쓰기 페널티는 RAID 5·6 이 작은 쓰기를 할 때 \"읽고-계산하고-쓰는\" 과정이 더 필요해서 생겨요.", 0)
                if (Raid.LEVELS.indexOf(i.str("lv")) == 0) note("RAID 0 은 속도만 빨라지고 디스크 하나만 고장 나도 전부 잃어요. 중요한 데이터에는 쓰지 마세요.", 2)
            }
        },
        // 2
        calc("calc_poe", G, "PoE 전력 예산 계산 (케이블 손실 포함)", "연결할 PoE 기기(AP·카메라·전화)의 전력 합계를 구하고, 케이블 길이에 따른 전력 손실을 더해서 스위치의 PoE 예산으로 충분한지 계산해요. IEEE 802.3af/at/bt 규격값을 써요",
            choice("std", "PoE 규격", Poe.STANDARDS.map { it.name }, Poe.STANDARDS[1].name), text("budget", "스위치 PoE 총 예산 (W)", "스위치 사양서의 \"PoE budget\"", "120"), text("len", "케이블 길이 (m)", "가장 먼 기기 기준. 규격 최대는 100m", "100"),
            multi("dev", "연결할 기기 (줄마다 이름, 전력(W), 개수)", "기기가 실제로 쓰는 전력(PD). 예: AP, 12.5, 3", "AP, 12.5, 3\n카메라, 7, 4\nIP 전화, 3.5, 6")) { i ->
            val std = Poe.STANDARDS.firstOrNull { it.name == i.str("std") } ?: Poe.STANDARDS[1]
            val budget = num(i, "budget")?.takeIf { it > 0 } ?: return@calc fail("스위치 PoE 예산(W)을 0 보다 큰 숫자로 적어 주세요"); val len = num(i, "len")?.takeIf { it in 1.0..300.0 } ?: return@calc fail("케이블 길이는 1~300m 사이의 숫자로 적어 주세요")
            val devs = parseDevices(i.raw("dev")) ?: return@calc fail("기기는 줄마다 \"이름, 전력(W), 개수\" 형식으로 적어 주세요 (예: AP, 12.5, 3)"); if (devs.isEmpty()) return@calc need("연결할 기기를 한 줄 이상 적어 주세요")
            val r = Poe.loopOhm(std, len); var pdTotal = 0.0; var pseTotal = 0.0; var ports = 0; var bad = false
            result {
                kv("규격", "${std.name} · 포트당 최대 ${d(std.psePort, 1)}W 공급 / 기기 사용 ${d(std.pdMax, 2)}W"); kv("케이블 루프 저항", "${d(r, 2)} Ω (${d(len, 0)}m)")
                head("기기별 전력"); header("기기", "기기 사용(W)", "스위치 공급(W)", "개수", "합계(W)")
                for ((name, w, cnt) in devs) {
                    val pse = Poe.pseWatts(w, std.volts, r)
                    if (w > std.pdMax + 1e-9 || pse == null || pse > std.psePort + 1e-9) { row(name, d(w, 1), "공급 불가", "$cnt", "-", level = 2); bad = true; continue }
                    pdTotal += w * cnt; pseTotal += pse * cnt; ports += cnt; row(name, d(w, 2), d(pse, 2), "$cnt", d(pse * cnt, 1))
                }
                head("합계"); kv("연결 포트 수", "${ports}개"); kv("기기가 쓰는 전력 합계", "${d(pdTotal, 1)} W"); kv("케이블 손실", "${d(pseTotal - pdTotal, 1)} W (${d(if (pseTotal > 0) (pseTotal - pdTotal) / pseTotal * 100 else 0.0, 1)}%)"); kv("스위치가 내보내야 하는 전력", "${d(pseTotal, 1)} W")
                kv("스위치 PoE 예산", "${d(budget, 1)} W"); kv("남는 예산", "${d(budget - pseTotal, 1)} W", level = if (budget - pseTotal < 0) 2 else if ((budget - pseTotal) / budget < 0.2) 1 else -1); kv("예산 사용률", "${d(pseTotal / budget * 100, 1)}%", level = if (pseTotal > budget) 2 else if (pseTotal / budget > 0.8) 1 else 0)
                if (bad) note("이 규격으로 공급할 수 없는 기기가 있어요(규격의 기기 사용 한도 ${d(std.pdMax, 2)}W 초과, 또는 케이블 손실을 합치면 포트 한도 ${d(std.psePort, 1)}W 초과). 더 높은 규격이나 더 짧은 케이블을 쓰세요.", 2)
                if (pseTotal > budget) note("예산이 모자라요. 스위치는 예산을 넘으면 우선순위가 낮은 포트의 전원을 끊어요. 예산이 큰 스위치나 PoE 인젝터를 추가하세요.", 2)
                else if (!bad && pseTotal / budget > 0.8) note("예산의 80%를 넘었어요. 기기를 늘릴 계획이라면 여유가 필요해요.", 1)
                note("PoE 예산은 스위치 전체에서 나눠 쓰는 합계예요. 포트마다 규격 한도까지 줄 수 있어도 모두를 한꺼번에 최대로 줄 수는 없어요. 기기의 \"최대 전력\"이 아니라 실제로 쓰는 전력(카메라는 적외선 LED 가 켜지는 밤)으로 계산하세요.", 0)
                note("계산: 스위치 출력전압 V(규격의 최저값 ${d(std.volts, 1)}V)에서 기기가 P 를 쓰려면 전류 I 는 V·I − I²·R = P 를 풀어 얻고, 스위치는 V·I 를 내보내요(I²·R 이 케이블에서 열로 사라져요).", 0)
            }
        },
        // 3
        calc("calc_ups", G, "UPS 가동 시간 계산 (페우케르트 보정)", "UPS(무정전 전원장치)가 정전 때 부하를 몇 분 버티는지 배터리 용량·인버터 효율·방전 한도로 계산하고, 큰 부하에서 배터리 용량이 줄어드는 페우케르트 효과를 반영한 값도 알려 줘요. 부하율 과부하도 확인해요",
            text("va", "UPS 용량 (VA)", "", "1500"), text("pf", "UPS 역률", "라인인터랙티브는 보통 0.6, 온라인은 0.9~1", "0.6"), text("load", "부하 합계 (W)", "연결한 기기가 실제로 쓰는 전력", "300"), text("bv", "배터리 1개 전압 (V)", "", "12"), text("bah", "배터리 1개 용량 (Ah)", "", "9"), text("bs", "직렬로 이은 개수", "전압을 올리는 연결", "2"), text("bp", "병렬로 이은 줄 수", "용량을 늘리는 연결", "1"),
            choice("chem", "배터리 종류", UPS_CHEM), text("eff", "인버터 효율 (%)", "", "90"), text("dod", "방전 한도 (%)", "배터리를 이만큼까지만 씀. 납축전지는 보통 80%", "80"), text("age", "배터리 남은 성능 (%)", "새것 100, 2~3년 쓴 납축전지는 70~80", "100")) { i ->
            val va = num(i, "va")?.takeIf { it > 0 } ?: return@calc fail("UPS 용량(VA)을 숫자로 적어 주세요"); val pf = num(i, "pf")?.takeIf { it in 0.1..1.0 } ?: return@calc fail("역률은 0.1~1 사이의 숫자예요"); val load = num(i, "load")?.takeIf { it > 0 } ?: return@calc fail("부하(W)를 0 보다 큰 숫자로 적어 주세요")
            val bv = num(i, "bv")?.takeIf { it > 0 } ?: return@calc fail("배터리 전압(V)을 적어 주세요"); val bah = num(i, "bah")?.takeIf { it > 0 } ?: return@calc fail("배터리 용량(Ah)을 적어 주세요"); val bs = i.int("bs")?.takeIf { it in 1..100 } ?: return@calc fail("직렬 개수는 1~100 이에요"); val bp = i.int("bp")?.takeIf { it in 1..100 } ?: return@calc fail("병렬 줄 수는 1~100 이에요")
            val eff = num(i, "eff")?.takeIf { it in 30.0..100.0 } ?: return@calc fail("인버터 효율은 30~100% 예요"); val dod = num(i, "dod")?.takeIf { it in 10.0..100.0 } ?: return@calc fail("방전 한도는 10~100% 예요"); val age = num(i, "age")?.takeIf { it in 10.0..100.0 } ?: return@calc fail("남은 성능은 10~100% 예요")
            val lithium = i.choice("chem", UPS_CHEM) == 1; val k = if (lithium) 1.05 else 1.2; val totalV = bv * bs; val totalAh = bah * bp; val wh = totalV * totalAh; val capW = va * pf
            val simple = Ups.simpleHours(wh, dod / 100, age / 100, eff / 100, load); val peukert = Ups.peukertHours(totalV, totalAh, 20.0, k, eff / 100, load, dod / 100, age / 100)
            fun mins(h: Double) = if (h * 60 >= 120) "${d(h, 1)}시간" else "${d(h * 60, 1)}분"
            result {
                kv("UPS 출력 한도", "${d(capW, 0)} W  (${d(va, 0)}VA × 역률 ${d(pf, 2)})"); kv("부하율", "${d(load / capW * 100, 1)}%", level = if (load > capW) 2 else if (load / capW > 0.8) 1 else 0)
                kv("배터리 구성", "${d(bv, 0)}V ${d(bah, 1)}Ah × 직렬 $bs × 병렬 $bp = ${d(totalV, 0)}V ${d(totalAh, 1)}Ah"); kv("배터리 에너지", "${d(wh, 0)} Wh")
                kv("가동 시간 (단순 계산)", mins(simple)); kv("가동 시간 (페우케르트 보정)", mins(peukert), level = if (peukert * 60 < 5) 1 else 0); kv("부하 전류 (배터리 쪽)", "${d(load / (totalV * eff / 100), 1)} A")
                if (load > capW) note("부하가 UPS 의 출력 한도(${d(capW, 0)}W)를 넘어요. 과부하로 꺼지거나 우회(bypass)로 바뀌어 정전을 못 막아요.", 2) else if (load / capW > 0.8) note("부하가 UPS 한도의 80%를 넘어요. 여유가 없으면 배터리도 빨리 소모돼요.", 1)
                note("단순 계산 = 배터리 에너지 × 방전 한도 × 남은 성능 × 인버터 효율 ÷ 부하. 페우케르트 보정은 ${d(k, 2)}(${if (lithium) "리튬" else "납축전지"} 대표값)승으로 큰 전류일수록 쓸 수 있는 용량이 줄어드는 걸 반영해요. 실제 시간은 두 값 사이이거나 더 짧을 수 있고, 제조사 방전 곡선표가 가장 정확해요.", 0)
                if (!lithium && age >= 100) note("납축전지는 2~4년이면 용량이 크게 줄어요. 오래된 UPS 는 \"남은 성능\"을 낮춰서 계산해 보세요.", 0)
                note("UPS 는 정전 때 \"안전하게 끌 시간\"을 버는 용도로 쓰는 게 좋아요(서버라면 자동 종료 설정).", 0)
            }
        },
        // 4
        calc("calc_ntp_offset", G, "NTP 시계 오차·왕복 지연 계산 (T1~T4)", "NTP 가 주고받는 네 시각(내가 보낸 T1, 서버가 받은 T2, 서버가 보낸 T3, 내가 받은 T4)으로 내 시계가 서버보다 얼마나 틀렸는지(오차 θ)와 왕복 지연(δ)을 계산해요",
            text("t1", "T1 내가 요청을 보낸 시각", "UTC 시각(2024-03-01T09:30:00.000Z) 또는 UNIX 초", "2024-03-01T09:30:00.000Z"), text("t2", "T2 서버가 요청을 받은 시각", "", "2024-03-01T09:30:00.060Z"), text("t3", "T3 서버가 응답을 보낸 시각", "", "2024-03-01T09:30:00.061Z"), text("t4", "T4 내가 응답을 받은 시각", "", "2024-03-01T09:30:00.021Z")) { i ->
            val ts = listOf("t1", "t2", "t3", "t4").map { parseTime(i.str(it)) ?: return@calc fail("${it.uppercase()} 를 읽지 못했어요. 2024-03-01T09:30:00.123Z 같은 UTC 시각이나 UNIX 초 숫자로 적어 주세요") }
            val (t1, t2, t3, t4) = ts; val (off, delay) = NtpDecode.offsetDelay(t1, t2, t3, t4); val ms = off * 1000; val absMs = abs(ms)
            result {
                kv("시계 오차(θ)", "%+.3f ms".format(ms), level = if (absMs > 128) 2 else if (absMs > 25) 1 else -1); kv("왕복 지연(δ)", "%.3f ms".format(delay * 1000), level = if (delay < 0) 2 else 0); kv("서버 처리 시간(T3−T2)", "%.3f ms".format((t3 - t2) * 1000)); kv("오차의 불확실성", "± %.3f ms".format(delay * 500))
                note(if (ms > 0) "내 시계가 서버보다 ${d(ms, 3)}ms 느려요. 내 시계에 ${d(ms, 3)}ms 를 더해야 맞아요." else if (ms < 0) "내 시계가 서버보다 ${d(-ms, 3)}ms 빨라요. 내 시계에서 ${d(-ms, 3)}ms 를 빼야 맞아요." else "내 시계가 서버와 정확히 같아요.", 0)
                if (delay < 0) note("왕복 지연이 음수예요. T1~T4 를 잘못 넣었거나 서로 다른 요청의 값이에요. (T1 < T4, T2 ≤ T3 이어야 해요)", 2)
                if (t4 < t1) note("T4 가 T1 보다 이전이에요. 순서를 확인하세요.", 2)
                if (absMs >= 1000) note("오차가 1초 이상이에요. chrony(makestep)·ntpd 는 이 정도면 시계를 한 번에 맞춰요(점프). 서버·클라이언트 설정과 시간대를 확인하세요.", 2)
                else if (absMs >= 128) note("오차가 128ms 이상이에요. ntpd 는 이 정도면 서서히 맞추지 않고 시계를 바로 고쳐요(step).", 1)
                else if (absMs < 1) note("오차가 1ms 미만이에요. 아주 잘 맞아요.", -1) else note("오차 ${d(absMs, 1)}ms 는 보통 업무용으로 충분해요. 금융 거래·로그 정밀 비교는 1ms 이하를 목표로 해요.", 0)
                note("θ = ((T2−T1)+(T3−T4))/2,  δ = (T4−T1)−(T3−T2).  가는 길과 오는 길의 지연이 같다고 가정한 값이라, 두 길이 다르면 최대 δ/2 만큼 틀릴 수 있어요.", 0)
            }
        },
        // 5
        calc("calc_mos", G, "VoIP 통화 품질 계산 (R값·MOS, E-model)", "지연·지터·패킷 손실·코덱으로 인터넷 전화 통화 품질을 E-model(ITU-T G.107 단순화)로 계산해요: R값과 MOS(1~4.5점), 사용자 만족도를 알려 줘요",
            choice("codec", "코덱", Voip.CODECS.map { it.name } + "직접 입력 (Ie·Bpl)"), text("net", "네트워크 지연 (한 방향, ms)", "핑(왕복)의 절반 정도", "60"), text("jit", "지터 버퍼 (ms)", "단말의 지터 버퍼 크기. 보통 20~60", "40"), text("cd", "코덱·패킷화 지연 (ms)", "비우면 코덱 기본값 (G.711 20ms, G.729A 35ms …)"), text("loss", "패킷 손실 (%)", "", "1"), text("burst", "손실 집중도 BurstR", "1 = 무작위 손실, 클수록 몰려서 손실", "1"),
            text("ie", "직접 입력: 코덱 손상 Ie", "G.711 은 0, 높을수록 압축 손상이 큼", "0"), text("bpl", "직접 입력: 손실 내성 Bpl", "클수록 손실에 강함", "10")) { i ->
            val codecs = Voip.CODECS.map { it.name }; val idx = codecs.indexOf(i.str("codec")).let { if (it < 0 && i.str("codec").startsWith("직접")) codecs.size else if (it < 0) 0 else it }
            val net = num(i, "net")?.takeIf { it in 0.0..5000.0 } ?: return@calc fail("네트워크 지연은 0~5000ms 숫자예요"); val jit = num(i, "jit")?.takeIf { it in 0.0..2000.0 } ?: return@calc fail("지터 버퍼는 0~2000ms 숫자예요")
            val loss = num(i, "loss")?.takeIf { it in 0.0..100.0 } ?: return@calc fail("패킷 손실은 0~100% 숫자예요"); val burst = num(i, "burst")?.takeIf { it >= 1.0 && it <= 100.0 } ?: return@calc fail("BurstR 은 1 이상의 숫자예요 (1 = 무작위 손실)")
            val ie: Double; val bpl: Double; val cdDefault: Double; val cname: String
            if (idx < codecs.size) { val c = Voip.CODECS[idx]; ie = c.ie; bpl = c.bpl; cdDefault = c.delayMs; cname = c.name } else { ie = num(i, "ie")?.takeIf { it in 0.0..95.0 } ?: return@calc fail("Ie 는 0~95 숫자예요"); bpl = num(i, "bpl")?.takeIf { it > 0 } ?: return@calc fail("Bpl 은 0 보다 큰 숫자예요"); cdDefault = 20.0; cname = "직접 입력" }
            val cd = if (i.str("cd").isEmpty()) cdDefault else num(i, "cd")?.takeIf { it in 0.0..1000.0 } ?: return@calc fail("코덱 지연은 0~1000ms 숫자예요")
            val dTotal = net + jit + cd; val id = Voip.delayImpairment(dTotal); val ieEff = Voip.effectiveIe(ie, bpl, loss, burst); val r = Voip.rFactor(dTotal, ieEff); val m = Voip.mos(r)
            result {
                kv("코덱", "$cname (Ie ${d(ie, 1)}, Bpl ${d(bpl, 1)})"); kv("입에서 귀까지 지연", "${d(dTotal, 1)} ms  (네트워크 ${d(net, 0)} + 지터 버퍼 ${d(jit, 0)} + 코덱 ${d(cd, 1)})", level = if (dTotal > 400) 2 else if (dTotal > 150) 1 else 0)
                kv("지연 손상 Id", d(id, 2)); kv("손실·코덱 손상 Ie_eff", d(ieEff, 2)); kv("R값", d(r, 1), level = if (r < 60) 2 else if (r < 80) 1 else -1); kv("MOS (1~4.5)", d(m, 2), level = if (m < 3.1) 2 else if (m < 3.6) 1 else -1); kv("사용자 만족도", Voip.category(r))
                note("R = 93.2 − Id − Ie_eff,  Id = 0.024·d + 0.11·(d−177.3)(d>177.3),  Ie_eff = Ie + (95−Ie)·Ppl/(Ppl/BurstR + Bpl),  MOS = 1 + 0.035R + R(R−60)(100−R)·7·10⁻⁶. (에코·소음·장비 손상 등은 기본값으로 둔 단순화 모델이에요.)", 0)
                note(when { dTotal > 400 -> "지연이 400ms 를 넘어요. ITU-T G.114 는 400ms 초과를 어떤 경우에도 권하지 않아요."; dTotal > 150 -> "지연이 150ms 를 넘었어요. G.114 권고는 150ms 이하이고, 넘으면 대화가 어색해지기 시작해요."; else -> "지연은 G.114 권고(150ms 이하) 안이에요." }, if (dTotal > 400) 2 else if (dTotal > 150) 1 else -1)
                if (loss >= 1 && ieEff - ie > 10) note("패킷 손실이 품질을 크게 깎고 있어요(손상 ${d(ieEff - ie, 1)}점). 손실 은닉(PLC)을 지원하는 코덱이나 우선순위(QoS)·유선 연결을 검토하세요.", 1)
                if (m >= 4.0) note("MOS 4.0 이상이면 일반 전화처럼 자연스러운 품질이에요.", -1)
            }
        },
        // 6
        calc("calc_cgnat_ports", G, "CGNAT 포트 블록 계획 (공인 IP 하나에 몇 명?)", "통신사 공용 NAT(CGNAT)에서 가입자 한 명에게 줄 포트 묶음의 크기에 따라 공인 IP 한 개가 몇 명을 수용하는지, 가입자 수에 필요한 공인 IP 수를 계산하고, 결정적(deterministic) NAT 방식에서 안쪽 주소가 어느 공인 IP·포트 범위를 쓰는지 찾아 줘요",
            text("pub", "공인 주소 (CIDR 또는 개수)", "예: 203.0.113.0/24 또는 256", "203.0.113.0/24"), text("block", "가입자 한 명당 포트 수", "", "1024"), text("p0", "쓸 포트 범위 시작", "1~1023 은 보통 제외", "1024"), text("p1", "쓸 포트 범위 끝", "", "65535"), text("subs", "가입자 수 (선택)", "필요한 공인 주소 수를 계산해요", "10000"),
            text("inside", "안쪽 주소 대역 (선택)", "예: 100.64.0.0/20 (CGNAT 대역)", "100.64.0.0/20"), text("who", "찾을 안쪽 주소 (선택)", "그 가입자가 쓰는 공인 IP·포트 범위를 알려 줘요", "100.64.1.77")) { i ->
            val block = i.int("block")?.takeIf { it in 1..65535 } ?: return@calc fail("가입자당 포트 수는 1~65535 예요"); val p0 = i.int("p0")?.takeIf { it in 1..65535 } ?: return@calc fail("포트 시작은 1~65535 예요"); val p1 = i.int("p1")?.takeIf { it in 1..65535 } ?: return@calc fail("포트 끝은 1~65535 예요")
            if (p1 < p0) return@calc fail("포트 끝이 시작보다 작아요"); if (p1 - p0 + 1 < block) return@calc fail("쓸 수 있는 포트(${p1 - p0 + 1}개)가 가입자당 포트 수보다 적어요")
            val pubText = i.str("pub"); val pubSubnet = Subnet.parse(pubText); val pubCount: Long = if (pubSubnet != null) 1L shl (32 - pubSubnet.prefix) else pubText.toLongOrNull()?.takeIf { it in 1..4_294_967_296L } ?: return@calc fail("공인 주소는 203.0.113.0/28 같은 CIDR 이나 개수(숫자)로 적어 주세요")
            val usable = p1 - p0 + 1; val per = Cgnat.subsPerIp(p0, p1, block); val capacity = pubCount * per; val subs = i.str("subs").let { if (it.isEmpty()) null else it.replace(",", "").toLongOrNull()?.takeIf { v -> v > 0 } ?: return@calc fail("가입자 수는 양의 정수로 적어 주세요") }
            result {
                kv("공인 주소 수", "${n(pubCount)}개"); kv("쓸 수 있는 포트", "${n(usable.toLong())}개 ($p0~$p1)"); kv("공인 IP 1개당 가입자 수", "${n(per.toLong())}명 (포트 ${usable} ÷ 가입자당 $block, 내림)"); kv("수용 가능한 가입자 수", "${n(capacity)}명")
                val leftover = usable - per * block; if (leftover > 0) kv("남는 포트 (공인 IP 1개당)", "${leftover}개")
                if (subs != null) { val need = ceil(subs.toDouble() / per).toLong(); kv("가입자 ${n(subs)}명에 필요한 공인 주소", "${n(need)}개", level = if (need > pubCount) 2 else 0); kv("가입자 대 공인 IP 비율", "${d(subs.toDouble() / max(1, min(pubCount, need)), 1)} : 1"); if (need > pubCount) note("공인 주소가 ${n(need - pubCount)}개 모자라요.", 2) else note("공인 주소 여유 ${n(pubCount - need)}개 (${d((pubCount - need) * 100.0 / pubCount, 1)}%).", -1) }
                val inside = i.str("inside").takeIf { it.isNotEmpty() }?.let { Subnet.parse(it) ?: return@result note("안쪽 주소 대역은 100.64.0.0/22 같은 CIDR 로 적어 주세요.", 2) }
                if (inside != null) {
                    val insideCount = 1L shl (32 - inside.prefix); kv("안쪽 주소 대역", "${IpUtil.v4Text(inside.network)}/${inside.prefix} (${n(insideCount)}개)", level = if (insideCount > capacity) 2 else 0)
                    if (insideCount > capacity) note("안쪽 주소(${n(insideCount)}개)가 수용 가능한 가입자(${n(capacity)}명)보다 많아서, 일부 안쪽 주소에는 공인 포트를 줄 수 없어요.", 2)
                    val whoText = i.str("who")
                    if (whoText.isNotEmpty()) {
                        val ip = IpUtil.parseV4(whoText)?.let { IpUtil.v4ToLong(it) } ?: return@result note("찾을 안쪽 주소를 IPv4 주소로 적어 주세요.", 2)
                        if (ip < inside.network || ip > inside.network + insideCount - 1) note("그 주소는 안쪽 주소 대역 안에 없어요.", 2)
                        else {
                            val idx = ip - inside.network; val m = Cgnat.map(idx, per, p0, block)
                            head("$whoText 가 쓰는 공인 주소·포트"); kv("안쪽 주소 순번", "$idx"); kv("공인 주소 순번", "${m.outsideIndex + 1}번째"); if (m.outsideIndex >= pubCount) note("공인 주소가 모자라서 이 가입자에게는 줄 공인 주소가 없어요.", 2) else {
                                kv("공인 주소", if (pubSubnet != null) IpUtil.v4Text(pubSubnet.network + m.outsideIndex) else "(공인 주소 목록의 ${m.outsideIndex + 1}번째)"); kv("포트 범위", "${m.first} ~ ${m.last} (${m.slot + 1}번째 블록)") }
                        }
                    }
                    head("예: 처음과 마지막 가입자"); header("안쪽 주소", "공인 주소", "포트 범위")
                    for (idx in listOf(0L, 1L, insideCount - 1)) { val m = Cgnat.map(idx, per, p0, block); row(IpUtil.v4Text(inside.network + idx), if (m.outsideIndex >= pubCount) "(모자람)" else if (pubSubnet != null) IpUtil.v4Text(pubSubnet.network + m.outsideIndex) else "${m.outsideIndex + 1}번째", "${m.first}~${m.last}", level = if (m.outsideIndex >= pubCount) 2 else 0) }
                }
                note("한 가입자가 동시에 쓰는 연결(웹 페이지·앱·게임)은 연결마다 포트 하나를 써요. 블록이 작으면(예: 256) 브라우저 탭을 많이 열거나 P2P 를 쓸 때 연결이 막혀요. 보통 가입자당 1,000~4,000개 정도를 줘요.", 0)
                note("결정적 NAT(RFC 7422)는 안쪽 주소 순번만으로 공인 주소·포트 블록이 정해져서 접속 기록(로그)을 일일이 남기지 않아도 \"이 공인 IP·포트는 누구?\"를 계산으로 찾을 수 있어요(법적 요청 대응에 쓰는 방식). 동적 방식은 로그가 필요해요.", 0)
            }
        },
        // 7
        calc("calc_fiber_budget", G, "광링크 손실 예산 계산 (거리·커넥터·융착)", "광트랜시버의 송신 세기와 수신 감도로 광케이블 구간이 통할지 계산해요: 광섬유·커넥터·융착 손실을 더해 받는 세기와 여유(dB), 안전 여유를 지킬 수 있는 최대 거리를 알려 줘요",
            text("tx", "송신 세기 (dBm)", "트랜시버 사양서의 최소 송신(Tx) 값이 안전해요", "-5"), text("rx", "수신 감도 (dBm)", "이보다 약하면 못 받아요 (Rx sensitivity)", "-14.4"), text("ovl", "수신 과부하 (dBm, 선택)", "이보다 세면 수신부가 포화돼요", "0.5"), choice("type", "광섬유", Fiber.TYPES.map { it.name }), text("att", "직접 입력: 감쇠 (dB/km)", "", "0.35"), text("km", "거리 (km)", "", "10"),
            text("conn", "커넥터 접속 수 (짝 수)", "패치 패널을 지날 때마다 늘어요", "4"), text("cdb", "커넥터 한 쌍 손실 (dB)", "일반 0.3~0.75", "0.5"), text("spl", "융착(스플라이스) 수", "", "2"), text("sdb", "융착 한 곳 손실 (dB)", "일반 0.05~0.1", "0.1"), text("safe", "안전 여유 (dB)", "온도·노후·수리 대비. 보통 3dB", "3")) { i ->
            val tx = num(i, "tx") ?: return@calc fail("송신 세기(dBm)를 숫자로 적어 주세요"); val rx = num(i, "rx") ?: return@calc fail("수신 감도(dBm)를 숫자로 적어 주세요"); val ovl = i.str("ovl").let { if (it.isEmpty()) null else it.toDoubleOrNull() ?: return@calc fail("수신 과부하(dBm)를 숫자로 적어 주세요") }
            val ft = Fiber.TYPES.firstOrNull { it.name == i.str("type") } ?: Fiber.TYPES[0]; val att = if (ft.dbPerKm > 0) ft.dbPerKm else num(i, "att")?.takeIf { it >= 0 } ?: return@calc fail("감쇠(dB/km)를 0 이상의 숫자로 적어 주세요")
            val km = num(i, "km")?.takeIf { it >= 0 } ?: return@calc fail("거리(km)를 0 이상의 숫자로 적어 주세요"); val conn = i.int("conn")?.takeIf { it >= 0 } ?: return@calc fail("커넥터 수는 0 이상의 정수예요"); val cdb = num(i, "cdb")?.takeIf { it >= 0 } ?: return@calc fail("커넥터 손실(dB)을 적어 주세요")
            val spl = i.int("spl")?.takeIf { it >= 0 } ?: return@calc fail("융착 수는 0 이상의 정수예요"); val sdb = num(i, "sdb")?.takeIf { it >= 0 } ?: return@calc fail("융착 손실(dB)을 적어 주세요"); val safe = num(i, "safe")?.takeIf { it >= 0 } ?: return@calc fail("안전 여유(dB)를 0 이상의 숫자로 적어 주세요")
            val b = Fiber.budget(tx, rx, att, km, conn, cdb, spl, sdb, safe)
            result {
                kv("광섬유", "${ft.name} · ${d(att, 2)} dB/km"); head("손실"); header("항목", "손실 (dB)"); row("광섬유 ${d(km, 2)}km × ${d(att, 2)}", d(b.fiberLoss, 2)); row("커넥터 ${conn}쌍 × ${d(cdb, 2)}", d(b.connLoss, 2)); row("융착 ${spl}곳 × ${d(sdb, 2)}", d(b.spliceLoss, 2)); row("합계", d(b.totalLoss, 2))
                head("결과"); kv("받는 세기", "${d(b.rxDbm, 2)} dBm"); kv("수신 감도", "${d(rx, 2)} dBm"); kv("링크 여유", "${d(b.marginDb, 2)} dB", level = if (b.marginDb < 0) 2 else if (b.marginDb < safe) 1 else -1); kv("안전 여유(${d(safe, 1)}dB)를 뺀 여유", "${d(b.marginAfterSafety, 2)} dB", level = if (b.marginAfterSafety < 0) 1 else -1)
                b.maxKm?.let { kv("안전 여유를 지키는 최대 거리", if (it < 0) "이 구성으로는 거리가 0 이어도 모자라요" else "${d(it, 2)} km", level = if (it < km) 2 else 0) }
                if (b.marginDb < 0) note("받는 세기가 수신 감도보다 약해서 링크가 안 돼요. 손실을 줄이거나(커넥터·융착 줄이기, 세척) 출력이 더 센 트랜시버·감도가 좋은 수신부를 쓰세요.", 2)
                else if (b.marginDb < safe) note("링크는 되지만 안전 여유(${d(safe, 1)}dB)가 모자라요. 먼지·구부러짐·노후로 손실이 늘면 끊길 수 있어요.", 1) else note("안전 여유까지 지킬 수 있어요.", -1)
                if (ovl != null && b.rxDbm > ovl) note("받는 세기(${d(b.rxDbm, 2)}dBm)가 수신 과부하(${d(ovl, 1)}dBm)보다 세요. 짧은 거리에서는 수신부가 포화돼 오류가 나요. ${d(b.rxDbm - ovl + 1, 1)}dB 정도의 감쇠기(attenuator)를 끼우세요.", 2)
                note("손실 예산 = 송신 세기 − 광섬유 손실 − 커넥터 손실 − 융착 손실.  사양서의 Tx 는 최소(보수적)와 최대가 있어요. 거리가 짧을 땐 최대 Tx 로 과부하도 따져 보세요.", 0)
                note("감쇠값은 대표값(케이블 규격의 상한 근처)이에요. 실제 케이블 시험 성적서(OTDR·광파워미터 측정)가 있으면 그 값을 쓰세요. 멀티모드는 파장·코어 규격(OM1~OM5)에 따라 달라요.", 0)
            }
        },
        // 8
        calc("calc_wire_speed", G, "이더넷 와이어 스피드 계산 (초당 패킷·실제 전송량)", "링크 속도와 프레임 크기로 한 초에 보낼 수 있는 최대 프레임 수(pps)와 IP·TCP·UDP 데이터 전송량을 계산해요(프리앰블·프레임 간 간격 20바이트 포함). 1Gbps 에서 64바이트면 1,488,095 pps 가 나와요",
            choice("speed", "링크 속도", SPEEDS, "1 Gbps"), text("frame", "프레임 크기 (바이트, FCS 포함)", "이더넷 최소 64, 일반 최대 1518, 점보 9018", "64"), choice("vlan", "VLAN 태그", VLAN)) { i ->
            val bps = SPEED_BPS[i.choice("speed", SPEEDS)]; val frame = i.int("frame")?.takeIf { it in 64..16000 } ?: return@calc fail("프레임 크기는 64~16000바이트(FCS 포함)예요. 이더넷 최소 프레임은 64바이트예요"); val vlan = if (i.choice("vlan", VLAN) == 1) 4 else 0
            fun gb(v: Double) = if (v >= 1e9) "${d(v / 1e9, 3)} Gbps" else "${d(v / 1e6, 2)} Mbps"
            fun sizeRow(f: Int): List<String> { val pps = WireSpeed.pps(bps, f); val l3 = f - 18 - vlan; val l4t = f - 18 - vlan - 40; val l4u = f - 18 - vlan - 28; return listOf("$f", n(pps.toLong()), gb(pps * f * 8), if (l3 > 0) gb(pps * l3 * 8) else "-", if (l4t > 0) gb(pps * l4t * 8) else "-", if (l4u > 0) gb(pps * l4u * 8) else "-") }
            val pps = WireSpeed.pps(bps, frame); val onWire = frame + WireSpeed.OVERHEAD
            result {
                kv("링크 속도", SPEEDS[i.choice("speed", SPEEDS)]); kv("선 위의 크기", "$onWire 바이트 (프레임 $frame + 프리앰블·SFD 8 + 프레임 간 간격 12)"); kv("최대 프레임 수", "${d(pps, 1)} 프레임/초 (${n(pps.toLong())} pps)"); kv("프레임 하나를 보내는 시간", "${d(onWire * 8.0 / bps * 1e9, 1)} ns")
                kv("회선 이용 효율", "${d(frame * 100.0 / onWire, 2)}% (나머지 ${d(WireSpeed.OVERHEAD * 100.0 / onWire, 2)}%는 프리앰블·간격)"); kv("이더넷 프레임 전송량", gb(pps * frame * 8))
                val l3 = frame - 18 - vlan; val l4t = frame - 18 - vlan - 40; val l4u = frame - 18 - vlan - 28
                kv("IP 데이터(IP 헤더 포함) 전송량", if (l3 > 0) "${gb(pps * l3 * 8)} (프레임당 ${l3}바이트)" else "-"); kv("TCP 데이터(IPv4) 전송량", if (l4t > 0) "${gb(pps * l4t * 8)} (프레임당 ${l4t}바이트)" else "-"); kv("UDP 데이터(IPv4) 전송량", if (l4u > 0) "${gb(pps * l4u * 8)} (프레임당 ${l4u}바이트)" else "-")
                head("프레임 크기별 비교"); header("프레임(B)", "초당 프레임", "프레임 전송량", "IP 데이터", "TCP 데이터", "UDP 데이터")
                for (f in listOf(64, 128, 256, 512, 1024, 1280, 1518, 9018)) rowList(sizeRow(f))
                if (frame == 64) note("64바이트는 가장 작은 프레임이라 같은 속도에서 초당 프레임 수(pps)가 가장 많아요. 라우터·방화벽의 한계는 보통 대역폭이 아니라 pps 로 와요.", 0)
                note("이더넷 프레임 = 목적지 MAC 6 + 출발지 MAC 6 + 종류 2 + 데이터 + FCS 4 (18바이트 + 데이터). IPv4+TCP 는 헤더 40바이트, IPv4+UDP 는 28바이트(옵션 없음)를 더 써요. VLAN 태그가 있으면 4바이트를 더 써요.", 0)
                note("TCP 의 실제 파일 전송 속도는 윈도 크기·지연·손실 때문에 이 값보다 낮고, ACK 패킷도 반대 방향으로 흘러요.", 0)
            }
        },
        // 9
        calc("calc_erlang", G, "Erlang B/C 계산 (통화로·콜센터 상담원 수)", "전화 회선 수를 정하는 Erlang B(통화 실패율)와 콜센터 상담원 수를 정하는 Erlang C(대기 확률·평균 대기·서비스 수준)를 계산해요. 부하는 얼랑(Erlang) 또는 시간당 호 수 × 평균 통화 시간으로 입력해요",
            choice("m", "무엇을 구할까요", ERLANG), text("a", "부하 (얼랑)", "비우면 아래 \"시간당 호 수 × 통화 시간\"으로 계산"), text("cph", "시간당 호(통화) 수", "", "300"), text("aht", "평균 통화 시간 (초)", "AHT. 상담 시간+후처리 시간", "180"), text("n", "회선·상담원 수 (알고 있다면)", "", "20"), text("b", "허용 통화 실패율 (%) — Erlang B", "", "1"),
            text("sl", "목표 서비스 수준 (%) — Erlang C", "예: 80", "80"), text("t", "서비스 수준 시간 (초)", "예: 20 → 20초 안에 받기", "20")) { i ->
            val aht = num(i, "aht")?.takeIf { it > 0 } ?: return@calc fail("평균 통화 시간(초)을 0 보다 큰 숫자로 적어 주세요")
            val a = if (i.str("a").isNotEmpty()) num(i, "a")?.takeIf { it > 0 } ?: return@calc fail("부하(얼랑)를 0 보다 큰 숫자로 적어 주세요") else (num(i, "cph")?.takeIf { it > 0 } ?: return@calc fail("시간당 호 수를 0 보다 큰 숫자로 적어 주세요")) * aht / 3600.0
            val mode = i.choice("m", ERLANG); val nn = i.int("n")
            val bt = if (mode == 0) (num(i, "b")?.takeIf { it > 0 && it < 100 } ?: return@calc fail("허용 통화 실패율은 0 보다 크고 100 보다 작은 %예요")) / 100 else 0.0
            val sl = if (mode == 2) (num(i, "sl")?.takeIf { it in 1.0..99.9 } ?: return@calc fail("목표 서비스 수준은 1~99.9% 예요")) / 100 else 0.0
            val t = if (mode >= 2) num(i, "t")?.takeIf { it >= 0 } ?: return@calc fail("서비스 수준 시간(초)을 적어 주세요") else 0.0
            val k = if (mode == 1 || mode == 3) nn?.takeIf { it in 1..100000 } ?: return@calc fail(if (mode == 1) "회선 수를 1 이상의 정수로 적어 주세요" else "상담원 수를 1 이상의 정수로 적어 주세요") else 0
            result {
                kv("부하", "${d(a, 3)} 얼랑 (동시에 평균 ${d(a, 1)}개의 통화가 진행)")
                when (mode) {
                    0 -> { val lines = Erlang.linesFor(a, bt); kv("필요한 통화로(회선) 수", "${lines}개", level = -1); kv("그때 통화 실패율", "${d(Erlang.b(lines, a) * 100, 3)}%"); kv("회선 사용률", "${d(a * (1 - Erlang.b(lines, a)) / lines * 100, 1)}%")
                        head("회선 수에 따른 통화 실패율"); header("회선 수", "통화 실패율", "목표 만족"); for (c in max(1, lines - 3)..lines + 2) row("$c", "${d(Erlang.b(c, a) * 100, 3)}%", if (Erlang.b(c, a) <= bt) "예" else "아니오", level = if (c == lines) -1 else 0)
                        note("Erlang B 는 회선이 다 차면 걸려 온 전화가 그냥 끊긴다(통화중 신호)고 보고, 대기열은 없다고 가정해요. 재다이얼이 많으면 실제 부하가 더 커져요.", 0) }
                    1 -> { val bb = Erlang.b(k, a); kv("회선 $k 개의 통화 실패율", "${d(bb * 100, 3)}%", level = if (bb > 0.05) 2 else if (bb > 0.01) 1 else -1); kv("통화에 성공하는 부하", "${d(a * (1 - bb), 3)} 얼랑"); kv("회선 사용률", "${d(a * (1 - bb) / k * 100, 1)}%")
                        if (a >= k) note("부하(${d(a, 1)}얼랑)가 회선 수 이상이에요. 회선이 항상 모자라 많은 전화가 실패해요.", 2) }
                    2 -> { val agents = Erlang.agentsFor(a, aht, t, sl)
                        kv("필요한 상담원 수", "${agents}명", level = -1); kv("서비스 수준", "${d(Erlang.serviceLevel(agents, a, aht, t) * 100, 1)}% 가 ${d(t, 0)}초 안에 연결"); kv("기다릴 확률", "${d(Erlang.c(agents, a) * 100, 1)}%"); kv("평균 대기 시간(ASA)", "${d(Erlang.avgWait(agents, a, aht), 1)}초"); kv("상담원 점유율", "${d(a / agents * 100, 1)}%", level = if (a / agents > 0.9) 1 else 0)
                        head("상담원 수에 따른 변화"); header("상담원", "서비스 수준", "기다릴 확률", "평균 대기(초)", "점유율"); for (c in max(floor(a).toInt() + 1, agents - 2)..agents + 2) row("$c", "${d(Erlang.serviceLevel(c, a, aht, t) * 100, 1)}%", "${d(Erlang.c(c, a) * 100, 1)}%", d(Erlang.avgWait(c, a, aht), 1), "${d(a / c * 100, 1)}%", level = if (c == agents) -1 else 0)
                        note("Erlang C 는 기다리는 사람이 끝까지 기다린다고 가정해요(포기 없음). 실제로는 중간에 끊는 사람이 있어서 대기가 이 값보다 덜 쌓이지만, 재시도가 생겨요. 휴가·교육·휴식 시간을 반영한 \"배치 인원\"은 이 수보다 20~35% 더 필요해요(shrinkage).", 0) }
                    else -> {
                        if (k <= a) { kv("상담원", "${k}명"); note("부하(${d(a, 1)}얼랑)가 상담원 수 이상이에요. 대기열이 끝없이 늘어요. 상담원이 최소 ${floor(a).toInt() + 1}명은 있어야 해요.", 2) }
                        else { kv("기다릴 확률", "${d(Erlang.c(k, a) * 100, 1)}%"); kv("평균 대기 시간(ASA)", "${d(Erlang.avgWait(k, a, aht), 1)}초"); kv("서비스 수준", "${d(Erlang.serviceLevel(k, a, aht, t) * 100, 1)}% 가 ${d(t, 0)}초 안에 연결"); kv("상담원 점유율", "${d(a / k * 100, 1)}%", level = if (a / k > 0.9) 1 else 0) } }
                }
            }
        },
        // 10
        calc("calc_p95", G, "95% 요금 계산 (버스터블 대역폭 과금)", "회선 사용량 샘플(보통 5분마다 측정한 Mbps)을 붙여 넣으면 상위 5%를 버리고 남은 최댓값(95번째 백분위)을 구해서 요금을 계산해요. 90·99 백분위도 돼요. 호스팅·IDC 대역폭 요금제에서 쓰는 방식이에요",
            multi("s", "사용량 샘플", "숫자를 줄마다 하나 또는 쉼표로. 예: 12.5, 80, 33", "12\n15\n14\n220\n13\n16\n18\n17\n19\n21\n14\n13\n15\n16\n22\n18\n17\n12\n14\n300"), choice("u", "샘플의 단위", PCT_UNIT), choice("p", "백분위", PCTL), text("price", "1Mbps 당 요금 (선택)", "예: 1500", "1500")) { i ->
            val samples = i.raw("s").split(Regex("[,;\\s]+")).filter { it.isNotEmpty() }.map { it.toDoubleOrNull()?.takeIf { v -> v >= 0 && !v.isInfinite() } ?: return@calc fail("숫자가 아닌 값이 있어요: \"$it\" (0 이상의 숫자만 쓸 수 있어요)") }
            if (samples.isEmpty()) return@calc need("사용량 샘플을 붙여 넣으세요"); if (samples.size > 2_000_000) return@calc fail("샘플은 2,000,000개까지 계산해요")
            val unit = i.str("u").ifEmpty { "Mbps" }; val toMbps = when (unit) { "kbps" -> 0.001; "Gbps" -> 1000.0; else -> 1.0 }; val p = i.str("p").toDoubleOrNull() ?: 95.0
            val price = i.str("price").let { if (it.isEmpty()) null else it.replace(",", "").toDoubleOrNull()?.takeIf { v -> v >= 0 } ?: return@calc fail("요금은 0 이상의 숫자로 적어 주세요") }
            val sorted = samples.sorted(); val k = Pctl.rank(samples.size, p); val pv = sorted[k - 1]; val avg = samples.average(); val peak = sorted.last(); val dropped = samples.size - k
            fun mb(v: Double) = "${d(v * toMbps, 2)} Mbps"
            result {
                kv("샘플 수", "${n(samples.size.toLong())}개"); kv("평균", mb(avg)); kv("최댓값(피크)", mb(peak)); kv("${i.str("p").ifEmpty { "95" }}번째 백분위", mb(pv), level = -1); kv("버리는 샘플", "${n(dropped.toLong())}개 (위쪽 ${d(dropped * 100.0 / samples.size, 2)}%)"); kv("순위", "작은 값부터 ${k}번째 (${samples.size} × ${d(p, 1)}% = ${d(samples.size * p / 100, 2)}, 올림)")
                kv("피크 대비", "${d(pv / peak * 100, 1)}% (피크가 몇 번 튀어도 요금에 반영되지 않는 정도)")
                if (price != null) { kv("요금 (백분위 기준)", "${d(pv * toMbps * price, 0)} (${d(pv * toMbps, 2)}Mbps × $price)"); kv("참고: 피크 기준이었다면", "${d(peak * toMbps * price, 0)}"); kv("참고: 평균 기준이었다면", "${d(avg * toMbps * price, 0)}") }
                head("큰 값 상위"); header("순위(큰 쪽부터)", "값", "요금에 반영?"); for ((j, v) in sorted.reversed().take(8).withIndex()) row("${j + 1}", mb(v), if (samples.size - j <= k) "예 (이 값부터 요금)" else "버려요")
                note("월 30일을 5분 간격으로 재면 샘플이 8,640개이고, 95% 요금은 가장 높은 432개(약 36시간)를 버려요. 하루 1~2시간 폭주해도 요금에는 안 나와요.", 0)
                if (samples.size < 100) note("샘플이 적어요(${samples.size}개). 실제 청구는 한 달치(수천 개)로 계산하니 결과가 달라질 수 있어요.", 1)
                note("계산 방식은 \"가장 가까운 순위(nearest-rank)\": 작은 값부터 늘어놓고 ceil(개수 × 백분위) 번째 값을 써요. 업체마다 5분 샘플의 \"큰 쪽(송신/수신 중 큰 값)\"을 쓰는지가 달라요. 계약서를 확인하세요.", 0)
            }
        },
    )
}
