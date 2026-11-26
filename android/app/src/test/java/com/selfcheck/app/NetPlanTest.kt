package com.selfcheck.app

import org.json.JSONArray
import org.json.JSONObject
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.File
import kotlin.math.abs

/*
 * 용량·전력·품질 계산 도구 10가지 시험.
 * 기준값(src/test/resources/netcalc/calc_cases.json)은 파이썬이 Kotlin 코드와 다른 방법으로 구했어요:
 * PoE 는 뉴턴 반복, Erlang 은 정확한 분수(Fraction), 95% 요금은 numpy inverted_cdf 와 분수 올림, RAID·UPS·VoIP·광링크·CGNAT·와이어 스피드는 정의대로 직접 계산.
 */
class NetPlanTest {
    private val cases: JSONObject by lazy { JSONObject(File("src/test/resources/netcalc/calc_cases.json").readText()) }
    private fun arr(k: String): JSONArray = cases.getJSONArray(k)
    private fun run(id: String, vararg kv: Pair<String, String>) = runNetTool(id, *kv)
    private fun near(msg: String, exp: Double, act: Double, tol: Double) = assertTrue("$msg: 기대 $exp, 실제 $act (허용 $tol)", abs(exp - act) <= tol)
    private fun relNear(msg: String, exp: Double, act: Double, rel: Double = 1e-9) = assertTrue("$msg: 기대 $exp, 실제 $act", abs(exp - act) <= rel * max(abs(exp), 1e-300) + 1e-300)
    private fun max(a: Double, b: Double) = if (a > b) a else b
    private fun first(s: String): Double = Regex("-?[0-9][0-9,]*(?:\\.[0-9]+)?").find(s)!!.value.replace(",", "").toDouble()

    // ============================================================ RAID

    @Test fun raidCapacityRebuildAndUreMatchPython() {
        val rows = arr("raid"); assertTrue(rows.length() >= 40)
        for (k in 0 until rows.length()) {
            val c = rows.getJSONObject(k); val lv = c.getString("lv"); val msg = c.toString()
            val r = run("calc_raid", "lv" to lv, "n" to "${c.getInt("n")}", "g" to "${c.getInt("g")}", "size" to "${c.getInt("size")}", "unit" to "TB", "rb" to "100", "ure" to c.getString("ure"))
            if (!lv.startsWith("RAID 0")) assertFalse(msg + "\n" + r.text(), r.hasError)                                                       // RAID 0 은 "전부 잃어요" 경고가 일부러 붙음
            near("$msg 용량", c.getDouble("usable_tb"), first(r.kv("쓸 수 있는 용량")), 0.006); near("$msg 효율", c.getDouble("usable_tb") / (c.getInt("n") * c.getInt("size")) * 100, first(r.kv("효율")), 0.06)
            if (c.isNull("ure_prob")) { assertFalse(msg, r.hasKv("복구 시간")); assertFalse(msg, r.hasKv("복구 중 읽기 오류를 만날 확률")) }
            else { near("$msg 복구 시간", c.getDouble("rebuild_h"), first(r.kv("복구 시간")), 0.06); near("$msg 오류 확률", c.getDouble("ure_prob") * 100, first(r.kv("복구 중 읽기 오류를 만날 확률")), 0.006) }
        }
        // 정의로 직접 센 값
        fun plan(lv: String, n: Int, g: Int = 2) = Raid.plan(lv, n, g)
        assertEquals(6, plan("RAID 5", 7).usableDisks); assertEquals(1, plan("RAID 5", 7).guaranteed); assertEquals(4, plan("RAID 5", 7).writePenalty); assertEquals(2, plan("RAID 6", 8).guaranteed); assertEquals(6, plan("RAID 6", 8).writePenalty); assertEquals(4, plan("RAID 10", 8).usableDisks); assertEquals(1, plan("RAID 10", 8).guaranteed); assertEquals(2, plan("RAID 10", 8).writePenalty)
        assertEquals(1, plan("RAID 1 (미러)", 4).usableDisks); assertEquals(3, plan("RAID 1 (미러)", 4).guaranteed); assertEquals(9, plan("RAID 50", 12, 3).usableDisks); assertEquals(6, plan("RAID 60", 12, 3).usableDisks); assertEquals(0, plan("RAID 0 (줄 세우기)", 3).guaranteed); assertEquals(5, plan("JBOD (이어 붙이기)", 5).usableDisks); assertEquals(0, plan("JBOD (이어 붙이기)", 5).guaranteed)
        assertEquals(3, plan("RAID 5", 4).rebuildReadDisks); assertEquals(2, plan("RAID 50", 9, 3).rebuildReadDisks); assertEquals(1, plan("RAID 10", 4).rebuildReadDisks)
        // 알려진 값: 8TB 디스크 4개 RAID 5 를 일반 HDD(10^-14)로 복구하면 3×8TB 를 읽다가 오류를 만날 확률이 85% 가 넘음
        near("푸아송 식", 1 - Math.exp(-3 * 8e12 * 8 * 1e-14), Raid.ureProbability(3 * 8e12, 1e-14), 1e-12); assertTrue(Raid.ureProbability(3 * 8e12, 1e-14) > 0.85); assertTrue(Raid.ureProbability(3 * 8e12, 1e-16) < 0.2); assertEquals(0.0, Raid.ureProbability(0.0, 1e-14), 0.0)
    }

    @Test fun raidToolMessagesAndValidation() {
        val r5 = run("calc_raid"); assertEquals("24.00 TB  (≈ 21.83 TiB)", r5.kv("쓸 수 있는 용량")); assertEquals("32.00 TB", r5.kv("전체 용량(디스크 합계)")); assertEquals("75.0%", r5.kv("효율")); assertEquals("디스크 1개까지", r5.kv("견디는 디스크 고장")); assertEquals("3개", r5.kv("최소 디스크 수")); assertEquals("쓰기 1번이 디스크 입출력 4번 (쓰기 페널티)", r5.kv("임의 쓰기 비용"))
        assertEquals(2, r5.kvLevel("복구 중 읽기 오류를 만날 확률")); assertEquals(1, r5.noteWith("RAID 6 이나 RAID 10")!!.level); assertEquals(1, r5.noteWith("백업이 아니에요")!!.level); assertTrue(r5.kv("복구 시간").startsWith("22.2시간")); assertNull(r5.noteWith("하루 넘게"))
        val r6 = run("calc_raid", "lv" to "RAID 6", "n" to "6"); assertEquals(0, r6.kvLevel("복구 중 읽기 오류를 만날 확률")); assertEquals(-1, r6.noteWith("두 번째 패리티")!!.level); assertEquals("32.00 TB  (≈ 29.10 TiB)", r6.kv("쓸 수 있는 용량"))
        assertEquals(2, run("calc_raid", "lv" to "RAID 0 (줄 세우기)").noteWith("전부 잃어요")!!.level); assertEquals("500.00 GB  (≈ 0.45 TiB)", run("calc_raid", "lv" to "JBOD (이어 붙이기)", "n" to "1", "size" to "500", "unit" to "GB").kv("쓸 수 있는 용량"))
        // 입력 확인: 조건에 안 맞는 개수는 이유를 알려 줌
        for ((lv, n, g, msg) in listOf(listOf("RAID 5", "2", "2", "3개 이상"), listOf("RAID 6", "3", "2", "4개 이상"), listOf("RAID 10", "5", "2", "짝수"), listOf("RAID 10", "2", "2", "짝수"), listOf("RAID 50", "10", "3", "나누어떨어지고"), listOf("RAID 50", "4", "2", "3개 이상"), listOf("RAID 50", "6", "1", "그룹이 2개 이상"), listOf("RAID 60", "6", "2", "4개 이상"), listOf("RAID 0 (줄 세우기)", "1", "2", "2개 이상"), listOf("RAID 1 (미러)", "1", "2", "2개 이상")))
            assertTrue("$lv $n", run("calc_raid", "lv" to lv, "n" to n, "g" to g).let { it.hasError && it.text().contains(msg) })
        for (bad in listOf("n" to "x", "n" to "5000", "size" to "0", "size" to "-4", "size" to "abc", "rb" to "0")) assertTrue(bad.toString(), run("calc_raid", bad).hasError)
        assertTrue(run("calc_raid", "rb" to "10").noteWith("하루 넘게") != null); assertNull(run("calc_raid", "rb" to "500").noteWith("하루 넘게"))
    }

    // ============================================================ PoE

    @Test fun poeSolverMatchesNewtonIterationAndTheStandard() {
        val rows = arr("poe"); assertTrue(rows.length() > 100)
        for (k in 0 until rows.length()) {
            val c = rows.getJSONObject(k); val s = Poe.STANDARDS.first { it.name == c.getString("std") }
            relNear(c.toString(), c.getDouble("pse"), Poe.pseWatts(c.getDouble("pd"), s.volts, Poe.loopOhm(s, c.getDouble("m")))!!, 1e-9)
        }
        // 규격표: 100m 에서 기기 사용 한도(PD)를 쓸 때 스위치가 내보내는 전력이 포트 공급 한도(PSE)와 같음 (af·at·bt3 는 정확히, bt4 는 한도 이하)
        for ((k, s) in Poe.STANDARDS.withIndex()) { val p = Poe.pseWatts(s.pdMax, s.volts, s.loopOhm100m)!!; relNear(s.name, arr("poe_spec").getJSONObject(k).getDouble("pse_at_pdmax_100m"), p); if (k < 3) near(s.name, s.psePort, p, 1e-9) else assertTrue(p < s.psePort) }
        assertEquals(0.0, Poe.pseWatts(0.0, 50.0, 12.5)!!, 0.0); assertNull(Poe.pseWatts(500.0, 50.0, 12.5)); assertEquals(6.25, Poe.loopOhm(Poe.STANDARDS[2], 100.0), 1e-12); assertEquals(3.125, Poe.loopOhm(Poe.STANDARDS[2], 50.0), 1e-12)
    }

    @Test fun poeToolBudgetUsesTheSolvedPowers() {
        val rows = arr("poe"); fun pse(pd: Double) = (0 until rows.length()).map { rows.getJSONObject(it) }.first { it.getString("std") == Poe.STANDARDS[1].name && it.getInt("m") == 100 && it.getDouble("pd") == pd }.getDouble("pse")
        val r = run("calc_poe"); val pdTotal = 3 * 12.5 + 4 * 7.0 + 6 * 3.5; val pseTotal = 3 * pse(12.5) + 4 * pse(7.0) + 6 * pse(3.5)
        near("PD 합계", pdTotal, first(r.kv("기기가 쓰는 전력 합계")), 0.06); near("PSE 합계", pseTotal, first(r.kv("스위치가 내보내야 하는 전력")), 0.06); near("손실", pseTotal - pdTotal, first(r.kv("케이블 손실")), 0.06); near("남는 예산", 120 - pseTotal, first(r.kv("남는 예산")), 0.06); assertEquals("13개", r.kv("연결 포트 수"))
        near("사용률", pseTotal / 120 * 100, first(r.kv("예산 사용률")), 0.06); assertEquals(-1, r.kvLevel("남는 예산")); assertEquals(0, r.kvLevel("예산 사용률")); assertEquals("12.50 Ω (100m)", r.kv("케이블 루프 저항")); assertTrue(r.kv("규격").startsWith("IEEE 802.3at (PoE+, 30W) · 포트당 최대 30.0W 공급 / 기기 사용 25.50W"))
        val row = r.rows().first { it[0] == "AP" }; assertEquals(listOf("AP", "12.50", "%.2f".format(pse(12.5)), "3", "%.1f".format(3 * pse(12.5))), row)
        // 짧은 케이블이면 손실이 줄어듦
        assertTrue(first(run("calc_poe", "len" to "10").kv("케이블 손실")) < first(r.kv("케이블 손실")) / 5)
        // 예산 부족·한도 초과·여유 적음
        assertEquals(2, run("calc_poe", "budget" to "60").noteWith("예산이 모자라요")!!.level); assertEquals(2, run("calc_poe", "budget" to "60").kvLevel("남는 예산")); assertEquals(1, run("calc_poe", "budget" to "105").noteWith("80%를 넘었어요")!!.level)
        val over = run("calc_poe", "std" to Poe.STANDARDS[0].name, "dev" to "AP, 20, 2\n카메라, 7, 1"); assertEquals(2, over.rowLevel("AP")); assertEquals("공급 불가", over.row("AP")[2]); assertEquals(2, over.noteWith("공급할 수 없는 기기")!!.level); assertTrue(over.rows().first { it[0] == "카메라" }[2] != "공급 불가")
        val bt = run("calc_poe", "std" to Poe.STANDARDS[3].name, "dev" to "PTZ 카메라, 60, 2", "budget" to "400"); assertEquals("PTZ 카메라", bt.row("PTZ 카메라")[0]); assertTrue(first(bt.kv("스위치가 내보내야 하는 전력")) > 2 * 60)
        // 입력 형식: 쉼표·공백·W 단위·x 개수·개수 생략
        val fmt = run("calc_poe", "dev" to "AP 12.5 3\nCCTV north, 7W, x4\n전화 3.5\nIP 전화 2층 3.5 6"); assertEquals("14개", fmt.kv("연결 포트 수")); assertTrue(fmt.rows().any { it[0] == "IP 전화 2층" && it[3] == "6" }); assertTrue(fmt.rows().any { it[0] == "CCTV north" && it[3] == "4" }); assertTrue(fmt.rows().any { it[0] == "전화" && it[3] == "1" })
        for (bad in listOf("budget" to "0", "budget" to "abc", "len" to "0", "len" to "500", "dev" to "AP", "dev" to "AP, abc, 2", "dev" to "AP, -5, 1", "dev" to "AP, 5, 0", "dev" to "AP, 5, x")) assertTrue(bad.toString(), run("calc_poe", bad).hasError); assertEquals(1, run("calc_poe", "dev" to "").notes().single().level)
    }

    // ============================================================ UPS

    @Test fun upsRuntimeMatchesPython() {
        val rows = arr("ups"); assertEquals(5, rows.length())
        for (k in 0 until rows.length()) {
            val c = rows.getJSONObject(k); val chem = if (c.getDouble("k") == 1.05) "리튬인산철 (LiFePO4)" else "납축전지 (VRLA)"
            val r = run("calc_ups", "va" to "5000", "pf" to "1", "load" to "${c.getDouble("load")}", "bv" to "${c.getDouble("bv")}", "bah" to "${c.getDouble("bah")}", "bs" to "${c.getInt("bs")}", "bp" to "${c.getInt("bp")}", "chem" to chem, "eff" to "${c.getDouble("eff")}", "dod" to "${c.getDouble("dod")}", "age" to "${c.getDouble("age")}")
            fun hours(s: String): Double { return first(s) / (if (s.contains("시간")) 1.0 else 60.0) }
            val msg = c.toString()
            fun tol(text: String): Double { return if (text.contains("시간")) 0.051 else 0.0009 }   // 화면에는 시간·분 모두 소수 첫째 자리까지 보여 줘요
            near("$msg 에너지", c.getDouble("wh"), first(r.kv("배터리 에너지")), 0.5); near("$msg 단순", c.getDouble("simple_h"), hours(r.kv("가동 시간 (단순 계산)")), tol(r.kv("가동 시간 (단순 계산)"))); near("$msg 페우케르트", c.getDouble("peukert_h"), hours(r.kv("가동 시간 (페우케르트 보정)")), tol(r.kv("가동 시간 (페우케르트 보정)")))
            relNear(msg, c.getDouble("simple_h"), Ups.simpleHours(c.getDouble("wh"), c.getDouble("dod") / 100, c.getDouble("age") / 100, c.getDouble("eff") / 100, c.getDouble("load"))); relNear(msg, c.getDouble("peukert_h"), Ups.peukertHours(c.getDouble("bv") * c.getInt("bs"), c.getDouble("bah") * c.getInt("bp"), 20.0, c.getDouble("k"), c.getDouble("eff") / 100, c.getDouble("load"), c.getDouble("dod") / 100, c.getDouble("age") / 100))
        }
    }

    @Test fun upsToolOutputsAndWarnings() {
        val r = run("calc_ups"); assertEquals("900 W  (1500VA × 역률 0.60)", r.kv("UPS 출력 한도")); assertEquals("33.3%", r.kv("부하율")); assertEquals("12V 9.0Ah × 직렬 2 × 병렬 1 = 24V 9.0Ah", r.kv("배터리 구성")); assertEquals("216 Wh", r.kv("배터리 에너지")); assertEquals("31.1분", r.kv("가동 시간 (단순 계산)")); assertEquals("13.9 A", r.kv("부하 전류 (배터리 쪽)")); assertFalse(r.hasError)
        assertTrue(first(r.kv("가동 시간 (페우케르트 보정)")) < first(r.kv("가동 시간 (단순 계산)")))                                              // 정격(20시간율) 전류보다 크게 쓰면 쓸 수 있는 용량이 줄어듦
        val light = run("calc_ups", "load" to "5"); assertTrue(light.kv("가동 시간 (단순 계산)").endsWith("시간")); assertTrue(first(light.kv("가동 시간 (페우케르트 보정)")) > first(light.kv("가동 시간 (단순 계산)")))        // 정격보다 작은 전류에서는 오히려 더 길게 계산됨
        val over = run("calc_ups", "load" to "1000"); assertEquals(2, over.kvLevel("부하율")); assertEquals(2, over.noteWith("과부하")!!.level); assertEquals(1, run("calc_ups", "load" to "800").noteWith("80%")!!.level); assertEquals(1, run("calc_ups", "load" to "800").kvLevel("부하율"))
        assertTrue(run("calc_ups", "chem" to "리튬인산철 (LiFePO4)").noteWith("1.05")!!.text.contains("리튬")); assertTrue(run("calc_ups").noteWith("2~4년") != null); assertNull(run("calc_ups", "age" to "70").noteWith("2~4년")); assertNull(run("calc_ups", "chem" to "리튬인산철 (LiFePO4)").noteWith("2~4년"))
        for (bad in listOf("va" to "0", "va" to "x", "pf" to "0", "pf" to "1.5", "load" to "0", "bv" to "0", "bah" to "-1", "bs" to "0", "bp" to "200", "eff" to "20", "dod" to "5", "age" to "0")) assertTrue(bad.toString(), run("calc_ups", bad).hasError)
        // 직렬은 전압을, 병렬은 용량을 늘림
        assertEquals("432 Wh", run("calc_ups", "bs" to "2", "bp" to "2").kv("배터리 에너지")); assertEquals("216 Wh", run("calc_ups", "bs" to "1", "bp" to "2").kv("배터리 에너지")); assertEquals("144 Wh", run("calc_ups", "bs" to "1", "bp" to "1", "bv" to "16").kv("배터리 에너지"))
    }

    // ============================================================ NTP 오차

    @Test fun ntpOffsetToolFormulaAndWarnings() {
        val r = run("calc_ntp_offset"); assertEquals("+50.000 ms", r.kv("시계 오차(θ)")); assertEquals("20.000 ms", r.kv("왕복 지연(δ)")); assertEquals("1.000 ms", r.kv("서버 처리 시간(T3−T2)")); assertEquals("± 10.000 ms", r.kv("오차의 불확실성")); assertTrue(r.noteWith("내 시계가 서버보다 50.000ms 느려요")!!.text.contains("더해야"))
        assertEquals(1, r.kvLevel("시계 오차(θ)")); assertEquals(-1, run("calc_ntp_offset", "t2" to "2024-03-01T09:30:00.011Z", "t3" to "2024-03-01T09:30:00.012Z", "t4" to "2024-03-01T09:30:00.022Z").kvLevel("시계 오차(θ)"))
        // 수식을 따로 푼 값: θ = ((T2−T1)+(T3−T4))/2, δ = (T4−T1)−(T3−T2) (UNIX 초 입력)
        for ((t1, t2, t3, t4) in listOf(listOf(100.0, 100.060, 100.061, 100.021), listOf(1700000000.0, 1700000000.2, 1700000000.2, 1700000000.4), listOf(0.0, 5.0, 5.0, 2.0), listOf(10.5, 10.4, 10.4, 10.7))) {
            val x = run("calc_ntp_offset", "t1" to "$t1", "t2" to "$t2", "t3" to "$t3", "t4" to "$t4"); near("θ $t1", (((t2 - t1) + (t3 - t4)) / 2) * 1000, first(x.kv("시계 오차(θ)")), 0.001); near("δ $t1", ((t4 - t1) - (t3 - t2)) * 1000, first(x.kv("왕복 지연(δ)")), 0.0011)
        }
        // 서버가 앞서 있으면 +, 뒤처져 있으면 − 와 크기별 안내
        val ahead = run("calc_ntp_offset", "t1" to "100", "t2" to "100.5", "t3" to "100.5", "t4" to "100.01"); assertTrue(ahead.kv("시계 오차(θ)").startsWith("+")); assertEquals(2, ahead.kvLevel("시계 오차(θ)")); assertEquals(1, ahead.noteWith("128ms 이상")!!.level); assertNull(ahead.noteWith("1초 이상"))
        val slow = run("calc_ntp_offset", "t1" to "100", "t2" to "99", "t3" to "99", "t4" to "100.01"); assertTrue(slow.kv("시계 오차(θ)").startsWith("-")); assertTrue(slow.noteWith("빨라요")!!.text.contains("빼야")); assertEquals(2, slow.noteWith("1초 이상")!!.level)
        assertEquals(-1, run("calc_ntp_offset", "t1" to "100", "t2" to "100.0001", "t3" to "100.0001", "t4" to "100.0002").noteWith("1ms 미만")!!.level)
        val bad = run("calc_ntp_offset", "t1" to "100", "t2" to "100", "t3" to "100", "t4" to "90"); assertEquals(2, bad.noteWith("T4 가 T1 보다 이전")!!.level); assertEquals(2, bad.noteWith("왕복 지연이 음수")!!.level); assertEquals(2, bad.kvLevel("왕복 지연(δ)"))
        // 시각 형식: ISO(Z) · 공백 · UNIX 초 가 같은 결과 (UNIX 초는 큰 수라서 부동소수 한 칸 오차 허용)
        assertEquals("+50.000 ms", run("calc_ntp_offset", "t1" to "2024-03-01 09:30:00.000", "t2" to "2024-03-01 09:30:00.060", "t3" to "2024-03-01 09:30:00.061", "t4" to "2024-03-01 09:30:00.021").kv("시계 오차(θ)")); near("UNIX 초", 50.0, first(run("calc_ntp_offset", "t1" to "1709285400", "t2" to "1709285400.060", "t3" to "1709285400.061", "t4" to "1709285400.021").kv("시계 오차(θ)")), 0.002)
        for (bad2 in listOf("t1" to "", "t2" to "내일", "t3" to "2024-13-01T00:00:00Z", "t4" to "abc")) assertTrue(bad2.toString(), run("calc_ntp_offset", bad2).hasError)
    }

    // ============================================================ VoIP

    @Test fun voipEModelMatchesPython() {
        val rows = arr("voip"); assertEquals(36, rows.length())
        for (k in 0 until rows.length()) {
            val c = rows.getJSONObject(k); val msg = c.toString(); val codec = Voip.CODECS.first { it.name == c.getString("codec") }
            val d = c.getDouble("net") + c.getDouble("jit") + codec.delayMs; relNear(msg, c.getDouble("d"), d); relNear("$msg Id", c.getDouble("id"), Voip.delayImpairment(d)); val ie = Voip.effectiveIe(codec.ie, codec.bpl, c.getDouble("loss"), c.getDouble("burst")); relNear("$msg Ie_eff", c.getDouble("ie_eff"), ie); relNear("$msg R", c.getDouble("r"), Voip.rFactor(d, ie)); relNear("$msg MOS", c.getDouble("mos"), Voip.mos(Voip.rFactor(d, ie)))
            val r = run("calc_mos", "codec" to c.getString("codec"), "net" to "${c.getDouble("net")}", "jit" to "${c.getDouble("jit")}", "loss" to "${c.getDouble("loss")}", "burst" to "${c.getDouble("burst")}")
            near("$msg 화면 R", c.getDouble("r"), first(r.kv("R값")), 0.051); near("$msg 화면 MOS", c.getDouble("mos"), first(r.kv("MOS (1~4.5)")), 0.0051); near("$msg 화면 Id", c.getDouble("id"), first(r.kv("지연 손상 Id")), 0.0051); near("$msg 화면 Ie", c.getDouble("ie_eff"), first(r.kv("손실·코덱 손상 Ie_eff")), 0.0051)
        }
        val t = arr("mos_table"); for (k in 0 until t.length()) relNear("R=${t.getJSONObject(k).getDouble("r")}", t.getJSONObject(k).getDouble("mos"), Voip.mos(t.getJSONObject(k).getDouble("r")), 1e-12)
        // ITU-T G.107 의 R↔MOS 환산식을 손으로 푼 값 (반올림): R 90 → 4.34, 80 → 4.02, 70 → 3.60, 60 → 3.10, 50 → 2.58
        for ((rr, m) in listOf(90 to 4.34, 80 to 4.02, 70 to 3.60, 60 to 3.10, 50 to 2.58)) near("R=$rr", m, Voip.mos(rr.toDouble()), 0.0051); assertEquals(1.0, Voip.mos(-5.0), 0.0); assertEquals(4.5, Voip.mos(120.0), 0.0)
        near("G.711 지연 100ms", 4.36, Voip.mos(Voip.rFactor(100.0, 0.0)), 0.005)                                                                                              // 저지연 G.711 은 약 4.36
        assertEquals("매우 만족 (모두 만족)", Voip.category(91.0)); assertEquals("만족", Voip.category(85.0)); assertEquals("일부 사용자가 불만", Voip.category(75.0)); assertEquals("많은 사용자가 불만", Voip.category(65.0)); assertEquals("거의 모든 사용자가 불만", Voip.category(55.0)); assertEquals("통화로 쓰기 어려움", Voip.category(40.0))
        assertEquals(0.0, Voip.delayImpairment(0.0), 0.0); near("177.3ms 경계", 0.024 * 177.3, Voip.delayImpairment(177.3), 1e-12); assertTrue(Voip.delayImpairment(300.0) > 0.024 * 300); assertEquals(11.0, Voip.effectiveIe(11.0, 19.0, 0.0, 1.0), 0.0)
    }

    @Test fun voipToolMessages() {
        val r = run("calc_mos"); assertEquals("G.711 (PLC 없음) (Ie 0.0, Bpl 4.3)", r.kv("코덱")); assertTrue(r.kv("입에서 귀까지 지연").startsWith("120.0 ms  (네트워크 60 + 지터 버퍼 40 + 코덱 20.0)")); assertEquals(0, r.kvLevel("입에서 귀까지 지연")); assertTrue(r.noteWith("권고(150ms 이하) 안")!!.level == -1)
        val slow = run("calc_mos", "net" to "250"); assertEquals(1, slow.kvLevel("입에서 귀까지 지연")); assertEquals(1, slow.noteWith("150ms 를 넘었어요")!!.level); assertEquals(2, run("calc_mos", "net" to "400").noteWith("400ms 를 넘어요")!!.level); assertEquals(2, run("calc_mos", "net" to "400").kvLevel("입에서 귀까지 지연"))
        val bad = run("calc_mos", "loss" to "10", "net" to "50"); assertEquals(2, bad.kvLevel("MOS (1~4.5)")); assertTrue(bad.noteWith("패킷 손실이 품질을 크게")!!.level == 1); assertEquals(-1, run("calc_mos", "loss" to "0", "net" to "20", "jit" to "10").kvLevel("MOS (1~4.5)")); assertTrue(run("calc_mos", "loss" to "0", "net" to "20", "jit" to "10").noteWith("MOS 4.0 이상") != null)
        val custom = run("calc_mos", "codec" to "직접 입력 (Ie·Bpl)", "ie" to "20", "bpl" to "10", "loss" to "2", "cd" to "30"); assertEquals("직접 입력 (Ie 20.0, Bpl 10.0)", custom.kv("코덱")); assertTrue(custom.kv("입에서 귀까지 지연").startsWith("130.0 ms")); near("직접 입력 Ie_eff", 20 + 75 * 2 / (2.0 + 10), first(custom.kv("손실·코덱 손상 Ie_eff")), 0.0051)
        assertTrue(run("calc_mos", "cd" to "100").kv("입에서 귀까지 지연").startsWith("200.0 ms")); assertTrue(run("calc_mos", "codec" to "G.729A").kv("입에서 귀까지 지연").startsWith("135.0 ms")); assertTrue(run("calc_mos", "codec" to "G.729A").kv("코덱").contains("Ie 11.0"))
        for (bad2 in listOf("net" to "-1", "net" to "x", "jit" to "9999", "loss" to "101", "loss" to "abc", "burst" to "0.5", "cd" to "-5", "cd" to "abc")) assertTrue(bad2.toString(), run("calc_mos", bad2).hasError); assertTrue(run("calc_mos", "codec" to "직접 입력 (Ie·Bpl)", "ie" to "96").hasError); assertTrue(run("calc_mos", "codec" to "직접 입력 (Ie·Bpl)", "bpl" to "0").hasError)
    }

    // ============================================================ CGNAT

    @Test fun cgnatMappingMatchesPython() {
        val rows = arr("cgnat"); assertEquals(10, rows.length())
        for (k in 0 until rows.length()) {
            val c = rows.getJSONObject(k); val msg = c.toString(); val per = Cgnat.subsPerIp(c.getInt("p0"), c.getInt("p1"), c.getInt("block")); assertEquals(msg, c.getInt("per"), per); assertEquals(msg, c.getLong("capacity"), c.getLong("pub") * per)
            val m = Cgnat.map(c.getLong("idx"), per, c.getInt("p0"), c.getInt("block")); assertEquals(msg, c.getLong("out"), m.outsideIndex); assertEquals(msg, c.getInt("slot"), m.slot); assertEquals(msg, c.getInt("first"), m.first); assertEquals(msg, c.getInt("last"), m.last)
        }
        // 서로 다른 안쪽 주소는 같은 (공인 주소, 포트) 를 쓰지 않음, 그리고 블록은 쓸 범위 안에 있음
        val per = Cgnat.subsPerIp(1024, 65535, 1024); val seen = HashSet<Triple<Long, Int, Int>>(); for (i in 0L until 5000) { val m = Cgnat.map(i, per, 1024, 1024); assertTrue(seen.add(Triple(m.outsideIndex, m.first, m.last))); assertTrue(m.first >= 1024 && m.last <= 65535) }
    }

    @Test fun cgnatToolPlanAndLookup() {
        val r = run("calc_cgnat_ports"); assertEquals("256개", r.kv("공인 주소 수")); assertEquals("64,512개 (1024~65535)", r.kv("쓸 수 있는 포트")); assertEquals("63명 (포트 64512 ÷ 가입자당 1024, 내림)", r.kv("공인 IP 1개당 가입자 수")); assertEquals("16,128명", r.kv("수용 가능한 가입자 수")); assertFalse(r.hasKv("남는 포트 (공인 IP 1개당)")); assertFalse(r.hasError)
        assertEquals("159개".replace("159", "${Math.ceil(10000 / 63.0).toInt()}"), r.kv("가입자 10,000명에 필요한 공인 주소")); assertEquals(0, r.kvLevel("가입자 10,000명에 필요한 공인 주소")); assertEquals(-1, r.noteWith("공인 주소 여유")!!.level); assertEquals("100.64.0.0/20 (4,096개)", r.kv("안쪽 주소 대역"))
        assertEquals("333", r.kv("안쪽 주소 순번")); assertEquals("6번째", r.kv("공인 주소 순번")); assertEquals("203.0.113.5", r.kv("공인 주소")); assertEquals("19456 ~ 20479 (19번째 블록)", r.kv("포트 범위"))
        val rows = r.rows().filter { it.size == 3 }; assertEquals(listOf("100.64.0.0", "203.0.113.0", "1024~2047"), rows[0]); assertEquals(listOf("100.64.0.1", "203.0.113.0", "2048~3071"), rows[1]); assertEquals(listOf("100.64.15.255", "203.0.113.65", "1024~2047"), rows[2])
        // 공인 주소가 모자라는 경우
        val small = run("calc_cgnat_ports", "pub" to "203.0.113.0/28", "subs" to "20000", "inside" to "100.64.0.0/22", "who" to "100.64.3.255"); assertEquals(2, small.kvLevel("가입자 20,000명에 필요한 공인 주소")); assertEquals(2, small.noteWith("공인 주소가")!!.level); assertTrue(small.noteWith("수용 가능한 가입자")!!.text.contains("1,008명")); assertTrue(small.rows().any { it[1] == "(모자람)" }); assertEquals(2, small.noteWith("모자라서")!!.level)
        // 개수로 입력 · 블록 크기 영향
        val count = run("calc_cgnat_ports", "pub" to "10", "block" to "4096", "inside" to "100.64.0.0/28", "who" to "100.64.0.3"); assertEquals("10개", count.kv("공인 주소 수")); assertEquals("15명 (포트 64512 ÷ 가입자당 4096, 내림)", count.kv("공인 IP 1개당 가입자 수")); assertEquals("1번째", count.kv("공인 주소 순번")); assertEquals("(공인 주소 목록의 1번째)", count.kv("공인 주소")); assertEquals("13312 ~ 17407 (4번째 블록)", count.kv("포트 범위"))
        assertTrue(first(run("calc_cgnat_ports", "block" to "256").kv("공인 IP 1개당 가입자 수")) > first(r.kv("공인 IP 1개당 가입자 수"))); assertEquals("512개", run("calc_cgnat_ports", "block" to "1000").kv("남는 포트 (공인 IP 1개당)"))
        // 입력 확인
        for (bad in listOf("pub" to "abc", "pub" to "0", "pub" to "203.0.113.0/33", "block" to "0", "block" to "70000", "p0" to "0", "p1" to "70000", "subs" to "-5", "subs" to "x")) assertTrue(bad.toString(), run("calc_cgnat_ports", bad).hasError)
        assertTrue(run("calc_cgnat_ports", "p0" to "5000", "p1" to "4000").hasError); assertTrue(run("calc_cgnat_ports", "p0" to "1", "p1" to "100", "block" to "1024").hasError); assertTrue(run("calc_cgnat_ports", "inside" to "100.64.0.0").hasError); assertTrue(run("calc_cgnat_ports", "who" to "10.0.0.1").hasError); assertTrue(run("calc_cgnat_ports", "who" to "abc").hasError)
    }

    // ============================================================ 광링크

    @Test fun fiberBudgetMatchesPython() {
        val rows = arr("fiber"); assertEquals(5, rows.length())
        for (k in 0 until rows.length()) {
            val c = rows.getJSONObject(k); val msg = c.toString(); val b = Fiber.budget(c.getDouble("tx"), c.getDouble("rx_sens"), c.getDouble("att"), c.getDouble("km"), c.getInt("conn"), c.getDouble("cdb"), c.getInt("spl"), c.getDouble("sdb"), c.getDouble("safe"))
            relNear("$msg 광섬유", c.getDouble("fiber_loss"), b.fiberLoss); relNear("$msg 합계", c.getDouble("total"), b.totalLoss); relNear("$msg 수신", c.getDouble("rx"), b.rxDbm); relNear("$msg 여유", c.getDouble("margin"), b.marginDb); relNear("$msg 안전여유", c.getDouble("margin_safe"), b.marginAfterSafety); relNear("$msg 최대거리", c.getDouble("max_km"), b.maxKm!!)
            val r = run("calc_fiber_budget", "tx" to "${c.getDouble("tx")}", "rx" to "${c.getDouble("rx_sens")}", "type" to "직접 입력 (dB/km)", "att" to "${c.getDouble("att")}", "km" to "${c.getDouble("km")}", "conn" to "${c.getInt("conn")}", "cdb" to "${c.getDouble("cdb")}", "spl" to "${c.getInt("spl")}", "sdb" to "${c.getDouble("sdb")}", "safe" to "${c.getDouble("safe")}", "ovl" to "")
            near("$msg 화면 수신", c.getDouble("rx"), first(r.kv("받는 세기")), 0.0051); near("$msg 화면 여유", c.getDouble("margin"), first(r.kv("링크 여유")), 0.0051); if (c.getDouble("max_km") < 0) assertEquals(msg, "이 구성으로는 거리가 0 이어도 모자라요", r.kv("안전 여유를 지키는 최대 거리")) else near("$msg 화면 최대거리", c.getDouble("max_km"), first(r.kv("안전 여유를 지키는 최대 거리")), 0.0051)
            val margin = c.getDouble("margin"); assertEquals(msg, margin < 0, r.hasError); assertEquals(msg, margin >= 0 && margin < c.getDouble("safe"), r.notes().any { it.level == 1 && it.text.contains("모자라요") })
        }
    }

    @Test fun fiberToolDefaultsAndAdvice() {
        val r = run("calc_fiber_budget")                                                                                                       // 단일모드 1310nm 10km, 커넥터 4쌍, 융착 2곳
        near("광섬유 손실", 3.5, first(r.rows().first { it[0].startsWith("광섬유") }[1]), 1e-9); near("커넥터", 2.0, first(r.rows().first { it[0].startsWith("커넥터") }[1]), 1e-9); near("융착", 0.2, first(r.rows().first { it[0].startsWith("융착") }[1]), 1e-9); near("합계", 5.7, first(r.rows().first { it[0] == "합계" }[1]), 1e-9)
        assertEquals("-10.70 dBm", r.kv("받는 세기")); assertEquals("3.70 dB", r.kv("링크 여유")); assertEquals(-1, r.kvLevel("링크 여유")); assertEquals("0.70 dB", r.kv("안전 여유(3.0dB)를 뺀 여유")); assertEquals("12.00 km", r.kv("안전 여유를 지키는 최대 거리")); assertEquals(0, r.kvLevel("안전 여유를 지키는 최대 거리")); assertEquals(-1, r.noteWith("안전 여유까지 지킬 수 있어요")!!.level); assertFalse(r.hasError)
        assertEquals(1, run("calc_fiber_budget", "km" to "13").noteWith("안전 여유(3.0dB)가 모자라요")!!.level); assertFalse(run("calc_fiber_budget", "km" to "13").hasError)            // 링크는 되지만 여유가 모자람
        val far = run("calc_fiber_budget", "km" to "25"); assertEquals(2, far.noteWith("링크가 안 돼요")!!.level); assertTrue(far.hasError); assertEquals(2, far.kvLevel("링크 여유")); assertEquals(2, far.kvLevel("안전 여유를 지키는 최대 거리"))
        // 과부하: 가까운 거리·센 송신
        val close = run("calc_fiber_budget", "tx" to "2", "km" to "0.1", "conn" to "2", "spl" to "0", "ovl" to "0.5"); assertEquals(2, close.noteWith("수신 과부하")!!.level); assertTrue(close.noteWith("수신 과부하")!!.text.contains("감쇠기")); assertNull(run("calc_fiber_budget", "ovl" to "").noteWith("수신 과부하")); assertNull(r.noteWith("수신 과부하"))
        // 광섬유 종류별 대표 감쇠
        for ((t, a) in listOf("단일모드 1310nm (OS2)" to 0.35, "단일모드 1550nm (OS2)" to 0.22, "멀티모드 850nm (OM3·OM4)" to 3.0, "멀티모드 1300nm (OM3·OM4)" to 1.0, "멀티모드 850nm (OM1·OM2)" to 3.5)) assertTrue(t, run("calc_fiber_budget", "type" to t).kv("광섬유").endsWith("${"%.2f".format(a)} dB/km"))
        assertTrue(run("calc_fiber_budget", "type" to "직접 입력 (dB/km)", "att" to "0.5").kv("광섬유").endsWith("0.50 dB/km"))
        for (bad in listOf("tx" to "x", "rx" to "", "ovl" to "x", "km" to "-1", "conn" to "-1", "cdb" to "-0.1", "spl" to "x", "sdb" to "-1", "safe" to "-1")) assertTrue(bad.toString(), run("calc_fiber_budget", bad).hasError); assertTrue(run("calc_fiber_budget", "type" to "직접 입력 (dB/km)", "att" to "-1").hasError)
    }

    // ============================================================ 와이어 스피드

    @Test fun wireSpeedMatchesPythonAndWellKnownNumbers() {
        val rows = arr("wire"); assertEquals(63, rows.length())
        for (k in 0 until rows.length()) { val c = rows.getJSONObject(k); relNear(c.toString(), c.getDouble("pps"), WireSpeed.pps(c.getDouble("bps"), c.getInt("frame")), 1e-12) }
        // 널리 알려진 값 (RFC 2544·벤더 자료)
        assertEquals(1488095, WireSpeed.pps(1e9, 64).toLong()); assertEquals(14880952, WireSpeed.pps(10e9, 64).toLong()); assertEquals(148809, WireSpeed.pps(100e6, 64).toLong()); assertEquals(81274, WireSpeed.pps(1e9, 1518).toLong()); assertEquals(812743, WireSpeed.pps(10e9, 1518).toLong()); assertEquals(14880, WireSpeed.pps(10e6, 64).toLong())
        val r = run("calc_wire_speed"); assertEquals("84 바이트 (프레임 64 + 프리앰블·SFD 8 + 프레임 간 간격 12)", r.kv("선 위의 크기")); assertEquals("1488095.2 프레임/초 (1,488,095 pps)", r.kv("최대 프레임 수")); assertEquals("672.0 ns", r.kv("프레임 하나를 보내는 시간")); assertEquals("76.19% (나머지 23.81%는 프리앰블·간격)", r.kv("회선 이용 효율")); assertEquals("761.90 Mbps", r.kv("이더넷 프레임 전송량"))
        assertEquals("1 Gbps", r.kv("링크 속도")); assertEquals("547.62 Mbps (프레임당 46바이트)", r.kv("IP 데이터(IP 헤더 포함) 전송량")); assertEquals("71.43 Mbps (프레임당 6바이트)", r.kv("TCP 데이터(IPv4) 전송량")); assertEquals("214.29 Mbps (프레임당 18바이트)", r.kv("UDP 데이터(IPv4) 전송량"))
        val big = run("calc_wire_speed", "speed" to "10 Gbps", "frame" to "1518"); assertEquals("812743.8 프레임/초 (812,743 pps)", big.kv("최대 프레임 수")); near("프레임 전송량", 812743.8 * 1518 * 8 / 1e9, first(big.kv("이더넷 프레임 전송량")), 0.0006); near("TCP 데이터", 812743.8 * (1518 - 58) * 8 / 1e9, first(big.kv("TCP 데이터(IPv4) 전송량")), 0.0006); near("UDP 데이터", 812743.8 * (1518 - 46) * 8 / 1e9, first(big.kv("UDP 데이터(IPv4) 전송량")), 0.0006)
        assertTrue(big.kv("TCP 데이터(IPv4) 전송량").endsWith("(프레임당 1460바이트)")); assertTrue(big.kv("UDP 데이터(IPv4) 전송량").endsWith("(프레임당 1472바이트)")); assertTrue(big.kv("IP 데이터(IP 헤더 포함) 전송량").endsWith("(프레임당 1500바이트)"))
        val vlan = run("calc_wire_speed", "frame" to "1518", "vlan" to "VLAN 태그(4바이트) 있음"); assertTrue(vlan.kv("IP 데이터(IP 헤더 포함) 전송량").endsWith("(프레임당 1496바이트)")); assertTrue(vlan.kv("TCP 데이터(IPv4) 전송량").endsWith("(프레임당 1456바이트)"))
        val table = r.rows().filter { it.size == 6 }; assertEquals(8, table.size); assertEquals(listOf("64", "1,488,095"), table[0].take(2)); assertEquals("1518", table[6][0]); assertEquals("81,274", table[6][1]); assertEquals("9018", table[7][0]); assertEquals("13,830", table[7][1]); assertTrue(r.noteWith("64바이트는 가장 작은 프레임") != null); assertNull(big.noteWith("64바이트는 가장 작은 프레임"))
        for (bad in listOf("frame" to "63", "frame" to "x", "frame" to "20000", "frame" to "")) assertTrue(bad.toString(), run("calc_wire_speed", bad).hasError)
        for (s in listOf("10 Mbps", "100 Mbps", "2.5 Gbps", "5 Gbps", "25 Gbps", "40 Gbps", "100 Gbps", "400 Gbps")) assertFalse(s, run("calc_wire_speed", "speed" to s).hasError)
    }

    // ============================================================ Erlang

    @Test fun erlangMatchesExactFractionsInPython() {
        val rows = arr("erlang"); assertEquals(31, rows.length())
        for (k in 0 until rows.length()) {
            val c = rows.getJSONObject(k); val msg = c.toString(); val a = c.getDouble("a"); val n = c.getInt("n"); relNear("$msg B", c.getDouble("b"), Erlang.b(n, a), 1e-12)
            if (c.isNull("c")) assertEquals(msg, 1.0, Erlang.c(n, a), 0.0) else { relNear("$msg C", c.getDouble("c"), Erlang.c(n, a), 1e-11); relNear("$msg SL", c.getDouble("sl"), Erlang.serviceLevel(n, a, 180.0, 20.0), 1e-10); relNear("$msg ASA", c.getDouble("asa"), Erlang.avgWait(n, a, 180.0), 1e-11) }
        }
        val lines = arr("erlang_lines"); for (k in 0 until lines.length()) { val c = lines.getJSONObject(k); val n = Erlang.linesFor(c.getDouble("a"), c.getDouble("target")); assertEquals(c.toString(), c.getInt("lines"), n); assertTrue(Erlang.b(n, c.getDouble("a")) <= c.getDouble("target")); assertTrue(n == 1 || Erlang.b(n - 1, c.getDouble("a")) > c.getDouble("target")) }
        val ag = arr("erlang_agents"); for (k in 0 until ag.length()) { val c = ag.getJSONObject(k); assertEquals(c.toString(), c.getInt("agents"), Erlang.agentsFor(c.getDouble("a"), c.getDouble("aht"), c.getDouble("t"), c.getDouble("target"))) }
        // 교과서 값: B(4,2)=0.0952, B(5,2)=0.0367, B(10,5)=0.0184, C(2,1)=1/3 (n=2, a=1 → 1/3)
        near("B(4,2)", 0.095238, Erlang.b(4, 2.0), 1e-6); near("B(5,2)", 0.036697, Erlang.b(5, 2.0), 1e-6); near("B(10,5)", 0.018385, Erlang.b(10, 5.0), 1e-6); near("C(2,1)", 1.0 / 3, Erlang.c(2, 1.0), 1e-12); assertEquals(1.0, Erlang.b(0, 3.0), 0.0); near("B(1,a)=a/(1+a)", 2.0 / 3, Erlang.b(1, 2.0), 1e-12); assertEquals(0.0, Erlang.serviceLevel(3, 5.0, 100.0, 10.0), 0.0); assertEquals(Double.POSITIVE_INFINITY, Erlang.avgWait(5, 5.0, 100.0), 0.0)
    }

    @Test fun erlangToolModes() {
        val lines = arr("erlang_lines").getJSONObject(0)                                                                                    // 5 얼랑, 1% → 11개
        val b = run("calc_erlang", "a" to "5", "b" to "1", "m" to "Erlang B — 필요한 통화로(회선) 수"); assertEquals("${lines.getInt("lines")}개", b.kv("필요한 통화로(회선) 수")); near("그때 실패율", lines.getDouble("b_at") * 100, first(b.kv("그때 통화 실패율")), 0.0006); assertEquals("5.000 얼랑 (동시에 평균 5.0개의 통화가 진행)", b.kv("부하")); assertEquals(-1, b.kvLevel("필요한 통화로(회선) 수"))
        val table = b.rows().filter { it.size == 3 && it[0].toIntOrNull() != null }; assertEquals((8..13).toList(), table.map { it[0].toInt() }); assertEquals(listOf("아니오", "아니오", "아니오", "예", "예", "예"), table.map { it[2] }); assertEquals(-1, b.rowLevel("11"))
        // 시간당 호 수 × 통화 시간으로 입력: 300통 × 180초 = 15 얼랑 → 1% 에는 24회선
        val auto = run("calc_erlang"); assertEquals("15.000 얼랑 (동시에 평균 15.0개의 통화가 진행)", auto.kv("부하")); assertEquals("${arr("erlang_lines").getJSONObject(7).getInt("lines")}개", auto.kv("필요한 통화로(회선) 수")); assertEquals("24개", auto.kv("필요한 통화로(회선) 수"))
        val bn = run("calc_erlang", "a" to "5", "n" to "10", "m" to "Erlang B — 회선 수에 따른 통화 실패율"); near("B(10,5)", 1.8385, first(bn.kv("회선 10 개의 통화 실패율")), 0.0006); assertEquals(1, bn.kvLevel("회선 10 개의 통화 실패율")); val full = run("calc_erlang", "a" to "5", "n" to "5", "m" to "Erlang B — 회선 수에 따른 통화 실패율"); assertEquals(2, full.kvLevel("회선 5 개의 통화 실패율")); assertEquals(2, full.noteWith("회선 수 이상")!!.level)
        val ag = arr("erlang_agents").getJSONObject(0); val c = run("calc_erlang", "m" to "Erlang C — 필요한 상담원 수")
        assertEquals("${ag.getInt("agents")}명", c.kv("필요한 상담원 수")); near("SL", ag.getDouble("sl") * 100, first(c.kv("서비스 수준")), 0.06); near("C", ag.getDouble("c") * 100, first(c.kv("기다릴 확률")), 0.06); near("ASA", ag.getDouble("asa"), first(c.kv("평균 대기 시간(ASA)")), 0.06); near("점유율", 15.0 / ag.getInt("agents") * 100, first(c.kv("상담원 점유율")), 0.06)
        val tableC = c.rows().filter { it.size == 5 && it[0].toIntOrNull() != null }; assertEquals(ag.getInt("agents"), tableC.first { c.rowLevel(it[0]) == -1 }[0].toInt()); assertTrue(tableC.zipWithNext().all { (x, y) -> first(x[1]) <= first(y[1]) + 1e-9 })                    // 상담원이 늘수록 서비스 수준이 좋아짐
        val modeC = "Erlang C — 상담원 수에 따른 대기·서비스 수준"; val cn = run("calc_erlang", "m" to modeC, "n" to "19"); near("C(19,15)", ag.getDouble("c") * 100, first(cn.kv("기다릴 확률")), 0.06); val few = run("calc_erlang", "m" to modeC, "n" to "15"); assertEquals(2, few.noteWith("대기열이 끝없이")!!.level); assertTrue(few.noteWith("최소 16명") != null)
        assertEquals(1, run("calc_erlang", "m" to modeC, "n" to "16").kvLevel("상담원 점유율"))
        for ((k, v, mode) in listOf(Triple("aht", "0", ""), Triple("aht", "x", ""), Triple("a", "-1", ""), Triple("a", "abc", ""), Triple("cph", "0", ""), Triple("b", "0", ""), Triple("b", "100", ""), Triple("n", "0", "Erlang B — 회선 수에 따른 통화 실패율"), Triple("sl", "100", "Erlang C — 필요한 상담원 수"), Triple("sl", "0", "Erlang C — 필요한 상담원 수"), Triple("t", "-1", "Erlang C — 필요한 상담원 수"))) assertTrue("$k=$v", run("calc_erlang", "m" to mode.ifEmpty { "Erlang B — 필요한 통화로(회선) 수" }, k to v).hasError)
    }

    // ============================================================ 95% 요금

    @Test fun percentileMatchesNumpyAndExactFractions() {
        val rows = arr("p95"); assertEquals(56, rows.length()); var checked = 0
        for (k in 0 until rows.length()) {
            val c = rows.getJSONObject(k); if (c.isNull("xs")) continue; val xs = (0 until c.getJSONArray("xs").length()).map { c.getJSONArray("xs").getDouble(it) }
            assertEquals(c.toString(), c.getDouble("value"), Pctl.nearestRank(xs, c.getString("p").toDouble()), 0.0); assertEquals(c.toString(), c.getInt("k"), Pctl.rank(xs.size, c.getString("p").toDouble())); checked++
            val r = run("calc_p95", "s" to xs.joinToString("\n"), "p" to c.getString("p"), "u" to "Mbps", "price" to ""); near(c.toString(), c.getDouble("value"), first(r.kv("${c.getString("p")}번째 백분위")), 0.0051); near("평균", c.getDouble("avg"), first(r.kv("평균")), 0.0051); near("최댓값", c.getDouble("max"), first(r.kv("최댓값(피크)")), 0.0051)
        }
        assertTrue("작은 표본 검사 수 $checked", checked >= 20)
        val big = arr("p95_big"); for (k in 0 until big.length()) { val c = big.getJSONObject(k); val xs = (0 until c.getJSONArray("xs").length()).map { c.getJSONArray("xs").getDouble(it) }; for (p in listOf("95", "90", "99", "99.9")) { assertEquals("n=${c.getInt("n")} p=$p", c.getJSONObject("answers").getDouble(p), Pctl.nearestRank(xs, p.toDouble()), 0.0); near("도구 n=${c.getInt("n")} p=$p", c.getJSONObject("answers").getDouble(p), first(run("calc_p95", "s" to xs.joinToString(","), "p" to p, "price" to "").kv("${p}번째 백분위")), 0.0051) } }
        // 정확히 떨어지는 경계: 20개 → 19번째, 100개 → 95번째, 부동소수 오차로 한 칸 어긋나지 않아야 함
        assertEquals(19.0, Pctl.nearestRank((1..20).map { it.toDouble() }, 95.0), 0.0); assertEquals(95.0, Pctl.nearestRank((1..100).map { it.toDouble() }, 95.0), 0.0); assertEquals(20.0, Pctl.nearestRank((1..21).map { it.toDouble() }, 95.0), 0.0); assertEquals(1.0, Pctl.nearestRank(listOf(1.0), 95.0), 0.0); assertEquals(7.0, Pctl.nearestRank(listOf(7.0, 7.0, 7.0), 99.9), 0.0)
        assertEquals(8208, Pctl.rank(8640, 95.0)); assertEquals(8640 - 432, Pctl.rank(8640, 95.0)); assertEquals(8632, Pctl.rank(8640, 99.9)); assertEquals(1, Pctl.rank(3, 1.0)); assertEquals(10, Pctl.rank(10, 100.0))
    }

    @Test fun percentileToolBillingAndMessages() {
        val r = run("calc_p95"); assertEquals("20개", r.kv("샘플 수")); assertEquals("300.00 Mbps", r.kv("최댓값(피크)")); assertEquals("220.00 Mbps", r.kv("95번째 백분위")); assertEquals("1개 (위쪽 5.00%)", r.kv("버리는 샘플")); assertEquals("작은 값부터 19번째 (20 × 95.0% = 19.00, 올림)", r.kv("순위")); assertEquals("40.30 Mbps", r.kv("평균"))
        assertEquals("330000 (220.00Mbps × 1500.0)", r.kv("요금 (백분위 기준)")); assertEquals("450000", r.kv("참고: 피크 기준이었다면")); assertEquals("60450", r.kv("참고: 평균 기준이었다면")); assertEquals("73.3% (피크가 몇 번 튀어도 요금에 반영되지 않는 정도)", r.kv("피크 대비"))
        assertEquals(listOf("1", "300.00 Mbps", "버려요"), r.rows().first { it[0] == "1" }); assertEquals("예 (이 값부터 요금)", r.rows().first { it[0] == "2" }[2]); assertEquals(1, r.noteWith("샘플이 적어요")!!.level); assertTrue(r.noteWith("8,640개")!!.text.contains("432개")); assertTrue(r.noteWith("nearest-rank") != null)
        // 단위·백분위·요금
        assertEquals("0.22 Mbps", run("calc_p95", "u" to "kbps").kv("95번째 백분위")); assertEquals("220000.00 Mbps", run("calc_p95", "u" to "Gbps").kv("95번째 백분위")); assertEquals("300.00 Mbps", run("calc_p95", "p" to "99.9").kv("99.9번째 백분위")); assertEquals("22.00 Mbps", run("calc_p95", "p" to "90").kv("90번째 백분위")); assertFalse(run("calc_p95", "price" to "").hasKv("요금 (백분위 기준)"))
        // 입력 형식: 쉼표·공백·줄바꿈·세미콜론 섞어도 됨
        assertEquals("5개", run("calc_p95", "s" to "1, 2 3\n4;5").kv("샘플 수")); assertEquals("5.00 Mbps", run("calc_p95", "s" to "1, 2 3\n4;5").kv("95번째 백분위"))
        for (bad in listOf("s" to "1, x, 3", "s" to "-5", "s" to "1e999", "price" to "-1", "price" to "abc")) assertTrue(bad.toString(), run("calc_p95", bad).hasError); assertEquals(1, run("calc_p95", "s" to "").notes().single().level); assertFalse(run("calc_p95", "s" to "").hasError)
    }

    // ============================================================ 전체

    @Test fun everyPlanToolRunsWithItsDefaultsAndChoices() {
        val ids = PlanTools.ALL.map { it.id }; assertEquals(listOf("calc_raid", "calc_poe", "calc_ups", "calc_ntp_offset", "calc_mos", "calc_cgnat_ports", "calc_fiber_budget", "calc_wire_speed", "calc_erlang", "calc_p95"), ids)
        for (t in PlanTools.ALL) { assertEquals(NetGroups.PLAN, t.group); assertEquals(ToolMode.OFFLINE, t.mode); assertTrue(t.id, t.desc.length > 40); assertTrue(t.id, t.live); val r = runNetTool(t.id); assertTrue(t.id, r.outs.isNotEmpty()); assertFalse("${t.id}\n${r.text()}", r.hasError) }
        assertTrue(NetGroups.PLAN in NetGroups.ALL)
        // 선택지를 하나씩 바꿔 보면, 기본 입력과 맞지 않는 조합에서만 안내(오류)가 나와야 함:
        // RAID 0 은 일부러 붙인 경고, RAID 50·60 은 기본 디스크 4개로는 그룹을 못 나눔, 멀티모드 광섬유는 10km 를 못 감
        val expected = setOf("calc_raid/lv=RAID 0 (줄 세우기)", "calc_raid/lv=RAID 50", "calc_raid/lv=RAID 60", "calc_fiber_budget/type=멀티모드 850nm (OM3·OM4)", "calc_fiber_budget/type=멀티모드 1300nm (OM3·OM4)", "calc_fiber_budget/type=멀티모드 850nm (OM1·OM2)")
        var combos = 0; val seen = HashSet<String>()
        for (t in PlanTools.ALL) for (f in t.fields.filter { it.kind == FieldKind.CHOICE }) for (c in f.choices) { combos++; val tag = "${t.id}/${f.key}=$c"; val r = runNetTool(t.id, f.key to c); assertEquals("$tag\n${r.text()}", tag in expected, r.hasError); if (r.hasError) seen += tag }
        assertEquals(expected, seen); assertTrue("선택지 조합 수 $combos", combos >= 40)
    }
}
