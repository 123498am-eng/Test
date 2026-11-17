package com.selfcheck.app

import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import kotlin.math.PI
import kotlin.math.abs
import kotlin.math.max
import kotlin.math.sin

class VoiceEngineTest {
    private val fs = 44100
    // 포먼트 폭을 넓게 (좁으면 음높이 배음 사이에 끼어 크기가 달라 보이는 것은 실제 목소리에서도 같은 현상)
    private val vowelA = listOf(700.0 to 120.0, 1250.0 to 150.0, 2600.0 to 200.0, 3300.0 to 250.0)

    private fun warp(x: FloatArray, y: FloatArray, a: Int) = VoiceTestUtil.bestFormantWarp(VoiceTestUtil.envelope(x, a), VoiceTestUtil.envelope(y, a), fs)

    private fun engine(chain: VoiceChain, rate: Int = fs) = VoiceEngine(rate).also { it.setChain(chain) }
    private fun voice(seconds: Double, f0: Double = 120.0, rate: Int = fs) = VoiceTestUtil.vowel(rate, seconds, { t -> f0 * (1 + 0.04 * sin(2 * PI * 0.7 * t)) }, vowelA)

    @Test fun dryPathIsPerfectlyAlignedAndTransparent() {
        val x = voice(1.5)
        val y = VoiceTestUtil.run(engine(VoiceChain(emptyList(), dry = 1f)), x, block = 256)
        var err = 0.0; for (i in x.indices) err = max(err, abs((x[i] - y[i]).toDouble()))
        assertTrue("최대 오차 $err", err < 1e-5)
    }

    @Test fun pitchShiftIsAccurateAndKeepsFormants() {
        val x = voice(4.0)
        val y = VoiceTestUtil.run(engine(VoiceChain(listOf(VoiceCfg(semitones = 5f)))), x)
        val a = (2.0 * fs).toInt(); val len = 2048
        // 같은 시각의 입력·출력 음높이 비율
        val ratios = ArrayList<Double>()
        var t = a
        while (t + len + 1200 < x.size) {
            val fi = VoiceTestUtil.f0(x, fs, t, len).first; val fo = VoiceTestUtil.f0(y, fs, t, len).first
            ratios += fo / fi; t += 3000
        }
        val med = ratios.sorted()[ratios.size / 2]
        val want = Math.pow(2.0, 5.0 / 12)
        assertEquals("음높이 비율 중앙값 $med (기대 $want)", want, med, want * 0.03)
        // 목소리 굵기(포먼트)는 거의 그대로
        val w = warp(x, y, a)
        assertEquals("포먼트 이동 배율 $w (기대 1.0)", 1.0, w, 0.05)
    }

    @Test fun formantOnlyShiftMovesFormantsNotPitch() {
        val x = voice(4.0)
        val y = VoiceTestUtil.run(engine(VoiceChain(listOf(VoiceCfg(formant = 1.25f)))), x)
        val a = (2.0 * fs).toInt()
        val fi = VoiceTestUtil.f0(x, fs, a, 2048).first; val fo = VoiceTestUtil.f0(y, fs, a, 2048).first
        assertEquals("음높이는 그대로", fi, fo, fi * 0.03)
        val w = warp(x, y, a)
        assertEquals("포먼트 이동 배율 $w (기대 1.25)", 1.25, w, 0.06)
    }

    @Test fun femaleAutoMovesMaleVoiceToTargetAndShiftsFormantsModerately() {
        val x = voice(6.0, f0 = 115.0)
        val chain = VoiceChain(listOf(VoiceCfg(targetHz = 205f, formantLink = 0.30f)))
        val e = engine(chain)
        val y = VoiceTestUtil.run(e, x)
        val a = (4.0 * fs).toInt()
        val fo = VoiceTestUtil.f0(y, fs, a, 2048).first
        // 억양(±4%)이 있어 순간값은 ±6% 안
        assertEquals("출력 음높이 $fo (내 평균 ${e.tracker.userF0})", 205.0, fo, 205.0 * 0.07)
        val want = Math.pow(205.0 / 115.0, 0.30)
        val w = warp(x, y, a)
        assertEquals("포먼트 이동 배율 $w (기대 $want)", want, w, 0.06)
    }

    @Test fun alreadyFemaleVoiceIsBarelyChanged() {
        val x = voice(6.0, f0 = 205.0)
        val e = engine(VoiceChain(listOf(VoiceCfg(targetHz = 205f, formantLink = 0.30f))))
        val y = VoiceTestUtil.run(e, x)
        val a = (4.0 * fs).toInt()
        val fi = VoiceTestUtil.f0(x, fs, a, 2048).first; val fo = VoiceTestUtil.f0(y, fs, a, 2048).first
        assertEquals(fi, fo, fi * 0.06)
        val w = warp(x, y, a)
        assertEquals("이미 여성인 목소리는 굵기를 거의 안 바꿈 $w", 1.0, w, 0.05)
    }

    @Test fun monotoneRobotHasFixedPitch() {
        val x = voice(4.0)
        val y = VoiceTestUtil.run(engine(VoiceChain(listOf(VoiceCfg(monotoneHz = 100f)))), x)
        val fos = (0 until 6).map { VoiceTestUtil.f0(y, fs, (1.5 * fs).toInt() + it * 6000, 2048).first }
        for (f in fos) assertEquals("고정 음높이 $fos", 100.0, f, 4.0)
    }

    @Test fun silenceStaysSilentAndNothingIsNaN() {
        for (p in VoicePresets.ALL.filter { it.chain.whisper == 0f && it.id != "telephone" && it.id != "bitcrush" }) {
            val y = VoiceTestUtil.run(engine(p.chain), FloatArray(fs)) 
            assertTrue("${p.id} 무음 → rms ${VoiceTestUtil.rms(y)}", VoiceTestUtil.rms(y) < 1e-4)
        }
    }

    @Test fun everyPresetIsStableLoudEnoughAndFast() {
        val x = voice(3.0)
        val noise = java.util.Random(3)
        // 모음 뒤에 마찰음(잡음)과 쉬는 구간
        val sig = x + FloatArray(fs / 2) { (noise.nextGaussian() * 0.08).toFloat() } + FloatArray(fs / 4) + voice(1.0, 180.0)
        val inRms = VoiceTestUtil.rms(sig)
        var worst = 0.0
        for (p in VoicePresets.ALL) {
            val e = engine(p.chain)
            val t0 = System.nanoTime()
            val y = VoiceTestUtil.run(e, sig)
            val rtf = (System.nanoTime() - t0) / 1e9 / (sig.size.toDouble() / fs)
            worst = max(worst, rtf)
            assertTrue("${p.id}: NaN/무한대", y.all { it.isFinite() })
            assertTrue("${p.id}: 최대 ${y.maxOf { abs(it) }}", y.maxOf { abs(it) } <= 1.0001f)
            val ratio = VoiceTestUtil.rms(y) / inRms
            assertTrue("${p.id}: 음량 비 $ratio", ratio in 0.55..1.8)
            assertTrue("${p.id}: 처리가 느림 rtf=$rtf", rtf < 0.5)
        }
        println("가장 느린 프리셋 실시간 배율(처리시간/소리길이): ${"%.3f".format(worst)}")
    }

    @Test fun noClicksWhenSwitchingPresetsMidStream() {
        val x = voice(4.0)
        val e = VoiceEngine(fs); e.setChain(VoicePresets.byId("fem_natural")!!.chain)
        val out = FloatArray(x.size); val b = 256; val ob = FloatArray(b)
        var p = 0; var switched = 0
        while (p + b <= x.size) {
            if (p > 0 && p % (fs / 2) < b) { e.setChain(VoicePresets.ALL[(switched++ * 7) % VoicePresets.ALL.size].chain) }
            e.process(x.copyOfRange(p, p + b), b, ob); System.arraycopy(ob, 0, out, p, b); p += b
        }
        assertTrue(out.all { it.isFinite() && abs(it) <= 1.0001f })
        var maxJump = 0f; for (i in 1 until out.size) maxJump = max(maxJump, abs(out[i] - out[i - 1]))
        assertTrue("큰 끊김 $maxJump", maxJump < 0.8f)
    }

    @Test fun worksAtOtherSampleRatesAndBlockSizes() {
        for (rate in listOf(16000, 22050, 48000)) {
            val x = voice(4.0, rate = rate)
            for (block in listOf(64, 480, 1024)) {
                val y = VoiceTestUtil.run(engine(VoiceChain(listOf(VoiceCfg(semitones = 4f))), rate), x, block)
                val a = (2.5 * rate).toInt()
                val ratio = VoiceTestUtil.f0(y, rate, a, 2048).first / VoiceTestUtil.f0(x, rate, a, 2048).first
                assertEquals("rate=$rate block=$block 비 $ratio", Math.pow(2.0, 4.0 / 12), ratio, 0.05)
            }
        }
    }

    @Test fun controlsChangeLiveWithoutRebuilding() {
        val x = voice(4.0)
        val e = engine(VoiceChain(listOf(VoiceCfg())))
        e.controls.semitoneOffset = 6f
        val y = VoiceTestUtil.run(e, x)
        val a = (2.5 * fs).toInt()
        val ratio = VoiceTestUtil.f0(y, fs, a, 2048).first / VoiceTestUtil.f0(x, fs, a, 2048).first
        assertEquals(Math.pow(2.0, 0.5), ratio, 0.04)
    }

    @Test fun whisperHasNoPitchAndSimilarLevel() {
        val x = voice(3.0)
        val y = VoiceTestUtil.run(engine(VoicePresets.byId("whisper")!!.chain), x)
        val a = (1.5 * fs).toInt()
        val level = VoiceTestUtil.rms(y, a, a + 20000) / VoiceTestUtil.rms(x, a, a + 20000)
        val (_, corr) = VoiceTestUtil.f0(y, fs, a, 2048)
        assertTrue("음량 비 $level", level in 0.2..3.0)
        assertTrue("주기성(자기상관) $corr — 속삭임은 음높이가 없어야 함", corr < 0.5)
    }

    @Test fun presetCatalog() {
        val all = VoicePresets.ALL
        assertTrue("프리셋 ${all.size}개", all.size >= 40)
        assertEquals(all.size, all.map { it.id }.toSet().size)
        assertEquals(all.size, all.map { it.name }.toSet().size)
        assertTrue("여성 프리셋", all.count { it.group == "여성" } >= 5)
        assertTrue(all.all { it.group in VoicePresets.GROUPS && it.desc.isNotBlank() })
        // 변조 종류 30가지 이상 (원음 제외)
        assertTrue(all.count { it.id != "dry" } >= 30)
    }

    /** 대역 제한 효과가 실제로 그 대역만 남기는지: 백색잡음을 넣고 대역별 에너지 비율 확인 */
    @Test fun bandLimitingEffectsReallyLimitTheBand() {
        val rnd = java.util.Random(5)
        val noise = FloatArray(fs * 2) { (rnd.nextGaussian() * 0.1).toFloat() }
        fun bandFrac(y: FloatArray, lo: Double, hi: Double): Double {
            val a = fs / 2
            val env = VoiceTestUtil.envelope(y, a, frames = 1, hop = 0, n = 4096, lifter = 4000)
            var tot = 0.0; var band = 0.0
            for (k in env.indices) { val f = k * fs.toDouble() / 4096; val p = Math.exp(2 * env[k]); tot += p; if (f in lo..hi) band += p }
            return band / tot
        }
        val tel = VoiceTestUtil.run(engine(VoicePresets.byId("telephone")!!.chain), noise)
        assertTrue("전화기: 300~3400Hz 비율 ${bandFrac(tel, 300.0, 3400.0)}", bandFrac(tel, 280.0, 3500.0) > 0.9)
        val uw = VoiceTestUtil.run(engine(VoicePresets.byId("underwater")!!.chain), noise)
        assertTrue("수중: 1.5kHz 아래 비율 ${bandFrac(uw, 0.0, 1500.0)}", bandFrac(uw, 0.0, 1500.0) > 0.85)
    }

    @Test fun echoAndReverbProduceTailsAfterInputStops() {
        val x = voice(1.0) + FloatArray(fs * 2)
        val echo = VoiceTestUtil.run(engine(VoicePresets.byId("echo")!!.chain), x)
        val dry = VoiceTestUtil.run(engine(VoicePresets.byId("dry")!!.chain), x)
        val a = fs + fs / 3; val b = a + fs / 4 // 입력이 끝난 직후 0.33~0.58초
        assertTrue("에코 꼬리 ${VoiceTestUtil.rms(echo, a, b)}", VoiceTestUtil.rms(echo, a, b) > 0.005)
        assertTrue("원음은 조용 ${VoiceTestUtil.rms(dry, a, b)}", VoiceTestUtil.rms(dry, a, b) < 1e-4)
        val cave = VoiceTestUtil.run(engine(VoicePresets.byId("cathedral")!!.chain), x)
        assertTrue("잔향 꼬리 ${VoiceTestUtil.rms(cave, a, b)}", VoiceTestUtil.rms(cave, a, b) > 0.003)
        // 꼬리가 점점 작아져야 함 (폭주 없음)
        assertTrue(VoiceTestUtil.rms(cave, fs * 2, fs * 2 + 20000) < VoiceTestUtil.rms(cave, a, b))
    }

    @Test fun commonVoicePresetsNeverRunOutOfLookahead() {
        val x = voice(5.0, 115.0)
        for (id in listOf("fem_natural", "fem_bright", "girl", "male_natural", "child", "helium", "robot", "autotune_hard")) {
            val e = engine(VoicePresets.byId(id)!!.chain); VoiceTestUtil.run(e, x)
            assertEquals("$id 미리 읽기 부족", 0, e.underruns)
        }
    }
}
