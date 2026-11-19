package com.selfcheck.app

import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import kotlin.math.PI
import kotlin.math.abs
import kotlin.math.ln
import kotlin.math.max
import kotlin.math.sin
import kotlin.math.sqrt

/** 자연스러움을 위한 개선(파형 보간, 비브라토 시작 지연, 숨소리 굵기 이동, 잔향·에코 등)이 실제로 동작하는지 */
class VoiceNaturalnessTest {
    private val fs = 44100
    private val vowelA = listOf(700.0 to 120.0, 1250.0 to 150.0, 2600.0 to 200.0, 3300.0 to 250.0)
    private fun vowel(seconds: Double, f0: Double = 120.0) = VoiceTestUtil.vowel(fs, seconds, { t -> f0 * (1 + 0.03 * sin(2 * PI * 0.7 * t)) }, vowelA)

    /** 주기마다 크기가 ±10% 쯤 다른 모음 (실제 목소리의 진폭 흔들림). 완전히 규칙적인 소리에서는 되풀이 잡음이 드러나지 않음 */
    private fun shimmerVowel(seconds: Double, f0: Double = 120.0): FloatArray {
        val v = vowel(seconds, f0)
        val rnd = java.util.Random(4)
        val period = fs / f0
        val gains = DoubleArray((seconds * f0).toInt() + 3) { 1 + 0.10 * (rnd.nextDouble() * 2 - 1) }
        return FloatArray(v.size) { i -> val p = i / period; val k = p.toInt(); val f = p - k; (v[i] * (gains[k] * (1 - f) + gains[k + 1] * f)).toFloat() }
    }

    private fun engine(chain: VoiceChain) = VoiceEngine(fs).also { it.setChain(chain) }

    /** 입력에 섞여 들어가는 아주 작은 마이크 잡음 */
    private fun withNoise(x: FloatArray, level: Float = 0.0005f): FloatArray { val r = java.util.Random(11); return FloatArray(x.size) { x[it] + (r.nextGaussian() * level).toFloat() } }

    /** 한 번 돌리면서 조각마다 (시각, 의도한 출력 Hz) 를 모음 */
    private fun traced(chain: VoiceChain, x: FloatArray, interpolate: Boolean = true): Pair<FloatArray, List<Pair<Double, Float>>> {
        val e = engine(chain)
        val pts = ArrayList<Pair<Double, Float>>()
        val padded = x + FloatArray(((x.size + e.latency + 479) / 480) * 480 - x.size)
        val out = FloatArray(padded.size); val ib = FloatArray(480); val ob = FloatArray(480)
        var p = 0
        while (p + 480 <= padded.size) {
            System.arraycopy(padded, p, ib, 0, 480)
            e.process(ib, 480, ob)
            if (p == 0) e.debugVoice?.let { v -> v.interpolate = interpolate; v.trace = { t, _, fo, _ -> pts += t to fo } }
            System.arraycopy(ob, 0, out, p, 480); p += 480
        }
        return out.copyOfRange(e.latency, e.latency + x.size) to pts
    }

    private fun cents(a: Float, b: Float) = 1200.0 * ln((a / b).toDouble()) / ln(2.0)

    @Test fun vibratoFadesInAfterTheVoiceStartsInsteadOfStartingAtOnce() {
        val x = FloatArray((0.4 * fs).toInt()) + VoiceTestUtil.vowel(fs, 2.0, { 120.0 }, vowelA) // 음높이 일정: 떨림만 따로 보기 위해
        val (_, pts) = traced(VoiceChain(listOf(VoiceCfg(vibratoHz = 5.5f, vibratoCents = 40f, vibratoOnsetMs = 200f)), matchLevel = false), withNoise(x))
        val start = pts.first { it.first > 0.35 }.first
        fun swing(a: Double, b: Double): Double {
            val v = pts.filter { it.first in start + a..start + b }.map { it.second }
            val mid = v.sorted()[v.size / 2]
            return v.maxOf { cents(it, mid) } - v.minOf { cents(it, mid) }
        }
        val early = swing(0.0, 0.12); val late = swing(0.8, 1.6)
        assertTrue("시작 직후 떨림 폭 $early 센트, 나중 $late 센트", early < 20.0 && late > 55.0)
    }

    @Test fun waveformInterpolationMakesNeighbouringOutputCyclesChangeSmoothly() {
        // 음높이를 한 옥타브 올리면 입력의 한 주기를 두 번씩 되풀이해서, 출력 주기가 "같음-다름-같음-다름"으로 번갈아 바뀜 (원래 음높이로 웅웅거림).
        // 이웃한 주기를 섞으면 주기마다 고르게 조금씩 바뀜. 이웃 출력 주기 사이 차이의 변동계수(표준편차/평균)로 비교.
        val x = withNoise(shimmerVowel(3.0))
        fun alternation(interp: Boolean): Double {
            val (y, pts) = traced(VoiceChain(listOf(VoiceCfg(semitones = 12f)), matchLevel = false), x, interp)
            val t = fs / 240.0
            val centers = pts.map { it.first * fs }.filter { it > fs && it < 2.2 * fs }
            val len = t.toInt()
            val diffs = ArrayList<Double>()
            for (k in 0 until centers.size - 1) {
                val a = (centers[k] - len / 2).toInt(); val b = (centers[k + 1] - len / 2).toInt()
                var d = 0.0; var e = 1e-12
                for (i in 0 until len) { val u = y[a + i]; val v = y[b + i]; d += (u - v) * (u - v); e += u * u }
                diffs += d / e
            }
            val m = diffs.average()
            return sqrt(diffs.sumOf { (it - m) * (it - m) } / diffs.size) / m
        }
        val smooth = alternation(true); val repeated = alternation(false)
        assertTrue("이웃 주기 차이의 변동계수: 보간 $smooth vs 반복 $repeated", smooth < repeated * 0.7)
    }

    @Test fun interpolationKeepsPitchAccurateAndStillWorksWhenLoweringPitch() {
        val x = withNoise(vowel(4.0))
        for (semi in listOf(12f, 7f, 3f, -4f, -9f)) {
            val y = traced(VoiceChain(listOf(VoiceCfg(semitones = semi)), matchLevel = false), x).first
            val a = 2 * fs
            val ratio = VoiceTestUtil.f0(y, fs, a, 2048, 50.0, 600.0).first / VoiceTestUtil.f0(x, fs, a, 2048).first
            val want = Math.pow(2.0, semi / 12.0)
            assertEquals("$semi 반음: 비 $ratio", want, ratio, want * 0.04)
            assertTrue(y.all { it.isFinite() })
        }
    }

    @Test fun breathNoiseMovesWithTheFormantsLikeTheVoice() {
        val x = withNoise(vowel(3.0))
        fun run(beta: Float): FloatArray {
            val e = engine(VoiceChain(emptyList(), whisper = 1f, breathTilt = 0.95, matchLevel = false))
            e.controls.formantScale = beta
            return VoiceTestUtil.run(e, x)
        }
        val a = fs
        val w = VoiceTestUtil.bestFormantWarp(VoiceTestUtil.envelope(run(1f), a, lifter = 60), VoiceTestUtil.envelope(run(1.3f), a, lifter = 60), fs)
        assertTrue("굵기 1.0 → 1.3 일 때 숨소리 스펙트럼 이동 배율 $w (기대 1.3)", w in 1.15..1.45)
    }

    @Test fun reverbWaitsForThePreDelayBeforeTheTailStarts() {
        val fx = Reverb(fs, 0.7f, 0.4f, 0.5f, preDelayMs = 20f)
        val b = FloatArray(4000); b[0] = 1f
        fx.process(b, b.size, 1f)
        val pre = (fs * 0.020).toInt()
        // 입력 펄스 자체(0번)를 빼고, 프리딜레이 동안은 잔향이 없어야 함
        val early = (1 until pre - 2).maxOf { abs(b[it]) }
        val late = (pre + 100 until 4000).maxOf { abs(b[it]) }
        assertTrue("프리딜레이 동안 $early, 이후 $late", early < 1e-6f && late > 1e-4f)
    }

    @Test fun echoRepeatsGetDarker() {
        val rnd = java.util.Random(2)
        val d = fs / 5 // 200ms
        val b = FloatArray(d * 4)
        for (i in 0 until 600) b[i] = (rnd.nextGaussian() * 0.3).toFloat() // 짧은 백색잡음 한 번
        Echo(fs, 200f, 0.7f, 1f, damp = 0.5f).process(b, b.size, 1f)
        fun hiFrac(k: Int): Double {
            var hi = 0.0; var all = 1e-12
            for (i in k * d until k * d + 600) { val s = b[i].toDouble(); all += s * s; if (i > k * d) { val dd = (b[i] - b[i - 1]).toDouble(); hi += dd * dd } }
            return hi / all
        }
        assertTrue("고음 비율 1번째 ${hiFrac(1)} → 3번째 ${hiFrac(3)}", hiFrac(3) < hiFrac(1) * 0.8)
    }

    @Test fun autotuneGlidesBetweenNotesInsteadOfJumping() {
        // 음이 120Hz 에서 130Hz 쪽으로 서서히 올라가는 소리: 오토튠 (부드럽게)는 계단 대신 매끈한 곡선
        val x = withNoise(VoiceTestUtil.vowel(fs, 3.0, { t -> 122.0 * Math.pow(2.0, 0.9 * t / 12) }, vowelA))
        val (_, soft) = traced(VoiceChain(listOf(VoiceCfg(snap = 1f, retuneMs = 70f)), matchLevel = false), x)
        val (_, hard) = traced(VoiceChain(listOf(VoiceCfg(snap = 1f, retuneMs = 4f)), matchLevel = false), x)
        fun maxJump(p: List<Pair<Double, Float>>): Double = p.filter { it.first > 0.5 }.zipWithNext().maxOf { (a, b) -> abs(cents(b.second, a.second)) }
        assertTrue("부드럽게 ${maxJump(soft)}센트 / 강하게 ${maxJump(hard)}센트", maxJump(soft) < maxJump(hard) && maxJump(soft) < 40.0)
    }

    @Test fun ensembleVoicesDriftDifferentlySoTheyDoNotPhaseLockIntoOneRobot() {
        val x = withNoise(vowel(4.0))
        val e = engine(VoicePresets.byId("choir")!!.chain)
        val y = VoiceTestUtil.run(e, x)
        assertTrue(y.all { it.isFinite() })
        // 합창 각 겹의 출력 음높이가 시간에 따라 서로 다른 방향으로 흔들리는지: 음높이 비 시계열의 상관이 1 이 아님
        val vs = listOf(VoiceCfg(semitones = 4f, driftCents = 8f, formant = 1.03f), VoiceCfg(semitones = 7f, driftCents = 8f, formant = 0.97f))
        val series = vs.map { cfg ->
            val (_, pts) = traced(VoiceChain(listOf(cfg), matchLevel = false), x)
            pts.filter { it.first > 0.5 }.map { cents(it.second, (120f * Math.pow(2.0, cfg.semitones / 12.0)).toFloat()) }
        }
        val n = minOf(series[0].size, series[1].size)
        val a = series[0].take(n); val b = series[1].take(n)
        val ma = a.average(); val mb = b.average()
        val corr = a.indices.sumOf { (a[it] - ma) * (b[it] - mb) } / sqrt(a.sumOf { (it - ma) * (it - ma) } * b.sumOf { (it - mb) * (it - mb) } + 1e-9)
        assertTrue("겹 사이 음높이 흔들림 상관 $corr", corr < 0.95)
    }

    private fun corr(a: FloatArray, b: FloatArray, from: Int, n: Int): Double {
        var ab = 0.0; var aa = 1e-12; var bb = 1e-12
        for (i in from until from + n) { ab += a[i] * b[i]; aa += a[i] * a[i]; bb += b[i] * b[i] }
        return ab / sqrt(aa * bb)
    }

    @Test fun originalVoiceCanBeMixedInOrLeftOut() {
        val x = withNoise(vowel(4.0))
        val cfg = VoiceChain(listOf(VoiceCfg(semitones = 5f)), matchLevel = false) // 완전 4도 위로 바꾼 소리 (옥타브 정수배는 펄스가 절반 겹쳐서 제외)
        val off = VoiceTestUtil.run(engine(cfg), x)
        val on = VoiceTestUtil.run(engine(cfg).also { it.controls.originalLevel = 1f }, x)
        val cOff = corr(off, x, fs, 2 * fs); val cOn = corr(on, x, fs, 2 * fs)
        // 끔: 변조된 소리만 (원본과 파형이 다름), 켬: 원본이 시간 맞춰 함께 들어 있어 원본과 뚜렷이 닮음
        assertTrue("원본과의 상관 끔 $cOff / 켬 $cOn", cOff < 0.35 && cOn > 0.55 && cOn > cOff + 0.3)
    }

    @Test fun togglingOriginalMixMidSentenceDoesNotClick() {
        val x = withNoise(vowel(3.0))
        val e = engine(VoiceChain(listOf(VoiceCfg(semitones = 12f)), matchLevel = false))
        val out = FloatArray(x.size); val ib = FloatArray(480); val ob = FloatArray(480)
        var p = 0
        while (p + 480 <= x.size) {
            if (p == fs) e.controls.originalLevel = 1f            // 1초 지점에서 켜고
            if (p == 2 * fs) e.controls.originalLevel = 0f        // 2초 지점에서 끔
            System.arraycopy(x, p, ib, 0, 480); e.process(ib, 480, ob); System.arraycopy(ob, 0, out, p, 480); p += 480
        }
        for (at in listOf(fs, 2 * fs)) {
            val seg = (at + e.latency - 200 until at + e.latency + 600)
            var worst = 0f; for (i in seg) worst = max(worst, abs(out[i] - out[i - 1]))
            assertTrue("켜고 끌 때 최대 변화 $worst", worst < 0.25f)
        }
    }

    @Test fun effectOnlyPresetsAreTheOnesWhereOriginalCannotBeSwitchedOff() {
        val effectOnly = VoicePresets.ALL.filter { it.chain.isEffectOnly }.map { it.id }.toSet()
        for (id in listOf("dry", "echo", "cave", "cathedral", "bathroom", "telephone", "radio", "megaphone", "underwater", "flanger", "tremolo", "bitcrush", "studio", "chorus"))
            assertTrue("$id 는 효과 전용", id in effectOnly)
        for (id in listOf("fem_natural", "girl_thin", "news_m_anchor", "whisper", "demon", "choir", "robot"))
            assertTrue("$id 는 목소리를 바꾸는 프리셋", id !in effectOnly)
        // 목소리를 바꾸는 프리셋에는 고정으로 원본이 섞여 있지 않음 (원본 섞기는 화면 스위치로만)
        assertTrue(VoicePresets.ALL.filter { !it.chain.isEffectOnly }.all { it.chain.dry == 0f })
    }
}
