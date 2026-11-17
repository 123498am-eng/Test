package com.selfcheck.app

import kotlin.math.PI
import kotlin.math.abs
import kotlin.math.exp
import kotlin.math.floor
import kotlin.math.ln
import kotlin.math.max
import kotlin.math.min
import kotlin.math.pow
import kotlin.math.roundToInt
import kotlin.math.sin
import kotlin.math.sqrt
import kotlin.math.tanh

/*
 * 실시간 음성 변조 엔진 (안드로이드에 의존하지 않는 순수 Kotlin → 컴퓨터에서도 시험 가능)
 *
 * 자연스러운 소리를 위해 음높이(피치)와 목소리 굵기(포먼트)를 따로 바꿉니다:
 *  1) PitchTracker: YIN 방식으로 목소리 높이(기본 주기)와 유성음 여부를 약 6ms 마다 추정
 *  2) PsolaVoice: 주기 두 개 길이의 조각(grain)을 잘라, 새 음높이 간격으로 겹쳐 붙이는 PSOLA.
 *     조각을 빠르게/느리게 읽으면(β) 목소리 굵기(포먼트)만 바뀝니다. 조각의 위치는 앞 조각과
 *     파형이 가장 비슷한 곳으로 맞춰서(파형 정렬) 떨림·잡음을 줄입니다.
 *  3) 무성음(ㅅ, ㅍ 등)은 10ms 간격 고정 조각으로 처리해 음높이 변화 없이 자연스럽게 통과
 *  4) 효과(에코·리버브·코러스·필터 등)와 속삭임(LPC 잡음 합성)
 */

/** 입력 소리를 저장하는 순환 저장소 */
class AudioRing(sizePow: Int = 17) {
    val size = 1 shl sizePow
    private val mask = (size - 1).toLong()
    private val data = FloatArray(size)
    var n = 0L; private set

    fun push(src: FloatArray, len: Int) {
        for (i in 0 until len) data[((n + i) and mask).toInt()] = src[i]
        n += len
    }

    fun get(i: Long): Float = if (i < 0 || i >= n || n - i >= size - 8) 0f else data[(i and mask).toInt()]

    /** 소수 위치의 값 (3차 보간) */
    fun at(pos: Double): Float {
        val p = floor(pos); val f = (pos - p).toFloat(); val i = p.toLong()
        val y0 = get(i - 1); val y1 = get(i); val y2 = get(i + 1); val y3 = get(i + 2)
        return y1 + 0.5f * f * (y2 - y0 + f * (2f * y0 - 5f * y1 + 4f * y2 - y3 + f * (3f * (y1 - y2) + y3 - y0)))
    }
}

/** 목소리 높이 추적 (YIN) */
class PitchTracker(val fs: Int, private val ring: AudioRing) {
    private val dFactor = max(1, (fs / 11025.0).roundToInt())
    private val fsd = fs / dFactor
    private val tauMin = max(2, fsd / 500)
    private val tauMax = fsd / 60
    private val w = tauMax
    private val need = w + tauMax + 2
    private val dec = FloatArray(4096)
    private var nDec = 0L
    private var accum = 0f
    private var accN = 0
    private var lastFrameDec = 0L
    private val hop = max(32, fsd / 170)
    private val tmp = FloatArray(need)
    private val d = FloatArray(tauMax + 2)
    private val cm = FloatArray(tauMax + 2)

    private val FR = 2048
    private val fCenter = LongArray(FR)
    private val fPeriod = FloatArray(FR)
    var nFrames = 0; private set
    /** 가장 최근 분석 위치 (입력 시간축) */
    @Volatile var lastCenter = -1L; private set
    @Volatile var userF0 = 120f; private set
    @Volatile var curF0 = 0f; private set
    @Volatile var level = 0f; private set
    private var logMean = ln(120.0)
    private var voicedCount = 0
    private var lastTau = 0f
    private var voicedRms = 0.05f
    private var sinceVoiced = 99

    /** 이 소리 크기(rms) 아래는 무음으로 봄 */
    var gate = 0.004f

    fun push(src: FloatArray, len: Int) {
        for (i in 0 until len) {
            accum += src[i]
            if (++accN == dFactor) {
                dec[(nDec and 4095).toInt()] = accum / dFactor
                nDec++; accum = 0f; accN = 0
                if (nDec - lastFrameDec >= hop && nDec >= need) { frame(); lastFrameDec = nDec }
            }
        }
    }

    private fun frame() {
        val start = nDec - need
        var e = 0.0
        for (j in 0 until need) { val v = dec[((start + j) and 4095).toInt()]; tmp[j] = v; e += v * v }
        val rms = sqrt(e / need).toFloat()
        level = rms
        val endFull = nDec * dFactor
        val center = endFull - (need.toLong() * dFactor) / 2
        var period = 0f
        if (rms >= gate) {
            for (tau in 1..tauMax) {
                var s = 0.0
                for (j in 0 until w) { val df = tmp[j] - tmp[j + tau]; s += df * df }
                d[tau] = s.toFloat()
            }
            var run = 0f
            cm[0] = 1f
            for (tau in 1..tauMax) { run += d[tau]; cm[tau] = if (run > 0f) d[tau] * tau / run else 1f }
            var tau = -1
            var t = tauMin
            while (t < tauMax) {
                if (cm[t] < 0.15f) { while (t + 1 < tauMax && cm[t + 1] < cm[t]) t++; tau = t; break }
                t++
            }
            if (tau < 0) {
                var best = tauMin
                for (k in tauMin until tauMax) if (cm[k] < cm[best]) best = k
                if (cm[best] < 0.35f) tau = best
            }
            // 직전 음높이와 이어지는 후보는 느슨한 기준으로도 받아들임 (말끝·모음 전환에서 끊기지 않게)
            if (tau < 0 && lastTau > 0 && sinceVoiced < 10) {
                val lo = max(tauMin, (lastTau * 0.85f).toInt()); val hi = min(tauMax - 2, (lastTau * 1.15f).toInt() + 1)
                var best = -1
                for (k in lo..hi) if (best < 0 || cm[k] < cm[best]) best = k
                if (best > 0 && cm[best] < 0.5f) tau = best
            }
            // 갑작스런 옥타브 점프는 직전 음높이 근처 후보로 되돌림
            if (tau > 0 && lastTau > 0 && sinceVoiced < 6) {
                val r = tau / lastTau
                if ((r < 0.7f || r > 1.43f) && cm[tau] > 0.08f) {
                    val lo = max(tauMin, (lastTau * 0.85f).toInt()); val hi = min(tauMax - 2, (lastTau * 1.15f).toInt() + 1)
                    var best = -1
                    for (k in lo..hi) if (best < 0 || cm[k] < cm[best]) best = k
                    if (best > 0 && cm[best] < 0.5f) tau = best
                }
            }
            if (tau >= 2 && tau < tauMax - 1) {
                val a = cm[tau - 1]; val b = cm[tau]; val c = cm[tau + 1]
                val den = a - 2 * b + c
                val off = if (abs(den) > 1e-9f) 0.5f * (a - c) / den else 0f
                val tauF = tau + off.coerceIn(-1f, 1f)
                period = refine(endFull, tauF * dFactor)
                lastTau = tauF; sinceVoiced = 0
                voicedRms += 0.1f * (rms - voicedRms)
                if (cm[tau] < 0.12f) updateUser(fs / period)
            } else if (lastTau > 0 && sinceVoiced < 5 && rms > 0.35f * voicedRms) {
                period = refine(endFull, lastTau * dFactor) // 목소리 끝자락: 소리가 아직 크면 직전 음높이를 잠깐 유지
            }
        }
        if (period <= 0f) sinceVoiced++ else if (sinceVoiced > 0 && lastTau > 0 && period > 0f && sinceVoiced < 5) sinceVoiced++
        val k = nFrames % FR
        fCenter[k] = center; fPeriod[k] = period
        nFrames++
        lastCenter = center
        curF0 = if (period > 0f) fs / period else 0f
    }

    /** 원래 표본 속도에서 자기상관이 가장 큰 간격으로 다듬기 */
    private fun refine(end: Long, t0: Float): Float {
        val wf = (2 * t0).toInt().coerceIn(64, 2400)
        val lo = (t0 - dFactor).toInt().coerceAtLeast(8); val hi = (t0 + dFactor).toInt() + 1
        val r = DoubleArray(hi - lo + 1)
        var bi = 0
        for (l in lo..hi) {
            var sab = 0.0; var saa = 0.0; var sbb = 0.0
            for (i in 0 until wf) {
                val a = ring.get(end - wf + i); val b = ring.get(end - wf + i - l)
                sab += a * b; saa += a * a; sbb += b * b
            }
            val v = sab / sqrt(saa * sbb + 1e-12)
            r[l - lo] = v
            if (v > r[bi]) bi = l - lo
        }
        var off = 0.0
        if (bi > 0 && bi < r.size - 1) {
            val a = r[bi - 1]; val b = r[bi]; val c = r[bi + 1]
            val den = a - 2 * b + c
            if (abs(den) > 1e-12) off = (0.5 * (a - c) / den).coerceIn(-1.0, 1.0)
        }
        return (lo + bi + off).toFloat()
    }

    private fun updateUser(f: Float) {
        if (f < 70f || f > 500f) return
        voicedCount++
        val c = max(0.002, 1.0 / voicedCount)
        logMean += c * (ln(f.toDouble()) - logMean)
        userF0 = exp(logMean).toFloat()
    }

    private fun idx(k: Int) = k % FR

    /** 입력 시간 t 에서의 주기 (표본 수). 무성음·무음이면 0 */
    fun periodAt(t: Long): Float {
        var k = nFrames - 1
        val oldest = max(0, nFrames - FR + 1)
        while (k >= oldest && fCenter[idx(k)] > t) k--
        if (k < oldest) return 0f
        val p = fPeriod[idx(k)]
        if (p <= 0f) return 0f
        if (k - 1 >= oldest && k + 1 < nFrames) {
            val a = fPeriod[idx(k - 1)]; val c = fPeriod[idx(k + 1)]
            if (a > 0f && c > 0f) return median3(a, p, c)
        }
        return p
    }

    private fun median3(a: Float, b: Float, c: Float) = max(min(a, b), min(max(a, b), c))
}

// ---------------------------------------------------------------- 음높이·굵기 바꾸기

/**
 * 목소리 한 겹의 설정.
 * 자동 목표 음높이(targetHz > 0): 내 평소 음높이를 알아내 그 높이로 옮기고, 억양(높낮이의 움직임)은 그대로 둡니다.
 * formantLink: 음높이를 올린 비율의 몇 제곱만큼 목소리 굵기(포먼트)도 함께 옮길지 (여성 변환은 약 0.3, 만화 목소리는 1)
 */
class VoiceCfg(
    val semitones: Float = 0f,
    val targetHz: Float = 0f,
    val intonation: Float = 1f,
    val formant: Float = 1f,
    val formantLink: Float = 0f,
    val gain: Float = 1f,
    val monotoneHz: Float = 0f,
    val snap: Float = 0f,
    val vibratoHz: Float = 0f,
    val vibratoCents: Float = 0f,
    val delayMs: Float = 0f,
)

/** 위의 설정에 따라 음높이·굵기를 바꾸는 한 겹 (PSOLA) */
class PsolaVoice(private val fs: Int, private val ring: AudioRing, private val tracker: PitchTracker,
                 val cfg: VoiceCfg, private val ctl: VoiceControls, startTimeline: Long) {
    private val outSize = 1 shl 14
    private val outMask = (outSize - 1).toLong()
    private val acc = FloatArray(outSize)
    private val wgt = FloatArray(outSize)
    /** 다음에 놓을 조각의 가운데 (입력 시간축과 같은 시간축) */
    private var s = startTimeline.toDouble() - cfg.delayMs * fs / 1000.0
    private var prevCenter = -1L
    private val unvoicedHop = (fs * 0.010).toInt()
    private val lMax = (fs * 0.0225).toInt()          // 조각 반길이 상한 (약 22ms)
    private val tMin = fs / 650f
    private val tMax = fs / 60f
    var underruns = 0; private set
    var grains = 0; private set
    private var lastLOut = 200
    @Volatile var lastOutHz = 0f

    // 정렬용 임시 배열
    private val refSeg = FloatArray(4096)

    fun render() {
        val lastC = tracker.lastCenter
        while (true) {
            if (s > lastC) break
            val tInRaw = tracker.periodAt(s.toLong())
            val voiced = tInRaw > 0f
            val tIn = if (voiced) tInRaw.coerceIn(fs / 520f, fs / 58f) else unvoicedHop.toFloat()
            val fIn = fs / tIn
            var tOut = tIn
            var beta = ctl.formantScale * cfg.formant
            if (voiced) {
                val (fOut, alpha0) = mapPitch(fIn)
                tOut = (fs / fOut).coerceIn(tMin, tMax)
                beta *= alpha0.pow(cfg.formantLink)
            }
            beta = beta.coerceIn(0.6f, 1.7f)
            val lOut = min(lMax.toFloat(), max(tIn / beta, tOut)).roundToInt().coerceAtLeast(8)
            val lIn = beta * lOut
            val need = s + tIn / 2 + lIn + 6
            if (need > ring.n - 1) break

            var a = s
            if (voiced && prevCenter >= 0 && s - prevCenter < 4 * tIn) a = align(s, tIn, prevCenter)
            place(a, s, lOut, beta)
            lastLOut = lOut
            prevCenter = if (voiced) a.toLong() else -1L
            s += tOut
            grains++
            if (voiced) lastOutHz = fs / tOut
        }
    }

    /** (출력 음높이 Hz, 음높이를 바꾼 비율 — 목소리 굵기 연동용: 떨림·음정보정은 뺀 값) */
    private fun mapPitch(fIn: Float): Pair<Float, Float> {
        var f = fIn
        val u = tracker.userF0
        if (cfg.targetHz > 0f) f = cfg.targetHz * (fIn / u).pow(cfg.intonation)
        f *= 2f.pow((cfg.semitones + ctl.semitoneOffset) / 12f)
        if (cfg.monotoneHz > 0f) f = cfg.monotoneHz
        val alpha0 = (f / fIn).coerceIn(0.3f, 3.5f)
        if (cfg.snap > 0f) {
            val midi = 69f + 12f * ln(f / 440f) / LN2
            val snapped = floor(midi + 0.5f)
            f = 440f * 2f.pow((midi + cfg.snap * (snapped - midi) - 69f) / 12f)
        }
        if (cfg.vibratoCents > 0f) f *= 2f.pow(cfg.vibratoCents / 1200f * sin(2.0 * PI * cfg.vibratoHz * s / fs).toFloat())
        return f.coerceIn(60f, 800f) to alpha0
    }

    /** 앞 조각과 파형이 가장 비슷한 가운데 위치를 s 근처에서 찾기 */
    private fun align(s0: Double, tIn: Float, prev: Long): Double {
        val m = (tIn / 2).toInt().coerceIn(8, 1500)
        val st = max(1, m / 50)
        var refE = 0.0
        var cnt = 0
        var i = -m
        while (i <= m) { val v = ring.get(prev + i); refSeg[cnt++] = v; refE += v * v; i += st }
        if (refE < 1e-9) return s0
        val c0 = s0.toLong()
        var best = c0; var bestV = -2.0
        var c = c0 - m
        while (c <= c0 + m) {
            var sab = 0.0; var sbb = 0.0
            var k = 0; i = -m
            while (i <= m) { val v = ring.get(c + i); sab += refSeg[k++] * v; sbb += v * v; i += st }
            val sc = sab / sqrt(refE * sbb + 1e-12)
            if (sc > bestV) { bestV = sc; best = c }
            c += st
        }
        if (st > 1) { // 촘촘하게 다시
            val lo = best - st; val hi = best + st
            var c2 = lo
            var bv = -2.0; var bb = best
            while (c2 <= hi) {
                var sab = 0.0; var sbb = 0.0; var saa = 0.0
                i = -m
                while (i <= m) { val a = ring.get(prev + i); val v = ring.get(c2 + i); sab += a * v; saa += a * a; sbb += v * v; i += 2 }
                val sc = sab / sqrt(saa * sbb + 1e-12)
                if (sc > bv) { bv = sc; bb = c2 }
                c2++
            }
            best = bb
        }
        return if (bestV < 0.2) s0 else best.toDouble()
    }

    /** 입력의 a 를 가운데로 한 조각을 β 배 속도로 읽어 출력 시간축의 s 에 붙이기 */
    private fun place(a: Double, sCenter: Double, lOut: Int, beta: Float) {
        val si = sCenter.roundToInt()
        val frac = sCenter - si
        val inv = (PI / lOut).toFloat()
        for (t in -lOut..lOut) {
            val rel = t - frac
            val x = rel.toFloat()
            if (abs(x) >= lOut) continue
            val win = 0.5f + 0.5f * kotlin.math.cos(inv * x)
            val v = ring.at(a + beta * rel)
            val j = ((si + t).toLong() and outMask).toInt()
            acc[j] += v * win
            wgt[j] += win
        }
    }

    /** 출력 시간축의 n 번째 표본 (한 번 읽으면 비움) */
    fun read(n: Long): Float {
        if (n < 0) return 0f
        if (n >= s - lastLOut - 4) underruns++
        val j = (n and outMask).toInt()
        val w = wgt[j]
        val v = if (w > 1e-3f) acc[j] / w else 0f
        acc[j] = 0f; wgt[j] = 0f
        return v
    }

    companion object { private const val LN2 = 0.6931472f }
}

/** 화면에서 바꿀 수 있는 값 (실시간 반영) */
class VoiceControls {
    @Volatile var semitoneOffset = 0f
    @Volatile var formantScale = 1f
    @Volatile var fxAmount = 1f
    @Volatile var inputGain = 1f
}

// ---------------------------------------------------------------- 속삭임 (LPC 잡음 합성)

class Whisper(private val fs: Int, private val ring: AudioRing) {
    private val order = 24
    private val frame = (fs * 0.025).toInt()
    private val hop = (fs * 0.010).toInt()
    private val a = DoubleArray(order + 1)
    private val hist = DoubleArray(order)
    private val buf = DoubleArray(frame)
    private val r = DoubleArray(order + 1)
    private val rnd = java.util.Random(7)
    private var gain = 0.0
    private var gainTarget = 0.0
    private var hpPrev = 0.0; private var hpOut = 0.0
    private var deemph = 0.0

    init { a[0] = 1.0 }

    private fun update(center: Long) {
        var mean = 0.0
        for (i in 0 until frame) {
            val w = 0.5 - 0.5 * kotlin.math.cos(2 * PI * (i + 0.5) / frame)
            val v = ring.get(center - frame / 2 + i).toDouble()
            buf[i] = v * w; mean += v * v
        }
        // 고음 강조 (0.95)
        for (i in frame - 1 downTo 1) buf[i] -= 0.95 * buf[i - 1]
        for (lag in 0..order) { var s = 0.0; for (i in lag until frame) s += buf[i] * buf[i - lag]; r[lag] = s }
        if (r[0] < 1e-9) { gainTarget = 0.0; return }
        r[0] *= 1.0001
        // Levinson-Durbin
        val tmp = DoubleArray(order + 1)
        val aa = DoubleArray(order + 1); aa[0] = 1.0
        var err = r[0]
        for (i in 1..order) {
            var acc = r[i]
            for (j in 1 until i) acc += aa[j] * r[i - j]
            val k = -acc / err
            for (j in 1 until i) tmp[j] = aa[j] + k * aa[i - j]
            for (j in 1 until i) aa[j] = tmp[j]
            aa[i] = k
            err *= (1 - k * k)
            if (err <= 0) break
        }
        for (i in 0..order) a[i] = aa[i]
        // 잔차 분산 = err / (창 에너지) 로 규격화하여 입력과 같은 에너지로
        var wsum = 0.0
        for (i in 0 until frame) { val w = 0.5 - 0.5 * kotlin.math.cos(2 * PI * (i + 0.5) / frame); wsum += w * w }
        gainTarget = sqrt(max(err, 0.0) / wsum)
    }

    private var phase = 0

    fun read(n: Long): Float {
        if (n < 0) return 0f
        if (n % hop == 0L) update(n)
        gain += 0.02 * (gainTarget - gain)
        var x = rnd.nextGaussian() * gain
        for (i in 1..order) x -= a[i] * hist[i - 1]
        for (i in order - 1 downTo 1) hist[i] = hist[i - 1]
        hist[0] = x
        // 앞서 고음을 강조해서(프리엠퍼시스) 분석했으므로 되돌리고(디엠퍼시스), 직류 성분 제거
        deemph = x + 0.95 * deemph
        val y = deemph - hpPrev + 0.995 * hpOut
        hpPrev = deemph; hpOut = y
        return y.toFloat()
    }
}

// ---------------------------------------------------------------- 효과

abstract class Fx { abstract fun process(b: FloatArray, n: Int, amt: Float) }

class Biquad(private val b0: Double, private val b1: Double, private val b2: Double, private val a1: Double, private val a2: Double) : Fx() {
    private var x1 = 0.0; private var x2 = 0.0; private var y1 = 0.0; private var y2 = 0.0
    fun tick(x: Double): Double {
        val y = b0 * x + b1 * x1 + b2 * x2 - a1 * y1 - a2 * y2
        x2 = x1; x1 = x; y2 = y1; y1 = y; return y
    }
    override fun process(b: FloatArray, n: Int, amt: Float) { for (i in 0 until n) b[i] = tick(b[i].toDouble()).toFloat() }

    companion object {
        private fun make(type: Int, fs: Int, f0: Double, q: Double, gainDb: Double = 0.0): Biquad {
            val w0 = 2 * PI * min(f0, fs * 0.48) / fs
            val cw = kotlin.math.cos(w0); val sw = sin(w0)
            val alpha = sw / (2 * q)
            val aGain = 10.0.pow(gainDb / 40)
            val b0: Double; val b1: Double; val b2: Double; val a0: Double; val a1: Double; val a2: Double
            when (type) {
                0 -> { b0 = (1 - cw) / 2; b1 = 1 - cw; b2 = (1 - cw) / 2; a0 = 1 + alpha; a1 = -2 * cw; a2 = 1 - alpha }          // 저역 통과
                1 -> { b0 = (1 + cw) / 2; b1 = -(1 + cw); b2 = (1 + cw) / 2; a0 = 1 + alpha; a1 = -2 * cw; a2 = 1 - alpha }       // 고역 통과
                2 -> { b0 = alpha; b1 = 0.0; b2 = -alpha; a0 = 1 + alpha; a1 = -2 * cw; a2 = 1 - alpha }                          // 대역 통과
                3 -> { b0 = 1 + alpha * aGain; b1 = -2 * cw; b2 = 1 - alpha * aGain; a0 = 1 + alpha / aGain; a1 = -2 * cw; a2 = 1 - alpha / aGain } // 특정 대역 올리기
                4 -> { val sq = 2 * sqrt(aGain) * alpha                                                                              // 저음 선반
                    b0 = aGain * ((aGain + 1) - (aGain - 1) * cw + sq); b1 = 2 * aGain * ((aGain - 1) - (aGain + 1) * cw); b2 = aGain * ((aGain + 1) - (aGain - 1) * cw - sq)
                    a0 = (aGain + 1) + (aGain - 1) * cw + sq; a1 = -2 * ((aGain - 1) + (aGain + 1) * cw); a2 = (aGain + 1) + (aGain - 1) * cw - sq }
                else -> { val sq = 2 * sqrt(aGain) * alpha                                                                           // 고음 선반
                    b0 = aGain * ((aGain + 1) + (aGain - 1) * cw + sq); b1 = -2 * aGain * ((aGain - 1) + (aGain + 1) * cw); b2 = aGain * ((aGain + 1) + (aGain - 1) * cw - sq)
                    a0 = (aGain + 1) - (aGain - 1) * cw + sq; a1 = 2 * ((aGain - 1) - (aGain + 1) * cw); a2 = (aGain + 1) - (aGain - 1) * cw - sq }
            }
            return Biquad(b0 / a0, b1 / a0, b2 / a0, a1 / a0, a2 / a0)
        }
        fun lowpass(fs: Int, f: Double, q: Double = 0.707) = make(0, fs, f, q)
        fun highpass(fs: Int, f: Double, q: Double = 0.707) = make(1, fs, f, q)
        fun bandpass(fs: Int, f: Double, q: Double) = make(2, fs, f, q)
        fun peak(fs: Int, f: Double, q: Double, db: Double) = make(3, fs, f, q, db)
        fun lowShelf(fs: Int, f: Double, db: Double) = make(4, fs, f, 0.707, db)
        fun highShelf(fs: Int, f: Double, db: Double) = make(5, fs, f, 0.707, db)
    }
}

/** 여러 단 필터를 이어 붙임 (가파른 대역 제한용) */
class FilterChain(private val parts: List<Biquad>) : Fx() {
    override fun process(b: FloatArray, n: Int, amt: Float) { for (p in parts) p.process(b, n, amt) }
}

class Echo(fs: Int, delayMs: Float, private val feedback: Float, private val mix: Float) : Fx() {
    private val buf = FloatArray(max(2, (fs * delayMs / 1000f).toInt()))
    private var pos = 0
    override fun process(b: FloatArray, n: Int, amt: Float) {
        val m = (mix * amt).coerceIn(0f, 1.2f)
        for (i in 0 until n) {
            val dl = buf[pos]; val x = b[i]
            buf[pos] = x + feedback * dl
            pos = if (pos + 1 == buf.size) 0 else pos + 1
            b[i] = x + m * dl
        }
    }
}

/** 프리버브 방식 잔향 */
class Reverb(fs: Int, room: Float, damp: Float, private val wet: Float) : Fx() {
    private val sc = fs / 44100.0
    private val combTune = intArrayOf(1116, 1188, 1277, 1356, 1422, 1491, 1557, 1617)
    private val apTune = intArrayOf(556, 441, 341, 225)
    private val combs = Array(8) { FloatArray(max(8, (combTune[it] * sc).toInt())) }
    private val combPos = IntArray(8)
    private val combStore = FloatArray(8)
    private val aps = Array(4) { FloatArray(max(8, (apTune[it] * sc).toInt())) }
    private val apPos = IntArray(4)
    private val fb = room * 0.28f + 0.7f
    private val d1 = damp * 0.4f

    override fun process(b: FloatArray, n: Int, amt: Float) {
        val w = (wet * amt).coerceIn(0f, 1f)
        for (i in 0 until n) {
            val x = b[i]; val inp = x * 0.015f
            var o = 0f
            for (c in 0 until 8) {
                val buf = combs[c]; val p = combPos[c]
                val y = buf[p]
                combStore[c] = y * (1 - d1) + combStore[c] * d1
                buf[p] = inp + combStore[c] * fb
                combPos[c] = if (p + 1 == buf.size) 0 else p + 1
                o += y
            }
            for (a in 0 until 4) {
                val buf = aps[a]; val p = apPos[a]
                val bo = buf[p]
                buf[p] = o + bo * 0.5f
                o = bo - o
                apPos[a] = if (p + 1 == buf.size) 0 else p + 1
            }
            b[i] = x * (1 - 0.5f * w) + o * 3f * w
        }
    }
}

/** 코러스·플랜저: 흔들리는 짧은 지연 */
class Chorus(private val fs: Int, private val baseMs: FloatArray, private val depthMs: Float, private val rateHz: Float,
             private val mix: Float, private val feedback: Float = 0f) : Fx() {
    private val len = ((baseMs.max() + depthMs + 3) * fs / 1000f).toInt() + 4
    private val buf = FloatArray(len)
    private var pos = 0
    private var ph = 0.0
    override fun process(b: FloatArray, n: Int, amt: Float) {
        val m = (mix * amt).coerceIn(0f, 1f)
        val inc = 2 * PI * rateHz / fs
        for (i in 0 until n) {
            val x = b[i]
            var sum = 0f
            for ((k, bm) in baseMs.withIndex()) {
                val lfo = sin(ph + k * 2.0 * PI / baseMs.size).toFloat()
                val d = (bm + depthMs * lfo) * fs / 1000f
                var rp = pos - d
                while (rp < 0) rp += len
                val i0 = rp.toInt(); val f = rp - i0
                val a0 = buf[i0 % len]; val a1 = buf[(i0 + 1) % len]
                sum += a0 + (a1 - a0) * f
            }
            sum /= baseMs.size
            buf[pos] = x + feedback * sum
            pos = if (pos + 1 == len) 0 else pos + 1
            ph += inc
            b[i] = x * (1 - 0.5f * m) + sum * m
        }
    }
}

class Tremolo(private val fs: Int, private val rateHz: Float, private val depth: Float) : Fx() {
    private var ph = 0.0
    override fun process(b: FloatArray, n: Int, amt: Float) {
        val dp = (depth * amt).coerceIn(0f, 1f)
        val inc = 2 * PI * rateHz / fs
        for (i in 0 until n) { b[i] *= 1f - dp * (0.5f + 0.5f * sin(ph).toFloat()); ph += inc }
    }
}

class RingMod(private val fs: Int, private val freq: Float, private val mix: Float) : Fx() {
    private var ph = 0.0
    override fun process(b: FloatArray, n: Int, amt: Float) {
        val m = (mix * amt).coerceIn(0f, 1f)
        val inc = 2 * PI * freq / fs
        for (i in 0 until n) { val x = b[i]; b[i] = x * (1 - m) + x * sin(ph).toFloat() * m; ph += inc }
    }
}

class Distort(private val drive: Float, private val mix: Float) : Fx() {
    private val norm = 1f / tanh(drive)
    override fun process(b: FloatArray, n: Int, amt: Float) {
        val m = (mix * amt).coerceIn(0f, 1f)
        for (i in 0 until n) { val x = b[i]; b[i] = x * (1 - m) + tanh(drive * x) * norm * m }
    }
}

/** 표본 속도·비트 수를 줄이는 효과 (게임기·전화기 느낌) */
class Crush(private val hold: Int, private val bits: Int) : Fx() {
    private var c = 0; private var held = 0f
    override fun process(b: FloatArray, n: Int, amt: Float) {
        val q = (1 shl (bits - 1)).toFloat()
        for (i in 0 until n) {
            if (c == 0) held = (b[i] * q).roundToInt() / q
            c = if (c + 1 >= hold) 0 else c + 1
            b[i] = held
        }
    }
}

class Compressor(private val fs: Int, private val thresholdDb: Float, private val ratio: Float, private val makeupDb: Float) : Fx() {
    private var env = 0f
    private val atk = exp(-1.0 / (0.005 * fs)).toFloat()
    private val rel = exp(-1.0 / (0.12 * fs)).toFloat()
    private val mk = 10f.pow(makeupDb / 20f)
    override fun process(b: FloatArray, n: Int, amt: Float) {
        for (i in 0 until n) {
            val a = abs(b[i])
            env = if (a > env) atk * env + (1 - atk) * a else rel * env + (1 - rel) * a
            val db = 20f * kotlin.math.log10(max(env, 1e-5f))
            val over = db - thresholdDb
            val g = if (over > 0) 10f.pow(-over * (1 - 1 / ratio) / 20f) else 1f
            b[i] = b[i] * g * mk
        }
    }
}

class Gain(private val g: Float) : Fx() { override fun process(b: FloatArray, n: Int, amt: Float) { for (i in 0 until n) b[i] *= g } }

// ---------------------------------------------------------------- 엔진

/**
 * 출력 음량을 입력 음량에 천천히 맞춥니다 (프리셋을 바꿔도 소리 크기가 비슷하게).
 * 말하는 동안에만 조정하고, 조용할 때는 값을 유지해서 잔향 꼬리가 커지지 않게 합니다.
 */
class LevelMatch(fs: Int) {
    private val kSlow = (1 - exp(-1.0 / (0.25 * fs))).toFloat()
    private val kFast = (1 - exp(-1.0 / (0.03 * fs))).toFloat()
    private val kGain = (1 - exp(-1.0 / (0.08 * fs))).toFloat()
    private var eIn = 0f; private var eOut = 0f; private var eFast = 0f
    var gain = 1f; private set

    fun process(ref: Float, y: Float): Float {
        eIn += (ref * ref - eIn) * kSlow
        eFast += (ref * ref - eFast) * kFast
        eOut += (y * y - eOut) * kSlow
        if (eFast > 1e-5f && eIn > 2e-6f && eOut > 1e-9f) {
            val target = sqrt(eIn / eOut).coerceIn(0.35f, 3f)
            gain += (target - gain) * kGain
        }
        return y * gain
    }
}

/** 음성 변조 한 가지 설정 (목소리 겹들 + 속삭임 + 효과) */
class VoiceChain(
    val voices: List<VoiceCfg>,
    val dry: Float = 0f,
    val whisper: Float = 0f,
    val fx: (Int) -> List<Fx> = { emptyList() },
    val outGain: Float = 1f,
    /** 출력 음량을 입력에 맞출지 (원음 통과는 끔) */
    val matchLevel: Boolean = true,
)

class VoiceEngine(val fs: Int) {
    val controls = VoiceControls()
    private val ring = AudioRing()
    val tracker = PitchTracker(fs, ring)
    /** 출력이 입력보다 늦는 표본 수 (조각 붙이기에 필요한 앞선 정보 + 겹치기) */
    val latency = (fs * 0.044).toInt()

    private class Active(val chain: VoiceChain, val voices: List<PsolaVoice>, val whisper: Whisper?, val fx: List<Fx>, val match: LevelMatch?)

    @Volatile private var pending: VoiceChain? = null
    private var cur: Active? = null
    private var old: Active? = null
    private var xfLeft = 0
    private val xfLen = (fs * 0.03).toInt()
    private val tmpIn = FloatArray(8192)
    private val bufA = FloatArray(8192)
    private val bufB = FloatArray(8192)
    var blocks = 0L; private set
    val underruns get() = (cur?.voices?.sumOf { it.underruns } ?: 0)
    val outHz get() = cur?.voices?.firstOrNull()?.lastOutHz ?: 0f

    fun setChain(c: VoiceChain) { pending = c }

    private fun build(c: VoiceChain, startTimeline: Long): Active =
        Active(c, c.voices.map { PsolaVoice(fs, ring, tracker, it, controls, startTimeline) },
            if (c.whisper > 0f) Whisper(fs, ring) else null, c.fx(fs), if (c.matchLevel) LevelMatch(fs) else null)

    /** n 표본의 입력을 받아 n 표본의 출력을 만듭니다 (n ≤ 8192). 출력은 입력보다 latency 표본 늦습니다. */
    fun process(input: FloatArray, n: Int, out: FloatArray) {
        require(n <= 8192)
        val g = controls.inputGain
        for (i in 0 until n) tmpIn[i] = input[i] * g
        val base = ring.n - latency            // 이번 블록 첫 출력의 시간축 위치
        ring.push(tmpIn, n)
        tracker.push(tmpIn, n)

        pending?.let { p ->
            pending = null
            old = cur; xfLeft = if (cur != null) xfLen else 0
            cur = build(p, base)
        }
        val a = cur
        if (a == null) { for (i in 0 until n) out[i] = 0f; return }
        mix(a, base, n, bufA)
        if (xfLeft > 0 && old != null) {
            mix(old!!, base, n, bufB)
            for (i in 0 until n) {
                val t = if (xfLeft > 0) xfLeft.toFloat() / xfLen else 0f
                bufA[i] = bufA[i] * (1 - t) + bufB[i] * t
                if (xfLeft > 0) xfLeft--
            }
            if (xfLeft <= 0) old = null
        }
        for (i in 0 until n) out[i] = softLimit(bufA[i])
        blocks++
    }

    private fun mix(a: Active, base: Long, n: Int, dst: FloatArray) {
        for (v in a.voices) v.render()
        val c = a.chain
        for (i in 0 until n) {
            val t = base + i
            var y = c.dry * ring.get(t)
            for (v in a.voices) y += v.cfg.gain * v.read(t)
            a.whisper?.let { y += c.whisper * it.read(t) }
            dst[i] = y
        }
        val amt = controls.fxAmount
        for (f in a.fx) f.process(dst, n, amt)
        a.match?.let { m -> for (i in 0 until n) dst[i] = m.process(ring.get(base + i), dst[i]) }
        if (c.outGain != 1f) for (i in 0 until n) dst[i] *= c.outGain
    }

    private fun softLimit(x: Float): Float {
        val ax = abs(x)
        return if (ax < 0.85f) x else (if (x < 0) -1f else 1f) * (0.85f + 0.15f * tanh((ax - 0.85f) / 0.15f))
    }
}
