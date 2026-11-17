package com.selfcheck.app

import java.io.ByteArrayOutputStream
import java.io.File
import java.nio.ByteBuffer
import java.nio.ByteOrder
import kotlin.math.PI
import kotlin.math.abs
import kotlin.math.max
import kotlin.math.min
import kotlin.math.sin
import kotlin.math.sqrt

object VoiceTestUtil {
    /** 16비트 모노 WAV 읽기 → (표본 속도, -1..1 배열) */
    fun readWav(f: File): Pair<Int, FloatArray> {
        val b = ByteBuffer.wrap(f.readBytes()).order(ByteOrder.LITTLE_ENDIAN)
        var pos = 12; var fs = 44100; var ch = 1
        while (pos + 8 <= b.capacity()) {
            val id = String(ByteArray(4) { b.get(pos + it) }); val sz = b.getInt(pos + 4)
            if (id == "fmt ") { ch = b.getShort(pos + 10).toInt(); fs = b.getInt(pos + 12) }
            if (id == "data") {
                val n = sz / 2 / ch
                return fs to FloatArray(n) { b.getShort(pos + 8 + it * 2 * ch) / 32768f }
            }
            pos += 8 + sz + (sz and 1)
        }
        error("no data")
    }

    fun writeWav(f: File, fs: Int, x: FloatArray) {
        val bo = ByteArrayOutputStream()
        val data = ByteBuffer.allocate(x.size * 2).order(ByteOrder.LITTLE_ENDIAN)
        for (v in x) data.putShort((v.coerceIn(-1f, 1f) * 32767f).toInt().toShort())
        val h = ByteBuffer.allocate(44).order(ByteOrder.LITTLE_ENDIAN)
        h.put("RIFF".toByteArray()).putInt(36 + x.size * 2).put("WAVEfmt ".toByteArray()).putInt(16).putShort(1).putShort(1)
            .putInt(fs).putInt(fs * 2).putShort(2).putShort(16).put("data".toByteArray()).putInt(x.size * 2)
        bo.write(h.array()); bo.write(data.array()); f.parentFile?.mkdirs(); f.writeBytes(bo.toByteArray())
    }

    /** 엔진에 블록 단위로 넣어 전체 출력을 받습니다 (출력은 latency 표본 늦으므로 앞을 잘라 입력과 정렬) */
    fun run(engine: VoiceEngine, x: FloatArray, block: Int = 480, tail: Int = 0): FloatArray {
        val total = x.size + engine.latency + tail
        val padded = x + FloatArray(((total + block - 1) / block) * block - x.size)
        val out = FloatArray(padded.size)
        val inb = FloatArray(block); val ob = FloatArray(block)
        var p = 0
        while (p + block <= padded.size) {
            System.arraycopy(padded, p, inb, 0, block)
            engine.process(inb, block, ob)
            System.arraycopy(ob, 0, out, p, block)
            p += block
        }
        return out.copyOfRange(engine.latency, engine.latency + x.size)
    }

    fun rms(x: FloatArray, a: Int = 0, b: Int = x.size): Double { var s = 0.0; for (i in a until b) s += x[i] * x[i]; return sqrt(s / max(1, b - a)) }

    /**
     * 합성 모음 소리 (성문 펄스 + 포먼트 공진). f0Of(t) 는 시간(초)별 음높이, formants 는 (주파수, 대역폭) 목록.
     * 목소리 굵기 시험에 쓰는 실제 값을 아는 소리입니다.
     */
    fun vowel(fs: Int, seconds: Double, f0Of: (Double) -> Double, formants: List<Pair<Double, Double>>): FloatArray {
        val n = (seconds * fs).toInt()
        val src = DoubleArray(n)
        var phase = 0.0
        for (i in 0 until n) {
            val f0 = f0Of(i.toDouble() / fs)
            phase += f0 / fs
            if (phase >= 1.0) phase -= 1.0
            // 로젠버그형 성문 펄스의 미분 (피크가 뚜렷한 소리)
            val t = phase
            src[i] = if (t < 0.4) sin(PI * t / 0.4) * (PI / 0.4) * 0.5 * (1 + kotlin.math.cos(PI * t / 0.4)) else if (t < 0.5) -sin(PI * (t - 0.4) / 0.1) * 1.2 else 0.0
        }
        var y = src
        for ((f, bw) in formants) {
            val r = kotlin.math.exp(-PI * bw / fs); val th = 2 * PI * f / fs
            val a1 = -2 * r * kotlin.math.cos(th); val a2 = r * r
            val o = DoubleArray(n)
            for (i in 0 until n) o[i] = y[i] * (1 - r) - a1 * (if (i > 0) o[i - 1] else 0.0) - a2 * (if (i > 1) o[i - 2] else 0.0)
            y = o
        }
        val m = y.maxOf { abs(it) }
        return FloatArray(n) { (y[it] / m * 0.5).toFloat() }
    }

    /** 자기상관으로 음높이(Hz) 추정 (엔진과 별개의 방법: 정규화 자기상관 + 가장 큰 봉우리) */
    fun f0(x: FloatArray, fs: Int, a: Int, len: Int, fmin: Double = 70.0, fmax: Double = 500.0): Pair<Double, Double> {
        val lo = (fs / fmax).toInt(); val hi = (fs / fmin).toInt()
        var best = lo; var bv = -1.0
        val r = DoubleArray(hi + 2)
        for (l in lo..hi + 1) {
            var sab = 0.0; var saa = 0.0; var sbb = 0.0
            for (i in a until a + len) { val u = x[i].toDouble(); val v = x[i + l].toDouble(); sab += u * v; saa += u * u; sbb += v * v }
            r[l] = sab / sqrt(saa * sbb + 1e-12)
        }
        // 첫 번째 큰 봉우리 (옥타브 오류 방지: 최댓값의 90% 이상인 가장 작은 지연)
        var mx = -1.0; for (l in lo..hi) if (r[l] > mx && r[l] >= r[l - 1].coerceAtLeast(-1.0) && r[l] >= r[l + 1]) mx = r[l]
        for (l in lo..hi) if (r[l] >= 0.9 * mx && r[l] >= r[l - 1] && r[l] >= r[l + 1]) { best = l; bv = r[l]; break }
        return fs.toDouble() / best to bv
    }

    private fun fft(re: DoubleArray, im: DoubleArray) {
        val n = re.size
        var j = 0
        for (i in 1 until n) { var bit = n shr 1; while (j and bit != 0) { j = j xor bit; bit = bit shr 1 }; j = j xor bit
            if (i < j) { val tr = re[i]; re[i] = re[j]; re[j] = tr; val ti = im[i]; im[i] = im[j]; im[j] = ti } }
        var len = 2
        while (len <= n) {
            val ang = -2 * PI / len
            for (i in 0 until n step len) for (k in 0 until len / 2) {
                val wr = kotlin.math.cos(ang * k); val wi = sin(ang * k)
                val ur = re[i + k]; val ui = im[i + k]
                val vr = re[i + k + len / 2] * wr - im[i + k + len / 2] * wi; val vi = re[i + k + len / 2] * wi + im[i + k + len / 2] * wr
                re[i + k] = ur + vr; im[i + k] = ui + vi; re[i + k + len / 2] = ur - vr; im[i + k + len / 2] = ui - vi
            }
            len = len shl 1
        }
    }

    /** 켑스트럼으로 매끈하게 만든 스펙트럼 포락선(로그 크기), 여러 프레임 평균. 음높이 배음이 아닌 목소리 굵기(포먼트)만 남김 */
    fun envelope(x: FloatArray, a: Int, frames: Int = 6, hop: Int = 1500, n: Int = 4096, lifter: Int = 100): DoubleArray {
        val acc = DoubleArray(n / 2 + 1)
        for (fr in 0 until frames) {
            val re = DoubleArray(n); val im = DoubleArray(n)
            for (i in 0 until n) re[i] = x[a + fr * hop + i] * (0.5 - 0.5 * kotlin.math.cos(2 * PI * (i + 0.5) / n))
            fft(re, im)
            val lg = DoubleArray(n) { kotlin.math.ln(sqrt(re[it] * re[it] + im[it] * im[it]) + 1e-9) }
            val cr = lg.copyOf(); val ci = DoubleArray(n)
            fft(cr, ci) // 실수 대칭이라 정방향 FFT 가 곧 켑스트럼
            for (i in 0 until n) { val q = if (i <= n / 2) i else n - i; if (q > lifter) { cr[i] = 0.0; ci[i] = 0.0 } }
            fft(cr, ci)
            for (k in 0..n / 2) acc[k] += cr[k] / n
        }
        return DoubleArray(acc.size) { acc[it] / frames }
    }

    /** 출력 포락선이 입력 포락선을 주파수축에서 β 배 늘린 것과 가장 닮은 β (300~4000Hz) */
    fun bestFormantWarp(envIn: DoubleArray, envOut: DoubleArray, fs: Int): Double {
        val n = (envIn.size - 1) * 2; val df = fs.toDouble() / n
        val lo = (300 / df).toInt(); val hi = (4000 / df).toInt()
        var best = 1.0; var bv = Double.MAX_VALUE
        var beta = 0.7
        while (beta <= 1.6) {
            val a = DoubleArray(hi - lo); val b = DoubleArray(hi - lo)
            for (k in lo until hi) { val src = k / beta; val i = src.toInt(); val f = src - i; a[k - lo] = envIn[i] * (1 - f) + envIn[min(i + 1, envIn.size - 1)] * f; b[k - lo] = envOut[k] }
            val ma = a.average(); val mb = b.average()
            var e = 0.0; for (i in a.indices) { val d = (a[i] - ma) - (b[i] - mb); e += d * d }
            if (e < bv) { bv = e; best = beta }
            beta += 0.01
        }
        return best
    }
}
