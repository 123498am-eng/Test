package com.selfcheck.app

import kotlin.math.PI
import kotlin.math.abs
import kotlin.math.acos
import kotlin.math.cos
import kotlin.math.hypot
import kotlin.math.max
import kotlin.math.min
import kotlin.math.sin
import kotlin.math.sqrt

/** 세 점의 가운데 각도 (도). b 가 꼭짓점 */
fun angleAt(ax: Float, ay: Float, bx: Float, by: Float, cx: Float, cy: Float): Float {
    val ux = ax - bx; val uy = ay - by; val vx = cx - bx; val vy = cy - by
    val d = hypot(ux, uy) * hypot(vx, vy)
    if (d < 1e-6f) return 180f
    return Math.toDegrees(acos(((ux * vx + uy * vy) / d).coerceIn(-1f, 1f).toDouble())).toFloat()
}

/** 운동 횟수: 값이 down 아래로 내려갔다가 up 위로 돌아오면 1회 (스쿼트 무릎 각도, 팔굽혀펴기 팔꿈치 각도 등) */
class RepCounter(private val down: Float, private val up: Float) {
    var count = 0; private set
    var isDown = false; private set
    /** 1회가 끝나면 true */
    fun update(v: Float): Boolean {
        if (!isDown && v < down) isDown = true
        else if (isDown && v > up) { isDown = false; count++; return true }
        return false
    }
    fun reset() { count = 0; isDown = false }
}

/** 두 상태(예: 팔벌려뛰기 벌림/모음)를 오가면 1회 */
class TwoStateCounter {
    var count = 0; private set
    private var state = 0 // 0 모름, 1 모음, 2 벌림
    fun update(open: Boolean?, closed: Boolean?): Boolean {
        if (open == true && state == 1) state = 2
        else if (closed == true) { val done = state == 2; state = 1; if (done) { count++; return true } }
        else if (open == true && state == 0) state = 2
        return false
    }
    fun reset() { count = 0; state = 0 }
}

/** 눈 깜빡임·감은 시간 (blink: 0~1 눈 감은 정도) */
class BlinkCounter(private val closeT: Float = 0.5f, private val openT: Float = 0.3f) {
    var count = 0; private set
    var closedSince = -1.0; private set
    private val times = ArrayDeque<Double>()
    private val closedLog = ArrayDeque<Pair<Double, Boolean>>()
    /** 지금까지 감고 있는 시간 (초, 떠 있으면 0) */
    fun update(t: Double, blink: Float): Double {
        val closed = if (closedSince >= 0) blink > openT else blink > closeT
        if (closed && closedSince < 0) closedSince = t
        if (!closed && closedSince >= 0) {
            if (t - closedSince < 0.8) { count++; times.addLast(t) } // 짧게 감았다 뜨면 깜빡임
            closedSince = -1.0
        }
        closedLog.addLast(t to closed)
        while (closedLog.isNotEmpty() && t - closedLog.first().first > 60) closedLog.removeFirst()
        while (times.isNotEmpty() && t - times.first() > 60) times.removeFirst()
        return if (closedSince >= 0) t - closedSince else 0.0
    }
    /** 최근 1분 깜빡임 수 */
    fun perMinute() = times.size
    /** 최근 1분 중 눈 감은 비율 (PERCLOS) */
    fun perclos(): Float = if (closedLog.isEmpty()) 0f else closedLog.count { it.second }.toFloat() / closedLog.size
    fun reset() { count = 0; closedSince = -1.0; times.clear(); closedLog.clear() }
}

/**
 * 맥박 추정: 피부(얼굴 또는 손가락) 밝기의 아주 작은 주기적 변화를 시간에 따라 모아
 * 0.7~3.5Hz(분당 42~210회) 중 가장 센 주기를 찾습니다. 참고용입니다.
 */
class HeartRate(private val windowSec: Double = 12.0) {
    private val t = ArrayDeque<Double>()
    private val v = ArrayDeque<Double>()
    fun add(time: Double, value: Double) {
        t.addLast(time); v.addLast(value)
        while (t.isNotEmpty() && time - t.first() > windowSec) { t.removeFirst(); v.removeFirst() }
    }
    fun seconds() = if (t.size < 2) 0.0 else t.last() - t.first()
    fun reset() { t.clear(); v.clear() }

    /** (분당 횟수, 신뢰도 0~1). 자료가 6초 미만이면 null */
    fun bpm(): Pair<Float, Float>? {
        if (seconds() < 6.0 || t.size < 40) return null
        val fs = 20.0
        val t0 = t.first(); val n = ((t.last() - t0) * fs).toInt()
        val ts = t.toDoubleArray(); val vs = v.toDoubleArray()
        val x = DoubleArray(n)
        var j = 0
        for (i in 0 until n) {
            val tt = t0 + i / fs
            while (j < ts.size - 2 && ts[j + 1] < tt) j++
            val a = ts[j]; val b = ts[j + 1]
            x[i] = if (b > a) vs[j] + (vs[j + 1] - vs[j]) * ((tt - a) / (b - a)).coerceIn(0.0, 1.0) else vs[j]
        }
        // 느린 변화(조명·움직임) 빼기: 1.5초 이동 평균
        val win = (1.5 * fs).toInt(); val y = DoubleArray(n)
        var sum = 0.0
        for (i in 0 until n) {
            sum += x[i]; if (i >= win) sum -= x[i - win]
            y[i] = x[i] - sum / min(i + 1, win)
        }
        val m = y.average(); var sd = 0.0; for (k in y) sd += (k - m) * (k - m); sd = sqrt(sd / n)
        if (sd < 1e-9) return null
        for (i in 0 until n) y[i] = (y[i] - m) / sd * (0.5 - 0.5 * cos(2 * PI * i / (n - 1))) // 한닝 창
        var best = 0.0; var bestF = 0.0; var total = 0.0
        val powers = ArrayList<Pair<Double, Double>>()
        var f = 0.7
        while (f <= 3.5) {
            var re = 0.0; var im = 0.0
            for (i in 0 until n) { val ph = 2 * PI * f * i / fs; re += y[i] * cos(ph); im -= y[i] * sin(ph) }
            val p = re * re + im * im
            powers += f to p; total += p
            if (p > best) { best = p; bestF = f }
            f += 0.01
        }
        // 가장 센 주기 주변(±0.1Hz)이 전체에서 차지하는 비율 = 신뢰도
        val near = powers.filter { abs(it.first - bestF) <= 0.1 }.sumOf { it.second }
        return (bestF * 60).toFloat() to (near / max(total, 1e-12)).toFloat().coerceIn(0f, 1f)
    }
}
