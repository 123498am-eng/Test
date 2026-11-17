package com.selfcheck.app

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import kotlin.math.PI
import kotlin.math.abs
import kotlin.math.sin

class LiveLogicTest {
    @Test fun angle() {
        assertEquals(90f, angleAt(1f, 0f, 0f, 0f, 0f, 1f), 0.01f)
        assertEquals(180f, angleAt(-1f, 0f, 0f, 0f, 1f, 0f), 0.01f)
    }

    @Test fun squatCounting() {
        val c = RepCounter(100f, 160f)
        // 서기 → 앉기 → 서기를 3번, 중간 흔들림(150° 근처)은 세지 않음
        val seq = listOf(170f, 150f, 120f, 90f, 85f, 120f, 165f, 170f, 95f, 150f, 161f, 155f, 158f, 90f, 170f)
        var done = 0
        seq.forEach { if (c.update(it)) done++ }
        assertEquals(3, c.count); assertEquals(3, done)
    }

    @Test fun jumpingJacks() {
        val c = TwoStateCounter()
        repeat(4) { c.update(open = false, closed = true); c.update(open = true, closed = false) }
        c.update(open = false, closed = true)
        assertEquals(4, c.count)
    }

    @Test fun blinksAndClosedTime() {
        val b = BlinkCounter()
        var t = 0.0
        repeat(10) { // 0.15초 감았다 뜨기 10번
            repeat(10) { b.update(t, 0.05f); t += 0.033 }
            repeat(5) { b.update(t, 0.9f); t += 0.033 }
        }
        repeat(5) { b.update(t, 0.05f); t += 0.033 }
        assertEquals(10, b.count)
        // 2초 동안 감고 있으면 감은 시간이 늘어나고, 깜빡임으로 세지 않음
        var closed = 0.0
        repeat(60) { closed = b.update(t, 0.95f); t += 0.033 }
        assertTrue(closed > 1.8)
        b.update(t, 0.0f)
        assertEquals(10, b.count)
    }

    @Test fun heartRateFromNoisySignal() {
        val hr = HeartRate()
        val rnd = java.util.Random(5)
        var t = 0.0
        assertNull(hr.bpm())
        // 72회/분(1.2Hz) 맥박 + 느린 조명 변화 + 잡음, 프레임 간격이 고르지 않음 (24~36fps)
        while (t < 12.0) {
            val v = 100 + 0.4 * sin(2 * PI * 1.2 * t) + 3 * sin(2 * PI * 0.1 * t) + rnd.nextGaussian() * 0.25
            hr.add(t, v)
            t += 1.0 / (24 + rnd.nextInt(13))
        }
        val r = hr.bpm()
        assertNotNull(r)
        assertTrue("bpm=${r!!.first}", abs(r.first - 72f) < 3f)
        assertTrue("quality=${r.second}", r.second > 0.2f)
    }
}
