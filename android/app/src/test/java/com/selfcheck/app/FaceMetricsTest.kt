package com.selfcheck.app

import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.File
import kotlin.math.cos
import kotlin.math.sin

class FaceMetricsTest {
    private val mirror = File("src/main/assets/face_mirror.txt").readText().trim().split(Regex("\\s+")).map { it.toInt() }.toIntArray()

    @Test fun mirrorTableIsInvolution() {
        assertEquals(478, mirror.size)
        for (i in mirror.indices) assertEquals(i, mirror[mirror[i]])
        assertEquals(263, mirror[33]); assertEquals(1, mirror[1]); assertEquals(473, mirror[468])
    }

    @Test fun alignResidualIsZeroForRotatedCopy() {
        val rnd = java.util.Random(7)
        val n = 50
        val a = DoubleArray(n * 3) { rnd.nextGaussian() }
        val t = 0.7; val p = -0.3
        val b = DoubleArray(n * 3)
        for (i in 0 until n) {
            val x = a[i * 3]; val y = a[i * 3 + 1]; val z = a[i * 3 + 2]
            val x1 = cos(t) * x + sin(t) * z; val z1 = -sin(t) * x + cos(t) * z
            val y2 = cos(p) * y - sin(p) * z1; val z2 = sin(p) * y + cos(p) * z1
            b[i * 3] = x1 + 5; b[i * 3 + 1] = y2 - 2; b[i * 3 + 2] = z2 + 1
        }
        assertTrue(Geom3.alignResidual(a, b) < 1e-6)
        // 다른 모양이면 차이가 남음
        val c = b.copyOf(); c[0] += 1.0
        assertTrue(Geom3.alignResidual(a, c) > 0.01)
    }

    /** 완전히 좌우 대칭인 가짜 얼굴(점 478개)은 대칭 점수 100, 한쪽 입꼬리를 올리면 점수가 내려감 */
    @Test fun symmetricFaceScoresHigh() {
        val pts = FloatArray(478 * 3)
        val rnd = java.util.Random(3)
        for (i in 0 until 478) {
            val j = mirror[i]
            if (j < i) continue
            val x = if (i == j) 0f else 0.05f + rnd.nextFloat() * 0.3f
            val y = rnd.nextFloat() * 0.8f - 0.4f; val z = rnd.nextFloat() * 0.1f
            pts[i * 3] = 0.5f - x; pts[i * 3 + 1] = 0.5f + y; pts[i * 3 + 2] = z
            pts[j * 3] = 0.5f + x; pts[j * 3 + 1] = 0.5f + y; pts[j * 3 + 2] = z
        }
        val m = FaceMetricsCalc.compute(pts, 1000f, 1000f, mirror, 0f, emptyMap())
        assertEquals(100, m.symmetry)
        val bent = pts.copyOf()
        for (i in intArrayOf(291, 409, 375, 308, 415, 324)) bent[i * 3 + 1] -= 0.05f
        val m2 = FaceMetricsCalc.compute(bent, 1000f, 1000f, mirror, 0f, emptyMap())
        assertTrue("${m2.symmetry}", m2.symmetry < 100)
    }

    @Test fun expressionNames() {
        assertEquals("미소", FaceMetricsCalc.expression(mapOf("mouthSmileLeft" to 0.7f, "mouthSmileRight" to 0.6f)))
        assertEquals("윙크", FaceMetricsCalc.expression(mapOf("eyeBlinkLeft" to 0.9f, "eyeBlinkRight" to 0.1f)))
        assertEquals("무표정", FaceMetricsCalc.expression(emptyMap()))
    }
}
