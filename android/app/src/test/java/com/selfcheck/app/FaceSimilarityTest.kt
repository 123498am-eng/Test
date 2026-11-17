package com.selfcheck.app

import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

class FaceSimilarityTest {
    @Test fun percentAnchors() {
        assertEquals(60, FaceSimilarity.percent(FaceSimilarity.THRESHOLD))
        assertEquals(20, FaceSimilarity.percent(0.0))
        assertEquals(98, FaceSimilarity.percent(0.8))
        assertEquals(99, FaceSimilarity.percent(0.99))
        assertEquals(0, FaceSimilarity.percent(-0.9))
        // 단조 증가
        var last = -1
        var c = -1.0
        while (c <= 1.0) { val p = FaceSimilarity.percent(c); assertTrue(p >= last); last = p; c += 0.01 }
        // 시험 사진 값: 다른 사람(-0.10~0.13) → 35% 이하, 같은 사람 사진 변형(0.72~0.97) → 90% 이상
        assertTrue(FaceSimilarity.percent(0.13) <= 35)
        assertTrue(FaceSimilarity.percent(0.72) >= 90)
    }

    @Test fun verdictBands() {
        assertEquals(3, FaceSimilarity.verdict(0.6).first)
        assertEquals(2, FaceSimilarity.verdict(0.40).first)
        assertEquals(1, FaceSimilarity.verdict(0.30).first)
        assertEquals(0, FaceSimilarity.verdict(0.1).first)
        // 판정 경계와 % 경계가 맞음: 같은 사람(2 이상) ⇔ 60% 이상
        var c = -0.5
        while (c < 1.0) { assertEquals("cos=$c", FaceSimilarity.verdict(c).first >= 2, FaceSimilarity.percent(c) >= 60); c += 0.0005 }
        assertEquals(59, FaceSimilarity.percent(0.3625))
    }

    @Test fun cosineAndTemplate() {
        val a = floatArrayOf(1f, 0f, 0f); val b = floatArrayOf(0f, 2f, 0f); val c = floatArrayOf(3f, 3f, 0f)
        assertEquals(0.0, FaceSimilarity.cosine(a, b), 1e-9)
        assertEquals(1.0, FaceSimilarity.cosine(a, floatArrayOf(5f, 0f, 0f)), 1e-9)
        assertEquals(Math.sqrt(0.5), FaceSimilarity.cosine(a, c), 1e-6)
        // 크기가 달라도 같은 비중으로 합침 → a, b 의 가운데 방향
        val t = FaceSimilarity.template(listOf(a, b))
        assertEquals(1.0, FaceSimilarity.cosine(t, c), 1e-6)
        assertEquals(1.0, Math.sqrt(t.sumOf { (it * it).toDouble() }), 1e-6)
    }

    @Test fun qualityWarnings() {
        assertTrue(FaceSimilarity.quality(31f, 0.92f, 85.0, 103.0, 0.05f).any { it.contains("작게") })
        assertTrue(FaceSimilarity.quality(150f, 0.92f, 3.0, 103.0, 0.05f).any { it.contains("흐립") })
        assertTrue(FaceSimilarity.quality(150f, 0.95f, 600.0, 120.0, 0.4f).any { it.contains("옆") })
        assertEquals(0, FaceSimilarity.quality(150f, 0.95f, 600.0, 120.0, 0.05f).size)
    }
}
