package com.selfcheck.app

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

/** 위치 공유 메시지 만들기 (순수 로직) — 안드로이드 API 없이 시험 */
class LocationShareTest {
    @Test fun validCoordRange() {
        assertTrue(LocationShare.isValidCoord(37.5663, 126.9779))
        assertTrue(LocationShare.isValidCoord(-33.8688, 151.2093))
        assertTrue(LocationShare.isValidCoord(90.0, 180.0)); assertTrue(LocationShare.isValidCoord(-90.0, -180.0))
        assertFalse(LocationShare.isValidCoord(90.1, 0.0)); assertFalse(LocationShare.isValidCoord(0.0, 180.1))
        assertFalse(LocationShare.isValidCoord(0.0, 0.0))                 // GPS 못 받았을 때 나오는 깨진 값
        assertFalse(LocationShare.isValidCoord(Double.NaN, 10.0)); assertFalse(LocationShare.isValidCoord(10.0, Double.POSITIVE_INFINITY))
    }

    @Test fun googleMapsLinkFormat() {
        // developers.google.com/maps/documentation/urls 의 공식 형식: query=위도,경도 (소수 6자리)
        assertEquals("https://www.google.com/maps/search/?api=1&query=37.566300,126.977900", LocationShare.googleMapsLink(37.5663, 126.9779))
        assertEquals("https://www.google.com/maps/search/?api=1&query=-33.868800,151.209300", LocationShare.googleMapsLink(-33.8688, 151.2093))
        assertEquals("https://www.google.com/maps/search/?api=1&query=0.000000,0.000000", LocationShare.googleMapsLink(0.0, 0.0))
    }

    @Test fun formatCoordRoundsToSixDecimals() {
        assertEquals("37.100000", LocationShare.formatCoord(37.1))
        assertEquals("-126.977900", LocationShare.formatCoord(-126.9779))
    }

    @Test fun accuracyLabelThresholds() {
        assertEquals("정확도를 알 수 없어요", LocationShare.accuracyLabel(null))
        assertEquals("정확도를 알 수 없어요", LocationShare.accuracyLabel(0f))
        assertEquals("정확도를 알 수 없어요", LocationShare.accuracyLabel(-5f))
        assertTrue(LocationShare.accuracyLabel(5f).let { it.contains("5m") && it.contains("정확한 편") })
        assertTrue(LocationShare.accuracyLabel(19.9f).contains("정확한 편"))
        assertTrue(LocationShare.accuracyLabel(20f).contains("보통"))
        assertTrue(LocationShare.accuracyLabel(99.9f).contains("보통"))
        assertTrue(LocationShare.accuracyLabel(100f).let { it.contains("100m") && it.contains("부정확") })
        assertTrue(LocationShare.accuracyLabel(5000f).contains("부정확"))
    }

    @Test fun ageLabelThresholds() {
        val t0 = 1_000_000_000_000L
        assertEquals("방금 확인한 위치", LocationShare.ageLabel(t0, t0))
        assertEquals("방금 확인한 위치", LocationShare.ageLabel(t0, t0 + 4_000))
        assertEquals("5초 전 위치", LocationShare.ageLabel(t0, t0 + 5_000))
        assertEquals("59초 전 위치", LocationShare.ageLabel(t0, t0 + 59_000))
        assertEquals("1분 전 위치", LocationShare.ageLabel(t0, t0 + 60_000))
        assertEquals("2분 전 위치", LocationShare.ageLabel(t0, t0 + 125_000))
        assertEquals("59분 전 위치", LocationShare.ageLabel(t0, t0 + 3_599_000))
        assertEquals("1시간 전 위치 — 오래돼서 지금과 다를 수 있어요", LocationShare.ageLabel(t0, t0 + 3_600_000))
        assertEquals("2시간 전 위치 — 오래돼서 지금과 다를 수 있어요", LocationShare.ageLabel(t0, t0 + 7_300_000))
        assertEquals("방금 확인한 위치", LocationShare.ageLabel(t0, t0 - 500))     // 시계가 거꾸로 가도 음수로 깨지지 않음
    }

    @Test fun messageContainsLinkCoordAndAccuracyInOrder() {
        val now = 1_700_000_000_000L
        val m = LocationShare.message(37.5663, 126.9779, 15f, now, now)
        val lines = m.split("\n")
        assertEquals(3, lines.size)
        assertTrue(lines[0].contains("방금 확인한 위치"))
        assertEquals(LocationShare.googleMapsLink(37.5663, 126.9779), lines[1])
        assertTrue(lines[2].startsWith("좌표 37.566300, 126.977900"))
        assertTrue(lines[2].contains("정확한 편"))
    }

    @Test fun messageWithoutAccuracyHasNoAccuracySuffix() {
        val now = 1_700_000_000_000L
        val m = LocationShare.message(37.5663, 126.9779, null, now, now)
        val lastLine = m.split("\n").last()
        assertFalse(lastLine.contains("·"))
        assertEquals("좌표 37.566300, 126.977900", lastLine)
    }

    @Test fun messageShowsStaleWarningForOldFix() {
        val fixAt = 1_700_000_000_000L
        val m = LocationShare.message(37.5663, 126.9779, 10f, fixAt, fixAt + 7_200_000)
        assertTrue(m.contains("2시간 전 위치 — 오래돼서 지금과 다를 수 있어요"))
    }
}
