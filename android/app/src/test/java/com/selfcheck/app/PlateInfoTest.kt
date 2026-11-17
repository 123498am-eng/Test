package com.selfcheck.app

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

class PlateInfoTest {
    private fun d(p: String) = PlateInfoDecoder.decode(p)!!

    @Test fun kinds() {
        assertEquals("승용차", d("12가3456").kind); assertEquals("승용차", d("123가4567").kind)
        assertEquals("승합차(버스·승합)", d("75바1234").kind); assertEquals("승합차(버스·승합)", d("712아1234").kind)
        assertEquals("화물차", d("85사1234").kind); assertEquals("화물차", d("800자1234").kind)
        assertEquals("특수차", d("98거1234").kind); assertEquals("특수차", d("990너1234").kind)
    }

    @Test fun usage() {
        assertTrue(d("12가3456").usage.startsWith("자가용")); assertTrue(d("12바3456").usage.startsWith("사업용"))
        assertTrue(d("12하3456").usage.startsWith("렌터카")); assertTrue(d("800배1234").usage.startsWith("택배"))
    }

    @Test fun formatAndRegion() {
        assertTrue(d("123가4567").format.startsWith("신형"))
        val r = d("서울12가3456"); assertEquals("서울", r.region); assertTrue(r.format.startsWith("구형 지역"))
        assertNull(d("12가3456").region)
    }

    @Test fun invalidRanges() {
        assertFalse(d("00가1234").valid); assertFalse(d("999가1234").valid); assertTrue(d("100가1234").valid)
        assertTrue(d("12가3456").valid)
    }

    @Test fun rejectsNonPlatesAndNeverClaimsOwner() {
        assertNull(PlateInfoDecoder.decode("안녕"))
        assertNotNull(PlateLinks.OWNER_NOTE)
        assertTrue(PlateLinks.ALL.all { it.url.startsWith("https://") && (it.url.endsWith("go.kr") || it.url.endsWith("gov.kr")) })
    }
}
