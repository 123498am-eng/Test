package com.selfcheck.app

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Test

class PlateParserTest {
    @Test fun newFormat() {
        assertEquals("12가3456", PlateParser.parse("12가 3456"))
        assertEquals("123가4567", PlateParser.parse("123가4567"))
        assertEquals("98허1234", PlateParser.parse(" 98 허 1234 "))
    }

    @Test fun regional() {
        assertEquals("서울12가3456", PlateParser.parse("서울 12 가 3456"))
        assertEquals("경기34바5678", PlateParser.parse("경기34바 5678"))
    }

    @Test fun ocrConfusions() {
        assertEquals("12가3456", PlateParser.parse("I2가 34S6"))
        assertEquals("10누8008", PlateParser.parse("1O누 BOO8"))
        assertEquals("12가3456", PlateParser.parse("12가-3456."))
    }

    @Test fun rejects() {
        assertNull(PlateParser.parse("안녕하세요"))
        assertNull(PlateParser.parse("12가 345"))        // 숫자 부족
        assertNull(PlateParser.parse("12깨3456"))        // 번호판에 안 쓰는 한글
        assertNull(PlateParser.parse("010-1234-5678"))
    }

    @Test fun extraDigitsInFront() {
        assertEquals("234가5678", PlateParser.parse("1234가5678"))
    }

    @Test fun pretty() {
        assertEquals("12가 3456", PlateParser.pretty("12가3456"))
        assertEquals("서울 12가 3456", PlateParser.pretty("서울12가3456"))
    }

    @Test fun voting() {
        assertNull(PlateParser.vote(listOf("12가3456")))
        assertEquals("12가3456", PlateParser.vote(listOf("12가3456", "12가3458", "12가3456")))
        assertNull(PlateParser.vote(listOf("12가3456", "12가3458")))
    }
}
