package com.selfcheck.app

import com.google.zxing.BarcodeFormat
import com.google.zxing.BinaryBitmap
import com.google.zxing.EncodeHintType
import com.google.zxing.RGBLuminanceSource
import com.google.zxing.common.HybridBinarizer
import com.google.zxing.qrcode.QRCodeReader
import com.google.zxing.qrcode.QRCodeWriter
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class SecurityToolsTest {
    @Test fun officialLinksAreNotFlagged() {
        for (u in listOf("https://www.naver.com", "https://m.kbstar.com/quics", "https://www.ibk.co.kr/", "https://accounts.google.com/signin")) {
            val r = LinkCheck.check(u)
            assertEquals("$u ${r.reasons}", 0, r.level)
        }
    }

    @Test fun phishingLinksAreFlagged() {
        assertEquals(2, LinkCheck.check("http://naver-login.xyz/verify").level)          // 이름 사칭 + 위험 도메인
        assertEquals(2, LinkCheck.check("https://kbstar.com.secure-check.net/login").level) // 공식 이름을 앞에 붙인 가짜
        assertEquals(2, LinkCheck.check("http://192.168.10.5/bank").level)                // IP 주소 + http
        assertEquals(2, LinkCheck.check("https://c0upang.com/order").level)               // 0 ↔ o
        assertEquals(2, LinkCheck.check("https://example.com/files/app.apk").level)       // 앱 설치 파일
        assertEquals(1, LinkCheck.check("https://bit.ly/3abcde").level)                   // 단축 주소
        assertTrue(LinkCheck.check("https://xn--80ak6aa92e.com").level >= 1)              // 퓨니코드
    }

    @Test fun registrableDomain() {
        assertEquals("naver.com", LinkCheck.registrable("m.blog.naver.com"))
        assertEquals("ibk.co.kr", LinkCheck.registrable("www.ibk.co.kr"))
        assertEquals("example.com", LinkCheck.registrable("example.com"))
    }

    @Test fun findsUrlsInText() {
        val u = LinkCheck.findUrls("[Web발신] 주소 확인 http://abc.xyz/a1 또는 www.test.kr 참고")
        assertTrue(u.toString(), u.any { it.startsWith("http://abc.xyz") })
        assertTrue(u.toString(), u.any { it.startsWith("www.test.kr") })
    }

    @Test fun smishingMessages() {
        val parcel = SmsCheck.check("[Web발신]\n고객님 택배가 주소지 불명으로 보관 중입니다. 주소 확인 http://cj-logis.xyz/a1")
        assertEquals(parcel.reasons.toString(), 2, parcel.level)
        val family = SmsCheck.check("엄마 나 폰 고장나서 친구 폰으로 문자해. 문화상품권 좀 사줄 수 있어?")
        assertTrue(family.reasons.toString(), family.level >= 1)
        val normal = SmsCheck.check("내일 3시에 회의실에서 봬요")
        assertEquals(0, normal.level)
        val intl = SmsCheck.check("[국외발신] 해외결제 승인 980,000원 본인 아니면 문의 +44 20 1234 5678")
        assertEquals(intl.reasons.toString(), 2, intl.level)
    }

    @Test fun passwordStrength() {
        assertEquals(0, PasswordCheck.check("qwer1234").score)
        assertEquals(0, PasswordCheck.check("123456").score)
        assertTrue(PasswordCheck.check("dkssudgktpdy").tips.any { it.contains("한글") }) // 안녕하세요
        assertTrue(PasswordCheck.check("T7#kq9!Lm2@vZx4%").score >= 3)
        val g = PasswordCheck.generate(20, true, true, true)
        assertEquals(20, g.length)
        assertTrue(g.any { it.isUpperCase() } && g.any { it.isDigit() } && g.any { !it.isLetterOrDigit() })
        assertTrue(PasswordCheck.check(g).score >= 3)
    }

    @Test fun hibpHelpers() {
        // "password" 의 SHA-1 (잘 알려진 값)
        assertEquals("5BAA61E4C9B93F3F0682250B6CF8331B7EE68FD8", PasswordCheck.sha1Hex("password"))
        val body = "1E4C9B93F3F0682250B6CF8331B7EE68FD8:9659365\r\n0018A45C4D1DEF81644B54AB7F969B88D65:3\r\n"
        assertEquals(9659365, PasswordCheck.countInRange(body, "1E4C9B93F3F0682250B6CF8331B7EE68FD8"))
        assertEquals(0, PasswordCheck.countInRange(body, "FFFFF"))
    }

    @Test fun privacyMasking() {
        val text = "주민번호 900101-1234567, 연락처 010-1234-5678, 카드 4111-1111-1111-1111, 메일 hong.gildong@example.com"
        val kinds = PrivacyMask.find(text).map { it.kind }
        assertTrue(kinds.toString(), kinds.containsAll(listOf("주민·외국인등록번호", "휴대폰 번호", "카드번호", "이메일")))
        val m = PrivacyMask.mask(text)
        assertFalse(m, m.contains("1234567"))
        assertFalse(m, m.contains("010-1234-5678"))
        assertTrue(m, m.contains("010-****-5678"))
        assertTrue(m, m.contains("1111") && !m.contains("4111-1111-1111-1111"))
        assertTrue(m, m.contains("ho") && m.contains("@example.com") && !m.contains("hong.gildong"))
        // 루흔 검사에 맞지 않는 16자리 숫자는 카드번호로 보지 않음
        assertFalse(PrivacyMask.find("주문번호 1234-5678-1234-5678").any { it.kind == "카드번호" })
    }

    @Test fun wifiQrRoundTrip() {
        val text = QrText.wifi("우리집;WiFi", "pa:ss")
        assertEquals("WIFI:T:WPA;S:우리집\\;WiFi;P:pa\\:ss;;", text)
        val m = QRCodeWriter().encode(text, BarcodeFormat.QR_CODE, 400, 400, mapOf(EncodeHintType.CHARACTER_SET to "UTF-8"))
        val px = IntArray(m.width * m.height) { if (m.get(it % m.width, it / m.width)) 0xFF000000.toInt() else -1 }
        val read = QRCodeReader().decode(BinaryBitmap(HybridBinarizer(RGBLuminanceSource(m.width, m.height, px))))
        assertEquals(text, read.text)
    }
}
