package com.selfcheck.app

/** 번호판 글자로 알 수 있는 일반 정보 (차량 종류·용도·형식). 소유자 등 개인 정보는 번호판에 들어 있지 않으며 이 앱은 조회하지 않습니다. */
class PlateInfo(
    val plate: String,
    val valid: Boolean,
    val format: String,
    val region: String?,
    val kind: String,
    val usage: String,
    val notes: List<String>,
)

object PlateInfoDecoder {
    private const val PRIVATE = "가나다라마거너더러머버서어저고노도로모보소오조구누두루무부수우주"
    private const val BUSINESS = "아바사자"
    private const val DELIVERY = "배"
    private const val RENTAL = "하허호"
    private val FORMAT = Regex("^(${PlateParser.REGIONS.joinToString("|")})?(\\d{2,3})([${PlateParser.HANGUL}])(\\d{4})$")

    /** plate: PlateParser.parse 결과 ("12가3456", "서울12가3456") */
    fun decode(plate: String): PlateInfo? {
        val m = FORMAT.find(plate) ?: return null
        val region = m.groupValues[1].ifEmpty { null }
        val digits = m.groupValues[2]; val ch = m.groupValues[3][0]
        val n = digits.toInt()
        val notes = ArrayList<String>()
        var valid = true

        val kind = if (digits.length == 2) when (n) {
            in 1..69 -> "승용차"; in 70..79 -> "승합차(버스·승합)"; in 80..97 -> "화물차"; in 98..99 -> "특수차"
            else -> { valid = false; "알 수 없음" }
        } else when (n) {
            in 100..699 -> "승용차"; in 700..799 -> "승합차(버스·승합)"; in 800..979 -> "화물차"; in 980..997 -> "특수차"
            else -> { valid = false; "알 수 없음" }
        }
        if (!valid) notes += "앞 숫자(${digits})가 번호판에 쓰이지 않는 범위입니다. 글자를 잘못 읽었을 수 있습니다."

        val usage = when {
            ch in PRIVATE -> "자가용(비사업용) — 보통 흰색 번호판 (전기차는 파란색 바탕)"
            ch in BUSINESS -> "사업용(택시·버스·화물 등 운수업) — 노란색 번호판 (구형은 녹색)"
            ch in DELIVERY -> "택배용 화물차 — 노란색 번호판 (2019년 이후)"
            ch in RENTAL -> "렌터카(대여 사업용) — 하늘색 번호판 (2019년 이후, 이전에는 노란색)"
            else -> "알 수 없음"
        }
        val format = when {
            region != null -> "구형 지역 표기 (등록 지역이 앞에 붙던 방식, 숫자 ${digits.length}자리)"
            digits.length == 3 -> "신형 (숫자 3자리, 2019년 9월 이후 발급 방식)"
            else -> "숫자 2자리 형식 (2019년 이전에 발급된 번호판에 많음)"
        }
        if (region != null) notes += "차량의 등록 지역 표기는 '$region'입니다 (이사해도 번호판을 바꾸지 않았다면 현재 사는 곳과 다를 수 있습니다)."
        notes += "전기차 여부·색상은 글자만으로는 알 수 없습니다 (전기차는 파란색 번호판, 2021년 이후)."
        notes += "번호판 글자에는 소유자·차종·연식·색상이 들어 있지 않습니다."
        return PlateInfo(plate, valid, format, region, kind, usage, notes)
    }
}

/** 번호판으로 쓸 수 있는 공식 서비스 (본인 차량·정당한 용도). 주소는 정부 서비스의 대표 주소입니다. */
object PlateLinks {
    class Link(val title: String, val desc: String, val url: String)
    val ALL = listOf(
        Link("자동차365 (내 차 정보·검사·정비)", "내 차의 검사 일정·정비 이력·리콜 등을 봅니다 (국토교통부, 본인 차량)", "https://www.car365.go.kr"),
        Link("정부24 (자동차 등록원부)", "내 차 등록원부를 발급·열람합니다. 본인 확인이 필요하며 다른 사람의 개인정보는 보여 주지 않습니다", "https://www.gov.kr"),
        Link("이파인 (교통 과태료·범칙금)", "받은 고지서의 과태료·범칙금을 조회·납부합니다 (고지 받은 본인)", "https://www.efine.go.kr"),
        Link("안전신문고 (불법 주정차·교통 위반 신고)", "번호판이 찍힌 사진으로 위반 차량을 신고합니다. 처리는 관할 기관이 합니다", "https://www.safetyreport.go.kr"),
    )
    const val OWNER_NOTE = "번호판으로 차 주인의 이름·연락처·주소를 찾는 기능은 없습니다. 개인정보 보호법상 소유자 정보는 본인이나 정당한 이해관계인(교통사고 피해자 등)이 경찰·보험사·관할 기관을 통해서만 확인할 수 있고, 일반인이 알아내면 스토킹·사적 보복에 악용될 수 있습니다. " +
        "접촉사고·뺑소니·불법 주차 피해는 112 또는 위 신고 서비스, 보험사로 알리세요."
}
