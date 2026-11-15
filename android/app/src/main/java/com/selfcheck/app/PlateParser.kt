package com.selfcheck.app

/**
 * 글자 인식 결과에서 대한민국 자동차 번호판을 찾아 정리합니다.
 * 형식: "12가3456", "123가4567"(신형), "서울12가3456"(지역 표기 구형)
 */
object PlateParser {
    /** 번호판 가운데에 쓰이는 한글 (자가용·사업용·렌터카·택배 등) */
    const val HANGUL = "가나다라마거너더러머버서어저고노도로모보소오조구누두루무부수우주아바사자배하허호"
    val REGIONS = listOf("서울", "부산", "대구", "인천", "광주", "대전", "울산", "세종", "경기", "강원", "충북", "충남", "전북", "전남", "경북", "경남", "제주")

    private val NEW = Regex("(\\d{2,3})([$HANGUL])(\\d{4})")
    private val OLD = Regex("(${REGIONS.joinToString("|")})(\\d{1,2})([$HANGUL])(\\d{4})")

    /** 숫자 자리에 자주 섞이는 비슷한 글자를 숫자로 고칩니다 (한글은 그대로) */
    private val DIGIT_FIX = mapOf(
        'O' to '0', 'o' to '0', 'Q' to '0', 'D' to '0', 'U' to '0',
        'I' to '1', 'l' to '1', '|' to '1', '!' to '1', 'i' to '1', 'L' to '1', 'J' to '1',
        'Z' to '2', 'z' to '2', 'S' to '5', 's' to '5', 'B' to '8', 'G' to '6', 'b' to '6', 'T' to '7', 'g' to '9', 'q' to '9',
    )

    fun normalize(raw: String): String {
        val sb = StringBuilder()
        for (c in raw) {
            when {
                c.isWhitespace() || c in "-.,:;·•_'\"`~()[]" -> {}
                c in '0'..'9' -> sb.append(c)
                c in '가'..'힣' -> sb.append(c)
                c in DIGIT_FIX -> sb.append(DIGIT_FIX[c])
                c in '０'..'９' -> sb.append('0' + (c - '０'))
            }
        }
        return sb.toString()
    }

    /** 한 줄(또는 이어 붙인 줄)에서 번호판을 찾으면 정리된 번호("12가3456" 형태)를 돌려줍니다 */
    fun parse(raw: String): String? {
        val t = normalize(raw)
        OLD.find(t)?.let { m -> return m.groupValues[1] + m.groupValues[2] + m.groupValues[3] + m.groupValues[4] }
        NEW.find(t)?.let { m ->
            // 앞에 숫자가 더 붙어 있으면(예: 1234가5678) 끝쪽 3자리만
            return m.groupValues[1] + m.groupValues[2] + m.groupValues[3]
        }
        return null
    }

    /** 보기 좋게: "12가 3456", "서울 12가 3456" */
    fun pretty(p: String): String {
        val r = REGIONS.firstOrNull { p.startsWith(it) }
        val body = if (r != null) p.removePrefix(r) else p
        val idx = body.indexOfFirst { it in '가'..'힣' }
        val core = if (idx > 0) body.substring(0, idx + 1) + " " + body.substring(idx + 1) else body
        return if (r != null) "$r $core" else core
    }

    /** 같은 번호판을 여러 번 읽은 결과로 다수결 (2번 이상 같고, 다른 후보보다 많을 때 확정) */
    fun vote(reads: List<String>): String? {
        if (reads.isEmpty()) return null
        val counts = reads.groupingBy { it }.eachCount().entries.sortedByDescending { it.value }
        val top = counts[0]
        val second = counts.getOrNull(1)?.value ?: 0
        return if (top.value >= 2 && top.value > second) top.key else null
    }
}
