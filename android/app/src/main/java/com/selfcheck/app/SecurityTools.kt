package com.selfcheck.app

import java.net.URI
import java.security.MessageDigest
import java.security.SecureRandom
import kotlin.math.ln
import kotlin.math.max
import kotlin.math.min
import kotlin.math.pow

/** 링크 검사 결과. level: 0 뚜렷한 위험 신호 없음, 1 주의, 2 위험 */
class LinkResult(val level: Int, val verdict: String, val reasons: List<String>, val host: String)

/** 주소(URL)만 보고 피싱·사칭 신호를 찾습니다 (접속하지 않음). 안전을 보장하지는 않습니다. */
object LinkCheck {
    val SHORTENERS = setOf("bit.ly", "bitly.com", "goo.gl", "t.co", "tinyurl.com", "is.gd", "ow.ly", "buff.ly", "han.gl", "me2.do", "url.kr",
        "vo.la", "t.ly", "cutt.ly", "rebrand.ly", "shorturl.at", "tiny.cc", "naver.me", "abit.ly", "buly.kr", "zrr.kr", "c11.kr", "lrl.kr",
        "asq.kr", "di.do", "u.to", "rb.gy", "qrco.de", "s.id", "lnk.to", "v.gd", "shrtco.de", "linktr.ee", "bit.do", "hoy.kr", "muz.so")
    private val BAD_TLDS = setOf("xyz", "top", "icu", "click", "zip", "mov", "tk", "ml", "ga", "cf", "gq", "work", "rest", "cam", "monster",
        "buzz", "sbs", "cfd", "lol", "quest", "bond", "cyou", "beauty", "hair", "skin", "makeup", "autos", "boats", "homes", "yachts", "loan", "win", "bid", "vip", "pw", "su")
    /** 사칭이 잦은 이름 → 공식 주소들 */
    val BRANDS = mapOf(
        "naver" to listOf("naver.com", "naver.me", "naver.net"), "kakao" to listOf("kakao.com", "kakaocorp.com", "kakaobank.com", "kakaopay.com"),
        "daum" to listOf("daum.net"), "coupang" to listOf("coupang.com"), "toss" to listOf("toss.im", "tossbank.com"),
        "kbstar" to listOf("kbstar.com"), "kbcard" to listOf("kbcard.com"), "shinhan" to listOf("shinhan.com", "shinhancard.com"),
        "wooribank" to listOf("wooribank.com"), "woori" to listOf("wooribank.com", "wooricard.com", "woorifg.com"), "hanabank" to listOf("hanabank.com"),
        "nonghyup" to listOf("nonghyup.com"), "nhbank" to listOf("nonghyup.com"), "ibk" to listOf("ibk.co.kr"), "kebhana" to listOf("kebhana.com"),
        "samsung" to listOf("samsung.com", "samsungcard.com"), "hyundaicard" to listOf("hyundaicard.com"), "lottecard" to listOf("lottecard.co.kr"),
        "google" to listOf("google.com", "google.co.kr", "youtube.com", "goo.gl"), "apple" to listOf("apple.com", "icloud.com"),
        "paypal" to listOf("paypal.com"), "microsoft" to listOf("microsoft.com", "live.com", "office.com"), "instagram" to listOf("instagram.com"),
        "facebook" to listOf("facebook.com", "fb.com"), "netflix" to listOf("netflix.com"), "amazon" to listOf("amazon.com", "amazon.co.jp"),
        "epost" to listOf("epost.go.kr"), "cjlogistics" to listOf("cjlogistics.com"), "hanjin" to listOf("hanjin.com", "hanjin.co.kr"),
        "lotteglogis" to listOf("lotteglogis.com"), "hometax" to listOf("hometax.go.kr"), "nhis" to listOf("nhis.or.kr"), "gov" to listOf("gov.kr"),
        "baemin" to listOf("baemin.com"), "11st" to listOf("11st.co.kr"), "gmarket" to listOf("gmarket.co.kr"), "kakaobank" to listOf("kakaobank.com"),
    )
    private val SECOND_LEVEL = setOf("co", "or", "go", "ne", "re", "ac", "pe", "mil", "com", "net", "org")

    /** 등록 도메인 (예: login.naver.com → naver.com, www.ibk.co.kr → ibk.co.kr) */
    fun registrable(host: String): String {
        val p = host.split('.').filter { it.isNotEmpty() }
        if (p.size <= 2) return p.joinToString(".")
        return if (p.last().length == 2 && p[p.size - 2] in SECOND_LEVEL) p.takeLast(3).joinToString(".") else p.takeLast(2).joinToString(".")
    }

    private fun lev(a: String, b: String): Int {
        val d = Array(a.length + 1) { IntArray(b.length + 1) }
        for (i in 0..a.length) d[i][0] = i
        for (j in 0..b.length) d[0][j] = j
        for (i in 1..a.length) for (j in 1..b.length) d[i][j] = minOf(d[i - 1][j] + 1, d[i][j - 1] + 1, d[i - 1][j - 1] + if (a[i - 1] == b[j - 1]) 0 else 1)
        return d[a.length][b.length]
    }
    /** 숫자·비슷한 글자로 바꾼 주소를 원래 글자로 (0→o, 1→l, rn→m ...) */
    private fun deconfuse(s: String) = s.replace("rn", "m").replace("vv", "w").replace('0', 'o').replace('1', 'l').replace('3', 'e').replace('5', 's').replace('4', 'a').replace('7', 't').replace('8', 'b')

    fun check(input: String): LinkResult {
        val raw = input.trim()
        val withScheme = if (Regex("^[a-zA-Z][a-zA-Z0-9+.-]*://").containsMatchIn(raw)) raw else "http://$raw"
        val uri = runCatching { URI(withScheme.replace(" ", "%20")) }.getOrNull()
        val host = (uri?.host ?: Regex("://([^/:?#@]+)").find(withScheme)?.groupValues?.get(1) ?: "").lowercase().trimEnd('.')
        if (host.isEmpty()) return LinkResult(1, "주소를 읽을 수 없음", listOf("올바른 링크 형식이 아닙니다"), "")
        val reasons = ArrayList<String>(); var score = 0
        fun add(s: Int, r: String) { score += s; reasons += r }
        val scheme = uri?.scheme?.lowercase() ?: "http"
        if (scheme == "http" && raw.startsWith("http://", true)) add(1, "암호화되지 않은 연결(http)입니다")
        if (scheme != "http" && scheme != "https") add(1, "웹 주소가 아닌 형식($scheme)입니다")
        if (Regex("^\\d{1,3}(\\.\\d{1,3}){3}$").matches(host) || host.startsWith("[")) add(2, "이름 대신 숫자(IP) 주소를 씁니다 — 피싱에 흔함")
        if (host.split('.').any { it.startsWith("xn--") }) add(2, "외국 글자로 비슷하게 만든 주소(퓨니코드)입니다")
        if (uri?.rawUserInfo != null || Regex("://[^/]*@").containsMatchIn(withScheme)) add(2, "주소에 @ 가 있어 실제 목적지를 숨길 수 있습니다")
        val reg = registrable(host)
        if (reg in SHORTENERS || host in SHORTENERS) add(1, "단축 주소라 실제 목적지가 숨겨져 있습니다")
        val tld = host.substringAfterLast('.')
        if (tld in BAD_TLDS) add(1, "피싱에 자주 쓰이는 도메인(.$tld)입니다")
        if (uri != null && uri.port != -1 && uri.port != 80 && uri.port != 443) add(1, "특이한 포트 번호(${uri.port})를 씁니다")
        val labels = host.split('.')
        if (labels.size > 4) add(1, "하위 주소가 지나치게 많습니다")
        if (host.count { it == '-' } >= 3) add(1, "주소에 '-' 가 많습니다")
        if (host.length > 40) add(1, "주소가 매우 깁니다")
        val path = (uri?.rawPath ?: "") + "?" + (uri?.rawQuery ?: "")
        if (Regex("\\.apk(\\?|$|/)", RegexOption.IGNORE_CASE).containsMatchIn(path)) add(3, "앱 설치 파일(apk)을 내려받는 링크입니다 — 스미싱 악성 앱에 주의")
        // 사칭: 유명 이름이 들어갔는데 공식 주소가 아님 / 공식 이름과 한두 글자만 다름
        val official = BRANDS.values.flatten().toSet()
        val isOfficial = reg in official || official.any { host == it || host.endsWith(".$it") }
        if (!isOfficial) {
            val hostFlat = deconfuse(host.replace("-", "").replace(".", ""))
            val hit = BRANDS.keys.firstOrNull { b -> b.length >= 4 && hostFlat.contains(b) }
            if (hit != null) add(3, "'$hit' 이름이 들어 있지만 공식 주소(${BRANDS[hit]!!.first()})가 아닙니다 — 사칭 의심")
            else {
                val first = deconfuse(reg.substringBefore('.'))
                val near = BRANDS.entries.firstOrNull { (b, sites) -> b.length >= 4 && sites.any { s -> val o = s.substringBefore('.'); o != first && lev(first, o) in 1..(if (o.length >= 7) 2 else 1) } }
                if (near != null) add(3, "공식 주소(${near.value.first()})와 한두 글자만 다릅니다 — 사칭 의심")
            }
            if (Regex("(login|signin|verify|account|update|secure|wallet|password|banking|auth|confirm)", RegexOption.IGNORE_CASE).containsMatchIn(host + path))
                add(1, "로그인·인증을 요구하는 주소입니다")
        }
        val level = when { score >= 3 -> 2; score >= 1 -> 1; else -> 0 }
        val verdict = when (level) { 2 -> "위험 — 열지 마세요"; 1 -> "주의 — 보낸 사람을 확인하세요"; else -> "뚜렷한 위험 신호 없음 (안전 보장은 아님)" }
        return LinkResult(level, verdict, reasons, host)
    }

    private val URL_RE = Regex("((https?://)|(www\\.))[^\\s<>\"']+|\\b[a-zA-Z0-9-]+(\\.[a-zA-Z0-9-]+)*\\.(com|net|org|kr|me|ly|io|co|xyz|top|icu|click|link|site|online|shop|info|cc|to|gl|do|so|im|app|page|live|vip|tk|ml|ga|cf|gq|cn|ru)(/[^\\s]*)?", RegexOption.IGNORE_CASE)
    fun findUrls(text: String): List<String> = URL_RE.findAll(text).map { it.value.trimEnd('.', ',', ')', '」', '"') }.filter { it.length > 4 }.distinct().toList()
}

class SmsResult(val level: Int, val score: Int, val verdict: String, val reasons: List<String>, val links: List<Pair<String, LinkResult>>)

/** 문자(스미싱) 검사: 흔한 사기 문자 유형의 단어·링크·전화번호를 봅니다. */
object SmsCheck {
    private class Rule(val score: Int, val reason: String, val words: List<String>)
    private val RULES = listOf(
        Rule(1, "택배·배송 안내를 사칭하는 유형", listOf("택배", "배송", "운송장", "주소지", "주소 확인", "주소확인", "부재", "반송", "통관", "관세", "보관 기간")),
        Rule(1, "결제·승인 안내를 사칭하는 유형", listOf("결제", "승인", "해외결제", "구매", "주문", "출금", "카드 발급", "카드발급", "결제완료")),
        Rule(1, "정부·기관을 사칭하는 유형", listOf("국민건강보험", "건강보험", "국세청", "환급", "지원금", "재난지원", "검찰", "경찰청", "법원", "출석요구", "벌금", "과태료", "범칙금", "교통위반", "민원", "고지서", "건강검진")),
        Rule(1, "대출 권유", listOf("대출", "저금리", "대환", "햇살론", "한도 조회", "신용 등급", "정부지원")),
        Rule(2, "가족·지인을 사칭하는 유형 ('폰 고장' 등)", listOf("폰이 고장", "폰 고장", "휴대폰 고장", "액정", "핸드폰이 깨", "문화상품권", "상품권", "대신 결제", "인증번호 좀", "신분증 사진", "엄마 나", "아빠 나")),
        Rule(1, "청첩장·부고 등 경조사 사칭", listOf("청첩장", "부고", "돌잔치", "모바일 초대장", "장례식장")),
        Rule(1, "계정 정지·본인 확인 요구", listOf("계정", "정지", "해지", "잠금", "비밀번호", "로그인", "본인 확인", "본인확인", "본인인증", "인증 필요")),
        Rule(1, "급하게 행동하게 만드는 말", listOf("즉시", "긴급", "오늘 중", "오늘까지", "24시간", "미확인 시", "확인하지 않으면", "자동 결제", "자동결제", "기한 내")),
        Rule(2, "앱 설치·원격 조종을 요구", listOf("설치", "앱 다운", ".apk", "원격", "팀뷰어", "애니데스크", "보안 앱", "보안앱")),
        Rule(2, "해외에서 보낸 문자 표시", listOf("[국외발신]", "[국제발신]", "[해외발신]")),
    )

    fun check(text: String): SmsResult {
        val reasons = ArrayList<String>(); var score = 0
        val t = text.lowercase()
        for (r in RULES) if (r.words.any { t.contains(it.lowercase()) }) { score += r.score; reasons += r.reason }
        val urls = LinkCheck.findUrls(text)
        val links = urls.map { it to LinkCheck.check(it) }
        if (links.isNotEmpty()) {
            score += 1; reasons += "링크가 들어 있습니다 (모르는 문자 속 링크는 누르지 마세요)"
            val worst = links.maxOf { it.second.level }
            if (worst == 2) { score += 3; reasons += "위험한 링크: " + links.filter { it.second.level == 2 }.joinToString { it.second.host } }
            else if (worst == 1) score += 1
            if (reasons.any { it.contains("택배") || it.contains("경조사") || it.contains("정부") }) score += 1 // 사칭 + 링크 조합
        }
        if (Regex("(\\+(?!82)\\d{1,3}[\\s-]?\\d{2,})|(\\b00[1-9]\\d{0,3}[\\s-]?\\d{3,})").containsMatchIn(text)) { score += 2; reasons += "국제 전화번호가 있습니다" }
        else if (Regex("\\b0\\d{1,2}[-\\s.]?\\d{3,4}[-\\s.]?\\d{4}\\b").containsMatchIn(text) && (t.contains("문의") || t.contains("고객센터") || t.contains("전화"))) { score += 1; reasons += "전화를 걸도록 유도합니다 (공식 번호인지 직접 확인하세요)" }
        val level = when { score >= 4 -> 2; score >= 2 -> 1; else -> 0 }
        val verdict = when (level) { 2 -> "스미싱 위험 높음 — 링크를 누르거나 전화하지 마세요"; 1 -> "주의 — 보낸 곳에 공식 번호로 직접 확인하세요"; else -> "뚜렷한 위험 신호 없음" }
        return SmsResult(level, score, verdict, reasons, links)
    }
}

class PwResult(val score: Int, val label: String, val bits: Double, val crack: String, val tips: List<String>)

/** 비밀번호 강도 (휴대폰 안에서만 계산) */
object PasswordCheck {
    private val COMMON = setOf("123456", "123456789", "12345678", "password", "qwerty", "1234567", "111111", "123123", "abc123", "1234567890",
        "000000", "iloveyou", "1q2w3e4r", "1q2w3e4r5t", "qwer1234", "asdf1234", "zxcv1234", "qwerty123", "a123456", "password1", "1qaz2wsx",
        "sarang", "saranghae", "sarang12", "dkssud", "tkfkd", "tkfkdgo", "qwe123", "asd123", "1234qwer", "q1w2e3r4", "admin", "letmein", "welcome",
        "monkey", "dragon", "football", "baseball", "superman", "princess", "sunshine", "master", "hello", "freedom", "whatever", "trustno1",
        "654321", "666666", "888888", "121212", "7777777", "112233", "11111111", "1111", "0000", "1234", "12341234", "aaaaaa", "abcd1234")
    private val ROWS = listOf("1234567890", "qwertyuiop", "asdfghjkl", "zxcvbnm", "abcdefghijklmnopqrstuvwxyz")

    private fun seqLen(p: String): Int {
        var best = 0
        val s = p.lowercase()
        for (row in ROWS + ROWS.map { it.reversed() }) for (len in 4..s.length) for (i in 0..s.length - len) if (row.contains(s.substring(i, i + len))) best = max(best, len)
        return best
    }

    /** 한글 단어를 영문 자판으로 친 것 같은지 (예: dkssud = 안녕) */
    fun looksKoreanTyped(p: String): Boolean {
        val letters = p.filter { it.isLetter() }.lowercase()
        if (letters.length < 4) return false
        return Regex("^([qwertasdfgzxcv]([yuiophjklbnm]|hk|ho|hl|nj|np|nl|ml){1}([qwertasdfgzxcv]{0,2}))+$").matches(letters)
    }

    fun check(pw: String): PwResult {
        if (pw.isEmpty()) return PwResult(0, "-", 0.0, "-", emptyList())
        var pool = 0
        if (pw.any { it.isLowerCase() && it.code < 128 }) pool += 26
        if (pw.any { it.isUpperCase() && it.code < 128 }) pool += 26
        if (pw.any { it.isDigit() }) pool += 10
        if (pw.any { !it.isLetterOrDigit() && it.code < 128 }) pool += 33
        if (pw.any { it.code >= 128 }) pool += 100
        var bits = pw.length * ln(max(pool, 2).toDouble()) / ln(2.0)
        val tips = ArrayList<String>()
        val low = pw.lowercase()
        if (low in COMMON || COMMON.any { it.length >= 6 && low.contains(it) }) { bits = min(bits, 12.0); tips += "아주 흔한 비밀번호(목록에 있음)입니다" }
        val seq = seqLen(pw)
        if (seq >= 4) { bits -= seq * 2.5; tips += "자판·숫자 순서(${seq}글자)가 들어 있습니다" }
        if (Regex("(.)\\1{2,}").containsMatchIn(pw)) { bits -= 8; tips += "같은 글자가 반복됩니다" }
        if (Regex("(19|20)\\d{2}([01]\\d)([0-3]\\d)|\\b\\d{6}\\b").containsMatchIn(pw)) { bits -= 10; tips += "날짜(생일 등)처럼 보입니다" }
        if (looksKoreanTyped(pw)) { bits -= 10; tips += "한글 단어를 영문 자판으로 친 것 같습니다 (사전 공격에 약함)" }
        if (pw.length < 10) tips += "10자 이상으로 늘리세요"
        if (pool <= 36) tips += "대문자·특수문자를 섞으세요"
        bits = max(bits, 0.0)
        val score = when { bits < 28 -> 0; bits < 40 -> 1; bits < 60 -> 2; bits < 80 -> 3; else -> 4 }
        val label = listOf("매우 약함", "약함", "보통", "강함", "매우 강함")[score]
        // 빠른 오프라인 공격(초당 100억 번) 기준 평균 시간
        val sec = 2.0.pow(bits) / 2 / 1e10
        return PwResult(score, label, bits, human(sec), tips)
    }

    fun human(sec: Double): String = when {
        sec < 1 -> "1초 안"
        sec < 60 -> "${sec.toInt()}초"
        sec < 3600 -> "${(sec / 60).toInt()}분"
        sec < 86400 -> "${(sec / 3600).toInt()}시간"
        sec < 86400 * 365 -> "${(sec / 86400).toInt()}일"
        sec < 86400 * 365 * 1e4 -> "${(sec / 86400 / 365).toInt()}년"
        sec < 86400 * 365 * 1e8 -> "${(sec / 86400 / 365 / 1e4).toInt()}만 년"
        else -> "1억 년 이상"
    }

    fun generate(len: Int, upper: Boolean, digits: Boolean, symbols: Boolean, rnd: SecureRandom = SecureRandom()): String {
        val lower = "abcdefghijkmnopqrstuvwxyz"; val up = "ABCDEFGHJKLMNPQRSTUVWXYZ"; val dg = "23456789"; val sy = "!@#$%^&*-_=+?"
        val sets = listOfNotNull(lower, up.takeIf { upper }, dg.takeIf { digits }, sy.takeIf { symbols })
        val all = sets.joinToString("")
        val out = CharArray(len) { all[rnd.nextInt(all.length)] }
        // 고른 종류가 적어도 한 글자씩 들어가게 (서로 다른 자리에)
        (0 until len).shuffled(rnd).take(sets.size).forEachIndexed { i, p -> out[p] = sets[i][rnd.nextInt(sets[i].length)] }
        return String(out)
    }

    private val WORDS = listOf("apple", "river", "cloud", "tiger", "piano", "maple", "ocean", "rocket", "pepper", "violet", "candle", "mirror",
        "garden", "silver", "planet", "forest", "window", "orange", "dragon", "bridge", "coffee", "lemon", "winter", "summer", "pencil", "rabbit",
        "castle", "island", "yellow", "purple", "button", "camera", "dinner", "rocket", "turtle", "jungle", "basket", "cookie", "marble", "breeze")
    fun passphrase(words: Int, rnd: SecureRandom = SecureRandom()) =
        (1..words).joinToString("-") { WORDS[rnd.nextInt(WORDS.size)] } + "-" + (10 + rnd.nextInt(90))

    fun sha1Hex(s: String): String = MessageDigest.getInstance("SHA-1").digest(s.toByteArray()).joinToString("") { "%02X".format(it) }

    /** HIBP range API 응답("접미사:횟수" 줄들)에서 내 비밀번호 접미사의 횟수 */
    fun countInRange(response: String, suffix: String): Int =
        response.lineSequence().map { it.trim() }.firstOrNull { it.substringBefore(':').equals(suffix, true) }?.substringAfter(':')?.trim()?.toIntOrNull() ?: 0
}

/** 글 속 개인정보 찾기·가리기 */
object PrivacyMask {
    class Hit(val kind: String, val text: String)
    private fun luhn(d: String): Boolean {
        var sum = 0; var alt = false
        for (i in d.length - 1 downTo 0) { var n = d[i] - '0'; if (alt) { n *= 2; if (n > 9) n -= 9 }; sum += n; alt = !alt }
        return sum % 10 == 0
    }
    private val RULES: List<Triple<String, Regex, (String) -> String>> = listOf(
        Triple("주민·외국인등록번호", Regex("\\b\\d{6}[-\\s]?[1-8]\\d{6}\\b")) { s -> s.substring(0, if (s.length == 14) 8 else 7) + "******" },
        Triple("카드번호", Regex("\\b\\d{4}[-\\s]?\\d{4}[-\\s]?\\d{4}[-\\s]?\\d{3,4}\\b")) { s -> s.dropLast(4).replace(Regex("\\d"), "*") + s.takeLast(4) },
        Triple("휴대폰 번호", Regex("\\b01[016789][-\\s.]?\\d{3,4}[-\\s.]?\\d{4}\\b")) { s -> val d = s.filter { it.isDigit() }; d.take(3) + "-****-" + d.takeLast(4) },
        Triple("전화번호", Regex("\\b0(2|[3-6][1-5])[-\\s.]?\\d{3,4}[-\\s.]?\\d{4}\\b")) { s -> s.replace(Regex("\\d(?=\\d{0,3}[-\\s.]\\d{4}$)"), "*") },
        Triple("운전면허번호", Regex("\\b\\d{2}-\\d{2}-\\d{6}-\\d{2}\\b")) { s -> s.take(6) + "******-**" },
        Triple("여권번호", Regex("\\b[MSRODG]\\d{8}\\b|\\b[MSRODG]\\d{3}[A-Z]\\d{4}\\b")) { s -> s.take(1) + "*".repeat(s.length - 3) + s.takeLast(2) },
        Triple("계좌번호(추정)", Regex("\\b\\d{2,6}-\\d{2,6}-\\d{2,7}(-\\d{1,3})?\\b")) { s -> s.replace(Regex("\\d(?=[\\d-]*-[\\d]+$)"), "*") },
        Triple("이메일", Regex("[\\w.+-]+@[\\w-]+(\\.[\\w-]+)+")) { s -> val id = s.substringBefore('@'); id.take(2) + "*".repeat(max(1, id.length - 2)) + "@" + s.substringAfter('@') },
        Triple("IP 주소", Regex("\\b\\d{1,3}(\\.\\d{1,3}){3}\\b")) { s -> s.substringBeforeLast('.') + ".***" },
        Triple("주소(번지)", Regex("[가-힣]+(로|길)\\s?\\d+(-\\d+)?(\\s?\\d+동)?(\\s?\\d+호)?")) { s -> s.replace(Regex("\\d"), "*") },
    )

    fun find(text: String): List<Hit> {
        val out = ArrayList<Hit>(); val used = ArrayList<IntRange>()
        for ((kind, re, _) in RULES) for (m in re.findAll(text)) {
            if (used.any { it.first <= m.range.last && m.range.first <= it.last }) continue
            if (kind == "카드번호" && !luhn(m.value.filter { it.isDigit() })) continue
            out += Hit(kind, m.value); used += m.range
        }
        return out
    }

    fun mask(text: String): String {
        var t = text
        val used = ArrayList<IntRange>()
        val repl = ArrayList<Pair<IntRange, String>>()
        for ((kind, re, f) in RULES) for (m in re.findAll(text)) {
            if (used.any { it.first <= m.range.last && m.range.first <= it.last }) continue
            if (kind == "카드번호" && !luhn(m.value.filter { it.isDigit() })) continue
            used += m.range; repl += m.range to f(m.value)
        }
        for ((r, s) in repl.sortedByDescending { it.first.first }) t = t.replaceRange(r, s)
        return t
    }
}

/** QR 코드 만들기용 글 (와이파이 등) */
object QrText {
    private fun esc(s: String) = s.replace("\\", "\\\\").replace(";", "\\;").replace(",", "\\,").replace(":", "\\:").replace("\"", "\\\"")
    fun wifi(ssid: String, password: String, hidden: Boolean = false): String =
        "WIFI:T:${if (password.isEmpty()) "nopass" else "WPA"};S:${esc(ssid)};" + (if (password.isNotEmpty()) "P:${esc(password)};" else "") + (if (hidden) "H:true;" else "") + ";"
    fun contact(name: String, phone: String, email: String) = "MECARD:N:${esc(name)};TEL:${esc(phone)};EMAIL:${esc(email)};;"
}
