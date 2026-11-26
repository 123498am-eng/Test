package com.selfcheck.app

import java.io.BufferedInputStream
import java.io.EOFException
import java.io.File
import java.io.InputStream
import java.net.Inet4Address
import java.net.InetAddress
import java.nio.ByteBuffer
import java.util.zip.GZIPInputStream

/*
 * 오프라인 IP 자료: IP 주소 → 국가 · 통신사(ASN 번호와 이름).
 * 자료는 DB-IP Lite (CC BY 4.0, https://db-ip.com) 의 국가·ASN 표를 작게 줄여 앱(assets/ipdb)에 넣은 것입니다.
 * 이 조회는 폰 안에서만 이루어지고 어디로도 IP 를 보내지 않습니다.
 * 주의: 나라는 "그 주소 블록이 쓰이는 나라" 수준이고, 개인의 위치나 집 주소와는 무관합니다.
 */

/** 나라 이름 (한국어). 코드는 ISO 3166-1 두 글자 */
object CountryNames {
    private val MAP: Map<String, String> by lazy {
        ("AD 안도라|AE 아랍에미리트|AF 아프가니스탄|AG 앤티가 바부다|AI 앵귈라|AL 알바니아|AM 아르메니아|AO 앙골라|AQ 남극|AR 아르헨티나|AS 아메리칸사모아|AT 오스트리아|AU 호주|AW 아루바|AX 올란드 제도|AZ 아제르바이잔|" +
            "BA 보스니아 헤르체고비나|BB 바베이도스|BD 방글라데시|BE 벨기에|BF 부르키나파소|BG 불가리아|BH 바레인|BI 부룬디|BJ 베냉|BL 생바르텔레미|BM 버뮤다|BN 브루나이|BO 볼리비아|BQ 보네르·신트외스타티위스·사바|BR 브라질|BS 바하마|BT 부탄|BV 부베 섬|BW 보츠와나|BY 벨라루스|BZ 벨리즈|" +
            "CA 캐나다|CC 코코스 제도|CD 콩고민주공화국|CF 중앙아프리카공화국|CG 콩고|CH 스위스|CI 코트디부아르|CK 쿡 제도|CL 칠레|CM 카메룬|CN 중국|CO 콜롬비아|CR 코스타리카|CU 쿠바|CV 카보베르데|CW 퀴라소|CX 크리스마스 섬|CY 키프로스|CZ 체코|" +
            "DE 독일|DJ 지부티|DK 덴마크|DM 도미니카연방|DO 도미니카공화국|DZ 알제리|EC 에콰도르|EE 에스토니아|EG 이집트|EH 서사하라|ER 에리트레아|ES 스페인|ET 에티오피아|FI 핀란드|FJ 피지|FK 포클랜드 제도|FM 미크로네시아|FO 페로 제도|FR 프랑스|" +
            "GA 가봉|GB 영국|GD 그레나다|GE 조지아|GF 프랑스령 기아나|GG 건지 섬|GH 가나|GI 지브롤터|GL 그린란드|GM 감비아|GN 기니|GP 과들루프|GQ 적도 기니|GR 그리스|GS 사우스조지아 사우스샌드위치 제도|GT 과테말라|GU 괌|GW 기니비사우|GY 가이아나|" +
            "HK 홍콩|HM 허드 맥도널드 제도|HN 온두라스|HR 크로아티아|HT 아이티|HU 헝가리|ID 인도네시아|IE 아일랜드|IL 이스라엘|IM 맨 섬|IN 인도|IO 영국령 인도양 지역|IQ 이라크|IR 이란|IS 아이슬란드|IT 이탈리아|JE 저지 섬|JM 자메이카|JO 요르단|JP 일본|" +
            "KE 케냐|KG 키르기스스탄|KH 캄보디아|KI 키리바시|KM 코모로|KN 세인트키츠 네비스|KP 북한|KR 대한민국|KW 쿠웨이트|KY 케이맨 제도|KZ 카자흐스탄|LA 라오스|LB 레바논|LC 세인트루시아|LI 리히텐슈타인|LK 스리랑카|LR 라이베리아|LS 레소토|LT 리투아니아|LU 룩셈부르크|LV 라트비아|LY 리비아|" +
            "MA 모로코|MC 모나코|MD 몰도바|ME 몬테네그로|MF 생마르탱|MG 마다가스카르|MH 마셜 제도|MK 북마케도니아|ML 말리|MM 미얀마|MN 몽골|MO 마카오|MP 북마리아나 제도|MQ 마르티니크|MR 모리타니|MS 몬트세랫|MT 몰타|MU 모리셔스|MV 몰디브|MW 말라위|MX 멕시코|MY 말레이시아|MZ 모잠비크|" +
            "NA 나미비아|NC 뉴칼레도니아|NE 니제르|NF 노퍽 섬|NG 나이지리아|NI 니카라과|NL 네덜란드|NO 노르웨이|NP 네팔|NR 나우루|NU 니우에|NZ 뉴질랜드|OM 오만|PA 파나마|PE 페루|PF 프랑스령 폴리네시아|PG 파푸아뉴기니|PH 필리핀|PK 파키스탄|PL 폴란드|PM 생피에르 미클롱|PN 핏케언 제도|PR 푸에르토리코|PS 팔레스타인|PT 포르투갈|PW 팔라우|PY 파라과이|" +
            "QA 카타르|RE 레위니옹|RO 루마니아|RS 세르비아|RU 러시아|RW 르완다|SA 사우디아라비아|SB 솔로몬 제도|SC 세이셸|SD 수단|SE 스웨덴|SG 싱가포르|SH 세인트헬레나|SI 슬로베니아|SJ 스발바르 얀마옌|SK 슬로바키아|SL 시에라리온|SM 산마리노|SN 세네갈|SO 소말리아|SR 수리남|SS 남수단|ST 상투메 프린시페|SV 엘살바도르|SX 신트마르턴|SY 시리아|SZ 에스와티니|" +
            "TC 터크스 케이커스 제도|TD 차드|TF 프랑스령 남방 지역|TG 토고|TH 태국|TJ 타지키스탄|TK 토켈라우|TL 동티모르|TM 투르크메니스탄|TN 튀니지|TO 통가|TR 튀르키예|TT 트리니다드 토바고|TV 투발루|TW 대만|TZ 탄자니아|UA 우크라이나|UG 우간다|UM 미국령 군소 제도|US 미국|UY 우루과이|UZ 우즈베키스탄|" +
            "VA 바티칸|VC 세인트빈센트 그레나딘|VE 베네수엘라|VG 영국령 버진아일랜드|VI 미국령 버진아일랜드|VN 베트남|VU 바누아투|WF 왈리스 푸투나|WS 사모아|XK 코소보|YE 예멘|YT 마요트|ZA 남아프리카공화국|ZM 잠비아|ZW 짐바브웨")
            .split('|').associate { it.substring(0, 2) to it.substring(3) }
    }

    fun ko(code: String?): String = code?.let { MAP[it.uppercase()] } ?: (code ?: "알 수 없음")
    fun label(code: String?): String = if (code == null) "자료 없음" else "${ko(code)} (${code.uppercase()})"
    fun isKnown(code: String) = MAP.containsKey(code.uppercase())
    val all: Map<String, String> get() = MAP

    /** "한국", "korea", "kr", "미국" 처럼 입력한 글에서 나라 코드를 찾음 (코드 · 한국어 이름 일부 · 자주 쓰는 영어 이름) */
    fun find(input: String): String? {
        val t = input.trim()
        if (t.isEmpty()) return null
        val up = t.uppercase()
        if (up.length == 2 && MAP.containsKey(up)) return up
        EN[t.lowercase()]?.let { return it }
        MAP.entries.firstOrNull { it.value == t }?.let { return it.key }
        return MAP.entries.firstOrNull { it.value.contains(t) }?.key
    }

    private val EN = mapOf(
        "korea" to "KR", "south korea" to "KR", "한국" to "KR", "japan" to "JP", "china" to "CN", "usa" to "US", "united states" to "US", "america" to "US", "russia" to "RU", "germany" to "DE", "france" to "FR",
        "united kingdom" to "GB", "uk" to "GB", "england" to "GB", "taiwan" to "TW", "hong kong" to "HK", "singapore" to "SG", "vietnam" to "VN", "india" to "IN", "brazil" to "BR", "canada" to "CA", "australia" to "AU",
        "turkey" to "TR", "netherlands" to "NL", "north korea" to "KP", "북한" to "KP",
    )
}

class GeoAsn(val asn: Int, val name: String) {
    override fun toString() = "AS$asn $name"
}

/** 한 IP 에 대한 오프라인 조회 결과 */
class IpGeoInfo(val ip: String, val country: String?, val asn: GeoAsn?) {
    val countryLabel: String get() = CountryNames.label(country)
    val orgLabel: String get() = asn?.let { "AS${it.asn} ${it.name}" } ?: "자료 없음"
}

class IpGeoDb(private val open: (String) -> InputStream) {
    private class VarReader(val ins: InputStream) {
        fun u8(): Int { val b = ins.read(); if (b < 0) throw EOFException(); return b }
        fun long(): Long { var r = 0L; var shift = 0; while (true) { val b = u8(); if (shift < 64) r = r or ((b and 0x7F).toLong() shl shift); if (b and 0x80 == 0) return r; shift += 7 } }
        fun int(): Int = long().toInt()
        fun bytes(n: Int): ByteArray { val a = ByteArray(n); var o = 0; while (o < n) { val r = ins.read(a, o, n - o); if (r < 0) throw EOFException(); o += r }; return a }
    }

    /** starts[i] 부터 다음 시작 전까지가 vals[i] (0 = 자료 없음) */
    private class Table(val starts: LongArray, val vals: IntArray)

    private fun reader(name: String): VarReader = VarReader(BufferedInputStream(GZIPInputStream(open(name), 1 shl 16), 1 shl 16))

    private fun readTable(r: VarReader, wideVals: Boolean): Table {
        val n = r.int()
        val starts = LongArray(n)
        var cur = 0L
        for (i in 0 until n) { cur += r.long(); starts[i] = cur }
        val vals = IntArray(n) { if (wideVals) r.int() else r.u8() }
        return Table(starts, vals)
    }

    private class CTable(val table: Table, val codes: List<String>)

    private fun loadC(name: String, magic: String): CTable {
        val r = reader(name)
        require(String(r.bytes(2), Charsets.US_ASCII) == magic) { "자료 형식이 달라요: $name" }
        val k = r.int(); val raw = r.bytes(k * 2)
        val codes = (0 until k).map { String(raw, it * 2, 2, Charsets.US_ASCII) }
        return CTable(readTable(r, false), codes)
    }

    private fun loadA(name: String, magic: String): Table {
        val r = reader(name)
        require(String(r.bytes(2), Charsets.US_ASCII) == magic) { "자료 형식이 달라요: $name" }
        return readTable(r, true)
    }

    private val c4 by lazy { loadC("ipdb/c4.bin", "C4") }
    private val c6 by lazy { loadC("ipdb/c6.bin", "C6") }
    private val a4 by lazy { loadA("ipdb/a4.bin", "A4") }
    private val a6 by lazy { loadA("ipdb/a6.bin", "A6") }

    private class AsnTable(val numbers: IntArray, val names: Array<String>)

    private val asns: AsnTable by lazy {
        val r = reader("ipdb/asn.bin")
        require(String(r.bytes(2), Charsets.US_ASCII) == "AS") { "자료 형식이 달라요: asn" }
        val m = r.int(); val nums = IntArray(m); val names = Array(m) { "" }
        var cur = 0L
        for (i in 0 until m) { cur += r.long(); nums[i] = cur.toInt(); val len = r.int(); names[i] = String(r.bytes(len), Charsets.UTF_8) }
        AsnTable(nums, names)
    }

    /** 자료 설명 (출처·기준일) */
    val sourceNote: String by lazy {
        runCatching { open("ipdb/info.txt").use { it.readBytes().toString(Charsets.UTF_8).trim() } }.getOrDefault("DB-IP Lite")
    }

    private fun find(t: Table, key: Long, unsigned: Boolean): Int {
        var lo = 0; var hi = t.starts.size - 1; var ans = -1
        while (lo <= hi) {
            val mid = (lo + hi) ushr 1
            val c = if (unsigned) java.lang.Long.compareUnsigned(t.starts[mid], key) else t.starts[mid].compareTo(key)
            if (c <= 0) { ans = mid; lo = mid + 1 } else hi = mid - 1
        }
        return ans
    }

    private fun isV4(a: InetAddress): Boolean {
        if (a is Inet4Address) return true
        val b = a.address
        return b.size == 4
    }

    private fun v4Key(a: InetAddress): Long = IpUtil.v4ToLong(a.address)
    private fun v6Key(a: InetAddress): Long = ByteBuffer.wrap(a.address, 0, 8).long

    /** IPv4 로 보이는 주소(::ffff:a.b.c.d 포함)면 IPv4 주소로 바꿈 */
    private fun norm(a: InetAddress): InetAddress {
        val b = a.address
        if (b.size == 16 && (0 until 10).all { b[it].toInt() == 0 } && b[10].toInt() == -1 && b[11].toInt() == -1) return InetAddress.getByAddress(b.copyOfRange(12, 16))
        return a
    }

    fun country(addr: InetAddress): String? {
        val a = norm(addr)
        return if (isV4(a)) { val t = c4; val i = find(t.table, v4Key(a), false); if (i < 0) null else t.codes.getOrNull(t.table.vals[i] - 1) }
        else { val t = c6; val i = find(t.table, v6Key(a), true); if (i < 0) null else t.codes.getOrNull(t.table.vals[i] - 1) }
    }

    fun asn(addr: InetAddress): GeoAsn? {
        val a = norm(addr)
        val v = if (isV4(a)) { val t = a4; val i = find(t, v4Key(a), false); if (i < 0) 0 else t.vals[i] }
        else { val t = a6; val i = find(t, v6Key(a), true); if (i < 0) 0 else t.vals[i] }
        if (v <= 0) return null
        val s = asns
        return GeoAsn(s.numbers[v - 1], s.names[v - 1])
    }

    fun lookup(addr: InetAddress): IpGeoInfo = IpGeoInfo(IpUtil.format(addr), country(addr), asn(addr))

    fun lookup(text: String): IpGeoInfo? = IpUtil.parse(text)?.let { lookup(it) }

    /** ASN 번호의 이름 */
    fun asnName(asn: Int): String? {
        val s = asns
        val i = java.util.Arrays.binarySearch(s.numbers, asn)
        return if (i >= 0) s.names[i] else null
    }

    /** 이름에 글자가 들어 있는 ASN 찾기 (대소문자 무시, 최대 limit 개). 숫자만 넣으면 번호가 같은 것도 포함 */
    fun searchAsn(query: String, limit: Int = 50): List<GeoAsn> {
        val q = query.trim().lowercase()
        if (q.isEmpty()) return emptyList()
        val s = asns
        val out = ArrayList<GeoAsn>()
        val num = q.removePrefix("as").toIntOrNull()
        for (i in s.numbers.indices) {
            if (s.numbers[i] == num || s.names[i].lowercase().contains(q)) { out += GeoAsn(s.numbers[i], s.names[i]); if (out.size >= limit) break }
        }
        return out
    }

    /** IPv4: 국가에 속한 주소 범위 (시작, 끝). 이웃한 범위는 합쳐서 돌려줌 */
    fun countryRanges(code: String): List<Pair<Long, Long>> {
        val t = c4
        val idx = t.codes.indexOf(code.uppercase()) + 1
        if (idx <= 0) return emptyList()
        return rangesOf(t.table, idx)
    }

    /** IPv4: ASN 이 쓰는 주소 범위 */
    fun asnRanges(asn: Int): List<Pair<Long, Long>> {
        val s = asns
        val k = java.util.Arrays.binarySearch(s.numbers, asn)
        if (k < 0) return emptyList()
        return rangesOf(a4, k + 1)
    }

    private fun rangesOf(t: Table, value: Int): List<Pair<Long, Long>> {
        val out = ArrayList<Pair<Long, Long>>()
        for (i in t.starts.indices) {
            if (t.vals[i] != value) continue
            val end = if (i + 1 < t.starts.size) t.starts[i + 1] - 1 else 0xFFFFFFFFL
            if (out.isNotEmpty() && out.last().second + 1 == t.starts[i]) out[out.size - 1] = out.last().first to end else out += t.starts[i] to end
        }
        return out
    }

    /** 가진 나라 코드 목록 */
    val countryCodes: List<String> get() = c4.codes

    companion object {
        @Volatile private var shared: IpGeoDb? = null
        fun shared(open: (String) -> InputStream): IpGeoDb = shared ?: synchronized(this) { shared ?: IpGeoDb(open).also { shared = it } }

        /** 컴퓨터에서 시험할 때: assets 폴더에서 바로 읽음 */
        fun ofAssetsDir(dir: File) = IpGeoDb { name -> File(dir, name).inputStream() }
    }
}
