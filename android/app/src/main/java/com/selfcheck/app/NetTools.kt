package com.selfcheck.app

import java.net.InetAddress
import java.util.TreeSet

/*
 * 네트워크 도구의 계산 부분 (화면·인터넷 없이 컴퓨터에서 시험할 수 있게 순수 코틀린으로).
 *  - IP 주소 읽기·종류 판별·글자로 만들기, 서브넷 계산
 *  - 포트 목록 읽기, 자주 쓰는 포트의 이름·위험 설명
 *  - /proc/net/arp 읽기, 임의(랜덤) MAC 판별
 */

/** IP 주소 종류. blocked = 포트 검사를 막는 주소, local = "내 망 안" 주소라서 확인 없이 검사해도 되는 주소 */
enum class IpKind(val label: String, val local: Boolean, val blocked: Boolean, val note: String) {
    PRIVATE("사설 주소 (내부망)", true, false, "집·사무실 공유기 안쪽에서만 쓰는 주소예요. 인터넷에서는 바로 접속할 수 없고, 같은 공유기에 연결된 기기끼리만 보여요."),
    LOOPBACK("루프백 (이 기기 자신)", true, false, "이 기기 자신을 가리키는 주소예요. 다른 기기에서는 접속할 수 없어요."),
    LINK_LOCAL("링크 로컬 (자동 할당)", true, false, "주소를 받지 못했을 때 자동으로 붙는 주소예요. 같은 선·같은 Wi-Fi 안에서만 통해요."),
    CGNAT("통신사 공용 주소 (CGNAT)", false, false, "통신사가 여러 가입자에게 함께 나눠 주는 주소예요. 이 범위의 기기는 내 것이 아닐 가능성이 커요."),
    PUBLIC("공인 주소 (인터넷)", false, false, "인터넷에서 보이는 주소예요. 이 주소에 열려 있는 포트는 누구나 접속을 시도할 수 있어요."),
    MULTICAST("멀티캐스트", false, true, "여러 기기에 한꺼번에 보내는 주소라서 포트를 검사할 수 없어요."),
    BROADCAST("브로드캐스트", false, true, "같은 망의 모든 기기에 보내는 주소라서 포트를 검사할 수 없어요."),
    UNSPECIFIED("미지정 주소", false, true, "\"어떤 주소도 아님\"을 뜻하는 주소라서 검사할 수 없어요."),
    RESERVED("예약·문서용 주소", false, true, "문서 예시·시험용·앞으로 쓸 용도로 따로 떼어 둔 주소라서 실제 장비가 없어요.");

    /** 내 망 밖(공인·통신사 공용) 주소: 검사하려면 "내 장비이거나 허락받았음"을 확인받아야 함 */
    val needsConsent: Boolean get() = !local && !blocked
}

object IpUtil {
    /** 점으로 나눈 IPv4 (192.168.0.1). 칸마다 0~255, 앞에 0 을 붙인 수(010)는 8진수와 헷갈려서 받지 않음 */
    fun parseV4(s: String): ByteArray? {
        val parts = s.trim().split('.')
        if (parts.size != 4) return null
        val out = ByteArray(4)
        for ((i, p) in parts.withIndex()) {
            if (p.isEmpty() || p.length > 3 || !p.all { it in '0'..'9' }) return null
            if (p.length > 1 && p[0] == '0') return null
            val v = p.toInt()
            if (v > 255) return null
            out[i] = v.toByte()
        }
        return out
    }

    /** IPv6 글자처럼 생겼는지 (콜론 2개 이상, 16진수·콜론·점만). 도메인 이름 조회(DNS)를 타지 않게 먼저 걸러 냄 */
    fun looksLikeV6(s: String) = s.count { it == ':' } >= 2 && s.all { it in '0'..'9' || it in 'a'..'f' || it in 'A'..'F' || it == ':' || it == '.' }

    /** IP 글자 → 주소. 도메인 이름은 null (인터넷에 물어보지 않음) */
    fun parse(input: String): InetAddress? {
        val t = input.trim().removePrefix("[").removeSuffix("]")
        parseV4(t)?.let { return InetAddress.getByAddress(it) }
        if (looksLikeV6(t)) return runCatching { InetAddress.getByName(t) }.getOrNull()
        return null
    }

    fun v4ToLong(b: ByteArray): Long = b.fold(0L) { acc, x -> (acc shl 8) or (x.toLong() and 0xff) }
    fun longToV4(v: Long): ByteArray = ByteArray(4) { ((v shr (24 - 8 * it)) and 0xff).toByte() }
    fun v4Text(v: Long): String = longToV4(v).joinToString(".") { (it.toInt() and 0xff).toString() }

    /** 사람이 읽는 글자. IPv6 은 연속된 0 을 ::, 칸 앞의 0 은 생략 */
    fun format(a: InetAddress): String {
        val b = a.address
        if (b.size == 4) return v4Text(v4ToLong(b))
        val g = IntArray(8) { ((b[2 * it].toInt() and 0xff) shl 8) or (b[2 * it + 1].toInt() and 0xff) }
        var bestStart = -1; var bestLen = 0; var i = 0
        while (i < 8) {
            if (g[i] == 0) { var j = i; while (j < 8 && g[j] == 0) j++; if (j - i > bestLen) { bestStart = i; bestLen = j - i }; i = j } else i++
        }
        if (bestLen < 2) bestStart = -1
        val sb = StringBuilder()
        var k = 0
        while (k < 8) {
            if (k == bestStart) { sb.append("::"); k += bestLen; continue }
            if (sb.isNotEmpty() && !sb.endsWith(":")) sb.append(':')
            sb.append(g[k].toString(16)); k++
        }
        return sb.toString()
    }

    /** IPv6 을 줄이지 않은 전체 표기 (2001:0db8:0000:...:0001). IPv4 면 null */
    fun expandV6(a: InetAddress): String? = a.address.takeIf { it.size == 16 }?.let { b ->
        (0 until 8).joinToString(":") { "%02x%02x".format(b[2 * it].toInt() and 0xff, b[2 * it + 1].toInt() and 0xff) }
    }

    private fun inCidr(v: Long, a: Int, b: Int, c: Int, d: Int, prefix: Int): Boolean {
        val base = (a.toLong() shl 24) or (b.toLong() shl 16) or (c.toLong() shl 8) or d.toLong()
        val mask = Subnet.maskOf(prefix)
        return (v and mask) == (base and mask)
    }

    private fun classifyV4(v: Long): IpKind = when {
        v == 0L -> IpKind.UNSPECIFIED
        v == 0xFFFFFFFFL -> IpKind.BROADCAST
        inCidr(v, 0, 0, 0, 0, 8) -> IpKind.RESERVED // "이 네트워크"
        inCidr(v, 10, 0, 0, 0, 8) || inCidr(v, 172, 16, 0, 0, 12) || inCidr(v, 192, 168, 0, 0, 16) -> IpKind.PRIVATE
        inCidr(v, 127, 0, 0, 0, 8) -> IpKind.LOOPBACK
        inCidr(v, 169, 254, 0, 0, 16) -> IpKind.LINK_LOCAL
        inCidr(v, 100, 64, 0, 0, 10) -> IpKind.CGNAT
        inCidr(v, 224, 0, 0, 0, 4) -> IpKind.MULTICAST
        inCidr(v, 240, 0, 0, 0, 4) -> IpKind.RESERVED
        inCidr(v, 192, 0, 0, 0, 24) || inCidr(v, 192, 0, 2, 0, 24) || inCidr(v, 198, 51, 100, 0, 24) || inCidr(v, 203, 0, 113, 0, 24) ||
            inCidr(v, 198, 18, 0, 0, 15) || inCidr(v, 192, 88, 99, 0, 24) -> IpKind.RESERVED
        else -> IpKind.PUBLIC
    }

    fun classify(a: InetAddress): IpKind {
        val b = a.address
        if (b.size == 4) return classifyV4(v4ToLong(b))
        val u = IntArray(16) { b[it].toInt() and 0xff }
        // IPv4 를 IPv6 안에 담은 ::ffff:a.b.c.d 는 안쪽 IPv4 로 판단
        if ((0 until 10).all { u[it] == 0 } && u[10] == 0xff && u[11] == 0xff) return classifyV4(v4ToLong(b.copyOfRange(12, 16)))
        return when {
            u.all { it == 0 } -> IpKind.UNSPECIFIED
            (0 until 15).all { u[it] == 0 } && u[15] == 1 -> IpKind.LOOPBACK
            u[0] == 0xff -> IpKind.MULTICAST
            u[0] == 0xfe && (u[1] and 0xc0) == 0x80 -> IpKind.LINK_LOCAL
            (u[0] and 0xfe) == 0xfc -> IpKind.PRIVATE // fc00::/7 (고유 로컬)
            u[0] == 0x20 && u[1] == 0x01 && u[2] == 0x0d && u[3] == 0xb8 -> IpKind.RESERVED // 문서용 2001:db8::/32
            (u[0] and 0xe0) == 0x20 -> IpKind.PUBLIC // 2000::/3 (일반 인터넷 주소)
            else -> IpKind.RESERVED
        }
    }

    /** 점이 가운데 낀 IPv4 의 여러 표기 (예: 192.168.0.1 → 십진 3232235521, 16진 C0A80001) */
    fun v4Forms(v: Long): List<Pair<String, String>> = listOf(
        "십진수" to v.toString(),
        "16진수" to "0x" + "%08X".format(v),
        "2진수" to (0 until 4).joinToString(".") { i -> ((v shr (24 - 8 * i)) and 0xff).toString(2).padStart(8, '0') },
        "역방향 조회 이름" to (3 downTo 0).joinToString(".") { i -> ((v shr (24 - 8 * i)) and 0xff).toString() } + ".in-addr.arpa",
    )
}

/** IPv4 서브넷 (CIDR) 계산 */
class Subnet(val network: Long, val prefix: Int) {
    val mask: Long get() = maskOf(prefix)
    val wildcard: Long get() = mask.inv() and 0xFFFFFFFFL
    val broadcast: Long get() = network or wildcard
    /** 쓸 수 있는 기기 주소 수 (/31 은 2, /32 는 1) */
    val hostCount: Long get() = when {
        prefix >= 32 -> 1L
        prefix == 31 -> 2L
        else -> (1L shl (32 - prefix)) - 2
    }
    val first: Long get() = if (prefix >= 31) network else network + 1
    val last: Long get() = if (prefix >= 31) broadcast else broadcast - 1

    companion object {
        fun maskOf(prefix: Int): Long = if (prefix <= 0) 0L else (0xFFFFFFFFL shl (32 - prefix.coerceAtMost(32))) and 0xFFFFFFFFL

        fun of(ip: Long, prefix: Int) = Subnet(ip and maskOf(prefix), prefix)

        /** "192.168.0.77/24" 또는 "192.168.0.77/255.255.255.0" (기기 주소를 줘도 네트워크 주소로 맞춰 줌) */
        fun parse(s: String): Subnet? {
            val t = s.trim()
            val slash = t.indexOf('/')
            if (slash < 0) return null
            val ip = IpUtil.parseV4(t.substring(0, slash))?.let { IpUtil.v4ToLong(it) } ?: return null
            val tail = t.substring(slash + 1).trim()
            val prefix = if ('.' in tail) {
                val m = IpUtil.parseV4(tail)?.let { IpUtil.v4ToLong(it) } ?: return null
                val inv = m.inv() and 0xFFFFFFFFL
                if ((inv and (inv + 1)) != 0L) return null // 1 이 이어진 마스크만 (255.0.255.0 같은 건 아님)
                java.lang.Long.bitCount(m)
            } else tail.toIntOrNull() ?: return null
            if (prefix !in 0..32) return null
            return of(ip, prefix)
        }
    }
}

object Lan {
    /** 기기 찾기 범위: 내 주소가 속한 네트워크. /24 보다 큰 망은 내 주소가 속한 /24 만 (두 번째 값 true = 줄였음) */
    fun range(ip: Long, prefix: Int): Pair<Subnet, Boolean> {
        val p = if (prefix in 24..30) prefix else 24
        return Subnet.of(ip, p) to (prefix < 24)
    }

    fun addresses(s: Subnet): List<Long> = (s.first..s.last).toList()
}

/** 이웃 기기 표 (/proc/net/arp) 한 줄 */
class ArpEntry(val ip: String, val mac: String, val device: String)

object Arp {
    /** 완성된 항목(Flags 0x2)만. MAC 이 전부 0 이면 제외 */
    fun parse(text: String): List<ArpEntry> = text.lineSequence().drop(1).mapNotNull { line ->
        val f = line.trim().split(Regex("\\s+"))
        if (f.size < 6) return@mapNotNull null
        val flags = f[2].removePrefix("0x").toIntOrNull(16) ?: return@mapNotNull null
        val mac = f[3].lowercase()
        if (flags and 2 == 0 || mac == "00:00:00:00:00:00" || IpUtil.parseV4(f[0]) == null) null else ArpEntry(f[0], mac, f[5])
    }.toList()

    /** 첫 바이트의 둘째 비트가 1 이면 기기가 연결할 때마다 바꾸는 임의(랜덤) MAC — 제조사를 알 수 없음 */
    fun isRandomMac(mac: String): Boolean = mac.take(2).toIntOrNull(16)?.let { (it and 2) != 0 } ?: false
}

/** 사용자가 붙여 넣은 글("https://user@Example.com:8443/path?q")에서 주소(호스트)만 뽑기 */
object HostInput {
    fun host(input: String): String {
        var s = input.trim()
        val scheme = s.indexOf("://")
        if (scheme >= 0) s = s.substring(scheme + 3)
        s = s.substringBefore('/').substringBefore('?').substringBefore('#').substringAfterLast('@')
        if (s.startsWith("[")) return s.substringAfter('[').substringBefore(']')
        if (s.count { it == ':' } == 1) s = s.substringBefore(':')
        return s.trimEnd('.')
    }

    /** 도메인 이름으로 쓸 수 있는 글자인지 (공백·기호 거르기). 숫자와 점만 있는데 IPv4 가 아니면 false */
    fun isPlausibleDomain(h: String): Boolean {
        if (h.isEmpty() || h.length > 253 || '.' !in h && h.length > 63) return false
        if (h.all { it in '0'..'9' || it == '.' }) return false
        return h.split('.').all { it.isNotEmpty() && it.length <= 63 && it.first() != '-' && it.last() != '-' } &&
            h.all { it.isLetterOrDigit() || it == '-' || it == '_' || it == '.' }
    }
}

/** 포트 하나에 대한 설명. risk: 0 보통, 1 주의, 2 위험(인터넷에 열려 있으면 안 되는 서비스) */
class PortInfo(val name: String, val risk: Int, val advice: String = "")

class PortSpec(val ports: List<Int>, val error: String?)

object Ports {
    /** 내 망 밖(공인) 주소는 한 번에 이만큼까지만 (남의 장비에 부담을 주지 않도록) */
    const val MAX_REMOTE = 2048
    const val MAX_ALL = 65535

    val SERVICES: Map<Int, PortInfo> = mapOf(
        21 to PortInfo("FTP (파일 전송)", 2, "암호화 없이 파일을 주고받아요. 꼭 필요하지 않으면 끄고, 필요하면 SFTP 를 쓰세요."),
        22 to PortInfo("SSH (원격 접속)", 1, "서버 원격 관리용이에요. 필요한 곳만 열고, 비밀번호 대신 키 인증과 접속 IP 제한을 쓰세요."),
        23 to PortInfo("Telnet (원격 접속)", 2, "암호화 없는 구식 원격 접속이에요. 거의 항상 꺼야 해요 (IoT 기기를 노리는 악성코드가 가장 먼저 찾는 문이에요)."),
        25 to PortInfo("SMTP (메일 보내기)", 1, "메일 서버가 아니라면 열려 있을 이유가 없어요."),
        53 to PortInfo("DNS (주소 풀이)", 1, "공유기·DNS 서버가 아니라면 닫아 두세요. 인터넷에 열면 공격에 악용될 수 있어요."),
        80 to PortInfo("HTTP (웹, 암호화 없음)", 0, "웹 관리 화면이라면 로그인 정보가 암호화되지 않고 오가요. 가능하면 HTTPS 를 쓰세요."),
        110 to PortInfo("POP3 (메일 받기)", 1, "암호화 없는 메일 받기예요."),
        111 to PortInfo("RPC (rpcbind)", 2, "리눅스 원격 호출 서비스예요. 인터넷에 열면 안 돼요."),
        135 to PortInfo("MS RPC (윈도)", 2, "윈도 원격 호출이에요. 인터넷에 열면 안 돼요."),
        139 to PortInfo("NetBIOS (윈도 공유)", 2, "구형 윈도 파일·프린터 공유예요. 인터넷에 열면 안 돼요."),
        143 to PortInfo("IMAP (메일 받기)", 1, "암호화 없는 메일 받기예요."),
        389 to PortInfo("LDAP (계정 목록)", 1, "회사 계정 목록 서비스예요. 외부에 열 이유가 거의 없어요."),
        443 to PortInfo("HTTPS (웹, 암호화)", 0),
        445 to PortInfo("SMB (윈도 파일 공유)", 2, "인터넷에 열려 있으면 랜섬웨어·웜이 가장 많이 파고드는 문이에요. 내부망에서만 쓰세요."),
        465 to PortInfo("SMTPS (메일 보내기)", 0),
        515 to PortInfo("LPD (프린터)", 1, "프린터 공유 서비스예요. 외부에 열 필요가 없어요."),
        548 to PortInfo("AFP (맥 파일 공유)", 1, "애플 파일 공유예요. 외부에 열 필요가 없어요."),
        554 to PortInfo("RTSP (카메라 영상)", 2, "CCTV·IP 카메라 영상 스트림이에요. 인터넷에 열려 있으면 영상이 노출될 수 있어요."),
        587 to PortInfo("SMTP 제출 (메일 보내기)", 0),
        631 to PortInfo("IPP (프린터 공유)", 1, "프린터 공유 서비스예요. 외부에 열 필요가 없어요."),
        873 to PortInfo("rsync (파일 동기화)", 1, "인증 없이 열려 있으면 파일이 그대로 읽힐 수 있어요."),
        993 to PortInfo("IMAPS (메일 받기, 암호화)", 0),
        995 to PortInfo("POP3S (메일 받기, 암호화)", 0),
        1080 to PortInfo("SOCKS (프록시)", 2, "열려 있으면 남이 내 연결을 중계 통로로 쓸 수 있어요."),
        1433 to PortInfo("SQL Server (데이터베이스)", 2, "데이터베이스는 인터넷에 직접 열지 마세요."),
        1521 to PortInfo("Oracle (데이터베이스)", 2, "데이터베이스는 인터넷에 직접 열지 마세요."),
        1723 to PortInfo("PPTP (구형 VPN)", 1, "보안이 약한 구형 VPN 이에요. WireGuard·IPsec 같은 것으로 바꾸세요."),
        1883 to PortInfo("MQTT (IoT 메시지)", 1, "인증 없이 열려 있는 경우가 많아요. 외부에 열었다면 꼭 계정을 거세요."),
        2049 to PortInfo("NFS (파일 공유)", 2, "인터넷에 열면 안 돼요."),
        2375 to PortInfo("Docker (원격 관리, 암호화 없음)", 2, "열려 있으면 서버를 통째로 넘겨줄 수 있어요. 바로 닫으세요."),
        3000 to PortInfo("개발용 웹 서버", 0, "개발 중인 서비스가 그대로 열려 있지 않은지 확인하세요."),
        3306 to PortInfo("MySQL (데이터베이스)", 2, "데이터베이스는 인터넷에 직접 열지 마세요."),
        3389 to PortInfo("RDP (윈도 원격 데스크톱)", 2, "인터넷에 열면 비밀번호 무차별 대입 공격이 쉴 새 없이 들어와요. VPN 뒤에 두세요."),
        5000 to PortInfo("UPnP · NAS · 개발 서버", 1, "NAS 관리 화면이거나 공유기의 UPnP 일 수 있어요."),
        5001 to PortInfo("NAS 관리 (HTTPS)", 0),
        5060 to PortInfo("SIP (인터넷 전화)", 1, "전화기·IP 전화가 아니라면 열려 있을 이유가 없어요."),
        5432 to PortInfo("PostgreSQL (데이터베이스)", 2, "데이터베이스는 인터넷에 직접 열지 마세요."),
        5555 to PortInfo("ADB (안드로이드 디버그)", 2, "열려 있으면 같은 망의 누구나 이 기기를 조종할 수 있어요. 개발자 옵션에서 끄세요."),
        5900 to PortInfo("VNC (원격 화면)", 2, "비밀번호가 약하거나 없는 경우가 많아요. 인터넷에 열면 안 돼요."),
        5984 to PortInfo("CouchDB (데이터베이스)", 2, "데이터베이스는 인터넷에 직접 열지 마세요."),
        5985 to PortInfo("WinRM (윈도 원격 관리)", 2, "인터넷에 열면 안 돼요."),
        6379 to PortInfo("Redis (데이터베이스)", 2, "비밀번호 없이 열려 있는 경우가 많아요. 인터넷에 열면 안 돼요."),
        7000 to PortInfo("AirPlay (애플 화면 공유)", 0),
        7547 to PortInfo("TR-069 (통신사 공유기 원격 관리)", 2, "통신사가 공유기를 관리하는 문이에요. 인터넷에 열려 있으면 취약점 공격 대상이 돼요."),
        8000 to PortInfo("HTTP 대체 (웹)", 0),
        8008 to PortInfo("HTTP 대체 · 크롬캐스트", 0),
        8009 to PortInfo("크롬캐스트", 0),
        8080 to PortInfo("HTTP 대체 (웹 관리 화면)", 0, "공유기·NAS·카메라의 관리 화면일 수 있어요. 기본 비밀번호를 바꿨는지 확인하세요."),
        8081 to PortInfo("HTTP 대체 (웹)", 0),
        8291 to PortInfo("MikroTik Winbox (공유기 관리)", 2, "인터넷에 열려 있으면 공격 대상이 돼요."),
        8443 to PortInfo("HTTPS 대체 (웹)", 0),
        8883 to PortInfo("MQTT (암호화)", 0),
        8888 to PortInfo("HTTP 대체 (웹)", 0),
        9000 to PortInfo("웹 관리 화면 (Portainer 등)", 0),
        9100 to PortInfo("프린터 인쇄 포트 (JetDirect)", 1, "누구나 인쇄를 보낼 수 있어요. 외부에 열 필요가 없어요."),
        9200 to PortInfo("Elasticsearch (검색 데이터)", 2, "인증 없이 열려 있으면 데이터가 그대로 읽혀요. 인터넷에 열면 안 돼요."),
        10000 to PortInfo("Webmin (서버 관리 웹)", 1, "서버 관리 화면이에요. 외부에 열었다면 접속 IP 를 제한하세요."),
        11211 to PortInfo("Memcached (캐시)", 2, "인터넷에 열면 안 돼요 (대규모 공격에 악용돼 왔어요)."),
        27017 to PortInfo("MongoDB (데이터베이스)", 2, "데이터베이스는 인터넷에 직접 열지 마세요."),
        34567 to PortInfo("DVR · CCTV 전용", 2, "녹화기 전용 포트예요. 인터넷에 열려 있으면 영상이 노출될 수 있어요."),
        37777 to PortInfo("Dahua 카메라 · DVR", 2, "카메라·녹화기 전용 포트예요. 인터넷에 열려 있으면 영상이 노출될 수 있어요."),
        49152 to PortInfo("UPnP (공유기 자동 포트 열기)", 1, "UPnP 가 켜져 있으면 기기들이 알아서 인터넷 쪽 문을 열 수 있어요. 필요 없으면 공유기에서 끄세요."),
        62078 to PortInfo("iOS 기기 (아이폰·아이패드)", 0, "애플 기기가 쓰는 포트예요."),
    )

    /** "빠른 검사"에서 보는 포트: 설명이 있는 주요 포트 전부 */
    val QUICK: List<Int> = SERVICES.keys.sorted()

    /** 연결되면 "HEAD /" 요청을 보내 서버 정보를 읽는 웹 포트 */
    val HTTP: Set<Int> = setOf(80, 81, 3000, 5000, 8000, 8008, 8080, 8081, 8888, 9000, 10000)

    /** 먼저 암호화 인사(TLS)를 해야 말하는 포트: 배너를 기다려도 소용없어서 건너뜀 */
    val TLS: Set<Int> = setOf(443, 465, 636, 993, 995, 2376, 5001, 5986, 8009, 8443, 8883)

    fun describe(port: Int): PortInfo? = SERVICES[port]

    /** "22, 80,443 8000-8100" → 정렬·중복 제거한 목록. max 는 한 번에 허용하는 포트 수 */
    fun parse(spec: String, max: Int): PortSpec {
        fun err(m: String) = PortSpec(emptyList(), m)
        val set = TreeSet<Int>()
        val tokens = spec.split(',', ' ', ';', '\n', '\t').map { it.trim() }.filter { it.isNotEmpty() }
        if (tokens.isEmpty()) return err("포트 번호를 입력하세요 (예: 22,80,443 또는 8000-8100)")
        for (tok in tokens) {
            val dash = tok.indexOf('-')
            if (dash < 0) {
                val p = tok.toIntOrNull() ?: return err("\"$tok\" 은(는) 포트 번호가 아니에요")
                if (p !in 1..65535) return err("포트 번호는 1~65535 사이예요 ($tok)")
                set += p
            } else {
                val a = tok.substring(0, dash).trim().toIntOrNull(); val b = tok.substring(dash + 1).trim().toIntOrNull()
                if (a == null || b == null) return err("범위는 \"8000-8100\" 처럼 적어 주세요 ($tok)")
                if (a !in 1..65535 || b !in 1..65535) return err("포트 번호는 1~65535 사이예요 ($tok)")
                if (a > b) return err("범위는 작은 수부터 적어 주세요 ($tok)")
                if (b - a + 1 > max) return err("한 번에 최대 ${"%,d".format(max)}개까지 검사할 수 있어요 ($tok)")
                for (p in a..b) { set += p; if (set.size > max) break }
            }
            if (set.size > max) return err("한 번에 최대 ${"%,d".format(max)}개까지 검사할 수 있어요")
        }
        return PortSpec(set.toList(), null)
    }
}
