package com.selfcheck.app

import java.time.Instant
import java.time.ZoneOffset
import java.time.format.DateTimeFormatter

/**
 * 패킷 해석 도구 10가지: tcpdump·와이어샤크에서 복사한 16진수 패킷, 또는 .pcap/.pcapng 캡처 파일을 폰 안에서 풀어 보여 줘요.
 * 읽기만 하고 어디로도 보내지 않아요. "패킷 만들기"도 16진수와 파일 가져오기용 글만 만들고 실제로 전송하지는 않아요.
 */
object PktTools {
    private const val G = NetGroups.PACKET
    private const val LOCAL = "붙여 넣은 바이트(또는 고른 파일)는 휴대폰 안에서만 해석하고 어디로도 보내지 않아요."
    private const val HEX_HINT = "16진수(공백·줄바꿈 자유). tcpdump -xx · hexdump -C · 와이어샤크 \"Copy as Hex Dump\" 글도 그대로 붙여 넣을 수 있어요"
    private const val BAD_HEX = "16진수로 읽지 못했어요. 0-9, a-f 글자만 쓰고 전체 글자 수가 짝수(바이트 단위)인지 확인하세요"
    private const val FILE_LIMIT = 24_000_000
    private val START = listOf("자동 판별", "이더넷부터", "IP 부터")
    private val CK_MODES = listOf("패킷의 체크섬 검사하고 고치기", "바이트 열의 체크섬만 계산 (RFC 1071)")

    private const val SAMPLE_SYN = "aa bb cc dd ee 01 52 54 00 12 34 56 08 00 45 00\n00 3c 1c 46 40 00 40 06 26 e9 c0 a8 01 0a 5d b8\nd8 22 d4 31 01 bb 00 00 03 e8 00 00 00 00 a0 02\nfa f0 77 c5 00 00 02 04 05 b4 04 02 08 0a 00 00\n03 e8 00 00 00 00 01 03 03 07"
    private const val SAMPLE_BAD = "aa bb cc dd ee 01 52 54 00 12 34 56 08 00 45 00\n00 28 1c 47 40 00 40 06 26 fc c0 a8 01 0a 5d b8\nd8 22 d4 31 01 bb 00 00 03 e8 00 00 00 00 50 02\nfa f0 12 34 00 00"
    private const val SAMPLE_DNS = "30 39 81 80 00 01 00 01 00 00 00 00 07 65 78 61\n6d 70 6c 65 03 63 6f 6d 00 00 01 00 01 07 65 78\n61 6d 70 6c 65 03 63 6f 6d 00 00 01 00 01 00 00\n01 2c 00 04 5d b8 d8 22"
    private const val SAMPLE_TLS = "16 03 01 01 46 01 00 01 42 03 03 da 55 53 41 97 ac b5 ae df 5a 65 1e 72 6d 19 42 45 9c 88 3e 39\nbb ac 68 42 0f 6c b6 15 94 94 b5 20 0e 46 ed 69 80 d6 93 69 f7 77 24 55 8c ab 04 7e 61 a3 8e 7c\na7 dc 5d 9f 4c d5 f7 23 54 53 82 ea 00 3e 13 02 13 03 13 01 c0 2c c0 30 00 9f cc a9 cc a8 cc aa\nc0 2b c0 2f 00 9e c0 24 c0 28 00 6b c0 23 c0 27 00 67 c0 0a c0 14 00 39 c0 09 c0 13 00 33 00 9d\n00 9c 00 3d 00 3c 00 35 00 2f 00 ff 01 00 00 bb 00 00 00 10 00 0e 00 00 0b 65 78 61 6d 70 6c 65\n2e 63 6f 6d 00 0b 00 04 03 00 01 02 00 0a 00 16 00 14 00 1d 00 17 00 1e 00 19 00 18 01 00 01 01\n01 02 01 03 01 04 00 23 00 00 00 10 00 0e 00 0c 02 68 32 08 68 74 74 70 2f 31 2e 31 00 16 00 00\n00 17 00 00 00 0d 00 2a 00 28 04 03 05 03 06 03 08 07 08 08 08 09 08 0a 08 0b 08 04 08 05 08 06\n04 01 05 01 06 01 03 03 03 01 03 02 04 02 05 02 06 02 00 2b 00 05 04 03 04 03 03 00 2d 00 02 01\n01 00 33 00 26 00 24 00 1d 00 20 74 5f 0e 2b 27 4f 25 81 0f 83 26 7e de fc 24 c7 86 02 c4 73 23\neb a4 48 40 96 8d c1 6d a0 ee 53"
    private const val SAMPLE_NTP = "24 02 06 e9 00 00 03 26 00 00 08 d4 c0 a8 01 01\ne8 fe 6b 98 00 00 00 00 e8 fe 6f 80 20 00 00 00\ne8 fe 6f 80 23 00 00 00 e8 fe 6f 80 23 10 00 00"
    private const val SAMPLE_DHCP = "02 01 06 00 12 34 56 78 00 00 00 00 00 00 00 00\nc0 a8 01 32 c0 a8 01 01 00 00 00 00 52 54 00 12\n34 56 00 00 00 00 00 00 00 00 00 00 00 00 00 00\n00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00\n00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00\n00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00\n00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00\n00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00\n00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00\n00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00\n00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00\n00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00\n00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00\n00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00\n00 00 00 00 00 00 00 00 00 00 00 00 63 82 53 63\n35 01 02 36 04 c0 a8 01 01 33 04 00 01 51 80 01\n04 ff ff ff 00 03 04 c0 a8 01 01 06 08 c0 a8 01\n01 08 08 08 08 0f 08 68 6f 6d 65 2e 6c 61 6e 3a\n04 00 00 a8 c0 3b 04 00 01 27 50 ff"

    private fun startKey(i: ToolInput) = when (i.choice("s", START)) { 1 -> "eth"; 2 -> "ip"; else -> "auto" }
    private fun hex(b: ByteArray) = b.joinToString("") { "%02x".format(it.toInt() and 0xff) }
    private fun hexLines(b: ByteArray) = (b.indices step 16).joinToString("\n") { Bx.hex(b, it, minOf(b.size, it + 16)) }
    private fun us(t: Long): String = DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss.SSS").withZone(ZoneOffset.UTC).format(Instant.ofEpochSecond(Math.floorDiv(t, 1_000_000L), Math.floorMod(t, 1_000_000L) * 1000)) + " UTC"

    /** 16진수 입력칸 → 바이트. 비었거나 읽을 수 없으면 안내 결과 */
    private fun bytesOrNull(i: ToolInput, key: String = "h"): ByteArray? = PacketHex.parse(i.raw(key))
    private fun hexProblem(i: ToolInput, key: String = "h"): ToolResult = if (i.str(key).isEmpty()) need("패킷 바이트를 붙여 넣으세요") else fail(BAD_HEX)

    private fun loadCap(host: ToolHost): Pair<PcapRead.Capture?, String?> {
        val f = host.file("f") ?: return null to "캡처 파일(.pcap / .pcapng)을 고르세요"
        val bytes = f.open()?.use { it.readUpTo(FILE_LIMIT) } ?: return null to "파일을 열지 못했어요"
        val cap = PcapRead.read(bytes)
        if (cap.packets.isEmpty()) return null to (cap.notes.firstOrNull() ?: "패킷이 하나도 없어요")
        val notes = cap.notes + (if (f.size > FILE_LIMIT) listOf("파일이 24MB 를 넘어서 앞부분만 분석했어요") else emptyList())
        return PcapRead.Capture(cap.packets, cap.format, cap.truncatedFile, notes) to null
    }

    private fun capTool(id: String, title: String, desc: String, run: (PcapRead.Capture, ToolHost) -> ToolResult) =
        tool(id, G, title, desc, listOf(file("f", "캡처 파일 (.pcap / .pcapng)")), ToolMode.OFFLINE, "$LOCAL 파일이 24MB 를 넘으면 앞부분만 읽어요. 내 장비·내 망에서 직접 캡처했거나 분석 허락을 받은 파일만 쓰세요.", runLabel = "분석") { _, host, _ ->
            val (cap, err) = loadCap(host); if (cap == null) need(err ?: "파일을 읽지 못했어요") else run(cap, host)
        }

    private fun where(host: ToolHost, ip: String) = LogUtil.where(host.geoDb(), ip)

    // ---------------------------------------------------------------- 패킷 만들기 도우미
    private val BUILD_TYPES = listOf("ICMP Echo 요청 (ping)", "ICMP Echo 응답", "UDP 데이터", "TCP SYN (연결 시작)", "TCP 데이터 (PSH+ACK)", "TCP RST (연결 끊기)", "ARP 요청 (누가 이 IP 인가?)", "ARP 응답", "Wake-on-LAN (매직 패킷)", "NTP 요청")

    private fun dataBytes(s: String): ByteArray? {
        val t = s.trim()
        if (t.startsWith("hex:", true)) return PacketHex.parse(t.substring(4))
        return t.toByteArray(Charsets.UTF_8)
    }

    // ---------------------------------------------------------------- 캡처 필터 도우미
    private class PortRange(val lo: Int, val hi: Int)

    private fun parsePortRanges(s: String): List<PortRange>? {
        val out = ArrayList<PortRange>()
        for (tok in s.split(',', ' ', ';').map { it.trim() }.filter { it.isNotEmpty() }) {
            val m = Regex("^(\\d{1,5})(?:-(\\d{1,5}))?$").find(tok) ?: return null
            val lo = m.groupValues[1].toInt(); val hi = m.groupValues[2].ifEmpty { m.groupValues[1] }.toInt()
            if (lo !in 1..65535 || hi !in 1..65535 || lo > hi) return null
            out += PortRange(lo, hi)
        }
        return out
    }

    private val BPF_PROTO = listOf("전체", "TCP", "UDP", "ICMP", "ICMPv6", "ARP", "IPv6")
    private val BPF_DIR = listOf("보내는 쪽·받는 쪽 모두", "보내는 쪽(출발지)만", "받는 쪽(목적지)만")
    private val BPF_FLAGS = listOf("조건 없음", "SYN 만 (연결 시작 요청)", "SYN+ACK (연결 수락)", "RST (연결 거부·강제 종료)", "FIN (연결 종료)", "PSH (데이터 즉시 전달)")

    val ALL: List<NetTool> = listOf(
        // 1
        tool("pkt_decode", G, "패킷 16진수 해석 (이더넷·IP·TCP·UDP·ICMP·ARP·DNS·TLS)", "tcpdump·와이어샤크에서 복사한 패킷 바이트를 층별로 풀고, 체크섬이 맞는지·TTL·플래그·옵션·응용 계층(DNS·TLS SNI·HTTP)까지 설명해요",
            listOf(multi("h", "패킷 바이트 (16진수)", HEX_HINT, SAMPLE_SYN), choice("s", "시작 위치", START)), ToolMode.OFFLINE, LOCAL, runLabel = "해석") { i, _, _ ->
            val b = bytesOrNull(i) ?: return@tool hexProblem(i)
            val d = PacketDecode.decode(b, startKey(i))
            result {
                kv("요약", d.summary.ifEmpty { "-" }); kv("전체 크기", "${b.size}바이트")
                for (l in d.layers) { head(l.name); for ((k, v) in l.fields) kv(k, v); for ((n, lv) in l.notes) note(n, lv) }
                if (d.truncated) note("캡처가 중간에 잘려 있어요(snaplen). 뒤쪽 층은 읽을 수 없거나 체크섬을 확인할 수 없어요. tcpdump 에 -s 0 을 주면 전체를 담아요.", 1)
            }
        },
        // 2
        tool("pkt_checksum", G, "인터넷 체크섬 검사·고치기 (IP·TCP·UDP·ICMP)", "패킷의 IP 머리글·TCP·UDP·ICMP(IPv6 는 ICMPv6) 체크섬이 맞는지 다시 계산해 보고, 틀리면 전부 고쳐 넣은 패킷을 만들어 줘요. 임의의 바이트 열에는 RFC 1071 체크섬만 계산해요",
            listOf(multi("h", "바이트 (16진수)", HEX_HINT, SAMPLE_BAD), choice("m", "할 일", CK_MODES), choice("s", "시작 위치", START)), ToolMode.OFFLINE, LOCAL, runLabel = "계산") { i, _, _ ->
            val b = bytesOrNull(i) ?: return@tool hexProblem(i)
            if (i.choice("m", CK_MODES) == 1) {
                val sum = InetChecksum.sum(b); val c = InetChecksum.checksum(b)
                result {
                    kv("바이트 수", "${b.size}"); kv("16비트 합(올림 접기)", "0x%04x".format(sum)); kv("체크섬(합의 보수)", "0x%04x".format(c)); kv("체크섬 바이트", "%02x %02x".format(c shr 8, c and 0xff))
                    kv("이미 들어 있는 체크섬 검증", if (sum == 0xffffL) "맞아요 (이 바이트 열 안에 올바른 체크섬이 들어 있어요)" else "맞지 않거나 체크섬이 들어 있지 않아요", level = if (sum == 0xffffL) -1 else 0)
                    if (b.size % 2 == 1) note("바이트 수가 홀수라서 마지막에 0 을 하나 붙여 계산했어요.", 0)
                    note("체크섬을 새로 넣을 때는 그 자리 2바이트를 0 으로 두고 계산한 값을 채워 넣어요. 받는 쪽은 체크섬 자리까지 모두 더해서 0xffff 가 나오는지 확인해요.", 0)
                }
            } else {
                val r = ChecksumFix.analyze(b, startKey(i))
                if (r.problem != null) return@tool fail(r.problem)
                result {
                    header("층", "저장된 값", "계산한 값", "결과")
                    for (it in r.items) row(it.layer, if (it.note != null && it.stored == 0 && it.computed == 0) "-" else "0x%04x".format(it.stored), if (it.note != null && it.stored == 0 && it.computed == 0) "-" else "0x%04x".format(it.computed), if (it.ok) "맞아요" else "틀려요", level = if (it.ok) -1 else 2)
                    for (it in r.items) it.note?.let { n -> note("${it.layer}: $n", if (it.ok) 0 else 2) }
                    if (r.allOk) note("확인할 수 있는 체크섬이 모두 맞아요.", -1)
                    else {
                        note("틀린 체크섬이 있어요. 아래 \"고친 패킷\"은 모든 체크섬을 다시 계산해 넣은 거예요. (같은 기기에서 캡처한 송신 패킷은 NIC 가 체크섬을 나중에 채우는 오프로드 때문에 틀리게 보이는 게 정상일 수 있어요.)", 1)
                        kv("고친 패킷(16진수)", hex(r.fixed)); block(hexLines(r.fixed))
                    }
                }
            }
        },
        // 3
        capTool("pkt_pcap", "캡처 파일(pcap·pcapng) 요약·문제 찾기", "캡처 파일에서 프로토콜 비율·대화 상위·통신량 많은 주소를 보여 주고, 대답 없는 접속(SYN)·연결 거부(RST)·재전송·DNS 실패·ICMP 오류·암호화 안 된 로그인 같은 문제 신호를 찾아내요") { cap, host ->
            val r = PcapStats.analyze(cap); val dur = (r.last - r.first) / 1e6
            result {
                kv("파일 형식", cap.format); kv("패킷 수", "${r.total}개" + if (cap.truncatedFile) " (파일 끝이 잘려 있어요)" else ""); kv("전체 크기", LogUtil.bytes(r.bytes)); kv("기간", "${us(r.first)} ~ ${us(r.last)}")
                kv("길이", "%.3f초".format(dur)); if (dur > 0) kv("평균 속도", "%.1f 패킷/초 · %s/초".format(r.total / dur, LogUtil.bytes((r.bytes / dur).toLong())))
                for (n in cap.notes) note(n, 1)
                head("프로토콜"); header("종류", "패킷", "비율"); for ((p, n) in LogUtil.top(r.protos, 12)) row(p, "$n", LogUtil.pct(n, r.total))
                head("대화(Flow) 상위"); header("종류", "한쪽", "다른 쪽", "패킷", "바이트", "지속")
                for (f in r.flows.take(10)) row(f.proto, f.a, f.b, "${f.packets}", LogUtil.bytes(f.bytes), "%.2f초".format((f.lastUs - f.firstUs) / 1e6))
                head("통신량이 많은 주소"); header("IP", "바이트", "국가·통신사"); for ((ip, n) in r.talkers.take(8)) row(ip, LogUtil.bytes(n), where(host, ip))
                head("점검 결과")
                var problems = 0
                for ((ep, n) in r.synUnanswered.take(6)) { problems++; note("$ep 로 연결(SYN)을 ${n}번 보냈는데 대답이 없어요. 서버가 꺼져 있거나 방화벽이 조용히 버리고(DROP) 있을 수 있어요.", if (n >= 3) 2 else 1) }
                if (r.rst > 0) { problems++; note("연결 거부·강제 종료(RST) ${r.rst}번: ${r.rstFrom.take(4).joinToString(", ") { "${it.first}(${it.second}번)" }}. 닫힌 포트이거나 서버·방화벽이 연결을 끊은 거예요.", 1) }
                if (r.retrans > 0) { problems++; note("재전송으로 보이는 패킷이 ${r.retrans}개(전체의 ${LogUtil.pct(r.retrans, r.total)}). 패킷 손실이나 느린 응답이 있다는 신호예요.", if (r.retrans * 50 >= r.total) 2 else 1) }
                if (r.zeroWin > 0) { problems++; note("TCP 윈도 크기 0 이 ${r.zeroWin}번: 받는 쪽이 느려서 \"그만 보내세요\"라고 한 거예요.", 1) }
                if (r.dnsUnanswered.isNotEmpty()) { problems++; note("답이 없는 DNS 질문: ${r.dnsUnanswered.take(5).joinToString(", ")}. DNS 서버에 닿지 않거나 막혀 있을 수 있어요.", 2) }
                if (r.dnsFail.isNotEmpty()) { problems++; note("DNS 실패 응답: ${r.dnsFail.distinct().take(5).joinToString(", ") { "${it.first} → ${it.second}" }}", 1) }
                for (m in r.icmpUnreach) { problems++; note("ICMP 오류: $m", 1) }
                if (r.arpUnanswered.isNotEmpty()) { problems++; note("ARP 로 물었는데 아무도 대답하지 않은 주소: ${r.arpUnanswered.take(5).joinToString(", ")}. 같은 망에 그 IP 를 가진 기기가 없거나 꺼져 있어요.", 1) }
                for ((what, n) in r.cleartext) { problems++; note("$what ${n}번: 암호화되지 않아 같은 망의 누구나 읽을 수 있어요. (이 도구는 내용을 보여 주지 않아요.)", 2) }
                if (r.fragments > 0) note("IP 조각(fragment) ${r.fragments}개는 안쪽 내용을 읽지 못하고 건너뛰었어요.", 0)
                if (r.notIp > 0) note("IP 가 아닌 프레임 ${r.notIp}개(LLDP·STP 등)는 통계에서 뺐어요.", 0)
                if (problems == 0) note("눈에 띄는 문제 신호가 없어요.", -1)
            }
        },
        // 4
        capTool("pkt_pcap_sites", "캡처 파일 속 접속 대상 (DNS 이름·TLS 서버 이름·HTTP 호스트)", "캡처 안에서 이 기기가 어떤 서버·서비스와 통신했는지 DNS 질문, TLS 의 SNI(접속하려는 서버 이름), 평문 HTTP 의 Host 로 모아서 보여 주고, 연결된 IP 의 국가·통신사를 붙여요") { cap, host ->
            val r = PcapStats.analyze(cap)
            class Row(val sources: LinkedHashMap<String, Int> = LinkedHashMap(), val ips: LinkedHashSet<String> = LinkedHashSet())
            val rows = LinkedHashMap<String, Row>()
            fun entry(name: String) = rows.getOrPut(name.lowercase()) { Row() }
            for ((q, n) in r.dnsQueries) { val name = q.substringBefore(' '); val rw = entry(name); rw.sources.merge("DNS", n, Int::plus); r.dnsAnswers[name.lowercase()]?.let { rw.ips += it } }
            for ((s, n) in r.sni) { val rw = entry(s); rw.sources.merge("TLS", n, Int::plus); r.sniIps[s]?.let { rw.ips += it } }
            for ((h, ips) in r.httpHostIps) { val rw = entry(h); rw.sources.merge("HTTP", r.http.filter { it.first.startsWith("$h ") }.sumOf { it.second }, Int::plus); rw.ips += ips }
            result {
                kv("캡처", "${r.total}개 패킷 · ${us(r.first)} ~ ${us(r.last)}"); kv("이름 수", "${rows.size}개")
                if (rows.isEmpty()) { note("DNS 질문·TLS 서버 이름·HTTP 호스트를 찾지 못했어요. (QUIC·DoH·DoT 처럼 이름이 암호화된 통신이거나, 연결 시작 부분이 캡처에 없을 수 있어요.)", 1); return@result }
                head("접속 대상"); header("이름", "확인한 경로", "IP (국가·통신사)")
                for ((name, rw) in rows.entries.sortedWith(compareByDescending<Map.Entry<String, Row>> { it.value.sources.values.sum() }.thenBy { it.key }).take(60)) {
                    row(name, rw.sources.entries.joinToString(" ") { "${it.key}×${it.value}" }, rw.ips.take(2).joinToString(" / ") { "$it (${where(host, it)})" }.ifEmpty { "-" })
                }
                if (r.dnsUnanswered.isNotEmpty()) note("답을 못 받은 DNS 이름: ${r.dnsUnanswered.take(8).joinToString(", ")}", 1)
                note("DNS·SNI 는 \"어느 서버 이름으로 접속하려 했는지\"만 알려 줘요. 안쪽 내용(암호화된 통신)은 볼 수 없고, 같은 IP 를 여러 사이트가 함께 쓰는 경우도 많아요(CDN).", 0)
                note("남의 통신을 몰래 캡처해서 분석하는 것은 불법일 수 있어요. 내 기기·내 망에서 직접 만든 캡처만 쓰세요.", 1)
            }
        },
        // 5
        tool("pkt_ja3", G, "TLS Hello 해석 (JA3 지문·SNI·암호군·약한 설정)", "TLS ClientHello(또는 ServerHello) 바이트에서 서버 이름(SNI)·ALPN·지원 버전·암호군·확장·JA3/JA3S 지문을 뽑고, 약한 암호군·오래된 버전을 알려 줘요",
            listOf(multi("h", "Hello 바이트 (16진수)", "TLS 기록(16 03 …)부터 또는 이더넷/IP/TCP 헤더까지 포함한 패킷 전체", SAMPLE_TLS)), ToolMode.OFFLINE, LOCAL, runLabel = "해석") { i, _, _ ->
            val b = bytesOrNull(i) ?: return@tool hexProblem(i)
            val h = TlsHello.parse(b) ?: return@tool fail("TLS Hello 를 찾지 못했어요. 바이트가 16 03 0x … 로 시작하는 TLS 핸드셰이크 기록(또는 그 앞에 이더넷·IP·TCP 헤더가 붙은 패킷)인지 확인하세요")
            fun ver(v: Int) = TlsHello.name(TlsHello.VERSIONS, v)
            result {
                kv("종류", if (h.client) "ClientHello (클라이언트 → 서버)" else "ServerHello (서버 → 클라이언트)")
                kv("핸드셰이크 버전", ver(h.version)); h.recordVersion?.let { kv("기록 버전", ver(it)) }
                if (h.supportedVersions.isNotEmpty()) kv(if (h.client) "지원 버전(확장)" else "고른 버전(확장)", h.supportedVersions.joinToString(", ") { ver(it) })
                if (h.client) { if (h.sni != null) kv("서버 이름(SNI)", h.sni) else kv("서버 이름(SNI)", "없음", level = 1) }
                if (h.alpn.isNotEmpty()) kv("ALPN", h.alpn.joinToString(", "))
                kv(if (h.client) "JA3 문자열" else "JA3S 문자열", h.ja3); kv(if (h.client) "JA3 해시(MD5)" else "JA3S 해시(MD5)", h.ja3Hash)
                kv("세션 ID", "${h.sessionId.size}바이트"); if (h.client) kv("압축 방식", h.compression.joinToString(", ") { if (it == 0) "없음" else "$it" })
                if (h.groups.isNotEmpty()) kv("지원 그룹(곡선)", h.groups.joinToString(", ") { TlsHello.name(TlsHello.GROUPS, it) })
                if (h.keyShareGroups.isNotEmpty()) kv("키 공유", h.keyShareGroups.joinToString(", ") { TlsHello.name(TlsHello.GROUPS, it) })
                if (h.sigAlgs.isNotEmpty()) kv("서명 알고리즘", h.sigAlgs.joinToString(", ") { TlsHello.name(TlsHello.SIGS, it) })
                head(if (h.client) "제시한 암호군 (${h.ciphers.size}개, 선호 순서)" else "서버가 고른 암호군"); header("번호", "이름")
                for ((n, c) in h.ciphers.withIndex().take(80)) row("${n + 1}", "0x%04x  %s".format(c, TlsHello.name(TlsHello.CIPHERS, c)), level = if (TlsHello.isWeakCipher(c)) 2 else 0)
                head("확장 (${h.exts.size}개, 순서대로)"); header("번호", "이름"); for (e in h.exts) row("${e.type}", TlsHello.name(TlsHello.EXTENSIONS, e.type))
                head("점검")
                var shown = 0
                if (!h.complete) { shown++; note("Hello 가 한 패킷에 다 들어 있지 않아요(TCP 조각). 뒤쪽 확장이 빠져서 JA3 가 실제와 다를 수 있어요.", 1) }
                if (h.client) {
                    val offered = h.supportedVersions.filter { !TlsHello.isGrease(it) }
                    val maxV = (offered + h.version).maxOrNull() ?: h.version
                    if (maxV >= 0x0304) { shown++; note("TLS 1.3 을 지원해요.", -1) } else { shown++; note("TLS 1.3 을 제시하지 않았어요(최대 ${ver(maxV)}). 오래된 클라이언트이거나 일부러 낮춘 설정이에요.", 1) }
                    val old = (offered + h.version).filter { it in 0x0300..0x0302 }.distinct()
                    if (old.isNotEmpty() && (offered.isNotEmpty() || h.version <= 0x0302)) { shown++; note("오래된 프로토콜 버전(${old.sortedDescending().joinToString(", ") { ver(it) }})을 받아들일 수 있다고 알렸어요. 지금은 쓰지 않는 게 좋아요.", 2) }
                    val weak = h.ciphers.filter { TlsHello.isWeakCipher(it) }
                    if (weak.isNotEmpty()) { shown++; note("약한 암호군 ${weak.size}개를 제시해요: ${weak.take(4).joinToString(", ") { TlsHello.name(TlsHello.CIPHERS, it) }}", 2) }
                    if (h.sni == null) { shown++; note("SNI 가 없어요. IP 로 직접 접속했거나 아주 오래된 클라이언트예요.", 1) }
                    if (h.exts.any { it.type == 65037 }) { shown++; note("ECH(암호화된 ClientHello)를 써서 서버 이름이 숨겨져요.", 0) }
                    if (h.keyShareGroups.any { it == 0x11ec || it == 0x6399 } || h.groups.any { it == 0x11ec || it == 0x6399 }) { shown++; note("양자 컴퓨터에도 견디는(하이브리드) 키 교환을 제시해요.", -1) }
                    if (h.ciphers.any { it == 0x5600 }) { shown++; note("TLS_FALLBACK_SCSV 가 들어 있어요: 낮은 버전으로 다시 시도하는 접속이라는 표시예요.", 1) }
                    val grease = h.ciphers.count { TlsHello.isGrease(it) } + h.exts.count { TlsHello.isGrease(it.type) }
                    if (grease > 0) { shown++; note("GREASE 값이 ${grease}개 들어 있어요(최신 브라우저가 쓰는 무작위 자리표시). JA3 계산에서는 빼요.", 0) }
                    if (h.ciphers.none { it in 0x1301..0x1305 || (TlsHello.CIPHERS[it]?.contains("ECDHE") == true) || (TlsHello.CIPHERS[it]?.contains("DHE") == true) }) { shown++; note("전방 비밀성(ECDHE·DHE)이 되는 암호군이 하나도 없어요.", 2) }
                } else {
                    val chosen = h.ciphers.firstOrNull()
                    if (chosen != null && TlsHello.isWeakCipher(chosen)) { shown++; note("서버가 약한 암호군을 골랐어요: ${TlsHello.name(TlsHello.CIPHERS, chosen)}", 2) }
                    val v = h.supportedVersions.firstOrNull() ?: h.version
                    shown++; note("서버가 고른 버전: ${ver(v)}", if (v >= 0x0303) -1 else 2)
                }
                note("JA3 는 \"어떤 TLS 프로그램이 접속했는지\" 구별하는 지문이에요. 같은 프로그램은 같은 값이 나오지만 값만으로 사람을 알 수는 없어요. 버전·암호군 순서는 프로그램마다 달라요.", 0)
            }
        },
        // 6
        tool("pkt_dns_decode", G, "DNS 패킷 해석 (질문·응답·플래그·레코드)", "DNS 질문·응답 바이트(또는 UDP/TCP 패킷 전체)를 풀어서 플래그(AA·TC·RD·RA·AD)·응답 코드·질문·답·권한·추가 레코드를 보여 줘요",
            listOf(multi("h", "DNS 바이트 (16진수)", HEX_HINT, SAMPLE_DNS)), ToolMode.OFFLINE, LOCAL, runLabel = "해석") { i, _, _ ->
            val b = bytesOrNull(i) ?: return@tool hexProblem(i)
            val tp = PacketDecode.transportPayload(b, setOf(53)); var dns = tp?.first ?: b
            if ((tp == null || tp.second == 6) && dns.size > 14 && Bx.u16(dns, 0) == dns.size - 2) dns = dns.copyOfRange(2, dns.size)                   // TCP DNS 는 앞에 길이 2바이트
            val m = DnsWire.parse(dns) ?: return@tool fail("DNS 메시지로 읽지 못했어요. 바이트가 DNS 헤더(12바이트)로 시작하는지, 또는 UDP/TCP 53번 포트 패킷 전체인지 확인하세요")
            val fl = m.flags; val opcode = (fl shr 11) and 15
            result {
                head("헤더"); kv("ID", "0x%04x".format(m.id)); kv("종류", if (m.isResponse) "응답" else "질문"); kv("opcode", when (opcode) { 0 -> "0 (표준 질의)"; 1 -> "1 (역방향·폐기)"; 2 -> "2 (서버 상태)"; 4 -> "4 (NOTIFY)"; 5 -> "5 (UPDATE)"; else -> "$opcode" })
                kv("플래그", listOfNotNull(if (m.aa) "AA(권한 있는 서버의 답)" else null, if (m.tc) "TC(잘림)" else null, if (m.rd) "RD(재귀 요청)" else null, if (m.ra) "RA(재귀 가능)" else null, if (m.ad) "AD(DNSSEC 검증됨)" else null, if (fl and 0x10 != 0) "CD(검증 끄기)" else null).joinToString(" · ").ifEmpty { "없음" })
                kv("응답 코드", DnsType.rcode(m.rcode), level = if (!m.isResponse || m.rcode == 0) 0 else if (m.rcode == 3) 1 else 2)
                kv("개수", "질문 ${m.questions.size} · 답 ${m.answers.size} · 권한 ${m.authority.size} · 추가 ${m.additional.size}")
                head("질문"); header("이름", "종류"); for ((n, t) in m.questions) row(n, DnsType.name(t))
                for ((title, list) in listOf("답" to m.answers, "권한(Authority)" to m.authority, "추가(Additional)" to m.additional)) if (list.isNotEmpty()) {
                    head(title); header("이름", "종류", "TTL", "내용"); for (r in list.take(60)) row(r.name, r.typeName, "${r.ttl}초", r.data.take(120))
                }
                if (m.tc) note("응답이 UDP 크기에 담기지 않아 잘렸어요(TC). 클라이언트는 같은 질문을 TCP 로 다시 해요.", 1)
                when { m.isResponse && m.rcode == 3 -> note("NXDOMAIN: 그런 이름이 없어요(오타이거나 등록되지 않은 도메인).", 1); m.isResponse && m.rcode == 2 -> note("SERVFAIL: 서버가 답을 만들지 못했어요(DNSSEC 검증 실패·상위 서버 장애일 수 있어요).", 2); m.isResponse && m.rcode == 5 -> note("REFUSED: 서버가 이 질문을 거부했어요(허용되지 않은 클라이언트이거나 재귀 질의 불가).", 2) }
                if (m.isResponse && m.rcode == 0 && m.answers.isEmpty()) note("오류는 아닌데 답이 없어요(NODATA): 이름은 있지만 그 종류의 레코드가 없어요.", 0)
                if (m.ad) note("AD 표시: 이 응답은 DNSSEC 검증을 통과했다고 서버가 알렸어요(서버를 믿을 때만 의미가 있어요).", -1)
                if (!m.isResponse && !m.rd) note("재귀를 요구하지 않는 질문이에요(권한 서버에 직접 묻는 모양이에요).", 0)
                if (m.isResponse && !m.ra && !m.aa) note("재귀 불가(RA 없음)·권한 응답(AA)도 아니에요: 위임(referral) 응답일 수 있어요.", 0)
            }
        },
        // 7
        tool("pkt_dhcp_decode", G, "DHCP 패킷 해석 (주소 제안·옵션·임대 시간)", "DHCP/BOOTP 메시지(또는 UDP 67·68번 패킷 전체)를 풀어서 메시지 종류·제안된 IP·게이트웨이·DNS·임대 시간·옵션을 보여 주고 이상한 값을 알려 줘요",
            listOf(multi("h", "DHCP 바이트 (16진수)", HEX_HINT, SAMPLE_DHCP)), ToolMode.OFFLINE, LOCAL, runLabel = "해석") { i, _, _ ->
            val b = bytesOrNull(i) ?: return@tool hexProblem(i)
            val raw = PacketDecode.payloadOf(b, setOf(67, 68)) ?: b
            val m = DhcpParse.parse(raw) ?: return@tool fail("DHCP 메시지로 읽지 못했어요. 시작 236바이트 뒤에 DHCP 표시(63 82 53 63)가 있는 UDP 67·68번 메시지인지 확인하세요")
            fun opt(code: Int) = m.options.firstOrNull { it.code == code }?.value
            result {
                kv("메시지 종류", m.msgType ?: "(옵션 53 없음)"); kv("방향", if (m.op == 1) "클라이언트 → 서버 (BOOTREQUEST)" else "서버 → 클라이언트 (BOOTREPLY)"); kv("거래 ID(xid)", "0x%08x".format(m.xid)); kv("클라이언트 MAC", m.chaddr)
                m.hostname?.let { kv("호스트 이름", it) }; kv("브로드캐스트로 답해 주세요", if (m.broadcast) "예" else "아니오")
                if (m.yiaddr != "0.0.0.0") kv("제안·할당된 IP (yiaddr)", m.yiaddr); if (m.ciaddr != "0.0.0.0") kv("클라이언트가 쓰던 IP (ciaddr)", m.ciaddr); if (m.siaddr != "0.0.0.0") kv("다음 서버 (siaddr)", m.siaddr); if (m.giaddr != "0.0.0.0") kv("릴레이 에이전트 (giaddr)", m.giaddr)
                head("옵션"); header("번호", "이름", "값"); for (o in m.options) row("${o.code}", o.name, o.value.take(160))
                head("점검")
                val lease = opt(51)?.substringBefore("초")?.toLongOrNull(); val t1 = opt(58)?.substringBefore("초")?.toLongOrNull(); val t2 = opt(59)?.substringBefore("초")?.toLongOrNull()
                if (lease != null) { note("임대 시간 ${lease}초(${lease / 3600}시간). 보통 절반(T1)에 갱신, 87.5%(T2)에 재결합을 시도해요.", 0)
                    if (t1 != null && t2 != null && t1 < t2 && t2 < lease) note("T1=${t1}초 · T2=${t2}초: 순서가 올바른 값이에요.", -1) else if (t1 != null && t2 != null) note("T1·T2 값의 순서가 이상해요(T1 < T2 < 임대 시간이어야 해요).", 2) }
                if (opt(252) != null) note("WPAD(옵션 252) 주소를 내려줘요. 프록시 자동 설정이 악용되면 접속이 가로채일 수 있어서, 안 쓰면 끄는 게 좋아요.", 1)
                val dnsList = opt(6)?.split(", ").orEmpty()
                if (dnsList.isNotEmpty()) note("DNS 서버: ${dnsList.joinToString(", ")}" + if (dnsList.any { IpUtil.parse(it)?.let { a -> IpUtil.classify(a).label.startsWith("공인") } == true }) " (공인 DNS 를 직접 내려줘요)" else "", 0)
                if (m.giaddr != "0.0.0.0") note("릴레이 에이전트를 거친 메시지예요(다른 서브넷의 클라이언트).", 0)
                if (m.msgType?.startsWith("OFFER") == true || m.msgType?.startsWith("ACK") == true) { val gw = opt(3); val sid = opt(54); if (gw != null && sid != null) note("게이트웨이 $gw · DHCP 서버 $sid" + if (gw != sid) " (게이트웨이와 DHCP 서버가 서로 다른 장비예요)" else "", 0) }
                if (m.msgType?.startsWith("DISCOVER") == true) note("같은 망에 DHCP 서버가 둘 이상 OFFER 를 보내면 가짜(rogue) 서버일 수 있어요. 서버 ID(옵션 54)가 서로 다른지 확인하세요.", 0)
            }
        },
        // 8
        tool("pkt_ntp_decode", G, "NTP 패킷 해석 (계층·기준·시각·오차)", "NTP 메시지 48바이트(또는 UDP 123번 패킷 전체)를 풀어서 계층(stratum)·기준 시계·시각 4개와 서버 처리 시간을 보여 주고, 내가 받은 시각(T4)을 알려 주면 시계 오차·왕복 지연을 계산해요",
            listOf(multi("h", "NTP 바이트 (16진수)", HEX_HINT, SAMPLE_NTP), text("t4", "내가 응답을 받은 시각 T4 (선택)", "UTC 시각 2023-11-14T22:13:20.5Z 또는 UNIX 초 1700000000.5")), ToolMode.OFFLINE, LOCAL, runLabel = "해석") { i, _, _ ->
            val b = bytesOrNull(i) ?: return@tool hexProblem(i)
            val raw = PacketDecode.payloadOf(b, setOf(123)) ?: b
            val m = NtpDecode.parse(raw) ?: return@tool fail("NTP 메시지로 읽지 못했어요. 48바이트 이상의 NTP 메시지(또는 UDP 123번 패킷)인지 확인하세요")
            result {
                kv("모드", "${m.mode} (${PacketDecode.ntpMode(m.mode)})"); kv("버전", "${m.vn}"); kv("윤초 표시(LI)", when (m.li) { 0 -> "없음"; 1 -> "하루가 61초(윤초 추가 예정)"; 2 -> "하루가 59초(윤초 삭제 예정)"; else -> "시계 동기 안 됨(경고)" }, level = if (m.li == 3) 2 else 0)
                kv("계층(stratum)", "${m.stratum}" + when { m.stratum == 0 -> " (표시 코드·kiss-o'-death)"; m.stratum == 1 -> " (원자시계·GPS 에 직접 연결)"; m.stratum in 2..15 -> " (${m.stratum - 1}단계 위의 서버에서 받음)"; else -> " (동기 안 됨)" }, level = if (m.stratum == 16) 2 else 0)
                kv("기준 ID", m.refId + if (m.stratum <= 1) " (기준 시계 종류)" else " (동기 대상 서버)")
                kv("폴 간격", "2^${m.poll} = ${1L shl maxOf(0, m.poll)}초"); kv("정밀도", "2^${m.precision} 초 ≈ %.3g초".format(Math.pow(2.0, m.precision.toDouble())))
                kv("루트 지연", "%.1f ms".format(m.rootDelay * 1000)); kv("루트 분산", "%.1f ms".format(m.rootDisp * 1000))
                head("시각 (UTC)"); kv("기준 시각(ref)", NtpDecode.fmt(m.ref)); kv("T1 원래 보낸 시각(orig)", NtpDecode.fmt(m.orig)); kv("T2 서버가 받은 시각", NtpDecode.fmt(m.recv)); kv("T3 서버가 보낸 시각", NtpDecode.fmt(m.xmit))
                if (m.mode == 4 && m.recv != 0.0 && m.xmit != 0.0) kv("서버 처리 시간(T3−T2)", "%.3f ms".format((m.xmit - m.recv) * 1000))
                val t4s = i.str("t4")
                if (t4s.isNotEmpty()) {
                    val t4 = t4s.toDoubleOrNull() ?: runCatching { Instant.parse(t4s).let { it.epochSecond + it.nano / 1e9 } }.getOrNull()
                    if (t4 == null) note("T4 형식을 읽지 못했어요. 2023-11-14T22:13:20.5Z 또는 UNIX 초 숫자로 쓰세요.", 2)
                    else if (m.orig == 0.0 || m.recv == 0.0 || m.xmit == 0.0) note("T1·T2·T3 중 0 인 값이 있어 오차를 계산할 수 없어요(응답 패킷이어야 해요).", 1)
                    else {
                        val (off, delay) = NtpDecode.offsetDelay(m.orig, m.recv, m.xmit, t4)
                        head("계산"); kv("시계 오차(θ)", "%+.3f ms".format(off * 1000), level = if (Math.abs(off) > 0.128) 2 else if (Math.abs(off) > 0.025) 1 else -1); kv("왕복 지연(δ)", "%.3f ms".format(delay * 1000), level = if (delay < 0) 2 else 0)
                        note(if (off > 0) "내 시계가 서버보다 ${"%.3f".format(off * 1000)}ms 느려요(내 시계에 +${"%.3f".format(off * 1000)}ms 해야 맞아요)." else if (off < 0) "내 시계가 서버보다 ${"%.3f".format(-off * 1000)}ms 빨라요." else "내 시계가 서버와 정확히 같아요.", 0)
                        if (delay < 0) note("왕복 지연이 음수예요: T1~T4 를 잘못 넣었거나 서로 다른 거래의 값이에요.", 2)
                        note("θ = ((T2−T1)+(T3−T4))/2, δ = (T4−T1)−(T3−T2). 오차는 왕복 지연이 길수록 불확실해요(최대 ±δ/2).", 0)
                    }
                }
                if (m.stratum == 0 && m.mode == 4) note("계층 0 은 서버가 \"RATE(너무 자주 물음)·DENY(거부)\" 같은 코드(기준 ID)로 요청을 거절한 응답이에요.", 2)
                if (m.mode == 3) note("클라이언트가 보낸 요청이에요: T3(보낸 시각)만 들어 있어요.", 0)
            }
        },
        // 9
        tool("pkt_build", G, "패킷 만들기 (ping·UDP·TCP SYN·ARP·Wake-on-LAN·NTP → 16진수)", "체크섬까지 맞게 계산한 패킷을 16진수로 만들어요. 와이어샤크의 \"Import from Hex Dump\"나 text2pcap 으로 .pcap 파일로 바꿔 쓸 수 있어요. 패킷을 실제로 보내지는 않아요",
            listOf(choice("t", "만들 패킷", BUILD_TYPES), text("smac", "출발지 MAC", "예: 52:54:00:12:34:56", "52:54:00:12:34:56"), text("dmac", "목적지 MAC (Wake-on-LAN 은 깨울 PC 의 MAC)", "ff:ff:ff:ff:ff:ff 는 브로드캐스트", "ff:ff:ff:ff:ff:ff"),
                text("sip", "출발지 IP (IPv4)", "", "192.168.1.10"), text("dip", "목적지 IP (IPv4)", "", "192.168.1.1"), text("sport", "출발지 포트", "", "40000"), text("dport", "목적지 포트", "", "53"),
                text("seq", "TCP 순서 번호·확인 번호 (seq,ack)", "예: 1000,0", "1000,0"), text("ttl", "TTL", "", "64"), text("data", "데이터 (글자 또는 hex:4142…)", "비워도 돼요", "hello")), ToolMode.OFFLINE, "패킷을 만들어 글로만 보여 줘요. 어디로도 보내지 않아요.", runLabel = "만들기") { i, _, _ ->
            val type = i.choice("t", BUILD_TYPES)
            val smac = Bx.parseMac(i.str("smac")) ?: return@tool fail("출발지 MAC 형식이 이상해요 (예: 52:54:00:12:34:56)")
            val dmac = Bx.parseMac(i.str("dmac")) ?: return@tool fail("목적지 MAC 형식이 이상해요 (예: ff:ff:ff:ff:ff:ff)")
            val sip = IpUtil.parseV4(i.str("sip")) ?: return@tool fail("출발지 IP 는 IPv4 주소(예: 192.168.1.10)여야 해요")
            val dip = IpUtil.parseV4(i.str("dip")) ?: return@tool fail("목적지 IP 는 IPv4 주소(예: 192.168.1.1)여야 해요")
            val sport = i.int("sport") ?: 40000; val dport = i.int("dport") ?: 53
            if (sport !in 1..65535 || dport !in 1..65535) return@tool fail("포트는 1~65535 여야 해요")
            val ttl = i.int("ttl") ?: 64; if (ttl !in 1..255) return@tool fail("TTL 은 1~255 여야 해요")
            val data = dataBytes(i.raw("data")) ?: return@tool fail("데이터를 hex: 뒤의 16진수로 읽지 못했어요")
            if (data.size > 1400) return@tool fail("데이터는 1400바이트까지만 넣을 수 있어요")
            val (sq, ak) = i.str("seq").split(',').map { it.trim().toLongOrNull() }.let { (it.getOrNull(0) ?: 1000L) to (it.getOrNull(1) ?: 0L) }
            val bcast = ByteArray(6) { 0xff.toByte() }
            val frame: ByteArray; val ipOnly: ByteArray?
            when (type) {
                0, 1 -> { ipOnly = PacketBuild.ipv4(sip, dip, 1, PacketBuild.icmpEcho(0x1234, 1, if (data.isEmpty()) ByteArray(32) { it.toByte() } else data, reply = type == 1), ttl); frame = PacketBuild.ether(dmac, smac, 0x0800, ipOnly) }
                2 -> { ipOnly = PacketBuild.ipv4(sip, dip, 17, PacketBuild.udp(sip, dip, sport, dport, data), ttl); frame = PacketBuild.ether(dmac, smac, 0x0800, ipOnly) }
                3 -> { ipOnly = PacketBuild.ipv4(sip, dip, 6, PacketBuild.tcp(sip, dip, sport, dport, sq, ak, 0x02, 64240, ByteArray(0), synOptions = true), ttl); frame = PacketBuild.ether(dmac, smac, 0x0800, ipOnly) }
                4 -> { ipOnly = PacketBuild.ipv4(sip, dip, 6, PacketBuild.tcp(sip, dip, sport, dport, sq, ak, 0x18, 64240, data), ttl); frame = PacketBuild.ether(dmac, smac, 0x0800, ipOnly) }
                5 -> { ipOnly = PacketBuild.ipv4(sip, dip, 6, PacketBuild.tcp(sip, dip, sport, dport, sq, ak, 0x14, 0, ByteArray(0)), ttl); frame = PacketBuild.ether(dmac, smac, 0x0800, ipOnly) }
                6 -> { ipOnly = null; frame = PacketBuild.ether(if (dmac.all { it == 0xff.toByte() } || dmac.all { it == 0.toByte() }) bcast else dmac, smac, 0x0806, PacketBuild.arp(1, smac, sip, ByteArray(6), dip)) }
                7 -> { ipOnly = null; frame = PacketBuild.ether(dmac, smac, 0x0806, PacketBuild.arp(2, smac, sip, dmac, dip)) }
                8 -> { ipOnly = PacketBuild.ipv4(sip, byteArrayOf(-1, -1, -1, -1), 17, PacketBuild.udp(sip, byteArrayOf(-1, -1, -1, -1), sport, 9, PacketBuild.wol(dmac)), ttl); frame = PacketBuild.ether(bcast, smac, 0x0800, ipOnly) }
                else -> { ipOnly = PacketBuild.ipv4(sip, dip, 17, PacketBuild.udp(sip, dip, sport, 123, PacketBuild.ntpRequest()), ttl); frame = PacketBuild.ether(dmac, smac, 0x0800, ipOnly) }
            }
            val d = PacketDecode.decode(frame, "eth")
            result {
                kv("종류", BUILD_TYPES[type]); kv("크기", "이더넷 프레임 ${frame.size}바이트" + (ipOnly?.let { " · IP 패킷 ${it.size}바이트" } ?: "")); kv("이 패킷을 다시 해석하면", d.summary.ifEmpty { "-" })
                kv("이더넷 프레임(16진수)", hex(frame)); ipOnly?.let { kv("IP 패킷(16진수)", hex(it)) }
                head("이더넷 프레임 (보기 좋게)"); block(hexLines(frame))
                head("와이어샤크·text2pcap 으로 가져오기용"); block((frame.indices step 16).joinToString("\n") { "%06x ".format(it) + Bx.hex(frame, it, minOf(frame.size, it + 16)) } + "\n")
                note("와이어샤크: 파일 → Import from Hex Dump → 위 글을 붙여 넣고 Encapsulation 을 Ethernet 으로 고르면 .pcap 으로 저장돼요. 명령줄: text2pcap dump.txt out.pcap", 0)
                if (d.layers.any { l -> l.notes.any { it.second == 2 } }) note("방금 만든 패킷에서 문제가 발견됐어요. 입력값을 확인하세요.", 2)
                note("이 도구는 패킷을 만들어 글로 보여 주기만 해요. 직접 전송하는 기능은 없어요.", 0)
            }
        },
        // 10
        tool("pkt_bpf", G, "캡처 필터 만들기 (tcpdump BPF + 와이어샤크 표시 필터)", "IP·네트워크·포트·프로토콜·TCP 플래그 조건을 고르면 tcpdump/tshark 캡처 필터(BPF)와 와이어샤크 표시 필터, 실행 명령을 만들어 줘요",
            listOf(text("host", "IP 주소 (선택)", "예: 192.168.1.10 또는 2001:db8::1"), text("net", "네트워크 CIDR (선택)", "예: 10.0.0.0/8"), text("ports", "포트 (선택)", "쉼표로 여러 개, 범위는 1000-2000 (예: 80,443,8000-8100)"),
                choice("p", "프로토콜", BPF_PROTO), choice("d", "방향", BPF_DIR), choice("f", "TCP 플래그", BPF_FLAGS), text("x", "제외할 IP (선택)", "이 IP 와의 통신은 뺄 때")), ToolMode.OFFLINE, LOCAL, runLabel = "만들기") { i, _, _ ->
            val dirI = i.choice("d", BPF_DIR); val dir = when (dirI) { 1 -> "src "; 2 -> "dst "; else -> "" }
            val protoI = i.choice("p", BPF_PROTO); val flagI = i.choice("f", BPF_FLAGS)
            val bpf = ArrayList<String>(); val dsp = ArrayList<String>(); val words = ArrayList<String>()
            val proto = if (flagI > 0 && protoI !in listOf(0, 1)) return@tool fail("TCP 플래그 조건은 프로토콜이 \"전체\"나 \"TCP\"일 때만 쓸 수 있어요") else if (flagI > 0) 1 else protoI
            if (proto > 0) { bpf += listOf("", "tcp", "udp", "icmp", "icmp6", "arp", "ip6")[proto]; dsp += listOf("", "tcp", "udp", "icmp", "icmpv6", "arp", "ipv6")[proto]; words += BPF_PROTO[proto] }
            fun ipField(a: java.net.InetAddress, d: String) = (if (a.address.size == 4) "ip" else "ipv6") + (when (d) { "src " -> ".src"; "dst " -> ".dst"; else -> ".addr" })
            val host = i.str("host")
            if (host.isNotEmpty()) { val a = IpUtil.parse(host) ?: return@tool fail("IP 주소 형식이 아니에요: $host"); val t = IpUtil.format(a); bpf += "${dir}host $t"; dsp += "${ipField(a, dir)} == $t"; words += "${t} ${when (dirI) { 1 -> "가 보낸"; 2 -> "가 받는"; else -> "가 보내거나 받는" }}" }
            val net = i.str("net")
            if (net.isNotEmpty()) {
                val v6 = net.contains(':'); val a = IpUtil.parse(net.substringBefore('/')); val len = net.substringAfter('/', "").toIntOrNull()
                if (a == null || len == null || len !in 0..(if (a.address.size == 16) 128 else 32) || (v6 != (a.address.size == 16)) || !net.contains('/')) return@tool fail("네트워크는 주소/길이 형식이어야 해요 (예: 10.0.0.0/8, 2001:db8::/32)")
                val base = if (a.address.size == 4) (Subnet.parse("${IpUtil.format(a)}/$len")?.let { IpUtil.v4Text(it.network) } ?: IpUtil.format(a)) else IpUtil.format(a)
                bpf += "${dir}net $base/$len"; dsp += "${ipField(a, dir)} == $base/$len"; words += "$base/$len 대역이 ${when (dirI) { 1 -> "보낸"; 2 -> "받는"; else -> "보내거나 받는" }}"
            }
            val ports = i.str("ports")
            if (ports.isNotEmpty()) {
                val pr = parsePortRanges(ports)?.takeIf { it.isNotEmpty() } ?: return@tool fail("포트는 1~65535 의 숫자를 쉼표로 나눠 쓰세요 (범위는 1000-2000)")
                val terms = pr.map { if (it.lo == it.hi) "${dir}port ${it.lo}" else "${dir}portrange ${it.lo}-${it.hi}" }
                bpf += if (terms.size == 1) terms[0] else terms.joinToString(" or ", "(", ")")
                val field = when (dirI) { 1 -> "srcport"; 2 -> "dstport"; else -> "port" }
                val set = pr.joinToString(" ", "{", "}") { if (it.lo == it.hi) "${it.lo}" else "${it.lo}..${it.hi}" }
                dsp += when (proto) { 1 -> "tcp.$field in $set"; 2 -> "udp.$field in $set"; else -> "(tcp.$field in $set || udp.$field in $set)" }.let { if (pr.size == 1 && pr[0].lo == pr[0].hi) it.replace(" in $set", " == ${pr[0].lo}") else it }
                words += "포트 ${pr.joinToString(", ") { if (it.lo == it.hi) "${it.lo}" else "${it.lo}~${it.hi}" }}"
            }
            when (flagI) {
                1 -> { bpf += "tcp[tcpflags] & (tcp-syn|tcp-ack) = tcp-syn"; dsp += "tcp.flags.syn == 1 && tcp.flags.ack == 0"; words += "연결을 시작하는 SYN" }
                2 -> { bpf += "tcp[tcpflags] & (tcp-syn|tcp-ack) = (tcp-syn|tcp-ack)"; dsp += "tcp.flags.syn == 1 && tcp.flags.ack == 1"; words += "연결을 수락하는 SYN+ACK" }
                3 -> { bpf += "tcp[tcpflags] & tcp-rst != 0"; dsp += "tcp.flags.reset == 1"; words += "연결을 거부·강제 종료하는 RST" }
                4 -> { bpf += "tcp[tcpflags] & tcp-fin != 0"; dsp += "tcp.flags.fin == 1"; words += "연결을 끝내는 FIN" }
                5 -> { bpf += "tcp[tcpflags] & tcp-push != 0"; dsp += "tcp.flags.push == 1"; words += "PSH 가 켜진" }
            }
            val ex = i.str("x")
            if (ex.isNotEmpty()) { val a = IpUtil.parse(ex) ?: return@tool fail("제외할 IP 형식이 아니에요: $ex"); val t = IpUtil.format(a); bpf += "not host $t"; dsp += "!(${if (a.address.size == 4) "ip" else "ipv6"}.addr == $t)"; words += "$t 와의 통신은 제외" }
            if (bpf.isEmpty()) return@tool need("조건을 하나 이상 고르거나 입력하세요 (아무 조건도 없으면 모든 패킷을 잡아요)")
            val expr = bpf.joinToString(" and "); val disp = dsp.joinToString(" && ")
            result {
                kv("캡처 필터 (tcpdump·tshark -f, BPF)", expr); kv("표시 필터 (와이어샤크 화면 위쪽 칸)", disp)
                head("실행 명령 (리눅스·맥, 관리자 권한 필요)")
                block("sudo tcpdump -i any -nn -s 0 -w capture.pcap '$expr'\nsudo tcpdump -i any -nn -c 100 '$expr'\ntshark -i any -f '$expr' -w capture.pcapng")
                note("잡는 패킷: " + words.joinToString(" · "), 0)
                note("캡처 필터는 잡을 때 걸러서 파일이 작아지고, 표시 필터는 잡은 뒤 화면에서만 걸러요. 두 문법은 달라서 서로 바꿔 쓸 수 없어요.", 0)
                note("-s 0 은 패킷 전체를 담아요(안 주면 일부만 담겨 체크섬을 확인할 수 없어요). -nn 은 이름·포트 이름 변환을 끄는 옵션이에요.", 0)
            }
        },
    )
}
