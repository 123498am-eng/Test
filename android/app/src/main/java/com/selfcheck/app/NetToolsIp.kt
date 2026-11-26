package com.selfcheck.app

import java.math.BigInteger
import java.net.InetAddress

/** IP·서브넷 계산 도구 30가지 (모두 오프라인) */
object IpTools {
    private const val G = NetGroups.IP
    private const val BAD_CIDR = "범위를 읽지 못했어요. 예: 192.168.0.0/24 (숫자 4개는 점으로, 접두 길이는 0~32)"

    private fun v4(s: String): Long? = IpUtil.parseV4(s.trim())?.let { IpUtil.v4ToLong(it) }
    private fun addr4(v: Long): InetAddress = InetAddress.getByAddress(IpUtil.longToV4(v))
    private fun n(v: Long) = "%,d".format(v)
    private fun bin32(v: Long) = java.lang.Long.toString(v, 2).padStart(32, '0').chunked(8).joinToString(".")
    private fun t(v: Long) = IpUtil.v4Text(v)

    /** "24", "/24", "255.255.255.0" → 접두 길이. 아니면 null */
    internal fun prefixOf(tok: String): Int? {
        val s = tok.trim().removePrefix("/")
        if ('.' in s) {
            val m = v4(s) ?: return null
            val inv = m.inv() and 0xFFFFFFFFL
            return if ((inv and (inv + 1)) == 0L) java.lang.Long.bitCount(m) else null
        }
        return s.toIntOrNull()?.takeIf { it in 0..32 }
    }

    private fun classLetter(first: Int) = when { first < 128 -> "A"; first < 192 -> "B"; first < 224 -> "C"; first < 240 -> "D (멀티캐스트)"; else -> "E (예약)" }

    /** "이름 100" 또는 "100" 한 줄 → (이름, 호스트 수) */
    private val NEED = Regex("""^(?:(.+?)\s+)?(\d{1,9})$""")

    private val chipsNet = listOf("192.168.0.0/24" to "192.168.0.77/24", "10.0.0.0/8" to "10.20.30.40/8", "172.16.0.0/12" to "172.16.5.9/12", "/26" to "192.168.1.100/26")

    val ALL: List<NetTool> = listOf(
        calc("subnet_calc", G, "서브넷 계산기 (IPv4)", "IP/접두 길이 하나로 네트워크·브로드캐스트·마스크·쓸 수 있는 주소·기기 수를 한꺼번에",
            text("net", "IP/접두 길이", "예: 192.168.0.77/24 또는 10.0.0.5/255.255.0.0", "192.168.0.77/24", chipsNet)) { i ->
            val raw = i.str("net")
            if (raw.isEmpty()) return@calc need("IP/접두 길이를 입력하세요")
            val c = Cidr4.parse(raw) ?: return@calc fail(BAD_CIDR)
            val given = v4(raw.substringBefore('/'))
            result {
                if (given != null && '/' in raw) kv("입력한 주소", t(given))
                kv("네트워크 주소", t(c.net)); kv("접두 길이", "/${c.prefix}")
                kv("서브넷 마스크", t(c.mask)); kv("와일드카드", t(c.mask.inv() and 0xFFFFFFFFL))
                if (c.prefix <= 30) {
                    kv("브로드캐스트", t(c.last)); kv("쓸 수 있는 주소", "${t(c.first + 1)} ~ ${t(c.last - 1)}")
                    kv("기기 수", "${n(c.size - 2)}대 (전체 주소 ${n(c.size)}개)")
                } else if (c.prefix == 31) { kv("쓸 수 있는 주소", "${t(c.first)}, ${t(c.last)}"); kv("기기 수", "2대 (점대점 연결용 /31, RFC 3021)") }
                else { kv("주소", t(c.net)); kv("기기 수", "1대 (한 대만 가리키는 /32)") }
                kv("마스크 2진수", bin32(c.mask))
                if (given != null) kv("주소 2진수", bin32(given))
                val kind = IpUtil.classify(addr4(c.net))
                kv("종류", kind.label); kv("옛 클래스", "${classLetter(((c.net shr 24) and 0xff).toInt())} 클래스 (지금은 CIDR 로 씀)")
                note(kind.note)
            }
        },

        calc("cidr_mask", G, "CIDR ↔ 서브넷 마스크", "/24 ↔ 255.255.255.0 서로 바꾸기 (기기 수도 같이)",
            text("v", "접두 길이 또는 마스크", "예: 24, /20, 255.255.240.0", "255.255.240.0", listOf("/24" to "/24", "/16" to "/16", "255.255.255.192" to "255.255.255.192"))) { i ->
            if (i.str("v").isEmpty()) return@calc need("접두 길이(24)나 마스크(255.255.255.0)를 입력하세요")
            val p = prefixOf(i.str("v")) ?: return@calc fail("읽지 못했어요. 접두 길이는 0~32, 마스크는 1 이 이어진 형태(255.255.255.0)만 돼요")
            val m = Subnet.maskOf(p)
            result {
                kv("접두 길이", "/$p"); kv("서브넷 마스크", t(m)); kv("와일드카드", t(m.inv() and 0xFFFFFFFFL)); kv("마스크 2진수", bin32(m))
                kv("전체 주소 수", n(1L shl (32 - p)))
                kv("쓸 수 있는 기기 수", when { p >= 32 -> "1"; p == 31 -> "2 (점대점)"; else -> n((1L shl (32 - p)) - 2) })
            }
        },

        calc("wildcard_mask", G, "와일드카드 마스크 (ACL용)", "접두 길이·마스크를 와일드카드로 (Cisco ACL·OSPF 에서 씀)",
            text("v", "IP/접두 길이 또는 마스크", "예: 10.1.0.0/16 또는 255.255.255.0", "192.168.10.0/24")) { i ->
            val raw = i.str("v")
            if (raw.isEmpty()) return@calc need("값을 입력하세요")
            val hasIp = '/' in raw && v4(raw.substringBefore('/')) != null
            val p = prefixOf(if (hasIp) raw.substringAfter('/') else raw) ?: return@calc fail("읽지 못했어요. 예: 10.1.0.0/16 또는 255.255.255.0")
            val w = Subnet.maskOf(p).inv() and 0xFFFFFFFFL
            result {
                kv("와일드카드", t(w)); kv("서브넷 마스크", t(Subnet.maskOf(p))); kv("접두 길이", "/$p")
                if (hasIp) {
                    val c = Cidr4.of(v4(raw.substringBefore('/'))!!, p)
                    kv("ACL 예", "permit ip ${t(c.net)} ${t(w)} any"); kv("OSPF 예", "network ${t(c.net)} ${t(w)} area 0")
                }
                note("와일드카드는 마스크를 뒤집은 값이에요 (0 = 그 자리 비트가 같아야 함, 1 = 상관없음).")
            }
        },

        calc("subnet_table", G, "서브넷 한눈 표 (/8~/32)", "접두 길이별 마스크·와일드카드·주소 수·기기 수 표 (외우지 않아도 돼요)") { _ ->
            result {
                header("접두", "마스크", "주소 수", "기기 수")
                for (p in 8..32) row("/$p", t(Subnet.maskOf(p)), n(1L shl (32 - p)), when { p == 32 -> "1"; p == 31 -> "2"; else -> n((1L shl (32 - p)) - 2) })
                note("기기 수 = 주소 수 − 2 (네트워크 주소와 브로드캐스트 주소 제외). /31 은 점대점, /32 는 한 대만 가리켜요.")
            }
        },

        calc("ip_in_cidr", G, "IP가 이 범위에 속하나요?", "IP 하나가 CIDR 범위 안에 있는지 확인 (IPv4·IPv6)",
            text("ip", "IP 주소", "예: 192.168.1.20", "192.168.1.20"), text("cidr", "범위 (CIDR)", "예: 192.168.0.0/16", "192.168.0.0/16")) { i ->
            val ip = IpUtil.parse(i.str("ip")); val cs = i.str("cidr")
            if (i.str("ip").isEmpty() || cs.isEmpty()) return@calc need("IP 와 범위를 모두 입력하세요")
            if (ip == null) return@calc fail("IP 주소를 읽지 못했어요")
            result {
                if (ip.address.size == 4) {
                    val c = Cidr4.parse(cs) ?: return@result note(BAD_CIDR, 2)
                    val x = IpUtil.v4ToLong(ip.address)
                    val inside = x in c
                    kv("결과", if (inside) "속해요 ✔" else "속하지 않아요 ✘", if (inside) -1 else 1)
                    kv("범위", "${c}  (${t(c.first)} ~ ${t(c.last)})")
                    if (inside) kv("범위 안 위치", "${n(x - c.first + 1)}번째 주소 / 전체 ${n(c.size)}개")
                } else {
                    val (a, p) = V6.parseCidr(cs) ?: return@result note("IPv6 범위를 읽지 못했어요. 예: 2001:db8::/32", 2)
                    val x = V6.toBig(ip)
                    val inside = x >= V6.network(a, p) && x <= V6.last(a, p)
                    kv("결과", if (inside) "속해요 ✔" else "속하지 않아요 ✘", if (inside) -1 else 1)
                    kv("범위", "${IpUtil.format(V6.fromBig(V6.network(a, p)))}/$p")
                }
            }
        },

        calc("cidr_overlap", G, "두 범위가 겹치나요?", "CIDR 두 개의 겹침·포함 관계 (방화벽·라우팅 규칙 점검에 유용)",
            text("a", "범위 A", "예: 10.0.0.0/8", "10.0.0.0/8"), text("b", "범위 B", "예: 10.20.0.0/16", "10.20.0.0/16")) { i ->
            if (i.str("a").isEmpty() || i.str("b").isEmpty()) return@calc need("두 범위를 모두 입력하세요")
            val a = Cidr4.parse(i.str("a")) ?: return@calc fail("범위 A 를 읽지 못했어요. $BAD_CIDR")
            val b = Cidr4.parse(i.str("b")) ?: return@calc fail("범위 B 를 읽지 못했어요. $BAD_CIDR")
            result {
                val rel = when {
                    a == b -> "같은 범위예요" to 0
                    a.contains(b) -> "A 가 B 를 통째로 포함해요 (B ⊂ A)" to 1
                    b.contains(a) -> "B 가 A 를 통째로 포함해요 (A ⊂ B)" to 1
                    a.overlaps(b) -> "일부만 겹쳐요" to 1
                    else -> "겹치지 않아요" to -1
                }
                kv("관계", rel.first, rel.second)
                kv("A", "$a  (${t(a.first)} ~ ${t(a.last)})"); kv("B", "$b  (${t(b.first)} ~ ${t(b.last)})")
                if (a.overlaps(b)) {
                    val s = maxOf(a.first, b.first); val e = minOf(a.last, b.last)
                    kv("겹치는 구간", "${t(s)} ~ ${t(e)}  (${n(e - s + 1)}개)")
                    kv("겹침을 CIDR 로", Cidr.rangeToCidrs(s, e).joinToString(", "))
                }
            }
        },

        calc("range_to_cidr", G, "IP 범위 → CIDR 변환", "시작~끝 주소를 가장 적은 CIDR 목록으로 (예: 방화벽 허용 목록 만들기)",
            text("s", "시작 IP", "예: 192.168.1.10", "192.168.1.10"), text("e", "끝 IP", "예: 192.168.1.200", "192.168.1.200")) { i ->
            if (i.str("s").isEmpty() || i.str("e").isEmpty()) return@calc need("시작과 끝 IP 를 입력하세요")
            val s = v4(i.str("s")) ?: return@calc fail("시작 IP 를 읽지 못했어요"); val e = v4(i.str("e")) ?: return@calc fail("끝 IP 를 읽지 못했어요")
            if (s > e) return@calc fail("시작이 끝보다 커요. 순서를 바꿔 입력하세요")
            val list = Cidr.rangeToCidrs(s, e)
            result {
                kv("범위", "${t(s)} ~ ${t(e)}"); kv("주소 수", n(e - s + 1)); kv("CIDR 개수", "${list.size}개")
                block(list.joinToString("\n"))
            }
        },

        calc("cidr_to_range", G, "CIDR → IP 범위", "CIDR 목록을 시작·끝 주소와 주소 수로 풀어 보기 (한 줄에 하나)",
            multi("list", "CIDR 목록", "한 줄에 하나\n예: 10.0.0.0/8\n192.168.0.0/22", "10.0.0.0/8\n192.168.0.0/22\n203.0.113.64/27")) { i ->
            val lines = i.lines("list")
            if (lines.isEmpty()) return@calc need("CIDR 를 한 줄에 하나씩 입력하세요")
            result {
                header("CIDR", "시작", "끝", "주소 수")
                var bad = 0
                for (l in lines) {
                    val c = Cidr4.parse(l)
                    if (c == null) { bad++; row(l, "읽지 못함", "", "", level = 2) } else row(c.toString(), t(c.first), t(c.last), n(c.size))
                }
                if (bad > 0) note("${bad}줄은 읽지 못했어요.", 1)
            }
        },

        calc("cidr_merge", G, "CIDR 합치기 (요약)", "여러 IP·CIDR·범위를 겹침 없이 가장 적은 CIDR 목록으로 합치기 (방화벽 규칙 줄이기)",
            multi("list", "목록", "한 줄에 하나: CIDR, IP, 또는 \"시작 - 끝\"\n예: 10.0.0.0/25\n10.0.0.128/25", "10.0.0.0/25\n10.0.0.128/25\n10.0.1.0/24\n192.168.1.5\n192.168.1.6\n192.168.1.4 - 192.168.1.7")) { i ->
            val lines = i.lines("list")
            if (lines.isEmpty()) return@calc need("목록을 한 줄에 하나씩 입력하세요")
            val cs = ArrayList<Cidr4>(); val bad = ArrayList<String>()
            for (l in lines) {
                val range = l.split('-').map { it.trim() }
                val c = if (range.size == 2 && '/' !in l) {
                    val a = v4(range[0]); val b = v4(range[1])
                    if (a != null && b != null && a <= b) Cidr.rangeToCidrs(a, b) else null
                } else Cidr4.parse(l)?.let { listOf(it) }
                if (c == null) bad += l else cs += c
            }
            val merged = Cidr.merge(cs)
            result {
                kv("입력", "${lines.size}줄 → CIDR ${cs.size}개"); kv("합친 결과", "${merged.size}개", if (merged.size < cs.size) -1 else 0)
                kv("총 주소 수", n(merged.sumOf { it.size }))
                if (merged.isNotEmpty()) block(merged.joinToString("\n"))
                if (bad.isNotEmpty()) note("읽지 못한 줄: " + bad.joinToString(" / "), 1)
            }
        },

        calc("cidr_split", G, "CIDR 나누기 (/n 으로)", "큰 네트워크를 더 작은 서브넷들로 쪼개기",
            text("c", "나눌 네트워크", "예: 192.168.0.0/24", "192.168.0.0/24"), text("p", "새 접두 길이", "예: 26", "26", listOf("/25" to "25", "/26" to "26", "/27" to "27", "/28" to "28"))) { i ->
            if (i.str("c").isEmpty() || i.str("p").isEmpty()) return@calc need("네트워크와 새 접두 길이를 입력하세요")
            val c = Cidr4.parse(i.str("c")) ?: return@calc fail(BAD_CIDR)
            val np = i.int("p")?.takeIf { it in 0..32 } ?: return@calc fail("새 접두 길이는 0~32 숫자예요")
            if (np < c.prefix) return@calc fail("새 접두 길이(/$np)는 원래(/${c.prefix})보다 크거나 같아야 해요 (작을수록 더 큰 네트워크)")
            val count = 1L shl (np - c.prefix)
            val list = Cidr.split(c, np, 1024)
            result {
                kv("원래 네트워크", c.toString()); kv("나눈 개수", "${n(count)}개 (각 /$np)")
                kv("서브넷 하나", "주소 ${n(1L shl (32 - np))}개 / 기기 ${if (np >= 31) "-" else n((1L shl (32 - np)) - 2)}대")
                block(list.joinToString("\n"))
                if (count > list.size) note("너무 많아서 처음 ${n(list.size.toLong())}개만 보여 드렸어요.", 1)
            }
        },

        calc("cidr_split_count", G, "CIDR 균등 N분할", "네트워크를 부서·층·VLAN 수만큼 같은 크기로 나누기",
            text("c", "나눌 네트워크", "예: 10.10.0.0/16", "10.10.0.0/16"), text("k", "필요한 개수", "예: 5", "5", listOf("2" to "2", "4" to "4", "5" to "5", "10" to "10"))) { i ->
            if (i.str("c").isEmpty() || i.str("k").isEmpty()) return@calc need("네트워크와 개수를 입력하세요")
            val c = Cidr4.parse(i.str("c")) ?: return@calc fail(BAD_CIDR)
            val k = i.long("k")?.takeIf { it in 1..65536 } ?: return@calc fail("개수는 1~65,536 숫자예요")
            val bits = Cidr.ceilLog2(k)
            if (c.prefix + bits > 32) return@calc fail("이 네트워크는 ${k}개로 나눌 수 없어요 (주소가 부족해요)")
            val np = c.prefix + bits
            val all = Cidr.split(c, np, 1024)
            result {
                kv("나눈 크기", "/$np (주소 ${n(1L shl (32 - np))}개, 기기 ${if (np >= 31) "-" else n((1L shl (32 - np)) - 2)}대)")
                kv("만들 수 있는 개수", "${n(1L shl bits)}개 (필요 ${n(k)}개)")
                block(all.take(k.toInt().coerceAtMost(1024)).joinToString("\n"))
                if ((1L shl bits) > k) note("나머지 ${n((1L shl bits) - k)}개는 비워 두었다가 나중에 쓸 수 있어요.")
            }
        },

        calc("vlsm", G, "VLSM 계산기", "부서마다 필요한 기기 수가 다를 때, 큰 것부터 낭비 없이 서브넷 배정",
            text("c", "전체 네트워크", "예: 192.168.10.0/24", "192.168.10.0/24"),
            multi("needs", "필요한 기기 수", "한 줄에 하나: 이름 기기수\n예: 영업팀 50\n개발팀 30", "영업팀 50\n개발팀 28\n서버실 10\n관리 2")) { i ->
            val base = Cidr4.parse(i.str("c")) ?: return@calc if (i.str("c").isEmpty()) need("전체 네트워크를 입력하세요") else fail(BAD_CIDR)
            val reqs = ArrayList<VlsmReq>(); val bad = ArrayList<String>()
            for ((idx, l) in i.lines("needs").withIndex()) {
                val m = NEED.find(l)
                if (m == null) bad += l else reqs += VlsmReq(m.groupValues[1].ifEmpty { "서브넷 ${idx + 1}" }, m.groupValues[2].toLong().coerceAtLeast(1))
            }
            if (reqs.isEmpty()) return@calc need("필요한 기기 수를 한 줄에 하나씩 입력하세요 (예: 영업팀 50)")
            val allocs = Cidr.vlsm(base, reqs)
            result {
                header("이름", "필요", "서브넷", "쓸 수 있는 주소", "기기")
                var used = 0L
                for (a in allocs) {
                    val c = a.cidr
                    if (c == null) row(a.req.name, n(a.req.hosts), "자리 없음", "", "", level = 2)
                    else { used += c.size; row(a.req.name, n(a.req.hosts), c.toString(), "${t(c.first + 1)} ~ ${t(c.last - 1)}", n(c.size - 2)) }
                }
                kv("사용한 주소", "${n(used)} / ${n(base.size)}개"); kv("남은 주소", n(base.size - used))
                if (allocs.any { it.cidr == null }) note("전체 네트워크가 부족해요. 더 큰 네트워크(접두 길이를 줄임)를 쓰거나 기기 수를 줄여 보세요.", 2)
                if (bad.isNotEmpty()) note("읽지 못한 줄: ${bad.joinToString(" / ")}", 1)
            }
        },

        calc("hosts_to_prefix", G, "필요 기기 수 → 접두 길이", "기기가 N대 들어가려면 /몇 이어야 하는지",
            text("h", "필요한 기기 수", "예: 100", "100", listOf("10" to "10", "50" to "50", "254" to "254", "1000" to "1000"))) { i ->
            val h = i.long("h") ?: return@calc if (i.str("h").isEmpty()) need("기기 수를 입력하세요") else fail("숫자로 입력하세요")
            if (h < 1 || h > 2_147_483_645L) return@calc fail("기기 수는 1~2,147,483,645 사이예요")
            val p = Cidr.prefixForHosts(h)
            result {
                kv("접두 길이", "/$p"); kv("서브넷 마스크", t(Subnet.maskOf(p))); kv("쓸 수 있는 기기", "${n((1L shl (32 - p)) - 2)}대"); kv("남는 기기 수", n((1L shl (32 - p)) - 2 - h))
                if (p > 0) kv("한 단계 큰 /${p - 1}", "${n((1L shl (33 - p)) - 2)}대")
                note("기기 수 + 2(네트워크·브로드캐스트 주소)를 담는 가장 작은 2의 거듭제곱 크기를 골라요.")
            }
        },

        calc("ip_add", G, "IP 더하기·빼기", "IP 에 N 을 더하거나 빼서 다음·이전 주소 구하기 (IPv4·IPv6)",
            text("ip", "IP 주소", "예: 192.168.0.250", "192.168.0.250"), text("n", "더할 수 (빼려면 -)", "예: 10 또는 -5", "10", listOf("+1" to "1", "-1" to "-1", "+256" to "256"))) { i ->
            if (i.str("ip").isEmpty() || i.str("n").isEmpty()) return@calc need("IP 와 더할 수를 입력하세요")
            val ip = IpUtil.parse(i.str("ip")) ?: return@calc fail("IP 주소를 읽지 못했어요")
            val d = i.str("n").replace(",", "").removePrefix("+").toBigIntegerOrNull() ?: return@calc fail("더할 수를 숫자로 입력하세요")
            val v = V6.toBig(ip).add(d)
            val max = if (ip.address.size == 4) BigInteger.valueOf(0xFFFFFFFFL) else BigInteger.ONE.shiftLeft(128).subtract(BigInteger.ONE)
            if (v.signum() < 0 || v > max) return@calc fail("주소 범위를 벗어났어요")
            result {
                val r = if (ip.address.size == 4) addr4(v.toLong()) else V6.fromBig(v)
                kv("시작", IpUtil.format(ip)); kv("더한 값", d.toString()); kv("결과", IpUtil.format(r)); kv("종류", IpUtil.classify(r).label)
            }
        },

        calc("ip_distance", G, "두 IP 사이 거리", "두 주소 사이에 주소가 몇 개 있는지 (IPv4·IPv6)",
            text("a", "IP A", "예: 192.168.0.1", "192.168.0.1"), text("b", "IP B", "예: 192.168.3.200", "192.168.3.200")) { i ->
            if (i.str("a").isEmpty() || i.str("b").isEmpty()) return@calc need("두 IP 를 모두 입력하세요")
            val a = IpUtil.parse(i.str("a")) ?: return@calc fail("IP A 를 읽지 못했어요"); val b = IpUtil.parse(i.str("b")) ?: return@calc fail("IP B 를 읽지 못했어요")
            if (a.address.size != b.address.size) return@calc fail("IPv4 와 IPv6 는 비교할 수 없어요")
            val d = V6.toBig(a).subtract(V6.toBig(b)).abs()
            result { kv("차이", V6.big(d)); kv("두 주소를 포함한 개수", V6.big(d.add(BigInteger.ONE))); kv("더 작은 주소", IpUtil.format(if (V6.toBig(a) <= V6.toBig(b)) a else b)) }
        },

        calc("ip_sort", G, "IP 정렬·중복 제거", "IP 목록을 숫자 순서로 정렬하고 중복을 없애기 (IPv4 먼저)",
            multi("list", "IP 목록", "한 줄에 하나", "192.168.0.10\n10.0.0.5\n192.168.0.2\n10.0.0.5\n2001:db8::1\n8.8.8.8")) { i ->
            val lines = i.lines("list")
            if (lines.isEmpty()) return@calc need("IP 를 한 줄에 하나씩 입력하세요")
            val ok = ArrayList<InetAddress>(); val bad = ArrayList<String>()
            for (l in lines) IpUtil.parse(l.substringBefore('/'))?.let { ok += it } ?: run { bad += l }
            val sorted = ok.distinctBy { IpUtil.format(it) }.sortedBy { IpText.sortKey(it) }
            result {
                kv("입력", "${lines.size}줄"); kv("정리 결과", "${sorted.size}개 (중복 ${ok.size - sorted.size}개 제거)")
                if (sorted.isNotEmpty()) block(sorted.joinToString("\n") { IpUtil.format(it) })
                if (bad.isNotEmpty()) note("IP 가 아닌 줄 ${bad.size}개: ${bad.take(5).joinToString(" / ")}", 1)
            }
        },

        calc("ip_class", G, "IPv4 클래스 판별", "A·B·C·D·E 클래스와 옛 기본 마스크 (네트워크 시험 단골)",
            text("ip", "IPv4 주소", "예: 172.20.5.9", "172.20.5.9")) { i ->
            val a = v4(i.str("ip")) ?: return@calc if (i.str("ip").isEmpty()) need("IPv4 주소를 입력하세요") else fail("IPv4 주소를 읽지 못했어요")
            val f = ((a shr 24) and 0xff).toInt()
            val (range, mask, use) = when {
                f < 128 -> Triple("0.0.0.0 ~ 127.255.255.255", "255.0.0.0 (/8)", "대형 네트워크 (호스트 약 1,677만)")
                f < 192 -> Triple("128.0.0.0 ~ 191.255.255.255", "255.255.0.0 (/16)", "중형 네트워크 (호스트 약 6.5만)")
                f < 224 -> Triple("192.0.0.0 ~ 223.255.255.255", "255.255.255.0 (/24)", "소형 네트워크 (호스트 254)")
                f < 240 -> Triple("224.0.0.0 ~ 239.255.255.255", "없음", "멀티캐스트")
                else -> Triple("240.0.0.0 ~ 255.255.255.255", "없음", "예약·실험용")
            }
            result {
                kv("주소", t(a)); kv("클래스", classLetter(f)); kv("범위", range); kv("옛 기본 마스크", mask); kv("용도", use); kv("첫 8비트", java.lang.Long.toString(a shr 24, 2).padStart(8, '0'))
                kv("지금 종류", IpUtil.classify(addr4(a)).label)
                note("클래스 구분은 옛 방식이에요. 지금은 접두 길이를 직접 정하는 CIDR 을 써요.")
            }
        },

        calc("ip_bulk_kind", G, "IP 목록 일괄 종류 판별", "여러 IP 가 사설·공인·루프백·예약 중 무엇인지 한꺼번에",
            multi("list", "IP 목록", "한 줄에 하나", "192.168.0.1\n8.8.8.8\n100.64.1.1\n127.0.0.1\n169.254.3.3\n224.0.0.251\n2001:db8::1\nfe80::1")) { i ->
            val lines = i.lines("list")
            if (lines.isEmpty()) return@calc need("IP 를 한 줄에 하나씩 입력하세요")
            val counts = LinkedHashMap<String, Int>()
            result {
                header("IP", "종류")
                for (l in lines) {
                    val a = IpUtil.parse(l)
                    if (a == null) row(l, "IP 아님", level = 2) else { val k = IpUtil.classify(a); counts.merge(k.label, 1, Int::plus); row(IpUtil.format(a), k.label, level = if (k == IpKind.PUBLIC) 0 else -1) }
                }
                head("종류별 개수")
                for ((k, v) in counts) kv(k, "${v}개")
            }
        },

        calc("ip_validate", G, "IP·CIDR 형식 검사", "목록의 각 줄이 올바른 IPv4/IPv6/CIDR 인지 (틀린 이유도 알려 줘요)",
            multi("list", "목록", "한 줄에 하나", "192.168.1.1\n256.1.1.1\n10.0.0.0/33\n2001:db8::/32\n192.168.001.001\nexample.com\n1.2.3")) { i ->
            val lines = i.lines("list")
            if (lines.isEmpty()) return@calc need("확인할 값을 한 줄에 하나씩 입력하세요")
            result {
                header("값", "결과")
                var ok = 0
                for (l in lines) {
                    val (res, lvl) = when {
                        '/' in l -> {
                            val c4 = Cidr4.parse(l)
                            when {
                                c4 != null -> "올바른 IPv4 CIDR (네트워크 ${c4})" to -1
                                V6.parseCidr(l) != null -> "올바른 IPv6 CIDR" to -1
                                else -> "CIDR 형식이 틀렸어요 (접두 길이 범위나 주소 확인)" to 2
                            }
                        }
                        IpUtil.parseV4(l) != null -> "올바른 IPv4" to -1
                        IpUtil.parse(l) != null -> "올바른 IPv6" to -1
                        l.split('.').size == 4 && l.split('.').all { it.all { c -> c.isDigit() } } -> {
                            val bad = l.split('.').firstOrNull { it.isEmpty() || it.toIntOrNull()?.let { v -> v > 255 } != false || (it.length > 1 && it[0] == '0') }
                            ("틀렸어요: ${if (bad != null && bad.length > 1 && bad[0] == '0') "\"$bad\" 처럼 앞에 0 을 붙이면 안 돼요" else "각 칸은 0~255 여야 해요"}") to 2
                        }
                        l.count { it == '.' } in 1..2 && l.all { it.isDigit() || it == '.' } -> "숫자 칸이 4개여야 해요 (${l.count { it == '.' } + 1}개뿐)" to 2
                        else -> "IP 주소가 아니에요 (도메인이거나 형식이 달라요)" to 2
                    }
                    if (lvl < 0) ok++
                    row(l, res, level = lvl)
                }
                kv("올바른 값", "$ok / ${lines.size}", if (ok == lines.size) -1 else 1)
            }
        },

        calc("ipv4_bases", G, "IPv4 진법 변환", "점 표기·십진수·16진수·2진수·8진수 서로 바꾸기 (피싱 주소 속임수 확인에도)",
            text("v", "IPv4 (어떤 표기든)", "예: 192.168.0.1, 3232235521, 0xC0A80001, 0o30052000001", "192.168.0.1", listOf("십진수" to "3232235521", "16진수" to "0xC0A80001", "2진수" to "11000000101010000000000000000001"))) { i ->
            val s = i.str("v")
            if (s.isEmpty()) return@calc need("값을 입력하세요")
            val value: Long? = when {
                IpUtil.parseV4(s) != null -> v4(s)
                s.startsWith("0x", true) -> s.substring(2).toLongOrNull(16)
                s.startsWith("0o", true) -> s.substring(2).toLongOrNull(8)
                s.length == 32 && s.all { it == '0' || it == '1' } -> s.toLongOrNull(2)
                s.split('.').size == 4 && s.split('.').all { it.length == 8 && it.all { c -> c == '0' || c == '1' } } -> s.replace(".", "").toLongOrNull(2)
                s.all { it.isDigit() } -> s.toLongOrNull()
                s.all { it in '0'..'9' || it in 'a'..'f' || it in 'A'..'F' } && s.length == 8 -> s.toLongOrNull(16)
                else -> null
            }
            if (value == null || value !in 0..0xFFFFFFFFL) return@calc fail("읽지 못했어요. 점 표기(192.168.0.1), 십진수(0~4294967295), 0x 16진수, 0o 8진수, 32자리 2진수를 넣어 보세요")
            result {
                kv("점 표기", t(value)); kv("십진수", value.toString()); kv("16진수", "0x" + "%08X".format(value)); kv("2진수", bin32(value)); kv("8진수", "0o" + java.lang.Long.toString(value, 8))
                kv("종류", IpUtil.classify(addr4(value)).label)
                note("브라우저는 http://${value}/ 처럼 십진수 주소로도 접속해요. 피싱 링크가 이런 숫자 주소로 목적지를 숨기기도 하니, 낯선 숫자 주소 링크는 조심하세요.")
            }
        },

        calc("ipv6_expand", G, "IPv6 표기 변환", "압축 표기(::)와 전체 표기를 서로 바꾸기",
            text("ip", "IPv6 주소", "예: 2001:db8::1 또는 2001:0db8:0000:0000:0000:0000:0000:0001", "2001:db8::1", listOf("::1" to "::1", "fe80::1" to "fe80::1"))) { i ->
            val a = IpUtil.parse(i.str("ip")) ?: return@calc if (i.str("ip").isEmpty()) need("IPv6 주소를 입력하세요") else fail("IPv6 주소를 읽지 못했어요")
            if (a.address.size == 4) return@calc result { kv("IPv4 주소예요", IpUtil.format(a)); kv("IPv6 로 쓰면", "::ffff:${IpUtil.format(a)}") }
            result {
                kv("압축 표기", IpUtil.format(a)); kv("전체 표기", IpUtil.expandV6(a)!!); kv("16진수(32자리)", IpUtil.expandV6(a)!!.replace(":", ""))
                kv("종류", IpUtil.classify(a).label); kv("역방향 이름", Ptr.name(a))
            }
        },

        calc("ipv6_subnet", G, "IPv6 서브넷 계산", "IPv6 접두 길이별 범위와 /64 서브넷 개수",
            text("c", "IPv6/접두 길이", "예: 2001:db8:abcd::/48", "2001:db8:abcd::/48", listOf("/64" to "2001:db8:1:2::/64", "/48" to "2001:db8:abcd::/48", "/32" to "2001:db8::/32"))) { i ->
            val (a, p) = V6.parseCidr(i.str("c")) ?: return@calc if (i.str("c").isEmpty()) need("IPv6/접두 길이를 입력하세요") else fail("읽지 못했어요. 예: 2001:db8::/32")
            val net = V6.network(a, p); val last = V6.last(a, p); val total = BigInteger.ONE.shiftLeft(128 - p)
            result {
                kv("네트워크", "${IpUtil.format(V6.fromBig(net))}/$p"); kv("첫 주소", IpUtil.format(V6.fromBig(net))); kv("끝 주소", IpUtil.format(V6.fromBig(last)))
                kv("전체 주소 수", V6.big(total))
                if (p <= 64) kv("/64 서브넷 개수", V6.big(BigInteger.ONE.shiftLeft(64 - p))) else kv("/64 서브넷", "한 개보다 작은 범위예요")
                kv("종류", IpUtil.classify(a).label)
                note("가정·사무실 한 구간(LAN)은 보통 /64 하나를 써요. 통신사는 가입자에게 /56 이나 /48 을 주기도 해요.")
            }
        },

        calc("ptr_name", G, "역방향 조회 이름 만들기", "IP → in-addr.arpa / ip6.arpa 이름 (DNS PTR 조회·영역 설정에 필요)",
            text("ip", "IP 주소", "예: 203.0.113.9 또는 2001:db8::1", "203.0.113.9")) { i ->
            val a = IpUtil.parse(i.str("ip")) ?: return@calc if (i.str("ip").isEmpty()) need("IP 주소를 입력하세요") else fail("IP 주소를 읽지 못했어요")
            result { kv("IP", IpUtil.format(a)); kv("역방향 이름", Ptr.name(a)); note("이 이름의 PTR 레코드를 조회하면 IP 에 등록된 도메인 이름이 나와요. 'DNS·도메인' 묶음의 PTR 조회로 직접 확인해 보세요.") }
        },

        calc("ipv4_to_ipv6", G, "IPv4 → IPv6 주소 만들기", "IPv4 를 IPv6 로 표현하는 세 가지 방법 (매핑·6to4·NAT64)",
            text("ip", "IPv4 주소", "예: 192.0.2.33", "192.0.2.33")) { i ->
            val v = v4(i.str("ip")) ?: return@calc if (i.str("ip").isEmpty()) need("IPv4 주소를 입력하세요") else fail("IPv4 주소를 읽지 못했어요")
            val hi = (v shr 16) and 0xffff; val lo = v and 0xffff
            result {
                kv("IPv4-매핑", "::ffff:${t(v)}  (= ::ffff:${"%x".format(hi)}:${"%x".format(lo)})")
                kv("6to4 대역", "2002:${"%x".format(hi)}:${"%x".format(lo)}::/48")
                kv("NAT64 (64:ff9b::/96)", "64:ff9b::${"%x".format(hi)}:${"%x".format(lo)}  (= 64:ff9b::${t(v)})")
                note("매핑 주소는 한 기기 안에서 IPv4 를 IPv6 소켓으로 다룰 때, 6to4 는 옛 터널 방식, NAT64 는 IPv6 전용 망에서 IPv4 서버에 접속할 때 써요.")
            }
        },

        calc("eui64", G, "MAC → EUI-64 / IPv6 주소", "MAC 주소로 IPv6 인터페이스 ID 와 링크 로컬 주소 만들기",
            text("mac", "MAC 주소", "예: 00:1a:2b:3c:4d:5e", "00:1a:2b:3c:4d:5e"), text("prefix", "앞부분 (64비트)", "예: 2001:db8:1:2::", "fe80::")) { i ->
            val m = Mac.parse(i.str("mac")) ?: return@calc if (i.str("mac").isEmpty()) need("MAC 주소를 입력하세요") else fail("MAC 주소를 읽지 못했어요 (16진수 12자리)")
            val pre = IpUtil.parse(i.str("prefix").ifEmpty { "fe80::" })?.takeIf { it.address.size == 16 } ?: return@calc fail("앞부분을 IPv6 형식으로 입력하세요 (예: fe80::)")
            val iid = Mac.eui64(m)
            val full = pre.address.copyOf(); System.arraycopy(iid, 0, full, 8, 8)
            result {
                kv("MAC", Mac.hex(m)); kv("EUI-64 ID", iid.toList().chunked(2).joinToString(":") { "%02x%02x".format(it[0].toInt() and 0xff, it[1].toInt() and 0xff) })
                kv("만들어진 주소", IpUtil.format(InetAddress.getByAddress(full)))
                note("MAC 의 가운데에 ff:fe 를 끼우고 첫 바이트의 7번째 비트를 뒤집어요. 요즘 기기는 개인정보 보호를 위해 이 방식 대신 무작위 ID 를 쓰는 경우가 많아요.")
            }
        },

        calc("mac_format", G, "MAC 주소 표기 변환", "콜론·하이픈·시스코(점)·무구분, 대소문자 한꺼번에 변환",
            text("mac", "MAC 주소", "어떤 표기든", "00-1A-2B-3C-4D-5E")) { i ->
            val m = Mac.parse(i.str("mac")) ?: return@calc if (i.str("mac").isEmpty()) need("MAC 주소를 입력하세요") else fail("MAC 주소를 읽지 못했어요 (16진수 12자리, 구분은 : - . 또는 없음)")
            result {
                kv("콜론 (소문자)", Mac.hex(m)); kv("콜론 (대문자)", Mac.hex(m, ":", true)); kv("하이픈 (윈도)", Mac.hex(m, "-", true)); kv("시스코 (점)", Mac.cisco(m))
                kv("무구분", Mac.hex(m, "")); kv("무구분 (대문자)", Mac.hex(m, "", true))
            }
        },

        calc("mac_info", G, "MAC 주소 종류·제조사", "유니캐스트/멀티캐스트, 전역/임의(랜덤) 주소 구분과 아는 제조사",
            text("mac", "MAC 주소", "예: da:a1:19:00:11:22", "da:a1:19:00:11:22", listOf("랜덤" to "da:a1:19:00:11:22", "가상머신" to "08:00:27:12:34:56", "라즈베리" to "b8:27:eb:01:02:03"))) { i ->
            val m = Mac.parse(i.str("mac")) ?: return@calc if (i.str("mac").isEmpty()) need("MAC 주소를 입력하세요") else fail("MAC 주소를 읽지 못했어요")
            result {
                kv("MAC", Mac.hex(m)); kv("앞 3바이트 (OUI)", Mac.hex(m.copyOfRange(0, 3), "-", true))
                kv("전송 방식", if (Mac.isBroadcast(m)) "브로드캐스트" else if (Mac.isMulticast(m)) "멀티캐스트" else "유니캐스트 (한 기기)")
                kv("관리 방식", if (Mac.isLocal(m)) "임의 지정(로컬) — 랜덤 MAC 일 가능성이 커요" else "제조사가 정한 고유 주소(전역)")
                kv("제조사", Mac.vendor(m) ?: "알 수 없음 (이 앱은 자주 보이는 몇 가지만 알아요)")
                if (Mac.isLocal(m)) note("스마트폰은 Wi-Fi 에 연결할 때 기기를 추적하지 못하게 일부러 무작위 MAC 을 써요. 이런 주소는 제조사를 알 수 없는 게 정상이에요.")
                else note("제조사 전체 목록은 IEEE 의 OUI 목록에서 앞 3바이트로 찾을 수 있어요.")
            }
        },

        calc("ip_anonymize", G, "IP 익명화 (로그용)", "로그·통계에 쓸 IP 의 끝자리를 지워 개인을 식별하기 어렵게",
            choice("mode", "방식", listOf("IPv4 끝 1칸 (/24)", "IPv4 끝 2칸 (/16)", "IPv6 앞 48비트만", "IPv6 앞 64비트만")),
            multi("list", "IP 목록", "한 줄에 하나", "203.0.113.57\n198.51.100.201\n2001:db8:1234:5678:9abc:def0:1234:5678")) { i ->
            val lines = i.lines("list")
            if (lines.isEmpty()) return@calc need("IP 를 한 줄에 하나씩 입력하세요")
            val mode = i.choice("mode", listOf("IPv4 끝 1칸 (/24)", "IPv4 끝 2칸 (/16)", "IPv6 앞 48비트만", "IPv6 앞 64비트만"))
            result {
                header("원래", "익명화")
                val out = ArrayList<String>()
                for (l in lines) {
                    val a = IpUtil.parse(l)
                    if (a == null) { row(l, "IP 아님", level = 2); continue }
                    val r = if (a.address.size == 4) {
                        val p = if (mode == 1) 16 else 24
                        IpUtil.v4Text(IpUtil.v4ToLong(a.address) and Subnet.maskOf(p)) + "/$p"
                    } else {
                        val p = if (mode == 2) 48 else 64
                        IpUtil.format(V6.fromBig(V6.network(a, p))) + "/$p"
                    }
                    out += r; row(IpUtil.format(a), r)
                }
                if (out.isNotEmpty()) block(out.joinToString("\n"))
                note("끝자리를 지워도 다른 정보와 합치면 개인을 다시 알아낼 수 있어요. 꼭 필요한 기간만 보관하세요.")
            }
        },

        calc("ip_extract", G, "글에서 IP 추출", "로그·메일·문서 속 IPv4/IPv6 주소만 뽑아 중복 없이 정렬",
            choice("scope", "대상", listOf("모두", "공인 주소만", "사설 주소만")),
            multi("text", "글 붙여 넣기", "로그나 메일 헤더를 통째로 붙여 넣으세요",
                "Jan 5 10:01:22 sshd: Failed password for root from 203.0.113.9 port 4022\nJan 5 10:01:25 sshd: Failed password for root from 203.0.113.9 port 4023\nclient 198.51.100.7 -> 10.0.0.5 via 2001:db8::7")) { i ->
            val txt = i.raw("text")
            if (txt.isBlank()) return@calc need("글을 붙여 넣으세요")
            val all = IpText.extract(txt)
            val scope = i.choice("scope", listOf("모두", "공인 주소만", "사설 주소만"))
            val kept = all.filter { a -> when (scope) { 1 -> IpUtil.classify(a) == IpKind.PUBLIC; 2 -> IpUtil.classify(a) == IpKind.PRIVATE; else -> true } }
            val counts = kept.groupingBy { IpUtil.format(it) }.eachCount()
            val uniq = kept.distinctBy { IpUtil.format(it) }.sortedBy { IpText.sortKey(it) }
            result {
                kv("찾은 주소", "${kept.size}개 (중복 제거 ${uniq.size}개)"); kv("IPv4 / IPv6", "${uniq.count { it.address.size == 4 }} / ${uniq.count { it.address.size == 16 }}")
                if (uniq.isNotEmpty()) { block(uniq.joinToString("\n") { IpUtil.format(it) }); head("나온 횟수"); for (a in uniq.take(30)) kv(IpUtil.format(a), "${counts[IpUtil.format(a)]}번") }
                else note("조건에 맞는 IP 를 찾지 못했어요.", 1)
            }
        },

        calc("ip_count", G, "로그 IP 집계 (Top N)", "접속 로그에서 IP 별 횟수를 세어 가장 많은 것부터 (공격·이상 접속 찾기)",
            choice("top", "보여줄 개수", listOf("5", "10", "20", "50"), "10"),
            multi("text", "로그 붙여 넣기", "한 줄에 IP 가 있는 로그", "203.0.113.9 - - GET /login\n203.0.113.9 - - GET /admin\n198.51.100.7 - - GET /\n203.0.113.9 - - POST /login\n192.0.2.44 - - GET /")) { i ->
            val lines = i.raw("text").lines().filter { it.isNotBlank() }
            if (lines.isEmpty()) return@calc need("로그를 붙여 넣으세요")
            val ips = lines.mapNotNull { IpText.extract(it).firstOrNull()?.let { a -> IpUtil.format(a) } }
            val counts = ips.groupingBy { it }.eachCount().entries.sortedByDescending { it.value }
            val top = i.str("top").toIntOrNull() ?: 10
            result {
                kv("분석한 줄", "${lines.size}줄 (IP 있음 ${ips.size}줄)"); kv("서로 다른 IP", "${counts.size}개")
                header("순위", "IP", "횟수", "비율")
                counts.take(top).forEachIndexed { idx, e -> row("${idx + 1}", e.key, "${e.value}", "%.1f%%".format(e.value * 100.0 / ips.size.coerceAtLeast(1))) }
                if (counts.size > top) note("나머지 ${counts.size - top}개 IP 는 생략했어요.")
            }
        },
    )
}
