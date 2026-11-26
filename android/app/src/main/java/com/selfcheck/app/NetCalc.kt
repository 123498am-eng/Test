package com.selfcheck.app

import java.math.BigDecimal
import java.math.BigInteger
import java.net.InetAddress

/*
 * IP 계산 엔진 (화면·인터넷 없이 컴퓨터에서 시험): IPv4 네트워크(CIDR) 연산, IPv6 큰 수 연산, MAC, 역방향 이름.
 */

/** IPv4 네트워크 (CIDR): 시작 주소는 항상 접두 길이에 맞게 정리됨 */
class Cidr4(val net: Long, val prefix: Int) : Comparable<Cidr4> {
    val size: Long get() = 1L shl (32 - prefix)
    val first: Long get() = net
    val last: Long get() = net + size - 1
    val mask: Long get() = Subnet.maskOf(prefix)
    operator fun contains(ip: Long) = ip in first..last
    fun contains(o: Cidr4) = o.first >= first && o.last <= last
    fun overlaps(o: Cidr4) = first <= o.last && o.first <= last
    override fun compareTo(other: Cidr4) = compareValuesBy(this, other, { it.net }, { it.prefix })
    override fun toString() = "${IpUtil.v4Text(net)}/$prefix"
    override fun equals(other: Any?) = other is Cidr4 && other.net == net && other.prefix == prefix
    override fun hashCode() = net.hashCode() * 31 + prefix

    companion object {
        fun of(ip: Long, prefix: Int) = Cidr4(ip and Subnet.maskOf(prefix), prefix)

        /** "192.168.0.5/24"(호스트 칸은 정리), "192.168.0.5"(=/32), "192.168.0.0/255.255.255.0" */
        fun parse(s: String): Cidr4? {
            val t = s.trim()
            if ('/' in t) return Subnet.parse(t)?.let { Cidr4(it.network, it.prefix) }
            return IpUtil.parseV4(t)?.let { Cidr4(IpUtil.v4ToLong(it), 32) }
        }
    }
}

class VlsmReq(val name: String, val hosts: Long)
class VlsmAlloc(val req: VlsmReq, val cidr: Cidr4?)

object Cidr {
    /** 시작~끝 주소를 가장 적은 CIDR 덩어리로 */
    fun rangeToCidrs(start: Long, end: Long): List<Cidr4> {
        val out = ArrayList<Cidr4>()
        var s = start
        while (s <= end) {
            var size = if (s == 0L) 1L shl 32 else (s and -s)  // 시작 주소 위치에서 가능한 가장 큰 덩어리
            val remain = end - s + 1
            while (size > remain) size = size shr 1
            out += Cidr4(s, 32 - java.lang.Long.numberOfTrailingZeros(size))
            s += size
        }
        return out
    }

    /** 겹치거나 이어진 범위를 합쳐 가장 적은 CIDR 목록으로 */
    fun merge(list: List<Cidr4>): List<Cidr4> {
        val ranges = list.map { it.first to it.last }.sortedBy { it.first }
        val merged = ArrayList<Pair<Long, Long>>()
        for ((a, b) in ranges) {
            if (merged.isNotEmpty() && a <= merged.last().second + 1) merged[merged.size - 1] = merged.last().first to maxOf(merged.last().second, b)
            else merged += a to b
        }
        return merged.flatMap { rangeToCidrs(it.first, it.second) }
    }

    /** c 를 newPrefix 짜리로 나눔 (개수 = 2^(newPrefix - prefix), 너무 많으면 limit 개까지만) */
    fun split(c: Cidr4, newPrefix: Int, limit: Int = 4096): List<Cidr4> {
        val count = 1L shl (newPrefix - c.prefix)
        val step = 1L shl (32 - newPrefix)
        return (0 until minOf(count, limit.toLong())).map { Cidr4(c.net + it * step, newPrefix) }
    }

    fun ceilLog2(v: Long): Int { var n = 0; var x = 1L; while (x < v) { x = x shl 1; n++ }; return n }

    /** 가변 길이 서브넷(VLSM): 큰 요구부터 정렬해 앞에서부터 맞춰 배정. 자리가 없으면 cidr = null */
    fun vlsm(base: Cidr4, reqs: List<VlsmReq>): List<VlsmAlloc> {
        var cursor = base.first
        return reqs.sortedByDescending { it.hosts }.map { r ->
            val bits = ceilLog2(r.hosts + 2).coerceAtLeast(2)
            if (bits > 32 - base.prefix) return@map VlsmAlloc(r, null)
            val size = 1L shl bits
            val start = (cursor + size - 1) / size * size
            if (start + size - 1 > base.last) VlsmAlloc(r, null)
            else { cursor = start + size; VlsmAlloc(r, Cidr4(start, 32 - bits)) }
        }
    }

    /** 필요한 기기 수를 담는 가장 긴 접두 길이 (기기 수 + 네트워크·브로드캐스트 주소 2개) */
    fun prefixForHosts(hosts: Long): Int = (32 - ceilLog2(hosts + 2)).coerceAtMost(30)
}

object V6 {
    fun toBig(a: InetAddress): BigInteger = BigInteger(1, a.address.let { if (it.size == 4) ByteArray(12) + it else it })
    fun fromBig(v: BigInteger): InetAddress {
        val raw = v.toByteArray()
        val b = ByteArray(16)
        val src = if (raw.size > 16) raw.copyOfRange(raw.size - 16, raw.size) else raw
        System.arraycopy(src, 0, b, 16 - src.size, src.size)
        return InetAddress.getByAddress(b)
    }
    fun mask(prefix: Int): BigInteger = if (prefix <= 0) BigInteger.ZERO else BigInteger.ONE.shiftLeft(128).subtract(BigInteger.ONE).shiftLeft(128 - prefix).and(BigInteger.ONE.shiftLeft(128).subtract(BigInteger.ONE))
    fun network(a: InetAddress, prefix: Int): BigInteger = toBig(a).and(mask(prefix))
    fun last(a: InetAddress, prefix: Int): BigInteger = network(a, prefix).or(BigInteger.ONE.shiftLeft(128 - prefix).subtract(BigInteger.ONE))

    /** "2001:db8::/32" → (주소, 접두 길이). 접두 길이가 없으면 128 */
    fun parseCidr(s: String): Pair<InetAddress, Int>? {
        val t = s.trim()
        val slash = t.indexOf('/')
        val addr = IpUtil.parse(if (slash >= 0) t.substring(0, slash) else t) ?: return null
        if (addr.address.size != 16) return null
        val p = if (slash >= 0) t.substring(slash + 1).trim().toIntOrNull() ?: return null else 128
        if (p !in 0..128) return null
        return addr to p
    }

    /** 큰 수를 읽기 좋게: 1조 미만은 자릿수 쉼표, 그 이상은 2^n 과 과학 표기 */
    fun big(v: BigInteger): String {
        if (v < BigInteger.valueOf(1_000_000_000_000L)) return "%,d".format(v)
        val bits = v.bitLength() - 1
        val exact = v.bitCount() == 1
        val sci = BigDecimal(v).let { d -> String.format("%.3e", d).replace("e+", "×10^").replace("e", "×10^") }
        return (if (exact) "2^$bits" else "약 2^$bits") + " ($sci)"
    }
}

object Mac {
    /** 어떤 표기(aa:bb:.., AA-BB-.., aabb.ccdd.eeff, aabbccddeeff)든 6바이트로. 아니면 null */
    fun parse(s: String): ByteArray? {
        val h = s.trim().filter { it != ':' && it != '-' && it != '.' && !it.isWhitespace() }
        if (h.length != 12 || !h.all { it in '0'..'9' || it in 'a'..'f' || it in 'A'..'F' }) return null
        return ByteArray(6) { h.substring(it * 2, it * 2 + 2).toInt(16).toByte() }
    }

    fun hex(b: ByteArray, sep: String = ":", upper: Boolean = false): String =
        b.joinToString(sep) { (if (upper) "%02X" else "%02x").format(it.toInt() and 0xff) }

    fun cisco(b: ByteArray): String = (0 until 3).joinToString(".") { "%02x%02x".format(b[2 * it].toInt() and 0xff, b[2 * it + 1].toInt() and 0xff) }

    fun isMulticast(b: ByteArray) = (b[0].toInt() and 1) == 1
    fun isLocal(b: ByteArray) = (b[0].toInt() and 2) == 2
    fun isBroadcast(b: ByteArray) = b.all { it == 0xff.toByte() }

    /** EUI-64 인터페이스 ID: 가운데에 ff:fe 를 끼우고 첫 바이트의 둘째 비트(U/L)를 뒤집음 */
    fun eui64(b: ByteArray): ByteArray = byteArrayOf((b[0].toInt() xor 2).toByte(), b[1], b[2], 0xff.toByte(), 0xfe.toByte(), b[3], b[4], b[5])

    /** 가상머신·라즈베리 파이 등 자주 보이는 것만 (제조사 전체 목록은 IEEE OUI 목록이 필요) */
    private val OUI = mapOf(
        "000c29" to "VMware (가상머신)", "005056" to "VMware (가상머신)", "000569" to "VMware (가상머신)", "001c14" to "VMware (가상머신)",
        "080027" to "Oracle VirtualBox (가상머신)", "00155d" to "Microsoft Hyper-V (가상머신)", "525400" to "QEMU/KVM (가상머신 기본값)",
        "b827eb" to "Raspberry Pi Foundation (라즈베리 파이)", "dca632" to "Raspberry Pi Trading (라즈베리 파이)",
        "e45f01" to "Raspberry Pi Trading (라즈베리 파이)", "28cdc1" to "Raspberry Pi Trading (라즈베리 파이)",
        "00005e" to "IANA (VRRP 등 공용 주소)", "01005e" to "IPv4 멀티캐스트용 MAC", "01c200" to "브리지/STP 제어용", "00000c" to "Cisco",
    )

    fun vendor(b: ByteArray): String? {
        val key = hex(b.copyOfRange(0, 3), "")
        if (b[0].toInt() and 0xff == 0x33 && b[1].toInt() and 0xff == 0x33) return "IPv6 멀티캐스트용 MAC"
        if (isBroadcast(b)) return "브로드캐스트"
        return OUI[key]
    }
}

object Ptr {
    /** 역방향 조회 이름: IPv4 → 4.3.2.1.in-addr.arpa, IPv6 → 니블을 뒤집은 ....ip6.arpa */
    fun name(a: InetAddress): String {
        val b = a.address
        if (b.size == 4) return (3 downTo 0).joinToString(".") { (b[it].toInt() and 0xff).toString() } + ".in-addr.arpa"
        val hex = b.joinToString("") { "%02x".format(it.toInt() and 0xff) }
        return hex.reversed().toCharArray().joinToString(".") + ".ip6.arpa"
    }
}

object IpText {
    private val RE4 = Regex("""(?<![\d.])\d{1,3}(?:\.\d{1,3}){3}(?!\d|\.\d)""")
    private val RE6 = Regex("""[0-9A-Fa-f:.]{2,}""")

    /** 글 속 IPv4·IPv6 주소를 나타난 순서대로 (중복 포함). 형식이 틀린 것(256.1.1.1 등)은 건너뜀 */
    fun extract(text: String): List<InetAddress> {
        val hits = ArrayList<Pair<Int, InetAddress>>()
        for (m in RE4.findAll(text)) IpUtil.parse(m.value)?.let { hits += m.range.first to it }
        for (m in RE6.findAll(text)) {
            val v = m.value.trim('.')
            if (v.count { it == ':' } >= 2) IpUtil.parse(v)?.let { hits += m.range.first to it }
        }
        return hits.sortedBy { it.first }.map { it.second }
    }

    /** IPv4 먼저, 숫자 순서로 정렬하기 위한 값 */
    fun sortKey(a: InetAddress): BigInteger = V6.toBig(a).let { if (a.address.size == 4) it else it.add(BigInteger.ONE.shiftLeft(128)) }
}
