package com.selfcheck.app

import android.content.Context
import android.net.ConnectivityManager
import android.net.Network
import android.net.NetworkCapabilities
import android.net.wifi.WifiManager
import android.os.Build
import java.net.HttpURLConnection
import java.net.Inet4Address
import java.net.Inet6Address
import java.net.NetworkInterface
import java.net.Socket
import java.net.URL

/** 지금 연결된 망 하나의 정보 (Wi-Fi·모바일 데이터·VPN 등) */
class NetRow(
    /** "Wi-Fi" · "모바일 데이터" · "이더넷" · "VPN" · "기타" */
    val transport: String,
    val ifName: String?,
    val ipv4: String?,
    val prefix: Int?,
    val ipv6: List<String>,
    val gateway: String?,
    val dns: List<String>,
    /** 지금 인터넷 연결에 쓰이는 기본 망인지 */
    val isDefault: Boolean,
    /** 소켓을 이 망에 묶을 때 쓰는 핸들 (시험·화면 그리기 때는 null) */
    val network: Network? = null,
) {
    /** 집·사무실 망(같은 공유기에 붙은 기기들이 있는 망) */
    val isLan: Boolean get() = transport == "Wi-Fi" || transport == "이더넷"
}

class IfaceInfo(val name: String, val label: String, val addrs: List<String>)

object LocalNet {
    /** 연결된 모든 망 (기본 망이 맨 앞). 정보를 못 읽으면 빈 목록 */
    @Suppress("DEPRECATION")
    fun networks(ctx: Context): List<NetRow> = try {
        val cm = ctx.getSystemService(ConnectivityManager::class.java)
        val active = cm.activeNetwork
        cm.allNetworks.mapNotNull { n ->
            val lp = cm.getLinkProperties(n) ?: return@mapNotNull null
            val caps = cm.getNetworkCapabilities(n)
            val transport = when {
                caps == null -> "기타"
                caps.hasTransport(NetworkCapabilities.TRANSPORT_VPN) -> "VPN"
                caps.hasTransport(NetworkCapabilities.TRANSPORT_WIFI) -> "Wi-Fi"
                caps.hasTransport(NetworkCapabilities.TRANSPORT_ETHERNET) -> "이더넷"
                caps.hasTransport(NetworkCapabilities.TRANSPORT_CELLULAR) -> "모바일 데이터"
                else -> "기타"
            }
            var v4: String? = null; var pre: Int? = null; val v6 = ArrayList<String>()
            for (la in lp.linkAddresses) {
                val a = la.address
                if (a is Inet4Address) { if (v4 == null) { v4 = IpUtil.format(a); pre = la.prefixLength } }
                else if (a is Inet6Address && !a.isLinkLocalAddress && !a.isLoopbackAddress) v6 += IpUtil.format(a)
            }
            val gw = lp.routes.firstOrNull { it.isDefaultRoute && it.gateway is Inet4Address }?.gateway?.let { IpUtil.format(it) }
            NetRow(transport, lp.interfaceName, v4, pre, v6, gw, lp.dnsServers.map { IpUtil.format(it) }, n == active, n)
        }.sortedByDescending { it.isDefault }
    } catch (_: Throwable) { emptyList() }

    /** 같은 망 기기 찾기에 쓸 망 (VPN 이 아닌 Wi-Fi·이더넷 중 IPv4 가 있는 것) */
    fun lan(rows: List<NetRow>): NetRow? = rows.firstOrNull { it.isLan && it.ipv4 != null }

    /** 이 망에 묶인 소켓을 만드는 함수 (망을 모르면 그냥 소켓) */
    fun socketFactory(row: NetRow?): () -> Socket = {
        Socket().also { s -> row?.network?.let { n -> runCatching { n.bindSocket(s) } } }
    }


    /** 연결 정보 한눈에 (이름 → 값). 읽지 못한 항목은 건너뜀 */
    @Suppress("DEPRECATION")
    fun details(ctx: Context): List<Pair<String, String>> = try {
        val cm = ctx.getSystemService(ConnectivityManager::class.java)
        val n = cm.activeNetwork
        val caps = cm.getNetworkCapabilities(n)
        val lp = cm.getLinkProperties(n)
        val out = ArrayList<Pair<String, String>>()
        fun yn(b: Boolean) = if (b) "예" else "아니요"
        if (n == null || caps == null) out += "연결" to "연결된 네트워크가 없어요"
        else {
            val kind = when {
                caps.hasTransport(NetworkCapabilities.TRANSPORT_VPN) -> "VPN"
                caps.hasTransport(NetworkCapabilities.TRANSPORT_WIFI) -> "Wi-Fi"
                caps.hasTransport(NetworkCapabilities.TRANSPORT_ETHERNET) -> "이더넷"
                caps.hasTransport(NetworkCapabilities.TRANSPORT_CELLULAR) -> "모바일 데이터"
                else -> "기타"
            }
            out += "연결 종류" to kind
            out += "인터넷 통하는지 확인됨" to yn(caps.hasCapability(NetworkCapabilities.NET_CAPABILITY_VALIDATED))
            out += "종량제(데이터 요금이 드는) 연결" to yn(!caps.hasCapability(NetworkCapabilities.NET_CAPABILITY_NOT_METERED))
            out += "로밍 중" to yn(!caps.hasCapability(NetworkCapabilities.NET_CAPABILITY_NOT_ROAMING))
            out += "VPN 사용" to yn(caps.hasTransport(NetworkCapabilities.TRANSPORT_VPN) || !caps.hasCapability(NetworkCapabilities.NET_CAPABILITY_NOT_VPN))
            out += "로그인 필요한 Wi-Fi(캡티브 포털) 감지" to yn(caps.hasCapability(NetworkCapabilities.NET_CAPABILITY_CAPTIVE_PORTAL))
            if (caps.linkDownstreamBandwidthKbps > 0) out += "내려받기 속도(운영체제 추정)" to "${caps.linkDownstreamBandwidthKbps / 1000} Mbps"
            if (caps.linkUpstreamBandwidthKbps > 0) out += "올리기 속도(운영체제 추정)" to "${caps.linkUpstreamBandwidthKbps / 1000} Mbps"
            if (lp != null) {
                lp.interfaceName?.let { out += "장치 이름" to it }
                if (Build.VERSION.SDK_INT >= 29 && lp.mtu > 0) out += "MTU" to lp.mtu.toString()
                out += "Private DNS(DNS over TLS)" to if (lp.isPrivateDnsActive) "켜짐" + (lp.privateDnsServerName?.let { " ($it)" } ?: "") else "꺼짐"
                out += "프록시" to (lp.httpProxy?.let { "${it.host}:${it.port}" } ?: "없음")
                if (lp.dnsServers.isNotEmpty()) out += "DNS 서버" to lp.dnsServers.joinToString(", ") { IpUtil.format(it) }
                lp.domains?.takeIf { it.isNotBlank() }?.let { out += "검색 도메인" to it }
            }
        }
        out
    } catch (_: Throwable) { emptyList() }

    /** Wi-Fi 신호·속도 (이름 → 값). Wi-Fi 에 연결돼 있지 않거나 읽을 수 없으면 null */
    @Suppress("DEPRECATION")
    fun wifi(ctx: Context): List<Pair<String, String>>? = try {
        val wm = ctx.applicationContext.getSystemService(Context.WIFI_SERVICE) as WifiManager
        val i = wm.connectionInfo
        // 연결 여부는 신호·주파수·속도로 판단 (안드로이드 12 이상은 위치 권한이 없으면 networkId 가 항상 -1 로 가려져서 쓸 수 없음)
        if (i == null || i.rssi <= -127 || (i.frequency <= 0 && i.linkSpeed <= 0)) null
        else {
            val out = ArrayList<Pair<String, String>>()
            out += "신호 세기" to "${i.rssi} dBm"
            if (i.linkSpeed > 0) out += "연결 속도" to "${i.linkSpeed} Mbps"
            if (Build.VERSION.SDK_INT >= 29) {
                if (i.txLinkSpeedMbps > 0) out += "올리기 연결 속도" to "${i.txLinkSpeedMbps} Mbps"
                if (i.rxLinkSpeedMbps > 0) out += "내려받기 연결 속도" to "${i.rxLinkSpeedMbps} Mbps"
            }
            if (i.frequency > 0) out += "주파수" to "${i.frequency} MHz"
            if (Build.VERSION.SDK_INT >= 30) out += "Wi-Fi 표준" to when (i.wifiStandard) {
                4 -> "802.11n (Wi-Fi 4)"; 5 -> "802.11ac (Wi-Fi 5)"; 6 -> "802.11ax (Wi-Fi 6/6E)"; 7 -> "802.11be (Wi-Fi 7)"; 1 -> "802.11a/b/g"; else -> "알 수 없음"
            }
            out
        }
    } catch (_: Throwable) { null }

    private fun labelOf(name: String) = when {
        name == "lo" -> "루프백"
        name.startsWith("wlan") || name.startsWith("wifi") -> "Wi-Fi"
        name.startsWith("rmnet") || name.startsWith("ccmni") || name.startsWith("v4-rmnet") || name.startsWith("data") || name.startsWith("pdp") -> "모바일 데이터"
        name.startsWith("eth") || name.startsWith("en") -> "이더넷"
        name.startsWith("tun") || name.startsWith("ppp") || name.startsWith("wg") || name.startsWith("tap") -> "VPN"
        name.startsWith("ap") || name.startsWith("swlan") -> "핫스폿"
        else -> "기타"
    }

    /** 이 기기의 네트워크 장치와 주소 (참고용: 안드로이드 버전에 따라 일부만 보일 수 있음) */
    fun interfaces(): List<IfaceInfo> = try {
        (NetworkInterface.getNetworkInterfaces()?.toList() ?: emptyList()).filter { it.isUp }.map { ni ->
            IfaceInfo(ni.name, labelOf(ni.name), ni.interfaceAddresses.filter { !it.address.isLinkLocalAddress || it.address is Inet4Address }
                .map { "${IpUtil.format(it.address)}/${it.networkPrefixLength}" })
        }.filter { it.addrs.isNotEmpty() }
    } catch (_: Throwable) { emptyList() }
}

object PublicIp {
    private val URLS = listOf("https://api.ipify.org", "https://checkip.amazonaws.com", "https://ifconfig.me/ip")

    /** 인터넷에서 보이는 내 IP 와, 물어본 서비스 주소. 못 찾으면 null. 서비스에는 내 IP 외에 아무것도 보내지 않음 */
    fun fetch(): Pair<String, String>? {
        for (u in URLS) {
            try {
                val c = URL(u).openConnection() as HttpURLConnection
                c.connectTimeout = 6000; c.readTimeout = 6000; c.setRequestProperty("User-Agent", "SelfCheck-Android")
                val text = c.inputStream.bufferedReader().use { it.readText() }.trim().take(64)
                if (IpUtil.parse(text) != null) return text to URL(u).host
            } catch (_: Exception) {}
        }
        return null
    }
}
