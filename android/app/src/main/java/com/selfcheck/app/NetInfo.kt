package com.selfcheck.app

import android.content.Context
import android.net.ConnectivityManager
import android.net.Network
import android.net.NetworkCapabilities
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
