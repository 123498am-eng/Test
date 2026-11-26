package com.selfcheck.app

import android.app.Activity
import android.graphics.Bitmap
import android.graphics.Canvas
import android.view.View
import android.view.View.MeasureSpec
import androidx.activity.ComponentActivity
import android.content.Context
import android.content.Intent
import androidx.test.core.app.ApplicationProvider
import androidx.work.Configuration
import androidx.work.WorkManager
import org.junit.Assume.assumeTrue
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.Robolectric
import org.robolectric.RobolectricTestRunner
import org.robolectric.annotation.Config
import org.robolectric.annotation.GraphicsMode
import java.io.File

/** -PuiShots 를 주지 않으면 시험을 통째로 무시 (Robolectric 이 안드로이드 SDK 를 내려받으려 하지 않게) */
class ShotRunner(cls: Class<*>) : RobolectricTestRunner(cls) {
    override fun isIgnored(child: org.junit.runners.model.FrameworkMethod): Boolean = System.getProperty("ui.shots.dir") == null || super.isIgnored(child)
}

/**
 * 화면을 컴퓨터에서 실제로 그려 PNG 로 저장해 눈으로 확인하는 시험 (-PuiShots=폴더 를 줄 때만 실행).
 * Robolectric 네이티브 그래픽으로 진짜 Activity 를 띄워서, 코드가 만든 화면 그대로를 그립니다.
 */
@RunWith(ShotRunner::class)
@GraphicsMode(GraphicsMode.Mode.NATIVE)
@Config(sdk = [35], qualifiers = "w411dp-h891dp-xxhdpi")
class UiShotTest {
    private val dir: File? = System.getProperty("ui.shots.dir")?.let { File(it) }

    private fun shoot(a: Activity, name: String, heightDp: Int = 891) {
        // 화면을 만든 뒤 쌓여 있는 그리기 작업을 먼저 처리해야, 나중에 다시 만든 칩의 글자까지 그려짐
        // (처리하지 않고 바로 그리면 시험용 그림에서만 글자가 빠짐: 같은 칩을 따로 그리면 글자가 있음)
        org.robolectric.shadows.ShadowLooper.idleMainLooper()
        val d = a.resources.displayMetrics
        val w = d.widthPixels; val h = (heightDp * d.density).toInt()
        val v: View = a.window.decorView
        v.measure(MeasureSpec.makeMeasureSpec(w, MeasureSpec.EXACTLY), MeasureSpec.makeMeasureSpec(h, MeasureSpec.EXACTLY))
        v.layout(0, 0, w, h)
        val bmp = Bitmap.createBitmap(w, h, Bitmap.Config.ARGB_8888)
        v.draw(Canvas(bmp))
        dir!!.mkdirs()
        File(dir, "$name.png").outputStream().use { bmp.compress(Bitmap.CompressFormat.PNG, 100, it) }
    }

    @Before fun initWork() {
        val ctx = ApplicationProvider.getApplicationContext<Context>()
        runCatching { WorkManager.initialize(ctx, Configuration.Builder().setExecutor(java.util.concurrent.Executors.newSingleThreadExecutor()).build()) }
    }

    private inline fun <reified T : ComponentActivity> screen(name: String, heightDp: Int = 891, extras: Map<String, String> = emptyMap(), tweak: (T) -> Unit = {}) {
        assumeTrue(dir != null)
        val intent = Intent(ApplicationProvider.getApplicationContext(), T::class.java).also { i -> extras.forEach { (k, v) -> i.putExtra(k, v) } }
        val c = Robolectric.buildActivity(T::class.java, intent).setup()
        tweak(c.get())
        shoot(c.get(), name, heightDp)
        c.pause().stop().destroy()
    }

    private inline fun <reified T : ComponentActivity> tryScreen(name: String, heightDp: Int, extras: Map<String, String> = emptyMap()) {
        try { screen<T>(name, heightDp, extras) } catch (e: Throwable) { if (e is org.junit.AssumptionViolatedException) throw e; System.err.println("스크린샷 건너뜀 $name: $e") }
    }

    private val tag get() = System.getProperty("ui.shots.tag") ?: "before"

    private fun voicePrefs(vararg kv: Pair<String, Any>) {
        val e = ApplicationProvider.getApplicationContext<Context>().getSharedPreferences("voice_ui", Context.MODE_PRIVATE).edit().clear()
        for ((k, v) in kv) when (v) { is Boolean -> e.putBoolean(k, v); is Float -> e.putFloat(k, v); is String -> e.putString(k, v) }
        e.commit()
    }

    @Test fun voice() = screen<VoiceChangerActivity>("${tag}_voice", 1500)
    /** 원본 목소리 섞기를 켜고, 변조 목소리 듣기를 끈 상태 (뉴스 앵커 선택) */
    @Test fun voiceToggles() { voicePrefs("preset" to "news_f_anchor", "category" to "뉴스 여성", "origOn" to true, "origLevel" to 0.7f, "monitor" to false); screen<VoiceChangerActivity>("${tag}_voice_toggles", 1100) }
    /** 효과 전용 프리셋: 원본 스위치가 비활성 */
    @Test fun voiceEffect() { voicePrefs("preset" to "cave", "category" to "효과"); screen<VoiceChangerActivity>("${tag}_voice_effect", 1100) }
    @Test fun edit() = screen<EditActivity>("${tag}_edit", 700)
    // 카메라 화면: 카메라 권한이 없는 상태에서 위쪽·아래쪽 버튼 줄이 어떻게 보이는지 (지원 안 되는 환경이면 건너뜀)
    @Test fun cameraPerson() = tryScreen<PersonActivity>("${tag}_cam_person", 891)
    @Test fun cameraLiveTool() = tryScreen<LiveToolActivity>("${tag}_cam_livetool", 891, mapOf("tool" to "squat"))
    @Test fun cameraPlate() = tryScreen<PlateActivity>("${tag}_cam_plate", 891)
    @Test fun photoToolLip() = screen<PhotoToolActivity>("${tag}_phototool_lip", 700, mapOf("tool" to "lip"))
    @Test fun utilityLink() = screen<UtilityActivity>("${tag}_utility_link", 700, mapOf("tool" to "link"))
    @Test fun photoInfo() {
        val f = java.io.File.createTempFile("shot", ".png")
        Bitmap.createBitmap(300, 400, Bitmap.Config.ARGB_8888).also { it.eraseColor(0xFFCCB6A0.toInt()) }.compress(Bitmap.CompressFormat.PNG, 100, f.outputStream())
        screen<PhotoActivity>("${tag}_photoinfo", 1000, mapOf("path" to f.absolutePath))
    }
    @Test fun home() = screen<MainActivity>("${tag}_home", 2400)
    @Test fun tools() = screen<ToolsActivity>("${tag}_tools", 1500)
    @Test fun faceScan() = screen<FaceScanActivity>("${tag}_facescan", 700)
    @Test fun faceCompare() = screen<FaceCompareActivity>("${tag}_facecompare", 1100)
    @Test fun plateLookup() = screen<PlateLookupActivity>("${tag}_platelookup", 900)
    @Test fun photoTool() = screen<PhotoToolActivity>("${tag}_phototool", 900, mapOf("tool" to "skin_smooth"))
    @Test fun utility() = screen<UtilityActivity>("${tag}_utility", 900, mapOf("tool" to "pw_strength"))
    @Test fun sensor() = screen<SensorActivity>("${tag}_sensor", 800, mapOf("tool" to "level"))


    // ---- 네트워크 도구 (인터넷에 접속하지 않고, 결과는 꾸민 값으로 그림)
    private fun addr(s: String) = IpUtil.parse(s)!!
    private val demoNets = listOf(
        NetRow("Wi-Fi", "wlan0", "192.168.0.12", 24, listOf("2001:db8:1:2::c"), "192.168.0.1", listOf("192.168.0.1", "8.8.8.8"), true),
        NetRow("모바일 데이터", "rmnet_data1", "10.121.43.7", 28, emptyList(), null, listOf("203.0.113.53"), false),
    )

    private fun demoReport() = ScanReport(
        "192.168.0.1", 71,
        listOf(
            PortResult(22, PortState.OPEN, 4, "SSH-2.0-dropbear_2020.81"),
            PortResult(23, PortState.OPEN, 3, "(바이너리 응답 7바이트)"),
            PortResult(53, PortState.OPEN, 3),
            PortResult(80, PortState.OPEN, 5, "HTTP/1.1 401 Unauthorized · www-authenticate: Basic realm=\"iptime\" · Server: httpd"),
            PortResult(443, PortState.OPEN, 6),
            PortResult(8080, PortState.OPEN, 5, "HTTP/1.1 200 OK · Server: lighttpd/1.4.55"),
        ) + (1..55).map { PortResult(1000 + it, PortState.CLOSED, 1) } + (1..10).map { PortResult(2000 + it, PortState.NO_REPLY, 700) },
        false, 3400,
    )

    @Test fun netPort() = screen<NetworkActivity>("${tag}_net_port", 1100, mapOf("tool" to "port_scan")) { a -> a.rows = demoNets; a.showTool("port_scan") }
    @Test fun netPortResult() = screen<NetworkActivity>("${tag}_net_port_result", 2300, mapOf("tool" to "port_scan")) { a -> a.renderScan(demoReport(), IpKind.PRIVATE) }
    @Test fun netPortClean() = screen<NetworkActivity>("${tag}_net_port_clean", 900, mapOf("tool" to "port_scan")) { a ->
        a.renderScan(ScanReport("93.184.216.34", 71, (1..71).map { PortResult(it, PortState.NO_REPLY, 1500) }, false, 28000), IpKind.PUBLIC)
    }
    @Test fun netLan() = screen<NetworkActivity>("${tag}_net_lan", 1500, mapOf("tool" to "lan_scan")) { a ->
        a.rows = demoNets; a.showTool("lan_scan")
        a.renderHosts(
            listOf(
                LanHost("192.168.0.1", "iptime", 3, listOf(53, 80, 443), "핑 응답"),
                LanHost("192.168.0.5", "Galaxy-Tab-S9", 12, emptyList(), "연결 거부 응답"),
                LanHost("192.168.0.8", null, 20, listOf(554, 80), "포트 80 응답"),
                LanHost("192.168.0.20", "Living-Room-TV", 9, listOf(8008, 8009), "핑 응답"),
                LanHost("192.168.0.31", null, 41, listOf(9100), "포트 9100 응답"),
                LanHost("192.168.0.44", "iPhone", 7, listOf(62078), "핑 응답"),
            ), "192.168.0.12", "192.168.0.1",
        )
    }
    @Test fun netLanNoWifi() = screen<NetworkActivity>("${tag}_net_lan_nowifi", 700, mapOf("tool" to "lan_scan")) { a -> a.rows = emptyList(); a.showTool("lan_scan") }
    @Test fun netMyIp() = screen<NetworkActivity>("${tag}_net_myip", 1900, mapOf("tool" to "my_ip")) { a ->
        NetworkActivity.myPublicIp = "211.234.100.17"
        a.renderMyIp(demoNets, listOf(IfaceInfo("wlan0", "Wi-Fi", listOf("192.168.0.12/24")), IfaceInfo("rmnet_data1", "모바일 데이터", listOf("10.121.43.7/28")), IfaceInfo("lo", "루프백", listOf("127.0.0.1/8"))))
        NetworkActivity.myPublicIp = null
    }
    @Test fun netDns() = screen<NetworkActivity>("${tag}_net_dns", 1300, mapOf("tool" to "dns")) { a ->
        a.renderDns("example.com", listOf(addr("93.184.216.34"), addr("2606:2800:21f:cb07:6820:80da:af6b:8b2c")), listOf(null, null), 87, false)
    }
    @Test fun netIpInfo() = screen<NetworkActivity>("${tag}_net_ipinfo", 1300, mapOf("tool" to "ip_info")) { a -> a.showIpInfo("192.168.0.77/24") }
    @Test fun netIpInfoAddr() = screen<NetworkActivity>("${tag}_net_ipinfo_addr", 1300, mapOf("tool" to "ip_info")) { a -> a.showIpInfo("100.64.1.5") }

    // ---- 네트워크 도구 170여 가지의 공통 실행 화면 (오프라인 도구는 진짜로 실행, 인터넷 도구는 꾸민 결과를 그려서 모양만 확인)
    @Test fun ntSubnet() = screen<NetToolActivity>("${tag}_nt_subnet", 1900, mapOf("tool" to "subnet_calc"))
    @Test fun ntCidrMerge() = screen<NetToolActivity>("${tag}_nt_cidr_merge", 1500, mapOf("tool" to "cidr_merge"))
    @Test fun ntRefPorts() = screen<NetToolActivity>("${tag}_nt_ref_ports", 1500, mapOf("tool" to "ref_ports"))
    @Test fun ntFirewall() = screen<NetToolActivity>("${tag}_nt_firewall", 1700, mapOf("tool" to "fw_iptables"))
    @Test fun ntJwt() = screen<NetToolActivity>("${tag}_nt_jwt", 1500, mapOf("tool" to "jwt_decode"))
    @Test fun ntPingStats() = screen<NetToolActivity>("${tag}_nt_ping_stats", 1500, mapOf("tool" to "ping_stats"))
    /** 인터넷 도구를 연 첫 모습: 안내(무엇을 보내는지), 입력 칸, 실행 버튼 */
    @Test fun ntOnlineIdle() = screen<NetToolActivity>("${tag}_nt_online_idle", 1100, mapOf("tool" to "dns_mail"))
    @Test fun ntPortCheckIdle() = screen<NetToolActivity>("${tag}_nt_portcheck_idle", 1200, mapOf("tool" to "port_check"))

    @Test fun ntDiagResult() = screen<NetToolActivity>("${tag}_nt_diag_result", 1700, mapOf("tool" to "internet_check")) { a ->
        a.render(result {
            header("단계", "결과", "내용")
            row("1. 네트워크 연결", "정상", "Wi-Fi · 안드로이드의 인터넷 확인: 예", level = -1)
            row("2. 공유기(192.168.0.1) 응답", "정상", "공유기가 응답해요", level = -1)
            row("3. 내 DNS 로 도메인 찾기", "문제", "도메인을 찾지 못했어요 (DNS 설정 문제일 수 있어요)", level = 2)
            row("4. 구글 DNS(8.8.8.8) 직접 질문", "정상", "인터넷의 DNS 에 닿아요", level = -1)
            row("5. 인터넷 서버(1.1.1.1:443) 연결", "정상", "IP 로는 인터넷에 나가요", level = -1)
            row("6. HTTPS 웹 접속", "정상", "웹 접속이 돼요", level = -1)
            row("7. 로그인 화면(캡티브 포털)", "정상", "없어요", level = -1)
            head("진단")
            note("DNS 문제로 보여요. DNS 를 8.8.8.8 이나 1.1.1.1 로 바꿔 보세요 (설정 → Private DNS).", 2)
        })
    }

    @Test fun ntTlsResult() = screen<NetToolActivity>("${tag}_nt_tls_result", 2100, mapOf("tool" to "tls_cert")) { a ->
        a.render(result {
            kv("접속", "example.com:443  (96ms)"); kv("TLS 버전", "TLSv1.3", -1); kv("암호 스위트", "TLS_AES_256_GCM_SHA384")
            kv("신뢰 여부", "믿을 수 있어요", -1); kv("이름 일치", "접속한 주소와 일치", -1)
            head("서버 인증서")
            kv("주체(Subject)", "CN=example.com, O=Example Org, L=Los Angeles, C=US"); kv("발급자(Issuer)", "CN=DigiCert Global G2 TLS RSA SHA256 2020 CA1, O=DigiCert Inc, C=US")
            kv("유효 끝", "2027-01-15 23:59 UTC"); kv("남은 기간", "21일 남음", 1); kv("서명 알고리즘", "SHA256withRSA"); kv("공개키", "RSA 2048비트")
            kv("SHA-256 지문", "5A:3B:CC:19:0F:64:A2:7D:E1:88:30:4B:92:0C:7E:15:A9:D2:6F:03:B7:4E:1C:8A:55:F0:2D:9B:61:C4:3E:77")
            kv("대체 이름(SAN)", "example.com, www.example.com, *.example.org")
            head("인증서 사슬 (3장)"); kv("1", "CN=example.com"); kv("2", "CN=DigiCert Global G2 TLS RSA SHA256 2020 CA1"); kv("3", "CN=DigiCert Global Root G2")
        })
    }

    @Test fun ntTraceResult() = screen<NetToolActivity>("${tag}_nt_trace_result", 1500, mapOf("tool" to "traceroute")) { a ->
        a.render(result {
            kv("목적지", "www.google.com (142.250.196.196)"); kv("결과", "도착했어요 (9홉)", -1)
            header("홉", "주소", "시간", "이름")
            row("1", "192.168.0.1", "2 ms", "iptime")
            row("2", "10.20.0.1", "6 ms", "")
            row("3", "*", "응답 없음", "", level = 1)
            row("4", "112.188.10.9", "9 ms", "")
            row("5", "112.174.47.25", "11 ms", "")
            row("9", "142.250.196.196", "12 ms", "lax17s55-in-f4.1e100.net")
            note("'*' 는 그 장비가 응답하지 않는다는 뜻이에요(정상인 경우가 많아요). 중간 홉의 시간은 기기에서 ping 을 실행한 전체 소요라 대략적인 값이에요.")
        })
    }

    @Test fun ntSpeedResult() = screen<NetToolActivity>("${tag}_nt_speed_result", 1200, mapOf("tool" to "speed_test")) { a ->
        a.render(result {
            kv("응답 시간", "9.4 ms", -1); kv("내려받기", "412.7 Mbps  (51.6 MB/s)", -1); kv("올리기", "187.3 Mbps", -1); kv("사용한 데이터", "약 238 MB")
            note("Wi-Fi 와 서버 거리에 따라 달라지는 값이에요. 여러 번 재 보세요. 유선 연결이 가장 정확해요.")
        })
    }

    // ---- 새로 늘린 묶음(IP 위치·보안·로그·패킷·만들기·계산): 오프라인 도구를 기본 입력으로 진짜 실행한 결과를 그림
    private fun real(id: String, vararg kv: Pair<String, String>): ToolResult = runNetTool(id, *kv)
    @Test fun ntGeoCountry() = screen<NetToolActivity>("${tag}_nt_geo_country", 1500, mapOf("tool" to "geo_country")) { a -> a.render(real("geo_country", "ip" to "8.8.8.8")) }
    @Test fun ntSecCvss() = screen<NetToolActivity>("${tag}_nt_sec_cvss", 1700, mapOf("tool" to "sec_cvss"))
    @Test fun ntLogAccess() = screen<NetToolActivity>("${tag}_nt_log_access", 2600, mapOf("tool" to "log_access")) { a -> a.render(real("log_access")) }
    @Test fun ntPktDecode() = screen<NetToolActivity>("${tag}_nt_pkt_decode", 2600, mapOf("tool" to "pkt_decode")) { a -> a.render(real("pkt_decode")) }
    @Test fun ntMakeCron() = screen<NetToolActivity>("${tag}_nt_make_cron", 2100, mapOf("tool" to "make_cron")) { a -> a.render(real("make_cron", "from" to "2024-03-01 09:30")) }
    @Test fun ntMakeNft() = screen<NetToolActivity>("${tag}_nt_make_nft", 2300, mapOf("tool" to "make_nftables")) { a -> a.render(real("make_nftables")) }
    @Test fun ntPlanPoe() = screen<NetToolActivity>("${tag}_nt_plan_poe", 2100, mapOf("tool" to "calc_poe"))
    @Test fun ntPlanRaid() = screen<NetToolActivity>("${tag}_nt_plan_raid", 1900, mapOf("tool" to "calc_raid"))

    @Test fun ntUpnpResult() = screen<NetToolActivity>("${tag}_nt_upnp_result", 1500, mapOf("tool" to "upnp_find")) { a ->
        a.render(result {
            kv("찾은 기기", "4대 (서비스 11개)")
            header("IP", "이름 · 제조사 · 모델", "서버 정보")
            row("192.168.0.1", "ipTIME A3004NS-M · ipTIME · A3004NS-M", "Linux/3.10 UPnP/1.1 MiniUPnPd/2.1")
            row("192.168.0.20", "거실 TV · Samsung Electronics · UN55TU8000", "Linux/4.14 UPnP/1.0")
            row("192.168.0.31", "Brother HL-L2350DW · Brother · HL-L2350DW", "")
            row("192.168.0.44", "-", "Roku/9.4")
            note("공유기의 UPnP 가 켜져 있어요. 편리하지만 기기가 마음대로 포트를 열 수 있어서, 필요 없다면 공유기 설정에서 끄는 것이 안전해요.", 1)
        })
    }
}
