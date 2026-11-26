package com.selfcheck.app

import kotlin.math.abs
import kotlin.math.log10
import kotlin.math.pow
import kotlin.math.sqrt

/** 속도·용량 계산 12가지 + 무선(Wi-Fi) 계산 7가지 (모두 오프라인) */
object CalcTools {
    private const val S = NetGroups.SPEED
    private const val W = NetGroups.WIFI

    internal fun f1(x: Double) = "%.1f".format(x)
    internal fun f2(x: Double) = "%.2f".format(x)

    /** 초 → "1시간 2분 3초" */
    internal fun dur(sec: Double): String {
        if (sec.isNaN() || sec.isInfinite()) return "-"
        if (sec < 1) return "%.2f초".format(sec)
        if (sec < 60) return "%.1f초".format(sec)
        val s = Math.round(sec)
        val d = s / 86400; val h = s % 86400 / 3600; val m = s % 3600 / 60; val r = s % 60
        return buildString {
            if (d > 0) append("${d}일 "); if (h > 0) append("${h}시간 "); if (m > 0) append("${m}분 "); if (r > 0 || isEmpty()) append("${r}초")
        }.trim()
    }

    private val SIZE_UNITS = listOf("KB" to 1e3, "MB" to 1e6, "GB" to 1e9, "TB" to 1e12, "KiB" to 1024.0, "MiB" to 1048576.0, "GiB" to 1073741824.0)
    private val SPEED_UNITS = listOf("Kbps" to 1e3, "Mbps" to 1e6, "Gbps" to 1e9, "KB/s" to 8e3, "MB/s" to 8e6, "GB/s" to 8e9)
    private val TIME_UNITS = listOf("초" to 1.0, "분" to 60.0, "시간" to 3600.0)

    private val ACTIVITIES = listOf(
        "음악 (128 kbps)" to 0.128, "음악 고음질 (320 kbps)" to 0.32, "유튜브 480p" to 1.0, "유튜브 720p" to 2.5, "유튜브 1080p" to 5.0, "유튜브 4K" to 20.0,
        "넷플릭스 SD" to 3.0, "넷플릭스 HD" to 5.0, "넷플릭스 4K" to 15.0, "화상회의 720p" to 1.5, "화상회의 1080p" to 3.0,
        "음성 통화 (VoIP)" to 0.1, "온라인 게임" to 0.1, "웹서핑·SNS" to 1.0,
    )

    private val VIDEO = listOf("360p" to 1.0, "480p" to 2.5, "720p 30fps" to 5.0, "720p 60fps" to 7.5, "1080p 30fps" to 8.0, "1080p 60fps" to 12.0, "1440p 30fps" to 16.0, "4K 30fps" to 35.0, "4K 60fps" to 53.0)
    private val CODECS = listOf("H.264" to 1.0, "H.265 (HEVC)" to 0.6, "AV1" to 0.5)

    private val VOIP = listOf(
        Triple("G.711 (64 kbps)", 64.0, 20), Triple("G.722 (64 kbps)", 64.0, 20), Triple("G.729 (8 kbps)", 8.0, 20), Triple("Opus (24 kbps)", 24.0, 20), Triple("Opus (32 kbps)", 32.0, 20),
    )

    private val TUNNELS = listOf("없음" to 0, "PPPoE (8)" to 8, "WireGuard IPv4 (60)" to 60, "WireGuard IPv6 (80)" to 80, "GRE (24)" to 24, "VXLAN (50)" to 50, "IPsec ESP 터널 (약 58)" to 58)

    internal fun speedLabel(bps: Double) = when { bps >= 1e9 -> "${f2(bps / 1e9)} Gbps"; bps >= 1e6 -> "${f2(bps / 1e6)} Mbps"; else -> "${f2(bps / 1e3)} Kbps" }

    val ALL: List<NetTool> = listOf(
        calc("download_time", S, "다운로드·업로드 시간 계산", "파일 크기와 회선 속도로 걸리는 시간 (실제 효율 반영)",
            text("size", "파일 크기", "예: 4.7", "4.7"), choice("su", "크기 단위", SIZE_UNITS.map { it.first }, "GB"),
            text("speed", "속도", "예: 500", "500"), choice("pu", "속도 단위", SPEED_UNITS.map { it.first }, "Mbps"), text("eff", "실제 효율(%)", "보통 80~95", "90")) { i ->
            val size = i.double("size") ?: return@calc if (i.str("size").isEmpty()) need("파일 크기를 입력하세요") else fail("크기를 숫자로 입력하세요")
            val speed = i.double("speed") ?: return@calc if (i.str("speed").isEmpty()) need("속도를 입력하세요") else fail("속도를 숫자로 입력하세요")
            val eff = (i.double("eff") ?: 90.0).coerceIn(1.0, 100.0)
            if (size <= 0 || speed <= 0) return@calc fail("0보다 큰 값을 입력하세요")
            val bits = size * SIZE_UNITS.first { it.first == i.str("su") }.second * 8
            val bps = speed * SPEED_UNITS.first { it.first == i.str("pu") }.second
            val t = bits / (bps * eff / 100)
            result {
                kv("걸리는 시간", dur(t), -1); kv("초", f1(t)); kv("실제 속도", "${speedLabel(bps * eff / 100)} (회선 ${speedLabel(bps)}의 ${f1(eff)}%)")
                head("다른 속도라면")
                header("회선", "시간")
                for (v in listOf(10e6 to "10 Mbps", 100e6 to "100 Mbps", 500e6 to "500 Mbps", 1e9 to "1 Gbps", 2.5e9 to "2.5 Gbps")) row(v.second, dur(bits / (v.first * eff / 100)))
            }
        },

        calc("bandwidth_needed", S, "필요한 회선 속도 계산", "파일을 정해진 시간 안에 보내려면 얼마의 속도가 필요한지",
            text("size", "파일 크기", "예: 50", "50"), choice("su", "크기 단위", SIZE_UNITS.map { it.first }, "GB"),
            text("time", "허용 시간", "예: 30", "30"), choice("tu", "시간 단위", TIME_UNITS.map { it.first }, "분"), text("eff", "실제 효율(%)", "", "90")) { i ->
            val size = i.double("size") ?: return@calc if (i.str("size").isEmpty()) need("파일 크기를 입력하세요") else fail("크기를 숫자로 입력하세요")
            val time = i.double("time") ?: return@calc if (i.str("time").isEmpty()) need("시간을 입력하세요") else fail("시간을 숫자로 입력하세요")
            val eff = (i.double("eff") ?: 90.0).coerceIn(1.0, 100.0)
            if (size <= 0 || time <= 0) return@calc fail("0보다 큰 값을 입력하세요")
            val bits = size * SIZE_UNITS.first { it.first == i.str("su") }.second * 8
            val sec = time * TIME_UNITS.first { it.first == i.str("tu") }.second
            val need = bits / sec / (eff / 100)
            result { kv("필요한 속도", speedLabel(need), -1); kv("바이트 속도로", "${f2(need / 8e6)} MB/s"); note("실제 효율 ${f1(eff)}%를 반영했어요. Wi-Fi 는 표시 속도의 절반 이하가 나오는 경우도 많아요.") }
        },

        calc("data_usage", S, "데이터 사용량 예측", "영상·음악·화상회의를 얼마나 쓰면 데이터가 얼마나 드는지 (요금제 고를 때)",
            choice("act", "활동", ACTIVITIES.map { it.first }, "유튜브 1080p"), text("h", "하루 이용 시간(시간)", "예: 2", "2"), text("d", "한 달 일수", "", "30")) { i ->
            val h = i.double("h") ?: return@calc if (i.str("h").isEmpty()) need("시간을 입력하세요") else fail("시간을 숫자로 입력하세요")
            val d = (i.double("d") ?: 30.0).coerceAtLeast(1.0)
            val mbps = ACTIVITIES.first { it.first == i.str("act") }.second
            val gbPerHour = mbps * 3600 / 8 / 1000
            result {
                kv("가정한 속도", "$mbps Mbps"); kv("1시간", "${f2(gbPerHour)} GB"); kv("하루", "${f2(gbPerHour * h)} GB"); kv("한 달", "${f1(gbPerHour * h * d)} GB", -1)
                note("권장 속도 기준의 최대치 어림이에요. 실제로는 화질 자동 조절 때문에 더 적게 쓰는 경우가 많아요.")
            }
        },

        calc("bdp", S, "대역폭-지연 곱 (BDP)", "회선을 꽉 채우려면 TCP 가 한 번에 띄워 둬야 하는 데이터 양과 윈도 크기",
            text("bw", "대역폭(Mbps)", "예: 1000", "1000"), text("rtt", "왕복 지연 RTT(ms)", "예: 40", "40")) { i ->
            val bw = i.double("bw") ?: return@calc if (i.str("bw").isEmpty()) need("대역폭을 입력하세요") else fail("숫자로 입력하세요")
            val rtt = i.double("rtt") ?: return@calc if (i.str("rtt").isEmpty()) need("RTT 를 입력하세요") else fail("숫자로 입력하세요")
            if (bw <= 0 || rtt <= 0) return@calc fail("0보다 큰 값을 입력하세요")
            val bytes = bw * 1e6 / 8 * rtt / 1000
            val noScale = 65535 * 8 / (rtt / 1000) / 1e6
            result {
                kv("BDP", "${"%,.0f".format(bytes)}바이트 (${f1(bytes / 1024)} KiB)", -1)
                kv("필요한 TCP 윈도", "약 ${f1(bytes / 1024)} KiB 이상")
                kv("윈도 스케일 없이 최대 속도", "${f2(noScale)} Mbps (윈도 64KiB 한계)", if (noScale < bw) 1 else 0)
                note("지연이 길수록(위성·해외 서버) 한 번에 띄울 데이터가 많아야 해요. 요즘 운영체제는 윈도 스케일을 자동으로 켜요.")
            }
        },

        calc("tcp_throughput", S, "TCP 최대 처리량 (손실 영향)", "RTT 와 패킷 손실률로 TCP 속도의 이론 한계 (Mathis 식)",
            text("mss", "MSS(바이트)", "", "1460"), text("rtt", "RTT(ms)", "예: 30", "30"), text("loss", "패킷 손실률(%)", "예: 0.1", "0.1"), text("link", "회선 속도(Mbps, 선택)", "예: 500", "500")) { i ->
            val mss = i.double("mss") ?: 1460.0; val rtt = i.double("rtt") ?: return@calc need("RTT 를 입력하세요"); val loss = i.double("loss") ?: return@calc need("손실률을 입력하세요")
            if (rtt <= 0 || loss <= 0) return@calc fail("RTT 와 손실률은 0보다 커야 해요 (손실이 0이면 회선 속도가 한계예요)")
            val bps = mss * 8 / (rtt / 1000) * (1.22 / sqrt(loss / 100))
            val link = i.double("link")
            result {
                kv("이론 최대 처리량", speedLabel(bps), -1)
                if (link != null && link > 0) kv("회선 속도 대비", "${f1(minOf(100.0, bps / (link * 1e6) * 100))}%", if (bps < link * 1e6) 1 else -1)
                note("손실이 조금만 있어도 지연이 긴 구간에서는 TCP 속도가 크게 떨어져요. 손실 0.1%, RTT 30ms 면 약 15 Mbps 가 한계예요.")
            }
        },

        calc("mtu_mss", S, "MTU·MSS 계산", "터널(VPN·PPPoE)을 쓰면 MTU 가 얼마로 줄고 MSS 와 효율이 어떻게 되는지",
            text("mtu", "회선 MTU", "", "1500"), choice("ip", "IP 버전", listOf("IPv4", "IPv6")), choice("tun", "터널·캡슐화", TUNNELS.map { it.first }), choice("ts", "TCP 타임스탬프", listOf("끔", "켬 (12바이트)"))) { i ->
            val mtu = i.int("mtu")?.takeIf { it in 576..9216 } ?: return@calc if (i.str("mtu").isEmpty()) need("MTU 를 입력하세요") else fail("MTU 는 576~9216 사이예요")
            val v6 = i.str("ip") == "IPv6"; val over = TUNNELS.first { it.first == i.str("tun") }.second; val opt = if (i.str("ts") == "켬 (12바이트)") 12 else 0
            val eff = mtu - over; val mss = eff - (if (v6) 40 else 20) - 20 - opt
            if (mss < 1) return@calc fail("MTU 가 너무 작아요")
            val wire = mtu + 38
            result {
                kv("실제 MTU", "$eff", if (over > 0) 1 else 0); kv("TCP MSS", "$mss", -1); kv("IP 헤더", "${if (v6) 40 else 20}바이트"); kv("TCP 헤더", "${20 + opt}바이트")
                kv("TCP 효율(이더넷 기준)", "${f1(mss * 100.0 / wire)}%"); kv("1Gbps 에서 최대 TCP 속도", "${"%.0f".format(1000 * mss / wire.toDouble())} Mbps")
                note("이더넷은 프레임마다 38바이트(프리앰블·헤더·FCS·프레임 간격)가 더 들어요. MTU 가 맞지 않으면 큰 파일 전송이 멈추거나 느려질 수 있어요(MTU 블랙홀) — VPN 에서는 MSS 를 ${mss} 로 줄여 보세요.")
            }
        },

        calc("uptime_sla", S, "가동률(SLA) ↔ 허용 다운타임", "99.9% 가 일 년에 얼마나 멈춰도 되는 건지",
            text("p", "가동률(%)", "예: 99.9", "99.9", listOf("99%" to "99", "99.9%" to "99.9", "99.99%" to "99.99", "99.999%" to "99.999"))) { i ->
            val p = i.double("p")?.takeIf { it in 0.0..100.0 } ?: return@calc if (i.str("p").isEmpty()) need("가동률을 입력하세요") else fail("0~100 사이 숫자로 입력하세요")
            val down = 1 - p / 100
            result {
                header("기간", "허용 다운타임")
                row("1년", dur(down * 365 * 86400)); row("1개월(30일)", dur(down * 30 * 86400)); row("1주", dur(down * 7 * 86400)); row("1일", dur(down * 86400))
                head("자주 쓰는 등급")
                header("가동률", "1년 다운타임", "1개월")
                for (x in listOf(99.0, 99.9, 99.95, 99.99, 99.999)) row("$x%", dur((1 - x / 100) * 365 * 86400), dur((1 - x / 100) * 30 * 86400))
            }
        },

        calc("voip_bandwidth", S, "VoIP(인터넷 전화) 대역폭", "동시 통화 수와 코덱으로 필요한 회선 속도",
            choice("codec", "코덱", VOIP.map { it.first }), text("n", "동시 통화 수", "예: 20", "20"), choice("eth", "이더넷 헤더 포함", listOf("포함 (18바이트)", "미포함"))) { i ->
            val n = i.int("n")?.takeIf { it in 1..100000 } ?: return@calc if (i.str("n").isEmpty()) need("통화 수를 입력하세요") else fail("1 이상의 정수를 입력하세요")
            val (_, rate, ptime) = VOIP.first { it.first == i.str("codec") }
            val pps = 1000.0 / ptime; val payload = rate * ptime / 8
            val overhead = 40 + if (i.str("eth").startsWith("포함")) 18 else 0
            val perCall = (payload + overhead) * 8 * pps / 1000
            result {
                kv("패킷", "${ptime}ms 마다 1개 (초당 ${pps.toInt()}개), 음성 ${f1(payload)}바이트 + 헤더 ${overhead}바이트")
                kv("통화 1개(한 방향)", "${f1(perCall)} kbps"); kv("통화 1개(양방향)", "${f1(perCall * 2)} kbps")
                kv("${n}통화 한 방향", "${f2(perCall * n / 1000)} Mbps", -1); kv("${n}통화 양방향", "${f2(perCall * 2 * n / 1000)} Mbps")
                note("IP·UDP·RTP 헤더 40바이트가 음성 자체보다 클 수 있어서 코덱 속도보다 훨씬 더 필요해요.")
            }
        },

        calc("latency_distance", S, "지연 시간 ↔ 거리 (빛의 속도 한계)", "광섬유에서 신호는 초속 약 20만 km — RTT 로 가능한 최대 거리, 거리로 가능한 최소 RTT",
            text("rtt", "RTT(ms) → 최대 거리", "예: 10", "10"), text("km", "거리(km) → 최소 RTT", "예: 9000 (서울~미국 서부)", "9000")) { i ->
            val rtt = i.double("rtt"); val km = i.double("km")
            if (rtt == null && km == null) return@calc need("RTT 나 거리를 입력하세요")
            result {
                if (rtt != null && rtt > 0) kv("RTT ${f1(rtt)}ms 면", "서버까지 직선 거리가 최대 약 ${"%,.0f".format(rtt * 100)}km 예요 (신호가 갔다 오는 시간의 절반 × 초속 20만 km)", -1)
                if (km != null && km > 0) kv("${"%,.0f".format(km)}km 거리면", "왕복 RTT 가 최소 약 ${f1(km / 100)}ms (광섬유 직선 기준, 실제는 경로가 구불구불해 1.5~2배)", -1)
                note("빛은 진공에서 초속 30만 km, 광섬유에서는 약 2/3 속도예요. 여기에 라우터 처리·돌아가는 경로 때문에 실제 RTT 는 이보다 길어요.")
            }
        },

        calc("ping_stats", S, "핑 결과 통계", "ping 출력을 붙여 넣으면 최소·평균·최대·지터·손실을 계산 (윈도·리눅스·맥, 한글 윈도 OK)",
            multi("t", "ping 결과", "ping 출력 전체", "64 bytes from 8.8.8.8: icmp_seq=1 ttl=117 time=23.4 ms\n64 bytes from 8.8.8.8: icmp_seq=2 ttl=117 time=24.1 ms\n64 bytes from 8.8.8.8: icmp_seq=3 ttl=117 time=22.9 ms\n64 bytes from 8.8.8.8: icmp_seq=4 ttl=117 time=25.2 ms\n64 bytes from 8.8.8.8: icmp_seq=5 ttl=117 time=24.0 ms",
                listOf("손실 있는 예" to "64 bytes from 8.8.8.8: icmp_seq=1 ttl=117 time=23.4 ms\nRequest timeout for icmp_seq 2\n64 bytes from 8.8.8.8: icmp_seq=3 ttl=117 time=95.0 ms\nRequest timeout for icmp_seq 4\n64 bytes from 8.8.8.8: icmp_seq=5 ttl=117 time=22.9 ms",
                    "윈도(한글) 예" to "8.8.8.8의 응답: 바이트=32 시간=23ms TTL=117\n8.8.8.8의 응답: 바이트=32 시간=24ms TTL=117\n요청 시간이 만료되었습니다.\n8.8.8.8의 응답: 바이트=32 시간=25ms TTL=117"))) { i ->
            val s = i.raw("t"); if (s.isBlank()) return@calc need("ping 결과를 붙여 넣으세요")
            val times = Regex("""(?:time|시간)\s*[=<]\s*([\d.]+)\s*ms""", RegexOption.IGNORE_CASE).findAll(s).mapNotNull { it.groupValues[1].toDoubleOrNull() }.toList()
            val lost = s.lines().count { Regex("""(?i)timed out|request timeout|요청 시간이 만료|unreachable|연결할 수 없|100% packet loss""").containsMatchIn(it) }
            if (times.isEmpty()) return@calc fail("시간 값(time=23.4 ms 또는 시간=23ms)을 찾지 못했어요")
            val st = PingStats.of(times, lost)
            result {
                kv("보낸 횟수", "${st.sent}"); kv("받은 횟수", "${st.received}"); kv("손실", "${f1(st.lossPercent)}%", if (st.lossPercent > 2) 2 else if (st.lossPercent > 0) 1 else -1)
                kv("최소", "${f1(st.min)} ms"); kv("평균", "${f1(st.avg)} ms"); kv("중앙값", "${f1(st.median)} ms"); kv("최대", "${f1(st.max)} ms"); kv("지터(연속 차이 평균)", "${f1(st.jitter)} ms", if (st.jitter > 30) 1 else 0)
                note(st.verdict(), if (st.lossPercent > 2 || st.avg > 150) 2 else if (st.lossPercent > 0 || st.jitter > 30 || st.avg > 80) 1 else -1)
            }
        },

        calc("video_bitrate", S, "영상 권장 비트레이트·업로드 속도", "라이브 방송·화상회의에 필요한 비트레이트와 업로드 속도(대략)",
            choice("res", "해상도", VIDEO.map { it.first }, "1080p 30fps"), choice("codec", "코덱", CODECS.map { it.first })) { i ->
            val base = VIDEO.first { it.first == i.str("res") }.second; val f = CODECS.first { it.first == i.str("codec") }.second
            val mbps = base * f
            result {
                kv("권장 비트레이트", "${f1(mbps)} Mbps", -1); kv("필요한 업로드 속도", "${f1(mbps * 1.5)} Mbps 이상 (여유 50%)"); kv("1시간 용량", "${f2(mbps * 3600 / 8 / 1000)} GB")
                note("유튜브 권장 업로드 비트레이트를 바탕으로 한 대략값이에요. 움직임이 많은 영상은 더 필요하고, H.265·AV1 은 같은 화질을 더 적은 데이터로 내요(방송 플랫폼이 지원해야 해요).")
            }
        },

        calc("link_util", S, "회선 사용률 계산", "쓰는 대역폭 ÷ 회선 용량 (여유가 있는지)",
            text("used", "사용 중(Mbps)", "예: 420", "420"), text("cap", "회선 용량(Mbps)", "예: 500", "500")) { i ->
            val u = i.double("used") ?: return@calc need("사용 중인 속도를 입력하세요"); val c = i.double("cap") ?: return@calc need("회선 용량을 입력하세요")
            if (c <= 0 || u < 0) return@calc fail("회선 용량은 0보다 커야 해요")
            val p = u / c * 100
            result {
                kv("사용률", "${f1(p)}%", if (p >= 90) 2 else if (p >= 70) 1 else -1); kv("남은 여유", "${f1(c - u)} Mbps")
                note(when { p >= 90 -> "거의 가득 찼어요. 지연·끊김이 생기기 쉬워요. 회선 증설이나 트래픽 정리를 고려하세요."; p >= 70 -> "여유가 크지 않아요. 순간 사용량(피크)을 확인해 보세요."; else -> "여유가 충분해요." }, if (p >= 90) 2 else if (p >= 70) 1 else -1)
            }
        },

        // ------------------------------------------------------------ 무선(Wi-Fi) 계산
        calc("dbm_mw", W, "dBm ↔ mW ↔ W 변환", "무선 출력·신호 세기 단위 변환",
            text("v", "값", "예: 20", "20"), choice("u", "단위", listOf("dBm", "mW", "W"))) { i ->
            val v = i.double("v") ?: return@calc if (i.str("v").isEmpty()) need("값을 입력하세요") else fail("숫자로 입력하세요")
            val mw = when (i.str("u")) { "dBm" -> 10.0.pow(v / 10); "W" -> v * 1000; else -> v }
            if (mw <= 0) return@calc fail("mW 와 W 는 0보다 커야 해요")
            result { kv("dBm", f2(10 * log10(mw))); kv("mW", if (mw < 0.001 || mw >= 1e6) "%.3e".format(mw) else "%.6f".format(mw).trimEnd('0').trimEnd('.')); kv("W", "%.6f".format(mw / 1000).trimEnd('0').trimEnd('.')); note("3 dB 가 늘면 출력은 약 2배, 10 dB 면 10배예요. 가정용 공유기 출력은 보통 20 dBm(100 mW) 안팎이에요.") }
        },

        calc("wifi_signal_quality", W, "Wi-Fi 신호 세기 해석", "-60 dBm 이면 좋은 건가? 신호 세기(dBm)를 품질로 풀이",
            text("dbm", "신호 세기(dBm)", "예: -62", "-62", listOf("-45" to "-45", "-60" to "-60", "-70" to "-70", "-80" to "-80"))) { i ->
            val d = i.double("dbm") ?: return@calc if (i.str("dbm").isEmpty()) need("dBm 값을 입력하세요 (보통 -30 ~ -90)") else fail("숫자로 입력하세요")
            if (d > 0 || d < -120) return@calc fail("Wi-Fi 신호는 보통 -30 ~ -90 dBm 이에요 (음수로 입력)")
            val (label, level, use) = when {
                d >= -50 -> Triple("매우 좋음", -1, "무엇이든 쾌적해요 (4K 스트리밍·게임)")
                d >= -60 -> Triple("좋음", -1, "대부분 문제없어요 (HD 영상·화상회의)")
                d >= -67 -> Triple("보통", 0, "영상·VoIP 가능, 속도 변동이 있을 수 있어요")
                d >= -70 -> Triple("약함", 1, "웹서핑 위주, 화상회의는 끊길 수 있어요")
                d >= -80 -> Triple("불안정", 1, "자주 끊기고 속도가 낮아요")
                else -> Triple("거의 안 됨", 2, "연결이 불안정해요. 공유기 가까이 가거나 중계기를 쓰세요")
            }
            result { kv("품질", label, level); kv("대략적인 막대 비율", "${(2 * (d + 100)).coerceIn(0.0, 100.0).toInt()}%"); kv("쓰임새", use); note("수치가 -30 에 가까울수록 강해요. 벽 하나에 보통 3~6 dB, 콘크리트·철근은 10 dB 이상 약해져요.") }
        },

        calc("fspl", W, "자유 공간 경로 손실 (FSPL)", "거리와 주파수로 신호가 얼마나 약해지는지, 받는 세기까지",
            text("d", "거리", "예: 30", "30"), choice("du", "거리 단위", listOf("m", "km")), text("f", "주파수", "예: 2.4", "2.4"), choice("fu", "주파수 단위", listOf("GHz", "MHz")),
            text("tx", "송신 출력(dBm, 선택)", "예: 20", "20"), text("g", "안테나 이득 합(dBi, 선택)", "예: 2", "2")) { i ->
            val d = i.double("d")?.takeIf { it > 0 } ?: return@calc need("거리를 입력하세요"); val f = i.double("f")?.takeIf { it > 0 } ?: return@calc need("주파수를 입력하세요")
            val km = if (i.str("du") == "m") d / 1000 else d; val mhz = if (i.str("fu") == "GHz") f * 1000 else f
            val loss = 20 * log10(km) + 20 * log10(mhz) + 32.44
            val tx = i.double("tx"); val g = i.double("g") ?: 0.0
            result {
                kv("경로 손실", "${f1(loss)} dB", -1)
                if (tx != null) kv("받는 세기(이론)", "${f1(tx + g - loss)} dBm")
                note("장애물 없는 직선 거리 기준의 이론값이에요. 거리가 2배가 되면 6 dB, 주파수가 2배가 되면 6 dB 더 약해져요. 실내에서는 벽·가구 때문에 훨씬 더 약해져요.")
            }
        },

        calc("wifi_range", W, "Wi-Fi 예상 도달 거리", "출력·주파수·벽 개수로 쓸 만한 신호가 닿는 거리를 대략 계산",
            text("tx", "공유기 출력(dBm)", "예: 20", "20"), text("g", "안테나 이득 합(dBi)", "예: 4", "4"), choice("band", "주파수", listOf("2.4 GHz", "5 GHz", "6 GHz"), "5 GHz"),
            text("walls", "벽 개수", "예: 2", "2"), text("need", "필요한 최소 신호(dBm)", "영상 -67, 웹 -70", "-67")) { i ->
            val tx = i.double("tx") ?: return@calc need("출력을 입력하세요"); val g = i.double("g") ?: 0.0; val walls = (i.double("walls") ?: 0.0).coerceAtLeast(0.0); val need = i.double("need") ?: -67.0
            val (mhz, wall) = when (i.str("band")) { "2.4 GHz" -> 2437.0 to 5.0; "6 GHz" -> 6175.0 to 8.0; else -> 5500.0 to 7.0 }
            val budget = tx + g - walls * wall - need
            val km = 10.0.pow((budget - 32.44 - 20 * log10(mhz)) / 20)
            result {
                kv("허용 손실", "${f1(budget)} dB (벽 ${walls.toInt()}개 × ${wall.toInt()} dB 반영)"); kv("이론상 도달 거리", if (km < 1) "${"%,.0f".format(km * 1000)} m" else "${f1(km)} km", -1)
                kv("실내 현실적 거리", "약 ${"%,.0f".format((km * 1000 * 0.3).coerceAtLeast(1.0))} m (이론값의 30% 가정)")
                note("벽 하나당 손실은 주파수별 평균값을 썼어요(2.4GHz 5dB, 5GHz 7dB, 6GHz 8dB). 5·6 GHz 는 빠르지만 벽에 더 약하고, 2.4 GHz 는 멀리 가지만 느리고 혼잡해요.")
            }
        },

        calc("wifi_channels", W, "Wi-Fi 채널 표", "채널 ↔ 중심 주파수와 겹치지 않는 채널 고르는 법",
            choice("band", "주파수", listOf("2.4 GHz", "5 GHz", "6 GHz"))) { i ->
            result {
                when (i.str("band")) {
                    "2.4 GHz" -> {
                        header("채널", "중심 주파수", "비고")
                        for (c in 1..13) row("$c", "${2407 + 5 * c} MHz", if (c in listOf(1, 6, 11)) "겹치지 않는 추천(20MHz)" else if (c == 13) "한국·유럽 사용" else "")
                        note("2.4 GHz 는 채널이 22 MHz 폭이라 1·6·11 번(또는 1·5·9·13)만 서로 겹치지 않아요. 한국은 1~13 채널을 써요. 공유기가 많은 곳에서는 가장 한가한 채널을 골라 보세요.")
                    }
                    "5 GHz" -> {
                        header("채널", "중심 주파수", "구간")
                        for (c in listOf(36, 40, 44, 48)) row("$c", "${5000 + 5 * c} MHz", "UNII-1")
                        for (c in listOf(52, 56, 60, 64)) row("$c", "${5000 + 5 * c} MHz", "UNII-2A (DFS)")
                        for (c in listOf(100, 104, 108, 112, 116, 120, 124, 128, 132, 136, 140)) row("$c", "${5000 + 5 * c} MHz", "UNII-2C (DFS)")
                        for (c in listOf(149, 153, 157, 161, 165)) row("$c", "${5000 + 5 * c} MHz", "UNII-3")
                        note("5 GHz 채널은 20 MHz 간격이라 겹침이 거의 없어요(80 MHz 폭이면 4개 채널을 묶어 써요). DFS 채널은 레이더가 감지되면 채널을 옮겨서 잠깐 끊길 수 있고, 일부 채널은 나라·기기마다 못 쓸 수 있어요.")
                    }
                    else -> {
                        header("채널", "중심 주파수")
                        for (c in listOf(1, 5, 9, 13, 17, 21, 25, 29, 33, 37, 41, 45, 49, 53, 57, 61, 65, 69, 73, 77, 81, 85, 89, 93)) row("$c", "${5950 + 5 * c} MHz")
                        note("6 GHz(Wi-Fi 6E·7)는 채널이 많고 간섭이 적지만 벽에 약해요. 쓸 수 있는 범위는 나라·시기마다 달라서 사용 전에 규정과 기기 설명서를 확인하세요.")
                    }
                }
            }
        },

        calc("channel_freq", W, "Wi-Fi 채널 ↔ 주파수 변환", "채널 번호를 주파수로, 주파수를 채널 번호로",
            choice("band", "대역", listOf("2.4 GHz", "5 GHz", "6 GHz"), "5 GHz"), text("v", "채널 번호 또는 주파수(MHz)", "예: 36 또는 5180", "36")) { i ->
            val v = i.int("v") ?: return@calc if (i.str("v").isEmpty()) need("값을 입력하세요") else fail("정수로 입력하세요")
            val band = i.str("band")
            result {
                if (v >= 1000) {
                    val ch = WifiChan.fromFreq(v)
                    if (ch == null) note("해당하는 Wi-Fi 채널이 없어요 (2412~7115 MHz 범위)", 2) else { kv("주파수", "$v MHz"); kv("채널", "${ch.first}"); kv("대역", ch.second, -1) }
                } else {
                    val f = WifiChan.toFreq(band, v)
                    if (f == null) note("$band 에는 ${v}번 채널이 없어요", 2) else { kv("대역", band); kv("채널", "$v"); kv("중심 주파수", "$f MHz", -1) }
                }
            }
        },

        calc("snr", W, "신호 대 잡음비(SNR) 해석", "신호 세기와 잡음 세기로 연결 품질을 가늠",
            text("sig", "신호(dBm)", "예: -60", "-60"), text("noise", "잡음 바닥(dBm)", "예: -92", "-92")) { i ->
            val s = i.double("sig") ?: return@calc need("신호 세기를 입력하세요"); val n = i.double("noise") ?: return@calc need("잡음 세기를 입력하세요")
            val snr = s - n
            val (q, level) = when { snr >= 40 -> "매우 좋음 (최고 속도)" to -1; snr >= 25 -> "좋음 (고속 연결 가능)" to -1; snr >= 15 -> "보통 (중간 속도)" to 0; snr >= 10 -> "약함 (낮은 속도·재전송 많음)" to 1; else -> "나쁨 (끊김)" to 2 }
            result { kv("SNR", "${f1(snr)} dB", level); kv("품질", q, level); note("SNR 이 높을수록 더 빠른 변조 방식을 써서 속도가 빨라져요. 신호가 세도 잡음(주변 공유기·전자레인지)이 크면 SNR 이 낮아요.") }
        },
    )
}

/** 핑 통계 */
class PingStats(val sent: Int, val received: Int, val min: Double, val avg: Double, val median: Double, val max: Double, val jitter: Double) {
    val lossPercent: Double get() = if (sent == 0) 0.0 else (sent - received) * 100.0 / sent

    fun verdict(): String = when {
        lossPercent > 2 -> "패킷 손실이 있어요. 무선 신호·회선 상태·공유기 부하를 점검해 보세요."
        avg > 150 -> "응답이 매우 느려요 (평균 ${CalcTools.f1(avg)}ms). 해외 서버거나 회선이 혼잡할 수 있어요."
        jitter > 30 -> "응답 시간이 들쭉날쭉해요 (지터 ${CalcTools.f1(jitter)}ms). 실시간 게임·화상회의가 끊길 수 있어요."
        avg > 80 -> "조금 느려요. 일반 사용에는 문제없지만 실시간 게임에는 불리해요."
        else -> "상태가 좋아요."
    }

    companion object {
        fun of(times: List<Double>, lost: Int): PingStats {
            val s = times.sorted()
            val med = if (s.size % 2 == 1) s[s.size / 2] else (s[s.size / 2 - 1] + s[s.size / 2]) / 2
            val jit = if (times.size < 2) 0.0 else times.zipWithNext { a, b -> abs(b - a) }.average()
            return PingStats(times.size + lost, times.size, s.first(), times.average(), med, s.last(), jit)
        }
    }
}

object WifiChan {
    /** 주파수(MHz) → (채널, 대역). 해당 없으면 null */
    fun fromFreq(mhz: Int): Pair<Int, String>? = when {
        mhz == 2484 -> 14 to "2.4 GHz"
        mhz in 2412..2472 && (mhz - 2407) % 5 == 0 -> (mhz - 2407) / 5 to "2.4 GHz"
        mhz in 5170..5895 && mhz % 5 == 0 -> (mhz - 5000) / 5 to "5 GHz"
        mhz in 5955..7115 && (mhz - 5950) % 5 == 0 -> (mhz - 5950) / 5 to "6 GHz"
        else -> null
    }

    fun toFreq(band: String, ch: Int): Int? = when (band) {
        "2.4 GHz" -> if (ch in 1..13) 2407 + 5 * ch else if (ch == 14) 2484 else null
        "5 GHz" -> if (ch in 32..177) 5000 + 5 * ch else null
        "6 GHz" -> if (ch in 1..233) 5950 + 5 * ch else null
        else -> null
    }
}
