package com.selfcheck.app

import java.security.SecureRandom
import java.time.LocalDate
import java.time.LocalDateTime
import java.time.LocalTime
import java.time.ZoneId
import java.time.ZonedDateTime
import java.time.format.DateTimeFormatter
import java.util.Base64

/**
 * 키·주소·설정 만들기 도구 14가지: 실제 키 만들기(WireGuard X25519 · SSH Ed25519), cron 해석, IPv6 ULA, Wi-Fi PSK, OpenSSL 명령,
 * tc 지연·손실 흉내, nftables 방화벽, systemd·netplan·chrony·fail2ban·HAProxy·sshd 설정.
 * 모두 폰 안에서 만들고 어디로도 보내지 않아요. 만든 설정은 실제 검증 도구(nft -c · sshd -t · haproxy -c 등)로 시험했어요.
 */
object MakeTools {
    private const val G = NetGroups.MAKE
    private const val LOCAL = "입력한 값은 휴대폰 안에서만 처리하고 어디로도 보내지 않아요."
    private val rnd = SecureRandom()

    private fun list(s: String, seps: String = ",;\n "): List<String> = s.split(*seps.toCharArray()).map { it.trim() }.filter { it.isNotEmpty() }
    private fun b64(b: ByteArray) = Base64.getEncoder().encodeToString(b)
    /** 비어 있으면 기본값, 숫자가 아니면 null (조용히 기본값으로 바뀌지 않게) */
    private fun ToolInput.intOr(k: String, default: Int): Int? = str(k).let { if (it.isEmpty()) default else it.toIntOrNull() }

    private fun lineList(s: String): List<String> = s.lines().map { it.trim() }.filter { it.isNotEmpty() }

    /** "host:port" 또는 "[ipv6]:port" */
    private fun hostPort(s: String): Pair<String, Int>? {
        val t = s.trim()
        if (t.startsWith("[")) { val e = t.indexOf("]:"); if (e < 0) return null; val ip = IpUtil.parse(t.substring(1, e)) ?: return null; return ("[" + IpUtil.format(ip) + "]") to (Valid.port(t.substring(e + 2)) ?: return null) }
        val i = t.lastIndexOf(':'); if (i <= 0 || t.count { it == ':' } != 1) return null
        return (Valid.ipOrHost(t.substring(0, i)) ?: return null) to (Valid.port(t.substring(i + 1)) ?: return null)
    }

    /** "example.com" · "example.com:8443" · "[2001:db8::1]:443" · "2001:db8::1" → "호스트:포트" (IPv6 는 대괄호). 틀리면 null */
    private fun sslTarget(s: String): String? {
        hostPort(s)?.let { return "${it.first}:${it.second}" }
        val h = Valid.ipOrHost(s) ?: return null
        return (if (h.contains(':')) "[$h]" else h) + ":443"
    }

    private val ZONES = listOf("UTC", "Asia/Seoul", "Asia/Tokyo", "America/New_York", "America/Los_Angeles", "Europe/London", "Europe/Berlin", "Australia/Sydney")
    private val ROUTE = listOf("VPN 안쪽 대역만", "전부 (인터넷 포함)")
    private val PSK_USE = listOf("사용", "사용 안 함")
    private val ULA_MODES = listOf("RFC 4193 방식 (시각 + MAC 의 SHA-1)", "무작위 40비트")
    private val WPA_SEC = listOf("WPA2-PSK (WPA2 개인)", "WPA3-SAE", "WPA2/WPA3 혼합")
    private val WPA_TARGET = listOf("접속하는 쪽 (wpa_supplicant.conf)", "공유기·AP (hostapd.conf)")
    private val NO_YES = listOf("아니오", "예")
    private val BAND = listOf("2.4GHz", "5GHz")
    private val NETEM_DIST = listOf("정규(normal)", "균등(uniform)", "파레토(pareto)", "지정 안 함")
    private val ICMP_OPT = listOf("허용 (속도 제한)", "막기")
    private val LOG_OPT = listOf("남기지 않음", "남김 (분당 5개)")
    private val RESTART = listOf("on-failure", "always", "no")
    private val HARDEN = listOf("없음", "기본 (NoNewPrivileges·PrivateTmp·ProtectSystem=full)", "강하게 (홈·커널·제어 그룹 보호, /var/lib/이름 만 쓰기)")
    private val YES_NO = listOf("예", "아니오")
    private val TIMER = listOf("없음 (계속 실행되는 서비스)", "매일 정해진 시각", "N분마다 (부팅 5분 뒤부터)", "OnCalendar 직접 입력")
    private val NETPLAN_MODES = listOf("DHCP (자동으로 받기)", "고정 IP", "브리지", "VLAN", "본딩 (active-backup)")
    private val NTS = listOf("사용 안 함", "사용 (NTS 를 지원하는 서버만)")
    private val LOCAL_CLOCK = listOf("아니오", "예 (local stratum 10)")
    private val F2B_ACT = listOf("nftables-multiport", "iptables-multiport", "ufw", "(기본값 사용)")
    private val F2B_SSHBK = listOf("systemd 저널 (최신 배포판)", "로그 파일 (/var/log/auth.log)")
    private val F2B_INC = listOf("예 (2배씩, 최대 5주)", "아니오")
    private val HA_MODE = listOf("HTTP (웹)", "TCP (그 밖의 서비스)")
    private val HA_BAL = listOf("roundrobin", "leastconn", "source")
    private val HA_USER = listOf("예 (패키지 기본)", "아니오")
    private val SSHD_ROOT = listOf("no (완전히 막기)", "prohibit-password (키로만 허용)")
    private val SSHD_PW = listOf("끄기 (공개키만)", "켜기")
    private val ALLOW = listOf("막기", "허용")
    private val SSHD_CRYPTO = listOf("최신 알고리즘만", "기본값 유지")
    private val SSL_OPS = listOf("자체 서명 인증서 + 키 (SAN 포함)", "키 + CSR(서명 요청, SAN 포함)", "인증서 + 키 → PFX(PKCS#12)", "PFX → PEM(키·인증서 분리)", "인증서 내용·만료일·지문 보기", "서버가 주는 인증서 확인 (접속함)", "인증서와 개인키가 짝인지 확인", "인증서 체인 검증", "무작위 비밀번호·키")
    private val WG_MODES = listOf("새 키 쌍 만들고 서버·클라이언트 설정까지", "비밀키로 공개키 계산", "사전 공유키(PSK)만 만들기")

    val ALL: List<NetTool> = listOf(
        // 1
        tool("make_wg_keys", G, "WireGuard 키 만들기 (키 쌍·사전 공유키·서버/클라이언트 설정)", "WireGuard 용 X25519 키 쌍을 새로 만들고(wg genkey/pubkey 와 같은 방식) 서버·클라이언트 설정 파일까지 짜 줘요. 비밀키로 공개키를 계산하거나 사전 공유키만 만들 수도 있어요",
            listOf(choice("m", "할 일", WG_MODES), text("priv", "비밀키 (공개키를 계산할 때)", "44글자 Base64, 끝이 ="), text("endpoint", "서버 주소:포트", "예: vpn.example.com:51820", "vpn.example.com:51820"),
                text("net", "VPN 안쪽 주소 대역", "서버는 첫 주소, 클라이언트는 둘째 주소를 써요", "10.8.0.0/24"), text("dns", "클라이언트 DNS (선택)", "", "1.1.1.1"), choice("route", "클라이언트가 VPN 으로 보낼 트래픽", ROUTE),
                choice("psk", "사전 공유키(PSK)", PSK_USE), text("nat", "서버의 인터넷 인터페이스 (선택)", "적으면 인터넷 공유(NAT) 설정도 넣어요. 예: eth0")), ToolMode.OFFLINE, "$LOCAL 만든 비밀키는 이 화면에만 보여요. 복사한 뒤 안전하게 보관하세요.", runLabel = "만들기") { i, _, _ ->
            val mode = i.choice("m", WG_MODES)
            when (mode) {
                1 -> {
                    val raw = try { Base64.getDecoder().decode(i.str("priv")) } catch (_: Exception) { return@tool fail("비밀키를 Base64 로 읽지 못했어요 (44글자, 끝이 = 인 글자)") }
                    if (raw.size != 32) return@tool fail("WireGuard 키는 32바이트(Base64 로 44글자)여야 해요. 지금은 ${raw.size}바이트예요")
                    result { kv("공개키", b64(X25519.publicKey(raw))); note("공개키는 상대 장비의 [Peer] PublicKey 에 넣는 값이에요. 비밀키로만 계산되니, 같은 비밀키는 언제나 같은 공개키가 나와요.", 0) }
                }
                2 -> result { kv("사전 공유키(PSK)", b64(ByteArray(32).also { rnd.nextBytes(it) })); note("양쪽 [Peer] 에 PresharedKey = 로 똑같이 넣으세요. 양자 컴퓨터 시대의 해독을 한 겹 더 막아 줘요.", 0) }
                else -> {
                    val (host, port) = hostPort(i.str("endpoint")) ?: return@tool fail("서버 주소는 \"호스트:포트\" 형식이어야 해요 (예: vpn.example.com:51820, IPv6 는 [2001:db8::1]:51820)")
                    val sn = Subnet.parse(i.str("net")) ?: return@tool fail("VPN 대역은 CIDR 형식이어야 해요 (예: 10.8.0.0/24)")
                    if (sn.prefix > 30) return@tool fail("VPN 대역은 /30 이하(주소가 4개 이상)여야 해요")
                    val dns = list(i.str("dns")).map { IpUtil.parse(it)?.let { a -> IpUtil.format(a) } ?: return@tool fail("DNS 는 IP 주소로 적어 주세요: $it") }
                    val natIf = i.str("nat"); if (natIf.isNotEmpty() && !Valid.iface(natIf)) return@tool fail("인터페이스 이름 형식이 이상해요: $natIf")
                    val srv = X25519.generate(); val cli = X25519.generate(); val psk = if (i.choice("psk", PSK_USE) == 0) b64(ByteArray(32).also { rnd.nextBytes(it) }) else null
                    val sa = IpUtil.v4Text(sn.network + 1); val ca = IpUtil.v4Text(sn.network + 2); val netText = IpUtil.v4Text(sn.network) + "/" + sn.prefix
                    val cfg = MakeCfg.WgPeerCfg(b64(srv.first), b64(srv.second), b64(cli.first), b64(cli.second), psk, "$sa/${sn.prefix}", "$ca/32", port, "$host:$port", dns.joinToString(", "), if (i.choice("route", ROUTE) == 1) "0.0.0.0/0, ::/0" else netText, natIf)
                    result {
                        head("서버 키"); kv("서버 비밀키", cfg.serverPriv, level = 1); kv("서버 공개키", cfg.serverPub)
                        head("클라이언트 키"); kv("클라이언트 비밀키", cfg.clientPriv, level = 1); kv("클라이언트 공개키", cfg.clientPub); if (psk != null) kv("사전 공유키(PSK)", psk, level = 1)
                        head("서버 설정 (/etc/wireguard/wg0.conf)"); block(MakeCfg.wgServer(cfg))
                        head("클라이언트 설정 (폰·PC 앱에 가져오기)"); block(MakeCfg.wgClient(cfg))
                        head("적용 명령 (서버)"); block("sudo install -m 600 wg0.conf /etc/wireguard/wg0.conf\nsudo systemctl enable --now wg-quick@wg0\nsudo wg show")
                        note("비밀키(와 PSK)는 이 화면과 위 설정에만 있어요. 만든 사람만 알아야 하니 메신저·메일로 그대로 보내지 마세요. 서버에는 서버 비밀키+클라이언트 공개키만, 클라이언트에는 클라이언트 비밀키+서버 공개키만 두면 돼요.", 1)
                        note("서버는 ${port}번 UDP 포트를 열어야 하고(공유기 포트포워딩·방화벽), 클라이언트가 여러 대면 [Peer] 와 주소(${IpUtil.v4Text(sn.network + 3)} …)를 늘려 가세요.", 0)
                    }
                }
            }
        },
        // 2
        tool("make_ssh_key", G, "SSH 키 쌍 만들기 (Ed25519, OpenSSH 형식)", "Ed25519 SSH 키 쌍을 새로 만들어요(ssh-keygen -t ed25519 와 같은 모양). 공개키 한 줄·개인키 파일 내용·지문과 서버에 등록하는 명령을 보여 줘요",
            listOf(text("c", "주석(comment)", "키를 알아보기 위한 이름. 예: me@phone", "me@phone")), ToolMode.OFFLINE, "$LOCAL 만든 개인키는 이 화면에만 보여요. 안전하게 보관하세요.", runLabel = "만들기") { i, _, _ ->
            val c = i.str("c"); if (c.length > 80 || c.any { it.isISOControl() }) return@tool fail("주석은 한 줄, 80글자 이하여야 해요")
            val seed = ByteArray(32).also { rnd.nextBytes(it) }; val pub = Ed25519.publicKey(seed); val line = SshKey.ed25519PublicLine(pub, c); val info = SshKey.parse(line)
            result {
                kv("종류", "Ed25519 (256비트)"); kv("지문(SHA256)", info.sha256); kv("공개키 (한 줄)", line)
                head("개인키 파일 내용 (id_ed25519)"); block(SshKey.ed25519PrivatePem(seed, pub, c))
                head("서버에 등록하기 (접속할 서버에서)"); block("mkdir -p ~/.ssh && chmod 700 ~/.ssh\necho '$line' >> ~/.ssh/authorized_keys\nchmod 600 ~/.ssh/authorized_keys")
                head("접속하기 (개인키를 id_ed25519 로 저장한 뒤)"); block("chmod 600 id_ed25519\nssh -i id_ed25519 사용자@서버")
                note("개인키는 암호(passphrase)를 걸지 않은 상태예요. 파일이 새면 누구나 접속할 수 있으니, 나중에 ssh-keygen -p -f id_ed25519 로 암호를 걸 수 있어요.", 1)
                note("공개키(한 줄)는 공개해도 돼요. 지문은 서버가 \"이 키를 등록했는지\" 확인할 때 대조하는 값이에요.", 0)
            }
        },
        // 3
        tool("make_cron", G, "cron 식 해석 · 다음 실행 시각 (시간대 선택)", "분 시 일 월 요일 5칸 cron 식(또는 @daily 같은 별칭)을 한국어로 풀어 주고, 정한 시간대에서 다음 실행 시각 여러 개를 계산해요. crontab 줄과 systemd OnCalendar 식도 만들어 줘요",
            listOf(text("e", "cron 식", "예: */15 9-18 * * 1-5", "*/15 9-18 * * 1-5"), choice("tz", "시간대", ZONES, "Asia/Seoul"), text("from", "기준 시각 (비우면 지금)", "예: 2024-03-01 09:30"), text("n", "보여 줄 실행 횟수", "1~50", "10")), ToolMode.OFFLINE, LOCAL, runLabel = "계산") { i, _, _ ->
            val spec = try { Cron.parse(i.str("e")) } catch (e: IllegalArgumentException) { return@tool fail(e.message ?: "cron 식을 읽지 못했어요") }
            val zone = ZoneId.of(ZONES[i.choice("tz", ZONES)]); val n = (i.intOr("n", 10) ?: return@tool fail("실행 횟수는 숫자로 적어 주세요 (1~50)")).coerceIn(1, 50)
            val fromText = i.str("from").replace('T', ' ')
            val from: ZonedDateTime = if (fromText.isEmpty()) ZonedDateTime.now(zone) else try {
                (if (fromText.length <= 10) LocalDate.parse(fromText).atStartOfDay() else LocalDateTime.parse(fromText, DateTimeFormatter.ofPattern(if (fromText.count { it == ':' } >= 2) "yyyy-MM-dd HH:mm:ss" else "yyyy-MM-dd HH:mm"))).atZone(zone)
            } catch (_: Exception) { return@tool fail("기준 시각은 2024-03-01 09:30 형식으로 적어 주세요") }
            val runs = Cron.nextRuns(spec, from, n)
            result {
                kv("뜻", Cron.describe(spec)); kv("정리한 식", spec.fields.joinToString(" "))
                head("칸별 값"); header("칸", "적은 값", "실제로 맞는 값")
                row("분", spec.fields[0], spec.minutes.joinToString(", ").let { if (it.length > 80) it.take(80) + " …" else it }); row("시", spec.fields[1], spec.hours.joinToString(", ")); row("일", spec.fields[2], spec.doms.joinToString(", ")); row("월", spec.fields[3], spec.months.joinToString(", "))
                row("요일", spec.fields[4], spec.dows.joinToString(", ") { Cron.DAY_KO[it] })
                head("다음 실행 시각 (${zone.id}, 기준 ${from.format(DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm"))})"); header("번호", "시각", "요일", "기준에서")
                if (runs.isEmpty()) note("100년 안에는 실행되는 날이 없어요. 날짜 칸을 확인하세요 (예: 2월 30일).", 2)
                for ((k, r) in runs.withIndex()) { val mins = java.time.Duration.between(from, r).toMinutes(); row("${k + 1}", r.format(DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm")), Cron.DAY_KO[r.dayOfWeek.value % 7] + "요일", if (mins < 60) "${mins}분 뒤" else if (mins < 1440) "${mins / 60}시간 ${mins % 60}분 뒤" else "${mins / 1440}일 ${(mins % 1440) / 60}시간 뒤") }
                head("다른 형식"); kv("crontab 줄", "${spec.fields.joinToString(" ")} /경로/명령"); kv("systemd OnCalendar", Cron.onCalendar(spec))
                for (c in Cron.caveats(spec)) note(c, 1)
                note("cron 은 서버의 시간대로 움직여요(CRON_TZ=Asia/Seoul 처럼 줄 앞에 지정하는 cron 도 있어요). 서머타임이 있는 지역은 전환하는 날 한 번 건너뛰거나 두 번 실행될 수 있어요.", 0)
                note("crontab 의 명령 안에서 % 는 줄바꿈이라 \\% 로 써야 해요. cron 은 PATH 가 짧으니 명령은 절대 경로로 쓰세요.", 0)
            }
        },
        // 4
        tool("make_ipv6_ula", G, "IPv6 사설 주소(ULA) 접두사 만들기 (RFC 4193)", "집·사무실 안에서만 쓰는 IPv6 사설 대역(fd00::/8)의 /48 접두사를 RFC 4193 규격대로 만들어요(현재 시각+MAC 의 SHA-1 아래 40비트). 안에서 쓸 /64 서브넷 목록도 보여 줘요",
            listOf(choice("m", "만드는 방식", ULA_MODES), text("mac", "이 기기의 MAC (선택)", "비우면 무작위 값을 써요. 예: 52:54:00:12:34:56")), ToolMode.OFFLINE, LOCAL, runLabel = "만들기") { i, _, _ ->
            val mode = i.choice("m", ULA_MODES); val macText = i.str("mac")
            val mac = if (macText.isEmpty()) ByteArray(6).also { rnd.nextBytes(it) } else Bx.parseMac(macText) ?: return@tool fail("MAC 은 52:54:00:12:34:56 형식이어야 해요")
            val gid = if (mode == 0) Ula.globalId(Ula.ntpTime(System.currentTimeMillis()), Ula.eui64(mac)) else ByteArray(5).also { rnd.nextBytes(it) }
            result {
                kv("ULA 접두사 (/48)", Ula.prefix(gid)); kv("전역 ID (40비트)", gid.joinToString("") { "%02x".format(it.toInt() and 0xff) }); kv("방식", if (mode == 0) "RFC 4193: SHA-1(NTP 시각 + EUI-64 ${Bx.hex(Ula.eui64(mac), 0, 8, ":")}) 의 아래 40비트" else "무작위 40비트")
                head("서브넷 (/64) 처음 16개"); header("번호", "서브넷")
                for (n in 0 until 16) row("$n", Ula.subnet(gid, n))
                note("한 번 만든 접두사는 계속 쓰세요. 이 대역은 인터넷으로 나가지 않는 사설 주소예요(fc00::/7 중 L=1 인 fd00::/8). 전역 ID 가 무작위라서 다른 사무실·VPN 과 합쳐도 겹칠 확률이 아주 낮아요.", 0)
                note("기기마다 /64 하나를 주면 SLAAC 로 주소가 자동으로 만들어져요. 라우터 광고(RA)에 이 접두사를 실어 주세요.", 0)
            }
        },
        // 5
        tool("make_wpa_conf", G, "Wi-Fi 설정 파일 만들기 (wpa_supplicant · hostapd, PSK 계산)", "SSID 와 비밀번호로 WPA2 의 256비트 PSK(PBKDF2-SHA1, 4096회)를 계산해서 리눅스 wpa_supplicant.conf(접속하는 쪽) 또는 hostapd.conf(공유기 만들기) 를 짜 줘요. WPA3(SAE)·혼합도 돼요",
            listOf(text("ssid", "SSID (와이파이 이름)", "", "MyWiFi"), text("pass", "비밀번호 (8~63글자)", "", "correct horse battery"), choice("sec", "보안 방식", WPA_SEC), choice("t", "만들 파일", WPA_TARGET),
                text("cc", "국가 코드 2글자", "전파 규정에 필요해요", "KR"), choice("hidden", "숨김 SSID (접속하는 쪽)", NO_YES), text("ch", "채널 (AP)", "2.4GHz 는 1~13, 5GHz 는 36·40·44·48 …", "6"), choice("band", "대역 (AP)", BAND), text("if", "무선 인터페이스 (AP)", "", "wlan0")), ToolMode.OFFLINE, "$LOCAL 비밀번호는 파일에 해시(PSK)로 들어가요. WPA3 에는 비밀번호 그대로가 필요해요.", runLabel = "만들기") { i, _, _ ->
            val ssid = i.raw("ssid").trim(); val pass = i.raw("pass")
            if (ssid.isEmpty() || ssid.toByteArray().size > 32) return@tool fail("SSID 는 1~32바이트여야 해요 (한글은 글자당 3바이트)")
            if (ssid.any { it == '"' || it == '\\' || it.isISOControl() }) return@tool fail("SSID 에 따옴표(\")·역슬래시·제어 문자는 쓸 수 없어요")
            if (pass.length !in 8..63 || pass.any { it.code !in 32..126 }) return@tool fail("비밀번호는 영문·숫자·기호(ASCII) 8~63글자여야 해요")
            val cc = i.str("cc").uppercase(); if (cc.isNotEmpty() && !Regex("^[A-Z]{2}$").matches(cc)) return@tool fail("국가 코드는 KR·US 처럼 알파벳 2글자예요")
            val sec = i.choice("sec", WPA_SEC)
            if (sec != 0 && pass.any { it == '"' || it == '\\' }) return@tool fail("WPA3(SAE)·혼합 설정에는 비밀번호에 따옴표(\")·역슬래시를 쓸 수 없어요")
            val psk = WpaPsk.psk(pass, ssid).joinToString("") { "%02x".format(it.toInt() and 0xff) }
            val ap = i.choice("t", WPA_TARGET) == 1
            val iface = i.str("if"); if (ap && !Valid.iface(iface)) return@tool fail("인터페이스 이름 형식이 이상해요")
            val band5 = i.choice("band", BAND) == 1; val ch = i.intOr("ch", 6) ?: return@tool fail("채널은 숫자로 적어 주세요")
            if (ap && (if (band5) ch !in listOf(36, 40, 44, 48, 52, 56, 60, 64, 100, 104, 108, 112, 116, 120, 124, 128, 132, 136, 140, 144, 149, 153, 157, 161, 165) else ch !in 1..14)) return@tool fail(if (band5) "5GHz 채널은 36·40·44·48·149·153·157·161 처럼 알려진 채널이어야 해요" else "2.4GHz 채널은 1~14 예요")
            result {
                kv("SSID", ssid); kv("PSK (64자리 16진수)", psk); kv("계산 방식", "PBKDF2-HMAC-SHA1(비밀번호, SSID, 4096회, 256비트)")
                head(if (ap) "hostapd.conf" else "wpa_supplicant.conf"); block(if (ap) MakeCfg.hostapd(ssid, psk, pass, sec, cc, ch, band5, iface) else MakeCfg.wpaSupplicant(ssid, psk, pass, sec, cc, i.choice("hidden", NO_YES) == 1))
                head("적용 명령"); block(if (ap) "sudo install -m 600 hostapd.conf /etc/hostapd/hostapd.conf\nsudo systemctl unmask hostapd && sudo systemctl enable --now hostapd" else "sudo install -m 600 wpa_supplicant.conf /etc/wpa_supplicant/wpa_supplicant-wlan0.conf\nsudo systemctl enable --now wpa_supplicant@wlan0")
                if (sec != 0) note("WPA3(SAE)는 해시(PSK)가 아니라 비밀번호 그대로를 설정에 넣어야 해서, 이 파일에는 비밀번호가 글자 그대로 들어 있어요. 파일 권한을 600 으로 하세요.", 1)
                else note("파일에는 비밀번호 대신 PSK 가 들어가요. 하지만 PSK 만 있어도 접속은 되니 비밀번호만큼 조심하세요.", 0)
                if (sec == 2) note("혼합 모드는 WPA2 만 되는 오래된 기기도 붙을 수 있지만, 그만큼 WPA3 의 보호가 약해져요(다운그레이드 공격 여지).", 1)
            }
        },
        // 6
        tool("make_openssl_cmd", G, "OpenSSL 명령 만들기 (인증서·CSR·PFX·확인·짝 맞추기)", "자체 서명 인증서, CSR, PFX 묶기/풀기, 인증서 내용·만료 확인, 서버 인증서 확인, 키·인증서 짝 맞추기, 체인 검증, 무작위 값 만들기 명령을 입력값에 맞춰 만들어 줘요",
            listOf(choice("op", "만들 명령", SSL_OPS),
                text("cn", "이름 (CN)", "예: example.com", "example.com"), text("san", "SAN 목록 (쉼표)", "도메인·IP. *.example.com 도 돼요", "example.com, www.example.com, 192.168.1.10"), choice("alg", "키 종류", MakeCfg.SSL_ALGS, "EC P-256"),
                text("days", "유효기간(일)", "", "365"), text("org", "조직 (선택)"), text("c", "국가 2글자 (선택)", "예: KR"), text("base", "파일 이름 (확장자 제외)", "", "server"), text("host", "확인할 서버 (서버 인증서 확인용)", "호스트 또는 호스트:포트", "example.com:443")), ToolMode.OFFLINE, "$LOCAL (\"서버가 주는 인증서 확인\" 명령만 실행할 때 서버에 접속해요.)", runLabel = "만들기") { i, _, _ ->
            val op = i.choice("op", SSL_OPS)
            val base = i.str("base"); if (!Regex("^[A-Za-z0-9._-]{1,40}$").matches(base)) return@tool fail("파일 이름은 영문·숫자·._- 만 쓸 수 있어요 (40글자까지)")
            val sansIn = list(i.str("san"), ",; \n").map { s -> if (IpUtil.parse(s) != null) IpUtil.format(IpUtil.parse(s)!!) else Valid.host(s, wildcard = true) ?: return@tool fail("SAN 항목이 도메인도 IP 도 아니에요: $s") }
            val cnRaw = i.str("cn"); val cn = cnRaw.ifEmpty { sansIn.firstOrNull().orEmpty() }
            if (cn.any { it in "/\"\\" || it.isISOControl() } || (op in 0..1 && cn.isEmpty())) return@tool fail("이름(CN)을 적어 주세요 (/ \" \\ 는 쓸 수 없어요)")
            val days = i.intOr("days", 365) ?: return@tool fail("유효기간은 숫자(일)로 적어 주세요"); if (days !in 1..36500) return@tool fail("유효기간은 1~36500일이어야 해요")
            val org = i.str("org"); if (org.any { it in "/\"\\" || it.isISOControl() } || org.length > 64) return@tool fail("조직 이름에는 / \" \\ 를 쓸 수 없고 64글자까지예요")
            val cc = i.str("c").uppercase(); if (cc.isNotEmpty() && !Regex("^[A-Z]{2}$").matches(cc)) return@tool fail("국가는 KR 처럼 알파벳 2글자예요")
            val host = if (op == 5) sslTarget(i.str("host")) ?: return@tool fail("서버는 example.com 또는 example.com:443 형식이어야 해요") else ""
            val alg = i.choice("alg", MakeCfg.SSL_ALGS)
            val items = MakeCfg.openssl(op, MakeCfg.SslIn(cn.ifEmpty { "example.com" }, sansIn, alg, days, org, cc, base, host))
            result {
                for ((title, cmd, why) in items) { head(title); block(cmd); note(why, 0) }
                if (op in 0..3) note("개인키(.key)는 서버 밖으로 꺼내지 말고 권한을 600 으로 하세요. 유효기간이 짧은 인증서를 자동으로 갱신하는 편이 안전해요(Let's Encrypt·ACME).", 0)
                if (op == 0 && days > 398) note("공인 인증서의 최대 유효기간은 398일이에요. 브라우저가 그보다 긴 공인 인증서는 거부하지만, 내 장비용 자체 서명은 상관없어요.", 0)
            }
        },
        // 7
        tool("make_tc_netem", G, "tc 지연·손실·속도 제한 명령 (netem·tbf)", "리눅스 tc 로 네트워크를 일부러 느리게 만드는 명령을 만들어요: 지연·지터·패킷 손실·중복·손상·순서 뒤바뀜·속도 제한. 적용·확인·원상복구 명령과 tbf 속도 제한의 burst·limit 계산값도 알려 줘요",
            listOf(text("dev", "네트워크 인터페이스", "예: eth0", "eth0"), text("delay", "지연 (ms)", "", "100"), text("jitter", "지터 (ms, 선택)", "지연이 오락가락하는 폭", "20"), choice("dist", "지연 분포", NETEM_DIST), text("loss", "패킷 손실 (%)", "", "1"), text("dup", "중복 (%)", "", "0"),
                text("corrupt", "손상 (%)", "", "0"), text("reorder", "순서 뒤바뀜 (%, 지연이 있어야 해요)", "", "0"), text("rate", "속도 제한 (선택)", "예: 10mbit · 512kbit · 1gbit (숫자만 쓰면 Mbit)", "10mbit"), text("lat", "큐 대기 허용 시간 (ms, tbf)", "속도 제한을 tbf 로 걸 때", "50")), ToolMode.OFFLINE, "$LOCAL 만든 명령은 리눅스 장비에서 직접 실행하세요(루트 권한 필요).", runLabel = "만들기") { i, _, _ ->
            val dev = i.str("dev"); if (!Valid.iface(dev)) return@tool fail("인터페이스 이름 형식이 이상해요 (영문·숫자·._:@- 15글자까지)")
            fun pct(k: String): Double = i.str(k).ifEmpty { "0" }.toDoubleOrNull() ?: Double.NaN
            val delay = i.str("delay").ifEmpty { "0" }.toDoubleOrNull(); val jitter = i.str("jitter").ifEmpty { "0" }.toDoubleOrNull()
            if (delay == null || delay < 0 || delay > 60000) return@tool fail("지연은 0~60000ms 숫자여야 해요"); if (jitter == null || jitter < 0 || jitter > 60000) return@tool fail("지터는 0~60000ms 숫자여야 해요")
            if (jitter > 0 && delay <= 0) return@tool fail("지터를 쓰려면 지연도 있어야 해요")
            val loss = pct("loss"); val dup = pct("dup"); val cor = pct("corrupt"); val reo = pct("reorder")
            for ((v, l) in listOf(loss to "손실", dup to "중복", cor to "손상", reo to "순서 뒤바뀜")) if (v.isNaN() || v < 0 || v > 100) return@tool fail("$l 은 0~100 사이의 숫자(%)여야 해요")
            if (reo > 0 && delay <= 0) return@tool fail("순서 뒤바뀜(reorder)은 지연이 있어야 동작해요. 지연을 함께 적어 주세요")
            val rateText = i.str("rate"); val rate = if (rateText.isEmpty()) 0L else TcCmd.parseRate(rateText) ?: return@tool fail("속도는 10mbit · 512kbit · 1gbit 처럼 적어 주세요 (kbit 이상 100gbit 이하)")
            val lat = i.intOr("lat", 50) ?: return@tool fail("큐 대기 허용 시간은 숫자(ms)로 적어 주세요"); if (lat !in 1..10000) return@tool fail("큐 대기 허용 시간은 1~10000ms 예요")
            if (delay == 0.0 && loss == 0.0 && dup == 0.0 && cor == 0.0 && reo == 0.0 && rate == 0L) return@tool need("지연·손실·중복·손상·순서·속도 중 하나는 적어 주세요")
            val dist = listOf("normal", "uniform", "pareto", "")[i.choice("dist", NETEM_DIST)]
            val n = TcCmd.Netem(delay, jitter, dist, loss, dup, cor, reo, rate)
            val oneLine = "sudo " + TcCmd.netem(dev, n)
            result {
                head("적용 (한 줄: 지연·손실·속도를 netem 하나로)"); block(oneLine)
                if (rate > 0) {
                    val burst = TcCmd.tbfBurstBytes(rate); val limit = TcCmd.tbfLimitBytes(rate, lat, burst)
                    head("속도 제한을 tbf 로 정확하게 걸고 싶을 때 (2단: netem → tbf)")
                    block("sudo " + TcCmd.netem(dev, TcCmd.Netem(delay, jitter, dist, loss, dup, cor, reo, 0), handle = "1:") + "\nsudo " + TcCmd.tbf(dev, rate, lat, parent = "parent 1:1", handle = "10:"))
                    kv("tbf burst", "${burst / 1024}kb ($burst 바이트)"); kv("tbf limit(큐 길이)", "$limit 바이트 (속도 × ${lat}ms + burst)")
                    note("burst 는 속도(${TcCmd.rateText(rate)})를 실제로 내려면 최소 속도÷HZ(250)÷8 = ${Math.ceil(rate / 8.0 / 250).toLong()}바이트는 있어야 해서, 2배 여유를 두고 KB 로 올림했어요. 너무 작으면 설정한 속도가 안 나와요.", 0)
                }
                head("확인"); block("tc qdisc show dev $dev\ntc -s qdisc show dev $dev")
                head("원상복구 (꼭 해 두세요)"); block("sudo tc qdisc del dev $dev root")
                head("들어오는 쪽(수신)도 흉내 내고 싶을 때 (ifb 로 돌려서)"); block("sudo modprobe ifb numifbs=1\nsudo ip link set dev ifb0 up\nsudo tc qdisc add dev $dev handle ffff: ingress\nsudo tc filter add dev $dev parent ffff: protocol all u32 match u32 0 0 action mirred egress redirect dev ifb0\n" + "sudo " + TcCmd.netem("ifb0", n))
                note("tc 는 \"나가는\" 패킷에 적용돼요. 원격(SSH)으로 접속한 장비에 적용하면 내 접속도 느려지니 먼저 sleep 으로 자동 복구를 걸어 두세요: sudo sh -c 'sleep 300; tc qdisc del dev $dev root' &", 1)
                if (loss > 10 || delay > 2000) note("손실이 10%를 넘거나 지연이 2초를 넘으면 대부분의 프로그램이 거의 동작하지 않아요.", 1)
                note("netem 은 시험·개발용이에요. 서비스 중인 운영 장비에는 쓰지 마세요.", 0)
            }
        },
        // 8
        tool("make_nftables", G, "nftables 방화벽 규칙 만들기 (SSH 제한·포트·차단 목록·NAT·포트포워딩)", "리눅스 nftables 방화벽 규칙 파일을 만들어요: 기본 차단, 이미 맺은 연결 허용, SSH 속도 제한·허용 IP, 열 포트, ping, 차단할 IP·대역 목록(IP 위치 도구의 국가 대역 결과를 붙여 넣어도 돼요), NAT 마스커레이드, 포트 포워딩",
            listOf(text("ssh", "SSH 포트 (0 이면 열지 않음)", "", "22"), text("sshfrom", "SSH 를 허용할 IP·대역 (선택)", "비우면 어디서나. 쉼표로 여러 개. 예: 192.168.0.0/24, 203.0.113.7"), text("sshrate", "SSH 새 연결 제한 (분당, 0=제한 없음)", "", "6"), text("tcp", "열 TCP 포트 (쉼표)", "", "80,443"), text("udp", "열 UDP 포트 (쉼표)"), choice("icmp", "ping(ICMP)", ICMP_OPT),
                multi("block", "차단할 IP·대역 (줄마다 하나, 선택)", "예: 198.51.100.0/24"), text("nat", "NAT 마스커레이드 인터페이스 (라우터일 때, 선택)", "예: eth0"), multi("fwd", "포트 포워딩 (줄마다 하나, 선택)", "외부포트->내부IP:포트  예: 8080->192.168.1.50:80  (UDP 는 끝에 /udp)"), choice("log", "차단한 패킷 기록", LOG_OPT)), ToolMode.OFFLINE, "$LOCAL 규칙은 만들기만 해요. 장비에 적용하는 건 직접 하세요.", runLabel = "만들기") { i, _, _ ->
            val ssh = i.intOr("ssh", 22) ?: return@tool fail("SSH 포트는 숫자로 적어 주세요 (0 이면 열지 않음)"); if (ssh !in 0..65535) return@tool fail("SSH 포트는 0~65535 예요")
            val from = list(i.raw("sshfrom"), ",; \n").map { Valid.ipOrCidr(it) ?: return@tool fail("SSH 허용 목록에 IP·대역이 아닌 값이 있어요: $it") }
            val rate = i.intOr("sshrate", 6) ?: return@tool fail("SSH 새 연결 제한은 숫자로 적어 주세요 (0 이면 제한 없음)"); if (rate !in 0..1000) return@tool fail("SSH 새 연결 제한은 0~1000 이에요")
            fun ports(k: String): List<Int>? { val out = ArrayList<Int>(); for (t in list(i.raw(k), ",; ")) out += Valid.port(t) ?: return null; return out.distinct() }
            val tcp = ports("tcp") ?: return@tool fail("TCP 포트는 1~65535 의 숫자를 쉼표로 나눠 적어 주세요"); val udp = ports("udp") ?: return@tool fail("UDP 포트는 1~65535 의 숫자를 쉼표로 나눠 적어 주세요")
            val block = lineList(i.raw("block")).flatMap { list(it, ", ;") }.map { Valid.ipOrCidr(it) ?: return@tool fail("차단 목록에 IP·대역이 아닌 값이 있어요: $it") }.distinct()
            if (block.size > 5000) return@tool fail("차단 목록은 5000개까지 넣을 수 있어요 (지금 ${block.size}개). 대역을 합쳐(cidr_merge 도구) 줄여 보세요")
            val nat = i.str("nat"); if (nat.isNotEmpty() && !Valid.iface(nat)) return@tool fail("NAT 인터페이스 이름 형식이 이상해요")
            val fwd = lineList(i.raw("fwd")).map { line ->
                val m = Regex("^(\\d{1,5})\\s*(?:->|→|=)\\s*([0-9.]+):(\\d{1,5})(?:/(tcp|udp))?$").find(line) ?: return@tool fail("포트 포워딩은 \"외부포트->내부IP:포트\" 형식이에요: $line")
                val ip = IpUtil.parseV4(m.groupValues[2]) ?: return@tool fail("내부 IP 가 IPv4 주소가 아니에요: ${m.groupValues[2]}")
                MakeCfg.NftForward(Valid.port(m.groupValues[1]) ?: return@tool fail("외부 포트가 이상해요: ${m.groupValues[1]}"), ip.joinToString(".") { (it.toInt() and 0xff).toString() }, Valid.port(m.groupValues[3]) ?: return@tool fail("내부 포트가 이상해요: ${m.groupValues[3]}"), m.groupValues[4].ifEmpty { "tcp" })
            }
            if (fwd.isNotEmpty() && nat.isEmpty()) return@tool fail("포트 포워딩을 쓰려면 NAT 인터페이스(바깥쪽 NIC 이름)도 적어 주세요")
            val cfg = MakeCfg.nft(MakeCfg.Nft(ssh, from, rate, tcp, udp, i.choice("icmp", ICMP_OPT) == 0, block, nat, fwd, i.choice("log", LOG_OPT) == 1))
            result {
                kv("규칙 줄 수", "${cfg.lines().size}줄"); if (block.isNotEmpty()) kv("차단 목록", "${block.size}개")
                head("nftables.conf"); block(cfg)
                head("적용 순서"); block("sudo nft -c -f nftables.conf     # 문법만 확인 (적용 안 함)\nsudo nft -f nftables.conf       # 적용\nsudo nft list ruleset            # 확인\nsudo install -m 644 nftables.conf /etc/nftables.conf && sudo systemctl enable --now nftables   # 부팅 때도 적용")
                if (ssh == 0) note("SSH 포트를 열지 않았어요. 원격으로 접속 중이라면 적용하는 순간 연결이 끊겨서 다시 들어올 수 없어요.", 2)
                note("처음 적용할 때는 원격 접속이 끊기지 않게 \"5분 뒤 규칙 모두 지우기\"를 먼저 걸어 두세요: sudo sh -c 'sleep 300; nft flush ruleset' &", 1)
                note("기본 정책은 들어오는 연결 모두 차단(drop)이에요. 열지 않은 포트는 접속할 수 없어요. 나가는 연결은 모두 허용해요.", 0)
                if (nat.isNotEmpty()) note("NAT/포워딩을 쓰려면 커널의 IP 전달도 켜세요: sudo sysctl -w net.ipv4.ip_forward=1 (영구: /etc/sysctl.d/99-forward.conf)", 0)
                if (block.isNotEmpty()) note("차단 목록은 집합(set)이라 수천 개여도 빠르게 걸러요. IPv4·IPv6 가 자동으로 나뉘어 들어가요.", 0)
            }
        },
        // 9
        tool("make_systemd", G, "systemd 서비스·타이머 파일 만들기", "프로그램을 서비스로 돌리는 .service 파일(자동 재시작·실행 계정·보안 강화 옵션)과, 정해진 시각·간격으로 돌리는 .timer 파일을 만들어요",
            listOf(text("name", "서비스 이름", "영문·숫자·-_ 만", "myapp"), text("desc", "설명", "", "My application"), text("exec", "실행 명령 (절대 경로)", "예: /usr/bin/python3 /opt/myapp/main.py", "/usr/bin/myapp --config /etc/myapp.conf"), text("user", "실행 계정 (선택)", "root 대신 쓸 전용 계정. 예: myapp"), text("workdir", "작업 폴더 (선택)", "예: /opt/myapp"),
                choice("restart", "다시 시작", RESTART), multi("env", "환경 변수 (줄마다 KEY=값, 선택)", "예: PORT=8080"), choice("hard", "보안 강화", HARDEN), choice("net", "네트워크가 켜진 뒤에 시작", YES_NO),
                choice("timer", "타이머", TIMER), text("when", "타이머 값", "시각 03:15 · 분 간격 15 · OnCalendar 식", "03:15")), ToolMode.OFFLINE, LOCAL, runLabel = "만들기") { i, _, _ ->
            val name = i.str("name"); if (!Valid.serviceName(name)) return@tool fail("서비스 이름은 영문·숫자·:_.@- 만 쓸 수 있어요 (60글자까지)")
            val desc = i.str("desc").ifEmpty { name }; if (desc.any { it.isISOControl() }) return@tool fail("설명은 한 줄이어야 해요")
            val exec = i.str("exec"); if (!exec.startsWith("/") || exec.any { it == '\n' }) return@tool fail("실행 명령은 /usr/bin/… 처럼 절대 경로로 시작해야 해요 (systemd 는 PATH 를 찾지 않아요)")
            val user = i.str("user"); if (user.isNotEmpty() && !Valid.unixName(user)) return@tool fail("실행 계정 이름 형식이 이상해요 (소문자·숫자·_-)")
            val wd = i.str("workdir"); if (wd.isNotEmpty() && (!wd.startsWith("/") || wd.any { it.isISOControl() })) return@tool fail("작업 폴더는 /opt/… 처럼 절대 경로여야 해요")
            val env = lineList(i.raw("env")).onEach { if (!Regex("^[A-Za-z_][A-Za-z0-9_]*=[^\"\n]*$").matches(it)) return@tool fail("환경 변수는 KEY=값 형식이어야 해요 (값에 \" 는 쓸 수 없어요): $it") }
            val restart = RESTART[i.choice("restart", RESTART)]
            val hard = i.choice("hard", HARDEN); val tIdx = i.choice("timer", TIMER); val w = i.str("when")
            var cal: String? = null; var every: Int? = null
            when (tIdx) {
                1 -> { val t = try { LocalTime.parse(w.padStart(5, '0')) } catch (_: Exception) { return@tool fail("시각은 03:15 처럼 적어 주세요") }; cal = "*-*-* %02d:%02d:00".format(t.hour, t.minute) }
                2 -> { every = w.toIntOrNull()?.takeIf { it in 1..10080 } ?: return@tool fail("분 간격은 1~10080 사이의 숫자예요") }
                3 -> { if (w.isEmpty() || w.any { it.isISOControl() }) return@tool fail("OnCalendar 식을 적어 주세요 (예: Mon..Fri *-*-* 09:00:00). cron 식은 \"cron 식 해석\" 도구에서 바꿀 수 있어요"); cal = w }
            }
            val files = MakeCfg.systemd(MakeCfg.Systemd(name, desc, exec, user, wd, restart, env, hard, i.choice("net", YES_NO) == 0, cal, every))
            result {
                for ((fn, body) in files) { head("/etc/systemd/system/$fn"); block(body) }
                head("설치·시작"); block("sudo cp ${files.joinToString(" ") { it.first }} /etc/systemd/system/\nsudo systemctl daemon-reload\n" + (if (files.size > 1) "sudo systemctl enable --now $name.timer\nsystemctl list-timers $name.timer" else "sudo systemctl enable --now $name.service\nsystemctl status $name.service\njournalctl -u $name.service -f"))
                if (user.isEmpty()) note("실행 계정을 정하지 않으면 root 로 실행돼요. 가능하면 전용 계정을 쓰세요: sudo useradd --system --no-create-home --shell /usr/sbin/nologin <이름>", 1)
                if (hard >= 2) note("\"강하게\" 옵션은 파일 시스템을 거의 읽기 전용으로 만들어요. 프로그램이 /var/lib/$name 밖에 써야 한다면 ReadWritePaths= 로 열어 주세요.", 0)
                if (files.size > 1) note("타이머를 쓸 때 서비스는 한 번 실행하고 끝나는(oneshot) 프로그램이어야 해요. [Install] 은 .timer 에만 있어요.", 0)
                note("파일을 고친 뒤에는 sudo systemctl daemon-reload 를 다시 실행하세요. 문법 확인: systemd-analyze verify /etc/systemd/system/$name.service", 0)
            }
        },
        // 10
        tool("make_netplan", G, "netplan 네트워크 설정 만들기 (DHCP·고정 IP·브리지·VLAN·본딩)", "우분투의 netplan YAML 을 만들어요: DHCP, 고정 IP(게이트웨이·DNS·MTU), 브리지, VLAN, 본딩(active-backup). 안전하게 적용하는 netplan try 순서도 알려 줘요",
            listOf(choice("m", "방식", NETPLAN_MODES), text("if", "인터페이스 이름", "일반: 랜카드 이름(eth0·enp3s0), 브리지·본딩·VLAN: 새로 만들 이름(br0·bond0·vlan100)", "eth0"), text("mem", "구성 랜카드 (브리지·본딩·VLAN)", "쉼표로 여러 개. VLAN 은 부모 랜카드 하나. 예: eth0, eth1"), text("addr", "IP 주소/길이 (고정·브리지·VLAN·본딩)", "쉼표로 여러 개. 예: 192.168.1.10/24", "192.168.1.10/24"),
                text("gw4", "IPv4 게이트웨이 (선택)", "", "192.168.1.1"), text("gw6", "IPv6 게이트웨이 (선택)"), text("dns", "DNS 서버 (선택)", "쉼표로 여러 개", "1.1.1.1, 8.8.8.8"), text("search", "검색 도메인 (선택)", "예: home.lan"), text("mtu", "MTU (선택)", "예: 1500, 점보 프레임 9000"), text("vlan", "VLAN ID (VLAN 방식)", "1~4094", "100")), ToolMode.OFFLINE, LOCAL, runLabel = "만들기") { i, _, _ ->
            val mode = i.choice("m", NETPLAN_MODES); val ifc = i.str("if"); if (!Valid.iface(ifc)) return@tool fail("인터페이스 이름 형식이 이상해요 (영문·숫자·._:@- 15글자까지)")
            val members = list(i.raw("mem"), ", ;").onEach { if (!Valid.iface(it)) return@tool fail("구성 랜카드 이름이 이상해요: $it") }
            if (mode == 2 && members.isEmpty()) return@tool fail("브리지에 넣을 랜카드를 적어 주세요 (예: eth0, eth1)")
            if (mode == 3 && members.size != 1) return@tool fail("VLAN 은 부모 랜카드 하나를 적어 주세요 (예: eth0)")
            if (mode == 4 && members.size < 2) return@tool fail("본딩은 랜카드를 2개 이상 적어 주세요")
            val vlan = if (mode == 3) (i.int("vlan")?.takeIf { it in 1..4094 } ?: return@tool fail("VLAN ID 는 1~4094 예요")) else null
            val addrs = if (mode == 0) emptyList() else list(i.raw("addr"), ", ;").map { Valid.cidr(it) ?: return@tool fail("IP 주소는 192.168.1.10/24 처럼 길이까지 적어 주세요: $it") }
            if (mode == 1 && addrs.isEmpty()) return@tool fail("고정 IP 방식에는 IP 주소가 필요해요")
            fun gw(k: String, v6: Boolean): String { val t = i.str(k); if (t.isEmpty() || mode == 0) return ""; val a = IpUtil.parse(t); if (a == null || (a.address.size == 16) != v6) throw IllegalArgumentException("${if (v6) "IPv6" else "IPv4"} 게이트웨이 주소가 이상해요: $t"); return IpUtil.format(a) }
            val g4 = try { gw("gw4", false) } catch (e: IllegalArgumentException) { return@tool fail(e.message!!) }; val g6 = try { gw("gw6", true) } catch (e: IllegalArgumentException) { return@tool fail(e.message!!) }
            val dns = if (mode == 0) emptyList() else list(i.raw("dns"), ", ;").map { IpUtil.parse(it)?.let { a -> IpUtil.format(a) } ?: return@tool fail("DNS 는 IP 주소여야 해요: $it") }
            val search = if (mode == 0) emptyList() else list(i.raw("search"), ", ;").map { Valid.host(it) ?: return@tool fail("검색 도메인 형식이 이상해요: $it") }
            val mtu = i.str("mtu").takeIf { it.isNotEmpty() }?.let { it.toIntOrNull()?.takeIf { v -> v in 576..9216 } ?: return@tool fail("MTU 는 576~9216 이에요") }
            val dhcp = mode == 0 || (mode >= 2 && addrs.isEmpty())
            val yaml = MakeCfg.netplan(MakeCfg.Netplan(mode, ifc, addrs, g4, g6, dns, search, mtu, vlan, members, dhcp))
            result {
                head("/etc/netplan/50-custom.yaml"); block(yaml)
                head("적용 순서 (원격 접속 중에도 안전)"); block("sudo install -m 600 50-custom.yaml /etc/netplan/50-custom.yaml\nsudo netplan generate    # 문법 확인\nsudo netplan try         # 적용해 보고, 120초 안에 Enter 를 안 누르면 자동으로 되돌려요\nsudo netplan apply       # 확정")
                if (mode >= 2 && addrs.isEmpty()) note("주소를 적지 않아서 DHCP 로 받도록 했어요.", 0)
                if (mode == 1 && g4.isEmpty()) note("게이트웨이를 적지 않았어요. 같은 대역 밖으로는 나갈 수 없어요.", 1)
                if (mode == 1 && dns.isEmpty()) note("DNS 를 적지 않았어요. 이름으로는 접속할 수 없을 수 있어요.", 1)
                note("YAML 은 들여쓰기가 중요해요(스페이스 2칸). 탭은 쓸 수 없어요. 파일 권한이 600 이 아니면 netplan 이 경고해요.", 0)
                note("클라우드 서버라면 /etc/netplan/50-cloud-init.yaml 이 이미 있어요. 그 파일을 덮어쓰기보다 cloud-init 의 네트워크 설정 변경을 끄고 새 파일을 쓰세요.", 0)
            }
        },
        // 11
        tool("make_chrony", G, "chrony 시간 동기화 설정 만들기 (NTP·NTS·서버 열기)", "chrony.conf 를 만들어요: 사용할 NTP 서버(pool 자동 인식)·NTS 암호화·부팅 직후 큰 시간 차이 보정(makestep)·내 망 기기에 시간 제공(allow)·오프라인 망의 기준 시계(local stratum)",
            listOf(multi("srv", "NTP 서버 (줄마다 하나)", "이름에 pool 이 들어 있으면 pool 로 써요", "time.cloudflare.com\ntime.google.com\n2.pool.ntp.org"), choice("nts", "NTS(암호화된 NTP)", NTS), text("allow", "시간을 제공할 내 망 대역 (선택)", "쉼표로 여러 개. 예: 192.168.1.0/24"), choice("local", "인터넷이 없는 망의 기준 시계", LOCAL_CLOCK), choice("step", "부팅 직후 큰 오차 즉시 보정(makestep)", YES_NO), choice("rtc", "하드웨어 시계 동기화(rtcsync)", YES_NO)), ToolMode.OFFLINE, LOCAL, runLabel = "만들기") { i, _, _ ->
            val servers = lineList(i.raw("srv")).flatMap { list(it, ", ;") }.map { Valid.ipOrHost(it) ?: return@tool fail("NTP 서버 이름이 이상해요: $it") }.distinct()
            if (servers.isEmpty()) return@tool need("NTP 서버를 하나 이상 적어 주세요")
            val allow = list(i.raw("allow"), ", ;").map { Valid.cidr(it) ?: return@tool fail("내 망 대역은 192.168.1.0/24 처럼 적어 주세요: $it") }
            val nts = i.choice("nts", NTS) == 1
            val cfg = MakeCfg.chrony(MakeCfg.Chrony(servers, nts, allow, i.choice("local", LOCAL_CLOCK) == 1, i.choice("step", YES_NO) == 0, i.choice("rtc", YES_NO) == 0, false))
            result {
                head("/etc/chrony/chrony.conf (RHEL 계열은 /etc/chrony.conf)"); block(cfg)
                head("적용·확인"); block("sudo cp chrony.conf /etc/chrony/chrony.conf\nsudo systemctl restart chrony    # RHEL: chronyd\nchronyc sources -v               # 서버 목록 (^* 가 현재 기준)\nchronyc tracking                 # 오차·정확도\n" + if (nts) "chronyc authdata                  # NTS 인증 상태" else "")
                if (nts) note("NTS 는 서버가 지원해야 해요. time.cloudflare.com·nts.netnod.se·ptbtime1.ptb.de 등이 지원해요. 지원하지 않는 서버에 nts 를 붙이면 동기화가 안 돼요.", 1)
                if (allow.isNotEmpty()) note("allow 를 쓰면 이 장비가 NTP 서버(UDP 123)가 돼요. 방화벽에서 ${allow.joinToString(", ")} 에서만 123/udp 를 열어 주세요.", 1)
                note("서버는 3~4개를 쓰면 하나가 틀려도 나머지가 바로잡아 줘요. 하나만 쓰면 그 서버가 틀릴 때 같이 틀려요.", 0)
            }
        },
        // 12
        tool("make_fail2ban", G, "fail2ban 설정 만들기 (jail.local: SSH·웹·메일 로그인 시도 차단)", "로그인에 계속 실패하는 IP 를 자동으로 막는 fail2ban 의 jail.local 을 만들어요. 사용할 감시 항목(sshd·nginx·apache·postfix·dovecot 등), 실패 횟수·감시 시간·차단 시간, 예외 IP, 반복 위반자 가중 차단을 정해요",
            listOf(multi("jails", "감시할 항목 (줄마다 하나)", "sshd · nginx-http-auth · nginx-botsearch · apache-auth · postfix · dovecot · vsftpd · mysqld-auth · recidive", "sshd"), text("sshport", "SSH 포트", "", "22"), text("max", "실패 허용 횟수", "", "5"), text("find", "감시 시간 (분)", "이 시간 안에 허용 횟수를 넘으면 차단", "10"), text("ban", "차단 시간 (분)", "", "60"), text("ignore", "예외로 둘 IP·대역 (선택)", "내 IP 는 꼭 넣으세요. 예: 203.0.113.7, 192.168.0.0/24"),
                choice("act", "차단 방식", F2B_ACT), choice("sshbk", "SSH 로그 읽는 곳", F2B_SSHBK), choice("inc", "반복 위반자 차단 시간 늘리기", F2B_INC)), ToolMode.OFFLINE, LOCAL, runLabel = "만들기") { i, _, _ ->
            val jails = lineList(i.raw("jails")).flatMap { list(it, ", ;") }.distinct().onEach { if (it !in MakeCfg.F2B_JAILS) return@tool fail("지원하지 않는 항목이에요: $it. 쓸 수 있는 이름: ${MakeCfg.F2B_JAILS.keys.joinToString(", ")}") }
            if (jails.isEmpty()) return@tool need("감시할 항목을 하나 이상 적어 주세요 (예: sshd)")
            val sp = Valid.port(i.str("sshport")) ?: return@tool fail("SSH 포트는 1~65535 예요")
            val max = i.int("max")?.takeIf { it in 1..100 } ?: return@tool fail("실패 허용 횟수는 1~100 이에요"); val find = i.int("find")?.takeIf { it in 1..10080 } ?: return@tool fail("감시 시간은 1~10080분이에요"); val ban = i.int("ban")?.takeIf { it in 1..525600 } ?: return@tool fail("차단 시간은 1~525600분이에요")
            val ignore = list(i.raw("ignore"), ", ;").map { Valid.ipOrCidr(it) ?: return@tool fail("예외 IP 형식이 이상해요: $it") }
            val act = listOf("nftables-multiport", "iptables-multiport", "ufw", "")[i.choice("act", F2B_ACT)]
            val cfg = MakeCfg.fail2ban(MakeCfg.Fail2ban(jails, sp, max, find, ban, ignore, act, i.choice("sshbk", F2B_SSHBK) == 0, i.choice("inc", F2B_INC) == 0))
            result {
                head("/etc/fail2ban/jail.local"); block(cfg)
                head("적용·확인"); block("sudo apt install fail2ban\nsudo cp jail.local /etc/fail2ban/jail.local\nsudo fail2ban-client -t            # 설정 시험\nsudo systemctl restart fail2ban\nsudo fail2ban-client status ${jails.first()}\nsudo fail2ban-client set ${jails.first()} unbanip 203.0.113.7   # 실수로 막힌 IP 풀기")
                if (ignore.isEmpty()) note("예외 IP 를 하나도 적지 않았어요. 내 IP 로 실수하면 내가 막혀요. 내 집·사무실 IP 를 넣어 두세요.", 1)
                if (max <= 2) note("허용 횟수가 너무 낮으면 비밀번호를 한두 번 틀린 것만으로 막혀요.", 1)
                note("fail2ban 은 \"로그에 남은 실패\"를 보고 막아요. 비밀번호 로그인을 아예 끄고 공개키만 쓰면(SSH 강화 도구) 더 확실해요.", 0)
            }
        },
        // 13
        tool("make_haproxy", G, "HAProxy 로드밸런서 설정 만들기 (웹·TCP, 상태 검사·TLS·속도 제한)", "여러 서버로 요청을 나눠 주는 haproxy.cfg 를 만들어요: HTTP/TCP 모드, 분배 방식, 상태 검사, TLS 종료와 HTTP→HTTPS 리다이렉트, IP 별 요청 속도 제한, 내부 상태 페이지",
            listOf(choice("mode", "방식", HA_MODE), text("port", "받을 포트", "", "80"), multi("srv", "뒤쪽 서버 (줄마다 하나)", "host:port 또는 host:port,가중치 (IPv6 는 [::1]:80)", "10.0.0.11:8080\n10.0.0.12:8080,2"), choice("bal", "분배 방식", HA_BAL), text("path", "상태 검사 주소 (HTTP)", "비우면 검사 안 함", "/health"), text("maxconn", "동시 연결 수 한도", "", "4096"),
                text("crt", "TLS 인증서 파일 경로 (선택, HTTP)", "키와 인증서를 합친 PEM. 적으면 TLS 로 받아요. 예: /etc/haproxy/certs/site.pem"), choice("redir", "80번으로 오면 HTTPS 로 보내기 (TLS 사용 시)", YES_NO), text("stats", "상태 페이지 비밀번호 (선택)", "적으면 127.0.0.1:8404/stats 를 열어요 (8글자 이상)"), text("rate", "IP 당 10초간 요청 한도 (HTTP, 0=없음)", "", "100"), choice("user", "haproxy 계정으로 실행", HA_USER)), ToolMode.OFFLINE, LOCAL, runLabel = "만들기") { i, _, _ ->
            val tcp = i.choice("mode", HA_MODE) == 1; val port = Valid.port(i.str("port")) ?: return@tool fail("받을 포트는 1~65535 예요")
            val servers = lineList(i.raw("srv")).map { line ->
                val hp = hostPort(line.substringBefore(',')) ?: return@tool fail("서버는 \"host:port\" 또는 \"host:port,가중치\" 형식이어야 해요: $line")
                val wgt = if (line.contains(',')) line.substringAfter(',').trim().toIntOrNull()?.takeIf { it in 0..256 } ?: return@tool fail("가중치는 0~256 이에요: $line") else 1
                MakeCfg.HaServer(hp.first, hp.second, wgt)
            }
            if (servers.isEmpty()) return@tool need("뒤쪽 서버를 하나 이상 적어 주세요")
            val path = i.str("path"); if (path.isNotEmpty() && (!path.startsWith("/") || path.any { it.isWhitespace() || it.isISOControl() })) return@tool fail("상태 검사 주소는 /health 처럼 /로 시작하고 공백이 없어야 해요")
            val mc = i.int("maxconn")?.takeIf { it in 1..1_000_000 } ?: return@tool fail("동시 연결 수는 1~1000000 이에요)")
            val crt = i.str("crt"); if (crt.isNotEmpty() && (!crt.startsWith("/") || crt.any { it.isWhitespace() || it.isISOControl() })) return@tool fail("인증서 경로는 /etc/… 처럼 절대 경로이고 공백이 없어야 해요")
            val stats = i.str("stats"); if (stats.isNotEmpty() && (stats.length < 8 || stats.any { it.isWhitespace() || it == ':' || it.code !in 33..126 })) return@tool fail("상태 페이지 비밀번호는 공백·콜론 없는 8글자 이상(영문·숫자·기호)이어야 해요")
            val rate = i.int("rate")?.takeIf { it in 0..100000 } ?: return@tool fail("요청 한도는 0~100000 이에요")
            val cfg = MakeCfg.haproxy(MakeCfg.Haproxy(tcp, port, servers, HA_BAL[i.choice("bal", HA_BAL)], path, mc, crt, i.choice("redir", YES_NO) == 0, stats, rate, i.choice("user", HA_USER) == 0))
            result {
                head("/etc/haproxy/haproxy.cfg"); block(cfg)
                head("적용·확인"); block("sudo cp haproxy.cfg /etc/haproxy/haproxy.cfg\nsudo haproxy -c -f /etc/haproxy/haproxy.cfg   # 문법 확인\nsudo systemctl reload haproxy\n" + if (stats.isNotEmpty()) "curl -u admin:비밀번호 http://127.0.0.1:8404/stats" else "")
                if (tcp && (path.isNotEmpty() || crt.isNotEmpty() || rate > 0)) note("TCP 모드에서는 HTTP 상태 검사·TLS 종료·요청 속도 제한 설정을 쓰지 않아요(무시했어요).", 0)
                if (!tcp && crt.isNotEmpty()) note("인증서 파일은 개인키와 인증서를 이어 붙인 PEM 이어야 해요: cat site.crt site.key > site.pem (권한 600).", 0)
                if (!tcp && path.isEmpty()) note("상태 검사를 안 하면 죽은 서버로도 요청을 보내요. /health 같은 주소가 있으면 꼭 쓰세요.", 1)
                note("서버가 1대뿐이면 로드밸런서는 장애 지점만 하나 늘려요. 2대 이상일 때 쓰세요.", 0)
            }
        },
        // 14
        tool("make_sshd_harden", G, "sshd 보안 강화 설정 만들기 (sshd_config)", "SSH 서버 설정을 안전하게 만들어요: 루트 로그인·비밀번호 로그인 끄기, 접속 허용 사용자, 인증 시도 횟수, 포워딩 제한, 최신 암호 알고리즘만 쓰기",
            listOf(text("port", "포트", "", "22"), choice("root", "루트 로그인", SSHD_ROOT), choice("pw", "비밀번호 로그인", SSHD_PW), text("users", "접속을 허용할 사용자 (선택)", "공백·쉼표로 구분. 비우면 모든 사용자. 예: alice bob"), text("tries", "인증 시도 한도", "", "3"), choice("fwd", "포트 포워딩(터널)", ALLOW), choice("x11", "X11 포워딩", ALLOW),
                choice("cr", "암호 알고리즘", SSHD_CRYPTO), text("alive", "유휴 연결 확인 간격 (초, 0=끄기)", "", "300")), ToolMode.OFFLINE, LOCAL, runLabel = "만들기") { i, _, _ ->
            val port = Valid.port(i.str("port")) ?: return@tool fail("포트는 1~65535 예요")
            val users = list(i.raw("users"), ", ;").onEach { if (!Regex("^[A-Za-z_][A-Za-z0-9_.-]{0,31}(@[0-9A-Za-z.*:/_-]{1,60})?$").matches(it)) return@tool fail("사용자 이름 형식이 이상해요: $it") }
            val tries = i.int("tries")?.takeIf { it in 1..10 } ?: return@tool fail("인증 시도 한도는 1~10 이에요"); val alive = i.int("alive")?.takeIf { it in 0..3600 } ?: return@tool fail("유휴 확인 간격은 0~3600초예요")
            val pwOn = i.choice("pw", SSHD_PW) == 1
            val cfg = MakeCfg.sshd(MakeCfg.Sshd(port, listOf("no", "prohibit-password")[i.choice("root", SSHD_ROOT)], pwOn, users, tries, i.choice("fwd", ALLOW) == 1, i.choice("x11", ALLOW) == 1, i.choice("cr", SSHD_CRYPTO) == 0, alive))
            result {
                head("/etc/ssh/sshd_config.d/99-hardening.conf"); block(cfg)
                head("적용 순서 (잠기지 않게)"); block("sudo cp 99-hardening.conf /etc/ssh/sshd_config.d/99-hardening.conf\nsudo sshd -t                      # 문법 확인 (아무 말 없으면 정상)\nsudo systemctl reload ssh          # RHEL: sshd\n# 지금 연결은 끊지 말고, 새 터미널에서 접속이 되는지 확인한 뒤에 닫으세요")
                if (!pwOn) note("비밀번호 로그인을 껐어요. 서버에 내 공개키가 등록돼 있고 키로 접속되는지 먼저 새 창에서 확인하세요. 안 되면 영영 못 들어와요.", 2)
                if (port != 22) note("포트를 ${port}번으로 바꿨어요. 방화벽에서 ${port}/tcp 를 먼저 열고, 접속할 때 -p $port 를 쓰세요. 포트 변경은 자동 스캔을 줄일 뿐 보안 대책은 아니에요.", 1)
                if (users.isNotEmpty()) note("AllowUsers 를 쓰면 목록에 없는 사용자는 올바른 키가 있어도 접속할 수 없어요.", 1)
                note("sshd_config.d 폴더는 OpenSSH 8.2+(Ubuntu 20.04+)에서 쓸 수 있어요. 더 오래된 시스템은 /etc/ssh/sshd_config 맨 위에 붙이세요(먼저 읽힌 값이 이겨요).", 0)
                note("\"최신 알고리즘만\"을 고르면 아주 오래된 SSH 클라이언트(예전 PuTTY·구형 장비)는 접속하지 못해요.", 0)
            }
        },
    )
}
