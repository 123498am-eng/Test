package com.selfcheck.app

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

/** 계산·사전·설정 만들기·명령어 도구 시험 (손으로 계산한 정답과 비교) */
class NetToolboxCalcTest {
    private fun run(id: String, vararg kv: Pair<String, String>): ToolResult {
        val t = requireNotNull(NetToolbox.byId(id)) { "도구 없음: $id" }
        return t.run(ToolInput(mapOf(*kv)), NoHost, ToolEnv())
    }
    private fun ToolResult.kv(label: String): String = (outs.firstOrNull { it is Out.Kv && it.label == label } as? Out.Kv)?.value ?: error("'$label' 줄이 없음:\n${text()}")
    private fun ToolResult.blocks(): List<String> = outs.filterIsInstance<Out.Block>().map { it.text }
    private fun ToolResult.rows(): List<List<String>> = outs.filterIsInstance<Out.Cols>().filter { !it.header }.map { it.cells }

    // ---------------------------------------------------------------- 속도·용량
    @Test fun downloadAndBandwidth() {
        val d = run("download_time", "size" to "4.7", "su" to "GB", "speed" to "500", "pu" to "Mbps", "eff" to "90")
        assertEquals("1분 24초", d.kv("걸리는 시간")); assertTrue(d.kv("실제 속도").startsWith("450.00 Mbps"))
        assertEquals("1.00 Gbps".let { "1분 24초" }, d.kv("걸리는 시간"))
        val b = run("bandwidth_needed", "size" to "50", "su" to "GB", "time" to "30", "tu" to "분", "eff" to "90")
        assertEquals("246.91 Mbps", b.kv("필요한 속도")); assertEquals("30.86 MB/s", b.kv("바이트 속도로"))
        assertTrue(run("download_time", "size" to "-1", "su" to "GB", "speed" to "1", "pu" to "Mbps", "eff" to "90").hasError)
    }

    @Test fun bdpAndThroughputAndMtu() {
        val b = run("bdp", "bw" to "1000", "rtt" to "40")
        assertTrue(b.kv("BDP").startsWith("5,000,000바이트")); assertTrue(b.kv("윈도 스케일 없이 최대 속도").startsWith("13.11 Mbps"))
        assertTrue(run("tcp_throughput", "mss" to "1460", "rtt" to "30", "loss" to "0.1", "link" to "500").kv("이론 최대 처리량").startsWith("15.02 Mbps"))
        assertTrue(run("tcp_throughput", "mss" to "1460", "rtt" to "30", "loss" to "0", "link" to "").hasError)
        val m = run("mtu_mss", "mtu" to "1500", "ip" to "IPv4", "tun" to "없음", "ts" to "끔")
        assertEquals("1460", m.kv("TCP MSS")); assertEquals("94.9%", m.kv("TCP 효율(이더넷 기준)")); assertEquals("949 Mbps", m.kv("1Gbps 에서 최대 TCP 속도"))
        assertEquals("1400", run("mtu_mss", "mtu" to "1500", "ip" to "IPv4", "tun" to "WireGuard IPv4 (60)", "ts" to "끔").kv("TCP MSS"))
        assertEquals("1452", run("mtu_mss", "mtu" to "1500", "ip" to "IPv4", "tun" to "PPPoE (8)", "ts" to "끔").kv("TCP MSS"))
        assertEquals("1440", run("mtu_mss", "mtu" to "1500", "ip" to "IPv6", "tun" to "없음", "ts" to "끔").kv("TCP MSS")); assertEquals("1448", run("mtu_mss", "mtu" to "1500", "ip" to "IPv4", "tun" to "없음", "ts" to "켬 (12바이트)").kv("TCP MSS"))
    }

    @Test fun slaVoipAndDistance() {
        val s = run("uptime_sla", "p" to "99.9").rows()
        assertEquals(listOf("1년", "8시간 45분 36초"), s[0]); assertEquals(listOf("1개월(30일)", "43분 12초"), s[1])
        assertTrue(s.any { it[0] == "99.99%" && it[1] == "52분 34초" })
        val v = run("voip_bandwidth", "codec" to "G.711 (64 kbps)", "n" to "20", "eth" to "포함 (18바이트)")
        assertEquals("87.2 kbps", v.kv("통화 1개(한 방향)")); assertEquals("1.74 Mbps", v.kv("20통화 한 방향"))
        assertEquals("31.2 kbps", run("voip_bandwidth", "codec" to "G.729 (8 kbps)", "n" to "1", "eth" to "포함 (18바이트)").kv("통화 1개(한 방향)"))
        val l = run("latency_distance", "rtt" to "10", "km" to "9000"); assertTrue(l.kv("RTT 10.0ms 면").contains("1,000km")); assertTrue(l.kv("9,000km 거리면").contains("90.0ms"))
    }

    @Test fun pingStatsHandlesLinuxAndKoreanWindows() {
        val r = run("ping_stats", "t" to "64 bytes from 8.8.8.8: icmp_seq=1 ttl=117 time=23.4 ms\n64 bytes from 8.8.8.8: icmp_seq=2 ttl=117 time=24.1 ms\nRequest timeout for icmp_seq 3\n64 bytes from 8.8.8.8: icmp_seq=4 ttl=117 time=22.9 ms\n64 bytes from 8.8.8.8: icmp_seq=5 ttl=117 time=45.0 ms")
        assertEquals("5", r.kv("보낸 횟수")); assertEquals("4", r.kv("받은 횟수")); assertEquals("20.0%", r.kv("손실")); assertEquals("22.9 ms", r.kv("최소")); assertEquals("45.0 ms", r.kv("최대")); assertEquals("8.0 ms", r.kv("지터(연속 차이 평균)"))
        val k = run("ping_stats", "t" to "8.8.8.8의 응답: 바이트=32 시간=23ms TTL=117\n8.8.8.8의 응답: 바이트=32 시간<1ms TTL=117\n요청 시간이 만료되었습니다.\n8.8.8.8의 응답: 바이트=32 시간=25ms TTL=117")
        assertEquals("4", k.kv("보낸 횟수")); assertEquals("3", k.kv("받은 횟수")); assertEquals("25.0%", k.kv("손실")); assertEquals("1.0 ms", k.kv("최소"))
        assertTrue(run("ping_stats", "t" to "아무 글").hasError)
        val st = PingStats.of(listOf(10.0, 12.0, 11.0), 0); assertEquals(0.0, st.lossPercent, 0.0); assertEquals(11.0, st.median, 0.0); assertTrue(st.verdict().contains("좋아요"))
    }

    @Test fun videoAndUtilizationAndDataUsage() {
        assertEquals("8.0 Mbps", run("video_bitrate", "res" to "1080p 30fps", "codec" to "H.264").kv("권장 비트레이트")); assertEquals("4.8 Mbps", run("video_bitrate", "res" to "1080p 30fps", "codec" to "H.265 (HEVC)").kv("권장 비트레이트"))
        assertEquals("84.0%", run("link_util", "used" to "420", "cap" to "500").kv("사용률")); assertTrue(run("link_util", "used" to "1", "cap" to "0").hasError)
        val u = run("data_usage", "act" to "유튜브 1080p", "h" to "2", "d" to "30"); assertEquals("2.25 GB", u.kv("1시간")); assertEquals("4.50 GB", u.kv("하루")); assertEquals("135.0 GB", u.kv("한 달"))
    }

    // ---------------------------------------------------------------- 무선
    @Test fun wifiCalculators() {
        assertEquals("100", run("dbm_mw", "v" to "20", "u" to "dBm").kv("mW")); assertEquals("30.00", run("dbm_mw", "v" to "1", "u" to "W").kv("dBm")); assertEquals("0.00", run("dbm_mw", "v" to "1", "u" to "mW").kv("dBm"))
        assertEquals("보통", run("wifi_signal_quality", "dbm" to "-62").kv("품질")); assertEquals("매우 좋음", run("wifi_signal_quality", "dbm" to "-45").kv("품질")); assertEquals("거의 안 됨", run("wifi_signal_quality", "dbm" to "-85").kv("품질")); assertTrue(run("wifi_signal_quality", "dbm" to "60").hasError)
        val f = run("fspl", "d" to "30", "du" to "m", "f" to "2.4", "fu" to "GHz", "tx" to "20", "g" to "2")
        assertEquals("69.6 dB", f.kv("경로 손실")); assertEquals("-47.6 dBm", f.kv("받는 세기(이론)"))
        assertEquals("31 m", run("wifi_range", "tx" to "20", "g" to "4", "band" to "5 GHz", "walls" to "2", "need" to "-67").kv("이론상 도달 거리"))
        assertEquals("32.0 dB", run("snr", "sig" to "-60", "noise" to "-92").kv("SNR")); assertTrue(run("snr", "sig" to "-60", "noise" to "-92").kv("품질").startsWith("좋음"))
        assertEquals(5180, WifiChan.toFreq("5 GHz", 36)); assertEquals(2437, WifiChan.toFreq("2.4 GHz", 6)); assertEquals(2484, WifiChan.toFreq("2.4 GHz", 14)); assertEquals(5955, WifiChan.toFreq("6 GHz", 1)); assertEquals(null, WifiChan.toFreq("2.4 GHz", 15))
        assertEquals(6 to "2.4 GHz", WifiChan.fromFreq(2437)); assertEquals(36 to "5 GHz", WifiChan.fromFreq(5180)); assertEquals(1 to "6 GHz", WifiChan.fromFreq(5955)); assertEquals(14 to "2.4 GHz", WifiChan.fromFreq(2484)); assertEquals(null, WifiChan.fromFreq(3000))
        assertEquals("5180 MHz", run("channel_freq", "band" to "5 GHz", "v" to "36").kv("중심 주파수")); assertEquals("6", run("channel_freq", "band" to "5 GHz", "v" to "2437").kv("채널")); assertTrue(run("channel_freq", "band" to "2.4 GHz", "v" to "36").hasError)
        assertEquals(13, run("wifi_channels", "band" to "2.4 GHz").rows().size)
    }

    // ---------------------------------------------------------------- 사전은 표가 어긋나지 않아야 함
    @Test fun referenceTablesAreWellFormed() {
        for (t in NetToolbox.ALL.filter { it.group == NetGroups.REF || it.group == NetGroups.CMD }) {
            val r = t.run(ToolInput(emptyMap()), NoHost, ToolEnv())
            val header = r.outs.filterIsInstance<Out.Cols>().firstOrNull { it.header }
            if (header != null) for (row in r.outs.filterIsInstance<Out.Cols>().filter { !it.header }) assertEquals("${t.id}: ${row.cells}", header.cells.size, row.cells.size)
            assertTrue("${t.id}: 비었음", r.outs.isNotEmpty())
        }
        val ports = RefTools.PORTS.map { it[0].toInt() }
        assertTrue(ports.all { it in 1..65535 }); assertEquals("포트 번호 중복", ports.size, ports.toSet().size); assertTrue(ports.size >= 100)
    }

    @Test fun referenceSearch() {
        val r = run("ref_ports", "q" to "443").rows(); assertTrue(r.any { it[0] == "443" && it[2].startsWith("HTTPS") })
        assertTrue(run("ref_ports", "q" to "ssh").rows().any { it[0] == "22" }); assertTrue(run("ref_ports", "q" to "zzzz없음").hasError.not() && run("ref_ports", "q" to "zzzz없음").text().contains("맞는 항목이 없어요"))
        assertTrue(run("ref_http_status", "q" to "404").rows().any { it[1] == "Not Found" }); assertTrue(run("ref_http_status", "q" to "").rows().size > 60)
        assertTrue(run("ref_dns_types", "q" to "MX").rows().any { it[1] == "MX" }); assertTrue(run("ref_glossary", "q" to "cgnat").rows().isNotEmpty())
        assertTrue(run("ref_special_ranges").rows().any { it[0] == "100.64.0.0/10" }); assertEquals(7, run("ref_osi").rows().size)
        assertTrue(run("ref_public_dns").rows().any { it[1].startsWith("168.126.63.1") })
    }

    // ---------------------------------------------------------------- 설정 만들기
    @Test fun firewallGenerators() {
        assertEquals("sudo iptables -A INPUT -p tcp --dport 22 -m comment --comment 'ssh' -j ACCEPT", run("fw_iptables", "chain" to "INPUT (들어오는)", "act" to "ACCEPT (허용)", "proto" to "tcp", "ports" to "22", "src" to "", "cm" to "ssh").blocks()[0])
        assertEquals("sudo iptables -A INPUT -p tcp -m multiport --dports 80,443,8000:8100 -s 192.168.0.0/24 -m comment --comment 'x y' -j DROP",
            run("fw_iptables", "chain" to "INPUT (들어오는)", "act" to "DROP (조용히 차단)", "proto" to "tcp", "ports" to "80,443,8000-8100", "src" to "192.168.0.0/24", "cm" to "x y").blocks()[0])
        assertEquals("sudo iptables -A INPUT -p icmp --icmp-type echo-request -j ACCEPT", run("fw_iptables", "chain" to "INPUT (들어오는)", "act" to "ACCEPT (허용)", "proto" to "icmp", "ports" to "", "src" to "", "cm" to "").blocks()[0])
        assertTrue(run("fw_iptables", "chain" to "INPUT (들어오는)", "act" to "ACCEPT (허용)", "proto" to "tcp", "ports" to "99999", "src" to "", "cm" to "").hasError)
        assertTrue(run("fw_iptables", "chain" to "INPUT (들어오는)", "act" to "ACCEPT (허용)", "proto" to "tcp", "ports" to "22", "src" to "300.1.1.1/24", "cm" to "").hasError)
        assertEquals("sudo ufw allow 443/tcp comment 'web'", run("fw_ufw", "act" to "allow (허용)", "proto" to "tcp", "ports" to "443", "src" to "", "cm" to "web").blocks()[0])
        assertEquals("sudo ufw allow from 192.168.0.0/24 to any port 22 proto tcp", run("fw_ufw", "act" to "allow (허용)", "proto" to "tcp", "ports" to "22", "src" to "192.168.0.0/24", "cm" to "").blocks()[0])
        assertEquals("sudo ufw deny 80,443/tcp", run("fw_ufw", "act" to "deny (차단)", "proto" to "tcp", "ports" to "80,443", "src" to "", "cm" to "").blocks()[0]); assertTrue(run("fw_ufw", "act" to "allow (허용)", "proto" to "모두", "ports" to "80,443", "src" to "", "cm" to "").hasError)
        assertEquals("netsh advfirewall firewall add rule name=\"RDP from office\" dir=in action=allow protocol=TCP localport=3389 remoteip=192.168.0.0/24",
            run("fw_windows", "name" to "RDP from office", "dir" to "in (들어오는)", "act" to "allow (허용)", "proto" to "TCP", "ports" to "3389", "remote" to "192.168.0.0/24").blocks()[0])
        assertEquals("ip access-list extended ACL-IN\n permit tcp 192.168.10.0 0.0.0.255 any eq 80\n permit tcp 192.168.10.0 0.0.0.255 any eq 443", run("acl_cisco", "name" to "ACL-IN", "act" to "permit", "proto" to "tcp", "src" to "192.168.10.0/24", "dst" to "any", "ports" to "80,443").blocks()[0])
        assertEquals("ip access-list extended X\n deny tcp any host 10.0.0.5 range 8000 8100", run("acl_cisco", "name" to "X", "act" to "deny", "proto" to "tcp", "src" to "any", "dst" to "10.0.0.5/32", "ports" to "8000-8100").blocks()[0])
    }

    @Test fun serverConfigGenerators() {
        val n = run("nginx_redirect", "d" to "www.example.com", "www" to "www 를 없앰").blocks()[0]
        assertTrue(n.contains("server_name example.com www.example.com;")); assertTrue(n.contains("return 301 https://example.com\$request_uri;")); assertTrue(n.contains("server_name www.example.com;"))
        assertTrue(run("nginx_headers", "hsts" to "1년 + 하위 도메인", "csp" to "넣음 (default-src 'self')").blocks()[0].contains("includeSubDomains")); assertFalse(run("nginx_headers", "hsts" to "끔 (처음 시험할 때)", "csp" to "넣지 않음").blocks()[0].contains("Strict-Transport"))
        assertTrue(run("apache_htaccess", "https" to "켬").blocks()[0].contains("RewriteRule ^(.*)\$ https://%{HTTP_HOST}%{REQUEST_URI} [L,R=301]"))
        val z = run("dns_zone", "d" to "example.com", "ip4" to "203.0.113.10", "ip6" to "2001:db8::10", "mx" to "mail.example.com", "ttl" to "3600").blocks()[0]
        assertTrue(z.contains("@        IN A     203.0.113.10")); assertTrue(z.contains("@        IN AAAA  2001:db8::10")); assertTrue(z.contains("10 mail.example.com.")); assertTrue(z.contains("0 issue"))
        val d = run("dhcp_conf", "net" to "192.168.10.0/24", "range" to "100-200", "gw" to "", "dns" to "1.1.1.1,8.8.8.8", "lease" to "12h", "fix" to "aa:bb:cc:dd:ee:ff=192.168.10.50=printer").blocks()
        assertTrue(d[0].contains("dhcp-range=192.168.10.100,192.168.10.200,255.255.255.0,12h")); assertTrue(d[0].contains("option:router,192.168.10.1")); assertTrue(d[0].contains("dhcp-host=aa:bb:cc:dd:ee:ff,192.168.10.50,printer"))
        assertTrue(d[1].contains("subnet 192.168.10.0 netmask 255.255.255.0")); assertTrue(d[1].contains("default-lease-time 43200;")); assertTrue(run("dhcp_conf", "net" to "192.168.10.0/24", "range" to "100-300", "gw" to "", "dns" to "1.1.1.1", "lease" to "12h", "fix" to "").hasError)
        assertEquals("192.168.0.20\tnas nas.local", run("hosts_entry", "ip" to "192.168.0.20", "names" to "nas nas.local").blocks()[0])
        val ssh = run("ssh_config", "alias" to "myserver", "host" to "203.0.113.10", "user" to "ubuntu", "port" to "2222", "key" to "~/.ssh/id_ed25519", "jump" to "bastion").blocks()[0]
        assertTrue(ssh.startsWith("Host myserver\n    HostName 203.0.113.10\n    User ubuntu\n    Port 2222")); assertTrue(ssh.contains("ProxyJump bastion"))
        val wg = run("wg_config", "net" to "10.8.0.0/24", "port" to "51820", "endpoint" to "vpn.example.com", "dns" to "1.1.1.1").blocks()
        assertTrue(wg[1].contains("Address = 10.8.0.1/24")); assertTrue(wg[2].contains("Address = 10.8.0.2/24")); assertTrue(wg[2].contains("Endpoint = vpn.example.com:51820")); assertTrue(wg[1].contains("AllowedIPs = 10.8.0.2/32"))
    }

    @Test fun mailRecordBuilders() {
        val s = run("spf_builder", "d" to "example.com", "mx" to "예", "a" to "아니요", "inc" to "_spf.google.com", "ip" to "", "pol" to "-all (거부, 권장)")
        assertEquals("v=spf1 mx include:_spf.google.com -all", s.blocks()[0]); assertEquals("2 / 10", s.kv("DNS 조회 횟수(대략)"))
        assertEquals("v=spf1 ip4:203.0.113.0/24 ip6:2001:db8::/32 ~all", run("spf_builder", "d" to "example.com", "mx" to "아니요", "a" to "아니요", "inc" to "", "ip" to "203.0.113.0/24, 2001:db8::/32", "pol" to "~all (의심 표시)").blocks()[0])
        assertTrue(run("spf_builder", "d" to "example.com", "mx" to "예", "a" to "예", "inc" to (1..9).joinToString(",") { "s$it.example.net" }, "ip" to "", "pol" to "-all (거부, 권장)").hasError)
        assertTrue(run("spf_builder", "d" to "example.com", "mx" to "예", "a" to "아니요", "inc" to "", "ip" to "999.1.1.1", "pol" to "-all (거부, 권장)").hasError)
        val dm = run("dmarc_builder", "d" to "example.com", "p" to "quarantine (스팸함)", "pct" to "50", "rua" to "dmarc@example.com", "al" to "strict (엄격)")
        assertEquals("v=DMARC1; p=quarantine; pct=50; rua=mailto:dmarc@example.com; adkim=s; aspf=s", dm.blocks()[0]); assertEquals("_dmarc.example.com", dm.kv("호스트 이름")); assertTrue(run("dmarc_builder", "d" to "example.com", "p" to "none (감시만)", "pct" to "200", "rua" to "", "al" to "relaxed (느슨)").hasError)
    }

    @Test fun commandGenerators() {
        assertEquals("curl -H 'Content-Type: application/json' 'https://api.example.com/items'", run("curl_cmd", "m" to "GET", "u" to "https://api.example.com/items", "h" to "Content-Type: application/json", "b" to "", "o" to "기본").blocks()[0])
        assertEquals("curl -X POST -H 'Content-Type: application/json' --data '{\"name\":\"it'\\''s\"}' 'https://api.example.com/items'", run("curl_cmd", "m" to "POST", "u" to "https://api.example.com/items", "h" to "Content-Type: application/json", "b" to "{\"name\":\"it's\"}", "o" to "기본").blocks()[0])
        assertTrue(run("curl_cmd", "m" to "HEAD", "u" to "https://x.com", "h" to "", "b" to "", "o" to "인증서 검사 끔(-k)").hasError); assertTrue(run("curl_cmd", "m" to "GET", "u" to "https://x.com", "h" to "", "b" to "", "o" to "응답 시간 보기").blocks()[0].contains("%{time_total}s"))
        assertEquals("ping -c 10 example.com", run("diag_cmd", "t" to "핑", "os" to "리눅스", "h" to "example.com", "p" to "443").blocks()[0]); assertTrue(run("diag_cmd", "t" to "핑", "os" to "윈도", "h" to "example.com", "p" to "443").blocks()[0].startsWith("ping -n 10 example.com"))
        assertTrue(run("diag_cmd", "t" to "포트 열림 확인", "os" to "윈도", "h" to "example.com", "p" to "8443").blocks()[0].contains("Test-NetConnection example.com -Port 8443")); assertTrue(run("diag_cmd", "t" to "포트 열림 확인", "os" to "맥", "h" to "example.com", "p" to "22").blocks()[0].startsWith("nc -vz example.com 22"))
        assertTrue(run("diag_cmd", "t" to "핑", "os" to "리눅스", "h" to "bad host!", "p" to "1").hasError)
        val g = run("port_forward_guide", "name" to "NAS 웹", "ip" to "192.168.0.20", "port" to "443", "proto" to "TCP").text()
        assertTrue(g.contains("192.168.0.1")); assertTrue(g.contains("외부 포트 443")); assertTrue(run("port_forward_guide", "name" to "x", "ip" to "8.8.8.8", "port" to "443", "proto" to "TCP").hasError)
    }

    @Test fun parsePortsAndQuoting() {
        val p = GenTools.parsePorts("80, 443 8000-8100;9000:9005")!!; assertEquals(listOf(80, 443), p.singles); assertEquals(listOf(8000 to 8100, 9000 to 9005), p.ranges); assertEquals("80,443,8000:8100,9000:9005", p.joined(":")); assertEquals("80,443,8000-8100,9000-9005", p.joined("-"))
        assertEquals(null, GenTools.parsePorts("0")); assertEquals(null, GenTools.parsePorts("100-50")); assertEquals(null, GenTools.parsePorts("abc")); assertEquals("'it'\\''s'", GenTools.sh("it's"))
    }

    @Test fun registryHasOverOneHundredTools() {
        val n = NetToolbox.ALL.size
        assertTrue("도구 수 $n", n >= 100)
        val byGroup = NetToolbox.ALL.groupingBy { it.group }.eachCount()
        for ((g, c) in byGroup) assertTrue("$g 묶음이 너무 작음($c)", c >= 5)
        System.out.println("도구 수: $n, 묶음별: $byGroup")
    }
}
