package com.selfcheck.app

/** 설정·명령 만들기 16가지 + 점검 순서·명령어 모음 10가지 (모두 오프라인, 글만 만들어 줘요) */
object GenTools {
    private const val G = NetGroups.GEN
    private const val K = NetGroups.CMD

    /** 포트 선택: "22", "80,443", "8000-8100" */
    class PortSel(val singles: List<Int>, val ranges: List<Pair<Int, Int>>) {
        val isEmpty get() = singles.isEmpty() && ranges.isEmpty()
        /** 쉼표로 이은 글. rangeSep: 범위 구분자 (iptables/ufw ':', netsh '-') */
        fun joined(rangeSep: String): String = (singles.map { it.toString() } + ranges.map { "${it.first}$rangeSep${it.second}" }).joinToString(",")
        val count get() = singles.size + ranges.size
    }

    internal fun parsePorts(s: String): PortSel? {
        val singles = ArrayList<Int>(); val ranges = ArrayList<Pair<Int, Int>>()
        for (tok in s.split(',', ' ', ';').map { it.trim() }.filter { it.isNotEmpty() }) {
            val sep = tok.indexOfFirst { it == '-' || it == ':' }
            if (sep < 0) { val p = tok.toIntOrNull()?.takeIf { it in 1..65535 } ?: return null; singles += p }
            else {
                val a = tok.substring(0, sep).toIntOrNull()?.takeIf { it in 1..65535 } ?: return null
                val b = tok.substring(sep + 1).toIntOrNull()?.takeIf { it in 1..65535 } ?: return null
                if (a > b) return null
                ranges += a to b
            }
        }
        return PortSel(singles, ranges)
    }

    internal fun sh(s: String) = "'" + s.replace("'", "'\\''") + "'"

    private val BAD_PORTS = "포트를 읽지 못했어요. 예: 22 · 80,443 · 8000-8100"
    private fun cidrOk(s: String): Boolean = s.isEmpty() || Cidr4.parse(s) != null || V6.parseCidr(s) != null

    private val PROTO = listOf("tcp", "udp", "icmp", "모두")

    val ALL: List<NetTool> = listOf(
        calc("fw_iptables", G, "iptables 규칙 만들기", "리눅스 방화벽(iptables) 허용·차단 명령 만들기 (IPv6 용 명령도)",
            choice("chain", "방향", listOf("INPUT (들어오는)", "OUTPUT (나가는)", "FORWARD (지나가는)")), choice("act", "동작", listOf("ACCEPT (허용)", "DROP (조용히 차단)", "REJECT (거부 응답)")),
            choice("proto", "프로토콜", PROTO), text("ports", "포트 (TCP·UDP)", "예: 22, 80,443, 8000-8100", "22"), text("src", "출발지 (선택)", "예: 192.168.0.0/24", ""), text("cm", "설명 (선택)", "예: ssh", "ssh")) { i ->
            val chain = i.str("chain").substringBefore(' '); val act = i.str("act").substringBefore(' '); val proto = i.str("proto")
            val src = i.str("src"); if (!cidrOk(src)) return@calc fail("출발지는 IP 나 CIDR 로 입력하세요 (예: 192.168.0.0/24)")
            val v6 = src.contains(':'); val cmd = if (v6) "ip6tables" else "iptables"
            val sel = if (proto == "tcp" || proto == "udp") (parsePorts(i.str("ports")) ?: return@calc fail(BAD_PORTS)) else null
            if (sel != null && sel.isEmpty) return@calc need("포트를 입력하세요")
            val sb = StringBuilder("sudo $cmd -A $chain")
            if (proto != "모두") sb.append(" -p $proto")
            if (proto == "icmp") sb.append(if (v6) " --icmpv6-type echo-request" else " --icmp-type echo-request")
            if (sel != null) { if (sel.count == 1) sb.append(" --dport ${sel.joined(":")}") else sb.append(" -m multiport --dports ${sel.joined(":")}") }
            if (src.isNotEmpty()) sb.append(" -s $src")
            if (i.str("cm").isNotEmpty()) sb.append(" -m comment --comment ${sh(i.str("cm"))}")
            sb.append(" -j $act")
            if (proto == "icmp" && v6) sb.replace(0, sb.length, sb.toString().replace("-p icmp", "-p icmpv6"))
            result {
                block(sb.toString())
                head("함께 알아 두기")
                note("규칙은 위에서부터 차례로 검사해요. 맨 앞에 넣으려면 -A 대신 -I $chain 1 을 쓰세요.")
                note("원격(SSH)으로 접속 중이라면 SSH 허용 규칙을 먼저 넣고 차단 규칙을 넣으세요. 잘못하면 접속이 끊겨요.", 1)
                block("# 지금 규칙 보기\nsudo $cmd -L -n --line-numbers\n# 번호로 지우기\nsudo $cmd -D $chain 1\n# 재부팅 후에도 유지 (Debian·Ubuntu)\nsudo apt install iptables-persistent && sudo netfilter-persistent save")
            }
        },

        calc("fw_ufw", G, "ufw 규칙 만들기", "우분투 방화벽(ufw) 허용·차단 명령",
            choice("act", "동작", listOf("allow (허용)", "deny (차단)", "limit (접속 횟수 제한)")), choice("proto", "프로토콜", listOf("tcp", "udp", "모두")),
            text("ports", "포트", "예: 22, 80,443, 8000-8100", "443"), text("src", "출발지 (선택)", "예: 192.168.0.0/24", ""), text("cm", "설명 (선택)", "", "web")) { i ->
            val act = i.str("act").substringBefore(' '); val proto = i.str("proto"); val src = i.str("src")
            if (!cidrOk(src)) return@calc fail("출발지는 IP 나 CIDR 로 입력하세요")
            val sel = parsePorts(i.str("ports")) ?: return@calc fail(BAD_PORTS)
            if (sel.isEmpty) return@calc need("포트를 입력하세요")
            if (proto == "모두" && sel.count > 1) return@calc fail("여러 포트는 tcp 나 udp 를 골라야 해요")
            val ports = sel.joined(":")
            val sb = StringBuilder("sudo ufw $act")
            if (src.isNotEmpty()) { sb.append(" from $src to any port $ports"); if (proto != "모두") sb.append(" proto $proto") }
            else sb.append(" $ports").also { if (proto != "모두") sb.append("/$proto") }
            if (i.str("cm").isNotEmpty()) sb.append(" comment ${sh(i.str("cm"))}")
            result { block(sb.toString()); block("sudo ufw status numbered      # 규칙 보기\nsudo ufw delete 3            # 3번 규칙 삭제\nsudo ufw enable              # 켜기 (SSH 허용을 먼저!)\nsudo ufw default deny incoming"); note("ufw 를 켜기 전에 SSH(22) 허용 규칙이 있는지 꼭 확인하세요.", 1) }
        },

        calc("fw_windows", G, "윈도 방화벽 규칙 만들기", "netsh 명령으로 윈도 방화벽 인바운드·아웃바운드 규칙 추가",
            text("name", "규칙 이름", "", "RDP from office"), choice("dir", "방향", listOf("in (들어오는)", "out (나가는)")), choice("act", "동작", listOf("allow (허용)", "block (차단)")),
            choice("proto", "프로토콜", listOf("TCP", "UDP")), text("ports", "포트", "예: 3389 또는 8000-8100", "3389"), text("remote", "상대 IP (선택)", "예: 192.168.0.0/24", "192.168.0.0/24")) { i ->
            val name = i.str("name"); if (name.isEmpty()) return@calc need("규칙 이름을 입력하세요")
            val sel = parsePorts(i.str("ports")) ?: return@calc fail(BAD_PORTS); if (sel.isEmpty) return@calc need("포트를 입력하세요")
            val remote = i.str("remote"); if (!cidrOk(remote)) return@calc fail("상대 IP 는 IP 나 CIDR 로 입력하세요")
            val dir = i.str("dir").substringBefore(' '); val port = if (dir == "in") "localport" else "remoteport"
            val sb = StringBuilder("netsh advfirewall firewall add rule name=\"${name.replace("\"", "")}\" dir=$dir action=${i.str("act").substringBefore(' ')} protocol=${i.str("proto")} $port=${sel.joined("-")}")
            if (remote.isNotEmpty()) sb.append(" remoteip=$remote")
            result { block(sb.toString()); block("netsh advfirewall firewall show rule name=\"${name.replace("\"", "")}\"\nnetsh advfirewall firewall delete rule name=\"${name.replace("\"", "")}\""); note("관리자 권한 명령 프롬프트(또는 PowerShell)에서 실행하세요. 규칙 이름이 같으면 여러 개가 만들어지니 구분되게 지어 주세요."); if (dir == "in" && i.str("act").startsWith("block")) note("들어오는 연결을 막는 규칙이에요. 원격 데스크톱(3389)이나 원격 지원으로 접속 중인 PC 라면 접속이 끊길 수 있으니, 화면 앞에서 직접 적용하세요.", 1) }
        },

        calc("acl_cisco", G, "시스코 ACL 만들기", "확장 ACL 한 줄(들) — 와일드카드 마스크를 자동 계산",
            text("name", "ACL 이름", "", "ACL-IN"), choice("act", "동작", listOf("permit", "deny")), choice("proto", "프로토콜", listOf("tcp", "udp", "icmp", "ip")),
            text("src", "출발지", "any 또는 192.168.10.0/24", "192.168.10.0/24"), text("dst", "목적지", "any 또는 10.0.0.5/32", "any"), text("ports", "목적지 포트 (tcp·udp)", "예: 80,443 또는 8000-8100", "80,443")) { i ->
            fun addr(s: String): String? = if (s.equals("any", true) || s.isEmpty()) "any" else Cidr4.parse(s)?.let { c -> if (c.prefix == 32) "host ${IpUtil.v4Text(c.net)}" else "${IpUtil.v4Text(c.net)} ${IpUtil.v4Text(c.mask.inv() and 0xFFFFFFFFL)}" }
            val src = addr(i.str("src")) ?: return@calc fail("출발지를 읽지 못했어요 (any 또는 CIDR)"); val dst = addr(i.str("dst")) ?: return@calc fail("목적지를 읽지 못했어요 (any 또는 CIDR)")
            val proto = i.str("proto"); val act = i.str("act"); val name = i.str("name").ifEmpty { "ACL" }
            val lines = ArrayList<String>()
            if (proto == "tcp" || proto == "udp") {
                val sel = if (i.str("ports").isEmpty()) PortSel(emptyList(), emptyList()) else parsePorts(i.str("ports")) ?: return@calc fail(BAD_PORTS)
                if (sel.isEmpty) lines += " $act $proto $src $dst"
                else { for (p in sel.singles) lines += " $act $proto $src $dst eq $p"; for ((a, b) in sel.ranges) lines += " $act $proto $src $dst range $a $b" }
            } else lines += " $act $proto $src $dst"
            result {
                block("ip access-list extended $name\n" + lines.joinToString("\n"))
                note("ACL 맨 끝에는 보이지 않는 \"deny ip any any\" 가 있어서, 허용하지 않은 것은 모두 막혀요. 적용: interface 설정에서 ip access-group $name in (또는 out).")
                note("관리 접속(SSH·텔넷)을 허용하는 줄이 없는 ACL 을 적용하면 접속이 끊겨요. 콘솔로 접속할 수 있을 때 적용하세요.", 1)
            }
        },

        calc("nginx_redirect", G, "nginx 리다이렉트 설정", "HTTP → HTTPS, www → 주소창 정리 설정 조각",
            text("d", "도메인", "예: example.com", "example.com"), choice("www", "www 처리", listOf("www 를 없앰", "www 로 통일", "그대로 둠"))) { i ->
            val d = HostInput.host(i.str("d")).removePrefix("www."); if (d.isEmpty() || !HostInput.isPlausibleDomain(d)) return@calc need("도메인을 입력하세요 (예: example.com)")
            val w = i.choice("www", listOf("www 를 없앰", "www 로 통일", "그대로 둠"))
            val canon = if (w == 1) "www.$d" else d
            result {
                block(buildString {
                    appendLine("# 80 번: 모두 https 로 보냄")
                    appendLine("server {\n    listen 80;\n    listen [::]:80;\n    server_name $d www.$d;\n    return 301 https://$canon\$request_uri;\n}")
                    if (w != 2) appendLine("\n# 443 번: 대표 주소가 아닌 쪽을 대표 주소로 보냄\nserver {\n    listen 443 ssl http2;\n    listen [::]:443 ssl http2;\n    server_name ${if (w == 1) d else "www.$d"};\n    # ssl_certificate / ssl_certificate_key 는 기존 설정과 같게\n    return 301 https://$canon\$request_uri;\n}")
                }.trim())
                note("설정을 넣은 뒤에는 sudo nginx -t 로 문법을 확인하고 sudo systemctl reload nginx 로 적용하세요. 301 은 영구 이동이라 한번 퍼지면 되돌리기 어려우니 먼저 302 로 시험해 보는 것도 방법이에요.", 1)
            }
        },

        calc("nginx_headers", G, "nginx 보안 헤더 설정", "HSTS·nosniff·X-Frame-Options 등 보안 응답 헤더 한 묶음",
            choice("hsts", "HSTS", listOf("1년 + 하위 도메인", "1년", "끔 (처음 시험할 때)")), choice("csp", "CSP", listOf("넣음 (default-src 'self')", "넣지 않음"))) { i ->
            val hsts = i.choice("hsts", listOf("1년 + 하위 도메인", "1년", "끔 (처음 시험할 때)"))
            result {
                block(buildString {
                    appendLine("# server { } 블록 안에 넣으세요")
                    when (hsts) { 0 -> appendLine("add_header Strict-Transport-Security \"max-age=31536000; includeSubDomains\" always;"); 1 -> appendLine("add_header Strict-Transport-Security \"max-age=31536000\" always;") }
                    appendLine("add_header X-Content-Type-Options \"nosniff\" always;")
                    appendLine("add_header X-Frame-Options \"SAMEORIGIN\" always;")
                    appendLine("add_header Referrer-Policy \"strict-origin-when-cross-origin\" always;")
                    appendLine("add_header Permissions-Policy \"camera=(), microphone=(), geolocation=()\" always;")
                    if (i.choice("csp", listOf("넣음 (default-src 'self')", "넣지 않음")) == 0) appendLine("add_header Content-Security-Policy \"default-src 'self'\" always;")
                }.trim())
                note("HSTS 는 한 번 켜면 브라우저가 기간 동안 https 만 쓰게 돼서 인증서가 깨지면 접속이 막혀요. CSP 는 외부 스크립트·이미지를 막으니 사이트에 맞게 조정하세요.", 1)
            }
        },

        calc("apache_htaccess", G, ".htaccess (Apache) 설정", "HTTPS 강제·보안 헤더·디렉터리 목록 끄기",
            choice("https", "HTTPS 강제", listOf("켬", "끔"))) { i ->
            result {
                block(buildString {
                    if (i.str("https") == "켬") appendLine("RewriteEngine On\nRewriteCond %{HTTPS} off\nRewriteRule ^(.*)\$ https://%{HTTP_HOST}%{REQUEST_URI} [L,R=301]\n")
                    appendLine("Options -Indexes\n")
                    appendLine("<IfModule mod_headers.c>")
                    appendLine("  Header always set Strict-Transport-Security \"max-age=31536000; includeSubDomains\"")
                    appendLine("  Header always set X-Content-Type-Options \"nosniff\"")
                    appendLine("  Header always set X-Frame-Options \"SAMEORIGIN\"")
                    appendLine("  Header always set Referrer-Policy \"strict-origin-when-cross-origin\"")
                    appendLine("</IfModule>")
                }.trim())
                note("mod_rewrite·mod_headers 모듈이 켜져 있어야 해요. 잘못 쓰면 500 오류가 나니 원본을 백업해 두세요.")
            }
        },

        calc("dns_zone", G, "DNS 영역 레코드 만들기", "BIND 영역 파일에 넣을 A·AAAA·MX·TXT·CAA 레코드 한 묶음",
            text("d", "도메인", "예: example.com", "example.com"), text("ip4", "웹서버 IPv4", "예: 203.0.113.10", "203.0.113.10"), text("ip6", "웹서버 IPv6 (선택)", "예: 2001:db8::10", ""),
            text("mx", "메일 서버 (선택)", "예: mail.example.com", "mail.example.com"), text("ttl", "TTL(초)", "", "3600")) { i ->
            val d = HostInput.host(i.str("d")); if (d.isEmpty() || !HostInput.isPlausibleDomain(d)) return@calc need("도메인을 입력하세요")
            val ip4 = i.str("ip4"); if (ip4.isNotEmpty() && IpUtil.parseV4(ip4) == null) return@calc fail("IPv4 를 읽지 못했어요")
            val ip6 = i.str("ip6"); if (ip6.isNotEmpty() && IpUtil.parse(ip6)?.address?.size != 16) return@calc fail("IPv6 를 읽지 못했어요")
            val ttl = i.int("ttl")?.takeIf { it in 60..604800 } ?: 3600; val mx = i.str("mx")
            result {
                block(buildString {
                    appendLine("\$TTL $ttl")
                    if (ip4.isNotEmpty()) { appendLine("@        IN A     $ip4"); appendLine("www      IN CNAME @") }
                    if (ip6.isNotEmpty()) appendLine("@        IN AAAA  $ip6")
                    if (mx.isNotEmpty()) { appendLine("@        IN MX    10 ${mx.trimEnd('.')}."); appendLine("@        IN TXT   \"v=spf1 mx -all\"") }
                    appendLine("@        IN CAA   0 issue \"letsencrypt.org\"")
                }.trim())
                note("@ 는 $d 자신을 뜻해요. 이름이 점으로 끝나야(예: mail.example.com.) 전체 이름으로 읽혀요. SPF·CAA 는 쓰는 서비스에 맞게 고치세요. 'DNS·도메인' 묶음의 조회 도구로 반영됐는지 확인할 수 있어요.")
            }
        },

        calc("dhcp_conf", G, "DHCP 설정 만들기", "dnsmasq / ISC dhcpd 설정 조각 (범위·게이트웨이·DNS·고정 배정)",
            text("net", "네트워크", "예: 192.168.10.0/24", "192.168.10.0/24"), text("range", "배정할 범위 (앞~끝 마지막 칸)", "예: 100-200", "100-200"), text("gw", "게이트웨이 (선택)", "비우면 .1", ""),
            text("dns", "DNS (쉼표로)", "예: 1.1.1.1,8.8.8.8", "1.1.1.1,8.8.8.8"), text("lease", "임대 시간", "예: 12h", "12h"), text("fix", "고정 배정 (선택)", "MAC=IP=이름", "aa:bb:cc:dd:ee:ff=192.168.10.50=printer")) { i ->
            val c = Cidr4.parse(i.str("net")) ?: return@calc fail("네트워크를 읽지 못했어요 (예: 192.168.10.0/24)"); if (c.prefix > 29) return@calc fail("범위가 너무 작아요")
            val rg = i.str("range").split('-'); val a = rg.getOrNull(0)?.trim()?.toLongOrNull(); val b = rg.getOrNull(1)?.trim()?.toLongOrNull()
            if (a == null || b == null || a > b || c.first + b > c.last) return@calc fail("범위를 읽지 못했어요 (예: 100-200, 네트워크 안이어야 해요)")
            val s = IpUtil.v4Text(c.first + a); val e = IpUtil.v4Text(c.first + b)
            val gw = i.str("gw").ifEmpty { IpUtil.v4Text(c.first + 1) }; if (IpUtil.parseV4(gw) == null) return@calc fail("게이트웨이를 읽지 못했어요")
            val dns = i.str("dns").split(',').map { it.trim() }.filter { it.isNotEmpty() }; if (dns.any { IpUtil.parseV4(it) == null }) return@calc fail("DNS 를 읽지 못했어요 (IPv4 만, 쉼표로 구분)")
            val lease = i.str("lease").ifEmpty { "12h" }; val sec = Regex("""(\d+)([smhd]?)""").matchEntire(lease)?.let { m -> m.groupValues[1].toLong() * when (m.groupValues[2]) { "m" -> 60; "h" -> 3600; "d" -> 86400; else -> 1 } } ?: return@calc fail("임대 시간은 12h, 30m, 1d 처럼 입력하세요")
            val fx = i.str("fix").split('=').map { it.trim() }.takeIf { it.size >= 2 && Mac.parse(it[0]) != null && IpUtil.parseV4(it[1]) != null }
            result {
                head("dnsmasq (/etc/dnsmasq.conf)")
                block("dhcp-range=$s,$e,${IpUtil.v4Text(c.mask)},$lease\ndhcp-option=option:router,$gw\ndhcp-option=option:dns-server,${dns.joinToString(",")}" + (fx?.let { "\ndhcp-host=${it[0]},${it[1]}" + (it.getOrNull(2)?.takeIf { n -> n.isNotEmpty() }?.let { n -> ",$n" } ?: "") } ?: ""))
                head("ISC dhcpd (/etc/dhcp/dhcpd.conf)")
                block("subnet ${IpUtil.v4Text(c.net)} netmask ${IpUtil.v4Text(c.mask)} {\n  range $s $e;\n  option routers $gw;\n  option domain-name-servers ${dns.joinToString(", ")};\n  default-lease-time $sec;\n  max-lease-time ${sec * 2};\n}" +
                    (fx?.let { "\n\nhost ${it.getOrNull(2)?.ifEmpty { null } ?: "fixed"} {\n  hardware ethernet ${it[0]};\n  fixed-address ${it[1]};\n}" } ?: ""))
                note("고정 배정 IP 는 배정 범위 밖에 두는 것이 안전해요. 한 망에 DHCP 서버가 둘이면 충돌하니 공유기의 DHCP 를 꺼야 할 수 있어요.", 1)
            }
        },

        calc("hosts_entry", G, "hosts 파일 항목 만들기", "도메인을 특정 IP 로 고정 연결하는 hosts 줄과 파일 위치·DNS 캐시 비우기",
            text("ip", "IP", "예: 192.168.0.20", "192.168.0.20"), text("names", "이름 (공백으로 여러 개)", "예: nas nas.local", "nas nas.local")) { i ->
            val ip = IpUtil.parse(i.str("ip")) ?: return@calc if (i.str("ip").isEmpty()) need("IP 를 입력하세요") else fail("IP 를 읽지 못했어요")
            val names = i.str("names").split(Regex("\\s+")).filter { it.isNotEmpty() }; if (names.isEmpty()) return@calc need("이름을 입력하세요")
            if (names.any { !HostInput.isPlausibleDomain(it) }) return@calc fail("이름에 쓸 수 없는 글자가 있어요")
            result {
                block("${IpUtil.format(ip)}\t${names.joinToString(" ")}")
                kv("윈도", "C:\\Windows\\System32\\drivers\\etc\\hosts (관리자 권한으로 편집)"); kv("리눅스·맥", "/etc/hosts (sudo)"); kv("안드로이드", "루트 없이는 수정할 수 없어요")
                block("# 적용 안 될 때 DNS 캐시 비우기\n윈도:  ipconfig /flushdns\n맥:    sudo dscacheutil -flushcache; sudo killall -HUP mDNSResponder\n리눅스: sudo resolvectl flush-caches")
                note("hosts 는 DNS 보다 먼저 확인돼요. 모르는 줄이 들어 있다면 악성코드가 가짜 사이트로 보내려고 바꾼 것일 수 있어요.", 1)
            }
        },

        calc("ssh_config", G, "SSH config 항목 만들기", "~/.ssh/config 에 넣어 `ssh 별칭` 으로 접속",
            text("alias", "별칭", "예: myserver", "myserver"), text("host", "서버 주소", "예: 203.0.113.10", "203.0.113.10"), text("user", "사용자", "", "ubuntu"), text("port", "포트", "", "22"),
            text("key", "키 파일 (선택)", "예: ~/.ssh/id_ed25519", "~/.ssh/id_ed25519"), text("jump", "점프 서버 (선택)", "예: bastion", "")) { i ->
            val alias = i.str("alias").ifEmpty { return@calc need("별칭을 입력하세요") }; val host = i.str("host").ifEmpty { return@calc need("서버 주소를 입력하세요") }
            if (alias.any { it.isWhitespace() } || host.any { it.isWhitespace() }) return@calc fail("별칭과 주소에는 공백을 쓸 수 없어요")
            val port = i.int("port") ?: 22; if (port !in 1..65535) return@calc fail("포트는 1~65535 예요")
            result {
                block(buildString {
                    appendLine("Host $alias"); appendLine("    HostName $host"); if (i.str("user").isNotEmpty()) appendLine("    User ${i.str("user")}"); if (port != 22) appendLine("    Port $port")
                    if (i.str("key").isNotEmpty()) { appendLine("    IdentityFile ${i.str("key")}"); appendLine("    IdentitiesOnly yes") }
                    if (i.str("jump").isNotEmpty()) appendLine("    ProxyJump ${i.str("jump")}")
                    appendLine("    ServerAliveInterval 60")
                }.trim())
                block("ssh $alias\nscp 파일 $alias:~/\nssh-keygen -t ed25519 -C \"my laptop\"   # 키 만들기\nssh-copy-id $alias                   # 공개키 올리기")
                note("비밀번호 대신 키로 접속하고, 서버의 /etc/ssh/sshd_config 에서 PasswordAuthentication no 로 바꾸면 무차별 대입 공격을 막을 수 있어요.")
            }
        },

        calc("wg_config", G, "WireGuard 설정 뼈대", "서버·클라이언트 설정 틀과 키 만드는 명령 (키는 직접 만들어 넣어요)",
            text("net", "VPN 내부 대역", "예: 10.8.0.0/24", "10.8.0.0/24"), text("port", "서버 포트", "", "51820"), text("endpoint", "서버 공인 주소", "예: vpn.example.com", "vpn.example.com"), text("dns", "클라이언트 DNS", "", "1.1.1.1")) { i ->
            val c = Cidr4.parse(i.str("net")) ?: return@calc fail("VPN 대역을 읽지 못했어요 (예: 10.8.0.0/24)"); val port = i.int("port")?.takeIf { it in 1..65535 } ?: 51820
            val srv = IpUtil.v4Text(c.first + 1); val cli = IpUtil.v4Text(c.first + 2)
            result {
                head("키 만들기 (서버·클라이언트 각각)"); block("umask 077\nwg genkey | tee privatekey | wg pubkey > publickey")
                head("서버 /etc/wireguard/wg0.conf"); block("[Interface]\nAddress = $srv/${c.prefix}\nListenPort = $port\nPrivateKey = <서버 개인키>\n\n[Peer]\nPublicKey = <클라이언트 공개키>\nAllowedIPs = $cli/32")
                head("클라이언트 설정"); block("[Interface]\nAddress = $cli/${c.prefix}\nPrivateKey = <클라이언트 개인키>\nDNS = ${i.str("dns").ifEmpty { "1.1.1.1" }}\n\n[Peer]\nPublicKey = <서버 공개키>\nEndpoint = ${i.str("endpoint").ifEmpty { "서버주소" }}:$port\nAllowedIPs = 0.0.0.0/0, ::/0\nPersistentKeepalive = 25")
                note("개인키는 절대 공유하지 마세요. 이 앱은 키를 만들지 않아요(위 명령으로 직접 만드세요). 서버에서는 UDP $port 를 열고 IP 포워딩(net.ipv4.ip_forward=1)과 NAT 규칙이 필요해요. 시작: sudo wg-quick up wg0", 1)
            }
        },

        calc("spf_builder", G, "SPF 레코드 만들기", "메일 위조를 막는 SPF TXT 레코드 만들기 (DNS 조회 횟수 경고)",
            text("d", "도메인", "예: example.com", "example.com"), choice("mx", "내 MX 서버 허용", listOf("예", "아니요")), choice("a", "내 웹서버(A) 허용", listOf("아니요", "예")),
            text("inc", "포함할 서비스 (쉼표)", "예: _spf.google.com, spf.protection.outlook.com", "_spf.google.com"), text("ip", "허용할 IP (쉼표)", "예: 203.0.113.10, 198.51.100.0/24", ""), choice("pol", "나머지는", listOf("-all (거부, 권장)", "~all (의심 표시)", "?all (판단 안 함)"))) { i ->
            val d = HostInput.host(i.str("d")); if (d.isEmpty() || !HostInput.isPlausibleDomain(d)) return@calc need("도메인을 입력하세요")
            val inc = i.str("inc").split(',').map { it.trim() }.filter { it.isNotEmpty() }; val ips = i.str("ip").split(',').map { it.trim() }.filter { it.isNotEmpty() }
            for (ip in ips) if (Cidr4.parse(ip) == null && V6.parseCidr(ip) == null) return@calc fail("\"$ip\" 는 IP 가 아니에요")
            val parts = ArrayList<String>(); parts += "v=spf1"
            if (i.str("mx") == "예") parts += "mx"; if (i.str("a") == "예") parts += "a"
            parts += inc.map { "include:$it" }; parts += ips.map { (if (':' in it) "ip6:" else "ip4:") + it }
            parts += i.str("pol").substringBefore(' ')
            val lookups = (if (i.str("mx") == "예") 1 else 0) + (if (i.str("a") == "예") 1 else 0) + inc.size
            result {
                kv("호스트 이름", "@  (또는 $d)"); kv("종류", "TXT"); block(parts.joinToString(" "))
                kv("DNS 조회 횟수(대략)", "$lookups / 10", if (lookups > 10) 2 else if (lookups > 8) 1 else -1)
                if (lookups > 10) note("SPF 는 DNS 조회가 10번을 넘으면 오류(permerror)가 돼요. include 를 줄이세요.", 2)
                note("TXT 레코드는 도메인당 SPF 하나만 두세요(여러 개면 무효). 설정 후 'DNS·도메인' 묶음의 SPF 점검으로 확인하세요.")
            }
        },

        calc("dmarc_builder", G, "DMARC 레코드 만들기", "SPF·DKIM 결과를 어떻게 처리할지 정하는 DMARC TXT 레코드",
            text("d", "도메인", "예: example.com", "example.com"), choice("p", "정책", listOf("none (감시만)", "quarantine (스팸함)", "reject (거부)")), text("pct", "적용 비율(%)", "", "100"),
            text("rua", "집계 보고서 받을 메일", "예: dmarc@example.com", "dmarc@example.com"), choice("al", "정렬 방식(SPF·DKIM)", listOf("relaxed (느슨)", "strict (엄격)"))) { i ->
            val d = HostInput.host(i.str("d")); if (d.isEmpty() || !HostInput.isPlausibleDomain(d)) return@calc need("도메인을 입력하세요")
            val pct = i.int("pct")?.takeIf { it in 0..100 } ?: return@calc fail("적용 비율은 0~100 이에요")
            val rua = i.str("rua"); if (rua.isNotEmpty() && !Regex("""[^@\s]+@[^@\s]+\.[^@\s]+""").matches(rua)) return@calc fail("보고서 메일 주소를 확인하세요")
            val al = if (i.str("al").startsWith("strict")) "s" else "r"
            val v = buildString { append("v=DMARC1; p=${i.str("p").substringBefore(' ')}"); if (pct != 100) append("; pct=$pct"); if (rua.isNotEmpty()) append("; rua=mailto:$rua"); append("; adkim=$al; aspf=$al") }
            result {
                kv("호스트 이름", "_dmarc.$d"); kv("종류", "TXT"); block(v)
                note("처음에는 p=none 으로 보고서만 모아 정상 메일이 모두 통과하는지 확인한 뒤 quarantine → reject 로 올리세요. SPF·DKIM 이 먼저 설정돼 있어야 해요.")
            }
        },

        calc("curl_cmd", G, "curl 명령 만들기", "요청 방식·헤더·본문·옵션으로 curl 명령 만들기",
            choice("m", "방식", listOf("GET", "POST", "PUT", "PATCH", "DELETE", "HEAD")), text("u", "URL", "예: https://api.example.com/items", "https://api.example.com/items"),
            multi("h", "헤더 (한 줄에 하나)", "예: Authorization: Bearer TOKEN", "Content-Type: application/json"), multi("b", "본문 (선택)", "예: {\"name\":\"a\"}", "{\"name\":\"test\"}"),
            choice("o", "옵션", listOf("기본", "리다이렉트 따라감(-L)", "자세히(-v)", "응답 시간 보기", "인증서 검사 끔(-k)"))) { i ->
            val url = i.str("u"); if (url.isEmpty()) return@calc need("URL 을 입력하세요")
            val m = i.str("m"); val o = i.str("o")
            val sb = StringBuilder("curl")
            if (m == "HEAD") sb.append(" -I") else if (m != "GET") sb.append(" -X $m")
            when (o) { "리다이렉트 따라감(-L)" -> sb.append(" -L"); "자세히(-v)" -> sb.append(" -v"); "응답 시간 보기" -> sb.append(" -s -o /dev/null -w ${sh("DNS %{time_namelookup}s  연결 %{time_connect}s  TLS %{time_appconnect}s  첫바이트 %{time_starttransfer}s  전체 %{time_total}s\\n")}"); "인증서 검사 끔(-k)" -> sb.append(" -k") }
            for (h in i.lines("h")) sb.append(" -H ${sh(h)}")
            if (i.str("b").isNotEmpty() && m != "GET" && m != "HEAD") sb.append(" --data ${sh(i.raw("b").trim())}")
            sb.append(" ${sh(url)}")
            result { block(sb.toString()); if (o == "인증서 검사 끔(-k)") note("-k 는 인증서 검사를 끄는 옵션이라 중간자 공격에 무방비예요. 시험용 서버에서만 쓰세요.", 2) }
        },

        calc("diag_cmd", G, "진단 명령 만들기 (OS별)", "ping·경로 추적·DNS·포트·HTTP 확인 명령을 윈도·리눅스·맥에 맞게",
            choice("t", "무엇을", listOf("핑", "경로 추적", "DNS 조회", "포트 열림 확인", "HTTP 응답 확인")), choice("os", "OS", listOf("윈도", "리눅스", "맥")),
            text("h", "대상 (도메인 또는 IP)", "예: example.com", "example.com"), text("p", "포트 (포트 확인용)", "", "443")) { i ->
            val h = HostInput.host(i.str("h")); if (h.isEmpty()) return@calc need("대상을 입력하세요")
            if (IpUtil.parse(h) == null && !HostInput.isPlausibleDomain(h)) return@calc fail("도메인이나 IP 형식이 아니에요")
            val os = i.str("os"); val p = i.int("p")?.takeIf { it in 1..65535 } ?: 443
            val cmds = when (i.str("t")) {
                "핑" -> if (os == "윈도") listOf("ping -n 10 $h", "ping -t $h        # 계속 (Ctrl+C 로 중지)") else listOf("ping -c 10 $h")
                "경로 추적" -> when (os) { "윈도" -> listOf("tracert $h", "pathping $h        # 각 구간 손실률까지 (몇 분 걸림)"); "리눅스" -> listOf("traceroute $h", "tracepath $h", "mtr -rw $h        # 설치돼 있다면 가장 좋음"); else -> listOf("traceroute $h", "mtr -rw $h        # brew install mtr") }
                "DNS 조회" -> if (os == "윈도") listOf("nslookup $h", "nslookup -type=MX $h 8.8.8.8", "Resolve-DnsName $h -Type A   # PowerShell") else listOf("dig $h", "dig +short $h", "dig MX $h @8.8.8.8", "nslookup $h")
                "포트 열림 확인" -> if (os == "윈도") listOf("Test-NetConnection $h -Port $p    # PowerShell", "tnc $h -Port $p") else listOf("nc -vz $h $p", "nc -vz -w 3 $h $p")
                else -> listOf("curl -I https://$h", "curl -sS -o /dev/null -w \"%{http_code} %{time_total}s\\n\" https://$h")
            }
            result { block(cmds.joinToString("\n")); if (os == "윈도" && i.str("t") != "DNS 조회" && i.str("t") != "포트 열림 확인") note("명령 프롬프트(cmd)에서 실행해요. 포트 확인·DNS 조회는 PowerShell 에서 더 편해요.") }
        },

        calc("port_forward_guide", G, "포트 포워딩 설정 안내문", "공유기에서 포트 포워딩 하는 순서와 점검 명령, 보안 주의사항을 내 값으로 정리",
            text("name", "서비스 이름", "예: NAS 웹", "NAS 웹"), text("ip", "내부 IP (고정 권장)", "예: 192.168.0.20", "192.168.0.20"), text("port", "포트", "예: 443", "443"), choice("proto", "프로토콜", listOf("TCP", "UDP", "TCP+UDP"))) { i ->
            val ip = IpUtil.parseV4(i.str("ip"))?.let { IpUtil.v4ToLong(it) }?.takeIf { IpUtil.classify(java.net.InetAddress.getByAddress(IpUtil.longToV4(it))) == IpKind.PRIVATE } ?: return@calc fail("내부 IP 는 사설 주소여야 해요 (예: 192.168.0.20)")
            val sel = parsePorts(i.str("port")) ?: return@calc fail(BAD_PORTS); if (sel.isEmpty) return@calc need("포트를 입력하세요")
            val name = i.str("name").ifEmpty { "서비스" }; val pr = i.str("proto")
            result {
                head("공유기 설정 순서")
                for ((idx, s) in listOf(
                    "공유기 관리 화면에 접속해요 (보통 게이트웨이 주소, 예: ${IpUtil.v4Text(ip and 0xFFFFFF00L or 1)}).",
                    "\"포트 포워딩\"(또는 가상 서버·NAT 설정) 메뉴를 열어요.",
                    "규칙을 추가해요: 이름 \"$name\" / 프로토콜 $pr / 외부 포트 ${sel.joined("-")} / 내부 IP ${IpUtil.v4Text(ip)} / 내부 포트 ${sel.joined("-")}.",
                    "내부 기기의 IP 가 바뀌지 않게 공유기에서 이 기기를 고정 IP(DHCP 예약)로 설정해요.",
                    "저장 후 모바일 데이터(다른 망)에서 이 앱의 '포트 검사'로 공인 IP 의 포트가 열렸는지 확인해요.",
                ).withIndex()) note("${idx + 1}. $s")
                note("통신사 공용 주소(CGNAT)를 받고 있다면 포트 포워딩이 동작하지 않아요. '내 IP 확인'에서 공인 IP 가 100.64.x.x 대역인지 보세요.", 1)
                note("꼭 필요한 포트만 열고, 관리자 화면·데이터베이스·원격 데스크톱(3389)·텔넷은 인터넷에 열지 마세요. 가능하면 VPN(WireGuard)을 쓰는 것이 훨씬 안전해요.", 1)
            }
        },

        // ------------------------------------------------------------ 점검 순서·명령어
        RefTools.ref("cmd_windows", "윈도 네트워크 명령 모음", "ipconfig·netstat·netsh·PowerShell 로 네트워크 상태 보기·고치기",
            listOf("명령", "하는 일"), RefTools.table(
                "ipconfig /all|IP·DNS·MAC 등 모든 설정 보기", "ipconfig /release  &  /renew|IP 를 반납하고 새로 받기 (DHCP 문제)", "ipconfig /flushdns|DNS 캐시 비우기", "ipconfig /displaydns|DNS 캐시 보기",
                "ping 8.8.8.8 -t|인터넷 연결 계속 확인", "tracert 호스트|경로 추적", "pathping 호스트|구간별 손실률까지 측정", "nslookup 도메인|DNS 조회", "netstat -ano|열린 포트·연결과 프로세스 번호 (findstr :443 으로 걸러 보세요)",
                "tasklist /fi \"pid eq 1234\"|PID 로 프로그램 찾기", "arp -a|같은 망 기기의 IP-MAC 표", "route print|라우팅 표", "netsh wlan show interfaces|Wi-Fi 신호·속도·채널", "netsh wlan show profiles|저장된 Wi-Fi 목록",
                "netsh wlan show profile name=\"이름\" key=clear|저장된 Wi-Fi 비밀번호 보기 (관리자)", "netsh interface ip show config|어댑터 IP 설정", "netsh winsock reset|네트워크 소켓 초기화 (재부팅 필요)", "netsh int ip reset|TCP/IP 스택 초기화",
                "netsh advfirewall show allprofiles|방화벽 상태", "nbtstat -n|NetBIOS 이름 보기", "Test-NetConnection 호스트 -Port 443|포트 열림 확인 (PowerShell)", "Get-NetIPConfiguration|IP 설정 요약 (PowerShell)", "Resolve-DnsName 도메인|DNS 조회 (PowerShell)",
            ), group = K, search = "예: dns, wifi, 포트"),
        RefTools.ref("cmd_linux", "리눅스 네트워크 명령 모음", "ip·ss·dig·tcpdump·nmcli 로 네트워크 상태 보기·고치기",
            listOf("명령", "하는 일"), RefTools.table(
                "ip -br a|인터페이스별 IP 요약", "ip r|라우팅 표 (default via = 게이트웨이)", "ip neigh|이웃(ARP) 표", "hostname -I|내 IP 들", "ss -tulpn|열린 포트와 프로세스", "ss -tn state established|연결된 TCP",
                "dig 도메인 / dig +short 도메인|DNS 조회", "dig +trace 도메인|루트부터 따라가며 DNS 조회", "dig -x IP|역방향 조회", "resolvectl status|DNS 서버 설정 (systemd-resolved)", "resolvectl flush-caches|DNS 캐시 비우기",
                "ping -c 4 호스트|연결 확인", "traceroute 호스트 / mtr -rw 호스트|경로 추적", "curl -I https://호스트|HTTP 헤더 보기", "nc -vz 호스트 포트|포트 열림 확인", "sudo tcpdump -i any port 53 -n|DNS 패킷 보기",
                "sudo iptables -L -n -v|방화벽 규칙", "sudo ufw status verbose|ufw 상태", "nmcli dev status|네트워크 장치 상태", "nmcli dev wifi list|주변 Wi-Fi", "iw dev wlan0 link|Wi-Fi 신호·속도", "ethtool eth0|링크 속도·듀플렉스",
                "sudo systemctl restart NetworkManager|네트워크 관리자 재시작", "journalctl -u NetworkManager -n 50|네트워크 로그",
            ), group = K, search = "예: dns, 포트, wifi"),
        RefTools.ref("cmd_mac", "맥 네트워크 명령 모음", "ifconfig·networksetup·scutil 로 네트워크 상태 보기·고치기",
            listOf("명령", "하는 일"), RefTools.table(
                "ifconfig|인터페이스·IP 보기", "ipconfig getifaddr en0|Wi-Fi IP 만 보기", "networksetup -listallhardwareports|장치 이름 목록", "networksetup -getairportnetwork en0|연결된 Wi-Fi 이름",
                "scutil --dns|DNS 설정 보기", "sudo dscacheutil -flushcache; sudo killall -HUP mDNSResponder|DNS 캐시 비우기", "netstat -rn|라우팅 표", "arp -a|이웃 기기 표", "lsof -i :80|80 포트를 쓰는 프로그램",
                "ping -c 4 호스트|연결 확인", "traceroute 호스트|경로 추적", "nc -vz 호스트 포트|포트 열림 확인", "curl -I https://호스트|HTTP 헤더", "system_profiler SPAirPortDataType|Wi-Fi 상세 정보", "networkQuality|Apple 의 인터넷 속도 측정 (macOS 12+)",
            ), group = K, search = "예: dns, wifi"),
        RefTools.ref("cmd_android", "안드로이드 네트워크 점검 명령 (ADB)", "컴퓨터에 USB 로 연결해 adb shell 로 확인하는 명령들",
            listOf("명령", "하는 일"), RefTools.table(
                "adb shell ip addr show wlan0|Wi-Fi IP", "adb shell ip route|라우팅 표", "adb shell ping -c 4 8.8.8.8|인터넷 연결", "adb shell dumpsys connectivity|연결 상태 상세", "adb shell dumpsys wifi|Wi-Fi 상태 상세 (RSSI 등)",
                "adb shell cmd wifi status|Wi-Fi 상태 요약 (안드로이드 11+)", "adb shell settings get global private_dns_mode|Private DNS 모드 (off/opportunistic/hostname)", "adb shell settings get global private_dns_specifier|Private DNS 서버 이름",
                "adb shell netstat -tn|연결된 TCP (기기에 따라 없을 수 있음)", "adb logcat -s ConnectivityService|연결 관련 로그",
            ), group = K, footer = "개발자 옵션의 USB 디버깅을 켜야 쓸 수 있어요. 끝나면 다시 꺼 두세요(켜 두면 컴퓨터에서 기기를 조종할 수 있어요)."),
        RefTools.ref("cmd_dig", "dig·nslookup 사용법", "DNS 레코드 조회 명령 옵션 모음",
            listOf("명령", "하는 일"), RefTools.table(
                "dig example.com|A 레코드 (기본)", "dig example.com AAAA|IPv6 주소", "dig example.com MX|메일 서버", "dig example.com TXT|SPF·DMARC 등 글자 레코드", "dig example.com NS|네임서버", "dig example.com ANY|모든 레코드 (거부하는 서버가 많음)",
                "dig +short example.com|답만 간단히", "dig @8.8.8.8 example.com|특정 DNS 서버로 질문", "dig +trace example.com|루트부터 위임을 따라감", "dig -x 8.8.8.8|IP → 이름", "dig +dnssec example.com|DNSSEC 서명 포함",
                "dig _dmarc.example.com TXT|DMARC 정책", "dig default._domainkey.example.com TXT|DKIM 키 (선택자 default)", "dig +tcp example.com|TCP 로 질문", "nslookup -type=MX example.com 8.8.8.8|nslookup 으로 MX 조회", "nslookup example.com|기본 조회",
            ), group = K, search = "예: MX, trace"),
        RefTools.ref("cmd_curl", "curl 자주 쓰는 옵션", "요청 확인·디버그에 쓰는 curl 옵션",
            listOf("옵션", "하는 일"), RefTools.table(
                "-I|헤더만 (HEAD 요청)", "-L|리다이렉트 따라감", "-v|요청·응답 과정을 자세히", "-s -S|진행 표시 끄고 오류만", "-o 파일 / -O|저장 (이름 지정 / 원래 이름)", "-H 'A: b'|헤더 추가", "-d '데이터'|본문 보내기 (POST)", "-X PUT|방식 지정",
                "-u 아이디:비번|Basic 인증", "-k|인증서 검사 끔 (위험, 시험용)", "--resolve 도메인:443:IP|DNS 를 건너뛰고 이 IP 로 접속 (이전·점검 시험)", "--connect-timeout 5|연결 제한 시간", "--max-time 20|전체 제한 시간",
                "--http2 / --http3|HTTP 버전 지정", "-w '%{http_code}'|응답 코드만 출력", "-w '%{time_total}'|전체 시간 출력", "--tlsv1.2|TLS 1.2 로 시도", "-4 / -6|IPv4 / IPv6 로만", "--proxy http://호스트:포트|프록시 사용",
            ), group = K, search = "예: 헤더, 시간"),
        RefTools.ref("cmd_openssl", "openssl 인증서 점검 명령", "서버 인증서 확인·만료일·체인 점검 명령",
            listOf("명령", "하는 일"), RefTools.table(
                "openssl s_client -connect 호스트:443 -servername 호스트|TLS 접속해 인증서 체인 보기 (끝내려면 Ctrl+D)", "openssl s_client -connect 호스트:443 -servername 호스트 </dev/null 2>/dev/null >cert.txt|서버 인증서를 cert.txt 로 저장",
                "openssl x509 -in cert.txt -noout -dates|저장한 인증서의 유효 기간(만료일)", "openssl x509 -in cert.txt -noout -subject -issuer|주체·발급자", "openssl x509 -in cert.txt -noout -fingerprint -sha256|SHA-256 지문", "openssl x509 -in cert.txt -noout -ext subjectAltName|대체 이름(SAN)",
                "openssl x509 -in cert.pem -text -noout|PEM 인증서 상세", "openssl s_client -connect 호스트:443 -tls1_2|TLS 1.2 만 시도",
                "openssl s_client -connect 호스트:443 -tls1_3|TLS 1.3 만 시도", "openssl verify -CAfile ca.pem cert.pem|체인 검증", "openssl req -new -newkey rsa:2048 -nodes -keyout 키.pem -out 요청.csr|개인키와 CSR 만들기", "openssl s_client -starttls smtp -connect 호스트:587|메일 서버 STARTTLS 점검",
            ), group = K, search = "예: 만료, tls"),
        RefTools.ref("trouble_internet", "인터넷이 안 될 때 점검 순서", "어디서 막혔는지 단계별로 좁혀 가는 순서 (집·사무실)",
            listOf("단계", "확인할 것", "결과가 이렇다면"), RefTools.table(
                "1|다른 기기도 안 되나요?|다른 기기는 되면 이 기기 문제(Wi-Fi 껐다 켜기·재부팅·프록시·VPN), 모두 안 되면 공유기·회선 문제", "2|공유기·모뎀 불빛|인터넷(WAN) 불이 꺼졌거나 빨간색이면 회선 문제 — 전원을 30초 뽑았다 꽂고 5분 기다려요",
                "3|케이블·전원|모뎀↔공유기 랜선이 단단히 꽂혔는지, 다른 랜선으로 바꿔 보세요", "4|내 IP 확인|169.254.x.x 면 DHCP 를 못 받은 것 → 공유기 재부팅, 0.0.0.0 이면 연결 안 됨", "5|공유기(게이트웨이) 핑|안 되면 Wi-Fi/랜 연결 문제, 되면 다음 단계",
                "6|8.8.8.8 핑|안 되면 공유기~통신사 구간 문제 (통신사 장애 확인), 되면 다음 단계", "7|도메인 핑(google.com)|8.8.8.8 은 되는데 도메인이 안 되면 DNS 문제 → DNS 를 8.8.8.8/1.1.1.1 로 바꿔 보세요", "8|브라우저 vs 앱|특정 앱만 안 되면 그 서비스 장애나 앱 설정, https 사이트만 안 되면 시간·인증서 확인",
                "9|프록시·VPN·보안 프로그램|끄고 다시 시도 (공용 Wi-Fi 는 로그인 화면이 있는지 확인)", "10|통신사 문의|위 단계를 거쳤는데도 안 되면 통신사에 회선 점검을 요청하세요 (ping 결과를 알려 주면 빨라요)",
            ), group = K),
        RefTools.ref("trouble_wifi", "Wi-Fi 가 느릴 때 점검 순서", "속도·끊김 원인을 하나씩 좁히기",
            listOf("확인할 것", "방법"), RefTools.table(
                "유선 속도 먼저|랜선으로 연결해 속도를 재 보세요. 유선도 느리면 회선·공유기 문제, 유선은 빠르면 Wi-Fi 문제", "5 GHz 로 연결|2.4 GHz 는 느리고 혼잡해요. 공유기에서 5 GHz 이름을 따로 두고 연결해 보세요", "공유기 위치|벽·바닥에서 떨어진 높은 곳, 기기와 가까운 곳. 금속·수족관·전자레인지 옆은 피하세요",
                "신호 세기|'Wi-Fi 신호·속도' 도구로 -67 dBm 보다 약하면 가까이 가거나 중계기·메시를 고려하세요", "채널 혼잡|이웃 공유기와 같은 채널이면 느려져요. 2.4 GHz 는 1·6·11, 5 GHz 는 한가한 채널로 바꿔 보세요", "채널 폭|2.4 GHz 는 20 MHz, 5 GHz 는 80 MHz 정도가 안정적이에요",
                "연결된 기기 수|많은 기기가 동시에 쓰면 느려요. 안 쓰는 기기를 끄고 확인", "펌웨어·재부팅|공유기 펌웨어를 최신으로, 가끔(주 1회) 재부팅", "기기 쪽|Wi-Fi 를 껐다 켜기, 절전 모드·VPN·백그라운드 다운로드 확인", "여전히 느리면|인터넷 속도 측정·핑 통계로 회선 자체가 느린지(통신사) 확인하세요",
            ), group = K),
        RefTools.ref("router_checklist", "공유기 보안 점검표", "내 공유기가 안전하게 설정돼 있는지 하나씩 확인",
            listOf("항목", "왜 중요한가", "어떻게"), RefTools.table(
                "관리자 비밀번호 변경|기본 비밀번호(admin 등)는 누구나 알아요|관리 화면 → 관리자 계정에서 길고 고유한 비밀번호로", "Wi-Fi 암호화 WPA2/WPA3|WEP·WPA·암호 없음은 쉽게 뚫려요|무선 보안 → WPA3(안 되면 WPA2-AES), 비밀번호 12자 이상", "WPS 끄기|PIN 방식이 취약해요|무선 설정 → WPS 비활성화",
                "원격 관리 끄기|밖(인터넷)에서 관리 화면에 접속할 수 있으면 공격 대상이 돼요|관리 → 원격 관리/WAN 관리 끄기 (이 앱 포트 검사로 확인)", "펌웨어 업데이트|알려진 취약점이 계속 발견돼요|관리 → 펌웨어 업그레이드, 자동 업데이트가 있으면 켜기", "UPnP 끄기|기기가 몰래 포트를 열 수 있어요|고급 → UPnP 비활성화 (필요한 포트만 직접 포워딩)",
                "게스트 Wi-Fi 분리|손님·IoT 기기를 내 기기와 분리해요|무선 → 게스트 망 켜기, 내부 망 접근 차단", "사용하지 않는 포트포워딩 삭제|열린 문을 줄여요|NAT/포트 포워딩 목록 정리", "DNS 설정 확인|악성코드가 DNS 를 바꿔 가짜 사이트로 보내기도 해요|WAN 의 DNS 가 통신사·공개 DNS 인지 확인", "공유기 이름·모델 노출 줄이기|제조사 기본 이름이면 모델이 드러나요|SSID 를 모델명 없이 바꾸기",
                "Telnet·SSH·FTP 서버 끄기|공유기에 열린 관리 서비스를 줄여요|관리 → 서비스 설정에서 끄기 (이 앱 포트 검사로 22·23·21 확인)", "로그 확인|낯선 접속 기록을 알 수 있어요|시스템 로그·연결 기기 목록 가끔 확인 (이 앱 '같은 Wi-Fi 기기 찾기' 활용)",
            ), group = K),
    )
}
