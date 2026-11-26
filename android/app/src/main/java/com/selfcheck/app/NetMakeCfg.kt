package com.selfcheck.app

import java.net.IDN

/*
 * 설정 파일 생성기: systemd 서비스·타이머, netplan, chrony, fail2ban, HAProxy, sshd, nftables, wpa_supplicant·hostapd, OpenSSL 명령.
 * 입력 확인(Valid)과 글 만들기만 해요. 글은 실제 도구(systemd-analyze·netplan·chronyd·fail2ban-client·haproxy·sshd·nft·openssl)로 검증해서 시험해요.
 */

object Valid {
    private val DNS = Regex("^(\\*\\.)?([A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?\\.)*[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?$")
    /** 호스트 이름 (한글 도메인은 퓨니코드로 바꿔 돌려줌). 올바르지 않으면 null */
    fun host(s: String, wildcard: Boolean = false): String? {
        val t = s.trim().trimEnd('.'); if (t.isEmpty() || t.length > 253) return null
        val a = try { IDN.toASCII(t, IDN.ALLOW_UNASSIGNED) } catch (_: Exception) { return null }
        if (a.startsWith("*.") && !wildcard) return null
        return if (DNS.matches(a)) a else null
    }
    fun ipOrHost(s: String): String? = IpUtil.parse(s)?.let { IpUtil.format(it) } ?: host(s)
    fun port(s: String): Int? = s.trim().toIntOrNull()?.takeIf { it in 1..65535 }
    /** "192.168.0.0/24" · "2001:db8::/32" (길이 필수). 정리한 글을 돌려줌 */
    fun cidr(s: String): String? {
        val t = s.trim(); val i = t.indexOf('/'); if (i < 0) return null
        val a = IpUtil.parse(t.substring(0, i)) ?: return null; val len = t.substring(i + 1).toIntOrNull() ?: return null
        val v6 = a.address.size == 16; if (len !in 0..(if (v6) 128 else 32)) return null
        return IpUtil.format(a) + "/" + len
    }
    /** IP 또는 CIDR (길이가 없으면 /32·/128) */
    fun ipOrCidr(s: String): String? = cidr(s) ?: IpUtil.parse(s)?.let { IpUtil.format(it) }
    fun isV6(s: String) = s.contains(':')
    fun unixName(s: String): Boolean = Regex("^[a-z_][a-z0-9_-]{0,31}$").matches(s)
    fun serviceName(s: String): Boolean = Regex("^[A-Za-z0-9:_.@-]{1,60}$").matches(s)
    fun iface(s: String): Boolean = Regex("^[A-Za-z0-9_.:@-]{1,15}$").matches(s)
}

object MakeCfg {

    // ============================================================ systemd

    class Systemd(val name: String, val desc: String, val exec: String, val user: String, val workdir: String, val restart: String, val env: List<String>, val hardening: Int, val netWait: Boolean, val onCalendar: String?, val everyMin: Int?)

    /** (파일 이름, 내용) 목록: 서비스 하나, 타이머를 쓰면 .timer 도 */
    fun systemd(o: Systemd): List<Pair<String, String>> {
        val timer = o.onCalendar != null || o.everyMin != null
        val svc = buildString {
            appendLine("[Unit]"); appendLine("Description=${o.desc}")
            if (o.netWait) { appendLine("After=network-online.target"); appendLine("Wants=network-online.target") }
            appendLine(); appendLine("[Service]"); appendLine("Type=${if (timer) "oneshot" else "simple"}")
            if (o.user.isNotEmpty()) appendLine("User=${o.user}")
            if (o.workdir.isNotEmpty()) appendLine("WorkingDirectory=${o.workdir}")
            for (e in o.env) appendLine("Environment=\"$e\"")
            appendLine("ExecStart=${o.exec}")
            if (!timer && o.restart != "no") { appendLine("Restart=${o.restart}"); appendLine("RestartSec=5") }
            if (o.hardening >= 1) { appendLine("NoNewPrivileges=true"); appendLine("PrivateTmp=true"); appendLine("ProtectSystem=${if (o.hardening >= 2) "strict" else "full"}") }
            if (o.hardening >= 2) {
                for (l in listOf("ProtectHome=true", "ProtectKernelTunables=true", "ProtectKernelModules=true", "ProtectControlGroups=true", "RestrictSUIDSGID=true", "LockPersonality=true", "RestrictRealtime=true", "SystemCallArchitectures=native")) appendLine(l)
                appendLine("StateDirectory=${o.name}")
            }
            if (!timer) { appendLine(); appendLine("[Install]"); appendLine("WantedBy=multi-user.target") }
        }
        val out = arrayListOf("${o.name}.service" to svc)
        if (timer) out += "${o.name}.timer" to buildString {
            appendLine("[Unit]"); appendLine("Description=${o.desc} (타이머)"); appendLine(); appendLine("[Timer]")
            if (o.onCalendar != null) { appendLine("OnCalendar=${o.onCalendar}"); appendLine("Persistent=true") } else { appendLine("OnBootSec=5min"); appendLine("OnUnitActiveSec=${o.everyMin}min") }
            appendLine("Unit=${o.name}.service"); appendLine(); appendLine("[Install]"); appendLine("WantedBy=timers.target")
        }
        return out
    }

    // ============================================================ netplan

    class Netplan(val mode: Int, val iface: String, val addresses: List<String>, val gateway4: String, val gateway6: String, val dns: List<String>, val search: List<String>, val mtu: Int?, val vlanId: Int?, val members: List<String>, val dhcp: Boolean)

    /** mode: 0 DHCP, 1 고정 IP, 2 브리지, 3 VLAN, 4 본딩(active-backup) */
    fun netplan(o: Netplan): String = buildString {
        fun l(n: Int, s: String) { appendLine("  ".repeat(n) + s) }
        fun addrBlock(n: Int) {
            if (o.dhcp) { l(n, "dhcp4: true"); l(n, "dhcp6: false") }
            else {
                l(n, "dhcp4: false"); if (o.addresses.isNotEmpty()) { l(n, "addresses:"); for (a in o.addresses) l(n + 1, "- $a") }
                if (o.gateway4.isNotEmpty() || o.gateway6.isNotEmpty()) { l(n, "routes:"); if (o.gateway4.isNotEmpty()) { l(n + 1, "- to: 0.0.0.0/0"); l(n + 2, "via: ${o.gateway4}") }; if (o.gateway6.isNotEmpty()) { l(n + 1, "- to: \"::/0\""); l(n + 2, "via: ${o.gateway6}") } }
                if (o.dns.isNotEmpty() || o.search.isNotEmpty()) { l(n, "nameservers:"); if (o.dns.isNotEmpty()) l(n + 1, "addresses: [${o.dns.joinToString(", ")}]"); if (o.search.isNotEmpty()) l(n + 1, "search: [${o.search.joinToString(", ")}]") }
            }
            o.mtu?.let { l(n, "mtu: $it") }
        }
        appendLine("network:"); l(1, "version: 2"); l(1, "renderer: networkd")
        when (o.mode) {
            0, 1 -> { l(1, "ethernets:"); l(2, "${o.iface}:"); addrBlock(3) }
            2 -> { l(1, "ethernets:"); for (m in o.members) l(2, "$m: {}"); l(1, "bridges:"); l(2, "${o.iface}:"); l(3, "interfaces: [${o.members.joinToString(", ")}]"); addrBlock(3); l(3, "parameters:"); l(4, "stp: false"); l(4, "forward-delay: 0") }
            3 -> { l(1, "ethernets:"); l(2, "${o.members[0]}: {}"); l(1, "vlans:"); l(2, "${o.iface}:"); l(3, "id: ${o.vlanId}"); l(3, "link: ${o.members[0]}"); addrBlock(3) }
            else -> { l(1, "ethernets:"); for (m in o.members) l(2, "$m: {}"); l(1, "bonds:"); l(2, "${o.iface}:"); l(3, "interfaces: [${o.members.joinToString(", ")}]"); addrBlock(3); l(3, "parameters:"); l(4, "mode: active-backup"); l(4, "mii-monitor-interval: 100"); l(4, "primary: ${o.members[0]}") }
        }
    }

    // ============================================================ chrony

    class Chrony(val servers: List<String>, val nts: Boolean, val allow: List<String>, val localStratum: Boolean, val makestep: Boolean, val rtcsync: Boolean, val logdir: Boolean)

    fun chrony(o: Chrony): String = buildString {
        for (s in o.servers) {
            val pool = s.contains("pool", ignoreCase = true)
            appendLine(if (pool) "pool $s iburst maxsources 4" else "server $s iburst" + if (o.nts) " nts" else "")
        }
        if (o.nts) appendLine("ntsdumpdir /var/lib/chrony")
        appendLine("driftfile /var/lib/chrony/chrony.drift")
        if (o.makestep) appendLine("makestep 1.0 3")
        if (o.rtcsync) appendLine("rtcsync")
        for (a in o.allow) appendLine("allow $a")
        if (o.localStratum) appendLine("local stratum 10")
        if (o.logdir) appendLine("logdir /var/log/chrony")
    }

    // ============================================================ fail2ban

    val F2B_JAILS = linkedMapOf("sshd" to "ssh", "nginx-http-auth" to "http,https", "nginx-botsearch" to "http,https", "apache-auth" to "http,https", "postfix" to "smtp,465,submission", "dovecot" to "pop3,pop3s,imap,imaps,submission,465,sieve", "vsftpd" to "ftp,ftp-data,ftps,ftps-data", "mysqld-auth" to "3306", "recidive" to "")

    class Fail2ban(val jails: List<String>, val sshPort: Int, val maxretry: Int, val findtimeMin: Int, val bantimeMin: Int, val ignore: List<String>, val banaction: String, val sshSystemd: Boolean, val increment: Boolean)

    fun fail2ban(o: Fail2ban): String = buildString {
        appendLine("[DEFAULT]")
        appendLine("bantime = ${o.bantimeMin}m"); appendLine("findtime = ${o.findtimeMin}m"); appendLine("maxretry = ${o.maxretry}")
        if (o.banaction.isNotEmpty()) appendLine("banaction = ${o.banaction}")
        if (o.ignore.isNotEmpty()) appendLine("ignoreip = 127.0.0.1/8 ::1 ${o.ignore.joinToString(" ")}")
        if (o.increment) { appendLine("bantime.increment = true"); appendLine("bantime.factor = 2"); appendLine("bantime.maxtime = 5w") }
        for (j in o.jails) {
            appendLine(); appendLine("[$j]"); appendLine("enabled = true")
            when (j) {
                "sshd" -> { appendLine("port = ${if (o.sshPort == 22) "ssh" else o.sshPort.toString()}"); if (o.sshSystemd) appendLine("backend = systemd") }
                "recidive" -> { appendLine("logpath = /var/log/fail2ban.log"); appendLine("bantime = 1w"); appendLine("findtime = 1d"); appendLine("maxretry = 3") }
                else -> appendLine("port = ${F2B_JAILS[j]}")
            }
        }
    }

    // ============================================================ HAProxy

    class HaServer(val host: String, val port: Int, val weight: Int)
    class Haproxy(val tcpMode: Boolean, val bindPort: Int, val servers: List<HaServer>, val balance: String, val checkPath: String, val maxconn: Int, val tlsCert: String, val redirectHttp: Boolean, val statsPassword: String, val rateLimit: Int, val runAsHaproxy: Boolean)

    fun haproxy(o: Haproxy): String = buildString {
        appendLine("global"); appendLine("    log /dev/log local0"); appendLine("    maxconn ${o.maxconn}")
        if (o.runAsHaproxy) { appendLine("    user haproxy"); appendLine("    group haproxy") }
        appendLine(); appendLine("defaults"); appendLine("    log global"); appendLine("    mode ${if (o.tcpMode) "tcp" else "http"}")
        if (o.tcpMode) appendLine("    option tcplog") else { appendLine("    option httplog"); appendLine("    option forwardfor") }
        appendLine("    option dontlognull"); appendLine("    retries 3"); appendLine("    timeout connect 5s"); appendLine("    timeout client 30s"); appendLine("    timeout server 30s")
        if (!o.tcpMode) appendLine("    timeout http-request 10s")
        appendLine(); appendLine("frontend main")
        if (o.tlsCert.isNotEmpty() && !o.tcpMode) { appendLine("    bind *:${o.bindPort} ssl crt ${o.tlsCert} alpn h2,http/1.1"); if (o.redirectHttp) { appendLine("    bind *:80"); appendLine("    http-request redirect scheme https code 301 unless { ssl_fc }") } }
        else appendLine("    bind *:${o.bindPort}")
        if (!o.tcpMode && o.rateLimit > 0) {
            appendLine("    stick-table type ip size 100k expire 30s store http_req_rate(10s)")
            appendLine("    http-request track-sc0 src")
            appendLine("    http-request deny deny_status 429 if { sc_http_req_rate(0) gt ${o.rateLimit} }")
        }
        appendLine("    default_backend app"); appendLine()
        appendLine("backend app"); appendLine("    balance ${o.balance}")
        if (o.tcpMode) appendLine("    option tcp-check") else if (o.checkPath.isNotEmpty()) { appendLine("    option httpchk GET ${o.checkPath}"); appendLine("    http-check expect status 200") }
        for ((i, s) in o.servers.withIndex()) appendLine("    server s${i + 1} ${s.host}:${s.port}" + (if (o.tcpMode || o.checkPath.isNotEmpty()) " check" else "") + (if (s.weight != 1) " weight ${s.weight}" else ""))
        if (o.statsPassword.isNotEmpty()) { appendLine(); appendLine("listen stats"); appendLine("    mode http"); appendLine("    bind 127.0.0.1:8404"); appendLine("    stats enable"); appendLine("    stats uri /stats"); appendLine("    stats refresh 10s"); appendLine("    stats auth admin:${o.statsPassword}") }
    }

    // ============================================================ sshd

    class Sshd(val port: Int, val rootLogin: String, val passwordAuth: Boolean, val allowUsers: List<String>, val maxAuthTries: Int, val forwarding: Boolean, val x11: Boolean, val modernCrypto: Boolean, val aliveSec: Int)

    fun sshd(o: Sshd): String = buildString {
        appendLine("Port ${o.port}"); appendLine("PermitRootLogin ${o.rootLogin}"); appendLine("PubkeyAuthentication yes")
        appendLine("PasswordAuthentication ${if (o.passwordAuth) "yes" else "no"}"); appendLine("PermitEmptyPasswords no"); appendLine("ChallengeResponseAuthentication no")
        appendLine("MaxAuthTries ${o.maxAuthTries}"); appendLine("LoginGraceTime 30")
        if (o.allowUsers.isNotEmpty()) appendLine("AllowUsers ${o.allowUsers.joinToString(" ")}")
        appendLine("X11Forwarding ${if (o.x11) "yes" else "no"}"); appendLine("AllowTcpForwarding ${if (o.forwarding) "yes" else "no"}"); appendLine("AllowAgentForwarding no")
        if (o.aliveSec > 0) { appendLine("ClientAliveInterval ${o.aliveSec}"); appendLine("ClientAliveCountMax 2") }
        if (o.modernCrypto) {
            appendLine("KexAlgorithms curve25519-sha256,curve25519-sha256@libssh.org,diffie-hellman-group16-sha512,diffie-hellman-group18-sha512")
            appendLine("Ciphers chacha20-poly1305@openssh.com,aes256-gcm@openssh.com,aes128-gcm@openssh.com,aes256-ctr,aes192-ctr,aes128-ctr")
            appendLine("MACs hmac-sha2-512-etm@openssh.com,hmac-sha2-256-etm@openssh.com,umac-128-etm@openssh.com")
            appendLine("HostKeyAlgorithms ssh-ed25519,rsa-sha2-512,rsa-sha2-256")
        }
    }

    // ============================================================ nftables

    class NftForward(val extPort: Int, val toIp: String, val toPort: Int, val proto: String)
    class Nft(val sshPort: Int, val sshFrom: List<String>, val sshRatePerMin: Int, val tcpPorts: List<Int>, val udpPorts: List<Int>, val icmp: Boolean, val blocklist: List<String>, val natIface: String, val forwards: List<NftForward>, val logDrops: Boolean)

    fun nft(o: Nft): String = buildString {
        val b4 = o.blocklist.filter { !Valid.isV6(it) }; val b6 = o.blocklist.filter { Valid.isV6(it) }
        appendLine("flush ruleset"); appendLine()
        appendLine("table inet filter {")
        if (b4.isNotEmpty()) { appendLine("    set blocklist4 {"); appendLine("        type ipv4_addr"); appendLine("        flags interval"); appendLine("        auto-merge"); appendLine("        elements = { ${b4.joinToString(", ")} }"); appendLine("    }") }
        if (b6.isNotEmpty()) { appendLine("    set blocklist6 {"); appendLine("        type ipv6_addr"); appendLine("        flags interval"); appendLine("        auto-merge"); appendLine("        elements = { ${b6.joinToString(", ")} }"); appendLine("    }") }
        appendLine("    chain input {"); appendLine("        type filter hook input priority 0; policy drop;")
        appendLine("        ct state invalid drop"); appendLine("        ct state { established, related } accept"); appendLine("        iifname \"lo\" accept")
        if (b4.isNotEmpty()) appendLine("        ip saddr @blocklist4 drop"); if (b6.isNotEmpty()) appendLine("        ip6 saddr @blocklist6 drop")
        if (o.icmp) {
            appendLine("        ip protocol icmp icmp type { echo-request, destination-unreachable, time-exceeded, parameter-problem } limit rate 10/second accept")
            appendLine("        ip6 nexthdr icmpv6 icmpv6 type { destination-unreachable, packet-too-big, time-exceeded, parameter-problem, echo-request, nd-router-solicit, nd-router-advert, nd-neighbor-solicit, nd-neighbor-advert } accept")
        }
        if (o.sshPort > 0) {
            val s4 = o.sshFrom.filter { !Valid.isV6(it) }; val s6 = o.sshFrom.filter { Valid.isV6(it) }; val rate = if (o.sshRatePerMin > 0) " limit rate ${o.sshRatePerMin}/minute" else ""
            if (o.sshFrom.isEmpty()) appendLine("        tcp dport ${o.sshPort} ct state new$rate accept")
            else { if (s4.isNotEmpty()) appendLine("        tcp dport ${o.sshPort} ip saddr { ${s4.joinToString(", ")} } ct state new$rate accept"); if (s6.isNotEmpty()) appendLine("        tcp dport ${o.sshPort} ip6 saddr { ${s6.joinToString(", ")} } ct state new$rate accept") }
        }
        if (o.tcpPorts.isNotEmpty()) appendLine("        tcp dport { ${o.tcpPorts.joinToString(", ")} } accept")
        if (o.udpPorts.isNotEmpty()) appendLine("        udp dport { ${o.udpPorts.joinToString(", ")} } accept")
        if (o.logDrops) appendLine("        limit rate 5/minute log prefix \"nft-drop: \" level info")
        appendLine("    }")
        appendLine("    chain forward {"); appendLine("        type filter hook forward priority 0; policy drop;"); appendLine("        ct state { established, related } accept")
        if (o.natIface.isNotEmpty()) appendLine("        iifname != \"${o.natIface}\" oifname \"${o.natIface}\" accept")
        for (f in o.forwards) appendLine("        ip daddr ${f.toIp} ${f.proto} dport ${f.toPort} ct status dnat accept")
        appendLine("    }")
        appendLine("    chain output {"); appendLine("        type filter hook output priority 0; policy accept;"); appendLine("    }")
        appendLine("}")
        if (o.natIface.isNotEmpty() || o.forwards.isNotEmpty()) {
            appendLine(); appendLine("table ip nat {")
            appendLine("    chain prerouting {"); appendLine("        type nat hook prerouting priority -100;")
            for (f in o.forwards) appendLine("        ${f.proto} dport ${f.extPort} dnat to ${f.toIp}:${f.toPort}")
            appendLine("    }")
            appendLine("    chain postrouting {"); appendLine("        type nat hook postrouting priority 100;")
            if (o.natIface.isNotEmpty()) appendLine("        oifname \"${o.natIface}\" masquerade")
            appendLine("    }"); appendLine("}")
        }
    }

    // ============================================================ Wi-Fi 설정 (wpa_supplicant · hostapd)

    /** security: 0 WPA2-PSK, 1 WPA3-SAE, 2 WPA2/WPA3 혼합 */
    fun wpaSupplicant(ssid: String, pskHex: String, pass: String, security: Int, country: String, hidden: Boolean): String = buildString {
        appendLine("ctrl_interface=DIR=/var/run/wpa_supplicant GROUP=netdev"); appendLine("update_config=1")
        if (country.isNotEmpty()) appendLine("country=$country")
        appendLine(); appendLine("network={"); appendLine("    ssid=\"$ssid\"")
        when (security) {
            0 -> { appendLine("    key_mgmt=WPA-PSK"); appendLine("    psk=$pskHex"); appendLine("    proto=RSN"); appendLine("    pairwise=CCMP") }
            1 -> { appendLine("    key_mgmt=SAE"); appendLine("    sae_password=\"$pass\""); appendLine("    ieee80211w=2") }
            else -> { appendLine("    key_mgmt=WPA-PSK SAE"); appendLine("    psk=$pskHex"); appendLine("    sae_password=\"$pass\""); appendLine("    ieee80211w=1") }
        }
        if (hidden) appendLine("    scan_ssid=1")
        appendLine("}")
    }

    fun hostapd(ssid: String, pskHex: String, pass: String, security: Int, country: String, channel: Int, band5: Boolean, iface: String): String = buildString {
        appendLine("interface=$iface"); appendLine("driver=nl80211"); appendLine("ssid=$ssid")
        if (country.isNotEmpty()) { appendLine("country_code=$country"); appendLine("ieee80211d=1") }
        appendLine("hw_mode=${if (band5) "a" else "g"}"); appendLine("channel=$channel"); appendLine("ieee80211n=1"); if (band5) appendLine("ieee80211ac=1"); appendLine("wmm_enabled=1")
        appendLine("auth_algs=1"); appendLine("wpa=2")
        when (security) {
            0 -> { appendLine("wpa_key_mgmt=WPA-PSK"); appendLine("wpa_psk=$pskHex") }
            1 -> { appendLine("wpa_key_mgmt=SAE"); appendLine("sae_password=$pass"); appendLine("ieee80211w=2") }
            else -> { appendLine("wpa_key_mgmt=WPA-PSK SAE"); appendLine("wpa_psk=$pskHex"); appendLine("sae_password=$pass"); appendLine("ieee80211w=1") }
        }
        appendLine("rsn_pairwise=CCMP")
    }

    // ============================================================ WireGuard 설정 글

    class WgPeerCfg(val serverPriv: String, val serverPub: String, val clientPriv: String, val clientPub: String, val psk: String?, val serverAddr: String, val clientAddr: String, val port: Int, val endpoint: String, val dns: String, val allowedIps: String, val natIface: String)

    fun wgServer(o: WgPeerCfg): String = buildString {
        appendLine("[Interface]"); appendLine("Address = ${o.serverAddr}"); appendLine("ListenPort = ${o.port}"); appendLine("PrivateKey = ${o.serverPriv}")
        if (o.natIface.isNotEmpty()) {
            appendLine("PostUp = sysctl -w net.ipv4.ip_forward=1; iptables -A FORWARD -i %i -j ACCEPT; iptables -t nat -A POSTROUTING -o ${o.natIface} -j MASQUERADE")
            appendLine("PostDown = iptables -D FORWARD -i %i -j ACCEPT; iptables -t nat -D POSTROUTING -o ${o.natIface} -j MASQUERADE")
        }
        appendLine(); appendLine("[Peer]"); appendLine("PublicKey = ${o.clientPub}"); if (o.psk != null) appendLine("PresharedKey = ${o.psk}"); appendLine("AllowedIPs = ${o.clientAddr}")
    }

    fun wgClient(o: WgPeerCfg): String = buildString {
        appendLine("[Interface]"); appendLine("Address = ${o.clientAddr}"); appendLine("PrivateKey = ${o.clientPriv}"); if (o.dns.isNotEmpty()) appendLine("DNS = ${o.dns}")
        appendLine(); appendLine("[Peer]"); appendLine("PublicKey = ${o.serverPub}"); if (o.psk != null) appendLine("PresharedKey = ${o.psk}")
        appendLine("Endpoint = ${o.endpoint}"); appendLine("AllowedIPs = ${o.allowedIps}"); appendLine("PersistentKeepalive = 25")
    }

    // ============================================================ OpenSSL 명령

    class SslIn(val cn: String, val sans: List<String>, val alg: Int, val days: Int, val org: String, val country: String, val base: String, val host: String)

    val SSL_ALGS = listOf("RSA 2048", "RSA 3072", "RSA 4096", "EC P-256", "EC P-384", "Ed25519")

    fun genpkey(alg: Int, out: String): String = when (alg) {
        0, 1, 2 -> "openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:${listOf(2048, 3072, 4096)[alg]} -out $out"
        3 -> "openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -out $out"
        4 -> "openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-384 -out $out"
        else -> "openssl genpkey -algorithm ED25519 -out $out"
    }

    fun sanText(sans: List<String>): String = sans.joinToString(",") { if (IpUtil.parse(it) != null) "IP:$it" else "DNS:$it" }

    fun subj(o: SslIn): String = "/" + listOfNotNull(if (o.country.isNotEmpty()) "C=${o.country}" else null, if (o.org.isNotEmpty()) "O=${o.org}" else null, "CN=${o.cn}").joinToString("/")

    /** 인증서·키 이름은 base 로. 각 항목은 (제목, 명령 여러 줄, 설명) */
    fun openssl(op: Int, o: SslIn): List<Triple<String, String, String>> {
        val b = o.base; val san = sanText(o.sans.ifEmpty { listOf(o.cn) })
        return when (op) {
            0 -> listOf(Triple("자체 서명 인증서 + 키", "${genpkey(o.alg, "$b.key")}\nopenssl req -new -x509 -key $b.key -out $b.crt -days ${o.days} -subj \"${subj(o)}\" -addext \"subjectAltName=$san\"\nchmod 600 $b.key",
                "키를 만들고, 그 키로 서명한 인증서(.crt)를 ${o.days}일 동안 쓰도록 만들어요. SAN 에 적은 이름·IP 로 접속할 때 브라우저가 이름을 확인해요. 인증기관이 서명한 게 아니라서 브라우저가 경고를 띄워요(내 장비·시험용)."))
            1 -> listOf(Triple("키 + CSR(인증서 서명 요청)", "${genpkey(o.alg, "$b.key")}\nopenssl req -new -key $b.key -out $b.csr -subj \"${subj(o)}\" -addext \"subjectAltName=$san\"\nchmod 600 $b.key",
                "$b.csr 를 인증기관(Let's Encrypt 가 아닌 유료 인증기관 등)에 내면 서명된 인증서를 돌려줘요. 키($b.key)는 절대 보내지 마세요."))
            2 -> listOf(Triple("인증서 + 키 → PFX(PKCS#12)", "openssl pkcs12 -export -inkey $b.key -in $b.crt -out $b.pfx -name \"${o.cn}\"", "윈도·자바·메일 프로그램 등이 쓰는 한 파일(.pfx)로 묶어요. 내보낼 때 비밀번호를 물어봐요. 체인 인증서가 있으면 -certfile chain.crt 를 더하세요."))
            3 -> listOf(Triple("PFX → PEM(키·인증서 분리)", "openssl pkcs12 -in $b.pfx -nocerts -nodes -out $b.key\nopenssl pkcs12 -in $b.pfx -clcerts -nokeys -out $b.crt\nchmod 600 $b.key", "PFX 를 풀어서 개인키(.key, 암호 없이)와 인증서(.crt)로 나눠요. 개인키 파일은 권한을 600 으로 하세요."))
            4 -> listOf(Triple("인증서 내용 보기", "openssl x509 -in $b.crt -noout -subject -issuer -dates -ext subjectAltName\nopenssl x509 -in $b.crt -noout -fingerprint -sha256\nopenssl x509 -in $b.crt -noout -checkend 2592000 && echo \"30일 안에 만료되지 않아요\" || echo \"30일 안에 만료돼요\"", "주체·발급자·유효기간·SAN 과 SHA-256 지문을 보고, 30일(2592000초) 안에 만료되는지 확인해요. -checkend 는 만료되면 종료 코드 1 을 줘서 스크립트에 쓰기 좋아요."))
            5 -> { val h0 = if (o.host.startsWith("[")) o.host.substring(1, o.host.indexOf(']')) else o.host.substringBeforeLast(':'); val p = o.host.substringAfterLast(':'); val c = if (h0.contains(':')) "[$h0]" else h0
                listOf(Triple("서버가 주는 인증서 확인", "echo | openssl s_client -connect $c:$p -servername $h0 2>/dev/null | openssl x509 -noout -subject -issuer -dates -ext subjectAltName\necho | openssl s_client -connect $c:$p -servername $h0 -showcerts 2>/dev/null | grep -E 'depth|verify|Verif'",
                    "서버에 접속해서 인증서의 주체·발급자·유효기간·SAN 을 보여 줘요. 두 번째 줄은 체인 검증 결과를 보여 줘요. (이 명령은 해당 서버에 TLS 로 접속해요.)")) }
            6 -> listOf(Triple("인증서와 개인키가 짝인지 확인", "openssl x509 -in $b.crt -noout -pubkey | openssl sha256\nopenssl pkey -in $b.key -pubout | openssl sha256", "두 줄의 해시가 같으면 짝이 맞는 거예요. (RSA·EC·Ed25519 모두 쓸 수 있어요.)"))
            7 -> listOf(Triple("인증서 체인 검증", "openssl verify -CAfile ca-bundle.crt -untrusted intermediate.crt $b.crt", "서버 인증서를 중간·루트 인증서까지 거슬러 올라가 검증해요. \"OK\" 가 나와야 해요."))
            else -> listOf(Triple("무작위 비밀번호·키", "openssl rand -base64 32\nopenssl rand -hex 32\nopenssl passwd -6", "처음 두 줄은 32바이트 무작위 값을 Base64·16진수로, 마지막은 비밀번호를 SHA-512 crypt(\$6\$) 해시로 바꿔요(/etc/shadow 용)."))
        }
    }
}
