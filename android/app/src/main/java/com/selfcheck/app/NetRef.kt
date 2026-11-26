package com.selfcheck.app

/** 프로토콜·네트워크 사전 17가지 (모두 오프라인, 검색 가능한 표) */
object RefTools {
    private const val R = NetGroups.REF

    /** "a|b|c" 줄들을 칸으로 나눔 */
    internal fun table(vararg lines: String): List<List<String>> = lines.map { l -> l.split('|').map { it.trim() } }

    /** 표 하나를 보여 주는 사전 도구. search = 검색 칸 안내(없으면 검색 칸 없음) */
    internal fun ref(
        id: String, title: String, desc: String, header: List<String>, rows: List<List<String>>, group: String = R,
        search: String? = null, footer: String? = null, chips: List<Pair<String, String>> = emptyList(),
    ): NetTool {
        val fields: Array<Field> = if (search != null) arrayOf(text("q", "검색", search, "", chips)) else emptyArray<Field>()
        return calc(id, group, title, desc, *fields, live = search != null, auto = true) { i ->
            val q = i.str("q").lowercase()
            val hit = if (q.isEmpty()) rows else rows.filter { r -> r.any { it.lowercase().contains(q) } }
            result {
                if (hit.isEmpty()) note("\"${i.str("q")}\" 와 맞는 항목이 없어요.", 1)
                else {
                    header(*header.toTypedArray())
                    for (r in hit) rowList(r)
                    if (q.isNotEmpty()) kv("찾은 항목", "${hit.size}개 / 전체 ${rows.size}개")
                }
                if (footer != null && q.isEmpty()) note(footer)
            }
        }
    }

    internal val PORTS = table(
        "7|TCP·UDP|Echo|받은 데이터를 그대로 돌려줌 (시험용)", "9|TCP·UDP|Discard|받은 데이터를 버림 (시험용), Wake-on-LAN 에도 쓰임", "13|TCP·UDP|Daytime|현재 날짜·시간 글자",
        "17|TCP·UDP|QOTD|오늘의 명언 (거의 안 씀)", "19|TCP·UDP|Chargen|글자 계속 생성 (증폭 공격에 악용되어 막아야 함)", "20|TCP|FTP 데이터|FTP 파일 전송 통로",
        "21|TCP|FTP|파일 전송 제어 (암호화 없음)", "22|TCP|SSH|암호화된 원격 접속·SFTP·SCP", "23|TCP|Telnet|암호화 없는 원격 접속 (쓰지 마세요)", "25|TCP|SMTP|메일 서버끼리 전달",
        "37|TCP·UDP|Time|옛 시간 프로토콜", "43|TCP|WHOIS|도메인·IP 등록 정보 조회", "49|TCP·UDP|TACACS+|네트워크 장비 로그인 인증", "53|TCP·UDP|DNS|도메인 이름 풀이",
        "67|UDP|DHCP 서버|IP 주소 자동 배정 (서버)", "68|UDP|DHCP 클라이언트|IP 주소 자동 배정 (기기)", "69|UDP|TFTP|단순 파일 전송 (장비 부팅·펌웨어)", "70|TCP|Gopher|옛 정보 검색 서비스",
        "79|TCP|Finger|사용자 정보 조회 (거의 안 씀)", "80|TCP|HTTP|웹 (암호화 없음)", "88|TCP·UDP|Kerberos|윈도 도메인 등 인증", "110|TCP|POP3|메일 받기 (암호화 없음)",
        "111|TCP·UDP|RPC portmapper|리눅스 원격 호출 안내", "113|TCP|Ident|접속 사용자 확인 (옛 방식)", "119|TCP|NNTP|유즈넷 뉴스", "123|UDP|NTP|시간 동기화",
        "135|TCP|MS RPC|윈도 원격 호출 (인터넷에 열면 안 됨)", "137|UDP|NetBIOS 이름|윈도 옛 이름 서비스", "138|UDP|NetBIOS 데이터그램|윈도 옛 공유", "139|TCP|NetBIOS 세션|윈도 옛 파일 공유",
        "143|TCP|IMAP|메일 받기 (암호화 없음)", "161|UDP|SNMP|네트워크 장비 상태 조회", "162|UDP|SNMP Trap|장비 경보 수신", "179|TCP|BGP|인터넷 경로 교환 (통신사)", "194|TCP|IRC|옛 채팅",
        "389|TCP·UDP|LDAP|계정 디렉터리 (암호화 없음)", "427|TCP·UDP|SLP|서비스 위치 찾기", "443|TCP|HTTPS|암호화된 웹 (UDP 443 은 QUIC·HTTP/3)", "445|TCP|SMB|윈도 파일 공유 (인터넷에 열면 위험)",
        "464|TCP·UDP|Kerberos 비밀번호|비밀번호 변경", "465|TCP|SMTPS|암호화 메일 보내기", "500|UDP|IKE|IPsec VPN 키 교환", "514|UDP|Syslog|장비 로그 전송 (TCP 514 는 옛 rsh)", "515|TCP|LPD|프린터 인쇄",
        "520|UDP|RIP|옛 라우팅 프로토콜", "524|TCP|NCP|넷웨어 파일 서비스", "546|UDP|DHCPv6 클라이언트|IPv6 주소 자동 배정", "547|UDP|DHCPv6 서버|IPv6 주소 자동 배정", "548|TCP|AFP|맥 파일 공유 (옛 방식)",
        "554|TCP·UDP|RTSP|카메라·영상 스트림", "587|TCP|SMTP 제출|메일 앱이 보낼 때 (STARTTLS)", "593|TCP|HTTP RPC|윈도 RPC over HTTP", "631|TCP·UDP|IPP/CUPS|프린터 공유",
        "636|TCP|LDAPS|암호화된 LDAP", "853|TCP·UDP|DNS over TLS|암호화된 DNS (Private DNS)", "873|TCP|rsync|파일 동기화", "902|TCP·UDP|VMware|ESXi 관리", "989|TCP|FTPS 데이터|암호화 FTP",
        "990|TCP|FTPS 제어|암호화 FTP", "993|TCP|IMAPS|암호화 메일 받기", "995|TCP|POP3S|암호화 메일 받기", "1080|TCP|SOCKS|프록시", "1194|UDP·TCP|OpenVPN|VPN", "1433|TCP|SQL Server|데이터베이스",
        "1434|UDP|SQL Server 브라우저|SQL Server 위치 안내", "1521|TCP|Oracle|데이터베이스", "1701|UDP|L2TP|VPN 터널", "1723|TCP|PPTP|구형 VPN (보안 약함)", "1812|UDP|RADIUS 인증|Wi-Fi·VPN 계정 인증",
        "1813|UDP|RADIUS 회계|사용 기록", "1883|TCP|MQTT|IoT 메시지 (암호화 없음)", "1900|UDP|SSDP/UPnP|기기 자동 찾기 (공유기 UPnP)", "2049|TCP·UDP|NFS|리눅스 파일 공유",
        "2082|TCP|cPanel|웹호스팅 관리", "2083|TCP|cPanel(SSL)|웹호스팅 관리 (암호화)", "2181|TCP|ZooKeeper|분산 시스템 조정", "2375|TCP|Docker|원격 API (암호화 없음, 인터넷에 열면 위험)", "2376|TCP|Docker(TLS)|원격 API (암호화)",
        "2379|TCP|etcd|쿠버네티스 저장소 클라이언트", "2380|TCP|etcd 피어|etcd 서버끼리", "3000|TCP|개발 서버|Node·Grafana 등", "3128|TCP|Squid|프록시", "3306|TCP|MySQL/MariaDB|데이터베이스",
        "3389|TCP·UDP|RDP|윈도 원격 데스크톱 (인터넷에 열면 공격 대상)", "3478|UDP·TCP|STUN/TURN|화상통화 연결 보조", "3690|TCP|Subversion|SVN 소스 저장소", "4369|TCP|EPMD|Erlang/RabbitMQ 안내",
        "4500|UDP|IPsec NAT-T|NAT 뒤 IPsec VPN", "4789|UDP|VXLAN|가상 네트워크 터널", "5000|TCP|UPnP·NAS·개발 서버|Synology NAS 관리, Flask 등", "5060|TCP·UDP|SIP|인터넷 전화 신호", "5061|TCP|SIP(TLS)|암호화된 인터넷 전화 신호",
        "5222|TCP|XMPP|메신저 클라이언트", "5353|UDP|mDNS|같은 망에서 기기 이름 찾기 (Bonjour)", "5432|TCP|PostgreSQL|데이터베이스", "5555|TCP|ADB|안드로이드 디버그 (열려 있으면 위험)", "5601|TCP|Kibana|로그 분석 화면",
        "5672|TCP|AMQP|RabbitMQ 메시지", "5900|TCP|VNC|원격 화면 공유 (인터넷에 열면 위험)", "5985|TCP|WinRM|윈도 원격 관리", "5986|TCP|WinRM(TLS)|윈도 원격 관리 (암호화)", "6000|TCP|X11|리눅스 원격 화면",
        "6379|TCP|Redis|캐시·데이터베이스 (인터넷에 열면 위험)", "6443|TCP|Kubernetes API|쿠버네티스 제어", "6667|TCP|IRC|채팅", "7000|TCP|Cassandra·AirPlay|데이터베이스 / 애플 화면 공유", "7547|TCP|TR-069|통신사 공유기 원격 관리",
        "8000|TCP|HTTP 대체|개발·관리 화면", "8008|TCP|HTTP 대체|크롬캐스트 등", "8009|TCP|Chromecast·AJP|크롬캐스트 / 톰캣 연동", "8080|TCP|HTTP 대체|웹 관리 화면·프록시", "8081|TCP|HTTP 대체|관리 화면",
        "8086|TCP|InfluxDB|시계열 데이터베이스", "8443|TCP|HTTPS 대체|암호화 웹 관리 화면", "8883|TCP|MQTT(TLS)|IoT 메시지 (암호화)", "8888|TCP|HTTP 대체|Jupyter 등", "9000|TCP|웹 관리 화면|Portainer·SonarQube 등",
        "9090|TCP|Prometheus·Cockpit|모니터링·서버 관리", "9092|TCP|Kafka|메시지 큐", "9100|TCP|프린터 RAW·exporter|프린터 직접 인쇄 / 모니터링", "9200|TCP|Elasticsearch|검색 엔진 (인터넷에 열면 위험)", "9300|TCP|Elasticsearch 노드|서버끼리",
        "9418|TCP|Git|git:// 프로토콜", "10000|TCP|Webmin|서버 관리 웹", "11211|TCP·UDP|Memcached|캐시 (인터넷에 열면 위험)", "15672|TCP|RabbitMQ 관리|관리 화면", "25565|TCP|Minecraft|마인크래프트 서버",
        "27015|UDP·TCP|Steam·게임 서버|Source 엔진 게임 서버", "27017|TCP|MongoDB|데이터베이스 (인터넷에 열면 위험)", "32400|TCP|Plex|미디어 서버", "33434|UDP|traceroute|경로 추적 시작 포트", "37777|TCP|Dahua DVR|카메라·녹화기",
        "51820|UDP|WireGuard|VPN 기본 포트", "62078|TCP|iPhone lockdown|아이폰·아이패드 동기화",
    )

    private val HTTP = table(
        "100|Continue|요청 헤더를 받았으니 본문을 계속 보내도 돼요", "101|Switching Protocols|프로토콜 전환 (웹소켓 등)", "102|Processing|처리 중 (WebDAV)", "103|Early Hints|최종 응답 전에 미리 힌트",
        "200|OK|성공", "201|Created|새 자원이 만들어졌어요", "202|Accepted|접수됐지만 아직 처리 전", "203|Non-Authoritative|프록시가 바꾼 정보", "204|No Content|성공, 돌려줄 내용 없음", "205|Reset Content|성공, 입력 칸을 비워 달라는 뜻",
        "206|Partial Content|일부만 전송 (이어받기·Range)", "207|Multi-Status|여러 결과 (WebDAV)", "208|Already Reported|이미 보고됨 (WebDAV)", "226|IM Used|차이만 전송",
        "300|Multiple Choices|선택지가 여러 개", "301|Moved Permanently|영구 이동 — 새 주소를 쓰세요 (검색엔진도 이전)", "302|Found|임시 이동", "303|See Other|다른 주소를 GET 으로 보세요",
        "304|Not Modified|바뀐 게 없으니 저장해 둔 걸 쓰세요 (캐시)", "307|Temporary Redirect|임시 이동 (요청 방식 유지)", "308|Permanent Redirect|영구 이동 (요청 방식 유지)",
        "400|Bad Request|요청 모양이 잘못됐어요", "401|Unauthorized|로그인(인증)이 필요하거나 실패", "402|Payment Required|결제 필요 (거의 안 씀)", "403|Forbidden|권한이 없어요 (로그인해도 접근 불가)",
        "404|Not Found|없는 주소", "405|Method Not Allowed|이 주소에 쓸 수 없는 요청 방식", "406|Not Acceptable|원하는 형식으로 줄 수 없음", "407|Proxy Auth Required|프록시 인증 필요", "408|Request Timeout|요청이 너무 오래 걸림",
        "409|Conflict|현재 상태와 충돌 (중복 등)", "410|Gone|영구 삭제됨", "411|Length Required|내용 길이 필요", "412|Precondition Failed|조건이 맞지 않음", "413|Content Too Large|보낸 내용이 너무 큼 (업로드 용량 제한)",
        "414|URI Too Long|주소가 너무 김", "415|Unsupported Media Type|지원하지 않는 형식", "416|Range Not Satisfiable|요청한 범위가 잘못됨", "417|Expectation Failed|기대 조건 실패", "418|I'm a teapot|주전자라서 커피 못 끓여요 (장난 RFC 2324)",
        "421|Misdirected Request|엉뚱한 서버로 보냄", "422|Unprocessable Content|형식은 맞지만 내용 검증 실패", "423|Locked|잠겨 있음", "424|Failed Dependency|앞선 요청 실패로 실패", "425|Too Early|너무 이른 요청 (TLS 0-RTT)",
        "426|Upgrade Required|프로토콜을 올려야 해요", "428|Precondition Required|조건부 요청 필요", "429|Too Many Requests|요청이 너무 많아요 (잠시 후 다시)", "431|Header Fields Too Large|헤더가 너무 큼", "451|Unavailable For Legal Reasons|법적 사유로 차단",
        "499|Client Closed Request|(nginx) 손님이 먼저 끊음", "500|Internal Server Error|서버 내부 오류", "501|Not Implemented|지원하지 않는 기능", "502|Bad Gateway|중간 서버(프록시)가 상위 서버에서 잘못된 응답을 받음",
        "503|Service Unavailable|점검 중이거나 과부하", "504|Gateway Timeout|상위 서버 응답 시간 초과", "505|HTTP Version Not Supported|지원하지 않는 HTTP 버전", "506|Variant Also Negotiates|설정 오류", "507|Insufficient Storage|서버 저장 공간 부족",
        "508|Loop Detected|무한 반복 감지", "510|Not Extended|확장 필요", "511|Network Auth Required|네트워크 로그인 필요 (공용 Wi-Fi 로그인 화면)",
        "520|Web Server Unknown Error|(Cloudflare) 원본 서버의 알 수 없는 오류", "521|Web Server Is Down|(Cloudflare) 원본 서버가 꺼져 있음", "522|Connection Timed Out|(Cloudflare) 원본 서버 연결 시간 초과",
        "523|Origin Is Unreachable|(Cloudflare) 원본 서버에 닿을 수 없음", "524|A Timeout Occurred|(Cloudflare) 원본 서버 응답이 너무 늦음", "525|SSL Handshake Failed|(Cloudflare) 원본 서버와 TLS 협상 실패", "526|Invalid SSL Certificate|(Cloudflare) 원본 서버 인증서 오류",
    )

    private val DNS_TYPES = table(
        "1|A|도메인 → IPv4 주소", "2|NS|이 도메인을 관리하는 네임서버", "5|CNAME|다른 이름의 별칭", "6|SOA|영역 관리 정보 (일련번호·갱신 주기)", "12|PTR|IP → 도메인 이름 (역방향)", "15|MX|메일을 받는 서버와 우선순위",
        "16|TXT|글자 정보 (SPF·DKIM·DMARC·소유 확인)", "28|AAAA|도메인 → IPv6 주소", "33|SRV|서비스 위치(서버·포트) 안내", "35|NAPTR|이름 규칙 변환 (전화번호 등)", "41|OPT|EDNS0 확장 정보 (실제 레코드 아님)",
        "43|DS|DNSSEC 위임 서명 (상위 영역에 등록)", "46|RRSIG|DNSSEC 레코드 서명", "47|NSEC|DNSSEC 존재하지 않음 증명", "48|DNSKEY|DNSSEC 공개키", "50|NSEC3|DNSSEC 존재하지 않음 증명 (해시)",
        "52|TLSA|DANE: 인증서 지문 고정", "64|SVCB|서비스 연결 정보", "65|HTTPS|HTTPS 연결 정보 (HTTP/3·ECH 힌트)", "99|SPF|(폐기) 메일 발신 허용 — TXT 로 대체", "252|AXFR|영역 전체 전송 (관리용, 막아야 함)",
        "255|ANY|모든 레코드 (대부분 서버가 거부)", "257|CAA|인증서를 발급해도 되는 기관 지정",
    )

    private val RCODES = table(
        "0|NOERROR|오류 없음 (레코드가 없을 때도 NOERROR 에 답 0개일 수 있어요)", "1|FORMERR|질문 형식이 잘못됨", "2|SERVFAIL|서버 내부 문제 (DNSSEC 검증 실패, 상위 서버 응답 없음 등)",
        "3|NXDOMAIN|그런 도메인이 없어요", "4|NOTIMP|지원하지 않는 요청", "5|REFUSED|서버가 답을 거부 (허용되지 않은 질문자)", "6|YXDOMAIN|있으면 안 되는 이름이 있음", "7|YXRRSET|있으면 안 되는 레코드 묶음이 있음",
        "8|NXRRSET|있어야 할 레코드 묶음이 없음", "9|NOTAUTH|이 영역의 권한 없음", "10|NOTZONE|영역 밖의 이름", "16|BADVERS/BADSIG|EDNS 버전 오류 / 서명 오류", "17|BADKEY|키를 찾을 수 없음", "18|BADTIME|서명 시간 오류", "23|BADCOOKIE|쿠키 오류",
    )

    private val ICMP = table(
        "0|0|Echo Reply|핑 응답", "3|0|Network Unreachable|네트워크에 닿을 수 없음", "3|1|Host Unreachable|호스트에 닿을 수 없음", "3|2|Protocol Unreachable|프로토콜 미지원", "3|3|Port Unreachable|포트가 닫혀 있음 (UDP 에서 닫힌 포트의 응답)",
        "3|4|Fragmentation Needed|패킷이 커서 쪼개야 하는데 DF 가 켜져 있음 (MTU 탐색)", "3|9/10|Network/Host Prohibited|관리자가 막음", "3|13|Communication Prohibited|방화벽이 막음", "5|0~3|Redirect|더 좋은 경로 알림",
        "8|0|Echo Request|핑 요청", "9|0|Router Advertisement|라우터 광고", "10|0|Router Solicitation|라우터 찾기", "11|0|TTL Exceeded|경유 한도(TTL) 초과 — traceroute 가 이 응답으로 경로를 찾아요",
        "11|1|Reassembly Timeout|조각 모으기 시간 초과", "12|0|Parameter Problem|헤더 오류", "13|0|Timestamp|시간 요청", "14|0|Timestamp Reply|시간 응답", "ICMPv6 1|0~7|Destination Unreachable|IPv6 에서 닿을 수 없음",
        "ICMPv6 2|0|Packet Too Big|IPv6 에서 패킷이 큼 (필수: 막으면 접속이 멈춤)", "ICMPv6 3|0|Time Exceeded|IPv6 TTL(hop limit) 초과", "ICMPv6 128|0|Echo Request|IPv6 핑 요청", "ICMPv6 129|0|Echo Reply|IPv6 핑 응답",
        "ICMPv6 133|0|Router Solicitation|IPv6 라우터 찾기", "ICMPv6 134|0|Router Advertisement|IPv6 라우터 광고 (주소 자동 설정)", "ICMPv6 135|0|Neighbor Solicitation|IPv4 의 ARP 와 같은 역할", "ICMPv6 136|0|Neighbor Advertisement|이웃 광고",
    )

    private val IPPROTO = table(
        "1|ICMP|핑·오류 알림", "2|IGMP|멀티캐스트 그룹 관리", "4|IP-in-IP|IP 를 IP 로 감싼 터널", "6|TCP|연결형 전송 (웹·메일·SSH)", "8|EGP|옛 경로 교환", "17|UDP|비연결 전송 (DNS·영상·게임)", "41|IPv6 캡슐화|IPv4 위에 IPv6 터널 (6in4·6to4)",
        "47|GRE|범용 터널", "50|ESP|IPsec 암호화 데이터", "51|AH|IPsec 인증 헤더", "58|ICMPv6|IPv6 용 ICMP", "88|EIGRP|시스코 라우팅", "89|OSPF|내부 라우팅", "103|PIM|멀티캐스트 라우팅", "112|VRRP|라우터 이중화", "115|L2TP|VPN 터널", "132|SCTP|스트림 전송 (통신 신호)",
    )

    private val ETHERTYPE = table(
        "0x0800|IPv4|IPv4 패킷", "0x0806|ARP|IP 주소 → MAC 주소 찾기", "0x0842|Wake-on-LAN|원격 켜기 (일부 방식)", "0x8100|802.1Q|VLAN 태그", "0x86DD|IPv6|IPv6 패킷", "0x8847|MPLS|MPLS 유니캐스트",
        "0x8863|PPPoE 발견|PPPoE 연결 시작", "0x8864|PPPoE 세션|PPPoE 데이터", "0x88A8|802.1ad|QinQ (이중 VLAN)", "0x88CC|LLDP|이웃 장비 알림", "0x88E5|MACsec|이더넷 암호화",
    )

    private val DSCP = table(
        "CS0 (BE)|0|기본 (최선 노력)", "CS1|8|저우선 (백업·대용량)", "AF11/12/13|10/12/14|데이터 클래스 1", "CS2|16|운영·관리", "AF21/22/23|18/20/22|트랜잭션 데이터", "CS3|24|신호 (SIP 등)",
        "AF31/32/33|26/28/30|스트리밍 영상", "CS4|32|실시간 영상 회의", "AF41/42/43|34/36/38|대화형 영상", "CS5|40|방송 영상", "EF|46|실시간 음성 (VoIP) — 최우선", "CS6|48|네트워크 제어 (라우팅)", "CS7|56|네트워크 제어",
    )

    private val SPECIAL = table(
        "0.0.0.0/8|이 네트워크|출발지로만 쓰이는 \"여기\" 주소", "10.0.0.0/8|사설|내부망", "100.64.0.0/10|통신사 공용(CGNAT)|통신사가 가입자에게 나눠 주는 공용 사설 대역", "127.0.0.0/8|루프백|자기 자신",
        "169.254.0.0/16|링크 로컬|DHCP 실패 시 자동 주소 (APIPA)", "172.16.0.0/12|사설|내부망 (172.16~172.31)", "192.0.0.0/24|IETF 프로토콜 할당|특수 용도", "192.0.2.0/24|문서용 (TEST-NET-1)|예시·설명용",
        "192.88.99.0/24|6to4 릴레이 (폐기)|옛 터널", "192.168.0.0/16|사설|가정·사무실 공유기 기본", "198.18.0.0/15|성능 시험용|벤치마크", "198.51.100.0/24|문서용 (TEST-NET-2)|예시·설명용",
        "203.0.113.0/24|문서용 (TEST-NET-3)|예시·설명용", "224.0.0.0/4|멀티캐스트|그룹 전송", "240.0.0.0/4|예약|미래용", "255.255.255.255/32|브로드캐스트|같은 망 모두",
        "::/128|미지정|\"주소 없음\"", "::1/128|루프백|자기 자신", "::ffff:0:0/96|IPv4-매핑|IPv4 를 IPv6 로 표현", "64:ff9b::/96|NAT64|IPv6 전용망 → IPv4", "100::/64|폐기 전용|버릴 트래픽",
        "2001::/32|Teredo|옛 IPv6 터널", "2001:db8::/32|문서용|예시·설명용", "2002::/16|6to4|옛 IPv6 터널", "2000::/3|글로벌 유니캐스트|인터넷 주소", "fc00::/7|고유 로컬(ULA)|IPv6 사설", "fe80::/10|링크 로컬|같은 망 안에서만", "ff00::/8|멀티캐스트|그룹 전송",
    )

    private val OSI = table(
        "7|응용|HTTP·DNS·SMTP·SSH|데이터|사용자가 쓰는 서비스", "6|표현|TLS(일부)·JPEG·인코딩|데이터|형식 변환·암호화·압축", "5|세션|NetBIOS·RPC|데이터|대화(세션) 열고 닫기", "4|전송|TCP·UDP|세그먼트/데이터그램|프로세스(포트)끼리 전달·신뢰성",
        "3|네트워크|IP·ICMP·라우팅|패킷|주소 지정과 경로 선택 (라우터)", "2|데이터 링크|이더넷·Wi-Fi·ARP|프레임|같은 망 안에서 전달 (스위치·MAC)", "1|물리|케이블·전파·허브|비트|신호 전송",
    )

    private val WIFI_STD = table(
        "802.11b|Wi-Fi 1|1999|2.4 GHz|11 Mbps", "802.11a|Wi-Fi 2|1999|5 GHz|54 Mbps", "802.11g|Wi-Fi 3|2003|2.4 GHz|54 Mbps", "802.11n|Wi-Fi 4|2009|2.4·5 GHz|600 Mbps", "802.11ac|Wi-Fi 5|2013|5 GHz|약 6.9 Gbps",
        "802.11ax|Wi-Fi 6 / 6E|2019 / 2021|2.4·5 GHz (6E: +6 GHz)|9.6 Gbps", "802.11be|Wi-Fi 7|2024|2.4·5·6 GHz|약 46 Gbps",
    )

    private val WIFI_SEC = table(
        "Open|암호 없음|누구나 연결, 내용이 그대로 보여요", "WEP|1999|RC4, 몇 분이면 깨져요 — 쓰면 안 돼요", "WPA (TKIP)|2003|구식, 취약 — 쓰지 마세요", "WPA2-Personal (AES)|2004|지금도 널리 쓰임, 비밀번호가 약하면 사전 공격에 취약",
        "WPA2-Enterprise|2004|계정별 인증(802.1X/RADIUS), 회사용", "WPA3-Personal (SAE)|2018|오프라인 사전 공격 방어, 가장 권장", "WPA3-Enterprise|2018|192비트 보안 모드 지원", "OWE (Enhanced Open)|2018|암호 없는 공용 Wi-Fi 에서 도청을 막아 줌",
    )

    private val CABLES = table(
        "Cat5|100 Mbps|100 MHz|100 m|거의 안 씀", "Cat5e|1 Gbps|100 MHz|100 m|가정·사무실 기본", "Cat6|1 Gbps (10 Gbps 55 m)|250 MHz|100 m|10G 는 짧은 거리", "Cat6a|10 Gbps|500 MHz|100 m|10G 권장",
        "Cat7|10 Gbps|600 MHz|100 m|차폐, 비표준 커넥터 (일반 RJ45 로는 거의 안 씀)", "Cat8|25·40 Gbps|2000 MHz|30 m|데이터센터 서버-스위치",
        "광 OM3 (다중모드)|10 Gbps|-|300 m|건물 안", "광 OM4 (다중모드)|10 Gbps|-|400 m|건물 안", "광 OS2 (단일모드)|10 Gbps 이상|-|10 km 이상|장거리·통신사",
    )

    private val PUBLIC_DNS = table(
        "구글|8.8.8.8 / 8.8.4.4|2001:4860:4860::8888|가장 널리 쓰임", "클라우드플레어|1.1.1.1 / 1.0.0.1|2606:4700:4700::1111|빠르고 개인정보 중시", "Quad9|9.9.9.9 / 149.112.112.112|2620:fe::fe|악성 도메인 차단",
        "OpenDNS (시스코)|208.67.222.222 / 208.67.220.220|2620:119:35::35|필터링 옵션", "AdGuard|94.140.14.14 / 94.140.15.15|2a10:50c0::ad1:ff|광고·추적 차단",
        "KT|168.126.63.1 / 168.126.63.2|-|국내 통신사", "SK브로드밴드|210.220.163.82 / 219.250.36.130|-|국내 통신사", "LG U+|164.124.101.2 / 203.248.252.2|-|국내 통신사",
    )

    private val SEC_HEADERS = table(
        "Strict-Transport-Security|브라우저가 항상 https 로만 접속하게 함|max-age=31536000; includeSubDomains", "Content-Security-Policy|불러올 수 있는 스크립트·이미지 출처를 제한 (XSS 방어)|default-src 'self'",
        "X-Content-Type-Options|파일 형식을 멋대로 추측하지 못하게 함|nosniff", "X-Frame-Options|다른 사이트가 내 페이지를 iframe 에 넣지 못하게 함 (클릭재킹 방어)|DENY 또는 SAMEORIGIN",
        "Referrer-Policy|다른 사이트로 갈 때 보내는 이전 주소 정보 제한|strict-origin-when-cross-origin", "Permissions-Policy|카메라·위치 등 브라우저 기능 사용 제한|camera=(), microphone=(), geolocation=()",
        "Cross-Origin-Opener-Policy|다른 출처 창과 분리|same-origin", "Cross-Origin-Resource-Policy|다른 출처가 내 자원을 가져가는 것 제한|same-origin", "Cache-Control|민감한 페이지 저장 방지|no-store", "X-XSS-Protection|(폐기) 옛 브라우저 필터 — 끄거나 쓰지 않음|0",
    )

    private val GLOSSARY = table(
        "ARP|IP 주소로 같은 망 기기의 MAC 주소를 알아내는 방법", "ASN|인터넷에서 통신사·기관을 구분하는 번호 (자율 시스템 번호)", "대역폭(Bandwidth)|한 번에 보낼 수 있는 데이터 양, 회선의 \"굵기\"", "BGP|통신사끼리 인터넷 경로를 주고받는 프로토콜",
        "브리지(Bridge)|두 네트워크를 이어 같은 망처럼 만드는 장비", "브로드캐스트|같은 망의 모든 기기에게 보내는 전송", "CDN|전 세계에 복사본을 두고 가까운 곳에서 전달하는 서비스", "CIDR|접두 길이로 주소 범위를 나타내는 방식 (예: /24)",
        "CGNAT|통신사가 한 공인 IP 를 여러 가입자가 나눠 쓰게 하는 NAT", "DDoS|여러 곳에서 한꺼번에 몰려와 서비스를 마비시키는 공격", "DHCP|IP 주소·게이트웨이·DNS 를 자동으로 나눠 주는 서비스", "DMZ|내부망과 인터넷 사이에 두는 공개 서버용 구역",
        "DNS|도메인 이름을 IP 주소로 바꿔 주는 전화번호부", "DoH|HTTPS 안에서 DNS 를 조회해 숨기는 방식", "DoT|TLS 로 암호화한 DNS (포트 853)", "DNSSEC|DNS 응답이 위조되지 않았음을 서명으로 증명",
        "도메인|사람이 읽는 인터넷 주소 (example.com)", "이더넷(Ethernet)|유선 LAN 의 표준 방식", "방화벽|들어오고 나가는 연결을 규칙으로 허용·차단하는 장치·소프트웨어", "FQDN|호스트명까지 모두 쓴 완전한 도메인 (www.example.com)",
        "게이트웨이|내 망 밖으로 나가는 출입구 (보통 공유기)", "호스트|네트워크에 연결된 기기", "HTTP/HTTPS|웹 통신 규칙 / 암호화된 웹 통신", "허브(Hub)|들어온 신호를 모든 포트에 뿌리는 옛 장비 (지금은 스위치)",
        "ICMP|핑·오류 알림에 쓰이는 제어 메시지 프로토콜", "IDS/IPS|침입 탐지/차단 시스템", "IPv4|32비트 주소 (약 43억 개), 점으로 나눈 숫자 4개", "IPv6|128비트 주소, 사실상 무한에 가까운 주소 공간",
        "ISP|인터넷 서비스 제공 업체 (통신사)", "지터(Jitter)|지연 시간의 들쭉날쭉한 정도 (실시간 통화·게임에 중요)", "LAN|집·사무실 같은 좁은 범위의 네트워크", "지연(Latency)|데이터가 오가는 데 걸리는 시간",
        "로드 밸런서|요청을 여러 서버에 나눠 주는 장치", "MAC 주소|네트워크 카드의 고유 주소 (48비트)", "MTU|한 번에 보낼 수 있는 최대 패킷 크기 (이더넷 1500)", "NAT|내부 사설 IP 를 공인 IP 하나로 바꿔 인터넷에 나가게 함",
        "NTP|컴퓨터 시계를 맞추는 프로토콜", "패킷(Packet)|네트워크로 보내는 데이터 조각", "패킷 손실|보낸 패킷이 도착하지 못한 비율", "핑(Ping)|ICMP 로 상대가 살아 있는지, 얼마나 걸리는지 재는 도구",
        "PoE|랜 케이블로 전기도 함께 보내는 방식 (카메라·AP)", "포트(Port)|한 기기 안에서 서비스를 구분하는 번호 (0~65535)", "포트 포워딩|공유기가 밖에서 들어온 연결을 내부 특정 기기로 넘겨 주는 설정", "프록시|중간에서 대신 요청해 주는 서버",
        "QoS|음성·영상 같은 중요한 트래픽을 먼저 보내는 우선순위 설정", "RADIUS|Wi-Fi·VPN 계정 인증 서버 프로토콜", "라우터|서로 다른 네트워크 사이에서 경로를 골라 전달하는 장비", "RTT|왕복 시간 (갔다 오는 데 걸리는 시간)",
        "SSID|Wi-Fi 이름", "서브넷(Subnet)|큰 네트워크를 나눈 작은 구역", "서브넷 마스크|주소 중 네트워크 부분을 가리는 값 (255.255.255.0)", "스위치(Switch)|MAC 주소를 보고 필요한 포트로만 전달하는 장비",
        "TCP|순서·재전송을 보장하는 연결형 전송", "TLS|통신을 암호화하는 규칙 (HTTPS 의 S)", "TTL|패킷이 거칠 수 있는 최대 횟수 (무한 반복 방지)", "UDP|확인 없이 빠르게 보내는 비연결 전송 (영상·게임·DNS)",
        "UPnP|기기가 공유기에게 포트를 자동으로 열어 달라고 요청하는 기능", "VLAN|물리적으로 한 망을 논리적으로 나눔", "VPN|공용 네트워크 위에 암호화된 개인 통로를 만드는 기술", "WAN|통신사 회선처럼 넓은 범위의 네트워크",
        "WPA2/WPA3|Wi-Fi 암호화 방식 (3 이 더 안전)", "WPS|버튼·PIN 으로 Wi-Fi 를 쉽게 연결 (보안상 끄는 것이 좋음)", "캡티브 포털|공용 Wi-Fi 에서 인터넷 전에 보이는 로그인·동의 화면", "SSID 숨김|Wi-Fi 이름을 방송하지 않음 (보안 효과는 거의 없음)",
        "메시(Mesh) Wi-Fi|여러 대가 하나의 Wi-Fi 처럼 넓게 덮는 방식", "백홀(Backhaul)|중계기·메시 장비가 본체와 연결되는 통로", "빔포밍|신호를 기기 방향으로 모아 보내는 기술", "MU-MIMO|여러 기기에 동시에 데이터를 보내는 기술",
        "Anycast|같은 주소를 여러 곳에 두고 가장 가까운 곳으로 연결", "Multicast|관심 있는 그룹에게만 보내는 전송", "mDNS|같은 망에서 이름(예: printer.local)으로 기기를 찾는 방법", "SSDP|UPnP 기기를 찾는 방송 프로토콜",
        "TTFB|요청 후 첫 응답 글자가 오기까지의 시간", "핸드셰이크|연결을 시작하며 서로 확인하는 절차 (TCP 3-way, TLS)", "세션|한 번의 연결·대화", "스니핑|네트워크 위의 패킷을 엿보는 일 (암호화로 막음)",
        "중간자 공격(MITM)|통신 중간에서 몰래 가로채거나 바꾸는 공격 (HTTPS·인증서 경고가 방어선)", "ARP 스푸핑|가짜 ARP 응답으로 트래픽을 가로채는 공격 (공용 Wi-Fi 위험)", "피싱|진짜 같은 가짜 사이트로 정보를 빼가는 사기", "포트 스캔|열린 포트를 찾아보는 점검 (내 장비만 하세요)",
    )

    val ALL: List<NetTool> = listOf(
        ref("ref_ports", "포트 번호 사전 (${PORTS.size}개)", "자주 보는 포트가 어떤 서비스인지 — 번호·이름·메일·원격 등으로 검색", listOf("포트", "프로토콜", "이름", "설명"), PORTS,
            search = "예: 443, ssh, 메일, 데이터베이스, 카메라", chips = listOf("22" to "22", "443" to "443", "메일" to "메일", "위험" to "위험")),
        ref("ref_http_status", "HTTP 상태 코드 사전", "200·301·404·502 같은 숫자가 무슨 뜻인지, 어디가 문제인지", listOf("코드", "이름", "뜻"), HTTP, search = "예: 404, 리다이렉트, 서버",
            footer = "4xx 는 요청한 쪽(주소·권한)의 문제, 5xx 는 서버쪽 문제예요. 502·504 는 앞단 프록시·로드밸런서와 뒤쪽 서버 사이의 문제예요."),
        ref("ref_dns_types", "DNS 레코드 타입 사전", "A·MX·TXT·CNAME 등 레코드가 무슨 역할인지", listOf("번호", "타입", "역할"), DNS_TYPES, search = "예: MX, 메일, 보안"),
        ref("ref_dns_rcode", "DNS 응답 코드 (RCODE)", "NXDOMAIN·SERVFAIL·REFUSED 가 무슨 뜻인지", listOf("코드", "이름", "뜻"), RCODES, search = "예: NXDOMAIN"),
        ref("ref_icmp", "ICMP 타입·코드 사전", "핑·\"도달 불가\"·TTL 초과 같은 ICMP 메시지의 뜻 (IPv4·IPv6)", listOf("타입", "코드", "이름", "뜻"), ICMP, search = "예: 도달, TTL, 핑"),
        ref("ref_ip_proto", "IP 프로토콜 번호", "IP 헤더의 \"프로토콜\" 칸 숫자 (6=TCP, 17=UDP …)", listOf("번호", "이름", "용도"), IPPROTO, search = "예: TCP, 터널"),
        ref("ref_ethertype", "이더넷 타입 (EtherType)", "이더넷 프레임이 담고 있는 것의 종류 (0x0800=IPv4 …)", listOf("값", "이름", "설명"), ETHERTYPE),
        ref("ref_dscp", "DSCP·QoS 우선순위 값", "음성·영상 우선순위를 나타내는 DSCP 값 표", listOf("이름", "값", "용도"), DSCP),
        ref("ref_special_ranges", "특수 용도 IP 대역 (IPv4·IPv6)", "사설·루프백·CGNAT·문서용·멀티캐스트 등 \"이 주소는 뭐야\" 표", listOf("대역", "이름", "설명"), SPECIAL, search = "예: 사설, 문서, ::1"),
        ref("ref_osi", "OSI 7계층 한눈에", "계층별 이름·대표 프로토콜·데이터 단위·장비", listOf("계층", "이름", "예", "단위", "하는 일"), OSI,
            footer = "TCP/IP 4계층은 응용(5~7) · 전송(4) · 인터넷(3) · 네트워크 접속(1~2) 으로 묶어요."),
        ref("ref_wifi_std", "Wi-Fi 표준 비교", "802.11 b/a/g/n/ac/ax/be 와 Wi-Fi 세대 이름·대역·속도", listOf("표준", "세대", "연도", "대역", "최대 속도(이론)"), WIFI_STD,
            footer = "최대 속도는 이상적인 이론값이에요. 실제는 보통 30~60% 정도 나와요."),
        ref("ref_wifi_sec", "Wi-Fi 보안 방식 비교", "WEP·WPA·WPA2·WPA3 중 무엇을 써야 하는지", listOf("방식", "시기", "평가"), WIFI_SEC),
        ref("ref_cables", "랜 케이블·광케이블 규격", "Cat5e·Cat6·Cat6a·Cat8·광 케이블의 속도와 거리", listOf("종류", "속도", "주파수", "최대 거리", "비고"), CABLES),
        ref("ref_public_dns", "공개 DNS 서버 목록", "구글·클라우드플레어·Quad9·국내 통신사 DNS 주소", listOf("제공자", "IPv4", "IPv6", "특징"), PUBLIC_DNS,
            footer = "DNS 를 바꾸면 접속이 빨라지거나 차단된 사이트가 풀릴 수 있지만, 입력한 도메인이 그 DNS 운영자에게 보여요."),
        ref("ref_security_headers", "웹 보안 헤더 사전", "HSTS·CSP·X-Frame-Options 등 응답 헤더가 막아 주는 것과 권장 값", listOf("헤더", "역할", "권장 값"), SEC_HEADERS),
        ref("ref_glossary", "네트워크 용어 사전 (${GLOSSARY.size}개)", "DNS·NAT·MTU·지터·CGNAT… 헷갈리는 용어를 쉽게", listOf("용어", "뜻"), GLOSSARY, search = "예: NAT, 보안, 속도, Wi-Fi"),
    )
}
