package com.selfcheck.app

import java.io.IOException
import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.Socket

/** 접속 진단 20가지 + 내 망 점검 6가지 + WHOIS 2가지 (인터넷·내 망을 사용하는 도구) */
object DiagTools {
    private const val D = NetGroups.DIAG
    private const val L = NetGroups.LAN
    private const val N = NetGroups.DNS

    private const val NOTE_WEB = "입력한 주소의 서버에 일반 웹 요청(GET/HEAD)을 한 번 보내요. 인터넷을 사용해요."
    private val URL_CHIPS = listOf("example.com" to "https://example.com", "google.com" to "https://www.google.com", "naver.com" to "https://www.naver.com", "github.com" to "https://github.com")
    private val HOST_CHIPS = listOf("example.com" to "example.com", "google.com" to "www.google.com", "naver.com" to "www.naver.com", "1.1.1.1" to "1.1.1.1")

    private fun urlField(def: String = "https://example.com") = text("u", "주소 (URL)", "예: https://example.com", def, URL_CHIPS)
    private fun hostField(def: String = "example.com", label: String = "도메인 또는 IP") = text("h", label, "예: example.com", def, HOST_CHIPS)
    private val INSECURE = listOf("인증서 검사함", "인증서 오류 무시 (위험)")

    private fun ms(v: Long) = "${v}ms"
    private fun f1(x: Double) = "%.1f".format(x)

    /** 대상 이름을 IP 로. 안 되면 null */
    private fun addrOf(h: String): InetAddress? = try { TlsInspect.resolve(h) } catch (_: Exception) { null }

    private fun socketsFor(addr: InetAddress, host: ToolHost): () -> Socket = if (IpUtil.classify(addr).local) host.lanSockets() else ({ Socket() })

    /** "https://user@Example.com:8443/path", "[::1]:443", "host:8443", "2001:db8::1" 에서 (호스트, 포트) 뽑기 */
    internal fun hostPort(input: String, defaultPort: Int = 443): Pair<String, Int> {
        var t = input.trim(); val sc = t.indexOf("://"); if (sc >= 0) t = t.substring(sc + 3)
        t = t.substringBefore('/').substringBefore('?').substringBefore('#').substringAfterLast('@')
        if (t.startsWith("[")) return t.substringAfter('[').substringBefore(']') to (t.substringAfter("]:", "").toIntOrNull()?.takeIf { it in 1..65535 } ?: defaultPort)
        if (t.count { it == ':' } == 1) return t.substringBefore(':').trimEnd('.') to (t.substringAfter(':').toIntOrNull()?.takeIf { it in 1..65535 } ?: defaultPort)
        return t.trimEnd('.') to defaultPort
    }

    internal fun titleOf(body: String?): String? = body?.let { Regex("<title[^>]*>([^<]{0,200})</title>", setOf(RegexOption.IGNORE_CASE, RegexOption.DOT_MATCHES_ALL)).find(it)?.groupValues?.get(1)?.trim()?.replace(Regex("\\s+"), " ") }?.takeIf { it.isNotEmpty() }

    internal fun timings(rb: Rb, r: HttpResult) {
        val t = r.timings
        rb.kv("DNS 조회", ms(t.dnsMs), if (t.dnsMs > 300) 1 else 0); rb.kv("TCP 연결", ms(t.connectMs), if (t.connectMs > 400) 1 else 0)
        t.tlsMs?.let { rb.kv("TLS 협상", ms(it), if (it > 600) 1 else 0) }
        rb.kv("첫 응답까지(TTFB)", ms(t.ttfbMs), if (t.ttfbMs > 1500) 2 else if (t.ttfbMs > 800) 1 else -1); rb.kv("전체", ms(t.totalMs))
    }

    internal fun httpSummary(rb: Rb, r: HttpResult) {
        rb.kv("주소", r.url); rb.kv("접속한 IP", r.remoteIp)
        rb.kv("상태", r.statusLine.removePrefix("HTTP/1.1 ").removePrefix("HTTP/1.0 "), when (r.status) { in 200..299 -> -1; in 300..399 -> 0; in 400..499 -> 1; else -> 2 })
        r.tls?.let { rb.kv("TLS", "${it.protocol} · ${it.cipher.take(40)}"); if (!it.trusted) rb.kv("인증서", it.trustError ?: "", 2); if (!it.hostnameOk) rb.kv("인증서 이름", "접속한 주소와 달라요", 2) }
        titleOf(r.body)?.let { rb.kv("페이지 제목", it) }
        for (n in listOf("Server", "Content-Type", "Content-Length", "Location", "Cache-Control", "Date", "Last-Modified")) r.header(n)?.let { rb.kv(n, it) }
    }

    private fun levelOfDays(d: Long) = if (d < 0) 2 else if (d < 14) 2 else if (d < 30) 1 else -1

    val ALL: List<NetTool> = listOf(
        online("ping_tcp", D, "TCP 핑 (연결 시간 측정)", "도메인·IP 의 포트에 반복 연결해 시간·지터·손실을 측정 (ICMP 핑이 막힌 곳도 잴 수 있어요)",
            hostField(), text("port", "포트", "예: 443", "443", listOf("443" to "443", "80" to "80", "53" to "53", "22" to "22")), choice("n", "횟수", listOf("5", "10", "20", "50"), "10"), choice("gap", "간격", listOf("0.3초", "0.5초", "1초"), "0.5초"),
            note = "상대 포트에 연결만 했다 끊어요(데이터는 보내지 않아요). 인터넷을 사용해요.") { i, host, env ->
            val h = HostInput.host(i.str("h")); if (h.isEmpty()) return@online need("도메인이나 IP 를 입력하세요")
            val port = i.int("port")?.takeIf { it in 1..65535 } ?: return@online fail("포트는 1~65535 예요")
            val addr = addrOf(h) ?: return@online fail("\"$h\" 의 주소를 찾지 못했어요")
            if (IpUtil.classify(addr).blocked) return@online fail("이 주소로는 연결할 수 없어요 (${IpUtil.classify(addr).label})")
            val n = i.str("n").toInt(); val gap = when (i.str("gap")) { "0.3초" -> 300L; "1초" -> 1000L; else -> 500L }
            val mk = socketsFor(addr, host)
            val times = ArrayList<Double>(); var lost = 0; val log = StringBuilder()
            for (k in 1..n) {
                if (env.cancel.get()) break
                env.progress("$k / $n")
                val t0 = System.nanoTime()
                try { mk().use { it.connect(InetSocketAddress(addr, port), 2000) }; val t = (System.nanoTime() - t0) / 1e6; times += t; log.append("%2d: %.1f ms\n".format(k, t)) }
                catch (e: IOException) { lost++; log.append("%2d: 응답 없음 (%s)\n".format(k, classifyFailure(e).first.label)) }
                if (k < n) Thread.sleep(gap)
            }
            if (times.isEmpty()) return@online result { kv("대상", "$h (${IpUtil.format(addr)}):$port"); note("모든 연결이 실패했어요 (${lost}번). 포트가 닫혀 있거나 방화벽이 막고 있거나 주소가 틀렸어요.", 2); block(log.toString().trim()) }
            val st = PingStats.of(times, lost)
            result {
                kv("대상", "$h (${IpUtil.format(addr)}):$port"); kv("성공 / 시도", "${st.received} / ${st.sent}"); kv("손실", "${f1(st.lossPercent)}%", if (st.lossPercent > 2) 2 else if (st.lossPercent > 0) 1 else -1)
                kv("최소 / 평균 / 최대", "${f1(st.min)} / ${f1(st.avg)} / ${f1(st.max)} ms"); kv("중앙값", "${f1(st.median)} ms"); kv("지터", "${f1(st.jitter)} ms", if (st.jitter > 30) 1 else 0)
                note(st.verdict(), if (st.lossPercent > 2 || st.avg > 150) 2 else if (st.lossPercent > 0 || st.jitter > 30 || st.avg > 80) 1 else -1)
                block(log.toString().trim())
            }
        },

        online("ping_icmp", D, "핑 (ICMP, 기기의 ping 사용)", "기기에 들어 있는 ping 명령으로 응답 시간·손실을 측정",
            hostField(), choice("n", "횟수", listOf("4", "10", "20"), "4"), note = "상대에게 ICMP 에코 요청을 보내요. 일부 기기·망은 ping 을 막아 \"응답 없음\"이 나올 수 있어요.") { i, _, env ->
            val h = HostInput.host(i.str("h")); if (h.isEmpty()) return@online need("도메인이나 IP 를 입력하세요")
            if (IpUtil.parse(h) == null && !HostInput.isPlausibleDomain(h)) return@online fail("도메인이나 IP 형식이 아니에요")
            val n = i.str("n").toInt()
            val lines = try { SystemPing.run(h, n, 2, null, env.cancel) } catch (e: IOException) { return@online fail("${e.message}. 'TCP 핑'을 써 보세요") }
            val parsed = lines.mapNotNull { SystemPing.parseLine(it) }
            val times = parsed.filter { it.kind == "reply" && it.ms != null }.map { it.ms!! }
            val sum = SystemPing.parseSummary(lines.joinToString("\n"))
            val sent = sum?.first ?: n; val lost = (sent - (sum?.second ?: times.size)).coerceAtLeast(0)
            result {
                kv("대상", h)
                if (times.isEmpty()) { note("응답이 없어요. 주소가 틀렸거나 ping 이 막혀 있을 수 있어요(방화벽·공유기). 'TCP 핑'으로 포트 연결을 확인해 보세요.", 2) }
                else { val st = PingStats.of(times, lost); kv("받은 / 보낸", "${st.received} / ${st.sent}"); kv("손실", "${f1(st.lossPercent)}%", if (st.lossPercent > 2) 2 else if (st.lossPercent > 0) 1 else -1); kv("최소 / 평균 / 최대", "${f1(st.min)} / ${f1(st.avg)} / ${f1(st.max)} ms"); kv("지터", "${f1(st.jitter)} ms"); note(st.verdict(), if (st.lossPercent > 2) 2 else 0) }
                if (lines.isNotEmpty()) block(lines.joinToString("\n").take(1500))
            }
        },

        online("traceroute", D, "경로 추적 (traceroute)", "목적지까지 어떤 장비(홉)를 거쳐 가는지, 어디서 느려지는지",
            hostField(), choice("max", "최대 홉", listOf("15", "20", "30"), "20"), note = "TTL 을 1부터 늘려 가며 ping 을 보내 경로의 각 장비 주소를 알아내요. 시간이 걸릴 수 있어요(중지 가능).") { i, _, env ->
            val h = HostInput.host(i.str("h")); if (h.isEmpty()) return@online need("도메인이나 IP 를 입력하세요")
            val dest = addrOf(h) ?: return@online fail("\"$h\" 의 주소를 찾지 못했어요")
            val max = i.str("max").toInt(); val hops = ArrayList<Triple<Int, String?, Double?>>(); var reached = false
            for (ttl in 1..max) {
                if (env.cancel.get()) break
                env.progress("$ttl 번째 홉 확인 중...")
                val t0 = System.nanoTime()
                val lines = try { SystemPing.run(IpUtil.format(dest), 1, 2, ttl, env.cancel) } catch (e: IOException) { return@online fail("${e.message}") }
                val wall = (System.nanoTime() - t0) / 1e6
                val p = lines.mapNotNull { SystemPing.parseLine(it) }.firstOrNull { it.kind == "reply" || it.kind == "exceeded" || it.kind == "unreachable" }
                hops += Triple(ttl, p?.from, p?.ms ?: if (p != null) wall else null)
                if (p?.kind == "reply") { reached = true; break }
            }
            val names = java.util.concurrent.ConcurrentHashMap<String, String>()
            hops.mapNotNull { it.second }.distinct().take(30).map { ip -> Thread { IpUtil.parse(ip)?.let { a -> Dns.reverse(a, 1200)?.let { n -> names[ip] = n } } }.also { it.start() } }.forEach { it.join(1500) }
            result {
                kv("목적지", "$h (${IpUtil.format(dest)})"); kv("결과", if (reached) "도착했어요 (${hops.size}홉)" else "목적지에 닿지 못했어요 (${hops.size}홉까지 확인)", if (reached) -1 else 1)
                header("홉", "주소", "시간", "이름")
                for ((ttl, ip, t) in hops) row("$ttl", ip ?: "*", t?.let { "%.0f ms".format(it) } ?: "응답 없음", ip?.let { names[it] } ?: "", level = if (ip == null) 1 else 0)
                note("'*' 는 그 장비가 응답하지 않는다는 뜻이에요(정상인 경우가 많아요). 중간 홉의 시간은 기기에서 ping 을 실행한 전체 소요라 대략적인 값이에요.")
                if (!reached) note("끝까지 닿지 못했어요. 목적지가 ping 을 막고 있을 수 있어요. 'TCP 핑'이나 '포트 열림 확인'을 함께 써 보세요.", 1)
            }
        },

        online("port_check", D, "포트 열림 확인 (최대 10개)", "도메인·IP 의 포트 몇 개가 열려 있는지 확인 (게임 서버·웹 서버 상태 점검)",
            hostField(), text("ports", "포트 (최대 10개)", "예: 80,443 또는 25565", "80,443", listOf("웹" to "80,443", "메일" to "25,465,587", "SSH" to "22", "원격" to "3389,5900")),
            note = "상대 서버의 포트에 연결만 시도해요(데이터는 보내지 않아요). 더 많은 포트는 '네트워크 도구'의 포트 검사를 쓰세요.",
            confirm = "입력한 주소의 포트에 접속을 시도해요(최대 10개). 내가 관리하는 장비이거나 사용을 허락받은 서버에만 쓰세요. 허락 없이 남의 서버를 검사하면 문제가 될 수 있어요. 계속할까요?") { i, host, env ->
            val h = HostInput.host(i.str("h")); if (h.isEmpty()) return@online need("도메인이나 IP 를 입력하세요")
            val sel = Ports.parse(i.str("ports"), 10); if (sel.error != null) return@online fail(sel.error)
            val addr = addrOf(h) ?: return@online fail("\"$h\" 의 주소를 찾지 못했어요")
            val kind = IpUtil.classify(addr); if (kind.blocked) return@online fail("이 주소는 검사할 수 없어요 (${kind.label})")
            env.progress("${sel.ports.size}개 포트 확인 중...")
            val rep = PortScanner.scan(addr, sel.ports, ScanOptions(timeoutMs = if (kind.local) 800 else 2000, threads = 5, banner = false, newSocket = socketsFor(addr, host)), env.cancel)
            result {
                kv("대상", "$h (${IpUtil.format(addr)}) · ${kind.label}")
                header("포트", "서비스", "상태")
                for (r in rep.results) row("${r.port}", Ports.describe(r.port)?.name ?: "-", r.state.label + (r.detail?.let { " ($it)" } ?: ""), level = if (r.state == PortState.OPEN) -1 else if (r.state == PortState.ERROR) 2 else 0)
                if (rep.open.isEmpty()) note(if (rep.hostAlive) "검사한 포트는 모두 닫혀 있어요." else "응답이 없어요 (방화벽이 막았거나 서버가 꺼져 있을 수 있어요).", 1)
            }
        },

        online("http_check", D, "웹사이트 응답 확인", "주소에 접속해 상태 코드·응답 시간·서버 정보·페이지 제목을 확인", urlField(), choice("follow", "리다이렉트", listOf("따라가지 않음", "따라감")), choice("ins", "인증서", INSECURE),
            note = NOTE_WEB) { i, host, env ->
            val u = i.str("u"); if (u.isEmpty()) return@online need("주소를 입력하세요")
            val insecure = i.str("ins") != "인증서 검사함"
            val chain = try { if (i.str("follow") == "따라감") MiniHttp.follow(u, 10, insecure) { n, c -> env.progress("$n 번째: $c") } else listOf(MiniHttp.request(u, maxBody = 8192, insecure = insecure)) } catch (e: IOException) { return@online fail("접속하지 못했어요: ${e.message}") }
            val r = chain.last()
            val final = if (chain.size > 1) try { MiniHttp.request(r.url, maxBody = 8192, insecure = insecure) } catch (_: IOException) { r } else r
            result {
                if (insecure) note("인증서 검사를 건너뛰었어요. 결과가 진짜 서버의 것인지 보장되지 않아요.", 1)
                if (chain.size > 1) { head("리다이렉트 ${chain.size - 1}번"); for ((k, c) in chain.withIndex()) kv("${k + 1}", "${c.status}  ${c.url}") }
                head("최종 응답"); httpSummary(this, final); head("응답 시간"); timings(this, final)
                head("모든 머리글"); block(final.headers.joinToString("\n") { "${it.first}: ${it.second}" })
            }
        },

        online("http_headers", D, "HTTP 응답 헤더 보기", "서버가 돌려주는 모든 응답 헤더 (HEAD 요청)", urlField(), note = NOTE_WEB) { i, _, _ ->
            val u = i.str("u"); if (u.isEmpty()) return@online need("주소를 입력하세요")
            var r = try { MiniHttp.request(u, "HEAD") } catch (e: IOException) { return@online fail("접속하지 못했어요: ${e.message}") }
            if (r.status == 405 || r.status == 501) r = try { MiniHttp.request(u, "GET") } catch (e: IOException) { return@online fail("접속하지 못했어요: ${e.message}") }
            result { kv("주소", r.url); kv("상태", r.statusLine.substringAfter(' ')); header("헤더", "값"); for ((k, v) in r.headers) row(k, v) }
        },

        online("redirect_trace", D, "리다이렉트 추적", "짧은 주소·로그인 링크가 어디로 이어지는지 한 단계씩 (최대 10번)", urlField("http://github.com"), choice("ins", "인증서", INSECURE), note = NOTE_WEB) { i, _, env ->
            val u = i.str("u"); if (u.isEmpty()) return@online need("주소를 입력하세요")
            val chain = try { MiniHttp.follow(u, 10, i.str("ins") != "인증서 검사함") { n, c -> env.progress("$n 번째: $c") } } catch (e: IOException) { return@online fail("접속하지 못했어요: ${e.message}") }
            result {
                header("단계", "상태", "주소", "시간")
                chain.forEachIndexed { k, c -> row("${k + 1}", "${c.status}", c.url, ms(c.timings.totalMs), level = if (c.isRedirect) 0 else if (c.status in 200..299) -1 else 1) }
                val last = chain.last()
                kv("최종 주소", last.url); kv("이동 횟수", "${chain.size - 1}번")
                if (last.isRedirect) note("10번을 넘게 이동해요. 무한 반복(루프)일 수 있어요.", 2)
                if (chain.first().url.startsWith("http://") && last.url.startsWith("https://")) note("http → https 로 올바르게 이동해요.", -1)
                if (chain.first().url.startsWith("https://") && last.url.startsWith("http://")) note("https 에서 http 로 내려가요. 암호화가 풀리니 주의하세요.", 2)
                if (chain.size > 5) note("이동이 많아요 (${chain.size - 1}번). 느려지고 추적에 쓰일 수 있어요.", 1)
            }
        },

        online("site_timing", D, "웹사이트 접속 시간 분석", "DNS·연결·TLS·첫 응답·전체 시간을 단계별로 재서 어디가 느린지", urlField(), choice("n", "측정 횟수", listOf("1", "3", "5"), "3"), note = NOTE_WEB) { i, _, env ->
            val u = i.str("u"); if (u.isEmpty()) return@online need("주소를 입력하세요")
            val n = i.str("n").toInt(); val rs = ArrayList<HttpResult>()
            for (k in 1..n) { if (env.cancel.get()) break; env.progress("$k / $n 번째 측정 중..."); try { rs += MiniHttp.request(u, "GET", maxBody = 0) } catch (e: IOException) { return@online fail("접속하지 못했어요: ${e.message}") }; if (k < n) Thread.sleep(300) }
            if (rs.isEmpty()) return@online need("측정이 중단됐어요")
            fun avg(sel: (HttpTimings) -> Long?) = rs.mapNotNull { sel(it.timings) }.let { if (it.isEmpty()) null else it.average() }
            result {
                kv("주소", rs[0].url); kv("접속한 IP", rs[0].remoteIp); rs[0].tls?.let { kv("TLS", it.protocol) }; kv("측정", "${rs.size}번 평균")
                avg { it.dnsMs }?.let { kv("DNS 조회", "%.0f ms".format(it), if (it > 300) 1 else 0) }; avg { it.connectMs }?.let { kv("TCP 연결", "%.0f ms".format(it), if (it > 400) 1 else 0) }
                avg { it.tlsMs }?.let { kv("TLS 협상", "%.0f ms".format(it), if (it > 600) 1 else 0) }; avg { it.ttfbMs }?.let { kv("첫 응답까지(TTFB)", "%.0f ms".format(it), if (it > 1500) 2 else if (it > 800) 1 else -1) }; avg { it.totalMs }?.let { kv("전체", "%.0f ms".format(it)) }
                val parts = listOf("DNS" to (avg { it.dnsMs } ?: 0.0), "연결" to (avg { it.connectMs } ?: 0.0), "TLS" to (avg { it.tlsMs } ?: 0.0))
                note("가장 오래 걸리는 준비 단계: ${parts.maxByOrNull { it.second }!!.first}. DNS 가 느리면 DNS 서버를 바꾸고, 연결·TLS 가 느리면 서버까지의 거리(해외 서버)나 회선이 원인일 수 있어요.")
                if (rs.size > 1) { head("측정별 전체 시간"); rs.forEachIndexed { k, r -> kv("${k + 1}번", ms(r.timings.totalMs)) } }
            }
        },

        online("tls_cert", D, "TLS 인증서 확인", "서버의 인증서 주체·발급자·만료일·이름·신뢰 여부와 TLS 버전", hostField("example.com", "도메인 (포트는 :8443 처럼)"), note = "서버에 TLS 접속(인사)만 하고 끊어요. 인터넷을 사용해요.") { i, host, _ ->
            val raw = i.str("h"); if (raw.isEmpty()) return@online need("도메인을 입력하세요")
            val (h, port) = hostPort(raw); if (h.isEmpty()) return@online need("도메인을 입력하세요")
            val rep = try { TlsInspect.inspect(h, port, newSocket = addrOf(h)?.let { socketsFor(it, host) } ?: { Socket() }) } catch (e: Exception) { return@online fail("TLS 접속에 실패했어요: ${e.message?.take(120) ?: e.javaClass.simpleName}") }
            val leaf = rep.chain.firstOrNull()
            result {
                kv("접속", "$h:$port  (${rep.ms}ms)"); kv("TLS 버전", rep.protocol, if (rep.protocol == "TLSv1.3" || rep.protocol == "TLSv1.2") -1 else 2); kv("암호 스위트", rep.cipher)
                kv("신뢰 여부", if (rep.trusted) "믿을 수 있어요" else (rep.trustError ?: "믿을 수 없어요"), if (rep.trusted) -1 else 2)
                kv("이름 일치", if (rep.hostnameOk) "접속한 주소와 일치" else "접속한 주소와 달라요", if (rep.hostnameOk) -1 else 2)
                if (leaf != null) { head("서버 인증서"); for ((k, v) in CertInfo.describe(leaf)) kv(k, v, if (k == "남은 기간") levelOfDays(CertInfo.daysLeft(leaf)) else 0) }
                if (rep.chain.size > 1) { head("인증서 사슬 (${rep.chain.size}장)"); rep.chain.forEachIndexed { k, c -> kv("${k + 1}", CertInfo.describe(c).first().second.take(70)) } }
            }
        },

        online("tls_versions", D, "서버가 지원하는 TLS 버전", "TLS 1.3 · 1.2 · 1.1 · 1.0 중 서버가 받아 주는 것 (낡은 버전이 켜져 있으면 위험)", hostField(), note = "버전마다 TLS 접속을 시도해 봐요(최대 4번). 인터넷을 사용해요.") { i, _, env ->
            val raw = i.str("h"); val h = HostInput.host(raw); if (h.isEmpty()) return@online need("도메인을 입력하세요")
            val mine = try { TlsInspect.supportedProtocols() } catch (_: Exception) { emptyList() }
            result {
                kv("서버", h); header("버전", "결과")
                for (p in listOf("TLSv1.3", "TLSv1.2", "TLSv1.1", "TLSv1")) {
                    if (env.cancel.get()) break
                    env.progress("$p 확인 중...")
                    if (p !in mine) { row(p, "이 기기가 지원하지 않아 확인할 수 없어요"); continue }
                    try { TlsInspect.inspect(h, 443, 6000, arrayOf(p)); row(p, "지원해요" + if (p == "TLSv1.1" || p == "TLSv1") " — 낡은 버전이라 끄는 게 좋아요" else "", level = if (p == "TLSv1.1" || p == "TLSv1") 2 else -1) }
                    catch (e: Exception) { row(p, "지원하지 않아요", level = if (p == "TLSv1.1" || p == "TLSv1") -1 else 1) }
                }
                note("TLS 1.2 이상만 켜는 것이 좋아요. 1.0·1.1 은 취약해서 주요 브라우저에서 이미 막았어요.")
            }
        },

        online("sec_headers", D, "웹 보안 헤더 점검", "HSTS·CSP·nosniff·클릭재킹·Referrer·Permissions 를 점검해 점수와 고칠 점 제시", urlField(), note = NOTE_WEB) { i, _, _ ->
            val u = i.str("u"); if (u.isEmpty()) return@online need("주소를 입력하세요")
            val r = try { MiniHttp.request(u, "GET", maxBody = 0) } catch (e: IOException) { return@online fail("접속하지 못했어요: ${e.message}") }
            val checks = SecHeaders.grade(r.headers, r.url.startsWith("https://")); val good = checks.count { it.level == -1 }
            result {
                kv("주소", r.url); kv("상태", r.statusLine.substringAfter(' ')); kv("점수", "$good / ${checks.size}", if (good >= 5) -1 else if (good >= 3) 1 else 2)
                header("항목", "결과", "내용")
                for (c in checks) row(c.name, if (c.level == -1) "좋음" else if (c.level == 1) "주의" else "없음", c.detail, level = c.level)
                val adv = checks.filter { it.advice.isNotEmpty() }; if (adv.isNotEmpty()) { head("이렇게 고쳐 보세요"); for (c in adv) note("${c.name}: ${c.advice}", 1) }
                for (l in SecHeaders.leaks(r.headers)) note(l, 1)
                val ck = SecHeaders.cookies(r.all("Set-Cookie"))
                if (ck.isNotEmpty()) { head("쿠키 (${ck.size}개)"); header("이름", "Secure", "HttpOnly", "SameSite"); for (c in ck) row(c.name, if (c.secure) "예" else "아니요", if (c.httpOnly) "예" else "아니요", c.sameSite ?: "없음", level = if (c.secure && c.httpOnly) -1 else 1) }
            }
        },

        online("cert_expiry", D, "인증서 만료일 일괄 확인", "여러 도메인의 인증서 남은 기간을 한 번에 (갱신 놓치기 방지)", multi("hosts", "도메인 (한 줄에 하나, 최대 10개)", "예: example.com", "example.com\ngithub.com\nwww.google.com"), note = "각 도메인에 TLS 접속(인사)만 해요. 인터넷을 사용해요.") { i, _, env ->
            val hosts = i.lines("hosts").map { HostInput.host(it) }.filter { it.isNotEmpty() }.distinct().take(10); if (hosts.isEmpty()) return@online need("도메인을 한 줄에 하나씩 입력하세요")
            val out = java.util.concurrent.ConcurrentHashMap<String, Pair<TlsReport?, String?>>()
            env.progress("${hosts.size}곳 확인 중...")
            hosts.map { h -> Thread { out[h] = try { TlsInspect.inspect(h, 443, 6000) to null } catch (e: Exception) { null to (e.message?.take(60) ?: "실패") } }.also { it.start() } }.forEach { it.join(10000) }
            result {
                header("도메인", "남은 기간", "만료일", "발급자")
                for (h in hosts) { val (r, err) = out[h] ?: (null to "응답 없음"); val leaf = r?.chain?.firstOrNull()
                    if (r == null || leaf == null) row(h, "-", err ?: "실패", "", level = 2)
                    else { val d = CertInfo.daysLeft(leaf); row(h, if (d < 0) "${-d}일 전 만료" else "${d}일", leaf.notAfter.toInstant().toString().take(10), CertInfo.describe(leaf)[1].second.substringAfter("CN=").substringBefore(',').take(24), level = levelOfDays(d).let { if (!r.trusted) 2 else it }) } }
                note("14일 이내면 위험, 30일 이내면 주의로 표시해요. 신뢰할 수 없는 인증서는 날짜와 관계없이 빨간색이에요.")
            }
        },

        online("captive_portal", D, "공용 Wi-Fi 로그인 화면(캡티브 포털) 감지", "카페·호텔 Wi-Fi 에서 인터넷이 안 될 때, 로그인·동의 화면이 가로채고 있는지", note = "구글의 연결 확인 주소(connectivitycheck.gstatic.com)에 http 요청 한 번을 보내요. 인터넷을 사용해요.") { _, host, _ ->
            val r = try { MiniHttp.request("http://connectivitycheck.gstatic.com/generate_204", maxBody = 2048, timeoutMs = 6000) } catch (e: IOException) { return@online fail("접속하지 못했어요: ${e.message}. 인터넷이 아예 안 되거나 DNS 문제일 수 있어요.") }
            result {
                kv("응답", r.statusLine.substringAfter(' ')); kv("접속한 IP", r.remoteIp)
                when {
                    r.status == 204 && (r.body.isNullOrEmpty()) -> note("정상이에요. 로그인 화면이 가로채지 않고 인터넷이 열려 있어요.", -1)
                    r.isRedirect || r.status == 200 || r.status == 511 -> { note("캡티브 포털로 보여요! 인터넷을 쓰기 전에 로그인·동의가 필요한 화면이 가로채고 있어요.", 2); r.header("Location")?.let { kv("이동하라는 곳", it) }; titleOf(r.body)?.let { kv("화면 제목", it) }; note("브라우저에서 http://neverssl.com 같은 http 주소를 열면 로그인 화면이 뜰 수 있어요. 그 화면에 개인정보나 카드번호를 입력하는 것은 조심하세요.", 1) }
                    else -> note("예상 밖의 응답(${r.status})이에요. 회사·학교 망의 필터링일 수 있어요.", 1)
                }
                host.netDetails().firstOrNull { it.first.startsWith("로그인 필요") }?.let { kv("안드로이드의 판단", it.second) }
            }
        },

        online("internet_check", D, "인터넷이 안 될 때 단계별 진단", "연결 → 공유기 → DNS → 인터넷 → HTTPS 순서로 어디서 막혔는지 찾아 줘요", note = "구글·클라우드플레어의 공개 서버에 연결 시도를 해요. 인터넷을 사용해요.") { _, host, env ->
            val steps = ArrayList<Triple<String, Boolean?, String>>()
            fun step(name: String, ok: Boolean?, detail: String) { steps += Triple(name, ok, detail) }
            fun stopped() = env.cancel.get()
            env.progress("연결 상태 확인...")
            val details = host.netDetails()
            step("1. 네트워크 연결", details.firstOrNull { it.first == "연결 종류" }?.second?.takeIf { it != "연결된 네트워크가 없어요" }?.let { true } ?: if (details.isEmpty()) null else false,
                details.firstOrNull { it.first == "연결 종류" }?.let { "${it.second}" + (details.firstOrNull { d -> d.first.startsWith("인터넷 통하는지") }?.let { v -> " · 안드로이드의 인터넷 확인: ${v.second}" } ?: "") } ?: "정보를 읽지 못했어요")
            val gw = host.gateway()
            if (stopped()) return@online need("중지했어요")
            if (gw != null) { env.progress("공유기 확인..."); val okGw = try { Socket().use { it.connect(InetSocketAddress(gw, 80), 1500) }; true } catch (e: IOException) { classifyFailure(e).first == PortState.CLOSED }; step("2. 공유기($gw) 응답", okGw, if (okGw) "공유기가 응답해요" else "공유기에 닿지 못했어요 (Wi-Fi 연결·공유기 전원을 확인)") } else step("2. 공유기 응답", null, "Wi-Fi 정보가 없어요 (모바일 데이터이거나 읽지 못함)")
            if (stopped()) return@online need("중지했어요")
            env.progress("DNS 확인...")
            val sysDns = Dns.resolve("www.google.com", 4000).isNotEmpty(); step("3. 내 DNS 로 도메인 찾기", sysDns, if (sysDns) "도메인을 IP 로 바꿀 수 있어요" else "도메인을 찾지 못했어요 (DNS 설정 문제일 수 있어요)")
            val directDns = try { DnsClient.query("8.8.8.8", "www.google.com", DnsType.A, timeoutMs = 2000, retries = 0).msg.answers.isNotEmpty() } catch (_: IOException) { false }; step("4. 구글 DNS(8.8.8.8) 직접 질문", directDns, if (directDns) "인터넷의 DNS 에 닿아요" else "닿지 못했어요 (UDP 53 이 막혔거나 인터넷이 끊김)")
            if (stopped()) return@online need("중지했어요")
            env.progress("인터넷 연결 확인...")
            val tcp = try { Socket().use { it.connect(InetSocketAddress("1.1.1.1", 443), 3000) }; true } catch (_: IOException) { false }; step("5. 인터넷 서버(1.1.1.1:443) 연결", tcp, if (tcp) "IP 로는 인터넷에 나가요" else "인터넷에 나가지 못해요 (회선·공유기 WAN 문제)")
            if (stopped()) return@online need("중지했어요")
            val https = try { MiniHttp.request("https://www.google.com/generate_204", timeoutMs = 5000).status in listOf(204, 200) } catch (_: IOException) { false }; step("6. HTTPS 웹 접속", https, if (https) "웹 접속이 돼요" else "HTTPS 접속이 안 돼요 (프록시·방화벽·시계·인증서 문제 가능)")
            val portal = try { MiniHttp.request("http://connectivitycheck.gstatic.com/generate_204", timeoutMs = 4000).status != 204 } catch (_: IOException) { null }; step("7. 로그인 화면(캡티브 포털)", portal?.not(), when (portal) { true -> "가로채는 로그인 화면이 있어요 (브라우저로 로그인)"; false -> "없어요"; null -> "확인하지 못했어요" })
            val firstBad = steps.firstOrNull { it.second == false }
            result {
                header("단계", "결과", "내용")
                for ((n, ok, d) in steps) row(n, when (ok) { true -> "정상"; false -> "문제"; null -> "모름" }, d, level = when (ok) { true -> -1; false -> 2; null -> 0 })
                head("진단")
                note(when {
                    firstBad == null -> "모든 단계가 정상이에요. 특정 사이트·앱만 안 된다면 그 서비스의 문제일 수 있어요."
                    firstBad.first.startsWith("1") -> "Wi-Fi 나 모바일 데이터 연결부터 확인하세요 (비행기 모드, Wi-Fi 껐다 켜기)."
                    firstBad.first.startsWith("2") -> "기기와 공유기 사이 문제예요. 공유기 전원을 껐다 켜고(30초), 신호가 약하지 않은지 보세요."
                    firstBad.first.startsWith("3") || firstBad.first.startsWith("4") -> "DNS 문제로 보여요. DNS 를 8.8.8.8 이나 1.1.1.1 로 바꿔 보세요 (설정 → Private DNS)."
                    firstBad.first.startsWith("5") -> "공유기 바깥(통신사 회선) 문제로 보여요. 모뎀·공유기를 재시작해도 안 되면 통신사에 문의하세요."
                    else -> "인터넷은 나가지만 HTTPS 에 문제가 있어요. 폰 시계(자동 설정), 프록시·VPN, 보안 앱을 확인하세요."
                }, if (firstBad == null) -1 else 2)
            }
        },

        online("speed_test", D, "인터넷 속도 측정", "다운로드·업로드 속도와 응답 시간을 측정 (Cloudflare 측정 서버 사용)", note = "Cloudflare 의 공개 속도 측정 주소(speed.cloudflare.com)와 데이터를 주고받아요. 빠른 회선이면 최대 약 300MB(내려받기 250MB + 올리기 60MB)까지 써요.",
            confirm = "속도를 재기 위해 데이터를 많이 주고받아요. 회선이 빠르면 최대 약 300MB 까지 써요. 모바일 데이터라면 요금이 들 수 있으니 Wi-Fi 에서 하는 것이 좋아요. 계속할까요?") { _, _, env ->
            val base = SpeedTest.CLOUDFLARE
            env.progress("응답 시간 측정 중..."); val lat = SpeedTest.latency(base) ?: return@online fail("속도 측정 서버(speed.cloudflare.com)에 접속하지 못했어요. 인터넷 연결을 확인하세요.")
            env.progress("내려받기 속도 측정 중 (7초)..."); val down = SpeedTest.download(base, cancel = env.cancel)
            env.progress("올리기 속도 측정 중 (5초)..."); val up = if (env.cancel.get()) null else SpeedTest.upload(base, cancel = env.cancel)
            result {
                kv("응답 시간", "${f1(lat)} ms", if (lat > 150) 1 else -1)
                if (down != null) kv("내려받기", "${f1(down.first)} Mbps  (${f1(down.first / 8)} MB/s)", -1) else note("내려받기 측정에 실패했어요", 2)
                if (up != null) kv("올리기", "${f1(up.first)} Mbps", -1) else if (!env.cancel.get()) note("올리기 측정에 실패했어요", 1)
                kv("사용한 데이터", "약 ${"%.0f".format(((down?.second ?: 0L) + (up?.second ?: 0L)) / 1e6)} MB")
                note("Wi-Fi 와 서버 거리에 따라 달라지는 값이에요. 여러 번 재 보세요. 유선 연결이 가장 정확해요.")
            }
        },

        online("latency_compare", D, "주요 서비스까지 응답 시간 비교", "구글·네이버·카카오·클라우드플레어·아마존·깃허브·마이크로소프트·애플까지 연결 시간을 비교", note = "각 서비스의 443 포트에 연결만 하고 끊어요(3번씩). 인터넷을 사용해요.") { _, _, env ->
            val targets = listOf("구글" to "www.google.com", "클라우드플레어" to "1.1.1.1", "네이버" to "www.naver.com", "카카오" to "www.kakao.com", "아마존(AWS)" to "aws.amazon.com", "깃허브" to "github.com", "마이크로소프트" to "www.microsoft.com", "애플" to "www.apple.com")
            val out = java.util.concurrent.ConcurrentHashMap<String, Pair<List<Double>, Int>>()
            env.progress("${targets.size}곳 측정 중...")
            targets.map { (_, h) -> Thread {
                val t = ArrayList<Double>(); var lost = 0
                for (k in 1..3) { try { val a = TlsInspect.resolve(h); val t0 = System.nanoTime(); Socket().use { it.connect(InetSocketAddress(a, 443), 2500) }; t += (System.nanoTime() - t0) / 1e6 } catch (_: Exception) { lost++ } }
                out[h] = t to lost
            }.also { it.start() } }.forEach { it.join(12000) }
            val sorted = targets.sortedBy { out[it.second]?.first?.minOrNull() ?: Double.MAX_VALUE }
            result {
                header("서비스", "최소", "평균", "손실")
                for ((name, h) in sorted) { val (t, lost) = out[h] ?: (emptyList<Double>() to 3); if (t.isEmpty()) row(name, "-", "연결 실패", "3/3", level = 2) else row(name, "${f1(t.min())} ms", "${f1(t.average())} ms", "$lost/3", level = if (t.min() > 200) 1 else 0) }
                note("가까운 서버일수록 빨라요. 국내 서비스는 보통 수~수십 ms, 해외 서버는 100ms 안팎(미국은 150~200ms)이에요. 값이 전반적으로 크면 내 회선·Wi-Fi 가 느린 거예요.")
            }
        },

        online("ntp_check", D, "시계 오차 확인 (NTP)", "시간 서버와 비교해 이 폰 시계가 얼마나 틀린지 (시계가 틀리면 HTTPS·인증서·OTP 가 오류나요)",
            text("s", "시간 서버", "예: time.google.com", "time.google.com", listOf("구글" to "time.google.com", "pool.ntp.org" to "pool.ntp.org", "KRISS" to "time.kriss.re.kr", "클라우드플레어" to "time.cloudflare.com", "애플" to "time.apple.com")),
            note = "NTP 서버에 UDP 123 번으로 시간 질문을 3번 보내요. 인터넷을 사용해요.") { i, host, env ->
            val s = HostInput.host(i.str("s")); if (s.isEmpty()) return@online need("서버를 입력하세요")
            val rs = ArrayList<NtpResult>(); var err: String? = null
            for (k in 1..3) { if (env.cancel.get()) break; env.progress("$k / 3 번째..."); try { rs += NtpClient.query(s, timeoutMs = 3000) } catch (e: IOException) { err = e.message } }
            if (rs.isEmpty()) return@online fail("시간을 확인하지 못했어요: ${err ?: "응답 없음"}")
            val best = rs.minByOrNull { it.delayMs }!!; val off = best.offsetMs; val a = Math.abs(off)
            result {
                kv("서버", s); kv("서버 층위(stratum)", "${best.stratum}"); kv("기준", best.refId)
                kv("시계 오차", "${if (off > 0) "폰이 ${f1(a)}ms 느려요 (서버가 앞서요)" else "폰이 ${f1(a)}ms 빨라요"}", if (a < 100) -1 else if (a < 1000) 1 else 2); kv("왕복 지연", "${f1(best.delayMs)} ms")
                note(when { a < 100 -> "시계가 정확해요."; a < 1000 -> "약간 틀렸지만 문제 되지 않아요."; a < 5000 -> "오차가 커요. 설정에서 \"날짜 및 시간 자동 설정\"을 켜 보세요."; else -> "시계가 많이 틀렸어요. HTTPS 인증서 오류·OTP 코드 불일치가 생길 수 있으니 자동 설정을 켜세요." }, if (a < 100) -1 else if (a < 1000) 0 else 2)
            }
        },

        online("cdn_detect", D, "CDN·서버 종류 알아보기", "응답 헤더로 이 사이트가 Cloudflare·CloudFront·Akamai 등 어느 서비스 뒤에 있는지, 웹 서버·기술", urlField(), note = NOTE_WEB) { i, _, _ ->
            val u = i.str("u"); if (u.isEmpty()) return@online need("주소를 입력하세요")
            val r = try { MiniHttp.request(u, "GET") } catch (e: IOException) { return@online fail("접속하지 못했어요: ${e.message}") }
            val hits = CdnDetect.detect(r.headers); val hints = CdnDetect.hints(r.headers)
            result {
                kv("주소", r.url); kv("접속한 IP", r.remoteIp); kv("상태", r.statusLine.substringAfter(' '))
                if (hits.isEmpty()) note("알려진 CDN 의 흔적을 찾지 못했어요. 직접 운영하는 서버이거나 헤더를 숨기고 있을 수 있어요.", 1) else { head("발견한 서비스"); for (h in hits) kv(h.service, h.evidence, -1) }
                if (hints.isNotEmpty()) { head("그 밖의 단서"); for ((k, v) in hints) kv(k, v) }
                note("헤더로 추정한 것이라 정확하지 않을 수 있어요.")
            }
        },

        online("robots_fetch", D, "robots.txt 보기", "사이트의 robots.txt(검색 로봇 규칙)와 사이트맵 주소", urlField(), note = NOTE_WEB) { i, _, _ ->
            val p = MiniHttp.parseUrl(i.str("u")) ?: return@online if (i.str("u").isEmpty()) need("주소를 입력하세요") else fail("URL 형식이 올바르지 않아요")
            val r = try { MiniHttp.follow("${p.scheme}://${if (':' in p.host) "[${p.host}]" else p.host}${if (p.port == (if (p.isHttps) 443 else 80)) "" else ":${p.port}"}/robots.txt", 3).last().let { f -> if (f.status in 200..299) MiniHttp.request(f.url, maxBody = 65536) else f } } catch (e: IOException) { return@online fail("접속하지 못했어요: ${e.message}") }
            result {
                kv("주소", r.url); kv("상태", r.statusLine.substringAfter(' '), if (r.status in 200..299) -1 else 1)
                if (r.status !in 200..299 || r.body.isNullOrBlank()) note("robots.txt 가 없거나 비어 있어요 (검색 로봇이 모든 곳을 돌아다녀도 된다는 뜻이에요).", 1)
                else { val info = Robots.parse(r.body); kv("User-agent", "${info.userAgents}개"); kv("Disallow(막은 경로)", "${info.disallow}개"); kv("Allow", "${info.allow}개"); info.sitemaps.forEach { kv("Sitemap", it) }; block(r.body.lines().take(80).joinToString("\n")); note("robots.txt 는 로봇에게 보내는 \"부탁\"일 뿐 접근을 막는 보안 장치가 아니에요. 숨기고 싶은 경로를 여기에 적으면 오히려 알려 주는 셈이에요.") }
            }
        },

        online("url_bulk", D, "여러 주소 상태 한꺼번에 확인", "주소 목록(최대 10개)의 상태 코드와 응답 시간을 동시에 확인 (사이트 모니터링)", multi("urls", "주소 (한 줄에 하나)", "예: https://example.com", "https://example.com\nhttps://www.google.com\nhttp://github.com"), note = NOTE_WEB) { i, _, env ->
            val urls = i.lines("urls").take(10); if (urls.isEmpty()) return@online need("주소를 한 줄에 하나씩 입력하세요")
            val out = java.util.concurrent.ConcurrentHashMap<String, Pair<HttpResult?, String?>>()
            env.progress("${urls.size}곳 확인 중...")
            urls.map { u -> Thread { out[u] = try { MiniHttp.request(u, "GET", timeoutMs = 7000) to null } catch (e: IOException) { null to (e.message?.take(50) ?: "실패") } }.also { it.start() } }.forEach { it.join(12000) }
            result {
                header("주소", "상태", "시간")
                for (u in urls) { val (r, err) = out[u] ?: (null to "응답 없음"); if (r == null) row(u, err ?: "실패", "-", level = 2) else row(u, "${r.status}", ms(r.timings.totalMs), level = when (r.status) { in 200..299 -> -1; in 300..399 -> 0; in 400..499 -> 1; else -> 2 }) }
                note("300번대는 다른 주소로 이동(리다이렉트), 400번대는 요청 문제, 500번대는 서버 문제예요.")
            }
        },

        // ------------------------------------------------------------ 내 망 점검
        lanTool("upnp_find", L, "UPnP 기기 찾기 (SSDP)", "같은 Wi-Fi 의 공유기·TV·프린터·스피커 등 UPnP 로 자신을 알리는 기기 (이름·제조사·모델)", note = "같은 망에 SSDP 방송(UDP 1900)을 보내고 응답을 받아요. 내 집·내 사무실 망에서만 쓰세요.") { _, host, env ->
            env.progress("기기를 찾는 중... (4초)")
            val devs = try { Ssdp.discover(4000, bind = { host.bindDatagram(it) }) } catch (e: IOException) { return@lanTool fail("방송을 보내지 못했어요: ${e.message}. Wi-Fi 에 연결돼 있는지 확인하세요.") }
            val byIp = devs.groupBy { it.ip }
            val desc = java.util.concurrent.ConcurrentHashMap<String, Triple<String?, String?, String?>>()
            byIp.entries.map { (ip, list) -> Thread { list.firstNotNullOfOrNull { d -> Ssdp.describe(d, host.lanSockets()) }?.let { desc[ip] = it } }.also { it.start() } }.forEach { it.join(4000) }
            result {
                if (devs.isEmpty()) { note("응답한 UPnP 기기가 없어요. 일부 공유기·망은 방송을 막아요(게스트 Wi-Fi 등).", 1) }
                else {
                    kv("찾은 기기", "${byIp.size}대 (서비스 ${devs.size}개)")
                    header("IP", "이름 · 제조사 · 모델", "서버 정보")
                    for ((ip, list) in byIp) { val d = desc[ip]; row(ip, listOfNotNull(d?.first, d?.second, d?.third).joinToString(" · ").ifEmpty { list.firstOrNull { it.st.contains("urn:") }?.st?.substringAfterLast(':', "")?.ifEmpty { null } ?: "-" }, list.firstNotNullOfOrNull { it.server }?.take(60) ?: "") }
                    if (devs.any { it.st.contains("InternetGatewayDevice") }) note("공유기의 UPnP 가 켜져 있어요. 편리하지만 기기가 마음대로 포트를 열 수 있어서, 필요 없다면 공유기 설정에서 끄는 것이 안전해요.", 1)
                }
            }
        },

        lanTool("wol_send", L, "Wake-on-LAN (원격으로 PC 켜기)", "MAC 주소로 매직 패킷을 보내 같은 망의 꺼진 PC·NAS 를 켜기", text("mac", "켤 기기의 MAC 주소", "예: aa:bb:cc:dd:ee:ff", ""), text("bc", "브로드캐스트 주소 (비우면 자동)", "예: 192.168.0.255", ""), choice("port", "포트", listOf("9", "7")),
            note = "같은 망에 UDP 매직 패킷을 한 번 방송해요. 기기의 BIOS/UEFI 와 랜카드에서 Wake-on-LAN 이 켜져 있어야 해요. 내 기기에만 쓰세요.") { i, host, _ ->
            val mac = Mac.parse(i.str("mac")) ?: return@lanTool if (i.str("mac").isEmpty()) need("MAC 주소를 입력하세요") else fail("MAC 주소를 읽지 못했어요 (16진수 12자리)")
            if (Mac.isMulticast(mac)) return@lanTool fail("멀티캐스트·브로드캐스트 MAC 으로는 켤 수 없어요")
            val bcText = i.str("bc").ifEmpty { host.lanIp()?.let { (ip, p) -> Subnet.of(IpUtil.v4ToLong(IpUtil.parseV4(ip)!!), p.coerceIn(8, 30)).broadcast.let { IpUtil.v4Text(it) } } ?: "255.255.255.255" }
            val bc = IpUtil.parse(bcText)?.takeIf { it.address.size == 4 } ?: return@lanTool fail("브로드캐스트 주소를 읽지 못했어요")
            val kind = IpUtil.classify(bc); if (!(kind.local || kind == IpKind.BROADCAST)) return@lanTool fail("내 망 안의 브로드캐스트 주소만 쓸 수 있어요 (예: 192.168.0.255)")
            try { Wol.send(mac, bc, i.str("port").toInt()) { host.bindDatagram(it) } } catch (e: IOException) { return@lanTool fail("보내지 못했어요: ${e.message}") }
            result { kv("MAC", Mac.hex(mac)); kv("보낸 곳", "$bcText:${i.str("port")} (UDP)"); kv("패킷", "102바이트 (FF×6 + MAC×16)"); note("매직 패킷을 보냈어요. 기기가 켜지는 데 몇 초~1분쯤 걸려요. 안 켜지면 BIOS 의 \"Wake on LAN/PCI-E\" 설정과 랜카드의 \"매직 패킷으로 깨우기\"를 확인하세요. 공유기 밖(인터넷)에서는 보통 동작하지 않아요.", -1) }
        },

        lanTool("nbns_name", L, "윈도 PC 이름 조회 (NetBIOS)", "내 망 안 PC 의 컴퓨터 이름·작업 그룹·MAC 주소", text("ip", "IP 주소 (내 망 안)", "예: 192.168.0.10", "", listOf("공유기" to "")), note = "그 PC 의 UDP 137 번에 이름 질문 한 번을 보내요. 내 망 안 장비에만 쓸 수 있어요.") { i, host, _ ->
            val ip = IpUtil.parse(i.str("ip").ifEmpty { host.gateway() ?: "" }) ?: return@lanTool if (i.str("ip").isEmpty()) need("IP 주소를 입력하세요") else fail("IP 주소를 읽지 못했어요")
            if (ip.address.size != 4 || IpUtil.classify(ip) !in listOf(IpKind.PRIVATE, IpKind.LINK_LOCAL, IpKind.LOOPBACK)) return@lanTool fail("내 망 안(사설) IPv4 주소만 조회할 수 있어요")
            val r = try { Nbns.ask(ip, bind = { host.bindDatagram(it) }) } catch (e: IOException) { return@lanTool fail("질문하지 못했어요: ${e.message}") }
            result {
                kv("IP", IpUtil.format(ip))
                if (r == null || r.names.isEmpty()) note("응답이 없어요. 윈도 PC 가 아니거나 NetBIOS 가 꺼져 있거나 방화벽이 막고 있어요 (요즘 기기는 대부분 응답하지 않아요).", 1)
                else { r.mac?.let { kv("MAC", it) }; header("이름", "코드", "종류"); for (n in r.names) row(n.name, "<%02X>".format(n.suffix), when { n.suffix == 0 && !n.group -> "컴퓨터 이름"; n.suffix == 0 && n.group -> "작업 그룹"; n.suffix == 0x20 -> "파일 공유 서비스"; n.suffix == 3 -> "메신저 서비스"; n.suffix == 0x1B -> "도메인 마스터"; n.suffix == 0x1C -> "도메인 컨트롤러 그룹"; n.suffix == 0x1D -> "마스터 브라우저"; n.suffix == 0x1E -> "브라우저 선거"; else -> if (n.group) "그룹" else "서비스" }) }
            }
        },

        lanTool("router_info", L, "공유기 관리 화면·열린 서비스 점검", "공유기(게이트웨이)의 관리 화면 정보와 열려 있는 관리 포트 — 불필요하게 열린 게 없는지", text("gw", "공유기 주소 (비우면 자동)", "예: 192.168.0.1", ""),
            note = "공유기에 웹 요청 한 번과 주요 포트(21·22·23·80·443·8080·8443·7547) 연결 시도를 해요. 내 공유기에만 쓰세요.") { i, host, env ->
            val gw = i.str("gw").ifEmpty { host.gateway() ?: "" }; if (gw.isEmpty()) return@lanTool fail("공유기 주소를 알 수 없어요. Wi-Fi 에 연결하거나 주소를 직접 입력하세요")
            val ip = IpUtil.parse(gw) ?: return@lanTool fail("주소를 읽지 못했어요"); if (!IpUtil.classify(ip).local) return@lanTool fail("내 망 안(사설) 주소만 점검할 수 있어요")
            env.progress("포트 확인 중...")
            val rep = PortScanner.scan(ip, listOf(21, 22, 23, 80, 443, 8080, 8443, 7547), ScanOptions(timeoutMs = 800, threads = 8, banner = false, newSocket = host.lanSockets()), env.cancel)
            val tries = listOf("http://$gw/", "https://$gw/")
            val web = tries.mapNotNull { u -> if (env.cancel.get()) null else try { MiniHttp.request(u, maxBody = 8192, timeoutMs = 3000, insecure = true, newSocket = host.lanSockets()) } catch (_: IOException) { null } }
            result {
                kv("공유기", IpUtil.format(ip))
                head("열린 포트"); if (rep.open.isEmpty()) note("검사한 관리 포트가 모두 닫혀 있어요.", -1) else for (r in rep.open) { val info = Ports.describe(r.port); kv("${r.port}", (info?.name ?: "") + (info?.takeIf { it.risk > 0 }?.let { " — ${it.advice}" } ?: ""), info?.risk ?: 0) }
                for (w in web) { head("웹 화면 ${w.url}"); kv("상태", w.statusLine.substringAfter(' ')); titleOf(w.body)?.let { kv("제목", it) }; w.header("Server")?.let { kv("서버", it) }; w.header("WWW-Authenticate")?.let { kv("로그인 방식", it.take(80)) }; w.tls?.let { if (!it.trusted) kv("인증서", "공인 인증서가 아니에요 (공유기는 보통 자체 서명이라 정상이에요)") } }
                if (web.isEmpty()) note("웹 관리 화면에 접속하지 못했어요 (포트·주소 확인).", 1)
                if (rep.open.any { it.port == 23 || it.port == 21 }) note("텔넷(23)이나 FTP(21)가 열려 있어요. 암호화가 없는 서비스라 공유기 설정에서 끄세요.", 2)
                if (rep.open.any { it.port == 7547 }) note("7547(TR-069)은 통신사가 공유기를 원격 관리하는 포트예요. 공유기 안쪽에서 열린 건 정상이지만, 인터넷(바깥)에서 열려 있으면 위험해요 (모바일 데이터에서 '포트 검사'로 확인).", 1)
                note("'공유기 보안 점검표'(점검 순서·명령어 묶음)와 함께 확인해 보세요.")
            }
        },

        NetTool("net_info", L, "내 연결 정보 한눈에", "연결 종류·종량제 여부·VPN·프록시·Private DNS·MTU·DNS 서버 (이 폰의 현재 연결)", emptyList(), ToolMode.LAN, "이 폰이 알고 있는 연결 정보를 읽기만 해요. 어디로도 보내지 않아요.", null, true, false, "새로 고침") { _, host, _ ->
            val d = host.netDetails()
            if (d.isEmpty()) fail("연결 정보를 읽지 못했어요")
            else result { for ((k, v) in d) kv(k, v, if (k.startsWith("로그인 필요") && v == "예") 2 else if (k == "프록시" && v != "없음") 1 else 0); note("값을 누르면 복사돼요. '종량제'가 예면 데이터 요금이 드는 연결이에요.") }
        },

        NetTool("wifi_info", L, "Wi-Fi 신호·속도 확인", "지금 연결된 Wi-Fi 의 신호 세기·연결 속도·주파수·채널·표준을 한눈에", emptyList(), ToolMode.LAN, "Wi-Fi 에 연결돼 있어야 해요. 위치 권한은 필요 없어요(Wi-Fi 이름은 보이지 않아요).", null, true, false, "새로 고침") { _, host, _ ->
            val w = host.wifiDetails() ?: return@NetTool fail("Wi-Fi 정보를 읽지 못했어요. Wi-Fi 에 연결돼 있는지 확인하세요(모바일 데이터에서는 볼 수 없어요).")
            result {
                for ((k, v) in w) kv(k, v)
                val dbm = w.firstOrNull { it.first == "신호 세기" }?.second?.substringBefore(' ')?.toIntOrNull()
                if (dbm != null) { val (q, lv) = when { dbm >= -50 -> "매우 좋음" to -1; dbm >= -60 -> "좋음" to -1; dbm >= -67 -> "보통" to 0; dbm >= -70 -> "약함" to 1; dbm >= -80 -> "불안정" to 1; else -> "거의 안 됨" to 2 }; kv("신호 품질", q, lv) }
                w.firstOrNull { it.first == "주파수" }?.second?.substringBefore(' ')?.toIntOrNull()?.let { f -> WifiChan.fromFreq(f)?.let { (ch, band) -> kv("채널", "$ch ($band)") } }
                note("신호가 약하면 공유기에 가까이 가거나 5 GHz 로 바꿔 보세요. 값이 계속 바뀌니 '새로 고침'으로 걸어 다니며 확인해 보세요.")
            }
        },

        // ------------------------------------------------------------ WHOIS (DNS·도메인 묶음)
        online("whois_domain", N, "WHOIS 도메인 등록 정보", "도메인의 등록 기관·등록일·만료일·네임서버 (IANA → 해당 등록 기관 WHOIS 서버)", DnsTools.domainField(), note = "도메인 이름을 WHOIS 서버(whois.iana.org 와 해당 TLD 서버, 43번 포트)로 보내요. 개인정보는 대부분 가려져 있어요.") { i, _, env ->
            val d = HostInput.host(i.str("d")); if (d.isEmpty() || !HostInput.isPlausibleDomain(d)) return@online need("도메인을 입력하세요 (예: example.com)")
            val ascii = try { java.net.IDN.toASCII(d) } catch (_: Exception) { d }; val tld = ascii.substringAfterLast('.')
            val iana = try { env.progress("IANA 에서 서버 찾는 중..."); Whois.query("whois.iana.org", tld) } catch (e: IOException) { return@online fail("WHOIS 서버에 접속하지 못했어요: ${e.message}") }
            val srv = Whois.referOf(iana) ?: return@online fail(".$tld 의 WHOIS 서버를 찾지 못했어요 (IANA 에 등록 정보가 없어요)")
            var text = try { env.progress("$srv 에 질문 중..."); Whois.query(srv, if (srv.contains("verisign")) "domain $ascii" else ascii) } catch (e: IOException) { return@online fail("$srv 에 접속하지 못했어요: ${e.message}") }
            val registrar = Whois.keyLines(text, listOf("Registrar WHOIS Server")).firstOrNull()?.second?.trim()?.removePrefix("http://")?.removePrefix("https://")?.trimEnd('/')
            if (registrar != null && !registrar.equals(srv, true) && registrar.isNotEmpty()) { try { env.progress("$registrar 에 질문 중..."); val t2 = Whois.query(registrar, ascii); if (t2.length > 200) text = t2 } catch (_: IOException) {} }
            val keys = listOf("Domain Name", "Registrar", "Creation Date", "Updated Date", "Registry Expiry Date", "Registrar Registration Expiration Date", "Name Server", "Domain Status", "DNSSEC", "등록일", "사용 종료일", "등록 대행자")
            result {
                kv("도메인", ascii); kv("조회한 서버", srv + (registrar?.let { " → $it" } ?: ""))
                val kl = Whois.keyLines(text, keys); if (kl.isNotEmpty()) { head("주요 항목"); for ((k, v) in kl.take(24)) kv(k, v) } else note("정리할 항목을 찾지 못했어요. 원문을 확인하세요.", 1)
                head("원문 (개인 연락처 항목은 지웠어요)"); block(Whois.redact(text).lines().filter { it.isNotBlank() }.take(80).joinToString("\n"))
                note("이 도구는 도메인의 등록 정보(등록 기관·날짜·네임서버)만 보여 줘요. 등록자의 이름·메일·전화·주소 같은 개인 연락처 항목은 화면에서 지워요.")
            }
        },

        online("whois_ip", N, "WHOIS IP 주소 블록 소유 기관", "IP 가 속한 주소 블록의 이름·할당 기관·국가 (통신사·클라우드 단위, 개인이 아니에요)", text("ip", "IP 주소", "예: 8.8.8.8", "8.8.8.8", listOf("8.8.8.8" to "8.8.8.8", "1.1.1.1" to "1.1.1.1")),
            note = "IP 주소를 WHOIS 서버(whois.iana.org 와 지역 인터넷 등록 기관)로 보내요. 결과는 주소 블록을 가진 기관 정보이며 사용자의 위치·신원이 아니에요.") { i, _, env ->
            val a = IpUtil.parse(i.str("ip")) ?: return@online if (i.str("ip").isEmpty()) need("IP 주소를 입력하세요") else fail("IP 주소를 읽지 못했어요")
            val kind = IpUtil.classify(a); if (kind != IpKind.PUBLIC) return@online fail("공인 IP 만 조회할 수 있어요 (${kind.label})")
            val ip = IpUtil.format(a)
            val iana = try { env.progress("IANA 에서 서버 찾는 중..."); Whois.query("whois.iana.org", ip) } catch (e: IOException) { return@online fail("WHOIS 서버에 접속하지 못했어요: ${e.message}") }
            val srv = Whois.referOf(iana) ?: return@online fail("이 주소의 WHOIS 서버를 찾지 못했어요")
            val text = try { env.progress("$srv 에 질문 중..."); Whois.query(srv, if (srv.contains("arin")) "n + $ip" else ip) } catch (e: IOException) { return@online fail("$srv 에 접속하지 못했어요: ${e.message}") }
            val keys = listOf("inetnum", "NetRange", "CIDR", "netname", "NetName", "descr", "OrgName", "org-name", "Organization", "country", "Country", "origin", "OriginAS", "route", "source", "mnt-by", "NetType")
            result {
                kv("IP", ip); kv("조회한 서버", srv)
                val kl = Whois.keyLines(text, keys); if (kl.isNotEmpty()) { head("주요 항목"); for ((k, v) in kl.take(20)) kv(k, v) } else note("정리할 항목을 찾지 못했어요. 원문을 확인하세요.", 1)
                head("원문 (개인 연락처 항목은 지웠어요)"); block(Whois.redact(text).lines().filter { it.isNotBlank() && !it.startsWith("%") && !it.startsWith("#") }.take(60).joinToString("\n"))
                note("이 정보는 주소 블록을 관리하는 기관(통신사·클라우드·회사)이에요. 이 IP 를 쓰는 사람의 위치나 신원을 알려 주지 않아요.")
            }
        },
    )
}
