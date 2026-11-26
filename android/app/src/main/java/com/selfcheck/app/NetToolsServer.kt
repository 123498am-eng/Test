package com.selfcheck.app

import org.json.JSONArray
import org.json.JSONObject
import java.io.IOException
import java.net.DatagramPacket
import java.net.DatagramSocket
import java.net.InetAddress
import java.net.Socket
import java.time.ZonedDateTime
import java.time.format.DateTimeFormatter

/**
 * 서버·서비스 점검 도구 19가지: 서버가 먼저 알려 주는 인사말과 공개된 상태 질문의 답만 읽습니다.
 * 로그인 시도·취약점 공격·대량 접속은 하지 않아요. (익명 FTP 확인은 사용자가 고를 때만 USER anonymous 한 번.)
 */
object ServerTools {
    private const val S = NetGroups.SERVER
    private const val NOTE_PROBE = "입력한 서버에 접속해 서버가 먼저 알려 주는 인사말과 지원 기능을 읽어요(로그인 시도 없음). 내가 관리하는 서버이거나 공개 서비스에만 쓰세요."

    private val HOST_CHIPS = listOf("example.com" to "example.com", "google.com" to "google.com", "내 서버" to "")
    private fun hostField(def: String = "example.com", label: String = "서버 주소 (도메인 또는 IP)") = text("h", label, "예: mail.example.com", def, HOST_CHIPS.filter { it.second.isNotEmpty() })
    private fun portField(def: String, chips: List<Pair<String, String>> = emptyList()) = text("port", "포트", "예: $def", def, chips)

    private fun socketsFor(addr: InetAddress, host: ToolHost): () -> Socket = if (IpUtil.classify(addr).local) host.lanSockets() else ({ Socket() })
    private fun addrOf(h: String): InetAddress? = try { TlsInspect.resolve(h) } catch (_: Exception) { null }

    private class Target(val host: String, val port: Int, val addr: InetAddress)

    /** 입력에서 (주소, 포트)를 읽고 연결해도 되는지 검사. 안 되면 결과(오류)를 돌려줌 */
    private fun target(i: ToolInput, defaultPort: Int, requireLocal: Boolean = false): Pair<Target?, ToolResult?> {
        val h = HostInput.host(i.str("h")); if (h.isEmpty()) return null to need("서버 주소를 입력하세요")
        val port = i.str("port").ifEmpty { "$defaultPort" }.toIntOrNull()?.takeIf { it in 1..65535 } ?: return null to fail("포트는 1~65535 예요")
        val a = addrOf(h) ?: return null to fail("\"$h\" 의 주소를 찾지 못했어요")
        val k = IpUtil.classify(a)
        if (k.blocked) return null to fail("이 주소로는 연결할 수 없어요 (${k.label})")
        if (requireLocal && !k.local) return null to fail("이 점검은 내 망 안(사설·루프백) 주소에만 쓸 수 있어요 (${k.label})")
        return Target(h, port, a) to null
    }

    private fun levelOfDays(d: Long) = if (d < 0) 2 else if (d < 14) 2 else if (d < 30) 1 else -1

    private fun tlsRows(rb: Rb, t: TlsReport) {
        rb.kv("TLS 버전", t.protocol, if (t.protocol == "TLSv1.3" || t.protocol == "TLSv1.2") -1 else 2)
        rb.kv("인증서 신뢰", if (t.trusted) "믿을 수 있어요" else (t.trustError ?: "믿을 수 없어요"), if (t.trusted) -1 else 2)
        rb.kv("이름 일치", if (t.hostnameOk) "접속한 주소와 일치" else "접속한 주소와 달라요", if (t.hostnameOk) -1 else 2)
        t.chain.firstOrNull()?.let { c -> val d = CertInfo.daysLeft(c); rb.kv("인증서 만료", if (d < 0) "${-d}일 전 만료" else "${d}일 남음", levelOfDays(d)); rb.kv("발급자", CertInfo.describe(c)[1].second.take(80)) }
    }

    private fun softwareNote(rb: Rb, banner: String) { if (Regex("""\d+\.\d+""").containsMatchIn(banner)) rb.note("인사말에 소프트웨어 이름·버전이 그대로 보여요. 공격자가 알려진 취약점을 고르는 데 쓸 수 있어서 가능하면 숨기는 것이 좋아요.", 1) }

    private fun mailRows(rb: Rb, name: String, r: MailReport, plainPort: Boolean, authCap: (String) -> Boolean) {
        rb.kv("인사말", r.banner.ifEmpty { "-" }); softwareNote(rb, r.banner)
        rb.kv("연결 방식", if (r.implicit) "처음부터 TLS(암호화) 연결" else "평문으로 시작 (STARTTLS 로 암호화 가능)")
        if (!r.implicit) rb.kv("STARTTLS", if (r.starttls) "지원해요" else "지원하지 않아요", if (r.starttls) -1 else 2)
        r.tls?.let { rb.head("TLS 암호화"); tlsRows(rb, it) }
        if (r.caps.isNotEmpty()) { rb.head("지원 기능"); rb.block(r.caps.joinToString("\n")) }
        val all = r.caps + r.capsAfterTls
        val authBefore = r.caps.filter(authCap)
        if (all.any(authCap)) rb.kv("로그인 방식", (r.capsAfterTls.filter(authCap).ifEmpty { authBefore }).joinToString(" · ").ifEmpty { "-" })
        if (!r.implicit && !r.starttls && r.tls == null) rb.note("$name 연결을 암호화할 수 없어요. 메일 내용과 로그인 정보가 평문으로 오가니 TLS(465/993/995)나 STARTTLS 를 켜세요.", 2)
        else if (!r.implicit && r.starttls && authBefore.isNotEmpty()) rb.note("암호화하기 전에도 로그인 방식(${authBefore.joinToString(" ")})을 받아요. STARTTLS 를 하지 않고 로그인하는 클라이언트가 있으면 암호가 평문으로 갈 수 있어요 — 암호화 후에만 로그인을 받게 설정하세요.", 1)
        if (plainPort && r.tls == null) rb.note("이 연결은 암호화되지 않았어요.", 1)
    }

    private fun parseHeaders(text: String): Map<String, String> = text.lines().mapNotNull { l -> l.indexOf(':').takeIf { it > 0 }?.let { l.substring(0, it).trim() to l.substring(it + 1).trim() } }.toMap()

    /** \r \n \t \0 \\ \xHH 를 바이트로 */
    internal fun unescape(s: String): ByteArray? {
        val out = java.io.ByteArrayOutputStream(); var i = 0
        while (i < s.length) {
            val c = s[i]
            if (c != '\\' || i + 1 >= s.length) { out.write(c.toString().toByteArray(Charsets.UTF_8)); i++; continue }
            when (val n = s[i + 1]) {
                'r' -> { out.write(13); i += 2 }; 'n' -> { out.write(10); i += 2 }; 't' -> { out.write(9); i += 2 }; '0' -> { out.write(0); i += 2 }; '\\' -> { out.write('\\'.code); i += 2 }
                'x' -> { val h = s.substring(i + 2, minOf(i + 4, s.length)).takeIf { it.length == 2 }?.toIntOrNull(16) ?: return null; out.write(h); i += 4 }
                else -> { out.write('\\'.code); out.write(n.toString().toByteArray(Charsets.UTF_8)); i += 2 }
            }
        }
        return out.toByteArray()
    }

    internal fun parseHex(s: String): ByteArray? {
        val t = s.replace(Regex("(?i)0x|[\\s:,-]"), ""); if (t.isEmpty() || t.length % 2 != 0 || !t.all { it in '0'..'9' || it in 'a'..'f' || it in 'A'..'F' }) return null
        return ByteArray(t.length / 2) { t.substring(it * 2, it * 2 + 2).toInt(16).toByte() }
    }

    private fun printable(b: ByteArray): String = String(b, Charsets.ISO_8859_1).map { if (it in ' '..'~' || it == '\n' || it == '\r' || it == '\t') it else '·' }.joinToString("")

    private fun showBytes(rb: Rb, b: ByteArray, title: String) {
        rb.head("$title (${b.size}바이트)")
        if (b.isEmpty()) { rb.note("받은 내용이 없어요.", 1); return }
        rb.block(printable(b).take(4000).trimEnd()); rb.block(hexDump(b, 256))
    }

    private fun yesNo(b: Boolean) = if (b) "예" else "아니요"

    val ALL: List<NetTool> = listOf(
        // ===== 메일 서버
        online("srv_smtp", S, "SMTP(메일 발송) 서버 점검", "메일 서버의 인사말·지원 기능·STARTTLS·인증서·로그인 방식을 점검 (25·587·465 포트)",
            hostField("smtp.gmail.com"), portField("587", listOf("587" to "587", "465 (TLS)" to "465", "25" to "25")), choice("mode", "암호화 방식", listOf("자동(465 는 TLS, 그 밖은 STARTTLS)", "처음부터 TLS", "STARTTLS 시도")),
            note = "$NOTE_PROBE (25번 포트는 이동통신·가정 회선이 막는 경우가 많아요.)") { i, host, env ->
            val (t, err) = target(i, 587); if (t == null) return@online err!!
            val implicit = when { i.str("mode").startsWith("처음부터") -> true; i.str("mode").startsWith("STARTTLS") -> false; else -> t.port == 465 }
            env.progress("${t.host}:${t.port} 에 접속 중...")
            val r = try { Smtp.probe(t.host, t.port, implicit, 7000, socketsFor(t.addr, host)) } catch (e: IOException) { return@online fail("점검하지 못했어요: ${e.message}") } catch (e: javax.net.ssl.SSLException) { return@online fail("TLS 연결에 실패했어요: ${e.message?.take(100)}") }
            result { kv("서버", "${t.host}:${t.port} (${IpUtil.format(t.addr)})"); mailRows(this, "SMTP", r, t.port == 25 || t.port == 587) { it.startsWith("AUTH", true) }
                r.capsAfterTls.plus(r.caps).firstOrNull { it.startsWith("SIZE", true) }?.let { kv("최대 메일 크기", it.substringAfter(' ').toLongOrNull()?.let { n -> "%.1f MB".format(n / 1048576.0) } ?: it) } }
        },

        online("srv_imap", S, "IMAP(메일 받기) 서버 점검", "IMAP 서버의 인사말·기능·STARTTLS·인증서 점검 (143·993 포트)", hostField("imap.gmail.com"), portField("993", listOf("993 (TLS)" to "993", "143" to "143")), choice("mode", "암호화 방식", listOf("자동(993 은 TLS, 그 밖은 STARTTLS)", "처음부터 TLS", "STARTTLS 시도")), note = NOTE_PROBE) { i, host, env ->
            val (t, err) = target(i, 993); if (t == null) return@online err!!
            val implicit = when { i.str("mode").startsWith("처음부터") -> true; i.str("mode").startsWith("STARTTLS") -> false; else -> t.port == 993 }
            env.progress("접속 중...")
            val r = try { Imap.probe(t.host, t.port, implicit, 7000, socketsFor(t.addr, host)) } catch (e: IOException) { return@online fail("점검하지 못했어요: ${e.message}") } catch (e: javax.net.ssl.SSLException) { return@online fail("TLS 연결에 실패했어요: ${e.message?.take(100)}") }
            result { kv("서버", "${t.host}:${t.port} (${IpUtil.format(t.addr)})"); mailRows(this, "IMAP", r, t.port == 143) { it.startsWith("AUTH=", true) || it.equals("LOGINDISABLED", true) }
                if (r.caps.any { it.equals("LOGINDISABLED", true) }) note("암호화 전에는 로그인을 막아 두었어요 (좋은 설정이에요).", -1) }
        },

        online("srv_pop3", S, "POP3(메일 받기) 서버 점검", "POP3 서버의 인사말·기능·STLS·인증서 점검 (110·995 포트)", hostField("pop.gmail.com"), portField("995", listOf("995 (TLS)" to "995", "110" to "110")), choice("mode", "암호화 방식", listOf("자동(995 는 TLS, 그 밖은 STLS)", "처음부터 TLS", "STLS 시도")), note = NOTE_PROBE) { i, host, env ->
            val (t, err) = target(i, 995); if (t == null) return@online err!!
            val implicit = when { i.str("mode").startsWith("처음부터") -> true; i.str("mode").startsWith("STLS") -> false; else -> t.port == 995 }
            env.progress("접속 중...")
            val r = try { Pop3.probe(t.host, t.port, implicit, 7000, socketsFor(t.addr, host)) } catch (e: IOException) { return@online fail("점검하지 못했어요: ${e.message}") } catch (e: javax.net.ssl.SSLException) { return@online fail("TLS 연결에 실패했어요: ${e.message?.take(100)}") }
            result { kv("서버", "${t.host}:${t.port} (${IpUtil.format(t.addr)})"); mailRows(this, "POP3", r, t.port == 110) { it.startsWith("SASL", true) || it.equals("USER", true) } }
        },

        online("srv_ftp", S, "FTP 서버 점검", "FTP 서버의 인사말·지원 기능·암호화(AUTH TLS) 여부와, 원하면 익명 로그인 허용 여부", hostField("ftp.example.com"), portField("21"), choice("anon", "익명 로그인", listOf("확인 안 함", "익명 로그인 시험 (USER anonymous 한 번)")),
            note = "$NOTE_PROBE 익명 로그인 시험은 \"anonymous\" 로 로그인을 한 번만 시도해요(내 서버에만 쓰세요).") { i, host, env ->
            val (t, err) = target(i, 21); if (t == null) return@online err!!
            env.progress("접속 중...")
            val r = try { Ftp.probe(t.host, t.port, i.str("anon").startsWith("익명"), 7000, socketsFor(t.addr, host)) } catch (e: IOException) { return@online fail("점검하지 못했어요: ${e.message}") } catch (e: javax.net.ssl.SSLException) { return@online fail("TLS 연결에 실패했어요: ${e.message?.take(100)}") }
            result {
                kv("서버", "${t.host}:${t.port}"); kv("인사말", r.banner.ifEmpty { "-" }); softwareNote(this, r.banner)
                if (r.features.isNotEmpty()) { head("지원 기능 (FEAT)"); block(r.features.joinToString("\n")) }
                r.tls?.let { head("TLS 암호화"); tlsRows(this, it) }
                if (r.tls == null) { if (r.features.any { it.startsWith("AUTH TLS", true) }) note("AUTH TLS 를 받았지만 TLS 전환에 실패했어요.", 1) else note("암호화(AUTH TLS)를 지원하지 않아요. FTP 는 아이디·암호가 평문으로 오가니 SFTP(SSH)나 FTPS 를 쓰세요.", 2) }
                r.anonymous?.let { if (it) note("익명 로그인이 허용돼요. 공개 자료실이 아니라면 끄세요.", 2) else kv("익명 로그인", "허용하지 않아요", -1) }
            }
        },

        online("srv_ssh", S, "SSH 서버 암호 설정 점검", "SSH 서버 버전과 지원하는 키 교환·암호·MAC 알고리즘을 읽고 낡거나 약한 것을 표시 (로그인 시도 없음)", hostField("example.com"), portField("22", listOf("22" to "22", "2222" to "2222")), note = NOTE_PROBE) { i, host, env ->
            val (t, err) = target(i, 22); if (t == null) return@online err!!
            env.progress("접속 중...")
            val r = try { Ssh.probe(t.host, t.port, 7000, socketsFor(t.addr, host)) } catch (e: IOException) { return@online fail("점검하지 못했어요: ${e.message}") }
            result {
                kv("서버", "${t.host}:${t.port}"); kv("버전 인사말", r.banner); softwareNote(this, r.banner)
                val k = r.kex ?: return@result note("암호 설정 목록(KEXINIT)을 읽지 못했어요.", 1)
                kv("키 교환 방식", "${k.kex.size}가지"); kv("호스트 키", k.hostKeys.joinToString(", ")); kv("암호", "${k.ciphers.size}가지"); kv("무결성(MAC)", "${k.macs.size}가지")
                kv("압축", k.compression.joinToString(", ").ifEmpty { "-" })
                val w = Ssh.weaknesses(k)
                if (w.isEmpty()) note("낡거나 약한 알고리즘이 보이지 않아요.", -1)
                else { head("낡거나 약한 알고리즘 ${w.size}개"); header("알고리즘", "이유"); for ((a, why, lv) in w) row(a, why, level = lv); note("설정(sshd_config 의 KexAlgorithms·Ciphers·MACs·HostKeyAlgorithms)에서 위 항목을 빼면 접속 가능한 클라이언트가 줄어도 더 안전해요. 오래된 장비가 접속하는지 먼저 확인하세요.", if (w.any { it.third == 2 }) 2 else 1) }
                head("키 교환"); block(k.kex.joinToString("\n")); head("암호"); block(k.ciphers.joinToString("\n")); head("무결성(MAC)"); block(k.macs.joinToString("\n"))
            }
        },

        online("srv_banner", S, "서비스 인사말(배너) 읽기", "포트에 접속해 서버가 먼저 보내는 글을 읽기 (SSH·FTP·SMTP·MySQL 같은 서비스가 무엇인지 확인)", hostField(), portField("22", listOf("22" to "22", "21" to "21", "25" to "25", "3306" to "3306")), choice("send", "먼저 보낼 것", listOf("아무것도 안 보냄", "빈 줄(\\r\\n)", "HTTP HEAD 요청")), choice("tls", "암호화", listOf("평문", "TLS")),
            note = "$NOTE_PROBE 3초 동안 오는 글을 읽어요.") { i, host, env ->
            val (t, err) = target(i, 22); if (t == null) return@online err!!
            env.progress("접속 중...")
            val got = try {
                ProbeConn(t.host, t.port, 6000, socketsFor(t.addr, host), tls = i.str("tls") == "TLS").use { c ->
                    when (i.str("send")) { "빈 줄(\\r\\n)" -> c.send("\r\n"); "HTTP HEAD 요청" -> c.send("HEAD / HTTP/1.0\r\nHost: ${t.host}\r\nUser-Agent: SelfCheck\r\n\r\n") }
                    c.readSome(4096, 3000) to c.tlsReport
                }
            } catch (e: IOException) { return@online fail("접속하지 못했어요: ${e.message}") } catch (e: javax.net.ssl.SSLException) { return@online fail("TLS 연결에 실패했어요: ${e.message?.take(100)}") }
            result { kv("서버", "${t.host}:${t.port}"); got.second?.let { kv("TLS", "${it.protocol} · ${if (it.trusted) "신뢰" else "신뢰할 수 없는 인증서"}") }; showBytes(this, got.first, "받은 글")
                if (got.first.isEmpty()) note("서버가 먼저 말하지 않는 서비스예요(웹 서버·데이터베이스 등). \"먼저 보낼 것\"을 바꿔 보세요.", 1) }
        },

        online("srv_tcp_send", S, "TCP 로 글 보내고 답 받기 (netcat)", "서버의 포트에 접속해 내가 쓴 글(또는 16진수)을 한 번 보내고 돌아오는 답을 확인 — 서비스 시험·디버깅용", hostField(), portField("80"),
            multi("data", "보낼 내용", "예: GET / HTTP/1.0\\r\\n\\r\\n", "GET / HTTP/1.0\\r\\n\\r\\n"), choice("mode", "내용 형식", listOf("글 (\\r \\n \\xHH 사용 가능)", "16진수")), choice("tls", "암호화", listOf("평문", "TLS")), choice("wait", "기다릴 시간", listOf("2초", "5초", "10초")),
            note = "서버에 연결해 내가 쓴 내용을 한 번 보내요(최대 4KB). 내가 관리하는 서버나 공개 서비스에만 쓰세요.") { i, host, env ->
            val (t, err) = target(i, 80); if (t == null) return@online err!!
            val raw = i.raw("data"); if (raw.isBlank()) return@online need("보낼 내용을 입력하세요")
            val bytes = (if (i.str("mode") == "16진수") parseHex(raw) else unescape(raw.trimEnd('\n'))) ?: return@online fail(if (i.str("mode") == "16진수") "16진수를 읽지 못했어요 (예: 48 54 54 50)" else "\\x 뒤에는 16진수 두 자리가 와야 해요")
            if (bytes.size > 4096) return@online fail("보낼 내용은 4KB 까지예요")
            env.progress("접속 중...")
            val wait = i.str("wait").removeSuffix("초").toInt() * 1000
            val got = try { ProbeConn(t.host, t.port, 6000, socketsFor(t.addr, host), tls = i.str("tls") == "TLS").use { c -> c.sendBytes(bytes); c.readSome(16384, wait) } } catch (e: IOException) { return@online fail("접속하지 못했어요: ${e.message}") } catch (e: javax.net.ssl.SSLException) { return@online fail("TLS 연결에 실패했어요: ${e.message?.take(100)}") }
            result { kv("서버", "${t.host}:${t.port}"); kv("보낸 바이트", "${bytes.size}바이트"); showBytes(this, got, "받은 내용") }
        },

        online("srv_udp_send", S, "UDP 로 글 보내고 답 받기", "서버의 UDP 포트에 한 개의 패킷(글 또는 16진수)을 보내고 답을 확인 — DNS·NTP·게임·IoT 서비스 시험", hostField(), portField("53"),
            multi("data", "보낼 내용", "예: 16진수 또는 글", "hello"), choice("mode", "내용 형식", listOf("글 (\\r \\n \\xHH 사용 가능)", "16진수")), choice("wait", "기다릴 시간", listOf("2초", "5초")),
            note = "서버의 UDP 포트에 패킷 1개를 보내요(최대 1KB). 내가 관리하는 서버나 공개 서비스에만 쓰세요.") { i, host, env ->
            val (t, err) = target(i, 53); if (t == null) return@online err!!
            val raw = i.raw("data"); if (raw.isBlank()) return@online need("보낼 내용을 입력하세요")
            val bytes = (if (i.str("mode") == "16진수") parseHex(raw) else unescape(raw.trimEnd('\n'))) ?: return@online fail("내용을 읽지 못했어요")
            if (bytes.size > 1024) return@online fail("보낼 내용은 1KB 까지예요")
            val wait = i.str("wait").removeSuffix("초").toInt() * 1000
            env.progress("보내는 중...")
            val got = try { DatagramSocket().use { s -> host.bindDatagram(s); s.soTimeout = wait; val t0 = System.nanoTime(); s.send(DatagramPacket(bytes, bytes.size, t.addr, t.port)); val buf = ByteArray(8192); val p = DatagramPacket(buf, buf.size)
                try { s.receive(p); buf.copyOf(p.length) to (System.nanoTime() - t0) / 1_000_000 } catch (_: java.net.SocketTimeoutException) { null } } } catch (e: IOException) { return@online fail("보내지 못했어요: ${e.message}") }
            result { kv("서버", "${t.host}:${t.port} (UDP)"); kv("보낸 바이트", "${bytes.size}바이트")
                if (got == null) note("답이 없어요. 서버가 이 내용을 모르거나, UDP 가 막혔거나, 포트가 닫혀 있어요 (UDP 는 닫혀 있어도 답이 없는 경우가 많아요).", 1) else { kv("응답 시간", "${got.second}ms"); showBytes(this, got.first, "받은 내용") } }
        },

        online("srv_http_req", S, "HTTP 요청 보내기 (미니 Postman)", "메서드·헤더·본문을 직접 정해 웹 서버·API 에 요청을 보내고 상태·응답 시간·헤더·본문을 확인", text("u", "주소 (URL)", "예: https://httpbin.org/get", "https://example.com/", listOf("example.com" to "https://example.com/")),
            choice("m", "메서드", listOf("GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS")), multi("hd", "헤더 (한 줄에 하나, 선택)", "예: Authorization: Bearer 토큰", ""), multi("body", "본문 (POST·PUT·PATCH, 선택)", "예: {\"a\":1}", ""), choice("ins", "인증서", listOf("검사함", "오류 무시 (위험)")),
            note = "입력한 주소로 내가 정한 HTTP 요청을 보내요. 헤더·본문에 비밀번호·토큰을 넣으면 그 서버로 전달돼요. 내가 사용 권한이 있는 서비스에만 쓰세요.") { i, _, env ->
            val u = i.str("u"); if (u.isEmpty()) return@online need("주소를 입력하세요")
            val m = i.str("m"); val hdr = parseHeaders(i.raw("hd")); val body = i.raw("body").takeIf { it.isNotEmpty() && m in listOf("POST", "PUT", "PATCH", "DELETE") }?.toByteArray()
            if ((body?.size ?: 0) > 65536) return@online fail("본문은 64KB 까지예요")
            env.progress("$m 요청 중...")
            val r = try { MiniHttp.request(u, m, hdr, 8192, 10000, i.str("ins") != "검사함", body = body) } catch (e: IOException) { return@online fail("요청하지 못했어요: ${e.message}") }
            result {
                if (i.str("ins") != "검사함") note("인증서 검사를 건너뛰었어요. 결과가 진짜 서버의 것인지 보장되지 않아요.", 1)
                kv("요청", "$m ${r.url}"); kv("상태", r.statusLine.substringAfter(' '), when (r.status) { in 200..299 -> -1; in 300..399 -> 0; in 400..499 -> 1; else -> 2 }); kv("서버 IP", r.remoteIp)
                DiagTools.timings(this, r)
                r.tls?.let { kv("TLS", it.protocol) }
                head("응답 헤더"); header("이름", "값"); for ((k, v) in r.headers) row(k, v)
                val bt = r.body
                if (!bt.isNullOrEmpty()) { head("응답 본문 (앞 8KB)"); block(prettyJson(bt) ?: bt) }
            }
        },

        online("srv_websocket", S, "WebSocket 연결 점검", "ws://·wss:// 주소로 연결(핸드셰이크)해서 서버가 WebSocket 을 제대로 받아 주는지, 메시지를 보내면 답하는지", text("u", "주소", "예: wss://echo.websocket.org", "wss://echo.websocket.org", listOf("echo" to "wss://echo.websocket.org")),
            text("msg", "보낼 메시지 (선택)", "예: hello", "hello"), note = "WebSocket 연결을 열고, 메시지를 하나 보낸 뒤 첫 응답만 읽고 닫아요.") { i, host, env ->
            val u = i.str("u"); if (u.isEmpty()) return@online need("주소를 입력하세요")
            env.progress("연결 중...")
            val r = try { WebSocketProbe.probe(u, i.str("msg").ifEmpty { null }, 7000) } catch (e: IOException) { return@online fail("연결하지 못했어요: ${e.message}") } catch (e: javax.net.ssl.SSLException) { return@online fail("TLS 연결에 실패했어요: ${e.message?.take(100)}") }
            result {
                kv("응답", r.statusLine, if (r.statusLine.contains(" 101")) -1 else 2)
                r.tls?.let { tlsRows(this, it) }
                if (r.statusLine.contains(" 101")) { kv("서버 확인(Accept 값)", if (r.acceptOk) "올바른 서버예요" else "값이 맞지 않아요", if (r.acceptOk) -1 else 2); r.headers["sec-websocket-protocol"]?.let { kv("하위 프로토콜", it) }; r.headers["sec-websocket-extensions"]?.let { kv("확장", it) }
                    kv("받은 첫 메시지", r.message ?: "(없음 — 서버가 먼저/답으로 보내지 않았어요)")
                    note(if (r.acceptOk) "WebSocket 연결이 정상으로 열렸어요." else "101 응답이지만 확인 값이 달라서 WebSocket 서버가 아닐 수 있어요.", if (r.acceptOk) -1 else 2) }
                else note("업그레이드(101)가 아니에요. 주소(경로)가 틀렸거나, 서버가 WebSocket 을 받지 않거나, 인증·Origin 확인이 필요해요.", 1)
                r.headers["server"]?.let { kv("Server", it) }
            }
        },

        online("srv_mqtt", S, "MQTT 브로커 점검", "MQTT(IoT) 서버에 접속 요청(CONNECT)을 보내 인증 없이 열려 있는지, 암호화를 쓰는지 확인 (구독·발행 안 함)", hostField("test.mosquitto.org"), portField("1883", listOf("1883" to "1883", "8883 (TLS)" to "8883")), choice("tls", "암호화", listOf("평문", "TLS")),
            note = "MQTT 접속 요청 한 번과 끊기(DISCONNECT)만 보내요. 구독·발행은 하지 않아요. 내가 관리하는 브로커에만 쓰세요.") { i, host, env ->
            val (t, err) = target(i, 1883); if (t == null) return@online err!!
            env.progress("접속 중...")
            val r = try { Mqtt.probe(t.host, t.port, i.str("tls") == "TLS", 7000, socketsFor(t.addr, host)) } catch (e: IOException) { return@online fail("점검하지 못했어요: ${e.message}") } catch (e: javax.net.ssl.SSLException) { return@online fail("TLS 연결에 실패했어요: ${e.message?.take(100)}") }
            result {
                kv("브로커", "${t.host}:${t.port}"); r.second?.let { tlsRows(this, it) }
                kv("결과 코드", "${r.first}: ${Mqtt.CODES[r.first] ?: "알 수 없음"}", if (r.first == 0) 1 else -1)
                if (r.first == 0) note("인증 없이 접속이 허용돼요. 인터넷에 열린 브로커라면 누구나 메시지를 읽고 보낼 수 있어서 위험해요. 내 망 안에서만 쓰거나 사용자·암호(와 TLS)를 요구하도록 설정하세요.", if (i.str("tls") == "TLS" || IpUtil.classify(t.addr).local) 1 else 2)
                if (r.second == null && !IpUtil.classify(t.addr).local) note("암호화(TLS)를 쓰지 않아요. 인터넷을 지나는 MQTT 는 TLS(8883)를 쓰세요.", 1)
            }
        },

        lanTool("srv_rtsp", S, "IP 카메라(RTSP) 점검", "내 망의 IP 카메라·NVR 이 영상 주소(RTSP)를 인증 없이 보여 주는지, 어떤 장비인지 확인", hostField("192.168.0.100", "카메라 주소 (내 망 안)"), portField("554"),
            note = "내 망 안 장비의 RTSP 포트에 \"어떤 기능을 지원해요?\"(OPTIONS)와 \"영상 정보 주세요\"(DESCRIBE) 질문을 한 번씩 보내요. 내 카메라에만 쓰세요.") { i, host, env ->
            val (t, err) = target(i, 554, requireLocal = true); if (t == null) return@lanTool err!!
            env.progress("접속 중...")
            val r = try { Rtsp.probe(t.host, t.port, 5000, host.lanSockets()) } catch (e: IOException) { return@lanTool fail("점검하지 못했어요: ${e.message}") }
            result {
                kv("장비", "${t.host}:${t.port}"); kv("OPTIONS", r.first.statusLine.removePrefix("RTSP/1.0 ")); r.first.headers["public"]?.let { kv("지원하는 명령", it) }; (r.first.headers["server"] ?: r.second?.headers?.get("server"))?.let { kv("서버 이름", it) }
                r.second?.let { d -> kv("DESCRIBE", d.statusLine.removePrefix("RTSP/1.0 "), when (d.status) { 200 -> 2; 401, 403 -> -1; else -> 0 })
                    when (d.status) { 200 -> note("인증 없이 영상 정보(SDP)를 줘요: 같은 망의 누구나 이 카메라 영상을 볼 수 있을 수 있어요. 카메라 설정에서 비밀번호(인증)를 켜세요.", 2); 401, 403 -> note("인증을 요구해요 (좋아요).", -1); 404 -> note("기본 경로(/)에는 영상이 없어요(404). 카메라마다 경로가 달라서 이것만으로 열려 있는지는 알 수 없어요.", 0); else -> note("DESCRIBE 응답 코드 ${d.status}", 0) } }
                note("카메라는 기본 비밀번호를 바꾸고, 인터넷(공유기 포트 포워딩)에 직접 열지 말고 VPN 으로만 접속하세요.")
            }
        },

        online("srv_sip", S, "SIP(인터넷 전화) 서버 점검", "SIP 서버·IP 전화기·공유기 전화 포트가 살아 있는지, 어떤 장비·소프트웨어인지 확인 (UDP 5060)", hostField("sip.example.com"), portField("5060"),
            note = "UDP 5060 으로 \"살아 있나요?\"(OPTIONS) 질문 1개를 보내요. 내가 관리하는 장비에만 쓰세요.") { i, host, env ->
            val (t, err) = target(i, 5060); if (t == null) return@online err!!
            env.progress("질문을 보내는 중...")
            val r = try { Sip.probe(t.host, t.port, 5000) { host.bindDatagram(it) } } catch (e: IOException) { return@online fail("점검하지 못했어요: ${e.message}") }
            result { kv("서버", "${t.host}:${t.port} (UDP)"); kv("응답", r.first.removePrefix("SIP/2.0 "), if (r.first.contains(" 200") || r.first.contains(" 401") || r.first.contains(" 403")) -1 else 1)
                (r.second["server"] ?: r.second["user-agent"])?.let { kv("서버 소프트웨어", it); softwareNote(this, it) }; r.second["allow"]?.let { kv("허용 메서드", it) }; r.second["supported"]?.let { kv("지원 기능", it) }
                note("SIP 서버가 응답했어요. 401·403 은 로그인이 필요하다는 정상적인 답이에요.", -1) }
        },

        online("srv_dns_server", S, "DNS 서버 종합 점검", "DNS 서버가 응답하는지·UDP/TCP 모두 되는지·재귀 조회·DNSSEC 검증·가짜 응답(NXDOMAIN 가로채기)이 없는지 한꺼번에", text("server", "DNS 서버 (IP)", "예: 8.8.8.8", "8.8.8.8", listOf("구글" to "8.8.8.8", "클라우드플레어" to "1.1.1.1", "Quad9" to "9.9.9.9", "KT" to "168.126.63.1")),
            note = "그 DNS 서버에 질문 몇 개(example.com·cloudflare.com·dnssec-failed.org·무작위 이름)를 보내요. 인터넷을 사용해요.") { i, host, env ->
            val sv = i.str("server").ifEmpty { host.dnsServers().firstOrNull() ?: "" }; if (sv.isEmpty()) return@online need("DNS 서버 주소를 입력하세요")
            val ip = IpUtil.parse(sv.substringBefore('#')) ?: return@online fail("DNS 서버는 IP 주소로 입력하세요")
            val local = IpUtil.classify(ip).local; val sock = if (local) host.lanSockets() else ({ Socket() }); val bind: (DatagramSocket) -> Unit = { if (local) host.bindDatagram(it) }
            fun q(name: String, tcp: Boolean = false, dnssec: Boolean = false): DnsResponse? = try { DnsClient.query(sv, name, DnsType.A, timeoutMs = 3000, dnssec = dnssec, retries = 0, tcpOnly = tcp, bind = bind, newSocket = sock) } catch (_: IOException) { null }
            env.progress("질문을 보내는 중...")
            val rnd = "selfcheck-" + java.util.UUID.randomUUID().toString().take(8) + ".example.com"
            val res = Par.map(listOf("udp", "tcp", "ad", "bad", "nx"), 5, 12000) { k -> when (k) { "udp" -> q("example.com"); "tcp" -> q("example.com", tcp = true); "ad" -> q("cloudflare.com", dnssec = true); "bad" -> q("dnssec-failed.org"); else -> q(rnd) } }
            val udp = res[0]; val tcp = res[1]; val ad = res[2]; val bad = res[3]; val nx = res[4]
            if (udp == null && tcp == null) return@online fail("이 DNS 서버가 응답하지 않아요 (주소가 틀렸거나 방화벽·서버 중지)")
            result {
                kv("DNS 서버", sv); header("점검", "결과", "설명")
                row("UDP 질문", if (udp != null) "응답 ${udp.ms}ms" else "응답 없음", if (udp != null && udp.msg.answers.isNotEmpty()) "example.com → ${udp.msg.answers.firstOrNull { it.type == DnsType.A }?.data ?: "-"}" else "", level = if (udp != null) -1 else 2)
                row("TCP 질문", if (tcp != null) "응답 ${tcp.ms}ms" else "응답 없음", "TCP 53 번도 되어야 큰 응답·DNSSEC 가 안전해요", level = if (tcp != null) -1 else 1)
                row("재귀 조회(RA)", if (udp?.msg?.ra == true) "됨" else "안 됨", if (udp?.msg?.ra == true) "다른 도메인도 대신 찾아 줘요 (리졸버)" else "권한 서버이거나 재귀를 막아 두었어요", level = if (udp?.msg?.ra == true) 0 else 1)
                val adSet = ad?.msg?.ad == true
                row("DNSSEC 검증", if (ad == null) "응답 없음" else if (adSet) "검증함 (AD)" else "검증 표시 없음", "서명된 도메인(cloudflare.com)의 응답에 AD 표시가 붙는지", level = if (adSet) -1 else 0)
                val validating = bad != null && bad.msg.rcode == 2
                row("가짜 서명 도메인", if (bad == null) "응답 없음" else if (validating) "차단함 (SERVFAIL)" else "그대로 답함", "dnssec-failed.org 는 서명이 일부러 틀린 도메인이에요 — 검증 리졸버는 SERVFAIL 로 막아요", level = if (validating) -1 else 0)
                val hijack = nx != null && nx.msg.rcode == 0 && nx.msg.answers.any { it.type == DnsType.A }
                row("없는 이름 처리", if (nx == null) "응답 없음" else if (hijack) "가짜 IP 를 돌려줌" else "NXDOMAIN(정상)", "없는 도메인에는 \"없음\"이라고 답해야 해요", level = if (hijack) 2 else -1)
                head("요약")
                if (hijack) note("없는 도메인에 IP 를 돌려줘요: 통신사·공유기가 오타 도메인을 광고 페이지로 보내는(NXDOMAIN 가로채기) 설정이거나 DNS 가 변조됐어요. 다른 DNS(1.1.1.1 등)를 써 보세요.", 2)
                else note("기본 점검에서 이상한 점이 없어요." + if (validating) " DNSSEC 검증도 해 줘요." else "", -1)
            }
        },

        online("srv_ntp_compare", S, "NTP 시간 서버 여러 곳 비교", "시간 서버 여러 곳이 알려 주는 시각을 비교해서 내 시계 오차와 서버 간 차이를 확인", multi("s", "시간 서버 (한 줄에 하나, 최대 8개)", "예: time.google.com", "time.google.com\ntime.cloudflare.com\npool.ntp.org\ntime.windows.com\ntime.kriss.re.kr"),
            note = "NTP 서버마다 UDP 123 번으로 시간 질문 1개를 보내요. 인터넷을 사용해요.") { i, host, env ->
            val sv = i.lines("s").map { it.trim() }.distinct().take(8); if (sv.isEmpty()) return@online need("시간 서버를 한 줄에 하나씩 입력하세요")
            env.progress("${sv.size}곳에 묻는 중...")
            val res = Par.map(sv, 8, 10000) { s -> runCatching { NtpClient.query(s, timeoutMs = 3500, bind = { host.bindDatagram(it) }) }.getOrNull() }
            val ok = res.filterNotNull()
            if (ok.isEmpty()) return@online fail("어느 서버에서도 응답이 없어요. UDP 123 번이 막힌 망일 수 있어요")
            val offs = ok.map { it.offsetMs }.sorted(); val med = offs[offs.size / 2]; val spread = offs.last() - offs.first()
            result {
                header("서버", "내 시계 오차", "왕복", "층위")
                sv.forEachIndexed { k, s -> val r = res[k]; if (r == null) row(s, "응답 없음", "", "", level = 1) else row(s, fmtOff(r.offsetMs), "%.0f ms".format(r.delayMs), "${r.stratum}", level = if (Math.abs(r.offsetMs) < 100) -1 else if (Math.abs(r.offsetMs) < 1000) 1 else 2) }
                kv("응답한 서버", "${ok.size} / ${sv.size}"); kv("내 시계 오차(중앙값)", fmtOff(med), if (Math.abs(med) < 100) -1 else if (Math.abs(med) < 1000) 1 else 2); kv("서버끼리 차이", "%.0f ms".format(spread), if (spread < 100) -1 else 1)
                note(when { Math.abs(med) < 100 -> "내 시계가 정확해요."; Math.abs(med) < 1000 -> "조금 틀렸지만 문제 되지 않아요."; else -> "시계가 많이 틀렸어요. \"날짜 및 시간 자동 설정\"을 켜세요 (HTTPS 오류·OTP 불일치의 원인이에요)." }, if (Math.abs(med) < 1000) -1 else 2)
                if (spread > 300) note("서버끼리 시각이 크게 달라요. 그 중 일부 서버가 틀렸거나 왕복 지연이 불안정해요. 중앙값을 믿으세요.", 1)
            }
        },

        online("srv_syslog", S, "Syslog 시험 메시지 보내기", "로그 수집 서버(Syslog)에 시험 메시지 한 줄(UDP)을 보내서 수집되는지 확인", hostField("192.168.0.10", "Syslog 서버"), portField("514"), choice("fac", "종류(facility)", Syslog.FACILITIES, "user"), choice("sev", "중요도(severity)", Syslog.SEVERITIES, "info"), text("app", "프로그램 이름", "예: selfcheck", "selfcheck"), text("msg", "메시지", "", "SelfCheck 시험 메시지"),
            note = "Syslog 서버의 UDP 포트에 시험 메시지 1개를 보내요. 내가 관리하는 로그 서버에만 쓰세요.") { i, host, env ->
            val (t, err) = target(i, 514); if (t == null) return@online err!!
            val msgText = i.str("msg"); if (msgText.isEmpty()) return@online need("메시지를 입력하세요")
            val fac = Syslog.FACILITIES.indexOf(i.str("fac")).coerceAtLeast(0); val sev = Syslog.SEVERITIES.indexOf(i.str("sev")).coerceAtLeast(0)
            val line = Syslog.message(Syslog.pri(fac, sev), ZonedDateTime.now().format(DateTimeFormatter.ISO_OFFSET_DATE_TIME), "selfcheck-phone", i.str("app").ifEmpty { "selfcheck" }.replace(' ', '_').take(48), msgText.take(900))
            val data = line.toByteArray()
            try { DatagramSocket().use { s -> host.bindDatagram(s); s.send(DatagramPacket(data, data.size, t.addr, t.port)) } } catch (e: IOException) { return@online fail("보내지 못했어요: ${e.message}") }
            result { kv("보낸 곳", "${t.host}:${t.port} (UDP)"); kv("우선순위", "<${Syslog.pri(fac, sev)}> = ${Syslog.FACILITIES[fac]}.${Syslog.SEVERITIES[sev]}"); head("보낸 메시지"); block(line)
                note("UDP 는 도착을 확인할 수 없어요. 서버의 로그 파일(예: /var/log/syslog)에서 메시지가 보이는지 확인하세요. 안 보이면 서버가 UDP 514 를 열어 두었는지, 방화벽이 막지 않는지 확인하세요.") }
        },

        lanTool("srv_redis", S, "Redis·Memcached 노출 점검 (내 망)", "내 망 안 서버의 Redis·Memcached 가 인증 없이 열려 있는지 확인 — 인터넷에 열리면 위험한 대표적인 서비스", hostField("192.168.0.10", "서버 주소 (내 망 안)"), choice("kind", "종류", listOf("Redis (6379)", "Memcached (11211)")),
            note = "내 망 안 서버에 \"살아 있나요?\"(PING 또는 version) 질문 한 번만 보내요. 데이터는 읽지 않아요. 내 서버에만 쓰세요.") { i, host, env ->
            val redis = i.str("kind").startsWith("Redis"); val (t, err) = target(ToolInput(mapOf("h" to i.str("h"), "port" to if (redis) "6379" else "11211")), 6379, requireLocal = true); if (t == null) return@lanTool err!!
            env.progress("접속 중...")
            val r = try { ProbeConn(t.host, t.port, 4000, host.lanSockets()).use { c ->
                if (redis) { c.send("PING\r\n"); val first = c.line() ?: ""; val info = if (first.startsWith("+PONG")) { c.send("INFO server\r\n"); runCatching { c.line(); val ver = generateSequence { c.line() }.take(40).firstOrNull { it.startsWith("redis_version:") }; ver?.substringAfter(':') }.getOrNull() } else null; Triple(first, info, true) }
                else { c.send("version\r\n"); Triple(c.line() ?: "", null, false) } } } catch (e: IOException) { return@lanTool fail("접속하지 못했어요: ${e.message}") }
            result {
                kv("서버", "${t.host}:${t.port}"); kv("첫 응답", r.first.take(100).ifEmpty { "(없음)" })
                if (r.third) when { r.first.startsWith("+PONG") -> { kv("인증", "필요 없음 (열려 있음)", 2); r.second?.let { kv("Redis 버전", it) }; note("암호 없이 누구나 명령을 보낼 수 있어요. 이 서버가 인터넷이나 같은 망의 낯선 기기에 닿는다면 매우 위험해요. requirepass·바인딩(127.0.0.1)·방화벽을 설정하세요.", 2) }
                    r.first.startsWith("-NOAUTH") -> { kv("인증", "필요해요", -1); note("암호가 설정돼 있어요 (좋아요).", -1) }
                    r.first.startsWith("-DENIED") || r.first.contains("protected mode", true) -> { kv("보호 모드", "켜짐", -1); note("외부 접속을 막는 보호 모드예요 (좋아요).", -1) }
                    else -> note("Redis 가 아닌 것 같아요.", 1) }
                else if (r.first.startsWith("VERSION")) { kv("Memcached 버전", r.first.removePrefix("VERSION ").trim()); note("Memcached 는 기본적으로 인증이 없어서 누구나 접속할 수 있어요. 외부에 열면 데이터 유출·반사 증폭 공격에 악용돼요. 127.0.0.1 로만 바인딩하고 방화벽으로 막으세요.", 2) } else note("Memcached 가 아닌 것 같아요.", 1)
            }
        },

        online("srv_minecraft", S, "마인크래프트 서버 상태 확인", "서버 주소만 넣으면 접속자 수·버전·서버 소개글(MOTD)·응답 시간을 확인 (자바 에디션)", hostField("mc.example.net", "서버 주소"), portField("25565"),
            note = "마인크래프트 서버 목록이 쓰는 \"상태 조회\" 질문 1개를 보내요(접속하지 않아요). 접속자 이름은 표시하지 않아요.") { i, host, env ->
            val (t, err) = target(i, 25565); if (t == null) return@online err!!
            env.progress("접속 중...")
            val s = try { Minecraft.probe(t.host, t.port, 6000, socketsFor(t.addr, host)) } catch (e: IOException) { return@online fail("조회하지 못했어요: ${e.message}") }
            result { kv("서버", "${t.host}:${t.port}"); kv("상태", "켜져 있어요", -1); s.version?.let { kv("버전", it + (s.protocol?.let { p -> " (프로토콜 $p)" } ?: "")) }; if (s.online != null) kv("접속자", "${s.online} / ${s.max ?: "?"}명")
                kv("소개글(MOTD)", s.motd.ifEmpty { "-" }); s.pingMs?.let { kv("응답 시간", "${it}ms", if (it < 100) -1 else if (it < 200) 0 else 1) }
                note("자바 에디션 서버의 상태 응답이에요. 베드락 에디션(UDP 19132)은 다른 방식이라 지원하지 않아요.") }
        },

        online("srv_source_query", S, "게임 서버 정보 조회 (Source 엔진)", "카운터스트라이크·TF2·Garry's Mod·발헤임 등 Source 방식 서버의 이름·맵·접속자 수 (UDP A2S_INFO)", hostField("game.example.net", "서버 주소"), portField("27015", listOf("27015" to "27015")),
            note = "서버의 조회 포트(UDP)에 정보 요청(A2S_INFO) 1~2개를 보내요. 서버가 공개하는 정보만 받아요.") { i, host, env ->
            val (t, err) = target(i, 27015); if (t == null) return@online err!!
            env.progress("질문을 보내는 중...")
            val r = try { SourceQuery.query(t.host, t.port, 3500) { host.bindDatagram(it) } } catch (e: IOException) { return@online fail("조회하지 못했어요: ${e.message}") }
            result { kv("서버", "${t.host}:${t.port} (UDP)"); kv("이름", r.name); kv("맵", r.map); kv("게임", r.game.ifEmpty { r.folder }); kv("접속자", "${r.players} / ${r.max}명" + if (r.bots > 0) " (봇 ${r.bots})" else ""); kv("종류", when (r.type) { 'd' -> "전용 서버"; 'l' -> "리슨(방장) 서버"; 'p' -> "SourceTV"; else -> "${r.type}" })
                kv("운영체제", when (r.env) { 'l' -> "리눅스"; 'w' -> "윈도"; 'm', 'o' -> "맥"; else -> "${r.env}" }); kv("비밀번호", if (r.visibility == 1) "있음" else "없음"); kv("VAC 보안", if (r.vac == 1) "켜짐" else "꺼짐"); kv("게임 번호(AppID)", "${r.appId}") }
        },
    )

    private fun fmtOff(ms: Double) = if (Math.abs(ms) < 1) "%.2f ms".format(ms) else "%+.0f ms".format(ms)

    internal fun prettyJson(text: String): String? {
        val t = text.trim()
        return try { if (t.startsWith("{")) JSONObject(t).toString(2) else if (t.startsWith("[")) JSONArray(t).toString(2) else null } catch (_: org.json.JSONException) { null }
    }
}
