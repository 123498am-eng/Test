package com.selfcheck.app

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Test
import java.io.IOException
import java.io.InputStream
import java.io.OutputStream
import java.net.DatagramPacket
import java.security.MessageDigest
import java.util.Base64

/*
 * 서버·서비스 점검 엔진과 도구 시험: 컴퓨터 안(127.0.0.1)에 SMTP·IMAP·POP3·FTP(STARTTLS 포함)·SSH·MQTT·RTSP·SIP·WebSocket·
 * 마인크래프트·Source·Redis·DNS·NTP·Syslog 가짜 서버를 열어 놓고 프로토콜 대화를 끝까지 확인합니다.
 * 패킷 모양은 파이썬으로 따로 만든 바이트(또는 RFC 예시)와 비교해요. 실제 인터넷 서버와는 연결하지 않았어요.
 */
class NetServerTest {
    private fun hex(s: String) = ByteArray(s.length / 2) { s.substring(it * 2, it * 2 + 2).toInt(16).toByte() }
    private fun ByteArray.hx() = joinToString("") { "%02x".format(it.toInt() and 0xff) }
    private fun text(r: ToolResult) = r.text()
    private fun run(id: String, vararg kv: Pair<String, String>) = runNetTool(id, *kv)

    // ================================================================ 가짜 메일·FTP 서버
    private fun w(out: OutputStream, s: String) { out.write(s.toByteArray()); out.flush() }

    private fun smtpServer(starttls: Boolean = true, authBeforeTls: Boolean = true, implicitTls: Boolean = false) = TestTcp { c0 ->
        var c: java.net.Socket = c0
        if (implicitTls) c = upgradeServerTls(c0)
        var ins: InputStream = c.getInputStream(); var out: OutputStream = c.getOutputStream(); var tlsOn = implicitTls
        w(out, "220 mx.example.com ESMTP Postfix (Ubuntu 22.04)\r\n")
        while (true) {
            val l = readLineRaw(ins) ?: break
            when {
                l.startsWith("EHLO", true) -> w(out, if (!tlsOn) "250-mx.example.com\r\n250-PIPELINING\r\n250-SIZE 52428800\r\n" + (if (starttls) "250-STARTTLS\r\n" else "") + (if (authBeforeTls) "250-AUTH PLAIN LOGIN\r\n" else "") + "250 8BITMIME\r\n" else "250-mx.example.com\r\n250-AUTH PLAIN LOGIN\r\n250 8BITMIME\r\n")
                l.equals("STARTTLS", true) -> { w(out, "220 2.0.0 Ready to start TLS\r\n"); val ssl = upgradeServerTls(c); ins = ssl.inputStream; out = ssl.outputStream; tlsOn = true }
                l.equals("QUIT", true) -> { w(out, "221 Bye\r\n"); break }
                else -> w(out, "502 5.5.2 Error: command not recognized\r\n")
            }
        }
    }

    @Test fun smtp_probe_starttlsAndTool() {
        smtpServer().use { s ->
            val r = Smtp.probe("127.0.0.1", s.port, false, 5000)
            assertEquals("mx.example.com ESMTP Postfix (Ubuntu 22.04)", r.banner); assertTrue(r.starttls); assertTrue("STARTTLS" in r.caps && "SIZE 52428800" in r.caps)
            assertNotNull(r.tls); assertFalse(r.tls!!.trusted); assertTrue(r.tls!!.hostnameOk); assertEquals(listOf("mx.example.com", "AUTH PLAIN LOGIN", "8BITMIME"), listOf("mx.example.com") + r.capsAfterTls)
            val t = text(run("srv_smtp", "h" to "127.0.0.1", "port" to "${s.port}", "mode" to "STARTTLS 시도"))
            assertTrue(t, t.contains("STARTTLS: 지원해요") && t.contains("자체 서명") && t.contains("암호화하기 전에도 로그인 방식(AUTH PLAIN LOGIN)") && t.contains("소프트웨어 이름·버전") && t.contains("50.0 MB") && t.contains("TLSv1"))
        }
        // STARTTLS 가 없으면 오류 표시
        smtpServer(starttls = false, authBeforeTls = false).use { s ->
            val r = run("srv_smtp", "h" to "127.0.0.1", "port" to "${s.port}", "mode" to "STARTTLS 시도"); assertTrue(r.hasError); assertTrue(text(r).contains("암호화할 수 없어요"))
        }
        // 처음부터 TLS(465 방식)
        smtpServer(implicitTls = true).use { s ->
            val t = text(run("srv_smtp", "h" to "127.0.0.1", "port" to "${s.port}", "mode" to "처음부터 TLS")); assertTrue(t, t.contains("처음부터 TLS(암호화) 연결") && t.contains("자체 서명"))
        }
        // SMTP 가 아닌 서버
        TestTcp { c -> w(c.getOutputStream(), "SSH-2.0-OpenSSH_8.9\r\n") }.use { s -> val r = run("srv_smtp", "h" to "127.0.0.1", "port" to "${s.port}"); assertTrue(r.hasError && text(r).contains("인사말이 아니에요")) }
        // 닫힌 포트
        val closed = java.net.ServerSocket(0, 1, LOOP).use { it.localPort }; assertTrue(run("srv_smtp", "h" to "127.0.0.1", "port" to "$closed").hasError)
    }

    @Test fun imap_pop3_ftp_probes() {
        TestTcp { c ->
            var ins: InputStream = c.getInputStream(); var out: OutputStream = c.getOutputStream(); var tls = false
            w(out, "* OK [CAPABILITY IMAP4rev1] Dovecot ready.\r\n")
            while (true) { val l = readLineRaw(ins) ?: break
                when {
                    l.endsWith("CAPABILITY") -> { val tag = l.substringBefore(' '); w(out, if (!tls) "* CAPABILITY IMAP4rev1 STARTTLS LOGINDISABLED AUTH=PLAIN\r\n$tag OK Capability completed.\r\n" else "* CAPABILITY IMAP4rev1 AUTH=PLAIN AUTH=LOGIN\r\n$tag OK Capability completed.\r\n") }
                    l.endsWith("STARTTLS") -> { w(out, "${l.substringBefore(' ')} OK Begin TLS negotiation now.\r\n"); val ssl = upgradeServerTls(c); ins = ssl.inputStream; out = ssl.outputStream; tls = true }
                    l.endsWith("LOGOUT") -> { w(out, "* BYE\r\n${l.substringBefore(' ')} OK Logout completed.\r\n"); break }
                } }
        }.use { s ->
            val r = Imap.probe("127.0.0.1", s.port, false, 5000); assertTrue(r.starttls); assertTrue("LOGINDISABLED" in r.caps); assertTrue("AUTH=LOGIN" in r.capsAfterTls); assertNotNull(r.tls)
            val t = text(run("srv_imap", "h" to "127.0.0.1", "port" to "${s.port}", "mode" to "STARTTLS 시도")); assertTrue(t, t.contains("STARTTLS: 지원해요") && t.contains("암호화 전에는 로그인을 막아 두었어요") && t.contains("AUTH=PLAIN"))
        }
        TestTcp { c ->
            var ins: InputStream = c.getInputStream(); var out: OutputStream = c.getOutputStream(); var tls = false
            w(out, "+OK POP3 server ready <1896.697170952@mx>\r\n")
            while (true) { val l = readLineRaw(ins) ?: break
                when (l.uppercase()) { "CAPA" -> w(out, if (!tls) "+OK Capability list follows\r\nUSER\r\nSTLS\r\nUIDL\r\n.\r\n" else "+OK\r\nUSER\r\nUIDL\r\n.\r\n"); "STLS" -> { w(out, "+OK Begin TLS negotiation\r\n"); val ssl = upgradeServerTls(c); ins = ssl.inputStream; out = ssl.outputStream; tls = true }; "QUIT" -> { w(out, "+OK bye\r\n"); break } } }
        }.use { s ->
            val r = Pop3.probe("127.0.0.1", s.port, false, 5000); assertTrue(r.starttls); assertTrue("STLS" in r.caps && "STLS" !in r.capsAfterTls); assertNotNull(r.tls)
            val t = text(run("srv_pop3", "h" to "127.0.0.1", "port" to "${s.port}", "mode" to "STLS 시도")); assertTrue(t, t.contains("STARTTLS: 지원해요") && t.contains("USER"))
        }
        TestTcp { c ->
            var ins: InputStream = c.getInputStream(); var out: OutputStream = c.getOutputStream(); var tls = false
            w(out, "220 ProFTPD 1.3.6 Server ready.\r\n")
            while (true) { val l = readLineRaw(ins) ?: break
                when {
                    l == "FEAT" -> w(out, "211-Features:\r\n AUTH TLS\r\n PBSZ\r\n UTF8\r\n211 End\r\n")
                    l == "AUTH TLS" -> { w(out, "234 AUTH TLS successful\r\n"); val ssl = upgradeServerTls(c); ins = ssl.inputStream; out = ssl.outputStream; tls = true }
                    l == "USER anonymous" -> w(out, if (tls) "331 Anonymous login ok, send your complete email address as your password\r\n" else "530 Login incorrect.\r\n")
                    l.startsWith("PASS") -> w(out, "230 Anonymous access granted, restrictions apply\r\n")
                    l == "QUIT" -> { w(out, "221 Goodbye.\r\n"); break }
                } }
        }.use { s ->
            val r = Ftp.probe("127.0.0.1", s.port, true, 5000); assertEquals("ProFTPD 1.3.6 Server ready.", r.banner); assertEquals(listOf("AUTH TLS", "PBSZ", "UTF8"), r.features); assertNotNull(r.tls); assertEquals(true, r.anonymous)
            val t = text(run("srv_ftp", "h" to "127.0.0.1", "port" to "${s.port}", "anon" to "익명 로그인 시험 (USER anonymous 한 번)")); assertTrue(t, t.contains("익명 로그인이 허용돼요") && t.contains("AUTH TLS") && t.contains("소프트웨어 이름·버전")); assertTrue(run("srv_ftp", "h" to "127.0.0.1", "port" to "${s.port}", "anon" to "익명 로그인 시험 (USER anonymous 한 번)").hasError)
            val none = Ftp.probe("127.0.0.1", s.port, false, 5000); assertNull(none.anonymous)
        }
        // 암호화 없는 FTP
        TestTcp { c -> val ins = c.getInputStream(); val out = c.getOutputStream(); w(out, "220 vsFTPd 3.0.3\r\n"); while (true) { val l = readLineRaw(ins) ?: break; if (l == "FEAT") w(out, "211-Features:\r\n UTF8\r\n211 End\r\n") else if (l == "QUIT") { w(out, "221 bye\r\n"); break } } }.use { s ->
            val r = run("srv_ftp", "h" to "127.0.0.1", "port" to "${s.port}"); assertTrue(r.hasError); assertTrue(text(r).contains("암호화(AUTH TLS)를 지원하지 않아요"))
        }
    }

    // ================================================================ SSH
    private val KEX = "000001ac0814000102030405060708090a0b0c0d0e0f00000048637572766532353531392d7368613235362c6469666669652d68656c6c6d616e2d67726f757031342d736861312c6469666669652d68656c6c6d616e2d67726f7570312d736861310000001b7373682d656432353531392c7373682d7273612c7373682d6473730000003c63686163686132302d706f6c7931333035406f70656e7373682e636f6d2c6165733132382d6374722c6165733132382d6362632c336465732d6362630000003c63686163686132302d706f6c7931333035406f70656e7373682e636f6d2c6165733132382d6374722c6165733132382d6362632c336465732d63626300000030686d61632d736861322d3235362d65746d406f70656e7373682e636f6d2c686d61632d736861312c686d61632d6d643500000030686d61632d736861322d3235362d65746d406f70656e7373682e636f6d2c686d61632d736861312c686d61632d6d6435000000156e6f6e652c7a6c6962406f70656e7373682e636f6d000000156e6f6e652c7a6c6962406f70656e7373682e636f6d000000000000000000000000000000000000000000"

    @Test fun ssh_parsesKexInitAndFlagsWeakAlgorithms() {
        val pkt = hex(KEX); val len = java.nio.ByteBuffer.wrap(pkt).int; val pad = pkt[4].toInt() and 0xFF
        val k = Ssh.parseKexInit(pkt.copyOfRange(5, 5 + len - 1 - pad))!!
        assertEquals(listOf("curve25519-sha256", "diffie-hellman-group14-sha1", "diffie-hellman-group1-sha1"), k.kex); assertEquals(listOf("ssh-ed25519", "ssh-rsa", "ssh-dss"), k.hostKeys)
        assertEquals(listOf("chacha20-poly1305@openssh.com", "aes128-ctr", "aes128-cbc", "3des-cbc"), k.ciphers); assertEquals(listOf("hmac-sha2-256-etm@openssh.com", "hmac-sha1", "hmac-md5"), k.macs); assertEquals(listOf("none", "zlib@openssh.com"), k.compression)
        val weak = Ssh.weaknesses(k).associate { it.first to it.third }
        assertEquals(2, weak["diffie-hellman-group1-sha1"]); assertEquals(1, weak["diffie-hellman-group14-sha1"]); assertEquals(2, weak["ssh-dss"]); assertEquals(1, weak["ssh-rsa"]); assertEquals(2, weak["3des-cbc"]); assertEquals(1, weak["aes128-cbc"]); assertEquals(1, weak["hmac-sha1"]); assertEquals(2, weak["hmac-md5"])
        assertFalse("curve25519-sha256" in weak || "aes128-ctr" in weak || "chacha20-poly1305@openssh.com" in weak)
        assertNull(Ssh.parseKexInit(ByteArray(10))); assertNull(Ssh.parseKexInit(pkt.copyOfRange(5, 40)))
    }

    @Test fun sshTool_endToEnd() {
        val seen = java.util.concurrent.CopyOnWriteArrayList<String>()
        TestTcp { c -> val out = c.getOutputStream(); w(out, "Welcome\r\nSSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.1\r\n"); seen += readLineRaw(c.getInputStream()) ?: ""; out.write(hex(KEX)); out.flush(); Thread.sleep(200) }.use { s ->
            val r = run("srv_ssh", "h" to "127.0.0.1", "port" to "${s.port}"); val t = text(r)
            assertTrue(t, t.contains("SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.1") && t.contains("낡거나 약한 알고리즘 8개") && t.contains("diffie-hellman-group1-sha1") && t.contains("1024비트 DH") && t.contains("curve25519-sha256") && t.contains("소프트웨어 이름·버전"))
            assertTrue(r.hasError); assertEquals("SSH-2.0-SelfCheck_1.0", seen.first())
        }
        TestTcp { c -> w(c.getOutputStream(), "HTTP/1.1 400 Bad Request\r\n\r\n") }.use { s -> assertTrue(text(run("srv_ssh", "h" to "127.0.0.1", "port" to "${s.port}")).contains("인사말(SSH-2.0-…)을 받지 못했어요")) }
    }

    // ================================================================ MQTT · RTSP · SIP
    @Test fun mqtt_packetAndTool() {
        assertEquals("101e00044d5154540402000a001273656c66636865636b2d6162636431323334", Mqtt.connectPacket("selfcheck-abcd1234").hx())
        assertEquals("00", Mqtt.remainingLength(0).hx()); assertEquals("7f", Mqtt.remainingLength(127).hx()); assertEquals("8001", Mqtt.remainingLength(128).hx()); assertEquals("ffff7f", Mqtt.remainingLength(2097151).hx())
        assertEquals(5, Mqtt.parseConnack(hex("20020005"))); assertNull(Mqtt.parseConnack(hex("30020000")))
        for ((rc, expect, bad) in listOf(Triple(0, "인증 없이 접속이 허용돼요", true), Triple(5, "접속 권한이 없어요", false), Triple(4, "사용자 이름·암호가 필요해요", false))) {
            val got = java.util.concurrent.CopyOnWriteArrayList<ByteArray>()
            TestTcp { c -> val ins = c.getInputStream(); val first = ByteArray(40); val n = ins.read(first); got += first.copyOf(n); c.getOutputStream().write(byteArrayOf(0x20, 2, 0, rc.toByte())); c.getOutputStream().flush(); Thread.sleep(100) }.use { s ->
                val r = run("srv_mqtt", "h" to "127.0.0.1", "port" to "${s.port}"); val t = text(r)
                assertTrue(t, t.contains(expect)); assertEquals("MQTT 접속 요청은 CONNECT(0x10)", 0x10, got.first()[0].toInt()); assertEquals(bad, t.contains("위험해요"))
            }
        }
        TestTcp { c -> c.getOutputStream().write("HTTP/1.1".toByteArray()) }.use { s -> assertTrue(run("srv_mqtt", "h" to "127.0.0.1", "port" to "${s.port}").hasError) }
    }

    @Test fun rtsp_tool_andLocalOnly() {
        fun cam(describe: String) = TestTcp { c ->
            val ins = c.getInputStream(); val out = c.getOutputStream()
            repeat(2) { val sb = StringBuilder(); var last4 = ""; while (!last4.endsWith("\r\n\r\n")) { val b = ins.read(); if (b < 0) return@TestTcp; sb.append(b.toChar()); last4 = sb.takeLast(4).toString() }
                if (sb.startsWith("OPTIONS")) w(out, "RTSP/1.0 200 OK\r\nCSeq: 1\r\nPublic: OPTIONS, DESCRIBE, SETUP, PLAY, TEARDOWN\r\nServer: Hikvision-Webs\r\n\r\n") else w(out, describe) }
        }
        cam("RTSP/1.0 200 OK\r\nCSeq: 2\r\nContent-Type: application/sdp\r\nContent-Length: 0\r\n\r\n").use { s ->
            val r = run("srv_rtsp", "h" to "127.0.0.1", "port" to "${s.port}"); val t = text(r); assertTrue(t, t.contains("Hikvision-Webs") && t.contains("OPTIONS, DESCRIBE") && t.contains("인증 없이 영상 정보(SDP)를 줘요")); assertTrue(r.hasError)
        }
        cam("RTSP/1.0 401 Unauthorized\r\nCSeq: 2\r\nWWW-Authenticate: Digest realm=\"cam\"\r\n\r\n").use { s -> val r = run("srv_rtsp", "h" to "127.0.0.1", "port" to "${s.port}"); assertFalse(r.hasError); assertTrue(text(r).contains("인증을 요구해요")) }
        cam("RTSP/1.0 404 Not Found\r\nCSeq: 2\r\n\r\n").use { s -> assertTrue(text(run("srv_rtsp", "h" to "127.0.0.1", "port" to "${s.port}")).contains("기본 경로(/)에는 영상이 없어요")) }
        assertEquals(401, Rtsp.parse("RTSP/1.0 401 Unauthorized\r\nCSeq: 2\r\nServer: X\r\n\r\n")!!.status); assertNull(Rtsp.parse("HTTP/1.1 200 OK"))
        assertTrue(text(run("srv_rtsp", "h" to "8.8.8.8")).contains("내 망 안")); assertTrue(run("srv_rtsp", "h" to "8.8.8.8").hasError)           // 내 망 밖은 거절
    }

    @Test fun sip_options() {
        TestUdp { p, sock ->
            val req = String(p.data, 0, p.length); val callId = Regex("Call-ID: (.+)\r").find(req)!!.groupValues[1]
            assertTrue(req.startsWith("OPTIONS sip:127.0.0.1 SIP/2.0\r\n") && req.contains("CSeq: 1 OPTIONS") && req.contains("Max-Forwards: 70") && req.contains("Content-Length: 0"))
            val resp = "SIP/2.0 200 OK\r\nVia: x\r\nCall-ID: $callId\r\nCSeq: 1 OPTIONS\r\nServer: Asterisk PBX 18.2.0\r\nAllow: INVITE, ACK, CANCEL, OPTIONS, BYE\r\nSupported: replaces, timer\r\nContent-Length: 0\r\n\r\n".toByteArray()
            sock.send(DatagramPacket(resp, resp.size, p.socketAddress))
        }.use { s ->
            val r = run("srv_sip", "h" to "127.0.0.1", "port" to "${s.port}"); val t = text(r); assertTrue(t, t.contains("200 OK") && t.contains("Asterisk PBX 18.2.0") && t.contains("INVITE, ACK, CANCEL") && t.contains("소프트웨어 이름·버전")); assertFalse(r.hasError)
        }
        // 다른 Call-ID 의 응답은 무시하고 시간 초과
        TestUdp { p, sock -> val resp = "SIP/2.0 200 OK\r\nCall-ID: someone-else@x\r\n\r\n".toByteArray(); sock.send(DatagramPacket(resp, resp.size, p.socketAddress)) }.use { s -> assertTrue(run("srv_sip", "h" to "127.0.0.1", "port" to "${s.port}").hasError) }
        assertNull(Sip.parse("HTTP/1.1 200 OK")); assertEquals("SIP/2.0 401 Unauthorized", Sip.parse("SIP/2.0 401 Unauthorized\r\nServer: x\r\n\r\n")!!.first)
    }

    // ================================================================ WebSocket
    @Test fun websocket_vectorsAndEndToEnd() {
        assertEquals("s3pPLMBiTxaQ9kYGzzhZRbK+xOo=", WebSocketProbe.acceptFor("dGhlIHNhbXBsZSBub25jZQ=="))                                   // RFC 6455 4.2.2 예시
        assertEquals("818537fa213d7f9f4d5158", WebSocketProbe.maskedFrame(1, "Hello".toByteArray(), hex("37fa213d")).hx())                    // RFC 6455 5.7 예시
        assertEquals("8882" + "00000000" + "03e8", WebSocketProbe.maskedFrame(8, byteArrayOf(3, 0xE8.toByte()), ByteArray(4)).hx())
        assertEquals(1 to "Hello", WebSocketProbe.readFrame(java.io.ByteArrayInputStream(hex("810548656c6c6f")))!!.let { it.first to String(it.second) })
        TestTcp { c ->
            val ins = c.getInputStream(); val out = c.getOutputStream(); val hs = LinkedHashMap<String, String>(); val first = readLineRaw(ins)!!
            while (true) { val l = readLineRaw(ins) ?: break; if (l.isEmpty()) break; hs[l.substringBefore(':').lowercase()] = l.substringAfter(':').trim() }
            assertTrue(first.startsWith("GET /socket HTTP/1.1")); assertEquals("websocket", hs["upgrade"]); assertEquals("13", hs["sec-websocket-version"])
            val acc = Base64.getEncoder().encodeToString(MessageDigest.getInstance("SHA-1").digest((hs["sec-websocket-key"]!! + "258EAFA5-E914-47DA-95CA-C5AB0DC85B11").toByteArray()))
            w(out, "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: $acc\r\nSec-WebSocket-Protocol: chat\r\nServer: ws-test\r\n\r\n")
            val b0 = ins.read(); val b1 = ins.read(); val len = b1 and 0x7F; val mask = ByteArray(4).also { ins.read(it) }; val pl = ByteArray(len).also { ins.read(it) }
            for (k in pl.indices) pl[k] = (pl[k].toInt() xor mask[k % 4].toInt()).toByte()
            assertEquals(0x81, b0); assertTrue("클라이언트 프레임은 마스크", b1 and 0x80 != 0)
            out.write(byteArrayOf(0x81.toByte(), (pl.size + 6).toByte()) + "echo: ".toByteArray() + pl); out.flush(); Thread.sleep(100)
        }.use { s ->
            val r = run("srv_websocket", "u" to "ws://127.0.0.1:${s.port}/socket", "msg" to "안녕"); val t = text(r)
            assertTrue(t, t.contains("101 Switching Protocols") && t.contains("올바른 서버예요") && t.contains("받은 첫 메시지: echo: 안녕") && t.contains("chat") && t.contains("ws-test")); assertFalse(r.hasError)
        }
        // Accept 값이 틀린 서버
        TestTcp { c -> val ins = c.getInputStream(); while (true) { val l = readLineRaw(ins) ?: break; if (l.isEmpty()) break }; w(c.getOutputStream(), "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: AAAA\r\n\r\n"); Thread.sleep(200) }.use { s ->
            val r = run("srv_websocket", "u" to "ws://127.0.0.1:${s.port}/", "msg" to ""); assertTrue(r.hasError); assertTrue(text(r).contains("값이 맞지 않아요"))
        }
        TestTcp { c -> val ins = c.getInputStream(); while (true) { val l = readLineRaw(ins) ?: break; if (l.isEmpty()) break }; w(c.getOutputStream(), "HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n") }.use { s -> assertTrue(text(run("srv_websocket", "u" to "ws://127.0.0.1:${s.port}/", "msg" to "")).contains("업그레이드(101)가 아니에요")) }
        assertTrue(run("srv_websocket", "u" to "").text().contains("입력하세요"))
    }

    // ================================================================ 게임 서버
    @Test fun minecraft_packetsAndTool() {
        assertEquals("1500fd050e6d632e6578616d706c652e6e657463dd010100", Minecraft.request("mc.example.net", 25565, 765).hx())
        assertEquals("ac02", Minecraft.varInt(300).hx()); assertEquals(300, Minecraft.readVarInt(java.io.ByteArrayInputStream(hex("ac02")))); assertEquals(0, Minecraft.readVarInt(java.io.ByteArrayInputStream(hex("00"))))
        assertEquals("Welcome to Test", Minecraft.flatten(org.json.JSONObject("""{"text":"","extra":[{"text":"§aWelcome "},{"text":"to Test"}]}""")))
        assertEquals("두 줄", Minecraft.flatten("§l두 줄§r"))
        val st = Minecraft.parseStatus("""{"version":{"name":"1.20.4","protocol":765},"players":{"max":20,"online":3},"description":"A\nB"}"""); assertEquals(3, st.online); assertEquals(20, st.max); assertEquals("A / B", st.motd)
        val RESP = "d80100d5017b2276657273696f6e223a7b226e616d65223a22506170657220312e32302e34222c2270726f746f636f6c223a3736357d2c22706c6179657273223a7b226d6178223a35302c226f6e6c696e65223a372c2273616d706c65223a5b7b226e616d65223a225374657665222c226964223a2278227d5d7d2c226465736372697074696f6e223a7b2274657874223a22222c226578747261223a5b7b2274657874223a22c2a76157656c636f6d6520222c22636f6c6f72223a22677265656e227d2c7b2274657874223a22746f2054657374227d5d7d7d"
        val got = java.util.concurrent.CopyOnWriteArrayList<ByteArray>()
        TestTcp { c ->
            val ins = c.getInputStream(); val out = c.getOutputStream()
            fun readN(n: Int) = ByteArray(n).also { var o = 0; while (o < n) { val r = ins.read(it, o, n - o); if (r < 0) break; o += r } }
            val hsLen = ins.read(); val hs = readN(hsLen); val stLen = ins.read(); val st = readN(stLen); got += byteArrayOf(hsLen.toByte()) + hs + byteArrayOf(stLen.toByte()) + st
            out.write(hex(RESP)); out.flush()
            val pingLen = ins.read(); val ping = ByteArray(pingLen).also { var o = 0; while (o < pingLen) { val r = ins.read(it, o, pingLen - o); if (r < 0) break; o += r } }
            out.write(byteArrayOf(pingLen.toByte()) + ping); out.flush(); Thread.sleep(100)
        }.use { s ->
            val t = text(run("srv_minecraft", "h" to "127.0.0.1", "port" to "${s.port}")); assertTrue(t, t.contains("Paper 1.20.4 (프로토콜 765)") && t.contains("접속자: 7 / 50명") && t.contains("소개글(MOTD): Welcome to Test") && t.contains("응답 시간") && !t.contains("Steve"))
            assertTrue(got.first().hx().startsWith("10" + "00" + "fd05" + "09" + "3132372e302e302e31")); assertTrue(got.first().hx().endsWith("010100"))
        }
        TestTcp { c -> c.getOutputStream().write(byteArrayOf(0x03, 0x00, 0x01, 0x7B)) }.use { s -> assertTrue(run("srv_minecraft", "h" to "127.0.0.1", "port" to "${s.port}").hasError) }
    }

    @Test fun sourceQuery_packetsAndTool() {
        val INFO = hex("ffffffff491154657374205365727665720064655f6475737432006373676f00436f756e7465722d537472696b653a20476c6f62616c204f6666656e7369766500da020c2002646c0001312e33382e382e310000")
        val i = SourceQuery.parseInfo(INFO)!!
        assertEquals(17, i.protocol); assertEquals("Test Server", i.name); assertEquals("de_dust2", i.map); assertEquals("csgo", i.folder); assertEquals("Counter-Strike: Global Offensive", i.game); assertEquals(730, i.appId)
        assertEquals(12, i.players); assertEquals(32, i.max); assertEquals(2, i.bots); assertEquals('d', i.type); assertEquals('l', i.env); assertEquals(0, i.visibility); assertEquals(1, i.vac)
        assertEquals("ffffffff54536f7572636520456e67696e6520517565727900", SourceQuery.REQUEST.hx()); assertEquals("0badc0de", SourceQuery.challenge(hex("ffffffff410badc0de"))!!.hx()); assertNull(SourceQuery.challenge(INFO)); assertNull(SourceQuery.parseInfo(hex("ffffffff4911")))
        TestUdp { p, sock ->
            val req = p.data.copyOf(p.length)
            val resp = if (req.size == SourceQuery.REQUEST.size) hex("ffffffff410badc0de") else { assertEquals("0badc0de", req.copyOfRange(SourceQuery.REQUEST.size, req.size).hx()); INFO }
            sock.send(DatagramPacket(resp, resp.size, p.socketAddress))
        }.use { s ->
            val t = text(run("srv_source_query", "h" to "127.0.0.1", "port" to "${s.port}")); assertTrue(t, t.contains("이름: Test Server") && t.contains("맵: de_dust2") && t.contains("12 / 32명 (봇 2)") && t.contains("전용 서버") && t.contains("리눅스") && t.contains("VAC 보안: 켜짐") && t.contains("게임 번호(AppID): 730"))
            assertEquals(2, s.received.size)
        }
        TestUdp().use { s -> assertTrue(run("srv_source_query", "h" to "127.0.0.1", "port" to "${s.port}").hasError) }
    }

    // ================================================================ 보내기·읽기 도구
    @Test fun bannerTcpUdpTools() {
        TestTcp { c -> w(c.getOutputStream(), "SSH-2.0-test\r\n") }.use { s -> val t = text(run("srv_banner", "h" to "127.0.0.1", "port" to "${s.port}")); assertTrue(t, t.contains("SSH-2.0-test") && t.contains("53 53 48")) }
        TestTcp { _ -> Thread.sleep(300) }.use { s -> assertTrue(text(run("srv_banner", "h" to "127.0.0.1", "port" to "${s.port}")).contains("먼저 말하지 않는 서비스")) }
        val got = java.util.concurrent.CopyOnWriteArrayList<ByteArray>()
        TestTcp { c -> val buf = ByteArray(100); val n = c.getInputStream().read(buf); got += buf.copyOf(n); c.getOutputStream().write("HTTP/1.0 200 OK\r\n\r\nhi".toByteArray()); c.getOutputStream().flush() }.use { s ->
            val t = text(run("srv_tcp_send", "h" to "127.0.0.1", "port" to "${s.port}", "data" to "GET / HTTP/1.0\\r\\nHost: x\\r\\n\\r\\n")); assertTrue(t, t.contains("200 OK") && t.contains("hi") && t.contains("보낸 바이트: 27바이트"))
            assertEquals("GET / HTTP/1.0\r\nHost: x\r\n\r\n", String(got.first()))
        }
        val got2 = java.util.concurrent.CopyOnWriteArrayList<ByteArray>()
        TestTcp { c -> val buf = ByteArray(100); val n = c.getInputStream().read(buf); got2 += buf.copyOf(n) }.use { s -> run("srv_tcp_send", "h" to "127.0.0.1", "port" to "${s.port}", "mode" to "16진수", "data" to "48 54:54-50 0x0a"); Thread.sleep(300); assertEquals("HTTP\n", String(got2.first())) }
        assertTrue(run("srv_tcp_send", "h" to "127.0.0.1", "port" to "9", "mode" to "16진수", "data" to "zz").hasError); assertTrue(run("srv_tcp_send", "h" to "127.0.0.1", "port" to "9", "data" to "\\xZZ").hasError)
        assertTrue(run("srv_tcp_send", "h" to "127.0.0.1", "port" to "9", "data" to "a".repeat(5000)).hasError); assertTrue(run("srv_tcp_send", "h" to "224.0.0.1", "port" to "9", "data" to "x").hasError)
        assertEquals("a\r\n\u0000\\ÿ".toByteArray(Charsets.ISO_8859_1).hx().takeLast(6), (ServerTools.unescape("a\\r\\n\\0\\\\\\xff") ?: ByteArray(0)).hx().takeLast(6)); assertNull(ServerTools.unescape("\\x1")); assertEquals("4142", ServerTools.parseHex("0x41 42")!!.hx()); assertNull(ServerTools.parseHex("4"))
        TestUdp { p, sock -> val d = ("echo:" + String(p.data, 0, p.length)).toByteArray(); sock.send(DatagramPacket(d, d.size, p.socketAddress)) }.use { s ->
            val t = text(run("srv_udp_send", "h" to "127.0.0.1", "port" to "${s.port}", "data" to "ping")); assertTrue(t, t.contains("echo:ping") && t.contains("응답 시간") && t.contains("보낸 바이트: 4바이트"))
        }
        TestUdp().use { s -> assertTrue(text(run("srv_udp_send", "h" to "127.0.0.1", "port" to "${s.port}", "data" to "x", "wait" to "2초")).contains("답이 없어요")) }
    }

    @Test fun httpRequestTool() {
        TestHttp { req, out -> out.respond("200 OK", "Content-Type: application/json", "X-Echo: ${req.headers["x-test"]}", body = """{"method":"${req.method}","path":"${req.path}","body":"${req.bodyText.replace("\"", "'")}","len":"${req.headers["content-length"]}"}""".toByteArray()) }.use { s ->
            val r = run("srv_http_req", "u" to s.url("/api/x?y=1"), "m" to "POST", "hd" to "X-Test: 안녕\nAuthorization: Bearer abc", "body" to """{"a":1}""")
            val t = text(r); assertTrue(t, t.contains("POST http://127.0.0.1:${s.port}/api/x?y=1") && t.contains("200 OK") && t.contains("\"method\": \"POST\"") && t.contains("\"len\": \"7\"") && t.contains("{'a':1}") && t.contains("첫 응답까지(TTFB)") && t.contains("X-Echo"))
            val q = s.requests.last(); assertEquals("POST", q.method); assertEquals("Bearer abc", q.headers["authorization"]); assertEquals("""{"a":1}""", q.bodyText)
            run("srv_http_req", "u" to s.url("/"), "m" to "GET", "body" to "무시됨"); assertEquals("", s.requests.last().bodyText)                     // GET 에는 본문을 붙이지 않음
            assertTrue(ServerTools.prettyJson("""{"a":1}""")!!.contains("\"a\": 1")); assertNull(ServerTools.prettyJson("not json")); assertTrue(ServerTools.prettyJson("[1,2]")!!.startsWith("["))
        }
        assertTrue(run("srv_http_req", "u" to "").text().contains("입력하세요")); assertTrue(run("srv_http_req", "u" to "http://127.0.0.1:1/", "m" to "POST", "body" to "x".repeat(70000)).hasError)
    }

    // ================================================================ DNS · NTP · Syslog · Redis
    @Test fun dnsServerCheck() {
        TestDns({ n -> if (n == "cloudflare.com") 0x0020 else 0 }) { name, type ->
            when {
                type != DnsType.A -> 0 to emptyList()
                name == "example.com" -> 0 to listOf(DnsAns.A("93.184.216.34"))
                name == "cloudflare.com" -> 0 to listOf(DnsAns.A("104.16.132.229"))
                name == "dnssec-failed.org" -> 2 to emptyList()
                else -> 3 to emptyList()
            }
        }.use { dns ->
            val r = run("srv_dns_server", "server" to dns.server); val t = text(r)
            assertTrue(t, t.contains("UDP 질문") && t.contains("example.com → 93.184.216.34") && t.contains("검증함 (AD)") && t.contains("차단함 (SERVFAIL)") && t.contains("NXDOMAIN(정상)") && t.contains("재귀 조회(RA)") && t.contains("DNSSEC 검증도 해 줘요"))
            assertTrue("TCP 는 가짜 서버가 안 받음: $t", t.contains("TCP 질문") && t.contains("응답 없음")); assertFalse(r.hasError)
        }
        TestDns { name, type -> if (type == DnsType.A && name.startsWith("selfcheck-")) 0 to listOf(DnsAns.A("203.0.113.66")) else if (type == DnsType.A) 0 to listOf(DnsAns.A("93.184.216.34")) else 0 to emptyList() }.use { dns ->
            val r = run("srv_dns_server", "server" to dns.server); assertTrue(text(r), r.hasError && text(r).contains("가짜 IP 를 돌려줌") && text(r).contains("NXDOMAIN 가로채기"))
        }
        TestUdp().use { silent -> assertTrue(run("srv_dns_server", "server" to "127.0.0.1#${silent.port}").hasError) }
        assertTrue(run("srv_dns_server", "server" to "dns.google").hasError)
    }

    @Test fun ntpCompare() {
        TestNtp(2000.0).use { a -> TestNtp(2100.0).use { b -> TestNtp(-50.0).use { c ->
            val t = text(run("srv_ntp_compare", "s" to "127.0.0.1#${a.port}\n127.0.0.1#${b.port}\n127.0.0.1#${c.port}\n127.0.0.1#9")); assertTrue(t, t.contains("응답한 서버: 3 / 4") && t.contains("응답 없음") && t.contains("서버끼리 차이") && t.contains("시계가 많이 틀렸어요"))
            val m = Regex("서버끼리 차이: (\\d+) ms").find(t)!!.groupValues[1].toInt(); assertTrue("차이 $m", m in 2050..2300)
        } } }
        assertTrue(run("srv_ntp_compare", "s" to "127.0.0.1#9", "x" to "").hasError); assertTrue(text(run("srv_ntp_compare", "s" to "")).contains("입력하세요"))
    }

    @Test fun syslogAndRedis() {
        TestUdp().use { s ->
            val t = text(run("srv_syslog", "h" to "127.0.0.1", "port" to "${s.port}", "fac" to "user", "sev" to "info", "msg" to "시험 메시지", "app" to "my app")); val deadline = System.currentTimeMillis() + 2000
            while (s.received.isEmpty() && System.currentTimeMillis() < deadline) Thread.sleep(20)
            val line = String(s.received.single(), Charsets.UTF_8); assertTrue(line, Regex("""^<14>1 \d{4}-\d\d-\d\dT[\d:.]+[+-Z][\d:]* selfcheck-phone my_app - - - 시험 메시지$""").matches(line)); assertTrue(t, t.contains("<14> = user.info"))
            run("srv_syslog", "h" to "127.0.0.1", "port" to "${s.port}", "fac" to "local7", "sev" to "emerg", "msg" to "x"); Thread.sleep(200); assertTrue(String(s.received.last()).startsWith("<184>1 "))        // 23*8+0
        }
        assertEquals(14, Syslog.pri(1, 6)); assertEquals(24, Syslog.FACILITIES.size); assertEquals("<14>1 T h a - - - m", Syslog.message(14, "T", "h", "a", "m"))
        assertTrue(text(run("srv_syslog", "h" to "127.0.0.1", "msg" to "")).contains("입력하세요"))
        fun redis(reply: String) = TestTcp { c -> val ins = c.getInputStream(); val out = c.getOutputStream(); while (true) { val l = readLineRaw(ins) ?: break
            if (l == "PING") w(out, reply) else if (l == "INFO server") w(out, "$61\r\n# Server\r\nredis_version:7.0.5\r\nredis_mode:standalone\r\n\r\n") } }
        redis("+PONG\r\n").use { s ->
            // 포트는 종류에 따라 6379 로 고정이라 직접 엔진 흐름만 확인: ProbeConn 으로 같은 대화
            ProbeConn("127.0.0.1", s.port, 3000).use { c -> c.send("PING\r\n"); assertEquals("+PONG", c.line()) }
        }
        assertTrue(run("srv_redis", "h" to "8.8.8.8").hasError)                                        // 내 망 밖은 거절
        assertTrue(text(run("srv_redis", "h" to "127.0.0.1")).let { it.contains("접속하지 못했어요") || it.contains("첫 응답") })      // 6379 가 닫혀 있거나 열려 있거나: 어느 쪽이든 끝까지 실행됨
    }

    @Test fun registry_serverGroup() {
        val tools = NetToolbox.ALL.filter { it.group == NetGroups.SERVER }
        println("SERVER tools: ${tools.size}")
        assertTrue("서버·서비스 점검 도구 수 ${tools.size}", tools.size >= 19)
        for (t in tools) assertFalse("${t.id}: 무엇이 나가는지 안내", t.note.isNullOrBlank())
    }
}
