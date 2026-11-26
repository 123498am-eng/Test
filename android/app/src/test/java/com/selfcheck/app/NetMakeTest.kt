package com.selfcheck.app

import org.json.JSONArray
import org.json.JSONObject
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Assume.assumeTrue
import org.junit.Test
import java.io.File
import java.nio.file.Files
import java.time.LocalDateTime
import java.time.ZoneId
import java.time.ZonedDateTime
import java.time.format.DateTimeFormatter
import java.util.Base64
import java.util.concurrent.TimeUnit

/*
 * 만들기 도구 14가지 시험.
 * - cron: croniter(파이썬)가 계산한 다음 실행 시각 29가지와 대조, 그리고 systemd-analyze calendar 가 계산한 시각과도 대조
 * - ULA·WireGuard·WPA: 파이썬(hashlib·ipaddress·cryptography)이 따로 계산한 값, 그리고 실제 `wg pubkey` / `ssh-keygen` / `openssl`
 * - 설정 생성기(nftables·systemd·netplan·chrony·fail2ban·HAProxy·sshd·tc): 만든 설정을 실제 검증 도구(nft -c · systemd-analyze verify · netplan generate ·
 *   chronyd -p · fail2ban-client -t · haproxy -c · sshd -t · tc)에 넣어 통과하는지 확인. 도구가 없는 컴퓨터에서는 해당 시험을 건너뛰어요.
 *   (장비를 바꾸는 명령은 쓰지 않아요: 검사 모드만, tc 는 존재하지 않는 장치 이름으로 문법만.)
 */
class NetMakeTest {
    private val dir = "src/test/resources/netmake"
    private fun json(name: String) = JSONArray(File("$dir/$name").readText())
    private fun run(id: String, vararg kv: Pair<String, String>) = runNetTool(id, *kv)
    private fun obj(a: JSONArray, k: Int): JSONObject = a.getJSONObject(k)
    private val minute = DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm")

    // ------------------------------------------------------------ 바깥 도구 실행 도우미
    private class Proc(val code: Int, val text: String)
    private fun exec(cwd: File?, vararg cmd: String, stdin: String? = null, timeoutSec: Long = 90): Proc = try {
        val pb = ProcessBuilder(*cmd).redirectErrorStream(true); if (cwd != null) pb.directory(cwd); pb.environment()["LC_ALL"] = "C"; pb.environment()["TZ"] = "UTC"
        val p = pb.start(); if (stdin != null) p.outputStream.use { it.write(stdin.toByteArray()) } else p.outputStream.close()
        val buf = StringBuilder(); val reader = Thread { buf.append(String(p.inputStream.readBytes(), Charsets.UTF_8)) }.also { it.start() }
        if (!p.waitFor(timeoutSec, TimeUnit.SECONDS)) { p.destroyForcibly(); Proc(-1, "시간 초과") } else { reader.join(5000); Proc(p.exitValue(), buf.toString()) }
    } catch (e: Exception) { Proc(-2, "실행 못 함: ${e.message}") }
    private fun have(cmd: String) = exec(null, "sh", "-c", "command -v $cmd").code == 0
    private fun tmp(): File = Files.createTempDirectory("netmake").toFile().also { it.deleteOnExit() }
    private fun ToolResult.blockAfter(headPrefix: String): String {
        val k = outs.indexOfFirst { it is Out.Head && it.text.startsWith(headPrefix) }; if (k < 0) error("'$headPrefix' 제목이 없음:\n${text()}")
        return (outs.drop(k + 1).first { it is Out.Block } as Out.Block).text
    }
    private fun ToolResult.cronTimes(): List<String> = rows().filter { it.size == 4 && it[0].toIntOrNull() != null }.map { it[1] }
    /** 일부러 넣은 "잠길 수 있어요" 같은 위험 안내(빨간 안내)를 뺀 진짜 실패 */
    private fun failures(r: ToolResult) = r.notes().filter { it.level == 2 && !it.text.contains("비밀번호 로그인을 껐어요") && !it.text.contains("SSH 포트를 열지 않았어요") }
    private fun hexOf(b: ByteArray) = b.joinToString("") { "%02x".format(it.toInt() and 0xff) }

    // ============================================================ cron

    @Test fun cronNextRunsMatchCroniter() {
        val cases = json("cron_cases.json"); assertTrue(cases.length() >= 25)
        for (k in 0 until cases.length()) {
            val c = obj(cases, k); val zone = ZoneId.of(c.getString("tz")); val from = LocalDateTime.parse(c.getString("from").replace(' ', 'T')).atZone(zone)
            val runs = Cron.nextRuns(Cron.parse(c.getString("expr")), from, 12).map { it.format(minute) }
            val exp = (0 until 12).map { c.getJSONArray("runs").getString(it) }
            assertEquals("${c.getString("expr")} (${c.getString("tz")}, ${c.getString("from")})", exp, runs)
        }
    }

    @Test fun cronToolShowsTheSameTimes() {
        val r = run("make_cron", "e" to "30 4 1,15 * 5", "tz" to "UTC", "from" to "2024-01-01 00:00", "n" to "5")
        assertEquals(listOf("2024-01-01 04:30", "2024-01-05 04:30", "2024-01-12 04:30", "2024-01-15 04:30", "2024-01-19 04:30"), r.cronTimes())
        assertEquals("매월 1일·15일 또는 매주 금요일 04:30 실행", r.kv("뜻")); assertEquals("30 4 1,15 * 5", r.kv("정리한 식")); assertEquals("30 4 1,15 * 5 /경로/명령", r.kv("crontab 줄")); assertEquals(1, r.noteWith("둘 다 맞아야")!!.level)
        assertEquals(listOf("분", "시", "일", "월", "요일"), r.rows().take(5).map { it[0] }); assertEquals("30", r.row("분")[2]); assertEquals("1, 15", r.row("일")[2]); assertEquals("금", r.row("요일")[2])
        // 시간대·기준 시각·횟수
        val seoul = run("make_cron", "e" to "0 9 * * *", "tz" to "Asia/Seoul", "from" to "2024-03-01T09:00", "n" to "3"); assertEquals(listOf("2024-03-02 09:00", "2024-03-03 09:00", "2024-03-04 09:00"), seoul.cronTimes()); assertEquals("1일 0시간 뒤", seoul.rows().first { it[0] == "1" }[3])
        assertEquals(50, run("make_cron", "n" to "999", "from" to "2024-03-01").cronTimes().size); assertEquals(1, run("make_cron", "n" to "0", "from" to "2024-03-01").cronTimes().size); assertEquals(10, run("make_cron", "from" to "2024-03-01 00:00:30").cronTimes().size)
        assertEquals("5분 뒤", run("make_cron", "e" to "*/5 * * * *", "from" to "2024-03-01 00:00").rows().first { it[0] == "1" }[3])
        assertTrue(run("make_cron", "e" to "0 0 30 2 *", "from" to "2024-03-01").hasError); assertTrue(run("make_cron", "e" to "0 0 30 2 *", "from" to "2024-03-01").noteWith("100년")!!.level == 2)
        assertTrue(run("make_cron", "from" to "내일").hasError); assertTrue(run("make_cron", "e" to "").hasError); assertTrue(run("make_cron", "e" to "* * * *").hasError)
        assertEquals("0 0 * * *", run("make_cron", "e" to "@daily", "from" to "2024-03-01").kv("정리한 식"))
    }

    @Test fun cronParserAcceptsAndRejectsLikeCron() {
        // 별칭·이름·7=일요일·범위+간격
        assertEquals(Cron.parse("0 0 * * 0").dows, Cron.parse("0 0 * * 7").dows); assertEquals(listOf(0), Cron.parse("0 0 * * 7").dows); assertEquals(listOf(0, 5, 6), Cron.parse("0 0 * * fri-sun").dows); assertEquals(listOf(5, 6, 0).sorted(), Cron.parse("0 0 * * 5-7").dows)
        assertEquals(listOf(1, 4, 7, 10), Cron.parse("0 0 1 */3 *").months); assertEquals(listOf(3, 4, 5), Cron.parse("0 0 1 MAR-MAY *").months); assertEquals(listOf(0, 20, 40), Cron.parse("*/20 * * * *").minutes); assertEquals(listOf(5, 20, 35, 50), Cron.parse("5-59/15 * * * *").minutes)
        assertEquals(listOf(5, 20, 35, 50), Cron.parse("5/15 * * * *").minutes); assertEquals((1..31 step 2).toList(), Cron.parse("0 0 */2 * *").doms); assertEquals(listOf(1, 2, 3, 59), Cron.parse("1,2,3,59 * * * *").minutes); assertEquals(Cron.parse("@daily").fields, listOf("0", "0", "*", "*", "*"))
        for ((a, b) in listOf("@hourly" to "0 * * * *", "@midnight" to "0 0 * * *", "@annually" to "0 0 1 1 *", "@monthly" to "0 0 1 * *", "@weekly" to "0 0 * * 0", "@YEARLY" to "0 0 1 1 *")) assertEquals(Cron.parse(b).fields, Cron.parse(a).fields)
        assertEquals(" 0  0 *  * * ".trim().split(" ").filter { it.isNotEmpty() }, Cron.parse(" 0   0 *\t* * ").fields)
        // 일·요일 의미 (Vixie cron): 둘 다 정하면 OR, 한쪽이 * 로 시작하면 AND
        assertTrue(Cron.parse("30 4 1,15 * 5").orSemantics); assertFalse(Cron.parse("30 4 * * 5").orSemantics); assertFalse(Cron.parse("30 4 1 * *").orSemantics); assertFalse(Cron.parse("30 4 */2 * 5").orSemantics)
        // 거부: 안내가 한국어이고 이유가 들어 있음
        fun err(e: String) = try { Cron.parse(e); "" } catch (x: IllegalArgumentException) { x.message!! }
        assertTrue(err("").contains("입력하세요")); assertTrue(err("* * * *").contains("칸이 4개")); assertTrue(err("0 0 * * * *").contains("Quartz")); assertTrue(err("0 0 0 * * * 2024").contains("칸이 7개")); assertTrue(err("@reboot").contains("부팅"))
        assertTrue(err("60 * * * *").contains("분 칸의 값은 0~59")); assertTrue(err("* 24 * * *").contains("시 칸의 값은 0~23")); assertTrue(err("* * 0 * *").contains("일 칸의 값은 1~31")); assertTrue(err("* * * 13 *").contains("월 칸의 값은 1~12")); assertTrue(err("* * * * 8").contains("요일 칸의 값은 0~7"))
        assertTrue(err("*/0 * * * *").contains("1 이상")); assertTrue(err("*/x * * * *").contains("숫자가 아니에요")); assertTrue(err("a * * * *").contains("읽지 못했어요")); assertTrue(err("1,,2 * * * *").contains("빈 항목")); assertTrue(err("5-1 * * * *").contains("0~59"))
        assertTrue(err("0 0 L * *").contains("Quartz")); assertTrue(err("0 0 15W * *").contains("Quartz")); assertTrue(err("0 0 * * 5#2").contains("Quartz")); assertTrue(err("0 0 * * FRI#3").contains("Quartz")); assertTrue(err("* * * foo *").contains("읽지 못했어요"))
        assertEquals("", err("0 0 * jul wed")); assertEquals("", err("0 0 * JUL WED"))                                       // 이름은 대소문자 무관 (JUL·WED 의 L·W 는 Quartz 기호가 아님)
    }

    @Test fun cronDescriptionsAreReadableKorean() {
        val cases = mapOf("*/15 9-18 * * 1-5" to "평일(월~금) 9~18시 사이 15분마다 실행", "0 0 * * *" to "매일 00:00 실행", "30 4 1,15 * 5" to "매월 1일·15일 또는 매주 금요일 04:30 실행", "0 */6 * * *" to "매일 6시간마다 정각 실행", "5 4 * * sun" to "매주 일요일 04:05 실행",
            "0 12 1 jan,jul *" to "1월·7월에 매월 1일 12:00 실행", "*/5 * * * *" to "매일 5분마다 실행", "@hourly" to "매일 매시 정각 실행", "@weekly" to "매주 일요일 00:00 실행", "@monthly" to "매월 1일 00:00 실행", "@yearly" to "1월에 매월 1일 00:00 실행", "* * * * *" to "매일 매분 실행",
            "0 22 * * 1-5" to "평일(월~금) 22:00 실행", "0 0 1 */3 *" to "1월·4월·7월·10월에 매월 1일 00:00 실행", "0 9 * * 6,0" to "주말(토·일) 09:00 실행", "15,45 */2 * * *" to "매일 2시간마다 15분·45분 실행", "* 9-17 * * *" to "매일 9~17시 동안 매분 실행", "0 8 1-7 * 1" to "매월 1~7일 또는 매주 월요일 08:00 실행",
            "0 9 * * 1,3,5" to "매주 월·수·금요일 09:00 실행", "0 9,12,18 * * *" to "매일 9시·12시·18시 정각 실행", "0 0 15 * *" to "매월 15일 00:00 실행", "0 0 * * */2" to "매주 일·화·목·토요일 00:00 실행")
        for ((e, d) in cases) assertEquals(e, d, Cron.describe(Cron.parse(e)))
    }

    @Test fun cronOnCalendarTextAndCaveats() {
        val exp = mapOf("*/15 9-18 * * 1-5" to "Mon..Fri *-*-* 09..18:00,15,30,45:00", "0 0 * * *" to "*-*-* 00:00:00", "5 4 * * sun" to "Sun *-*-* 04:05:00", "0 12 1 jan,jul *" to "*-1,7-1 12:00:00", "0 9 * * 1,3,5" to "Mon,Wed,Fri *-*-* 09:00:00", "*/5 * * * *" to "*-*-* *:00,05,10,15,20,25,30,35,40,45,50,55:00",
            "0 0 1 */3 *" to "*-1,4,7,10-1 00:00:00", "0 9-12 * * *" to "*-*-* 09..12:00:00", "0 9 * * 6,0" to "Sun,Sat *-*-* 09:00:00", "59 23 31 * *" to "*-*-31 23:59:00")
        for ((e, o) in exp) assertEquals(e, o, Cron.onCalendar(Cron.parse(e)))
        assertEquals(1, Cron.caveats(Cron.parse("30 4 1,15 * 5")).size); assertTrue(Cron.caveats(Cron.parse("59 23 31 * *"))[0].contains("31일")); assertTrue(Cron.caveats(Cron.parse("0 0 29 2 *")).any { it.contains("윤년") }); assertTrue(Cron.caveats(Cron.parse("0 0 * * *")).isEmpty())
    }

    @Test fun cronOnCalendarAgreesWithSystemdAnalyze() {
        assumeTrue("systemd-analyze 없음", have("systemd-analyze")); val probe = exec(null, "systemd-analyze", "calendar", "--iterations=1", "--base-time=2024-03-01 00:00:00", "*-*-* 00:00:00"); assumeTrue("이 systemd 는 --base-time 을 몰라요", probe.code == 0)
        for (expr in listOf("*/15 9-18 * * 1-5", "0 0 * * *", "5 4 * * sun", "0 12 1 jan,jul *", "0 9 * * 1,3,5", "*/7 * * * *", "0 0 1 */3 *", "15,45 */2 * * *", "0 9-12 * * *", "0 9 * * 6,0", "59 23 31 * *", "0 0 29 2 *", "10 10 10 10 *", "*/5 0-6 * * *", "1,2,3,59 23 * * *", "0 3 * * mon-sat", "30 18 * * fri-sun", "0 0 1 mar-may *")) {
            val spec = Cron.parse(expr); val cal = Cron.onCalendar(spec)
            val r = exec(null, "systemd-analyze", "calendar", "--iterations=8", "--base-time=2024-03-01 09:30:00", cal); assertEquals("$expr → $cal\n${r.text}", 0, r.code)
            val sys = Regex("(?:Next elapse|Iteration #\\d+): \\w+ (\\d{4}-\\d{2}-\\d{2} \\d{2}:\\d{2}):00 UTC").findAll(r.text).map { it.groupValues[1] }.toList()
            val ours = Cron.nextRuns(spec, LocalDateTime.of(2024, 3, 1, 9, 30).atZone(ZoneId.of("UTC")), 8).map { it.format(minute) }
            assertEquals("$expr → $cal", ours, sys)
        }
        // 일·요일을 둘 다 정하면 cron(OR) 과 systemd(AND) 가 달라짐 — 도구가 경고하는 이유
        val spec = Cron.parse("0 0 13 * 5"); val sys = exec(null, "systemd-analyze", "calendar", "--iterations=4", "--base-time=2024-01-01 00:00:00", Cron.onCalendar(spec)).text
        val ours = Cron.nextRuns(spec, LocalDateTime.of(2024, 1, 1, 0, 0).atZone(ZoneId.of("UTC")), 4).map { it.format(minute) }; assertFalse(sys.contains(ours[0]) && sys.contains(ours[1]) && sys.contains(ours[2]))
    }

    // ============================================================ IPv6 ULA

    @Test fun ulaMatchesPythonReference() {
        val cases = json("ula_cases.json"); assertEquals(8, cases.length())
        for (k in 0 until cases.length()) {
            val c = obj(cases, k); val mac = Bx.parseMac(c.getString("mac"))!!; val eui = Ula.eui64(mac); assertEquals(c.getString("eui64"), hexOf(eui))
            val gid = Ula.globalId(c.getLong("ntp"), eui); assertEquals(c.getString("gid"), hexOf(gid)); assertEquals(c.getString("prefix"), Ula.prefix(gid))
            for ((j, n) in (0 until c.getJSONArray("subnet_ns").length()).map { c.getJSONArray("subnet_ns").getInt(it) }.withIndex()) assertEquals(c.getJSONArray("subnets").getString(j), Ula.subnet(gid, n))
            assertTrue(Ula.prefix(gid).startsWith("fd")); assertEquals(5, gid.size)
        }
        assertEquals((1700000000L + 2208988800L) shl 32, Ula.ntpTime(1700000000000L)); assertEquals(((1700000000L + 2208988800L) shl 32) or 0x80000000L, Ula.ntpTime(1700000000500L)); assertEquals(2208988800L shl 32, Ula.ntpTime(0))
        // RFC 4291 부록 A 의 EUI-64 예: 34:56:78:9A:BC:DE → 36:56:78:FF:FE:9A:BC:DE (첫 바이트의 U/L 비트 뒤집기 + 가운데 FF:FE)
        assertEquals("365678fffe9abcde", hexOf(Ula.eui64(Bx.parseMac("34:56:78:9A:BC:DE")!!))); assertEquals("02005efffe005301", hexOf(Ula.eui64(Bx.parseMac("00:00:5e:00:53:01")!!))); assertEquals("fdfffffffeffffff", hexOf(Ula.eui64(Bx.parseMac("ff:ff:ff:ff:ff:ff")!!)))
    }

    @Test fun toolIpv6UlaGeneratesValidPrefixes() {
        val r = run("make_ipv6_ula", "mac" to "52:54:00:12:34:56"); val prefix = r.kv("ULA 접두사 (/48)"); assertTrue(prefix, Regex("^fd[0-9a-f]{2}:[0-9a-f]{1,4}:[0-9a-f]{1,4}::/48$").matches(prefix))
        assertEquals(10, r.kv("전역 ID (40비트)").length); assertTrue(r.kv("방식"), r.kv("방식").contains("SHA-1") && r.kv("방식").contains("50:54:00:ff:fe:12:34:56"))
        assertEquals(prefix, Ula.prefix(r.kv("전역 ID (40비트)").chunked(2).map { it.toInt(16).toByte() }.toByteArray())); val subs = r.rows().filter { it.size == 2 && it[0].toIntOrNull() != null }; assertEquals(16, subs.size); assertEquals(prefix.removeSuffix("/48") + "/64", subs[0][1]); assertTrue(subs[10][1].endsWith(":a::/64")); assertTrue(subs.all { it[1].startsWith(prefix.removeSuffix("::/48")) })
        // 시각이 들어가므로 매번 다름 (무작위 MAC) / 무작위 모드 / 잘못된 MAC
        assertNotEquals(run("make_ipv6_ula").kv("ULA 접두사 (/48)"), run("make_ipv6_ula").kv("ULA 접두사 (/48)")); val rnd = run("make_ipv6_ula", "m" to "무작위 40비트"); assertEquals("무작위 40비트", rnd.kv("방식")); assertTrue(rnd.kv("ULA 접두사 (/48)").startsWith("fd"))
        assertTrue(run("make_ipv6_ula", "mac" to "zz:zz").hasError); assertTrue(run("make_ipv6_ula", "mac" to "52:54:00:12:34").hasError)
        // 만들어진 접두사는 올바른 IPv6 ULA 대역으로 분류돼야 함
        assertEquals(IpKind.PRIVATE, IpUtil.classify(IpUtil.parse(prefix.removeSuffix("/48") + "1")!!))
    }

    // ============================================================ tc

    @Test fun tcRateParsingAndTbfMath() {
        assertEquals(10_000_000L, TcCmd.parseRate("10mbit")); assertEquals(10_000_000L, TcCmd.parseRate("10")); assertEquals(10_000_000L, TcCmd.parseRate("10 Mbps")); assertEquals(512_000L, TcCmd.parseRate("512kbit")); assertEquals(1_000_000_000L, TcCmd.parseRate("1gbit")); assertEquals(1_500_000L, TcCmd.parseRate("1.5m")); assertEquals(100_000_000_000L, TcCmd.parseRate("100G"))
        assertEquals(999_000_000L, TcCmd.parseRate("999"))                                                  // 단위를 안 쓰면 Mbit
        for (bad in listOf("", "abc", "10x", "-5mbit", "0", "200gbit", "10kb", "1,5mbit", "mbit", "999g")) assertNull(bad, TcCmd.parseRate(bad))
        assertEquals("10mbit", TcCmd.rateText(10_000_000)); assertEquals("512kbit", TcCmd.rateText(512_000)); assertEquals("1gbit", TcCmd.rateText(1_000_000_000)); assertEquals("1500kbit", TcCmd.rateText(1_500_000)); assertEquals("1234567bit", TcCmd.rateText(1_234_567))
        // 손으로 계산한 값: burst = max(2×rate/8/250, 3028) 를 KB 로 올림
        assertEquals(10240L, TcCmd.tbfBurstBytes(10_000_000)); assertEquals(3072L, TcCmd.tbfBurstBytes(1_000_000)); assertEquals(100352L, TcCmd.tbfBurstBytes(100_000_000)); assertEquals(1_000_448L, TcCmd.tbfBurstBytes(1_000_000_000)); assertEquals(3072L, TcCmd.tbfBurstBytes(56_000))
        assertEquals(1250000L * 50 / 1000 + 10240, TcCmd.tbfLimitBytes(10_000_000, 50, 10240)); assertEquals(72740L, TcCmd.tbfLimitBytes(10_000_000, 50, 10240))
        assertEquals("tc qdisc add dev eth0 root netem delay 100ms 20ms distribution normal loss 1% duplicate 0.5% corrupt 0.1% reorder 10% 50% rate 10mbit", TcCmd.netem("eth0", TcCmd.Netem(100.0, 20.0, "normal", 1.0, 0.5, 0.1, 10.0, 10_000_000)))
        assertEquals("tc qdisc add dev eth0 root netem loss 5%", TcCmd.netem("eth0", TcCmd.Netem(0.0, 0.0, "normal", 5.0, 0.0, 0.0, 0.0, 0))); assertEquals("tc qdisc add dev eth0 root handle 1: netem delay 80ms", TcCmd.netem("eth0", TcCmd.Netem(80.0, 0.0, "", 0.0, 0.0, 0.0, 0.0, 0), handle = "1:"))
        assertEquals("tc qdisc add dev eth0 parent 1:1 handle 10: tbf rate 10mbit burst 10kb latency 50ms", TcCmd.tbf("eth0", 10_000_000, 50, parent = "parent 1:1", handle = "10:")); assertEquals("0.25", TcCmd.num(0.25)); assertEquals("100", TcCmd.num(100.0)); assertEquals("0.001", TcCmd.num(0.0010))
    }

    @Test fun toolTcNetemOutput() {
        val r = run("make_tc_netem"); val one = r.blockAfter("적용 (한 줄")
        assertEquals("sudo tc qdisc add dev eth0 root netem delay 100ms 20ms distribution normal loss 1% rate 10mbit", one)
        assertEquals("10kb (10240 바이트)", r.kv("tbf burst")); assertEquals("72740 바이트 (속도 × 50ms + burst)", r.kv("tbf limit(큐 길이)")); assertTrue(r.blockAfter("속도 제한을 tbf").contains("handle 1: netem delay 100ms 20ms distribution normal loss 1%\nsudo tc qdisc add dev eth0 parent 1:1 handle 10: tbf rate 10mbit burst 10kb latency 50ms"))
        assertEquals("sudo tc qdisc del dev eth0 root", r.blockAfter("원상복구")); assertTrue(r.blockAfter("확인").contains("tc -s qdisc show dev eth0")); assertTrue(r.blockAfter("들어오는 쪽").contains("sudo modprobe ifb numifbs=1") && r.blockAfter("들어오는 쪽").contains("sudo tc qdisc add dev ifb0 root netem delay 100ms"))
        assertEquals(1, r.noteWith("SSH")!!.level); assertTrue(run("make_tc_netem", "loss" to "20").noteWith("10%")!!.level == 1)
        val full = run("make_tc_netem", "dev" to "wlan0", "delay" to "30", "jitter" to "5", "dist" to "파레토(pareto)", "loss" to "0.5", "dup" to "1", "corrupt" to "0.1", "reorder" to "25", "rate" to "512kbit", "lat" to "200")
        assertEquals("sudo tc qdisc add dev wlan0 root netem delay 30ms 5ms distribution pareto loss 0.5% duplicate 1% corrupt 0.1% reorder 25% 50% rate 512kbit", full.blockAfter("적용 (한 줄")); assertEquals("3kb (3072 바이트)", full.kv("tbf burst")); assertEquals("${64000L * 200 / 1000 + 3072} 바이트 (속도 × 200ms + burst)", full.kv("tbf limit(큐 길이)"))
        assertFalse(run("make_tc_netem", "rate" to "", "delay" to "10", "loss" to "0").hasKv("tbf burst")); assertEquals("sudo tc qdisc add dev eth0 root netem delay 10ms", run("make_tc_netem", "rate" to "", "delay" to "10", "jitter" to "0", "loss" to "0").blockAfter("적용 (한 줄"))
        // 입력 확인
        assertEquals(1, run("make_tc_netem", "delay" to "0", "jitter" to "0", "loss" to "0", "rate" to "").notes().single().level); for (bad in listOf("dev" to "eth0;rm", "delay" to "-5", "delay" to "abc", "loss" to "101", "loss" to "-1", "dup" to "x", "rate" to "fast", "lat" to "0", "jitter" to "10000000")) assertTrue(bad.toString(), run("make_tc_netem", bad).hasError)
        assertTrue(run("make_tc_netem", "delay" to "0", "jitter" to "5").hasError); assertTrue(run("make_tc_netem", "delay" to "0", "jitter" to "0", "reorder" to "10").noteWith("지연이 있어야")!!.level == 2)
    }

    @Test fun tcCommandsParseWithTheRealTcAgainstAMissingDevice() {
        assumeTrue("tc 없음", have("tc")); assumeTrue("nodev0 이름의 장치가 실제로 있어서 건너뜀", exec(null, "ip", "link", "show", "nodev0").code != 0)
        fun check(cmd: String, ok: Boolean) {
            val r = exec(null, "sh", "-c", cmd.removePrefix("sudo ") + " 2>&1")
            if (ok) { assertTrue("tc 가 문법을 받아들여야 해요(장치가 없다는 오류만 나와야 함): $cmd\n${r.text}", r.text.contains("Cannot find device")); assertFalse(r.text, r.text.contains("Illegal") || r.text.contains("mandatory") || r.text.contains("required") || r.text.contains("Usage")) }
            else assertTrue("틀린 명령은 tc 가 문법 오류로 거부해야 해요: $cmd\n${r.text}", r.text.contains("Illegal") || r.text.contains("mandatory") || r.text.contains("required") || r.text.contains("Usage") || r.text.contains("What") || r.text.contains("not complete"))
        }
        val inputs = listOf(listOf("delay" to "100", "jitter" to "20", "loss" to "1", "rate" to "10mbit"), listOf("delay" to "30", "jitter" to "5", "dist" to "파레토(pareto)", "loss" to "0.5", "dup" to "1", "corrupt" to "0.1", "reorder" to "25", "rate" to "512kbit"), listOf("delay" to "0", "jitter" to "0", "loss" to "5", "rate" to ""),
            listOf("delay" to "250", "jitter" to "0", "loss" to "0", "rate" to "1gbit", "dist" to "균등(uniform)"), listOf("delay" to "10", "jitter" to "2", "loss" to "0", "rate" to "100kbit", "lat" to "500"), listOf("delay" to "0", "jitter" to "0", "loss" to "0", "dup" to "3", "rate" to ""), listOf("delay" to "0", "jitter" to "0", "loss" to "0", "corrupt" to "0.05", "rate" to "2.5mbit"))
        var checked = 0
        for (inp in inputs) {
            val r = run("make_tc_netem", "dev" to "nodev0", *inp.toTypedArray())
            for (o in r.outs.filterIsInstance<Out.Block>()) for (line in o.text.lines().filter { (it.contains("tc qdisc add") || it.contains("tc filter add")) && it.contains(" dev nodev0 ") }) { check(line.trim(), true); checked++ }          // 없는 장치(nodev0)에 대한 줄만 실행: 실제 장치는 건드리지 않음
        }
        assertTrue("검사한 tc 명령 수 $checked", checked >= 20)
        // 시험 장치가 제대로 동작하는지: 일부러 틀린 명령은 거부돼야 함
        check("tc qdisc add dev nodev0 root netem delay abc", false); check("tc qdisc add dev nodev0 root tbf rate 10mbit", false); check("tc qdisc add dev nodev0 root netem loss 1% rate", false)
    }

    // ============================================================ WireGuard · SSH 키

    @Test fun wireGuardPublicKeysMatchCryptographyLibrary() {
        val cases = json("wg_cases.json"); assertEquals(8, cases.length())
        for (k in 0 until cases.length()) { val c = obj(cases, k); assertEquals(c.getString("pub"), run("make_wg_keys", "m" to "비밀키로 공개키 계산", "priv" to c.getString("priv")).kv("공개키")); assertEquals(c.getString("pub"), Base64.getEncoder().encodeToString(X25519.publicKey(Base64.getDecoder().decode(c.getString("priv"))))) }
        assertTrue(run("make_wg_keys", "m" to "비밀키로 공개키 계산", "priv" to "short").hasError); assertTrue(run("make_wg_keys", "m" to "비밀키로 공개키 계산", "priv" to "!!!").hasError); assertTrue(run("make_wg_keys", "m" to "비밀키로 공개키 계산", "priv" to Base64.getEncoder().encodeToString(ByteArray(31))).hasError); assertTrue(run("make_wg_keys", "m" to "비밀키로 공개키 계산", "priv" to "").hasError)
    }

    @Test fun wireGuardGeneratedKeysAndConfigs() {
        val r = run("make_wg_keys"); fun key(label: String) = Base64.getDecoder().decode(r.kv(label)).also { assertEquals(label, 32, it.size) }
        val sp = key("서버 비밀키"); val cp = key("클라이언트 비밀키"); val sPub = key("서버 공개키"); val cPub = key("클라이언트 공개키"); val psk = key("사전 공유키(PSK)")
        for (p in listOf(sp, cp)) { assertEquals(0, p[0].toInt() and 7); assertEquals(0, p[31].toInt() and 0x80); assertEquals(0x40, p[31].toInt() and 0x40) }                 // 비트 정리가 된 개인키 (wg genkey 와 같은 모양)
        assertEquals(hexOf(X25519.publicKey(sp)), hexOf(sPub)); assertEquals(hexOf(X25519.publicKey(cp)), hexOf(cPub)); assertNotEquals(hexOf(sp), hexOf(cp)); assertEquals(44, r.kv("서버 공개키").length); assertTrue(r.kv("서버 공개키").endsWith("="))
        val server = r.blockAfter("서버 설정"); val client = r.blockAfter("클라이언트 설정")
        assertEquals("[Interface]\nAddress = 10.8.0.1/24\nListenPort = 51820\nPrivateKey = ${r.kv("서버 비밀키")}\n\n[Peer]\nPublicKey = ${r.kv("클라이언트 공개키")}\nPresharedKey = ${r.kv("사전 공유키(PSK)")}\nAllowedIPs = 10.8.0.2/32\n", server)
        assertEquals("[Interface]\nAddress = 10.8.0.2/32\nPrivateKey = ${r.kv("클라이언트 비밀키")}\nDNS = 1.1.1.1\n\n[Peer]\nPublicKey = ${r.kv("서버 공개키")}\nPresharedKey = ${r.kv("사전 공유키(PSK)")}\nEndpoint = vpn.example.com:51820\nAllowedIPs = 10.8.0.0/24\nPersistentKeepalive = 25\n", client)
        assertEquals(1, r.kvLevel("서버 비밀키")); assertEquals(0, r.kvLevel("서버 공개키")); assertTrue(r.noteWith("만든 사람만")!!.level == 1); assertTrue(r.noteWith("51820번 UDP")!!.text.contains("10.8.0.3"))
        // 선택에 따른 변화: 전부 보내기·PSK 없음·NAT·다른 대역·IPv6 엔드포인트·DNS 여러 개
        val full = run("make_wg_keys", "route" to "전부 (인터넷 포함)", "psk" to "사용 안 함", "nat" to "eth0", "net" to "192.168.77.0/28", "endpoint" to "[2001:db8::5]:443", "dns" to "9.9.9.9, 149.112.112.112")
        assertFalse(full.hasKv("사전 공유키(PSK)")); val c = full.blockAfter("클라이언트 설정"); assertTrue(c.contains("Address = 192.168.77.2/32") && c.contains("AllowedIPs = 0.0.0.0/0, ::/0") && c.contains("Endpoint = [2001:db8::5]:443") && c.contains("DNS = 9.9.9.9, 149.112.112.112") && !c.contains("PresharedKey"))
        val s = full.blockAfter("서버 설정"); assertTrue(s.contains("Address = 192.168.77.1/28") && s.contains("ListenPort = 443") && s.contains("PostUp = sysctl -w net.ipv4.ip_forward=1; iptables -A FORWARD -i %i -j ACCEPT; iptables -t nat -A POSTROUTING -o eth0 -j MASQUERADE") && s.contains("PostDown = ") && !s.contains("PresharedKey"))
        assertNotEquals(r.kv("서버 비밀키"), run("make_wg_keys").kv("서버 비밀키")); assertTrue(run("make_wg_keys", "m" to "사전 공유키(PSK)만 만들기").kv("사전 공유키(PSK)").let { Base64.getDecoder().decode(it).size == 32 })
        for (bad in listOf("endpoint" to "vpn.example.com", "endpoint" to "vpn.example.com:99999", "endpoint" to "[::1]", "net" to "10.8.0.0", "net" to "10.8.0.0/31", "net" to "10.8.0.0/33", "dns" to "dns.example.com", "nat" to "eth0;x")) assertTrue(bad.toString(), run("make_wg_keys", bad).hasError)
    }

    @Test fun wireGuardKeysAgreeWithRealWgTool() {
        assumeTrue("wg 없음", have("wg")); val r = run("make_wg_keys")
        for ((priv, pub) in listOf("서버 비밀키" to "서버 공개키", "클라이언트 비밀키" to "클라이언트 공개키")) assertEquals(r.kv(pub), exec(null, "wg", "pubkey", stdin = r.kv(priv) + "\n").text.trim())
        val cases = json("wg_cases.json"); for (k in 0 until cases.length()) assertEquals(obj(cases, k).getString("pub"), exec(null, "wg", "pubkey", stdin = obj(cases, k).getString("priv") + "\n").text.trim())
        if (have("wg-quick")) { val dir = tmp(); val conf = File(dir, "wg-test.conf").also { it.writeText(r.blockAfter("서버 설정")) }; val parsed = exec(dir, "wg-quick", "strip", conf.absolutePath); assertEquals(parsed.text, 0, parsed.code); assertTrue(parsed.text, parsed.text.contains("[Peer]") && parsed.text.contains("PublicKey = ${r.kv("클라이언트 공개키")}")) }
    }

    @Test fun sshKeyToolAndRealSshKeygen() {
        val r = run("make_ssh_key", "c" to "test@phone"); val line = r.kv("공개키 (한 줄)"); val info = SshKey.parse(line)
        assertEquals("ssh-ed25519", info.type); assertEquals("test@phone", info.comment); assertEquals(info.sha256, r.kv("지문(SHA256)")); assertEquals("Ed25519 (256비트)", r.kv("종류")); assertTrue(line.startsWith("ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAA"))
        val pem = r.blockAfter("개인키 파일 내용"); assertTrue(pem.startsWith("-----BEGIN OPENSSH PRIVATE KEY-----\n") && pem.trimEnd().endsWith("-----END OPENSSH PRIVATE KEY-----")); assertTrue(r.blockAfter("서버에 등록하기").contains("echo '$line' >> ~/.ssh/authorized_keys")); assertEquals(1, r.noteWith("암호(passphrase)")!!.level)
        assertNotEquals(line, run("make_ssh_key", "c" to "test@phone").kv("공개키 (한 줄)")); assertEquals("ssh-ed25519", run("make_ssh_key", "c" to "").kv("공개키 (한 줄)").split(" ")[0]); assertEquals(2, run("make_ssh_key", "c" to "").kv("공개키 (한 줄)").split(" ").size)
        assertTrue(run("make_ssh_key", "c" to "a".repeat(81)).hasError); assertTrue(run("make_ssh_key", "c" to "a\nb").hasError)
        // 실제 OpenSSH 가 우리 개인키 파일을 읽어서 같은 공개키·지문을 내야 함
        assumeTrue("ssh-keygen 없음", have("ssh-keygen")); val dir = tmp(); val key = File(dir, "id_ed25519").also { it.writeText(pem) }; exec(dir, "chmod", "600", key.absolutePath)
        val pub = exec(dir, "ssh-keygen", "-y", "-f", key.absolutePath); assertEquals(pub.text, 0, pub.code); assertEquals(line.split(" ").take(2), pub.text.trim().split(" ").take(2))
        val pubFile = File(dir, "id.pub").also { it.writeText(line + "\n") }; val fp = exec(dir, "ssh-keygen", "-l", "-f", pubFile.absolutePath); assertEquals(fp.text, 0, fp.code); assertTrue(fp.text, fp.text.contains(info.sha256)); assertTrue(fp.text.contains("ED25519"))
        val sign = exec(dir, "ssh-keygen", "-Y", "sign", "-f", key.absolutePath, "-n", "file", File(dir, "msg.txt").also { it.writeText("hello") }.absolutePath); assertEquals(sign.text, 0, sign.code)                          // 개인키로 실제 서명까지 됨
    }

    // ============================================================ Wi-Fi

    @Test fun wpaPskMatchesPythonPbkdf2AndConfigsAreWellFormed() {
        val cases = json("wpa_cases.json"); assertTrue(cases.length() >= 6)
        for (k in 0 until cases.length()) { val c = obj(cases, k); assertEquals(c.getString("psk"), run("make_wpa_conf", "ssid" to c.getString("ssid"), "pass" to c.getString("pass")).kv("PSK (64자리 16진수)")) }
        assertEquals("f42c6fc52df0ebef9ebb4b90b38a5f902e83fe1b135a70e23aed762e9710a12e", run("make_wpa_conf", "ssid" to "IEEE", "pass" to "password").kv("PSK (64자리 16진수)"))              // IEEE 802.11i 부록 H.4.1
        val sup = run("make_wpa_conf", "ssid" to "MyWiFi", "pass" to "correct horse battery"); val psk = sup.kv("PSK (64자리 16진수)"); val conf = sup.blockAfter("wpa_supplicant.conf")
        assertEquals("ctrl_interface=DIR=/var/run/wpa_supplicant GROUP=netdev\nupdate_config=1\ncountry=KR\n\nnetwork={\n    ssid=\"MyWiFi\"\n    key_mgmt=WPA-PSK\n    psk=$psk\n    proto=RSN\n    pairwise=CCMP\n}\n", conf); assertFalse(conf.contains("correct horse")); assertEquals(0, sup.noteWith("PSK 만 있어도")!!.level)
        val hidden = run("make_wpa_conf", "hidden" to "예", "cc" to "us").blockAfter("wpa_supplicant.conf"); assertTrue(hidden.contains("scan_ssid=1") && hidden.contains("country=US"))
        val sae = run("make_wpa_conf", "sec" to "WPA3-SAE", "pass" to "correct horse battery"); val saeConf = sae.blockAfter("wpa_supplicant.conf"); assertTrue(saeConf.contains("key_mgmt=SAE") && saeConf.contains("sae_password=\"correct horse battery\"") && saeConf.contains("ieee80211w=2") && !saeConf.contains("psk=")); assertEquals(1, sae.noteWith("비밀번호가 글자 그대로")!!.level)
        val mixed = run("make_wpa_conf", "sec" to "WPA2/WPA3 혼합"); val mixConf = mixed.blockAfter("wpa_supplicant.conf"); assertTrue(mixConf.contains("key_mgmt=WPA-PSK SAE") && mixConf.contains("psk=") && mixConf.contains("sae_password=") && mixConf.contains("ieee80211w=1")); assertTrue(mixed.noteWith("다운그레이드")!!.level == 1)
        val ap = run("make_wpa_conf", "t" to "공유기·AP (hostapd.conf)", "ch" to "11", "if" to "wlan1"); assertEquals("interface=wlan1\ndriver=nl80211\nssid=MyWiFi\ncountry_code=KR\nieee80211d=1\nhw_mode=g\nchannel=11\nieee80211n=1\nwmm_enabled=1\nauth_algs=1\nwpa=2\nwpa_key_mgmt=WPA-PSK\nwpa_psk=${ap.kv("PSK (64자리 16진수)")}\nrsn_pairwise=CCMP\n", ap.blockAfter("hostapd.conf"))
        val ap5 = run("make_wpa_conf", "t" to "공유기·AP (hostapd.conf)", "band" to "5GHz", "ch" to "36", "sec" to "WPA3-SAE").blockAfter("hostapd.conf"); assertTrue(ap5.contains("hw_mode=a") && ap5.contains("ieee80211ac=1") && ap5.contains("channel=36") && ap5.contains("wpa_key_mgmt=SAE") && ap5.contains("sae_password=correct horse battery"))
        // 입력 확인
        for (bad in listOf("ssid" to "", "ssid" to "a".repeat(33), "ssid" to "가".repeat(11), "ssid" to "my\"wifi", "pass" to "short", "pass" to "a".repeat(64), "pass" to "한글비밀번호1234", "cc" to "KOR", "cc" to "1")) assertTrue(bad.toString(), run("make_wpa_conf", bad).hasError)
        assertTrue(run("make_wpa_conf", "t" to "공유기·AP (hostapd.conf)", "ch" to "15").hasError); assertTrue(run("make_wpa_conf", "t" to "공유기·AP (hostapd.conf)", "band" to "5GHz", "ch" to "6").hasError); assertTrue(run("make_wpa_conf", "t" to "공유기·AP (hostapd.conf)", "if" to "wlan0;x").hasError); assertFalse(run("make_wpa_conf", "ssid" to "가".repeat(10)).hasError)
    }

    // ============================================================ OpenSSL (실제 openssl 로 실행)

    @Test fun opensslCommandsReallyWork() {
        assumeTrue("openssl 없음", have("openssl")); assumeTrue("bash 없음", have("bash"))
        fun script(r: ToolResult) = r.outs.filterIsInstance<Out.Block>().joinToString("\n") { it.text }
        var n = 0
        fun sh(dir: File, text: String): Proc { val f = File(dir, "step${n++}.sh").also { it.writeText(text + "\n") }; return exec(dir, "bash", "-e", f.absolutePath) }
        for (alg in MakeCfg.SSL_ALGS) {
            val dir = tmp(); val san = "example.com, *.example.org, 192.168.1.10, 2001:db8::1"
            val r = run("make_openssl_cmd", "op" to "자체 서명 인증서 + 키 (SAN 포함)", "alg" to alg, "san" to san, "cn" to "example.com", "org" to "Test Org", "c" to "kr", "base" to "srv", "days" to "30")
            val o = sh(dir, script(r)); assertEquals("$alg\n${script(r)}\n${o.text}", 0, o.code)
            val text = sh(dir, "openssl x509 -in srv.crt -noout -text").text
            assertTrue("$alg SAN\n$text", text.contains("DNS:example.com") && text.contains("DNS:*.example.org") && text.contains("IP Address:192.168.1.10") && text.contains("IP Address:2001:DB8:0:0:0:0:0:1")); assertTrue(text, text.contains("Subject: C = KR, O = Test Org, CN = example.com"))
            assertTrue(alg, when (alg) { "Ed25519" -> text.contains("ED25519"); "EC P-256" -> text.contains("prime256v1"); "EC P-384" -> text.contains("secp384r1"); else -> text.contains("Public-Key: (${alg.substringAfter(' ')} bit)") })
            assertEquals(alg, 0, sh(dir, "openssl x509 -in srv.crt -noout -checkend 0").code); assertEquals(alg, 1, sh(dir, "openssl x509 -in srv.crt -noout -checkend ${31 * 86400}").code)                   // 30일짜리: 지금은 유효, 31일 뒤엔 만료
            assertEquals(alg, "600", sh(dir, "stat -c %a srv.key").text.trim())
            // 같은 키·인증서로 나머지 명령: 짝 확인 · 내용 보기 · PFX 묶기/풀기
            val pair = sh(dir, script(run("make_openssl_cmd", "op" to "인증서와 개인키가 짝인지 확인", "base" to "srv"))); assertEquals(pair.text, 0, pair.code); val hashes = pair.text.lines().filter { it.isNotBlank() }; assertEquals(pair.text, 2, hashes.size); assertEquals(hashes[0].substringAfterLast(' '), hashes[1].substringAfterLast(' '))
            val view = sh(dir, script(run("make_openssl_cmd", "op" to "인증서 내용·만료일·지문 보기", "base" to "srv"))); assertEquals(view.text, 0, view.code); assertTrue(view.text, view.text.contains("subject=") && view.text.contains("notAfter=") && view.text.contains("sha256 Fingerprint=") && view.text.contains("30일 안에 만료돼요"))
            val pfx = sh(dir, script(run("make_openssl_cmd", "op" to "인증서 + 키 → PFX(PKCS#12)", "base" to "srv", "cn" to "example.com")).replace("-out srv.pfx", "-passout pass:pw -out srv.pfx")); assertEquals(pfx.text, 0, pfx.code)
            if (alg != "Ed25519") { val back = sh(dir, script(run("make_openssl_cmd", "op" to "PFX → PEM(키·인증서 분리)", "base" to "srv")).replace("openssl pkcs12 -in srv.pfx", "openssl pkcs12 -passin pass:pw -in srv.pfx").replace("-nodes -out srv.key", "-nodes -out back.key").replace("-out srv.crt", "-out back.crt").replace("chmod 600 srv.key", "chmod 600 back.key")); assertEquals("$alg\n${back.text}", 0, back.code); assertTrue(sh(dir, "grep -c 'BEGIN' back.key back.crt").text.contains("back.crt:1")) }
        }
        // CSR: 키 + 요청서에 SAN 이 들어가고 서명이 유효
        for (alg in listOf("RSA 2048", "EC P-256", "Ed25519")) { val dir = tmp(); val r = run("make_openssl_cmd", "op" to "키 + CSR(서명 요청, SAN 포함)", "alg" to alg, "san" to "a.example.com, 10.1.2.3", "cn" to "a.example.com", "base" to "req"); val o = sh(dir, script(r)); assertEquals("$alg\n${o.text}", 0, o.code)
            val csr = sh(dir, "openssl req -in req.csr -noout -text -verify").text; assertTrue(csr, csr.contains("DNS:a.example.com") && csr.contains("IP Address:10.1.2.3") && csr.contains("CN = a.example.com") && csr.contains("verify OK")) }
        // 무작위 값 · 체인 검증(자체 서명은 스스로가 루트) · 서버 인증서 확인(로컬 TLS 서버로)
        val dir = tmp(); val rand = sh(dir, "openssl rand -base64 32; openssl rand -hex 32"); assertEquals(0, rand.code); assertTrue(script(run("make_openssl_cmd", "op" to "무작위 비밀번호·키")).lines().take(2) == listOf("openssl rand -base64 32", "openssl rand -hex 32"))
        sh(dir, script(run("make_openssl_cmd", "op" to "자체 서명 인증서 + 키 (SAN 포함)", "alg" to "EC P-256", "san" to "localhost, 127.0.0.1", "cn" to "localhost", "base" to "srv")))
        sh(dir, "cp srv.crt ca-bundle.crt; cp srv.crt intermediate.crt"); val chain = sh(dir, script(run("make_openssl_cmd", "op" to "인증서 체인 검증", "base" to "srv"))); assertEquals(chain.text, 0, chain.code); assertTrue(chain.text, chain.text.contains("srv.crt: OK"))
        val port = java.net.ServerSocket(0).use { it.localPort }; val server = ProcessBuilder("openssl", "s_server", "-accept", "$port", "-cert", File(dir, "srv.crt").absolutePath, "-key", File(dir, "srv.key").absolutePath, "-quiet", "-www").redirectErrorStream(true).start()
        try { Thread.sleep(800); val sc = sh(dir, script(run("make_openssl_cmd", "op" to "서버가 주는 인증서 확인 (접속함)", "host" to "localhost:$port"))); assertEquals(sc.text, 0, sc.code); assertTrue(sc.text, sc.text.contains("subject=CN = localhost") && sc.text.contains("notAfter=") && sc.text.contains("IP Address:127.0.0.1")) } finally { server.destroyForcibly() }
    }

    @Test fun opensslToolTextAndValidation() {
        val r = run("make_openssl_cmd"); assertEquals(1, r.outs.filterIsInstance<Out.Block>().size); val cmd = r.blocks()
        assertEquals("openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -out server.key\nopenssl req -new -x509 -key server.key -out server.crt -days 365 -subj \"/CN=example.com\" -addext \"subjectAltName=DNS:example.com,DNS:www.example.com,IP:192.168.1.10\"\nchmod 600 server.key", cmd)
        assertTrue(run("make_openssl_cmd", "alg" to "RSA 4096").blocks().contains("rsa_keygen_bits:4096")); assertTrue(run("make_openssl_cmd", "alg" to "Ed25519").blocks().contains("openssl genpkey -algorithm ED25519")); assertTrue(run("make_openssl_cmd", "days" to "500").noteWith("398일") != null); assertNull(run("make_openssl_cmd", "days" to "300").noteWith("398일"))
        assertTrue(run("make_openssl_cmd", "san" to "", "cn" to "only.example.com").blocks().contains("subjectAltName=DNS:only.example.com")); assertTrue(run("make_openssl_cmd", "san" to "한글.example.com", "cn" to "x").blocks().contains("DNS:xn--")); assertTrue(run("make_openssl_cmd", "org" to "A Corp", "c" to "us").blocks().contains("/C=US/O=A Corp/CN=example.com"))
        val sc = run("make_openssl_cmd", "op" to "서버가 주는 인증서 확인 (접속함)", "host" to "mail.example.com"); assertTrue(sc.blocks().contains("openssl s_client -connect mail.example.com:443 -servername mail.example.com")); assertTrue(sc.noteWith("접속해요") != null); assertTrue(run("make_openssl_cmd", "op" to "서버가 주는 인증서 확인 (접속함)", "host" to "[2001:db8::1]:8443").blocks().contains("-connect [2001:db8::1]:8443 -servername 2001:db8::1"))
        for (bad in listOf("base" to "a b", "base" to "../x", "base" to "", "san" to "not a host!", "cn" to "a/b", "cn" to "a\"b", "days" to "0", "days" to "99999", "org" to "A/B", "c" to "KOR")) assertTrue(bad.toString(), run("make_openssl_cmd", bad).hasError)
        assertTrue(run("make_openssl_cmd", "op" to "서버가 주는 인증서 확인 (접속함)", "host" to "bad host!").hasError)
        for (op in listOf("인증서 + 키 → PFX(PKCS#12)", "PFX → PEM(키·인증서 분리)", "인증서 내용·만료일·지문 보기", "인증서와 개인키가 짝인지 확인", "인증서 체인 검증", "무작위 비밀번호·키")) assertFalse(op, run("make_openssl_cmd", "op" to op).hasError)
    }

    // ============================================================ 설정 파일 생성기 + 실제 검증 도구

    @Test fun nftablesRulesPassRealNftCheckMode() {
        assumeTrue("nft 없음", have("nft")); val dir = tmp(); val probe = File(dir, "probe.nft").also { it.writeText("table inet t { }\n") }; assumeTrue("nft -c 를 이 환경에서 쓸 수 없음", exec(dir, "nft", "-c", "-f", probe.absolutePath).code == 0)
        fun ok(name: String, r: ToolResult) { val f = File(dir, "$name.nft").also { it.writeText(r.blockAfter("nftables.conf")) }; val o = exec(dir, "nft", "-c", "-f", f.absolutePath); assertEquals("$name\n${f.readText()}\n${o.text}", 0, o.code) }
        ok("default", run("make_nftables"))
        ok("full", run("make_nftables", "ssh" to "2222", "sshfrom" to "192.168.0.0/24, 203.0.113.7, 2001:db8::/32", "sshrate" to "3", "tcp" to "80, 443, 8443", "udp" to "51820, 53", "block" to "198.51.100.0/24\n192.0.2.7\n2001:db8:bad::/48\n203.0.113.0/25, 203.0.113.128", "nat" to "eth0", "fwd" to "8080->192.168.1.50:80\n5353->192.168.1.60:53/udp", "log" to "남김 (분당 5개)"))
        ok("closed", run("make_nftables", "ssh" to "0", "tcp" to "", "udp" to "", "icmp" to "막기", "sshrate" to "0")); ok("sshOnlyV6", run("make_nftables", "sshfrom" to "2001:db8::1")); ok("natOnly", run("make_nftables", "nat" to "ppp0", "tcp" to "", "ssh" to "22")); ok("noRate", run("make_nftables", "sshrate" to "0", "sshfrom" to "10.0.0.0/8"))
        val big = (1..3000).joinToString("\n") { "10.${it / 250}.${it % 250}.0/24" } + "\n10.0.0.0/8\n10.1.0.0/16\n10.1.5.0/24"; ok("big", run("make_nftables", "block" to big))         // 겹치는 대역은 auto-merge 로 합쳐짐
        // 검사 장치 확인: 틀린 글은 거부돼야 함
        val bad = File(dir, "bad.nft").also { it.writeText("table inet t { chain c { tcp dport 22 acept } }\n") }; assertNotEquals(0, exec(dir, "nft", "-c", "-f", bad.absolutePath).code)
    }

    @Test fun nftablesToolContentAndValidation() {
        val r = run("make_nftables"); val cfg = r.blockAfter("nftables.conf")
        assertTrue(cfg.startsWith("flush ruleset\n\ntable inet filter {\n")); assertTrue(cfg.contains("chain input {\n        type filter hook input priority 0; policy drop;")); assertTrue(cfg.contains("ct state { established, related } accept") && cfg.contains("iifname \"lo\" accept"))
        assertTrue(cfg.contains("tcp dport 22 ct state new limit rate 6/minute accept") && cfg.contains("tcp dport { 80, 443 } accept") && cfg.contains("ip protocol icmp icmp type") && cfg.contains("limit rate 10/second accept")); assertFalse(cfg.contains("udp dport")); assertFalse(cfg.contains("table ip nat")); assertFalse(cfg.contains("blocklist"))
        assertEquals("${cfg.lines().size}줄", r.kv("규칙 줄 수")); assertEquals(1, r.noteWith("5분 뒤")!!.level); assertTrue(r.noteWith("기본 정책은")!!.text.contains("drop"))
        val f = run("make_nftables", "block" to "1.2.3.0/24\n2001:db8::/32\n1.2.3.0/24", "nat" to "eth0", "fwd" to "8080->10.0.0.5:80", "sshfrom" to "10.0.0.0/8, 2001:db8:1::/48", "udp" to "53"); val c = f.blockAfter("nftables.conf")
        assertTrue(c.contains("set blocklist4 {\n        type ipv4_addr\n        flags interval\n        auto-merge\n        elements = { 1.2.3.0/24 }") && c.contains("set blocklist6 {") && c.contains("ip saddr @blocklist4 drop") && c.contains("ip6 saddr @blocklist6 drop")); assertEquals("2개", f.kv("차단 목록"))
        assertTrue(c.contains("tcp dport 22 ip saddr { 10.0.0.0/8 } ct state new limit rate 6/minute accept") && c.contains("tcp dport 22 ip6 saddr { 2001:db8:1::/48 } ct state new limit rate 6/minute accept") && c.contains("udp dport { 53 } accept"))
        assertTrue(c.contains("tcp dport 8080 dnat to 10.0.0.5:80") && c.contains("oifname \"eth0\" masquerade") && c.contains("ip daddr 10.0.0.5 tcp dport 80 ct status dnat accept")); assertTrue(f.noteWith("ip_forward")!!.level == 0); assertTrue(f.noteWith("집합(set)") != null)
        assertEquals(2, run("make_nftables", "ssh" to "0").noteWith("SSH 포트를 열지 않았어요")!!.level)
        for (bad in listOf("ssh" to "70000", "ssh" to "x", "sshfrom" to "host.example.com", "sshfrom" to "10.0.0.0/99", "sshrate" to "5000", "tcp" to "80,abc", "tcp" to "0", "udp" to "99999", "block" to "nope", "block" to "1.2.3.4/40", "nat" to "eth0 ;", "fwd" to "8080-10.0.0.5:80"))
            assertTrue(bad.toString(), run("make_nftables", bad).hasError)
        assertTrue(run("make_nftables", "fwd" to "8080->10.0.0.5:80").hasError); assertTrue(run("make_nftables", "nat" to "eth0", "fwd" to "8080->10.0.0.5:99999").hasError); assertTrue(run("make_nftables", "nat" to "eth0", "fwd" to "8080->host:80").hasError)
        assertTrue(run("make_nftables", "block" to (1..5001).joinToString("\n") { "10.${it / 250}.${it % 250}.1" }).hasError)
    }

    @Test fun systemdUnitsPassRealVerify() {
        assumeTrue("systemd-analyze 없음", have("systemd-analyze")); val dir = tmp()
        fun ok(name: String, r: ToolResult) {
            val d = File(dir, name).also { it.mkdirs() }; val files = r.outs.filterIsInstance<Out.Head>().map { it.text }.filter { it.startsWith("/etc/systemd/system/") }.map { it.substringAfterLast('/') }; assertTrue(name, files.isNotEmpty())
            for (fn in files) File(d, fn).writeText(r.blockAfter("/etc/systemd/system/$fn"))
            val o = exec(d, "systemd-analyze", "verify", *files.map { File(d, it).absolutePath }.toTypedArray()); assertEquals("$name\n${files.joinToString { File(d, it).readText() }}\n${o.text}", 0, o.code)
            assertFalse("$name\n${o.text}", Regex("(?i)unknown (key|section|lvalue)|failed to|not executable|invalid|error").containsMatchIn(o.text))
        }
        val base = arrayOf("name" to "svc1", "exec" to "/bin/echo hello", "user" to "root")
        ok("plain", run("make_systemd", *base)); ok("always", run("make_systemd", *base, "restart" to "always", "workdir" to "/tmp", "env" to "A=1\nB=two words\nPORT=8080"))
        ok("hard1", run("make_systemd", *base, "hard" to "기본 (NoNewPrivileges·PrivateTmp·ProtectSystem=full)")); ok("hard2", run("make_systemd", *base, "hard" to "강하게 (홈·커널·제어 그룹 보호, /var/lib/이름 만 쓰기)", "net" to "아니오"))
        ok("daily", run("make_systemd", *base, "timer" to "매일 정해진 시각", "when" to "03:15")); ok("every", run("make_systemd", *base, "timer" to "N분마다 (부팅 5분 뒤부터)", "when" to "15", "hard" to "기본 (NoNewPrivileges·PrivateTmp·ProtectSystem=full)"))
        ok("cal", run("make_systemd", *base, "timer" to "OnCalendar 직접 입력", "when" to Cron.onCalendar(Cron.parse("*/15 9-18 * * 1-5")))); ok("norestart", run("make_systemd", *base, "restart" to "no"))
        val bad = File(dir, "bad.service").also { it.writeText("[Unit]\nDescription=x\n\n[Service]\nBogusKey=1\nExecStart=/bin/echo\n") }; assertTrue(exec(dir, "systemd-analyze", "verify", bad.absolutePath).text.contains("Unknown key"))                             // 검사 장치 확인
    }

    @Test fun systemdToolContentAndValidation() {
        val r = run("make_systemd"); val svc = r.blockAfter("/etc/systemd/system/myapp.service")
        assertEquals("[Unit]\nDescription=My application\nAfter=network-online.target\nWants=network-online.target\n\n[Service]\nType=simple\nExecStart=/usr/bin/myapp --config /etc/myapp.conf\nRestart=on-failure\nRestartSec=5\n\n[Install]\nWantedBy=multi-user.target\n", svc)
        assertEquals(1, r.noteWith("root 로 실행돼요")!!.level); assertTrue(r.blockAfter("설치·시작").contains("sudo systemctl enable --now myapp.service")); assertEquals(1, r.outs.filterIsInstance<Out.Head>().count { it.text.startsWith("/etc/systemd/system/") })
        val t = run("make_systemd", "timer" to "매일 정해진 시각", "when" to "3:05", "user" to "myapp"); assertEquals("[Unit]\nDescription=My application (타이머)\n\n[Timer]\nOnCalendar=*-*-* 03:05:00\nPersistent=true\nUnit=myapp.service\n\n[Install]\nWantedBy=timers.target\n", t.blockAfter("/etc/systemd/system/myapp.timer"))
        val ts = t.blockAfter("/etc/systemd/system/myapp.service"); assertTrue(ts.contains("Type=oneshot") && ts.contains("User=myapp") && !ts.contains("Restart=") && !ts.contains("[Install]")); assertTrue(t.blockAfter("설치·시작").contains("enable --now myapp.timer")); assertNull(t.noteWith("root 로 실행돼요")); assertTrue(t.noteWith("oneshot") != null)
        assertTrue(run("make_systemd", "timer" to "N분마다 (부팅 5분 뒤부터)", "when" to "30").blockAfter("/etc/systemd/system/myapp.timer").contains("OnBootSec=5min\nOnUnitActiveSec=30min"))
        val h2 = run("make_systemd", "hard" to "강하게 (홈·커널·제어 그룹 보호, /var/lib/이름 만 쓰기)").blockAfter("/etc/systemd/system/myapp.service"); assertTrue(h2.contains("ProtectSystem=strict") && h2.contains("ProtectHome=true") && h2.contains("StateDirectory=myapp") && h2.contains("NoNewPrivileges=true")); assertTrue(run("make_systemd", "hard" to "기본 (NoNewPrivileges·PrivateTmp·ProtectSystem=full)").blockAfter("/etc/systemd/system/myapp.service").contains("ProtectSystem=full"))
        val e = run("make_systemd", "env" to "A=1\nB=two words", "workdir" to "/opt/x", "net" to "아니오").blockAfter("/etc/systemd/system/myapp.service"); assertTrue(e.contains("Environment=\"A=1\"\nEnvironment=\"B=two words\"") && e.contains("WorkingDirectory=/opt/x") && !e.contains("network-online"))
        for (bad in listOf("name" to "my app", "name" to "", "name" to "a/b", "exec" to "myapp", "exec" to "", "user" to "Root", "user" to "a b", "workdir" to "opt", "env" to "1A=x", "env" to "A=\"x\"", "env" to "novalue", "when" to "25:00")) if (bad.first != "when") assertTrue(bad.toString(), run("make_systemd", bad).hasError)
        assertTrue(run("make_systemd", "timer" to "매일 정해진 시각", "when" to "25:61").hasError); assertTrue(run("make_systemd", "timer" to "N분마다 (부팅 5분 뒤부터)", "when" to "0").hasError); assertTrue(run("make_systemd", "timer" to "N분마다 (부팅 5분 뒤부터)", "when" to "abc").hasError); assertTrue(run("make_systemd", "timer" to "OnCalendar 직접 입력", "when" to "").hasError)
    }

    @Test fun netplanFilesPassRealNetplanGenerate() {
        assumeTrue("netplan 없음", have("netplan")); val dir = tmp()
        /** netplan 이 이해했다면 root/run/systemd/network 에 networkd 설정 파일을 만들어요 (맨 끝의 systemctl 호출 실패는 이 환경에 systemd 가 없어서라 무시) */
        fun gen(name: String, yaml: String): Map<String, String> {
            val root = File(dir, name); File(root, "etc/netplan").mkdirs(); File(root, "etc/netplan/50-custom.yaml").also { it.writeText(yaml); exec(null, "chmod", "600", it.absolutePath) }
            val o = exec(root, "netplan", "generate", "--root-dir", root.absolutePath)
            val out = File(root, "run/systemd/network").listFiles()?.associate { it.name to it.readText() } ?: emptyMap(); assertTrue("$name: netplan 이 설정을 만들지 못했어요\n$yaml\n${o.text}", out.isNotEmpty()); return out
        }
        fun yamlOf(r: ToolResult) = r.blockAfter("/etc/netplan/50-custom.yaml")
        assertTrue(gen("dhcp", yamlOf(run("make_netplan"))).entries.single { it.key.endsWith("eth0.network") }.value.contains("DHCP=ipv4"))
        val st = gen("static", yamlOf(run("make_netplan", "m" to "고정 IP", "gw6" to "fe80::1", "mtu" to "1500", "search" to "home.lan, lan.example.com", "addr" to "192.168.1.10/24, 2001:db8::10/64"))).entries.single { it.key.endsWith("eth0.network") }.value
        assertTrue(st, st.contains("Address=192.168.1.10/24") && st.contains("Address=2001:db8::10/64") && st.contains("DNS=1.1.1.1") && st.contains("DNS=8.8.8.8") && st.contains("Domains=home.lan lan.example.com") && st.contains("MTUBytes=1500")); assertTrue(st, st.contains("Gateway=192.168.1.1") && st.contains("Gateway=fe80::1"))
        val br = gen("bridge", yamlOf(run("make_netplan", "m" to "브리지", "if" to "br0", "mem" to "eth0, eth1", "addr" to "10.0.0.2/24"))); assertTrue(br.keys.toString(), br.keys.any { it.endsWith("br0.netdev") } && br.keys.any { it.endsWith("br0.network") } && br.keys.count { it.contains("eth") } == 2); assertTrue(br.entries.first { it.key.endsWith("br0.netdev") }.value.contains("Kind=bridge")); assertTrue(br.entries.first { it.key.endsWith("br0.network") }.value.contains("Address=10.0.0.2/24"))
        val bd = gen("bridgeDhcp", yamlOf(run("make_netplan", "m" to "브리지", "if" to "br0", "mem" to "eth0", "addr" to ""))); assertTrue(bd.entries.first { it.key.endsWith("br0.network") }.value.contains("DHCP=ipv4"))
        val vl = gen("vlan", yamlOf(run("make_netplan", "m" to "VLAN", "if" to "vlan100", "mem" to "eth0", "vlan" to "100", "addr" to "10.100.0.2/24", "gw4" to "10.100.0.1"))); assertTrue(vl.entries.first { it.key.endsWith("vlan100.netdev") }.value.let { it.contains("Kind=vlan") && it.contains("Id=100") })
        val bo = gen("bond", yamlOf(run("make_netplan", "m" to "본딩 (active-backup)", "if" to "bond0", "mem" to "eth0, eth1", "addr" to "10.0.0.3/24", "gw4" to "10.0.0.1", "mtu" to "9000"))); assertTrue(bo.entries.first { it.key.endsWith("bond0.netdev") }.value.let { it.contains("Kind=bond") && it.contains("Mode=active-backup") && it.contains("MIIMonitorSec=") }); assertTrue(bo.entries.first { it.key.endsWith("bond0.network") }.value.contains("MTUBytes=9000"))
        // 검사 장치 확인: 틀린 YAML 은 netplan 이 설정을 만들지 못해야 함
        val root = File(dir, "bad"); File(root, "etc/netplan").mkdirs(); File(root, "etc/netplan/50-custom.yaml").also { it.writeText("network:\n  version: 2\n  ethernets:\n    eth0:\n      dhcp4: maybe\n      bogus-key: 1\n"); exec(null, "chmod", "600", it.absolutePath) }
        val o = exec(root, "netplan", "generate", "--root-dir", root.absolutePath); assertTrue(o.text, File(root, "run/systemd/network").listFiles().isNullOrEmpty()); assertTrue(o.text, Regex("(?i)invalid|unknown|error").containsMatchIn(o.text))
    }

    @Test fun netplanToolContentAndValidation() {
        val d = run("make_netplan").blockAfter("/etc/netplan/50-custom.yaml"); assertEquals("network:\n  version: 2\n  renderer: networkd\n  ethernets:\n    eth0:\n      dhcp4: true\n      dhcp6: false\n", d)
        val s = run("make_netplan", "m" to "고정 IP", "gw6" to "fe80::1", "mtu" to "9000", "search" to "home.lan").blockAfter("/etc/netplan/50-custom.yaml")
        assertEquals("network:\n  version: 2\n  renderer: networkd\n  ethernets:\n    eth0:\n      dhcp4: false\n      addresses:\n        - 192.168.1.10/24\n      routes:\n        - to: 0.0.0.0/0\n          via: 192.168.1.1\n        - to: \"::/0\"\n          via: fe80::1\n      nameservers:\n        addresses: [1.1.1.1, 8.8.8.8]\n        search: [home.lan]\n      mtu: 9000\n", s)
        val b = run("make_netplan", "m" to "브리지", "if" to "br0", "mem" to "eth0,eth1", "addr" to "10.0.0.2/24", "gw4" to ""); val y = b.blockAfter("/etc/netplan/50-custom.yaml"); assertTrue(y.contains("  ethernets:\n    eth0: {}\n    eth1: {}\n  bridges:\n    br0:\n      interfaces: [eth0, eth1]\n") && y.contains("stp: false"))
        val v = run("make_netplan", "m" to "VLAN", "if" to "vlan100", "mem" to "eth0", "vlan" to "100").blockAfter("/etc/netplan/50-custom.yaml"); assertTrue(v.contains("  vlans:\n    vlan100:\n      id: 100\n      link: eth0\n")); val bo = run("make_netplan", "m" to "본딩 (active-backup)", "if" to "bond0", "mem" to "eth0, eth1").blockAfter("/etc/netplan/50-custom.yaml"); assertTrue(bo.contains("mode: active-backup") && bo.contains("primary: eth0") && bo.contains("mii-monitor-interval: 100"))
        assertTrue(run("make_netplan", "m" to "브리지", "if" to "br0", "mem" to "eth0", "addr" to "").noteWith("DHCP 로 받도록")!!.level == 0); assertTrue(run("make_netplan").blockAfter("적용 순서").contains("netplan try")); assertEquals(1, run("make_netplan", "m" to "고정 IP", "gw4" to "", "dns" to "").noteWith("게이트웨이를 적지")!!.level); assertEquals(1, run("make_netplan", "m" to "고정 IP", "dns" to "").noteWith("DNS 를 적지")!!.level)
        for (bad in listOf("if" to "eth 0", "if" to "", "addr" to "192.168.1.10", "addr" to "192.168.1.10/33", "addr" to "", "gw4" to "2001:db8::1", "gw4" to "x", "gw6" to "192.168.1.1", "dns" to "dns.google", "search" to "bad_domain!", "mtu" to "100", "mtu" to "abc")) assertTrue(bad.toString(), run("make_netplan", "m" to "고정 IP", bad).hasError)
        assertTrue(run("make_netplan", "m" to "브리지", "mem" to "").hasError); assertTrue(run("make_netplan", "m" to "VLAN", "mem" to "eth0, eth1", "vlan" to "100").hasError); assertTrue(run("make_netplan", "m" to "VLAN", "mem" to "eth0", "vlan" to "5000").hasError); assertTrue(run("make_netplan", "m" to "본딩 (active-backup)", "mem" to "eth0").hasError); assertTrue(run("make_netplan", "m" to "브리지", "mem" to "eth!0").hasError)
        assertFalse(run("make_netplan", "addr" to "garbage", "dns" to "garbage").hasError)                                                                    // DHCP 방식은 주소 칸을 쓰지 않음
    }

    @Test fun chronyConfigsPassRealChronyd() {
        assumeTrue("chronyd 없음", have("chronyd")); val dir = tmp()
        fun ok(name: String, r: ToolResult) { val f = File(dir, "$name.conf").also { it.writeText(r.blockAfter("/etc/chrony/chrony.conf")) }; val o = exec(dir, "chronyd", "-p", "-f", f.absolutePath); assertEquals("$name\n${f.readText()}\n${o.text}", 0, o.code) }
        ok("default", run("make_chrony")); ok("nts", run("make_chrony", "nts" to "사용 (NTS 를 지원하는 서버만)", "srv" to "time.cloudflare.com\nnts.netnod.se")); ok("serve", run("make_chrony", "allow" to "192.168.1.0/24, 10.0.0.0/8, 2001:db8::/32", "local" to "예 (local stratum 10)"))
        ok("minimal", run("make_chrony", "step" to "아니오", "rtc" to "아니오", "srv" to "192.0.2.1")); ok("pools", run("make_chrony", "srv" to "0.pool.ntp.org, 1.pool.ntp.org\nntp.ubuntu.com"))
        val bad = File(dir, "bad.conf").also { it.writeText("serverr time.example.com\n") }; assertNotEquals(0, exec(dir, "chronyd", "-p", "-f", bad.absolutePath).code)
    }

    @Test fun chronyToolContentAndValidation() {
        val r = run("make_chrony"); assertEquals("server time.cloudflare.com iburst\nserver time.google.com iburst\npool 2.pool.ntp.org iburst maxsources 4\ndriftfile /var/lib/chrony/chrony.drift\nmakestep 1.0 3\nrtcsync\n", r.blockAfter("/etc/chrony/chrony.conf"))
        val n = run("make_chrony", "nts" to "사용 (NTS 를 지원하는 서버만)", "srv" to "time.cloudflare.com\n1.pool.ntp.org").blockAfter("/etc/chrony/chrony.conf"); assertTrue(n.contains("server time.cloudflare.com iburst nts\n") && n.contains("pool 1.pool.ntp.org iburst maxsources 4\n") && n.contains("ntsdumpdir /var/lib/chrony")); assertEquals(1, run("make_chrony", "nts" to "사용 (NTS 를 지원하는 서버만)").noteWith("NTS 는 서버가 지원해야")!!.level)
        val a = run("make_chrony", "allow" to "192.168.1.0/24", "local" to "예 (local stratum 10)"); assertTrue(a.blockAfter("/etc/chrony/chrony.conf").contains("allow 192.168.1.0/24\nlocal stratum 10\n")); assertEquals(1, a.noteWith("123/udp")!!.level); assertTrue(r.blockAfter("적용·확인").contains("chronyc tracking"))
        assertEquals(1, run("make_chrony", "srv" to "a.example.com, a.example.com").blockAfter("/etc/chrony/chrony.conf").lines().count { it.startsWith("server ") })
        for (bad in listOf("srv" to "bad host!", "srv" to "a.example.com\nbad_host", "allow" to "192.168.1.0", "allow" to "host/24")) assertTrue(bad.toString(), run("make_chrony", bad).hasError); assertEquals(1, run("make_chrony", "srv" to "").notes().single().level); assertFalse(run("make_chrony", "srv" to "").hasError)
    }

    @Test fun fail2banConfigsPassRealFail2banTest() {
        assumeTrue("fail2ban-client 없음", have("fail2ban-client")); assumeTrue("/etc/fail2ban 없음", File("/etc/fail2ban/filter.d").isDirectory); val dir = tmp()
        val fakeLog = File(dir, "x.log").also { it.writeText("") }
        /** 설정 문법·필터 이름은 그대로 검사하고, 이 컴퓨터에 없을 수 있는 로그 파일 경로만 빈 파일로 바꿔서 시험 */
        fun withLogs(text: String): String = text.lines().joinToString("\n") { if (it.startsWith("logpath =")) "logpath = ${fakeLog.absolutePath}" else it }.replace(Regex("(?m)^(enabled = true)$(?![\\s\\S]*?^logpath)"), "$1").let { t ->
            val out = StringBuilder(); var jail = ""; var hasLog = false
            for (line in t.lines()) { if (line.startsWith("[")) { if (jail.isNotEmpty() && jail != "DEFAULT" && !hasLog) out.append("logpath = ${fakeLog.absolutePath}\n"); jail = line.trim('[', ']'); hasLog = false }; if (line.startsWith("logpath")) hasLog = true; out.append(line).append('\n') }
            if (jail.isNotEmpty() && jail != "DEFAULT" && !hasLog) out.append("logpath = ${fakeLog.absolutePath}\n"); out.toString() }
        fun ok(name: String, r: ToolResult) {
            val cfg = File(dir, name); exec(null, "cp", "-r", "/etc/fail2ban", cfg.absolutePath); File(cfg, "jail.local").writeText(withLogs(r.blockAfter("/etc/fail2ban/jail.local"))); File(cfg, "jail.d").listFiles()?.forEach { if (it.name.contains("defaults")) it.writeText("") }
            val o = exec(dir, "fail2ban-client", "-c", cfg.absolutePath, "-t"); assertEquals("$name\n${File(cfg, "jail.local").readText()}\n${o.text}", 0, o.code); assertTrue(o.text, o.text.contains("configuration test is successful"))
        }
        ok("default", run("make_fail2ban")); ok("all", run("make_fail2ban", "jails" to MakeCfg.F2B_JAILS.keys.joinToString("\n"), "sshport" to "2222", "max" to "3", "find" to "30", "ban" to "1440", "ignore" to "203.0.113.7, 192.168.0.0/24, 2001:db8::/32", "act" to "iptables-multiport", "sshbk" to "로그 파일 (/var/log/auth.log)", "inc" to "아니오"))
        ok("ufw", run("make_fail2ban", "jails" to "sshd, nginx-http-auth", "act" to "ufw")); ok("noaction", run("make_fail2ban", "act" to "(기본값 사용)", "ignore" to "")); ok("recidive", run("make_fail2ban", "jails" to "recidive"))
        val bad = File(dir, "bad"); exec(null, "cp", "-r", "/etc/fail2ban", bad.absolutePath); File(bad, "jail.local").writeText("[sshd]\nenabled = true\nfilter = doesnotexist\n"); assertNotEquals(0, exec(dir, "fail2ban-client", "-c", bad.absolutePath, "-t").code)
    }

    @Test fun fail2banToolContentAndValidation() {
        val r = run("make_fail2ban"); assertEquals("[DEFAULT]\nbantime = 60m\nfindtime = 10m\nmaxretry = 5\nbanaction = nftables-multiport\nbantime.increment = true\nbantime.factor = 2\nbantime.maxtime = 5w\n\n[sshd]\nenabled = true\nport = ssh\nbackend = systemd\n", r.blockAfter("/etc/fail2ban/jail.local"))
        assertEquals(1, r.noteWith("예외 IP 를 하나도")!!.level); assertTrue(r.blockAfter("적용·확인").contains("fail2ban-client status sshd") && r.blockAfter("적용·확인").contains("unbanip"))
        val c = run("make_fail2ban", "jails" to "sshd\nnginx-http-auth\nrecidive", "sshport" to "2222", "max" to "2", "find" to "5", "ban" to "30", "ignore" to "1.2.3.4, 10.0.0.0/8", "act" to "(기본값 사용)", "sshbk" to "로그 파일 (/var/log/auth.log)", "inc" to "아니오").blockAfter("/etc/fail2ban/jail.local")
        assertEquals("[DEFAULT]\nbantime = 30m\nfindtime = 5m\nmaxretry = 2\nignoreip = 127.0.0.1/8 ::1 1.2.3.4 10.0.0.0/8\n\n[sshd]\nenabled = true\nport = 2222\n\n[nginx-http-auth]\nenabled = true\nport = http,https\n\n[recidive]\nenabled = true\nlogpath = /var/log/fail2ban.log\nbantime = 1w\nfindtime = 1d\nmaxretry = 3\n", c)
        assertTrue(run("make_fail2ban", "max" to "2").noteWith("너무 낮으면")!!.level == 1); assertNull(run("make_fail2ban", "ignore" to "1.2.3.4").noteWith("예외 IP 를 하나도"))
        for (bad in listOf("jails" to "unknown-jail", "sshport" to "0", "max" to "0", "max" to "101", "find" to "0", "ban" to "0", "ban" to "99999999", "ignore" to "host.example.com", "max" to "abc")) assertTrue(bad.toString(), run("make_fail2ban", bad).hasError); assertEquals(1, run("make_fail2ban", "jails" to "").notes().single().level); assertTrue(run("make_fail2ban", "jails" to "unknown-jail").text().contains("sshd, nginx-http-auth"))
    }

    @Test fun haproxyConfigsPassRealHaproxyCheck() {
        assumeTrue("haproxy 없음", have("haproxy")); val dir = tmp(); val hasUser = exec(null, "id", "haproxy").code == 0
        // TLS 시험용 인증서(키+인증서 합친 PEM)
        assumeTrue("openssl 없음", have("openssl")); exec(dir, "openssl", "req", "-x509", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:P-256", "-nodes", "-keyout", "k.pem", "-out", "c.pem", "-subj", "/CN=t", "-days", "2"); val pem = File(dir, "site.pem").also { it.writeText(File(dir, "c.pem").readText() + File(dir, "k.pem").readText()) }
        fun ok(name: String, r: ToolResult) { val f = File(dir, "$name.cfg").also { it.writeText(r.blockAfter("/etc/haproxy/haproxy.cfg")) }; val o = exec(dir, "haproxy", "-c", "-f", f.absolutePath); assertEquals("$name\n${f.readText()}\n${o.text}", 0, o.code); assertTrue(o.text, o.text.contains("Configuration file is valid")) }
        val user = if (hasUser) "예 (패키지 기본)" else "아니오"
        ok("default", run("make_haproxy", "user" to user)); ok("tcp", run("make_haproxy", "mode" to "TCP (그 밖의 서비스)", "port" to "3306", "srv" to "10.0.0.5:3306\n10.0.0.6:3306,3", "bal" to "leastconn", "user" to "아니오"))
        ok("tls", run("make_haproxy", "crt" to pem.absolutePath, "port" to "443", "user" to "아니오")); ok("tlsNoRedirect", run("make_haproxy", "crt" to pem.absolutePath, "port" to "443", "redir" to "아니오", "stats" to "s3cretpass", "rate" to "50", "bal" to "source", "user" to "아니오"))
        ok("v6", run("make_haproxy", "srv" to "[2001:db8::1]:8080\nlocalhost:80,0\n10.0.0.1:81", "path" to "/up?x=1", "maxconn" to "100", "user" to "아니오")); ok("noCheck", run("make_haproxy", "path" to "", "rate" to "0", "user" to "아니오"))
        val bad = File(dir, "bad.cfg").also { it.writeText("global\n  bogus_option 1\n") }; assertNotEquals(0, exec(dir, "haproxy", "-c", "-f", bad.absolutePath).code)
    }

    @Test fun haproxyToolContentAndValidation() {
        val r = run("make_haproxy"); assertEquals("global\n    log /dev/log local0\n    maxconn 4096\n    user haproxy\n    group haproxy\n\ndefaults\n    log global\n    mode http\n    option httplog\n    option forwardfor\n    option dontlognull\n    retries 3\n    timeout connect 5s\n    timeout client 30s\n    timeout server 30s\n    timeout http-request 10s\n\nfrontend main\n    bind *:80\n    stick-table type ip size 100k expire 30s store http_req_rate(10s)\n    http-request track-sc0 src\n    http-request deny deny_status 429 if { sc_http_req_rate(0) gt 100 }\n    default_backend app\n\nbackend app\n    balance roundrobin\n    option httpchk GET /health\n    http-check expect status 200\n    server s1 10.0.0.11:8080 check\n    server s2 10.0.0.12:8080 check weight 2\n", r.blockAfter("/etc/haproxy/haproxy.cfg"))
        assertEquals(1, run("make_haproxy", "path" to "").noteWith("상태 검사를 안 하면")!!.level); assertTrue(r.blockAfter("적용·확인").contains("haproxy -c -f /etc/haproxy/haproxy.cfg"))
        val t = run("make_haproxy", "crt" to "/etc/haproxy/certs/site.pem", "port" to "443", "stats" to "s3cretpass").blockAfter("/etc/haproxy/haproxy.cfg"); assertTrue(t.contains("bind *:443 ssl crt /etc/haproxy/certs/site.pem alpn h2,http/1.1\n    bind *:80\n    http-request redirect scheme https code 301 unless { ssl_fc }") && t.contains("listen stats\n    mode http\n    bind 127.0.0.1:8404") && t.contains("stats auth admin:s3cretpass"))
        val tcp = run("make_haproxy", "mode" to "TCP (그 밖의 서비스)", "path" to "/health", "crt" to "/x.pem", "rate" to "10"); val tc = tcp.blockAfter("/etc/haproxy/haproxy.cfg"); assertTrue(tc.contains("mode tcp\n    option tcplog") && tc.contains("option tcp-check") && tc.contains("server s1 10.0.0.11:8080 check") && !tc.contains("httpchk") && !tc.contains("ssl crt") && !tc.contains("stick-table") && !tc.contains("forwardfor")); assertTrue(tcp.noteWith("TCP 모드에서는") != null)
        assertTrue(run("make_haproxy", "crt" to "/x.pem").noteWith("개인키와 인증서를 이어 붙인")!!.level == 0); assertFalse(run("make_haproxy", "user" to "아니오").blockAfter("/etc/haproxy/haproxy.cfg").contains("user haproxy"))
        for (bad in listOf("port" to "0", "srv" to "10.0.0.1", "srv" to "10.0.0.1:99999", "srv" to "bad host:80", "srv" to "10.0.0.1:80,x", "srv" to "10.0.0.1:80,999", "path" to "health", "path" to "/a b", "maxconn" to "0", "crt" to "site.pem", "crt" to "/a b.pem", "stats" to "short", "stats" to "has space1", "stats" to "colon:pass12", "rate" to "-1")) assertTrue(bad.toString(), run("make_haproxy", bad).hasError)
        assertEquals(1, run("make_haproxy", "srv" to "").notes().single().level)
    }

    @Test fun sshdConfigsPassRealSshdTest() {
        assumeTrue("sshd 없음", have("sshd")); val dir = tmp(); val probe = File(dir, "probe.conf").also { it.writeText("Port 2222\n") }; assumeTrue("sshd -t 를 이 환경에서 쓸 수 없음(호스트 키·/run/sshd 필요): ${exec(dir, "sshd", "-t", "-f", probe.absolutePath).text}", exec(dir, "sshd", "-t", "-f", probe.absolutePath).code == 0)
        fun ok(name: String, r: ToolResult) { val f = File(dir, "$name.conf").also { it.writeText(r.blockAfter("/etc/ssh/sshd_config.d/99-hardening.conf")) }; val o = exec(dir, "sshd", "-t", "-f", f.absolutePath); assertEquals("$name\n${f.readText()}\n${o.text}", 0, o.code); assertEquals(o.text, "", o.text.trim()) }
        ok("default", run("make_sshd_harden")); ok("loose", run("make_sshd_harden", "port" to "2200", "root" to "prohibit-password (키로만 허용)", "pw" to "켜기", "users" to "alice bob@192.168.0.*, carol", "tries" to "6", "fwd" to "허용", "x11" to "허용", "cr" to "기본값 유지", "alive" to "0")); ok("strict", run("make_sshd_harden", "tries" to "1", "alive" to "3600"))
        val bad = File(dir, "bad.conf").also { it.writeText("Port 22\nBogusOption yes\n") }; assertNotEquals(0, exec(dir, "sshd", "-t", "-f", bad.absolutePath).code)
    }

    @Test fun sshdToolContentAndValidation() {
        val r = run("make_sshd_harden"); assertEquals("Port 22\nPermitRootLogin no\nPubkeyAuthentication yes\nPasswordAuthentication no\nPermitEmptyPasswords no\nChallengeResponseAuthentication no\nMaxAuthTries 3\nLoginGraceTime 30\nX11Forwarding no\nAllowTcpForwarding no\nAllowAgentForwarding no\nClientAliveInterval 300\nClientAliveCountMax 2\n" +
            "KexAlgorithms curve25519-sha256,curve25519-sha256@libssh.org,diffie-hellman-group16-sha512,diffie-hellman-group18-sha512\nCiphers chacha20-poly1305@openssh.com,aes256-gcm@openssh.com,aes128-gcm@openssh.com,aes256-ctr,aes192-ctr,aes128-ctr\nMACs hmac-sha2-512-etm@openssh.com,hmac-sha2-256-etm@openssh.com,umac-128-etm@openssh.com\nHostKeyAlgorithms ssh-ed25519,rsa-sha2-512,rsa-sha2-256\n", r.blockAfter("/etc/ssh/sshd_config.d/99-hardening.conf"))
        assertEquals(2, r.noteWith("비밀번호 로그인을 껐어요")!!.level); assertTrue(r.blockAfter("적용 순서").contains("sudo sshd -t")); assertNull(r.noteWith("포트를")); assertNull(r.noteWith("AllowUsers"))
        val l = run("make_sshd_harden", "port" to "2200", "pw" to "켜기", "users" to "alice, bob", "cr" to "기본값 유지", "fwd" to "허용", "alive" to "0", "root" to "prohibit-password (키로만 허용)"); val c = l.blockAfter("/etc/ssh/sshd_config.d/99-hardening.conf")
        assertTrue(c.contains("Port 2200\nPermitRootLogin prohibit-password") && c.contains("PasswordAuthentication yes") && c.contains("AllowUsers alice bob") && c.contains("AllowTcpForwarding yes") && !c.contains("KexAlgorithms") && !c.contains("ClientAliveInterval")); assertEquals(1, l.noteWith("2200번으로")!!.level); assertEquals(1, l.noteWith("AllowUsers")!!.level); assertNull(l.noteWith("비밀번호 로그인을 껐어요"))
        for (bad in listOf("port" to "0", "port" to "abc", "users" to "bad user!", "users" to "1abc", "tries" to "0", "tries" to "11", "alive" to "-1", "alive" to "99999")) assertTrue(bad.toString(), run("make_sshd_harden", bad).hasError)
    }

    @Test fun everyMakeToolRunsWithItsDefaults() {
        val ids = MakeTools.ALL.map { it.id }; assertEquals(listOf("make_wg_keys", "make_ssh_key", "make_cron", "make_ipv6_ula", "make_wpa_conf", "make_openssl_cmd", "make_tc_netem", "make_nftables", "make_systemd", "make_netplan", "make_chrony", "make_fail2ban", "make_haproxy", "make_sshd_harden"), ids)
        for (t in MakeTools.ALL) { assertEquals(NetGroups.MAKE, t.group); assertEquals(ToolMode.OFFLINE, t.mode); assertTrue(t.id, t.note!!.contains("어디로도") || t.note!!.contains("안에서만")); assertTrue(t.desc.length > 25); val r = runNetTool(t.id); assertTrue(t.id, r.outs.isNotEmpty()); assertTrue("${t.id}\n${r.text()}", failures(r).isEmpty()) }
        // 선택지를 하나씩 바꿔도 동작해야 함 (필요한 입력칸이 비어 있어서 안내를 내는 조합만 예외)
        val needsMoreInput = setOf("make_wg_keys/m=비밀키로 공개키 계산", "make_netplan/m=브리지", "make_netplan/m=VLAN", "make_netplan/m=본딩 (active-backup)", "make_systemd/timer=N분마다 (부팅 5분 뒤부터)")
        var combos = 0
        for (t in MakeTools.ALL) for (f in t.fields.filter { it.kind == FieldKind.CHOICE }) for (c in f.choices) {
            val r = runNetTool(t.id, f.key to c); combos++
            if ("${t.id}/${f.key}=$c" in needsMoreInput) assertTrue("${t.id}/${f.key}=$c 는 입력이 더 필요하다는 안내가 나와야 해요", r.hasError || r.notes().any { it.level >= 1 }) else assertTrue("${t.id}/${f.key}=$c\n${r.text()}", failures(r).isEmpty())
        }
        assertTrue("선택지 조합 수 $combos", combos >= 90)
    }
}
