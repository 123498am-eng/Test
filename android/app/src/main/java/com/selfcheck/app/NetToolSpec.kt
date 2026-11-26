package com.selfcheck.app

import java.io.InputStream
import java.net.Socket
import java.util.concurrent.atomic.AtomicBoolean

/*
 * 네트워크 도구 모음의 공통 틀.
 * 도구 하나 = 입력 칸 몇 개 + 계산 함수 하나. 계산 결과는 화면과 상관없는 "결과 줄" 목록이라서
 * 컴퓨터(JVM)에서 그대로 시험할 수 있고, 화면(NetToolActivity)은 이 목록을 그리기만 합니다.
 */

enum class FieldKind { TEXT, MULTILINE, CHOICE, FILE }

class Field(
    val key: String,
    val label: String,
    val hint: String = "",
    val default: String = "",
    val kind: FieldKind = FieldKind.TEXT,
    /** kind == CHOICE 일 때 고를 수 있는 값 (default 가 비면 첫 번째) */
    val choices: List<String> = emptyList(),
    /** 눌러서 채우는 예시 칩: (칩 글자 → 채울 값) */
    val chips: List<Pair<String, String>> = emptyList(),
)

/** 결과 한 줄. level: 0 보통, 1 주의, 2 위험·오류, -1 좋음 */
sealed class Out {
    class Kv(val label: String, val value: String, val level: Int = 0) : Out()
    class Block(val text: String, val mono: Boolean = true) : Out()
    class Head(val text: String) : Out()
    class Note(val text: String, val level: Int = 0) : Out()
    class Cols(val cells: List<String>, val header: Boolean = false, val level: Int = 0) : Out()
}

class ToolResult(val outs: List<Out>) {
    /** 복사·시험용 글 */
    fun text(): String = outs.joinToString("\n") { o ->
        when (o) {
            is Out.Kv -> "${o.label}: ${o.value}"
            is Out.Block -> o.text
            is Out.Head -> "\n[${o.text}]"
            is Out.Note -> o.text
            is Out.Cols -> o.cells.joinToString("  |  ")
        }
    }.trim()

    val hasError: Boolean get() = outs.any { (it is Out.Note && it.level == 2) }
}

/** 결과 만들기 도우미 */
class Rb {
    val outs = ArrayList<Out>()
    fun kv(label: String, value: String, level: Int = 0) { outs += Out.Kv(label, value, level) }
    fun head(t: String) { outs += Out.Head(t) }
    fun note(t: String, level: Int = 0) { outs += Out.Note(t, level) }
    fun block(t: String, mono: Boolean = true) { outs += Out.Block(t, mono) }
    fun row(vararg c: String, level: Int = 0) { outs += Out.Cols(c.toList(), false, level) }
    fun header(vararg c: String) { outs += Out.Cols(c.toList(), true) }
    fun rowList(c: List<String>, level: Int = 0) { outs += Out.Cols(c, false, level) }
}

fun result(f: Rb.() -> Unit): ToolResult { val b = Rb(); b.f(); return ToolResult(b.outs) }
fun fail(msg: String) = result { note(msg, 2) }
/** 입력이 비었을 때 같은 안내 (주의 색) */
fun need(msg: String) = result { note(msg, 1) }

class ToolInput(private val values: Map<String, String>) {
    fun raw(k: String) = values[k] ?: ""
    fun str(k: String) = raw(k).trim()
    fun int(k: String): Int? = str(k).replace(",", "").toIntOrNull()
    fun long(k: String): Long? = str(k).replace(",", "").toLongOrNull()
    fun double(k: String): Double? = str(k).replace(",", "").toDoubleOrNull()
    fun lines(k: String): List<String> = raw(k).lines().map { it.trim() }.filter { it.isNotEmpty() }
    fun choice(k: String, options: List<String>): Int = options.indexOf(str(k)).let { if (it < 0) 0 else it }
}

class FileRef(val name: String, val size: Long, val open: () -> InputStream?)

/** 도구가 휴대폰 쪽에서 얻어야 하는 것들 (화면이 채워 주고, 시험에서는 NoHost) */
interface ToolHost {
    fun file(key: String): FileRef? = null
    /** 지금 연결의 DNS 서버들 */
    fun dnsServers(): List<String> = emptyList()
    fun gateway(): String? = null
    /** 내 Wi-Fi 의 내 IP 와 접두 길이 (모르면 null) */
    fun lanIp(): Pair<String, Int>? = null
    /** 연결 정보 한눈에 (이름 → 값) */
    fun netDetails(): List<Pair<String, String>> = emptyList()
    /** Wi-Fi 신호·속도 (권한·연결이 없으면 null) */
    fun wifiDetails(): List<Pair<String, String>>? = null
    /** 내 망 안 장비에 닿도록 Wi-Fi 망에 묶은 소켓을 만드는 함수 */
    fun lanSockets(): () -> Socket = { Socket() }
    /** UDP(DatagramSocket)를 Wi-Fi 망에 묶기 */
    fun bindDatagram(s: java.net.DatagramSocket) {}
}

object NoHost : ToolHost

class ToolEnv(val cancel: AtomicBoolean = AtomicBoolean(false), val progress: (String) -> Unit = {})

enum class ToolMode(val label: String) { OFFLINE("오프라인 계산"), ONLINE("인터넷 사용"), LAN("내 망 안") }

class NetTool(
    val id: String,
    val group: String,
    val title: String,
    val desc: String,
    val fields: List<Field> = emptyList(),
    val mode: ToolMode = ToolMode.OFFLINE,
    /** 인터넷·내 망으로 무엇을 보내는지 같은 안내 (화면 위쪽에 보임) */
    val note: String? = null,
    /** 실행 전에 한 번 더 확인받을 내용 (데이터 많이 쓰는 도구 등) */
    val confirm: String? = null,
    /** 열자마자 실행 (입력 칸이 없는 사전·표) */
    val auto: Boolean = false,
    /** 글자를 바꿀 때마다 바로 실행 (가벼운 오프라인 도구) */
    val live: Boolean = false,
    val runLabel: String = "실행",
    val run: (ToolInput, ToolHost, ToolEnv) -> ToolResult,
)

// ---------------------------------------------------------------- 도구를 짧게 정의하는 도우미

/** 모든 옵션을 직접 지정하는 도구 정의 */
fun tool(
    id: String, group: String, title: String, desc: String, fields: List<Field>, mode: ToolMode,
    note: String? = null, confirm: String? = null, auto: Boolean = false, live: Boolean = false, runLabel: String = "실행",
    run: (ToolInput, ToolHost, ToolEnv) -> ToolResult,
) = NetTool(id, group, title, desc, fields, mode, note, confirm, auto, live, runLabel, run)

/** 오프라인 계산 도구: 입력만 받아 결과를 돌려줌 */
fun calc(
    id: String, group: String, title: String, desc: String, vararg fields: Field,
    live: Boolean = fields.isNotEmpty(), auto: Boolean = fields.isEmpty(), run: (ToolInput) -> ToolResult,
) = NetTool(id, group, title, desc, fields.toList(), ToolMode.OFFLINE, null, null, auto, live, "계산") { i, _, _ -> run(i) }

/** 인터넷을 쓰는 도구 */
fun online(
    id: String, group: String, title: String, desc: String, vararg fields: Field,
    note: String? = null, confirm: String? = null, run: (ToolInput, ToolHost, ToolEnv) -> ToolResult,
) = NetTool(id, group, title, desc, fields.toList(), ToolMode.ONLINE, note, confirm, false, false, "실행", run)

/** 내 망 안 장비를 대상으로 하는 도구 */
fun lanTool(
    id: String, group: String, title: String, desc: String, vararg fields: Field,
    note: String? = null, run: (ToolInput, ToolHost, ToolEnv) -> ToolResult,
) = NetTool(id, group, title, desc, fields.toList(), ToolMode.LAN, note, null, false, false, "실행", run)

fun text(key: String, label: String, hint: String = "", default: String = "", chips: List<Pair<String, String>> = emptyList()) =
    Field(key, label, hint, default, FieldKind.TEXT, emptyList(), chips)

fun multi(key: String, label: String, hint: String = "", default: String = "", chips: List<Pair<String, String>> = emptyList()) =
    Field(key, label, hint, default, FieldKind.MULTILINE, emptyList(), chips)

fun choice(key: String, label: String, choices: List<String>, default: String = "") =
    Field(key, label, "", default.ifEmpty { choices.first() }, FieldKind.CHOICE, choices)

fun file(key: String, label: String = "파일") = Field(key, label, "", "", FieldKind.FILE)

/** 묶음(그룹) 이름: 도구 모음 화면의 칩 */
object NetGroups {
    const val IP = "IP·서브넷 계산"
    const val CONVERT = "변환·인코딩"
    const val HASH = "해시·토큰"
    const val DNS = "DNS·도메인"
    const val DIAG = "접속 진단"
    const val LAN = "내 망 점검"
    const val SPEED = "속도·용량 계산"
    const val WIFI = "무선(Wi-Fi) 계산"
    const val GEN = "설정 만들기"
    const val REF = "프로토콜 사전"
    const val CMD = "점검 순서·명령어"
    val ALL = listOf(IP, CONVERT, HASH, DNS, DIAG, LAN, SPEED, WIFI, GEN, REF, CMD)
}
