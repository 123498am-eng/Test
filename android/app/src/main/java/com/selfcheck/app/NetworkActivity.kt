package com.selfcheck.app

import android.app.AlertDialog
import android.content.res.ColorStateList
import android.graphics.Typeface
import android.os.Bundle
import android.os.SystemClock
import android.text.InputType
import android.view.Gravity
import android.view.View
import android.view.ViewGroup.LayoutParams.MATCH_PARENT
import android.view.ViewGroup.LayoutParams.WRAP_CONTENT
import android.view.WindowManager
import android.view.inputmethod.EditorInfo
import android.widget.Button
import android.widget.CheckBox
import android.widget.EditText
import android.widget.LinearLayout
import android.widget.ProgressBar
import android.widget.TextView
import java.io.File
import java.net.InetAddress
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicInteger
import java.util.concurrent.atomic.AtomicLong
import kotlin.concurrent.thread

/**
 * 네트워크 도구: 포트 검사 · 같은 Wi-Fi 기기 찾기 · 내 IP · 도메인↔IP · IP 정보(서브넷 계산).
 * 내가 관리하는 장비(공유기·NAS·서버·카메라)에 열린 문이 없는지 점검하는 용도입니다.
 * 검사는 평범한 TCP 연결 시도뿐이고, 내 망 밖 주소는 "내 장비이거나 허락받았음"을 확인한 뒤에만 검사합니다.
 */
class NetworkActivity : ColumnActivity() {
    companion object {
        val TOOLS = listOf(
            Triple("port_scan", "포트 검사", "IP(또는 도메인)를 넣으면 열려 있는 포트와 위험한 문을 찾아 줘요"),
            Triple("lan_scan", "같은 Wi-Fi 기기 찾기", "내 공유기에 연결된 기기들의 IP 를 찾아요"),
            Triple("my_ip", "내 IP 확인", "이 휴대폰의 내부 IP·공유기·DNS, 인터넷에서 보이는 공인 IP"),
            Triple("dns", "도메인 ↔ IP 변환", "도메인의 IP 주소, IP 에 등록된 이름 찾기"),
            Triple("ip_info", "IP 정보 · 서브넷 계산", "사설/공인 구분, 표기 변환, 192.168.0.0/24 같은 범위 계산"),
        )
        private val SHORT = mapOf("port_scan" to "포트 검사", "lan_scan" to "기기 찾기", "my_ip" to "내 IP", "dns" to "도메인 ↔ IP", "ip_info" to "IP 정보")

        /** 이번 실행 중에 확인한 내 공인 IP (내 IP 를 검사할 때는 허락 확인을 생략) */
        @Volatile var myPublicIp: String? = null
        private val consented: MutableSet<String> = java.util.Collections.synchronizedSet(HashSet())
    }

    private lateinit var tabBox: LinearLayout
    private lateinit var body: LinearLayout
    private var cancel = AtomicBoolean(false)
    private var scanStop: AtomicBoolean? = null
    internal var rows: List<NetRow> = emptyList()
    private var scanResults: LinearLayout? = null
    private var hostResults: LinearLayout? = null
    private var dnsResults: LinearLayout? = null
    private var infoResults: LinearLayout? = null
    private var current = ""

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setupColumn("네트워크 도구", "내 망·내 서버에 열린 포트와 IP 를 점검해요")
        rows = LocalNet.networks(this)
        tabBox = LinearLayout(this).apply { orientation = LinearLayout.VERTICAL }
        col.addView(tabBox, lp(top = 4))
        body = LinearLayout(this).apply { orientation = LinearLayout.VERTICAL }
        col.addView(body, lp(top = 8))
        val first = intent.getStringExtra("tool")?.takeIf { id -> TOOLS.any { it.first == id } } ?: "port_scan"
        showTool(first, intent.getStringExtra("target"))
    }

    override fun onDestroy() {
        cancel.set(true); scanStop?.set(true)
        window.clearFlags(WindowManager.LayoutParams.FLAG_KEEP_SCREEN_ON)
        super.onDestroy()
    }

    // ------------------------------------------------------------------ 공통
    private fun lp(top: Int = 0, bottom: Int = 0) = UiKit.params(top = top, bottom = bottom, ctx = this)

    /** 화면이 바뀌었거나 닫혔으면(c 가 취소됨) 결과를 그리지 않음 */
    private fun onUi(c: AtomicBoolean, f: () -> Unit) = runOnUiThread { if (!c.get() && !isFinishing && !isDestroyed) f() }

    private fun label(t: String) = UiKit.text(this, t, 13.5f, Pal.text, true)

    /** 안내 상자·작은 설명 (한글 낱말 가운데서 줄이 바뀌지 않게) */
    private fun note(t: String, warn: Boolean = false) = tip(UiKit.keepWords(t), warn)
    private fun small(t: String) = hint(UiKit.keepWords(t))

    /** "•" 목록 한 줄 (줄이 길어져도 글자가 점 아래로 돌아오지 않게) */
    private fun bullet(t: String): View = LinearLayout(this).apply {
        orientation = LinearLayout.HORIZONTAL; setPadding(0, dp(3), 0, dp(3))
        addView(UiKit.text(this@NetworkActivity, "•", 13f, Pal.text2), LinearLayout.LayoutParams(dp(14), WRAP_CONTENT))
        addView(UiKit.text(this@NetworkActivity, UiKit.keepWords(t), 13f, Pal.text2).apply { setLineSpacing(0f, 1.2f) }, LinearLayout.LayoutParams(0, WRAP_CONTENT, 1f))
    }

    private fun mono(t: String, sp: Float = 15f, color: Int = Pal.text) =
        UiKit.text(this, t, sp, color).apply { typeface = Typeface.MONOSPACE; setTextIsSelectable(true) }

    private fun input(hintText: String, text: String?): EditText = EditText(this).apply {
        hint = hintText
        inputType = InputType.TYPE_CLASS_TEXT or InputType.TYPE_TEXT_VARIATION_URI or InputType.TYPE_TEXT_FLAG_NO_SUGGESTIONS
        imeOptions = EditorInfo.IME_ACTION_GO
        if (!text.isNullOrEmpty()) setText(text)
    }.also { styleInput(it) }

    private fun EditText.onGo(f: () -> Unit) {
        setOnEditorActionListener { _, a, _ -> if (a == EditorInfo.IME_ACTION_GO || a == EditorInfo.IME_ACTION_DONE) { f(); true } else false }
    }

    private fun progressBar() = ProgressBar(this, null, android.R.attr.progressBarStyleHorizontal).apply {
        max = 1000; isIndeterminate = false
        progressTintList = ColorStateList.valueOf(Pal.primary); progressBackgroundTintList = ColorStateList.valueOf(0xFFD9DEEC.toInt())
    }

    private fun pill(t: String, fg: Int, bg: Int) = TextView(this).apply {
        text = t; textSize = 11.5f; setTextColor(fg); typeface = Typeface.DEFAULT_BOLD
        setPadding(dp(9), dp(3), dp(9), dp(3)); background = UiKit.rounded(this@NetworkActivity, bg, 20f)
    }

    private fun kindPill(k: IpKind) = when {
        k.blocked -> pill(k.label.substringBefore(" ("), Pal.bad, Pal.badSoft)
        k == IpKind.PUBLIC -> pill("공인", Pal.primaryDark, Pal.primarySoft)
        k == IpKind.CGNAT -> pill("통신사 공용", Pal.warn, Pal.warnSoft)
        else -> pill(k.label.substringBefore(" ("), Pal.good, Pal.goodSoft)
    }

    /** 이름: 값 한 줄 (눌러서 복사) */
    private fun kv(label: String, value: String, copyable: Boolean = true, monoValue: Boolean = true): View = LinearLayout(this).apply {
        orientation = LinearLayout.HORIZONTAL; setPadding(0, dp(6), 0, dp(6))
        addView(UiKit.text(this@NetworkActivity, label, 13.5f, Pal.text2), LinearLayout.LayoutParams(dp(96), WRAP_CONTENT))
        addView(UiKit.text(this@NetworkActivity, value, 14.5f, Pal.text).apply { if (monoValue) typeface = Typeface.MONOSPACE }, LinearLayout.LayoutParams(0, WRAP_CONTENT, 1f))
        if (copyable) { isClickable = true; setOnClickListener { copy(value, label) } }
    }

    private fun scrollTo(v: View) { scroll.post { scroll.smoothScrollTo(0, (body.top + v.top - dp(8)).coerceAtLeast(0)) } }

    private fun refreshRows() { rows = LocalNet.networks(this) }

    /** 실행/중지 버튼과 진행 표시 한 벌 */
    private inner class RunUi(val btn: Button, val box: View, val bar: ProgressBar, val status: TextView, val idle: String, val busy: String) {
        fun running(on: Boolean) {
            btn.text = if (on) busy else idle
            UiKit.styleButton(btn, if (on) BtnStyle.DANGER else BtnStyle.PRIMARY)
            box.visibility = if (on) View.VISIBLE else View.GONE
        }
        fun progress(done: Int, total: Int, text: String) { bar.progress = if (total <= 0) 0 else (done * 1000L / total).toInt(); status.text = text }
    }

    private fun runUi(card: LinearLayout, idle: String, busy: String): RunUi {
        val btn = primaryButton(idle) {}
        card.addView(btn, lp(top = 12))
        val bar = progressBar(); val status = small("")
        val box = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL; visibility = View.GONE
            addView(bar, LinearLayout.LayoutParams(MATCH_PARENT, dp(8)))
            addView(status, lp(top = 6))
        }
        card.addView(box, lp(top = 12))
        return RunUi(btn, box, bar, status, idle, busy)
    }

    // ------------------------------------------------------------------ 도구 전환
    internal fun showTool(id: String, target: String? = null) {
        cancel.set(true); scanStop?.set(true); scanStop = null
        cancel = AtomicBoolean(false)
        window.clearFlags(WindowManager.LayoutParams.FLAG_KEEP_SCREEN_ON)
        current = id
        tabBox.removeAllViews()
        tabBox.addView(UiKit.chipRow(this, TOOLS.map { t -> UiKit.chip(this, SHORT[t.first] ?: t.second, t.first == id) { if (t.first != current) showTool(t.first) } }))
        body.removeAllViews()
        scanResults = null; hostResults = null; dnsResults = null; infoResults = null
        when (id) {
            "port_scan" -> portScan(target)
            "lan_scan" -> lanScan()
            "my_ip" -> myIp()
            "dns" -> dnsTool(target)
            "ip_info" -> ipInfo(target)
        }
        scroll.scrollTo(0, 0)
    }

    // ================================================================== 포트 검사
    private fun portScan(prefill: String?) {
        body.addView(note("내가 관리하는 장비(공유기·NAS·서버·카메라)에 의도치 않게 열린 문이 없는지 점검하는 도구예요. 연결을 시도해서 대답하는지만 확인하고, 남의 장비에는 쓰지 마세요."))
        val card = UiKit.card(this)
        body.addView(card, lp(top = 10))
        card.addView(label("검사할 IP 또는 도메인"))
        val target = input("예: 192.168.0.1 또는 example.com", prefill)
        card.addView(target, lp(top = 6))

        // 자주 검사하는 대상 채우기
        val quick = ArrayList<Pair<String, String>>()
        LocalNet.lan(rows)?.gateway?.let { quick += "공유기 $it" to it }
        quick += "이 휴대폰" to "127.0.0.1"
        myPublicIp?.let { quick += "내 공인 IP" to it }
        card.addView(UiKit.chipRow(this, quick.map { (t, v) -> UiKit.chip(this, t, false) { target.setText(v); target.setSelection(v.length) } }), lp(top = 8))

        card.addView(label("검사할 포트").apply { setPadding(0, dp(14), 0, 0) })
        var profile = 0
        val custom = input("예: 22,80,443,8000-8100", null).apply { visibility = View.GONE }
        val profileNote = small("").apply { setPadding(0, dp(6), 0, 0) }
        val notes = listOf(
            "공유기·NAS·카메라·서버가 자주 쓰는 포트와 위험한 포트 ${Ports.QUICK.size}개를 빠르게 봐요.",
            "잘 알려진 포트 1,024개를 모두 봐요.",
            "원하는 포트만 봐요. 내 망 밖 주소는 한 번에 ${"%,d".format(Ports.MAX_REMOTE)}개까지예요.",
            "1–65535 전부 봐요. 내 망 안의 장비만 가능하고, 몇 분 걸릴 수 있어요.",
        )
        val names = listOf("빠른 ${Ports.QUICK.size}개", "1–1024", "직접 입력", "전체")
        lateinit var chips: List<TextView>
        fun pick(i: Int) {
            profile = i
            chips.forEachIndexed { j, c -> UiKit.setChip(c, j == i) }
            custom.visibility = if (i == 2) View.VISIBLE else View.GONE
            profileNote.text = UiKit.keepWords(notes[i])
        }
        chips = names.mapIndexed { i, n -> UiKit.chip(this, n, i == 0) { pick(i) } }
        card.addView(UiKit.chipRow(this, chips), lp(top = 6))
        card.addView(custom, lp(top = 8))
        card.addView(profileNote)
        profileNote.text = UiKit.keepWords(notes[0])

        val bannerRow = UiKit.switchRow(this, "🔎", "서비스 정보 읽기", UiKit.keepWords("열린 포트에서 SSH·웹 서버 이름 같은 인사말을 읽어요"), true) {}
        card.addView(bannerRow.view, lp(top = 8))

        val ui = runUi(card, "검사 시작", "중지")
        val res = LinearLayout(this).apply { orientation = LinearLayout.VERTICAL }
        body.addView(res, lp(top = 12))
        scanResults = res

        var stopFlag: AtomicBoolean? = null
        ui.btn.setOnClickListener {
            val running = stopFlag
            if (running != null) { running.set(true); ui.status.text = "멈추는 중..."; return@setOnClickListener }
            res.removeAllViews()
            val flag = AtomicBoolean(false)
            stopFlag = flag; scanStop = flag
            ui.running(true)
            beginScan(target.text.toString(), profile, custom.text.toString(), bannerRow.sw.isChecked, ui, flag) { stopFlag = null; ui.running(false) }
        }
        target.onGo { ui.btn.performClick() }
    }

    /** 1) 주소 확인(도메인이면 IP 로 바꿈) → 2) 포트 목록·허락 확인 → 3) 검사 */
    private fun beginScan(input: String, profile: Int, customSpec: String, banner: Boolean, ui: RunUi, stop: AtomicBoolean, done: () -> Unit) {
        val c = cancel
        val host = HostInput.host(input)
        if (host.isEmpty()) { toast("검사할 IP 나 도메인을 입력하세요"); done(); return }
        ui.progress(0, 0, "주소 확인 중...")
        thread {
            var addr = IpUtil.parse(host)
            var via: String? = null
            if (addr == null) {
                if (!HostInput.isPlausibleDomain(host)) {
                    onUi(c) { scanFail("\"$host\" 은(는) IP 주소나 도메인 이름 형식이 아니에요.\n예: 192.168.0.1 · 2001:db8::1 · example.com", done) }; return@thread
                }
                val list = Dns.resolve(host)
                addr = list.firstOrNull()
                if (addr == null) { onUi(c) { scanFail("\"$host\" 의 IP 를 찾지 못했어요. 도메인 이름과 인터넷 연결을 확인하세요.", done) }; return@thread }
                via = "$host → ${IpUtil.format(addr)}" + if (list.size > 1) " 외 ${list.size - 1}개" else ""
            }
            val a = addr
            val n = via
            onUi(c) { prepareScan(a, IpUtil.classify(a), n, profile, customSpec, banner, ui, stop, done) }
        }
    }

    private fun scanFail(msg: String, done: () -> Unit) {
        scanResults?.let { it.removeAllViews(); it.addView(note(msg, warn = true)) }
        done()
    }

    private fun prepareScan(addr: InetAddress, kind: IpKind, via: String?, profile: Int, customSpec: String, banner: Boolean, ui: RunUi, stop: AtomicBoolean, done: () -> Unit) {
        val ip = IpUtil.format(addr)
        if (kind.blocked) { scanFail("$ip · ${kind.label}\n${kind.note}", done); return }
        val max = if (kind.local) Ports.MAX_ALL else Ports.MAX_REMOTE
        val ports: List<Int> = when (profile) {
            0 -> Ports.QUICK
            1 -> (1..1024).toList()
            3 -> {
                if (!kind.local) { scanFail("전체 포트(1–65535) 검사는 내 망 안의 장비만 할 수 있어요. 내 망 밖 주소는 한 번에 ${"%,d".format(Ports.MAX_REMOTE)}개까지 검사해요.", done); return }
                (1..Ports.MAX_ALL).toList()
            }
            else -> {
                val spec = Ports.parse(customSpec, max)
                if (spec.error != null) { scanFail(spec.error, done); return }
                spec.ports
            }
        }
        val own = ip == myPublicIp || ip in consented
        if (kind.needsConsent && !own) askConsent(ip, kind, { runScan(addr, kind, ports, banner, via, ui, stop, done) }, done)
        else runScan(addr, kind, ports, banner, via, ui, stop, done)
    }

    /** 내 망 밖(인터넷·통신사 공용) 주소는 내 장비이거나 허락받았다고 확인해야 검사 */
    private fun askConsent(ip: String, kind: IpKind, onYes: () -> Unit, onNo: () -> Unit) {
        val box = LinearLayout(this).apply { orientation = LinearLayout.VERTICAL; setPadding(dp(22), dp(8), dp(22), 0) }
        box.addView(TextView(this).apply {
            text = "$ip 는 ${kind.label} 예요.\n\n내 장비(내 서버, 내 공유기의 인터넷 주소 등)이거나 점검을 허락받은 곳만 검사하세요. 허락 없이 남의 장비를 검사하면 법에 걸릴 수 있고, 상대 장비에는 접속 시도 기록이 남아요."
            textSize = 14.5f; setTextColor(Pal.text); setLineSpacing(0f, 1.15f)
        })
        val cb = CheckBox(this).apply { text = "내 장비이거나 점검을 허락받았어요"; setPadding(dp(6), dp(14), 0, dp(6)) }
        box.addView(cb)
        val d = AlertDialog.Builder(this).setTitle("인터넷 주소 검사").setView(box)
            .setPositiveButton("검사 시작") { _, _ -> consented += ip; onYes() }
            .setNegativeButton("취소") { _, _ -> onNo() }
            .setOnCancelListener { onNo() }
            .create()
        d.setOnShowListener { d.getButton(AlertDialog.BUTTON_POSITIVE)?.isEnabled = false }
        cb.setOnCheckedChangeListener { _, on -> d.getButton(AlertDialog.BUTTON_POSITIVE)?.isEnabled = on }
        d.show()
    }

    private fun runScan(addr: InetAddress, kind: IpKind, ports: List<Int>, banner: Boolean, via: String?, ui: RunUi, stop: AtomicBoolean, done: () -> Unit) {
        val c = cancel
        window.addFlags(WindowManager.LayoutParams.FLAG_KEEP_SCREEN_ON)
        // 내 망 안 장비는 Wi-Fi 망에 묶은 소켓으로 (모바일 데이터가 기본 연결이어도 공유기에 닿도록)
        val lan = if (kind.local && kind != IpKind.LOOPBACK) LocalNet.lan(rows) else null
        val opt = if (kind.local) ScanOptions(timeoutMs = 700, threads = 96, banner = banner, newSocket = LocalNet.socketFactory(lan))
        else ScanOptions(timeoutMs = 1500, threads = 24, banner = banner)
        val open = AtomicInteger(); val last = AtomicLong(0)
        ui.progress(0, ports.size, "${IpUtil.format(addr)} 검사 중... 0/${"%,d".format(ports.size)}")
        thread {
            val rep = PortScanner.scan(addr, ports, opt, stop) { d, t, found ->
                if (found != null) open.incrementAndGet()
                val now = SystemClock.uptimeMillis()
                if (d == t || now - last.get() > 150) { last.set(now); onUi(c) { ui.progress(d, t, "검사 중... ${"%,d".format(d)}/${"%,d".format(t)} · 열린 포트 ${open.get()}개") } }
            }
            onUi(c) {
                window.clearFlags(WindowManager.LayoutParams.FLAG_KEEP_SCREEN_ON)
                done()
                renderScan(rep, kind, via)
                scanResults?.let { scrollTo(it) }
            }
        }
    }

    private fun portCard(r: PortResult): View {
        val info = Ports.describe(r.port)
        val risk = info?.risk ?: 0
        val c = UiKit.card(this, 14, 16f)
        val top = LinearLayout(this).apply { orientation = LinearLayout.HORIZONTAL; gravity = Gravity.CENTER_VERTICAL }
        top.addView(UiKit.text(this, "${r.port}", 19f, Pal.text, true))
        top.addView(UiKit.text(this, info?.name ?: "알 수 없는 서비스", 14f, Pal.text2).apply { setPadding(dp(10), 0, dp(8), 0) }, LinearLayout.LayoutParams(0, WRAP_CONTENT, 1f))
        top.addView(when (risk) { 2 -> pill("위험", Pal.bad, Pal.badSoft); 1 -> pill("주의", Pal.warn, Pal.warnSoft); else -> pill("보통", Pal.text2, Pal.surface2) })
        c.addView(top)
        r.banner?.let { c.addView(UiKit.text(this, "응답: $it", 12.5f, Pal.text2).apply { typeface = Typeface.MONOSPACE; setPadding(0, dp(6), 0, 0) }) }
        if (info != null && info.advice.isNotBlank())
            c.addView(UiKit.text(this, UiKit.keepWords(info.advice), 12.5f, if (risk == 2) Pal.bad else if (risk == 1) Pal.warn else Pal.text2).apply { setPadding(0, dp(6), 0, 0) })
        return c
    }

    /** 검사 결과 그리기 (시험·화면 그리기에서도 부름) */
    internal fun renderScan(rep: ScanReport, kind: IpKind?, via: String? = null) {
        val box = scanResults ?: return
        box.removeAllViews()
        val open = rep.open.sortedWith(compareByDescending<PortResult> { Ports.describe(it.port)?.risk ?: 0 }.thenBy { it.port })
        val worst = rep.worstRisk
        val dangerCount = open.count { (Ports.describe(it.port)?.risk ?: 0) == 2 }
        val (fg, bg) = when {
            open.isEmpty() -> Pal.good to Pal.goodSoft
            worst >= 2 -> Pal.bad to Pal.badSoft
            worst == 1 -> Pal.warn to Pal.warnSoft
            else -> Pal.primaryDark to Pal.primarySoft
        }
        val head = UiKit.card(this, 16, 18f, bg)
        head.addView(UiKit.text(this, if (open.isEmpty()) "열린 포트가 없어요" else "열린 포트 ${open.size}개" + if (dangerCount > 0) " · 위험 ${dangerCount}개" else "", 20f, fg, true))
        head.addView(UiKit.text(this, rep.target + (via?.let { "  ($it)" } ?: ""), 14f, Pal.text).apply { typeface = Typeface.MONOSPACE; setPadding(0, dp(6), 0, 0) })
        kind?.let { head.addView(UiKit.text(this, it.label, 12.5f, Pal.text2).apply { setPadding(0, dp(2), 0, 0) }) }
        head.addView(UiKit.text(this, "검사 ${"%,d".format(rep.results.size)}개 · 닫힘 ${"%,d".format(rep.closedCount)} · 응답 없음 ${"%,d".format(rep.noReplyCount)}" +
            (if (rep.errorCount > 0) " · 오류 ${rep.errorCount}" else "") + " · ${"%.1f".format(rep.elapsedMs / 1000.0)}초", 12.5f, Pal.text2).apply { setPadding(0, dp(4), 0, 0) })
        val sentence = when {
            rep.cancelled -> "중간에 멈춰서 ${"%,d".format(rep.results.size)}/${"%,d".format(rep.requested)}개만 검사했어요."
            open.isNotEmpty() && worst >= 2 -> "인터넷에 열려 있으면 안 되는 서비스가 있어요. 필요 없다면 끄고, 필요하다면 접속 IP 를 제한하거나 VPN 뒤에 두세요."
            open.isNotEmpty() -> "열린 포트가 모두 의도한 것인지 확인해 보세요. 쓰지 않는 서비스는 끄는 것이 안전해요."
            rep.hostAlive -> "장비는 응답했지만 검사한 포트는 모두 닫혀 있어요."
            rep.results.isNotEmpty() && rep.noReplyCount == rep.results.size -> "모든 포트가 응답이 없어요. 방화벽이 막고 있거나, 장비가 꺼져 있거나, 다른 망에 있을 수 있어요."
            rep.errorCount > 0 -> "네트워크 오류가 있었어요: " + (rep.results.firstOrNull { it.state == PortState.ERROR }?.detail ?: "연결 상태를 확인하세요")
            else -> ""
        }
        if (sentence.isNotEmpty()) head.addView(UiKit.text(this, UiKit.keepWords(sentence), 13.5f, Pal.text).apply { setLineSpacing(0f, 1.15f); setPadding(0, dp(10), 0, 0) })
        box.addView(head)
        if (kind == IpKind.PUBLIC && rep.target == myPublicIp)
            box.addView(note("같은 공유기(Wi-Fi) 안에서 내 공인 IP 를 검사하면 결과가 정확하지 않을 수 있어요. 모바일 데이터로 바꿔서 다시 검사하면 밖에서 보이는 모습을 알 수 있어요."))

        if (open.isNotEmpty()) box.addView(UiKit.sectionTitle(this, "열린 포트", "위험한 순서로 보여요"))
        for (r in open.take(200)) box.addView(portCard(r), lp(bottom = 8))
        if (open.size > 200) box.addView(small("… 외 ${open.size - 200}개 (결과 복사로 전체를 볼 수 있어요)"))
        box.addView(buttons("결과 복사" to { copy(rep.toText(), "포트 검사 결과") }), lp(top = 12))
        box.addView(small("연결을 시도해 대답을 확인한 결과예요. 방화벽이 응답을 숨기면 열려 있어도 안 보일 수 있어요.").apply { setPadding(dp(4), dp(10), dp(4), 0) })
    }

    // ================================================================== 같은 Wi-Fi 기기 찾기
    private fun lanScan() {
        body.addView(note("내 집·사무실처럼 내가 쓰는 Wi-Fi 에서 켜져 있는 기기들의 IP 를 찾아요. 공용 Wi-Fi(카페·호텔 등)나 남의 망에서는 쓰지 마세요."))
        val card = UiKit.card(this)
        body.addView(card, lp(top = 10))
        val lan = LocalNet.lan(rows)
        val me = lan?.ipv4?.let { IpUtil.parseV4(it) }?.let { IpUtil.v4ToLong(it) }
        if (lan == null || me == null) {
            card.addView(UiKit.text(this, "Wi-Fi(또는 이더넷)에 연결되어 있지 않아요", 16f, Pal.text, true))
            card.addView(small("모바일 데이터에서는 같은 공유기에 붙은 기기를 찾을 수 없어요. Wi-Fi 에 연결한 뒤 다시 눌러 주세요.").apply { setPadding(0, dp(6), 0, 0) })
            card.addView(button("새로 고침") { refreshRows(); showTool("lan_scan") }, lp(top = 12))
            return
        }
        val (sub, trimmed) = Lan.range(me, lan.prefix ?: 24)
        card.addView(kv("연결", lan.transport + (lan.ifName?.let { " ($it)" } ?: ""), copyable = false, monoValue = false))
        card.addView(kv("내 IP", "${lan.ipv4}/${lan.prefix ?: 24}"))
        card.addView(kv("공유기", lan.gateway ?: "알 수 없음"))
        card.addView(kv("검사 범위", "${IpUtil.v4Text(sub.first)} ~ ${IpUtil.v4Text(sub.last)}  (${sub.hostCount}개)"))
        if (trimmed) card.addView(small("큰 망이라 내 주소가 속한 /24 범위(254개)만 검사해요.").apply { setPadding(0, dp(4), 0, 0) })
        if (rows.any { it.transport == "VPN" }) card.addView(note("VPN 이 켜져 있어요. 같은 Wi-Fi 기기는 VPN 을 끄고 찾는 게 정확해요.", warn = true))

        val ui = runUi(card, "기기 찾기", "중지")
        val res = LinearLayout(this).apply { orientation = LinearLayout.VERTICAL }
        body.addView(res, lp(top = 12))
        hostResults = res
        var stopFlag: AtomicBoolean? = null
        ui.btn.setOnClickListener {
            val running = stopFlag
            if (running != null) { running.set(true); ui.status.text = "멈추는 중..."; return@setOnClickListener }
            res.removeAllViews()
            val flag = AtomicBoolean(false)
            stopFlag = flag; scanStop = flag
            ui.running(true)
            runLan(lan, sub, me, ui, flag) { stopFlag = null; ui.running(false) }
        }
    }

    private fun runLan(lan: NetRow, sub: Subnet, me: Long, ui: RunUi, stop: AtomicBoolean, done: () -> Unit) {
        val c = cancel
        window.addFlags(WindowManager.LayoutParams.FLAG_KEEP_SCREEN_ON)
        val addrs = Lan.addresses(sub).filter { it != me }.map { InetAddress.getByAddress(IpUtil.longToV4(it)) }
        val found = AtomicInteger(); val last = AtomicLong(0)
        ui.progress(0, addrs.size, "찾는 중... 0/${addrs.size}")
        thread {
            val hosts = LanScanner.sweep(addrs, threads = 96, icmp = true, newSocket = LocalNet.socketFactory(lan), cancel = stop) { d, t, h ->
                if (h != null) found.incrementAndGet()
                val now = SystemClock.uptimeMillis()
                if (d == t || now - last.get() > 150) { last.set(now); onUi(c) { ui.progress(d, t, "찾는 중... $d/$t · 기기 ${found.get()}대") } }
            }
            // 안드로이드 9 이하에서는 이웃 기기 표(ARP)에서 MAC 주소와 응답하지 않던 기기도 알 수 있음 (10 이상은 읽기 막힘)
            val arp = runCatching { Arp.parse(File("/proc/net/arp").readText()) }.getOrDefault(emptyList())
                .filter { e -> IpUtil.parseV4(e.ip)?.let { IpUtil.v4ToLong(it) }?.let { it in sub.network..sub.broadcast && it != me } == true }
            val merged = mergeArp(hosts, arp)
            onUi(c) {
                window.clearFlags(WindowManager.LayoutParams.FLAG_KEEP_SCREEN_ON)
                done()
                renderHosts(merged, lan.ipv4, lan.gateway, stop.get())
                hostResults?.let { scrollTo(it) }
            }
        }
    }

    private fun mergeArp(hosts: List<LanHost>, arp: List<ArpEntry>): List<LanHost> {
        val byIp = arp.associateBy { it.ip }
        val out = hosts.map { h -> byIp[h.ip]?.let { LanHost(h.ip, h.hostName, h.ms, h.openPorts, h.how, it.mac) } ?: h }.toMutableList()
        for (e in arp) if (out.none { it.ip == e.ip }) out += LanHost(e.ip, null, 0, emptyList(), "이웃 기기 표(ARP)에 있음", e.mac)
        return out.sortedBy { IpUtil.parseV4(it.ip)?.let { b -> IpUtil.v4ToLong(b) } ?: Long.MAX_VALUE }
    }

    private fun emojiFor(h: LanHost, gateway: String?): String = when {
        h.ip == gateway -> "📶"
        554 in h.openPorts -> "📷"
        h.openPorts.any { it == 9100 || it == 515 || it == 631 } -> "🖨️"
        h.openPorts.any { it == 8008 || it == 8009 || it == 7000 } -> "📺"
        62078 in h.openPorts -> "📱"
        else -> "💻"
    }

    /** 찾은 기기 목록 그리기 (시험·화면 그리기에서도 부름) */
    internal fun renderHosts(hosts: List<LanHost>, meIp: String?, gateway: String?, stopped: Boolean = false) {
        val box = hostResults ?: return
        box.removeAllViews()
        val total = hosts.size + if (meIp != null) 1 else 0
        box.addView(UiKit.sectionTitle(this, "찾은 기기 ${total}대", if (stopped) "중간에 멈췄어요" else "눌러서 그 기기의 포트를 검사해요"))
        if (meIp != null) box.addView(UiKit.listCard(this, "📱", meIp, "이 휴대폰", Pal.primarySoft) { copy(meIp, "내 IP") }, lp(bottom = 8))
        for (h in hosts) {
            val tags = ArrayList<String>()
            if (h.ip == gateway) tags += "공유기"
            h.hostName?.let { tags += it }
            if (h.openPorts.isNotEmpty()) tags += "열린 포트 " + h.openPorts.joinToString(", ")
            h.mac?.let { tags += "MAC $it" + if (Arp.isRandomMac(it)) " (임의 주소)" else "" }
            if (tags.isEmpty() || (tags.size == 1 && h.ip == gateway)) tags += h.how
            box.addView(UiKit.listCard(this, emojiFor(h, gateway), h.ip, tags.joinToString(" · "), if (h.ip == gateway) Pal.warnSoft else Pal.primarySoft) { showTool("port_scan", h.ip) }, lp(bottom = 8))
        }
        if (hosts.isEmpty()) box.addView(note("이 휴대폰 말고는 응답한 기기를 찾지 못했어요. 기기가 꺼져 있거나, 모든 연결을 막고 있을 수 있어요. 같은 Wi-Fi 인지(게스트 망은 서로 막혀 있어요) 확인해 보세요.", warn = true))
        box.addView(small("핑이나 포트 연결에 응답하는 기기만 보여요. 절전 중이거나 모든 연결을 막는 기기는 빠질 수 있어요. 안드로이드 10 이상에서는 앱이 다른 기기의 MAC 주소를 읽을 수 없어요.").apply { setPadding(dp(4), dp(10), dp(4), 0) })
    }

    // ================================================================== 내 IP
    private fun myIp() {
        renderMyIp(rows, LocalNet.interfaces())
    }

    /** 내 IP 화면 그리기 (시험·화면 그리기에서도 부름) */
    internal fun renderMyIp(nets: List<NetRow>, ifaces: List<IfaceInfo>) {
        body.removeAllViews()
        if (nets.isEmpty()) body.addView(note("연결된 네트워크를 찾지 못했어요. Wi-Fi 나 모바일 데이터가 켜져 있는지 확인하세요.", warn = true))
        for (r in nets) {
            val c = UiKit.card(this)
            val top = LinearLayout(this).apply { orientation = LinearLayout.HORIZONTAL; gravity = Gravity.CENTER_VERTICAL }
            top.addView(UiKit.text(this, r.transport, 16.5f, Pal.text, true), LinearLayout.LayoutParams(0, WRAP_CONTENT, 1f))
            if (r.isDefault) top.addView(pill("기본 연결", Pal.primaryDark, Pal.primarySoft))
            c.addView(top)
            r.ipv4?.let { c.addView(kv("내 IP", "$it/${r.prefix ?: 24}")) }
            for (v6 in r.ipv6.take(3)) c.addView(kv("IPv6", v6))
            r.gateway?.let { c.addView(kv("공유기", it)) }
            if (r.dns.isNotEmpty()) c.addView(kv("DNS 서버", r.dns.take(3).joinToString("\n")))
            r.ifName?.let { c.addView(kv("장치", it, copyable = false)) }
            c.addView(small("값을 누르면 복사돼요").apply { setPadding(0, dp(4), 0, 0); textSize = 11.5f; setTextColor(Pal.text3) })
            body.addView(c, lp(top = 10))
        }

        // 인터넷에서 보이는 공인 IP: 누를 때만 인터넷에 물어봄
        val pub = UiKit.card(this)
        pub.addView(UiKit.text(this, "인터넷에서 보이는 내 IP (공인 IP)", 16.5f, Pal.text, true))
        val value = mono(myPublicIp ?: "아직 확인하지 않았어요", 20f, if (myPublicIp != null) Pal.text else Pal.text3).apply { setPadding(0, dp(10), 0, 0) }
        pub.addView(value)
        val kindLine = UiKit.text(this, "", 12.5f, Pal.text2).apply { setPadding(0, dp(4), 0, 0) }
        pub.addView(kindLine)
        fun showKind(ip: String) {
            IpUtil.parse(ip)?.let { a -> val k = IpUtil.classify(a); kindLine.text = UiKit.keepWords(k.label + " — " + k.note) }
        }
        myPublicIp?.let { showKind(it) }
        pub.addView(small("누르면 api.ipify.org 같은 \"IP 알려 주는 서비스\"에 요청해서 알아내요. 요청에는 내 IP 외에 다른 정보를 담지 않고, 누르기 전에는 인터넷에 접속하지 않아요.").apply { setPadding(0, dp(8), 0, 0) })
        val btn = primaryButton(if (myPublicIp == null) "공인 IP 확인" else "다시 확인") {}
        pub.addView(btn, lp(top = 12))
        val act = LinearLayout(this).apply { orientation = LinearLayout.HORIZONTAL; visibility = if (myPublicIp != null) View.VISIBLE else View.GONE }
        act.addView(button("복사") { myPublicIp?.let { copy(it, "공인 IP") } }, LinearLayout.LayoutParams(0, WRAP_CONTENT, 1f))
        act.addView(button("이 IP 포트 검사") { myPublicIp?.let { showTool("port_scan", it) } }, LinearLayout.LayoutParams(0, WRAP_CONTENT, 1f).apply { leftMargin = dp(8) })
        pub.addView(act, lp(top = 8))
        btn.setOnClickListener {
            val c = cancel
            btn.isEnabled = false; btn.text = "확인 중..."
            thread {
                val r = PublicIp.fetch()
                onUi(c) {
                    btn.isEnabled = true; btn.text = "다시 확인"
                    if (r == null) { toast("확인하지 못했어요. 인터넷 연결을 확인하세요") }
                    else { myPublicIp = r.first; value.text = r.first; value.setTextColor(Pal.text); showKind(r.first); act.visibility = View.VISIBLE }
                }
            }
        }
        body.addView(pub, lp(top = 10))

        val why = UiKit.card(this)
        why.addView(UiKit.text(this, "내부 IP 와 공인 IP 의 차이", 15f, Pal.text, true))
        why.addView(bullet("내부 IP(192.168.x.x 등): 공유기 안에서만 쓰는 주소예요."), lp(top = 8))
        why.addView(bullet("공인 IP: 인터넷에서 우리 집(공유기)으로 보이는 주소예요. 같은 공유기에 붙은 기기는 모두 같은 공인 IP 를 써요."))
        why.addView(bullet("IP 주소만으로는 누구인지, 정확히 어디에 사는지는 알 수 없어요."))
        body.addView(why, lp(top = 10))

        if (ifaces.isNotEmpty()) {
            val dev = UiKit.card(this)
            dev.addView(UiKit.text(this, "이 기기의 네트워크 장치", 15f, Pal.text, true))
            for (i in ifaces.take(8)) dev.addView(kv(i.label, i.name + "\n" + i.addrs.take(2).joinToString("\n")))
            dev.addView(small("안드로이드 버전에 따라 일부만 보일 수 있어요.").apply { setPadding(0, dp(4), 0, 0); textSize = 11.5f; setTextColor(Pal.text3) })
            body.addView(dev, lp(top = 10))
        }
        body.addView(button("새로 고침") { refreshRows(); showTool("my_ip") }, lp(top = 10))
    }

    // ================================================================== 도메인 ↔ IP
    private fun dnsTool(prefill: String?) {
        body.addView(note("도메인(example.com)을 넣으면 IP 주소를, IP 를 넣으면 등록된 이름(역방향 조회)을 찾아요. 주소창에서 복사한 \"https://…\" 주소도 돼요."))
        val card = UiKit.card(this)
        body.addView(card, lp(top = 10))
        card.addView(label("도메인 또는 IP"))
        val et = input("예: example.com 또는 8.8.8.8", prefill)
        card.addView(et, lp(top = 6))
        val btn = primaryButton("찾기") {}
        card.addView(btn, lp(top = 12))
        val res = LinearLayout(this).apply { orientation = LinearLayout.VERTICAL }
        body.addView(res, lp(top = 12))
        dnsResults = res

        fun go() {
            val host = HostInput.host(et.text.toString())
            if (host.isEmpty()) { toast("도메인이나 IP 를 입력하세요"); return }
            val c = cancel
            res.removeAllViews(); res.addView(small("찾는 중..."))
            btn.isEnabled = false
            thread {
                val t0 = SystemClock.uptimeMillis()
                val ip = IpUtil.parse(host)
                if (ip != null) {
                    val name = Dns.reverse(ip, 4000)
                    onUi(c) { btn.isEnabled = true; renderDns(host, listOf(ip), listOf(name), SystemClock.uptimeMillis() - t0, true) }
                } else if (!HostInput.isPlausibleDomain(host)) {
                    onUi(c) { btn.isEnabled = true; res.removeAllViews(); res.addView(note("\"$host\" 은(는) 도메인 이름이나 IP 형식이 아니에요.", warn = true)) }
                } else {
                    val list = Dns.resolve(host, 7000).take(8)
                    val names = arrayOfNulls<String>(list.size)
                    list.mapIndexed { i, a -> thread { names[i] = Dns.reverse(a, 1500) } }.forEach { it.join(2500) }
                    onUi(c) { btn.isEnabled = true; renderDns(host, list, names.toList(), SystemClock.uptimeMillis() - t0, false) }
                }
            }
        }
        btn.setOnClickListener { go() }
        et.onGo { go() }
        if (!prefill.isNullOrEmpty()) btn.post { go() }
    }

    /** 이름 조회 결과 그리기 (시험·화면 그리기에서도 부름) */
    internal fun renderDns(host: String, addrs: List<InetAddress>, names: List<String?>, ms: Long, isIp: Boolean) {
        val res = dnsResults ?: return
        res.removeAllViews()
        if (addrs.isEmpty()) { res.addView(note("\"$host\" 의 IP 를 찾지 못했어요. 도메인 이름이 맞는지, 인터넷에 연결돼 있는지 확인하세요.", warn = true)); return }
        val v4 = addrs.count { it.address.size == 4 }
        res.addView(UiKit.sectionTitle(this, if (isIp) "이름 조회 결과" else "$host 의 IP 주소", if (isIp) "${ms}ms" else "IPv4 ${v4}개 · IPv6 ${addrs.size - v4}개 · ${ms}ms"))
        addrs.forEachIndexed { i, a ->
            val ip = IpUtil.format(a); val k = IpUtil.classify(a)
            val c = UiKit.card(this, 14, 16f)
            val top = LinearLayout(this).apply { orientation = LinearLayout.HORIZONTAL; gravity = Gravity.CENTER_VERTICAL }
            top.addView(mono(ip, if (ip.length > 22) 13f else 16f), LinearLayout.LayoutParams(0, WRAP_CONTENT, 1f).apply { rightMargin = dp(8) })
            top.addView(kindPill(k))
            c.addView(top)
            c.addView(UiKit.text(this, names.getOrNull(i)?.let { "이름: $it" } ?: "등록된 이름(역방향 조회) 없음", 13f, Pal.text2).apply { setPadding(0, dp(6), 0, 0) })
            c.addView(UiKit.text(this, UiKit.keepWords(k.note), 12f, Pal.text3).apply { setPadding(0, dp(4), 0, 0) })
            val act = LinearLayout(this).apply { orientation = LinearLayout.HORIZONTAL }
            act.addView(button("복사") { copy(ip, "IP") }, LinearLayout.LayoutParams(0, WRAP_CONTENT, 1f))
            if (!k.blocked) act.addView(button("포트 검사") { showTool("port_scan", ip) }, LinearLayout.LayoutParams(0, WRAP_CONTENT, 1f).apply { leftMargin = dp(8) })
            c.addView(act, lp(top = 10))
            res.addView(c, lp(bottom = 8))
        }
        if (!isIp && addrs.all { IpUtil.classify(it).local })
            res.addView(note("이 도메인은 내 망 안(사설·로컬) 주소로 풀려요. 사내망 서비스이거나, DNS 설정이 바뀌었거나 차단된 것일 수 있어요.", warn = true))
    }

    // ================================================================== IP 정보 · 서브넷 계산
    private fun ipInfo(prefill: String?) {
        body.addView(note("IP 주소가 어떤 종류인지(사설·공인…) 알려 주고 다른 표기로 바꿔 줘요. \"192.168.0.0/24\" 처럼 범위를 넣으면 서브넷을 계산해요."))
        val card = UiKit.card(this)
        body.addView(card, lp(top = 10))
        card.addView(label("IP 주소 또는 범위"))
        val et = input("예: 192.168.0.12 · 8.8.8.8 · 10.0.0.0/16", prefill)
        card.addView(et, lp(top = 6))
        val samples = listOf("192.168.0.0/24", "10.0.0.0/16", "8.8.8.8", "100.64.1.5", "2001:db8::1")
        card.addView(UiKit.chipRow(this, samples.map { s -> UiKit.chip(this, s, false) { et.setText(s); showIpInfo(s) } }), lp(top = 8))
        val btn = primaryButton("알아보기") { showIpInfo(et.text.toString()) }
        card.addView(btn, lp(top = 12))
        val res = LinearLayout(this).apply { orientation = LinearLayout.VERTICAL }
        body.addView(res, lp(top = 12))
        infoResults = res
        et.onGo { showIpInfo(et.text.toString()) }
        if (!prefill.isNullOrEmpty()) btn.post { showIpInfo(prefill) }
    }

    /** IP 정보·서브넷 계산 결과 그리기 (시험·화면 그리기에서도 부름) */
    internal fun showIpInfo(text: String) {
        val res = infoResults ?: return
        res.removeAllViews()
        val t = text.trim()
        if (t.isEmpty()) { toast("IP 주소나 범위를 입력하세요"); return }
        Subnet.parse(t)?.let { s ->
            val c = UiKit.card(this)
            c.addView(UiKit.text(this, "서브넷 ${IpUtil.v4Text(s.network)}/${s.prefix}", 17f, Pal.text, true))
            c.addView(kv("네트워크 주소", IpUtil.v4Text(s.network)))
            c.addView(kv("서브넷 마스크", IpUtil.v4Text(s.mask)))
            c.addView(kv("와일드카드", IpUtil.v4Text(s.wildcard)))
            c.addView(kv("브로드캐스트", IpUtil.v4Text(s.broadcast)))
            c.addView(kv("쓸 수 있는 주소", "${IpUtil.v4Text(s.first)} ~ ${IpUtil.v4Text(s.last)}"))
            c.addView(kv("기기 수", "${"%,d".format(s.hostCount)}대", monoValue = false))
            val k = IpUtil.classify(InetAddress.getByAddress(IpUtil.longToV4(s.network)))
            c.addView(kv("범위 종류", k.label, copyable = false, monoValue = false))
            c.addView(UiKit.text(this, UiKit.keepWords(k.note), 12.5f, Pal.text2).apply { setLineSpacing(0f, 1.15f); setPadding(0, dp(6), 0, 0) })
            res.addView(c)
            return
        }
        val a = IpUtil.parse(HostInput.host(t))
        if (a == null) {
            res.addView(note("IP 주소(192.168.0.1), IPv6(2001:db8::1), 범위(192.168.0.0/24) 형식으로 입력하세요. 숫자 사이는 점, 칸마다 0~255, 앞에 0 을 붙이지 않아요.", warn = true))
            return
        }
        val ip = IpUtil.format(a); val k = IpUtil.classify(a)
        val c = UiKit.card(this)
        val top = LinearLayout(this).apply { orientation = LinearLayout.HORIZONTAL; gravity = Gravity.CENTER_VERTICAL }
        top.addView(mono(ip, 19f), LinearLayout.LayoutParams(0, WRAP_CONTENT, 1f))
        top.addView(kindPill(k))
        c.addView(top)
        c.addView(UiKit.text(this, k.label, 14.5f, Pal.text, true).apply { setPadding(0, dp(8), 0, 0) })
        c.addView(UiKit.text(this, UiKit.keepWords(k.note), 13f, Pal.text2).apply { setLineSpacing(0f, 1.15f); setPadding(0, dp(2), 0, dp(6)) })
        if (a.address.size == 4) for ((n, v) in IpUtil.v4Forms(IpUtil.v4ToLong(a.address))) c.addView(kv(n, v))
        else IpUtil.expandV6(a)?.let { c.addView(kv("전체 표기", it)) }
        val act = LinearLayout(this).apply { orientation = LinearLayout.HORIZONTAL }
        act.addView(button("복사") { copy(ip, "IP") }, LinearLayout.LayoutParams(0, WRAP_CONTENT, 1f))
        act.addView(button("이름 조회") { showTool("dns", ip) }, LinearLayout.LayoutParams(0, WRAP_CONTENT, 1f).apply { leftMargin = dp(8) })
        if (!k.blocked) act.addView(button("포트 검사") { showTool("port_scan", ip) }, LinearLayout.LayoutParams(0, WRAP_CONTENT, 1f).apply { leftMargin = dp(8) })
        c.addView(act, lp(top = 10))
        res.addView(c)
    }
}
