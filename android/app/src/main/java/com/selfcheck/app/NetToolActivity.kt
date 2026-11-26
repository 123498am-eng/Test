package com.selfcheck.app

import android.app.AlertDialog
import android.graphics.Paint
import android.graphics.Typeface
import android.net.Uri
import android.os.Bundle
import android.os.Handler
import android.os.Looper
import android.provider.OpenableColumns
import android.text.Editable
import android.text.InputType
import android.text.TextPaint
import android.text.TextWatcher
import android.util.TypedValue
import android.view.Gravity
import android.view.View
import android.view.ViewGroup.LayoutParams.MATCH_PARENT
import android.view.ViewGroup.LayoutParams.WRAP_CONTENT
import android.view.WindowManager
import android.view.inputmethod.EditorInfo
import android.widget.Button
import android.widget.EditText
import android.widget.LinearLayout
import android.widget.TextView
import androidx.activity.result.contract.ActivityResultContracts
import java.net.Socket
import java.util.IdentityHashMap
import java.util.concurrent.atomic.AtomicBoolean
import kotlin.concurrent.thread

/**
 * 네트워크 도구 모음의 공통 실행 화면: 도구 정의(NetTool)의 입력 칸을 그리고, 실행하면 결과 줄(Out)을 그립니다.
 * 오프라인 계산은 바로, 인터넷·내 망 도구는 백그라운드에서 돌려 "중지" 버튼을 보여 줍니다.
 */
class NetToolActivity : ColumnActivity(), ToolHost {
    private lateinit var tool: NetTool
    private val getters = LinkedHashMap<String, () -> String>()
    private val picked = HashMap<String, Pair<Uri, String>>()
    private var pickKey: String? = null
    private lateinit var results: LinearLayout
    private lateinit var status: TextView
    private var runBtn: Button? = null
    private var cancel = AtomicBoolean(false)
    private var running = false
    private var confirmed = false
    private var destroyed = false
    private val ui = Handler(Looper.getMainLooper())
    private var liveJob: Runnable? = null
    private var netRows: List<NetRow> = emptyList()
    internal var lastResult: ToolResult? = null

    private val pickFile = registerForActivityResult(ActivityResultContracts.OpenDocument()) { uri ->
        val key = pickKey ?: return@registerForActivityResult
        if (uri == null) return@registerForActivityResult
        val name = runCatching {
            contentResolver.query(uri, null, null, null, null)?.use { c -> if (c.moveToFirst()) c.getString(c.getColumnIndexOrThrow(OpenableColumns.DISPLAY_NAME)) else null }
        }.getOrNull() ?: uri.lastPathSegment ?: "선택한 파일"
        picked[key] = uri to name
        fileLabels[key]?.text = name
    }
    private val fileLabels = HashMap<String, TextView>()

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        val id = intent.getStringExtra("tool") ?: ""
        val t = NetToolbox.byId(id)
        if (t == null) { finish(); return }
        tool = t
        netRows = LocalNet.networks(this)
        setupColumn(tool.title, tool.desc.let { UiKit.keepWords(it) })

        // 묶음·사용 방식 표시
        val tags = LinearLayout(this).apply { orientation = LinearLayout.HORIZONTAL }
        tags.addView(pill(tool.group, Pal.primaryDark, Pal.primarySoft))
        val (modeFg, modeBg) = when (tool.mode) {
            ToolMode.OFFLINE -> Pal.good to Pal.goodSoft
            ToolMode.ONLINE -> Pal.warn to Pal.warnSoft
            ToolMode.LAN -> Pal.primaryDark to Pal.primarySoft
        }
        tags.addView(pill(tool.mode.label, modeFg, modeBg), LinearLayout.LayoutParams(WRAP_CONTENT, WRAP_CONTENT).apply { leftMargin = dp(8) })
        col.addView(tags, lp(top = 2, bottom = 4))
        tool.note?.let { col.addView(tip(UiKit.keepWords(it), warn = tool.mode == ToolMode.ONLINE)) }

        if (tool.fields.isNotEmpty()) {
            val card = UiKit.card(this)
            tool.fields.forEachIndexed { i, f -> addField(card, f, i == 0) }
            col.addView(card, lp(top = 10))
        }

        status = hint("").apply { setPadding(dp(4), dp(8), dp(4), 0); visibility = View.GONE }
        if (!(tool.auto && tool.fields.isEmpty())) {
            runBtn = primaryButton(tool.runLabel) { runTool() }
            col.addView(runBtn, lp(top = 12))
        }
        col.addView(status)
        results = LinearLayout(this).apply { orientation = LinearLayout.VERTICAL }
        col.addView(results, lp(top = 12))
        // 열자마자 계산: 모든 칸에 기본값이 있는 오프라인 도구 ("(선택)" 칸은 비어 있어도 됨, 단 채워진 칸이 하나는 있어야 함)
        val optional = { f: Field -> f.label.contains("(선택") || f.label.contains("비우면") }
        val prefilled = tool.mode == ToolMode.OFFLINE && tool.fields.isNotEmpty() &&
            tool.fields.all { it.kind == FieldKind.CHOICE || optional(it) || (it.kind != FieldKind.FILE && it.default.isNotEmpty()) } &&
            tool.fields.any { it.kind == FieldKind.CHOICE || it.default.isNotEmpty() }
        if (tool.auto || prefilled) runTool()
    }

    override fun onDestroy() {
        destroyed = true; cancel.set(true)
        window.clearFlags(WindowManager.LayoutParams.FLAG_KEEP_SCREEN_ON)
        super.onDestroy()
    }

    // ------------------------------------------------------------------ 입력 칸
    private fun lp(top: Int = 0, bottom: Int = 0) = UiKit.params(top = top, bottom = bottom, ctx = this)

    private fun pill(t: String, fg: Int, bg: Int) = TextView(this).apply {
        text = t; textSize = 11.5f; setTextColor(fg); typeface = Typeface.DEFAULT_BOLD
        setPadding(dp(9), dp(3), dp(9), dp(3)); background = UiKit.rounded(this@NetToolActivity, bg, 20f)
    }

    private fun addField(card: LinearLayout, f: Field, first: Boolean) {
        card.addView(UiKit.text(this, f.label, 13.5f, Pal.text, true).apply { if (!first) setPadding(0, dp(14), 0, 0) })
        when (f.kind) {
            FieldKind.TEXT, FieldKind.MULTILINE -> {
                val et = EditText(this).apply {
                    hint = f.hint
                    if (f.kind == FieldKind.MULTILINE) {
                        inputType = InputType.TYPE_CLASS_TEXT or InputType.TYPE_TEXT_FLAG_MULTI_LINE or InputType.TYPE_TEXT_FLAG_NO_SUGGESTIONS
                        minLines = 4; maxLines = 12; gravity = Gravity.TOP or Gravity.START
                    } else {
                        inputType = InputType.TYPE_CLASS_TEXT or InputType.TYPE_TEXT_VARIATION_URI or InputType.TYPE_TEXT_FLAG_NO_SUGGESTIONS
                        imeOptions = EditorInfo.IME_ACTION_GO
                        setOnEditorActionListener { _, a, _ -> if (a == EditorInfo.IME_ACTION_GO || a == EditorInfo.IME_ACTION_DONE) { runTool(); true } else false }
                    }
                    if (f.default.isNotEmpty()) setText(f.default)
                }
                styleInput(et)
                card.addView(et, lp(top = 6))
                getters[f.key] = { et.text.toString() }
                if (tool.live) et.addTextChangedListener(object : TextWatcher {
                    override fun afterTextChanged(s: Editable?) { scheduleLive() }
                    override fun beforeTextChanged(s: CharSequence?, a: Int, b: Int, c: Int) {}
                    override fun onTextChanged(s: CharSequence?, a: Int, b: Int, c: Int) {}
                })
                if (f.chips.isNotEmpty()) card.addView(UiKit.chipRow(this, f.chips.map { (label, value) ->
                    UiKit.chip(this, label, false) { et.setText(value); et.setSelection(value.length); if (!tool.live) et.requestFocus() }
                }), lp(top = 8))
            }
            FieldKind.CHOICE -> {
                var cur = f.default.ifEmpty { f.choices.firstOrNull() ?: "" }
                lateinit var chips: List<TextView>
                chips = f.choices.map { c ->
                    UiKit.chip(this, c, c == cur) { cur = c; chips.forEachIndexed { j, v -> UiKit.setChip(v, f.choices[j] == cur) }; if (tool.live) scheduleLive() }
                }
                card.addView(UiKit.chipRow(this, chips), lp(top = 6))
                getters[f.key] = { cur }
            }
            FieldKind.FILE -> {
                val name = TextView(this).apply { text = "고른 파일 없음"; textSize = 13f; setTextColor(Pal.text2); setPadding(dp(4), dp(6), 0, 0) }
                fileLabels[f.key] = name
                card.addView(button("파일 고르기") { pickKey = f.key; pickFile.launch(arrayOf("*/*")) }, lp(top = 6))
                card.addView(name)
                getters[f.key] = { picked[f.key]?.second ?: "" }
            }
        }
    }

    private fun scheduleLive() {
        liveJob?.let { ui.removeCallbacks(it) }
        val job = Runnable { runTool() }
        liveJob = job
        ui.postDelayed(job, 250)
    }

    private fun values(): Map<String, String> = getters.mapValues { it.value() }

    // ------------------------------------------------------------------ 실행
    private fun runTool() {
        if (running) { cancel.set(true); status.text = "멈추는 중..."; return }
        val msg = tool.confirm
        if (msg != null && !confirmed) {
            AlertDialog.Builder(this).setTitle("실행할까요?").setMessage(msg)
                .setPositiveButton("실행") { _, _ -> confirmed = true; runTool() }.setNegativeButton("취소", null).show()
            return
        }
        val input = ToolInput(values())
        val flag = AtomicBoolean(false); cancel = flag
        val env = ToolEnv(flag) { m -> runOnUiThread { if (!destroyed) { status.visibility = View.VISIBLE; status.text = m } } }
        val offline = tool.mode == ToolMode.OFFLINE && tool.fields.none { it.kind == FieldKind.FILE }
        if (offline) {
            val r = try { tool.run(input, this, env) } catch (e: Throwable) { fail("계산하지 못했어요: ${e.message ?: e.javaClass.simpleName}") }
            render(r); return
        }
        setRunning(true)
        thread {
            val r = try { tool.run(input, this, env) } catch (e: Throwable) { fail("실행하지 못했어요: ${e.message ?: e.javaClass.simpleName}") }
            runOnUiThread {
                if (destroyed) return@runOnUiThread
                setRunning(false); status.visibility = View.GONE
                render(r)
                results.parent?.let { scroll.post { scroll.smoothScrollTo(0, (results.top - dp(12)).coerceAtLeast(0)) } }
            }
        }
    }

    private fun setRunning(on: Boolean) {
        running = on
        runBtn?.let { b ->
            b.text = if (on) "중지" else tool.runLabel
            UiKit.styleButton(b, if (on) BtnStyle.DANGER else BtnStyle.PRIMARY)
        }
        if (on) { status.visibility = View.VISIBLE; status.text = "실행 중..."; window.addFlags(WindowManager.LayoutParams.FLAG_KEEP_SCREEN_ON) }
        else window.clearFlags(WindowManager.LayoutParams.FLAG_KEEP_SCREEN_ON)
    }

    // ------------------------------------------------------------------ 결과 그리기
    internal fun render(r: ToolResult) {
        lastResult = r
        results.removeAllViews()
        var card: LinearLayout? = null
        fun cardOf(): LinearLayout = card ?: UiKit.card(this, 14, 16f).also { c -> card = c; results.addView(c, lp(bottom = 10)) }
        // 이어진 표 줄(같은 칸 수, 머리글로 시작)마다 칸 너비를 한 번에 계산해서 머리글과 내용의 칸이 정확히 맞게
        val specs = IdentityHashMap<Out.Cols, TableSpec>()
        var k = 0
        while (k < r.outs.size) {
            val o = r.outs[k]
            if (o is Out.Cols) {
                var j = k + 1
                while (j < r.outs.size) { val q = r.outs[j]; if (q is Out.Cols && !q.header && q.cells.size == o.cells.size) j++ else break }
                val rows = r.outs.subList(k, j).filterIsInstance<Out.Cols>()
                val spec = tableSpec(rows); for (row in rows) specs[row] = spec
                k = j
            } else k++
        }
        for (o in r.outs) when (o) {
            is Out.Head -> { card = null; results.addView(UiKit.text(this, o.text, 15f, Pal.text, true).apply { setPadding(dp(4), dp(6), 0, dp(6)) }) }
            is Out.Note -> { card = null; results.addView(noteBox(o.text, o.level), lp(bottom = 10)) }
            is Out.Kv -> cardOf().addView(kvRow(o))
            is Out.Cols -> cardOf().addView(colsRow(o, specs[o]))
            is Out.Block -> { card = null; results.addView(blockView(o), lp(bottom = 10)) }
        }
        if (r.outs.isNotEmpty() && !(r.outs.size == 1 && r.outs[0] is Out.Block)) {
            results.addView(buttons("결과 복사" to { copy(r.text(), tool.title) }), lp(top = 2))
        }
    }

    private fun levelColor(level: Int) = when (level) { 2 -> Pal.bad; 1 -> Pal.warn; -1 -> Pal.good; else -> Pal.text }

    private fun noteBox(t: String, level: Int): View {
        val (fg, bg) = when (level) { 2 -> Pal.bad to Pal.badSoft; 1 -> 0xFF8A4B0B.toInt() to Pal.warnSoft; -1 -> Pal.good to Pal.goodSoft; else -> Pal.primaryDark to Pal.primarySoft }
        return TextView(this).apply {
            text = UiKit.keepWords(t); textSize = 13.5f; setLineSpacing(0f, 1.18f); setTextColor(fg)
            setPadding(dp(14), dp(12), dp(14), dp(12)); background = UiKit.rounded(this@NetToolActivity, bg, 16f)
            setTextIsSelectable(true)
        }
    }

    private fun kvRow(o: Out.Kv): View = LinearLayout(this).apply {
        orientation = LinearLayout.HORIZONTAL; setPadding(0, dp(5), 0, dp(5))
        addView(UiKit.text(this@NetToolActivity, UiKit.keepWords(o.label), 13.5f, Pal.text2), LinearLayout.LayoutParams(dp(108), WRAP_CONTENT))
        addView(UiKit.text(this@NetToolActivity, UiKit.keepWords(o.value), 14.5f, levelColor(o.level), o.level != 0), LinearLayout.LayoutParams(0, WRAP_CONTENT, 1f))
        isClickable = true; setOnClickListener { copy(o.value, o.label) }
    }

    /** 한 표의 칸 너비: 칸마다 "가장 긴 낱말"은 줄이 바뀌지 않을 만큼(최소 너비), 남는 폭은 글이 긴 칸에 더 줌 */
    private class TableSpec(val minPx: IntArray, val weights: FloatArray)

    private val WS = Regex("\\s+")

    private fun tableSpec(rows: List<Out.Cols>): TableSpec {
        val n = rows.maxOf { it.cells.size }
        val dm = resources.displayMetrics
        // 화면 좌우 여백(16dp×2) + 카드 여백(14dp×2) + 줄 안쪽 여백(8dp×2)
        val avail = ((if (col.width > 0) col.width else dm.widthPixels) - dp(32) - dp(28) - dp(16)).coerceAtLeast(dp(200))
        val paint = TextPaint(Paint.ANTI_ALIAS_FLAG).apply { textSize = TypedValue.applyDimension(TypedValue.COMPLEX_UNIT_SP, 12.5f, dm); typeface = Typeface.DEFAULT_BOLD }
        val pad = dp(8)                                           // 칸 안쪽 여백(왼쪽 2dp + 오른쪽 6dp)
        val tokens = Array(n) { ArrayList<Int>() }                // 칸마다, 줄마다 "가장 긴 낱말"의 너비
        val full = IntArray(n)
        for (row in rows) row.cells.forEachIndexed { i, c ->
            val t = UiKit.keepWords(c)
            full[i] = maxOf(full[i], paint.measureText(t).toInt())
            tokens[i] += t.split(WS).filter { it.isNotEmpty() }.maxOfOrNull { paint.measureText(it).toInt() } ?: 0
        }
        // 최소 너비 = 대부분(85%) 줄의 가장 긴 낱말이 줄바꿈 없이 들어갈 폭. 드물게 긴 낱말 하나 때문에 칸 전체를 넓히지 않음
        val mins = IntArray(n) { i ->
            val sorted = tokens[i].sorted()
            val idx = if (sorted.size <= 6) sorted.size - 1 else ((sorted.size - 1) * 0.85).toInt()
            minOf(sorted.getOrElse(idx) { 0 } + pad, avail / 2)
        }
        // 합쳐서 화면보다 넓으면 가장 넓은 칸부터 줄임 (짧은 낱말 칸은 그대로 둠)
        var over = mins.sum() - avail
        val floor = dp(44)
        while (over > 0) {
            val top = mins.max()
            val widest = mins.indices.filter { mins[it] == top }
            val next = maxOf(mins.filter { it < top }.maxOrNull() ?: 0, floor)
            val can = top - next
            if (can <= 0) break
            val d = minOf(can, (over + widest.size - 1) / widest.size)
            for (i in widest) mins[i] -= d
            over -= d * widest.size
        }
        val extra = FloatArray(n) { maxOf(0, minOf(full[it] + pad, avail) - mins[it]).toFloat() }
        return TableSpec(mins, if (extra.sum() > 0f) extra else FloatArray(n) { 1f })
    }

    private fun colsRow(o: Out.Cols, spec: TableSpec?): View {
        val n = o.cells.size
        val row = LinearLayout(this).apply {
            orientation = LinearLayout.HORIZONTAL
            setPadding(dp(8), dp(if (o.header) 6 else 5), dp(8), dp(if (o.header) 6 else 5))      // 머리글 줄과 내용 줄의 좌우 여백을 같게 (칸이 어긋나지 않게)
            if (o.header) background = UiKit.rounded(this@NetToolActivity, Pal.surface2, 10f)
        }
        o.cells.forEachIndexed { i, c ->
            val params = if (spec != null && i < spec.minPx.size) LinearLayout.LayoutParams(spec.minPx[i], WRAP_CONTENT, spec.weights[i]) else LinearLayout.LayoutParams(0, WRAP_CONTENT, 1f)
            row.addView(
                UiKit.text(this, UiKit.keepWords(c), 12.5f, if (o.header) Pal.text2 else levelColor(o.level), o.header || (i == 0 && n >= 3)).apply { setPadding(dp(2), 0, dp(6), 0) },
                params,
            )
        }
        row.isClickable = !o.header
        if (!o.header) row.setOnClickListener { copy(o.cells.joinToString("  "), "표") }
        return row
    }

    private fun blockView(o: Out.Block): View {
        val box = LinearLayout(this).apply { orientation = LinearLayout.VERTICAL }
        box.addView(TextView(this).apply {
            text = o.text; textSize = 12.5f; setTextColor(Pal.text); setLineSpacing(0f, 1.15f)
            if (o.mono) typeface = Typeface.MONOSPACE
            setTextIsSelectable(true); setPadding(dp(14), dp(12), dp(14), dp(12))
            background = UiKit.rounded(this@NetToolActivity, Pal.surface, 14f, Pal.outline, 1)
        })
        box.addView(buttons("복사" to { copy(o.text, tool.title) }), lp(top = 6))
        return box
    }

    // ------------------------------------------------------------------ ToolHost (휴대폰 쪽 정보)
    override fun file(key: String): FileRef? {
        val (uri, name) = picked[key] ?: return null
        val size = runCatching { contentResolver.query(uri, null, null, null, null)?.use { c -> if (c.moveToFirst()) c.getLong(c.getColumnIndexOrThrow(OpenableColumns.SIZE)) else -1L } }.getOrNull() ?: -1L
        return FileRef(name, size) { runCatching { contentResolver.openInputStream(uri) }.getOrNull() }
    }

    override fun dnsServers(): List<String> = (netRows.firstOrNull { it.isDefault && it.dns.isNotEmpty() } ?: netRows.firstOrNull { it.dns.isNotEmpty() })?.dns ?: emptyList()
    override fun gateway(): String? = LocalNet.lan(netRows)?.gateway
    override fun lanIp(): Pair<String, Int>? = LocalNet.lan(netRows)?.let { r -> r.ipv4?.let { it to (r.prefix ?: 24) } }
    override fun netDetails(): List<Pair<String, String>> = LocalNet.details(this)
    override fun wifiDetails(): List<Pair<String, String>>? = LocalNet.wifi(this)
    override fun lanSockets(): () -> Socket = LocalNet.socketFactory(LocalNet.lan(netRows))
    override fun bindDatagram(s: java.net.DatagramSocket) { LocalNet.lan(netRows)?.network?.let { runCatching { it.bindSocket(s) } } }
    override fun geoDb(): IpGeoDb? = runCatching { IpGeoDb.shared { assets.open(it) } }.getOrNull()
}
