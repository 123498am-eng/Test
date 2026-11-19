package com.selfcheck.app

import android.Manifest
import android.content.Intent
import android.content.pm.PackageManager
import android.graphics.Color
import android.graphics.Typeface
import android.os.Bundle
import android.os.Handler
import android.os.Looper
import android.view.Gravity
import android.view.View
import android.view.ViewGroup.LayoutParams.MATCH_PARENT
import android.view.ViewGroup.LayoutParams.WRAP_CONTENT
import android.view.WindowManager
import android.widget.Button
import android.widget.LinearLayout
import android.widget.ScrollView
import android.widget.TextView
import android.widget.Toast
import androidx.activity.ComponentActivity
import androidx.activity.result.contract.ActivityResultContracts
import androidx.core.content.ContextCompat
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale
import kotlin.concurrent.thread
import kotlin.math.log10
import kotlin.math.roundToInt

/** 실시간 음성 변조: 마이크로 말하면 바로 다른 목소리로 이어폰·스피커에 나옵니다. */
class VoiceChangerActivity : ComponentActivity() {
    private val st = VoiceSettings()
    private lateinit var runner: VoiceRunner
    private val ui = Handler(Looper.getMainLooper())

    // 위쪽·카드
    private lateinit var statusChip: TextView
    private lateinit var heroIcon: TextView
    private lateinit var heroName: TextView
    private lateinit var heroDesc: TextView
    private lateinit var inMeter: MeterView
    private lateinit var outMeter: MeterView
    private lateinit var statLatency: TextView
    private lateinit var statPitch: TextView
    // 듣기 설정
    private lateinit var monitorRow: UiKit.SwitchRow
    private lateinit var originalRow: UiKit.SwitchRow
    private lateinit var origBox: LinearLayout
    // 목소리 고르기
    private lateinit var catRow: LinearLayout
    private lateinit var grid: LinearLayout
    private val catChips = LinkedHashMap<String, TextView>()
    private var category = ""
    // 세부 조절
    private lateinit var tuneNote: TextView
    private val sliders = ArrayList<UiKit.SliderRow>()
    // 아래 고정 버튼
    private lateinit var startBtn: Button
    private lateinit var recBtn: Button
    private lateinit var scroll: ScrollView
    private var pulse = 0

    private val tick = object : Runnable {
        override fun run() { refresh(); ui.postDelayed(this, 100) }
    }
    private val askMic = registerForActivityResult(ActivityResultContracts.RequestPermission()) { ok ->
        if (ok) begin() else toast("마이크 권한이 필요합니다 (설정 → 앱 → 권한)")
    }

    private fun dp(v: Int) = dip(v)
    private fun toast(t: String) = Toast.makeText(this, t, Toast.LENGTH_SHORT).show()

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        window.addFlags(WindowManager.LayoutParams.FLAG_KEEP_SCREEN_ON)
        st.load(this)
        runner = VoiceRunner(this) { err -> runOnUiThread { onStopped(err) } }
        runner.monitor = st.monitorOn

        val root = LinearLayout(this).apply { orientation = LinearLayout.VERTICAL; setBackgroundColor(Pal.bg) }
        root.setOnApplyWindowInsetsListener { v, insets ->
            @Suppress("DEPRECATION")
            v.setPadding(0, insets.systemWindowInsetTop, 0, insets.systemWindowInsetBottom); insets
        }
        statusChip = TextView(this).apply { textSize = 12.5f; typeface = Typeface.DEFAULT_BOLD; setPadding(dp(12), dp(6), dp(12), dp(6)) }
        root.addView(UiKit.topBar(this, "음성 변조", { finish() }, statusChip))

        val content = LinearLayout(this).apply { orientation = LinearLayout.VERTICAL; setPadding(dp(16), dp(6), dp(16), dp(24)) }
        scroll = ScrollView(this).apply { addView(content); isVerticalScrollBarEnabled = false }
        root.addView(scroll, LinearLayout.LayoutParams(MATCH_PARENT, 0, 1f))

        content.addView(buildHero())
        content.addView(UiKit.sectionTitle(this, "듣기 설정", "내 귀에 들리는 소리를 정해요"))
        content.addView(buildListenCard())
        content.addView(UiKit.sectionTitle(this, "목소리 고르기", "${VoicePresets.ALL.size}가지 · 말하는 중에도 바꿀 수 있어요"))
        catRow = LinearLayout(this).apply { orientation = LinearLayout.VERTICAL }
        content.addView(catRow)
        grid = LinearLayout(this).apply { orientation = LinearLayout.VERTICAL; setPadding(0, dp(10), 0, 0) }
        content.addView(grid)
        content.addView(UiKit.sectionTitle(this, "세부 조절", "고른 목소리를 취향에 맞게 다듬어요"))
        content.addView(buildTuneCard())
        content.addView(buildNotice(), UiKit.params(top = 18, ctx = this))

        root.addView(buildBottomBar())
        setContentView(root)

        category = st.category.takeIf { it.isNotEmpty() } ?: (VoicePresets.byId(st.presetId)?.group ?: VoicePresets.GROUPS.first())
        buildCategories()
        select(VoicePresets.byId(st.presetId)!!, save = false)
        updateListenUi()
        updateButtons(); updateStatus()
    }

    // ------------------------------------------------------------------ 화면 조각
    private fun buildHero(): View {
        val hero = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL; setPadding(dp(18), dp(18), dp(18), dp(16))
            background = UiKit.gradient(this@VoiceChangerActivity, 24f)
            elevation = dipf(3f)
        }
        val top = LinearLayout(this).apply { orientation = LinearLayout.HORIZONTAL; gravity = Gravity.CENTER_VERTICAL }
        heroIcon = UiKit.badge(this, "🎙️", 56, 0x33FFFFFF, 28f)
        top.addView(heroIcon)
        val col = LinearLayout(this).apply { orientation = LinearLayout.VERTICAL; setPadding(dp(14), 0, 0, 0) }
        heroName = TextView(this).apply { textSize = 19f; setTextColor(Color.WHITE); typeface = Typeface.DEFAULT_BOLD; maxLines = 2 }
        heroDesc = TextView(this).apply { textSize = 12.5f; setTextColor(0xDDFFFFFF.toInt()); maxLines = 3; setLineSpacing(0f, 1.1f); setPadding(0, dp(3), 0, 0) }
        col.addView(heroName); col.addView(heroDesc)
        top.addView(col, LinearLayout.LayoutParams(0, WRAP_CONTENT, 1f))
        hero.addView(top)

        fun meterRow(label: String): MeterView {
            val r = LinearLayout(this).apply { orientation = LinearLayout.HORIZONTAL; gravity = Gravity.CENTER_VERTICAL }
            r.addView(TextView(this).apply { text = label; textSize = 11.5f; setTextColor(0xCCFFFFFF.toInt()) }, LinearLayout.LayoutParams(dp(34), WRAP_CONTENT))
            val m = MeterView(this, onDark = true)
            r.addView(m, LinearLayout.LayoutParams(0, dp(8), 1f))
            hero.addView(r, UiKit.params(top = 8, ctx = this).also { it.topMargin = dp(if (label == "입력") 16 else 8) })
            return m
        }
        inMeter = meterRow("입력"); outMeter = meterRow("출력")

        val stats = LinearLayout(this).apply { orientation = LinearLayout.HORIZONTAL; setPadding(0, dp(14), 0, 0) }
        fun pill(): TextView = TextView(this).apply {
            textSize = 12f; setTextColor(Color.WHITE); setPadding(dp(10), dp(5), dp(10), dp(5)); setSingleLine()
            background = UiKit.rounded(this@VoiceChangerActivity, 0x33FFFFFF, 20f)
        }
        statLatency = pill(); statPitch = pill()
        stats.addView(statLatency); stats.addView(statPitch, LinearLayout.LayoutParams(WRAP_CONTENT, WRAP_CONTENT).apply { leftMargin = dp(8) })
        hero.addView(stats)
        return hero
    }

    private fun buildListenCard(): View {
        val card = UiKit.card(this)
        monitorRow = UiKit.switchRow(this, "🎧", "변조 목소리 듣기", "", st.monitorOn) { c ->
            st.monitorOn = c; runner.monitor = c; st.save(this); updateListenUi(); updateStatus()
        }
        card.addView(monitorRow.view)
        card.addView(divider())
        originalRow = UiKit.switchRow(this, "🗣️", "원본 목소리 섞기", "", st.originalOn) { c ->
            st.originalOn = c; applyToEngine(); st.save(this); updateListenUi()
        }
        card.addView(originalRow.view)
        origBox = LinearLayout(this).apply { orientation = LinearLayout.VERTICAL; setPadding(dp(52), 0, 0, dp(2)) }
        val s = UiKit.sliderRow(this, "원본 크기", 100, (st.originalLevel * 100).roundToInt(), { "$it%" }) { p ->
            st.originalLevel = p / 100f; applyToEngine(); st.save(this)
        }
        origBox.addView(s.view)
        card.addView(origBox)
        card.addView(TextView(this).apply {
            text = "귀에 직접 들리는 진짜 내 목소리(공기와 뼈로 전해지는 소리)는 앱에서 끌 수 없어요. 귀를 막아 주는 이어폰을 쓰면 변조된 소리가 더 또렷하게 들려요."
            textSize = 12f; setTextColor(Pal.text3); setLineSpacing(0f, 1.1f); setPadding(0, dp(10), 0, 0)
        })
        return card
    }

    private fun divider() = View(this).apply { setBackgroundColor(Pal.outline); layoutParams = LinearLayout.LayoutParams(MATCH_PARENT, dp(1)).apply { topMargin = dp(6); bottomMargin = dp(6); leftMargin = dp(52) } }

    private fun buildTuneCard(): View {
        val card = UiKit.card(this)
        fun add(label: String, max: Int, init: Int, fmt: (Int) -> String, onChange: (Int) -> Unit) {
            val s = UiKit.sliderRow(this, label, max, init, fmt) { p -> onChange(p); applyToEngine(); st.save(this) }
            sliders += s; card.addView(s.view, UiKit.params(top = 6, ctx = this))
        }
        add("음높이", 120, ((st.semitones + 6f) * 10).roundToInt(), { "%+.1f 반음".format((it - 60) / 10f) }) { st.semitones = (it - 60) / 10f }
        add("목소리 굵기", 60, (st.formant * 100).roundToInt() - 70, { "%d%%".format(70 + it) }) { st.formant = (70 + it) / 100f }
        add("효과 세기", 150, (st.fxAmount * 100).roundToInt(), { "%d%%".format(it) }) { st.fxAmount = it / 100f }
        add("마이크 감도", 300, (st.micGain * 100).roundToInt() - 50, { "%d%%".format(it + 50) }) { st.micGain = (it + 50) / 100f }
        tuneNote = TextView(this).apply { textSize = 12f; setTextColor(Pal.text3); setPadding(0, dp(8), 0, 0) }
        card.addView(tuneNote)
        card.addView(UiKit.button(this, "기본값으로 되돌리기", BtnStyle.GHOST, 13.5f) {
            st.semitones = 0f; st.formant = 1f; st.fxAmount = 1f; st.micGain = 1f
            sliders[0].bar.progress = 60; sliders[1].bar.progress = 30; sliders[2].bar.progress = 100; sliders[3].bar.progress = 50
            applyToEngine(); st.save(this)
        }, UiKit.params(top = 10, ctx = this))
        return card
    }

    private fun buildNotice(): View {
        val c = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL; setPadding(dp(14), dp(12), dp(14), dp(12))
            background = UiKit.rounded(this@VoiceChangerActivity, Pal.warnSoft, 16f)
        }
        c.addView(TextView(this).apply { text = "알아 두세요"; textSize = 13.5f; setTextColor(Pal.warn); typeface = Typeface.DEFAULT_BOLD })
        c.addView(TextView(this).apply {
            text = "• 이어폰을 끼지 않고 스피커로 내면 소리가 마이크로 다시 들어가 '삐—' 하는 소리가 납니다.\n" +
                "• 안드로이드 제한으로 통화·다른 앱의 마이크로는 변조된 소리를 보낼 수 없어요. 이 앱에서 듣거나 [녹음]해서 공유하세요.\n" +
                "• 다른 사람을 속이는 목적(사칭·보이스피싱 등)으로 쓰지 마세요."
            textSize = 12.5f; setTextColor(0xFF7A4A0B.toInt()); setLineSpacing(0f, 1.15f); setPadding(0, dp(6), 0, 0)
        })
        return c
    }

    private fun buildBottomBar(): View {
        val bar = LinearLayout(this).apply {
            orientation = LinearLayout.HORIZONTAL; gravity = Gravity.CENTER_VERTICAL
            setPadding(dp(16), dp(10), dp(16), dp(12)); setBackgroundColor(Pal.surface); elevation = dipf(8f)
        }
        recBtn = UiKit.button(this, "● 녹음", BtnStyle.SOFT, 15f) { toggleRecord() }
        startBtn = UiKit.button(this, "▶ 시작", BtnStyle.PRIMARY, 16f) { toggle() }
        bar.addView(recBtn, LinearLayout.LayoutParams(0, dp(52), 1f))
        bar.addView(startBtn, LinearLayout.LayoutParams(0, dp(52), 2f).apply { leftMargin = dp(10) })
        return bar
    }

    // ------------------------------------------------------------------ 목소리 고르기
    private fun iconFor(p: VoicePreset): String = when {
        p.id.startsWith("news_f") -> "👩‍💼"
        p.id.startsWith("news_m") -> "👨‍💼"
        p.id.startsWith("girl") -> "🎀"
        p.id.startsWith("fem_") -> "👩"
        p.id == "grandma" -> "👵"
        p.id == "grandpa" -> "👴"
        p.id.startsWith("male_") -> "🧔"
        else -> mapOf(
            "giant" to "🗿", "child" to "🧒", "baby" to "👶", "helium" to "🎈", "squirrel" to "🐿️", "elf" to "🧚", "goblin" to "👺",
            "orc" to "👹", "monster" to "👾", "demon" to "😈", "alien" to "👽", "ghost" to "👻", "robot" to "🤖", "dalek" to "🛸",
            "whisper" to "🤫", "choir" to "🎶", "duet" to "👥", "autotune_hard" to "🎚️", "autotune_soft" to "🎚️", "opera" to "🎭",
            "nervous" to "😰", "doubler" to "👯", "chorus" to "👥", "dry" to "🎤", "echo" to "🏔️", "cave" to "🕳️", "cathedral" to "⛪",
            "bathroom" to "🚿", "telephone" to "☎️", "radio" to "📻", "megaphone" to "📢", "underwater" to "🌊", "flanger" to "✈️",
            "tremolo" to "〰️", "bitcrush" to "🎮", "studio" to "🎧",
        )[p.id] ?: "🎙️"
    }

    private fun categories(): List<String> = (if (st.recent.isNotEmpty()) listOf(RECENT) else emptyList()) + VoicePresets.GROUPS

    private fun buildCategories() {
        catRow.removeAllViews(); catChips.clear()
        val chips = categories().map { g ->
            UiKit.chip(this, if (g == RECENT) "★ 최근" else "$g ${VoicePresets.ALL.count { it.group == g }}", g == category) { category = g; st.category = g; buildCategories() }
                .also { catChips[g] = it }
        }
        catRow.addView(UiKit.chipRow(this, chips))
        buildGrid()
    }

    private fun buildGrid() {
        grid.removeAllViews()
        val list = if (category == RECENT) st.recent.mapNotNull { VoicePresets.byId(it) } else VoicePresets.ALL.filter { it.group == category }
        list.chunked(2).forEach { pair ->
            val row = LinearLayout(this).apply { orientation = LinearLayout.HORIZONTAL }
            pair.forEachIndexed { i, p ->
                row.addView(presetCard(p, p.id == st.presetId), LinearLayout.LayoutParams(0, WRAP_CONTENT, 1f).apply { if (i == 1) leftMargin = dp(10) })
            }
            if (pair.size == 1) row.addView(View(this), LinearLayout.LayoutParams(0, 1, 1f).apply { leftMargin = dp(10) })
            grid.addView(row, UiKit.params(bottom = 10, ctx = this))
        }
    }

    private fun presetCard(p: VoicePreset, selected: Boolean): LinearLayout = LinearLayout(this).apply {
        orientation = LinearLayout.HORIZONTAL; gravity = Gravity.CENTER_VERTICAL
        setPadding(dp(10), dp(10), dp(12), dp(10)); minimumHeight = dp(66); isClickable = true
        val base = if (selected) UiKit.rounded(this@VoiceChangerActivity, Pal.primarySoft, 16f, Pal.primary, 2) else UiKit.rounded(this@VoiceChangerActivity, Pal.surface, 16f, Pal.outline, 1)
        background = UiKit.ripple(this@VoiceChangerActivity, base, 16f)
        addView(UiKit.badge(this@VoiceChangerActivity, iconFor(p), 40, if (selected) Pal.surface else Pal.surface2, 19f))
        // 분류 칩(뉴스 여성 등)이 이미 성별을 알려 주므로 "최근" 목록에서만 성별을 덧붙임
        val (title, sub) = VoicePresets.labels(p.name, withGender = category == RECENT)
        addView(LinearLayout(this@VoiceChangerActivity).apply {
            orientation = LinearLayout.VERTICAL; setPadding(dp(10), 0, 0, 0)
            addView(TextView(this@VoiceChangerActivity).apply {
                text = UiKit.keepWords(title); textSize = 14f; maxLines = 2; typeface = Typeface.DEFAULT_BOLD
                setTextColor(if (selected) Pal.primaryDark else Pal.text)
            })
            if (sub != null) addView(TextView(this@VoiceChangerActivity).apply {
                text = UiKit.keepWords(sub); textSize = 11.5f; maxLines = 2; setTextColor(if (selected) Pal.primary else Pal.text2); setPadding(0, dp(1), 0, 0)
                breakStrategy = android.text.Layout.BREAK_STRATEGY_BALANCED
            })
        }, LinearLayout.LayoutParams(0, WRAP_CONTENT, 1f))
        setOnClickListener { select(p) }
    }

    private fun select(p: VoicePreset, save: Boolean = true) {
        st.presetId = p.id
        if (save) { st.touchRecent(p.id) }
        heroIcon.text = iconFor(p); heroName.text = p.name; heroDesc.text = p.desc
        runner.engine?.setChain(p.chain)
        if (save) { st.save(this); if (category != RECENT) buildCategories() else buildGrid() } else buildGrid()
        updateListenUi()
    }

    // ------------------------------------------------------------------ 상태 반영
    private fun applyToEngine() { runner.engine?.let { st.apply(it.controls) } }

    /** 스위치 설명·활성 상태를 현재 선택에 맞게 */
    private fun updateListenUi() {
        val p = VoicePresets.byId(st.presetId)!!
        monitorRow.desc.text = if (st.monitorOn) "변조된 목소리를 이어폰·스피커로 내보내요" else "소리를 내지 않아요 (녹음은 그대로 돼요)"
        val effectOnly = p.chain.isEffectOnly
        originalRow.sw.isEnabled = !effectOnly
        originalRow.view.alpha = if (effectOnly) 0.5f else 1f
        originalRow.desc.text = when {
            effectOnly -> "이 효과는 원본에 효과를 입히는 방식이라 항상 들어 있어요"
            st.originalOn -> "내 원래 목소리도 함께 내보내요"
            else -> "끄면 변조된 목소리만 나와요"
        }
        origBox.visibility = if (st.originalOn && !effectOnly) View.VISIBLE else View.GONE
        tuneNote.text = if (effectOnly) "이 효과는 목소리 자체를 바꾸지 않아서 음높이·굵기 조절은 적용되지 않아요." else ""
        tuneNote.visibility = if (effectOnly) View.VISIBLE else View.GONE
    }

    private fun updateButtons() {
        val on = runner.running
        startBtn.text = if (on) "■ 정지" else "▶ 시작"
        UiKit.styleButton(startBtn, if (on) BtnStyle.DANGER else BtnStyle.PRIMARY)
        startBtn.textSize = 16f
        recBtn.isEnabled = on
        if (!runner.recording) { recBtn.text = "● 녹음"; UiKit.styleButton(recBtn, BtnStyle.SOFT); recBtn.isEnabled = on }
    }

    private fun updateStatus() {
        val (txt, fg, bg) = when {
            !runner.running -> Triple("● 대기", Pal.text2, Pal.surface2)
            !st.monitorOn -> Triple("● 듣기 끔", Pal.warn, Pal.warnSoft)
            else -> Triple("● 변조 중", Pal.good, Pal.goodSoft)
        }
        statusChip.text = txt; statusChip.setTextColor(fg)
        statusChip.background = UiKit.rounded(this, bg, 20f)
        if (!runner.running) {
            statLatency.text = "시작하면 지연이 표시돼요"; statPitch.text = "내 음높이 측정 대기"
            inMeter.level = 0f; outMeter.level = 0f
        }
    }

    private fun db(x: Float) = ((20 * log10(x.coerceAtLeast(1e-4f)) + 70f) / 70f).coerceIn(0f, 1f)

    private fun refresh() {
        if (!runner.running) return
        inMeter.level = db(runner.inLevel); outMeter.level = db(runner.outLevel)
        val e = runner.engine ?: return
        statLatency.text = "지연 약 ${runner.latencyMs}ms"
        val out = e.outHz.roundToInt()
        statPitch.text = "내 목소리 ${e.tracker.userF0.roundToInt()}Hz" + if (out > 0 && !VoicePresets.byId(st.presetId)!!.chain.isEffectOnly) " → ${out}Hz" else ""
        pulse++
        statusChip.alpha = if (pulse % 10 < 5) 1f else 0.72f
        if (runner.recording) {
            val sec = runner.recordedSeconds.roundToInt()
            recBtn.text = "■ 녹음 끝 %d:%02d".format(sec / 60, sec % 60)
        }
    }

    // ------------------------------------------------------------------ 시작·정지·녹음
    private fun toggle() { if (runner.running) stopAll() else begin(check = true) }

    private fun begin(check: Boolean = false) {
        if (ContextCompat.checkSelfPermission(this, Manifest.permission.RECORD_AUDIO) != PackageManager.PERMISSION_GRANTED) { askMic.launch(Manifest.permission.RECORD_AUDIO); return }
        // 소리를 내보내는데 이어폰이 없으면 하울링 경고 (듣기를 꺼 두면 소리가 안 나가므로 경고하지 않음)
        if (check && st.monitorOn && !VoiceRunner.hasHeadphones(this)) {
            android.app.AlertDialog.Builder(this).setTitle("이어폰을 연결하세요")
                .setMessage("스피커로 소리를 내면 마이크로 다시 들어가 '삐—' 하는 소리가 나고 귀가 아플 수 있습니다. 이어폰(유선 권장)을 연결하는 것을 권장합니다.\n\n소리 없이 녹음만 하려면 '변조 목소리 듣기'를 끄세요.")
                .setPositiveButton("그래도 시작") { _, _ -> go() }.setNegativeButton("취소", null).show()
            return
        }
        go()
    }

    private fun go() {
        val chain = VoicePresets.byId(st.presetId)!!.chain
        runner.monitor = st.monitorOn
        val err = runner.start(chain) { e -> st.apply(e.controls) }
        if (err != null) { toast(err); return }
        updateButtons(); updateStatus()
        if (VoiceRunner.isBluetoothOutput(this)) toast("블루투스 이어폰은 지연이 0.2초 이상 늘어 말하기 어려워요. 유선 이어폰을 권장해요.")
        ui.post(tick)
    }

    private fun stopAll() {
        if (runner.recording) toggleRecord()
        runner.stop()
    }

    private fun onStopped(err: String?) {
        ui.removeCallbacks(tick)
        statusChip.alpha = 1f
        updateButtons(); updateStatus()
        if (err != null) toast("중지됨: $err")
    }

    private fun toggleRecord() {
        if (!runner.recording) { runner.beginRecording(); UiKit.styleButton(recBtn, BtnStyle.DANGER); recBtn.text = "■ 녹음 끝 0:00"; return }
        val name = "voice_${SimpleDateFormat("yyyyMMdd_HHmmss", Locale.KOREA).format(Date())}.wav"
        recBtn.text = "● 녹음"; UiKit.styleButton(recBtn, BtnStyle.SOFT)
        thread {
            val r = runCatching { runner.endRecordingAndSave(name) }
            runOnUiThread {
                val v = r.getOrNull()
                if (v == null) { Toast.makeText(this, "저장 실패: ${r.exceptionOrNull()?.message ?: "녹음된 소리가 없습니다"}", Toast.LENGTH_LONG).show(); return@runOnUiThread }
                android.app.AlertDialog.Builder(this).setTitle("녹음을 저장했습니다").setMessage(v.first)
                    .setPositiveButton("공유") { _, _ ->
                        runCatching { startActivity(Intent.createChooser(Intent(Intent.ACTION_SEND).setType("audio/wav").putExtra(Intent.EXTRA_STREAM, v.second).addFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION), "보내기")) }
                    }.setNegativeButton("닫기", null).show()
            }
        }
    }

    override fun onStop() { super.onStop(); if (runner.running) stopAll() } // 화면을 벗어나면 마이크를 놓음
    override fun onDestroy() { super.onDestroy(); ui.removeCallbacks(tick); runner.stop() }

    companion object { private const val RECENT = "최근" }
}
