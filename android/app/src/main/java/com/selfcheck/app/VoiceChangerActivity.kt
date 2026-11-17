package com.selfcheck.app

import android.Manifest
import android.content.Intent
import android.content.pm.PackageManager
import android.graphics.Color
import android.graphics.Typeface
import android.graphics.drawable.GradientDrawable
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
import android.widget.ProgressBar
import android.widget.ScrollView
import android.widget.SeekBar
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
    private lateinit var startBtn: Button
    private lateinit var recBtn: Button
    private lateinit var status: TextView
    private lateinit var presetInfo: TextView
    private lateinit var inBar: ProgressBar
    private lateinit var outBar: ProgressBar
    private val presetButtons = HashMap<String, Button>()
    private val ui = Handler(Looper.getMainLooper())
    private var lastSaved: android.net.Uri? = null
    private val tick = object : Runnable {
        override fun run() { refresh(); ui.postDelayed(this, 100) }
    }
    private val askMic = registerForActivityResult(ActivityResultContracts.RequestPermission()) { ok ->
        if (ok) begin() else status.text = "마이크 권한이 필요합니다 (설정 → 앱 → 권한)"
    }

    private fun dp(v: Int) = (v * resources.displayMetrics.density).toInt()

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        window.addFlags(WindowManager.LayoutParams.FLAG_KEEP_SCREEN_ON)
        runner = VoiceRunner(this) { err -> runOnUiThread { onStopped(err) } }

        val root = LinearLayout(this).apply { orientation = LinearLayout.VERTICAL; setBackgroundColor(Color.WHITE) }
        root.setOnApplyWindowInsetsListener { v, insets ->
            @Suppress("DEPRECATION")
            v.setPadding(0, insets.systemWindowInsetTop, 0, insets.systemWindowInsetBottom); insets
        }
        // ---- 위쪽 고정 영역
        val top = LinearLayout(this).apply { orientation = LinearLayout.VERTICAL; setPadding(dp(14), dp(10), dp(14), dp(6)) }
        top.addView(TextView(this).apply { text = "실시간 음성 변조"; textSize = 20f; setTypeface(null, Typeface.BOLD); setTextColor(Color.BLACK) })
        presetInfo = TextView(this).apply { textSize = 13f; setTextColor(Color.DKGRAY) }
        top.addView(presetInfo)

        val row = LinearLayout(this).apply { orientation = LinearLayout.HORIZONTAL }
        startBtn = Button(this).apply { text = "시작"; textSize = 16f; setOnClickListener { toggle() } }
        recBtn = Button(this).apply { text = "녹음"; isEnabled = false; setOnClickListener { toggleRecord() } }
        row.addView(startBtn, LinearLayout.LayoutParams(0, WRAP_CONTENT, 2f))
        row.addView(recBtn, LinearLayout.LayoutParams(0, WRAP_CONTENT, 1f))
        top.addView(row)
        status = TextView(this).apply { textSize = 12f; setTextColor(Color.DKGRAY); text = "이어폰을 끼고 [시작]을 누르세요" }
        top.addView(status)
        val levels = LinearLayout(this).apply { orientation = LinearLayout.HORIZONTAL; setPadding(0, dp(4), 0, 0) }
        fun lv(label: String): ProgressBar {
            levels.addView(TextView(this).apply { text = label; textSize = 11f; setTextColor(Color.GRAY); setPadding(0, 0, dp(4), 0) })
            return ProgressBar(this, null, android.R.attr.progressBarStyleHorizontal).apply { max = 100 }
                .also { levels.addView(it, LinearLayout.LayoutParams(0, dp(10), 1f).apply { rightMargin = dp(10) }) }
        }
        inBar = lv("입력"); outBar = lv("출력")
        top.addView(levels)

        fun slider(label: String, max: Int, init: Int, fmt: (Int) -> String, onChange: (Int) -> Unit) {
            val l = LinearLayout(this).apply { orientation = LinearLayout.HORIZONTAL; gravity = Gravity.CENTER_VERTICAL }
            val t = TextView(this).apply { text = label; textSize = 12f; setTextColor(Color.BLACK) }
            val v = TextView(this).apply { text = fmt(init); textSize = 12f; setTextColor(Color.DKGRAY); gravity = Gravity.END }
            l.addView(t, LinearLayout.LayoutParams(dp(78), WRAP_CONTENT))
            l.addView(SeekBar(this).apply {
                this.max = max; progress = init
                setOnSeekBarChangeListener(object : SeekBar.OnSeekBarChangeListener {
                    override fun onProgressChanged(sb: SeekBar, p: Int, u: Boolean) { v.text = fmt(p); onChange(p); runner.engine?.let { st.apply(it.controls) } }
                    override fun onStartTrackingTouch(sb: SeekBar) {}
                    override fun onStopTrackingTouch(sb: SeekBar) {}
                })
            }, LinearLayout.LayoutParams(0, WRAP_CONTENT, 1f))
            l.addView(v, LinearLayout.LayoutParams(dp(54), WRAP_CONTENT))
            top.addView(l)
        }
        slider("음높이", 120, 60, { "%+.1f 반음".format((it - 60) / 10f) }) { st.semitones = (it - 60) / 10f }
        slider("목소리 굵기", 60, 30, { "%d%%".format(70 + it) }) { st.formant = (70 + it) / 100f }
        slider("효과 세기", 150, 100, { "%d%%".format(it) }) { st.fxAmount = it / 100f }
        slider("마이크 감도", 300, 100, { "%d%%".format(it + 50) }) { st.micGain = (it + 50) / 100f }
        top.addView(TextView(this).apply {
            text = "※ 이어폰을 끼지 않으면 스피커 소리가 마이크로 들어가 삐— 소리가 납니다. 통화·다른 앱의 마이크로는 변조된 소리를 보낼 수 없고(안드로이드 제한), " +
                "변조한 소리는 이 앱에서 듣거나 [녹음] 후 공유할 수 있습니다. 다른 사람을 속이는 목적(사칭·보이스피싱 등)으로 쓰지 마세요."
            textSize = 11f; setTextColor(Color.rgb(150, 80, 0)); setPadding(0, dp(4), 0, 0)
        })
        root.addView(top, LinearLayout.LayoutParams(MATCH_PARENT, WRAP_CONTENT))

        // ---- 프리셋 목록
        val list = LinearLayout(this).apply { orientation = LinearLayout.VERTICAL; setPadding(dp(10), 0, dp(10), dp(24)) }
        for (g in VoicePresets.GROUPS) {
            list.addView(TextView(this).apply { text = "$g (${VoicePresets.ALL.count { it.group == g }})"; textSize = 15f; setTypeface(null, Typeface.BOLD); setTextColor(Color.BLACK); setPadding(dp(4), dp(14), 0, dp(4)) })
            VoicePresets.ALL.filter { it.group == g }.chunked(2).forEach { pair ->
                val r = LinearLayout(this).apply { orientation = LinearLayout.HORIZONTAL }
                for (p in pair) {
                    val b = Button(this).apply { text = p.name; textSize = 13f; isAllCaps = false; setOnClickListener { select(p) } }
                    presetButtons[p.id] = b
                    r.addView(b, LinearLayout.LayoutParams(0, WRAP_CONTENT, 1f).apply { setMargins(dp(2), 0, dp(2), 0) })
                }
                if (pair.size == 1) r.addView(View(this), LinearLayout.LayoutParams(0, 1, 1f))
                list.addView(r)
            }
        }
        root.addView(ScrollView(this).apply { addView(list) }, LinearLayout.LayoutParams(MATCH_PARENT, 0, 1f))
        setContentView(root)
        select(VoicePresets.byId(st.presetId)!!)
    }

    private fun select(p: VoicePreset) {
        st.presetId = p.id
        presetInfo.text = "${p.name} — ${p.desc}"
        for ((id, b) in presetButtons) {
            val sel = id == p.id
            b.setTextColor(if (sel) Color.WHITE else Color.BLACK)
            b.background = GradientDrawable().apply { cornerRadius = dp(8).toFloat(); setColor(if (sel) Color.rgb(40, 110, 230) else Color.rgb(236, 238, 242)) }
        }
        runner.engine?.setChain(p.chain)
    }

    private fun toggle() { if (runner.running) stopAll() else begin(check = true) }

    private fun begin(check: Boolean = false) {
        if (ContextCompat.checkSelfPermission(this, Manifest.permission.RECORD_AUDIO) != PackageManager.PERMISSION_GRANTED) { askMic.launch(Manifest.permission.RECORD_AUDIO); return }
        if (check && !VoiceRunner.hasHeadphones(this)) {
            android.app.AlertDialog.Builder(this).setTitle("이어폰을 연결하세요")
                .setMessage("스피커로 소리를 내면 마이크로 다시 들어가 '삐—' 하는 하울링이 생기고 귀가 아플 수 있습니다. 이어폰(유선 권장)을 연결하고 시작하는 것을 권장합니다.")
                .setPositiveButton("그래도 시작") { _, _ -> go() }.setNegativeButton("취소", null).show()
            return
        }
        go()
    }

    private fun go() {
        val chain = VoicePresets.byId(st.presetId)!!.chain
        val err = runner.start(chain) { e -> st.apply(e.controls) }
        if (err != null) { status.text = err; return }
        startBtn.text = "정지"; recBtn.isEnabled = true
        val bt = VoiceRunner.isBluetoothOutput(this)
        status.text = "변조 중 · 예상 지연 약 ${runner.latencyMs}ms" + if (bt) "\n블루투스 이어폰은 지연이 0.2초 이상 늘어 말하기 어렵습니다. 유선 이어폰을 권장합니다." else ""
        ui.post(tick)
    }

    private fun stopAll() {
        if (runner.recording) toggleRecord()
        runner.stop()
    }

    private fun onStopped(err: String?) {
        ui.removeCallbacks(tick)
        startBtn.text = "시작"; recBtn.isEnabled = false; recBtn.text = "녹음"
        inBar.progress = 0; outBar.progress = 0
        status.text = if (err != null) "중지됨: $err" else "정지했습니다"
    }

    private fun toggleRecord() {
        if (!runner.recording) { runner.beginRecording(); recBtn.text = "녹음 끝"; return }
        recBtn.text = "녹음"
        val name = "voice_${SimpleDateFormat("yyyyMMdd_HHmmss", Locale.KOREA).format(Date())}.wav"
        thread {
            val r = runCatching { runner.endRecordingAndSave(name) }
            runOnUiThread {
                val v = r.getOrNull()
                if (v == null) { Toast.makeText(this, "저장 실패: ${r.exceptionOrNull()?.message ?: "녹음된 소리가 없습니다"}", Toast.LENGTH_LONG).show(); return@runOnUiThread }
                lastSaved = v.second
                android.app.AlertDialog.Builder(this).setTitle("녹음을 저장했습니다").setMessage(v.first)
                    .setPositiveButton("공유") { _, _ ->
                        runCatching { startActivity(Intent.createChooser(Intent(Intent.ACTION_SEND).setType("audio/wav").putExtra(Intent.EXTRA_STREAM, v.second).addFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION), "보내기")) }
                    }.setNegativeButton("닫기", null).show()
            }
        }
    }

    private fun db(x: Float) = ((20 * log10(x.coerceAtLeast(1e-4f)) + 70f) / 70f * 100f).roundToInt().coerceIn(0, 100)

    private fun refresh() {
        if (!runner.running) return
        inBar.progress = db(runner.inLevel); outBar.progress = db(runner.outLevel)
        val e = runner.engine ?: return
        val f0 = e.tracker.curF0
        val sb = StringBuilder("변조 중 · 지연 약 ${runner.latencyMs}ms")
        if (e.tracker.userF0 > 0) sb.append(" · 내 평균 음높이 ${e.tracker.userF0.roundToInt()}Hz")
        if (f0 > 0) sb.append(" → ${e.outHz.roundToInt().takeIf { it > 0 } ?: "-"}Hz")
        if (runner.recording) sb.append("\n● 녹음 중 ${runner.recordedSeconds.roundToInt()}초")
        status.text = sb.toString()
    }

    override fun onStop() { super.onStop(); if (runner.running) stopAll() } // 화면을 벗어나면 마이크를 놓음
    override fun onDestroy() { super.onDestroy(); ui.removeCallbacks(tick); runner.stop() }
}
