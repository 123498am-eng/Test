package com.selfcheck.app

import android.Manifest
import android.annotation.SuppressLint
import android.content.Context
import android.content.pm.PackageManager
import android.graphics.Canvas
import android.graphics.Color
import android.graphics.Paint
import android.graphics.Path
import android.hardware.Sensor
import android.hardware.SensorEvent
import android.hardware.SensorEventListener
import android.hardware.SensorManager
import android.media.AudioFormat
import android.media.AudioManager
import android.media.AudioRecord
import android.media.MediaRecorder
import android.media.ToneGenerator
import android.os.Bundle
import android.view.View
import android.view.ViewGroup.LayoutParams.MATCH_PARENT
import android.widget.LinearLayout
import android.widget.TextView
import androidx.activity.result.contract.ActivityResultContracts
import androidx.core.content.ContextCompat
import kotlin.concurrent.thread
import kotlin.math.abs
import kotlin.math.atan2
import kotlin.math.cos
import kotlin.math.log10
import kotlin.math.max
import kotlin.math.min
import kotlin.math.roundToInt
import kotlin.math.sin
import kotlin.math.sqrt

/** 휴대폰 센서 도구: 수평계·소음·조도·나침반·진동·자기장(금속 탐지) */
class SensorActivity : ColumnActivity(), SensorEventListener {
    companion object {
        val TOOLS = listOf(
            Triple("level", "수평계", "액자·선반 수평 맞추기 (평평하면 삐 소리)"),
            Triple("sound", "소음 측정", "주변 소리 크기 (대략적인 dB)"),
            Triple("light", "조도계", "밝기(럭스)와 공부·작업에 알맞은지"),
            Triple("compass", "나침반", "방향과 각도"),
            Triple("vibration", "진동 측정", "흔들림 세기 그래프 (세탁기·차량 진동 등)"),
            Triple("magnet", "금속 탐지기", "자기장 변화로 쇠붙이·자석 찾기 (벽 속 철근 등)"),
        )
    }

    private lateinit var id: String
    private lateinit var big: TextView
    private lateinit var info: TextView
    private lateinit var gauge: Gauge
    private lateinit var sm: SensorManager
    private var tone: ToneGenerator? = null
    private val grav = FloatArray(3); private val geo = FloatArray(3)
    private var hasGrav = false; private var hasGeo = false
    private var base = -1f
    private var lastBeep = 0L
    @Volatile private var recording = false
    private var askedMic = false
    private var minV = Float.MAX_VALUE; private var maxV = -Float.MAX_VALUE; private var sumV = 0.0; private var nV = 0
    private val askMic = registerForActivityResult(ActivityResultContracts.RequestPermission()) { ok -> if (ok) startMic() else info.text = "마이크 권한이 필요합니다" }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        id = intent.getStringExtra("tool") ?: ""
        val t = TOOLS.firstOrNull { it.first == id } ?: run { finish(); return }
        setupColumn(t.second, t.third)
        sm = getSystemService(SensorManager::class.java)
        tone = runCatching { ToneGenerator(AudioManager.STREAM_MUSIC, 70) }.getOrNull()
        big = TextView(this).apply { textSize = 44f; setTextColor(Pal.text); setPadding(dp(4), dp(8), 0, 0); typeface = android.graphics.Typeface.DEFAULT_BOLD }
        col.addView(big)
        info = hint("")
        col.addView(info)
        gauge = Gauge(this, id)
        col.addView(gauge, LinearLayout.LayoutParams(MATCH_PARENT, (resources.displayMetrics.widthPixels * 0.9f).toInt()).apply { topMargin = dp(12) })
        if (id == "sound" || id == "vibration" || id == "magnet") full(button("최소·최대 초기화") { minV = Float.MAX_VALUE; maxV = -Float.MAX_VALUE; sumV = 0.0; nV = 0; base = -1f; gauge.history.clear() })
    }

    override fun onResume() {
        super.onResume()
        fun reg(type: Int): Boolean { val s = sm.getDefaultSensor(type) ?: return false; sm.registerListener(this, s, SensorManager.SENSOR_DELAY_GAME); return true }
        val ok = when (id) {
            "level" -> reg(Sensor.TYPE_GRAVITY) || reg(Sensor.TYPE_ACCELEROMETER)
            "light" -> reg(Sensor.TYPE_LIGHT)
            "compass" -> (reg(Sensor.TYPE_GRAVITY) || reg(Sensor.TYPE_ACCELEROMETER)) && reg(Sensor.TYPE_MAGNETIC_FIELD)
            "vibration" -> reg(Sensor.TYPE_LINEAR_ACCELERATION) || reg(Sensor.TYPE_ACCELEROMETER)
            "magnet" -> reg(Sensor.TYPE_MAGNETIC_FIELD)
            "sound" -> {
                if (ContextCompat.checkSelfPermission(this, Manifest.permission.RECORD_AUDIO) == PackageManager.PERMISSION_GRANTED) startMic()
                else if (!askedMic) { askedMic = true; askMic.launch(Manifest.permission.RECORD_AUDIO) } // 한 번만 묻기 (거절 후 다시 묻는 반복 방지)
                true
            }
            else -> false
        }
        if (!ok) { big.textSize = 20f; big.text = "이 휴대폰에는 필요한 센서가 없어요" }
    }

    override fun onPause() { super.onPause(); sm.unregisterListener(this); recording = false }
    override fun onDestroy() { super.onDestroy(); tone?.release() }
    override fun onAccuracyChanged(sensor: Sensor?, accuracy: Int) {}

    private fun beep(intervalMs: Long, kind: Int = ToneGenerator.TONE_PROP_BEEP) {
        val now = System.currentTimeMillis(); if (now - lastBeep < intervalMs) return
        lastBeep = now; runCatching { tone?.startTone(kind, 80) }
    }
    private fun stat(v: Float) { minV = min(minV, v); maxV = max(maxV, v); sumV += v; nV++ }

    override fun onSensorChanged(e: SensorEvent) {
        when (e.sensor.type) {
            Sensor.TYPE_GRAVITY, Sensor.TYPE_ACCELEROMETER -> {
                if (id == "vibration") { vib(sqrt(e.values[0] * e.values[0] + e.values[1] * e.values[1] + e.values[2] * e.values[2]) - SensorManager.GRAVITY_EARTH); return }
                for (i in 0..2) grav[i] = if (hasGrav && e.sensor.type == Sensor.TYPE_ACCELEROMETER) grav[i] * 0.85f + e.values[i] * 0.15f else e.values[i]
                hasGrav = true
                if (id == "level") level()
                else if (id == "compass") compass()
            }
            Sensor.TYPE_LINEAR_ACCELERATION -> vib(sqrt(e.values[0] * e.values[0] + e.values[1] * e.values[1] + e.values[2] * e.values[2]))
            Sensor.TYPE_MAGNETIC_FIELD -> {
                for (i in 0..2) geo[i] = e.values[i]; hasGeo = true
                if (id == "compass") compass() else magnet()
            }
            Sensor.TYPE_LIGHT -> light(e.values[0])
        }
    }

    private fun level() {
        val g = sqrt(grav[0] * grav[0] + grav[1] * grav[1] + grav[2] * grav[2]).coerceAtLeast(0.1f)
        val flat = abs(grav[2]) / g > 0.7f // 바닥에 눕혀 놓음
        val (a, b) = if (flat) {
            Math.toDegrees(atan2(grav[0].toDouble(), grav[2].toDouble())).toFloat() to Math.toDegrees(atan2(grav[1].toDouble(), grav[2].toDouble())).toFloat()
        } else Math.toDegrees(atan2(grav[0].toDouble(), grav[1].toDouble())).toFloat() to 0f
        big.text = if (flat) "%.1f° / %.1f°".format(a, b) else "%.1f°".format(a)
        val ok = abs(a) < 0.5f && abs(b) < 0.5f
        info.text = (if (flat) "바닥에 눕힌 상태: 좌우 / 앞뒤 기울기" else "세운 상태: 휴대폰 긴 변을 맞대고 기울기를 보세요") + if (ok) "\n✔ 수평입니다" else ""
        big.setTextColor(if (ok) Pal.good else Pal.text)
        if (ok) beep(1200, ToneGenerator.TONE_PROP_ACK)
        gauge.a = a; gauge.b = b; gauge.flat = flat; gauge.invalidate()
    }

    private fun compass() {
        if (!hasGrav || !hasGeo) return
        val r = FloatArray(9); val o = FloatArray(3)
        if (!SensorManager.getRotationMatrix(r, null, grav, geo)) return
        SensorManager.getOrientation(r, o)
        var az = Math.toDegrees(o[0].toDouble()).toFloat(); if (az < 0) az += 360f
        gauge.a = gauge.a + (((az - gauge.a + 540f) % 360f) - 180f) * 0.15f // 부드럽게
        val d = (gauge.a + 360f) % 360f
        val names = listOf("북", "북동", "동", "남동", "남", "남서", "서", "북서")
        big.text = "${names[((d + 22.5f) / 45f).toInt() % 8]} ${d.roundToInt()}°"
        info.text = "휴대폰을 평평하게 들고, 8자를 그리듯 돌리면 더 정확해집니다 (자석·쇠붙이 근처에서는 틀림)"
        gauge.invalidate()
    }

    private fun light(lux: Float) {
        stat(lux)
        big.text = "${lux.roundToInt()} 럭스"
        info.text = when {
            lux < 50 -> "매우 어두움 — 독서·공부에 부족 (300~500 럭스 권장)"
            lux < 300 -> "조금 어두움 — 책 읽기에는 더 밝게 (300~500)"
            lux < 1000 -> "책 읽기·공부에 알맞음"
            lux < 10000 -> "매우 밝음 (흐린 날 바깥 정도)"
            else -> "햇빛 수준"
        } + "\n센서는 보통 휴대폰 앞면 위쪽에 있습니다"
        gauge.push(log10(max(lux, 1f)) / 5f); gauge.invalidate()
    }

    private fun vib(m: Float) {
        val v = abs(m); stat(v)
        gauge.push((v / 5f).coerceAtMost(1f)); gauge.invalidate()
        big.text = "%.2f m/s²".format(v)
        info.text = "최대 %.2f · 평균 %.2f — ".format(maxV, sumV / max(1, nV)) + when { v < 0.05f -> "고요함"; v < 0.3f -> "약한 진동"; v < 1.5f -> "느껴지는 진동"; else -> "강한 진동" } +
            "\n휴대폰을 대상 위에 올려 두세요"
    }

    private fun magnet() {
        val m = sqrt(geo[0] * geo[0] + geo[1] * geo[1] + geo[2] * geo[2]); stat(m)
        if (base < 0) base = m
        val d = abs(m - base)
        big.text = "${m.roundToInt()} μT"
        info.text = "기준 ${base.roundToInt()} μT 와 차이 ${d.roundToInt()} μT — " + when { d < 10 -> "변화 없음"; d < 40 -> "쇠붙이 가까이 있음"; else -> "강한 자기장 (자석·전자제품)" } +
            "\n지구 자기장은 보통 25~65 μT. 쇠붙이가 없는 곳에서 '초기화'를 눌러 기준을 다시 잡으세요"
        if (d > 10) beep((900 - d * 8).toLong().coerceIn(80L, 900L))
        gauge.push((d / 100f).coerceAtMost(1f)); gauge.invalidate()
    }

    @SuppressLint("MissingPermission")
    private fun startMic() {
        if (recording) return
        recording = true
        thread {
            val rate = 44100
            val bufSize = max(AudioRecord.getMinBufferSize(rate, AudioFormat.CHANNEL_IN_MONO, AudioFormat.ENCODING_PCM_16BIT), 4096)
            val rec = runCatching { AudioRecord(MediaRecorder.AudioSource.MIC, rate, AudioFormat.CHANNEL_IN_MONO, AudioFormat.ENCODING_PCM_16BIT, bufSize) }.getOrNull()
            if (rec == null || rec.state != AudioRecord.STATE_INITIALIZED) { runOnUiThread { info.text = "마이크를 열 수 없습니다" }; recording = false; return@thread }
            val buf = ShortArray(rate / 10)
            rec.startRecording()
            try {
                while (recording) {
                    val n = rec.read(buf, 0, buf.size); if (n <= 0) continue
                    var s = 0.0; for (i in 0 until n) s += buf[i].toDouble() * buf[i]
                    val rms = sqrt(s / n)
                    val dbfs = 20 * log10(max(rms, 1.0) / 32768.0)
                    val db = (dbfs + 94).toFloat().coerceAtLeast(20f) // 휴대폰마다 다름: 대략적인 값
                    runOnUiThread {
                        stat(db)
                        big.text = "${db.roundToInt()} dB"
                        info.text = "최소 ${minV.roundToInt()} · 최대 ${maxV.roundToInt()} · 평균 ${(sumV / max(1, nV)).roundToInt()} dB — " + when {
                            db < 40 -> "조용함 (도서관)"; db < 60 -> "보통 (사무실·대화)"; db < 75 -> "시끄러움 (번화가)"; db < 85 -> "매우 시끄러움 (지하철)"
                            else -> "위험 — 오래 들으면 청력 손상"
                        } + "\n휴대폰 마이크로 잰 대략적인 값입니다 (정밀 측정 아님)"
                        gauge.push(((db - 20f) / 80f).coerceIn(0f, 1f)); gauge.invalidate()
                    }
                }
            } finally { runCatching { rec.stop() }; rec.release() }
        }
    }

    /** 도구마다 다른 그림 (수평 기포, 나침반, 그래프) */
    class Gauge(ctx: Context, private val id: String) : View(ctx) {
        var a = 0f; var b = 0f; var flat = false
        val history = ArrayDeque<Float>()
        private val p = Paint(Paint.ANTI_ALIAS_FLAG)
        fun push(v: Float) { history.addLast(v); while (history.size > 200) history.removeFirst() }
        override fun onDraw(c: Canvas) {
            val w = width.toFloat(); val h = height.toFloat(); val cx = w / 2; val cy = h / 2; val r = min(w, h) * 0.42f
            when (id) {
                "level" -> {
                    p.style = Paint.Style.FILL; p.color = 0xFFE8F6EC.toInt(); c.drawCircle(cx, cy, r, p)
                    p.style = Paint.Style.STROKE; p.strokeWidth = 4f; p.color = 0xFFB7C4DC.toInt(); c.drawCircle(cx, cy, r, p); c.drawCircle(cx, cy, r * 0.12f, p)
                    c.drawLine(cx - r, cy, cx + r, cy, p); c.drawLine(cx, cy - r, cx, cy + r, p)
                    val bx = cx - (a / 15f).coerceIn(-1f, 1f) * r * 0.85f
                    val by = if (flat) cy + (b / 15f).coerceIn(-1f, 1f) * r * 0.85f else cy
                    p.style = Paint.Style.FILL; p.color = if (abs(a) < 0.5f && abs(b) < 0.5f) Color.rgb(40, 180, 80) else Color.rgb(250, 190, 40)
                    c.drawCircle(bx, by, r * 0.1f, p)
                }
                "compass" -> {
                    c.save(); c.rotate(-a, cx, cy)
                    p.style = Paint.Style.STROKE; p.strokeWidth = 4f; p.color = Color.DKGRAY; c.drawCircle(cx, cy, r, p)
                    p.style = Paint.Style.FILL; p.textSize = r * 0.18f; p.textAlign = Paint.Align.CENTER
                    for ((i, n) in listOf("N", "E", "S", "W").withIndex()) {
                        val ang = Math.toRadians(i * 90.0); p.color = if (i == 0) Color.rgb(220, 40, 40) else Color.BLACK
                        c.drawText(n, cx + (sin(ang) * r * 0.78f).toFloat(), cy - (cos(ang) * r * 0.78f).toFloat() + p.textSize / 3, p)
                    }
                    for (d in 0 until 360 step 15) { val ang = Math.toRadians(d.toDouble()); val k = if (d % 90 == 0) 0.88f else 0.93f
                        p.color = Color.GRAY; p.strokeWidth = 2f
                        c.drawLine(cx + (sin(ang) * r * k).toFloat(), cy - (cos(ang) * r * k).toFloat(), cx + (sin(ang) * r).toFloat(), cy - (cos(ang) * r).toFloat(), p) }
                    c.restore()
                    val path = Path().apply { moveTo(cx, cy - r * 0.95f); lineTo(cx - r * 0.06f, cy - r * 0.8f); lineTo(cx + r * 0.06f, cy - r * 0.8f); close() }
                    p.color = Color.rgb(220, 40, 40); c.drawPath(path, p)
                }
                else -> {
                    p.style = Paint.Style.FILL; p.color = Color.rgb(244, 246, 250); c.drawRect(0f, 0f, w, h, p)
                    if (history.size < 2) return
                    p.style = Paint.Style.STROKE; p.strokeWidth = 4f; p.color = Color.rgb(40, 110, 230)
                    val path = Path()
                    history.forEachIndexed { i, v -> val x = w * i / 199f; val y = h - v.coerceIn(0f, 1f) * h * 0.95f; if (i == 0) path.moveTo(x, y) else path.lineTo(x, y) }
                    c.drawPath(path, p)
                }
            }
        }
    }
}
