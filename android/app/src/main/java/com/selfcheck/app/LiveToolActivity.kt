package com.selfcheck.app

import android.Manifest
import android.content.Context
import android.content.Intent
import android.content.pm.PackageManager
import android.graphics.Bitmap
import android.graphics.Canvas
import android.graphics.Color
import android.graphics.Matrix
import android.graphics.Paint
import android.graphics.RectF
import android.hardware.camera2.CameraCharacteristics
import android.media.AudioManager
import android.media.ToneGenerator
import android.net.Uri
import android.os.Bundle
import android.os.SystemClock
import android.util.Size
import android.view.Gravity
import android.view.MotionEvent
import android.view.View
import android.view.ViewGroup.LayoutParams.MATCH_PARENT
import android.view.ViewGroup.LayoutParams.WRAP_CONTENT
import android.widget.Button
import android.widget.FrameLayout
import android.widget.LinearLayout
import android.widget.TextView
import android.widget.Toast
import androidx.activity.ComponentActivity
import androidx.activity.result.contract.ActivityResultContracts
import androidx.camera.camera2.interop.Camera2CameraInfo
import androidx.camera.camera2.interop.ExperimentalCamera2Interop
import androidx.camera.core.Camera
import androidx.camera.core.CameraSelector
import androidx.camera.core.ImageAnalysis
import androidx.camera.core.ImageProxy
import androidx.camera.core.Preview
import androidx.camera.core.resolutionselector.AspectRatioStrategy
import androidx.camera.core.resolutionselector.ResolutionSelector
import androidx.camera.core.resolutionselector.ResolutionStrategy
import androidx.camera.lifecycle.ProcessCameraProvider
import androidx.camera.view.PreviewView
import androidx.core.content.ContextCompat
import com.google.android.gms.tasks.Tasks
import com.google.mediapipe.framework.image.BitmapImageBuilder
import com.google.mediapipe.tasks.components.containers.NormalizedLandmark
import com.google.mediapipe.tasks.core.BaseOptions
import com.google.mediapipe.tasks.core.Delegate
import com.google.mediapipe.tasks.vision.core.RunningMode
import com.google.mediapipe.tasks.vision.facelandmarker.FaceLandmarker
import com.google.mediapipe.tasks.vision.gesturerecognizer.GestureRecognizer
import com.google.mediapipe.tasks.vision.objectdetector.ObjectDetector
import com.google.mediapipe.tasks.vision.poselandmarker.PoseLandmarker
import com.google.mlkit.vision.barcode.BarcodeScanner
import com.google.mlkit.vision.barcode.BarcodeScanning
import com.google.mlkit.vision.barcode.common.Barcode
import com.google.mlkit.vision.common.InputImage
import java.util.concurrent.Executors
import kotlin.concurrent.thread
import kotlin.math.abs
import kotlin.math.atan2
import kotlin.math.hypot
import kotlin.math.max
import kotlin.math.min
import kotlin.math.roundToInt

class LiveToolDef(val id: String, val title: String, val desc: String, val front: Boolean)

object LiveTools {
    val ALL = listOf(
        LiveToolDef("qr", "QR·바코드 스캔", "QR 코드·바코드를 읽고 링크가 위험한지(큐싱) 검사", false),
        LiveToolDef("gesture", "손동작 인식", "주먹·손바닥·브이·엄지 위/아래·검지·사랑해 7가지", true),
        LiveToolDef("fingers", "손가락 숫자 세기", "펼친 손가락 개수 (두 손 0~10)", true),
        LiveToolDef("squat", "스쿼트 횟수", "무릎 각도로 횟수 세기 (몸 전체가 보이게 세워 두세요)", true),
        LiveToolDef("pushup", "팔굽혀펴기 횟수", "팔꿈치 각도로 횟수 세기 (옆에서 찍기)", true),
        LiveToolDef("jumping", "팔벌려뛰기 횟수", "팔·다리를 벌렸다 모으면 1회", true),
        LiveToolDef("plank", "플랭크 타이머", "몸이 일직선일 때만 시간이 갑니다 (옆에서 찍기)", true),
        LiveToolDef("posture", "자세 교정 알림", "어깨 기울기·고개 숙임(거북목)이 5초 넘으면 알림", true),
        LiveToolDef("drowsy", "졸음 감지", "눈을 1.2초 넘게 감으면 경보음 (공부·작업용, 운전 중 조작 금지)", true),
        LiveToolDef("blink", "눈 깜빡임 측정", "분당 깜빡임 수 (화면을 오래 보면 줄어듭니다)", true),
        LiveToolDef("smile", "미소 셔터", "웃으면 자동으로 사진을 찍어 저장", true),
        LiveToolDef("heart", "심박수 측정 (참고용)", "얼굴 피부색 또는 손가락(플래시)의 미세한 변화로 맥박 추정. 의료 기기가 아닙니다.", true),
        LiveToolDef("color", "색상 찾기", "화면 가운데(또는 누른 곳)의 색 이름·색 코드", false),
        LiveToolDef("distance", "얼굴 거리 측정", "화면과 눈 사이 거리 (홍채 크기 기준), 30cm 보다 가까우면 경고", true),
        LiveToolDef("expression", "표정 인식", "웃음·놀람·찡그림·윙크 등 실시간 표정", true),
        LiveToolDef("objects", "물체 개수 세기", "사람·자동차·컵 등 80종류를 종류별로 세기", false),
    )
    fun byId(id: String) = ALL.firstOrNull { it.id == id }
}

/** 화면에 그릴 내용 */
class ToolFrame(val big: String, val text: String, val color: Int = Color.WHITE, val draw: ((Canvas, Float) -> Unit)? = null)

class ToolOverlay(ctx: Context) : View(ctx) {
    private var frame: ToolFrame? = null
    private var bw = 1; private var bh = 1
    var onTapImage: ((Float, Float) -> Unit)? = null
    fun set(f: ToolFrame, w: Int, h: Int) { frame = f; bw = w; bh = h; invalidate() }
    private fun scale() = max(width / bw.toFloat(), height / bh.toFloat())
    override fun onDraw(c: Canvas) {
        val d = frame?.draw ?: return
        val s = scale(); c.save(); c.translate((width - bw * s) / 2, (height - bh * s) / 2); c.scale(s, s); d(c, 1f / s); c.restore()
    }
    override fun onTouchEvent(e: MotionEvent): Boolean {
        if (e.actionMasked == MotionEvent.ACTION_UP) {
            val s = scale(); onTapImage?.invoke((e.x - (width - bw * s) / 2) / s, (e.y - (height - bh * s) / 2) / s)
        }
        return true
    }
}

class LiveToolActivity : ComponentActivity() {
    private lateinit var def: LiveToolDef
    private lateinit var previewView: PreviewView
    private lateinit var overlay: ToolOverlay
    private lateinit var big: TextView
    private lateinit var info: TextView
    private lateinit var bar: LinearLayout
    private val exec = Executors.newSingleThreadExecutor()
    private var front = true
    private var camera: Camera? = null
    @Volatile private var lastTs = 0L
    @Volatile private var running = true
    private var tone: ToneGenerator? = null
    private var focalPx = 0f // 분석 사진 긴 변 1px 당 초점 거리 비율 (f_mm / 센서 긴 변 mm)

    // 모델 (분석 스레드에서만 사용)
    private var face: FaceLandmarker? = null
    private var pose: PoseLandmarker? = null
    private var gest: GestureRecognizer? = null
    private var barcode: BarcodeScanner? = null
    private var det: ObjectDetector? = null

    // 상태
    private val rep = RepCounter(100f, 160f)
    private val pushRep = RepCounter(90f, 155f)
    private val jj = TwoStateCounter()
    private var plankSec = 0.0; private var lastT = 0.0
    private val blinks = BlinkCounter()
    private var yawnSince = -1.0; private var yawns = 0
    private var lastAlarm = 0.0
    private var badSince = -1.0
    private var baseNeck = 0f; private var neckSamples = ArrayList<Float>()
    @Volatile private var setBase = false
    private var smileSince = -1.0; private var lastShot = 0.0
    private val heart = HeartRate()
    @Volatile private var fingerMode = false
    @Volatile private var tapX = -1f; @Volatile private var tapY = -1f
    private val seen = LinkedHashMap<String, String>()
    @Volatile private var lastCode: String? = null
    @Volatile private var resetAll = false

    private val askCamera = registerForActivityResult(ActivityResultContracts.RequestPermission()) { ok -> if (ok) startCamera() else info.text = "카메라 권한이 필요합니다" }

    private fun dp(v: Int) = (v * resources.displayMetrics.density).toInt()

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        def = LiveTools.byId(intent.getStringExtra("tool") ?: "") ?: run { finish(); return }
        front = def.front
        tone = runCatching { ToneGenerator(AudioManager.STREAM_MUSIC, 90) }.getOrNull()
        val root = FrameLayout(this).apply { setBackgroundColor(Color.BLACK) }
        previewView = PreviewView(this).apply { implementationMode = PreviewView.ImplementationMode.PERFORMANCE; scaleType = PreviewView.ScaleType.FILL_CENTER }
        root.addView(previewView, FrameLayout.LayoutParams(MATCH_PARENT, MATCH_PARENT))
        overlay = ToolOverlay(this)
        overlay.onTapImage = { x, y -> tapX = x; tapY = y }
        root.addView(overlay, FrameLayout.LayoutParams(MATCH_PARENT, MATCH_PARENT))
        val top = LinearLayout(this).apply { orientation = LinearLayout.VERTICAL; setPadding(dp(12), dp(8), dp(12), dp(8)); setBackgroundColor(Color.argb(120, 0, 0, 0)) }
        top.addView(TextView(this).apply { text = def.title; setTextColor(Color.WHITE); textSize = 15f })
        big = TextView(this).apply { text = "준비 중"; setTextColor(Color.WHITE); textSize = 34f; setShadowLayer(6f, 0f, 0f, Color.BLACK) }
        top.addView(big)
        info = TextView(this).apply { text = def.desc; setTextColor(Color.WHITE); textSize = 13f }
        top.addView(info)
        root.addView(top, FrameLayout.LayoutParams(MATCH_PARENT, WRAP_CONTENT, Gravity.TOP))
        bar = LinearLayout(this).apply { orientation = LinearLayout.HORIZONTAL; setPadding(dp(8), dp(4), dp(8), dp(8)); setBackgroundColor(Color.argb(110, 0, 0, 0)) }
        fun btn(t: String, f: (Button) -> Unit) = Button(this).apply { text = t; textSize = 12f; UiKit.styleButton(this, BtnStyle.ON_DARK, 12f, 8); setOnClickListener { f(this) } }
            .also { bar.addView(it, LinearLayout.LayoutParams(0, WRAP_CONTENT, 1f).apply { setMargins(dp(3), 0, dp(3), 0) }) }
        btn("카메라 전환") { front = !front; fingerMode = false; startCamera() }
        when (def.id) {
            "qr" -> { btn("복사") { lastCode?.let { c -> copy(c) } }; btn("열기") { openCode() } }
            "squat", "pushup", "jumping", "plank", "blink", "drowsy" -> btn("다시 세기") { resetAll = true }
            "posture" -> btn("지금 자세를 기준으로") { setBase = true; toast("바른 자세로 2초간 있어 주세요") }
            "heart" -> btn("방식: 얼굴") { b -> fingerMode = !fingerMode; front = !fingerMode; heart.reset(); b.text = if (fingerMode) "방식: 손가락" else "방식: 얼굴"; startCamera() }
            "color" -> btn("가운데로") { tapX = -1f; tapY = -1f }
        }
        root.addView(bar, FrameLayout.LayoutParams(MATCH_PARENT, WRAP_CONTENT, Gravity.BOTTOM))
        root.setOnApplyWindowInsetsListener { _, insets ->
            @Suppress("DEPRECATION")
            top.setPadding(dp(12), insets.systemWindowInsetTop + dp(8), dp(12), dp(8))
            @Suppress("DEPRECATION")
            bar.setPadding(dp(8), dp(4), dp(8), insets.systemWindowInsetBottom + dp(8))
            insets
        }
        setContentView(root)
        if (def.id == "heart") info.text = def.desc + "\n얼굴 방식: 밝은 곳에서 10초 이상 가만히. 손가락 방식: 후면 카메라와 플래시를 손가락 끝으로 살짝 덮기."
        if (ContextCompat.checkSelfPermission(this, Manifest.permission.CAMERA) == PackageManager.PERMISSION_GRANTED) startCamera()
        else askCamera.launch(Manifest.permission.CAMERA)
    }

    private fun toast(t: String) = Toast.makeText(this, t, Toast.LENGTH_SHORT).show()
    private fun copy(t: String) {
        getSystemService(android.content.ClipboardManager::class.java).setPrimaryClip(android.content.ClipData.newPlainText("코드", t)); toast("복사했습니다")
    }

    private fun openCode() {
        val c = lastCode ?: return
        val url = if (c.startsWith("http://") || c.startsWith("https://")) c else return toast("링크가 아닙니다")
        val r = LinkCheck.check(url)
        val go = { runCatching { startActivity(Intent(Intent.ACTION_VIEW, Uri.parse(url))) } }
        if (r.level >= 1) android.app.AlertDialog.Builder(this).setTitle("주의: ${r.verdict}").setMessage(r.reasons.joinToString("\n") + "\n\n그래도 열까요?")
            .setPositiveButton("열기") { _, _ -> go() }.setNegativeButton("취소", null).show()
        else go()
    }

    @androidx.annotation.OptIn(ExperimentalCamera2Interop::class)
    private fun startCamera() {
        val future = ProcessCameraProvider.getInstance(this)
        future.addListener({
            val provider = future.get()
            val ratio = AspectRatioStrategy.RATIO_4_3_FALLBACK_AUTO_STRATEGY
            val preview = Preview.Builder().setResolutionSelector(ResolutionSelector.Builder().setAspectRatioStrategy(ratio).build())
                .build().also { it.surfaceProvider = previewView.surfaceProvider }
            val res = if (def.id == "qr" || def.id == "heart") Size(1920, 1440) else Size(1280, 960)
            val analysis = ImageAnalysis.Builder()
                .setResolutionSelector(ResolutionSelector.Builder().setAspectRatioStrategy(ratio)
                    .setResolutionStrategy(ResolutionStrategy(res, ResolutionStrategy.FALLBACK_RULE_CLOSEST_LOWER_THEN_HIGHER)).build())
                .setBackpressureStrategy(ImageAnalysis.STRATEGY_KEEP_ONLY_LATEST)
                .setOutputImageFormat(ImageAnalysis.OUTPUT_IMAGE_FORMAT_RGBA_8888)
                .build()
            analysis.setAnalyzer(exec) { analyze(it) }
            runCatching {
                provider.unbindAll()
                val cam = provider.bindToLifecycle(this, if (front) CameraSelector.DEFAULT_FRONT_CAMERA else CameraSelector.DEFAULT_BACK_CAMERA, preview, analysis)
                camera = cam
                cam.cameraControl.enableTorch(def.id == "heart" && fingerMode)
                runCatching {
                    val ci = Camera2CameraInfo.from(cam.cameraInfo)
                    val fl = ci.getCameraCharacteristic(CameraCharacteristics.LENS_INFO_AVAILABLE_FOCAL_LENGTHS)?.firstOrNull()
                    val ss = ci.getCameraCharacteristic(CameraCharacteristics.SENSOR_INFO_PHYSICAL_SIZE)
                    focalPx = if (fl != null && ss != null) fl / max(ss.width, ss.height) else 0f
                }
            }.onFailure { info.text = "카메라를 열 수 없습니다: ${it.message}" }
        }, ContextCompat.getMainExecutor(this))
    }

    override fun onDestroy() {
        super.onDestroy()
        running = false
        exec.execute {
            runCatching { face?.close() }; runCatching { pose?.close() }; runCatching { gest?.close() }
            runCatching { barcode?.close() }; runCatching { det?.close() }
        }
        exec.shutdown()
        tone?.release()
    }

    private fun beep(kind: Int = ToneGenerator.TONE_PROP_BEEP, ms: Int = 120) { runCatching { tone?.startTone(kind, ms) } }

    private fun analyze(img: ImageProxy) {
        if (!running) { img.close(); return }
        try {
            val raw = img.toBitmap()
            val m = Matrix().apply { postRotate(img.imageInfo.rotationDegrees.toFloat()); if (front) postScale(-1f, 1f) }
            var bmp = Bitmap.createBitmap(raw, 0, 0, raw.width, raw.height, m, true)
            if (bmp !== raw) raw.recycle()
            val maxSide = if (def.id == "qr") 1600 else 960
            if (max(bmp.width, bmp.height) > maxSide) { val s = Cv.scaleTo(bmp, maxSide); if (s !== bmp) { bmp.recycle(); bmp = s } }
            val ts = max(SystemClock.uptimeMillis(), lastTs + 1).also { lastTs = it }
            val t = ts / 1000.0
            if (resetAll) { resetAll = false; rep.reset(); pushRep.reset(); jj.reset(); plankSec = 0.0; blinks.reset(); yawns = 0 }
            val f = when (def.id) {
                "qr" -> qr(bmp)
                "gesture", "fingers" -> hands(bmp, ts)
                "squat", "pushup", "jumping", "plank", "posture" -> poseTool(bmp, ts, t)
                "heart" -> if (fingerMode) finger(bmp, t) else faceTool(bmp, ts, t)
                "color" -> color(bmp)
                "objects" -> objects(bmp)
                else -> faceTool(bmp, ts, t)
            }
            val w = bmp.width; val h = bmp.height
            runOnUiThread { if (running) { overlay.set(f, w, h); big.text = f.big; big.setTextColor(f.color); info.text = f.text } }
        } catch (e: Throwable) {
            runOnUiThread { info.text = "오류: ${e.message}" }
        } finally { img.close() }
    }

    private fun stroke(c: Int, w: Float) = Paint(Paint.ANTI_ALIAS_FLAG).apply { color = c; style = Paint.Style.STROKE; strokeWidth = w }
    private fun fill(c: Int) = Paint(Paint.ANTI_ALIAS_FLAG).apply { color = c }
    private fun label(cv: Canvas, s: String, x: Float, y: Float, k: Float, c: Int = Color.WHITE) {
        val p = Paint(Paint.ANTI_ALIAS_FLAG).apply { color = c; textSize = 16f * k; setShadowLayer(4f * k, 0f, 0f, Color.BLACK) }
        cv.drawText(s, x, y, p)
    }

    // ---------------- QR·바코드
    private fun qr(b: Bitmap): ToolFrame {
        val sc = barcode ?: BarcodeScanning.getClient().also { barcode = it }
        val list = Tasks.await(sc.process(InputImage.fromBitmap(b, 0)))
        val boxes = ArrayList<Triple<RectF, Int, String>>()
        for (bc in list) {
            val raw = bc.rawValue ?: continue
            if (raw !in seen) { seen[raw] = describe(bc); beep(); while (seen.size > 8) seen.remove(seen.keys.first()) }
            lastCode = raw
            val level = if (bc.valueType == Barcode.TYPE_URL || raw.startsWith("http")) LinkCheck.check(bc.url?.url ?: raw).level else 0
            val col = when (level) { 0 -> Color.rgb(40, 220, 90); 1 -> Color.rgb(255, 170, 0); else -> Color.rgb(255, 50, 50) }
            bc.boundingBox?.let { boxes += Triple(RectF(it), col, raw.take(28)) }
        }
        val latest = lastCode
        return ToolFrame(if (latest == null) "코드를 비춰 주세요" else "읽음 ${seen.size}개", if (latest == null) "QR·바코드를 화면에 비추세요" else (seen[latest] ?: latest),
            if (latest != null && (seen[latest] ?: "").contains("위험")) Color.rgb(255, 80, 80) else Color.WHITE) { c, k ->
            for ((r, col, s) in boxes) { c.drawRect(r, stroke(col, 4f * k)); label(c, s, r.left, r.top - 6 * k, k, col) }
        }
    }

    private fun describe(bc: Barcode): String = when (bc.valueType) {
        Barcode.TYPE_URL -> { val u = bc.url?.url ?: bc.rawValue ?: ""; val r = LinkCheck.check(u); "링크: $u\n판정: ${r.verdict}" + (if (r.reasons.isNotEmpty()) "\n- " + r.reasons.joinToString("\n- ") else "") }
        Barcode.TYPE_WIFI -> "와이파이: ${bc.wifi?.ssid} (암호 ${if (bc.wifi?.password.isNullOrEmpty()) "없음" else "있음"})\n※ 모르는 곳의 와이파이는 조심하세요"
        Barcode.TYPE_PHONE -> "전화번호: ${bc.phone?.number}"
        Barcode.TYPE_SMS -> "문자 보내기: ${bc.sms?.phoneNumber}\n${bc.sms?.message ?: ""}\n" + SmsCheck.check(bc.sms?.message ?: "").verdict
        Barcode.TYPE_EMAIL -> "이메일: ${bc.email?.address}"
        Barcode.TYPE_PRODUCT, Barcode.TYPE_ISBN -> "상품 번호: ${bc.rawValue}" + (if ((bc.rawValue ?: "").startsWith("880")) " (한국 상품)" else "")
        Barcode.TYPE_CONTACT_INFO -> "연락처: ${bc.contactInfo?.name?.formattedName ?: ""}"
        else -> "글: ${bc.rawValue}"
    }

    // ---------------- 손
    private val HAND = listOf(0 to 1, 1 to 2, 2 to 3, 3 to 4, 0 to 5, 5 to 6, 6 to 7, 7 to 8, 5 to 9, 9 to 10, 10 to 11, 11 to 12, 9 to 13, 13 to 14, 14 to 15, 15 to 16, 13 to 17, 17 to 18, 18 to 19, 19 to 20, 0 to 17)
    private val GESTURE_KO = mapOf("Closed_Fist" to "주먹 ✊", "Open_Palm" to "손바닥 ✋", "Pointing_Up" to "검지 위로 ☝", "Thumb_Down" to "엄지 아래 👎",
        "Thumb_Up" to "엄지 위 👍", "Victory" to "브이 ✌", "ILoveYou" to "사랑해 🤟", "None" to "-")

    private fun fingersUp(l: List<NormalizedLandmark>, w: Float, h: Float): Int {
        fun d(a: Int, b: Int) = hypot((l[a].x() - l[b].x()) * w, (l[a].y() - l[b].y()) * h)
        var n = 0
        for ((tip, pip) in listOf(8 to 6, 12 to 10, 16 to 14, 20 to 18)) if (d(tip, 0) > d(pip, 0) * 1.12f) n++
        if (d(4, 17) > d(3, 17) * 1.05f && d(4, 5) > d(0, 5) * 0.45f) n++ // 엄지
        return n
    }

    private fun hands(b: Bitmap, ts: Long): ToolFrame {
        val g = gest ?: GestureRecognizer.createFromOptions(this, GestureRecognizer.GestureRecognizerOptions.builder()
            .setBaseOptions(BaseOptions.builder().setModelAssetPath("gesture_recognizer.task").setDelegate(Delegate.CPU).build())
            .setRunningMode(RunningMode.VIDEO).setNumHands(2).build()).also { gest = it }
        val r = g.recognizeForVideo(BitmapImageBuilder(b).build(), ts)
        val w = b.width.toFloat(); val h = b.height.toFloat()
        val hands = r.landmarks()
        if (hands.isEmpty()) return ToolFrame("—", "손을 화면에 보여 주세요")
        val names = ArrayList<String>(); var total = 0
        val counts = hands.map { fingersUp(it, w, h) }
        hands.indices.forEach { i ->
            val cat = r.gestures().getOrNull(i)?.firstOrNull()
            names += GESTURE_KO[cat?.categoryName()] ?: (cat?.categoryName() ?: "-")
            total += counts[i]
        }
        val isCount = def.id == "fingers"
        return ToolFrame(if (isCount) "$total" else names.joinToString("  "), if (isCount) "손 ${hands.size}개 · 손가락 ${counts.joinToString(" + ")}" else "손 ${hands.size}개") { c, k ->
            val ln = stroke(Color.rgb(0, 230, 160), 3f * k); val dot = fill(Color.WHITE)
            hands.forEachIndexed { i, lm ->
                for ((a, bb) in HAND) c.drawLine(lm[a].x() * w, lm[a].y() * h, lm[bb].x() * w, lm[bb].y() * h, ln)
                for (p in lm) c.drawCircle(p.x() * w, p.y() * h, 3f * k, dot)
                label(c, if (isCount) "${counts[i]}" else names[i], lm[0].x() * w, lm[0].y() * h + 24 * k, k * 1.3f)
            }
        }
    }

    // ---------------- 몸 (자세)
    private val BODY = listOf(11 to 12, 11 to 13, 13 to 15, 12 to 14, 14 to 16, 11 to 23, 12 to 24, 23 to 24, 23 to 25, 25 to 27, 24 to 26, 26 to 28, 27 to 31, 28 to 32)

    private fun poseTool(b: Bitmap, ts: Long, t: Double): ToolFrame {
        val p = pose ?: PoseLandmarker.createFromOptions(this, PoseLandmarker.PoseLandmarkerOptions.builder()
            .setBaseOptions(BaseOptions.builder().setModelAssetPath("pose_landmarker_lite.task").setDelegate(Delegate.CPU).build())
            .setRunningMode(RunningMode.VIDEO).setNumPoses(1).setMinPoseDetectionConfidence(0.5f).setMinTrackingConfidence(0.5f).build()).also { pose = it }
        val lm = p.detectForVideo(BitmapImageBuilder(b).build(), ts).landmarks().firstOrNull()
        val dt = if (lastT > 0) (t - lastT).coerceIn(0.0, 0.5) else 0.0
        lastT = t
        if (lm == null) return ToolFrame(bigFor(), "몸이 화면에 보이게 서 주세요")
        val W = b.width.toFloat(); val H = b.height.toFloat()
        fun x(i: Int) = lm[i].x() * W
        fun y(i: Int) = lm[i].y() * H
        fun v(i: Int) = lm[i].visibility().orElse(0f)
        val left = v(23) + v(25) + v(27) + v(11) + v(13) + v(15) >= v(24) + v(26) + v(28) + v(12) + v(14) + v(16)
        val (sh, el, wr, hip, kn, an) = if (left) listOf(11, 13, 15, 23, 25, 27) else listOf(12, 14, 16, 24, 26, 28)
        var text: String
        var col = Color.WHITE
        when (def.id) {
            "squat" -> {
                val a = angleAt(x(hip), y(hip), x(kn), y(kn), x(an), y(an))
                if (rep.update(a)) beep()
                text = "무릎 각도 ${a.roundToInt()}° · ${if (rep.isDown) "앉음 → 일어서세요" else "서 있음 → 앉으세요 (100° 아래)"}"
            }
            "pushup" -> {
                val a = angleAt(x(sh), y(sh), x(el), y(el), x(wr), y(wr))
                if (pushRep.update(a)) beep()
                text = "팔꿈치 각도 ${a.roundToInt()}° · ${if (pushRep.isDown) "내려감 → 밀어 올리세요" else "올라옴 → 내려가세요 (90° 아래)"}"
            }
            "jumping" -> {
                val sw = abs(x(11) - x(12)).coerceAtLeast(1f); val ad = abs(x(27) - x(28))
                val armsUp = y(15) < y(11) && y(16) < y(12); val armsDown = y(15) > y(11) && y(16) > y(12)
                if (jj.update(armsUp && ad > 1.3f * sw, armsDown && ad < 1.15f * sw)) beep()
                text = if (armsUp) "벌림 → 모으세요" else "모음 → 팔다리를 벌리세요"
            }
            "plank" -> {
                val a = angleAt(x(sh), y(sh), x(hip), y(hip), x(an), y(an))
                val flat = abs(y(sh) - y(an)) < abs(x(sh) - x(an)) * 0.6f
                val ok = a > 160f && flat
                if (ok) plankSec += dt
                text = if (!flat) "몸을 옆으로 눕혀 엎드리세요 (옆에서 찍기)" else if (ok) "일직선 ✓ (${a.roundToInt()}°)" else "엉덩이 높이를 맞추세요 (${a.roundToInt()}°, 160° 이상)"
                col = if (ok) Color.rgb(80, 255, 120) else Color.rgb(255, 200, 60)
            }
            else -> { // 자세
                val sw = hypot(x(12) - x(11), y(12) - y(11)).coerceAtLeast(1f)
                var tilt = Math.toDegrees(atan2((y(12) - y(11)).toDouble(), (x(12) - x(11)).toDouble())).toFloat()
                if (tilt > 90) tilt -= 180f; if (tilt < -90) tilt += 180f
                val neck = ((y(11) + y(12)) / 2 - y(0)) / sw // 코가 어깨선보다 얼마나 위에 있나
                if (setBase) { neckSamples += neck; if (neckSamples.size >= 30) { baseNeck = neckSamples.average().toFloat(); neckSamples.clear(); setBase = false } }
                if (baseNeck == 0f) { neckSamples += neck; if (neckSamples.size >= 45) { baseNeck = neckSamples.average().toFloat(); neckSamples.clear() } }
                val issues = ArrayList<String>()
                if (abs(tilt) > 7f) issues += "어깨가 ${abs(tilt).roundToInt()}° 기울었어요"
                if (baseNeck > 0f && neck < baseNeck * 0.8f) issues += "고개가 숙여졌어요 (거북목 주의)"
                if (issues.isEmpty()) badSince = -1.0 else if (badSince < 0) badSince = t
                if (badSince >= 0 && t - badSince > 5 && t - lastAlarm > 3) { lastAlarm = t; beep(ToneGenerator.TONE_PROP_ACK, 300) }
                text = if (baseNeck == 0f) "기준 자세 저장 중... 바르게 앉아 주세요" else if (issues.isEmpty()) "어깨 ${abs(tilt).roundToInt()}° · 고개 ${(neck / baseNeck * 100).roundToInt()}%" else issues.joinToString("\n")
                col = if (issues.isEmpty()) Color.rgb(80, 255, 120) else Color.rgb(255, 90, 70)
            }
        }
        val label = bigFor()
        return ToolFrame(label, text, col) { c, k ->
            val ln = stroke(Color.rgb(0, 220, 255), 4f * k); val dot = fill(Color.WHITE)
            for ((a, bb) in BODY) if (v(a) > 0.4f && v(bb) > 0.4f) c.drawLine(x(a), y(a), x(bb), y(bb), ln)
            for (i in listOf(0, 11, 12, 13, 14, 15, 16, 23, 24, 25, 26, 27, 28)) if (v(i) > 0.4f) c.drawCircle(x(i), y(i), 5f * k, dot)
        }
    }

    private fun bigFor() = when (def.id) {
        "squat" -> "${rep.count}회"; "pushup" -> "${pushRep.count}회"; "jumping" -> "${jj.count}회"
        "plank" -> "%d:%02d".format(plankSec.toInt() / 60, plankSec.toInt() % 60)
        "posture" -> if (badSince >= 0) "자세 주의" else "바른 자세"
        else -> ""
    }

    // ---------------- 얼굴
    private fun faceTool(b: Bitmap, ts: Long, t: Double): ToolFrame {
        val f = face ?: GpuGuard.create(this, "face_live_bs", {
            FaceLandmarker.createFromOptions(this, FaceLandmarker.FaceLandmarkerOptions.builder()
                .setBaseOptions(BaseOptions.builder().setModelAssetPath("face_landmarker.task").setDelegate(Delegate.GPU).build())
                .setRunningMode(RunningMode.VIDEO).setNumFaces(1).setOutputFaceBlendshapes(true).build())
        }, {
            FaceLandmarker.createFromOptions(this, FaceLandmarker.FaceLandmarkerOptions.builder()
                .setBaseOptions(BaseOptions.builder().setModelAssetPath("face_landmarker.task").setDelegate(Delegate.CPU).build())
                .setRunningMode(RunningMode.VIDEO).setNumFaces(1).setOutputFaceBlendshapes(true).build())
        }).also { face = it }
        val r = f.detectForVideo(BitmapImageBuilder(b).build(), ts)
        val lm = r.faceLandmarks().firstOrNull()
        if (lm == null) { blinks.update(t, 0f); return ToolFrame("—", "얼굴을 화면에 보여 주세요") }
        val bs = r.faceBlendshapes().orElse(null)?.firstOrNull()?.associate { it.categoryName() to it.score() } ?: emptyMap()
        val W = b.width.toFloat(); val H = b.height.toFloat()
        fun x(i: Int) = lm[i].x() * W
        fun y(i: Int) = lm[i].y() * H
        fun g(k: String) = bs[k] ?: 0f
        val blink = (g("eyeBlinkLeft") + g("eyeBlinkRight")) / 2
        val dots: (Canvas, Float) -> Unit = { c, k -> val p = fill(Color.argb(160, 0, 255, 170)); for (i in listOf(33, 133, 362, 263, 1, 61, 291, 152, 10, 468, 473)) c.drawCircle(x(i), y(i), 3f * k, p) }
        return when (def.id) {
            "drowsy" -> {
                val closed = blinks.update(t, blink)
                if (g("jawOpen") > 0.55f) { if (yawnSince < 0) yawnSince = t } else { if (yawnSince >= 0 && t - yawnSince > 1.5) yawns++; yawnSince = -1.0 }
                val alarm = closed > 1.2
                if (alarm && t - lastAlarm > 0.9) { lastAlarm = t; beep(ToneGenerator.TONE_CDMA_EMERGENCY_RINGBACK, 800) }
                ToolFrame(if (alarm) "졸음 경고!" else "깨어 있음", "최근 1분 눈 감은 비율 ${(blinks.perclos() * 100).roundToInt()}% · 하품 ${yawns}회 · 깜빡임 ${blinks.perMinute()}회/분",
                    if (alarm) Color.rgb(255, 60, 60) else Color.rgb(80, 255, 120)) { c, k -> if (alarm) c.drawColor(Color.argb(90, 255, 0, 0)); dots(c, k) }
            }
            "blink" -> {
                blinks.update(t, blink)
                val pm = blinks.perMinute()
                ToolFrame("${pm}회/분", "총 ${blinks.count}회 · 보통 15~20회/분" + if (pm < 10 && blinks.count > 3) "\n깜빡임이 적어요. 20분마다 20초간 먼 곳을 보세요 (20-20-20)" else "", if (pm < 10) Color.rgb(255, 190, 60) else Color.WHITE, dots)
            }
            "smile" -> {
                val s = (g("mouthSmileLeft") + g("mouthSmileRight")) / 2
                if (s > 0.6f) { if (smileSince < 0) smileSince = t } else smileSince = -1.0
                if (smileSince >= 0 && t - smileSince > 0.4 && t - lastShot > 3) {
                    lastShot = t; beep(ToneGenerator.TONE_PROP_ACK, 150)
                    val shot = b.copy(Bitmap.Config.ARGB_8888, false)
                    thread { val msg = runCatching { MediaSave.savePng(this, shot, "smile_${System.currentTimeMillis()}.png") }.getOrNull(); runOnUiThread { toast(if (msg != null) "찰칵! $msg" else "저장 실패") } }
                }
                ToolFrame("미소 ${(s * 100).roundToInt()}%", "60% 넘게 웃으면 자동으로 찍습니다 (3초 간격)", if (s > 0.6f) Color.rgb(255, 220, 80) else Color.WHITE, dots)
            }
            "distance" -> {
                val ia = hypot(x(469) - x(471), y(469) - y(471)); val ib = hypot(x(474) - x(476), y(474) - y(476))
                val iris = max(ia, ib)
                val fpx = if (focalPx > 0f) focalPx * max(W, H) else max(W, H) * 0.85f // 정보가 없으면 화각 약 65° 로 가정
                val cm = fpx * 11.7f / iris.coerceAtLeast(1f) / 10f
                val col = when { cm < 30 -> Color.rgb(255, 70, 60); cm < 40 -> Color.rgb(255, 190, 60); else -> Color.rgb(80, 255, 120) }
                ToolFrame("%.0f cm".format(cm), when { cm < 30 -> "너무 가까워요! 30cm 이상 떨어지세요"; cm < 40 -> "조금 가까워요 (40cm 이상 권장)"; else -> "좋은 거리입니다" } +
                    if (focalPx <= 0f) "\n(카메라 정보가 없어 대략적인 값)" else "", col, dots)
            }
            "heart" -> {
                // 이마(점 151 주변)와 양 볼의 초록빛 평균
                val iod = hypot(x(263) - x(33), y(263) - y(33))
                var sum = 0.0; var n = 0
                fun roi(cx: Float, cy: Float, rw: Float, rh: Float) {
                    val x0 = (cx - rw / 2).toInt().coerceIn(0, b.width - 1); val x1 = (cx + rw / 2).toInt().coerceIn(x0 + 1, b.width)
                    val y0 = (cy - rh / 2).toInt().coerceIn(0, b.height - 1); val y1 = (cy + rh / 2).toInt().coerceIn(y0 + 1, b.height)
                    val px = IntArray((x1 - x0) * (y1 - y0)); b.getPixels(px, 0, x1 - x0, x0, y0, x1 - x0, y1 - y0)
                    for (p in px) { val r0 = Color.red(p); val g0 = Color.green(p); val b0 = Color.blue(p); val s = r0 + g0 + b0; if (s > 30) { sum += g0.toDouble() / s; n++ } }
                }
                roi(x(151), y(151), iod * 0.35f, iod * 0.15f); roi(x(117), y(117), iod * 0.15f, iod * 0.15f); roi(x(346), y(346), iod * 0.15f, iod * 0.15f)
                if (n > 0) heart.add(t, sum / n)
                heartFrame(dots)
            }
            else -> { // 표정
                val e = FaceMetricsCalc.expression(bs)
                val emoji = mapOf("미소" to "🙂", "활짝 웃음" to "😄", "살짝 미소" to "🙂", "놀람" to "😮", "찡그림" to "😠", "슬픈 표정" to "😢", "윙크" to "😉", "눈 감음" to "😌", "입 오므림" to "😗", "볼 부풀림" to "🐡", "입 벌림" to "😮", "무표정" to "😐")[e] ?: ""
                val top = bs.entries.filter { it.key != "_neutral" }.sortedByDescending { it.value }.take(3).joinToString(" · ") { "${FaceMetricsCalc.blendName(it.key)} ${(it.value * 100).roundToInt()}%" }
                ToolFrame("$emoji $e", top, Color.WHITE, dots)
            }
        }
    }

    private fun heartFrame(draw: ((Canvas, Float) -> Unit)?): ToolFrame {
        val r = heart.bpm()
        val sec = heart.seconds()
        return if (r == null) ToolFrame("측정 중 ${sec.toInt()}초", "가만히 계세요 (6초 이상 필요)", Color.WHITE, draw)
        else ToolFrame("♥ ${r.first.roundToInt()}", "신뢰도 ${(r.second * 100).roundToInt()}%" + (if (r.second < 0.25f) " (낮음: 더 밝은 곳에서 움직이지 마세요)" else "") + "\n참고용 추정치이며 의료 기기가 아닙니다",
            if (r.second < 0.25f) Color.rgb(255, 190, 60) else Color.rgb(255, 90, 110), draw)
    }

    private fun finger(b: Bitmap, t: Double): ToolFrame {
        val cw = b.width / 2; val ch = b.height / 2
        val px = IntArray(cw * ch); b.getPixels(px, 0, cw, b.width / 4, b.height / 4, cw, ch)
        var r = 0.0; var g = 0.0
        for (p in px) { r += Color.red(p); g += Color.green(p) }
        r /= px.size; g /= px.size
        if (r < 80 || r < g * 1.5) { heart.reset(); return ToolFrame("손가락을 대세요", "후면 카메라와 플래시를 손가락 끝으로 살짝 덮으세요 (누르지 말고)") }
        heart.add(t, r)
        return heartFrame(null)
    }

    // ---------------- 색
    private fun color(b: Bitmap): ToolFrame {
        val cx = if (tapX >= 0) tapX.toInt().coerceIn(5, b.width - 6) else b.width / 2
        val cy = if (tapY >= 0) tapY.toInt().coerceIn(5, b.height - 6) else b.height / 2
        val px = IntArray(11 * 11); b.getPixels(px, 0, 11, cx - 5, cy - 5, 11, 11)
        val r = px.map { Color.red(it) }.average().roundToInt(); val g = px.map { Color.green(it) }.average().roundToInt(); val bl = px.map { Color.blue(it) }.average().roundToInt()
        val hex = "#%02X%02X%02X".format(r, g, bl)
        return ToolFrame(ColorNames.name(r, g, bl), "$hex · RGB($r, $g, $bl) · 다른 곳을 누르면 그 색을 봅니다", Color.WHITE) { c, k ->
            val p = stroke(Color.WHITE, 3f * k)
            c.drawCircle(cx.toFloat(), cy.toFloat(), 18f * k, p); c.drawLine(cx - 30 * k, cy.toFloat(), cx - 18 * k, cy.toFloat(), p); c.drawLine(cx + 18 * k, cy.toFloat(), cx + 30 * k, cy.toFloat(), p)
            c.drawRoundRect(RectF(cx + 26 * k, cy - 50 * k, cx + 76 * k, cy - 22 * k), 6 * k, 6 * k, fill(Color.rgb(r, g, bl)))
            c.drawRoundRect(RectF(cx + 26 * k, cy - 50 * k, cx + 76 * k, cy - 22 * k), 6 * k, 6 * k, stroke(Color.WHITE, 2f * k))
        }
    }

    // ---------------- 물체
    private fun objects(b: Bitmap): ToolFrame {
        val d = det ?: ObjectDetector.createFromOptions(this, ObjectDetector.ObjectDetectorOptions.builder()
            .setBaseOptions(BaseOptions.builder().setModelAssetPath("efficientdet_lite2.tflite").setDelegate(Delegate.CPU).build())
            .setRunningMode(RunningMode.IMAGE).setMaxResults(40).setScoreThreshold(0.35f).build()).also { det = it }
        val list = d.detect(BitmapImageBuilder(b).build()).detections()
        val counts = LinkedHashMap<String, Int>()
        val boxes = list.map { det0 ->
            val name = LocalProducts.korean(det0.categories().firstOrNull()?.categoryName() ?: "?")
            counts[name] = (counts[name] ?: 0) + 1
            name to det0.boundingBox()
        }
        val sorted = counts.entries.sortedByDescending { it.value }
        return ToolFrame(if (list.isEmpty()) "0개" else "${list.size}개", if (sorted.isEmpty()) "물체를 비춰 주세요" else sorted.joinToString(" · ") { "${it.key} ${it.value}" }) { c, k ->
            val p = stroke(Color.rgb(255, 210, 0), 3f * k)
            for ((n, bb) in boxes) { c.drawRect(bb, p); label(c, n, bb.left, bb.top - 5 * k, k, Color.rgb(255, 210, 0)) }
        }
    }
}

private operator fun <T> List<T>.component6(): T = this[5]
