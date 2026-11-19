package com.selfcheck.app

import android.Manifest
import android.content.Context
import android.content.pm.PackageManager
import android.graphics.Bitmap
import android.graphics.Canvas
import android.graphics.Color
import android.graphics.Paint
import android.graphics.RectF
import android.os.Bundle
import android.os.SystemClock
import android.util.Size
import android.view.Gravity
import android.view.MotionEvent
import android.view.ScaleGestureDetector
import android.view.View
import android.view.ViewGroup.LayoutParams.MATCH_PARENT
import android.view.ViewGroup.LayoutParams.WRAP_CONTENT
import android.widget.Button
import android.widget.FrameLayout
import android.widget.LinearLayout
import android.widget.TextView
import androidx.activity.ComponentActivity
import androidx.activity.result.contract.ActivityResultContracts
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
import com.google.mediapipe.framework.image.BitmapImageBuilder
import com.google.mediapipe.tasks.components.containers.NormalizedLandmark
import com.google.mediapipe.tasks.core.BaseOptions
import com.google.mediapipe.tasks.core.Delegate
import com.google.mediapipe.tasks.vision.core.RunningMode
import com.google.mediapipe.tasks.vision.objectdetector.ObjectDetector
import com.google.mediapipe.tasks.vision.poselandmarker.PoseLandmarker
import java.util.concurrent.Executors
import java.util.concurrent.atomic.AtomicReference
import kotlin.math.abs
import kotlin.math.hypot
import kotlin.math.max
import kotlin.math.min

/** 사람 한 명: 관절 33개(x, y 사진 픽셀, 보임 여부) — 관절을 못 찾은 먼 사람은 상자만 */
class PersonInfo(val id: Int, val rect: RectF, val pts: FloatArray?, val ok: BooleanArray?, val posture: String)

class PersonFrame(val w: Int, val h: Int, val people: List<PersonInfo>, val now: Int, val total: Int)

private class PersonTrack(val id: Int, var rect: RectF, now: Long) {
    var lastSeen = now
    var frames = 1
    var counted = false
}

/** 몸 관절 연결선 */
val POSE_EDGES = arrayOf(
    intArrayOf(11, 12), intArrayOf(11, 13), intArrayOf(13, 15), intArrayOf(12, 14), intArrayOf(14, 16),
    intArrayOf(11, 23), intArrayOf(12, 24), intArrayOf(23, 24), intArrayOf(23, 25), intArrayOf(25, 27),
    intArrayOf(24, 26), intArrayOf(26, 28), intArrayOf(27, 31), intArrayOf(28, 32), intArrayOf(27, 29), intArrayOf(28, 30),
    intArrayOf(0, 11), intArrayOf(0, 12), intArrayOf(15, 19), intArrayOf(16, 20))

/**
 * 사람 인식: 카메라에 비친 사람을 찾아 몸 관절(뼈대)과 상자를 그리고, 사람마다 번호와 자세(서 있음·앉음·손 듦·누움·움직임)를 표시합니다.
 * 지금 화면의 인원과 누적 인원을 셉니다. 누구인지 알아내는 기능은 없습니다 (번호로만 구분).
 * 관절 모델이 놓치는 먼 사람은 물체 인식(사람)으로 찾고, 그 부분을 확대해서 관절을 다시 찾습니다.
 */
class PersonActivity : ComponentActivity() {
    private lateinit var previewView: PreviewView
    private lateinit var overlay: PersonOverlay
    private lateinit var status: TextView
    private val exec = Executors.newSingleThreadExecutor()
    private var pose: PoseLandmarker? = null
    private var poseCrop: PoseLandmarker? = null
    private var detector: ObjectDetector? = null
    private var camera: Camera? = null
    private var front = false
    private var lastTs = 0L
    private val tracks = mutableListOf<PersonTrack>()
    private var nextId = 1
    @Volatile private var total = 0
    @Volatile private var resetCount = false

    private val askCamera = registerForActivityResult(ActivityResultContracts.RequestPermission()) { ok -> if (ok) startCamera() else status.text = "카메라 권한이 필요합니다" }

    private fun dp(v: Int) = (v * resources.displayMetrics.density).toInt()

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        val root = FrameLayout(this).apply { setBackgroundColor(Color.BLACK) }
        previewView = PreviewView(this).apply { implementationMode = PreviewView.ImplementationMode.PERFORMANCE; scaleType = PreviewView.ScaleType.FILL_CENTER }
        root.addView(previewView, FrameLayout.LayoutParams(MATCH_PARENT, MATCH_PARENT))
        overlay = PersonOverlay(this) { f -> zoomBy(f) }
        root.addView(overlay, FrameLayout.LayoutParams(MATCH_PARENT, MATCH_PARENT))
        val bottom = LinearLayout(this).apply { orientation = LinearLayout.VERTICAL; setPadding(dp(8), dp(4), dp(8), dp(8)); setBackgroundColor(Color.argb(110, 0, 0, 0)) }
        status = TextView(this).apply { text = "사람을 화면에 비춰 주세요"; setTextColor(Color.WHITE); textSize = 13f; gravity = Gravity.CENTER }
        bottom.addView(status)
        val bar = LinearLayout(this).apply { orientation = LinearLayout.HORIZONTAL }
        fun btn(t: String, f: (Button) -> Unit) = Button(this).apply { text = t; textSize = 12f; UiKit.styleButton(this, BtnStyle.ON_DARK, 12f, 8); setOnClickListener { f(this) } }
            .also { bar.addView(it, LinearLayout.LayoutParams(0, WRAP_CONTENT, 1f).apply { setMargins(dp(3), 0, dp(3), 0) }) }
        btn("카메라 전환") { front = !front; resetCount = true; startCamera() }
        btn("누적 초기화") { resetCount = true }
        btn("뼈대: 켬") { b -> overlay.skeleton = !overlay.skeleton; b.text = if (overlay.skeleton) "뼈대: 켬" else "뼈대: 끔" }
        bottom.addView(bar)
        root.addView(bottom, FrameLayout.LayoutParams(MATCH_PARENT, WRAP_CONTENT, Gravity.BOTTOM))
        root.setOnApplyWindowInsetsListener { _, insets ->
            @Suppress("DEPRECATION")
            bottom.setPadding(dp(8), dp(4), dp(8), insets.systemWindowInsetBottom + dp(8))
            @Suppress("DEPRECATION")
            overlay.topInset = insets.systemWindowInsetTop
            insets
        }
        setContentView(root)
        if (ContextCompat.checkSelfPermission(this, Manifest.permission.CAMERA) == PackageManager.PERMISSION_GRANTED) startCamera()
        else askCamera.launch(Manifest.permission.CAMERA)
    }

    private fun startCamera() {
        val future = ProcessCameraProvider.getInstance(this)
        future.addListener({
            val provider = future.get()
            val ratio = AspectRatioStrategy.RATIO_4_3_FALLBACK_AUTO_STRATEGY
            val preview = Preview.Builder().setResolutionSelector(ResolutionSelector.Builder().setAspectRatioStrategy(ratio).build())
                .build().also { it.surfaceProvider = previewView.surfaceProvider }
            val analysis = ImageAnalysis.Builder()
                .setResolutionSelector(ResolutionSelector.Builder().setAspectRatioStrategy(ratio)
                    .setResolutionStrategy(ResolutionStrategy(Size(1920, 1440), ResolutionStrategy.FALLBACK_RULE_CLOSEST_LOWER_THEN_HIGHER)).build())
                .setBackpressureStrategy(ImageAnalysis.STRATEGY_KEEP_ONLY_LATEST)
                .setOutputImageFormat(ImageAnalysis.OUTPUT_IMAGE_FORMAT_RGBA_8888)
                .build()
            analysis.setAnalyzer(exec) { analyze(it) }
            runCatching {
                provider.unbindAll()
                camera = provider.bindToLifecycle(this, if (front) CameraSelector.DEFAULT_FRONT_CAMERA else CameraSelector.DEFAULT_BACK_CAMERA, preview, analysis)
                camera?.cameraInfo?.zoomState?.observe(this) { z -> overlay.zoom = z.zoomRatio }
            }.onFailure { status.text = "카메라를 열 수 없습니다: ${it.message}" }
        }, ContextCompat.getMainExecutor(this))
    }

    private fun zoomBy(f: Float) {
        val cam = camera ?: return
        val z = cam.cameraInfo.zoomState.value ?: return
        cam.cameraControl.setZoomRatio((z.zoomRatio * f).coerceIn(z.minZoomRatio, z.maxZoomRatio))
    }

    private fun makePose(mode: RunningMode, n: Int, allowGpu: Boolean, lite: Boolean = false): PoseLandmarker {
        fun make(d: Delegate) = PoseLandmarker.createFromOptions(this, PoseLandmarker.PoseLandmarkerOptions.builder()
            .setBaseOptions(BaseOptions.builder().setModelAssetPath(if (lite) "pose_landmarker_lite.task" else "pose_landmarker_full.task").setDelegate(d).build())
            .setRunningMode(mode).setNumPoses(n)
            .setMinPoseDetectionConfidence(0.45f).setMinTrackingConfidence(0.45f).build())
        return if (allowGpu) GpuGuard.create(this, "pose", { make(Delegate.GPU) }, { make(Delegate.CPU) }) else make(Delegate.CPU)
    }

    private fun makeDetector(): ObjectDetector {
        fun make(d: Delegate) = ObjectDetector.createFromOptions(this, ObjectDetector.ObjectDetectorOptions.builder()
            .setBaseOptions(BaseOptions.builder().setModelAssetPath("efficientdet_lite2.tflite").setDelegate(d).build())
            .setRunningMode(RunningMode.IMAGE).setMaxResults(10).setScoreThreshold(0.35f)
            .setCategoryAllowlist(listOf("person")).build())
        return make(Delegate.CPU) // 보조 모델은 CPU (GPU 를 여러 개 동시에 켜면 일부 기기에서 앱이 종료됨)
    }

    /** 관절 → (픽셀 좌표, 믿을 만한지) — 보임 0.6 이상이고 존재 0.5 이상일 때만 믿음 */
    private fun convert(lm: List<NormalizedLandmark>, ox: Float, oy: Float, sw: Float, sh: Float): Pair<FloatArray, BooleanArray> {
        val pts = FloatArray(33 * 2); val ok = BooleanArray(33)
        for (i in 0 until min(33, lm.size)) {
            val p = lm[i]
            pts[i * 2] = ox + p.x() * sw; pts[i * 2 + 1] = oy + p.y() * sh
            ok[i] = p.visibility().orElse(0f) > 0.6f && p.presence().orElse(0f) > 0.5f
        }
        return pts to ok
    }

    private fun boxOf(pts: FloatArray, ok: BooleanArray): RectF? {
        var l = Float.MAX_VALUE; var t = Float.MAX_VALUE; var r = -Float.MAX_VALUE; var b = -Float.MAX_VALUE; var n = 0
        for (i in 0 until 33) if (ok[i]) { l = min(l, pts[i * 2]); r = max(r, pts[i * 2]); t = min(t, pts[i * 2 + 1]); b = max(b, pts[i * 2 + 1]); n++ }
        if (n < 4) return null
        val pw = (r - l) * 0.12f; val ph = (b - t) * 0.08f
        return RectF(l - pw, t - ph * 2, r + pw, b + ph)
    }

    /** 자세 판별 (화면 밖이거나 가려진 관절은 쓰지 않음) */
    private fun posture(p: FloatArray, ok: BooleanArray): String {
        fun x(i: Int) = p[i * 2]
        fun y(i: Int) = p[i * 2 + 1]
        if (!(ok[11] && ok[12])) return "사람"
        val shw = abs(x(11) - x(12)) + 1e-3f
        val hand = (ok[15] && ok[13] && y(15) < y(11) - 0.6f * shw) || (ok[16] && ok[14] && y(16) < y(12) - 0.6f * shw)
        val extra = if (hand) " · 손 듦" else ""
        if (!(ok[23] && ok[24])) return "상반신$extra"
        val sx = (x(11) + x(12)) / 2; val sy = (y(11) + y(12)) / 2; val hx = (x(23) + x(24)) / 2; val hy = (y(23) + y(24)) / 2
        val torso = hypot(sx - hx, sy - hy) + 1e-3f
        if (abs(sx - hx) > abs(sy - hy) * 1.2f) return "누움$extra"
        if (!(ok[25] && ok[26])) return "서 있음$extra"
        val t1 = y(25) - y(23); val t2 = y(26) - y(24)
        if (t1 < 0.35f * torso && t2 < 0.35f * torso) return "앉음$extra"
        if (min(t1, t2) < 0.35f * torso || (ok[27] && ok[28] && abs(y(27) - y(28)) > 0.5f * torso)) return "움직임$extra"
        return "서 있음$extra"
    }

    private fun iou(a: RectF, b: RectF): Float {
        val l = max(a.left, b.left); val t = max(a.top, b.top); val r = min(a.right, b.right); val bt = min(a.bottom, b.bottom)
        if (r <= l || bt <= t) return 0f
        val inter = (r - l) * (bt - t)
        return inter / (a.width() * a.height() + b.width() * b.height() - inter)
    }

    private var frameNo = 0
    private var tileIdx = 0
    private var lastDet: List<RectF> = emptyList()

    /** 잘라 낸 영역에서 관절 찾기 (가벼운 Lite 모델) → 전체 사진 좌표 */
    private fun poseInCrop(bmp: Bitmap, r: RectF): Pair<FloatArray, BooleanArray>? {
        val ex = r.width() * 0.3f; val ey = r.height() * 0.15f
        val l = (r.left - ex).toInt().coerceIn(0, bmp.width - 2); val t = (r.top - ey).toInt().coerceIn(0, bmp.height - 2)
        val rr = (r.right + ex).toInt().coerceIn(l + 2, bmp.width); val bb = (r.bottom + ey).toInt().coerceIn(t + 2, bmp.height)
        if (rr - l < 16 || bb - t < 24) return null
        val crop = Bitmap.createBitmap(bmp, l, t, rr - l, bb - t)
        val pc = poseCrop ?: makePose(RunningMode.IMAGE, 1, false, lite = true).also { poseCrop = it }
        val res = runCatching { pc.detect(BitmapImageBuilder(crop).build()).landmarks().firstOrNull() }.getOrNull()
        if (crop !== bmp) crop.recycle()
        res ?: return null
        val (pts, ok) = convert(res, l.toFloat(), t.toFloat(), (rr - l).toFloat(), (bb - t).toFloat())
        return if (boxOf(pts, ok) != null) pts to ok else null
    }

    private fun analyze(img: ImageProxy) {
        try {
            val raw = img.toBitmap()
            val m = android.graphics.Matrix().apply { postRotate(img.imageInfo.rotationDegrees.toFloat()); if (front) postScale(-1f, 1f) }
            val bmp = Bitmap.createBitmap(raw, 0, 0, raw.width, raw.height, m, true) // 고해상도 (1920×1440)
            if (bmp !== raw) raw.recycle()
            val w = bmp.width.toFloat(); val h = bmp.height.toFloat()
            val ts = max(SystemClock.uptimeMillis(), lastTs + 1).also { lastTs = it }
            if (resetCount) { resetCount = false; tracks.clear(); total = 0 }

            // 화면 전체 분석은 줄인 사진으로 (빠르게)
            val ds = min(1f, 960f / max(w, h))
            val small = if (ds < 1f) Bitmap.createScaledBitmap(bmp, (w * ds).toInt(), (h * ds).toInt(), true) else bmp

            // 1) 화면 전체에서 관절 (가까운 사람, 최대 5명)
            val pl = pose ?: makePose(RunningMode.VIDEO, 5, false).also { pose = it }
            val found = ArrayList<Triple<RectF, FloatArray?, BooleanArray?>>()
            for (lm in pl.detectForVideo(BitmapImageBuilder(small).build(), ts).landmarks()) {
                val (pts, ok) = convert(lm, 0f, 0f, w, h)
                boxOf(pts, ok)?.let { found += Triple(it, pts, ok) }
            }
            // 2) 자동 확대: 물체 인식(사람)을 짝수 프레임엔 화면 전체(줄인 사진), 홀수 프레임엔 원래 해상도 조각 하나로
            val det = detector ?: makeDetector().also { detector = it }
            val boxes = ArrayList<RectF>()
            if (frameNo % 2 == 0) {
                det.detect(BitmapImageBuilder(small).build()).detections().forEach { d -> val b = d.boundingBox(); boxes += RectF(b.left / ds, b.top / ds, b.right / ds, b.bottom / ds) }
            } else {
                val grid = tiles(w, h, 0.5f)
                val tr = grid[tileIdx++ % grid.size]
                val crop = Bitmap.createBitmap(bmp, tr.left.toInt(), tr.top.toInt(), tr.width().toInt().coerceAtMost(bmp.width - tr.left.toInt()), tr.height().toInt().coerceAtMost(bmp.height - tr.top.toInt()))
                det.detect(BitmapImageBuilder(crop).build()).detections().forEach { d -> val b = d.boundingBox(); boxes += RectF(b.left + tr.left, b.top + tr.top, b.right + tr.left, b.bottom + tr.top) }
                crop.recycle()
            }
            frameNo++
            // 이전 결과와 합쳐서 (조각은 돌아가며 보므로) 잠시 기억
            val merged = ArrayList<RectF>()
            for (r in boxes + lastDet) if (merged.none { iou(it, r) > 0.4f }) merged += r
            lastDet = boxes.ifEmpty { lastDet.filter { d -> tracks.any { iou(it.rect, d) > 0.3f } } }
            // 3) 관절을 못 찾은 사람 상자는 원래 해상도로 잘라서 관절 찾기 (최대 4명)
            var cropped = 0
            for (r in merged.sortedByDescending { it.height() }) {
                if (found.any { iou(it.first, r) > 0.3f }) continue
                val res = if (cropped < 4) { cropped++; poseInCrop(bmp, r) } else null
                found += if (res != null) Triple(RectF(r), res.first, res.second) else Triple(RectF(r), null, null)
            }
            // 4) 이미 추적 중인 작은(먼) 사람은 이번 프레임에 못 찾았어도 그 자리를 다시 확대해서 봄 (찾았을 때만 유지)
            for (t in tracks) {
                if (cropped >= 6 || t.rect.height() > h * 0.5f || found.any { iou(it.first, t.rect) > 0.3f }) continue
                cropped++
                poseInCrop(bmp, t.rect)?.let { (pts, ok) -> boxOf(pts, ok)?.let { b -> found += Triple(b, pts, ok) } }
            }
            if (small !== bmp) small.recycle()
            bmp.recycle()
            // 5) 번호 붙이기 (추적), 상자는 부드럽게, 3프레임 이상 보이면 누적 인원에 셈
            val now = ts
            val used = HashSet<PersonTrack>()
            val people = ArrayList<PersonInfo>()
            for ((r, pts, ok) in found.sortedByDescending { it.first.height() }) {
                val t = tracks.filter { it !in used }.maxByOrNull { iou(it.rect, r) }?.takeIf { iou(it.rect, r) > 0.25f }
                    ?: PersonTrack(nextId++, RectF(r), now).also { tracks += it }
                used += t
                t.rect.set(t.rect.left + (r.left - t.rect.left) * 0.6f, t.rect.top + (r.top - t.rect.top) * 0.6f,
                    t.rect.right + (r.right - t.rect.right) * 0.6f, t.rect.bottom + (r.bottom - t.rect.bottom) * 0.6f)
                t.lastSeen = now; t.frames++
                if (!t.counted && t.frames >= 3) { t.counted = true; total++ }
                people += PersonInfo(t.id, RectF(t.rect), pts, ok, if (pts != null && ok != null) posture(pts, ok) else "사람 (멀리)")
            }
            tracks.removeAll { now - it.lastSeen > 1500 }
            overlay.post(PersonFrame(w.toInt(), h.toInt(), people, people.size, total))
            runOnUiThread { status.text = if (people.isEmpty()) "사람을 화면에 비춰 주세요 (두 손가락으로 확대)" else "사람 ${people.size}명 인식 중" }
        } catch (e: Exception) {
            runOnUiThread { status.text = "오류: ${e.message}" }
        } finally {
            img.close()
        }
    }

    override fun onDestroy() {
        super.onDestroy()
        exec.execute { pose?.close(); poseCrop?.close(); detector?.close() }
        exec.shutdown()
    }
}

/** 뼈대·상자·번호·자세와 왼쪽 위 인원 수를 그립니다. 두 손가락으로 줌. */
class PersonOverlay(ctx: Context, private val onZoom: (Float) -> Unit) : View(ctx) {
    private val latest = AtomicReference<PersonFrame?>()
    @Volatile var skeleton = true
    @Volatile var zoom = 1f
    var topInset = 0
    private val d = resources.displayMetrics.density
    private val line = Paint(Paint.ANTI_ALIAS_FLAG).apply { strokeWidth = 3 * d; strokeCap = Paint.Cap.ROUND }
    private val dot = Paint(Paint.ANTI_ALIAS_FLAG)
    private val box = Paint(Paint.ANTI_ALIAS_FLAG).apply { style = Paint.Style.STROKE; strokeWidth = 2.5f * d }
    private val fill = Paint(Paint.ANTI_ALIAS_FLAG)
    private val text = Paint(Paint.ANTI_ALIAS_FLAG).apply { color = Color.WHITE; textSize = 14 * d; isFakeBoldText = true }
    private val colors = intArrayOf(Color.rgb(0, 210, 255), Color.rgb(255, 170, 0), Color.rgb(120, 230, 90), Color.rgb(255, 90, 160), Color.rgb(180, 140, 255))
    private val scale = ScaleGestureDetector(ctx, object : ScaleGestureDetector.SimpleOnScaleGestureListener() {
        override fun onScale(dt: ScaleGestureDetector): Boolean { onZoom(dt.scaleFactor); return true }
    })

    fun post(f: PersonFrame) { latest.set(f); postInvalidate() }
    override fun onTouchEvent(e: MotionEvent): Boolean { scale.onTouchEvent(e); return true }

    override fun onDraw(c: Canvas) {
        val f = latest.get() ?: return
        val m = FillCenter(width, height, f.w, f.h)
        for (p in f.people) {
            val col = colors[(p.id - 1) % colors.size]
            val r = m.rect(p.rect)
            box.color = col
            val k = min(r.width(), r.height()) * 0.2f
            c.drawLine(r.left, r.top, r.left + k, r.top, box); c.drawLine(r.left, r.top, r.left, r.top + k, box)
            c.drawLine(r.right, r.top, r.right - k, r.top, box); c.drawLine(r.right, r.top, r.right, r.top + k, box)
            c.drawLine(r.left, r.bottom, r.left + k, r.bottom, box); c.drawLine(r.left, r.bottom, r.left, r.bottom - k, box)
            c.drawLine(r.right, r.bottom, r.right - k, r.bottom, box); c.drawLine(r.right, r.bottom, r.right, r.bottom - k, box)
            val pts = p.pts; val ok = p.ok
            if (skeleton && pts != null && ok != null) {
                line.color = col
                for (e in POSE_EDGES) if (ok[e[0]] && ok[e[1]])
                    c.drawLine(m.x(pts[e[0] * 2]), m.y(pts[e[0] * 2 + 1]), m.x(pts[e[1] * 2]), m.y(pts[e[1] * 2 + 1]), line)
                dot.color = Color.WHITE
                for (i in 0 until 33) if (ok[i] && i !in 1..10) c.drawCircle(m.x(pts[i * 2]), m.y(pts[i * 2 + 1]), 3.5f * d, dot)
            }
            val label = "사람 #${p.id} · ${p.posture}"
            val tw = text.measureText(label)
            fill.color = Color.argb(210, Color.red(col) / 3, Color.green(col) / 3, Color.blue(col) / 3)
            c.drawRoundRect(RectF(r.left, r.top - text.textSize - 12 * d, r.left + tw + 12 * d, r.top - 2 * d), 6 * d, 6 * d, fill)
            c.drawText(label, r.left + 6 * d, r.top - 8 * d, text)
        }
        // 왼쪽 위 인원 수
        val s1 = "지금 ${f.now}명"; val s2 = "누적 ${f.total}명"
        val left = 10 * d; val top = topInset + 10 * d
        val w = max(text.measureText(s1), text.measureText(s2)) + 24 * d
        fill.color = Color.argb(200, 15, 18, 26)
        c.drawRoundRect(RectF(left, top, left + w, top + 2 * text.textSize + 26 * d), 12 * d, 12 * d, fill)
        c.drawText(s1, left + 12 * d, top + 10 * d + text.textSize, text)
        c.drawText(s2, left + 12 * d, top + 16 * d + 2 * text.textSize, text)
        if (zoom > 1.05f) {
            fill.color = Color.argb(170, 0, 0, 0)
            c.drawRoundRect(RectF(width - 90 * d, top, width - 10 * d, top + 30 * d), 8 * d, 8 * d, fill)
            c.drawText("줌 %.1fx".format(zoom), width - 82 * d, top + 21 * d, text)
        }
    }
}
