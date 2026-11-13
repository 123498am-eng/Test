package com.selfcheck.app

import android.Manifest
import android.app.AlertDialog
import android.content.Context
import android.content.pm.PackageManager
import android.graphics.Bitmap
import android.graphics.Canvas
import android.graphics.Color
import android.graphics.Paint
import android.graphics.Rect
import android.graphics.RectF
import android.opengl.GLES20
import android.opengl.GLSurfaceView
import android.opengl.Matrix
import android.os.Bundle
import android.os.SystemClock
import android.text.InputType
import android.text.Layout
import android.text.StaticLayout
import android.text.TextPaint
import android.util.Size
import android.view.Gravity
import android.view.View
import android.view.ViewGroup.LayoutParams.MATCH_PARENT
import android.view.ViewGroup.LayoutParams.WRAP_CONTENT
import android.widget.Button
import android.widget.EditText
import android.widget.FrameLayout
import android.widget.LinearLayout
import android.widget.TextView
import androidx.activity.ComponentActivity
import androidx.activity.result.contract.ActivityResultContracts
import androidx.camera.core.CameraSelector
import androidx.camera.core.ImageAnalysis
import androidx.camera.core.ImageProxy
import androidx.camera.core.resolutionselector.ResolutionSelector
import androidx.camera.core.resolutionselector.ResolutionStrategy
import androidx.camera.lifecycle.ProcessCameraProvider
import androidx.core.content.ContextCompat
import com.google.mediapipe.framework.image.BitmapImageBuilder
import com.google.mediapipe.tasks.core.BaseOptions
import com.google.mediapipe.tasks.vision.core.RunningMode
import com.google.mediapipe.tasks.vision.facelandmarker.FaceLandmarker
import com.google.mediapipe.tasks.vision.objectdetector.ObjectDetector
import java.util.concurrent.ExecutorService
import java.util.concurrent.Executors
import java.util.concurrent.atomic.AtomicReference
import javax.microedition.khronos.egl.EGLConfig
import javax.microedition.khronos.opengles.GL10
import kotlin.math.max
import kotlin.math.min

// ---------- 화면에 보낼 데이터 ----------

/** 스캔이 끝나 고정된 3D 모델 (얼굴 번호별). */
class FaceModel(val id: Int, val mesh: MeshData, val side: Int /* 1 왼쪽, 2 오른쪽 */)

/** 얼굴 하나의 표시 정보. */
class FaceInfo(val id: Int, val rect: RectF, val progress: Float, val model: FaceModel?, val dots: FloatArray)

/** 사물 하나의 표시 정보. */
class ObjInfo(val rect: RectF, val label: String, val score: Float)

/** 한 프레임: 카메라 사진 + 얼굴/사물 정보. */
class LiveFrame(val bitmap: Bitmap, val faces: List<FaceInfo>, val objects: List<ObjInfo>) {
    val w = bitmap.width
    val h = bitmap.height
}

// ---------- 얼굴 추적 ----------

/** 프레임 사이에서 같은 얼굴을 이어 주고, 1.5초 스캔 후 3D 모델을 만들어 고정합니다. */
private class FaceTrack(val id: Int, var rect: RectF, now: Long) {
    val start = now
    var lastSeen = now
    var frames = 0
    var sum: FloatArray? = null
    var model: FaceModel? = null
    var pts = FloatArray(0)

    fun progress(now: Long) = if (model != null) 1f else min((now - start) / SCAN_MS.toFloat(), frames / MIN_FRAMES.toFloat()).coerceIn(0f, 1f)

    companion object {
        const val SCAN_MS = 1500L
        const val MIN_FRAMES = 12
        const val LOST_MS = 900L
    }
}

private fun iou(a: RectF, b: RectF): Float {
    val l = max(a.left, b.left); val t = max(a.top, b.top); val r = min(a.right, b.right); val bt = min(a.bottom, b.bottom)
    if (r <= l || bt <= t) return 0f
    val inter = (r - l) * (bt - t)
    return inter / (a.width() * a.height() + b.width() * b.height() - inter)
}

// ---------- 화면 ----------

/**
 * 실시간 카메라.
 * - 얼굴 3D: 여러 얼굴을 번호로 구분해 추적하고, 얼굴마다 스캔이 끝나면 3D 모델을 그 얼굴 옆에 고정해 천천히 왼쪽으로 돌립니다.
 *   얼굴이 누구인지 알아내는 기능은 없습니다.
 * - 제품 인식: 기기 안에서 80종 사물을 찾고, Claude API 키가 있으면 제품 이름과 설명을 받아 왼쪽 위에 보여 줍니다.
 */
class LiveActivity : ComponentActivity() {
    private lateinit var glView: GLSurfaceView
    private lateinit var overlay: OverlayView
    private lateinit var status: TextView
    private lateinit var faceBar: LinearLayout
    private lateinit var productBar: LinearLayout
    private lateinit var modeBtn: Button
    private val renderer = LiveRenderer()
    private lateinit var analysisExec: ExecutorService
    private val aiExec = Executors.newSingleThreadExecutor()

    @Volatile private var productMode = false
    @Volatile private var resetRequested = false
    private var front = true
    private var lastTs = 0L

    // 얼굴 (분석 스레드 전용)
    private var landmarker: FaceLandmarker? = null
    private val tracks = mutableListOf<FaceTrack>()
    private var nextId = 1

    // 제품 (분석 스레드 전용)
    private var detector: ObjectDetector? = null
    private var stableLabel: String? = null
    private var stableCount = 0
    private var lastAskedLabel: String? = null
    private var lastAskTime = 0L
    @Volatile private var aiBusy = false
    @Volatile private var manualAsk = false

    private val askCamera = registerForActivityResult(ActivityResultContracts.RequestPermission()) { ok ->
        if (ok) startCamera() else status.text = "카메라 권한이 필요합니다"
    }

    private fun dp(v: Int) = (v * resources.displayMetrics.density).toInt()

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        analysisExec = Executors.newSingleThreadExecutor()

        val root = FrameLayout(this).apply { setBackgroundColor(Color.BLACK) }
        glView = GLSurfaceView(this).apply {
            setEGLContextClientVersion(2)
            setEGLConfigChooser(MsaaConfigChooser())
            setRenderer(renderer)
            renderMode = GLSurfaceView.RENDERMODE_CONTINUOUSLY
        }
        root.addView(glView, FrameLayout.LayoutParams(MATCH_PARENT, MATCH_PARENT))
        overlay = OverlayView(this)
        root.addView(overlay, FrameLayout.LayoutParams(MATCH_PARENT, MATCH_PARENT))

        val bottom = LinearLayout(this).apply { orientation = LinearLayout.VERTICAL; setPadding(dp(8), dp(4), dp(8), dp(8)) }
        status = TextView(this).apply {
            text = "카메라 준비 중..."; setTextColor(Color.WHITE); textSize = 14f; gravity = Gravity.CENTER
            setShadowLayer(4f, 0f, 0f, Color.BLACK); setPadding(0, 0, 0, dp(4))
        }
        bottom.addView(status)

        fun bar() = LinearLayout(this).apply { orientation = LinearLayout.HORIZONTAL }
        fun LinearLayout.btn(t: String, f: (Button) -> Unit) = Button(this@LiveActivity).apply {
            text = t; textSize = 12f; setOnClickListener { f(this) }
        }.also { addView(it, LinearLayout.LayoutParams(0, WRAP_CONTENT, 1f)) }

        val common = bar()
        modeBtn = common.btn("모드: 얼굴 3D") { setProductMode(!productMode) }
        common.btn("카메라 전환") { front = !front; resetRequested = true; startCamera() }
        bottom.addView(common)

        faceBar = bar()
        faceBar.btn("다시 스캔") { resetRequested = true }
        val sides = listOf("위치: 자동", "위치: 왼쪽", "위치: 오른쪽")
        faceBar.btn(sides[0]) { b -> renderer.sideOverride = (renderer.sideOverride + 1) % 3; b.text = sides[renderer.sideOverride] }
        val modes = listOf("보기: 사진", "보기: 음영", "보기: 선")
        faceBar.btn(modes[0]) { b -> renderer.mode = (renderer.mode + 1) % 3; b.text = modes[renderer.mode] }
        bottom.addView(faceBar)

        productBar = bar()
        productBar.btn("지금 분석") { if (Store.apiKey(this).isEmpty()) askKey() else manualAsk = true }
        productBar.btn(if (Store.autoProduct(this)) "자동 분석: 켬" else "자동 분석: 끔") { b ->
            val v = !Store.autoProduct(this); Store.setAutoProduct(this, v); b.text = if (v) "자동 분석: 켬" else "자동 분석: 끔"
        }
        productBar.btn("API 키") { askKey() }
        productBar.visibility = View.GONE
        bottom.addView(productBar)
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

    private fun setProductMode(on: Boolean) {
        productMode = on
        resetRequested = true
        modeBtn.text = if (on) "모드: 제품 인식" else "모드: 얼굴 3D"
        faceBar.visibility = if (on) View.GONE else View.VISIBLE
        productBar.visibility = if (on) View.VISIBLE else View.GONE
        overlay.product = null
        if (on && Store.apiKey(this).isEmpty()) {
            overlay.product = ProductInfo("제품 인식", "", "", "기기 안에서는 80종의 기본 사물만 알아봅니다. 'API 키'에 Claude API 키를 넣으면 거의 모든 제품의 이름과 설명을 볼 수 있습니다.", emptyList(), "안내")
        }
    }

    private fun askKey() {
        val input = EditText(this).apply {
            hint = "sk-ant-..."; setText(Store.apiKey(this@LiveActivity))
            inputType = InputType.TYPE_CLASS_TEXT or InputType.TYPE_TEXT_VARIATION_PASSWORD
        }
        AlertDialog.Builder(this)
            .setTitle("Claude API 키")
            .setMessage("제품 설명에 씁니다. 키는 이 휴대폰에만 저장되고, 분석할 때 카메라 사진이 Anthropic 서버로 전송됩니다. 사용량에 따라 요금이 나옵니다.")
            .setView(input)
            .setPositiveButton("저장") { _, _ -> Store.setApiKey(this, input.text.toString()) }
            .setNegativeButton("취소", null)
            .show()
    }

    private fun startCamera() {
        val future = ProcessCameraProvider.getInstance(this)
        future.addListener({
            val provider = future.get()
            val analysis = ImageAnalysis.Builder()
                .setResolutionSelector(ResolutionSelector.Builder()
                    .setResolutionStrategy(ResolutionStrategy(Size(1280, 720), ResolutionStrategy.FALLBACK_RULE_CLOSEST_LOWER_THEN_HIGHER))
                    .build())
                .setBackpressureStrategy(ImageAnalysis.STRATEGY_KEEP_ONLY_LATEST)
                .setOutputImageFormat(ImageAnalysis.OUTPUT_IMAGE_FORMAT_RGBA_8888)
                .build()
            analysis.setAnalyzer(analysisExec) { img -> analyze(img) }
            val selector = if (front) CameraSelector.DEFAULT_FRONT_CAMERA else CameraSelector.DEFAULT_BACK_CAMERA
            runCatching {
                provider.unbindAll()
                provider.bindToLifecycle(this, selector, analysis)
            }.onFailure { status.text = "카메라를 열 수 없습니다: ${it.message}" }
        }, ContextCompat.getMainExecutor(this))
    }

    private fun analyze(img: ImageProxy) {
        try {
            val raw = img.toBitmap()
            val m = android.graphics.Matrix().apply {
                postRotate(img.imageInfo.rotationDegrees.toFloat())
                if (front) postScale(-1f, 1f)
            }
            val bmp = Bitmap.createBitmap(raw, 0, 0, raw.width, raw.height, m, true)
            if (bmp !== raw) raw.recycle()
            val ts = max(SystemClock.uptimeMillis(), lastTs + 1).also { lastTs = it }

            if (resetRequested) {
                resetRequested = false
                tracks.clear(); stableLabel = null; stableCount = 0; lastAskedLabel = null
            }

            val frame = if (productMode) analyzeProducts(bmp, ts) else analyzeFaces(bmp, ts)
            renderer.post(frame)
            overlay.post(frame)
        } catch (e: Exception) {
            runOnUiThread { status.text = "오류: ${e.message}" }
        } finally {
            img.close()
        }
    }

    // ----- 얼굴 -----

    private fun analyzeFaces(bmp: Bitmap, ts: Long): LiveFrame {
        val lm = landmarker ?: FaceMesh.create(this, RunningMode.VIDEO, 5, false).also { landmarker = it }
        val faces = lm.detectForVideo(BitmapImageBuilder(bmp).build(), ts).faceLandmarks()
        val w = bmp.width.toFloat(); val h = bmp.height.toFloat()
        val now = ts

        // 이번 프레임 얼굴들
        val dets = faces.map { f ->
            val pts = FloatArray(f.size * 3)
            var minX = 1f; var minY = 1f; var maxX = 0f; var maxY = 0f
            f.forEachIndexed { i, p ->
                pts[i * 3] = p.x(); pts[i * 3 + 1] = p.y(); pts[i * 3 + 2] = p.z()
                minX = min(minX, p.x()); maxX = max(maxX, p.x()); minY = min(minY, p.y()); maxY = max(maxY, p.y())
            }
            RectF(minX * w, minY * h, maxX * w, maxY * h) to pts
        }

        // 기존 얼굴과 짝짓기 (겹치는 정도가 큰 순서대로)
        val pairs = mutableListOf<Triple<Float, Int, FaceTrack>>()
        dets.forEachIndexed { i, (r, _) -> tracks.forEach { t -> val v = iou(r, t.rect); if (v > 0.2f) pairs += Triple(v, i, t) } }
        pairs.sortByDescending { it.first }
        val usedDet = HashSet<Int>(); val usedTrack = HashSet<FaceTrack>()
        for ((_, i, t) in pairs) {
            if (i in usedDet || t in usedTrack) continue
            usedDet += i; usedTrack += t
            t.rect = dets[i].first; t.pts = dets[i].second; t.lastSeen = now; t.frames++
        }
        dets.forEachIndexed { i, (r, pts) ->
            if (i !in usedDet) tracks += FaceTrack(nextId++, r, now).also { it.pts = pts; it.frames = 1; usedTrack += it }
        }
        tracks.removeAll { now - it.lastSeen > FaceTrack.LOST_MS }

        // 스캔: 1.5초 동안 얼굴 모양을 평균 내고, 끝나면 텍스처와 함께 고정
        val sub = Subdivision.get(this)
        for (t in tracks) {
            if (t.model != null || t.lastSeen != now) continue
            val mesh = MeshData.build(sub, t.pts, w, h, RectF(0f, 0f, w, h), null)
            val s = t.sum ?: FloatArray(mesh.pos.size).also { t.sum = it }
            for (k in s.indices) s[k] += mesh.pos[k]
            if (t.progress(now) >= 1f) t.model = finishModel(t, bmp, sub)
        }

        val infos = tracks.filter { now - it.lastSeen < 300 }.map { t ->
            val dots = if (t.model == null) FloatArray(t.pts.size / 3 / 3 * 2).also { d ->
                var j = 0
                for (i in 0 until t.pts.size / 3 step 3) { if (j + 1 < d.size) { d[j++] = t.pts[i * 3] * w; d[j++] = t.pts[i * 3 + 1] * h } }
            } else FloatArray(0)
            FaceInfo(t.id, RectF(t.rect), t.progress(now), t.model, dots)
        }
        val scanning = infos.count { it.model == null }
        val done = infos.count { it.model != null }
        runOnUiThread {
            status.text = when {
                infos.isEmpty() -> "얼굴을 카메라에 비춰 주세요"
                scanning > 0 -> "얼굴 ${infos.size}개 인식 · ${scanning}개 스캔 중 · ${done}개 완료"
                else -> "얼굴 ${infos.size}개 · 3D 모델 고정됨"
            }
        }
        return LiveFrame(bmp, infos, emptyList())
    }

    private fun finishModel(t: FaceTrack, bmp: Bitmap, sub: Subdivision): FaceModel {
        val w = bmp.width.toFloat(); val h = bmp.height.toFloat()
        // 얼굴 부분만 512px 텍스처로 잘라 둡니다
        val side = max(t.rect.width(), t.rect.height()) * 1.2f
        val cx = t.rect.centerX(); val cy = t.rect.centerY()
        val crop = Rect((cx - side / 2).toInt(), (cy - side / 2).toInt(), (cx + side / 2).toInt(), (cy + side / 2).toInt())
        val tex = Bitmap.createBitmap(512, 512, Bitmap.Config.ARGB_8888)
        Canvas(tex).apply { drawColor(Color.rgb(40, 34, 32)); drawBitmap(bmp, crop, Rect(0, 0, 512, 512), Paint(Paint.FILTER_BITMAP_FLAG)) }
        val last = MeshData.build(sub, t.pts, w, h, RectF(crop), tex)
        val avg = t.sum!!.copyOf().also { a -> for (k in a.indices) a[k] /= t.frames.coerceAtLeast(1) }
        val mesh = MeshData(avg, last.uv, MeshData.normals(avg, sub.tris), sub.tris, tex)
        val sideChoice = if (w - t.rect.right >= t.rect.left) 2 else 1 // 공간이 넓은 쪽에 고정
        return FaceModel(t.id, mesh, sideChoice)
    }

    // ----- 제품 -----

    private fun analyzeProducts(bmp: Bitmap, ts: Long): LiveFrame {
        val det = detector ?: ObjectDetector.createFromOptions(this, ObjectDetector.ObjectDetectorOptions.builder()
            .setBaseOptions(BaseOptions.builder().setModelAssetPath("efficientdet_lite0.tflite").build())
            .setRunningMode(RunningMode.VIDEO)
            .setMaxResults(5)
            .setScoreThreshold(0.4f)
            .build()).also { detector = it }
        val res = det.detectForVideo(BitmapImageBuilder(bmp).build(), ts)
        val objs = res.detections().mapNotNull { d ->
            val c = d.categories().firstOrNull() ?: return@mapNotNull null
            if (c.categoryName() == "person") return@mapNotNull null // 사람은 제품이 아니므로 제외
            ObjInfo(RectF(d.boundingBox()), c.categoryName(), c.score())
        }
        // 가장 크고 확실한 사물을 주 대상으로
        val main = objs.maxByOrNull { it.score * it.rect.width() * it.rect.height() }
        if (main != null && main.label == stableLabel) stableCount++ else { stableLabel = main?.label; stableCount = if (main != null) 1 else 0 }

        val key = Store.apiKey(this)
        val now = SystemClock.uptimeMillis()
        val stable = main != null && stableCount >= 8
        val auto = stable && Store.autoProduct(this) && main!!.label != lastAskedLabel && now - lastAskTime > 4000
        if (key.isEmpty()) {
            if (stable) LocalProducts.info(main!!.label)?.let { info -> if (overlay.product?.name != info.name) overlay.product = info.copy(features = listOf("API 키를 넣으면 실제 제품명과 자세한 설명을 볼 수 있습니다")) }
            manualAsk = false
        } else if (!aiBusy && (auto || manualAsk)) {
            manualAsk = false
            lastAskedLabel = main?.label; lastAskTime = now
            val crop = cropFor(bmp, main?.rect)
            val hint = main?.label?.let { LocalProducts.korean(it) }
            aiBusy = true
            val local = main?.let { LocalProducts.info(it.label) }
            overlay.product = (local ?: ProductInfo("분석 중", "", "", "", emptyList(), "")).copy(source = "Claude 분석 중...")
            aiExec.execute {
                val info = runCatching { ProductAI.describe(key, crop, hint) }
                    .getOrElse { ProductInfo("분석 실패", "", "", it.message ?: "알 수 없는 오류", emptyList(), "오류") }
                crop.recycle()
                overlay.product = info
                aiBusy = false
            }
        }
        runOnUiThread {
            status.text = when {
                main == null -> "제품을 화면 가운데에 비춰 주세요"
                aiBusy -> "${LocalProducts.korean(main.label)} 인식 · Claude 분석 중..."
                else -> "${LocalProducts.korean(main.label)} 인식 (${(main.score * 100).toInt()}%)"
            }
        }
        return LiveFrame(bmp, emptyList(), objs)
    }

    /** 분석용 사진: 사물 영역(여유 15%), 없으면 화면 가운데. 긴 변 768px. */
    private fun cropFor(bmp: Bitmap, r: RectF?): Bitmap {
        val w = bmp.width; val h = bmp.height
        val rect = if (r != null) {
            val mx = r.width() * 0.15f; val my = r.height() * 0.15f
            Rect(max(0, (r.left - mx).toInt()), max(0, (r.top - my).toInt()), min(w, (r.right + mx).toInt()), min(h, (r.bottom + my).toInt()))
        } else {
            val s = (min(w, h) * 0.8f).toInt()
            Rect((w - s) / 2, (h - s) / 2, (w + s) / 2, (h + s) / 2)
        }
        val sc = min(1f, 768f / max(rect.width(), rect.height()))
        val out = Bitmap.createBitmap(max(1, (rect.width() * sc).toInt()), max(1, (rect.height() * sc).toInt()), Bitmap.Config.ARGB_8888)
        Canvas(out).drawBitmap(bmp, rect, Rect(0, 0, out.width, out.height), Paint(Paint.FILTER_BITMAP_FLAG))
        return out
    }

    override fun onPause() { super.onPause(); glView.onPause() }
    override fun onResume() { super.onResume(); glView.onResume() }

    override fun onDestroy() {
        super.onDestroy()
        analysisExec.execute { landmarker?.close(); landmarker = null; detector?.close(); detector = null }
        analysisExec.shutdown()
        aiExec.shutdown()
    }
}

/** 카메라 화면과 같은 비율로 계산하는 좌표 변환 (사진 픽셀 → 화면 픽셀). */
class FillCenter(vw: Int, vh: Int, bw: Int, bh: Int) {
    val s = max(vw / bw.toFloat(), vh / bh.toFloat())
    val ox = (vw - bw * s) / 2
    val oy = (vh - bh * s) / 2
    fun x(v: Float) = v * s + ox
    fun y(v: Float) = v * s + oy
    fun rect(r: RectF) = RectF(x(r.left), y(r.top), x(r.right), y(r.bottom))
}

/** 얼굴 스캔 상태, 사물 상자, 제품 설명 패널을 그리는 투명한 위층. */
class OverlayView(ctx: Context) : View(ctx) {
    private val latest = AtomicReference<LiveFrame?>()
    @Volatile var product: ProductInfo? = null
        set(v) { field = v; postInvalidate() }
    var topInset = 0
    private val d = resources.displayMetrics.density
    private val box = Paint(Paint.ANTI_ALIAS_FLAG).apply { style = Paint.Style.STROKE; strokeWidth = 3 * d }
    private val fill = Paint(Paint.ANTI_ALIAS_FLAG)
    private val text = TextPaint(Paint.ANTI_ALIAS_FLAG).apply { color = Color.WHITE; textSize = 13 * d }
    private val title = TextPaint(Paint.ANTI_ALIAS_FLAG).apply { color = Color.WHITE; textSize = 18 * d; isFakeBoldText = true }
    private val small = TextPaint(Paint.ANTI_ALIAS_FLAG).apply { color = Color.rgb(190, 220, 255); textSize = 12 * d }

    fun post(f: LiveFrame) { latest.set(f); postInvalidate() }

    override fun onDraw(c: Canvas) {
        val f = latest.get()
        if (f != null) {
            val m = FillCenter(width, height, f.w, f.h)
            for (face in f.faces) drawFace(c, m, face)
            for (o in f.objects) drawObject(c, m, o)
        }
        product?.let { drawPanel(c, it) }
    }

    private fun corners(c: Canvas, r: RectF, color: Int) {
        box.color = color
        val l = min(r.width(), r.height()) * 0.22f
        c.drawLine(r.left, r.top, r.left + l, r.top, box); c.drawLine(r.left, r.top, r.left, r.top + l, box)
        c.drawLine(r.right, r.top, r.right - l, r.top, box); c.drawLine(r.right, r.top, r.right, r.top + l, box)
        c.drawLine(r.left, r.bottom, r.left + l, r.bottom, box); c.drawLine(r.left, r.bottom, r.left, r.bottom - l, box)
        c.drawLine(r.right, r.bottom, r.right - l, r.bottom, box); c.drawLine(r.right, r.bottom, r.right, r.bottom - l, box)
    }

    private fun pill(c: Canvas, label: String, x: Float, y: Float, bg: Int, progress: Float? = null) {
        val pad = 6 * d
        val tw = text.measureText(label)
        val r = RectF(x, y - text.textSize - pad * 2, x + tw + pad * 2, y)
        fill.color = bg
        c.drawRoundRect(r, 8 * d, 8 * d, fill)
        if (progress != null) {
            fill.color = Color.argb(230, 0, 230, 160)
            c.drawRect(r.left, r.bottom - 3 * d, r.left + r.width() * progress, r.bottom, fill)
        }
        c.drawText(label, x + pad, y - pad - 2 * d, text)
    }

    private fun drawFace(c: Canvas, m: FillCenter, face: FaceInfo) {
        val r = m.rect(face.rect)
        val done = face.model != null
        corners(c, r, if (done) Color.rgb(80, 230, 120) else Color.rgb(0, 210, 255))
        if (!done) {
            fill.color = Color.argb(170, 0, 230, 200)
            for (i in 0 until face.dots.size / 2) c.drawCircle(m.x(face.dots[i * 2]), m.y(face.dots[i * 2 + 1]), 1.6f * d, fill)
        }
        val label = if (done) "얼굴 #${face.id} · 3D 완료" else "얼굴 #${face.id} · 스캔 중 ${(face.progress * 100).toInt()}%"
        pill(c, label, r.left, r.top - 4 * d, if (done) Color.argb(200, 20, 110, 50) else Color.argb(200, 0, 80, 120),
            if (done) null else face.progress)
    }

    private fun drawObject(c: Canvas, m: FillCenter, o: ObjInfo) {
        val r = m.rect(o.rect)
        box.color = Color.rgb(255, 196, 0)
        c.drawRoundRect(r, 10 * d, 10 * d, box)
        pill(c, "${LocalProducts.korean(o.label)} ${(o.score * 100).toInt()}%", r.left, r.top - 4 * d, Color.argb(210, 140, 95, 0))
    }

    /** 왼쪽 위 제품 설명 패널 */
    private fun drawPanel(c: Canvas, p: ProductInfo) {
        val pad = 12 * d
        val w = min(width * 0.62f, 320 * d)
        val inner = (w - pad * 2).toInt()
        fun layout(s: String, tp: TextPaint) = StaticLayout.Builder.obtain(s, 0, s.length, tp, inner)
            .setAlignment(Layout.Alignment.ALIGN_NORMAL).setLineSpacing(0f, 1.1f).build()
        val parts = mutableListOf<StaticLayout>()
        parts += layout(p.name, title)
        val meta = listOf(p.brand, p.category).filter { it.isNotBlank() && it != "-" }.joinToString(" · ")
        if (meta.isNotEmpty()) parts += layout(meta, small)
        if (p.description.isNotBlank()) parts += layout(p.description, text)
        p.features.take(3).forEach { parts += layout("• $it", text) }
        if (p.source.isNotBlank()) parts += layout(p.source, small)
        val gap = 6 * d
        val h = pad * 2 + parts.sumOf { it.height.toDouble() }.toFloat() + gap * (parts.size - 1)
        val left = 12 * d; val top = topInset + 12 * d
        fill.color = Color.argb(205, 15, 18, 26)
        c.drawRoundRect(RectF(left, top, left + w, top + h), 14 * d, 14 * d, fill)
        var y = top + pad
        for (l in parts) {
            c.save(); c.translate(left + pad, y); l.draw(c); c.restore()
            y += l.height + gap
        }
    }
}

/** 카메라 화면을 배경으로 그리고, 스캔이 끝난 얼굴마다 3D 모델을 그 얼굴 옆에 고정해 천천히 왼쪽으로 돌립니다. */
class LiveRenderer : GLSurfaceView.Renderer {
    @Volatile var mode = MeshGL.MODE_TEXTURE
    @Volatile var sideOverride = 0 // 0 자동(얼굴마다 고정된 쪽), 1 왼쪽, 2 오른쪽
    private val pending = AtomicReference<LiveFrame?>()
    private val bg = MeshGL()
    private val models = HashMap<Int, MeshGL>()
    private val modelSeen = HashMap<Int, Long>()
    private val boxes = HashMap<Int, RectF>()
    private var current: LiveFrame? = null
    private var vw = 1; private var vh = 1
    private var yaw = 0f
    private var lastTime = 0L
    private val proj = FloatArray(16); private val view = FloatArray(16)
    private val model = FloatArray(16); private val tmp = FloatArray(16); private val mvp = FloatArray(16)

    fun post(f: LiveFrame) { pending.getAndSet(f)?.bitmap?.recycle() }

    override fun onSurfaceCreated(g: GL10?, config: EGLConfig?) {
        bg.init()
        models.clear(); modelSeen.clear(); boxes.clear()
        current = null
        GLES20.glClearColor(0f, 0f, 0f, 1f)
        Matrix.perspectiveM(proj, 0, 35f, 1f, 0.1f, 50f)
        Matrix.setLookAtM(view, 0, 0f, 0f, 4.2f, 0f, 0f, 0f, 0f, 1f, 0f)
    }

    override fun onSurfaceChanged(g: GL10?, w: Int, h: Int) { vw = w; vh = h }

    override fun onDrawFrame(g: GL10?) {
        val now = System.nanoTime()
        val dt = if (lastTime == 0L) 0f else (now - lastTime) / 1e9f
        lastTime = now
        yaw -= dt * 22f // 천천히 왼쪽으로 (초당 22도)
        if (yaw < -360f) yaw += 360f

        pending.getAndSet(null)?.let { f ->
            bg.uploadTexture(f.bitmap)
            current?.bitmap?.recycle()
            current = f
            for (face in f.faces) {
                val fm = face.model ?: continue
                modelSeen[fm.id] = now
                if (fm.id !in models) {
                    models[fm.id] = MeshGL().also { it.init(); fm.mesh.texture?.let { t -> it.uploadTexture(t) }; it.setMesh(fm.mesh) }
                }
            }
            // 사라진 얼굴의 모델 정리
            val gone = modelSeen.filter { now - it.value > 1_500_000_000L }.keys
            for (id in gone) { models.remove(id)?.release(); modelSeen.remove(id); boxes.remove(id) }
        }

        GLES20.glViewport(0, 0, vw, vh)
        GLES20.glClear(GLES20.GL_COLOR_BUFFER_BIT or GLES20.GL_DEPTH_BUFFER_BIT)
        val f = current ?: return
        val bw = f.w; val bh = f.h
        val m = FillCenter(vw, vh, bw, bh)
        GLES20.glDisable(GLES20.GL_DEPTH_TEST)
        bg.drawBackground(-m.ox / m.s / bw, (vw - m.ox) / m.s / bw, -m.oy / m.s / bh, (vh - m.oy) / m.s / bh)

        GLES20.glEnable(GLES20.GL_DEPTH_TEST)
        for (face in f.faces) {
            val fm = face.model ?: continue
            val gl = models[fm.id] ?: continue
            val r = m.rect(face.rect)
            val size = r.height() * 1.35f
            val side = if (sideOverride == 0) fm.side else sideOverride
            val cx = if (side == 2) r.right + size * 0.5f else r.left - size * 0.5f
            val target = RectF(cx - size / 2, r.centerY() - size / 2, cx + size / 2, r.centerY() + size / 2)
            val b = boxes.getOrPut(fm.id) { RectF(target) }
            val k = 0.3f
            b.set(b.left + (target.left - b.left) * k, b.top + (target.top - b.top) * k,
                b.right + (target.right - b.right) * k, b.bottom + (target.bottom - b.bottom) * k)

            GLES20.glViewport(b.left.toInt(), (vh - b.bottom).toInt(), b.width().toInt(), b.height().toInt())
            GLES20.glClear(GLES20.GL_DEPTH_BUFFER_BIT)
            Matrix.setIdentityM(model, 0)
            Matrix.rotateM(model, 0, yaw + fm.id * 40f, 0f, 1f, 0f)
            Matrix.multiplyMM(tmp, 0, view, 0, model, 0)
            Matrix.multiplyMM(mvp, 0, proj, 0, tmp, 0)
            gl.drawMesh(mvp, model, mode)
        }
    }
}
