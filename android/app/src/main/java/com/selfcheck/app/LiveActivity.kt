package com.selfcheck.app

import android.Manifest
import android.app.AlertDialog
import android.content.Context
import android.content.pm.PackageManager
import android.graphics.Bitmap
import android.graphics.Canvas
import android.graphics.Color
import android.graphics.Paint
import android.graphics.PixelFormat
import android.content.Intent
import android.net.Uri
import android.view.MotionEvent
import android.view.GestureDetector
import android.view.ScaleGestureDetector
import android.widget.PopupMenu
import android.hardware.camera2.CameraCharacteristics
import androidx.camera.camera2.interop.Camera2CameraInfo
import androidx.camera.camera2.interop.ExperimentalCamera2Interop
import androidx.camera.core.Camera
import java.util.concurrent.ConcurrentLinkedQueue
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
import androidx.camera.core.Preview
import androidx.camera.core.resolutionselector.AspectRatioStrategy
import androidx.camera.view.PreviewView
import androidx.camera.core.resolutionselector.ResolutionSelector
import androidx.camera.core.resolutionselector.ResolutionStrategy
import androidx.camera.lifecycle.ProcessCameraProvider
import androidx.core.content.ContextCompat
import com.google.mediapipe.framework.image.BitmapImageBuilder
import com.google.mediapipe.tasks.core.BaseOptions
import com.google.mediapipe.tasks.core.Delegate
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
class FaceInfo(
    val id: Int, val rect: RectF, val progress: Float, val model: FaceModel?, val dots: FloatArray,
    val hidden: Boolean, val side: Int, val distanceM: Float?, val yaw: Float, val pitch: Float, val far: Boolean,
)

/** 얼굴을 눌렀을 때 고른 3D 모델을 크게 보기 화면으로 넘겨 줍니다. */
object ModelHolder { @Volatile var mesh: MeshData? = null }

/** 사물 하나의 표시 정보. info 는 실시간 검색(Claude) 결과가 오면 채워집니다. */
class ObjInfo(val id: Int, val rect: RectF, val label: String, val score: Float, val info: ProductInfo?, val searching: Boolean)

/** 한 프레임의 분석 결과 (분석한 사진의 크기 + 얼굴/사물 정보). 카메라 화면은 미리보기가 따로 그립니다. */
class LiveFrame(val w: Int, val h: Int, val faces: List<FaceInfo>, val objects: List<ObjInfo>)

/** 프레임 사이에서 같은 물건을 이어 주고, 물건마다 검색 결과를 붙여 둡니다. */
private class ObjTrack(val id: Int, var rect: RectF, var label: String, var score: Float, now: Long) {
    var lastSeen = now
    var frames = 1
    @Volatile var info: ProductInfo? = null
    @Volatile var searching = false
    var asked = false
    companion object { const val LOST_MS = 1500L }
}

// ---------- 얼굴 추적 ----------

/** 프레임 사이에서 같은 얼굴을 이어 주고, 1.5초 스캔 후 3D 모델을 만들어 고정합니다. */
private class FaceTrack(val id: Int, var rect: RectF, now: Long) {
    var start = now
    var hidden = false
    var sideOverride = 0 // 0: 스캔 때 정한 쪽, 1 왼쪽, 2 오른쪽
    var lastSeen = now
    var frames = 0
    var sum: FloatArray? = null // 정면 보정한 점 468개의 합
    var model: FaceModel? = null
    var pts = FloatArray(0)
    var far = false

    fun progress(now: Long) = if (model != null) 1f else min((now - start) / SCAN_MS.toFloat(), frames / MIN_FRAMES.toFloat()).coerceIn(0f, 1f)

    companion object {
        const val SCAN_MS = 1500L
        const val MIN_FRAMES = 12
        const val LOST_MS = 1200L
    }
}

/** 화면을 덮는 겹치는 정사각형 조각들 (한 변 = 짧은 변 × frac, 간격 75%). */
private val tileCache = HashMap<Triple<Int, Int, Float>, List<RectF>>()
private fun tiles(w: Float, h: Float, frac: Float): List<RectF> = synchronized(tileCache) {
    tileCache.getOrPut(Triple(w.toInt(), h.toInt(), frac)) {
        val s = min(w, h) * frac
        fun starts(len: Float): List<Float> {
            if (s >= len) return listOf(0f)
            val out = mutableListOf<Float>(); var x = 0f
            while (x + s < len) { out += x; x += s * 0.75f }
            out += len - s
            return out
        }
        val ys = starts(h); val xs = starts(w)
        // 가운데부터 훑도록 정렬 (사람은 보통 화면 가운데에 있음)
        ys.flatMap { y -> xs.map { x -> RectF(x, y, x + s, y + s) } }
            .sortedBy { r -> val dx = r.centerX() - w / 2; val dy = r.centerY() - h / 2; dx * dx + dy * dy }
    }
}

/** 한 프레임에서 찾은 얼굴. src 0: 화면 전체, 1: 조각 확대, 2: 먼 얼굴 정밀 추적 */
private class FaceDet(val rect: RectF, val pts: FloatArray, val src: Int)

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
    private val aiExec = Executors.newFixedThreadPool(3)

    @Volatile private var productMode = false
    @Volatile private var resetRequested = false
    private var front = true
    private var lastTs = 0L

    // 얼굴 (분석 스레드 전용)
    private var landmarker: FaceLandmarker? = null
    private var roiLandmarker: FaceLandmarker? = null // 원거리: 잘라 낸 영역용
    private val tracks = mutableListOf<FaceTrack>()
    private var nextId = 1
    private var tileA = 0 // 큰 조각(가로 45%) 순서
    private var tileB = 0 // 작은 조각(가로 25%) 순서
    private var roiDetector: ObjectDetector? = null
    private val faceCommands = ConcurrentLinkedQueue<(List<FaceTrack>) -> Unit>()

    // 원거리 모드 / 줌 / 거리 추정
    @Volatile private var longRange = true
    private var camera: Camera? = null
    @Volatile private var focalPxPerLongSide = 0f // 초점 거리 (사진 긴 변 1px 기준 비율)
    @Volatile private var zoomRatio = 1f
    private lateinit var anchor: View

    // 제품 (분석 스레드 전용)
    private var detector: ObjectDetector? = null
    private val objTracks = mutableListOf<ObjTrack>()
    private var nextObjId = 1
    private val inFlight = java.util.concurrent.atomic.AtomicInteger(0)
    @Volatile private var manualAsk = false
    private var lastStatus = ""
    private lateinit var previewView: PreviewView

    private val askCamera = registerForActivityResult(ActivityResultContracts.RequestPermission()) { ok ->
        if (ok) startCamera() else status.text = "카메라 권한이 필요합니다"
    }

    private fun dp(v: Int) = (v * resources.displayMetrics.density).toInt()

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        analysisExec = Executors.newSingleThreadExecutor()

        val root = FrameLayout(this).apply { setBackgroundColor(Color.BLACK) }
        // 카메라 화면은 미리보기가 원래 속도로 그리고, 3D 모델만 투명한 GL 층에 그립니다
        previewView = PreviewView(this).apply {
            implementationMode = PreviewView.ImplementationMode.PERFORMANCE
            scaleType = PreviewView.ScaleType.FILL_CENTER
        }
        root.addView(previewView, FrameLayout.LayoutParams(MATCH_PARENT, MATCH_PARENT))
        glView = GLSurfaceView(this).apply {
            setEGLContextClientVersion(2)
            setEGLConfigChooser(MsaaConfigChooser(2))
            holder.setFormat(PixelFormat.TRANSLUCENT)
            setZOrderOnTop(true)
            setRenderer(renderer)
            renderMode = GLSurfaceView.RENDERMODE_CONTINUOUSLY
        }
        root.addView(glView, FrameLayout.LayoutParams(MATCH_PARENT, MATCH_PARENT))
        overlay = OverlayView(this, onPanelTap = { info -> openSearch(info) }, onFaceTap = { face, x, y -> showFaceMenu(face, x, y) },
            onZoom = { f -> zoomBy(f) })
        root.addView(overlay, FrameLayout.LayoutParams(MATCH_PARENT, MATCH_PARENT))
        anchor = View(this)
        root.addView(anchor, FrameLayout.LayoutParams(1, 1))

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
        common.btn("원거리: 켬") { b -> longRange = !longRange; b.text = if (longRange) "원거리: 켬" else "원거리: 끔"; resetRequested = true; startCamera() }
        bottom.addView(common)

        faceBar = bar()
        faceBar.btn("다시 스캔") { resetRequested = true }
        val sides = listOf("위치: 자동", "위치: 왼쪽", "위치: 오른쪽")
        faceBar.btn(sides[0]) { b -> renderer.sideOverride = (renderer.sideOverride + 1) % 3; b.text = sides[renderer.sideOverride] }
        val modes = listOf("보기: 사진", "보기: 음영", "보기: 선")
        faceBar.btn(modes[0]) { b -> renderer.mode = (renderer.mode + 1) % 3; b.text = modes[renderer.mode] }
        bottom.addView(faceBar)

        productBar = bar()
        productBar.btn("다시 검색") { if (Store.apiKey(this).isEmpty()) askKey() else manualAsk = true }
        productBar.btn(if (Store.autoProduct(this)) "실시간 검색: 켬" else "실시간 검색: 끔") { b ->
            val v = !Store.autoProduct(this); Store.setAutoProduct(this, v); b.text = if (v) "실시간 검색: 켬" else "실시간 검색: 끔"
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
            overlay.product = ProductInfo("제품 인식", "", "", "기기 안에서는 80종의 기본 사물만 알아봅니다. 'API 키'에 Claude API 키를 넣으면 비추는 물건을 실시간으로 검색해 제품 이름과 설명을 보여 줍니다.", emptyList(), "안내")
        }
    }

    /** 패널을 누르면 그 제품을 웹에서 검색합니다. */
    private fun openSearch(info: ProductInfo) {
        val q = listOf(info.brand, info.name).filter { it.isNotBlank() && it != "-" && it != "알 수 없음" }.joinToString(" ")
        if (q.isBlank()) return
        runCatching { startActivity(Intent(Intent.ACTION_VIEW, Uri.parse("https://www.google.com/search?q=" + Uri.encode(q)))) }
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
            val ratio = AspectRatioStrategy.RATIO_4_3_FALLBACK_AUTO_STRATEGY
            val preview = Preview.Builder()
                .setResolutionSelector(ResolutionSelector.Builder().setAspectRatioStrategy(ratio).build())
                .build().also { it.surfaceProvider = previewView.surfaceProvider }
            val analysis = ImageAnalysis.Builder()
                .setResolutionSelector(ResolutionSelector.Builder()
                    .setAspectRatioStrategy(ratio)
                    .setResolutionStrategy(ResolutionStrategy(if (longRange) Size(1280, 960) else Size(640, 480),
                        ResolutionStrategy.FALLBACK_RULE_CLOSEST_LOWER_THEN_HIGHER))
                    .build())
                .setBackpressureStrategy(ImageAnalysis.STRATEGY_KEEP_ONLY_LATEST)
                .setOutputImageFormat(ImageAnalysis.OUTPUT_IMAGE_FORMAT_RGBA_8888)
                .build()
            analysis.setAnalyzer(analysisExec) { img -> analyze(img) }
            val selector = if (front) CameraSelector.DEFAULT_FRONT_CAMERA else CameraSelector.DEFAULT_BACK_CAMERA
            runCatching {
                provider.unbindAll()
                camera = provider.bindToLifecycle(this, selector, preview, analysis).also { cam ->
                    readFocal(cam)
                    cam.cameraInfo.zoomState.observe(this) { z -> zoomRatio = z.zoomRatio; overlay.zoom = z.zoomRatio }
                }
            }.onFailure { status.text = "카메라를 열 수 없습니다: ${it.message}" }
        }, ContextCompat.getMainExecutor(this))
    }

    /** 거리 추정용: 렌즈 초점 거리와 센서 크기에서 "사진 긴 변 대비 초점 거리" 비율을 구합니다. */
    @androidx.annotation.OptIn(ExperimentalCamera2Interop::class)
    private fun readFocal(cam: Camera) {
        runCatching {
            val info = Camera2CameraInfo.from(cam.cameraInfo)
            val f = info.getCameraCharacteristic(CameraCharacteristics.LENS_INFO_AVAILABLE_FOCAL_LENGTHS)?.firstOrNull() ?: return
            val size = info.getCameraCharacteristic(CameraCharacteristics.SENSOR_INFO_PHYSICAL_SIZE) ?: return
            focalPxPerLongSide = f / max(size.width, size.height)
        }
    }

    private fun zoomBy(factor: Float) {
        val cam = camera ?: return
        val z = cam.cameraInfo.zoomState.value ?: return
        cam.cameraControl.setZoomRatio((z.zoomRatio * factor).coerceIn(z.minZoomRatio, z.maxZoomRatio))
    }

    /** 얼굴을 누르면 그 자리에 옵션이 나타납니다. */
    private fun showFaceMenu(face: FaceInfo, x: Float, y: Float) {
        anchor.translationX = x; anchor.translationY = y
        overlay.selectedId = face.id
        val menu = PopupMenu(this, anchor, Gravity.NO_GRAVITY)
        val m = menu.menu
        val model = face.model
        if (model != null) {
            m.add(0, 1, 0, "3D 모델 크게 보기")
            m.add(0, 7, 0, "3D 자세히 보기 (주름)")
            m.add(0, 2, 1, "OBJ로 저장")
            m.add(0, 3, 2, if (face.hidden) "모델 보이기" else "모델 숨기기")
            m.add(0, 4, 3, if (face.side == 2) "모델을 왼쪽으로" else "모델을 오른쪽으로")
        }
        m.add(0, 5, 4, "이 얼굴 다시 스캔")
        m.add(0, 6, 5, "얼굴 정보")
        menu.setOnMenuItemClickListener { item ->
            when (item.itemId) {
                1 -> { ModelHolder.mesh = model!!.mesh; startActivity(Intent(this, Face3DActivity::class.java).putExtra("live", true)) }
                2 -> ObjExport.save(this, model!!.mesh)
                7 -> { ModelHolder.mesh = model!!.mesh; startActivity(Intent(this, Face3DActivity::class.java).putExtra("live", true).putExtra("detail", true)) }
                3 -> faceCommands += { ts -> ts.find { it.id == face.id }?.let { it.hidden = !it.hidden } }
                4 -> faceCommands += { ts -> ts.find { it.id == face.id }?.let { it.sideOverride = if (face.side == 2) 1 else 2 } }
                5 -> faceCommands += { ts -> ts.find { it.id == face.id }?.let { it.model = null; it.sum = null; it.frames = 0; it.start = SystemClock.uptimeMillis() } }
                6 -> showFaceInfo(face)
            }
            true
        }
        menu.setOnDismissListener { overlay.selectedId = -1 }
        menu.show()
    }

    private fun showFaceInfo(face: FaceInfo) {
        fun dir(v: Float, pos: String, neg: String) = if (kotlin.math.abs(v) < 5) "정면" else "$pos ${kotlin.math.abs(v).toInt()}°".let { if (v > 0) it else "$neg ${kotlin.math.abs(v).toInt()}°" }
        val lines = listOf(
            "번호: #${face.id} (화면에서 붙인 번호이며, 누구인지는 알 수 없습니다)",
            "상태: " + if (face.model != null) "3D 스캔 완료" else "스캔 중 ${(face.progress * 100).toInt()}%",
            "추정 거리: " + (face.distanceM?.let { "약 %.1f m".format(it) } ?: "알 수 없음"),
            "좌우 방향: " + dir(face.yaw, "화면 오른쪽", "화면 왼쪽"),
            "위아래 방향: " + dir(face.pitch, "위", "아래"),
            "인식 방식: " + if (face.far) "원거리 확대 추적" else "일반",
        )
        AlertDialog.Builder(this).setTitle("얼굴 #${face.id}").setMessage(lines.joinToString("\n") + "\n\n거리는 평균 눈 사이 거리로 계산한 대략적인 값입니다.")
            .setPositiveButton("닫기", null).show()
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
                tracks.clear(); objTracks.clear()
            }

            val frame = if (productMode) analyzeProducts(bmp, ts) else analyzeFaces(bmp, ts)
            bmp.recycle()
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
        val lm = landmarker ?: FaceMesh.createFast(this).also { landmarker = it }
        val w = bmp.width.toFloat(); val h = bmp.height.toFloat()
        val now = ts
        while (true) { val cmd = faceCommands.poll() ?: break; cmd(tracks) }

        // 잘라 낸 영역의 얼굴 점을 전체 사진 기준으로 바꿉니다 (cx, cy, cw, ch: 잘라 낸 영역 픽셀)
        fun toDet(f: List<com.google.mediapipe.tasks.components.containers.NormalizedLandmark>, cx: Float, cy: Float, cw: Float, ch: Float, src: Int): FaceDet {
            val pts = FloatArray(f.size * 3)
            var minX = Float.MAX_VALUE; var minY = Float.MAX_VALUE; var maxX = -Float.MAX_VALUE; var maxY = -Float.MAX_VALUE
            f.forEachIndexed { i, p ->
                val x = (cx + p.x() * cw) / w; val y = (cy + p.y() * ch) / h
                pts[i * 3] = x; pts[i * 3 + 1] = y; pts[i * 3 + 2] = p.z() * cw / w
                minX = min(minX, x); maxX = max(maxX, x); minY = min(minY, y); maxY = max(maxY, y)
            }
            return FaceDet(RectF(minX * w, minY * h, maxX * w, maxY * h), pts, src)
        }

        // 1) 화면 전체
        val all = mutableListOf<FaceDet>()
        lm.detectForVideo(BitmapImageBuilder(bmp).build(), ts).faceLandmarks().forEach { all += toDet(it, 0f, 0f, w, h, 0) }

        if (longRange) {
            val roi = roiLandmarker ?: FaceMesh.createRoi(this).also { roiLandmarker = it }
            // 2) 화면을 겹치는 정사각형 조각으로 나눠, 프레임마다 큰 조각 1개 + 작은 조각 1개씩 확대해서 먼 얼굴을 찾습니다
            //    (얼굴이 조각의 1/4 이상이어야 찾을 수 있어서, 작은 조각일수록 더 먼 얼굴을 찾습니다)
            val ga = tiles(w, h, 0.45f); val gb = tiles(w, h, 0.25f)
            val ta = ga[tileA % ga.size]; tileA = (tileA + 1) % ga.size
            val tb = gb[tileB % gb.size]; tileB = (tileB + 1) % gb.size
            for (t in listOf(ta, tb)) cropDetect(roi, bmp, t.left, t.top, t.width(), t.height())?.forEach { all += toDet(it, t.left, t.top, t.width(), t.height(), 1) }
            // 3) 이미 찾은 작은(먼) 얼굴은 그 주변만 잘라서 매 프레임 정밀 추적
            tracks.filter { it.rect.height() < h * 0.3f }.sortedBy { it.rect.height() }.take(4).forEach { t ->
                val side = max(t.rect.width(), t.rect.height()) * 2.4f
                val cx = (t.rect.centerX() - side / 2).coerceIn(0f, max(0f, w - side))
                val cy = (t.rect.centerY() - side / 2).coerceIn(0f, max(0f, h - side))
                val cw = min(side, w); val ch = min(side, h)
                cropDetect(roi, bmp, cx, cy, cw, ch)?.minByOrNull { lmk ->
                    val mx = lmk.sumOf { it.x().toDouble() } / lmk.size - 0.5; val my = lmk.sumOf { it.y().toDouble() } / lmk.size - 0.5
                    mx * mx + my * my
                }?.let { all += toDet(it, cx, cy, cw, ch, 2) }
            }
        }
        // 겹치는 결과는 더 확대해서 본 것(정밀한 것)만 남깁니다
        all.sortByDescending { it.src }
        val dets = mutableListOf<Pair<RectF, FloatArray>>()
        val srcOf = mutableListOf<Int>()
        for (d in all) if (dets.none { iou(it.first, d.rect) > 0.35f }) { dets += d.rect to d.pts; srcOf += d.src }

        // 기존 얼굴과 짝짓기 (겹치는 정도가 큰 순서대로)
        val pairs = mutableListOf<Triple<Float, Int, FaceTrack>>()
        dets.forEachIndexed { i, (r, _) -> tracks.forEach { t -> val v = iou(r, t.rect); if (v > 0.2f) pairs += Triple(v, i, t) } }
        pairs.sortByDescending { it.first }
        val usedDet = HashSet<Int>(); val usedTrack = HashSet<FaceTrack>()
        for ((_, i, t) in pairs) {
            if (i in usedDet || t in usedTrack) continue
            usedDet += i; usedTrack += t
            t.rect = dets[i].first; t.pts = dets[i].second; t.lastSeen = now; t.frames++; t.far = srcOf[i] > 0
        }
        dets.forEachIndexed { i, (r, pts) ->
            if (i !in usedDet) tracks += FaceTrack(nextId++, r, now).also { it.pts = pts; it.frames = 1; it.far = srcOf[i] > 0; usedTrack += it }
        }
        tracks.removeAll { now - it.lastSeen > FaceTrack.LOST_MS }

        // 스캔: 1.5초 동안 얼굴 모양을 평균 내고, 끝나면 텍스처와 함께 고정
        for (t in tracks) {
            if (t.model != null || t.lastSeen != now) continue
            val fb = MeshData.frontal(MeshData.imageBase(t.pts, w, h)) // 점 468개만: 가벼움
            val s = t.sum ?: FloatArray(fb.size).also { t.sum = it }
            for (k in s.indices) s[k] += fb[k]
            if (t.progress(now) >= 1f) t.model = finishModel(t, bmp, Subdivision.get(this))
        }

        val infos = tracks.filter { now - it.lastSeen < 300 }.map { t ->
            val dots = if (t.model == null) FloatArray(t.pts.size / 3 / 3 * 2).also { d ->
                var j = 0
                for (i in 0 until t.pts.size / 3 step 3) { if (j + 1 < d.size) { d[j++] = t.pts[i * 3] * w; d[j++] = t.pts[i * 3 + 1] * h } }
            } else FloatArray(0)
            val angles = FaceMesh.headAngles(t.pts, w, h)
            FaceInfo(t.id, RectF(t.rect), t.progress(now), t.model, dots, t.hidden,
                if (t.sideOverride != 0) t.sideOverride else (t.model?.side ?: 2), distance(t.pts, w, h), angles.first, angles.second, t.far)
        }
        val scanning = infos.count { it.model == null }
        val done = infos.count { it.model != null }
        setStatus(when {
            infos.isEmpty() -> "얼굴을 카메라에 비춰 주세요"
            scanning > 0 -> "얼굴 ${infos.size}개 인식 · ${scanning}개 스캔 중 · ${done}개 완료"
            else -> "얼굴 ${infos.size}개 · 3D 모델 고정됨"
        })
        return LiveFrame(bmp.width, bmp.height, infos, emptyList())
    }

    /** 눈꼬리 사이 거리(평균 약 9cm)와 초점 거리로 카메라까지의 거리를 대략 계산합니다. */
    private fun distance(p: FloatArray, w: Float, h: Float): Float? {
        if (focalPxPerLongSide <= 0f || p.size < 264 * 3) return null
        val dx = (p[263 * 3] - p[33 * 3]) * w; val dy = (p[263 * 3 + 1] - p[33 * 3 + 1]) * h; val dz = (p[263 * 3 + 2] - p[33 * 3 + 2]) * w
        val eyePx = kotlin.math.sqrt(dx * dx + dy * dy + dz * dz)
        if (eyePx < 1f) return null
        val focalPx = focalPxPerLongSide * max(w, h) * zoomRatio
        return 0.09f * focalPx / eyePx
    }

    /** 사진 일부를 잘라 얼굴 점을 찾습니다. */
    private fun cropDetect(roi: FaceLandmarker, bmp: Bitmap, x: Float, y: Float, cw: Float, ch: Float): List<List<com.google.mediapipe.tasks.components.containers.NormalizedLandmark>>? {
        val l = x.toInt().coerceIn(0, bmp.width - 1); val t = y.toInt().coerceIn(0, bmp.height - 1)
        val rw = cw.toInt().coerceIn(1, bmp.width - l); val rh = ch.toInt().coerceIn(1, bmp.height - t)
        if (rw < 32 || rh < 32) return null
        val crop = Bitmap.createBitmap(bmp, l, t, rw, rh)
        return try { roi.detect(BitmapImageBuilder(crop).build()).faceLandmarks() } finally { if (crop !== bmp) crop.recycle() }
    }

    private fun finishModel(t: FaceTrack, bmp: Bitmap, sub: Subdivision): FaceModel {
        val w = bmp.width.toFloat(); val h = bmp.height.toFloat()
        // 얼굴 부분만 512px 텍스처로 잘라 둡니다
        val side = max(t.rect.width(), t.rect.height()) * 1.2f
        val cx = t.rect.centerX(); val cy = t.rect.centerY()
        val crop = Rect((cx - side / 2).toInt(), (cy - side / 2).toInt(), (cx + side / 2).toInt(), (cy + side / 2).toInt())
        val tex = Bitmap.createBitmap(512, 512, Bitmap.Config.ARGB_8888)
        Canvas(tex).apply { drawColor(Color.rgb(40, 34, 32)); drawBitmap(bmp, crop, Rect(0, 0, 512, 512), Paint(Paint.FILTER_BITMAP_FLAG)) }
        val avg = t.sum!!.copyOf().also { a -> for (k in a.indices) a[k] /= t.frames.coerceAtLeast(1) }
        val mesh = MeshData.fromBase(sub, avg, MeshData.imageBase(t.pts, w, h), RectF(crop), tex)
        val sideChoice = if (w - t.rect.right >= t.rect.left) 2 else 1 // 공간이 넓은 쪽에 고정
        return FaceModel(t.id, mesh, sideChoice)
    }

    // ----- 제품 -----

    private fun setStatus(t: String) {
        if (t == lastStatus) return
        lastStatus = t
        runOnUiThread { status.text = t }
    }

    private fun analyzeProducts(bmp: Bitmap, ts: Long): LiveFrame {
        val det = detector ?: createDetector(RunningMode.VIDEO).also { detector = it }
        val res = det.detectForVideo(BitmapImageBuilder(bmp).build(), ts)
        val raw = res.detections().mapNotNull { d ->
            val c = d.categories().firstOrNull() ?: return@mapNotNull null
            if (c.categoryName() == "person") return@mapNotNull null // 사람은 제품이 아니므로 제외
            Triple(RectF(d.boundingBox()), c.categoryName(), c.score())
        }.toMutableList()
        if (longRange) {
            // 원거리: 겹치는 조각 중 하나를 확대해서 작은(먼) 물건도 찾습니다
            val w = bmp.width.toFloat(); val h = bmp.height.toFloat()
            val ga = tiles(w, h, 0.5f)
            val tr = ga[tileA % ga.size]; tileA = (tileA + 1) % ga.size
            val tx = tr.left; val ty = tr.top; val tw = tr.width(); val th = tr.height()
            val rd = roiDetector ?: createDetector(RunningMode.IMAGE).also { roiDetector = it }
            val crop = Bitmap.createBitmap(bmp, tx.toInt(), ty.toInt(), tw.toInt(), th.toInt())
            rd.detect(BitmapImageBuilder(crop).build()).detections().forEach { d ->
                val c = d.categories().firstOrNull() ?: return@forEach
                if (c.categoryName() == "person") return@forEach
                val b = d.boundingBox()
                raw += Triple(RectF(b.left + tx, b.top + ty, b.right + tx, b.bottom + ty), c.categoryName(), c.score())
            }
            crop.recycle()
        }
        val dets = mutableListOf<Triple<RectF, String, Float>>()
        for (d in raw.sortedByDescending { it.third }) if (dets.none { iou(it.first, d.first) > 0.45f }) dets += d
        val now = ts

        // 물건 추적: 같은 물건이면 이전 검색 결과를 그대로 씁니다
        val pairs = mutableListOf<Triple<Float, Int, ObjTrack>>()
        dets.forEachIndexed { i, (r, _, _) -> objTracks.forEach { t -> val v = iou(r, t.rect); if (v > 0.25f) pairs += Triple(v, i, t) } }
        pairs.sortByDescending { it.first }
        val usedDet = HashSet<Int>(); val usedTrack = HashSet<ObjTrack>()
        for ((_, i, t) in pairs) {
            if (i in usedDet || t in usedTrack) continue
            usedDet += i; usedTrack += t
            val (r, label, score) = dets[i]
            t.rect = r; t.label = label; t.score = score; t.lastSeen = now; t.frames++
        }
        dets.forEachIndexed { i, (r, label, score) -> if (i !in usedDet) objTracks += ObjTrack(nextObjId++, r, label, score, now) }
        objTracks.removeAll { now - it.lastSeen > ObjTrack.LOST_MS }

        val visible = objTracks.filter { now - it.lastSeen < 400 }
        val main = visible.maxByOrNull { it.score * it.rect.width() * it.rect.height() }
        val key = Store.apiKey(this)

        if (key.isNotEmpty()) {
            // 실시간 검색: 물건이 0.3초(3프레임) 보이면 바로 검색 (동시에 최대 3개)
            val auto = Store.autoProduct(this)
            val manual = manualAsk.also { manualAsk = false }
            if (manual && main != null) { main.asked = false; main.info = null }
            val candidates = if (auto || manual) visible.filter { !it.asked && it.frames >= 3 }.sortedByDescending { it === main } else emptyList()
            for (t in candidates) {
                if (inFlight.get() >= 3) break
                t.asked = true; t.searching = true
                inFlight.incrementAndGet()
                val crop = cropFor(bmp, t.rect)
                val hint = LocalProducts.korean(t.label)
                aiExec.execute {
                    val info = runCatching { ProductAI.describe(key, crop, hint) { partial -> t.info = partial; refreshPanel() } }
                        .getOrElse { ProductInfo("검색 실패", "", "", it.message ?: "알 수 없는 오류", emptyList(), "오류") }
                    crop.recycle()
                    t.info = info; t.searching = false
                    inFlight.decrementAndGet()
                    refreshPanel()
                }
            }
            if (manual && main == null && inFlight.get() < 3) {
                // 인식된 물건이 없으면 화면 가운데를 검색
                val crop = cropFor(bmp, null)
                inFlight.incrementAndGet()
                overlay.product = ProductInfo("검색 중", "", "", "", emptyList(), "Claude 검색 중...")
                aiExec.execute {
                    val info = runCatching { ProductAI.describe(key, crop, null) { overlay.product = it } }
                        .getOrElse { ProductInfo("검색 실패", "", "", it.message ?: "알 수 없는 오류", emptyList(), "오류") }
                    crop.recycle(); inFlight.decrementAndGet()
                    overlay.product = info
                }
            }
        }
        panelTrack = main
        refreshPanel()

        setStatus(when {
            main == null -> "제품을 화면에 비춰 주세요"
            main.searching -> "${LocalProducts.korean(main.label)} 인식 · 실시간 검색 중..."
            else -> "물건 ${visible.size}개 인식 · 패널을 누르면 웹 검색"
        })
        val objs = visible.map { ObjInfo(it.id, RectF(it.rect), it.label, it.score, it.info, it.searching) }
        return LiveFrame(bmp.width, bmp.height, emptyList(), objs)
    }

    @Volatile private var panelTrack: ObjTrack? = null

    /** 왼쪽 위 패널: 주 대상 물건의 검색 결과(없으면 기기 내 기본 설명). */
    private fun refreshPanel() {
        val t = panelTrack ?: return
        val info = t.info
        overlay.product = when {
            info != null -> if (t.searching && info.source.isEmpty()) info.copy(source = "Claude 검색 중...") else info
            Store.apiKey(this).isEmpty() -> LocalProducts.info(t.label)?.copy(features = listOf("API 키를 넣으면 실제 제품명과 자세한 설명을 실시간으로 볼 수 있습니다"))
            t.searching -> (LocalProducts.info(t.label) ?: ProductInfo(t.label, "", "", "", emptyList(), "")).copy(source = "Claude 검색 중...")
            else -> LocalProducts.info(t.label)
        }
    }

    /** GPU 로 먼저 시도하고, 안 되면 CPU 로. */
    private fun createDetector(mode: RunningMode): ObjectDetector {
        fun make(d: Delegate) = ObjectDetector.createFromOptions(this, ObjectDetector.ObjectDetectorOptions.builder()
            .setBaseOptions(BaseOptions.builder().setModelAssetPath("efficientdet_lite0.tflite").setDelegate(d).build())
            .setRunningMode(mode)
            .setMaxResults(5)
            .setScoreThreshold(0.4f)
            .build())
        return runCatching { make(Delegate.GPU) }.getOrElse { make(Delegate.CPU) }
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
        analysisExec.execute {
            landmarker?.close(); landmarker = null; roiLandmarker?.close(); roiLandmarker = null
            detector?.close(); detector = null; roiDetector?.close(); roiDetector = null
        }
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
class OverlayView(
    ctx: Context,
    private val onPanelTap: (ProductInfo) -> Unit,
    private val onFaceTap: (FaceInfo, Float, Float) -> Unit,
    private val onZoom: (Float) -> Unit,
) : View(ctx) {
    @Volatile var selectedId = -1
        set(v) { field = v; postInvalidate() }
    @Volatile var zoom = 1f
        set(v) { field = v; postInvalidate() }
    private val scaleDetector = ScaleGestureDetector(ctx, object : ScaleGestureDetector.SimpleOnScaleGestureListener() {
        override fun onScale(d: ScaleGestureDetector): Boolean { onZoom(d.scaleFactor); return true }
    })
    private val tapDetector = GestureDetector(ctx, object : GestureDetector.SimpleOnGestureListener() {
        override fun onDown(e: MotionEvent) = true
        override fun onSingleTapUp(e: MotionEvent): Boolean { handleTap(e.x, e.y); return true }
        override fun onDoubleTap(e: MotionEvent): Boolean { onZoom(1f / zoom.coerceAtLeast(0.01f)); return true }
    })
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

    private var panelRect: RectF? = null

    fun post(f: LiveFrame) { latest.set(f); postInvalidate() }

    override fun onTouchEvent(e: MotionEvent): Boolean {
        scaleDetector.onTouchEvent(e)
        if (!scaleDetector.isInProgress) tapDetector.onTouchEvent(e)
        return true
    }

    private fun handleTap(x: Float, y: Float) {
        val p = product
        if (p != null && panelRect?.contains(x, y) == true) { onPanelTap(p); return }
        val f = latest.get() ?: return
        val m = FillCenter(width, height, f.w, f.h)
        // 작은(먼) 얼굴도 누르기 쉽게 누르는 범위를 넓힙니다
        val pad = 24 * d
        val hit = f.faces.filter { face -> m.rect(face.rect).apply { inset(-pad, -pad) }.contains(x, y) }
            .minByOrNull { face -> val r = m.rect(face.rect); (r.centerX() - x) * (r.centerX() - x) + (r.centerY() - y) * (r.centerY() - y) }
        if (hit != null) onFaceTap(hit, x, y)
    }

    override fun onDraw(c: Canvas) {
        val f = latest.get()
        if (f != null) {
            val m = FillCenter(width, height, f.w, f.h)
            for (face in f.faces) drawFace(c, m, face)
            for (o in f.objects) drawObject(c, m, o)
        }
        val p = product
        if (p != null) drawPanel(c, p) else panelRect = null
        if (zoom > 1.05f) pill(c, "줌 %.1fx".format(zoom), width - 90 * d, topInset + 40 * d, Color.argb(180, 0, 0, 0))
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
        if (face.id == selectedId) {
            fill.color = Color.argb(60, 255, 255, 255)
            c.drawRoundRect(RectF(r).apply { inset(-6 * d, -6 * d) }, 10 * d, 10 * d, fill)
        }
        corners(c, r, if (face.id == selectedId) Color.WHITE else if (done) Color.rgb(80, 230, 120) else Color.rgb(0, 210, 255))
        if (!done) {
            fill.color = Color.argb(170, 0, 230, 200)
            for (i in 0 until face.dots.size / 2) c.drawCircle(m.x(face.dots[i * 2]), m.y(face.dots[i * 2 + 1]), 1.6f * d, fill)
        }
        val dist = face.distanceM?.let { if (it >= 10) " · ${it.toInt()}m" else " · %.1fm".format(it) } ?: ""
        val label = (if (done) "얼굴 #${face.id} · 3D 완료" else "얼굴 #${face.id} · 스캔 중 ${(face.progress * 100).toInt()}%") + dist + if (face.far) " · 원거리" else ""
        pill(c, label, r.left, r.top - 4 * d, if (done) Color.argb(200, 20, 110, 50) else Color.argb(200, 0, 80, 120),
            if (done) null else face.progress)
    }

    private fun drawObject(c: Canvas, m: FillCenter, o: ObjInfo) {
        val r = m.rect(o.rect)
        val known = o.info != null && o.info.source != "오류"
        box.color = if (known) Color.rgb(80, 230, 120) else Color.rgb(255, 196, 0)
        c.drawRoundRect(r, 10 * d, 10 * d, box)
        val name = if (known) o.info!!.name else LocalProducts.korean(o.label)
        val label = if (o.searching && !known) "$name · 검색 중..." else name
        pill(c, label, r.left, r.top - 4 * d, if (known) Color.argb(210, 20, 110, 50) else Color.argb(210, 140, 95, 0))
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
        val src = listOf(p.source, if (p.source.startsWith("Claude 분석") && !p.source.contains("중")) "눌러서 웹 검색" else "").filter { it.isNotBlank() }.joinToString(" · ")
        if (src.isNotBlank()) parts += layout(src, small)
        val gap = 6 * d
        val h = pad * 2 + parts.sumOf { it.height.toDouble() }.toFloat() + gap * (parts.size - 1)
        val left = 12 * d; val top = topInset + 12 * d
        fill.color = Color.argb(205, 15, 18, 26)
        val pr = RectF(left, top, left + w, top + h)
        panelRect = pr
        c.drawRoundRect(pr, 14 * d, 14 * d, fill)
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
    private val models = HashMap<Int, MeshGL>()
    private val modelSeen = HashMap<Int, Long>()
    private val boxes = HashMap<Int, RectF>()
    private var current: LiveFrame? = null
    private var vw = 1; private var vh = 1
    private var yaw = 0f
    private var lastTime = 0L
    private val proj = FloatArray(16); private val view = FloatArray(16)
    private val model = FloatArray(16); private val tmp = FloatArray(16); private val mvp = FloatArray(16)

    fun post(f: LiveFrame) { pending.set(f) }

    override fun onSurfaceCreated(g: GL10?, config: EGLConfig?) {
        models.clear(); modelSeen.clear(); boxes.clear()
        current = null
        GLES20.glClearColor(0f, 0f, 0f, 0f) // 투명: 아래의 카메라 미리보기가 보이도록
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

        GLES20.glEnable(GLES20.GL_DEPTH_TEST)
        for (face in f.faces) {
            val fm = face.model ?: continue
            val gl = models[fm.id] ?: continue
            val r = m.rect(face.rect)
            val size = r.height() * 1.35f
            if (face.hidden) continue
            val side = if (sideOverride == 0) face.side else sideOverride
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
