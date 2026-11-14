package com.selfcheck.app

import android.Manifest
import android.app.AlertDialog
import android.content.pm.PackageManager
import android.graphics.Bitmap
import android.graphics.Canvas
import android.graphics.Color
import android.graphics.Paint
import android.graphics.Rect
import android.net.Uri
import android.opengl.GLES20
import android.opengl.GLSurfaceView
import android.opengl.GLUtils
import android.os.Bundle
import android.os.SystemClock
import android.util.Size
import android.view.Gravity
import android.view.View
import android.view.ViewGroup.LayoutParams.MATCH_PARENT
import android.view.ViewGroup.LayoutParams.WRAP_CONTENT
import android.widget.Button
import android.widget.FrameLayout
import android.widget.ImageView
import android.widget.LinearLayout
import android.widget.SeekBar
import android.widget.TextView
import android.widget.Toast
import androidx.activity.ComponentActivity
import androidx.activity.result.PickVisualMediaRequest
import androidx.activity.result.contract.ActivityResultContracts
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
import com.google.mediapipe.tasks.vision.core.RunningMode
import com.google.mediapipe.tasks.vision.facelandmarker.FaceLandmarker
import org.opencv.core.MatOfFloat6
import org.opencv.core.Point
import org.opencv.imgproc.Subdiv2D
import java.nio.ByteBuffer
import java.nio.ByteOrder
import java.nio.FloatBuffer
import java.nio.ShortBuffer
import java.util.concurrent.Executors
import java.util.concurrent.atomic.AtomicReference
import javax.microedition.khronos.egl.EGLConfig
import javax.microedition.khronos.opengles.GL10
import kotlin.concurrent.thread
import kotlin.math.cos
import kotlin.math.max
import kotlin.math.min
import kotlin.math.sin
import kotlin.math.sqrt

/** 대상(사진/동영상 속 인물) 한 프레임: 사진 + 얼굴 점(사진 좌표) + 얼굴 좌표계. face 가 없으면 얼굴을 못 찾은 프레임. */
class TargetFrame(val bitmap: Bitmap, val base: FloatArray?, val frame: MeshData.Companion.FaceFrame?)

/** 내 얼굴 움직임: 기준 표정 대비 표정 변화(얼굴 좌표), 고개 회전, 위치 이동(얼굴 높이 단위). */
class DriverState(val delta: FloatArray, val rot: FloatArray, val tx: Float, val ty: Float)

/** 입 안쪽 테두리 (윗입술 안쪽 → 아랫입술 안쪽) */
private val INNER_LIP = intArrayOf(78, 191, 80, 81, 82, 13, 312, 311, 310, 415, 308, 324, 318, 402, 317, 14, 87, 178, 88, 95)

/**
 * 표정 따라하기: 고른 사진(또는 동영상) 속 인물이 카메라 앞의 내 표정과 고개 움직임을 따라 합니다.
 * 얼굴 점 468개로 사진을 늘이고 줄이는 방식(메시 워프)이며, 화면과 녹화 영상에 "AI 편집" 표시가 붙습니다.
 */
class ReenactActivity : ComponentActivity() {
    private lateinit var root: FrameLayout
    private lateinit var info: TextView
    private lateinit var thumb: ImageView
    private var source: Uri? = null
    private var isVideo = false
    private val renderer = WarpRenderer()
    private var glView: GLSurfaceView? = null
    private lateinit var previewView: PreviewView
    private val camExec = Executors.newSingleThreadExecutor()
    private val encExec = Executors.newSingleThreadExecutor()
    @Volatile private var running = false
    @Volatile private var recalibrate = false
    private var recBtn: Button? = null

    // 내 얼굴 (카메라 스레드 전용)
    private var myLm: FaceLandmarker? = null
    private var lastTs = 0L
    private var calib = 0
    private var neutralSum: FloatArray? = null
    private var neutral: FloatArray? = null
    private var neutralFrame: MeshData.Companion.FaceFrame? = null

    // 녹화
    private var encoder: VideoEncoder? = null
    private var recOut: MediaSave.VideoOut? = null
    private var recStart = 0L
    private val pending = java.util.concurrent.atomic.AtomicInteger(0)

    private val pick = registerForActivityResult(ActivityResultContracts.PickVisualMedia()) { uri -> if (uri != null) onPicked(uri) }
    private val askCamera = registerForActivityResult(ActivityResultContracts.RequestPermission()) { ok -> if (ok) startLive() else info.text = "카메라 권한이 필요합니다" }

    private fun dp(v: Int) = (v * resources.displayMetrics.density).toInt()

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        root = FrameLayout(this).apply { setBackgroundColor(Color.rgb(24, 24, 28)) }
        root.setOnApplyWindowInsetsListener { v, insets ->
            @Suppress("DEPRECATION")
            v.setPadding(0, insets.systemWindowInsetTop, 0, insets.systemWindowInsetBottom); insets
        }
        setContentView(root)
        showPicker()
        if (!getSharedPreferences("selfcheck", MODE_PRIVATE).getBoolean("reenact_ok", false)) {
            AlertDialog.Builder(this)
                .setTitle("표정 따라하기 사용 안내")
                .setMessage("본인 또는 사용에 동의한 사람의 사진·동영상만 쓰세요.\n\n만든 영상으로 다른 사람인 척하거나, 사람들을 속이거나, 남을 곤란하게 만드는 데 쓰면 안 됩니다. 화면과 녹화 영상에는 'AI 편집' 표시가 들어갑니다.")
                .setPositiveButton("확인했습니다") { _, _ -> getSharedPreferences("selfcheck", MODE_PRIVATE).edit().putBoolean("reenact_ok", true).apply() }
                .setNegativeButton("닫기") { _, _ -> finish() }
                .setCancelable(false)
                .show()
        }
    }

    // ---------- 1단계: 사진/동영상 고르기 ----------

    private fun showPicker() {
        root.removeAllViews()
        val col = LinearLayout(this).apply { orientation = LinearLayout.VERTICAL; setPadding(dp(16), dp(16), dp(16), dp(16)) }
        col.addView(TextView(this).apply { text = "표정 따라하기"; textSize = 20f; setTextColor(Color.WHITE) })
        info = TextView(this).apply {
            text = "얼굴이 정면으로 잘 보이는 사진이나 동영상을 고르고 '편집'을 누르면 카메라가 켜집니다. 내가 표정을 짓고 고개를 움직이면 사진 속 인물이 똑같이 따라 합니다."
            textSize = 13f; setTextColor(Color.LTGRAY); setPadding(0, dp(6), 0, dp(10))
        }
        col.addView(info)
        thumb = ImageView(this).apply { scaleType = ImageView.ScaleType.FIT_CENTER; setBackgroundColor(Color.rgb(40, 40, 46)) }
        col.addView(thumb, LinearLayout.LayoutParams(MATCH_PARENT, 0, 1f))
        val bar = LinearLayout(this).apply { orientation = LinearLayout.HORIZONTAL; setPadding(0, dp(8), 0, 0) }
        bar.addView(Button(this).apply {
            text = "사진/동영상 고르기"; setOnClickListener { pick.launch(PickVisualMediaRequest(ActivityResultContracts.PickVisualMedia.ImageAndVideo)) }
        }, LinearLayout.LayoutParams(0, WRAP_CONTENT, 1f))
        bar.addView(Button(this).apply {
            text = "편집"
            setOnClickListener {
                if (source == null) { Toast.makeText(this@ReenactActivity, "먼저 사진이나 동영상을 고르세요", Toast.LENGTH_SHORT).show(); return@setOnClickListener }
                if (ContextCompat.checkSelfPermission(this@ReenactActivity, Manifest.permission.CAMERA) == PackageManager.PERMISSION_GRANTED) startLive()
                else askCamera.launch(Manifest.permission.CAMERA)
            }
        }, LinearLayout.LayoutParams(0, WRAP_CONTENT, 1f))
        col.addView(bar)
        root.addView(col, FrameLayout.LayoutParams(MATCH_PARENT, MATCH_PARENT))
    }

    private fun onPicked(uri: Uri) {
        source = uri
        isVideo = contentResolver.getType(uri)?.startsWith("video") == true
        thread {
            val b = runCatching { if (isVideo) VideoSource(this, uri).use { it.frames(0, 1, 720).firstOrNull() } else FaceMatcher.decodeUri(contentResolver, uri) }.getOrNull()
            runOnUiThread {
                if (b == null) { info.text = "파일을 열 수 없습니다"; return@runOnUiThread }
                thumb.setImageBitmap(b)
                info.text = (if (isVideo) "동영상" else "사진") + "을 골랐습니다. '편집'을 누르세요."
            }
        }
    }

    // ---------- 2단계: 카메라 켜고 따라하기 ----------

    private fun startLive() {
        val uri = source ?: return
        running = true
        root.removeAllViews()
        val gl = GLSurfaceView(this).apply {
            setEGLContextClientVersion(2)
            setEGLConfigChooser(MsaaConfigChooser(2))
            setRenderer(renderer)
            renderMode = GLSurfaceView.RENDERMODE_CONTINUOUSLY
        }
        glView = gl
        root.addView(gl, FrameLayout.LayoutParams(MATCH_PARENT, MATCH_PARENT))
        // 내 카메라는 오른쪽 아래 작은 창
        previewView = PreviewView(this).apply { implementationMode = PreviewView.ImplementationMode.COMPATIBLE; scaleType = PreviewView.ScaleType.FILL_CENTER }
        root.addView(previewView, FrameLayout.LayoutParams(dp(110), dp(146), Gravity.END or Gravity.BOTTOM).apply { setMargins(0, 0, dp(12), dp(150)) })
        // AI 편집 표시 (항상)
        root.addView(TextView(this).apply {
            text = "AI 편집"; setTextColor(Color.WHITE); textSize = 13f; setPadding(dp(8), dp(4), dp(8), dp(4))
            setBackgroundColor(Color.argb(150, 0, 0, 0))
        }, FrameLayout.LayoutParams(WRAP_CONTENT, WRAP_CONTENT, Gravity.TOP or Gravity.END).apply { setMargins(0, dp(12), dp(12), 0) })

        val bottom = LinearLayout(this).apply { orientation = LinearLayout.VERTICAL; setPadding(dp(8), dp(4), dp(8), dp(8)); setBackgroundColor(Color.argb(120, 0, 0, 0)) }
        info = TextView(this).apply { setTextColor(Color.WHITE); textSize = 13f; gravity = Gravity.CENTER; text = "준비 중..." }
        bottom.addView(info)
        val row = LinearLayout(this).apply { orientation = LinearLayout.HORIZONTAL; gravity = Gravity.CENTER_VERTICAL }
        row.addView(TextView(this).apply { text = "표정 강도"; setTextColor(Color.WHITE); textSize = 12f; setPadding(dp(4), 0, dp(6), 0) })
        row.addView(SeekBar(this).apply {
            max = 200; progress = 100
            setOnSeekBarChangeListener(object : SeekBar.OnSeekBarChangeListener {
                override fun onProgressChanged(sb: SeekBar, p: Int, u: Boolean) { renderer.gain = p / 100f }
                override fun onStartTrackingTouch(sb: SeekBar) {}
                override fun onStopTrackingTouch(sb: SeekBar) {}
            })
        }, LinearLayout.LayoutParams(0, WRAP_CONTENT, 1f))
        bottom.addView(row)
        val bar = LinearLayout(this).apply { orientation = LinearLayout.HORIZONTAL }
        fun btn(t: String, f: (Button) -> Unit) = Button(this).apply { text = t; textSize = 12f; setOnClickListener { f(this) } }
            .also { bar.addView(it, LinearLayout.LayoutParams(0, WRAP_CONTENT, 1f)) }
        btn("기준 표정 다시") { recalibrate = true }
        recBtn = btn("녹화") { toggleRecord() }
        btn("닫기") { stopLive(); showPicker() }
        bottom.addView(bar)
        root.addView(bottom, FrameLayout.LayoutParams(MATCH_PARENT, WRAP_CONTENT, Gravity.BOTTOM))

        startTarget(uri)
        startCamera()
    }

    /** 대상 사진/동영상을 읽어 얼굴 점을 찾고 화면에 넘깁니다 (동영상은 반복 재생). */
    private fun startTarget(uri: Uri) {
        thread(name = "target") {
            val lm = FaceMesh.create(this, RunningMode.IMAGE, 1, false)
            fun frameOf(b: Bitmap): TargetFrame {
                val f = lm.detect(BitmapImageBuilder(b).build()).faceLandmarks().firstOrNull()
                    ?: return TargetFrame(b, null, null)
                val pts = FloatArray(f.size * 3)
                f.forEachIndexed { i, p -> pts[i * 3] = p.x(); pts[i * 3 + 1] = p.y(); pts[i * 3 + 2] = p.z() }
                val base = MeshData.imageBase(pts, b.width.toFloat(), b.height.toFloat())
                return TargetFrame(b, base, MeshData.faceFrame(base))
            }
            try {
                if (!isVideo) {
                    val b = FaceMatcher.decodeUri(contentResolver, uri, 1600)
                    val t = frameOf(b)
                    runOnUiThread { if (t.base == null) info.text = "사진에서 얼굴을 찾지 못했습니다. 얼굴이 잘 보이는 사진을 써 보세요." }
                    renderer.postTarget(t, keep = true)
                } else VideoSource(this, uri).use { src ->
                    val frameMs = (1000f / src.fps).toLong()
                    while (running) {
                        var i = 0
                        while (running && i < src.count) {
                            val chunk = src.frames(i, 8, 720)
                            if (chunk.isEmpty()) break
                            for (b in chunk) {
                                val t0 = SystemClock.uptimeMillis()
                                if (!running) { b.recycle(); continue }
                                renderer.postTarget(frameOf(b), keep = false)
                                val wait = frameMs - (SystemClock.uptimeMillis() - t0)
                                if (wait > 0) Thread.sleep(wait)
                            }
                            i += chunk.size
                        }
                    }
                }
            } catch (e: Exception) {
                runOnUiThread { info.text = "대상 파일 오류: ${e.message}" }
            } finally {
                lm.close()
            }
        }
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
                    .setResolutionStrategy(ResolutionStrategy(Size(640, 480), ResolutionStrategy.FALLBACK_RULE_CLOSEST_LOWER_THEN_HIGHER)).build())
                .setBackpressureStrategy(ImageAnalysis.STRATEGY_KEEP_ONLY_LATEST)
                .setOutputImageFormat(ImageAnalysis.OUTPUT_IMAGE_FORMAT_RGBA_8888)
                .build()
            analysis.setAnalyzer(camExec) { img -> analyzeMe(img) }
            runCatching {
                provider.unbindAll()
                provider.bindToLifecycle(this, CameraSelector.DEFAULT_FRONT_CAMERA, preview, analysis)
            }.onFailure { info.text = "카메라를 열 수 없습니다: ${it.message}" }
        }, ContextCompat.getMainExecutor(this))
    }

    /** 내 얼굴: 기준 표정(처음 15프레임 평균)과 비교해 표정 변화·고개 회전·위치 이동을 계산 */
    private fun analyzeMe(img: ImageProxy) {
        try {
            if (!running) return
            val raw = img.toBitmap()
            val m = android.graphics.Matrix().apply { postRotate(img.imageInfo.rotationDegrees.toFloat()); postScale(-1f, 1f) } // 거울처럼
            val bmp = Bitmap.createBitmap(raw, 0, 0, raw.width, raw.height, m, true)
            if (bmp !== raw) raw.recycle()
            val lm = myLm ?: FaceMesh.createFast(this).also { myLm = it }
            val ts = max(SystemClock.uptimeMillis(), lastTs + 1).also { lastTs = it }
            val f = lm.detectForVideo(BitmapImageBuilder(bmp).build(), ts).faceLandmarks().firstOrNull()
            val w = bmp.width.toFloat(); val h = bmp.height.toFloat()
            bmp.recycle()
            if (f == null) { setInfo("카메라에 얼굴이 보이지 않습니다"); return }
            val pts = FloatArray(f.size * 3)
            f.forEachIndexed { i, p -> pts[i * 3] = p.x(); pts[i * 3 + 1] = p.y(); pts[i * 3 + 2] = p.z() }
            val base = MeshData.imageBase(pts, w, h)
            val fr = MeshData.faceFrame(base)
            val front = MeshData.frontal(base, fr)

            if (recalibrate) { recalibrate = false; calib = 0; neutral = null; neutralSum = null }
            val n = neutral
            if (n == null) {
                val sum = neutralSum ?: FloatArray(front.size).also { neutralSum = it }
                for (k in sum.indices) sum[k] += front[k]
                calib++
                setInfo("정면을 보고 무표정으로 잠시 있어 주세요 (기준 표정 잡는 중 ${calib * 100 / 15}%)")
                if (calib >= 15) {
                    neutral = FloatArray(sum.size) { sum[it] / calib }
                    neutralFrame = fr
                }
                return
            }
            val nf = neutralFrame!!
            val delta = FloatArray(front.size) { front[it] - n[it] }
            // 고개 회전: 기준 → 지금 (R = F_now · F_neutralᵀ)
            val rot = FloatArray(9)
            val now = arrayOf(fr.ex, fr.ey, fr.ez); val ref = arrayOf(nf.ex, nf.ey, nf.ez)
            for (r in 0..2) for (c in 0..2) {
                var s = 0f
                for (k in 0..2) s += now[k][r] * ref[k][c]
                rot[r * 3 + c] = s
            }
            val tx = ((fr.c[0] - nf.c[0]) / nf.faceH).coerceIn(-0.3f, 0.3f)
            val ty = ((fr.c[1] - nf.c[1]) / nf.faceH).coerceIn(-0.3f, 0.3f)
            renderer.driver.set(DriverState(delta, rot, tx, ty))
            setInfo(if (encoder != null) "녹화 중 · 표정과 고개 움직임을 따라 합니다" else "표정과 고개 움직임을 따라 합니다")
        } catch (e: Exception) {
            setInfo("오류: ${e.message}")
        } finally {
            img.close()
        }
    }

    private var lastInfo = ""
    private fun setInfo(t: String) { if (t != lastInfo) { lastInfo = t; runOnUiThread { info.text = t } } }

    // ---------- 녹화 ----------

    private fun toggleRecord() {
        if (encoder == null && recOut == null) {
            val gv = glView ?: return
            val (w, h) = VideoEncoder.fitSize(gv.width, gv.height, 960)
            val out = MediaSave.newVideo(this, "ai_edit_${System.currentTimeMillis()}.mp4")
            recOut = out
            encExec.execute { runCatching { encoder = VideoEncoder(out.pfd.fileDescriptor, w, h, 20) }.onFailure { e -> runOnUiThread { info.text = "녹화를 시작할 수 없습니다: ${e.message}" } } }
            recStart = SystemClock.uptimeMillis()
            renderer.onCapture = { bmp -> captureFrame(bmp, w, h) }
            recBtn?.text = "녹화 중지"
        } else {
            renderer.onCapture = null
            val out = recOut
            encExec.execute {
                encoder?.finish(); encoder = null
                out?.done()
                runOnUiThread { Toast.makeText(this, "${out?.label} 에 저장했습니다", Toast.LENGTH_LONG).show() }
            }
            recOut = null
            recBtn?.text = "녹화"
        }
    }

    /** 화면 한 장 → 크기 맞추고 "AI 편집" 표시를 넣어 인코더로 */
    private fun captureFrame(src: Bitmap, w: Int, h: Int) {
        if (pending.get() > 3) { src.recycle(); return } // 밀리면 버림
        pending.incrementAndGet()
        val pts = (SystemClock.uptimeMillis() - recStart) * 1000
        encExec.execute {
            try {
                val frame = Bitmap.createScaledBitmap(src, w, h, true)
                if (frame !== src) src.recycle()
                val c = Canvas(frame)
                val p = Paint(Paint.ANTI_ALIAS_FLAG).apply { textSize = h / 28f; color = Color.WHITE; setShadowLayer(4f, 0f, 0f, Color.BLACK) }
                c.drawText("AI 편집", w - p.measureText("AI 편집") - h / 40f, h / 20f, p)
                encoder?.addFrame(frame, pts)
                frame.recycle()
            } finally {
                pending.decrementAndGet()
            }
        }
    }

    private fun stopLive() {
        running = false
        if (encoder != null || recOut != null) toggleRecord()
        runCatching { ProcessCameraProvider.getInstance(this).get().unbindAll() }
        camExec.execute { myLm?.close(); myLm = null; neutral = null; neutralSum = null; calib = 0 }
        glView?.onPause(); glView = null
    }

    override fun onPause() { super.onPause(); glView?.onPause() }
    override fun onResume() { super.onResume(); glView?.onResume() }
    override fun onDestroy() {
        super.onDestroy()
        stopLive()
        camExec.shutdown(); encExec.shutdown()
    }
}

/**
 * 대상 사진을 삼각형 메시로 나누고(얼굴 점 + 얼굴 둘레 고리 + 사진 테두리),
 * 내 표정 변화와 고개 회전을 대상 얼굴 좌표계에 적용해 얼굴 점을 옮겨 그립니다. 테두리와 고리는 고정되어 배경은 그대로입니다.
 */
class WarpRenderer : GLSurfaceView.Renderer {
    val driver = AtomicReference<DriverState?>()
    @Volatile var gain = 1f
    @Volatile var onCapture: ((Bitmap) -> Unit)? = null
    private val pendingTarget = AtomicReference<Pair<TargetFrame, Boolean>?>()
    private var cur: TargetFrame? = null
    private var curKeep = false

    // 메시 (첫 얼굴 프레임에서 한 번 만듦)
    private var tris: ShortBuffer? = null
    private var triCount = 0
    private var fixedPts: FloatArray? = null // 고리 + 테두리 점 (사진 좌표)
    private var identity: FloatArray? = null // 대상 얼굴의 평소 모양 (얼굴 좌표)
    private var identitySum: FloatArray? = null
    private var identityN = 0
    private var meshW = 0; private var meshH = 0

    private var prog = 0; private var tex = 0
    private var vw = 1; private var vh = 1
    private var posBuf: FloatBuffer? = null; private var uvBuf: FloatBuffer? = null
    private val mouthBuf = ByteBuffer.allocateDirect((INNER_LIP.size + 2) * 3 * 4).order(ByteOrder.nativeOrder()).asFloatBuffer()

    fun postTarget(t: TargetFrame, keep: Boolean) {
        pendingTarget.getAndSet(t to keep)?.let { (old, k) -> if (!k) old.bitmap.recycle() }
    }

    override fun onSurfaceCreated(g: GL10?, c: EGLConfig?) {
        fun sh(t: Int, src: String) = GLES20.glCreateShader(t).also { GLES20.glShaderSource(it, src); GLES20.glCompileShader(it) }
        prog = GLES20.glCreateProgram()
        GLES20.glAttachShader(prog, sh(GLES20.GL_VERTEX_SHADER,
            "attribute vec3 aPos; attribute vec2 aUV; varying vec2 vUV; void main(){ vUV=aUV; gl_Position=vec4(aPos,1.0); }"))
        GLES20.glAttachShader(prog, sh(GLES20.GL_FRAGMENT_SHADER,
            "precision mediump float; uniform sampler2D uTex; uniform int uFill; uniform vec4 uColor; varying vec2 vUV;" +
                "void main(){ gl_FragColor = uFill == 1 ? uColor : texture2D(uTex, vUV); }"))
        GLES20.glLinkProgram(prog)
        val ids = IntArray(1); GLES20.glGenTextures(1, ids, 0); tex = ids[0]
        GLES20.glBindTexture(GLES20.GL_TEXTURE_2D, tex)
        GLES20.glTexParameteri(GLES20.GL_TEXTURE_2D, GLES20.GL_TEXTURE_MIN_FILTER, GLES20.GL_LINEAR)
        GLES20.glTexParameteri(GLES20.GL_TEXTURE_2D, GLES20.GL_TEXTURE_MAG_FILTER, GLES20.GL_LINEAR)
        GLES20.glTexParameteri(GLES20.GL_TEXTURE_2D, GLES20.GL_TEXTURE_WRAP_S, GLES20.GL_CLAMP_TO_EDGE)
        GLES20.glTexParameteri(GLES20.GL_TEXTURE_2D, GLES20.GL_TEXTURE_WRAP_T, GLES20.GL_CLAMP_TO_EDGE)
        cur?.let { GLUtils.texImage2D(GLES20.GL_TEXTURE_2D, 0, it.bitmap, 0) }
        GLES20.glClearColor(0.07f, 0.07f, 0.08f, 1f)
    }

    override fun onSurfaceChanged(g: GL10?, w: Int, h: Int) { vw = w; vh = h; GLES20.glViewport(0, 0, w, h) }

    /** 첫 얼굴 프레임에서 들로네 삼각분할 (입 안쪽은 비워 둠) */
    private fun buildMesh(t: TargetFrame) {
        val base = t.base!!
        val w = t.bitmap.width.toFloat(); val h = t.bitmap.height.toFloat()
        meshW = t.bitmap.width; meshH = t.bitmap.height
        val pts = ArrayList<FloatArray>()
        for (i in 0 until 468) pts += floatArrayOf(base[i * 3], -base[i * 3 + 1])
        // 얼굴 둘레 고리 (얼굴 크기의 약 1.45배 타원) — 여기부터 바깥은 움직이지 않음
        var minX = Float.MAX_VALUE; var maxX = -Float.MAX_VALUE; var minY = Float.MAX_VALUE; var maxY = -Float.MAX_VALUE
        for (i in 0 until 468) { minX = min(minX, pts[i][0]); maxX = max(maxX, pts[i][0]); minY = min(minY, pts[i][1]); maxY = max(maxY, pts[i][1]) }
        val cx = (minX + maxX) / 2; val cy = (minY + maxY) / 2
        val rx = (maxX - minX) * 0.75f; val ry = (maxY - minY) * 0.72f
        val fixed = ArrayList<FloatArray>()
        for (k in 0 until 28) {
            val a = (k * 2 * Math.PI / 28).toFloat()
            fixed += floatArrayOf((cx + rx * cos(a)).coerceIn(0f, w - 1), (cy + ry * sin(a)).coerceIn(0f, h - 1))
        }
        for (k in 0..4) { val f = k / 4f; fixed += floatArrayOf(f * (w - 1), 0f); fixed += floatArrayOf(f * (w - 1), h - 1) }
        for (k in 1..3) { val f = k / 4f; fixed += floatArrayOf(0f, f * (h - 1)); fixed += floatArrayOf(w - 1, f * (h - 1)) }
        val all = pts + fixed
        val sub = Subdiv2D(org.opencv.core.Rect(-2, -2, meshW + 4, meshH + 4))
        val index = HashMap<Long, Int>()
        fun key(x: Float, y: Float) = ((x * 16).toLong() shl 32) xor ((y * 16).toLong() and 0xffffffffL)
        all.forEachIndexed { i, p ->
            val k = key(p[0], p[1])
            if (k !in index) { index[k] = i; runCatching { sub.insert(Point(p[0].toDouble(), p[1].toDouble())) } }
        }
        val list = MatOfFloat6(); sub.getTriangleList(list)
        val arr = list.toArray()
        val mouth = INNER_LIP.toHashSet()
        val out = ArrayList<Short>()
        for (j in arr.indices step 6) {
            val a = index[key(arr[j].toFloat(), arr[j + 1].toFloat())] ?: continue
            val b = index[key(arr[j + 2].toFloat(), arr[j + 3].toFloat())] ?: continue
            val c = index[key(arr[j + 4].toFloat(), arr[j + 5].toFloat())] ?: continue
            if (a in mouth && b in mouth && c in mouth) continue // 입 안쪽은 비움 (입을 벌리면 어두운 입속이 보이게)
            out += a.toShort(); out += b.toShort(); out += c.toShort()
        }
        tris = ByteBuffer.allocateDirect(out.size * 2).order(ByteOrder.nativeOrder()).asShortBuffer().apply { put(out.toShortArray()); position(0) }
        triCount = out.size
        fixedPts = FloatArray(fixed.size * 2).also { fp -> fixed.forEachIndexed { i, p -> fp[i * 2] = p[0]; fp[i * 2 + 1] = p[1] } }
        identity = null; identitySum = null; identityN = 0
    }

    override fun onDrawFrame(g: GL10?) {
        pendingTarget.getAndSet(null)?.let { (t, keep) ->
            GLES20.glBindTexture(GLES20.GL_TEXTURE_2D, tex)
            GLUtils.texImage2D(GLES20.GL_TEXTURE_2D, 0, t.bitmap, 0)
            cur?.let { if (!curKeep && it !== t) it.bitmap.recycle() }
            cur = t; curKeep = keep
            if (t.base != null && (tris == null || t.bitmap.width != meshW || t.bitmap.height != meshH)) buildMesh(t)
            // 대상의 평소 얼굴 모양: 처음 10프레임 평균 (동영상 속 인물의 원래 표정 대신 내 표정을 씁니다)
            if (t.base != null && t.frame != null && identityN < 10) {
                val f = MeshData.frontal(t.base, t.frame)
                val s = identitySum ?: FloatArray(f.size).also { identitySum = it }
                for (k in s.indices) s[k] += f[k]
                identityN++
                identity = FloatArray(s.size) { s[it] / identityN }
            }
        }
        GLES20.glEnable(GLES20.GL_DEPTH_TEST)
        GLES20.glDepthFunc(GLES20.GL_LEQUAL)
        GLES20.glClear(GLES20.GL_COLOR_BUFFER_BIT or GLES20.GL_DEPTH_BUFFER_BIT)
        val t = cur ?: return
        val iw = t.bitmap.width.toFloat(); val ih = t.bitmap.height.toFloat()
        // 화면에 맞추기 (가운데, 비율 유지)
        val sc = min(vw / iw, vh / ih)
        val sx = iw * sc / vw; val sy = ih * sc / vh
        fun nx(px: Float) = (px / iw * 2f - 1f) * sx
        fun ny(py: Float) = (1f - py / ih * 2f) * sy

        GLES20.glUseProgram(prog)
        val aPos = GLES20.glGetAttribLocation(prog, "aPos"); val aUV = GLES20.glGetAttribLocation(prog, "aUV")
        val uFill = GLES20.glGetUniformLocation(prog, "uFill"); val uColor = GLES20.glGetUniformLocation(prog, "uColor")
        GLES20.glActiveTexture(GLES20.GL_TEXTURE0); GLES20.glBindTexture(GLES20.GL_TEXTURE_2D, tex)
        GLES20.glUniform1i(GLES20.glGetUniformLocation(prog, "uTex"), 0)

        // 원본 사진을 먼저 깔아 둡니다 (얼굴을 크게 돌려 메시에 틈이 생겨도 배경이 비치지 않게)
        val zb = 0.98f // 가장 뒤
        val q = floatArrayOf(nx(0f), ny(ih), zb, 0f, 1f, nx(iw), ny(ih), zb, 1f, 1f, nx(0f), ny(0f), zb, 0f, 0f, nx(iw), ny(0f), zb, 1f, 0f)
        val qb = ByteBuffer.allocateDirect(q.size * 4).order(ByteOrder.nativeOrder()).asFloatBuffer().apply { put(q); position(0) }
        GLES20.glUniform1i(uFill, 0)
        qb.position(0); GLES20.glEnableVertexAttribArray(aPos); GLES20.glVertexAttribPointer(aPos, 3, GLES20.GL_FLOAT, false, 20, qb)
        qb.position(3); GLES20.glEnableVertexAttribArray(aUV); GLES20.glVertexAttribPointer(aUV, 2, GLES20.GL_FLOAT, false, 20, qb)
        GLES20.glDrawArrays(GLES20.GL_TRIANGLE_STRIP, 0, 4)

        val base = t.base; val fr = t.frame; val fixed = fixedPts; val tb = tris; val idn = identity
        if (base == null || fr == null || fixed == null || tb == null || idn == null) { capture(); return } // 얼굴이 없는 프레임: 그대로

        // 얼굴 점 옮기기: 대상 평소 모양 + 내 표정 변화 → 내 고개 회전 → 대상 사진 좌표
        val d = driver.get()
        val n = 468; val nFixed = fixed.size / 2
        val pos = FloatArray((n + nFixed) * 3); val uv = FloatArray((n + nFixed) * 2)
        // 깊이: 카메라에 가까운 면이 앞에 오도록 (메시가 접혀도 겹쳐 보이지 않게)
        fun depth(pz: Float) = (-(pz - fr.c[2]) / (fr.faceH * 2f)).coerceIn(-0.6f, 0.6f)
        val tmp = FloatArray(3)
        val gk = gain
        for (i in 0 until n) {
            var fx = idn[i * 3]; var fy = idn[i * 3 + 1]; var fz = idn[i * 3 + 2]
            if (d != null) { fx += d.delta[i * 3] * gk; fy += d.delta[i * 3 + 1] * gk; fz += d.delta[i * 3 + 2] * gk }
            fr.toImage(fx, fy, fz, tmp, 0)
            var px = tmp[0]; var py = tmp[1]; var pz = tmp[2]
            if (d != null) {
                val r = d.rot
                val ox = px - fr.c[0]; val oy = py - fr.c[1]; val oz = pz - fr.c[2]
                px = fr.c[0] + r[0] * ox + r[1] * oy + r[2] * oz + d.tx * fr.faceH * 0.8f
                py = fr.c[1] + r[3] * ox + r[4] * oy + r[5] * oz + d.ty * fr.faceH * 0.8f
            }
            pos[i * 3] = nx(px); pos[i * 3 + 1] = ny(-py); pos[i * 3 + 2] = depth(pz)
            uv[i * 2] = base[i * 3] / iw; uv[i * 2 + 1] = -base[i * 3 + 1] / ih
        }
        for (j in 0 until nFixed) {
            val x = fixed[j * 2]; val y = fixed[j * 2 + 1]
            pos[(n + j) * 3] = nx(x); pos[(n + j) * 3 + 1] = ny(y); pos[(n + j) * 3 + 2] = 0.9f
            uv[(n + j) * 2] = x / iw; uv[(n + j) * 2 + 1] = y / ih
        }
        val pb = fill(posBuf, pos).also { posBuf = it }
        val ub = fill(uvBuf, uv).also { uvBuf = it }

        // 입속 (어두운 색)
        var mcx = 0f; var mcy = 0f; var mz = 0f
        for (i in INNER_LIP) { mcx += pos[i * 3]; mcy += pos[i * 3 + 1]; mz += pos[i * 3 + 2] }
        mcx /= INNER_LIP.size; mcy /= INNER_LIP.size; mz = mz / INNER_LIP.size + 0.02f // 입술보다 살짝 뒤
        mouthBuf.position(0); mouthBuf.put(mcx); mouthBuf.put(mcy); mouthBuf.put(mz)
        for (i in INNER_LIP) { mouthBuf.put(pos[i * 3]); mouthBuf.put(pos[i * 3 + 1]); mouthBuf.put(mz) }
        mouthBuf.put(pos[INNER_LIP[0] * 3]); mouthBuf.put(pos[INNER_LIP[0] * 3 + 1]); mouthBuf.put(mz); mouthBuf.position(0)
        GLES20.glUniform1i(uFill, 1); GLES20.glUniform4f(uColor, 0.16f, 0.05f, 0.06f, 1f)
        GLES20.glDisableVertexAttribArray(aUV)
        GLES20.glEnableVertexAttribArray(aPos); GLES20.glVertexAttribPointer(aPos, 3, GLES20.GL_FLOAT, false, 0, mouthBuf)
        GLES20.glDrawArrays(GLES20.GL_TRIANGLE_FAN, 0, INNER_LIP.size + 2)

        // 사진 메시
        GLES20.glUniform1i(uFill, 0)
        GLES20.glVertexAttribPointer(aPos, 3, GLES20.GL_FLOAT, false, 0, pb)
        GLES20.glEnableVertexAttribArray(aUV); GLES20.glVertexAttribPointer(aUV, 2, GLES20.GL_FLOAT, false, 0, ub)
        tb.position(0)
        GLES20.glDrawElements(GLES20.GL_TRIANGLES, triCount, GLES20.GL_UNSIGNED_SHORT, tb)
        capture()
    }

    private var lastCapture = 0L
    /** 녹화 중이면 화면을 읽어 넘깁니다 (초당 20장). */
    private fun capture() {
        val cb = onCapture ?: return
        val now = SystemClock.uptimeMillis()
        if (now - lastCapture < 50) return
        lastCapture = now
        val buf = ByteBuffer.allocateDirect(vw * vh * 4).order(ByteOrder.nativeOrder())
        GLES20.glReadPixels(0, 0, vw, vh, GLES20.GL_RGBA, GLES20.GL_UNSIGNED_BYTE, buf)
        val b = Bitmap.createBitmap(vw, vh, Bitmap.Config.ARGB_8888)
        buf.position(0); b.copyPixelsFromBuffer(buf)
        // GL 은 아래부터 읽으므로 위아래 뒤집기
        val flipped = Bitmap.createBitmap(b, 0, 0, vw, vh, android.graphics.Matrix().apply { postScale(1f, -1f) }, false)
        b.recycle()
        cb(flipped)
    }

    private fun fill(buf: FloatBuffer?, a: FloatArray): FloatBuffer =
        (if (buf != null && buf.capacity() == a.size) buf else ByteBuffer.allocateDirect(a.size * 4).order(ByteOrder.nativeOrder()).asFloatBuffer())
            .apply { position(0); put(a); position(0) }
}
