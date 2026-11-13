package com.selfcheck.app

import android.Manifest
import android.content.pm.PackageManager
import android.graphics.Bitmap
import android.graphics.Color
import android.graphics.RectF
import android.opengl.GLES20
import android.opengl.GLSurfaceView
import android.opengl.Matrix
import android.os.Bundle
import android.os.SystemClock
import android.util.Size
import android.view.Gravity
import android.view.ViewGroup.LayoutParams.MATCH_PARENT
import android.view.ViewGroup.LayoutParams.WRAP_CONTENT
import android.widget.Button
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
import com.google.mediapipe.tasks.vision.core.RunningMode
import com.google.mediapipe.tasks.vision.facelandmarker.FaceLandmarker
import java.util.concurrent.ExecutorService
import java.util.concurrent.Executors
import java.util.concurrent.atomic.AtomicReference
import javax.microedition.khronos.egl.EGLConfig
import javax.microedition.khronos.opengles.GL10

/** 한 프레임의 카메라 사진 + 그 얼굴로 만든 3D 메시. */
class LiveFrame(val bitmap: Bitmap, val mesh: MeshData?, val faceRect: RectF?)

/**
 * 실시간 카메라. 얼굴을 찾으면 그 얼굴로 만든 3D 모델을 얼굴 옆에 띄우고
 * 천천히 왼쪽으로 돌립니다. 모든 처리는 휴대폰 안에서만 합니다.
 */
class LiveActivity : ComponentActivity() {
    private lateinit var glView: GLSurfaceView
    private lateinit var status: TextView
    private val renderer = LiveRenderer()
    private lateinit var analysisExec: ExecutorService
    private var landmarker: FaceLandmarker? = null
    private var front = true
    private var lastTs = 0L
    private var prevPos: FloatArray? = null

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

        val overlay = LinearLayout(this).apply { orientation = LinearLayout.VERTICAL; setPadding(dp(12), dp(12), dp(12), dp(12)) }
        status = TextView(this).apply {
            text = "카메라 준비 중..."; setTextColor(Color.WHITE); textSize = 15f
            setShadowLayer(4f, 0f, 0f, Color.BLACK)
        }
        overlay.addView(status)
        root.addView(overlay, FrameLayout.LayoutParams(MATCH_PARENT, WRAP_CONTENT, Gravity.TOP))

        val bar = LinearLayout(this).apply { orientation = LinearLayout.HORIZONTAL; setPadding(dp(8), dp(8), dp(8), dp(8)) }
        fun btn(t: String, f: (Button) -> Unit) = Button(this).apply { text = t; setOnClickListener { f(this) } }
            .also { bar.addView(it, LinearLayout.LayoutParams(0, WRAP_CONTENT, 1f)) }
        btn("카메라 전환") { front = !front; prevPos = null; startCamera() }
        val sides = listOf("위치: 자동", "위치: 왼쪽", "위치: 오른쪽")
        btn(sides[0]) { b -> renderer.side = (renderer.side + 1) % 3; b.text = sides[renderer.side] }
        val modes = listOf("보기: 사진", "보기: 음영", "보기: 선")
        btn(modes[0]) { b -> renderer.mode = (renderer.mode + 1) % 3; b.text = modes[renderer.mode] }
        root.addView(bar, FrameLayout.LayoutParams(MATCH_PARENT, WRAP_CONTENT, Gravity.BOTTOM))

        root.setOnApplyWindowInsetsListener { _, insets ->
            @Suppress("DEPRECATION")
            overlay.setPadding(dp(12), insets.systemWindowInsetTop + dp(8), dp(12), dp(8))
            @Suppress("DEPRECATION")
            bar.setPadding(dp(8), dp(8), dp(8), insets.systemWindowInsetBottom + dp(8))
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
                status.text = "얼굴을 카메라에 비춰 주세요"
            }.onFailure { status.text = "카메라를 열 수 없습니다: ${it.message}" }
        }, ContextCompat.getMainExecutor(this))
    }

    /** 분석 스레드: 사진 회전/좌우반전 → 얼굴 점 찾기 → 3D 메시 만들기 */
    private fun analyze(img: ImageProxy) {
        try {
            val raw = img.toBitmap()
            val m = android.graphics.Matrix().apply {
                postRotate(img.imageInfo.rotationDegrees.toFloat())
                if (front) postScale(-1f, 1f) // 앞 카메라는 거울처럼 보이게
            }
            val bmp = Bitmap.createBitmap(raw, 0, 0, raw.width, raw.height, m, true)
            if (bmp !== raw) raw.recycle()

            val lm = landmarker ?: FaceMesh.create(this, RunningMode.VIDEO, 1, false).also { landmarker = it }
            val ts = maxOf(SystemClock.uptimeMillis(), lastTs + 1).also { lastTs = it }
            val faces = lm.detectForVideo(BitmapImageBuilder(bmp).build(), ts).faceLandmarks()

            var mesh: MeshData? = null
            var rect: RectF? = null
            if (faces.isNotEmpty()) {
                val f = faces[0]
                val pts = FloatArray(f.size * 3)
                var minX = 1f; var minY = 1f; var maxX = 0f; var maxY = 0f
                f.forEachIndexed { i, p ->
                    pts[i * 3] = p.x(); pts[i * 3 + 1] = p.y(); pts[i * 3 + 2] = p.z()
                    minX = minOf(minX, p.x()); maxX = maxOf(maxX, p.x()); minY = minOf(minY, p.y()); maxY = maxOf(maxY, p.y())
                }
                val w = bmp.width.toFloat(); val h = bmp.height.toFloat()
                rect = RectF(minX * w, minY * h, maxX * w, maxY * h)
                mesh = MeshData.build(Subdivision.get(this), pts, w, h, RectF(0f, 0f, w, h), null, prevPos, 0.35f)
                prevPos = mesh.pos
            } else prevPos = null

            renderer.post(LiveFrame(bmp, mesh, rect))
            val found = mesh != null
            runOnUiThread { status.text = if (found) "얼굴 인식됨 · 3D 모델 회전 중" else "얼굴을 찾는 중..." }
        } catch (e: Exception) {
            runOnUiThread { status.text = "오류: ${e.message}" }
        } finally {
            img.close()
        }
    }

    override fun onPause() { super.onPause(); glView.onPause() }
    override fun onResume() { super.onResume(); glView.onResume() }

    override fun onDestroy() {
        super.onDestroy()
        analysisExec.execute { landmarker?.close(); landmarker = null }
        analysisExec.shutdown()
    }
}

/** 카메라 화면을 배경으로 그리고, 얼굴 옆에 3D 모델을 천천히 왼쪽으로 돌리며 그립니다. */
class LiveRenderer : GLSurfaceView.Renderer {
    @Volatile var mode = MeshGL.MODE_TEXTURE
    @Volatile var side = 0 // 0 자동, 1 왼쪽, 2 오른쪽
    private val pending = AtomicReference<LiveFrame?>()
    private val gl = MeshGL()
    private var current: LiveFrame? = null
    private var vw = 1; private var vh = 1
    private var yaw = 0f
    private var lastTime = 0L
    private var lastFaceTime = 0L
    private val box = RectF() // 화면에서 모델이 놓이는 정사각형 (부드럽게 이동)
    private var boxValid = false
    private var placeRight = true
    private val proj = FloatArray(16); private val view = FloatArray(16)
    private val model = FloatArray(16); private val tmp = FloatArray(16); private val mvp = FloatArray(16)

    fun post(f: LiveFrame) { pending.getAndSet(f)?.bitmap?.recycle() }

    override fun onSurfaceCreated(g: GL10?, config: EGLConfig?) {
        gl.init()
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
        yaw -= dt * 22f // 천천히 왼쪽으로 회전 (초당 22도)
        if (yaw < -360f) yaw += 360f

        pending.getAndSet(null)?.let { f ->
            gl.uploadTexture(f.bitmap)
            current?.bitmap?.recycle()
            current = f
            f.mesh?.let { gl.setMesh(it); lastFaceTime = now }
        }

        GLES20.glViewport(0, 0, vw, vh)
        GLES20.glClear(GLES20.GL_COLOR_BUFFER_BIT or GLES20.GL_DEPTH_BUFFER_BIT)
        val f = current ?: return
        val bw = f.bitmap.width.toFloat(); val bh = f.bitmap.height.toFloat()
        // 화면을 꽉 채우도록 확대 (가운데 기준으로 잘림)
        val s = maxOf(vw / bw, vh / bh)
        val offX = (vw - bw * s) / 2; val offY = (vh - bh * s) / 2
        GLES20.glDisable(GLES20.GL_DEPTH_TEST)
        gl.drawBackground(-offX / s / bw, (vw - offX) / s / bw, -offY / s / bh, (vh - offY) / s / bh)

        val r = f.faceRect
        if (f.mesh == null || r == null) {
            if (now - lastFaceTime > 500_000_000L) boxValid = false
            return
        }
        // 얼굴 위치(화면 좌표)
        val fl = r.left * s + offX; val fr = r.right * s + offX
        val ft = r.top * s + offY; val fb = r.bottom * s + offY
        val size = (fb - ft) * 1.35f
        val cy = (ft + fb) / 2
        val roomLeft = fl; val roomRight = vw - fr
        placeRight = when (side) {
            1 -> false
            2 -> true
            else -> if (placeRight) roomRight > roomLeft * 0.8f else roomRight > roomLeft * 1.25f // 경계에서 깜빡임 방지
        }
        val cx = if (placeRight) fr + size * 0.5f else fl - size * 0.5f
        val target = RectF(cx - size / 2, cy - size / 2, cx + size / 2, cy + size / 2)
        if (!boxValid) { box.set(target); boxValid = true }
        else {
            val k = 0.25f
            box.set(box.left + (target.left - box.left) * k, box.top + (target.top - box.top) * k,
                box.right + (target.right - box.right) * k, box.bottom + (target.bottom - box.bottom) * k)
        }

        GLES20.glViewport(box.left.toInt(), (vh - box.bottom).toInt(), box.width().toInt(), box.height().toInt())
        GLES20.glEnable(GLES20.GL_DEPTH_TEST)
        GLES20.glClear(GLES20.GL_DEPTH_BUFFER_BIT)
        Matrix.setIdentityM(model, 0)
        Matrix.rotateM(model, 0, yaw, 0f, 1f, 0f)
        Matrix.multiplyMM(tmp, 0, view, 0, model, 0)
        Matrix.multiplyMM(mvp, 0, proj, 0, tmp, 0)
        gl.drawMesh(mvp, model, mode)
    }
}
