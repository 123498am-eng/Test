package com.selfcheck.app

import android.content.ContentValues
import android.graphics.Bitmap
import android.graphics.Canvas
import android.graphics.Color
import android.graphics.Paint
import android.graphics.Rect
import android.graphics.RectF
import android.opengl.GLES20
import android.opengl.GLSurfaceView
import android.opengl.Matrix
import android.os.Build
import android.os.Bundle
import android.os.Environment
import android.provider.MediaStore
import android.view.Gravity
import android.view.MotionEvent
import android.view.ScaleGestureDetector
import android.view.ViewGroup.LayoutParams.MATCH_PARENT
import android.view.ViewGroup.LayoutParams.WRAP_CONTENT
import android.widget.Button
import android.widget.SeekBar
import android.content.Intent
import android.widget.FrameLayout
import android.widget.LinearLayout
import android.widget.TextView
import android.widget.Toast
import androidx.activity.ComponentActivity
import java.io.File
import java.io.OutputStream
import java.util.zip.ZipOutputStream
import javax.microedition.khronos.egl.EGLConfig
import javax.microedition.khronos.opengles.GL10
import kotlin.concurrent.thread

/** 사진에서 만든 고품질 3D 얼굴 메시를 돌려 보고, OBJ 파일로 저장합니다. */
class Face3DActivity : ComponentActivity() {
    private lateinit var frame: FrameLayout
    private lateinit var status: TextView
    private var mesh: MeshData? = null
    private var renderer: PhotoRenderer? = null
    private var detail = false
    private var lightMode = false
    private lateinit var hint: TextView
    private var glView: GLSurfaceView? = null

    private fun dp(v: Int) = (v * resources.displayMetrics.density).toInt()

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        val live = intent.getBooleanExtra("live", false)
        val path = intent.getStringExtra("path")
        detail = intent.getBooleanExtra("detail", false)
        if (!live && path == null) { finish(); return }

        val root = LinearLayout(this).apply { orientation = LinearLayout.VERTICAL; setBackgroundColor(Color.rgb(24, 24, 28)) }
        root.setOnApplyWindowInsetsListener { v, insets ->
            @Suppress("DEPRECATION")
            v.setPadding(0, insets.systemWindowInsetTop, 0, insets.systemWindowInsetBottom); insets
        }
        frame = FrameLayout(this)
        status = TextView(this).apply {
            text = if (detail) "3D 자세히 보기 준비 중...\n(고해상도 텍스처와 주름 맵을 만듭니다)" else "고품질 3D 얼굴 모델 만드는 중..."
            setTextColor(Color.WHITE); textSize = 15f; gravity = Gravity.CENTER
        }
        frame.addView(status, FrameLayout.LayoutParams(MATCH_PARENT, MATCH_PARENT))
        root.addView(frame, LinearLayout.LayoutParams(MATCH_PARENT, 0, 1f))
        hint = TextView(this).apply {
            text = if (detail) "한 손가락: 돌리기 · 두 손가락: 확대(최대 12배)/이동" else "한 손가락: 돌리기 · 두 손가락: 확대/축소"
            setTextColor(Color.LTGRAY); textSize = 12f; gravity = Gravity.CENTER; setPadding(0, dp(6), 0, dp(2))
        }
        root.addView(hint)
        fun bar() = LinearLayout(this).apply { orientation = LinearLayout.HORIZONTAL; setPadding(dp(8), dp(2), dp(8), dp(2)) }
        fun LinearLayout.btn(t: String, f: (Button) -> Unit) = Button(this@Face3DActivity).apply { text = t; textSize = 12f; setOnClickListener { f(this) } }
            .also { addView(it, LinearLayout.LayoutParams(0, WRAP_CONTENT, 1f)) }

        if (detail) {
            // 주름 강도
            val row = bar()
            row.addView(TextView(this).apply { text = "주름 강도"; setTextColor(Color.WHITE); textSize = 13f; setPadding(dp(4), 0, dp(8), 0) })
            row.addView(SeekBar(this).apply {
                max = 150; progress = 60
                setOnSeekBarChangeListener(object : SeekBar.OnSeekBarChangeListener {
                    override fun onProgressChanged(sb: SeekBar, p: Int, fromUser: Boolean) { renderer?.detailStrength = p / 100f; glView?.requestRender() }
                    override fun onStartTrackingTouch(sb: SeekBar) {}
                    override fun onStopTrackingTouch(sb: SeekBar) {}
                })
            }, LinearLayout.LayoutParams(0, WRAP_CONTENT, 1f))
            root.addView(row)
        }
        val bar = bar()
        val modes = if (detail) listOf("사진+주름", "점토(굴곡만)", "선", "사진만") else listOf("사진 입힘", "음영", "선")
        val modeIds = if (detail) listOf(MeshGL.MODE_TEXTURE, MeshGL.MODE_SHADED, MeshGL.MODE_WIRE, MeshGL.MODE_PHOTO_ONLY)
            else listOf(MeshGL.MODE_TEXTURE, MeshGL.MODE_SHADED, MeshGL.MODE_WIRE)
        var modeIdx = 0
        bar.btn("보기: ${modes[0]}") { b ->
            modeIdx = (modeIdx + 1) % modes.size
            renderer?.let { r -> r.mode = modeIds[modeIdx]; b.text = "보기: ${modes[modeIdx]}"; glView?.requestRender() }
        }
        if (detail) {
            bar.btn("조명 이동") { b ->
                lightMode = !lightMode
                b.text = if (lightMode) "조명 이동 중" else "조명 이동"
                hint.text = if (lightMode) "한 손가락으로 끌어 조명 방향을 바꾸세요 (비스듬한 빛에서 주름이 잘 보입니다)"
                    else "한 손가락: 돌리기 · 두 손가락: 확대(최대 12배)/이동"
            }
            bar.btn("처음으로") { renderer?.let { it.yaw = 0f; it.pitch = 0f; it.zoom = 1f; it.panX = 0f; it.panY = 0f }; glView?.requestRender() }
        } else {
            bar.btn("자동 회전") { b ->
                renderer?.let { r -> r.autoRotate = !r.autoRotate; b.text = if (r.autoRotate) "회전 멈춤" else "자동 회전" }
                glView?.renderMode = if (renderer?.autoRotate == true) GLSurfaceView.RENDERMODE_CONTINUOUSLY else GLSurfaceView.RENDERMODE_WHEN_DIRTY
            }
            bar.btn("자세히 보기") {
                startActivity(Intent(intent).putExtra("detail", true))
            }
        }
        bar.btn("OBJ 저장") { exportObj() }
        root.addView(bar)
        setContentView(root)

        if (live) {
            val m = ModelHolder.mesh
            if (m == null) { status.text = "모델이 없습니다"; return }
            if (!detail) { showMesh(m); return }
            thread {
                // 실시간 카메라로 만든 모델: 텍스처(512px)에서 주름 맵을 만듭니다
                val r = runCatching {
                    MeshData(m.pos, m.uv, m.normal, m.tris, m.texture).also { d -> d.detail = m.texture?.let { DetailMap.make(it) } }
                }
                runOnUiThread { r.getOrNull()?.let { showMesh(it) } ?: run { status.text = "오류: ${r.exceptionOrNull()?.message}" } }
            }
            return
        }
        thread {
            val result = runCatching { buildMesh(File(path!!)) }
            runOnUiThread {
                val m = result.getOrNull()
                when {
                    result.isFailure -> status.text = "오류: ${result.exceptionOrNull()?.message}"
                    m == null -> status.text = "얼굴을 찾지 못했습니다.\n얼굴이 정면으로 잘 보이는 사진을 써 보세요."
                    else -> showMesh(m)
                }
            }
        }
    }

    /**
     * 고해상도로 열어서 얼굴 점을 찾고, 얼굴 부분만 텍스처로 잘라 씁니다.
     * 기본: 원본 2048px → 텍스처 1024px. 자세히 보기: 원본 4096px → 텍스처 2048px + 주름 맵 + 더 잘게 나눈 메시.
     */
    private fun buildMesh(file: File): MeshData? {
        val bmp = if (detail) runCatching { FaceMatcher.decodeFile(file, 4096) }.getOrElse { FaceMatcher.decodeFile(file, 2048) }
            else FaceMatcher.decodeFile(file, 2048)
        val res = FaceMesh.analyze(this, bmp) ?: return null
        val w = bmp.width.toFloat(); val h = bmp.height.toFloat()
        var minX = Float.MAX_VALUE; var minY = Float.MAX_VALUE; var maxX = -Float.MAX_VALUE; var maxY = -Float.MAX_VALUE
        for (i in 0 until res.points.size / 3) {
            minX = minOf(minX, res.points[i * 3] * w); maxX = maxOf(maxX, res.points[i * 3] * w)
            minY = minOf(minY, res.points[i * 3 + 1] * h); maxY = maxOf(maxY, res.points[i * 3 + 1] * h)
        }
        val side = maxOf(maxX - minX, maxY - minY) * 1.15f
        val cx = (minX + maxX) / 2; val cy = (minY + maxY) / 2
        val crop = RectF(cx - side / 2, cy - side / 2, cx + side / 2, cy + side / 2)
        val texSize = if (detail) 2048 else 1024
        val tex = Bitmap.createBitmap(texSize, texSize, Bitmap.Config.ARGB_8888)
        Canvas(tex).apply {
            drawColor(Color.rgb(40, 34, 32))
            drawBitmap(bmp, Rect(crop.left.toInt(), crop.top.toInt(), crop.right.toInt(), crop.bottom.toInt()),
                Rect(0, 0, texSize, texSize), Paint(Paint.FILTER_BITMAP_FLAG))
        }
        // drawBitmap 은 정수 영역으로 잘라서, 텍스처 좌표도 같은 영역으로 맞춥니다
        val used = RectF(crop.left.toInt().toFloat(), crop.top.toInt().toFloat(), crop.right.toInt().toFloat(), crop.bottom.toInt().toFloat())
        val mesh = MeshData.build(Subdivision.get(this, if (detail) 3 else 2), res.points, w, h, used, tex)
        if (detail) {
            runOnUiThread { status.text = "주름 맵 만드는 중..." }
            mesh.detail = DetailMap.make(tex)
            mesh.tangents // 미리 계산
        }
        bmp.recycle()
        return mesh
    }

    private fun showMesh(m: MeshData) {
        mesh = m
        val r = PhotoRenderer(m)
        renderer = r
        val v = GLSurfaceView(this).apply {
            setEGLContextClientVersion(2)
            setEGLConfigChooser(MsaaConfigChooser())
            setRenderer(r)
            renderMode = GLSurfaceView.RENDERMODE_WHEN_DIRTY
        }
        glView = v
        var lastX = 0f; var lastY = 0f
        if (detail) { r.light = floatArrayOf(0.75f, 0.55f, 0.6f) } // 비스듬한 빛: 주름이 잘 보임
        var lastFx = 0f; var lastFy = 0f
        val scale = ScaleGestureDetector(this, object : ScaleGestureDetector.SimpleOnScaleGestureListener() {
            override fun onScaleBegin(d: ScaleGestureDetector): Boolean { lastFx = d.focusX; lastFy = d.focusY; return true }
            override fun onScale(d: ScaleGestureDetector): Boolean {
                r.zoom = (r.zoom * d.scaleFactor).coerceIn(0.4f, if (detail) 12f else 4f)
                if (detail) {
                    // 두 손가락 이동: 화면 이동 (확대할수록 천천히)
                    val k = 2.4f / (v.height.coerceAtLeast(1) * r.zoom)
                    r.panX -= (d.focusX - lastFx) * k; r.panY += (d.focusY - lastFy) * k
                    lastFx = d.focusX; lastFy = d.focusY
                }
                v.requestRender(); return true
            }
        })
        v.setOnTouchListener { _, e ->
            scale.onTouchEvent(e)
            when (e.actionMasked) {
                MotionEvent.ACTION_DOWN -> { lastX = e.x; lastY = e.y }
                MotionEvent.ACTION_MOVE -> if (e.pointerCount == 1 && !scale.isInProgress && lightMode) {
                    // 조명 방향: 화면에서 손가락 위치 쪽에서 빛이 옵니다
                    val lx = (e.x / v.width.coerceAtLeast(1)) * 2f - 1f
                    val ly = 1f - (e.y / v.height.coerceAtLeast(1)) * 2f
                    r.light = floatArrayOf(lx * 1.2f, ly * 1.2f, 0.45f)
                    v.requestRender()
                } else if (e.pointerCount == 1 && !scale.isInProgress) {
                    val sp = 0.4f / maxOf(1f, r.zoom * 0.5f)
                    r.yaw += (e.x - lastX) * sp
                    r.pitch = (r.pitch + (e.y - lastY) * sp).coerceIn(-85f, 85f)
                    lastX = e.x; lastY = e.y
                    v.requestRender()
                }
                MotionEvent.ACTION_POINTER_UP -> { lastX = e.x; lastY = e.y }
            }
            true
        }
        frame.removeAllViews()
        frame.addView(v, FrameLayout.LayoutParams(MATCH_PARENT, MATCH_PARENT))
    }

    override fun onPause() { super.onPause(); glView?.onPause() }
    override fun onResume() { super.onResume(); glView?.onResume() }

    private fun exportObj() {
        val m = mesh ?: run { Toast.makeText(this, "모델이 아직 없습니다", Toast.LENGTH_SHORT).show(); return }
        ObjExport.save(this, m)
    }
}

/** face.obj + face.mtl + face.jpg 를 zip 하나로 묶어 다운로드 폴더에 저장합니다. */
object ObjExport {
    fun save(act: android.app.Activity, m: MeshData) {
        thread {
            val name = "face_3d_${System.currentTimeMillis()}.zip"
            val msg = runCatching {
                val write: (OutputStream) -> Unit = { os -> ZipOutputStream(os).use { m.writeZip(it) } }
                if (Build.VERSION.SDK_INT >= 29) {
                    val cv = ContentValues().apply {
                        put(MediaStore.Downloads.DISPLAY_NAME, name)
                        put(MediaStore.Downloads.MIME_TYPE, "application/zip")
                        put(MediaStore.Downloads.RELATIVE_PATH, Environment.DIRECTORY_DOWNLOADS + "/SelfCheck")
                    }
                    val uri = act.contentResolver.insert(MediaStore.Downloads.EXTERNAL_CONTENT_URI, cv)!!
                    act.contentResolver.openOutputStream(uri)!!.use(write)
                    "다운로드/SelfCheck/$name 에 저장했습니다"
                } else {
                    val f = File(act.getExternalFilesDir(Environment.DIRECTORY_DOWNLOADS), name)
                    f.outputStream().use(write)
                    "${f.absolutePath} 에 저장했습니다"
                }
            }.getOrElse { "저장 실패: ${it.message}" }
            act.runOnUiThread { Toast.makeText(act, msg, Toast.LENGTH_LONG).show() }
        }
    }
}

class PhotoRenderer(private val m: MeshData) : GLSurfaceView.Renderer {
    @Volatile var yaw = 0f
    @Volatile var pitch = 0f
    @Volatile var zoom = 1f
    @Volatile var mode = MeshGL.MODE_TEXTURE
    @Volatile var autoRotate = false
    @Volatile var panX = 0f
    @Volatile var panY = 0f
    @Volatile var light = floatArrayOf(0.35f, 0.45f, 1f)
    @Volatile var detailStrength = 0.6f
    private var lastTime = 0L
    private val gl = MeshGL()
    private val proj = FloatArray(16); private val view = FloatArray(16)
    private val model = FloatArray(16); private val tmp = FloatArray(16); private val mvp = FloatArray(16)

    override fun onSurfaceCreated(g: GL10?, config: EGLConfig?) {
        gl.init()
        m.texture?.let { gl.uploadTexture(it) }
        m.detail?.let { gl.uploadDetail(it) }
        gl.setMesh(m)
        GLES20.glClearColor(0.094f, 0.094f, 0.11f, 1f)
        GLES20.glEnable(GLES20.GL_DEPTH_TEST)
    }

    override fun onSurfaceChanged(g: GL10?, w: Int, h: Int) {
        GLES20.glViewport(0, 0, w, h)
        Matrix.perspectiveM(proj, 0, 35f, w.toFloat() / h.coerceAtLeast(1), 0.02f, 50f)
    }

    override fun onDrawFrame(g: GL10?) {
        val now = System.nanoTime()
        if (autoRotate && lastTime != 0L) yaw -= (now - lastTime) / 1e9f * 25f
        lastTime = now
        GLES20.glClear(GLES20.GL_COLOR_BUFFER_BIT or GLES20.GL_DEPTH_BUFFER_BIT)
        Matrix.setLookAtM(view, 0, panX, panY, 4.2f / zoom, panX, panY, 0f, 0f, 1f, 0f)
        gl.light = light
        gl.detailStrength = detailStrength
        Matrix.setIdentityM(model, 0)
        Matrix.rotateM(model, 0, pitch, 1f, 0f, 0f)
        Matrix.rotateM(model, 0, yaw, 0f, 1f, 0f)
        Matrix.multiplyMM(tmp, 0, view, 0, model, 0)
        Matrix.multiplyMM(mvp, 0, proj, 0, tmp, 0)
        gl.drawMesh(mvp, model, mode)
    }
}
