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
    private var glView: GLSurfaceView? = null

    private fun dp(v: Int) = (v * resources.displayMetrics.density).toInt()

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        val file = File(intent.getStringExtra("path") ?: run { finish(); return })

        val root = LinearLayout(this).apply { orientation = LinearLayout.VERTICAL; setBackgroundColor(Color.rgb(24, 24, 28)) }
        root.setOnApplyWindowInsetsListener { v, insets ->
            @Suppress("DEPRECATION")
            v.setPadding(0, insets.systemWindowInsetTop, 0, insets.systemWindowInsetBottom); insets
        }
        frame = FrameLayout(this)
        status = TextView(this).apply {
            text = "고품질 3D 얼굴 모델 만드는 중..."; setTextColor(Color.WHITE); textSize = 15f; gravity = Gravity.CENTER
        }
        frame.addView(status, FrameLayout.LayoutParams(MATCH_PARENT, MATCH_PARENT))
        root.addView(frame, LinearLayout.LayoutParams(MATCH_PARENT, 0, 1f))
        root.addView(TextView(this).apply {
            text = "한 손가락: 돌리기 · 두 손가락: 확대/축소"; setTextColor(Color.LTGRAY); textSize = 12f
            gravity = Gravity.CENTER; setPadding(0, dp(6), 0, dp(2))
        })
        val bar = LinearLayout(this).apply { orientation = LinearLayout.HORIZONTAL; setPadding(dp(8), dp(4), dp(8), dp(8)) }
        fun btn(t: String, f: (Button) -> Unit) = Button(this).apply { text = t; setOnClickListener { f(this) } }
            .also { bar.addView(it, LinearLayout.LayoutParams(0, WRAP_CONTENT, 1f)) }
        val modes = listOf("사진 입힘", "음영", "선")
        btn("보기: ${modes[0]}") { b ->
            renderer?.let { r -> r.mode = (r.mode + 1) % 3; b.text = "보기: ${modes[r.mode]}"; glView?.requestRender() }
        }
        btn("자동 회전") { b ->
            renderer?.let { r -> r.autoRotate = !r.autoRotate; b.text = if (r.autoRotate) "회전 멈춤" else "자동 회전" }
            glView?.renderMode = if (renderer?.autoRotate == true) GLSurfaceView.RENDERMODE_CONTINUOUSLY else GLSurfaceView.RENDERMODE_WHEN_DIRTY
        }
        btn("OBJ 저장") { exportObj() }
        root.addView(bar)
        setContentView(root)

        thread {
            val result = runCatching { buildMesh(file) }
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

    /** 고해상도로 열어서 얼굴 점을 찾고, 얼굴 부분만 1024px 텍스처로 잘라 씁니다. */
    private fun buildMesh(file: File): MeshData? {
        val bmp = FaceMatcher.decodeFile(file, 2048)
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
        val texSize = 1024
        val tex = Bitmap.createBitmap(texSize, texSize, Bitmap.Config.ARGB_8888)
        Canvas(tex).apply {
            drawColor(Color.rgb(40, 34, 32))
            drawBitmap(bmp, Rect(crop.left.toInt(), crop.top.toInt(), crop.right.toInt(), crop.bottom.toInt()),
                Rect(0, 0, texSize, texSize), Paint(Paint.FILTER_BITMAP_FLAG))
        }
        // drawBitmap 은 정수 영역으로 잘라서, 텍스처 좌표도 같은 영역으로 맞춥니다
        val used = RectF(crop.left.toInt().toFloat(), crop.top.toInt().toFloat(), crop.right.toInt().toFloat(), crop.bottom.toInt().toFloat())
        return MeshData.build(Subdivision.get(this), res.points, w, h, used, tex)
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
        val scale = ScaleGestureDetector(this, object : ScaleGestureDetector.SimpleOnScaleGestureListener() {
            override fun onScale(d: ScaleGestureDetector): Boolean {
                r.zoom = (r.zoom * d.scaleFactor).coerceIn(0.4f, 4f); v.requestRender(); return true
            }
        })
        v.setOnTouchListener { _, e ->
            scale.onTouchEvent(e)
            when (e.actionMasked) {
                MotionEvent.ACTION_DOWN -> { lastX = e.x; lastY = e.y }
                MotionEvent.ACTION_MOVE -> if (e.pointerCount == 1 && !scale.isInProgress) {
                    r.yaw += (e.x - lastX) * 0.4f
                    r.pitch = (r.pitch + (e.y - lastY) * 0.4f).coerceIn(-85f, 85f)
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

    /** face.obj + face.mtl + face.jpg 를 zip 하나로 묶어 다운로드 폴더에 저장합니다. */
    private fun exportObj() {
        val m = mesh ?: run { Toast.makeText(this, "모델이 아직 없습니다", Toast.LENGTH_SHORT).show(); return }
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
                    val uri = contentResolver.insert(MediaStore.Downloads.EXTERNAL_CONTENT_URI, cv)!!
                    contentResolver.openOutputStream(uri)!!.use(write)
                    "다운로드/SelfCheck/$name 에 저장했습니다"
                } else {
                    val f = File(getExternalFilesDir(Environment.DIRECTORY_DOWNLOADS), name)
                    f.outputStream().use(write)
                    "${f.absolutePath} 에 저장했습니다"
                }
            }.getOrElse { "저장 실패: ${it.message}" }
            runOnUiThread { Toast.makeText(this, msg, Toast.LENGTH_LONG).show() }
        }
    }
}

class PhotoRenderer(private val m: MeshData) : GLSurfaceView.Renderer {
    @Volatile var yaw = 0f
    @Volatile var pitch = 0f
    @Volatile var zoom = 1f
    @Volatile var mode = MeshGL.MODE_TEXTURE
    @Volatile var autoRotate = false
    private var lastTime = 0L
    private val gl = MeshGL()
    private val proj = FloatArray(16); private val view = FloatArray(16)
    private val model = FloatArray(16); private val tmp = FloatArray(16); private val mvp = FloatArray(16)

    override fun onSurfaceCreated(g: GL10?, config: EGLConfig?) {
        gl.init()
        m.texture?.let { gl.uploadTexture(it) }
        gl.setMesh(m)
        GLES20.glClearColor(0.094f, 0.094f, 0.11f, 1f)
        GLES20.glEnable(GLES20.GL_DEPTH_TEST)
    }

    override fun onSurfaceChanged(g: GL10?, w: Int, h: Int) {
        GLES20.glViewport(0, 0, w, h)
        Matrix.perspectiveM(proj, 0, 35f, w.toFloat() / h.coerceAtLeast(1), 0.1f, 50f)
    }

    override fun onDrawFrame(g: GL10?) {
        val now = System.nanoTime()
        if (autoRotate && lastTime != 0L) yaw -= (now - lastTime) / 1e9f * 25f
        lastTime = now
        GLES20.glClear(GLES20.GL_COLOR_BUFFER_BIT or GLES20.GL_DEPTH_BUFFER_BIT)
        Matrix.setLookAtM(view, 0, 0f, 0f, 4.2f / zoom, 0f, 0f, 0f, 0f, 1f, 0f)
        Matrix.setIdentityM(model, 0)
        Matrix.rotateM(model, 0, pitch, 1f, 0f, 0f)
        Matrix.rotateM(model, 0, yaw, 0f, 1f, 0f)
        Matrix.multiplyMM(tmp, 0, view, 0, model, 0)
        Matrix.multiplyMM(mvp, 0, proj, 0, tmp, 0)
        gl.drawMesh(mvp, model, mode)
    }
}
