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
        val bar2 = bar()
        val lights = listOf("정면" to floatArrayOf(0.35f, 0.45f, 1f), "비스듬히" to floatArrayOf(0.75f, 0.55f, 0.6f), "왼쪽" to floatArrayOf(-1.1f, 0.2f, 0.45f),
            "오른쪽" to floatArrayOf(1.1f, 0.2f, 0.45f), "위" to floatArrayOf(0f, 1.2f, 0.4f), "아래" to floatArrayOf(0f, -1.1f, 0.45f), "역광" to floatArrayOf(0.2f, 0.4f, -1f))
        var li = if (detail) 1 else 0
        bar2.btn("조명: ${lights[li].first}") { b -> li = (li + 1) % lights.size; b.text = "조명: ${lights[li].first}"; renderer?.light = lights[li].second; glView?.requestRender() }
        bar2.btn("화면 저장") { captureScreen() }
        bar2.btn("STL 저장") { mesh?.let { ObjExport.saveStl(this, it) } ?: Toast.makeText(this, "모델이 아직 없습니다", Toast.LENGTH_SHORT).show() }
        bar2.btn("PLY 저장") { mesh?.let { ObjExport.savePly(this, it) } ?: Toast.makeText(this, "모델이 아직 없습니다", Toast.LENGTH_SHORT).show() }
        root.addView(bar2)
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
        runOnUiThread { status.text = "얼굴 점 정밀 측정 중 (6번 측정해 중앙값)..." }
        val res = FaceMesh.analyzeTTA(this, bmp) { i -> runOnUiThread { status.text = "얼굴 점 정밀 측정 중 ${i + 1}/6" } } ?: return null
        runOnUiThread { status.text = "3D 모델 만드는 중..." }
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
            // 텍스처에서 눈꼬리 사이 거리 (주름 찾기 굵기 기준)
            val iodPx = kotlin.math.hypot((res.points[263 * 3] - res.points[33 * 3]) * w, (res.points[263 * 3 + 1] - res.points[33 * 3 + 1]) * h)
            mesh.detail = DetailMap.make(tex, this, iodPx * texSize / used.width())
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

    private fun captureScreen() {
        val r = renderer ?: return
        r.capture = { bmp ->
            thread {
                val msg = runCatching { MediaSave.savePng(this, bmp, "face_3d_${System.currentTimeMillis()}.png") + " 에 저장했습니다" }.getOrElse { "저장 실패: ${it.message}" }
                runOnUiThread { Toast.makeText(this, msg, Toast.LENGTH_SHORT).show() }
            }
        }
        glView?.requestRender()
    }

    private fun exportObj() {
        val m = mesh ?: run { Toast.makeText(this, "모델이 아직 없습니다", Toast.LENGTH_SHORT).show(); return }
        ObjExport.save(this, m)
    }
}

/** face.obj + face.mtl + face.jpg 를 zip 하나로 묶어 다운로드 폴더에 저장합니다. STL(3D 프린터용)·PLY(색 포함)도 저장합니다. */
object ObjExport {
    fun save(act: android.app.Activity, m: MeshData) =
        saveFile(act, "face_3d_${System.currentTimeMillis()}.zip", "application/zip") { os -> ZipOutputStream(os).use { m.writeZip(it) } }

    /** 바이너리 STL: 3D 프린터 프로그램에서 열 수 있습니다 (크기는 프로그램에서 맞추세요) */
    fun saveStl(act: android.app.Activity, m: MeshData) = saveFile(act, "face_3d_${System.currentTimeMillis()}.stl", "model/stl") { os ->
        val n = m.tris.size / 3
        val bb = java.nio.ByteBuffer.allocate(84 + n * 50).order(java.nio.ByteOrder.LITTLE_ENDIAN)
        val head = "SelfCheck face mesh".toByteArray(); bb.put(head); bb.position(80); bb.putInt(n)
        val sc = 100f // 단위: 대략 mm 로 보이게 키움
        for (t in 0 until n) {
            val a = m.tris[t * 3]; val b = m.tris[t * 3 + 1]; val c = m.tris[t * 3 + 2]
            fun p(i: Int, k: Int) = m.pos[i * 3 + k]
            val ux = p(b, 0) - p(a, 0); val uy = p(b, 1) - p(a, 1); val uz = p(b, 2) - p(a, 2)
            val vx = p(c, 0) - p(a, 0); val vy = p(c, 1) - p(a, 1); val vz = p(c, 2) - p(a, 2)
            var nx = uy * vz - uz * vy; var ny = uz * vx - ux * vz; var nz = ux * vy - uy * vx
            val l = kotlin.math.sqrt(nx * nx + ny * ny + nz * nz).coerceAtLeast(1e-12f); nx /= l; ny /= l; nz /= l
            bb.putFloat(nx); bb.putFloat(ny); bb.putFloat(nz)
            for (i in intArrayOf(a, b, c)) { bb.putFloat(p(i, 0) * sc); bb.putFloat(p(i, 1) * sc); bb.putFloat(p(i, 2) * sc) }
            bb.putShort(0)
        }
        os.write(bb.array())
    }

    /** PLY: 점마다 사진 색을 담은 3D 파일 (MeshLab·Blender 등) */
    fun savePly(act: android.app.Activity, m: MeshData) = saveFile(act, "face_3d_${System.currentTimeMillis()}.ply", "application/octet-stream") { os ->
        val tex = m.texture
        val px = tex?.let { IntArray(it.width * it.height).also { a -> it.getPixels(a, 0, it.width, 0, 0, it.width, it.height) } }
        val sb = StringBuilder("ply\nformat ascii 1.0\ncomment SelfCheck face mesh\nelement vertex ${m.count}\nproperty float x\nproperty float y\nproperty float z\n" +
            "property float nx\nproperty float ny\nproperty float nz\nproperty uchar red\nproperty uchar green\nproperty uchar blue\nelement face ${m.tris.size / 3}\nproperty list uchar int vertex_indices\nend_header\n")
        for (i in 0 until m.count) {
            var col = Color.LTGRAY
            if (tex != null && px != null) {
                val x = (m.uv[i * 2] * (tex.width - 1)).toInt().coerceIn(0, tex.width - 1); val y = (m.uv[i * 2 + 1] * (tex.height - 1)).toInt().coerceIn(0, tex.height - 1)
                col = px[y * tex.width + x]
            }
            sb.append(String.format(java.util.Locale.US, "%.5f %.5f %.5f %.4f %.4f %.4f %d %d %d\n", m.pos[i * 3], m.pos[i * 3 + 1], m.pos[i * 3 + 2],
                m.normal[i * 3], m.normal[i * 3 + 1], m.normal[i * 3 + 2], Color.red(col), Color.green(col), Color.blue(col)))
        }
        for (t in m.tris.indices step 3) sb.append("3 ${m.tris[t]} ${m.tris[t + 1]} ${m.tris[t + 2]}\n")
        os.write(sb.toString().toByteArray())
    }

    fun saveFile(act: android.app.Activity, name: String, mime: String, write: (OutputStream) -> Unit) {
        thread {
            val msg = runCatching {
                if (Build.VERSION.SDK_INT >= 29) {
                    val cv = ContentValues().apply {
                        put(MediaStore.Downloads.DISPLAY_NAME, name)
                        put(MediaStore.Downloads.MIME_TYPE, mime)
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
    /** 다음 그림을 비트맵으로 받아 보는 콜백 (GL 스레드에서 불림) */
    @Volatile var capture: ((Bitmap) -> Unit)? = null
    private var vw = 1; private var vh = 1
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
        vw = w; vh = h
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
        capture?.let { cb ->
            capture = null
            val buf = java.nio.ByteBuffer.allocateDirect(vw * vh * 4).order(java.nio.ByteOrder.nativeOrder())
            GLES20.glReadPixels(0, 0, vw, vh, GLES20.GL_RGBA, GLES20.GL_UNSIGNED_BYTE, buf)
            val raw = Bitmap.createBitmap(vw, vh, Bitmap.Config.ARGB_8888); buf.rewind(); raw.copyPixelsFromBuffer(buf)
            val flip = android.graphics.Matrix().apply { postScale(1f, -1f) }
            cb(Bitmap.createBitmap(raw, 0, 0, vw, vh, flip, false)); raw.recycle()
        }
    }
}
