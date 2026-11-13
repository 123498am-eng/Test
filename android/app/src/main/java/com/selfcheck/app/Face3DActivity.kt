package com.selfcheck.app

import android.content.ContentValues
import android.graphics.Bitmap
import android.graphics.Color
import android.opengl.GLES20
import android.opengl.GLSurfaceView
import android.opengl.GLUtils
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
import java.io.ByteArrayOutputStream
import java.io.File
import java.io.OutputStream
import java.nio.ByteBuffer
import java.nio.ByteOrder
import java.nio.FloatBuffer
import java.nio.ShortBuffer
import java.util.Locale
import java.util.zip.ZipEntry
import java.util.zip.ZipOutputStream
import javax.microedition.khronos.egl.EGLConfig
import javax.microedition.khronos.opengles.GL10
import kotlin.concurrent.thread
import kotlin.math.sqrt

/** 사진에서 만든 3D 얼굴 메시를 손가락으로 돌려 보고, OBJ 파일로 저장합니다. */
class Face3DActivity : ComponentActivity() {
    private lateinit var frame: FrameLayout
    private lateinit var status: TextView
    private var mesh: MeshData? = null
    private var renderer: FaceRenderer? = null
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
            text = "3D 얼굴 모델 만드는 중..."; setTextColor(Color.WHITE); textSize = 15f; gravity = Gravity.CENTER
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
        btn("처음 각도") { renderer?.let { it.yaw = 0f; it.pitch = 0f; it.zoom = 1f; glView?.requestRender() } }
        btn("OBJ 저장") { exportObj() }
        root.addView(bar)
        setContentView(root)

        thread {
            val result = runCatching {
                val bmp = FaceMatcher.decodeFile(file)
                FaceMesh.analyze(this, bmp)?.let { MeshData.build(it, FaceMesh.triangles(this)) }
            }
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

    private fun showMesh(m: MeshData) {
        mesh = m
        val r = FaceRenderer(m)
        renderer = r
        val v = GLSurfaceView(this).apply {
            setEGLContextClientVersion(2)
            setEGLConfigChooser(8, 8, 8, 8, 16, 0)
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

/** 렌더링·내보내기에 쓰는 메시 데이터. 좌표는 가운데 정렬하고 [-1, 1] 크기로 맞춥니다. */
class MeshData(
    val bitmap: Bitmap,
    val pos: FloatArray,   // n*3
    val uv: FloatArray,    // n*2 (사진 좌표, 위가 0)
    val normal: FloatArray, // n*3
    val tris: IntArray,
) {
    val count get() = pos.size / 3

    companion object {
        fun build(r: FaceMeshResult, tris: IntArray): MeshData {
            val n = 468 // 삼각형이 쓰는 점 (홍채 점 10개 제외)
            val w = r.bitmap.width.toFloat(); val h = r.bitmap.height.toFloat()
            val pos = FloatArray(n * 3); val uv = FloatArray(n * 2)
            for (i in 0 until n) {
                val x = r.points[i * 3]; val y = r.points[i * 3 + 1]; val z = r.points[i * 3 + 2]
                pos[i * 3] = x * w; pos[i * 3 + 1] = -y * h; pos[i * 3 + 2] = -z * w
                uv[i * 2] = x; uv[i * 2 + 1] = y
            }
            // 가운데 정렬 + 크기 맞춤
            val mins = FloatArray(3) { Float.MAX_VALUE }; val maxs = FloatArray(3) { -Float.MAX_VALUE }
            for (i in 0 until n) for (k in 0..2) { mins[k] = minOf(mins[k], pos[i * 3 + k]); maxs[k] = maxOf(maxs[k], pos[i * 3 + k]) }
            val c = FloatArray(3) { (mins[it] + maxs[it]) / 2 }
            val s = 2f / maxOf(maxs[0] - mins[0], maxs[1] - mins[1])
            for (i in 0 until n) for (k in 0..2) pos[i * 3 + k] = (pos[i * 3 + k] - c[k]) * s

            // 점마다 법선(면 방향) 계산
            val nor = FloatArray(n * 3)
            for (t in tris.indices step 3) {
                val a = tris[t]; val b = tris[t + 1]; val cc = tris[t + 2]
                val ux = pos[b * 3] - pos[a * 3]; val uy = pos[b * 3 + 1] - pos[a * 3 + 1]; val uz = pos[b * 3 + 2] - pos[a * 3 + 2]
                val vx = pos[cc * 3] - pos[a * 3]; val vy = pos[cc * 3 + 1] - pos[a * 3 + 1]; val vz = pos[cc * 3 + 2] - pos[a * 3 + 2]
                val nx = uy * vz - uz * vy; val ny = uz * vx - ux * vz; val nz = ux * vy - uy * vx
                for (idx in intArrayOf(a, b, cc)) { nor[idx * 3] += nx; nor[idx * 3 + 1] += ny; nor[idx * 3 + 2] += nz }
            }
            var sumZ = 0f
            for (i in 0 until n) sumZ += nor[i * 3 + 2]
            val flip = if (sumZ < 0) -1f else 1f // 법선이 카메라 쪽을 향하도록
            for (i in 0 until n) {
                val l = sqrt(nor[i * 3] * nor[i * 3] + nor[i * 3 + 1] * nor[i * 3 + 1] + nor[i * 3 + 2] * nor[i * 3 + 2]).coerceAtLeast(1e-6f)
                for (k in 0..2) nor[i * 3 + k] = nor[i * 3 + k] / l * flip
            }
            return MeshData(r.bitmap, pos, uv, nor, tris)
        }
    }

    fun writeZip(zip: ZipOutputStream) {
        val sb = StringBuilder("# 셀프 점검 앱에서 만든 3D 얼굴 메시\nmtllib face.mtl\n")
        for (i in 0 until count) sb.append(String.format(Locale.US, "v %.5f %.5f %.5f\n", pos[i * 3], pos[i * 3 + 1], pos[i * 3 + 2]))
        for (i in 0 until count) sb.append(String.format(Locale.US, "vt %.5f %.5f\n", uv[i * 2], 1 - uv[i * 2 + 1]))
        for (i in 0 until count) sb.append(String.format(Locale.US, "vn %.4f %.4f %.4f\n", normal[i * 3], normal[i * 3 + 1], normal[i * 3 + 2]))
        sb.append("usemtl face\n")
        // 법선 방향과 맞도록 삼각형 순서를 정합니다
        for (t in tris.indices step 3) {
            val a = tris[t] + 1; val b = tris[t + 1] + 1; val c = tris[t + 2] + 1
            sb.append("f $a/$a/$a $b/$b/$b $c/$c/$c\n")
        }
        zip.putNextEntry(ZipEntry("face.obj")); zip.write(sb.toString().toByteArray()); zip.closeEntry()
        zip.putNextEntry(ZipEntry("face.mtl"))
        zip.write("newmtl face\nKa 1 1 1\nKd 1 1 1\nmap_Kd face.jpg\n".toByteArray()); zip.closeEntry()
        val jpg = ByteArrayOutputStream().also { bitmap.compress(Bitmap.CompressFormat.JPEG, 92, it) }.toByteArray()
        zip.putNextEntry(ZipEntry("face.jpg")); zip.write(jpg); zip.closeEntry()
    }
}

/** OpenGL ES 2.0 렌더러. mode 0: 사진 입힘, 1: 음영, 2: 선 */
class FaceRenderer(private val m: MeshData) : GLSurfaceView.Renderer {
    @Volatile var yaw = 0f
    @Volatile var pitch = 0f
    @Volatile var zoom = 1f
    @Volatile var mode = 0

    private val proj = FloatArray(16); private val view = FloatArray(16)
    private val model = FloatArray(16); private val tmp = FloatArray(16); private val mvp = FloatArray(16)
    private var prog = 0; private var tex = 0
    private lateinit var posBuf: FloatBuffer; private lateinit var uvBuf: FloatBuffer; private lateinit var norBuf: FloatBuffer
    private lateinit var triBuf: ShortBuffer; private lateinit var lineBuf: ShortBuffer
    private var lineCount = 0

    private fun fb(a: FloatArray) = ByteBuffer.allocateDirect(a.size * 4).order(ByteOrder.nativeOrder()).asFloatBuffer().apply { put(a); position(0) }
    private fun sb(a: ShortArray) = ByteBuffer.allocateDirect(a.size * 2).order(ByteOrder.nativeOrder()).asShortBuffer().apply { put(a); position(0) }

    private val vs = """
        uniform mat4 uMVP; uniform mat4 uModel;
        attribute vec3 aPos; attribute vec2 aUV; attribute vec3 aNor;
        varying vec2 vUV; varying vec3 vNor;
        void main() { vUV = aUV; vNor = mat3(uModel) * aNor; gl_Position = uMVP * vec4(aPos, 1.0); }
    """
    private val fs = """
        precision mediump float;
        uniform sampler2D uTex; uniform int uMode;
        varying vec2 vUV; varying vec3 vNor;
        void main() {
            vec3 n = normalize(vNor);
            float d = max(dot(n, normalize(vec3(0.3, 0.4, 1.0))), 0.0);
            if (uMode == 0) { vec4 c = texture2D(uTex, vUV); gl_FragColor = vec4(c.rgb * (0.75 + 0.35 * d), 1.0); }
            else if (uMode == 1) { gl_FragColor = vec4(vec3(0.86, 0.78, 0.72) * (0.25 + 0.8 * d), 1.0); }
            else { gl_FragColor = vec4(0.2, 0.95, 0.7, 1.0); }
        }
    """

    private fun shader(type: Int, src: String) = GLES20.glCreateShader(type).also {
        GLES20.glShaderSource(it, src); GLES20.glCompileShader(it)
    }

    override fun onSurfaceCreated(gl: GL10?, config: EGLConfig?) {
        prog = GLES20.glCreateProgram()
        GLES20.glAttachShader(prog, shader(GLES20.GL_VERTEX_SHADER, vs))
        GLES20.glAttachShader(prog, shader(GLES20.GL_FRAGMENT_SHADER, fs))
        GLES20.glLinkProgram(prog)

        posBuf = fb(m.pos); uvBuf = fb(m.uv); norBuf = fb(m.normal)
        triBuf = sb(ShortArray(m.tris.size) { m.tris[it].toShort() })
        val edges = LinkedHashSet<Long>()
        for (t in m.tris.indices step 3) for (k in 0..2) {
            val a = m.tris[t + k]; val b = m.tris[t + (k + 1) % 3]
            edges += (minOf(a, b).toLong() shl 32) or maxOf(a, b).toLong()
        }
        val lines = ShortArray(edges.size * 2)
        edges.forEachIndexed { i, e -> lines[i * 2] = (e shr 32).toShort(); lines[i * 2 + 1] = (e and 0xffffffffL).toShort() }
        lineBuf = sb(lines); lineCount = lines.size

        val ids = IntArray(1); GLES20.glGenTextures(1, ids, 0); tex = ids[0]
        GLES20.glBindTexture(GLES20.GL_TEXTURE_2D, tex)
        GLES20.glTexParameteri(GLES20.GL_TEXTURE_2D, GLES20.GL_TEXTURE_MIN_FILTER, GLES20.GL_LINEAR)
        GLES20.glTexParameteri(GLES20.GL_TEXTURE_2D, GLES20.GL_TEXTURE_MAG_FILTER, GLES20.GL_LINEAR)
        GLES20.glTexParameteri(GLES20.GL_TEXTURE_2D, GLES20.GL_TEXTURE_WRAP_S, GLES20.GL_CLAMP_TO_EDGE)
        GLES20.glTexParameteri(GLES20.GL_TEXTURE_2D, GLES20.GL_TEXTURE_WRAP_T, GLES20.GL_CLAMP_TO_EDGE)
        GLUtils.texImage2D(GLES20.GL_TEXTURE_2D, 0, m.bitmap, 0)

        GLES20.glClearColor(0.094f, 0.094f, 0.11f, 1f)
        GLES20.glEnable(GLES20.GL_DEPTH_TEST)
    }

    override fun onSurfaceChanged(gl: GL10?, w: Int, h: Int) {
        GLES20.glViewport(0, 0, w, h)
        Matrix.perspectiveM(proj, 0, 35f, w.toFloat() / h.coerceAtLeast(1), 0.1f, 50f)
    }

    override fun onDrawFrame(gl: GL10?) {
        GLES20.glClear(GLES20.GL_COLOR_BUFFER_BIT or GLES20.GL_DEPTH_BUFFER_BIT)
        Matrix.setLookAtM(view, 0, 0f, 0f, 4.2f / zoom, 0f, 0f, 0f, 0f, 1f, 0f)
        Matrix.setIdentityM(model, 0)
        Matrix.rotateM(model, 0, pitch, 1f, 0f, 0f)
        Matrix.rotateM(model, 0, yaw, 0f, 1f, 0f)
        Matrix.multiplyMM(tmp, 0, view, 0, model, 0)
        Matrix.multiplyMM(mvp, 0, proj, 0, tmp, 0)

        GLES20.glUseProgram(prog)
        GLES20.glUniformMatrix4fv(GLES20.glGetUniformLocation(prog, "uMVP"), 1, false, mvp, 0)
        GLES20.glUniformMatrix4fv(GLES20.glGetUniformLocation(prog, "uModel"), 1, false, model, 0)
        GLES20.glUniform1i(GLES20.glGetUniformLocation(prog, "uMode"), mode)
        GLES20.glActiveTexture(GLES20.GL_TEXTURE0)
        GLES20.glBindTexture(GLES20.GL_TEXTURE_2D, tex)
        GLES20.glUniform1i(GLES20.glGetUniformLocation(prog, "uTex"), 0)

        fun attr(name: String, size: Int, buf: FloatBuffer) {
            val loc = GLES20.glGetAttribLocation(prog, name)
            if (loc < 0) return
            GLES20.glEnableVertexAttribArray(loc)
            GLES20.glVertexAttribPointer(loc, size, GLES20.GL_FLOAT, false, 0, buf)
        }
        attr("aPos", 3, posBuf); attr("aUV", 2, uvBuf); attr("aNor", 3, norBuf)

        if (mode == 2) GLES20.glDrawElements(GLES20.GL_LINES, lineCount, GLES20.GL_UNSIGNED_SHORT, lineBuf)
        else GLES20.glDrawElements(GLES20.GL_TRIANGLES, m.tris.size, GLES20.GL_UNSIGNED_SHORT, triBuf)
    }
}
