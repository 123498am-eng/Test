package com.selfcheck.app

import android.content.Context
import android.graphics.Bitmap
import android.graphics.RectF
import android.opengl.GLES20
import android.opengl.GLSurfaceView
import android.opengl.GLUtils
import java.io.ByteArrayOutputStream
import java.nio.ByteBuffer
import java.nio.ByteOrder
import java.nio.FloatBuffer
import java.nio.ShortBuffer
import java.util.Locale
import java.util.zip.ZipEntry
import java.util.zip.ZipOutputStream
import javax.microedition.khronos.egl.EGL10
import javax.microedition.khronos.egl.EGLConfig
import javax.microedition.khronos.egl.EGLDisplay
import kotlin.math.sqrt

/**
 * Loop 세분화를 미리 계산해 둔 것. 세분화는 선형 연산이라, 새 점마다
 * "원래 468개 점의 가중합"으로 저장해 두면 매 프레임 빠르게 적용할 수 있습니다.
 */
class Subdivision(val tris: IntArray, private val rowStart: IntArray, private val cols: IntArray, private val w: FloatArray) {
    val vCount get() = rowStart.size - 1

    /** src: 원래 점 (468*3) → dst: 세분화된 점 (vCount*3) */
    fun apply(src: FloatArray, dst: FloatArray) {
        for (v in 0 until vCount) {
            var x = 0f; var y = 0f; var z = 0f
            for (k in rowStart[v] until rowStart[v + 1]) {
                val c = cols[k] * 3; val wk = w[k]
                x += src[c] * wk; y += src[c + 1] * wk; z += src[c + 2] * wk
            }
            dst[v * 3] = x; dst[v * 3 + 1] = y; dst[v * 3 + 2] = z
        }
    }

    companion object {
        const val BASE = 468
        @Volatile private var cached: Subdivision? = null

        fun get(ctx: Context, levels: Int = 2): Subdivision = cached ?: build(FaceMesh.triangles(ctx), BASE, levels).also { cached = it }

        fun build(baseTris: IntArray, baseCount: Int, levels: Int): Subdivision {
            var tris = baseTris
            var vCount = baseCount
            // rows[v] = 원래 점에 대한 가중치
            var rows: List<Map<Int, Float>> = List(baseCount) { mapOf(it to 1f) }
            repeat(levels) {
                val edgeIndex = HashMap<Long, Int>()
                val edgeOpp = ArrayList<IntArray>() // a, b, opp1, opp2(-1)
                val nbrs = Array(vCount) { HashSet<Int>() }
                fun key(a: Int, b: Int) = (minOf(a, b).toLong() shl 32) or maxOf(a, b).toLong()
                for (t in tris.indices step 3) for (k in 0..2) {
                    val a = tris[t + k]; val b = tris[t + (k + 1) % 3]; val c = tris[t + (k + 2) % 3]
                    nbrs[a] += b; nbrs[b] += a
                    val id = edgeIndex.getOrPut(key(a, b)) { edgeOpp += intArrayOf(a, b, c, -1); edgeOpp.size - 1 }
                    val e = edgeOpp[id]
                    if (e[2] != c && e[3] == -1) e[3] = c
                }
                // 경계(테두리) 점과 그 경계 이웃
                val bNbrs = Array(vCount) { ArrayList<Int>() }
                for (e in edgeOpp) if (e[3] == -1) { bNbrs[e[0]] += e[1]; bNbrs[e[1]] += e[0] }

                val newLocal = ArrayList<Map<Int, Float>>(vCount + edgeOpp.size)
                for (v in 0 until vCount) {
                    val m = HashMap<Int, Float>()
                    if (bNbrs[v].isNotEmpty()) {
                        if (bNbrs[v].size == 2) {
                            m[v] = 0.75f; m.merge(bNbrs[v][0], 0.125f, Float::plus); m.merge(bNbrs[v][1], 0.125f, Float::plus)
                        } else m[v] = 1f
                    } else {
                        val n = nbrs[v].size
                        val beta = if (n == 3) 3f / 16f else 3f / (8f * n)
                        m[v] = 1f - n * beta
                        nbrs[v].forEach { m.merge(it, beta, Float::plus) }
                    }
                    newLocal += m
                }
                for (e in edgeOpp) {
                    newLocal += if (e[3] == -1) mapOf(e[0] to 0.5f, e[1] to 0.5f)
                    else mapOf(e[0] to 0.375f, e[1] to 0.375f, e[2] to 0.125f, e[3] to 0.125f)
                }
                val newTris = IntArray(tris.size * 4)
                var o = 0
                for (t in tris.indices step 3) {
                    val a = tris[t]; val b = tris[t + 1]; val c = tris[t + 2]
                    val ab = vCount + edgeIndex[key(a, b)]!!
                    val bc = vCount + edgeIndex[key(b, c)]!!
                    val ca = vCount + edgeIndex[key(c, a)]!!
                    intArrayOf(a, ab, ca, ab, b, bc, ca, bc, c, ab, bc, ca).forEach { newTris[o++] = it }
                }
                // 원래 점 기준 가중치로 합성
                val prev = rows
                rows = newLocal.map { local ->
                    val acc = HashMap<Int, Float>()
                    for ((pv, pw) in local) for ((bv, bw) in prev[pv]) acc.merge(bv, pw * bw, Float::plus)
                    acc
                }
                tris = newTris
                vCount = newLocal.size
            }
            val rowStart = IntArray(vCount + 1)
            val total = rows.sumOf { it.size }
            val cols = IntArray(total); val w = FloatArray(total)
            var k = 0
            rows.forEachIndexed { v, m ->
                rowStart[v] = k
                for ((c, wt) in m) { cols[k] = c; w[k] = wt; k++ }
            }
            rowStart[vCount] = k
            return Subdivision(tris, rowStart, cols, w)
        }
    }
}

/** 렌더링·내보내기용 메시. 좌표는 얼굴 정면 기준으로 맞추고 대략 [-1, 1] 크기입니다. */
class MeshData(val pos: FloatArray, val uv: FloatArray, val normal: FloatArray, val tris: IntArray, val texture: Bitmap?) {
    val count get() = pos.size / 3

    companion object {
        /**
         * points: 얼굴 점 (x, y, z, 사진 기준 0~1). imgW/imgH: 사진 크기.
         * uvRect: 텍스처로 쓰는 사진 영역(픽셀). prevPos 를 주면 프레임 사이 떨림을 줄입니다.
         */
        /** 얼굴 점 468개를 사진 픽셀 좌표(y 위쪽, z 카메라 쪽)로 바꿉니다. */
        fun imageBase(points: FloatArray, imgW: Float, imgH: Float): FloatArray {
            val n = Subdivision.BASE
            val base = FloatArray(n * 3)
            for (i in 0 until n) {
                base[i * 3] = points[i * 3] * imgW
                base[i * 3 + 1] = -points[i * 3 + 1] * imgH
                base[i * 3 + 2] = -points[i * 3 + 2] * imgW
            }
            return base
        }

        /**
         * 얼굴 기준 좌표계로 정면 보정 (오른쪽 눈꼬리 33, 왼쪽 263, 이마 10, 턱 152).
         * 결과는 가운데 정렬, 대략 [-1, 1] 크기. 점 468개만 다루므로 매 프레임 돌려도 가볍습니다.
         */
        fun frontal(base: FloatArray): FloatArray {
            val n = base.size / 3
            fun p(i: Int) = floatArrayOf(base[i * 3], base[i * 3 + 1], base[i * 3 + 2])
            val r = p(33); val l = p(263); val top = p(10); val chin = p(152)
            val ex = norm(sub3(l, r))
            var ey = sub3(top, chin)
            val faceH = len(ey)
            ey = norm(sub3(ey, scale(ex, dot(ey, ex))))
            val ez = cross(ex, ey)
            val c = FloatArray(3)
            for (i in 0 until n) for (k in 0..2) c[k] += base[i * 3 + k] / n
            val s = 2f / (faceH * 1.15f)
            val out = FloatArray(n * 3)
            var meanZ = 0f
            for (i in 0 until n) {
                val d = floatArrayOf(base[i * 3] - c[0], base[i * 3 + 1] - c[1], base[i * 3 + 2] - c[2])
                out[i * 3] = dot(d, ex) * s; out[i * 3 + 1] = dot(d, ey) * s; out[i * 3 + 2] = dot(d, ez) * s
                meanZ += out[i * 3 + 2] / n
            }
            for (i in 0 until n) out[i * 3 + 2] -= meanZ
            return out
        }

        /**
         * frontalBase: 정면 보정된 점 468개 (여러 프레임 평균일 수 있음).
         * imgBase: 텍스처 좌표를 만들 프레임의 사진 좌표 점. uvRect: 텍스처로 쓰는 사진 영역(픽셀).
         */
        fun fromBase(sub: Subdivision, frontalBase: FloatArray, imgBase: FloatArray, uvRect: RectF, texture: Bitmap?): MeshData {
            val v = sub.vCount
            val pos = FloatArray(v * 3); sub.apply(frontalBase, pos)
            val img = FloatArray(v * 3); sub.apply(imgBase, img)
            val uv = FloatArray(v * 2)
            for (i in 0 until v) {
                uv[i * 2] = (img[i * 3] - uvRect.left) / uvRect.width()
                uv[i * 2 + 1] = (-img[i * 3 + 1] - uvRect.top) / uvRect.height()
            }
            return MeshData(pos, uv, normals(pos, sub.tris), sub.tris, texture)
        }

        /** 사진 한 장의 얼굴 점으로 바로 메시를 만듭니다. */
        fun build(sub: Subdivision, points: FloatArray, imgW: Float, imgH: Float, uvRect: RectF, texture: Bitmap?): MeshData {
            val base = imageBase(points, imgW, imgH)
            return fromBase(sub, frontal(base), base, uvRect, texture)
        }

        fun normals(pos: FloatArray, tris: IntArray): FloatArray {
            val nor = FloatArray(pos.size)
            for (t in tris.indices step 3) {
                val a = tris[t] * 3; val b = tris[t + 1] * 3; val c = tris[t + 2] * 3
                val ux = pos[b] - pos[a]; val uy = pos[b + 1] - pos[a + 1]; val uz = pos[b + 2] - pos[a + 2]
                val vx = pos[c] - pos[a]; val vy = pos[c + 1] - pos[a + 1]; val vz = pos[c + 2] - pos[a + 2]
                val nx = uy * vz - uz * vy; val ny = uz * vx - ux * vz; val nz = ux * vy - uy * vx
                for (i in intArrayOf(a, b, c)) { nor[i] += nx; nor[i + 1] += ny; nor[i + 2] += nz }
            }
            for (i in nor.indices step 3) {
                val l = sqrt(nor[i] * nor[i] + nor[i + 1] * nor[i + 1] + nor[i + 2] * nor[i + 2]).coerceAtLeast(1e-9f)
                nor[i] /= l; nor[i + 1] /= l; nor[i + 2] /= l
            }
            return nor
        }

        private fun sub3(a: FloatArray, b: FloatArray) = floatArrayOf(a[0] - b[0], a[1] - b[1], a[2] - b[2])
        private fun dot(a: FloatArray, b: FloatArray) = a[0] * b[0] + a[1] * b[1] + a[2] * b[2]
        private fun scale(a: FloatArray, s: Float) = floatArrayOf(a[0] * s, a[1] * s, a[2] * s)
        private fun len(a: FloatArray) = sqrt(dot(a, a))
        private fun norm(a: FloatArray) = scale(a, 1f / len(a).coerceAtLeast(1e-9f))
        private fun cross(a: FloatArray, b: FloatArray) =
            floatArrayOf(a[1] * b[2] - a[2] * b[1], a[2] * b[0] - a[0] * b[2], a[0] * b[1] - a[1] * b[0])
    }

    fun writeZip(zip: ZipOutputStream) {
        val sb = StringBuilder("# 셀프 점검 앱에서 만든 3D 얼굴 메시\nmtllib face.mtl\n")
        for (i in 0 until count) sb.append(String.format(Locale.US, "v %.5f %.5f %.5f\n", pos[i * 3], pos[i * 3 + 1], pos[i * 3 + 2]))
        for (i in 0 until count) sb.append(String.format(Locale.US, "vt %.5f %.5f\n", uv[i * 2], 1 - uv[i * 2 + 1]))
        for (i in 0 until count) sb.append(String.format(Locale.US, "vn %.4f %.4f %.4f\n", normal[i * 3], normal[i * 3 + 1], normal[i * 3 + 2]))
        sb.append("usemtl face\ns 1\n")
        for (t in tris.indices step 3) {
            val a = tris[t] + 1; val b = tris[t + 1] + 1; val c = tris[t + 2] + 1
            sb.append("f $a/$a/$a $b/$b/$b $c/$c/$c\n")
        }
        zip.putNextEntry(ZipEntry("face.obj")); zip.write(sb.toString().toByteArray()); zip.closeEntry()
        zip.putNextEntry(ZipEntry("face.mtl"))
        zip.write("newmtl face\nKa 1 1 1\nKd 1 1 1\nKs 0.1 0.1 0.1\nNs 30\nmap_Kd face.jpg\n".toByteArray()); zip.closeEntry()
        texture?.let { t ->
            val jpg = ByteArrayOutputStream().also { t.compress(Bitmap.CompressFormat.JPEG, 95, it) }.toByteArray()
            zip.putNextEntry(ZipEntry("face.jpg")); zip.write(jpg); zip.closeEntry()
        }
    }
}

/** 4배 안티앨리어싱(MSAA)을 우선 시도하고, 안 되면 일반 설정으로 내려갑니다. */
class MsaaConfigChooser(private val samples: Int = 4) : GLSurfaceView.EGLConfigChooser {
    override fun chooseConfig(egl: EGL10, display: EGLDisplay): EGLConfig {
        val base = intArrayOf(EGL10.EGL_RED_SIZE, 8, EGL10.EGL_GREEN_SIZE, 8, EGL10.EGL_BLUE_SIZE, 8,
            EGL10.EGL_ALPHA_SIZE, 8, EGL10.EGL_DEPTH_SIZE, 16, EGL10.EGL_RENDERABLE_TYPE, 4)
        val tries = listOf(
            base + intArrayOf(EGL10.EGL_SAMPLE_BUFFERS, 1, EGL10.EGL_SAMPLES, samples, EGL10.EGL_NONE),
            base + intArrayOf(EGL10.EGL_NONE),
        )
        for (attrs in tries) {
            val num = IntArray(1); val cfgs = arrayOfNulls<EGLConfig>(1)
            if (egl.eglChooseConfig(display, attrs, cfgs, 1, num) && num[0] > 0) return cfgs[0]!!
        }
        throw IllegalStateException("OpenGL 설정을 찾지 못했습니다")
    }
}

/** 메시와 배경을 그리는 OpenGL 도구 (GL 스레드에서만 사용). */
class MeshGL {
    companion object {
        const val MODE_TEXTURE = 0
        const val MODE_SHADED = 1
        const val MODE_WIRE = 2
        private const val MODE_BACKGROUND = 3
    }

    private var prog = 0
    var tex = 0; private set
    private var posBuf: FloatBuffer? = null; private var uvBuf: FloatBuffer? = null; private var norBuf: FloatBuffer? = null
    private var triBuf: ShortBuffer? = null; private var lineBuf: ShortBuffer? = null
    private var triCount = 0; private var lineCount = 0
    private var trisRef: IntArray? = null
    private val quadPos = fb(floatArrayOf(-1f, -1f, 0f, 1f, -1f, 0f, -1f, 1f, 0f, 1f, 1f, 0f))
    private val quadUv = fb(FloatArray(8))
    private val identity = FloatArray(16).also { android.opengl.Matrix.setIdentityM(it, 0) }

    private fun fb(a: FloatArray) = ByteBuffer.allocateDirect(a.size * 4).order(ByteOrder.nativeOrder()).asFloatBuffer().apply { put(a); position(0) }
    private fun sb(a: ShortArray) = ByteBuffer.allocateDirect(a.size * 2).order(ByteOrder.nativeOrder()).asShortBuffer().apply { put(a); position(0) }
    private fun fill(buf: FloatBuffer?, a: FloatArray): FloatBuffer =
        (if (buf != null && buf.capacity() == a.size) buf else ByteBuffer.allocateDirect(a.size * 4).order(ByteOrder.nativeOrder()).asFloatBuffer())
            .apply { position(0); put(a); position(0) }

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
            if (uMode == 3) { gl_FragColor = vec4(texture2D(uTex, vUV).rgb, 1.0); return; }
            if (uMode == 2) { gl_FragColor = vec4(0.25, 0.95, 0.75, 1.0); return; }
            vec3 n = normalize(vNor);
            float back = 1.0;
            if (!gl_FrontFacing) { n = -n; back = 0.45; }
            vec3 L = normalize(vec3(0.35, 0.45, 1.0));
            vec3 H = normalize(L + vec3(0.0, 0.0, 1.0));
            float d = max(dot(n, L), 0.0);
            float s = pow(max(dot(n, H), 0.0), 40.0);
            vec3 base = uMode == 0 ? texture2D(uTex, vUV).rgb : vec3(0.87, 0.79, 0.73);
            vec3 c = uMode == 0 ? base * (0.62 + 0.48 * d) + vec3(0.10 * s)
                                : base * (0.22 + 0.80 * d) + vec3(0.25 * s);
            gl_FragColor = vec4(c * back, 1.0);
        }
    """

    private fun shader(type: Int, src: String) = GLES20.glCreateShader(type).also {
        GLES20.glShaderSource(it, src); GLES20.glCompileShader(it)
    }

    fun init() {
        prog = GLES20.glCreateProgram()
        GLES20.glAttachShader(prog, shader(GLES20.GL_VERTEX_SHADER, vs))
        GLES20.glAttachShader(prog, shader(GLES20.GL_FRAGMENT_SHADER, fs))
        GLES20.glLinkProgram(prog)
        val ids = IntArray(1); GLES20.glGenTextures(1, ids, 0); tex = ids[0]
        trisRef = null; posBuf = null; uvBuf = null; norBuf = null
    }

    fun release() {
        if (tex != 0) GLES20.glDeleteTextures(1, intArrayOf(tex), 0)
        if (prog != 0) GLES20.glDeleteProgram(prog)
        tex = 0; prog = 0
    }

    fun uploadTexture(bmp: Bitmap) {
        GLES20.glBindTexture(GLES20.GL_TEXTURE_2D, tex)
        val pot = bmp.width == bmp.height && (bmp.width and (bmp.width - 1)) == 0
        GLUtils.texImage2D(GLES20.GL_TEXTURE_2D, 0, bmp, 0)
        if (pot) {
            GLES20.glGenerateMipmap(GLES20.GL_TEXTURE_2D)
            GLES20.glTexParameteri(GLES20.GL_TEXTURE_2D, GLES20.GL_TEXTURE_MIN_FILTER, GLES20.GL_LINEAR_MIPMAP_LINEAR)
        } else {
            GLES20.glTexParameteri(GLES20.GL_TEXTURE_2D, GLES20.GL_TEXTURE_MIN_FILTER, GLES20.GL_LINEAR)
        }
        GLES20.glTexParameteri(GLES20.GL_TEXTURE_2D, GLES20.GL_TEXTURE_MAG_FILTER, GLES20.GL_LINEAR)
        GLES20.glTexParameteri(GLES20.GL_TEXTURE_2D, GLES20.GL_TEXTURE_WRAP_S, GLES20.GL_CLAMP_TO_EDGE)
        GLES20.glTexParameteri(GLES20.GL_TEXTURE_2D, GLES20.GL_TEXTURE_WRAP_T, GLES20.GL_CLAMP_TO_EDGE)
    }

    fun setMesh(m: MeshData) {
        posBuf = fill(posBuf, m.pos); uvBuf = fill(uvBuf, m.uv); norBuf = fill(norBuf, m.normal)
        if (trisRef !== m.tris) {
            trisRef = m.tris
            triBuf = sb(ShortArray(m.tris.size) { m.tris[it].toShort() }); triCount = m.tris.size
            val edges = LinkedHashSet<Long>()
            for (t in m.tris.indices step 3) for (k in 0..2) {
                val a = m.tris[t + k]; val b = m.tris[t + (k + 1) % 3]
                edges += (minOf(a, b).toLong() shl 32) or maxOf(a, b).toLong()
            }
            val lines = ShortArray(edges.size * 2)
            edges.forEachIndexed { i, e -> lines[i * 2] = (e shr 32).toShort(); lines[i * 2 + 1] = (e and 0xffffffffL).toShort() }
            lineBuf = sb(lines); lineCount = lines.size
        }
    }

    private fun attr(name: String, size: Int, buf: FloatBuffer) {
        val loc = GLES20.glGetAttribLocation(prog, name)
        if (loc < 0) return
        GLES20.glEnableVertexAttribArray(loc)
        GLES20.glVertexAttribPointer(loc, size, GLES20.GL_FLOAT, false, 0, buf)
    }

    private fun begin(mvp: FloatArray, model: FloatArray, mode: Int) {
        GLES20.glUseProgram(prog)
        GLES20.glUniformMatrix4fv(GLES20.glGetUniformLocation(prog, "uMVP"), 1, false, mvp, 0)
        GLES20.glUniformMatrix4fv(GLES20.glGetUniformLocation(prog, "uModel"), 1, false, model, 0)
        GLES20.glUniform1i(GLES20.glGetUniformLocation(prog, "uMode"), mode)
        GLES20.glActiveTexture(GLES20.GL_TEXTURE0)
        GLES20.glBindTexture(GLES20.GL_TEXTURE_2D, tex)
        GLES20.glUniform1i(GLES20.glGetUniformLocation(prog, "uTex"), 0)
    }

    fun drawMesh(mvp: FloatArray, model: FloatArray, mode: Int) {
        val p = posBuf ?: return
        begin(mvp, model, mode)
        attr("aPos", 3, p); attr("aUV", 2, uvBuf!!); attr("aNor", 3, norBuf!!)
        if (mode == MODE_WIRE) GLES20.glDrawElements(GLES20.GL_LINES, lineCount, GLES20.GL_UNSIGNED_SHORT, lineBuf)
        else GLES20.glDrawElements(GLES20.GL_TRIANGLES, triCount, GLES20.GL_UNSIGNED_SHORT, triBuf)
    }

    /** 현재 텍스처를 화면 전체에 그립니다. u0..u1, v0..v1 = 보이는 영역 (위가 v0). */
    fun drawBackground(u0: Float, u1: Float, v0: Float, v1: Float) {
        quadUv.position(0); quadUv.put(floatArrayOf(u0, v1, u1, v1, u0, v0, u1, v0)); quadUv.position(0)
        begin(identity, identity, MODE_BACKGROUND)
        attr("aPos", 3, quadPos); attr("aUV", 2, quadUv)
        val nl = GLES20.glGetAttribLocation(prog, "aNor")
        if (nl >= 0) { GLES20.glDisableVertexAttribArray(nl); GLES20.glVertexAttrib3f(nl, 0f, 0f, 1f) }
        GLES20.glDrawArrays(GLES20.GL_TRIANGLE_STRIP, 0, 4)
    }
}
