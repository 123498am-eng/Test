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
        private val cache = HashMap<Int, Subdivision>()

        /** levels 2: 삼각형 14,368개 (기본), 3: 57,472개 (자세히 보기) */
        fun get(ctx: Context, levels: Int = 2): Subdivision = synchronized(cache) {
            cache.getOrPut(levels) { build(FaceMesh.triangles(ctx), BASE, levels) }
        }

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

    /** 주름·피부 결 맵 (R,G: 굴곡 기울기, B: 높이). 자세히 보기에서만 만듭니다. */
    @Volatile var detail: Bitmap? = null

    /** 노멀 맵용 접선(u 방향)과 종접선(v 방향). */
    val tangents: Pair<FloatArray, FloatArray> by lazy { computeTangents() }

    private fun computeTangents(): Pair<FloatArray, FloatArray> {
        val t = FloatArray(pos.size); val b = FloatArray(pos.size)
        for (k in tris.indices step 3) {
            val i0 = tris[k]; val i1 = tris[k + 1]; val i2 = tris[k + 2]
            val e1x = pos[i1 * 3] - pos[i0 * 3]; val e1y = pos[i1 * 3 + 1] - pos[i0 * 3 + 1]; val e1z = pos[i1 * 3 + 2] - pos[i0 * 3 + 2]
            val e2x = pos[i2 * 3] - pos[i0 * 3]; val e2y = pos[i2 * 3 + 1] - pos[i0 * 3 + 1]; val e2z = pos[i2 * 3 + 2] - pos[i0 * 3 + 2]
            val du1 = uv[i1 * 2] - uv[i0 * 2]; val dv1 = uv[i1 * 2 + 1] - uv[i0 * 2 + 1]
            val du2 = uv[i2 * 2] - uv[i0 * 2]; val dv2 = uv[i2 * 2 + 1] - uv[i0 * 2 + 1]
            val det = du1 * dv2 - du2 * dv1
            if (kotlin.math.abs(det) < 1e-12f) continue
            val r = 1f / det
            val tx = (e1x * dv2 - e2x * dv1) * r; val ty = (e1y * dv2 - e2y * dv1) * r; val tz = (e1z * dv2 - e2z * dv1) * r
            val bx = (e2x * du1 - e1x * du2) * r; val by = (e2y * du1 - e1y * du2) * r; val bz = (e2z * du1 - e1z * du2) * r
            for (i in intArrayOf(i0, i1, i2)) {
                t[i * 3] += tx; t[i * 3 + 1] += ty; t[i * 3 + 2] += tz
                b[i * 3] += bx; b[i * 3 + 1] += by; b[i * 3 + 2] += bz
            }
        }
        for (i in 0 until count) {
            // 법선에 수직이 되도록 정리
            val nx = normal[i * 3]; val ny = normal[i * 3 + 1]; val nz = normal[i * 3 + 2]
            var d = t[i * 3] * nx + t[i * 3 + 1] * ny + t[i * 3 + 2] * nz
            var x = t[i * 3] - nx * d; var y = t[i * 3 + 1] - ny * d; var z = t[i * 3 + 2] - nz * d
            var l = sqrt(x * x + y * y + z * z).coerceAtLeast(1e-9f)
            t[i * 3] = x / l; t[i * 3 + 1] = y / l; t[i * 3 + 2] = z / l
            d = b[i * 3] * nx + b[i * 3 + 1] * ny + b[i * 3 + 2] * nz
            x = b[i * 3] - nx * d; y = b[i * 3 + 1] - ny * d; z = b[i * 3 + 2] - nz * d
            l = sqrt(x * x + y * y + z * z).coerceAtLeast(1e-9f)
            b[i * 3] = x / l; b[i * 3 + 1] = y / l; b[i * 3 + 2] = z / l
        }
        return t to b
    }

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
        const val MODE_PHOTO_ONLY = 4
        private const val MODE_BACKGROUND = 3
    }

    private var prog = 0
    var tex = 0; private set
    private var posBuf: FloatBuffer? = null; private var uvBuf: FloatBuffer? = null; private var norBuf: FloatBuffer? = null
    private var tanBuf: FloatBuffer? = null; private var bitBuf: FloatBuffer? = null
    private var detTex = 0
    /** 주름 강도 (0 = 끔). 자세히 보기 맵이 있을 때만 적용됩니다. */
    @Volatile var detailStrength = 0.6f
    /** 조명 방향 (화면 기준, 오른쪽 x, 위 y, 앞 z) */
    @Volatile var light = floatArrayOf(0.35f, 0.45f, 1f)
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
        attribute vec3 aPos; attribute vec2 aUV; attribute vec3 aNor; attribute vec3 aTan; attribute vec3 aBit;
        varying vec2 vUV; varying vec3 vNor; varying vec3 vTan; varying vec3 vBit;
        void main() {
            mat3 m = mat3(uModel);
            vUV = aUV; vNor = m * aNor; vTan = m * aTan; vBit = m * aBit;
            gl_Position = uMVP * vec4(aPos, 1.0);
        }
    """
    // uMode 0: 사진, 1: 점토(굴곡만), 2: 선, 3: 배경, 4: 사진만(조명·주름 없이)
    private val fs = """
        precision highp float;
        uniform sampler2D uTex; uniform sampler2D uDet; uniform int uMode; uniform int uHasDet;
        uniform float uDetail; uniform vec3 uLight;
        varying vec2 vUV; varying vec3 vNor; varying vec3 vTan; varying vec3 vBit;
        void main() {
            if (uMode == 3 || uMode == 4) { gl_FragColor = vec4(texture2D(uTex, vUV).rgb, 1.0); return; }
            if (uMode == 2) { gl_FragColor = vec4(0.25, 0.95, 0.75, 1.0); return; }
            vec3 n = normalize(vNor);
            float back = 1.0;
            if (!gl_FrontFacing) { n = -n; back = 0.45; }
            float cav = 0.0;
            if (uHasDet == 1 && uDetail > 0.0) {
                // 노멀 맵: 사진에서 뽑은 주름·피부 결을 표면 굴곡으로
                vec4 dm = texture2D(uDet, vUV);
                vec2 g = dm.rg * 2.0 - 1.0;
                vec3 nt = normalize(vec3(-g.x * uDetail * 2.5, -g.y * uDetail * 2.5, 1.0));
                vec3 T = normalize(vTan - n * dot(n, vTan));
                vec3 B = normalize(vBit - n * dot(n, vBit) - T * dot(T, vBit));
                n = normalize(T * nt.x + B * nt.y + n * nt.z);
                cav = clamp((0.5 - dm.b) * 2.0, 0.0, 1.0) * uDetail; // 홈은 조금 더 어둡게
            }
            vec3 L = normalize(uLight);
            vec3 H = normalize(L + vec3(0.0, 0.0, 1.0));
            float d = max(dot(n, L), 0.0);
            float s = pow(max(dot(n, H), 0.0), 40.0);
            float ao = 1.0 - 0.35 * cav;
            vec3 base = uMode == 0 ? texture2D(uTex, vUV).rgb : vec3(0.87, 0.79, 0.73);
            vec3 c = uMode == 0 ? base * (0.62 + 0.48 * d) * ao + vec3(0.10 * s)
                                : base * (0.22 + 0.80 * d) * ao + vec3(0.25 * s);
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
        val ids = IntArray(2); GLES20.glGenTextures(2, ids, 0); tex = ids[0]; detTex = ids[1]
        trisRef = null; posBuf = null; uvBuf = null; norBuf = null; tanBuf = null; bitBuf = null
        hasDetail = false
    }

    private var hasDetail = false

    /** 주름 맵을 올립니다 (자세히 보기). */
    fun uploadDetail(bmp: Bitmap) {
        val keep = tex
        tex = detTex
        uploadTexture(bmp)
        tex = keep
        hasDetail = true
    }

    fun release() {
        if (tex != 0) GLES20.glDeleteTextures(2, intArrayOf(tex, detTex), 0)
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
        if (m.detail != null) { val (t, b) = m.tangents; tanBuf = fill(tanBuf, t); bitBuf = fill(bitBuf, b) }
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
        GLES20.glActiveTexture(GLES20.GL_TEXTURE1)
        GLES20.glBindTexture(GLES20.GL_TEXTURE_2D, detTex)
        GLES20.glUniform1i(GLES20.glGetUniformLocation(prog, "uDet"), 1)
        GLES20.glActiveTexture(GLES20.GL_TEXTURE0)
        val det = hasDetail && tanBuf != null
        GLES20.glUniform1i(GLES20.glGetUniformLocation(prog, "uHasDet"), if (det) 1 else 0)
        GLES20.glUniform1f(GLES20.glGetUniformLocation(prog, "uDetail"), detailStrength)
        GLES20.glUniform3f(GLES20.glGetUniformLocation(prog, "uLight"), light[0], light[1], light[2])
    }

    private fun constAttr(name: String) {
        val loc = GLES20.glGetAttribLocation(prog, name)
        if (loc >= 0) { GLES20.glDisableVertexAttribArray(loc); GLES20.glVertexAttrib3f(loc, 1f, 0f, 0f) }
    }

    fun drawMesh(mvp: FloatArray, model: FloatArray, mode: Int) {
        val p = posBuf ?: return
        begin(mvp, model, mode)
        attr("aPos", 3, p); attr("aUV", 2, uvBuf!!); attr("aNor", 3, norBuf!!)
        val tb = tanBuf; val bb = bitBuf
        if (tb != null && bb != null) { attr("aTan", 3, tb); attr("aBit", 3, bb) } else { constAttr("aTan"); constAttr("aBit") }
        if (mode == MODE_WIRE) GLES20.glDrawElements(GLES20.GL_LINES, lineCount, GLES20.GL_UNSIGNED_SHORT, lineBuf)
        else GLES20.glDrawElements(GLES20.GL_TRIANGLES, triCount, GLES20.GL_UNSIGNED_SHORT, triBuf)
    }

    /** 현재 텍스처를 화면 전체에 그립니다. u0..u1, v0..v1 = 보이는 영역 (위가 v0). */
    fun drawBackground(u0: Float, u1: Float, v0: Float, v1: Float) {
        quadUv.position(0); quadUv.put(floatArrayOf(u0, v1, u1, v1, u0, v0, u1, v0)); quadUv.position(0)
        begin(identity, identity, MODE_BACKGROUND)
        attr("aPos", 3, quadPos); attr("aUV", 2, quadUv); constAttr("aTan"); constAttr("aBit")
        val nl = GLES20.glGetAttribLocation(prog, "aNor")
        if (nl >= 0) { GLES20.glDisableVertexAttribArray(nl); GLES20.glVertexAttrib3f(nl, 0f, 0f, 1f) }
        GLES20.glDrawArrays(GLES20.GL_TRIANGLE_STRIP, 0, 4)
    }
}

/**
 * 사진에서 주름·피부 결 맵을 만듭니다.
 * 큰 명암(조명, 피부색)은 걸러 내고 작은 명암 변화만 남겨 높이로 보고, 그 기울기를 노멀 맵으로 씁니다.
 * 어두운 선(주름)은 홈, 밝은 부분은 솟은 곳으로 표현됩니다.
 */
object DetailMap {
    fun make(tex: Bitmap): Bitmap {
        check(org.opencv.android.OpenCVLoader.initLocal()) { "OpenCV를 불러오지 못했습니다" }
        val cv = org.opencv.core.CvType.CV_32F
        val rgba = org.opencv.core.Mat(); org.opencv.android.Utils.bitmapToMat(tex, rgba)
        val gray = org.opencv.core.Mat(); org.opencv.imgproc.Imgproc.cvtColor(rgba, gray, org.opencv.imgproc.Imgproc.COLOR_RGBA2GRAY)
        val g = org.opencv.core.Mat(); gray.convertTo(g, cv, 1.0 / 255.0)
        val sz = tex.width.toDouble()
        val zero = org.opencv.core.Size(0.0, 0.0)
        val low = org.opencv.core.Mat(); org.opencv.imgproc.Imgproc.GaussianBlur(g, low, zero, sz / 110.0)
        val hp = org.opencv.core.Mat(); org.opencv.core.Core.subtract(g, low, hp)
        val h = org.opencv.core.Mat(); org.opencv.imgproc.Imgproc.GaussianBlur(hp, h, zero, maxOf(0.9, sz / 1000.0)) // 잡티 줄이기
        val mean = org.opencv.core.MatOfDouble(); val std = org.opencv.core.MatOfDouble()
        org.opencv.core.Core.meanStdDev(h, mean, std)
        org.opencv.core.Core.multiply(h, org.opencv.core.Scalar(1.0 / (3.0 * maxOf(std.toArray()[0], 1e-6))), h)
        val gx = org.opencv.core.Mat(); val gy = org.opencv.core.Mat()
        org.opencv.imgproc.Imgproc.Sobel(h, gx, cv, 1, 0, 3)
        org.opencv.imgproc.Imgproc.Sobel(h, gy, cv, 0, 1, 3)
        org.opencv.core.Core.meanStdDev(gx, mean, std); val sx = std.toArray()[0]
        org.opencv.core.Core.meanStdDev(gy, mean, std); val sy = std.toArray()[0]
        val sc = 0.35 / maxOf(sx, sy, 1e-6)
        val r8 = org.opencv.core.Mat(); val g8 = org.opencv.core.Mat(); val b8 = org.opencv.core.Mat()
        gx.convertTo(r8, org.opencv.core.CvType.CV_8U, 127.5 * sc, 127.5)
        gy.convertTo(g8, org.opencv.core.CvType.CV_8U, 127.5 * sc, 127.5)
        h.convertTo(b8, org.opencv.core.CvType.CV_8U, 127.5 * 0.45, 127.5)
        val a8 = org.opencv.core.Mat(h.rows(), h.cols(), org.opencv.core.CvType.CV_8U, org.opencv.core.Scalar(255.0))
        val out = org.opencv.core.Mat()
        org.opencv.core.Core.merge(listOf(r8, g8, b8, a8), out)
        val bmp = Bitmap.createBitmap(tex.width, tex.height, Bitmap.Config.ARGB_8888)
        org.opencv.android.Utils.matToBitmap(out, bmp)
        listOf(rgba, gray, g, low, hp, h, gx, gy, r8, g8, b8, a8, out).forEach { it.release() }
        return bmp
    }
}
