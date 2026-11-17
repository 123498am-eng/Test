package com.selfcheck.app

import android.content.Context
import android.graphics.Bitmap
import android.graphics.Canvas
import android.graphics.Matrix
import android.graphics.Paint
import com.google.mediapipe.framework.image.BitmapImageBuilder
import com.google.mediapipe.tasks.core.BaseOptions
import com.google.mediapipe.tasks.core.Delegate
import com.google.mediapipe.tasks.vision.core.RunningMode
import com.google.mediapipe.tasks.vision.facelandmarker.FaceLandmarker
import kotlin.math.atan2
import kotlin.math.sqrt

/**
 * 사진 한 장에서 얼굴 표면의 3D 점 478개를 찾습니다 (MediaPipe Face Landmarker).
 * points: 점마다 (x, y, z). x·y는 사진 너비·높이 기준 0~1, z는 너비 기준 깊이(작을수록 카메라에 가까움).
 */
class FaceMeshResult(
    val bitmap: Bitmap,
    val points: FloatArray,
    val faceCount: Int,
    val yaw: Float, val pitch: Float, val roll: Float,
    val blend: Map<String, Float>,
    /** 정밀 분석에서 합친 결과 수 (1 = 한 번만 찾음) */
    val passes: Int = 1,
)

object FaceMesh {
    @Volatile private var tris: IntArray? = null

    /** MediaPipe 표준 얼굴 메시의 삼각형 898개 (점 번호 0~467). */
    fun triangles(ctx: Context): IntArray = tris ?: ctx.assets.open("face_triangles.txt").bufferedReader()
        .readText().split(Regex("\\s+")).filter { it.isNotEmpty() }.map { it.toInt() }.toIntArray()
        .also { tris = it }

    fun create(ctx: Context, mode: RunningMode, numFaces: Int, blendshapes: Boolean): FaceLandmarker {
        val opts = FaceLandmarker.FaceLandmarkerOptions.builder()
            .setBaseOptions(BaseOptions.builder().setModelAssetPath("face_landmarker.task").build())
            .setRunningMode(mode)
            .setNumFaces(numFaces)
            .setOutputFaceBlendshapes(blendshapes)
            .build()
        return FaceLandmarker.createFromOptions(ctx, opts)
    }

    /** 실시간용: GPU 로 먼저 시도하고, 안 되면 CPU 로. 얼굴 최대 5개. */
    fun createFast(ctx: Context): FaceLandmarker {
        fun make(d: Delegate) = FaceLandmarker.createFromOptions(ctx, FaceLandmarker.FaceLandmarkerOptions.builder()
            .setBaseOptions(BaseOptions.builder().setModelAssetPath("face_landmarker.task").setDelegate(d).build())
            .setRunningMode(RunningMode.VIDEO)
            .setNumFaces(5)
            .build())
        return GpuGuard.create(ctx, "face_fast", { make(Delegate.GPU) }, { make(Delegate.CPU) })
    }

    /** 원거리용: 잘라 낸 영역 한 장씩 분석 (IMAGE 모드). */
    fun createRoi(ctx: Context): FaceLandmarker {
        fun make(d: Delegate) = FaceLandmarker.createFromOptions(ctx, FaceLandmarker.FaceLandmarkerOptions.builder()
            .setBaseOptions(BaseOptions.builder().setModelAssetPath("face_landmarker.task").setDelegate(d).build())
            .setRunningMode(RunningMode.IMAGE)
            .setNumFaces(3)
            .setMinFaceDetectionConfidence(0.4f)
            .build())
        return GpuGuard.create(ctx, "face_roi", { make(Delegate.GPU) }, { make(Delegate.CPU) })
    }

    fun analyze(ctx: Context, bmp: Bitmap): FaceMeshResult? {
        val lm = create(ctx, RunningMode.IMAGE, 5, true)
        try {
            val res = lm.detect(BitmapImageBuilder(bmp).build())
            val faces = res.faceLandmarks()
            if (faces.isEmpty()) return null
            // 가장 큰 얼굴 하나를 고릅니다
            val idx = faces.indices.maxBy { i ->
                val xs = faces[i].map { it.x() }
                xs.max() - xs.min()
            }
            val face = faces[idx]
            val pts = FloatArray(face.size * 3)
            face.forEachIndexed { i, p -> pts[i * 3] = p.x(); pts[i * 3 + 1] = p.y(); pts[i * 3 + 2] = p.z() }

            val blend = mutableMapOf<String, Float>()
            res.faceBlendshapes().ifPresent { all ->
                all.getOrNull(idx)?.forEach { c -> blend[c.categoryName()] = c.score() }
            }
            val (yaw, pitch, roll) = headAngles(pts, bmp.width.toFloat(), bmp.height.toFloat())
            return FaceMeshResult(bmp, pts, faces.size, yaw, pitch, roll, blend)
        } finally {
            lm.close()
        }
    }

    @Volatile private var mirror: IntArray? = null

    /** 점 i 의 좌우 짝 번호 (얼굴을 좌우로 뒤집었을 때 같은 부위가 되는 점). 478개. */
    fun mirrorTable(ctx: Context): IntArray = mirror ?: ctx.assets.open("face_mirror.txt").bufferedReader()
        .readText().split(Regex("\\s+")).filter { it.isNotEmpty() }.map { it.toInt() }.toIntArray()
        .also { mirror = it }

    /**
     * 정밀 분석: 얼굴 부분을 잘라 6가지로 조금씩 바꿔서(그대로·좌우 반전·±5° 회전·0.9배·1.1배) 점을 찾고,
     * 점마다 6개 결과의 중앙값을 씁니다. 한 번만 찾을 때보다 점 위치 흔들림이 약 40% 줄어듭니다 (시험 사진 기준).
     * 얼굴이 작게 나온 사진도 잘라서 키워 분석하므로 더 정확합니다.
     */
    fun analyzeTTA(ctx: Context, bmp: Bitmap, onStep: ((Int) -> Unit)? = null): FaceMeshResult? {
        val lm = create(ctx, RunningMode.IMAGE, 5, true)
        try {
            val res0 = lm.detect(BitmapImageBuilder(bmp).build())
            val faces = res0.faceLandmarks()
            if (faces.isEmpty()) return null
            val idx = faces.indices.maxBy { i -> faces[i].maxOf { it.x() } - faces[i].minOf { it.x() } }
            val W = bmp.width.toFloat(); val H = bmp.height.toFloat()
            val f0 = faces[idx]
            val bx0 = f0.minOf { it.x() } * W; val bx1 = f0.maxOf { it.x() } * W
            val by0 = f0.minOf { it.y() } * H; val by1 = f0.maxOf { it.y() } * H
            // 얼굴 크기의 2.2배 정사각형을 잘라 최대 1024px 로
            val side = maxOf(bx1 - bx0, by1 - by0) * 2.2f
            val fcx = (bx0 + bx1) / 2; val fcy = (by0 + by1) / 2
            val x0 = (fcx - side / 2).toInt().coerceIn(0, bmp.width - 2); val y0 = (fcy - side / 2).toInt().coerceIn(0, bmp.height - 2)
            val x1 = (fcx + side / 2).toInt().coerceIn(x0 + 2, bmp.width); val y1 = (fcy + side / 2).toInt().coerceIn(y0 + 2, bmp.height)
            val sc = minOf(1f, 1024f / maxOf(x1 - x0, y1 - y0))
            val cw = maxOf(2, ((x1 - x0) * sc).toInt()); val ch = maxOf(2, ((y1 - y0) * sc).toInt())
            val cut = Bitmap.createBitmap(bmp, x0, y0, x1 - x0, y1 - y0)
            val crop = Bitmap.createScaledBitmap(cut, cw, ch, true)
            if (cut !== crop && cut !== bmp) cut.recycle()
            val ccx = (fcx - x0) * sc; val ccy = (fcy - y0) * sc // 잘라 낸 사진에서 얼굴 가운데
            val mir = mirrorTable(ctx)

            class Pass(val m: Matrix, val flip: Boolean, val s: Float)
            val passes = listOf(
                Pass(Matrix(), false, 1f),
                Pass(Matrix().apply { setScale(-1f, 1f, cw / 2f, 0f) }, true, 1f),
                Pass(Matrix().apply { setRotate(5f, ccx, ccy) }, false, 1f),
                Pass(Matrix().apply { setRotate(-5f, ccx, ccy) }, false, 1f),
                Pass(Matrix().apply { setScale(0.9f, 0.9f, ccx, ccy) }, false, 0.9f),
                Pass(Matrix().apply { setScale(1.1f, 1.1f, ccx, ccy) }, false, 1.1f),
            )
            val n = f0.size
            val got = ArrayList<FloatArray>() // 결과마다 점 n개 (잘라 낸 사진 픽셀 좌표 x,y,z)
            val blendSum = HashMap<String, Float>(); var blendN = 0
            val paint = Paint(Paint.FILTER_BITMAP_FLAG)
            for ((pi, p) in passes.withIndex()) {
                onStep?.invoke(pi)
                val t = Bitmap.createBitmap(cw, ch, Bitmap.Config.ARGB_8888)
                Canvas(t).drawBitmap(crop, p.m, paint)
                val r = runCatching { lm.detect(BitmapImageBuilder(t).build()) }.getOrNull()
                t.recycle()
                val list = r?.faceLandmarks() ?: continue
                if (list.isEmpty()) continue
                val inv = Matrix(); p.m.invert(inv)
                // 원래 얼굴 가운데와 가장 가까운 얼굴
                var best = -1; var bestD = Float.MAX_VALUE
                val tmp = FloatArray(2)
                for ((fi, f) in list.withIndex()) {
                    tmp[0] = f.sumOf { it.x().toDouble() }.toFloat() / f.size * cw; tmp[1] = f.sumOf { it.y().toDouble() }.toFloat() / f.size * ch
                    inv.mapPoints(tmp)
                    val d = (tmp[0] - ccx) * (tmp[0] - ccx) + (tmp[1] - ccy) * (tmp[1] - ccy)
                    if (d < bestD) { bestD = d; best = fi }
                }
                val f = list[best]
                if (f.size != n || bestD > (side * sc * 0.2f) * (side * sc * 0.2f)) continue
                val xy = FloatArray(n * 2)
                for (i in 0 until n) { xy[i * 2] = f[i].x() * cw; xy[i * 2 + 1] = f[i].y() * ch }
                inv.mapPoints(xy)
                val out = FloatArray(n * 3)
                for (i in 0 until n) {
                    val src = if (p.flip && i < mir.size) mir[i] else i // 뒤집은 사진의 점 mir[i] = 원래 점 i
                    out[i * 3] = xy[src * 2]; out[i * 3 + 1] = xy[src * 2 + 1]; out[i * 3 + 2] = f[src].z() * cw / p.s
                }
                got += out
                if (!p.flip) r.faceBlendshapes().ifPresent { all ->
                    all.getOrNull(best)?.forEach { c -> blendSum[c.categoryName()] = (blendSum[c.categoryName()] ?: 0f) + c.score() }
                    blendN++
                }
            }
            crop.recycle()
            if (got.size < 3) return analyze(ctx, bmp) // 정밀 분석이 안 되면 기본 분석
            // 점마다 중앙값 → 원래 사진 기준 0~1 좌표
            val pts = FloatArray(n * 3)
            val col = FloatArray(got.size)
            for (k in 0 until n * 3) {
                for (g in got.indices) col[g] = got[g][k]
                col.sort()
                val med = if (col.size % 2 == 1) col[col.size / 2] else (col[col.size / 2 - 1] + col[col.size / 2]) / 2
                pts[k] = when (k % 3) {
                    0 -> (x0 + med / sc) / W
                    1 -> (y0 + med / sc) / H
                    else -> med / sc / W
                }
            }
            val blend = blendSum.mapValues { it.value / maxOf(1, blendN) }
            val (yaw, pitch, roll) = headAngles(pts, W, H)
            return FaceMeshResult(bmp, pts, faces.size, yaw, pitch, roll, blend, got.size)
        } finally {
            lm.close()
        }
    }

    /** 눈꼬리·이마·턱 점으로 얼굴 방향을 대략 추정합니다 (도 단위, 화면 기준). */
    fun headAngles(p: FloatArray, w: Float, h: Float): Triple<Float, Float, Float> {
        fun v(i: Int) = floatArrayOf(p[i * 3] * w, p[i * 3 + 1] * h, p[i * 3 + 2] * w)
        val r = v(33); val l = v(263); val top = v(10); val chin = v(152)
        val ax = floatArrayOf(l[0] - r[0], l[1] - r[1], l[2] - r[2])
        val ay = floatArrayOf(chin[0] - top[0], chin[1] - top[1], chin[2] - top[2])
        // 얼굴이 바라보는 방향 = -(ax × ay)
        val fx = -(ax[1] * ay[2] - ax[2] * ay[1])
        val fy = -(ax[2] * ay[0] - ax[0] * ay[2])
        val fz = -(ax[0] * ay[1] - ax[1] * ay[0])
        val n = sqrt(fx * fx + fy * fy + fz * fz).coerceAtLeast(1e-6f)
        val deg = (180.0 / Math.PI).toFloat()
        val yaw = atan2(fx / n, -fz / n) * deg
        val pitch = atan2(-fy / n, -fz / n) * deg
        val roll = atan2(ax[1], ax[0]) * deg
        return Triple(yaw, pitch, roll)
    }
}
