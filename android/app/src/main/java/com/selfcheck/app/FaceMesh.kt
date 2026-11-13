package com.selfcheck.app

import android.content.Context
import android.graphics.Bitmap
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
        return runCatching { make(Delegate.GPU) }.getOrElse { make(Delegate.CPU) }
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

    /** 눈꼬리·이마·턱 점으로 얼굴 방향을 대략 추정합니다 (도 단위, 화면 기준). */
    private fun headAngles(p: FloatArray, w: Float, h: Float): Triple<Float, Float, Float> {
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
