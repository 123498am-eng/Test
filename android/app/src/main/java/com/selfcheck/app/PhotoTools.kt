package com.selfcheck.app

import android.content.Context
import android.graphics.Bitmap
import android.graphics.Canvas
import android.graphics.Color
import android.graphics.Paint
import android.graphics.RectF
import android.graphics.Typeface
import com.google.android.gms.tasks.Tasks
import com.google.mediapipe.framework.image.BitmapImageBuilder
import com.google.mediapipe.tasks.vision.core.RunningMode
import com.google.mlkit.vision.common.InputImage
import com.google.mlkit.vision.text.TextRecognition
import com.google.mlkit.vision.text.korean.KoreanTextRecognizerOptions
import org.opencv.android.OpenCVLoader
import org.opencv.android.Utils
import org.opencv.core.Core
import org.opencv.core.CvType
import org.opencv.core.Mat
import org.opencv.core.MatOfPoint
import org.opencv.core.MatOfPoint2f
import org.opencv.core.Point
import org.opencv.core.Rect
import org.opencv.core.Scalar
import org.opencv.core.Size
import org.opencv.core.TermCriteria
import org.opencv.imgproc.Imgproc
import org.opencv.photo.Photo
import kotlin.math.abs
import kotlin.math.atan2
import kotlin.math.hypot
import kotlin.math.max
import kotlin.math.min
import kotlin.math.pow
import kotlin.math.roundToInt
import kotlin.math.sqrt

/** 사진 도구에 넘기는 값 */
class ToolCtx(
    val ctx: Context,
    val src: Bitmap,
    val option: Int,
    val value: Int,
    val text: String,
    /** 가장 큰 얼굴의 점 478개 (픽셀 x,y) — 처음 부를 때 한 번만 계산 */
    val face: () -> FloatArray?,
    /** 사진 속 모든 얼굴 */
    val faces: () -> List<FloatArray>,
    val exifInfo: () -> String,
)

class ToolOut(val bitmap: Bitmap?, val text: String? = null, val jpeg: Int = 0)

class PhotoTool(
    val id: String, val title: String, val desc: String,
    val options: List<String> = emptyList(),
    val param: String? = null, val paramDefault: Int = 50,
    val textHint: String? = null,
    val run: (ToolCtx) -> ToolOut,
)

/** OpenCV 보조 함수 */
object Cv {
    fun init() = check(OpenCVLoader.initLocal()) { "OpenCV를 불러오지 못했습니다" }
    fun rgb(b: Bitmap): Mat { val m = Mat(); Utils.bitmapToMat(b, m); val r = Mat(); Imgproc.cvtColor(m, r, Imgproc.COLOR_RGBA2RGB); m.release(); return r }
    fun bmp(m: Mat): Bitmap {
        val rgba = Mat()
        when (m.channels()) { 1 -> Imgproc.cvtColor(m, rgba, Imgproc.COLOR_GRAY2RGBA); 3 -> Imgproc.cvtColor(m, rgba, Imgproc.COLOR_RGB2RGBA); else -> m.copyTo(rgba) }
        val b = Bitmap.createBitmap(rgba.cols(), rgba.rows(), Bitmap.Config.ARGB_8888); Utils.matToBitmap(rgba, b); rgba.release(); return b
    }
    fun poly(w: Int, h: Int, q: FloatArray, idx: IntArray, ox: Float = 0f, oy: Float = 0f): Mat {
        val m = Mat.zeros(h, w, CvType.CV_8U)
        val pts = idx.map { Point((q[it * 2] - ox).toDouble(), (q[it * 2 + 1] - oy).toDouble()) }
        Imgproc.fillConvexPoly(m, MatOfPoint(*SkinCore.hull(pts).toTypedArray()), Scalar(255.0)); return m
    }
    /** 0/255 마스크 → 0~1 부드러운 마스크 (CV_32F) */
    fun soft(m: Mat, sigma: Double): Mat { val f = Mat(); m.convertTo(f, CvType.CV_32F, 1 / 255.0); if (sigma > 0.3) Imgproc.GaussianBlur(f, f, Size(0.0, 0.0), sigma); return f }
    /** a + (b - a)·mask·alpha (a, b: RGB 8비트, mask: 0~1) */
    fun mix(a: Mat, b: Mat, mask: Mat, alpha: Double): Mat {
        val fa = Mat(); val fb = Mat(); a.convertTo(fa, CvType.CV_32FC3); b.convertTo(fb, CvType.CV_32FC3)
        val m3 = Mat(); Core.merge(listOf(mask, mask, mask), m3)
        Core.subtract(fb, fa, fb); Core.multiply(fb, m3, fb); Core.scaleAdd(fb, alpha, fa, fa)
        val out = Mat(); fa.convertTo(out, CvType.CV_8UC3); listOf(fa, fb, m3).forEach { it.release() }; return out
    }
    fun box(q: FloatArray, n: Int = 468): RectF {
        var x0 = Float.MAX_VALUE; var y0 = Float.MAX_VALUE; var x1 = -Float.MAX_VALUE; var y1 = -Float.MAX_VALUE
        for (i in 0 until min(n, q.size / 2)) { x0 = min(x0, q[i * 2]); x1 = max(x1, q[i * 2]); y0 = min(y0, q[i * 2 + 1]); y1 = max(y1, q[i * 2 + 1]) }
        return RectF(x0, y0, x1, y1)
    }
    /** 얼굴 주변 영역 (얼굴 크기의 margin 배만큼 넓힘), 사진 안으로 자름 */
    fun roi(q: FloatArray, w: Int, h: Int, margin: Float): Rect {
        val b = box(q); val mw = b.width() * margin; val mh = b.height() * margin
        val x0 = (b.left - mw).toInt().coerceIn(0, w - 2); val y0 = (b.top - mh).toInt().coerceIn(0, h - 2)
        val x1 = (b.right + mw).toInt().coerceIn(x0 + 2, w); val y1 = (b.bottom + mh).toInt().coerceIn(y0 + 2, h)
        return Rect(x0, y0, x1 - x0, y1 - y0)
    }
    fun iod(q: FloatArray) = hypot(q[263 * 2] - q[33 * 2], q[263 * 2 + 1] - q[33 * 2 + 1])
    fun scaleTo(b: Bitmap, maxSide: Int): Bitmap {
        val s = maxSide.toFloat() / max(b.width, b.height)
        return if (s >= 1f) b else Bitmap.createScaledBitmap(b, (b.width * s).toInt().coerceAtLeast(1), (b.height * s).toInt().coerceAtLeast(1), true)
    }
}

/** 사진 속 얼굴 찾기 (큰 사진은 원래 해상도 조각으로도 찾아 작은 얼굴까지) */
object Faces {
    fun all(ctx: Context, bmp: Bitmap): List<FloatArray> {
        val lm = FaceMesh.create(ctx, RunningMode.IMAGE, 10, false)
        try {
            val out = ArrayList<FloatArray>()
            fun iou(a: RectF, b: RectF): Float {
                val ix = max(0f, min(a.right, b.right) - max(a.left, b.left)); val iy = max(0f, min(a.bottom, b.bottom) - max(a.top, b.top))
                val inter = ix * iy; return inter / (a.width() * a.height() + b.width() * b.height() - inter + 1e-3f)
            }
            fun scan(b: Bitmap, ox: Float, oy: Float, k: Float) {
                for (f in lm.detect(BitmapImageBuilder(b).build()).faceLandmarks()) {
                    val q = FloatArray(f.size * 2)
                    f.forEachIndexed { i, p -> q[i * 2] = ox + p.x() * b.width * k; q[i * 2 + 1] = oy + p.y() * b.height * k }
                    val bq = Cv.box(q)
                    if (out.none { iou(Cv.box(it), bq) > 0.3f }) out += q
                }
            }
            val big = max(bmp.width, bmp.height)
            val small = Cv.scaleTo(bmp, 1600)
            scan(small, 0f, 0f, bmp.width.toFloat() / small.width)
            if (big > 1600) {
                val tw = (bmp.width * 0.6f).toInt(); val th = (bmp.height * 0.6f).toInt()
                for (ty in listOf(0, bmp.height - th)) for (tx in listOf(0, bmp.width - tw)) {
                    val tile = Bitmap.createBitmap(bmp, tx, ty, tw, th)
                    val ts = Cv.scaleTo(tile, 1600)
                    scan(ts, tx.toFloat(), ty.toFloat(), tw.toFloat() / ts.width)
                    if (ts !== tile) ts.recycle(); tile.recycle()
                }
            }
            return out
        } finally { lm.close() }
    }

    fun largest(ctx: Context, bmp: Bitmap): FloatArray? {
        val r = FaceMesh.analyze(ctx, bmp) ?: return null
        val n = r.points.size / 3
        return FloatArray(n * 2) { i -> if (i % 2 == 0) r.points[(i / 2) * 3] * bmp.width else r.points[(i / 2) * 3 + 1] * bmp.height }
    }
}

object PhotoTools {
    private fun needFace(t: ToolCtx): FloatArray = t.face() ?: throw IllegalStateException("얼굴을 찾지 못했습니다. 얼굴이 잘 보이는 사진을 써 주세요.")

    // ---------------- 얼굴 보정
    private fun skinSmooth(t: ToolCtx): ToolOut {
        Cv.init(); val q = needFace(t)
        val r = Cv.roi(q, t.src.width, t.src.height, 0.25f)
        val img = Cv.rgb(t.src); val roi = img.submat(r)
        val roiBmp = Bitmap.createBitmap(t.src, r.x, r.y, r.width, r.height)
        val prob = Segment.one(t.ctx, roiBmp, 3) ?: Cv.soft(Cv.poly(r.width, r.height, q, FaceIdx.OVAL, r.x.toFloat(), r.y.toFloat()), 0.0)
        val iod = Cv.iod(q)
        val keep = Mat.zeros(r.height, r.width, CvType.CV_8U)
        for (idx in listOf(FaceIdx.EYE_A, FaceIdx.EYE_B, FaceIdx.BROW_A, FaceIdx.BROW_B, FaceIdx.LIPS)) {
            val p = Cv.poly(r.width, r.height, q, idx, r.x.toFloat(), r.y.toFloat()); Core.bitwise_or(keep, p, keep); p.release()
        }
        Imgproc.dilate(keep, keep, Imgproc.getStructuringElement(Imgproc.MORPH_ELLIPSE, Size(iod * 0.06 + 1, iod * 0.06 + 1)))
        val mask = Mat(); Imgproc.threshold(prob, mask, 0.5, 1.0, Imgproc.THRESH_BINARY)
        val keepF = Cv.soft(keep, 0.0); Core.subtract(mask, keepF, mask); Core.max(mask, Scalar(0.0), mask)
        Imgproc.GaussianBlur(mask, mask, Size(0.0, 0.0), max(1.0, iod * 0.025))
        val roiC = roi.clone()
        val sm = Mat(); Photo.edgePreservingFilter(roiC, sm, Photo.RECURS_FILTER, (iod * 0.12f).coerceIn(15f, 200f), 0.18f + 0.25f * t.value / 100f)
        // 결(아주 작은 무늬)은 조금 남겨 플라스틱처럼 보이지 않게: sm + 0.35·(원본 - 살짝 흐린 원본), 음수도 살리려고 실수로 계산
        val fr = Mat(); roiC.convertTo(fr, CvType.CV_32FC3)
        val bl = Mat(); Imgproc.GaussianBlur(fr, bl, Size(0.0, 0.0), 1.0)
        val fine = Mat(); Core.subtract(fr, bl, fine)
        val smf = Mat(); sm.convertTo(smf, CvType.CV_32FC3); Core.scaleAdd(fine, 0.35, smf, smf); smf.convertTo(sm, CvType.CV_8UC3)
        val out = Cv.mix(roiC, sm, mask, (0.35 + 0.65 * t.value / 100.0))
        listOf(roiC, fr, smf).forEach { it.release() }
        out.copyTo(roi)
        return ToolOut(Cv.bmp(img)).also { listOf(img, out, sm, fine, bl, mask, keep, keepF, prob).forEach { it.release() } }
    }

    private fun spotRemove(t: ToolCtx): ToolOut {
        Cv.init(); val q = needFace(t)
        val pts = FloatArray(q.size / 2 * 3) { i -> when (i % 3) { 0 -> q[(i / 3) * 2] / t.src.width; 1 -> q[(i / 3) * 2 + 1] / t.src.height; else -> 0f } }
        val f = SkinAnalysis.analyze(t.ctx, t.src, pts, 0f)
        val img = Cv.rgb(t.src)
        val mask = Mat.zeros(img.rows(), img.cols(), CvType.CV_8U)
        val k = 1f / f.scale
        val grow = 1.3f + t.value / 100f
        var n = 0
        for (s in f.res.spots) { Imgproc.circle(mask, Point((f.x0 + s[0] * k).toDouble(), (f.y0 + s[1] * k).toDouble()), ((s[2] * grow + 2) * k).roundToInt(), Scalar(255.0), -1); n++ }
        if (t.option == 1) for (i in f.res.pores) { Imgproc.circle(mask, Point((f.x0 + (i % f.res.w) * k).toDouble(), (f.y0 + (i / f.res.w) * k).toDouble()), (2.2f * k).roundToInt().coerceAtLeast(2), Scalar(255.0), -1); n++ }
        if (n == 0) return ToolOut(t.src, "지울 잡티를 찾지 못했습니다")
        val out = Mat(); Photo.inpaint(img, mask, out, 3.0 * k, Photo.INPAINT_TELEA)
        return ToolOut(Cv.bmp(out), "잡티 ${f.res.spots.size}개" + (if (t.option == 1) ", 모공 ${f.res.pores.size}개" else "") + "를 지웠습니다").also { listOf(img, mask, out).forEach { it.release() } }
    }

    private fun teethWhiten(t: ToolCtx): ToolOut {
        Cv.init(); val q = needFace(t)
        val r = Cv.roi(q, t.src.width, t.src.height, 0.05f)
        val img = Cv.rgb(t.src); val roi = img.submat(r)
        val mouth = Cv.poly(r.width, r.height, q, FaceIdx.MOUTH_IN, r.x.toFloat(), r.y.toFloat())
        if (Core.countNonZero(mouth) < 30) return ToolOut(t.src, "입이 다물려 있어 이가 보이지 않습니다")
        val lab = Mat(); Imgproc.cvtColor(roi, lab, Imgproc.COLOR_RGB2Lab)
        val n = r.width * r.height
        val lb = ByteArray(n * 3); lab.get(0, 0, lb); val mb = ByteArray(n); mouth.get(0, 0, mb)
        var sum = 0.0; var c = 0
        for (i in 0 until n) if (mb[i].toInt() != 0) { sum += lb[i * 3].toInt() and 255; c++ }
        val meanL = sum / max(1, c)
        val teeth = Mat.zeros(r.height, r.width, CvType.CV_8U); val tb = ByteArray(n)
        for (i in 0 until n) if (mb[i].toInt() != 0) {
            val l = lb[i * 3].toInt() and 255; val a = (lb[i * 3 + 1].toInt() and 255) - 128
            if (l > meanL - 5 && a < 18) tb[i] = 255.toByte() // 밝고 붉지 않은 곳 = 이
        }
        teeth.put(0, 0, tb)
        val m = Cv.soft(teeth, max(1.0, Cv.iod(q) * 0.006)); val mf = SkinCore.floats(m)
        val s = t.value / 100f
        for (i in 0 until n) {
            val w = mf[i] * s; if (w < 0.01f) continue
            val l = (lb[i * 3].toInt() and 255).toFloat(); val a = (lb[i * 3 + 1].toInt() and 255) - 128f; val b = (lb[i * 3 + 2].toInt() and 255) - 128f
            lb[i * 3] = (l + 22f * w).coerceIn(0f, 255f).toInt().toByte()
            lb[i * 3 + 1] = (128 + a * (1 - 0.4f * w)).toInt().coerceIn(0, 255).toByte()
            lb[i * 3 + 2] = (128 + b * (1 - 0.85f * w)).toInt().coerceIn(0, 255).toByte()
        }
        lab.put(0, 0, lb); Imgproc.cvtColor(lab, roi, Imgproc.COLOR_Lab2RGB)
        return ToolOut(Cv.bmp(img)).also { listOf(img, lab, mouth, teeth, m).forEach { it.release() } }
    }

    /** 점 c 주변 반지름 R 안을 부풀리거나(+) 끌어당기는 변형 */
    private fun warp(img: Mat, region: Rect, field: (Float, Float) -> Pair<Float, Float>) {
        val w = region.width; val h = region.height
        val mx = FloatArray(w * h); val my = FloatArray(w * h)
        for (y in 0 until h) for (x in 0 until w) {
            val (sx, sy) = field((region.x + x).toFloat(), (region.y + y).toFloat())
            mx[y * w + x] = sx; my[y * w + x] = sy
        }
        val sub = img.submat(region)
        // 원본 전체에서 읽어 영역 크기 결과를 만든 뒤 덮어씀 (읽는 동안 원본은 바뀌지 않음)
        val out = Mat(); Imgproc.remap(img, out, SkinCore.fmat(mx, w, h), SkinCore.fmat(my, w, h), Imgproc.INTER_LINEAR, Core.BORDER_REPLICATE)
        out.copyTo(sub); out.release()
    }

    private fun eyeEnlarge(t: ToolCtx): ToolOut {
        Cv.init(); val q = needFace(t)
        val img = Cv.rgb(t.src)
        val a = 0.05f + 0.22f * t.value / 100f
        for ((p0, p1) in listOf(33 to 133, 362 to 263)) {
            val cx = (q[p0 * 2] + q[p1 * 2]) / 2; val cy = (q[p0 * 2 + 1] + q[p1 * 2 + 1]) / 2
            val rad = hypot(q[p1 * 2] - q[p0 * 2], q[p1 * 2 + 1] - q[p0 * 2 + 1]) * 1.05f
            val reg = Rect((cx - rad).toInt().coerceAtLeast(0), (cy - rad).toInt().coerceAtLeast(0), 1, 1)
            reg.width = ((cx + rad).toInt() - reg.x).coerceIn(1, img.cols() - reg.x); reg.height = ((cy + rad).toInt() - reg.y).coerceIn(1, img.rows() - reg.y)
            warp(img, reg) { x, y ->
                val dx = x - cx; val dy = y - cy; val d2 = (dx * dx + dy * dy) / (rad * rad)
                if (d2 >= 1f) x to y else { val k = 1 - a * (1 - d2) * (1 - d2); (cx + dx * k) to (cy + dy * k) }
            }
        }
        return ToolOut(Cv.bmp(img)).also { img.release() }
    }

    private fun faceSlim(t: ToolCtx): ToolOut {
        Cv.init(); val q = needFace(t)
        val img = Cv.rgb(t.src)
        val cx = q[1 * 2]; val cy = (q[1 * 2 + 1] + q[152 * 2 + 1]) / 2 // 코끝과 턱 사이
        val iod = Cv.iod(q)
        val rad = iod * 0.45f
        val str = 0.02f + 0.1f * t.value / 100f
        // 아래턱선 점들을 얼굴 가운데 쪽으로 (위쪽 두 점은 약하게)
        val ctrl = ArrayList<FloatArray>()
        for (idx in listOf(FaceIdx.JAW_A, FaceIdx.JAW_B)) for ((j, i) in idx.withIndex()) {
            val px = q[i * 2]; val py = q[i * 2 + 1]
            val k = if (j < 2) 0.5f else 1f
            ctrl += floatArrayOf(px, py, (cx - px) * str * k, (cy - py) * str * k * 0.4f)
        }
        val reg = Cv.roi(q, img.cols(), img.rows(), 0.15f)
        warp(img, reg) { x, y ->
            var sx = x; var sy = y
            for (c in ctrl) {
                val dx = x - c[0]; val dy = y - c[1]; val d2 = dx * dx + dy * dy
                if (d2 >= rad * rad) continue
                val m2 = c[2] * c[2] + c[3] * c[3]
                val wgt = ((rad * rad - d2) / (rad * rad - d2 + m2)).pow(2)
                sx -= wgt * c[2]; sy -= wgt * c[3]
            }
            sx to sy
        }
        return ToolOut(Cv.bmp(img)).also { img.release() }
    }

    private val LIP_COLORS = listOf(Triple(220, 70, 105), Triple(240, 105, 85), Triple(195, 25, 40), Triple(135, 40, 80), Triple(205, 125, 115))
    private fun lipTint(t: ToolCtx): ToolOut {
        Cv.init(); val q = needFace(t)
        val r = Cv.roi(q, t.src.width, t.src.height, 0.05f)
        val img = Cv.rgb(t.src); val roi = img.submat(r)
        val outer = Mat.zeros(r.height, r.width, CvType.CV_8U)
        Imgproc.fillPoly(outer, listOf(MatOfPoint(*FaceIdx.LIPS.map { Point((q[it * 2] - r.x).toDouble(), (q[it * 2 + 1] - r.y).toDouble()) }.toTypedArray())), Scalar(255.0))
        val inner = Mat.zeros(r.height, r.width, CvType.CV_8U)
        Imgproc.fillPoly(inner, listOf(MatOfPoint(*FaceIdx.MOUTH_IN.map { Point((q[it * 2] - r.x).toDouble(), (q[it * 2 + 1] - r.y).toDouble()) }.toTypedArray())), Scalar(255.0))
        Core.subtract(outer, inner, outer)
        val m = Cv.soft(outer, max(1.0, Cv.iod(q) * 0.008))
        val (cr, cg, cb) = LIP_COLORS[t.option.coerceIn(0, LIP_COLORS.size - 1)]
        val tgt = Mat(1, 1, CvType.CV_8UC3, Scalar(cr.toDouble(), cg.toDouble(), cb.toDouble())); val tl = Mat(); Imgproc.cvtColor(tgt, tl, Imgproc.COLOR_RGB2Lab)
        val tv = ByteArray(3); tl.get(0, 0, tv)
        val ta = (tv[1].toInt() and 255).toFloat(); val tbb = (tv[2].toInt() and 255).toFloat()
        val lab = Mat(); Imgproc.cvtColor(roi, lab, Imgproc.COLOR_RGB2Lab)
        val n = r.width * r.height; val lb = ByteArray(n * 3); lab.get(0, 0, lb); val mf = SkinCore.floats(m)
        val s = t.value / 100f
        for (i in 0 until n) {
            val w = mf[i] * s; if (w < 0.01f) continue
            lb[i * 3 + 1] = ((lb[i * 3 + 1].toInt() and 255) + (ta - (lb[i * 3 + 1].toInt() and 255)) * w).toInt().coerceIn(0, 255).toByte()
            lb[i * 3 + 2] = ((lb[i * 3 + 2].toInt() and 255) + (tbb - (lb[i * 3 + 2].toInt() and 255)) * w).toInt().coerceIn(0, 255).toByte()
        }
        lab.put(0, 0, lb); Imgproc.cvtColor(lab, roi, Imgproc.COLOR_Lab2RGB)
        return ToolOut(Cv.bmp(img)).also { listOf(img, outer, inner, m, tgt, tl, lab).forEach { it.release() } }
    }

    private fun portraitBlur(t: ToolCtx): ToolOut {
        Cv.init()
        val p = Segment.person(t.ctx, t.src) ?: throw IllegalStateException("사람을 찾지 못했습니다")
        Imgproc.GaussianBlur(p, p, Size(0.0, 0.0), max(1.5, max(t.src.width, t.src.height) / 600.0))
        val img = Cv.rgb(t.src)
        val small = Mat(); Imgproc.resize(img, small, Size(img.cols() / 2.0, img.rows() / 2.0), 0.0, 0.0, Imgproc.INTER_AREA)
        val sigma = 2.0 + max(img.cols(), img.rows()) * 0.012 * t.value / 100.0
        Imgproc.GaussianBlur(small, small, Size(0.0, 0.0), sigma / 2)
        val bl = Mat(); Imgproc.resize(small, bl, img.size(), 0.0, 0.0, Imgproc.INTER_LINEAR)
        val inv = Mat(); Core.subtract(Mat(p.size(), CvType.CV_32F, Scalar(1.0)), p, inv)
        val out = Cv.mix(img, bl, inv, 1.0)
        return ToolOut(Cv.bmp(out)).also { listOf(p, img, small, bl, inv, out).forEach { it.release() } }
    }

    private val ID_SIZES = listOf(Triple(30f, 40f, 0.72f), Triple(35f, 45f, 0.75f), Triple(25f, 30f, 0.70f), Triple(30f, 40f, 0.72f))
    private fun idPhoto(t: ToolCtx): ToolOut {
        Cv.init(); val q = needFace(t)
        val (wmm, hmm, headRatio) = ID_SIZES[t.option.coerceIn(0, ID_SIZES.size - 1)]
        val chinX = q[152 * 2]; val chinY = q[152 * 2 + 1]; val topY = q[10 * 2 + 1]
        val faceLen = chinY - topY
        val headTop = topY - 0.30f * faceLen // 머리 꼭대기 추정
        val headPx = chinY - headTop
        val hPx = headPx / headRatio; val wPx = hPx * wmm / hmm
        val cx = (q[234 * 2] + q[454 * 2]) / 2
        val left = cx - wPx / 2; val top = headTop - hPx * 0.09f
        // 사람만 남기고 흰 배경
        val pad = (max(wPx, hPx) * 0.1f).toInt()
        val rx0 = (left - pad).toInt().coerceIn(0, t.src.width - 2); val ry0 = (top - pad).toInt().coerceIn(0, t.src.height - 2)
        val rx1 = (left + wPx + pad).toInt().coerceIn(rx0 + 2, t.src.width); val ry1 = (top + hPx + pad).toInt().coerceIn(ry0 + 2, t.src.height)
        val sub = Bitmap.createBitmap(t.src, rx0, ry0, rx1 - rx0, ry1 - ry0)
        val p = Segment.person(t.ctx, sub)
        val img = Cv.rgb(sub)
        val white = Mat(img.size(), CvType.CV_8UC3, Scalar(255.0, 255.0, 255.0))
        val cut = if (p != null) { Imgproc.GaussianBlur(p, p, Size(0.0, 0.0), 1.2); val inv = Mat(); Core.subtract(Mat(p.size(), CvType.CV_32F, Scalar(1.0)), p, inv); Cv.mix(img, white, inv, 1.0) } else img
        val dpi = 300f / 25.4f
        val ow = (wmm * dpi).roundToInt(); val oh = (hmm * dpi).roundToInt()
        val cutBmp = Cv.bmp(cut)
        val photo = Bitmap.createBitmap(ow, oh, Bitmap.Config.ARGB_8888)
        Canvas(photo).apply {
            drawColor(Color.WHITE)
            val sc = ow / wPx
            translate(-(left - rx0) * sc, -(top - ry0) * sc); scale(sc, sc)
            drawBitmap(cutBmp, 0f, 0f, Paint(Paint.FILTER_BITMAP_FLAG))
        }
        val result = if (t.option == 3) {
            // 4×6인치(10×15cm) 인화지에 반명함 9장
            val sheet = Bitmap.createBitmap(1200, 1800, Bitmap.Config.ARGB_8888)
            val c = Canvas(sheet); c.drawColor(Color.WHITE)
            val gx = (1200 - 3 * ow) / 4f; val gy = (1800 - 3 * oh) / 4f
            val line = Paint().apply { color = Color.LTGRAY; strokeWidth = 1f }
            for (r in 0 until 3) for (k in 0 until 3) {
                val x = gx + k * (ow + gx); val y = gy + r * (oh + gy)
                c.drawBitmap(photo, x, y, null); c.drawRect(x, y, x + ow, y + oh, line.apply { style = Paint.Style.STROKE })
            }
            sheet
        } else photo
        return ToolOut(result, "${wmm / 10}×${hmm / 10}cm, 300dpi (${ow}×${oh}px). 머리 위치는 자동 추정이므로 규정(머리 크기·여백)을 확인하세요.")
    }

    private fun faceMosaic(t: ToolCtx): ToolOut {
        Cv.init()
        val faces = t.faces()
        if (faces.isEmpty()) return ToolOut(t.src, "얼굴을 찾지 못했습니다")
        val img = Cv.rgb(t.src)
        for (q in faces) {
            val b = Cv.box(q); val mw = b.width() * 0.18f; val mh = b.height() * 0.22f
            val r = Rect((b.left - mw).toInt().coerceIn(0, img.cols() - 2), (b.top - mh).toInt().coerceIn(0, img.rows() - 2), 1, 1)
            r.width = ((b.right + mw).toInt() - r.x).coerceIn(1, img.cols() - r.x); r.height = ((b.bottom + mh * 0.5f).toInt() - r.y).coerceIn(1, img.rows() - r.y)
            val sub = img.submat(r)
            when (t.option) {
                0 -> { val blocks = (4 + (100 - t.value) / 8).coerceAtLeast(3); val s = Mat(); Imgproc.resize(sub, s, Size(blocks.toDouble(), max(2.0, blocks * r.height / r.width.toDouble())), 0.0, 0.0, Imgproc.INTER_AREA); Imgproc.resize(s, sub, sub.size(), 0.0, 0.0, Imgproc.INTER_NEAREST); s.release() }
                1 -> Imgproc.GaussianBlur(sub, sub, Size(0.0, 0.0), r.width * (0.08 + 0.12 * t.value / 100.0))
                2 -> { // 눈 가리기
                    val ex0 = q[33 * 2]; val ex1 = q[263 * 2]; val ey = (q[33 * 2 + 1] + q[263 * 2 + 1]) / 2
                    val pad = abs(ex1 - ex0) * 0.25f; val hh = abs(ex1 - ex0) * 0.28f
                    val ang = Math.toDegrees(atan2((q[263 * 2 + 1] - q[33 * 2 + 1]).toDouble(), (ex1 - ex0).toDouble()))
                    val rr = org.opencv.core.RotatedRect(Point(((ex0 + ex1) / 2).toDouble(), ey.toDouble()), Size((abs(ex1 - ex0) + 2 * pad).toDouble(), (2 * hh).toDouble()), ang)
                    val pts = arrayOfNulls<Point>(4); rr.points(pts)
                    Imgproc.fillConvexPoly(img, MatOfPoint(*pts.requireNoNulls()), Scalar(0.0, 0.0, 0.0))
                }
                else -> Imgproc.ellipse(img, Point(r.x + r.width / 2.0, r.y + r.height / 2.0), Size(r.width / 2.0, r.height / 2.0), 0.0, 0.0, 360.0, Scalar(255.0, 205.0, 40.0), -1)
            }
        }
        return ToolOut(Cv.bmp(img), "얼굴 ${faces.size}개를 가렸습니다. 놓친 얼굴이 없는지 확인하세요.").also { img.release() }
    }

    private fun textBlocks(ctx: Context, b: Bitmap): List<Pair<String, android.graphics.Rect>> {
        val rec = TextRecognition.getClient(KoreanTextRecognizerOptions.Builder().build())
        try {
            val out = ArrayList<Pair<String, android.graphics.Rect>>()
            fun scan(bm: Bitmap, ox: Int, oy: Int, k: Float) {
                val res = Tasks.await(rec.process(InputImage.fromBitmap(bm, 0)))
                for (blk in res.textBlocks) for (ln in blk.lines) {
                    val bb = ln.boundingBox ?: continue
                    out += ln.text to android.graphics.Rect(ox + (bb.left * k).toInt(), oy + (bb.top * k).toInt(), ox + (bb.right * k).toInt(), oy + (bb.bottom * k).toInt())
                }
            }
            val small = Cv.scaleTo(b, 2048); scan(small, 0, 0, b.width.toFloat() / small.width)
            if (max(b.width, b.height) > 2400) {
                val tw = (b.width * 0.6f).toInt(); val th = (b.height * 0.6f).toInt()
                for (ty in listOf(0, b.height - th)) for (tx in listOf(0, b.width - tw)) {
                    val tile = Bitmap.createBitmap(b, tx, ty, tw, th); val ts = Cv.scaleTo(tile, 2048)
                    scan(ts, tx, ty, tw.toFloat() / ts.width); if (ts !== tile) ts.recycle(); tile.recycle()
                }
            }
            return out
        } finally { rec.close() }
    }

    private fun plateBlur(t: ToolCtx): ToolOut {
        Cv.init()
        val blocks = textBlocks(t.ctx, t.src)
        val plates = blocks.filter { PlateParser.parse(it.first) != null }
        if (plates.isEmpty()) return ToolOut(t.src, "번호판을 찾지 못했습니다 (가까이 찍힌 한국 번호판만 찾습니다)")
        val img = Cv.rgb(t.src)
        val done = ArrayList<android.graphics.Rect>()
        for ((_, bb) in plates) {
            if (done.any { android.graphics.Rect.intersects(it, bb) }) continue
            done += bb
            val padX = (bb.width() * 0.15f).toInt(); val padY = (bb.height() * 0.4f).toInt()
            val r = Rect((bb.left - padX).coerceIn(0, img.cols() - 2), (bb.top - padY).coerceIn(0, img.rows() - 2), 1, 1)
            r.width = (bb.right + padX - r.x).coerceIn(1, img.cols() - r.x); r.height = (bb.bottom + padY - r.y).coerceIn(1, img.rows() - r.y)
            val sub = img.submat(r)
            val s = Mat(); Imgproc.resize(sub, s, Size(8.0, 3.0), 0.0, 0.0, Imgproc.INTER_AREA); Imgproc.resize(s, sub, sub.size(), 0.0, 0.0, Imgproc.INTER_NEAREST); s.release()
        }
        return ToolOut(Cv.bmp(img), "번호판 ${done.size}개를 가렸습니다").also { img.release() }
    }

    // ---------------- 기본 편집
    private fun resize(t: ToolCtx): ToolOut {
        val b = when (t.option) { 0 -> Bitmap.createScaledBitmap(t.src, max(1, t.src.width / 2), max(1, t.src.height / 2), true); 1 -> Cv.scaleTo(t.src, 1920); 2 -> Cv.scaleTo(t.src, 1280); else -> Cv.scaleTo(t.src, 800) }
        val quality = (30 + t.value * 0.7f).roundToInt().coerceIn(30, 100)
        val before = java.io.ByteArrayOutputStream().also { t.src.compress(Bitmap.CompressFormat.JPEG, 95, it) }.size()
        val after = java.io.ByteArrayOutputStream().also { b.compress(Bitmap.CompressFormat.JPEG, quality, it) }.size()
        fun kb(n: Int) = if (n > 1_000_000) "%.1fMB".format(n / 1e6) else "${n / 1000}KB"
        return ToolOut(b, "${t.src.width}×${t.src.height} → ${b.width}×${b.height}, 화질 $quality: 약 ${kb(before)} → ${kb(after)}", jpeg = quality)
    }

    private fun rotate(t: ToolCtx): ToolOut {
        val m = android.graphics.Matrix()
        when (t.option) { 0 -> m.postRotate(90f); 1 -> m.postRotate(-90f); 2 -> m.postRotate(180f); 3 -> m.postScale(-1f, 1f); else -> m.postScale(1f, -1f) }
        return ToolOut(Bitmap.createBitmap(t.src, 0, 0, t.src.width, t.src.height, m, true))
    }

    private fun autoContrast(t: ToolCtx): ToolOut {
        Cv.init(); val img = Cv.rgb(t.src); val lab = Mat(); Imgproc.cvtColor(img, lab, Imgproc.COLOR_RGB2Lab)
        val ch = ArrayList<Mat>(); Core.split(lab, ch)
        Imgproc.createCLAHE(1.0 + 3.0 * t.value / 100.0, Size(8.0, 8.0)).apply(ch[0], ch[0])
        Core.merge(ch, lab); Imgproc.cvtColor(lab, img, Imgproc.COLOR_Lab2RGB)
        return ToolOut(Cv.bmp(img)).also { img.release(); lab.release(); ch.forEach { it.release() } }
    }

    private fun denoise(t: ToolCtx): ToolOut {
        Cv.init(); val b = Cv.scaleTo(t.src, 1600); val img = Cv.rgb(b); val out = Mat()
        val h = 3f + 12f * t.value / 100f
        Photo.fastNlMeansDenoisingColored(img, out, h, h, 7, 21)
        return ToolOut(Cv.bmp(out), if (b !== t.src) "속도를 위해 1600px 로 줄여 처리했습니다" else null).also { img.release(); out.release() }
    }

    private fun sharpen(t: ToolCtx): ToolOut {
        Cv.init(); val img = Cv.rgb(t.src); val bl = Mat(); Imgproc.GaussianBlur(img, bl, Size(0.0, 0.0), 1.3)
        val a = 0.3 + 1.7 * t.value / 100.0; val out = Mat(); Core.addWeighted(img, 1 + a, bl, -a, 0.0, out)
        return ToolOut(Cv.bmp(out)).also { listOf(img, bl, out).forEach { it.release() } }
    }

    // ---------------- 필터
    /** 픽셀마다 RGB 를 바꾸는 필터 (빠름) */
    private fun perPixel(src: Bitmap, f: (Int, Int, Int, Int, Int) -> Int): Bitmap {
        val w = src.width; val h = src.height
        val px = IntArray(w * h); src.getPixels(px, 0, w, 0, 0, w, h)
        for (y in 0 until h) for (x in 0 until w) { val p = px[y * w + x]; px[y * w + x] = f(Color.red(p), Color.green(p), Color.blue(p), x, y) }
        return Bitmap.createBitmap(w, h, Bitmap.Config.ARGB_8888).also { it.setPixels(px, 0, w, 0, 0, w, h) }
    }
    private fun c255(v: Float) = v.roundToInt().coerceIn(0, 255)
    private fun lerp(a: Int, b: Float, s: Float) = c255(a + (b - a) * s)

    private fun blackWhite(t: ToolCtx): ToolOut {
        val s = t.value / 100f
        return ToolOut(perPixel(t.src) { r, g, b, _, _ ->
            var y = when (t.option) { 2 -> 0.7f * r + 0.25f * g + 0.05f * b; else -> 0.299f * r + 0.587f * g + 0.114f * b }
            if (t.option == 1) y = 127.5f + (y - 127.5f) * 1.6f
            Color.rgb(lerp(r, y, s), lerp(g, y, s), lerp(b, y, s))
        })
    }

    private fun sepia(t: ToolCtx): ToolOut {
        val s = t.value / 100f
        return ToolOut(perPixel(t.src) { r, g, b, _, _ ->
            Color.rgb(lerp(r, 0.393f * r + 0.769f * g + 0.189f * b, s), lerp(g, 0.349f * r + 0.686f * g + 0.168f * b, s), lerp(b, 0.272f * r + 0.534f * g + 0.131f * b, s))
        })
    }

    private fun vintage(t: ToolCtx): ToolOut {
        val s = t.value / 100f; val w = t.src.width; val h = t.src.height
        val rnd = java.util.Random(1)
        return ToolOut(perPixel(t.src) { r, g, b, x, y ->
            val dx = (x - w / 2f) / (w / 2f); val dy = (y - h / 2f) / (h / 2f)
            val vig = 1f - 0.45f * s * (dx * dx + dy * dy).pow(1.1f).coerceAtMost(1.6f)
            val noise = (rnd.nextFloat() - 0.5f) * 18f * s
            val rr = (r * 0.9f + 30f) * vig + noise; val gg = (g * 0.85f + 22f) * vig + noise; val bb = (b * 0.7f + 18f) * vig + noise
            Color.rgb(lerp(r, rr, s), lerp(g, gg, s), lerp(b, bb, s))
        })
    }

    private fun colorAdjust(t: ToolCtx): ToolOut {
        val s = t.value / 100f
        return ToolOut(perPixel(t.src) { r, g, b, _, _ ->
            when (t.option) {
                0 -> Color.rgb(c255(r + 30 * s), c255(g + 8 * s), c255(b - 25 * s))
                1 -> Color.rgb(c255(r - 25 * s), c255(g + 3 * s), c255(b + 30 * s))
                2, 3 -> { val y = 0.299f * r + 0.587f * g + 0.114f * b; val k = if (t.option == 2) 1 + 0.8f * s else 1 - 0.8f * s; Color.rgb(c255(y + (r - y) * k), c255(y + (g - y) * k), c255(y + (b - y) * k)) }
                4 -> { val k = 1 + 0.5f * s; Color.rgb(c255(r * k + 10 * s), c255(g * k + 10 * s), c255(b * k + 10 * s)) }
                else -> { val k = 1 - 0.45f * s; Color.rgb(c255(r * k), c255(g * k), c255(b * k)) }
            }
        })
    }

    private fun vignette(t: ToolCtx): ToolOut {
        val s = t.value / 100f; val w = t.src.width; val h = t.src.height
        return ToolOut(perPixel(t.src) { r, g, b, x, y ->
            val dx = (x - w / 2f) / (w / 2f); val dy = (y - h / 2f) / (h / 2f)
            val f = 1f - 0.7f * s * ((dx * dx + dy * dy) / 2f).pow(1.2f)
            Color.rgb(c255(r * f), c255(g * f), c255(b * f))
        })
    }

    private fun sketch(t: ToolCtx): ToolOut {
        Cv.init(); val img = Cv.rgb(Cv.scaleTo(t.src, 2000)); val g = Mat(); val c = Mat()
        Photo.pencilSketch(img, g, c, 40f + t.value * 0.6f, 0.07f, 0.03f + 0.04f * t.value / 100f)
        return ToolOut(Cv.bmp(if (t.option == 0) g else c)).also { listOf(img, g, c).forEach { it.release() } }
    }

    private fun cartoon(t: ToolCtx): ToolOut {
        Cv.init(); val img = Cv.rgb(Cv.scaleTo(t.src, 1600))
        var small = Mat(); Imgproc.pyrDown(img, small)
        repeat(4 + t.value / 25) { val tmp = Mat(); Imgproc.bilateralFilter(small, tmp, 9, 30.0, 7.0); small.release(); small = tmp }
        val col = Mat(); Imgproc.resize(small, col, img.size())
        val gray = Mat(); Imgproc.cvtColor(img, gray, Imgproc.COLOR_RGB2GRAY); Imgproc.medianBlur(gray, gray, 7)
        val edge = Mat(); Imgproc.adaptiveThreshold(gray, edge, 255.0, Imgproc.ADAPTIVE_THRESH_MEAN_C, Imgproc.THRESH_BINARY, 9, 2.0)
        val e3 = Mat(); Imgproc.cvtColor(edge, e3, Imgproc.COLOR_GRAY2RGB)
        val out = Mat(); Core.bitwise_and(col, e3, out)
        return ToolOut(Cv.bmp(out)).also { listOf(img, small, col, gray, edge, e3, out).forEach { it.release() } }
    }

    private fun watercolor(t: ToolCtx): ToolOut {
        Cv.init(); val img = Cv.rgb(Cv.scaleTo(t.src, 1600)); val out = Mat()
        Photo.stylization(img, out, 30f + t.value * 1.2f, 0.45f)
        return ToolOut(Cv.bmp(out)).also { img.release(); out.release() }
    }

    private fun hdr(t: ToolCtx): ToolOut {
        Cv.init(); val img = Cv.rgb(Cv.scaleTo(t.src, 2400)); val out = Mat()
        Photo.detailEnhance(img, out, 10f, 0.05f + 0.25f * t.value / 100f)
        return ToolOut(Cv.bmp(out)).also { img.release(); out.release() }
    }

    private fun kmeansColors(img: Mat, k: Int): Pair<Mat, IntArray> {
        val data = Mat(); img.reshape(1, img.rows() * img.cols()).convertTo(data, CvType.CV_32F)
        val labels = Mat(); val centers = Mat()
        Core.kmeans(data, k, labels, TermCriteria(TermCriteria.EPS + TermCriteria.COUNT, 20, 1.0), 3, Core.KMEANS_PP_CENTERS, centers)
        val lab = IntArray(labels.rows()); labels.get(0, 0, lab)
        data.release(); labels.release()
        return centers to lab
    }

    private fun pixelArt(t: ToolCtx): ToolOut {
        Cv.init(); val img = Cv.rgb(t.src)
        val block = (4 + t.value * 0.28f).roundToInt()
        val sw = max(4, img.cols() / block); val sh = max(4, img.rows() / block)
        val small = Mat(); Imgproc.resize(img, small, Size(sw.toDouble(), sh.toDouble()), 0.0, 0.0, Imgproc.INTER_AREA)
        val (centers, lab) = kmeansColors(small, 16)
        val cv = FloatArray(16 * 3); centers.get(0, 0, cv)
        val px = ByteArray(sw * sh * 3)
        for (i in 0 until sw * sh) for (c in 0 until 3) px[i * 3 + c] = cv[lab[i] * 3 + c].roundToInt().coerceIn(0, 255).toByte()
        small.put(0, 0, px)
        val out = Mat(); Imgproc.resize(small, out, Size(sw * block.toDouble(), sh * block.toDouble()), 0.0, 0.0, Imgproc.INTER_NEAREST)
        return ToolOut(Cv.bmp(out)).also { listOf(img, small, centers, out).forEach { it.release() } }
    }

    private fun watermark(t: ToolCtx): ToolOut {
        val text = t.text.ifBlank { "© 내 사진" }
        val out = t.src.copy(Bitmap.Config.ARGB_8888, true)
        val c = Canvas(out)
        val size = max(out.width, out.height) * (0.02f + 0.06f * t.value / 100f)
        val p = Paint(Paint.ANTI_ALIAS_FLAG).apply { textSize = size; color = Color.argb(170, 255, 255, 255); typeface = Typeface.DEFAULT_BOLD; setShadowLayer(size * 0.08f, 0f, 0f, Color.argb(160, 0, 0, 0)) }
        val tw = p.measureText(text)
        when (t.option) {
            0 -> c.drawText(text, out.width - tw - size * 0.6f, out.height - size * 0.6f, p)
            1 -> c.drawText(text, (out.width - tw) / 2, out.height / 2f, p)
            else -> { p.color = Color.argb(70, 255, 255, 255); c.rotate(-30f, out.width / 2f, out.height / 2f)
                var y = -out.height.toFloat(); while (y < out.height * 2) { var x = -out.width.toFloat(); while (x < out.width * 2) { c.drawText(text, x, y, p); x += tw + size * 2 }; y += size * 3 } }
        }
        return ToolOut(out)
    }

    private fun orderQuad(p: List<Point>): List<Point> {
        val s = p.sortedBy { it.x + it.y }; val d = p.sortedBy { it.y - it.x }
        return listOf(s.first(), d.first(), s.last(), d.last()) // 왼위, 오른위, 오른아래, 왼아래
    }

    private fun docScan(t: ToolCtx): ToolOut {
        Cv.init(); val img = Cv.rgb(t.src)
        val k = 800.0 / max(img.cols(), img.rows())
        val small = Mat(); Imgproc.resize(img, small, Size(img.cols() * k, img.rows() * k), 0.0, 0.0, Imgproc.INTER_AREA)
        val g = Mat(); Imgproc.cvtColor(small, g, Imgproc.COLOR_RGB2GRAY); Imgproc.GaussianBlur(g, g, Size(5.0, 5.0), 0.0)
        val e = Mat(); Imgproc.Canny(g, e, 50.0, 150.0); Imgproc.dilate(e, e, Mat.ones(3, 3, CvType.CV_8U))
        val cs = ArrayList<MatOfPoint>(); Imgproc.findContours(e, cs, Mat(), Imgproc.RETR_LIST, Imgproc.CHAIN_APPROX_SIMPLE)
        var quad: List<Point>? = null
        for (c in cs.sortedByDescending { Imgproc.contourArea(it) }.take(8)) {
            val c2 = MatOfPoint2f(*c.toArray()); val ap = MatOfPoint2f()
            Imgproc.approxPolyDP(c2, ap, 0.02 * Imgproc.arcLength(c2, true), true)
            if (ap.rows() == 4 && Imgproc.contourArea(ap) > small.cols() * small.rows() * 0.15) { quad = ap.toList().map { Point(it.x / k, it.y / k) }; break }
        }
        val note: String
        val warped = if (quad != null) {
            val (tl, tr, br, bl) = orderQuad(quad)
            val wpx = max(hypot(tr.x - tl.x, tr.y - tl.y), hypot(br.x - bl.x, br.y - bl.y))
            val hpx = max(hypot(bl.x - tl.x, bl.y - tl.y), hypot(br.x - tr.x, br.y - tr.y))
            val m = Imgproc.getPerspectiveTransform(MatOfPoint2f(tl, tr, br, bl), MatOfPoint2f(Point(0.0, 0.0), Point(wpx, 0.0), Point(wpx, hpx), Point(0.0, hpx)))
            val o = Mat(); Imgproc.warpPerspective(img, o, m, Size(wpx, hpx), Imgproc.INTER_CUBIC); note = "문서 모서리를 찾아 반듯하게 폈습니다"; o
        } else { note = "문서 모서리를 찾지 못해 사진 전체를 썼습니다 (어두운 바탕에 문서를 놓고 찍으면 잘 찾습니다)"; img.clone() }
        val out = when (t.option) {
            1 -> { val gg = Mat(); Imgproc.cvtColor(warped, gg, Imgproc.COLOR_RGB2GRAY); val o = Mat(); Imgproc.adaptiveThreshold(gg, o, 255.0, Imgproc.ADAPTIVE_THRESH_GAUSSIAN_C, Imgproc.THRESH_BINARY, 25, 10.0); gg.release(); o }
            2 -> { val lab = Mat(); Imgproc.cvtColor(warped, lab, Imgproc.COLOR_RGB2Lab); val ch = ArrayList<Mat>(); Core.split(lab, ch)
                Imgproc.createCLAHE(2.5, Size(8.0, 8.0)).apply(ch[0], ch[0]); Core.merge(ch, lab); val o = Mat(); Imgproc.cvtColor(lab, o, Imgproc.COLOR_Lab2RGB); o }
            else -> warped
        }
        return ToolOut(Cv.bmp(out), note)
    }

    private fun ocr(t: ToolCtx): ToolOut {
        val blocks = textBlocks(t.ctx, t.src)
        if (blocks.isEmpty()) return ToolOut(t.src, "글자를 찾지 못했습니다")
        val out = t.src.copy(Bitmap.Config.ARGB_8888, true)
        val c = Canvas(out); val p = Paint().apply { style = Paint.Style.STROKE; color = Color.rgb(30, 120, 255); strokeWidth = max(2f, out.width / 500f) }
        blocks.forEach { c.drawRect(it.second, p) }
        val text = blocks.sortedWith(compareBy({ it.second.top / max(1, it.second.height()) }, { it.second.left })).joinToString("\n") { it.first }
        return ToolOut(out, text)
    }

    private fun palette(t: ToolCtx): ToolOut {
        Cv.init(); val img = Cv.rgb(Cv.scaleTo(t.src, 120))
        val k = 6; val (centers, lab) = kmeansColors(img, k)
        val cv = FloatArray(k * 3); centers.get(0, 0, cv)
        val counts = IntArray(k); lab.forEach { counts[it]++ }
        val order = (0 until k).sortedByDescending { counts[it] }
        val strip = (t.src.height * 0.18f).toInt().coerceAtLeast(80)
        val out = Bitmap.createBitmap(t.src.width, t.src.height + strip, Bitmap.Config.ARGB_8888)
        val c = Canvas(out); c.drawBitmap(t.src, 0f, 0f, null)
        val sb = StringBuilder()
        var x = 0f
        val txt = Paint(Paint.ANTI_ALIAS_FLAG).apply { textSize = strip * 0.16f; textAlign = Paint.Align.CENTER }
        for (i in order) {
            val r = cv[i * 3].roundToInt().coerceIn(0, 255); val g = cv[i * 3 + 1].roundToInt().coerceIn(0, 255); val b = cv[i * 3 + 2].roundToInt().coerceIn(0, 255)
            val wseg = out.width * counts[i].toFloat() / lab.size
            c.drawRect(x, t.src.height.toFloat(), x + wseg, out.height.toFloat(), Paint().apply { color = Color.rgb(r, g, b) })
            val hex = "#%02X%02X%02X".format(r, g, b)
            txt.color = if (0.299 * r + 0.587 * g + 0.114 * b > 140) Color.BLACK else Color.WHITE
            if (wseg > txt.measureText(hex) * 1.1f) c.drawText(hex, x + wseg / 2, t.src.height + strip * 0.58f, txt)
            sb.append("$hex  ${(100f * counts[i] / lab.size).roundToInt()}%  ${ColorNames.name(r, g, b)}\n")
            x += wseg
        }
        return ToolOut(out, sb.toString().trim()).also { img.release(); centers.release() }
    }

    private fun symmetricFace(t: ToolCtx): ToolOut {
        Cv.init(); val q = needFace(t)
        val img = Cv.rgb(t.src)
        // 눈이 수평이 되게 돌림
        val ang = Math.toDegrees(atan2((q[263 * 2 + 1] - q[33 * 2 + 1]).toDouble(), (q[263 * 2] - q[33 * 2]).toDouble()))
        val c = Point(q[1 * 2].toDouble(), q[1 * 2 + 1].toDouble())
        val rot = Imgproc.getRotationMatrix2D(c, ang, 1.0)
        val ri = Mat(); Imgproc.warpAffine(img, ri, rot, img.size(), Imgproc.INTER_LINEAR, Core.BORDER_REPLICATE)
        val rv = DoubleArray(6); rot.get(0, 0, rv)
        fun tx(i: Int) = rv[0] * q[i * 2] + rv[1] * q[i * 2 + 1] + rv[2]
        fun ty(i: Int) = rv[3] * q[i * 2] + rv[4] * q[i * 2 + 1] + rv[5]
        // 가운데 선: 좌우 짝 점들의 가운데 평균
        val mir = FaceMesh.mirrorTable(t.ctx)
        var sx = 0.0; var cnt = 0
        for (i in 0 until 468) { val j = mir[i]; if (j > i) { sx += (tx(i) + tx(j)) / 2; cnt++ } }
        val mid = sx / max(1, cnt)
        var x0 = Double.MAX_VALUE; var x1 = -Double.MAX_VALUE; var y0 = Double.MAX_VALUE; var y1 = -Double.MAX_VALUE
        for (i in 0 until 468) { x0 = min(x0, tx(i)); x1 = max(x1, tx(i)); y0 = min(y0, ty(i)); y1 = max(y1, ty(i)) }
        val half = max(mid - x0, x1 - mid) * 1.15
        val top = (y0 - (y1 - y0) * 0.15).coerceAtLeast(0.0); val bot = (y1 + (y1 - y0) * 0.08).coerceAtMost(ri.rows() - 1.0)
        val w = (2 * half).toInt().coerceAtLeast(4); val h = (bot - top).toInt().coerceAtLeast(4)
        fun make(leftHalf: Boolean?): Mat {
            val mx = FloatArray(w * h); val my = FloatArray(w * h)
            for (y in 0 until h) for (x in 0 until w) {
                var X = mid - half + x
                if (leftHalf == true && X > mid) X = 2 * mid - X
                if (leftHalf == false && X < mid) X = 2 * mid - X
                mx[y * w + x] = X.toFloat(); my[y * w + x] = (top + y).toFloat()
            }
            val o = Mat(); Imgproc.remap(ri, o, SkinCore.fmat(mx, w, h), SkinCore.fmat(my, w, h), Imgproc.INTER_LINEAR, Core.BORDER_REPLICATE); return o
        }
        val out = when (t.option) {
            1 -> make(true)
            2 -> make(false)
            else -> { val o = Mat(); Core.hconcat(listOf(make(true), make(null), make(false)), o); o }
        }
        return ToolOut(Cv.bmp(out), if (t.option == 0) "왼쪽: 사진 왼쪽 반으로 만든 얼굴 · 가운데: 원본 · 오른쪽: 사진 오른쪽 반으로 만든 얼굴" else null)
            .also { listOf(img, ri, out, rot).forEach { it.release() } }
    }

    private fun exifRemove(t: ToolCtx): ToolOut =
        ToolOut(t.src, "지울 정보:\n" + t.exifInfo() + "\n\n저장하면 촬영 정보·위치(GPS) 없이 새 JPEG 로 저장됩니다.", jpeg = 95)

    val ALL: List<PhotoTool> = listOf(
        PhotoTool("skin_smooth", "피부 보정", "얼굴 피부만 매끈하게 (눈·눈썹·입술은 그대로, 피부 결은 조금 남김)", param = "세기", paramDefault = 55, run = ::skinSmooth),
        PhotoTool("spot_remove", "잡티 제거", "피부 분석으로 찾은 잡티를 주변 피부로 메움", listOf("잡티만", "잡티 + 모공"), "범위", 40, run = ::spotRemove),
        PhotoTool("teeth", "치아 미백", "입 안의 밝은 부분(이)만 누런기를 줄이고 밝게", param = "세기", paramDefault = 60, run = ::teethWhiten),
        PhotoTool("eye_big", "눈 키우기", "눈 주변을 자연스럽게 확대", param = "세기", paramDefault = 40, run = ::eyeEnlarge),
        PhotoTool("face_slim", "얼굴 갸름하게", "아래턱선을 안쪽으로", param = "세기", paramDefault = 40, run = ::faceSlim),
        PhotoTool("lip", "입술 색", "입술에만 색 입히기", listOf("로즈", "코랄", "레드", "플럼", "누드"), "세기", 45, run = ::lipTint),
        PhotoTool("portrait", "인물 배경 흐림", "사람은 선명하게, 배경은 흐리게 (인물 사진 모드)", param = "흐림", paramDefault = 50, run = ::portraitBlur),
        PhotoTool("id_photo", "증명사진 만들기", "얼굴 위치를 맞춰 자르고 흰 배경으로 (300dpi)", listOf("반명함 3×4cm", "여권 3.5×4.5cm", "명함 2.5×3cm", "인화용 4×6 (반명함 9장)"), run = ::idPhoto),
        PhotoTool("mosaic", "얼굴 가리기", "사진 속 모든 얼굴 자동 가리기 (개인정보 보호)", listOf("모자이크", "흐림", "눈 가리기", "노란 원"), "세기", 60, run = ::faceMosaic),
        PhotoTool("plate_blur", "번호판 가리기", "한국 차량 번호판을 찾아 모자이크", run = ::plateBlur),
        PhotoTool("exif", "촬영 정보·위치 지우기", "GPS 위치·기종·날짜 같은 숨은 정보를 지우고 저장", run = ::exifRemove),
        PhotoTool("resize", "크기 줄이기·압축", "보내기 좋게 크기와 용량 줄이기", listOf("가로세로 절반", "최대 1920px", "최대 1280px", "최대 800px"), "화질", 80, run = ::resize),
        PhotoTool("rotate", "회전·뒤집기", "사진 방향 바꾸기", listOf("시계 방향 90°", "반시계 90°", "180°", "좌우 뒤집기", "상하 뒤집기"), run = ::rotate),
        PhotoTool("contrast", "자동 밝기·대비", "어둡거나 뿌연 사진을 또렷하게 (CLAHE)", param = "세기", paramDefault = 40, run = ::autoContrast),
        PhotoTool("denoise", "잡음 제거", "어두운 곳에서 찍은 자글자글한 잡음 줄이기", param = "세기", paramDefault = 45, run = ::denoise),
        PhotoTool("sharpen", "선명하게", "흐릿한 사진의 윤곽을 또렷하게", param = "세기", paramDefault = 40, run = ::sharpen),
        PhotoTool("bw", "흑백", "흑백 사진으로", listOf("기본", "고대비", "붉은 필터(피부 밝게)"), "세기", 100, run = ::blackWhite),
        PhotoTool("sepia", "세피아", "오래된 갈색 사진 느낌", param = "세기", paramDefault = 85, run = ::sepia),
        PhotoTool("vintage", "빈티지", "바랜 색 + 가장자리 어둡게 + 필름 입자", param = "세기", paramDefault = 70, run = ::vintage),
        PhotoTool("color", "색감 조절", "따뜻하게·차갑게·채도·밝기", listOf("따뜻하게", "차갑게", "채도 올리기", "채도 내리기", "밝게", "어둡게"), "세기", 50, run = ::colorAdjust),
        PhotoTool("vignette", "가장자리 어둡게", "비네팅 효과로 가운데에 시선 모으기", param = "세기", paramDefault = 50, run = ::vignette),
        PhotoTool("sketch", "연필 스케치", "연필로 그린 그림처럼", listOf("흑백", "컬러"), "부드러움", 50, run = ::sketch),
        PhotoTool("cartoon", "만화 효과", "색을 단순하게 + 굵은 윤곽선", param = "단순함", paramDefault = 50, run = ::cartoon),
        PhotoTool("watercolor", "수채화 효과", "물감으로 칠한 그림처럼", param = "번짐", paramDefault = 50, run = ::watercolor),
        PhotoTool("hdr", "HDR 디테일", "어두운 곳·밝은 곳의 질감을 살림", param = "세기", paramDefault = 40, run = ::hdr),
        PhotoTool("pixel", "픽셀 아트", "도트 그림처럼 (16색)", param = "칸 크기", paramDefault = 30, run = ::pixelArt),
        PhotoTool("watermark", "워터마크 넣기", "사진에 내 글자 넣기 (무단 사용 방지)", listOf("오른쪽 아래", "가운데", "전체 반복"), "글자 크기", 40, textHint = "넣을 글자 (예: © 내 이름)", run = ::watermark),
        PhotoTool("doc_scan", "문서 스캔", "비스듬히 찍은 문서를 반듯하게 펴기", listOf("컬러", "흑백 문서", "선명하게"), run = ::docScan),
        PhotoTool("ocr", "글자 추출", "사진 속 글자(한글·영어)를 글로 뽑아 복사", run = ::ocr),
        PhotoTool("palette", "색상 팔레트", "사진의 주요 색 6가지와 색 코드", run = ::palette),
        PhotoTool("symmetry", "좌우 대칭 얼굴", "얼굴 왼쪽 반·오른쪽 반으로 각각 대칭 얼굴 만들기", listOf("셋 나란히", "사진 왼쪽 반 대칭", "사진 오른쪽 반 대칭"), run = ::symmetricFace),
    )

    fun byId(id: String) = ALL.firstOrNull { it.id == id }
}

/** RGB 에 가까운 한국어 색 이름 */
object ColorNames {
    private val NAMES = listOf(
        "검정" to intArrayOf(0, 0, 0), "흰색" to intArrayOf(255, 255, 255), "회색" to intArrayOf(128, 128, 128), "진회색" to intArrayOf(64, 64, 64), "연회색" to intArrayOf(200, 200, 200),
        "빨강" to intArrayOf(220, 30, 30), "진빨강" to intArrayOf(140, 10, 20), "분홍" to intArrayOf(255, 160, 190), "진분홍" to intArrayOf(230, 60, 140), "살구색" to intArrayOf(250, 190, 150),
        "주황" to intArrayOf(255, 140, 0), "갈색" to intArrayOf(140, 80, 30), "베이지" to intArrayOf(225, 205, 170), "노랑" to intArrayOf(255, 230, 0), "황토색" to intArrayOf(200, 150, 50),
        "연두" to intArrayOf(150, 220, 70), "초록" to intArrayOf(30, 160, 60), "진초록" to intArrayOf(10, 80, 30), "올리브" to intArrayOf(128, 128, 0), "민트" to intArrayOf(150, 230, 200),
        "청록" to intArrayOf(0, 150, 150), "하늘색" to intArrayOf(120, 200, 250), "파랑" to intArrayOf(30, 90, 220), "남색" to intArrayOf(20, 30, 110), "보라" to intArrayOf(130, 60, 180),
        "연보라" to intArrayOf(190, 160, 230), "자주" to intArrayOf(150, 30, 100), "금색" to intArrayOf(212, 175, 55), "은색" to intArrayOf(192, 192, 200), "카키" to intArrayOf(150, 140, 90),
    )
    fun name(r: Int, g: Int, b: Int): String {
        // 사람 눈에 가까운 거리 (붉은 정도에 따라 가중치)
        val rm = r / 2.0
        return NAMES.minBy { (_, c) -> val dr = r - c[0]; val dg = g - c[1]; val db = b - c[2]; (2 + rm / 256) * dr * dr + 4 * dg * dg + (2 + (255 - rm) / 256) * db * db }.first
    }
}
