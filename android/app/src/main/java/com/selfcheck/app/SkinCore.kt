package com.selfcheck.app

import org.opencv.core.Core
import org.opencv.core.CvType
import org.opencv.core.Mat
import org.opencv.core.MatOfPoint
import org.opencv.core.Point
import org.opencv.core.Size
import org.opencv.imgproc.Imgproc
import kotlin.math.abs
import kotlin.math.exp
import kotlin.math.hypot
import kotlin.math.max
import kotlin.math.min
import kotlin.math.roundToInt
import kotlin.math.sqrt

/** MediaPipe 얼굴 점(478개) 중 부위별 번호. "왼쪽/오른쪽"은 사진에서 보이는 방향입니다. */
object FaceIdx {
    val OVAL = intArrayOf(10, 338, 297, 332, 284, 251, 389, 356, 454, 323, 361, 288, 397, 365, 379, 378, 400, 377, 152, 148, 176, 149, 150, 136, 172, 58, 132, 93, 234, 127, 162, 21, 54, 103, 67, 109)
    val EYE_A = intArrayOf(33, 7, 163, 144, 145, 153, 154, 155, 133, 173, 157, 158, 159, 160, 161, 246) // 사진 왼쪽 눈
    val EYE_B = intArrayOf(263, 249, 390, 373, 374, 380, 381, 382, 362, 398, 384, 385, 386, 387, 388, 466) // 사진 오른쪽 눈
    val BROW_A = intArrayOf(70, 63, 105, 66, 107, 55, 65, 52, 53, 46)
    val BROW_B = intArrayOf(300, 293, 334, 296, 336, 285, 295, 282, 283, 276)
    val LIPS = intArrayOf(61, 146, 91, 181, 84, 17, 314, 405, 321, 375, 291, 409, 270, 269, 267, 0, 37, 39, 40, 185)
    val MOUTH_IN = intArrayOf(78, 95, 88, 178, 87, 14, 317, 402, 318, 324, 308, 415, 310, 311, 312, 13, 82, 81, 80, 191)
    val NOSTRIL = intArrayOf(98, 97, 2, 326, 327, 294, 278, 344, 440, 275, 4, 45, 220, 115, 48, 64)
    val NOSE = intArrayOf(168, 6, 197, 195, 5, 4, 1, 19, 94, 2, 98, 64, 129, 49, 131, 134, 51, 281, 363, 360, 279, 358, 294, 327)
    val JAW_A = intArrayOf(132, 58, 172, 136, 150, 149, 176, 148) // 사진 왼쪽 턱선
    val JAW_B = intArrayOf(361, 288, 397, 365, 379, 378, 400, 377)
}

class SkinMetric(val key: String, val name: String, val degree: Float, val value: String, val note: String)

/** 피부 분석 결과. 좌표·배열은 모두 분석한 얼굴 부분(w×h) 기준입니다. */
class SkinResult(
    val w: Int, val h: Int, val u: Float,
    val skin: BooleanArray,
    val regionMask: IntArray,
    val wrinkle: BooleanArray,
    val wrinkleV: FloatArray,
    val fine: BooleanArray,
    val pores: IntArray,
    val spots: List<FloatArray>,
    val red: BooleanArray,
    val shine: BooleanArray,
    val regionScores: LinkedHashMap<String, Float?>,
    val fineScores: LinkedHashMap<String, Float?>,
    val regionLines: Map<String, Int>,
    val metrics: List<SkinMetric>,
    val overall: Int,
    val warnings: List<String>,
)

/**
 * 피부·주름 분석의 계산 부분 (OpenCV 와 배열만 씀 → 컴퓨터에서도 시험 가능).
 * 파이썬 시제품(skin_proto.py)과 같은 방법·같은 기준값입니다.
 *  - 주름: 밝기(L)의 2차 미분(헤시안)으로 "어두운 가는 선"을 세 가지 굵기로 찾고, 길고 가는 선만 남김
 *  - 잔주름: 더 가는 굵기로 따로 찾음 (깨끗한 피부에서는 0)
 *  - 모공: 작은 어두운 점(DoG 극대), 잡티: 주변보다 어두운 동그란 얼룩, 홍조: 피부 평균보다 붉은 곳(a*)
 *  - 번들거림: T존의 아주 밝고 채도 낮은 곳, 다크서클: 볼과 눈밑의 밝기 차, 톤: 색(a*, b*)의 얼룩, 피부결: 고주파 거칠기
 */
object SkinCore {
    const val WEAK = 0.8f
    const val STRONG = 1.8f

    /** 부위 이름 (비트 번호 순서) */
    val REGIONS = arrayOf("이마", "미간", "왼쪽 눈가", "오른쪽 눈가", "왼쪽 눈밑", "오른쪽 눈밑", "왼쪽 팔자", "오른쪽 팔자",
        "왼쪽 볼", "오른쪽 볼", "코", "왼쪽 입가", "오른쪽 입가", "턱")
    /** 주름을 재는 부위 */
    val WRINKLE_REGIONS = intArrayOf(0, 1, 2, 3, 4, 5, 6, 7, 11, 12)
    /** 잔주름을 재는 부위 */
    val FINE_REGIONS = intArrayOf(0, 2, 3, 4, 5)
    // 부위별 기준값(시험 사진으로 맞춤): 점수 = 100·(1 - exp(-밀도/D0))
    private val D0 = floatArrayOf(.5f, .35f, .35f, .35f, .4f, .4f, .6f, .6f, 0f, 0f, 0f, .4f, .4f, 0f)
    private val WT = floatArrayOf(1f, .7f, 1f, 1f, .8f, .8f, 1f, 1f, 0f, 0f, 0f, .6f, .6f, 0f)

    private fun odd(v: Double) = (max(1, v.toInt()) or 1).toDouble()
    private fun ell(k: Double): Mat = Imgproc.getStructuringElement(Imgproc.MORPH_ELLIPSE, Size(odd(k), odd(k)))

    fun fmat(a: FloatArray, w: Int, h: Int): Mat = Mat(h, w, CvType.CV_32F).also { it.put(0, 0, a) }
    fun floats(m: Mat): FloatArray = FloatArray(m.rows() * m.cols()).also { m.get(0, 0, it) }
    private fun bytes(m: Mat): ByteArray = ByteArray(m.rows() * m.cols()).also { m.get(0, 0, it) }
    private fun gauss(m: Mat, sigma: Double): FloatArray {
        val d = Mat(); Imgproc.GaussianBlur(m, d, Size(0.0, 0.0), sigma)
        return floats(d).also { d.release() }
    }

    /** 볼록 껍질(점을 감싸는 가장 작은 볼록 다각형) — Andrew 단조 사슬 */
    fun hull(pts: List<Point>): List<Point> {
        val p = pts.sortedWith(compareBy({ it.x }, { it.y }))
        if (p.size < 3) return p
        fun cross(o: Point, a: Point, b: Point) = (a.x - o.x) * (b.y - o.y) - (a.y - o.y) * (b.x - o.x)
        val lower = ArrayList<Point>()
        for (q in p) { while (lower.size >= 2 && cross(lower[lower.size - 2], lower[lower.size - 1], q) <= 0) lower.removeAt(lower.size - 1); lower += q }
        val upper = ArrayList<Point>()
        for (q in p.asReversed()) { while (upper.size >= 2 && cross(upper[upper.size - 2], upper[upper.size - 1], q) <= 0) upper.removeAt(upper.size - 1); upper += q }
        lower.removeAt(lower.size - 1); upper.removeAt(upper.size - 1)
        return lower + upper
    }

    fun fillHull(m: Mat, q: FloatArray, idx: IntArray) {
        val pts = idx.map { Point(q[it * 2].toInt().toDouble(), q[it * 2 + 1].toInt().toDouble()) }
        Imgproc.fillConvexPoly(m, MatOfPoint(*hull(pts).toTypedArray()), org.opencv.core.Scalar(255.0))
    }

    private fun percentile(sorted: FloatArray, p: Double): Float {
        if (sorted.isEmpty()) return 0f
        val pos = (sorted.size - 1) * p / 100.0
        val lo = pos.toInt(); val hi = min(sorted.size - 1, lo + 1)
        return (sorted[lo] + (sorted[hi] - sorted[lo]) * (pos - lo)).toFloat()
    }

    /**
     * 헤시안 선 검출: 어두운 가는 선일수록 큰 값. scales 는 눈꼬리 거리(u)에 대한 비율.
     * v = (l2/4)·exp(-(|l1|/|l2|)²/0.5), l2 = 선을 가로지르는 방향의 곡률(깊이), |l1|/|l2| 가 작을수록 선 모양.
     */
    fun ridge(L: Mat, u: Float, scales: DoubleArray, minSigma: Double, pre: Double): FloatArray {
        val n = L.rows() * L.cols()
        val ls = Mat(); Imgproc.GaussianBlur(L, ls, Size(0.0, 0.0), pre)
        val v = FloatArray(n)
        val g = Mat(); val dxx = Mat(); val dyy = Mat(); val dxy = Mat()
        for (s in scales) {
            val sg = max(minSigma, s * u)
            Imgproc.GaussianBlur(ls, g, Size(0.0, 0.0), sg)
            Imgproc.Sobel(g, dxx, CvType.CV_32F, 2, 0, 3)
            Imgproc.Sobel(g, dyy, CvType.CV_32F, 0, 2, 3)
            Imgproc.Sobel(g, dxy, CvType.CV_32F, 1, 1, 3)
            val a = floats(dxx); val b = floats(dyy); val c = floats(dxy)
            val k2 = (sg * sg).toFloat()
            for (i in 0 until n) {
                val xx = a[i] * k2; val yy = b[i] * k2; val xy = c[i] * k2
                val t = sqrt((xx - yy) * (xx - yy) + 4 * xy * xy)
                val l2 = (xx + yy + t) / 2
                if (l2 <= 0f) continue
                val l1 = (xx + yy - t) / 2
                val rb = abs(l1) / (abs(l2) + 1e-6f)
                val vv = (l2 / 4f) * exp(-rb * rb / 0.5f)
                if (vv > v[i]) v[i] = vv
            }
        }
        listOf(ls, g, dxx, dyy, dxy).forEach { it.release() }
        return v
    }

    /** 약한 선(weak) 덩어리 중 길고 가늘며 확실한 부분(strong)이 있는 것만 남깁니다. depth 가 있으면 진하기 범위도 봅니다. */
    private fun keepLines(V: FloatArray, w: Int, h: Int, weak: Float, strong: Float, minLen: Float, fill: Float, fillAdd: Float,
                          minArea: Int, depth: FloatArray?): Pair<BooleanArray, IntArray> {
        val n = w * h
        val wb = ByteArray(n) { if (V[it] > weak) 1 else 0 }
        val wm = Mat(h, w, CvType.CV_8U); wm.put(0, 0, wb)
        val labels = Mat(); val stats = Mat(); val cents = Mat()
        val nl = Imgproc.connectedComponentsWithStats(wm, labels, stats, cents, 8, CvType.CV_32S)
        val lab = IntArray(n); labels.get(0, 0, lab)
        val st = IntArray(nl * 5); stats.get(0, 0, st)
        val hasStrong = BooleanArray(nl); val dsum = DoubleArray(nl)
        for (i in 0 until n) {
            val l = lab[i]; if (l == 0) continue
            if (V[i] > strong) hasStrong[l] = true
            if (depth != null) dsum[l] += depth[i]
        }
        val keep = BooleanArray(nl)
        for (l in 1 until nl) {
            val ww = st[l * 5 + 2]; val hh = st[l * 5 + 3]; val a = st[l * 5 + 4]
            if (a < minArea || max(ww, hh) < minLen || a > fill * ww * hh + fillAdd || !hasStrong[l]) continue
            if (depth != null) { val dm = dsum[l] / a; if (dm < 0.6 || dm > 12) continue } // 머리카락·그늘 경계처럼 너무 진한 선 제외
            keep[l] = true
        }
        val out = BooleanArray(n) { lab[it] != 0 && keep[lab[it]] }
        listOf(wm, labels, stats, cents).forEach { it.release() }
        return out to lab
    }

    /**
     * rgb: 얼굴 부분 RGB (CV_8UC3), q: 점 478개 (x, y 픽셀, rgb 기준), u: 눈꼬리(33·263) 사이 거리(픽셀),
     * skinProb: 얼굴 피부 확률 맵 (CV_32F, rgb 와 같은 크기, 없으면 null), iodOrig: 원본 사진에서의 눈꼬리 거리, yaw: 좌우 방향(도)
     */
    fun analyze(rgb: Mat, q: FloatArray, u: Float, skinProb: Mat?, iodOrig: Float, yaw: Float): SkinResult {
        val w = rgb.cols(); val h = rgb.rows(); val n = w * h
        fun qx(i: Int) = q[i * 2]
        fun qy(i: Int) = q[i * 2 + 1]
        val ud = u.toDouble()

        // 색 공간: Lab (L 0~100, a·b -128~127), HSV 채도
        val lab8 = Mat(); Imgproc.cvtColor(rgb, lab8, Imgproc.COLOR_RGB2Lab)
        val lb = ByteArray(n * 3); lab8.get(0, 0, lb); lab8.release()
        val L = FloatArray(n); val A = FloatArray(n); val B = FloatArray(n)
        for (i in 0 until n) {
            L[i] = (lb[i * 3].toInt() and 255) * (100f / 255f)
            A[i] = (lb[i * 3 + 1].toInt() and 255) - 128f
            B[i] = (lb[i * 3 + 2].toInt() and 255) - 128f
        }
        val hsv = Mat(); Imgproc.cvtColor(rgb, hsv, Imgproc.COLOR_RGB2HSV)
        val hb = ByteArray(n * 3); hsv.get(0, 0, hb); hsv.release()
        val Lm = fmat(L, w, h); val Am = fmat(A, w, h); val Bm = fmat(B, w, h)

        // 피부 영역: 얼굴 윤곽(넉넉히) ∩ 얼굴 피부(분할 모델) − 눈·눈썹·입술·콧구멍
        val face = Mat.zeros(h, w, CvType.CV_8U); fillHull(face, q, FaceIdx.OVAL)
        val excl = Mat.zeros(h, w, CvType.CV_8U)
        for (idx in listOf(FaceIdx.EYE_A, FaceIdx.EYE_B, FaceIdx.BROW_A, FaceIdx.BROW_B, FaceIdx.LIPS, FaceIdx.NOSTRIL)) fillHull(excl, q, idx)
        Imgproc.dilate(excl, excl, ell(0.05 * ud))
        val skinc = Mat()
        if (skinProb != null) {
            Imgproc.threshold(skinProb, skinc, 0.5, 255.0, Imgproc.THRESH_BINARY); skinc.convertTo(skinc, CvType.CV_8U)
            Imgproc.morphologyEx(skinc, skinc, Imgproc.MORPH_CLOSE, ell(0.06 * ud)) // 잡티 같은 작은 구멍 메움
            Imgproc.erode(skinc, skinc, ell(0.03 * ud))
        } else Imgproc.erode(face, skinc, ell(0.05 * ud))
        // 얼굴 윤곽점은 돌린 얼굴의 먼 쪽에서 실제 경계보다 안쪽에 놓이므로 넉넉히 키우고, 경계는 피부 분할이 정함
        val faceBig = Mat(); Imgproc.dilate(face, faceBig, ell(0.2 * ud))
        val skinM = Mat(); Core.bitwise_not(excl, excl); Core.bitwise_and(faceBig, excl, skinM); Core.bitwise_and(skinM, skinc, skinM)
        val sb = bytes(skinM); val fb = bytes(faceBig)
        val faceArea = Core.countNonZero(face)
        listOf(excl, skinc, skinM).forEach { it.release() }
        val sk = BooleanArray(n) { sb[it].toInt() != 0 }

        // 얼굴 기준 좌표: 눈꼬리 가운데가 원점, 눈꼬리 거리 = 1, 아래가 +Y
        val ox = (qx(33) + qx(263)) / 2; val oy = (qy(33) + qy(263)) / 2
        val exx = (qx(263) - qx(33)) / u; val exy = (qy(263) - qy(33)) / u
        val eyx = -exy; val eyy = exx
        fun ax(x: Float, y: Float) = ((x - ox) * exx + (y - oy) * exy) / u
        fun ay(x: Float, y: Float) = ((x - ox) * eyx + (y - oy) * eyy) / u

        // 눈 주변 제외: 위(쌍꺼풀 선)·아래(속눈썹 선)는 넓게, 옆(눈가 주름)은 좁게
        for ((a, b) in listOf(33 to 133, 362 to 263)) {
            val cx = (qx(a) + qx(b)) / 2; val cy = (qy(a) + qy(b)) / 2
            val hw = hypot(qx(b) - qx(a), qy(b) - qy(a)) / u / 2
            val r = (0.45f * u).toInt()
            for (y in max(0, cy.toInt() - r) until min(h, cy.toInt() + r + 1)) for (x in max(0, cx.toInt() - r) until min(w, cx.toInt() + r + 1)) {
                val xe = ((x - cx) * exx + (y - cy) * exy) / u; val ye = ((x - cx) * eyx + (y - cy) * eyy) / u
                val ex = xe / (hw + 0.035f); val ey = ye / (if (ye < 0) 0.17f else 0.12f)
                if (ex * ex + ey * ey < 1f) sk[y * w + x] = false
            }
        }

        // 부위 (비트)
        val brow = (FaceIdx.BROW_A + FaceIdx.BROW_B)
        val browTop = brow.minOf { ay(qx(it), qy(it)) }
        val topY = ay(qx(10), qy(10))
        val y17 = ay(qx(17), qy(17))
        val noseM = Mat.zeros(h, w, CvType.CV_8U); fillHull(noseM, q, FaceIdx.NOSE)
        val nb = bytes(noseM); noseM.release()
        fun segDist(px: Float, py: Float, ax0: Float, ay0: Float, bx: Float, by: Float): Float {
            val dx = bx - ax0; val dy = by - ay0
            val t = (((px - ax0) * dx + (py - ay0) * dy) / (dx * dx + dy * dy + 1e-6f)).coerceIn(0f, 1f)
            return hypot(px - (ax0 + t * dx), py - (ay0 + t * dy)) / u
        }
        val mlx = qx(61) + eyx * u * 0.28f; val mly = qy(61) + eyy * u * 0.28f
        val mrx = qx(291) + eyx * u * 0.28f; val mry = qy(291) + eyy * u * 0.28f
        val reg = IntArray(n)
        for (y in 0 until h) for (x in 0 until w) {
            val i = y * w + x
            val fx = x.toFloat(); val fy = y.toFloat()
            val X = ax(fx, fy); val Y = ay(fx, fy)
            var m = 0
            if (Y < browTop - 0.04f && Y > topY + 0.03f && abs(X) < 0.7f) m = m or 1
            if (abs(X) < 0.17f && Y > browTop - 0.02f && Y < -0.03f) m = m or 2
            if (-X > 0.5f && -X < 0.85f && Y > -0.2f && Y < 0.25f) m = m or (1 shl 2)
            if (X > 0.5f && X < 0.85f && Y > -0.2f && Y < 0.25f) m = m or (1 shl 3)
            if (-X > 0.1f && -X < 0.5f && Y > 0.07f && Y < 0.3f) m = m or (1 shl 4)
            if (X > 0.1f && X < 0.5f && Y > 0.07f && Y < 0.3f) m = m or (1 shl 5)
            val nlA = Y > 0f && segDist(fx, fy, qx(129), qy(129), qx(61), qy(61)) < 0.07f
            val nlB = Y > 0f && segDist(fx, fy, qx(358), qy(358), qx(291), qy(291)) < 0.07f
            if (nlA) m = m or (1 shl 6)
            if (nlB) m = m or (1 shl 7)
            if (-X > 0.22f && -X < 0.78f && Y > 0.3f && Y < 0.85f && !nlA) m = m or (1 shl 8)
            if (X > 0.22f && X < 0.78f && Y > 0.3f && Y < 0.85f && !nlB) m = m or (1 shl 9)
            if (nb[i].toInt() != 0) m = m or (1 shl 10)
            if (Y > 0f && segDist(fx, fy, qx(61), qy(61), mlx, mly) < 0.07f) m = m or (1 shl 11)
            if (Y > 0f && segDist(fx, fy, qx(291), qy(291), mrx, mry) < 0.07f) m = m or (1 shl 12)
            if (abs(X) < 0.3f && Y > y17 + 0.05f) m = m or (1 shl 13)
            reg[i] = m
        }
        // 부위가 보이는 비율 (머리카락·모자·안경에 가려진 정도)
        val vis = FloatArray(REGIONS.size)
        run {
            val inFace = IntArray(REGIONS.size); val inSkin = IntArray(REGIONS.size)
            for (i in 0 until n) {
                val m = reg[i]; if (m == 0) continue
                for (k in REGIONS.indices) if (m and (1 shl k) != 0) {
                    if (fb[i].toInt() != 0) inFace[k]++
                    if (sk[i]) inSkin[k]++
                }
            }
            for (k in REGIONS.indices) vis[k] = inSkin[k].toFloat() / max(1, inFace[k])
        }
        for (i in 0 until n) if (!sk[i]) reg[i] = 0

        // 피부 경계(머리카락·배경과 닿는 곳)의 그늘은 주름·잡티가 아님
        val skin8 = Mat(h, w, CvType.CV_8U); skin8.put(0, 0, ByteArray(n) { if (sk[it]) 1 else 0 })
        val dist = Mat(); Imgproc.distanceTransform(skin8, dist, Imgproc.DIST_L2, 3)
        val bd = floats(dist); dist.release(); skin8.release()
        val inner = BooleanArray(n) { bd[it] / u > 0.035f }

        // 1) 주름
        val V = ridge(Lm, u, doubleArrayOf(0.004, 0.007, 0.011), 0.8, 0.6)
        for (i in 0 until n) if (!sk[i] || !inner[i] || nb[i].toInt() != 0) V[i] = 0f
        val bgL = gauss(Lm, 0.02 * ud)
        val depth = FloatArray(n) { bgL[it] - L[it] }
        val (wr, wlab) = keepLines(V, w, h, WEAK, STRONG, 0.05f * u, 0.6f, 5f, 4, depth)

        // 2) 잔주름 (더 가는 선, 깨끗한 피부에서는 거의 0)
        val VF = ridge(Lm, u, doubleArrayOf(0.0025, 0.004), 0.7, 0.5)
        for (i in 0 until n) if (!sk[i] || !inner[i] || nb[i].toInt() != 0) VF[i] = 0f
        val (fine, _) = keepLines(VF, w, h, 0.5f, 1.0f, 0.03f * u, 0.55f, 4f, 3, null)

        // 3) 모공: 작고 동그란 어두운 점 (DoG 극대)
        val g1 = gauss(Lm, max(0.6, 0.0035 * ud)); val g2 = gauss(Lm, max(1.2, 0.009 * ud))
        val dog = FloatArray(n) { g2[it] - g1[it] }
        val dogM = fmat(dog, w, h); val mxM = Mat()
        Imgproc.dilate(dogM, mxM, Mat.ones(3, 3, CvType.CV_8U))
        val mx = floats(mxM); dogM.release(); mxM.release()
        val wr8 = Mat(h, w, CvType.CV_8U); wr8.put(0, 0, ByteArray(n) { if (wr[it]) 1 else 0 })
        Imgproc.dilate(wr8, wr8, Mat.ones(5, 5, CvType.CV_8U))
        val wrd = bytes(wr8); wr8.release()
        val poreList = ArrayList<Int>()
        val pore = BooleanArray(n)
        for (i in 0 until n) if (sk[i] && inner[i] && dog[i] > 1.2f && dog[i] >= mx[i] && wrd[i].toInt() == 0) { pore[i] = true; poreList += i }

        // 4) 잡티: 주변보다 어두운 동그란 얼룩 (모공보다 큼)
        val bg = gauss(Lm, 0.05 * ud); val sm = gauss(Lm, 0.006 * ud)
        val sp = Mat(h, w, CvType.CV_8U)
        sp.put(0, 0, ByteArray(n) { if (sk[it] && inner[it] && bg[it] - sm[it] > 5f) 1 else 0 })
        val spots = ArrayList<FloatArray>()
        val spotPix = BooleanArray(n)
        run {
            val labels = Mat(); val stats = Mat(); val cents = Mat()
            val nl = Imgproc.connectedComponentsWithStats(sp, labels, stats, cents, 8, CvType.CV_32S)
            val st = IntArray(nl * 5); stats.get(0, 0, st)
            val ce = DoubleArray(nl * 2); cents.get(0, 0, ce)
            val lab = IntArray(n); labels.get(0, 0, lab)
            val amin = (0.012f * u) * (0.012f * u); val amax = (0.09f * u) * (0.09f * u)
            val ok = BooleanArray(nl)
            for (l in 1 until nl) {
                val ww = st[l * 5 + 2]; val hh = st[l * 5 + 3]; val a = st[l * 5 + 4]
                if (a >= amin && a <= amax && max(ww, hh) <= 3 * min(ww, hh) + 2) {
                    ok[l] = true; spots += floatArrayOf(ce[l * 2].toFloat(), ce[l * 2 + 1].toFloat(), sqrt(a / Math.PI.toFloat()))
                }
            }
            for (i in 0 until n) if (lab[i] != 0 && ok[lab[i]]) spotPix[i] = true
            listOf(labels, stats, cents).forEach { it.release() }
        }
        sp.release()

        // 피부 통계
        var skinCount = 0
        for (i in 0 until n) if (sk[i]) skinCount++
        val skA = FloatArray(skinCount); val skL = FloatArray(skinCount)
        run { var j = 0; for (i in 0 until n) if (sk[i]) { skA[j] = A[i]; skL[j] = L[i]; j++ } }
        skA.sort(); skL.sort()
        val amed = percentile(skA, 50.0)
        val dev = FloatArray(skinCount) { abs(skA[it] - amed) }; dev.sort()
        val mad = 1.4826f * percentile(dev, 50.0)
        val lp97 = percentile(skL, 97.0); val lmed = percentile(skL, 50.0)

        // 5) 홍조: 피부 평균보다 뚜렷이 붉은 곳
        val redT = max(6f, 2.5f * mad)
        val red = BooleanArray(n) { sk[it] && A[it] - amed > redT }
        // 6) 번들거림: T존(이마·미간·코)의 아주 밝고 채도 낮은 곳
        val tz = 1 or 2 or (1 shl 10)
        val shine = BooleanArray(n) { reg[it] and tz != 0 && L[it] >= lp97 && L[it] > lmed + 15f && (hb[it * 3 + 1].toInt() and 255) < 70 }

        fun count(bits: Int, f: (Int) -> Boolean = { true }): Int { var c = 0; for (i in 0 until n) if (reg[i] and bits != 0 && f(i)) c++; return c }
        fun meanL(bits: Int): Float { var s = 0.0; var c = 0; for (i in 0 until n) if (reg[i] and bits != 0) { s += L[i]; c++ }; return if (c == 0) Float.NaN else (s / c).toFloat() }
        val cheeks = (1 shl 8) or (1 shl 9) or (1 shl 10)
        val under = (1 shl 4) or (1 shl 5)

        // 부위별 주름 점수
        val regionScores = LinkedHashMap<String, Float?>()
        val regionLines = HashMap<String, Int>()
        val dens = FloatArray(REGIONS.size); val area = IntArray(REGIONS.size)
        val fineDens = FloatArray(REGIONS.size)
        val linesIn = Array(REGIONS.size) { HashSet<Int>() }
        for (i in 0 until n) {
            val m = reg[i]; if (m == 0) continue
            for (k in REGIONS.indices) if (m and (1 shl k) != 0) {
                area[k]++
                if (wr[i]) { dens[k] += V[i]; linesIn[k].add(wlab[i]) }
                if (fine[i]) fineDens[k] += VF[i]
            }
        }
        var wsum = 0f; var wtot = 0f
        for (k in WRINKLE_REGIONS) {
            val d = dens[k] / max(1, area[k])
            val s = if (vis[k] >= 0.3f && area[k] > 0) (100 * (1 - exp(-d / D0[k]))) else null
            regionScores[REGIONS[k]] = s?.let { (it * 10).roundToInt() / 10f }
            regionLines[REGIONS[k]] = linesIn[k].size
            if (s != null) { wsum += s * WT[k]; wtot += WT[k] }
        }
        val fineScores = LinkedHashMap<String, Float?>()
        var fsum = 0f; var fcnt = 0
        for (k in FINE_REGIONS) {
            val d = fineDens[k] / max(1, area[k])
            val s = if (vis[k] >= 0.3f && area[k] > 0) 100 * (1 - exp(-d / 0.08f)) else null
            fineScores[REGIONS[k]] = s?.let { (it * 10).roundToInt() / 10f }
            if (s != null) { fsum += s; fcnt++ }
        }

        // 나머지 항목
        val cheekArea = count(cheeks)
        val poreN = poreList.count { reg[it] and cheeks != 0 }
        val poreDensity = poreN / max(1e-3f, cheekArea / (u * u))
        var spotArea = 0; for (i in 0 until n) if (spotPix[i]) spotArea++
        val spotPct = 100f * spotArea / max(1, skinCount)
        val rcBits = cheeks or (1 shl 13)
        val redPct = 100f * count(rcBits) { red[it] } / max(1, count(rcBits))
        val shinePct = 100f * count(tz) { shine[it] } / max(1, count(tz))
        val dc = (meanL((1 shl 8) or (1 shl 9)) - meanL(under)).let { if (it.isNaN()) 0f else it }
        val ma1 = gauss(Am, 0.03 * ud); val ma2 = gauss(Am, 0.2 * ud); val mb1 = gauss(Bm, 0.03 * ud); val mb2 = gauss(Bm, 0.2 * ud)
        fun std(f: (Int) -> Float, use: (Int) -> Boolean): Float {
            var s = 0.0; var s2 = 0.0; var c = 0
            for (i in 0 until n) if (use(i)) { val v = f(i).toDouble(); s += v; s2 += v * v; c++ }
            if (c < 2) return 0f
            val m = s / c; return sqrt(max(0.0, s2 / c - m * m)).toFloat()
        }
        val sa = std({ ma1[it] - ma2[it] }, { sk[it] }); val sbb = std({ mb1[it] - mb2[it] }, { sk[it] })
        val tone = sqrt(sa * sa + sbb * sbb)
        val hp = gauss(Lm, 0.006 * ud)
        val texture = std({ L[it] - hp[it] }, { reg[it] and cheeks != 0 && !pore[it] && !wr[it] })

        val wrinkleDeg = if (wtot > 0) wsum / wtot else 0f
        fun sat(v: Float, d: Float) = (100 * (1 - exp(-max(0f, v) / d)))
        val metrics = listOf(
            SkinMetric("wrinkle", "주름", wrinkleDeg, "%.0f / 100".format(wrinkleDeg), "부위별 주름 길이×깊이의 넓이당 양"),
            SkinMetric("fine", "잔주름", if (fcnt > 0) fsum / fcnt else 0f, "%.0f / 100".format(if (fcnt > 0) fsum / fcnt else 0f), "아주 가는 선 (이마·눈가·눈밑)"),
            SkinMetric("pore", "모공", sat(poreDensity, 150f), "%d개 (볼·코)".format(poreN), "눈꼬리 거리² 넓이당 %.0f개".format(poreDensity)),
            SkinMetric("spot", "잡티·색소", sat(spotPct, 2.5f), "%d개, 피부의 %.1f%%".format(spots.size, spotPct), "주변보다 어두운 동그란 얼룩"),
            SkinMetric("red", "홍조", sat(redPct, 10f), "볼·코·턱의 %.1f%%".format(redPct), "피부 평균보다 뚜렷이 붉은 곳"),
            SkinMetric("shine", "번들거림(유분)", sat(shinePct, 12f), "T존의 %.1f%%".format(shinePct), "이마·코의 반사광"),
            SkinMetric("dark", "다크서클", ((dc - 2f) * 8f).coerceIn(0f, 100f), "볼보다 %.1f 어두움".format(dc), "눈밑과 볼의 밝기(L) 차"),
            SkinMetric("tone", "톤 불균일", sat(tone - 1.5f, 5f), "색 얼룩 %.1f".format(tone), "붉은기·누런기의 고르지 않음"),
            SkinMetric("texture", "피부결 거칠기", sat(texture, 2.5f), "%.2f".format(texture), "볼의 미세한 요철 (사진 화질 영향 큼)"),
        )
        val wt = mapOf("wrinkle" to .25f, "fine" to .05f, "spot" to .15f, "pore" to .1f, "red" to .1f, "tone" to .1f, "texture" to .1f, "dark" to .1f, "shine" to .05f)
        val overall = (100f - metrics.sumOf { (it.degree * (wt[it.key] ?: 0f)).toDouble() }.toFloat()).roundToInt().coerceIn(0, 100)

        val warnings = ArrayList<String>()
        if (iodOrig < 160f) warnings += "얼굴이 작게 찍혀 잔주름·모공은 정확하지 않습니다. 더 가까이서 찍은 사진을 쓰세요."
        else if (iodOrig < 300f) warnings += "잔주름까지 정확히 보려면 얼굴이 더 크게 나온 고해상도 사진이 좋습니다."
        if (lmed < 35f) warnings += "사진이 어두워 결과가 부정확할 수 있습니다."
        val la = meanL(1 shl 8); val lbb = meanL(1 shl 9)
        if (!la.isNaN() && !lbb.isNaN() && abs(la - lbb) > 12f) warnings += "조명이 한쪽으로 치우쳐 있습니다. 그늘진 쪽 주름이 실제보다 강하게 나올 수 있습니다."
        if (abs(yaw) > 20f) warnings += "얼굴이 옆으로 돌아가 있습니다. 정면 사진이 가장 정확합니다."
        if (skinCount < faceArea * 0.45f) warnings += "머리카락·안경·손 등에 가려진 부분이 많습니다."

        listOf(Lm, Am, Bm, face, faceBig).forEach { it.release() }
        return SkinResult(w, h, u, sk, reg, wr, V, fine, poreList.toIntArray(), spots, red, shine,
            regionScores, fineScores, regionLines, metrics, overall, warnings)
    }
}
