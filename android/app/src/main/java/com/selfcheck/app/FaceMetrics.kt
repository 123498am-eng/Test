package com.selfcheck.app

import kotlin.math.abs
import kotlin.math.hypot
import kotlin.math.max
import kotlin.math.min
import kotlin.math.roundToInt
import kotlin.math.sqrt

/** 얼굴 비율·대칭·치수 분석 결과 */
class FaceMetrics(
    /** 좌우 대칭 점수 0~100 (100 = 완전 대칭) */
    val symmetry: Int,
    /** 평균 비대칭 (눈꼬리 거리 대비 %) */
    val asymPct: Float,
    val symReliable: Boolean,
    val parts: List<Pair<String, String>>,
    /** 위(점 10~미간)·가운데(미간~코밑)·아래(코밑~턱) 길이 비율 % */
    val thirds: FloatArray,
    /** 코밑~입 : 입~턱 */
    val lowerSplit: FloatArray,
    /** 얼굴 너비 5등분 (얼굴 끝~눈꼬리, 눈, 미간, 눈, 눈꼬리~얼굴 끝) % */
    val fifths: FloatArray,
    val shape: String,
    val shapeWhy: String,
    val ratios: List<Pair<String, String>>,
    val mmPerPx: Float,
    val measures: List<Pair<String, String>>,
    val expression: String,
    val topBlend: List<Pair<String, Float>>,
    val notes: List<String>,
)

/** 3D 점 맞추기 (Horn 사원수 방법): 이동·회전으로 b 를 a 에 최대한 겹친 뒤 평균 거리 */
object Geom3 {
    /** 대칭 4×4 행렬의 가장 큰 고유값의 고유벡터 (Jacobi 회전) */
    fun topEigen4(m: Array<DoubleArray>): DoubleArray {
        val a = Array(4) { m[it].copyOf() }
        val v = Array(4) { i -> DoubleArray(4) { j -> if (i == j) 1.0 else 0.0 } }
        repeat(60) {
            var off = 0.0
            for (p in 0 until 4) for (q in p + 1 until 4) off += a[p][q] * a[p][q]
            if (off < 1e-22) return@repeat
            for (p in 0 until 4) for (q in p + 1 until 4) {
                if (abs(a[p][q]) < 1e-30) continue
                val theta = (a[q][q] - a[p][p]) / (2 * a[p][q])
                val t = (if (theta >= 0) 1.0 else -1.0) / (abs(theta) + sqrt(theta * theta + 1))
                val c = 1 / sqrt(t * t + 1); val s = t * c
                for (k in 0 until 4) {
                    val akp = a[k][p]; val akq = a[k][q]
                    a[k][p] = c * akp - s * akq; a[k][q] = s * akp + c * akq
                }
                for (k in 0 until 4) {
                    val apk = a[p][k]; val aqk = a[q][k]
                    a[p][k] = c * apk - s * aqk; a[q][k] = s * apk + c * aqk
                }
                for (k in 0 until 4) {
                    val vkp = v[k][p]; val vkq = v[k][q]
                    v[k][p] = c * vkp - s * vkq; v[k][q] = s * vkp + c * vkq
                }
            }
        }
        var best = 0
        for (i in 1 until 4) if (a[i][i] > a[best][best]) best = i
        return DoubleArray(4) { v[it][best] }
    }

    /** a, b: 점 n 개 (x,y,z 이어 붙임). b 를 회전·이동해 a 에 맞춘 뒤 평균 거리 */
    fun alignResidual(a: DoubleArray, b: DoubleArray): Double {
        val n = a.size / 3
        val ca = DoubleArray(3); val cb = DoubleArray(3)
        for (i in 0 until n) for (k in 0 until 3) { ca[k] += a[i * 3 + k] / n; cb[k] += b[i * 3 + k] / n }
        val s = Array(3) { DoubleArray(3) } // s[i][j] = Σ b_i a_j
        for (p in 0 until n) for (i in 0 until 3) for (j in 0 until 3) s[i][j] += (b[p * 3 + i] - cb[i]) * (a[p * 3 + j] - ca[j])
        val (sxx, sxy, sxz) = Triple(s[0][0], s[0][1], s[0][2])
        val (syx, syy, syz) = Triple(s[1][0], s[1][1], s[1][2])
        val (szx, szy, szz) = Triple(s[2][0], s[2][1], s[2][2])
        val nm = arrayOf(
            doubleArrayOf(sxx + syy + szz, syz - szy, szx - sxz, sxy - syx),
            doubleArrayOf(syz - szy, sxx - syy - szz, sxy + syx, szx + sxz),
            doubleArrayOf(szx - sxz, sxy + syx, -sxx + syy - szz, syz + szy),
            doubleArrayOf(sxy - syx, szx + sxz, syz + szy, -sxx - syy + szz),
        )
        val q = topEigen4(nm)
        val (q0, q1, q2, q3) = listOf(q[0], q[1], q[2], q[3])
        val r = arrayOf(
            doubleArrayOf(q0 * q0 + q1 * q1 - q2 * q2 - q3 * q3, 2 * (q1 * q2 - q0 * q3), 2 * (q1 * q3 + q0 * q2)),
            doubleArrayOf(2 * (q2 * q1 + q0 * q3), q0 * q0 - q1 * q1 + q2 * q2 - q3 * q3, 2 * (q2 * q3 - q0 * q1)),
            doubleArrayOf(2 * (q3 * q1 - q0 * q2), 2 * (q3 * q2 + q0 * q1), q0 * q0 - q1 * q1 - q2 * q2 + q3 * q3),
        )
        var sum = 0.0
        for (p in 0 until n) {
            val bx = b[p * 3] - cb[0]; val by = b[p * 3 + 1] - cb[1]; val bz = b[p * 3 + 2] - cb[2]
            val rx = r[0][0] * bx + r[0][1] * by + r[0][2] * bz
            val ry = r[1][0] * bx + r[1][1] * by + r[1][2] * bz
            val rz = r[2][0] * bx + r[2][1] * by + r[2][2] * bz
            val dx = rx - (a[p * 3] - ca[0]); val dy = ry - (a[p * 3 + 1] - ca[1]); val dz = rz - (a[p * 3 + 2] - ca[2])
            sum += sqrt(dx * dx + dy * dy + dz * dz)
        }
        return sum / n
    }
}

object FaceMetricsCalc {
    private val BLEND_KO = mapOf(
        "_neutral" to "무표정", "browDownLeft" to "눈썹 내림 (왼)", "browDownRight" to "눈썹 내림 (오른)", "browInnerUp" to "눈썹 안쪽 올림",
        "browOuterUpLeft" to "눈썹 바깥 올림 (왼)", "browOuterUpRight" to "눈썹 바깥 올림 (오른)", "cheekPuff" to "볼 부풀림",
        "cheekSquintLeft" to "볼 올림 (왼)", "cheekSquintRight" to "볼 올림 (오른)", "eyeBlinkLeft" to "눈 감음 (왼)", "eyeBlinkRight" to "눈 감음 (오른)",
        "eyeLookDownLeft" to "아래 봄 (왼눈)", "eyeLookDownRight" to "아래 봄 (오른눈)", "eyeLookInLeft" to "안쪽 봄 (왼눈)", "eyeLookInRight" to "안쪽 봄 (오른눈)",
        "eyeLookOutLeft" to "바깥 봄 (왼눈)", "eyeLookOutRight" to "바깥 봄 (오른눈)", "eyeLookUpLeft" to "위 봄 (왼눈)", "eyeLookUpRight" to "위 봄 (오른눈)",
        "eyeSquintLeft" to "눈 찡그림 (왼)", "eyeSquintRight" to "눈 찡그림 (오른)", "eyeWideLeft" to "눈 크게 뜸 (왼)", "eyeWideRight" to "눈 크게 뜸 (오른)",
        "jawForward" to "턱 내밂", "jawLeft" to "턱 왼쪽", "jawOpen" to "입 벌림", "jawRight" to "턱 오른쪽", "mouthClose" to "입 다묾",
        "mouthDimpleLeft" to "보조개 (왼)", "mouthDimpleRight" to "보조개 (오른)", "mouthFrownLeft" to "입꼬리 내림 (왼)", "mouthFrownRight" to "입꼬리 내림 (오른)",
        "mouthFunnel" to "입 동그랗게", "mouthLeft" to "입 왼쪽", "mouthLowerDownLeft" to "아랫입술 내림 (왼)", "mouthLowerDownRight" to "아랫입술 내림 (오른)",
        "mouthPressLeft" to "입술 누름 (왼)", "mouthPressRight" to "입술 누름 (오른)", "mouthPucker" to "입 오므림", "mouthRight" to "입 오른쪽",
        "mouthRollLower" to "아랫입술 말기", "mouthRollUpper" to "윗입술 말기", "mouthShrugLower" to "아랫입술 올림", "mouthShrugUpper" to "윗입술 올림",
        "mouthSmileLeft" to "입꼬리 올림 (왼)", "mouthSmileRight" to "입꼬리 올림 (오른)", "mouthStretchLeft" to "입 옆으로 (왼)", "mouthStretchRight" to "입 옆으로 (오른)",
        "mouthUpperUpLeft" to "윗입술 들기 (왼)", "mouthUpperUpRight" to "윗입술 들기 (오른)", "noseSneerLeft" to "코 찡그림 (왼)", "noseSneerRight" to "코 찡그림 (오른)",
    )
    fun blendName(k: String) = BLEND_KO[k] ?: k

    /** 표정 이름 (블렌드셰이프 값으로 간단히 나눔) */
    fun expression(b: Map<String, Float>): String {
        fun g(k: String) = b[k] ?: 0f
        fun avg(a: String, c: String) = (g(a) + g(c)) / 2
        val blinkL = g("eyeBlinkLeft"); val blinkR = g("eyeBlinkRight")
        val smile = avg("mouthSmileLeft", "mouthSmileRight"); val jaw = g("jawOpen")
        return when {
            (blinkL > 0.6f && blinkR < 0.3f) || (blinkR > 0.6f && blinkL < 0.3f) -> "윙크"
            blinkL > 0.6f && blinkR > 0.6f -> "눈 감음"
            smile > 0.5f -> if (jaw > 0.3f) "활짝 웃음" else "미소"
            avg("eyeWideLeft", "eyeWideRight") > 0.3f && (jaw > 0.3f || g("browInnerUp") > 0.5f) -> "놀람"
            avg("browDownLeft", "browDownRight") > 0.4f || avg("noseSneerLeft", "noseSneerRight") > 0.4f -> "찡그림"
            avg("mouthFrownLeft", "mouthFrownRight") > 0.3f && g("browInnerUp") > 0.3f -> "슬픈 표정"
            g("mouthPucker") > 0.5f -> "입 오므림"
            g("cheekPuff") > 0.4f -> "볼 부풀림"
            jaw > 0.4f -> "입 벌림"
            smile > 0.25f -> "살짝 미소"
            else -> "무표정"
        }
    }

    /**
     * pts: 점 478개 (x,y 는 0~1, z 는 너비 기준), w·h: 사진 크기, mirror: 좌우 짝 번호표, yaw: 좌우 방향(도), blend: 표정 값
     */
    fun compute(pts: FloatArray, w: Float, h: Float, mirror: IntArray, yaw: Float, blend: Map<String, Float>): FaceMetrics {
        val n = min(pts.size / 3, 478)
        fun x(i: Int) = pts[i * 3] * w
        fun y(i: Int) = pts[i * 3 + 1] * h
        fun z(i: Int) = pts[i * 3 + 2] * w
        val notes = ArrayList<String>()

        // 1) 좌우 대칭: 점들을 좌우로 뒤집어(번호도 짝끼리 바꿈) 원래 얼굴에 3D 로 맞춘 뒤 남는 차이.
        //    MediaPipe 의 깊이(z) 크기가 얼굴 방향에 따라 달라서, 깊이 배율을 몇 가지 시험해 가장 잘 맞는 것을 씁니다.
        val m = min(468, n)
        var best = Double.MAX_VALUE; var bestZs = 1.0
        for (zs in doubleArrayOf(0.8, 1.0, 1.2, 1.4, 1.6, 1.8)) {
            val a = DoubleArray(m * 3); val b = DoubleArray(m * 3)
            for (i in 0 until m) {
                a[i * 3] = x(i).toDouble(); a[i * 3 + 1] = y(i).toDouble(); a[i * 3 + 2] = z(i) * zs
                val j = mirror[i]
                b[i * 3] = -x(j).toDouble(); b[i * 3 + 1] = y(j).toDouble(); b[i * 3 + 2] = z(j) * zs
            }
            val r = Geom3.alignResidual(a, b)
            if (r < best) { best = r; bestZs = zs }
        }
        val zs = bestZs.toFloat()
        fun d3(i: Int, j: Int): Float {
            val dx = x(i) - x(j); val dy = y(i) - y(j); val dz = (z(i) - z(j)) * zs
            return sqrt(dx * dx + dy * dy + dz * dz)
        }
        val iod3 = d3(33, 263).coerceAtLeast(1e-3f)
        val asym = (best / iod3 * 100).toFloat()
        val symmetry = (100f - 25f * max(0f, asym - 0.3f)).roundToInt().coerceIn(0, 100)
        val reliable = abs(yaw) <= 12f
        if (!reliable) notes += "얼굴이 옆으로 ${abs(yaw).roundToInt()}° 돌아가 있어 대칭·비율은 참고만 하세요 (정면 사진이 정확합니다)."

        // 2) 크기 기준: 홍채 지름은 사람마다 거의 같음 (약 11.7mm)
        val irisA = max(hypot(x(469) - x(471), y(469) - y(471)), hypot(x(470) - x(472), y(470) - y(472)))
        val irisB = max(hypot(x(474) - x(476), y(474) - y(476)), hypot(x(475) - x(477), y(475) - y(477)))
        // 가로·세로 지름 중 큰 값 (눈꺼풀에 가리거나 얼굴이 돌아가면 한쪽이 작아짐), 두 눈 중 큰 값
        val iris = if (n >= 478) max(irisA, irisB) else 0f
        val mmPerPx = if (iris > 1f) 11.7f / iris else 0f

        // 3) 얼굴 기준 좌표 (기울기 보정): 눈꼬리 가운데 원점, 아래 +Y
        val ux = (x(263) - x(33)); val uy = (y(263) - y(33)); val ul = hypot(ux, uy).coerceAtLeast(1e-3f)
        val exx = ux / ul; val exy = uy / ul
        val ox = (x(33) + x(263)) / 2; val oy = (y(33) + y(263)) / 2
        fun ax(i: Int) = (x(i) - ox) * exx + (y(i) - oy) * exy
        fun ay(i: Int) = -(x(i) - ox) * exy + (y(i) - oy) * exx
        fun meanAy(idx: IntArray) = idx.map { ay(it) }.average().toFloat()
        fun mm(px: Float) = if (mmPerPx > 0) "%.1f mm".format(px * mmPerPx) else "%.1f%%".format(px / ul * 100)

        val parts = ArrayList<Pair<String, String>>()
        fun side(v: Float, pos: String, neg: String) = if (abs(v) < 1e-3f) "같음" else if (v > 0) pos else neg
        val eyeD = meanAy(FaceIdx.EYE_A) - meanAy(FaceIdx.EYE_B)
        parts += "눈 높이 차" to "${mm(abs(eyeD))} (${side(eyeD, "사진 오른쪽 눈이 높음", "사진 왼쪽 눈이 높음")})"
        val browD = meanAy(FaceIdx.BROW_A) - meanAy(FaceIdx.BROW_B)
        parts += "눈썹 높이 차" to "${mm(abs(browD))} (${side(browD, "사진 오른쪽이 높음", "사진 왼쪽이 높음")})"
        val mouthD = ay(61) - ay(291)
        parts += "입꼬리 높이 차" to "${mm(abs(mouthD))} (${side(mouthD, "사진 오른쪽이 높음", "사진 왼쪽이 높음")})"
        val mid = (ax(133) + ax(362)) / 2
        val noseD = ax(1) - mid
        parts += "코끝 치우침" to "${mm(abs(noseD))} (${side(noseD, "사진 오른쪽으로", "사진 왼쪽으로")})"
        val chinD = ax(152) - mid
        parts += "턱끝 치우침" to "${mm(abs(chinD))} (${side(chinD, "사진 오른쪽으로", "사진 왼쪽으로")})"
        val openA = hypot(x(159) - x(145), y(159) - y(145)); val openB = hypot(x(386) - x(374), y(386) - y(374))
        if (max(openA, openB) > 0.5f) parts += "눈 뜬 크기 차" to "%.0f%%".format(abs(openA - openB) / max(openA, openB) * 100)

        // 4) 비율
        val top = ay(10); val glab = ay(9); val sub = ay(2); val chin = ay(152); val stom = (ay(13) + ay(14)) / 2
        val t1 = glab - top; val t2 = sub - glab; val t3 = chin - sub; val ts = (t1 + t2 + t3).coerceAtLeast(1e-3f)
        val thirds = floatArrayOf(t1 / ts * 100, t2 / ts * 100, t3 / ts * 100)
        val l1 = stom - sub; val l2 = chin - stom; val ls = (l1 + l2).coerceAtLeast(1e-3f)
        val lower = floatArrayOf(l1 / ls * 100, l2 / ls * 100)
        val seg = floatArrayOf(abs(ax(33) - ax(234)), abs(ax(133) - ax(33)), abs(ax(362) - ax(133)), abs(ax(263) - ax(362)), abs(ax(454) - ax(263)))
        val segSum = seg.sum().coerceAtLeast(1e-3f)
        val fifths = FloatArray(5) { seg[it] / segSum * 100 }

        // 5) 얼굴형 (3D 거리 → 얼굴 방향 영향 줄임)
        val wc = d3(234, 454); val wj = d3(172, 397); val wf = d3(54, 284); val len = d3(10, 152)
        val rl = len / wc; val rj = wj / wc; val rf = wf / wc
        val shape = when {
            rj > 0.84f -> if (rl > 1.22f) "직사각형(긴 각진형)" else "각진형"
            rl > 1.28f -> "긴 얼굴형"
            rl < 1.05f -> "둥근형"
            rj < 0.74f && rf > 0.86f -> "하트형(역삼각형)"
            rj < 0.74f && rf < 0.78f -> "다이아몬드형"
            else -> "계란형"
        }
        val why = "길이/너비 %.2f (보통 1.15), 턱/광대 %.2f (보통 0.78), 이마/광대 %.2f (보통 0.82)".format(rl, rj, rf)
        val ratios = listOf(
            "눈 사이 / 눈 너비" to "%.2f (1에 가까울수록 표준)".format(abs(ax(362) - ax(133)) / ((seg[1] + seg[3]) / 2).coerceAtLeast(1e-3f)),
            "입 너비 / 코 너비" to "%.2f (보통 1.4~1.6)".format(d3(61, 291) / d3(129, 358).coerceAtLeast(1e-3f)),
            "아랫입술 / 윗입술 두께" to "%.2f".format(d3(14, 17) / d3(0, 13).coerceAtLeast(1e-3f)),
            "얼굴 길이 / 너비" to "%.2f".format(rl),
        )

        val measures = ArrayList<Pair<String, String>>()
        if (mmPerPx > 0f) {
            fun mm3(i: Int, j: Int) = "%.0f mm".format(d3(i, j) * mmPerPx)
            measures += "동공 사이 거리" to "%.1f mm".format(d3(468, 473) * mmPerPx)
            measures += "얼굴 너비 (귀 앞)" to mm3(234, 454)
            measures += "얼굴 길이 (이마 위~턱)" to mm3(10, 152)
            measures += "턱 너비" to mm3(172, 397)
            measures += "이마 너비" to mm3(54, 284)
            measures += "눈 너비 (사진 왼쪽/오른쪽)" to "%.1f / %.1f mm".format(d3(33, 133) * mmPerPx, d3(362, 263) * mmPerPx)
            measures += "눈 사이" to "%.1f mm".format(d3(133, 362) * mmPerPx)
            measures += "코 너비" to mm3(129, 358)
            measures += "코 길이 (미간~코밑)" to mm3(168, 2)
            measures += "입 너비" to mm3(61, 291)
            measures += "인중 길이" to "%.1f mm".format(d3(2, 0) * mmPerPx)
            notes += "치수는 홍채 지름(평균 11.7mm)을 기준으로 한 추정치입니다 (±10% 정도 차이 날 수 있음)."
        }
        val top5 = blend.entries.filter { it.key != "_neutral" }.sortedByDescending { it.value }.take(5).map { blendName(it.key) to it.value }
        return FaceMetrics(symmetry, asym, reliable, parts, thirds, lower, fifths, shape, why, ratios, mmPerPx, measures,
            expression(blend), top5, notes)
    }
}
