package com.selfcheck.app

import kotlin.math.roundToInt
import kotlin.math.sqrt

/**
 * 얼굴 특징(SFace 128차원)으로 닮은 정도와 같은 사람 판정을 계산합니다.
 * 기준: SFace 코사인 유사도 0.363 이상이면 같은 사람 (OpenCV 권장값, LFW 정확도 99.4%).
 *
 * 닮은 정도 %는 사람이 읽기 쉽게 코사인 값을 바꾼 것입니다 (확률이 아님):
 *   코사인 ≤ 0 → 0~20%, 0 ~ 0.363 → 20~60%, 0.363 ~ 0.8 → 60~98% (최대 99%)
 * 즉 60% 가 같은 사람 기준선입니다. 시험 사진에서 다른 사람끼리는 15~35%, 같은 사람은 60% 이상이었습니다.
 */
object FaceSimilarity {
    const val THRESHOLD = 0.363
    const val SAME_PERCENT = 60

    fun cosine(a: FloatArray, b: FloatArray): Double {
        var d = 0.0; var na = 0.0; var nb = 0.0
        for (i in a.indices) { d += a[i] * b[i]; na += a[i] * a[i]; nb += b[i] * b[i] }
        return if (na <= 0 || nb <= 0) 0.0 else d / (sqrt(na) * sqrt(nb))
    }

    /** 같은 사람 사진 여러 장의 특징을 하나로 (각각 길이 1로 맞춘 뒤 평균) */
    fun template(feats: List<FloatArray>): FloatArray {
        require(feats.isNotEmpty())
        val out = FloatArray(feats[0].size)
        for (f in feats) {
            var n = 0.0; for (v in f) n += v * v
            val k = if (n > 0) (1 / sqrt(n)).toFloat() else 0f
            for (i in f.indices) out[i] += f[i] * k
        }
        var n = 0.0; for (v in out) n += v * v
        val k = if (n > 0) (1 / sqrt(n)).toFloat() else 0f
        for (i in out.indices) out[i] *= k
        return out
    }

    fun percent(cos: Double): Int {
        val p = when {
            cos >= THRESHOLD -> 60 + (cos - THRESHOLD) / (0.8 - THRESHOLD) * 38
            cos >= 0 -> 20 + cos / THRESHOLD * 40
            else -> 20 + cos * 40
        }
        // 기준 바로 아래가 반올림으로 60% 가 되어 판정(애매함)과 어긋나지 않게: 기준 미만은 59% 이하, 이상은 60% 이상
        val r = p.roundToInt()
        return (if (cos < THRESHOLD) minOf(59, r) else maxOf(60, r)).coerceIn(0, 99)
    }

    /** (단계, 판정 글) 단계: 3 같은 사람, 2 같은 사람일 가능성 높음, 1 애매함, 0 다른 사람 */
    fun verdict(cos: Double): Pair<Int, String> = when {
        cos >= 0.45 -> 3 to "같은 사람으로 보입니다"
        cos >= THRESHOLD -> 2 to "같은 사람일 가능성이 높습니다 (기준을 조금 넘음)"
        cos >= 0.28 -> 1 to "애매합니다 — 닮았지만 다른 사람일 가능성이 높습니다"
        else -> 0 to "다른 사람으로 보입니다"
    }

    /** 얼굴 사진 상태 경고 (w: 원본에서 얼굴 너비 px, det: 검출 확신도, sharp: 정렬된 얼굴의 라플라시안 분산, mean: 밝기, turn: 코 치우침 비율) */
    fun quality(w: Float, det: Float, sharp: Double, mean: Double, turn: Float): List<String> {
        val out = ArrayList<String>()
        if (w < 60) out += "얼굴이 작게 찍혔습니다 (너비 ${w.roundToInt()}px) — 정확도가 낮습니다"
        else if (w < 90) out += "얼굴이 조금 작습니다 (너비 ${w.roundToInt()}px)"
        if (sharp < 40) out += "얼굴이 흐립니다"
        if (det < 0.85f) out += "얼굴이 일부 가려졌거나 불분명합니다"
        if (mean < 60) out += "너무 어둡습니다" else if (mean > 200) out += "너무 밝습니다"
        if (turn > 0.28f) out += "얼굴이 옆으로 돌아가 있습니다 — 정면 사진이 정확합니다"
        return out
    }
}
