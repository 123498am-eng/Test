package com.selfcheck.app

import android.content.Context
import android.graphics.Bitmap
import android.graphics.Canvas
import android.graphics.Color
import android.graphics.Paint
import android.graphics.Path
import com.google.mediapipe.framework.image.BitmapImageBuilder
import com.google.mediapipe.framework.image.ByteBufferExtractor
import com.google.mediapipe.tasks.core.BaseOptions
import com.google.mediapipe.tasks.core.Delegate
import com.google.mediapipe.tasks.vision.imagesegmenter.ImageSegmenter
import org.json.JSONArray
import org.json.JSONObject
import org.opencv.android.OpenCVLoader
import org.opencv.android.Utils
import org.opencv.core.CvType
import org.opencv.core.Mat
import org.opencv.core.MatOfPoint
import org.opencv.core.Size
import org.opencv.imgproc.Imgproc
import java.io.File
import java.nio.ByteOrder
import kotlin.math.hypot
import kotlin.math.max
import kotlin.math.min
import kotlin.math.roundToInt

/** 사람 분할 모델(selfie_multiclass): 0 배경, 1 머리카락, 2 몸 피부, 3 얼굴 피부, 4 옷, 5 기타 */
object Segment {
    fun create(ctx: Context): ImageSegmenter = ImageSegmenter.createFromOptions(ctx, ImageSegmenter.ImageSegmenterOptions.builder()
        .setBaseOptions(BaseOptions.builder().setModelAssetPath("selfie_multiclass_256x256.tflite").setDelegate(Delegate.CPU).build())
        .setOutputConfidenceMasks(true).setOutputCategoryMask(false).build())

    /** 분류별 확률 맵 (CV_32F, 사진 크기). classes 순서대로 */
    fun probs(seg: ImageSegmenter, bmp: Bitmap, classes: IntArray): List<Mat> {
        val masks = seg.segment(BitmapImageBuilder(bmp).build()).confidenceMasks().orElse(null) ?: return emptyList()
        return classes.map { c ->
            val m = masks[c]
            val buf = ByteBufferExtractor.extract(m).order(ByteOrder.nativeOrder()).asFloatBuffer()
            val arr = FloatArray(m.width * m.height); buf.position(0); buf.get(arr)
            val mat = Mat(m.height, m.width, CvType.CV_32F); mat.put(0, 0, arr)
            if (m.width != bmp.width || m.height != bmp.height)
                Imgproc.resize(mat, mat, Size(bmp.width.toDouble(), bmp.height.toDouble()), 0.0, 0.0, Imgproc.INTER_LINEAR)
            mat
        }
    }

    fun one(ctx: Context, bmp: Bitmap, cls: Int): Mat? = runCatching {
        val s = create(ctx)
        try { probs(s, bmp, intArrayOf(cls)).firstOrNull() } finally { s.close() }
    }.getOrNull()

    /** 사람일 확률 (1 - 배경) */
    fun person(ctx: Context, bmp: Bitmap): Mat? = one(ctx, bmp, 0)?.also { org.opencv.core.Core.subtract(Mat(it.size(), CvType.CV_32F, org.opencv.core.Scalar(1.0)), it, it) }
}

/** 사진 한 장의 피부·주름 분석 (휴대폰용 포장: 자르기·크기 맞추기·피부 분할 → SkinCore) */
object SkinAnalysis {
    /** crop: 분석한 얼굴 부분(작업 크기), x0·y0: 원본에서 자른 위치, scale: 작업 크기/원본, q: 점(작업 크기 픽셀) */
    class Full(val res: SkinResult, val crop: Bitmap, val x0: Int, val y0: Int, val scale: Float, val q: FloatArray)

    fun analyze(ctx: Context, bmp: Bitmap, pts: FloatArray, yaw: Float): Full {
        check(OpenCVLoader.initLocal()) { "OpenCV를 불러오지 못했습니다" }
        val W = bmp.width; val H = bmp.height
        val np = min(478, pts.size / 3)
        val px = FloatArray(478 * 2) { i -> val k = min(i / 2, np - 1); if (i % 2 == 0) pts[k * 3] * W else pts[k * 3 + 1] * H }
        val iod = hypot(px[263 * 2] - px[33 * 2], px[263 * 2 + 1] - px[33 * 2 + 1]).coerceAtLeast(4f)
        val s = if (iod > 450f) 450f / iod else 1f
        var minX = Float.MAX_VALUE; var minY = Float.MAX_VALUE; var maxX = -Float.MAX_VALUE; var maxY = -Float.MAX_VALUE
        for (i in 0 until min(468, np)) { minX = min(minX, px[i * 2]); maxX = max(maxX, px[i * 2]); minY = min(minY, px[i * 2 + 1]); maxY = max(maxY, px[i * 2 + 1]) }
        val x0 = (minX - 0.25f * iod).toInt().coerceIn(0, W - 2); val y0 = (minY - 0.25f * iod).toInt().coerceIn(0, H - 2)
        val x1 = (maxX + 0.25f * iod).toInt().coerceIn(x0 + 2, W); val y1 = (maxY + 0.25f * iod).toInt().coerceIn(y0 + 2, H)
        val cut = Bitmap.createBitmap(bmp, x0, y0, x1 - x0, y1 - y0)
        val rgba = Mat(); Utils.bitmapToMat(cut, rgba)
        if (cut !== bmp) cut.recycle()
        if (s < 1f) Imgproc.resize(rgba, rgba, Size(((x1 - x0) * s).roundToInt().toDouble(), ((y1 - y0) * s).roundToInt().toDouble()), 0.0, 0.0, Imgproc.INTER_AREA)
        val work = Bitmap.createBitmap(rgba.cols(), rgba.rows(), Bitmap.Config.ARGB_8888)
        Utils.matToBitmap(rgba, work)
        val rgb = Mat(); Imgproc.cvtColor(rgba, rgb, Imgproc.COLOR_RGBA2RGB); rgba.release()
        val q = FloatArray(478 * 2) { i -> (px[i] - (if (i % 2 == 0) x0 else y0)) * s }
        val prob = Segment.one(ctx, work, 3) // 얼굴 피부
        val res = SkinCore.analyze(rgb, q, iod * s, prob, iod, yaw)
        rgb.release(); prob?.release()
        return Full(res, work, x0, y0, s, q)
    }

    val LAYERS = listOf("wrinkle" to "주름", "fine" to "잔주름", "heat" to "주름 지도", "pore" to "모공", "spot" to "잡티",
        "red" to "홍조", "shine" to "번들거림", "region" to "부위·점수", "points" to "얼굴 점")

    private fun heat(t: Float): Int { // 파랑 → 초록 → 노랑 → 빨강
        val r = (t * 3 - 1.2f).coerceIn(0f, 1f); val g = (if (t < 0.6f) t / 0.6f else (1 - t) / 0.4f).coerceIn(0f, 1f); val b = (1 - t * 2.5f).coerceIn(0f, 1f)
        return Color.rgb((r * 255).toInt(), (g * 255).toInt(), (b * 255).toInt())
    }

    /** 선택한 층을 얼굴 사진 위에 그립니다 */
    fun overlay(f: Full, layers: Set<String>): Bitmap {
        val r = f.res; val w = r.w; val h = r.h
        val out = f.crop.copy(Bitmap.Config.ARGB_8888, true)
        val px = IntArray(w * h); out.getPixels(px, 0, w, 0, 0, w, h)
        fun blend(i: Int, c: Int, a: Float) {
            val p = px[i]
            px[i] = Color.rgb(
                (Color.red(p) * (1 - a) + Color.red(c) * a).toInt(),
                (Color.green(p) * (1 - a) + Color.green(c) * a).toInt(),
                (Color.blue(p) * (1 - a) + Color.blue(c) * a).toInt())
        }
        if ("heat" in layers) {
            for (i in 0 until w * h) if (r.skin[i]) {
                val t = (r.wrinkleV[i] / 3.5f).coerceIn(0f, 1f)
                if (t > 0.06f) blend(i, heat(t), 0.25f + 0.6f * t) else blend(i, Color.rgb(20, 30, 90), 0.18f)
            }
        }
        if ("red" in layers) for (i in 0 until w * h) if (r.red[i]) blend(i, Color.rgb(255, 40, 40), 0.45f)
        if ("shine" in layers) for (i in 0 until w * h) if (r.shine[i]) blend(i, Color.rgb(255, 240, 0), 0.55f)
        if ("fine" in layers) for (i in 0 until w * h) if (r.fine[i]) blend(i, Color.rgb(120, 255, 60), 0.85f)
        if ("wrinkle" in layers) for (i in 0 until w * h) if (r.wrinkle[i]) blend(i, Color.rgb(255, 0, 210), 0.9f)
        out.setPixels(px, 0, w, 0, 0, w, h)
        val c = Canvas(out)
        val k = max(1f, r.u / 300f)
        if ("pore" in layers) {
            val p = Paint(Paint.ANTI_ALIAS_FLAG).apply { color = Color.rgb(0, 230, 255) }
            for (i in r.pores) c.drawCircle((i % w).toFloat(), (i / w).toFloat(), 1.2f * k, p)
        }
        if ("spot" in layers) {
            val p = Paint(Paint.ANTI_ALIAS_FLAG).apply { color = Color.rgb(255, 140, 0); style = Paint.Style.STROKE; strokeWidth = 1.5f * k }
            for (s in r.spots) c.drawCircle(s[0], s[1], s[2] + 3 * k, p)
        }
        if ("points" in layers) {
            val p = Paint(Paint.ANTI_ALIAS_FLAG).apply { color = Color.argb(200, 0, 255, 170) }
            for (i in 0 until f.q.size / 2) c.drawCircle(f.q[i * 2], f.q[i * 2 + 1], 1.1f * k, p)
        }
        if ("region" in layers) {
            val line = Paint(Paint.ANTI_ALIAS_FLAG).apply { color = Color.argb(220, 255, 255, 255); style = Paint.Style.STROKE; strokeWidth = 1.2f * k }
            val txt = Paint(Paint.ANTI_ALIAS_FLAG).apply { color = Color.WHITE; textSize = 11f * k; textAlign = Paint.Align.CENTER }
            val shadow = Paint(txt).apply { color = Color.BLACK; style = Paint.Style.STROKE; strokeWidth = 3f * k }
            for ((bit, name) in SkinCore.REGIONS.withIndex()) {
                val m = Mat(h, w, CvType.CV_8U)
                m.put(0, 0, ByteArray(w * h) { if (r.regionMask[it] and (1 shl bit) != 0) 1 else 0 })
                val cs = ArrayList<MatOfPoint>()
                Imgproc.findContours(m, cs, Mat(), Imgproc.RETR_EXTERNAL, Imgproc.CHAIN_APPROX_SIMPLE)
                m.release()
                var sx = 0.0; var sy = 0.0; var cnt = 0
                for (ct in cs) {
                    val pts = ct.toArray(); if (pts.size < 3) continue
                    val path = Path(); path.moveTo(pts[0].x.toFloat(), pts[0].y.toFloat())
                    for (p in pts.drop(1)) { path.lineTo(p.x.toFloat(), p.y.toFloat()); sx += p.x; sy += p.y; cnt++ }
                    path.close(); c.drawPath(path, line)
                }
                val score = r.regionScores[name]
                if (cnt > 0 && score != null) {
                    val label = name.replace("왼쪽 ", "").replace("오른쪽 ", "") + " " + score.roundToInt()
                    c.drawText(label, (sx / cnt).toFloat(), (sy / cnt).toFloat(), shadow)
                    c.drawText(label, (sx / cnt).toFloat(), (sy / cnt).toFloat(), txt)
                }
            }
        }
        return out
    }
}

/** 피부 분석 기록 (휴대폰 안에만 저장) */
object SkinHistory {
    private fun file(ctx: Context) = File(ctx.filesDir, "skin_history.json")

    fun load(ctx: Context): List<JSONObject> = runCatching {
        val a = JSONArray(file(ctx).readText()); List(a.length()) { a.getJSONObject(it) }
    }.getOrDefault(emptyList())

    fun add(ctx: Context, label: String, r: SkinResult, fm: FaceMetrics?) {
        val o = JSONObject().put("time", System.currentTimeMillis()).put("label", label).put("overall", r.overall)
        val mets = JSONObject(); r.metrics.forEach { mets.put(it.name, it.degree.toDouble()) }
        val regs = JSONObject(); r.regionScores.forEach { (k, v) -> if (v != null) regs.put(k, v.toDouble()) }
        o.put("metrics", mets).put("regions", regs)
        if (fm != null) o.put("symmetry", fm.symmetry)
        val all = JSONArray(); (load(ctx) + o).takeLast(200).forEach { all.put(it) }
        file(ctx).writeText(all.toString())
    }

    fun clear(ctx: Context) { file(ctx).delete() }
}
