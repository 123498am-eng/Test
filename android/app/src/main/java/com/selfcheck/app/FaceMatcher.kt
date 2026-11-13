package com.selfcheck.app

import android.content.ContentResolver
import android.content.Context
import android.graphics.Bitmap
import android.graphics.ImageDecoder
import android.net.Uri
import org.opencv.android.OpenCVLoader
import org.opencv.android.Utils
import org.opencv.core.Mat
import org.opencv.core.Size
import org.opencv.imgproc.Imgproc
import org.opencv.objdetect.FaceDetectorYN
import org.opencv.objdetect.FaceRecognizerSF
import java.io.File
import java.nio.ByteBuffer

/** 내 얼굴과 다른 사진 속 얼굴을 휴대폰 안에서만 비교합니다 (YuNet + SFace). */
class FaceMatcher(ctx: Context, onStatus: (String) -> Unit = {}) {
    companion object {
        /** SFace 코사인 유사도 기준값 (OpenCV 권장 0.363). 이 이상이면 같은 사람일 가능성이 높음 */
        const val SAME_PERSON = 0.363
        private const val ZOO = "https://media.githubusercontent.com/media/opencv/opencv_zoo/main/models/"
        private const val DET = "face_detection_yunet/face_detection_yunet_2023mar.onnx"
        private const val REC = "face_recognition_sface/face_recognition_sface_2021dec.onnx"

        fun refsDir(ctx: Context) = File(ctx.filesDir, "refs").apply { mkdirs() }

        private fun ensureModel(ctx: Context, rel: String, onStatus: (String) -> Unit): File {
            val dir = File(ctx.filesDir, "models").apply { mkdirs() }
            val f = File(dir, rel.substringAfterLast('/'))
            if (!f.exists() || f.length() < 100_000) {
                onStatus("얼굴 모델 내려받는 중: ${f.name}")
                val bytes = UsernameChecker.fetchBytes(ZOO + rel, 120_000, 60_000_000)
                val tmp = File(dir, f.name + ".part")
                tmp.writeBytes(bytes)
                tmp.renameTo(f)
            }
            return f
        }

        private fun decode(src: ImageDecoder.Source, maxSideLimit: Int = 1024): Bitmap {
            val bmp = ImageDecoder.decodeBitmap(src) { decoder, info, _ ->
                decoder.allocator = ImageDecoder.ALLOCATOR_SOFTWARE
                val w = info.size.width; val h = info.size.height
                val maxSide = maxOf(w, h)
                if (maxSide > maxSideLimit) {
                    val s = maxSideLimit.toDouble() / maxSide
                    decoder.setTargetSize((w * s).toInt().coerceAtLeast(1), (h * s).toInt().coerceAtLeast(1))
                }
            }
            return if (bmp.config == Bitmap.Config.ARGB_8888) bmp else bmp.copy(Bitmap.Config.ARGB_8888, false)
        }

        fun decodeFile(f: File, maxSide: Int = 1024) = decode(ImageDecoder.createSource(f), maxSide)
        fun decodeUri(cr: ContentResolver, uri: Uri) = decode(ImageDecoder.createSource(cr, uri))
        fun decodeBytes(b: ByteArray) = decode(ImageDecoder.createSource(ByteBuffer.wrap(b)))
    }

    private val det: FaceDetectorYN
    private val rec: FaceRecognizerSF
    private val refs = mutableListOf<Mat>()

    init {
        check(OpenCVLoader.initLocal()) { "OpenCV를 불러오지 못했습니다" }
        val d = ensureModel(ctx, DET, onStatus)
        val r = ensureModel(ctx, REC, onStatus)
        det = FaceDetectorYN.create(d.absolutePath, "", Size(320.0, 320.0), 0.8f)
        rec = FaceRecognizerSF.create(r.absolutePath, "")
    }

    val refCount get() = refs.size

    /** 기준 사진마다 첫 번째(가장 확실한) 얼굴 하나를 등록합니다. */
    fun loadRefs(ctx: Context): Int {
        refs.clear()
        refsDir(ctx).listFiles()?.sortedBy { it.name }?.forEach { f ->
            runCatching { features(decodeFile(f)).firstOrNull() }.getOrNull()?.let { refs += it }
        }
        return refs.size
    }

    private fun features(bmp: Bitmap): List<Mat> {
        val rgba = Mat()
        Utils.bitmapToMat(bmp, rgba)
        val bgr = Mat()
        Imgproc.cvtColor(rgba, bgr, Imgproc.COLOR_RGBA2BGR)
        det.setInputSize(Size(bgr.cols().toDouble(), bgr.rows().toDouble()))
        val faces = Mat()
        det.detect(bgr, faces)
        val out = mutableListOf<Mat>()
        for (i in 0 until faces.rows()) {
            val aligned = Mat()
            rec.alignCrop(bgr, faces.row(i), aligned)
            val feat = Mat()
            rec.feature(aligned, feat)
            out += feat.clone()
        }
        return out
    }

    /** 사진 속 얼굴 중 내 얼굴과 가장 비슷한 점수. 얼굴이 없으면 null. */
    fun bestScore(bmp: Bitmap): Double? {
        check(refs.isNotEmpty()) { "기준 사진이 없습니다" }
        val feats = features(bmp)
        if (feats.isEmpty()) return null
        return refs.maxOf { r -> feats.maxOf { f -> rec.match(r, f, FaceRecognizerSF.FR_COSINE) } }
    }
}
