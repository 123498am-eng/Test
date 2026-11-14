package com.selfcheck.app

import android.graphics.Bitmap
import android.graphics.Color
import android.graphics.Matrix
import android.graphics.drawable.ColorDrawable
import android.net.Uri
import android.os.Bundle
import android.os.Handler
import android.os.Looper
import android.view.Gravity
import android.view.MotionEvent
import android.view.View
import android.view.ViewGroup.LayoutParams.MATCH_PARENT
import android.view.ViewGroup.LayoutParams.WRAP_CONTENT
import android.widget.Button
import android.widget.FrameLayout
import android.widget.ImageView
import android.widget.LinearLayout
import android.widget.MediaController
import android.widget.ProgressBar
import android.widget.SeekBar
import android.widget.TextView
import android.widget.Toast
import android.widget.VideoView
import androidx.activity.ComponentActivity
import androidx.activity.result.PickVisualMediaRequest
import androidx.activity.result.contract.ActivityResultContracts
import org.opencv.android.OpenCVLoader
import org.opencv.android.Utils
import org.opencv.core.Core
import org.opencv.core.CvType
import org.opencv.core.Mat
import org.opencv.core.Scalar
import org.opencv.core.Size
import org.opencv.imgproc.Imgproc
import java.util.concurrent.Executors
import kotlin.concurrent.thread
import kotlin.math.max
import kotlin.math.min

/** 크로마키 설정 */
data class KeySettings(
    val key: Int,          // 지울 배경색 (RGB)
    val tolerance: Float,  // 허용 범위: 배경색과 이 정도 가까우면 완전히 지움 (0~120)
    val softness: Float,   // 부드러움: 경계가 반투명해지는 폭 (1~120)
    val spill: Float,      // 색 번짐 제거 (0~1)
    val choke: Int,        // 가장자리 줄이기 (픽셀)
)

/** 배경을 무엇으로 바꿀지 */
enum class KeyBack(val label: String) { TRANSPARENT("투명"), WHITE("흰색"), BLACK("검정"), IMAGE("사진") }

/**
 * 크로마키(그린·블루 스크린) 전용: 초록/파란 배경을 색으로 지우고 다른 배경으로 바꿉니다.
 * 화면을 누르면 그 색을 배경색으로 고르고, 막대로 범위·부드러움·색 번짐·가장자리를 조절합니다. 사진과 동영상 모두 됩니다.
 */
class ChromaKeyActivity : ComponentActivity() {
    private lateinit var stage: FrameLayout
    private lateinit var preview: ImageView
    private lateinit var info: TextView
    private lateinit var swatch: View
    private lateinit var progress: ProgressBar
    private lateinit var backBtn: Button
    private var source: Uri? = null
    private var isVideo = false
    private var frame: Bitmap? = null      // 미리보기용 원본 (사진, 또는 동영상 첫 장면, 긴 변 900px)
    private var backImage: Bitmap? = null
    private var back = KeyBack.TRANSPARENT
    private var key = Color.rgb(0, 177, 64)
    private var tol = 40f; private var soft = 30f; private var spill = 0.6f; private var choke = 1
    private val worker = Executors.newSingleThreadExecutor()
    private val ui = Handler(Looper.getMainLooper())
    @Volatile private var busy = false
    private var pendingPreview: Runnable? = null

    private val pick = registerForActivityResult(ActivityResultContracts.PickVisualMedia()) { uri -> if (uri != null) load(uri) }
    private val pickBack = registerForActivityResult(ActivityResultContracts.PickVisualMedia()) { uri ->
        if (uri != null) thread {
            backImage = runCatching { FaceMatcher.decodeUri(contentResolver, uri, 2048) }.getOrNull()
            runOnUiThread { back = KeyBack.IMAGE; backBtn.text = "배경: 사진"; schedulePreview() }
        }
    }

    private fun dp(v: Int) = (v * resources.displayMetrics.density).toInt()

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        check(OpenCVLoader.initLocal()) { "OpenCV를 불러오지 못했습니다" }
        val root = LinearLayout(this).apply { orientation = LinearLayout.VERTICAL; setBackgroundColor(Color.rgb(24, 24, 28)) }
        root.setOnApplyWindowInsetsListener { v, insets ->
            @Suppress("DEPRECATION")
            v.setPadding(0, insets.systemWindowInsetTop, 0, insets.systemWindowInsetBottom); insets
        }
        root.addView(TextView(this).apply { text = "크로마키"; textSize = 20f; setTextColor(Color.WHITE); setPadding(dp(16), dp(12), dp(16), dp(2)) })
        info = TextView(this).apply {
            text = "초록·파란 배경에서 찍은 사진이나 동영상을 고르세요. 화면에서 배경을 누르면 그 색을 지웁니다."
            textSize = 13f; setTextColor(Color.LTGRAY); setPadding(dp(16), 0, dp(16), dp(6))
        }
        root.addView(info)
        stage = FrameLayout(this)
        preview = ImageView(this).apply { scaleType = ImageView.ScaleType.FIT_CENTER }
        preview.setOnTouchListener { v, e -> if (e.action == MotionEvent.ACTION_UP) pickColor(e.x, e.y); true }
        stage.addView(preview, FrameLayout.LayoutParams(MATCH_PARENT, MATCH_PARENT))
        root.addView(stage, LinearLayout.LayoutParams(MATCH_PARENT, 0, 1f))
        progress = ProgressBar(this, null, android.R.attr.progressBarStyleHorizontal).apply { visibility = View.GONE }
        root.addView(progress, LinearLayout.LayoutParams(MATCH_PARENT, WRAP_CONTENT).apply { setMargins(dp(16), 0, dp(16), 0) })

        // 배경색 표시
        val keyRow = LinearLayout(this).apply { orientation = LinearLayout.HORIZONTAL; gravity = Gravity.CENTER_VERTICAL; setPadding(dp(16), dp(4), dp(16), 0) }
        keyRow.addView(TextView(this).apply { text = "지울 색"; setTextColor(Color.WHITE); textSize = 13f })
        swatch = View(this).apply { background = ColorDrawable(key) }
        keyRow.addView(swatch, LinearLayout.LayoutParams(dp(36), dp(20)).apply { setMargins(dp(8), 0, dp(8), 0) })
        keyRow.addView(TextView(this).apply { text = "(화면을 눌러 바꾸기)"; setTextColor(Color.GRAY); textSize = 12f })
        root.addView(keyRow)

        fun slider(label: String, maxV: Int, init: Int, on: (Int) -> Unit) {
            val row = LinearLayout(this).apply { orientation = LinearLayout.HORIZONTAL; gravity = Gravity.CENTER_VERTICAL; setPadding(dp(16), 0, dp(12), 0) }
            row.addView(TextView(this).apply { text = label; setTextColor(Color.WHITE); textSize = 13f }, LinearLayout.LayoutParams(dp(110), WRAP_CONTENT))
            row.addView(SeekBar(this).apply {
                max = maxV; progress = init
                setOnSeekBarChangeListener(object : SeekBar.OnSeekBarChangeListener {
                    override fun onProgressChanged(sb: SeekBar, p: Int, u: Boolean) { on(p); schedulePreview() }
                    override fun onStartTrackingTouch(sb: SeekBar) {}
                    override fun onStopTrackingTouch(sb: SeekBar) {}
                })
            }, LinearLayout.LayoutParams(0, WRAP_CONTENT, 1f))
            root.addView(row)
        }
        slider("허용 범위", 120, tol.toInt()) { tol = it.toFloat() }
        slider("부드러움", 120, soft.toInt()) { soft = max(1, it).toFloat() }
        slider("색 번짐 제거", 100, (spill * 100).toInt()) { spill = it / 100f }
        slider("가장자리 줄이기", 8, choke) { choke = it }

        val bar = LinearLayout(this).apply { orientation = LinearLayout.HORIZONTAL; setPadding(dp(8), dp(4), dp(8), dp(8)) }
        fun btn(t: String, f: () -> Unit) = Button(this).apply { text = t; textSize = 12f; setOnClickListener { f() } }
            .also { bar.addView(it, LinearLayout.LayoutParams(0, WRAP_CONTENT, 1f)) }
        btn("사진/동영상 고르기") { if (!busy) pick.launch(PickVisualMediaRequest(ActivityResultContracts.PickVisualMedia.ImageAndVideo)) }
        backBtn = btn("배경: 투명") { cycleBack() }
        btn("저장") { save() }
        root.addView(bar)
        setContentView(root)
    }

    private fun settings() = KeySettings(key, tol, soft, spill, choke)

    private fun cycleBack() {
        val order = KeyBack.values().filter { !(isVideo && it == KeyBack.TRANSPARENT) }
        val next = order[(order.indexOf(back) + 1) % order.size]
        if (next == KeyBack.IMAGE) { pickBack.launch(PickVisualMediaRequest(ActivityResultContracts.PickVisualMedia.ImageOnly)); return }
        back = next; backBtn.text = "배경: ${back.label}"; schedulePreview()
    }

    private fun load(uri: Uri) {
        source = uri
        isVideo = contentResolver.getType(uri)?.startsWith("video") == true
        if (isVideo && back == KeyBack.TRANSPARENT) { back = KeyBack.BLACK; backBtn.text = "배경: ${back.label}" }
        stage.removeAllViews(); stage.addView(preview, FrameLayout.LayoutParams(MATCH_PARENT, MATCH_PARENT))
        thread {
            val b = runCatching {
                if (isVideo) VideoSource(this, uri).use { it.frames(0, 1, 900).firstOrNull() } else FaceMatcher.decodeUri(contentResolver, uri, 900)
            }.getOrNull()
            runOnUiThread {
                if (b == null) { info.text = "파일을 열 수 없습니다"; return@runOnUiThread }
                frame = b
                key = ChromaKey.autoKey(b)
                swatch.background = ColorDrawable(key)
                info.text = "가장자리에서 배경색을 찾았습니다. 다르면 화면에서 배경을 눌러 고르세요. 막대로 다듬은 뒤 '저장'."
                schedulePreview()
            }
        }
    }

    /** 미리보기 위 좌표 → 원본 색 고르기 (5×5 평균) */
    private fun pickColor(x: Float, y: Float) {
        val b = frame ?: return
        val s = min(preview.width / b.width.toFloat(), preview.height / b.height.toFloat())
        val ox = (preview.width - b.width * s) / 2; val oy = (preview.height - b.height * s) / 2
        val ix = ((x - ox) / s).toInt(); val iy = ((y - oy) / s).toInt()
        if (ix !in 0 until b.width || iy !in 0 until b.height) return
        var r = 0; var g = 0; var bl = 0; var n = 0
        for (dy in -2..2) for (dx in -2..2) {
            val px = (ix + dx).coerceIn(0, b.width - 1); val py = (iy + dy).coerceIn(0, b.height - 1)
            val c = b.getPixel(px, py); r += Color.red(c); g += Color.green(c); bl += Color.blue(c); n++
        }
        key = Color.rgb(r / n, g / n, bl / n)
        swatch.background = ColorDrawable(key)
        schedulePreview()
    }

    /** 막대를 움직이는 동안 너무 자주 계산하지 않도록 잠깐 기다렸다가 미리보기 */
    private fun schedulePreview() {
        pendingPreview?.let { ui.removeCallbacks(it) }
        val r = Runnable {
            val f = frame ?: return@Runnable
            val st = settings(); val bk = back; val bi = backImage
            worker.execute {
                val out = runCatching { ChromaKey.apply(f, st, bk, bi, previewMode = true) }.getOrNull()
                runOnUiThread { out?.let { preview.setImageBitmap(it) } }
            }
        }
        pendingPreview = r
        ui.postDelayed(r, 120)
    }

    private fun save() {
        val uri = source ?: run { Toast.makeText(this, "먼저 사진이나 동영상을 고르세요", Toast.LENGTH_SHORT).show(); return }
        if (busy) return
        busy = true
        val st = settings(); val bk = back; val bi = backImage
        progress.visibility = View.VISIBLE; progress.isIndeterminate = !isVideo
        info.text = "저장 중..."
        thread {
            val msg = runCatching {
                if (!isVideo) {
                    val full = FaceMatcher.decodeUri(contentResolver, uri, 4096)
                    val out = ChromaKey.apply(full, st, bk, bi, previewMode = false)
                    MediaSave.savePng(this, out, "chroma_${System.currentTimeMillis()}.png") + " 에 저장했습니다"
                } else {
                    val label = processVideo(uri, st, bk, bi)
                    "$label 에 저장했습니다 (원본 소리 포함)"
                }
            }.getOrElse { "실패: ${it.message}" }
            runOnUiThread {
                busy = false; progress.visibility = View.GONE; info.text = msg
                Toast.makeText(this, msg, Toast.LENGTH_LONG).show()
            }
        }
    }

    private fun processVideo(uri: Uri, st: KeySettings, bk: KeyBack, bi: Bitmap?): String {
        VideoSource(this, uri).use { src ->
            val first = src.frames(0, 1, 1280).first()
            val (ow, oh) = VideoEncoder.fitSize(first.width, first.height, 1280)
            first.recycle()
            val fps = src.fps.toInt().coerceIn(10, 60)
            val out = MediaSave.newVideo(this, "chroma_${System.currentTimeMillis()}.mp4")
            val enc = VideoEncoder(out.pfd.fileDescriptor, ow, oh, fps, AudioPassthrough(this, uri))
            try {
                var i = 0
                while (i < src.count) {
                    val chunk = src.frames(i, 10, 1280)
                    if (chunk.isEmpty()) break
                    chunk.forEachIndexed { k, f ->
                        val comp = ChromaKey.apply(f, st, if (bk == KeyBack.TRANSPARENT) KeyBack.BLACK else bk, bi, previewMode = false)
                        val scaled = Bitmap.createScaledBitmap(comp, ow, oh, true)
                        enc.addFrame(scaled, ((i + k) * 1_000_000.0 / src.fps).toLong())
                        if (scaled !== comp) scaled.recycle()
                        comp.recycle(); f.recycle()
                    }
                    i += chunk.size
                    val p = (i * 100 / src.count).coerceAtMost(100)
                    runOnUiThread { progress.progress = p; info.text = "동영상 처리 중... $p%" }
                }
            } finally {
                enc.finish(); out.done()
            }
            runOnUiThread {
                stage.removeAllViews()
                val vv = VideoView(this)
                stage.addView(vv, FrameLayout.LayoutParams(MATCH_PARENT, MATCH_PARENT, Gravity.CENTER))
                vv.setMediaController(MediaController(this).also { it.setAnchorView(vv) })
                vv.setVideoURI(out.uri); vv.setOnPreparedListener { it.isLooping = true; vv.start() }
            }
            return out.label
        }
    }

    override fun onDestroy() { super.onDestroy(); worker.shutdown() }
}

/** 크로마키 계산 (OpenCV) */
object ChromaKey {
    /** 사진 가장자리 띠에서 가장 채도가 높은 색들의 평균 = 배경색 추정 (없으면 초록) */
    fun autoKey(b: Bitmap): Int {
        var r = 0L; var g = 0L; var bl = 0L; var n = 0
        val w = b.width; val h = b.height
        val step = max(1, min(w, h) / 120)
        fun take(x: Int, y: Int) {
            val c = b.getPixel(x, y)
            val mx = max(Color.red(c), max(Color.green(c), Color.blue(c))); val mn = min(Color.red(c), min(Color.green(c), Color.blue(c)))
            if (mx - mn > 50) { r += Color.red(c); g += Color.green(c); bl += Color.blue(c); n++ }
        }
        for (x in 0 until w step step) { for (y in 0 until h / 12 step step) take(x, y) }
        for (y in 0 until h step step) { for (x in 0 until w / 12 step step) { take(x, y); take(w - 1 - x, y) } }
        return if (n < 10) Color.rgb(0, 177, 64) else Color.rgb((r / n).toInt(), (g / n).toInt(), (bl / n).toInt())
    }

    /**
     * 1) YCrCb 의 색 성분(Cr, Cb)에서 배경색과의 거리로 알파 계산 (밝기 차이·그림자에 덜 민감)
     * 2) 가장자리 줄이기 3) 색 번짐 제거 (초록 배경이면 초록 성분을 빨강·파랑 수준으로 눌러 줌) 4) 새 배경과 합성
     */
    fun apply(src: Bitmap, s: KeySettings, back: KeyBack, backImage: Bitmap?, previewMode: Boolean): Bitmap {
        val rgba = Mat(); Utils.bitmapToMat(src, rgba)
        val rgb = Mat(); Imgproc.cvtColor(rgba, rgb, Imgproc.COLOR_RGBA2RGB)
        val ycc = Mat(); Imgproc.cvtColor(rgb, ycc, Imgproc.COLOR_RGB2YCrCb); ycc.convertTo(ycc, CvType.CV_32FC3)
        val ch = ArrayList<Mat>(); Core.split(ycc, ch)
        val keyM = Mat(1, 1, CvType.CV_8UC3, Scalar(Color.red(s.key).toDouble(), Color.green(s.key).toDouble(), Color.blue(s.key).toDouble()))
        val keyY = Mat(); Imgproc.cvtColor(keyM, keyY, Imgproc.COLOR_RGB2YCrCb)
        val kv = keyY.get(0, 0)
        val dcr = Mat(); Core.subtract(ch[1], Scalar(kv[1]), dcr); Core.multiply(dcr, dcr, dcr)
        val dcb = Mat(); Core.subtract(ch[2], Scalar(kv[2]), dcb); Core.multiply(dcb, dcb, dcb)
        val dist = Mat(); Core.add(dcr, dcb, dist); Core.sqrt(dist, dist)
        // alpha = (dist - tol) / soft
        val a = Mat(); Core.subtract(dist, Scalar(s.tolerance.toDouble()), a); Core.multiply(a, Scalar(255.0 / s.softness), a)
        val alpha = Mat(); a.convertTo(alpha, CvType.CV_8U)
        if (s.choke > 0) {
            val k = Imgproc.getStructuringElement(Imgproc.MORPH_ELLIPSE, Size(2.0 * s.choke + 1, 2.0 * s.choke + 1))
            Imgproc.erode(alpha, alpha, k)
            Imgproc.GaussianBlur(alpha, alpha, Size(0.0, 0.0), max(0.6, s.choke * 0.5))
        }
        // 색 번짐 제거
        val f = Mat(); rgb.convertTo(f, CvType.CV_32FC3)
        val c3 = ArrayList<Mat>(); Core.split(f, c3)
        val kr = Color.red(s.key); val kg = Color.green(s.key); val kb = Color.blue(s.key)
        if (s.spill > 0f) {
            val (target, o1, o2) = when {
                kg >= kr && kg >= kb -> Triple(1, 0, 2)  // 초록 배경
                kb >= kr && kb >= kg -> Triple(2, 0, 1)  // 파란 배경
                else -> Triple(0, 1, 2)
            }
            val lim = Mat(); Core.max(c3[o1], c3[o2], lim)
            val over = Mat(); Core.subtract(c3[target], lim, over); Core.max(over, Scalar(0.0), over)
            Core.multiply(over, Scalar(s.spill.toDouble()), over)
            Core.subtract(c3[target], over, c3[target])
            lim.release(); over.release()
        }
        val fg = Mat(); Core.merge(c3, fg)
        // 배경
        val bg = Mat(rgb.size(), CvType.CV_32FC3)
        when (back) {
            KeyBack.WHITE -> bg.setTo(Scalar(255.0, 255.0, 255.0))
            KeyBack.BLACK, KeyBack.TRANSPARENT -> bg.setTo(Scalar(0.0, 0.0, 0.0))
            KeyBack.IMAGE -> {
                val bi = backImage
                if (bi == null) bg.setTo(Scalar(0.0, 0.0, 0.0)) else {
                    // 화면을 꽉 채우도록 (가운데 기준 잘라 맞춤)
                    val sc = max(src.width / bi.width.toFloat(), src.height / bi.height.toFloat())
                    val m = Matrix().apply { postScale(sc, sc); postTranslate((src.width - bi.width * sc) / 2, (src.height - bi.height * sc) / 2) }
                    val fitted = Bitmap.createBitmap(src.width, src.height, Bitmap.Config.ARGB_8888)
                    android.graphics.Canvas(fitted).drawBitmap(bi, m, android.graphics.Paint(android.graphics.Paint.FILTER_BITMAP_FLAG))
                    val bm = Mat(); Utils.bitmapToMat(fitted, bm); Imgproc.cvtColor(bm, bm, Imgproc.COLOR_RGBA2RGB); bm.convertTo(bg, CvType.CV_32FC3)
                    bm.release(); fitted.recycle()
                }
            }
        }
        val out = Mat()
        val bmp = Bitmap.createBitmap(src.width, src.height, Bitmap.Config.ARGB_8888)
        if (back == KeyBack.TRANSPARENT) {
            val fg8 = Mat(); fg.convertTo(fg8, CvType.CV_8UC3)
            val parts = ArrayList<Mat>(); Core.split(fg8, parts); parts.add(alpha)
            Core.merge(parts, out)
            if (previewMode) {
                // 미리보기는 체크무늬 위에 보여 줌
                val chk = checker(src.width, src.height)
                val a4 = Mat(); alpha.convertTo(a4, CvType.CV_32F, 1.0 / 255.0)
                val a3 = Mat(); Core.merge(listOf(a4, a4, a4), a3)
                val inv = Mat(); Core.subtract(Mat(a3.size(), CvType.CV_32FC3, Scalar.all(1.0)), a3, inv)
                val ff = Mat(); Core.multiply(fg, a3, ff); Core.multiply(chk, inv, chk); Core.add(ff, chk, ff)
                val o8 = Mat(); ff.convertTo(o8, CvType.CV_8UC3); Imgproc.cvtColor(o8, out, Imgproc.COLOR_RGB2RGBA)
                listOf(chk, a4, a3, inv, ff, o8).forEach { it.release() }
                Utils.matToBitmap(out, bmp)
            } else Utils.matToBitmap(out, bmp, true)
            fg8.release(); parts.forEach { if (it !== alpha) it.release() }
        } else {
            val a1 = Mat(); alpha.convertTo(a1, CvType.CV_32F, 1.0 / 255.0)
            val a3 = Mat(); Core.merge(listOf(a1, a1, a1), a3)
            val inv = Mat(); Core.subtract(Mat(a3.size(), CvType.CV_32FC3, Scalar.all(1.0)), a3, inv)
            Core.multiply(fg, a3, fg); Core.multiply(bg, inv, bg); Core.add(fg, bg, fg)
            val o8 = Mat(); fg.convertTo(o8, CvType.CV_8UC3); Imgproc.cvtColor(o8, out, Imgproc.COLOR_RGB2RGBA)
            Utils.matToBitmap(out, bmp)
            listOf(a1, a3, inv, o8).forEach { it.release() }
        }
        (listOf(rgba, rgb, ycc, keyM, keyY, dcr, dcb, dist, a, alpha, f, fg, bg, out) + ch + c3).forEach { it.release() }
        return bmp
    }

    private fun checker(w: Int, h: Int): Mat {
        val m = Mat(h, w, CvType.CV_32FC3)
        val s = max(8, min(w, h) / 40)
        val small = Mat(2, 2, CvType.CV_32FC3)
        small.put(0, 0, 200.0, 200.0, 200.0, 150.0, 150.0, 150.0, 150.0, 150.0, 150.0, 200.0, 200.0, 200.0)
        val big = Mat(); Imgproc.resize(small, big, Size(2.0 * s, 2.0 * s), 0.0, 0.0, Imgproc.INTER_NEAREST)
        Core.repeat(big, h / (2 * s) + 1, w / (2 * s) + 1, m)
        val out = m.submat(0, h, 0, w).clone()
        small.release(); big.release(); m.release()
        return out
    }
}
