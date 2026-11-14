package com.selfcheck.app

import android.content.Context
import android.graphics.Bitmap
import android.graphics.BitmapShader
import android.graphics.Canvas
import android.graphics.Color
import android.graphics.Paint
import android.graphics.Rect
import android.graphics.RectF
import android.graphics.Shader
import android.graphics.drawable.BitmapDrawable
import android.net.Uri
import android.os.Bundle
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
import kotlin.concurrent.thread
import kotlin.math.abs
import kotlin.math.max
import kotlin.math.min

/** 배경을 무엇으로 바꿀지 */
enum class Backdrop(val label: String) { TRANSPARENT("투명"), WHITE("흰색"), BLACK("검정"), GREEN("초록"), BLUR("흐리게") }

/**
 * 배경 제거: 사진이나 동영상을 고르고, 남길 물체를 사각형으로 지정한 뒤 "편집"을 누르면
 * 그 물체를 뺀 나머지 배경을 지웁니다 (OpenCV GrabCut). 동영상은 프레임마다 물체를 따라가며 처리합니다.
 */
class BgRemoveActivity : ComponentActivity() {
    private lateinit var stage: FrameLayout
    private lateinit var selector: RectSelectView
    private lateinit var info: TextView
    private lateinit var progress: ProgressBar
    private lateinit var editBtn: Button
    private lateinit var saveBtn: Button
    private lateinit var bgBtn: Button
    private var source: Uri? = null
    private var isVideo = false
    private var image: Bitmap? = null // 사진, 또는 동영상 첫 프레임
    private var result: Bitmap? = null
    private var backdrop = Backdrop.TRANSPARENT
    @Volatile private var busy = false

    private val pick = registerForActivityResult(ActivityResultContracts.PickVisualMedia()) { uri -> if (uri != null) load(uri) }

    private fun dp(v: Int) = (v * resources.displayMetrics.density).toInt()

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        val root = LinearLayout(this).apply { orientation = LinearLayout.VERTICAL; setBackgroundColor(Color.rgb(24, 24, 28)) }
        root.setOnApplyWindowInsetsListener { v, insets ->
            @Suppress("DEPRECATION")
            v.setPadding(0, insets.systemWindowInsetTop, 0, insets.systemWindowInsetBottom); insets
        }
        root.addView(TextView(this).apply {
            text = "배경 제거"; textSize = 20f; setTextColor(Color.WHITE); setPadding(dp(16), dp(12), dp(16), dp(4))
        })
        info = TextView(this).apply {
            text = "사진이나 동영상을 고른 뒤, 남길 물체를 사각형으로 감싸고 '편집'을 누르세요."
            textSize = 13f; setTextColor(Color.LTGRAY); setPadding(dp(16), 0, dp(16), dp(8))
        }
        root.addView(info)
        stage = FrameLayout(this)
        selector = RectSelectView(this)
        stage.addView(selector, FrameLayout.LayoutParams(MATCH_PARENT, MATCH_PARENT))
        root.addView(stage, LinearLayout.LayoutParams(MATCH_PARENT, 0, 1f))
        progress = ProgressBar(this, null, android.R.attr.progressBarStyleHorizontal).apply { visibility = View.GONE }
        root.addView(progress, LinearLayout.LayoutParams(MATCH_PARENT, WRAP_CONTENT).apply { setMargins(dp(16), dp(4), dp(16), 0) })

        val bar = LinearLayout(this).apply { orientation = LinearLayout.HORIZONTAL; setPadding(dp(8), dp(4), dp(8), dp(8)) }
        fun btn(t: String, f: () -> Unit) = Button(this).apply { text = t; textSize = 12f; setOnClickListener { f() } }
            .also { bar.addView(it, LinearLayout.LayoutParams(0, WRAP_CONTENT, 1f)) }
        btn("사진/동영상 고르기") { if (!busy) pick.launch(PickVisualMediaRequest(ActivityResultContracts.PickVisualMedia.ImageAndVideo)) }
        bgBtn = btn("배경: 투명") { cycleBackdrop() }
        editBtn = btn("편집") { runEdit() }
        saveBtn = btn("저장") { saveResult() }.apply { visibility = View.GONE }
        root.addView(bar)
        setContentView(root)
        check(OpenCVLoader.initLocal()) { "OpenCV를 불러오지 못했습니다" }
    }

    private fun cycleBackdrop() {
        val all = Backdrop.values().filter { !(isVideo && it == Backdrop.TRANSPARENT) } // 동영상은 투명을 지원하지 않음
        backdrop = all[(all.indexOf(backdrop) + 1) % all.size]
        bgBtn.text = "배경: ${backdrop.label}"
    }

    private fun load(uri: Uri) {
        source = uri
        isVideo = contentResolver.getType(uri)?.startsWith("video") == true
        if (isVideo && backdrop == Backdrop.TRANSPARENT) { backdrop = Backdrop.WHITE; bgBtn.text = "배경: ${backdrop.label}" }
        result = null; saveBtn.visibility = View.GONE
        showSelector()
        thread {
            val bmp = runCatching {
                if (isVideo) VideoSource(this, uri).use { it.frames(0, 1, 1280).firstOrNull() }
                else FaceMatcher.decodeUri(contentResolver, uri, 2048)
            }.getOrNull()
            runOnUiThread {
                if (bmp == null) { info.text = "파일을 열 수 없습니다"; return@runOnUiThread }
                image = bmp
                selector.setImage(bmp)
                info.text = (if (isVideo) "동영상 첫 장면입니다. " else "") + "남길 물체를 사각형으로 감싸세요 (모서리를 끌어 크기 조절, 안쪽을 끌어 이동)."
            }
        }
    }

    private fun showSelector() {
        stage.removeAllViews()
        stage.addView(selector, FrameLayout.LayoutParams(MATCH_PARENT, MATCH_PARENT))
    }

    private fun runEdit() {
        val img = image ?: run { Toast.makeText(this, "먼저 사진이나 동영상을 고르세요", Toast.LENGTH_SHORT).show(); return }
        if (busy) return
        val rect = selector.imageRect() ?: return
        busy = true; editBtn.isEnabled = false
        progress.visibility = View.VISIBLE; progress.isIndeterminate = !isVideo
        info.text = "배경을 지우는 중..."
        if (!isVideo) thread {
            val out = runCatching { Cutout.composite(img, Cutout.photoMask(img, rect), backdrop) }
            runOnUiThread {
                busy = false; editBtn.isEnabled = true; progress.visibility = View.GONE
                out.onSuccess { r ->
                    result = r; showImageResult(r); saveBtn.visibility = View.VISIBLE
                    info.text = "완료. '저장'을 누르면 갤러리에 PNG로 저장됩니다. 다시 하려면 사진을 다시 고르세요."
                }.onFailure { info.text = "실패: ${it.message}" }
            }
        } else thread { processVideo(source!!, rect, img.width, img.height) }
    }

    /** 동영상: 프레임마다 물체를 따라가며 배경을 지우고 MP4로 저장 */
    private fun processVideo(uri: Uri, rect: Rect, w0: Int, h0: Int) {
        var outInfo: MediaSave.VideoOut? = null
        val r = runCatching {
            VideoSource(this, uri).use { src ->
                val (ow, oh) = VideoEncoder.fitSize(w0, h0, 1280)
                val fps = src.fps.toInt().coerceIn(10, 30)
                val step = max(1, (src.fps / fps).toInt())
                val out = MediaSave.newVideo(this, "bg_removed_${System.currentTimeMillis()}.mp4").also { outInfo = it }
                val enc = VideoEncoder(out.pfd.fileDescriptor, ow, oh, fps)
                val tracker = Cutout.VideoTracker(rect, w0, h0)
                var written = 0
                try {
                    var i = 0
                    while (i < src.count) {
                        val chunk = src.frames(i, 10, 1280)
                        if (chunk.isEmpty()) break
                        chunk.forEachIndexed { k, f ->
                            if ((i + k) % step == 0) {
                                val alpha = tracker.next(f)
                                val comp = Cutout.composite(f, alpha, backdrop)
                                val scaled = Bitmap.createScaledBitmap(comp, ow, oh, true)
                                enc.addFrame(scaled, written * 1_000_000L / fps)
                                written++
                                if (scaled !== comp) scaled.recycle()
                                comp.recycle()
                            }
                            f.recycle()
                        }
                        i += chunk.size
                        val p = (i * 100 / src.count).coerceAtMost(100)
                        runOnUiThread { progress.progress = p; info.text = "동영상 처리 중... $p% (프레임 $i/${src.count})" }
                    }
                } finally {
                    enc.finish()
                    out.done()
                }
                if (written == 0) throw IllegalStateException("처리한 프레임이 없습니다")
                out
            }
        }
        runOnUiThread {
            busy = false; editBtn.isEnabled = true; progress.visibility = View.GONE
            r.onSuccess { out ->
                info.text = "완료. ${out.label} 에 저장했습니다 (소리는 빠집니다)."
                showVideoResult(out.uri)
            }.onFailure { info.text = "실패: ${it.message}"; outInfo?.done() }
        }
    }

    private fun checker(): BitmapDrawable {
        val s = dp(10)
        val b = Bitmap.createBitmap(s * 2, s * 2, Bitmap.Config.ARGB_8888)
        Canvas(b).apply {
            drawColor(Color.rgb(200, 200, 200))
            val p = Paint().apply { color = Color.rgb(150, 150, 150) }
            drawRect(0f, 0f, s.toFloat(), s.toFloat(), p); drawRect(s.toFloat(), s.toFloat(), 2f * s, 2f * s, p)
        }
        return BitmapDrawable(resources, b).apply { setTileModeXY(Shader.TileMode.REPEAT, Shader.TileMode.REPEAT) }
    }

    private fun showImageResult(b: Bitmap) {
        stage.removeAllViews()
        stage.addView(ImageView(this).apply {
            setImageBitmap(b); scaleType = ImageView.ScaleType.FIT_CENTER
            background = checker()
        }, FrameLayout.LayoutParams(MATCH_PARENT, MATCH_PARENT))
    }

    private fun showVideoResult(uri: Uri) {
        stage.removeAllViews()
        val vv = VideoView(this)
        stage.addView(vv, FrameLayout.LayoutParams(MATCH_PARENT, MATCH_PARENT, Gravity.CENTER))
        vv.setMediaController(MediaController(this).also { it.setAnchorView(vv) })
        vv.setVideoURI(uri)
        vv.setOnPreparedListener { it.isLooping = true; vv.start() }
    }

    private fun saveResult() {
        val r = result ?: return
        thread {
            val msg = runCatching { MediaSave.savePng(this, r, "bg_removed_${System.currentTimeMillis()}.png") }
                .fold({ "$it 에 저장했습니다" }, { "저장 실패: ${it.message}" })
            runOnUiThread { Toast.makeText(this, msg, Toast.LENGTH_LONG).show() }
        }
    }
}

/** GrabCut 으로 사각형 안의 물체만 남깁니다. */
object Cutout {
    private const val WORK = 720 // 계산은 이 크기로 줄여서 (빠르게)

    private fun rgbSmall(src: Bitmap, maxSide: Int): Pair<Mat, Float> {
        val rgba = Mat(); Utils.bitmapToMat(src, rgba)
        val sc = min(1f, maxSide.toFloat() / max(src.width, src.height))
        val small = Mat()
        if (sc < 1f) Imgproc.resize(rgba, small, Size(src.width * sc.toDouble(), src.height * sc.toDouble()), 0.0, 0.0, Imgproc.INTER_AREA)
        else rgba.copyTo(small)
        val rgb = Mat(); Imgproc.cvtColor(small, rgb, Imgproc.COLOR_RGBA2RGB)
        rgba.release(); small.release()
        return rgb to sc
    }

    private fun fgOf(mask: Mat): Mat {
        val a = Mat(); val b = Mat(); val fg = Mat()
        Core.compare(mask, Scalar(Imgproc.GC_FGD.toDouble()), a, Core.CMP_EQ)
        Core.compare(mask, Scalar(Imgproc.GC_PR_FGD.toDouble()), b, Core.CMP_EQ)
        Core.bitwise_or(a, b, fg)
        a.release(); b.release()
        // 작은 구멍과 잡티 정리
        val k = Imgproc.getStructuringElement(Imgproc.MORPH_ELLIPSE, Size(5.0, 5.0))
        Imgproc.morphologyEx(fg, fg, Imgproc.MORPH_OPEN, k)
        Imgproc.morphologyEx(fg, fg, Imgproc.MORPH_CLOSE, k)
        return fg
    }

    /** 작은 크기의 0/255 마스크 → 원래 크기의 부드러운 알파 */
    private fun toAlpha(fg: Mat, w: Int, h: Int): Mat {
        val soft = Mat(); Imgproc.GaussianBlur(fg, soft, Size(0.0, 0.0), 1.5)
        val full = Mat(); Imgproc.resize(soft, full, Size(w.toDouble(), h.toDouble()), 0.0, 0.0, Imgproc.INTER_LINEAR)
        soft.release()
        return full
    }

    private fun scaled(r: Rect, sc: Float, w: Int, h: Int): org.opencv.core.Rect {
        val l = (r.left * sc).toInt().coerceIn(1, w - 3); val t = (r.top * sc).toInt().coerceIn(1, h - 3)
        val rr = (r.right * sc).toInt().coerceIn(l + 2, w - 1); val b = (r.bottom * sc).toInt().coerceIn(t + 2, h - 1)
        return org.opencv.core.Rect(l, t, rr - l, b - t)
    }

    /** 사진: 사각형으로 시작해 GrabCut 5회 → 원래 크기 알파 마스크 */
    fun photoMask(src: Bitmap, rect: Rect): Mat {
        val (rgb, sc) = rgbSmall(src, WORK)
        val mask = Mat(); val bgd = Mat(); val fgd = Mat()
        Imgproc.grabCut(rgb, mask, scaled(rect, sc, rgb.cols(), rgb.rows()), bgd, fgd, 5, Imgproc.GC_INIT_WITH_RECT)
        val fg = fgOf(mask)
        val alpha = toAlpha(fg, src.width, src.height)
        listOf(rgb, mask, bgd, fgd, fg).forEach { it.release() }
        return alpha
    }

    /** 동영상: 앞 프레임에서 찾은 물체 모양으로 다음 프레임을 시작해서 물체를 따라갑니다. */
    class VideoTracker(private val rect: Rect, private val w0: Int, private val h0: Int) {
        private var prev: Mat? = null

        fun next(frame: Bitmap): Mat {
            val (rgb, sc) = rgbSmall(frame, 480)
            val mask = Mat(); val bgd = Mat(); val fgd = Mat()
            val p = prev
            val rx = frame.width.toFloat() / w0; val ry = frame.height.toFloat() / h0
            val r0 = Rect((rect.left * rx).toInt(), (rect.top * ry).toInt(), (rect.right * rx).toInt(), (rect.bottom * ry).toInt())
            val fg = runCatching {
                if (p == null || Core.countNonZero(p) < 50 || p.size() != rgb.size()) {
                    Imgproc.grabCut(rgb, mask, scaled(r0, sc, rgb.cols(), rgb.rows()), bgd, fgd, 4, Imgproc.GC_INIT_WITH_RECT)
                } else {
                    // 확실한 물체(안쪽) / 아마 물체 / 아마 배경(가장자리 띠) / 확실한 배경
                    mask.create(rgb.size(), CvType.CV_8U); mask.setTo(Scalar(Imgproc.GC_BGD.toDouble()))
                    val band = Mat(); Imgproc.dilate(p, band, Imgproc.getStructuringElement(Imgproc.MORPH_ELLIPSE, Size(25.0, 25.0)))
                    mask.setTo(Scalar(Imgproc.GC_PR_BGD.toDouble()), band)
                    mask.setTo(Scalar(Imgproc.GC_PR_FGD.toDouble()), p)
                    val sure = Mat(); Imgproc.erode(p, sure, Imgproc.getStructuringElement(Imgproc.MORPH_ELLIPSE, Size(9.0, 9.0)))
                    mask.setTo(Scalar(Imgproc.GC_FGD.toDouble()), sure)
                    band.release(); sure.release()
                    Imgproc.grabCut(rgb, mask, org.opencv.core.Rect(), bgd, fgd, 2, Imgproc.GC_INIT_WITH_MASK)
                }
                fgOf(mask)
            }.getOrElse { p?.clone() ?: Mat.zeros(rgb.size(), CvType.CV_8U) }
            prev?.release(); prev = fg.clone()
            val alpha = toAlpha(fg, frame.width, frame.height)
            listOf(rgb, mask, bgd, fgd, fg).forEach { it.release() }
            return alpha
        }
    }

    /** 알파 마스크로 물체만 남기고 배경을 바꿉니다. 마스크는 이 함수에서 해제합니다. */
    fun composite(src: Bitmap, alpha: Mat, bg: Backdrop): Bitmap {
        val rgba = Mat(); Utils.bitmapToMat(src, rgba)
        val out = Mat()
        if (bg == Backdrop.TRANSPARENT) {
            val ch = ArrayList<Mat>(); Core.split(rgba, ch)
            Core.min(ch[3], alpha, ch[3])
            Core.merge(ch, out)
            ch.forEach { it.release() }
        } else {
            val back = Mat()
            when (bg) {
                Backdrop.BLUR -> Imgproc.GaussianBlur(rgba, back, Size(0.0, 0.0), max(src.width, src.height) / 50.0)
                else -> {
                    val c = when (bg) { Backdrop.WHITE -> Scalar(255.0, 255.0, 255.0, 255.0); Backdrop.BLACK -> Scalar(0.0, 0.0, 0.0, 255.0)
                        else -> Scalar(0.0, 177.0, 64.0, 255.0) }
                    back.create(rgba.size(), CvType.CV_8UC4); back.setTo(c)
                }
            }
            val a = Mat(); alpha.convertTo(a, CvType.CV_32F, 1.0 / 255.0)
            val a4 = Mat(); Core.merge(listOf(a, a, a, a), a4)
            val f = Mat(); rgba.convertTo(f, CvType.CV_32FC4)
            val b = Mat(); back.convertTo(b, CvType.CV_32FC4)
            val ones = Mat(a4.size(), CvType.CV_32FC4, Scalar.all(1.0))
            val inv = Mat(); Core.subtract(ones, a4, inv)
            Core.multiply(f, a4, f); Core.multiply(b, inv, b)
            Core.add(f, b, f)
            f.convertTo(out, CvType.CV_8UC4)
            listOf(back, a, a4, f, b, ones, inv).forEach { it.release() }
        }
        val bmp = Bitmap.createBitmap(src.width, src.height, Bitmap.Config.ARGB_8888)
        Utils.matToBitmap(out, bmp, bg == Backdrop.TRANSPARENT)
        rgba.release(); out.release(); alpha.release()
        return bmp
    }
}

/** 사진 위에 사각형 틀을 그리고, 끌어서 옮기거나 모서리로 크기를 바꿉니다. */
class RectSelectView(ctx: Context) : View(ctx) {
    private var bmp: Bitmap? = null
    private var sel = RectF() // 사진 좌표
    private val d = resources.displayMetrics.density
    private val dim = Paint().apply { color = Color.argb(140, 0, 0, 0) }
    private val line = Paint(Paint.ANTI_ALIAS_FLAG).apply { style = Paint.Style.STROKE; strokeWidth = 2.5f * d; color = Color.rgb(0, 210, 255) }
    private val knob = Paint(Paint.ANTI_ALIAS_FLAG).apply { color = Color.WHITE }
    private val hint = Paint(Paint.ANTI_ALIAS_FLAG).apply { color = Color.LTGRAY; textSize = 15 * d; textAlign = Paint.Align.CENTER }
    private var drag = -1 // 0..3 모서리, 4 이동
    private var lastX = 0f; private var lastY = 0f

    fun setImage(b: Bitmap) {
        bmp = b
        sel = RectF(b.width * 0.2f, b.height * 0.2f, b.width * 0.8f, b.height * 0.8f)
        invalidate()
    }

    fun imageRect(): Rect? = bmp?.let { Rect(sel.left.toInt(), sel.top.toInt(), sel.right.toInt(), sel.bottom.toInt()) }

    private fun fit(): Pair<Float, PointF2> {
        val b = bmp!!
        val s = min(width / b.width.toFloat(), height / b.height.toFloat())
        return s to PointF2((width - b.width * s) / 2, (height - b.height * s) / 2)
    }

    private class PointF2(val x: Float, val y: Float)

    override fun onDraw(c: Canvas) {
        val b = bmp
        if (b == null) { c.drawText("사진이나 동영상을 고르세요", width / 2f, height / 2f, hint); return }
        val (s, o) = fit()
        val dst = RectF(o.x, o.y, o.x + b.width * s, o.y + b.height * s)
        c.drawBitmap(b, null, dst, null)
        val r = RectF(o.x + sel.left * s, o.y + sel.top * s, o.x + sel.right * s, o.y + sel.bottom * s)
        // 사각형 바깥(지워질 부분)을 어둡게
        c.drawRect(dst.left, dst.top, dst.right, r.top, dim); c.drawRect(dst.left, r.bottom, dst.right, dst.bottom, dim)
        c.drawRect(dst.left, r.top, r.left, r.bottom, dim); c.drawRect(r.right, r.top, dst.right, r.bottom, dim)
        c.drawRect(r, line)
        for ((x, y) in listOf(r.left to r.top, r.right to r.top, r.left to r.bottom, r.right to r.bottom)) c.drawCircle(x, y, 9 * d, knob)
    }

    override fun onTouchEvent(e: MotionEvent): Boolean {
        val b = bmp ?: return false
        val (s, o) = fit()
        val ix = (e.x - o.x) / s; val iy = (e.y - o.y) / s
        when (e.actionMasked) {
            MotionEvent.ACTION_DOWN -> {
                val tol = 32 * d / s
                val corners = listOf(sel.left to sel.top, sel.right to sel.top, sel.left to sel.bottom, sel.right to sel.bottom)
                drag = corners.indexOfFirst { (x, y) -> abs(x - ix) < tol && abs(y - iy) < tol }
                if (drag < 0 && sel.contains(ix, iy)) drag = 4
                if (drag < 0) { sel = RectF(ix, iy, ix + 1, iy + 1); drag = 3 } // 새로 그리기
                lastX = ix; lastY = iy
            }
            MotionEvent.ACTION_MOVE -> {
                val minS = 16f
                when (drag) {
                    0 -> { sel.left = min(ix, sel.right - minS); sel.top = min(iy, sel.bottom - minS) }
                    1 -> { sel.right = max(ix, sel.left + minS); sel.top = min(iy, sel.bottom - minS) }
                    2 -> { sel.left = min(ix, sel.right - minS); sel.bottom = max(iy, sel.top + minS) }
                    3 -> { sel.right = max(ix, sel.left + minS); sel.bottom = max(iy, sel.top + minS) }
                    4 -> sel.offset(ix - lastX, iy - lastY)
                }
                // 사진 안으로 제한
                sel.left = sel.left.coerceIn(0f, b.width - 2f); sel.top = sel.top.coerceIn(0f, b.height - 2f)
                sel.right = sel.right.coerceIn(sel.left + 2f, b.width.toFloat()); sel.bottom = sel.bottom.coerceIn(sel.top + 2f, b.height.toFloat())
                lastX = ix; lastY = iy
                invalidate()
            }
            MotionEvent.ACTION_UP, MotionEvent.ACTION_CANCEL -> drag = -1
        }
        return true
    }
}
