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
import android.widget.SeekBar
import android.graphics.PorterDuff
import android.graphics.PorterDuffXfermode
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
import com.google.mediapipe.framework.image.BitmapImageBuilder
import com.google.mediapipe.framework.image.ByteBufferExtractor
import com.google.mediapipe.tasks.components.containers.NormalizedKeypoint
import com.google.mediapipe.tasks.core.BaseOptions
import com.google.mediapipe.tasks.core.Delegate
import com.google.mediapipe.tasks.vision.interactivesegmenter.InteractiveSegmenter
import java.nio.ByteOrder
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
    private lateinit var brushBar: LinearLayout
    private var editor: MaskEditView? = null
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
            text = "사진이나 동영상을 고른 뒤, 남길 물체를 사각형으로 감싸고 '편집'을 누르세요. AI 가 사각형 가운데의 물체 모양을 찾아 나머지를 지웁니다."
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
        // 붓 (사진 결과를 손으로 고치기)
        brushBar = LinearLayout(this).apply { orientation = LinearLayout.HORIZONTAL; setPadding(dp(8), 0, dp(8), 0); visibility = View.GONE; gravity = Gravity.CENTER_VERTICAL }
        brushBar.addView(Button(this).apply {
            text = "붓: 복원"; textSize = 12f
            setOnClickListener { editor?.let { e -> e.restore = !e.restore; text = if (e.restore) "붓: 복원" else "붓: 지우기" } }
        }, LinearLayout.LayoutParams(0, WRAP_CONTENT, 1f))
        brushBar.addView(TextView(this).apply { text = "굵기"; setTextColor(Color.WHITE); textSize = 12f; setPadding(dp(8), 0, dp(4), 0) })
        brushBar.addView(SeekBar(this).apply {
            max = 100; progress = 30
            setOnSeekBarChangeListener(object : SeekBar.OnSeekBarChangeListener {
                override fun onProgressChanged(sb: SeekBar, p: Int, u: Boolean) { editor?.brushDp = 6f + p * 0.6f }
                override fun onStartTrackingTouch(sb: SeekBar) {}
                override fun onStopTrackingTouch(sb: SeekBar) {}
            })
        }, LinearLayout.LayoutParams(0, WRAP_CONTENT, 1.5f))
        root.addView(brushBar)
        root.addView(bar)
        setContentView(root)
        check(OpenCVLoader.initLocal()) { "OpenCV를 불러오지 못했습니다" }
    }

    private fun cycleBackdrop() {
        val all = Backdrop.values().filter { !(isVideo && it == Backdrop.TRANSPARENT) } // 동영상은 투명을 지원하지 않음
        backdrop = all[(all.indexOf(backdrop) + 1) % all.size]
        bgBtn.text = "배경: ${backdrop.label}"
        editor?.setBackdrop(backdrop)
    }

    private fun load(uri: Uri) {
        source = uri
        isVideo = contentResolver.getType(uri)?.startsWith("video") == true
        if (isVideo && backdrop == Backdrop.TRANSPARENT) { backdrop = Backdrop.WHITE; bgBtn.text = "배경: ${backdrop.label}" }
        result = null; saveBtn.visibility = View.GONE; brushBar.visibility = View.GONE; editor = null
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
            val out = runCatching { MaskEditView.maskToBitmap(Cutout.photoMask(this, img, rect)) }
            runOnUiThread {
                busy = false; editBtn.isEnabled = true; progress.visibility = View.GONE
                out.onSuccess { mask ->
                    showEditor(img, mask); saveBtn.visibility = View.VISIBLE; brushBar.visibility = View.VISIBLE
                    info.text = "완료. 잘못 지워진 곳은 '붓: 복원'으로 문질러 되살리고, 남은 배경은 '붓: 지우기'로 지우세요. 다 되면 '저장'."
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
                val enc = VideoEncoder(out.pfd.fileDescriptor, ow, oh, fps, AudioPassthrough(this, uri)) // 원본 소리도 함께
                val tracker = Cutout.VideoTracker(this, rect, w0, h0)
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
                                enc.addFrame(scaled, ((i + k) * 1_000_000.0 / src.fps).toLong()) // 원본과 같은 시간축 (소리와 맞음)
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
                    tracker.close()
                    out.done()
                }
                if (written == 0) throw IllegalStateException("처리한 프레임이 없습니다")
                out
            }
        }
        runOnUiThread {
            busy = false; editBtn.isEnabled = true; progress.visibility = View.GONE
            r.onSuccess { out ->
                info.text = "완료. ${out.label} 에 저장했습니다 (원본 소리 포함)."
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

    private fun showEditor(src: Bitmap, mask: Bitmap) {
        stage.removeAllViews()
        val e = MaskEditView(this, src, mask, checker())
        e.setBackdrop(backdrop)
        editor = e
        stage.addView(e, FrameLayout.LayoutParams(MATCH_PARENT, MATCH_PARENT))
    }

    private fun saveResult() {
        val e = editor
        val img = image
        thread {
            val msg = runCatching {
                val r = if (e != null && img != null) Cutout.composite(img, MaskEditView.bitmapToMask(e.mask), backdrop) else result ?: error("결과가 없습니다")
                MediaSave.savePng(this, r, "bg_removed_${System.currentTimeMillis()}.png")
            }
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

    /** 사진: 사각형으로 시작해 GrabCut 5회 → 원래 크기 알파 마스크 (AI 가 실패했을 때 씀) */
    private fun grabCutMask(src: Bitmap, rect: Rect): Mat {
        val (rgb, sc) = rgbSmall(src, WORK)
        val mask = Mat(); val bgd = Mat(); val fgd = Mat()
        Imgproc.grabCut(rgb, mask, scaled(rect, sc, rgb.cols(), rgb.rows()), bgd, fgd, 5, Imgproc.GC_INIT_WITH_RECT)
        val fg = fgOf(mask)
        val alpha = toAlpha(fg, src.width, src.height)
        listOf(rgb, mask, bgd, fgd, fg).forEach { it.release() }
        return alpha
    }

    /** AI 한 번: 한 점을 가리켜 그 물체의 확신도(0~1) 맵 */
    private fun aiConf(seg: InteractiveSegmenter, img: Bitmap, nx: Float, ny: Float): Mat? {
        val res = seg.segment(BitmapImageBuilder(img).build(),
            InteractiveSegmenter.RegionOfInterest.create(NormalizedKeypoint.create(nx.coerceIn(0f, 1f), ny.coerceIn(0f, 1f))))
        val m = res.confidenceMasks().orElse(null)?.firstOrNull() ?: return null
        val buf = ByteBufferExtractor.extract(m).order(ByteOrder.nativeOrder()).asFloatBuffer()
        val arr = FloatArray(m.width * m.height); buf.position(0); buf.get(arr)
        return Mat(m.height, m.width, CvType.CV_32F).also { it.put(0, 0, arr) }
    }

    /**
     * 사각형 안 여러 점(가운데 + 네 군데)에서 AI 로 물체를 찾아 합칩니다.
     * 한 점만 쓰면 물체의 일부분만 잡히거나 구멍이 생겨, 남겨야 할 곳이 지워지던 문제를 줄입니다.
     * 결과 중 사각형(25% 넓힘) 안에 80% 이상 들어가는 것만 합쳐서, 바깥 배경이 딸려 오지 않게 합니다.
     * 그 뒤 물체 안쪽의 구멍을 메우고, 경계만 살짝 부드럽게 합니다. 결과: 작은 크기의 0~255 마스크.
     */
    private fun aiMask(seg: InteractiveSegmenter, src: Bitmap, rect: RectF, maxSide: Int, points: Int): Mat? {
        val sc = min(1f, maxSide.toFloat() / max(src.width, src.height))
        val small = if (sc < 1f) Bitmap.createScaledBitmap(src, (src.width * sc).toInt(), (src.height * sc).toInt(), true) else src
        try {
            val w = small.width; val h = small.height
            val ex = rect.width() * 0.25f; val ey = rect.height() * 0.25f
            val lim = Mat.zeros(h, w, CvType.CV_8U)
            Imgproc.rectangle(lim, org.opencv.core.Point(((rect.left - ex) * sc).toDouble(), ((rect.top - ey) * sc).toDouble()),
                org.opencv.core.Point(((rect.right + ex) * sc).toDouble(), ((rect.bottom + ey) * sc).toDouble()), Scalar(255.0), -1)
            val offs = listOf(0f to 0f, -0.22f to -0.22f, 0.22f to -0.22f, -0.22f to 0.22f, 0.22f to 0.22f, 0f to -0.3f, 0f to 0.3f).take(points)
            val union = Mat.zeros(h, w, CvType.CV_8U)
            val inside = Mat()
            for ((ox, oy) in offs) {
                val px = rect.centerX() + ox * rect.width(); val py = rect.centerY() + oy * rect.height()
                val conf = aiConf(seg, small, px / src.width, py / src.height) ?: continue
                val bin = Mat(); Imgproc.threshold(conf, bin, 0.5, 255.0, Imgproc.THRESH_BINARY); conf.release()
                bin.convertTo(bin, CvType.CV_8U)
                val area = Core.countNonZero(bin)
                if (area < w * h / 500) { bin.release(); continue }
                Core.bitwise_and(bin, lim, inside)
                if (Core.countNonZero(inside) >= area * 0.7) Core.bitwise_or(union, bin, union) // 대부분 사각형 근처면 물체로 인정
                bin.release()
            }
            inside.release()
            lim.release()
            // 사각형과 겹치는 덩어리는 사각형 밖으로 나간 부분(팔, 발 등)까지 통째로 살리고, 떨어진 배경 조각만 버립니다
            val big = Mat.zeros(h, w, CvType.CV_8U)
            Imgproc.rectangle(big, org.opencv.core.Point(((rect.left - rect.width() * 0.6f) * sc).toDouble(), ((rect.top - rect.height() * 0.6f) * sc).toDouble()),
                org.opencv.core.Point(((rect.right + rect.width() * 0.6f) * sc).toDouble(), ((rect.bottom + rect.height() * 0.6f) * sc).toDouble()), Scalar(255.0), -1)
            Core.bitwise_and(union, big, union); big.release()
            keepTouching(union, org.opencv.core.Rect((rect.left * sc).toInt(), (rect.top * sc).toInt(), (rect.width() * sc).toInt().coerceAtLeast(1), (rect.height() * sc).toInt().coerceAtLeast(1)))
            if (Core.countNonZero(union) < w * h / 400) { union.release(); return null }
            fillHoles(union)
            Imgproc.GaussianBlur(union, union, Size(0.0, 0.0), 1.2) // 경계만 부드럽게
            return union
        } finally {
            if (small !== src) small.recycle()
        }
    }

    /** 가장 큰 덩어리와, 넓이의 30% 이상이 사각형 안에 있는 덩어리만 남깁니다 */
    private fun keepTouching(m: Mat, r: org.opencv.core.Rect) {
        val labels = Mat(); val stats = Mat(); val cent = Mat()
        val n = Imgproc.connectedComponentsWithStats(m, labels, stats, cent)
        if (n <= 1) { labels.release(); stats.release(); cent.release(); return }
        var largest = 1
        for (i in 1 until n) if (stats.get(i, Imgproc.CC_STAT_AREA)[0] > stats.get(largest, Imgproc.CC_STAT_AREA)[0]) largest = i
        val rr = org.opencv.core.Rect(r.x.coerceIn(0, m.cols() - 1), r.y.coerceIn(0, m.rows() - 1), 1, 1)
        rr.width = r.width.coerceAtMost(m.cols() - rr.x); rr.height = r.height.coerceAtMost(m.rows() - rr.y)
        val inRect = labels.submat(rr)
        val keep = Mat.zeros(m.size(), CvType.CV_8U)
        val comp = Mat(); val compIn = Mat()
        for (i in 1 until n) {
            val area = stats.get(i, Imgproc.CC_STAT_AREA)[0]
            Core.compare(inRect, Scalar(i.toDouble()), compIn, Core.CMP_EQ)
            if (i == largest || Core.countNonZero(compIn) >= area * 0.3) {
                Core.compare(labels, Scalar(i.toDouble()), comp, Core.CMP_EQ)
                Core.bitwise_or(keep, comp, keep)
            }
        }
        keep.copyTo(m)
        listOf(labels, stats, cent, keep, comp, compIn).forEach { it.release() }
    }

    /** 물체 안쪽에 생긴 구멍(물체 넓이의 8% 이하)을 메웁니다 */
    private fun fillHoles(m: Mat) {
        val k = Imgproc.getStructuringElement(Imgproc.MORPH_ELLIPSE, Size(7.0, 7.0))
        Imgproc.morphologyEx(m, m, Imgproc.MORPH_CLOSE, k)
        val contours = ArrayList<org.opencv.core.MatOfPoint>(); val hier = Mat()
        Imgproc.findContours(m.clone(), contours, hier, Imgproc.RETR_CCOMP, Imgproc.CHAIN_APPROX_SIMPLE)
        val total = Core.countNonZero(m).toDouble()
        for (i in contours.indices) {
            val parent = hier.get(0, i)[3].toInt()
            if (parent >= 0 && Imgproc.contourArea(contours[i]) <= total * 0.08) Imgproc.drawContours(m, contours, i, Scalar(255.0), -1)
        }
        hier.release()
    }

    private fun segmenter(ctx: Context): InteractiveSegmenter {
        fun make(d: Delegate) = InteractiveSegmenter.createFromOptions(ctx, InteractiveSegmenter.InteractiveSegmenterOptions.builder()
            .setBaseOptions(BaseOptions.builder().setModelAssetPath("magic_touch.tflite").setDelegate(d).build())
            .setOutputConfidenceMasks(true).setOutputCategoryMask(false).build())
        return runCatching { make(Delegate.GPU) }.getOrElse { make(Delegate.CPU) }
    }

    /** 사진: AI 로 물체 모양 → 원래 크기 알파 마스크. AI 가 못 찾으면 GrabCut. */
    fun photoMask(ctx: Context, src: Bitmap, rect: Rect): Mat {
        val seg = segmenter(ctx)
        try {
            val m = aiMask(seg, src, RectF(rect), 1024, 7) ?: return grabCutMask(src, rect)
            val full = Mat(); Imgproc.resize(m, full, Size(src.width.toDouble(), src.height.toDouble()), 0.0, 0.0, Imgproc.INTER_LINEAR)
            m.release()
            return full
        } finally {
            seg.close()
        }
    }

    /**
     * 동영상: 프레임마다 AI 로 물체를 다시 찾습니다 (3개 점).
     * 범위는 앞 프레임 물체의 중심을 따라가되 처음 사각형보다 작아지지 않게 해서, 조금씩 깎여 나가던 문제를 막습니다.
     * 갑자기 물체가 30% 넘게 줄면 그 프레임만 놓친 것으로 보고 앞 프레임 모양을 합칩니다.
     */
    class VideoTracker(ctx: Context, rect: Rect, private val w0: Int, private val h0: Int) {
        private val seg = segmenter(ctx)
        private val r0 = RectF(rect)
        private var area = RectF(rect)
        private var prev: Mat? = null

        fun next(frame: Bitmap): Mat {
            val rx = frame.width.toFloat() / w0; val ry = frame.height.toFloat() / h0
            val r = RectF(area.left * rx, area.top * ry, area.right * rx, area.bottom * ry)
            var m = aiMask(seg, frame, r, 512, 3)
            val p = prev
            if (m == null) m = p?.clone() ?: Mat.zeros(1, 1, CvType.CV_8U)
            else if (p != null && p.size() == m.size() && Core.countNonZero(m) < Core.countNonZero(p) * 0.7) Core.max(m, p, m)
            prev?.release(); prev = m.clone()
            // 다음 프레임 범위: 물체 중심을 따라가고, 크기는 max(물체 크기, 처음 사각형)
            val bin = Mat(); Imgproc.threshold(m, bin, 127.0, 255.0, Imgproc.THRESH_BINARY)
            val box = Imgproc.boundingRect(bin); bin.release()
            if (box.width > 4 && box.height > 4 && m.cols() > 1) {
                val sx = w0.toFloat() / m.cols(); val sy = h0.toFloat() / m.rows()
                val cx = (box.x + box.width / 2f) * sx; val cy = (box.y + box.height / 2f) * sy
                val hw = max(box.width * sx, r0.width()) / 2; val hh = max(box.height * sy, r0.height()) / 2
                area = RectF(cx - hw, cy - hh, cx + hw, cy + hh)
            }
            val full = Mat()
            if (m.cols() > 1) Imgproc.resize(m, full, Size(frame.width.toDouble(), frame.height.toDouble()), 0.0, 0.0, Imgproc.INTER_LINEAR)
            else { full.create(frame.height, frame.width, CvType.CV_8U); full.setTo(Scalar(0.0)) }
            m.release()
            return full
        }

        fun close() { seg.close(); prev?.release() }
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

/**
 * 배경 제거 결과를 손으로 고치는 화면. "복원" 붓으로 문지르면 지워진 곳이 되살아나고, "지우기" 붓으로 남은 배경을 지웁니다.
 * mask: 사진과 같은 크기의 ALPHA_8 비트맵 (255 = 남김)
 */
class MaskEditView(ctx: Context, private val src: Bitmap, val mask: Bitmap, private val checker: BitmapDrawable) : View(ctx) {
    var restore = true
    var brushDp = 24f
    private var backdrop = Backdrop.TRANSPARENT
    private var blurred: Bitmap? = null
    private val d = resources.displayMetrics.density
    private val dstIn = Paint().apply { xfermode = PorterDuffXfermode(PorterDuff.Mode.DST_IN); isFilterBitmap = true }
    private val paintOn = Paint(Paint.ANTI_ALIAS_FLAG).apply { color = Color.BLACK; style = Paint.Style.STROKE; strokeCap = Paint.Cap.ROUND; strokeJoin = Paint.Join.ROUND }
    private val paintOff = Paint(Paint.ANTI_ALIAS_FLAG).apply { xfermode = PorterDuffXfermode(PorterDuff.Mode.CLEAR); style = Paint.Style.STROKE; strokeCap = Paint.Cap.ROUND; strokeJoin = Paint.Join.ROUND }
    private val ring = Paint(Paint.ANTI_ALIAS_FLAG).apply { style = Paint.Style.STROKE; strokeWidth = 2 * d; color = Color.rgb(0, 210, 255) }
    private var lastX = 0f; private var lastY = 0f
    private var touchX = -1f; private var touchY = -1f

    fun setBackdrop(b: Backdrop) {
        backdrop = b
        if (b == Backdrop.BLUR && blurred == null) {
            val m = Mat(); Utils.bitmapToMat(src, m)
            Imgproc.GaussianBlur(m, m, Size(0.0, 0.0), max(src.width, src.height) / 50.0)
            blurred = Bitmap.createBitmap(src.width, src.height, Bitmap.Config.ARGB_8888).also { Utils.matToBitmap(m, it) }
            m.release()
        }
        invalidate()
    }

    private fun dst(): RectF {
        val s = min(width / src.width.toFloat(), height / src.height.toFloat())
        val ox = (width - src.width * s) / 2; val oy = (height - src.height * s) / 2
        return RectF(ox, oy, ox + src.width * s, oy + src.height * s)
    }

    override fun onDraw(c: Canvas) {
        val r = dst()
        when (backdrop) {
            Backdrop.TRANSPARENT -> { checker.setBounds(r.left.toInt(), r.top.toInt(), r.right.toInt(), r.bottom.toInt()); checker.draw(c) }
            Backdrop.WHITE -> c.drawRect(r, Paint().apply { color = Color.WHITE })
            Backdrop.BLACK -> c.drawRect(r, Paint().apply { color = Color.BLACK })
            Backdrop.GREEN -> c.drawRect(r, Paint().apply { color = Color.rgb(0, 177, 64) })
            Backdrop.BLUR -> blurred?.let { c.drawBitmap(it, null, r, null) }
        }
        val layer = c.saveLayer(r, null)
        c.drawBitmap(src, null, r, Paint(Paint.FILTER_BITMAP_FLAG))
        c.drawBitmap(mask, null, r, dstIn) // 마스크(알파)가 있는 곳만 남김
        c.restoreToCount(layer)
        if (touchX >= 0) c.drawCircle(touchX, touchY, brushDp * d, ring)
    }

    override fun onTouchEvent(e: MotionEvent): Boolean {
        val r = dst()
        val s = r.width() / src.width
        val ix = (e.x - r.left) / s; val iy = (e.y - r.top) / s
        val p = if (restore) paintOn else paintOff
        p.strokeWidth = brushDp * d * 2 / s
        when (e.actionMasked) {
            MotionEvent.ACTION_DOWN -> { lastX = ix; lastY = iy; Canvas(mask).drawPoint(ix, iy, p) }
            MotionEvent.ACTION_MOVE -> { Canvas(mask).drawLine(lastX, lastY, ix, iy, p); lastX = ix; lastY = iy }
        }
        touchX = if (e.actionMasked == MotionEvent.ACTION_UP || e.actionMasked == MotionEvent.ACTION_CANCEL) -1f else e.x
        touchY = e.y
        invalidate()
        return true
    }

    companion object {
        /** 0~255 Mat → ALPHA_8 비트맵 (줄 끝 여백 고려). Mat 은 해제합니다. */
        fun maskToBitmap(m: Mat): Bitmap {
            val w = m.cols(); val h = m.rows()
            val bmp = Bitmap.createBitmap(w, h, Bitmap.Config.ALPHA_8)
            val row = ByteArray(w); val stride = bmp.rowBytes
            val buf = java.nio.ByteBuffer.allocate(stride * h)
            for (y in 0 until h) { m.get(y, 0, row); buf.position(y * stride); buf.put(row) }
            buf.position(0); bmp.copyPixelsFromBuffer(buf)
            m.release()
            return bmp
        }

        /** ALPHA_8 비트맵 → 0~255 Mat */
        fun bitmapToMask(b: Bitmap): Mat {
            val w = b.width; val h = b.height; val stride = b.rowBytes
            val buf = java.nio.ByteBuffer.allocate(stride * h)
            b.copyPixelsToBuffer(buf)
            val m = Mat(h, w, CvType.CV_8U); val row = ByteArray(w)
            for (y in 0 until h) { buf.position(y * stride); buf.get(row); m.put(y, 0, row) }
            return m
        }
    }
}
