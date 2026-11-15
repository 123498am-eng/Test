package com.selfcheck.app

import android.Manifest
import android.app.AlertDialog
import android.content.ContentValues
import android.content.Context
import android.content.pm.PackageManager
import android.graphics.Bitmap
import android.graphics.Canvas
import android.graphics.Color
import android.graphics.Paint
import android.graphics.RectF
import android.os.Build
import android.os.Bundle
import android.os.Environment
import android.provider.MediaStore
import android.util.Size
import android.view.Gravity
import android.view.MotionEvent
import android.view.ScaleGestureDetector
import android.view.View
import android.view.ViewGroup.LayoutParams.MATCH_PARENT
import android.view.ViewGroup.LayoutParams.WRAP_CONTENT
import android.widget.Button
import android.widget.FrameLayout
import android.widget.LinearLayout
import android.widget.TextView
import android.widget.Toast
import androidx.activity.ComponentActivity
import androidx.activity.OnBackPressedCallback
import androidx.activity.result.contract.ActivityResultContracts
import androidx.camera.core.Camera
import androidx.camera.core.CameraSelector
import androidx.camera.core.ImageAnalysis
import androidx.camera.core.ImageProxy
import androidx.camera.core.Preview
import androidx.camera.core.resolutionselector.AspectRatioStrategy
import androidx.camera.core.resolutionselector.ResolutionSelector
import androidx.camera.core.resolutionselector.ResolutionStrategy
import androidx.camera.lifecycle.ProcessCameraProvider
import androidx.camera.view.PreviewView
import androidx.core.content.ContextCompat
import com.google.android.gms.tasks.Tasks
import com.google.mlkit.vision.common.InputImage
import com.google.mlkit.vision.text.TextRecognition
import com.google.mlkit.vision.text.korean.KoreanTextRecognizerOptions
import java.io.File
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale
import java.util.concurrent.Executors
import java.util.concurrent.atomic.AtomicReference
import kotlin.concurrent.thread
import kotlin.math.max
import kotlin.math.min

/** 인식한 번호판 한 개 (목록용) */
class PlateEntry(val plate: String, val first: Long, var last: Long, var count: Int)

/** 화면에 그릴 번호판 상자 */
class PlateBox(val rect: RectF, val text: String?, val confirmed: Boolean)

class PlateFrame(val w: Int, val h: Int, val boxes: List<PlateBox>)

/** 프레임 사이에서 같은 번호판을 이어 주고, 여러 번 읽은 결과로 다수결합니다. */
private class PlateTrack(var rect: RectF, now: Long) {
    val reads = ArrayList<String>()
    var confirmed: String? = null
    var lastSeen = now
}

/**
 * 번호판 인식: 카메라에 비친 대한민국 자동차 번호판을 찾아 사각형으로 표시하고,
 * 확정된 번호는 왼쪽 위 목록에 쌓습니다. 나갈 때 목록을 저장할지 묻습니다.
 * 글자 인식은 휴대폰 안에서만(ML Kit 한국어) 하고, 목록은 저장을 누를 때만 다운로드 폴더에 남습니다.
 */
class PlateActivity : ComponentActivity() {
    private lateinit var previewView: PreviewView
    private lateinit var overlay: PlateOverlay
    private lateinit var status: TextView
    private val exec = Executors.newSingleThreadExecutor()
    private val recognizer = TextRecognition.getClient(KoreanTextRecognizerOptions.Builder().build())
    private var camera: Camera? = null
    private var torch = false
    private val tracks = mutableListOf<PlateTrack>()
    private var frameNo = 0
    private var tileIdx = 0
    /** 확정된 번호판 목록 (UI 스레드와 분석 스레드가 함께 씀) */
    private val found = LinkedHashMap<String, PlateEntry>()

    private val askCamera = registerForActivityResult(ActivityResultContracts.RequestPermission()) { ok ->
        if (ok) startCamera() else status.text = "카메라 권한이 필요합니다"
    }

    private fun dp(v: Int) = (v * resources.displayMetrics.density).toInt()

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        val root = FrameLayout(this).apply { setBackgroundColor(Color.BLACK) }
        previewView = PreviewView(this).apply { implementationMode = PreviewView.ImplementationMode.PERFORMANCE; scaleType = PreviewView.ScaleType.FILL_CENTER }
        root.addView(previewView, FrameLayout.LayoutParams(MATCH_PARENT, MATCH_PARENT))
        overlay = PlateOverlay(this) { f -> zoomBy(f) }
        root.addView(overlay, FrameLayout.LayoutParams(MATCH_PARENT, MATCH_PARENT))

        val bottom = LinearLayout(this).apply { orientation = LinearLayout.VERTICAL; setPadding(dp(8), dp(4), dp(8), dp(8)); setBackgroundColor(Color.argb(110, 0, 0, 0)) }
        status = TextView(this).apply {
            text = "번호판을 화면에 비춰 주세요 (두 손가락으로 확대)"; setTextColor(Color.WHITE); textSize = 13f; gravity = Gravity.CENTER
        }
        bottom.addView(status)
        val bar = LinearLayout(this).apply { orientation = LinearLayout.HORIZONTAL }
        fun btn(t: String, f: (Button) -> Unit) = Button(this).apply { text = t; textSize = 12f; setOnClickListener { f(this) } }
            .also { bar.addView(it, LinearLayout.LayoutParams(0, WRAP_CONTENT, 1f)) }
        btn("목록 저장") { saveList(false) }
        btn("목록 비우기") {
            synchronized(found) { found.clear() }; overlay.list = emptyList()
        }
        btn("플래시") { b -> torch = !torch; camera?.cameraControl?.enableTorch(torch); b.text = if (torch) "플래시 끔" else "플래시" }
        bottom.addView(bar)
        root.addView(bottom, FrameLayout.LayoutParams(MATCH_PARENT, WRAP_CONTENT, Gravity.BOTTOM))
        root.setOnApplyWindowInsetsListener { _, insets ->
            @Suppress("DEPRECATION")
            bottom.setPadding(dp(8), dp(4), dp(8), insets.systemWindowInsetBottom + dp(8))
            @Suppress("DEPRECATION")
            overlay.topInset = insets.systemWindowInsetTop
            insets
        }
        setContentView(root)

        // 나갈 때 목록 저장 여부 묻기
        onBackPressedDispatcher.addCallback(this, object : OnBackPressedCallback(true) {
            override fun handleOnBackPressed() {
                val n = synchronized(found) { found.size }
                if (n == 0) { finish(); return }
                AlertDialog.Builder(this@PlateActivity)
                    .setTitle("번호판 목록 저장")
                    .setMessage("인식한 번호판 ${n}개를 저장할까요? 다운로드/SelfCheck 폴더에 CSV 파일(엑셀로 열 수 있음)로 저장됩니다.")
                    .setPositiveButton("저장") { _, _ -> saveList(true) }
                    .setNegativeButton("저장 안 함") { _, _ -> finish() }
                    .setNeutralButton("취소", null)
                    .show()
            }
        })

        if (ContextCompat.checkSelfPermission(this, Manifest.permission.CAMERA) == PackageManager.PERMISSION_GRANTED) startCamera()
        else askCamera.launch(Manifest.permission.CAMERA)
    }

    private fun startCamera() {
        val future = ProcessCameraProvider.getInstance(this)
        future.addListener({
            val provider = future.get()
            val ratio = AspectRatioStrategy.RATIO_4_3_FALLBACK_AUTO_STRATEGY
            val preview = Preview.Builder().setResolutionSelector(ResolutionSelector.Builder().setAspectRatioStrategy(ratio).build())
                .build().also { it.surfaceProvider = previewView.surfaceProvider }
            // 자동 확대: 1920×1440 고해상도로 받아 두고, 조각·번호판 부분을 원래 해상도로 잘라 읽음
            val analysis = ImageAnalysis.Builder()
                .setResolutionSelector(ResolutionSelector.Builder().setAspectRatioStrategy(ratio)
                    .setResolutionStrategy(ResolutionStrategy(Size(1920, 1440), ResolutionStrategy.FALLBACK_RULE_CLOSEST_LOWER_THEN_HIGHER)).build())
                .setBackpressureStrategy(ImageAnalysis.STRATEGY_KEEP_ONLY_LATEST)
                .setOutputImageFormat(ImageAnalysis.OUTPUT_IMAGE_FORMAT_RGBA_8888)
                .build()
            analysis.setAnalyzer(exec) { analyze(it) }
            runCatching {
                provider.unbindAll()
                camera = provider.bindToLifecycle(this, CameraSelector.DEFAULT_BACK_CAMERA, preview, analysis)
                camera?.cameraInfo?.zoomState?.observe(this) { z -> overlay.zoom = z.zoomRatio }
            }.onFailure { status.text = "카메라를 열 수 없습니다: ${it.message}" }
        }, ContextCompat.getMainExecutor(this))
    }

    private fun zoomBy(f: Float) {
        val cam = camera ?: return
        val z = cam.cameraInfo.zoomState.value ?: return
        cam.cameraControl.setZoomRatio((z.zoomRatio * f).coerceIn(z.minZoomRatio, z.maxZoomRatio))
    }

    /** 사진에서 번호판 후보 찾기: 줄 하나, 또는 위아래 두 줄(구형 2줄 번호판)을 이어 붙여 형식 검사 */
    private fun findPlates(bmp: Bitmap, ox: Float, oy: Float, scale: Float): List<Pair<RectF, String>> {
        val res = Tasks.await(recognizer.process(InputImage.fromBitmap(bmp, 0)))
        val out = ArrayList<Pair<RectF, String>>()
        fun box(r: android.graphics.Rect) = RectF(ox + r.left / scale, oy + r.top / scale, ox + r.right / scale, oy + r.bottom / scale)
        for (block in res.textBlocks) {
            val lines = block.lines.filter { it.boundingBox != null }
            for ((i, line) in lines.withIndex()) {
                PlateParser.parse(line.text)?.let { out += box(line.boundingBox!!) to it; continue }
                if (i + 1 < lines.size) {
                    val nxt = lines[i + 1]
                    PlateParser.parse(line.text + nxt.text)?.let { p ->
                        val r = RectF(box(line.boundingBox!!)); r.union(box(nxt.boundingBox!!)); out += r to p
                    }
                }
            }
            if (lines.size > 2) PlateParser.parse(block.text)?.let { p -> block.boundingBox?.let { out += box(it) to p } }
        }
        return out
    }

    private fun analyze(img: ImageProxy) {
        try {
            val raw = img.toBitmap()
            val m = android.graphics.Matrix().apply { postRotate(img.imageInfo.rotationDegrees.toFloat()) }
            val bmp = Bitmap.createBitmap(raw, 0, 0, raw.width, raw.height, m, true)
            if (bmp !== raw) raw.recycle()
            val now = System.currentTimeMillis()
            val w = bmp.width.toFloat(); val h = bmp.height.toFloat()

            val cands = ArrayList<Pair<RectF, String>>()
            if (frameNo % 2 == 0) {
                // 1) 짝수 프레임: 화면 전체를 줄여서 (가까운 번호판, 빠르게)
                val ds = min(1f, 1280f / max(w, h))
                val small = if (ds < 1f) Bitmap.createScaledBitmap(bmp, (w * ds).toInt(), (h * ds).toInt(), true) else bmp
                cands += findPlates(small, 0f, 0f, ds)
                if (small !== bmp) small.recycle()
            } else {
                // 2) 홀수 프레임: 화면을 나눈 조각 하나를 원래 해상도로 (확대한 것과 같은 효과, 먼 번호판)
                val grid = tiles(w, h, 0.5f)
                val tr = grid[tileIdx++ % grid.size]
                val tw = tr.width().toInt().coerceAtMost(bmp.width - tr.left.toInt()); val th = tr.height().toInt().coerceAtMost(bmp.height - tr.top.toInt())
                val crop = Bitmap.createBitmap(bmp, tr.left.toInt(), tr.top.toInt(), tw, th)
                cands += findPlates(crop, tr.left, tr.top, 1f)
                crop.recycle()
            }
            frameNo++
            // 3) 아직 확정 안 된 번호판은 그 부분만 잘라 크게 키워서 다시 읽음 (최대 2개)
            tracks.filter { it.confirmed == null && now - it.lastSeen < 800 }.sortedBy { it.rect.width() }.take(2).forEach { t ->
                val r = t.rect
                val ex = r.width() * 0.4f; val ey = r.height() * 0.8f
                val l = (r.left - ex).toInt().coerceIn(0, bmp.width - 2); val tp = (r.top - ey).toInt().coerceIn(0, bmp.height - 2)
                val rr = (r.right + ex).toInt().coerceIn(l + 2, bmp.width); val bb = (r.bottom + ey).toInt().coerceIn(tp + 2, bmp.height)
                val crop = Bitmap.createBitmap(bmp, l, tp, rr - l, bb - tp)
                val up = 640f / crop.width
                val big = if (up > 1.05f) Bitmap.createScaledBitmap(crop, 640, (crop.height * up).toInt().coerceAtLeast(1), true) else crop
                val sc = big.width.toFloat() / crop.width
                cands += findPlates(big, l.toFloat(), tp.toFloat(), sc)
                if (big !== crop) big.recycle(); crop.recycle()
            }
            bmp.recycle()

            // 추적 + 다수결
            for ((r, p) in cands) {
                val t = tracks.maxByOrNull { iou(it.rect, r) }?.takeIf { iou(it.rect, r) > 0.2f }
                    ?: tracks.firstOrNull { it.reads.lastOrNull() == p }
                    ?: PlateTrack(RectF(r), now).also { tracks += it }
                // 상자는 부드럽게 따라감 (흔들림 줄이기)
                t.rect.set(t.rect.left + (r.left - t.rect.left) * 0.6f, t.rect.top + (r.top - t.rect.top) * 0.6f,
                    t.rect.right + (r.right - t.rect.right) * 0.6f, t.rect.bottom + (r.bottom - t.rect.bottom) * 0.6f)
                t.reads += p; if (t.reads.size > 10) t.reads.removeAt(0)
                t.lastSeen = now
                val v = PlateParser.vote(t.reads)
                if (v != null && v != t.confirmed) {
                    t.confirmed = v
                    synchronized(found) {
                        val e = found[v]
                        if (e == null) found[v] = PlateEntry(v, now, now, 1) else { e.last = now; e.count++ }
                    }
                }
                if (t.confirmed != null) synchronized(found) { found[t.confirmed]?.last = now }
            }
            tracks.removeAll { now - it.lastSeen > 1500 }

            val boxes = tracks.filter { now - it.lastSeen < 500 }.map { t ->
                PlateBox(RectF(t.rect), t.confirmed ?: t.reads.lastOrNull(), t.confirmed != null)
            }
            overlay.post(PlateFrame(w.toInt(), h.toInt(), boxes))
            val list = synchronized(found) { found.values.sortedByDescending { it.first } }
            overlay.list = list
            runOnUiThread {
                status.text = if (boxes.isEmpty()) "번호판을 화면에 비춰 주세요 (두 손가락으로 확대)"
                    else "번호판 ${boxes.size}개 인식 중 · 목록 ${list.size}개"
            }
        } catch (e: Exception) {
            runOnUiThread { status.text = "오류: ${e.message}" }
        } finally {
            img.close()
        }
    }

    private fun iou(a: RectF, b: RectF): Float {
        val l = max(a.left, b.left); val t = max(a.top, b.top); val r = min(a.right, b.right); val bt = min(a.bottom, b.bottom)
        if (r <= l || bt <= t) return 0f
        val inter = (r - l) * (bt - t)
        return inter / (a.width() * a.height() + b.width() * b.height() - inter)
    }

    /** 목록을 CSV 로 다운로드 폴더에 저장 (엑셀에서 한글이 깨지지 않게 BOM 포함) */
    private fun saveList(thenFinish: Boolean) {
        val list = synchronized(found) { found.values.sortedBy { it.first } }
        if (list.isEmpty()) { Toast.makeText(this, "저장할 번호판이 없습니다", Toast.LENGTH_SHORT).show(); if (thenFinish) finish(); return }
        thread {
            val fmt = SimpleDateFormat("yyyy-MM-dd HH:mm:ss", Locale.KOREA)
            val csv = buildString {
                append('﻿'); append("번호판,처음 인식,마지막 인식,인식 횟수\n")
                list.forEach { append("${PlateParser.pretty(it.plate)},${fmt.format(Date(it.first))},${fmt.format(Date(it.last))},${it.count}\n") }
            }
            val name = "plates_${SimpleDateFormat("yyyyMMdd_HHmmss", Locale.KOREA).format(Date())}.csv"
            val msg = runCatching {
                if (Build.VERSION.SDK_INT >= 29) {
                    val cv = ContentValues().apply {
                        put(MediaStore.Downloads.DISPLAY_NAME, name)
                        put(MediaStore.Downloads.MIME_TYPE, "text/csv")
                        put(MediaStore.Downloads.RELATIVE_PATH, Environment.DIRECTORY_DOWNLOADS + "/SelfCheck")
                    }
                    val uri = contentResolver.insert(MediaStore.Downloads.EXTERNAL_CONTENT_URI, cv)!!
                    contentResolver.openOutputStream(uri)!!.use { it.write(csv.toByteArray()) }
                    "다운로드/SelfCheck/$name 에 ${list.size}개를 저장했습니다"
                } else {
                    val f = File(getExternalFilesDir(Environment.DIRECTORY_DOWNLOADS), name)
                    f.writeText(csv)
                    "${f.absolutePath} 에 저장했습니다"
                }
            }.getOrElse { "저장 실패: ${it.message}" }
            runOnUiThread { Toast.makeText(this, msg, Toast.LENGTH_LONG).show(); if (thenFinish) finish() }
        }
    }

    override fun onDestroy() {
        super.onDestroy()
        exec.shutdown(); recognizer.close()
    }
}

/** 번호판 상자와 왼쪽 위 목록을 그립니다. 두 손가락으로 줌. */
class PlateOverlay(ctx: Context, private val onZoom: (Float) -> Unit) : View(ctx) {
    private val latest = AtomicReference<PlateFrame?>()
    @Volatile var list: List<PlateEntry> = emptyList()
        set(v) { field = v; postInvalidate() }
    @Volatile var zoom = 1f
        set(v) { field = v; postInvalidate() }
    var topInset = 0
    private val d = resources.displayMetrics.density
    private val box = Paint(Paint.ANTI_ALIAS_FLAG).apply { style = Paint.Style.STROKE; strokeWidth = 3 * d }
    private val fill = Paint(Paint.ANTI_ALIAS_FLAG)
    private val text = Paint(Paint.ANTI_ALIAS_FLAG).apply { color = Color.WHITE; textSize = 15 * d; isFakeBoldText = true }
    private val small = Paint(Paint.ANTI_ALIAS_FLAG).apply { color = Color.rgb(200, 220, 255); textSize = 12 * d }
    private val fmt = SimpleDateFormat("HH:mm:ss", Locale.KOREA)
    private val scale = ScaleGestureDetector(ctx, object : ScaleGestureDetector.SimpleOnScaleGestureListener() {
        override fun onScale(dt: ScaleGestureDetector): Boolean { onZoom(dt.scaleFactor); return true }
    })

    fun post(f: PlateFrame) { latest.set(f); postInvalidate() }

    override fun onTouchEvent(e: MotionEvent): Boolean { scale.onTouchEvent(e); return true }

    override fun onDraw(c: Canvas) {
        val f = latest.get()
        if (f != null) {
            val m = FillCenter(width, height, f.w, f.h)
            for (b in f.boxes) {
                val r = m.rect(b.rect).apply { inset(-6 * d, -6 * d) }
                box.color = if (b.confirmed) Color.rgb(60, 230, 110) else Color.rgb(255, 200, 0)
                c.drawRoundRect(r, 6 * d, 6 * d, box)
                val label = b.text?.let { PlateParser.pretty(it) + if (b.confirmed) "" else " ?" } ?: "읽는 중"
                val tw = text.measureText(label)
                fill.color = if (b.confirmed) Color.argb(220, 20, 110, 50) else Color.argb(220, 130, 95, 0)
                c.drawRoundRect(RectF(r.left, r.top - text.textSize - 12 * d, r.left + tw + 12 * d, r.top - 2 * d), 6 * d, 6 * d, fill)
                c.drawText(label, r.left + 6 * d, r.top - 8 * d, text)
            }
        }
        // 왼쪽 위 목록
        val items = list.take(10)
        val pad = 10 * d
        val lineH = text.textSize + 6 * d
        val w = 220 * d
        val h = pad * 2 + lineH * (items.size + 1)
        val left = 10 * d; val top = topInset + 10 * d
        fill.color = Color.argb(200, 15, 18, 26)
        c.drawRoundRect(RectF(left, top, left + w, top + h), 12 * d, 12 * d, fill)
        c.drawText("인식한 번호판 ${list.size}개", left + pad, top + pad + text.textSize, text)
        items.forEachIndexed { i, e ->
            val y = top + pad + lineH * (i + 2) - 4 * d
            c.drawText(PlateParser.pretty(e.plate), left + pad, y, text)
            c.drawText(fmt.format(Date(e.first)), left + w - pad - small.measureText("00:00:00"), y, small)
        }
        if (zoom > 1.05f) {
            val z = "줌 %.1fx".format(zoom)
            fill.color = Color.argb(170, 0, 0, 0)
            c.drawRoundRect(RectF(width - 90 * d, top, width - 10 * d, top + 30 * d), 8 * d, 8 * d, fill)
            c.drawText(z, width - 82 * d, top + 21 * d, small)
        }
    }
}
