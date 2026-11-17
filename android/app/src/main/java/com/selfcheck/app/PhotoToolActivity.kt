package com.selfcheck.app

import android.annotation.SuppressLint
import android.graphics.Bitmap
import android.net.Uri
import android.os.Bundle
import android.view.MotionEvent
import android.view.View
import android.view.ViewGroup.LayoutParams.MATCH_PARENT
import android.view.ViewGroup.LayoutParams.WRAP_CONTENT
import android.widget.EditText
import android.widget.HorizontalScrollView
import android.widget.LinearLayout
import android.widget.RadioButton
import android.widget.RadioGroup
import android.widget.SeekBar
import android.widget.TextView
import androidx.exifinterface.media.ExifInterface
import java.util.Locale
import kotlin.concurrent.thread

/** 사진 도구 하나: 사진 고르기 → (항목·세기 조절) → 미리보기 → 저장·공유. 결과에 이어서 다른 도구도 쓸 수 있습니다. */
class PhotoToolActivity : ColumnActivity() {
    private lateinit var tool: PhotoTool
    private val input = ImageInput(this) { uri -> load(uri) }
    private var src: Bitmap? = null
    private var srcUri: Uri? = null
    private var out: ToolOut? = null
    private var option = 0
    private var value = 50
    private var faceDone = false
    private var faceCache: FloatArray? = null
    private var facesCache: List<FloatArray>? = null
    @Volatile private var busy = false
    @Volatile private var again = false
    private lateinit var view: ZoomImageView
    private lateinit var status: TextView
    private lateinit var info: TextView
    private lateinit var copyBtn: View
    private lateinit var controls: LinearLayout
    private var textBox: EditText? = null

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        tool = PhotoTools.byId(intent.getStringExtra("tool") ?: "") ?: run { finish(); return }
        setupColumn(tool.title, tool.desc)
        col.addView(buttons("사진 고르기" to { _ -> input.pickPhoto() }, "카메라로 찍기" to { _ -> input.takePhoto() }))
        view = ZoomImageView(this)
        col.addView(view, LinearLayout.LayoutParams(MATCH_PARENT, resources.displayMetrics.widthPixels).apply { topMargin = dp(8) })
        status = hint("사진을 고르세요")
        col.addView(status)
        controls = LinearLayout(this).apply { orientation = LinearLayout.VERTICAL }
        col.addView(controls)
        buildControls()
        info = TextView(this).apply { textSize = 14f; setTextColor(android.graphics.Color.BLACK); setTextIsSelectable(true); setPadding(0, dp(8), 0, dp(4)) }
        col.addView(info)
        copyBtn = button("글 복사") { copy(out?.text ?: "", tool.title) }.also { it.visibility = View.GONE }
        full(copyBtn, 0)
        col.addView(buttons("저장" to { _ -> save() }, "보내기" to { _ -> share() }))
        full(button("이 결과에 이어서 다른 도구 쓰기") { chain() }, 2)
    }

    @SuppressLint("ClickableViewAccessibility")
    private fun buildControls() {
        controls.removeAllViews()
        option = 0; value = tool.paramDefault
        // 누르고 있는 동안 원본 보기
        val hold = button("누르고 있으면 원본") { }
        hold.setOnTouchListener { _, e ->
            when (e.actionMasked) {
                MotionEvent.ACTION_DOWN -> src?.let { view.setImage(it, keepView = true) }
                MotionEvent.ACTION_UP, MotionEvent.ACTION_CANCEL -> (out?.bitmap ?: src)?.let { view.setImage(it, keepView = true) }
            }
            false
        }
        controls.addView(hold, LinearLayout.LayoutParams(MATCH_PARENT, WRAP_CONTENT))
        if (tool.options.isNotEmpty()) {
            val rg = RadioGroup(this).apply { orientation = RadioGroup.HORIZONTAL }
            tool.options.forEachIndexed { i, name -> rg.addView(RadioButton(this).apply { id = 1000 + i; text = name; isChecked = i == 0 }) }
            rg.setOnCheckedChangeListener { _, id -> option = id - 1000; run() }
            controls.addView(HorizontalScrollView(this).apply { addView(rg) })
        }
        if (tool.param != null) {
            val label = hint("${tool.param}: $value")
            controls.addView(label)
            controls.addView(SeekBar(this).apply {
                max = 100; progress = value
                setOnSeekBarChangeListener(object : SeekBar.OnSeekBarChangeListener {
                    override fun onProgressChanged(sb: SeekBar, p: Int, u: Boolean) { value = p; label.text = "${tool.param}: $p" }
                    override fun onStartTrackingTouch(sb: SeekBar) {}
                    override fun onStopTrackingTouch(sb: SeekBar) { run() }
                })
            })
        }
        if (tool.textHint != null) {
            val et = EditText(this).apply { hint = tool.textHint; setSingleLine() }
            textBox = et
            controls.addView(et)
            controls.addView(button("글자 적용") { run() })
        } else textBox = null
    }

    private fun load(uri: Uri) {
        srcUri = uri
        status.text = "사진 여는 중..."
        thread {
            val b = runCatching { FaceMatcher.decodeUri(contentResolver, uri, 3000) }.getOrNull()
            runOnUiThread {
                if (b == null) { status.text = "사진을 열 수 없습니다"; return@runOnUiThread }
                src = b; out = null; faceDone = false; faceCache = null; facesCache = null
                view.setImage(b); run()
            }
        }
    }

    private fun exifSummary(): String {
        val u = srcUri ?: return "(카메라·갤러리 원본 정보 없음)"
        val ex = runCatching { contentResolver.openInputStream(u)?.use { ExifInterface(it) } }.getOrNull() ?: return "(읽을 수 있는 정보 없음)"
        val lines = ArrayList<String>()
        ex.latLong?.let { lines += String.format(Locale.US, "• 위치(GPS): %.5f, %.5f ⚠", it[0], it[1]) }
        listOf(ExifInterface.TAG_MAKE to "제조사", ExifInterface.TAG_MODEL to "기종", ExifInterface.TAG_DATETIME_ORIGINAL to "촬영 일시",
            ExifInterface.TAG_SOFTWARE to "프로그램", ExifInterface.TAG_LENS_MODEL to "렌즈", ExifInterface.TAG_ARTIST to "작성자")
            .forEach { (tag, name) -> ex.getAttribute(tag)?.takeIf { it.isNotBlank() }?.let { lines += "• $name: $it" } }
        return if (lines.isEmpty()) "(숨은 정보 없음 — 사진 선택기가 이미 지웠을 수 있습니다)" else lines.joinToString("\n")
    }

    private fun run() {
        val b = src ?: return
        if (busy) { again = true; return }
        busy = true
        status.text = "처리 중..."
        val ctx = ToolCtx(this, b, option, value, textBox?.text?.toString() ?: "",
            face = { if (!faceDone) { faceCache = Faces.largest(this, b); faceDone = true }; faceCache },
            faces = { facesCache ?: Faces.all(this, b).also { facesCache = it } },
            exifInfo = { exifSummary() })
        val t0 = System.currentTimeMillis()
        thread {
            val r = runCatching { tool.run(ctx) }
            runOnUiThread {
                busy = false
                r.onSuccess { o ->
                    out = o
                    o.bitmap?.let { view.setImage(it, keepView = true) }
                    info.text = o.text ?: ""
                    copyBtn.visibility = if (o.text != null && tool.id == "ocr" || tool.id == "palette") View.VISIBLE else View.GONE
                    status.text = "완료 (${(System.currentTimeMillis() - t0) / 100 / 10.0}초) · ${o.bitmap?.width ?: 0}×${o.bitmap?.height ?: 0}"
                }.onFailure { status.text = "실패: ${it.message}" }
                if (again) { again = false; run() }
            }
        }
    }

    private fun save() {
        val o = out ?: run { toast("먼저 사진을 고르세요"); return }
        val b = o.bitmap ?: return
        thread {
            val msg = runCatching {
                val name = "${tool.id}_${System.currentTimeMillis()}"
                if (o.jpeg > 0) MediaSave.saveJpeg(this, b, "$name.jpg", o.jpeg) else MediaSave.savePng(this, b, "$name.png")
            }.fold({ "$it 에 저장했습니다" }, { "저장 실패: ${it.message}" })
            runOnUiThread { toast(msg) }
        }
    }

    private fun share() {
        val b = out?.bitmap ?: run { toast("먼저 사진을 고르세요"); return }
        runCatching { MediaSave.share(this, b, out?.text) }.onFailure { toast("보낼 수 없습니다: ${it.message}") }
    }

    private fun chain() {
        val b = out?.bitmap ?: run { toast("먼저 결과를 만드세요"); return }
        val names = PhotoTools.ALL.map { it.title }.toTypedArray()
        android.app.AlertDialog.Builder(this).setTitle("이어서 쓸 도구").setItems(names) { _, i ->
            tool = PhotoTools.ALL[i]
            src = b; out = null; faceDone = false; faceCache = null; facesCache = null; srcUri = null
            (col.getChildAt(0) as TextView).text = tool.title
            (col.getChildAt(1) as TextView).text = tool.desc
            buildControls(); info.text = ""; run()
        }.show()
    }
}
