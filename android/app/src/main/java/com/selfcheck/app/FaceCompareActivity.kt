package com.selfcheck.app

import android.graphics.Bitmap
import android.graphics.Canvas
import android.graphics.Color
import android.graphics.Paint
import android.graphics.Typeface
import android.net.Uri
import android.os.Bundle
import android.view.Gravity
import android.view.View
import android.view.ViewGroup.LayoutParams.MATCH_PARENT
import android.view.ViewGroup.LayoutParams.WRAP_CONTENT
import android.widget.HorizontalScrollView
import android.widget.ImageView
import android.widget.LinearLayout
import android.widget.TextView
import androidx.activity.result.PickVisualMediaRequest
import androidx.activity.result.contract.ActivityResultContracts
import kotlin.concurrent.thread
import kotlin.math.max

/**
 * 얼굴 비교: 기준 사진(여러 장 가능) 속 사람과, 카메라로 찍거나 첨부한 사진 속 사람이
 * 얼마나 닮았는지(%)와 같은 사람인지 판정합니다. 모든 비교는 휴대폰 안에서만 합니다 (YuNet + SFace).
 */
class FaceCompareActivity : ColumnActivity() {
    private class Photo(val bmp: Bitmap, val faces: List<FaceHit>, var sel: Int = 0) { val face get() = faces.getOrNull(sel) }

    private val refs = ArrayList<Photo>()
    private var probe: Photo? = null
    /** 화면 아래 "사진 보기"에 띄운 사진 (얼굴 고르기용) */
    private var active: Photo? = null
    @Volatile private var matcher: FaceMatcher? = null
    private val lock = Object()

    private lateinit var refRow: LinearLayout
    private lateinit var probeRow: LinearLayout
    private lateinit var status: TextView
    private lateinit var result: LinearLayout
    private lateinit var viewer: ZoomImageView
    private lateinit var viewerHint: TextView

    private val pickRefs = registerForActivityResult(ActivityResultContracts.PickMultipleVisualMedia(5)) { uris -> if (uris.isNotEmpty()) load(uris, true) }
    private val camRef = ImageInput(this) { uri -> load(listOf(uri), true) }
    private val probeIn = ImageInput(this) { uri -> load(listOf(uri), false) }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setupColumn("얼굴 비교", "사진 속 사람과 찍은(또는 첨부한) 사진 속 사람이 얼마나 닮았는지 %로 보여 주고, 같은 사람인지 판정합니다. 비교는 휴대폰 안에서만 합니다.")
        col.addView(hint("다른 사람의 사진은 본인 동의를 받고 쓰세요. 결과는 추정이며 틀릴 수 있으니 중요한 판단(신분 확인 등)에 쓰지 마세요."))

        col.addView(section("1. 기준 사진 (이 사람)"))
        col.addView(hint("같은 사람 사진을 여러 장(최대 5장) 넣으면 더 정확합니다."))
        col.addView(buttons("사진 올리기" to { _ -> pickRefs.launch(PickVisualMediaRequest(ActivityResultContracts.PickVisualMedia.ImageOnly)) },
            "카메라로 찍기" to { _ -> camRef.takePhoto() }, "비우기" to { _ -> refs.clear(); refreshRows(); compare() }))
        refRow = LinearLayout(this).apply { orientation = LinearLayout.HORIZONTAL }
        col.addView(HorizontalScrollView(this).apply { addView(refRow) })

        col.addView(section("2. 비교할 사진"))
        col.addView(buttons("카메라로 찍기" to { _ -> probeIn.takePhoto() }, "사진 첨부" to { _ -> probeIn.pickPhoto() }))
        probeRow = LinearLayout(this).apply { orientation = LinearLayout.HORIZONTAL }
        col.addView(probeRow)

        status = hint("")
        col.addView(status)
        result = LinearLayout(this).apply { orientation = LinearLayout.VERTICAL }
        col.addView(result)

        col.addView(section("사진 보기 · 얼굴 고르기"))
        viewerHint = hint("사진에 얼굴이 여러 명이면 비교할 얼굴을 누르세요 (초록 상자 = 선택한 얼굴). 위의 작은 얼굴을 누르면 그 사진이 여기 나옵니다.")
        col.addView(viewerHint)
        viewer = ZoomImageView(this)
        viewer.onTap = { x, y -> pickFace(x, y) }
        col.addView(viewer, LinearLayout.LayoutParams(MATCH_PARENT, resources.displayMetrics.widthPixels).apply { topMargin = dp(6) })
        refreshRows()
    }

    private fun matcher(): FaceMatcher = synchronized(lock) {
        matcher ?: FaceMatcher(this) { s -> runOnUiThread { status.text = s } }.also { matcher = it }
    }

    private fun load(uris: List<Uri>, isRef: Boolean) {
        status.text = "얼굴 찾는 중..."
        thread {
            val got = ArrayList<Photo>(); var noFace = 0; var err: String? = null
            for (u in uris) {
                runCatching {
                    val b = FaceMatcher.decodeUri(contentResolver, u, 1600)
                    val fs = matcher().faces(b)
                    if (fs.isEmpty()) noFace++ else got += Photo(b, fs)
                }.onFailure { err = it.message }
            }
            runOnUiThread {
                if (isRef) { refs += got; while (refs.size > 5) refs.removeAt(0) } else got.lastOrNull()?.let { probe = it }
                got.lastOrNull()?.let { show(it) }
                status.text = listOfNotNull(
                    if (noFace > 0) "사진 ${noFace}장에서 얼굴을 찾지 못했습니다 (얼굴이 잘 보이는 사진을 쓰세요)" else null,
                    err?.let { "오류: $it" },
                    got.firstOrNull { it.faces.size > 1 }?.let { "얼굴이 ${it.faces.size}명입니다. 아래 사진에서 비교할 얼굴을 누르세요" },
                ).joinToString("\n")
                refreshRows(); compare()
            }
        }
    }

    private fun faceThumb(p: Photo, label: String): View {
        val box = LinearLayout(this).apply { orientation = LinearLayout.VERTICAL; gravity = Gravity.CENTER_HORIZONTAL; setPadding(dp(4), dp(4), dp(4), dp(4)) }
        box.addView(ImageView(this).apply {
            setImageBitmap(p.face?.crop); scaleType = ImageView.ScaleType.CENTER_CROP
            setBackgroundColor(if (p === active) Color.rgb(40, 180, 90) else Color.LTGRAY); setPadding(dp(3), dp(3), dp(3), dp(3))
        }, LinearLayout.LayoutParams(dp(84), dp(84)))
        box.addView(TextView(this).apply { text = label + if (p.faces.size > 1) " (${p.sel + 1}/${p.faces.size})" else ""; textSize = 12f; setTextColor(Color.DKGRAY) })
        box.setOnClickListener { show(p) }
        return box
    }

    private fun refreshRows() {
        refRow.removeAllViews()
        if (refs.isEmpty()) refRow.addView(hint("아직 없음"))
        refs.forEachIndexed { i, p -> refRow.addView(faceThumb(p, "기준 ${i + 1}")) }
        probeRow.removeAllViews()
        probe?.let { probeRow.addView(faceThumb(it, "비교할 얼굴")) } ?: probeRow.addView(hint("아직 없음"))
    }

    /** 사진에 얼굴 상자와 번호를 그려 "사진 보기"에 띄움 */
    private fun show(p: Photo) {
        active = p
        val out = p.bmp.copy(Bitmap.Config.ARGB_8888, true)
        val c = Canvas(out)
        val k = max(out.width, out.height) / 700f
        val txt = Paint(Paint.ANTI_ALIAS_FLAG).apply { textSize = 22f * k; typeface = Typeface.DEFAULT_BOLD }
        p.faces.forEachIndexed { i, f ->
            val col = if (i == p.sel) Color.rgb(40, 220, 90) else Color.WHITE
            c.drawRect(f.box, Paint(Paint.ANTI_ALIAS_FLAG).apply { style = Paint.Style.STROKE; strokeWidth = 3f * k; color = col })
            txt.color = col; txt.setShadowLayer(4f * k, 0f, 0f, Color.BLACK)
            c.drawText("${i + 1}", f.box.left, f.box.top - 6 * k, txt)
        }
        viewer.setImage(out)
        refreshRows()
    }

    private fun pickFace(x: Float, y: Float) {
        val p = active ?: return
        if (p.faces.size < 2) return
        val i = p.faces.indexOfFirst { it.box.contains(x, y) }.takeIf { it >= 0 }
            ?: p.faces.indices.minByOrNull { val b = p.faces[it].box; val dx = b.centerX() - x; val dy = b.centerY() - y; dx * dx + dy * dy } ?: return
        p.sel = i; show(p); compare()
    }

    private fun compare() {
        result.removeAllViews()
        val pf = probe?.face
        val rf = refs.mapNotNull { it.face }
        if (pf == null || rf.isEmpty()) {
            if (refs.isNotEmpty() || probe != null) result.addView(hint(if (pf == null) "비교할 사진을 찍거나 첨부하세요" else "기준 사진을 올리세요"))
            return
        }
        val cos = FaceSimilarity.cosine(FaceSimilarity.template(rf.map { it.feat }), pf.feat)
        val pct = FaceSimilarity.percent(cos)
        val (level, verdict) = FaceSimilarity.verdict(cos)
        val each = rf.map { FaceSimilarity.cosine(it.feat, pf.feat) }
        val color = when (level) { 3 -> Color.rgb(20, 140, 60); 2 -> Color.rgb(60, 140, 40); 1 -> Color.rgb(200, 120, 0); else -> Color.rgb(200, 40, 40) }

        val card = card()
        val faces = LinearLayout(this).apply { orientation = LinearLayout.HORIZONTAL; gravity = Gravity.CENTER }
        val best = rf[each.indices.maxByOrNull { each[it] } ?: 0]
        fun img(b: Bitmap) = ImageView(this).apply { setImageBitmap(b); scaleType = ImageView.ScaleType.CENTER_CROP }
        faces.addView(img(best.crop), LinearLayout.LayoutParams(dp(110), dp(110)))
        faces.addView(TextView(this).apply { text = "VS"; textSize = 18f; setTypeface(null, Typeface.BOLD); setTextColor(Color.GRAY); setPadding(dp(14), 0, dp(14), 0) })
        faces.addView(img(pf.crop), LinearLayout.LayoutParams(dp(110), dp(110)))
        card.addView(faces)
        card.addView(TextView(this).apply { text = "닮은 정도 $pct%"; textSize = 30f; setTypeface(null, Typeface.BOLD); setTextColor(Color.BLACK); gravity = Gravity.CENTER; setPadding(0, dp(10), 0, 0) },
            LinearLayout.LayoutParams(MATCH_PARENT, WRAP_CONTENT))
        card.addView(BarView(this, pct.toFloat(), lowIsGood = false), LinearLayout.LayoutParams(MATCH_PARENT, dp(10)).apply { topMargin = dp(4); bottomMargin = dp(8) })
        card.addView(TextView(this).apply { text = verdict; textSize = 19f; setTypeface(null, Typeface.BOLD); setTextColor(color); gravity = Gravity.CENTER },
            LinearLayout.LayoutParams(MATCH_PARENT, WRAP_CONTENT))
        card.addView(hint("얼굴 인식 점수 %.3f · 같은 사람 기준 %.3f (= 닮은 정도 %d%%)".format(cos, FaceSimilarity.THRESHOLD, FaceSimilarity.SAME_PERCENT)).apply { gravity = Gravity.CENTER },
            LinearLayout.LayoutParams(MATCH_PARENT, WRAP_CONTENT))
        if (rf.size > 1) card.addView(hint("기준 사진별: " + each.mapIndexed { i, v -> "${i + 1}번 ${FaceSimilarity.percent(v)}%" }.joinToString(" · ") + "\n(여러 장을 합쳐서 판정했습니다)"))
        val warns = (rf.flatMapIndexed { i, f -> f.warnings.map { "기준 ${i + 1}: $it" } } + pf.warnings.map { "비교할 사진: $it" })
        warns.forEach { card.addView(warn("⚠ $it")) }
        if (warns.isNotEmpty() && level <= 1) card.addView(hint("사진 상태가 좋지 않으면 같은 사람도 점수가 낮게 나올 수 있습니다. 밝은 곳에서 정면으로, 얼굴이 크게 나오게 다시 찍어 보세요."))
        card.addView(hint("쌍둥이·형제자매나 아주 닮은 사람은 틀릴 수 있습니다. 오래된 사진, 큰 각도·조명 차이, 마스크·선글라스는 점수를 낮춥니다."))
        result.addView(card, LinearLayout.LayoutParams(MATCH_PARENT, WRAP_CONTENT).apply { topMargin = dp(10) })
        result.addView(buttons("결과 복사" to { _ ->
            copy("얼굴 비교: 닮은 정도 $pct% — $verdict (점수 %.3f, 기준 %.3f)".format(cos, FaceSimilarity.THRESHOLD), "얼굴 비교 결과")
        }, "결과 사진 저장" to { _ -> saveResult(best.crop, pf.crop, pct, verdict, color) }))
        scroll.post { scroll.smoothScrollTo(0, result.top) }
    }

    private fun saveResult(a: Bitmap, b: Bitmap, pct: Int, verdict: String, color: Int) {
        val w = 720; val h = 520
        val out = Bitmap.createBitmap(w, h, Bitmap.Config.ARGB_8888)
        val c = Canvas(out); c.drawColor(Color.WHITE)
        val src = android.graphics.Rect(0, 0, a.width, a.height)
        c.drawBitmap(a, src, android.graphics.Rect(60, 40, 320, 300), Paint(Paint.FILTER_BITMAP_FLAG))
        c.drawBitmap(b, android.graphics.Rect(0, 0, b.width, b.height), android.graphics.Rect(400, 40, 660, 300), Paint(Paint.FILTER_BITMAP_FLAG))
        val p = Paint(Paint.ANTI_ALIAS_FLAG).apply { textAlign = Paint.Align.CENTER; typeface = Typeface.DEFAULT_BOLD }
        p.textSize = 34f; p.color = Color.GRAY; c.drawText("VS", w / 2f, 185f, p)
        p.textSize = 52f; p.color = Color.BLACK; c.drawText("닮은 정도 $pct%", w / 2f, 385f, p)
        p.textSize = 30f; p.color = color; c.drawText(verdict.substringBefore(" ("), w / 2f, 440f, p)
        p.textSize = 20f; p.color = Color.GRAY; p.typeface = Typeface.DEFAULT; c.drawText("셀프 점검 · 얼굴 인식 추정치 (틀릴 수 있음)", w / 2f, 495f, p)
        thread {
            val msg = runCatching { MediaSave.savePng(this, out, "face_compare_${System.currentTimeMillis()}.png") + " 에 저장했습니다" }.getOrElse { "저장 실패: ${it.message}" }
            runOnUiThread { toast(msg) }
        }
    }
}
