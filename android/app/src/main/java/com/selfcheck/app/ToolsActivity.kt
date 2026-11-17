package com.selfcheck.app

import android.content.Intent
import android.graphics.Color
import android.graphics.Typeface
import android.os.Bundle
import android.text.Editable
import android.text.TextWatcher
import android.view.ViewGroup.LayoutParams.MATCH_PARENT
import android.view.ViewGroup.LayoutParams.WRAP_CONTENT
import android.widget.EditText
import android.widget.LinearLayout
import android.widget.TextView

/** 모든 도구를 종류별로 모아 둔 화면 (검색 가능) */
class ToolsActivity : ColumnActivity() {
    private class Entry(val group: String, val title: String, val desc: String, val open: () -> Intent)
    private lateinit var list: LinearLayout
    private val entries = ArrayList<Entry>()

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        fun photo(group: String, vararg ids: String) = ids.forEach { id ->
            val t = PhotoTools.byId(id) ?: return@forEach
            entries += Entry(group, t.title, t.desc) { Intent(this, PhotoToolActivity::class.java).putExtra("tool", id) }
        }
        entries += Entry("정밀 얼굴 분석", "정밀 얼굴 스캔", "주름(부위별·잔주름)·모공·잡티·홍조·번들거림·다크서클·톤·피부결·대칭·비율·얼굴형·치수·표정 52가지") { Intent(this, FaceScanActivity::class.java) }
        entries += Entry("정밀 얼굴 분석", "3D 얼굴 (실시간 카메라)", "카메라로 얼굴 3D 모델 만들기") { Intent(this, LiveActivity::class.java) }
        photo("얼굴 보정", "skin_smooth", "spot_remove", "teeth", "eye_big", "face_slim", "lip", "symmetry")
        photo("인물·증명사진", "portrait", "id_photo")
        photo("개인정보 보호", "mosaic", "plate_blur", "exif")
        entries += Entry("개인정보 보호", "개인정보 가리기 (글)", "주민번호·전화·카드·계좌·주소를 찾아 가림") { Intent(this, UtilityActivity::class.java).putExtra("tool", "privacy") }
        photo("사진 편집", "resize", "rotate", "contrast", "denoise", "sharpen", "hdr")
        photo("필터·효과", "bw", "sepia", "vintage", "color", "vignette", "sketch", "cartoon", "watercolor", "pixel", "watermark")
        photo("문서·글자·색", "doc_scan", "ocr", "palette")
        for (t in LiveTools.ALL) entries += Entry("실시간 카메라", t.title, t.desc) { Intent(this, LiveToolActivity::class.java).putExtra("tool", t.id) }
        for ((id, title, desc) in UtilityActivity.TOOLS) if (id != "privacy") entries += Entry("보안·생활", title, desc) { Intent(this, UtilityActivity::class.java).putExtra("tool", id) }
        for ((id, title, desc) in SensorActivity.TOOLS) entries += Entry("센서", title, desc) { Intent(this, SensorActivity::class.java).putExtra("tool", id) }

        setupColumn("도구 모음", "도구 ${entries.size}가지 · 사진·얼굴 분석은 모두 휴대폰 안에서 처리합니다")
        val search = EditText(this).apply { hint = "도구 찾기 (예: 주름, 모자이크, QR)"; setSingleLine() }
        full(search)
        list = LinearLayout(this).apply { orientation = LinearLayout.VERTICAL }
        col.addView(list)
        search.addTextChangedListener(object : TextWatcher {
            override fun afterTextChanged(s: Editable?) { show(s?.toString()?.trim() ?: "") }
            override fun beforeTextChanged(s: CharSequence?, a: Int, b: Int, c: Int) {}
            override fun onTextChanged(s: CharSequence?, a: Int, b: Int, c: Int) {}
        })
        show("")
    }

    private fun show(q: String) {
        list.removeAllViews()
        val shown = entries.filter { q.isEmpty() || it.title.contains(q, true) || it.desc.contains(q, true) || it.group.contains(q, true) }
        if (shown.isEmpty()) { list.addView(hint("찾는 도구가 없습니다")); return }
        for ((g, items) in shown.groupBy { it.group }) {
            list.addView(section("$g (${items.size})"))
            for (e in items) {
                val c = card()
                c.addView(TextView(this).apply { text = e.title; textSize = 16f; setTypeface(null, Typeface.BOLD); setTextColor(Color.BLACK) })
                c.addView(TextView(this).apply { text = e.desc; textSize = 13f; setTextColor(Color.DKGRAY) })
                c.setOnClickListener { startActivity(e.open()) }
                list.addView(c, LinearLayout.LayoutParams(MATCH_PARENT, WRAP_CONTENT).apply { topMargin = dp(6) })
            }
        }
    }
}
