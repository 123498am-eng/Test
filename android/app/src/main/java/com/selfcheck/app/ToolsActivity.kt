package com.selfcheck.app

import android.content.Context
import android.content.Intent
import android.graphics.Color
import android.graphics.Typeface
import android.os.Bundle
import android.text.Editable
import android.text.TextWatcher
import android.view.Gravity
import android.view.ViewGroup.LayoutParams.MATCH_PARENT
import android.view.ViewGroup.LayoutParams.WRAP_CONTENT
import android.widget.EditText
import android.widget.LinearLayout
import android.widget.TextView

/** 모든 도구를 종류별로 모아 둔 화면 (검색 가능) */
class ToolsActivity : ColumnActivity() {
    internal class Entry(val group: String, val title: String, val desc: String, val open: () -> Intent)
    private lateinit var list: LinearLayout
    private val entries = ArrayList<Entry>()

    companion object {
        /** 도구 모음에 나오는 모든 도구 (홈 화면의 도구 수 문구도 이 목록에서 셉니다) */
        internal fun buildEntries(ctx: Context): List<Entry> {
            val entries = ArrayList<Entry>()
            fun photo(group: String, vararg ids: String) = ids.forEach { id ->
                val t = PhotoTools.byId(id) ?: return@forEach
                entries += Entry(group, t.title, t.desc) { Intent(ctx, PhotoToolActivity::class.java).putExtra("tool", id) }
            }
            entries += Entry("정밀 얼굴 분석", "정밀 얼굴 스캔", "주름(부위별·잔주름)·모공·잡티·홍조·번들거림·다크서클·톤·피부결·대칭·비율·얼굴형·치수·표정 52가지") { Intent(ctx, FaceScanActivity::class.java) }
            entries += Entry("정밀 얼굴 분석", "얼굴 비교", "두 사진 속 사람이 얼마나 닮았는지 %와 같은 사람인지 판정 (기준 사진 여러 장 가능, 카메라로 찍기)") { Intent(ctx, FaceCompareActivity::class.java) }
            entries += Entry("정밀 얼굴 분석", "3D 얼굴 (실시간 카메라)", "카메라로 얼굴 3D 모델 만들기") { Intent(ctx, LiveActivity::class.java) }
            entries += Entry("음성", "실시간 음성 변조", "여성·귀여운 소녀 4가지·뉴스 아나운서 여성/남성 5가지씩 등 60가지 목소리·효과 (음높이와 목소리 굵기를 따로 바꿔 자연스럽게), 녹음·공유") { Intent(ctx, VoiceChangerActivity::class.java) }
            photo("얼굴 보정", "skin_smooth", "spot_remove", "teeth", "eye_big", "face_slim", "lip", "symmetry")
            photo("인물·증명사진", "portrait", "id_photo")
            photo("개인정보 보호", "mosaic", "plate_blur", "exif")
            entries += Entry("개인정보 보호", "개인정보 가리기 (글)", "주민번호·전화·카드·계좌·주소를 찾아 가림") { Intent(ctx, UtilityActivity::class.java).putExtra("tool", "privacy") }
            photo("사진 편집", "resize", "rotate", "contrast", "denoise", "sharpen", "hdr")
            photo("필터·효과", "bw", "sepia", "vintage", "color", "vignette", "sketch", "cartoon", "watercolor", "pixel", "watermark")
            photo("문서·글자·색", "doc_scan", "ocr", "palette")
            entries += Entry("문서·글자·색", "번호판 조회", "번호판 글자로 차량 종류·용도 풀이 + 공식 조회 서비스 연결 (소유자 조회 없음)") { Intent(ctx, PlateLookupActivity::class.java) }
            for (t in LiveTools.ALL) entries += Entry("실시간 카메라", t.title, t.desc) { Intent(ctx, LiveToolActivity::class.java).putExtra("tool", t.id) }
            for ((id, title, desc) in UtilityActivity.TOOLS) if (id != "privacy") entries += Entry("보안·생활", title, desc) { Intent(ctx, UtilityActivity::class.java).putExtra("tool", id) }
            for ((id, title, desc) in NetworkActivity.TOOLS) entries += Entry("네트워크", title, desc) { Intent(ctx, NetworkActivity::class.java).putExtra("tool", id) }
            for (t in NetToolbox.ALL) entries += Entry(t.group, t.title, t.desc) { Intent(ctx, NetToolActivity::class.java).putExtra("tool", t.id) }
            for ((id, title, desc) in SensorActivity.TOOLS) entries += Entry("센서", title, desc) { Intent(ctx, SensorActivity::class.java).putExtra("tool", id) }

            return entries
        }

        /** "240여 가지" 처럼 10 단위로 내린 도구 수 문구 */
        fun countLabel(ctx: Context): String = "${buildEntries(ctx).size / 10 * 10}여 가지"
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        entries += buildEntries(this)

        setupColumn("도구 모음", "도구 ${entries.size}가지 · 사진·얼굴 분석은 모두 휴대폰 안에서 처리해요")
        val search = EditText(this).apply { hint = "도구 찾기 (예: 주름, 모자이크, QR)"; setSingleLine() }
        styleInput(search)
        col.addView(search, UiKit.params(top = 4, ctx = this))
        val groups = entries.map { it.group }.distinct()
        chipBox = LinearLayout(this).apply { orientation = LinearLayout.VERTICAL }
        col.addView(chipBox, UiKit.params(top = 10, ctx = this))
        list = LinearLayout(this).apply { orientation = LinearLayout.VERTICAL }
        col.addView(list)
        fun chips() {
            chipBox.removeAllViews()
            val all = listOf("전체") + groups
            chipBox.addView(UiKit.chipRow(this, all.map { g -> UiKit.chip(this, if (g == "전체") "전체 ${entries.size}" else "$g ${entries.count { it.group == g }}", (g == "전체" && picked == null) || g == picked) {
                picked = if (g == "전체") null else g; chips(); show(search.text.toString().trim())
            } }))
        }
        chipsRefresh = { chips() }
        searchBox = search
        chips()
        search.addTextChangedListener(object : TextWatcher {
            override fun afterTextChanged(s: Editable?) { show(s?.toString()?.trim() ?: "") }
            override fun beforeTextChanged(s: CharSequence?, a: Int, b: Int, c: Int) {}
            override fun onTextChanged(s: CharSequence?, a: Int, b: Int, c: Int) {}
        })
        show("")
    }

    private var picked: String? = null
    private var chipsRefresh: (() -> Unit)? = null
    private var searchBox: EditText? = null
    private fun searchText() = searchBox?.text?.toString()?.trim() ?: ""
    private lateinit var chipBox: LinearLayout

    private fun iconOf(group: String) = mapOf(
        "정밀 얼굴 분석" to "🧖", "음성" to "🎙️", "얼굴 보정" to "💄", "인물·증명사진" to "🆔", "개인정보 보호" to "🛡️", "사진 편집" to "🖼️",
        "필터·효과" to "🎨", "문서·글자·색" to "📄", "실시간 카메라" to "📷", "보안·생활" to "🔐", "네트워크" to "🌐", "센서" to "📡",
        NetGroups.IP to "🧮", NetGroups.CONVERT to "🔁", NetGroups.HASH to "🔑", NetGroups.DNS to "🧭", NetGroups.DIAG to "🩺", NetGroups.LAN to "🏠",
        NetGroups.SPEED to "🚀", NetGroups.WIFI to "📶", NetGroups.GEN to "🛠️", NetGroups.REF to "📚", NetGroups.CMD to "💻",
        NetGroups.GEO to "📍", NetGroups.SERVER to "🖥️", NetGroups.WEB to "🕸️", NetGroups.MAIL to "✉️", NetGroups.SEC to "🔒", NetGroups.LOG to "📜", NetGroups.PACKET to "📦", NetGroups.MAKE to "🔧",
    )[group] ?: "🧰"

    private fun show(q: String) {
        list.removeAllViews()
        val shown = entries.filter { (picked == null || it.group == picked) && (q.isEmpty() || it.title.contains(q, true) || it.desc.contains(q, true) || it.group.contains(q, true)) }
        if (shown.isEmpty()) { list.addView(hint("찾는 도구가 없어요").apply { setPadding(dp(4), dp(16), 0, 0) }); return }
        val preview = picked == null && q.isEmpty()
        for ((g, items) in shown.groupBy { it.group }) {
            list.addView(UiKit.sectionTitle(this, g, "${items.size}가지"))
            val vis = if (preview && items.size > 4) items.take(3) else items
            for (e in vis) list.addView(UiKit.listCard(this, iconOf(e.group), e.title, e.desc) { startActivity(e.open()) }, UiKit.params(bottom = 8, ctx = this))
            if (vis.size < items.size) list.addView(button("${g} ${items.size}가지 모두 보기") { picked = g; chipsRefresh?.invoke(); show(searchText()) }, UiKit.params(bottom = 8, ctx = this))
        }
    }
}
