package com.selfcheck.app

import android.content.Intent
import android.graphics.Color
import android.net.Uri
import android.os.Bundle
import android.widget.EditText
import android.widget.LinearLayout
import android.widget.TextView
import kotlin.concurrent.thread

/** 번호판 조회: 번호판에서 알 수 있는 정보(차량 종류·용도·형식)와 공식 조회 서비스 바로가기. 소유자 조회는 하지 않습니다. */
class PlateLookupActivity : ColumnActivity() {
    private lateinit var input: EditText
    private lateinit var out: LinearLayout
    private val photo = ImageInput(this) { uri -> readPhoto(uri) }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setupColumn("번호판 조회", "번호판 글자로 알 수 있는 정보를 풀어 주고, 공식 조회 서비스로 연결합니다. 모든 해석은 휴대폰 안에서 합니다.")
        input = EditText(this).apply { hint = "번호판 입력 (예: 12가 3456, 서울 12가 3456)"; setSingleLine(); setText(intent.getStringExtra("plate")?.let { PlateParser.pretty(it) } ?: "") }
        full(input)
        col.addView(buttons("조회" to { _ -> lookup(input.text.toString()) }, "사진에서 읽기" to { _ -> photo.pickPhoto() }, "카메라로 찍기" to { _ -> photo.takePhoto() }))
        out = LinearLayout(this).apply { orientation = LinearLayout.VERTICAL }
        col.addView(out)
        val c = card()
        c.addView(TextView(this).apply { text = PlateLinks.OWNER_NOTE; textSize = 13f; setTextColor(Color.rgb(150, 70, 0)) })
        full(c, 14)
        if (input.text.isNotBlank()) lookup(input.text.toString())
    }

    private fun readPhoto(uri: Uri) {
        out.removeAllViews(); out.addView(hint("사진에서 번호판 찾는 중..."))
        thread {
            val plates = runCatching {
                val b = FaceMatcher.decodeUri(contentResolver, uri, 3000)
                PhotoTools.textBlocks(this, b).mapNotNull { PlateParser.parse(it.first) }.distinct()
            }
            runOnUiThread {
                out.removeAllViews()
                val list = plates.getOrNull()
                when {
                    plates.isFailure -> out.addView(warn("읽기 실패: ${plates.exceptionOrNull()?.message}"))
                    list.isNullOrEmpty() -> out.addView(warn("번호판을 찾지 못했습니다. 번호판이 크고 또렷하게 나온 사진을 쓰거나 직접 입력하세요."))
                    list.size == 1 -> { input.setText(PlateParser.pretty(list[0])); lookup(list[0]) }
                    else -> {
                        out.addView(hint("번호판 ${list.size}개를 찾았습니다. 조회할 번호판을 누르세요."))
                        list.forEach { p -> out.addView(button(PlateParser.pretty(p)) { input.setText(PlateParser.pretty(p)); lookup(p) }) }
                    }
                }
            }
        }
    }

    private fun lookup(raw: String) {
        out.removeAllViews()
        val plate = PlateParser.parse(raw)
        val info = plate?.let { PlateInfoDecoder.decode(it) }
        if (info == null) { out.addView(warn("번호판 형식이 아닙니다. 예: 12가 3456, 123가 4567, 서울 12가 3456")); return }
        val c = card()
        c.addView(TextView(this).apply { text = PlateParser.pretty(info.plate); textSize = 30f; setTextColor(Color.BLACK); setTypeface(null, android.graphics.Typeface.BOLD) })
        for ((k, v) in listOf("차량 종류" to info.kind, "용도" to info.usage, "형식" to info.format)) c.addView(rowView(k, v))
        if (!info.valid) c.addView(warn("⚠ 형식이 이상합니다"))
        info.notes.forEach { c.addView(hint("• $it")) }
        out.addView(c, LinearLayout.LayoutParams(-1, -2).apply { topMargin = dp(10) })
        out.addView(section("공식 조회 서비스 (본인 차량·정당한 용도)"))
        for (l in PlateLinks.ALL) {
            val cc = card()
            cc.addView(TextView(this).apply { text = l.title; textSize = 15f; setTextColor(Color.BLACK); setTypeface(null, android.graphics.Typeface.BOLD) })
            cc.addView(hint(l.desc))
            cc.setOnClickListener { runCatching { startActivity(Intent(Intent.ACTION_VIEW, Uri.parse(l.url))) } }
            out.addView(cc, LinearLayout.LayoutParams(-1, -2).apply { topMargin = dp(6) })
        }
        out.addView(button("번호판 복사") { copy(PlateParser.pretty(info.plate), "번호판") })
    }
}
