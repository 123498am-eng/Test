package com.selfcheck.app

import android.content.Intent
import android.os.Bundle

/** 편집 메뉴: 표정 따라하기 / 배경 제거 / 크로마키 */
class EditActivity : ColumnActivity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setupColumn("편집", "사진·동영상을 고르고 원하는 편집을 선택하세요")
        fun item(emoji: String, tint: Int, title: String, desc: String, target: Class<*>) {
            col.addView(UiKit.listCard(this, emoji, title, desc, tint) { startActivity(Intent(this, target)) }, UiKit.params(top = 10, ctx = this))
        }
        item("🎭", 0xFFFCE7F3.toInt(), "표정 따라하기 (사진·동영상)",
            "사진이나 동영상을 고르고 '편집'을 누르면 카메라가 켜져요. 사진 속 인물이 내 표정과 고개 움직임을 실시간으로 따라 하고, 녹화할 수 있어요.", ReenactActivity::class.java)
        item("✂️", 0xFFE0F2FE.toInt(), "배경 제거 (사진·동영상)",
            "남길 물체를 사각형으로 감싸고 '편집'을 누르면 나머지 배경이 지워져요. 배경은 투명·흰색·검정·초록·흐리게 중에서 고를 수 있어요.", BgRemoveActivity::class.java)
        item("🟩", 0xFFDCFCE7.toInt(), "크로마키 (그린·블루 스크린)",
            "초록이나 파란 배경에서 찍은 사진·동영상의 배경색을 지우고 투명·흰색·검정·다른 사진으로 바꿔요. 허용 범위·부드러움·색 번짐 제거를 조절해요.", ChromaKeyActivity::class.java)
        col.addView(tip("표정 따라하기는 본인 또는 동의받은 사람의 사진만 쓰세요. 결과물에는 'AI 편집' 표시가 들어가요.", warn = true))
    }
}
