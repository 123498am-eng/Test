package com.selfcheck.app

import android.content.Intent
import android.graphics.Color
import android.os.Bundle
import android.view.ViewGroup.LayoutParams.MATCH_PARENT
import android.view.ViewGroup.LayoutParams.WRAP_CONTENT
import android.widget.Button
import android.widget.LinearLayout
import android.widget.TextView
import androidx.activity.ComponentActivity

/** 편집 메뉴: 표정 따라하기 / 배경 제거 */
class EditActivity : ComponentActivity() {
    private fun dp(v: Int) = (v * resources.displayMetrics.density).toInt()

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        val col = LinearLayout(this).apply { orientation = LinearLayout.VERTICAL; setPadding(dp(16), dp(16), dp(16), dp(16)); setBackgroundColor(Color.WHITE) }
        col.setOnApplyWindowInsetsListener { v, insets ->
            @Suppress("DEPRECATION")
            v.setPadding(dp(16), insets.systemWindowInsetTop + dp(16), dp(16), insets.systemWindowInsetBottom + dp(16)); insets
        }
        col.addView(TextView(this).apply { text = "편집"; textSize = 24f; setTextColor(Color.BLACK) })
        fun item(title: String, desc: String, target: Class<*>) {
            col.addView(Button(this).apply {
                text = title; textSize = 16f
                setOnClickListener { startActivity(Intent(this@EditActivity, target)) }
            }, LinearLayout.LayoutParams(MATCH_PARENT, WRAP_CONTENT).apply { topMargin = dp(16) })
            col.addView(TextView(this).apply { text = desc; textSize = 13f; setTextColor(Color.DKGRAY); setPadding(dp(4), dp(4), dp(4), 0) })
        }
        item("표정 따라하기 (사진·동영상)",
            "사진이나 동영상을 고르고 '편집'을 누르면 카메라가 켜집니다. 사진 속 인물이 내 표정과 고개 움직임을 실시간으로 따라 하고, 녹화할 수 있습니다. 본인 또는 동의받은 사람의 사진만 쓰세요.",
            ReenactActivity::class.java)
        item("배경 제거 (사진·동영상)",
            "사진이나 동영상을 고르고 남길 물체를 사각형으로 감싼 뒤 '편집'을 누르면 나머지 배경이 지워집니다. 배경은 투명·흰색·검정·초록·흐리게 중에서 고를 수 있습니다.",
            BgRemoveActivity::class.java)
        setContentView(col)
    }
}
