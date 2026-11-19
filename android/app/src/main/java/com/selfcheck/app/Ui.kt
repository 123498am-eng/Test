package com.selfcheck.app

import android.content.ClipData
import android.content.ClipboardManager
import android.content.Context
import android.graphics.Bitmap
import android.graphics.Canvas
import android.graphics.Color
import android.graphics.Matrix
import android.graphics.Paint
import android.graphics.RectF
import android.graphics.Typeface
import android.graphics.drawable.GradientDrawable
import android.view.GestureDetector
import android.view.Gravity
import android.view.MotionEvent
import android.view.ScaleGestureDetector
import android.view.View
import android.view.ViewGroup.LayoutParams.MATCH_PARENT
import android.view.ViewGroup.LayoutParams.WRAP_CONTENT
import android.widget.Button
import android.widget.FrameLayout
import android.widget.LinearLayout
import android.widget.ScrollView
import android.widget.TextView
import android.widget.Toast
import androidx.activity.ComponentActivity
import kotlin.math.max
import kotlin.math.min

/** 세로로 쌓는 화면(글자·막대·버튼)의 공통 부품. 위쪽 고정 바(뒤로 가기 + 제목) 아래에 내용이 스크롤됩니다. */
open class ColumnActivity : ComponentActivity() {
    lateinit var col: LinearLayout
    lateinit var scroll: ScrollView
    lateinit var titleView: TextView
    var subtitleView: TextView? = null

    fun dp(v: Int) = dip(v)

    fun setupColumn(title: String, subtitle: String? = null) {
        val root = LinearLayout(this).apply { orientation = LinearLayout.VERTICAL; setBackgroundColor(Pal.bg) }
        val bar = UiKit.topBar(this, title, { finish() })
        titleView = bar.getChildAt(1) as TextView
        root.addView(bar, LinearLayout.LayoutParams(MATCH_PARENT, WRAP_CONTENT))
        col = LinearLayout(this).apply { orientation = LinearLayout.VERTICAL; setPadding(dp(16), dp(4), dp(16), dp(32)) }
        scroll = ScrollView(this).apply { addView(col); setBackgroundColor(Pal.bg); isVerticalScrollBarEnabled = false; clipToPadding = false }
        root.addView(scroll, LinearLayout.LayoutParams(MATCH_PARENT, 0, 1f))
        root.setOnApplyWindowInsetsListener { v, insets ->
            @Suppress("DEPRECATION")
            v.setPadding(0, insets.systemWindowInsetTop, 0, insets.systemWindowInsetBottom); insets
        }
        setContentView(root)
        if (subtitle != null) subtitleView = hint(subtitle).also { it.setPadding(dp(4), dp(2), dp(4), dp(8)); col.addView(it) }
    }

    fun section(t: String): View = UiKit.sectionTitle(this, t)
    fun hint(t: String) = TextView(this).apply {
        text = t; textSize = 13f; setTextColor(Pal.text2); setLineSpacing(0f, 1.1f)
        breakStrategy = android.text.Layout.BREAK_STRATEGY_BALANCED
    }

    /** 눈에 띄는 안내 상자 (warn=true 면 주황색 주의 상자) */
    fun tip(t: String, warn: Boolean = false): View = TextView(this).apply {
        text = t; textSize = 13f; setLineSpacing(0f, 1.15f); setPadding(dp(14), dp(12), dp(14), dp(12))
        setTextColor(if (warn) 0xFF8A4B0B.toInt() else Pal.primaryDark)
        background = UiKit.rounded(this@ColumnActivity, if (warn) Pal.warnSoft else Pal.primarySoft, 16f)
        breakStrategy = android.text.Layout.BREAK_STRATEGY_BALANCED
        layoutParams = LinearLayout.LayoutParams(MATCH_PARENT, WRAP_CONTENT).apply { topMargin = dp(10) }
    }
    fun warn(t: String) = TextView(this).apply {
        text = t; textSize = 13f; setTextColor(Pal.warn); setPadding(dp(12), dp(8), dp(12), dp(8))
        background = UiKit.rounded(this@ColumnActivity, Pal.warnSoft, 12f)
        layoutParams = LinearLayout.LayoutParams(MATCH_PARENT, WRAP_CONTENT).apply { topMargin = dp(6) }
    }

    fun rowView(label: String, value: String) = LinearLayout(this).apply {
        orientation = LinearLayout.HORIZONTAL; setPadding(0, dp(5), 0, dp(5))
        addView(TextView(context).apply { text = label; textSize = 13.5f; setTextColor(Pal.text2) }, LinearLayout.LayoutParams(dp(130), WRAP_CONTENT))
        addView(TextView(context).apply { text = value; textSize = 14.5f; setTextColor(Pal.text) }, LinearLayout.LayoutParams(0, WRAP_CONTENT, 1f))
    }

    /** 0~100 막대. lowIsGood=true 면 낮을수록 초록 */
    fun bar(label: String, value: Float?, text: String, lowIsGood: Boolean = true, onClick: (() -> Unit)? = null): View {
        val v = LinearLayout(this).apply { orientation = LinearLayout.VERTICAL; setPadding(0, dp(6), 0, dp(6)) }
        val top = LinearLayout(this).apply { orientation = LinearLayout.HORIZONTAL }
        top.addView(TextView(this).apply { this.text = label; textSize = 14.5f; setTextColor(Pal.text) }, LinearLayout.LayoutParams(0, WRAP_CONTENT, 1f))
        top.addView(TextView(this).apply { this.text = text; textSize = 13f; setTextColor(Pal.text2) })
        v.addView(top)
        v.addView(BarView(this, value, lowIsGood), LinearLayout.LayoutParams(MATCH_PARENT, dp(8)).apply { topMargin = dp(5) })
        if (onClick != null) v.setOnClickListener { onClick() }
        return v
    }

    fun button(t: String, onClick: (Button) -> Unit) = UiKit.button(this, t, BtnStyle.SOFT, 14.5f, onClick)
    fun primaryButton(t: String, onClick: (Button) -> Unit) = UiKit.button(this, t, BtnStyle.PRIMARY, 15f, onClick)
    fun buttons(vararg items: Pair<String, (Button) -> Unit>) = LinearLayout(this).apply {
        orientation = LinearLayout.HORIZONTAL
        items.forEachIndexed { i, (t, f) ->
            addView(button(t, f).apply { textSize = 13.5f }, LinearLayout.LayoutParams(0, WRAP_CONTENT, 1f).apply { if (i > 0) leftMargin = dp(8) })
        }
    }
    fun full(v: View, top: Int = 8) = col.addView(v, LinearLayout.LayoutParams(MATCH_PARENT, WRAP_CONTENT).apply { topMargin = dp(top) })

    fun toast(t: String) = Toast.makeText(this, t, Toast.LENGTH_SHORT).show()
    fun copy(text: String, what: String = "내용") {
        getSystemService(ClipboardManager::class.java).setPrimaryClip(ClipData.newPlainText(what, text)); toast("복사했습니다")
    }
    fun card(): LinearLayout = UiKit.card(this)

    /** 둥근 입력창 */
    fun styleInput(e: android.widget.EditText) {
        e.background = UiKit.rounded(this, Pal.surface, 14f, Pal.outline, 1)
        e.setPadding(dp(14), dp(12), dp(14), dp(12)); e.textSize = 15f; e.setTextColor(Pal.text); e.setHintTextColor(Pal.text3)
    }
}

/** 0~100 값 막대 */
class BarView(ctx: Context, private val value: Float?, private val lowIsGood: Boolean) : View(ctx) {
    private val bg = Paint(Paint.ANTI_ALIAS_FLAG).apply { color = 0xFFE3E8F4.toInt() }
    private val fg = Paint(Paint.ANTI_ALIAS_FLAG)
    override fun onDraw(c: Canvas) {
        val r = height / 2f
        c.drawRoundRect(RectF(0f, 0f, width.toFloat(), height.toFloat()), r, r, bg)
        val v = value ?: return
        val t = (v / 100f).coerceIn(0f, 1f)
        val bad = if (lowIsGood) t else 1 - t
        fg.color = when { bad < 0.33f -> 0xFF22C55E.toInt(); bad < 0.6f -> 0xFFF59E0B.toInt(); else -> 0xFFEF4444.toInt() }
        c.drawRoundRect(RectF(0f, 0f, max(height.toFloat(), width * t), height.toFloat()), r, r, fg)
    }
}

/** 두 손가락으로 확대·이동, 두 번 누르면 원래대로 */
class ZoomImageView(ctx: Context) : View(ctx) {
    private var bmp: Bitmap? = null
    private val m = Matrix()
    private var scale = 1f; private var tx = 0f; private var ty = 0f
    private val paint = Paint(Paint.FILTER_BITMAP_FLAG)
    var onTap: ((Float, Float) -> Unit)? = null

    init {
        background = GradientDrawable().apply { setColor(0xFF111426.toInt()); cornerRadius = ctx.dipf(18f) }
        outlineProvider = android.view.ViewOutlineProvider.BACKGROUND; clipToOutline = true
    }

    fun setImage(b: Bitmap?, keepView: Boolean = false) { bmp = b; if (!keepView) { scale = 1f; tx = 0f; ty = 0f }; invalidate() }

    private fun base(): Pair<Float, Float> {
        val b = bmp ?: return 1f to 0f
        val s = min(width / b.width.toFloat(), height / b.height.toFloat())
        return s to 0f
    }

    override fun onDraw(c: Canvas) {
        val b = bmp ?: return
        val (s0, _) = base()
        val s = s0 * scale
        val ox = (width - b.width * s) / 2 + tx; val oy = (height - b.height * s) / 2 + ty
        m.reset(); m.postScale(s, s); m.postTranslate(ox, oy)
        c.drawBitmap(b, m, paint)
    }

    private val sg = ScaleGestureDetector(ctx, object : ScaleGestureDetector.SimpleOnScaleGestureListener() {
        override fun onScale(d: ScaleGestureDetector): Boolean {
            val ns = (scale * d.scaleFactor).coerceIn(1f, 10f); val f = ns / scale
            tx = (tx - (d.focusX - width / 2f)) * f + (d.focusX - width / 2f)
            ty = (ty - (d.focusY - height / 2f)) * f + (d.focusY - height / 2f)
            scale = ns; invalidate(); return true
        }
    })
    private val gd = GestureDetector(ctx, object : GestureDetector.SimpleOnGestureListener() {
        override fun onScroll(e1: MotionEvent?, e2: MotionEvent, dx: Float, dy: Float): Boolean { tx -= dx; ty -= dy; invalidate(); return true }
        override fun onDoubleTap(e: MotionEvent): Boolean { scale = if (scale > 1.5f) 1f else 3f; if (scale == 1f) { tx = 0f; ty = 0f }; invalidate(); return true }
        override fun onSingleTapConfirmed(e: MotionEvent): Boolean {
            val b = bmp ?: return false
            val s = base().first * scale
            val ox = (width - b.width * s) / 2 + tx; val oy = (height - b.height * s) / 2 + ty
            onTap?.invoke((e.x - ox) / s, (e.y - oy) / s); return true
        }
    })

    override fun onTouchEvent(e: MotionEvent): Boolean {
        parent?.requestDisallowInterceptTouchEvent(scale > 1f || e.pointerCount > 1)
        sg.onTouchEvent(e); gd.onTouchEvent(e); return true
    }
}

/** 화면 위에 띄우는 진행 표시 */
fun progressOverlay(ctx: Context, text: String): Pair<FrameLayout, TextView> {
    val f = FrameLayout(ctx).apply { setBackgroundColor(Color.argb(150, 0, 0, 0)); isClickable = true }
    val t = TextView(ctx).apply { this.text = text; setTextColor(Color.WHITE); textSize = 16f; gravity = Gravity.CENTER }
    f.addView(t, FrameLayout.LayoutParams(MATCH_PARENT, MATCH_PARENT))
    return f to t
}
