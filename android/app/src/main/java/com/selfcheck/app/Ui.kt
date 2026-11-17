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

/** 세로로 쌓는 화면(글자·막대·버튼)의 공통 부품 */
open class ColumnActivity : ComponentActivity() {
    lateinit var col: LinearLayout
    lateinit var scroll: ScrollView

    fun dp(v: Int) = (v * resources.displayMetrics.density).toInt()

    fun setupColumn(title: String, subtitle: String? = null) {
        col = LinearLayout(this).apply { orientation = LinearLayout.VERTICAL; setPadding(dp(16), dp(16), dp(16), dp(32)) }
        scroll = ScrollView(this).apply { addView(col); setBackgroundColor(Color.WHITE) }
        scroll.setOnApplyWindowInsetsListener { v, insets ->
            @Suppress("DEPRECATION")
            v.setPadding(0, insets.systemWindowInsetTop, 0, insets.systemWindowInsetBottom); insets
        }
        setContentView(scroll)
        col.addView(TextView(this).apply { text = title; textSize = 22f; setTypeface(null, Typeface.BOLD); setTextColor(Color.BLACK) })
        if (subtitle != null) col.addView(hint(subtitle))
    }

    fun section(t: String) = TextView(this).apply {
        text = t; textSize = 16f; setTypeface(null, Typeface.BOLD); setTextColor(Color.BLACK); setPadding(0, dp(18), 0, dp(4))
    }
    fun hint(t: String) = TextView(this).apply { text = t; textSize = 13f; setTextColor(Color.DKGRAY) }
    fun warn(t: String) = TextView(this).apply { text = t; textSize = 13f; setTextColor(Color.rgb(190, 90, 0)) }

    fun rowView(label: String, value: String) = LinearLayout(this).apply {
        orientation = LinearLayout.HORIZONTAL; setPadding(0, dp(3), 0, dp(3))
        addView(TextView(context).apply { text = label; textSize = 14f; setTextColor(Color.GRAY) }, LinearLayout.LayoutParams(dp(130), WRAP_CONTENT))
        addView(TextView(context).apply { text = value; textSize = 14f; setTextColor(Color.BLACK) }, LinearLayout.LayoutParams(0, WRAP_CONTENT, 1f))
    }

    /** 0~100 막대. lowIsGood=true 면 낮을수록 초록 */
    fun bar(label: String, value: Float?, text: String, lowIsGood: Boolean = true, onClick: (() -> Unit)? = null): View {
        val v = LinearLayout(this).apply { orientation = LinearLayout.VERTICAL; setPadding(0, dp(4), 0, dp(4)) }
        val top = LinearLayout(this).apply { orientation = LinearLayout.HORIZONTAL }
        top.addView(TextView(this).apply { this.text = label; textSize = 14f; setTextColor(Color.BLACK) }, LinearLayout.LayoutParams(0, WRAP_CONTENT, 1f))
        top.addView(TextView(this).apply { this.text = text; textSize = 13f; setTextColor(Color.DKGRAY) })
        v.addView(top)
        v.addView(BarView(this, value, lowIsGood), LinearLayout.LayoutParams(MATCH_PARENT, dp(8)).apply { topMargin = dp(3) })
        if (onClick != null) v.setOnClickListener { onClick() }
        return v
    }

    fun button(t: String, onClick: (Button) -> Unit) = Button(this).apply { text = t; isAllCaps = false; setOnClickListener { onClick(this) } }
    fun buttons(vararg items: Pair<String, (Button) -> Unit>) = LinearLayout(this).apply {
        orientation = LinearLayout.HORIZONTAL
        items.forEach { (t, f) -> addView(button(t, f).apply { textSize = 13f }, LinearLayout.LayoutParams(0, WRAP_CONTENT, 1f)) }
    }
    fun full(v: View, top: Int = 6) = col.addView(v, LinearLayout.LayoutParams(MATCH_PARENT, WRAP_CONTENT).apply { topMargin = dp(top) })

    fun toast(t: String) = Toast.makeText(this, t, Toast.LENGTH_SHORT).show()
    fun copy(text: String, what: String = "내용") {
        getSystemService(ClipboardManager::class.java).setPrimaryClip(ClipData.newPlainText(what, text)); toast("복사했습니다")
    }
    fun card(): LinearLayout = LinearLayout(this).apply {
        orientation = LinearLayout.VERTICAL; setPadding(dp(14), dp(12), dp(14), dp(12))
        background = GradientDrawable().apply { cornerRadius = dp(12).toFloat(); setColor(Color.rgb(244, 246, 250)) }
    }
}

/** 0~100 값 막대 */
class BarView(ctx: Context, private val value: Float?, private val lowIsGood: Boolean) : View(ctx) {
    private val bg = Paint(Paint.ANTI_ALIAS_FLAG).apply { color = Color.rgb(230, 232, 236) }
    private val fg = Paint(Paint.ANTI_ALIAS_FLAG)
    override fun onDraw(c: Canvas) {
        val r = height / 2f
        c.drawRoundRect(RectF(0f, 0f, width.toFloat(), height.toFloat()), r, r, bg)
        val v = value ?: return
        val t = (v / 100f).coerceIn(0f, 1f)
        val bad = if (lowIsGood) t else 1 - t
        fg.color = when { bad < 0.33f -> Color.rgb(40, 170, 90); bad < 0.6f -> Color.rgb(240, 170, 30); else -> Color.rgb(225, 70, 60) }
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
