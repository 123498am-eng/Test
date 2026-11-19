package com.selfcheck.app

import android.content.Context
import android.content.res.ColorStateList
import android.graphics.Canvas
import android.graphics.Color
import android.graphics.LinearGradient
import android.graphics.Paint
import android.graphics.RectF
import android.graphics.Shader
import android.graphics.Typeface
import android.graphics.drawable.GradientDrawable
import android.graphics.drawable.RippleDrawable
import android.graphics.drawable.StateListDrawable
import android.view.Gravity
import android.view.View
import android.view.ViewGroup
import android.view.ViewGroup.LayoutParams.MATCH_PARENT
import android.view.ViewGroup.LayoutParams.WRAP_CONTENT
import android.widget.Button
import android.widget.HorizontalScrollView
import android.widget.LinearLayout
import android.widget.SeekBar
import android.widget.Switch
import android.widget.TextView
import kotlin.math.max

fun Context.dip(v: Int): Int = (v * resources.displayMetrics.density + 0.5f).toInt()
fun Context.dipf(v: Float): Float = v * resources.displayMetrics.density

/** 앱 전체 색 */
object Pal {
    val bg = 0xFFF3F5FB.toInt()
    val surface = 0xFFFFFFFF.toInt()
    val surface2 = 0xFFEEF1F8.toInt()
    val outline = 0xFFE3E7F1.toInt()
    val text = 0xFF151A2D.toInt()
    val text2 = 0xFF5B6580.toInt()
    val text3 = 0xFF8A93AB.toInt()
    val primary = 0xFF4F46E5.toInt()
    val primaryDark = 0xFF3730A3.toInt()
    val primarySoft = 0xFFE8E7FD.toInt()
    val accent = 0xFF7C3AED.toInt()
    val good = 0xFF16A34A.toInt()
    val goodSoft = 0xFFDDF5E5.toInt()
    val warn = 0xFFD97706.toInt()
    val warnSoft = 0xFFFFF1DC.toInt()
    val bad = 0xFFDC2626.toInt()
    val badSoft = 0xFFFDE4E4.toInt()
    val dark = 0xFF1B1F33.toInt()
}

enum class BtnStyle { PRIMARY, SOFT, DANGER, GHOST, ON_DARK }

/** 화면을 만드는 공통 부품 (버튼·칩·카드·스위치·슬라이더·미터 등) */
object UiKit {
    fun rounded(ctx: Context, color: Int, radiusDp: Float, strokeColor: Int = 0, strokeDp: Int = 0): GradientDrawable =
        GradientDrawable().apply {
            setColor(color); cornerRadius = ctx.dipf(radiusDp)
            if (strokeDp > 0) setStroke(ctx.dip(strokeDp), strokeColor)
        }

    fun ripple(ctx: Context, content: android.graphics.drawable.Drawable, radiusDp: Float, rippleColor: Int = 0x334F46E5): RippleDrawable {
        val mask = GradientDrawable().apply { setColor(Color.WHITE); cornerRadius = ctx.dipf(radiusDp) }
        return RippleDrawable(ColorStateList.valueOf(rippleColor), content, mask)
    }

    private fun states(vararg pairs: Pair<IntArray, Int>) = ColorStateList(pairs.map { it.first }.toTypedArray(), pairs.map { it.second }.toIntArray())
    private val DISABLED = intArrayOf(-android.R.attr.state_enabled)
    private val ANY = intArrayOf()
    private val CHECKED = intArrayOf(android.R.attr.state_checked)

    // ------------------------------------------------------------ 버튼
    fun styleButton(b: Button, style: BtnStyle, radiusDp: Float = 14f, padDp: Int = 14) {
        val ctx = b.context
        val (bg, fg, rip) = when (style) {
            BtnStyle.PRIMARY -> Triple(Pal.primary, Color.WHITE, 0x33FFFFFF)
            BtnStyle.DANGER -> Triple(Pal.bad, Color.WHITE, 0x33FFFFFF)
            BtnStyle.SOFT -> Triple(Pal.primarySoft, Pal.primaryDark, 0x334F46E5)
            BtnStyle.GHOST -> Triple(Color.TRANSPARENT, Pal.primaryDark, 0x224F46E5)
            BtnStyle.ON_DARK -> Triple(0x30FFFFFF, Color.WHITE, 0x33FFFFFF)
        }
        val normal = rounded(ctx, bg, radiusDp, if (style == BtnStyle.GHOST) Pal.outline else 0, if (style == BtnStyle.GHOST) 1 else 0)
        val sl = StateListDrawable().apply {
            addState(DISABLED, rounded(ctx, if (style == BtnStyle.ON_DARK) 0x18FFFFFF else 0xFFEEF0F6.toInt(), radiusDp))
            addState(ANY, ripple(ctx, normal, radiusDp, rip))
        }
        b.background = sl
        b.setTextColor(states(DISABLED to (if (style == BtnStyle.ON_DARK) 0x66FFFFFF else 0xFF9AA3B8.toInt()), ANY to fg))
        b.isAllCaps = false
        b.typeface = Typeface.DEFAULT_BOLD
        b.stateListAnimator = null
        b.minHeight = ctx.dip(46); b.minimumHeight = ctx.dip(46); b.minWidth = 0; b.minimumWidth = 0
        b.setPadding(ctx.dip(padDp), 0, ctx.dip(padDp), 0)
    }

    fun button(ctx: Context, text: String, style: BtnStyle = BtnStyle.SOFT, textSp: Float = 14.5f, onClick: (Button) -> Unit = {}): Button =
        Button(ctx).also { b -> b.text = text; b.textSize = textSp; styleButton(b, style); b.setOnClickListener { onClick(b) } }

    // ------------------------------------------------------------ 칩 (선택 가능한 알약)
    fun chip(ctx: Context, text: String, selected: Boolean, onClick: () -> Unit): TextView =
        TextView(ctx).also { t ->
            t.text = text; t.textSize = 13.5f; t.gravity = Gravity.CENTER; t.isClickable = true
            t.setPadding(ctx.dip(14), ctx.dip(8), ctx.dip(14), ctx.dip(8)); t.setSingleLine()
            setChip(t, selected)
            t.setOnClickListener { onClick() }
        }

    fun setChip(t: TextView, selected: Boolean) {
        val ctx = t.context
        val base = if (selected) rounded(ctx, Pal.primary, 40f) else rounded(ctx, Pal.surface, 40f, Pal.outline, 1)
        t.background = ripple(ctx, base, 40f, if (selected) 0x33FFFFFF else 0x224F46E5)
        t.setTextColor(if (selected) Color.WHITE else Pal.text2)
        t.typeface = if (selected) Typeface.DEFAULT_BOLD else Typeface.DEFAULT
    }

    // ------------------------------------------------------------ 카드·글자
    fun card(ctx: Context, padDp: Int = 16, radiusDp: Float = 18f, color: Int = Pal.surface): LinearLayout =
        LinearLayout(ctx).apply {
            orientation = LinearLayout.VERTICAL
            setPadding(ctx.dip(padDp), ctx.dip(padDp), ctx.dip(padDp), ctx.dip(padDp))
            background = rounded(ctx, color, radiusDp, Pal.outline, 1)
            elevation = ctx.dipf(1.5f)
        }

    fun text(ctx: Context, s: String, sp: Float, color: Int = Pal.text, bold: Boolean = false): TextView =
        TextView(ctx).apply {
            text = s; textSize = sp; setTextColor(color); if (bold) typeface = Typeface.DEFAULT_BOLD
            breakStrategy = android.text.Layout.BREAK_STRATEGY_BALANCED // 줄바꿈을 고르게 (한 글자만 덩그러니 남지 않게)
        }

    /** 한글 낱말 안에서 줄이 바뀌지 않게 (자세한 설명은 [keepKoreanWords]) */
    fun keepWords(s: String): String = keepKoreanWords(s)

    fun sectionTitle(ctx: Context, title: String, sub: String? = null): LinearLayout =
        LinearLayout(ctx).apply {
            orientation = LinearLayout.VERTICAL
            setPadding(ctx.dip(4), ctx.dip(22), ctx.dip(4), ctx.dip(8))
            addView(text(ctx, title, 17f, Pal.text, true))
            if (sub != null) addView(text(ctx, sub, 12.5f, Pal.text3).apply { setPadding(0, ctx.dip(2), 0, 0) })
        }

    /** 동그란 배경 위 이모지 아이콘 */
    fun badge(ctx: Context, emoji: String, sizeDp: Int, bg: Int, sp: Float = 20f): TextView =
        TextView(ctx).apply {
            text = emoji; textSize = sp; gravity = Gravity.CENTER
            background = GradientDrawable().apply { shape = GradientDrawable.OVAL; setColor(bg) }
            layoutParams = LinearLayout.LayoutParams(ctx.dip(sizeDp), ctx.dip(sizeDp))
        }

    // ------------------------------------------------------------ 스위치 행
    class SwitchRow(val view: LinearLayout, val sw: Switch, val title: TextView, val desc: TextView)

    fun styleSwitch(s: Switch) {
        s.thumbTintList = states(CHECKED to Color.WHITE, ANY to 0xFFF4F5F9.toInt())
        s.trackTintList = states(CHECKED to Pal.primary, ANY to 0xFFC9D0E2.toInt())
        s.showText = false
    }

    fun switchRow(ctx: Context, emoji: String, title: String, desc: String, checked: Boolean, onChange: (Boolean) -> Unit): SwitchRow {
        val row = LinearLayout(ctx).apply { orientation = LinearLayout.HORIZONTAL; gravity = Gravity.CENTER_VERTICAL; setPadding(0, ctx.dip(6), 0, ctx.dip(6)) }
        row.addView(badge(ctx, emoji, 40, Pal.primarySoft, 19f))
        val col = LinearLayout(ctx).apply { orientation = LinearLayout.VERTICAL; setPadding(ctx.dip(12), 0, ctx.dip(8), 0) }
        val t = text(ctx, title, 15.5f, Pal.text, true); val d = text(ctx, desc, 12.5f, Pal.text2)
        col.addView(t); col.addView(d)
        row.addView(col, LinearLayout.LayoutParams(0, WRAP_CONTENT, 1f))
        val sw = Switch(ctx).apply { isChecked = checked; styleSwitch(this) }
        sw.setOnCheckedChangeListener { _, c -> onChange(c) }
        row.addView(sw)
        row.setOnClickListener { if (sw.isEnabled) sw.toggle() }
        return SwitchRow(row, sw, t, d)
    }

    // ------------------------------------------------------------ 슬라이더 행
    class SliderRow(val view: LinearLayout, val bar: SeekBar, val value: TextView)

    fun styleSeek(s: SeekBar) {
        s.progressTintList = ColorStateList.valueOf(Pal.primary)
        s.thumbTintList = ColorStateList.valueOf(Pal.primary)
        s.progressBackgroundTintList = ColorStateList.valueOf(0xFFD9DEEC.toInt())
    }

    fun sliderRow(ctx: Context, label: String, max: Int, init: Int, fmt: (Int) -> String, onChange: (Int) -> Unit): SliderRow {
        val box = LinearLayout(ctx).apply { orientation = LinearLayout.VERTICAL; setPadding(0, ctx.dip(4), 0, ctx.dip(2)) }
        val top = LinearLayout(ctx).apply { orientation = LinearLayout.HORIZONTAL; gravity = Gravity.CENTER_VERTICAL }
        top.addView(text(ctx, label, 14f, Pal.text, true), LinearLayout.LayoutParams(0, WRAP_CONTENT, 1f))
        val v = text(ctx, fmt(init), 12.5f, Pal.primaryDark, true).apply {
            setPadding(ctx.dip(10), ctx.dip(3), ctx.dip(10), ctx.dip(3)); background = rounded(ctx, Pal.primarySoft, 20f)
        }
        top.addView(v)
        box.addView(top)
        val sb = SeekBar(ctx).apply {
            this.max = max; progress = init; styleSeek(this)
            setOnSeekBarChangeListener(object : SeekBar.OnSeekBarChangeListener {
                override fun onProgressChanged(sb: SeekBar, p: Int, u: Boolean) { v.text = fmt(p); onChange(p) }
                override fun onStartTrackingTouch(sb: SeekBar) {}
                override fun onStopTrackingTouch(sb: SeekBar) {}
            })
        }
        box.addView(sb, LinearLayout.LayoutParams(MATCH_PARENT, ctx.dip(36)))
        return SliderRow(box, sb, v)
    }

    // ------------------------------------------------------------ 상단 바
    fun topBar(ctx: Context, title: String, onBack: () -> Unit, right: View? = null): LinearLayout =
        LinearLayout(ctx).apply {
            orientation = LinearLayout.HORIZONTAL; gravity = Gravity.CENTER_VERTICAL
            setPadding(ctx.dip(12), ctx.dip(8), ctx.dip(16), ctx.dip(6))
            val back = TextView(ctx).apply {
                text = "‹"; textSize = 28f; gravity = Gravity.CENTER; setTextColor(Pal.text); includeFontPadding = false
                background = ripple(ctx, rounded(ctx, Pal.surface, 22f, Pal.outline, 1), 22f)
                setOnClickListener { onBack() }; isClickable = true
                contentDescription = "뒤로"
            }
            addView(back, LinearLayout.LayoutParams(ctx.dip(44), ctx.dip(44)))
            addView(TextView(ctx).apply { text = title; textSize = 19f; setTextColor(Pal.text); typeface = Typeface.DEFAULT_BOLD; setSingleLine(); ellipsize = android.text.TextUtils.TruncateAt.END; setPadding(ctx.dip(12), 0, 0, 0) },
                LinearLayout.LayoutParams(0, WRAP_CONTENT, 1f))
            if (right != null) addView(right)
        }

    /** 아이콘 + 제목 + 설명 + 화살표 한 줄 카드 (눌러서 이동) */
    fun listCard(ctx: Context, emoji: String, title: String, desc: String, tint: Int = Pal.primarySoft, onClick: () -> Unit): LinearLayout =
        LinearLayout(ctx).apply {
            orientation = LinearLayout.HORIZONTAL; gravity = Gravity.CENTER_VERTICAL; isClickable = true
            setPadding(ctx.dip(12), ctx.dip(12), ctx.dip(14), ctx.dip(12))
            background = ripple(ctx, rounded(ctx, Pal.surface, 16f, Pal.outline, 1), 16f)
            addView(badge(ctx, emoji, 44, tint, 20f))
            addView(LinearLayout(ctx).apply {
                orientation = LinearLayout.VERTICAL; setPadding(ctx.dip(12), 0, ctx.dip(8), 0)
                addView(text(ctx, keepWords(title), 15.5f, Pal.text, true))
                addView(text(ctx, keepWords(desc), 12.5f, Pal.text2).apply { setLineSpacing(0f, 1.1f); setPadding(0, ctx.dip(2), 0, 0) })
            }, LinearLayout.LayoutParams(0, WRAP_CONTENT, 1f))
            addView(TextView(ctx).apply { text = "›"; textSize = 24f; setTextColor(Pal.text3) })
            setOnClickListener { onClick() }
        }

    /** 가로로 밀어서 보는 칩 줄 */
    fun chipRow(ctx: Context, chips: List<TextView>): HorizontalScrollView =
        HorizontalScrollView(ctx).apply {
            isHorizontalScrollBarEnabled = false
            addView(LinearLayout(ctx).apply {
                orientation = LinearLayout.HORIZONTAL
                setPadding(ctx.dip(2), ctx.dip(2), ctx.dip(2), ctx.dip(2))
                chips.forEachIndexed { i, c -> addView(c, LinearLayout.LayoutParams(WRAP_CONTENT, WRAP_CONTENT).apply { rightMargin = ctx.dip(8); if (i == 0) leftMargin = 0 }) }
            })
        }

    fun gradient(ctx: Context, radiusDp: Float, from: Int = Pal.primary, to: Int = Pal.accent): GradientDrawable =
        GradientDrawable(GradientDrawable.Orientation.TL_BR, intArrayOf(from, to)).apply { cornerRadius = ctx.dipf(radiusDp) }

    fun params(w: Int = MATCH_PARENT, h: Int = WRAP_CONTENT, top: Int = 0, bottom: Int = 0, start: Int = 0, end: Int = 0, ctx: Context? = null, weight: Float = 0f): LinearLayout.LayoutParams {
        val d = ctx?.resources?.displayMetrics?.density ?: 1f
        return LinearLayout.LayoutParams(w, h, weight).apply { setMargins((start * d).toInt(), (top * d).toInt(), (end * d).toInt(), (bottom * d).toInt()) }
    }
}

/** 소리 크기 막대 (최고점이 잠깐 남았다가 내려감) */
class MeterView(ctx: Context, private val onDark: Boolean = false) : View(ctx) {
    private val track = Paint(Paint.ANTI_ALIAS_FLAG).apply { color = if (onDark) 0x33FFFFFF else 0xFFE3E8F4.toInt() }
    private val fill = Paint(Paint.ANTI_ALIAS_FLAG)
    private val peakP = Paint(Paint.ANTI_ALIAS_FLAG).apply { color = if (onDark) 0xFFFFFFFF.toInt() else Pal.text2; strokeWidth = ctx.dipf(2f) }
    private var peak = 0f
    var level = 0f
        set(v) { field = v.coerceIn(0f, 1f); if (field > peak) peak = field; invalidate() }

    override fun onSizeChanged(w: Int, h: Int, ow: Int, oh: Int) {
        fill.shader = LinearGradient(0f, 0f, max(1, w).toFloat(), 0f, intArrayOf(0xFF22C55E.toInt(), 0xFF84CC16.toInt(), 0xFFF59E0B.toInt(), 0xFFEF4444.toInt()), floatArrayOf(0f, 0.55f, 0.8f, 1f), Shader.TileMode.CLAMP)
    }

    override fun onDraw(c: Canvas) {
        val w = width.toFloat(); val h = height.toFloat(); val r = h / 2
        c.drawRoundRect(RectF(0f, 0f, w, h), r, r, track)
        if (level > 0.005f) c.drawRoundRect(RectF(0f, 0f, max(h, w * level), h), r, r, fill)
        if (peak > 0.02f) { val x = (w * peak).coerceIn(r, w - 1f); c.drawLine(x, h * 0.15f, x, h * 0.85f, peakP) }
        peak = max(level, peak - 0.012f)
    }
}

/**
 * 한글 낱말 한가운데서 줄이 바뀌지 않게 해서 "여\n성" 처럼 한 글자만 다음 줄로 넘어가는 모양을 막습니다
 * (글자 사이에 폭 없는 U+2060 을 끼워 공백에서만 줄을 바꿈, " · " 앞은 붙여서 점이 줄 맨 앞에 서지 않게).
 * 화면에 고정으로 쓰는 짧은 문구용이며, 복사해 가는 결과 글에는 쓰지 않습니다.
 */
internal fun keepKoreanWords(s: String): String {
    val sb = StringBuilder(s.length * 2)
    for (i in s.indices) {
        sb.append(s[i])
        if (i + 1 < s.length && s[i] in '\uAC00'..'\uD7A3' && s[i + 1] in '\uAC00'..'\uD7A3') sb.append('\u2060')
    }
    return sb.toString()
        .replace(" · ", "\u00A0· ")                                   // 띄어 쓴 점: 앞 낱말에 붙임
        .replace(Regex("(?<=[^\\s\u00A0\u2060])\u00B7"), "\u2060\u00B7") // 붙여 쓴 점(A·B·C): 점 뒤에서만 줄바꿈
}
