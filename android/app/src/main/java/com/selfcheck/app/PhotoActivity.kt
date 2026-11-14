package com.selfcheck.app

import android.content.Intent
import android.graphics.Bitmap
import android.graphics.BitmapFactory
import android.graphics.Canvas
import android.graphics.Color
import android.graphics.Paint
import android.graphics.Typeface
import android.net.Uri
import android.os.Bundle
import android.view.ViewGroup.LayoutParams.MATCH_PARENT
import android.view.ViewGroup.LayoutParams.WRAP_CONTENT
import android.widget.Button
import android.widget.ImageView
import android.widget.LinearLayout
import android.widget.ScrollView
import android.widget.TextView
import androidx.activity.ComponentActivity
import androidx.exifinterface.media.ExifInterface
import java.io.File
import java.util.Locale
import kotlin.concurrent.thread
import kotlin.math.abs
import kotlin.math.roundToInt

/** 등록한 사진 한 장의 정보(EXIF, 얼굴 분석)를 보여 줍니다. */
class PhotoActivity : ComponentActivity() {
    private lateinit var root: LinearLayout
    private lateinit var image: ImageView
    private lateinit var faceBox: LinearLayout
    private lateinit var file: File

    private fun dp(v: Int) = (v * resources.displayMetrics.density).toInt()

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        file = File(intent.getStringExtra("path") ?: run { finish(); return })

        root = LinearLayout(this).apply { orientation = LinearLayout.VERTICAL; setPadding(dp(16), dp(16), dp(16), dp(32)) }
        val scroll = ScrollView(this).apply { addView(root); setBackgroundColor(Color.WHITE) }
        scroll.setOnApplyWindowInsetsListener { v, insets ->
            @Suppress("DEPRECATION")
            v.setPadding(0, insets.systemWindowInsetTop, 0, insets.systemWindowInsetBottom); insets
        }
        setContentView(scroll)

        root.addView(TextView(this).apply { text = "사진 정보"; textSize = 22f; setTypeface(null, Typeface.BOLD); setTextColor(Color.BLACK) })
        image = ImageView(this).apply { adjustViewBounds = true }
        root.addView(image, LinearLayout.LayoutParams(MATCH_PARENT, WRAP_CONTENT).apply { topMargin = dp(8) })

        root.addView(Button(this).apply {
            text = "3D 자세히 보기 (주름·피부 결)"
            setOnClickListener {
                startActivity(Intent(this@PhotoActivity, Face3DActivity::class.java).putExtra("path", file.absolutePath).putExtra("detail", true))
            }
        }, LinearLayout.LayoutParams(MATCH_PARENT, WRAP_CONTENT).apply { topMargin = dp(8) })

        root.addView(Button(this).apply {
            text = "3D 얼굴 모델 보기"
            setOnClickListener {
                startActivity(Intent(this@PhotoActivity, Face3DActivity::class.java).putExtra("path", file.absolutePath))
            }
        }, LinearLayout.LayoutParams(MATCH_PARENT, WRAP_CONTENT).apply { topMargin = dp(8) })

        faceBox = LinearLayout(this).apply { orientation = LinearLayout.VERTICAL }
        root.addView(section("얼굴 분석"))
        root.addView(faceBox)
        faceBox.addView(rowView("상태", "분석 중..."))

        showExif()

        root.addView(Button(this).apply {
            text = "이 사진 삭제"
            setOnClickListener { file.delete(); finish() }
        }, LinearLayout.LayoutParams(MATCH_PARENT, WRAP_CONTENT).apply { topMargin = dp(16) })

        thread { analyzeFace() }
    }

    private fun analyzeFace() {
        val bmp = runCatching { FaceMatcher.decodeFile(file) }.getOrNull()
        if (bmp == null) {
            runOnUiThread { faceBox.removeAllViews(); faceBox.addView(rowView("상태", "사진을 열 수 없습니다")) }
            return
        }
        runOnUiThread { image.setImageBitmap(bmp) }
        val r = runCatching { FaceMesh.analyze(this, bmp) }
        runOnUiThread {
            faceBox.removeAllViews()
            val res = r.getOrNull()
            when {
                r.isFailure -> faceBox.addView(rowView("상태", "분석 오류: ${r.exceptionOrNull()?.message}"))
                res == null -> faceBox.addView(rowView("상태", "얼굴을 찾지 못했습니다"))
                else -> {
                    image.setImageBitmap(withDots(bmp, res.points))
                    fun side(v: Float, pos: String, neg: String) =
                        if (abs(v) < 5) "정면" else "${if (v > 0) pos else neg} ${abs(v).roundToInt()}°"
                    fun pct(vararg keys: String): String {
                        val vals = keys.mapNotNull { res.blend[it] }
                        return if (vals.isEmpty()) "-" else "${(vals.average() * 100).roundToInt()}%"
                    }
                    faceBox.addView(rowView("찾은 얼굴 수", "${res.faceCount}명 (가장 큰 얼굴 기준)"))
                    faceBox.addView(rowView("얼굴 점", "${res.points.size / 3}개 (3D 좌표)"))
                    faceBox.addView(rowView("좌우 방향", side(res.yaw, "화면 오른쪽", "화면 왼쪽")))
                    faceBox.addView(rowView("위아래 방향", side(res.pitch, "위", "아래")))
                    faceBox.addView(rowView("기울기", side(res.roll, "시계 방향", "반시계 방향")))
                    faceBox.addView(rowView("미소", pct("mouthSmileLeft", "mouthSmileRight")))
                    faceBox.addView(rowView("눈 감김", pct("eyeBlinkLeft", "eyeBlinkRight")))
                    faceBox.addView(rowView("입 벌림", pct("jawOpen")))
                    faceBox.addView(hint("방향과 표정 값은 자동 추정치입니다."))
                }
            }
        }
    }

    private fun withDots(src: Bitmap, pts: FloatArray): Bitmap {
        val out = src.copy(Bitmap.Config.ARGB_8888, true)
        val c = Canvas(out)
        val paint = Paint(Paint.ANTI_ALIAS_FLAG).apply { color = Color.argb(200, 0, 230, 160) }
        val r = maxOf(1.5f, out.width / 400f)
        for (i in 0 until pts.size / 3) c.drawCircle(pts[i * 3] * out.width, pts[i * 3 + 1] * out.height, r, paint)
        return out
    }

    private fun showExif() {
        root.addView(section("파일"))
        root.addView(rowView("이름", file.name))
        root.addView(rowView("용량", formatSize(file.length())))
        val bounds = BitmapFactory.Options().apply { inJustDecodeBounds = true }
        BitmapFactory.decodeFile(file.absolutePath, bounds)
        if (bounds.outWidth > 0) {
            val mp = bounds.outWidth.toLong() * bounds.outHeight / 1_000_000.0
            root.addView(rowView("해상도", "${bounds.outWidth} × ${bounds.outHeight} (%.1f MP)".format(mp)))
        }
        bounds.outMimeType?.let { root.addView(rowView("형식", it)) }

        val exif = runCatching { ExifInterface(file) }.getOrNull()
        root.addView(section("촬영 정보 (EXIF)"))
        if (exif == null) { root.addView(hint("EXIF 정보를 읽을 수 없습니다")); return }

        fun s(tag: String) = exif.getAttribute(tag)?.trim()?.takeIf { it.isNotEmpty() }
        fun d(tag: String) = exif.getAttributeDouble(tag, Double.NaN).takeIf { !it.isNaN() && it > 0 }
        var any = false
        fun add(label: String, value: String?) { if (value != null) { root.addView(rowView(label, value)); any = true } }

        add("촬영 일시", s(ExifInterface.TAG_DATETIME_ORIGINAL) ?: s(ExifInterface.TAG_DATETIME))
        add("제조사", s(ExifInterface.TAG_MAKE))
        add("기종", s(ExifInterface.TAG_MODEL))
        add("렌즈", s(ExifInterface.TAG_LENS_MODEL))
        add("초점 거리", d(ExifInterface.TAG_FOCAL_LENGTH)?.let { "%.1f mm".format(it) } +
            (exif.getAttributeInt(ExifInterface.TAG_FOCAL_LENGTH_IN_35MM_FILM, 0).takeIf { it > 0 }?.let { " (35mm 환산 $it mm)" } ?: ""))
            .takeIf { d(ExifInterface.TAG_FOCAL_LENGTH) != null }
        add("조리개", d(ExifInterface.TAG_F_NUMBER)?.let { "f/%.1f".format(it) })
        add("셔터 속도", d(ExifInterface.TAG_EXPOSURE_TIME)?.let {
            if (it < 1) "1/${(1 / it).roundToInt()}초" else "%.1f초".format(it)
        })
        add("ISO", exif.getAttributeInt(ExifInterface.TAG_PHOTOGRAPHIC_SENSITIVITY, 0).takeIf { it > 0 }?.toString())
        add("플래시", exif.getAttributeInt(ExifInterface.TAG_FLASH, -1).takeIf { it >= 0 }?.let { if (it and 1 == 1) "터짐" else "안 터짐" })
        add("회전 정보", when (exif.getAttributeInt(ExifInterface.TAG_ORIENTATION, 0)) {
            ExifInterface.ORIENTATION_NORMAL -> "정상"
            ExifInterface.ORIENTATION_ROTATE_90 -> "90° 회전"
            ExifInterface.ORIENTATION_ROTATE_180 -> "180° 회전"
            ExifInterface.ORIENTATION_ROTATE_270 -> "270° 회전"
            0 -> null
            else -> "뒤집힘/기타"
        })
        add("편집 프로그램", s(ExifInterface.TAG_SOFTWARE))
        if (!any) root.addView(hint("촬영 정보가 없습니다 (스크린샷이거나 SNS에서 받은 사진은 보통 지워져 있습니다)"))

        root.addView(section("위치 (GPS)"))
        val ll = exif.latLong
        if (ll != null) {
            root.addView(rowView("좌표", String.format(Locale.US, "%.5f, %.5f", ll[0], ll[1])))
            exif.getAltitude(Double.NaN).takeIf { !it.isNaN() }?.let { root.addView(rowView("고도", "%.0f m".format(it))) }
            root.addView(TextView(this).apply {
                text = "⚠ 이 사진에는 촬영 위치가 들어 있습니다. 그대로 SNS 등에 올리면 위치가 노출될 수 있습니다."
                setTextColor(Color.rgb(180, 30, 30)); textSize = 13f
            })
            root.addView(Button(this).apply {
                text = "지도에서 보기"
                setOnClickListener {
                    runCatching { startActivity(Intent(Intent.ACTION_VIEW, Uri.parse("geo:${ll[0]},${ll[1]}?q=${ll[0]},${ll[1]}"))) }
                }
            })
        } else {
            root.addView(hint("위치 정보 없음 (Android 사진 선택기는 개인정보 보호를 위해 위치 정보를 지우기도 합니다)"))
        }
    }

    private fun formatSize(b: Long) = when {
        b >= 1_000_000 -> "%.1f MB".format(b / 1_000_000.0)
        b >= 1_000 -> "%.0f KB".format(b / 1_000.0)
        else -> "$b B"
    }

    private fun section(t: String) = TextView(this).apply {
        text = t; textSize = 16f; setTypeface(null, Typeface.BOLD); setTextColor(Color.BLACK); setPadding(0, dp(18), 0, dp(4))
    }
    private fun hint(t: String) = TextView(this).apply { text = t; textSize = 13f; setTextColor(Color.DKGRAY) }
    private fun rowView(label: String, value: String) = LinearLayout(this).apply {
        orientation = LinearLayout.HORIZONTAL
        setPadding(0, dp(3), 0, dp(3))
        addView(TextView(context).apply { text = label; textSize = 14f; setTextColor(Color.GRAY) },
            LinearLayout.LayoutParams(dp(110), WRAP_CONTENT))
        addView(TextView(context).apply { text = value; textSize = 14f; setTextColor(Color.BLACK) },
            LinearLayout.LayoutParams(0, WRAP_CONTENT, 1f))
    }
}
