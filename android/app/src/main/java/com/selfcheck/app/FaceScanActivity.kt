package com.selfcheck.app

import android.Manifest
import android.content.Intent
import android.content.pm.PackageManager
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
import android.widget.CheckBox
import android.widget.HorizontalScrollView
import android.widget.LinearLayout
import android.widget.TextView
import androidx.activity.ComponentActivity
import androidx.activity.result.PickVisualMediaRequest
import androidx.activity.result.contract.ActivityResultContracts
import androidx.core.content.ContextCompat
import androidx.core.content.FileProvider
import java.io.File
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale
import kotlin.concurrent.thread
import kotlin.math.abs
import kotlin.math.roundToInt

/** 사진 고르기 / 카메라로 찍기 (시스템 카메라 앱) */
class ImageInput(private val act: ComponentActivity, private val onImage: (Uri) -> Unit) {
    private val pick = act.registerForActivityResult(ActivityResultContracts.PickVisualMedia()) { uri -> uri?.let(onImage) }
    private var shotUri: Uri? = null
    private val shoot = act.registerForActivityResult(ActivityResultContracts.TakePicture()) { ok -> if (ok) shotUri?.let(onImage) }
    private val askCam = act.registerForActivityResult(ActivityResultContracts.RequestPermission()) { ok -> if (ok) launchCamera() }

    fun pickPhoto() = pick.launch(PickVisualMediaRequest(ActivityResultContracts.PickVisualMedia.ImageOnly))
    fun takePhoto() {
        if (ContextCompat.checkSelfPermission(act, Manifest.permission.CAMERA) == PackageManager.PERMISSION_GRANTED) launchCamera()
        else askCam.launch(Manifest.permission.CAMERA)
    }
    private fun launchCamera() {
        val dir = File(act.cacheDir, "shots").apply { mkdirs() }
        dir.listFiles()?.filter { System.currentTimeMillis() - it.lastModified() > 86_400_000L }?.forEach { it.delete() }
        val f = File(dir, "shot_${System.currentTimeMillis()}.jpg")
        val u = FileProvider.getUriForFile(act, "${act.packageName}.files", f)
        shotUri = u
        runCatching { shoot.launch(u) }.onFailure { android.widget.Toast.makeText(act, "카메라 앱을 열 수 없습니다", android.widget.Toast.LENGTH_SHORT).show() }
    }
}

/**
 * 정밀 얼굴 스캔: 얼굴 점 정밀 측정(6회 중앙값) → 피부·주름 분석 → 비율·대칭·치수 → 표정.
 * 모든 분석은 휴대폰 안에서만 합니다.
 */
class FaceScanActivity : ColumnActivity() {
    private val input = ImageInput(this) { uri -> start { FaceMatcher.decodeUri(contentResolver, uri, 3000) } }
    private lateinit var body: LinearLayout
    private var full: SkinAnalysis.Full? = null
    private var metrics: FaceMetrics? = null
    private var mesh: FaceMeshResult? = null
    private var srcFile: File? = null
    private var srcBmp: Bitmap? = null
    private val layers = linkedSetOf("wrinkle", "fine", "spot", "region")
    private lateinit var view: ZoomImageView
    private val chipOf = HashMap<String, TextView>()

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setupColumn("정밀 얼굴 스캔", "주름(부위별·잔주름)·모공·잡티·홍조·번들거림·다크서클·톤·피부결과 얼굴 비율·대칭·치수·표정을 분석합니다. 사진은 휴대폰 밖으로 나가지 않습니다.")
        col.addView(buttons("사진 고르기" to { _ -> input.pickPhoto() }, "카메라로 찍기" to { _ -> input.takePhoto() }))
        col.addView(tip("📸 정확하게 찍는 법: 정면, 밝고 고른 빛(창가 등), 화장·필터 없이, 얼굴이 화면을 크게 채우게 해 주세요."))
        body = LinearLayout(this).apply { orientation = LinearLayout.VERTICAL }
        col.addView(body)
        intent.getStringExtra("path")?.let { p -> srcFile = File(p); start { FaceMatcher.decodeFile(File(p), 3000) } }
    }

    private fun start(load: () -> Bitmap) {
        body.removeAllViews()
        val statusCard = card()
        val status = TextView(this).apply { text = "분석 준비 중..."; textSize = 15f; setTextColor(Pal.primaryDark); typeface = Typeface.DEFAULT_BOLD }
        statusCard.addView(status)
        body.addView(statusCard, LinearLayout.LayoutParams(MATCH_PARENT, WRAP_CONTENT).apply { topMargin = dp(12) })
        thread {
            fun say(t: String) = runOnUiThread { status.text = t }
            val r = runCatching {
                say("사진 여는 중...")
                val bmp = load()
                srcBmp = bmp
                say("얼굴 점 정밀 측정 중 (6번 측정해 중앙값)...")
                val m = FaceMesh.analyzeTTA(this, bmp) { i -> say("얼굴 점 정밀 측정 중 ${i + 1}/6") } ?: return@runCatching null
                say("피부·주름 분석 중...")
                val f = SkinAnalysis.analyze(this, bmp, m.points, m.yaw)
                say("비율·대칭 계산 중...")
                val fm = FaceMetricsCalc.compute(m.points, bmp.width.toFloat(), bmp.height.toFloat(), FaceMesh.mirrorTable(this), m.yaw, m.blend)
                Triple(m, f, fm)
            }
            runOnUiThread {
                val v = r.getOrNull()
                when {
                    r.isFailure -> status.text = "분석 오류: ${r.exceptionOrNull()?.message}"
                    v == null -> status.text = "얼굴을 찾지 못했습니다. 얼굴이 잘 보이는 사진을 써 보세요."
                    else -> { mesh = v.first; full = v.second; metrics = v.third; show() }
                }
            }
        }
    }

    private fun refresh() { full?.let { view.setImage(SkinAnalysis.overlay(it, layers), keepView = true) } }

    private fun toggle(key: String, on: Boolean? = null) {
        val want = on ?: (key !in layers)
        if (want) layers += key else layers -= key
        chipOf[key]?.let { UiKit.setChip(it, want) }
        refresh()
    }

    /** 제목 + 카드 한 묶음을 만들어 본문에 붙이고, 카드를 돌려줍니다 */
    private fun group(title: String, sub: String? = null): LinearLayout {
        body.addView(UiKit.sectionTitle(this, title, sub))
        return card().also { body.addView(it, LinearLayout.LayoutParams(MATCH_PARENT, WRAP_CONTENT)) }
    }

    private fun show() {
        val f = full ?: return; val r = f.res; val fm = metrics ?: return; val m = mesh ?: return
        body.removeAllViews()

        // 사진 (둥근 모서리) + 층 선택 칩
        view = ZoomImageView(this)
        body.addView(view, LinearLayout.LayoutParams(MATCH_PARENT, (resources.displayMetrics.widthPixels * 1.05f).toInt()).apply { topMargin = dp(12) })
        body.addView(hint("두 손가락으로 확대, 두 번 누르면 3배 확대/원래대로").apply { setPadding(dp(4), dp(6), 0, dp(6)) })
        val chips = ArrayList<TextView>()
        for ((k, name) in SkinAnalysis.LAYERS) {
            val c = UiKit.chip(this, name, k in layers) { toggle(k) }
            chipOf[k] = c; chips += c
        }
        body.addView(UiKit.chipRow(this, chips))
        body.addView(hint("색: 주름=분홍, 잔주름=연두, 모공=하늘색 점, 잡티=주황 원, 홍조=빨강, 번들거림=노랑").apply { setPadding(dp(4), dp(8), 0, 0) })
        refresh()

        // 종합 점수 (큰 숫자 + 등급)
        val grade = when { r.overall >= 85 -> "매우 좋음"; r.overall >= 70 -> "좋음"; r.overall >= 55 -> "보통"; r.overall >= 40 -> "관리 필요"; else -> "집중 관리 필요" }
        val gcol = when { r.overall >= 70 -> Pal.good; r.overall >= 55 -> Pal.warn; else -> Pal.bad }
        val hero = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL; setPadding(dp(20), dp(18), dp(20), dp(18))
            background = UiKit.gradient(this@FaceScanActivity, 22f)
        }
        val row = LinearLayout(this).apply { orientation = LinearLayout.HORIZONTAL; gravity = Gravity.CENTER_VERTICAL }
        row.addView(TextView(this).apply { text = "${r.overall}"; textSize = 54f; setTextColor(Color.WHITE); typeface = Typeface.DEFAULT_BOLD; includeFontPadding = false })
        row.addView(LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL; setPadding(dp(14), 0, 0, 0)
            addView(TextView(context).apply { text = "종합 피부 점수 (100점 만점)"; textSize = 13f; setTextColor(0xCCFFFFFF.toInt()) })
            addView(TextView(context).apply { text = grade; textSize = 15f; setTextColor(Color.WHITE); typeface = Typeface.DEFAULT_BOLD
                setPadding(dp(12), dp(4), dp(12), dp(4)); background = UiKit.rounded(context, gcol, 20f)
                layoutParams = LinearLayout.LayoutParams(WRAP_CONTENT, WRAP_CONTENT).apply { topMargin = dp(6) } })
        }, LinearLayout.LayoutParams(0, WRAP_CONTENT, 1f))
        hero.addView(row)
        val worst = r.metrics.filter { it.key != "texture" }.maxByOrNull { it.degree }
        if (worst != null && worst.degree >= 30f) hero.addView(TextView(this).apply { text = "가장 두드러진 항목: ${worst.name} (${worst.degree.roundToInt()})"; textSize = 13f; setTextColor(Color.WHITE); setPadding(0, dp(10), 0, 0) })
        body.addView(hero, LinearLayout.LayoutParams(MATCH_PARENT, WRAP_CONTENT).apply { topMargin = dp(14) })
        r.warnings.forEach { body.addView(warn("⚠ $it")) }
        body.addView(hint("자동 추정치입니다. 조명·화질·화장·표정에 따라 달라지며 의료 진단이 아닙니다. 같은 조건(같은 장소·조명·거리)에서 찍어 기록을 비교하면 변화를 보기 좋습니다.").apply { setPadding(dp(4), dp(8), dp(4), 0) })

        group("항목별", "높을수록 두드러집니다 · 누르면 사진에 표시").also { g ->
            val layerOf = mapOf("wrinkle" to "wrinkle", "fine" to "fine", "pore" to "pore", "spot" to "spot", "red" to "red", "shine" to "shine")
            for (x in r.metrics) g.addView(bar(x.name, x.degree, "${x.degree.roundToInt()} · ${x.value}") { layerOf[x.key]?.let { toggle(it, true) }; toast(x.note) })
        }
        group("부위별 주름", "0~100").also { g ->
            for ((name, s) in r.regionScores) g.addView(bar(name, s, if (s == null) "가려짐·안 보임" else "${s.roundToInt()} · 선 ${r.regionLines[name] ?: 0}개"))
        }
        group("잔주름", "아주 가는 선").also { g ->
            for ((name, s) in r.fineScores) g.addView(bar(name, s, s?.roundToInt()?.toString() ?: "가려짐·안 보임"))
        }
        group("얼굴 대칭").also { g ->
            g.addView(bar("좌우 대칭 점수", fm.symmetry.toFloat(), "${fm.symmetry}점 (평균 차이 %.1f%%)".format(fm.asymPct), lowIsGood = false))
            fm.parts.forEach { (k, v) -> g.addView(rowView(k, v)) }
        }
        group("얼굴 비율").also { g ->
            g.addView(rowView("3등분 (위:가운데:아래)", "%.0f : %.0f : %.0f".format(fm.thirds[0], fm.thirds[1], fm.thirds[2])))
            g.addView(hint("가운데(미간~코밑)와 아래(코밑~턱)가 비슷할수록 균형. 위는 머리선이 아닌 이마 윗부분 기준이라 작게 나옵니다."))
            g.addView(rowView("코밑~입 : 입~턱", "%.0f : %.0f (보통 33:67)".format(fm.lowerSplit[0], fm.lowerSplit[1])))
            g.addView(rowView("가로 5등분", fm.fifths.joinToString(" : ") { "%.0f".format(it) } + " (고르면 각 20)"))
            fm.ratios.forEach { (k, v) -> g.addView(rowView(k, v)) }
            g.addView(rowView("얼굴형", fm.shape))
            g.addView(hint(fm.shapeWhy))
        }
        if (fm.measures.isNotEmpty()) group("치수", "추정치").also { g ->
            fm.measures.forEach { (k, v) -> g.addView(rowView(k, v)) }
            fm.notes.forEach { g.addView(hint("※ $it").apply { setPadding(0, dp(4), 0, 0) }) }
        }
        group("표정").also { g ->
            g.addView(rowView("표정", fm.expression))
            fm.topBlend.forEach { (k, v) -> g.addView(bar(k, v * 100, "${(v * 100).roundToInt()}%", lowIsGood = false)) }
            val allBox = LinearLayout(this).apply { orientation = LinearLayout.VERTICAL; visibility = View.GONE }
            g.addView(button("표정 52가지 모두 보기") { b ->
                if (allBox.visibility == View.GONE) {
                    if (allBox.childCount == 0) m.blend.entries.sortedByDescending { it.value }.forEach { (k, v) ->
                        allBox.addView(bar(FaceMetricsCalc.blendName(k), v * 100, "${(v * 100).roundToInt()}%", lowIsGood = false))
                    }
                    allBox.visibility = View.VISIBLE; b.text = "표정 접기"
                } else { allBox.visibility = View.GONE; b.text = "표정 52가지 모두 보기" }
            }, LinearLayout.LayoutParams(MATCH_PARENT, WRAP_CONTENT).apply { topMargin = dp(8) })
            g.addView(allBox)
        }
        group("얼굴 방향·측정").also { g ->
            fun side(v: Float, pos: String, neg: String) = if (abs(v) < 5) "정면" else "${if (v > 0) pos else neg} ${abs(v).roundToInt()}°"
            g.addView(rowView("좌우", side(m.yaw, "화면 오른쪽", "화면 왼쪽")))
            g.addView(rowView("위아래", side(m.pitch, "위", "아래")))
            g.addView(rowView("기울기", side(m.roll, "시계 방향", "반시계 방향")))
            g.addView(rowView("정밀 측정", "${m.passes}번 측정의 중앙값 (점 ${m.points.size / 3}개)"))
        }
        body.addView(UiKit.sectionTitle(this, "저장·기록"))
        val actions = card()
        actions.addView(buttons("결과 사진 저장" to { _ -> saveImage() }, "결과 글 복사" to { _ -> copy(summary(), "얼굴 스캔 결과") }))
        actions.addView(buttons("기록에 저장" to { _ -> SkinHistory.add(this, "스캔", r, fm); toast("기록에 저장했습니다 (휴대폰 안)") }, "기록과 비교" to { _ -> compare() }),
            LinearLayout.LayoutParams(MATCH_PARENT, WRAP_CONTENT).apply { topMargin = dp(8) })
        actions.addView(primaryButton("3D 주름 강조 보기") { open3D() }, LinearLayout.LayoutParams(MATCH_PARENT, WRAP_CONTENT).apply { topMargin = dp(8) })
        body.addView(actions)
        scroll.post { scroll.smoothScrollTo(0, body.top) }
    }

    private fun summary(): String {
        val r = full?.res ?: return ""; val fm = metrics ?: return ""
        val sb = StringBuilder("정밀 얼굴 스캔 결과 (${SimpleDateFormat("yyyy-MM-dd HH:mm", Locale.KOREA).format(Date())})\n")
        sb.append("종합 피부 점수 ${r.overall}점\n")
        r.metrics.forEach { sb.append("- ${it.name}: ${it.degree.roundToInt()} (${it.value})\n") }
        sb.append("부위별 주름: ").append(r.regionScores.entries.joinToString(", ") { "${it.key} ${it.value?.roundToInt() ?: "-"}" }).append('\n')
        sb.append("대칭 ${fm.symmetry}점, 얼굴형 ${fm.shape}, 표정 ${fm.expression}\n")
        fm.measures.take(3).forEach { sb.append("${it.first} ${it.second}\n") }
        sb.append("(자동 추정치, 의료 진단 아님)")
        return sb.toString()
    }

    private fun saveImage() {
        val f = full ?: return
        val img = SkinAnalysis.overlay(f, layers)
        val head = (img.width * 0.12f).toInt().coerceAtLeast(40)
        val out = Bitmap.createBitmap(img.width, img.height + head, Bitmap.Config.ARGB_8888)
        val c = Canvas(out); c.drawColor(Color.WHITE); c.drawBitmap(img, 0f, head.toFloat(), null)
        val p = Paint(Paint.ANTI_ALIAS_FLAG).apply { color = Color.BLACK; textSize = head * 0.42f; typeface = Typeface.DEFAULT_BOLD }
        c.drawText("피부 ${f.res.overall}점 · 주름 ${f.res.metrics[0].degree.roundToInt()} · 대칭 ${metrics?.symmetry ?: "-"}", head * 0.2f, head * 0.62f, p)
        thread {
            val msg = runCatching { MediaSave.savePng(this, out, "face_scan_${System.currentTimeMillis()}.png") + " 에 저장했습니다" }.getOrElse { "저장 실패: ${it.message}" }
            runOnUiThread { toast(msg) }
        }
    }

    private fun compare() {
        val r = full?.res ?: return
        val hist = SkinHistory.load(this)
        if (hist.isEmpty()) { toast("저장된 기록이 없습니다. 먼저 '기록에 저장'을 누르세요."); return }
        val fmt = SimpleDateFormat("MM-dd HH:mm", Locale.KOREA)
        val sb = StringBuilder()
        for (h in hist.takeLast(8).asReversed()) {
            val d = r.overall - h.optInt("overall")
            sb.append("${fmt.format(Date(h.optLong("time")))}  종합 ${h.optInt("overall")}점 → 지금 ${r.overall}점 (${if (d >= 0) "+" else ""}$d)\n")
            val mets = h.optJSONObject("metrics")
            if (mets != null) for (x in r.metrics) if (mets.has(x.name)) {
                val dd = x.degree - mets.getDouble(x.name).toFloat()
                if (abs(dd) >= 3) sb.append("   ${x.name} ${if (dd > 0) "▲" else "▼"}${abs(dd).roundToInt()}\n")
            }
        }
        sb.append("\n▲ = 지금이 더 두드러짐, ▼ = 줄어듦 (같은 조명·거리에서 찍어야 비교가 정확합니다)")
        android.app.AlertDialog.Builder(this).setTitle("기록과 비교").setMessage(sb.toString())
            .setPositiveButton("닫기", null)
            .setNeutralButton("기록 모두 지우기") { _, _ -> SkinHistory.clear(this); toast("기록을 지웠습니다") }
            .show()
    }

    private fun open3D() {
        val file = srcFile
        if (file != null) { startActivity(Intent(this, Face3DActivity::class.java).putExtra("path", file.absolutePath).putExtra("detail", true)); return }
        val b = srcBmp ?: return
        // 고른 사진은 앱 안 임시 파일로 저장해서 넘김
        thread {
            val tmp = File(cacheDir, "scan_src.jpg")
            runCatching { tmp.outputStream().use { b.compress(Bitmap.CompressFormat.JPEG, 95, it) } }
            runOnUiThread { startActivity(Intent(this, Face3DActivity::class.java).putExtra("path", tmp.absolutePath).putExtra("detail", true)) }
        }
    }
}
