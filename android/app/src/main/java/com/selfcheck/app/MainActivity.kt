package com.selfcheck.app

import android.Manifest
import android.content.Intent
import android.graphics.Color
import android.graphics.Typeface
import android.net.Uri
import android.os.Build
import android.os.Bundle
import android.text.InputType
import android.view.ViewOutlineProvider
import android.view.Gravity
import android.view.View
import android.view.ViewGroup.LayoutParams.MATCH_PARENT
import android.view.ViewGroup.LayoutParams.WRAP_CONTENT
import android.widget.Button
import android.widget.HorizontalScrollView
import android.widget.ImageView
import android.widget.CompoundButton
import android.widget.EditText
import android.widget.LinearLayout
import android.widget.ProgressBar
import android.widget.ScrollView
import android.widget.TextView
import android.widget.Toast
import androidx.activity.ComponentActivity
import androidx.activity.result.PickVisualMediaRequest
import androidx.activity.result.contract.ActivityResultContracts
import androidx.work.WorkInfo
import androidx.work.WorkManager
import java.io.File
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale
import kotlin.concurrent.thread

class MainActivity : ComponentActivity() {

    private lateinit var usernameInput: EditText
    private lateinit var photoInfo: TextView
    private lateinit var thumbs: LinearLayout
    private lateinit var repeatSwitch: CompoundButton
    private lateinit var startBtn: Button
    private lateinit var progressBar: ProgressBar
    private lateinit var statusText: TextView
    private lateinit var results: LinearLayout
    private var running = false

    private val pickRefs = registerForActivityResult(ActivityResultContracts.PickMultipleVisualMedia(10)) { uris ->
        if (uris.isNotEmpty()) saveRefs(uris)
    }
    private val pickSuspects = registerForActivityResult(ActivityResultContracts.PickMultipleVisualMedia(30)) { uris ->
        if (uris.isNotEmpty()) compareSuspects(uris)
    }
    private val askNoti = registerForActivityResult(ActivityResultContracts.RequestPermission()) { }

    private fun dp(v: Int) = dip(v)

    /** 홈 화면의 기능 바로가기 */
    private class Feature(val emoji: String, val title: String, val sub: String, val tint: Int, val isNew: Boolean = false, val open: () -> Unit)

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        ScanWorker.ensureChannel(this)
        if (Build.VERSION.SDK_INT >= 33) askNoti.launch(Manifest.permission.POST_NOTIFICATIONS)

        val page = LinearLayout(this).apply { orientation = LinearLayout.VERTICAL; setPadding(dp(16), dp(10), dp(16), dp(32)) }
        val scroll = ScrollView(this).apply { addView(page); setBackgroundColor(Pal.bg); isVerticalScrollBarEnabled = false }
        scroll.setOnApplyWindowInsetsListener { v, insets ->
            @Suppress("DEPRECATION")
            v.setPadding(0, insets.systemWindowInsetTop, 0, insets.systemWindowInsetBottom); insets
        }
        setContentView(scroll)

        page.addView(buildHero())

        // ---- 기능 바로가기
        page.addView(UiKit.sectionTitle(this, "바로 가기", "자주 쓰는 기능을 한 번에 열어요"))
        val features = listOf(
            Feature("🧖", "정밀 얼굴 스캔", "주름·피부·대칭 분석", 0xFFFFE4EC.toInt()) { go(FaceScanActivity::class.java) },
            Feature("🆚", "얼굴 비교", "닮은 정도를 %로", 0xFFE0F2FE.toInt()) { go(FaceCompareActivity::class.java) },
            Feature("🎙️", "음성 변조", "소녀·뉴스 앵커 등 ${VoicePresets.ALL.size}가지", 0xFFEDE9FE.toInt()) { go(VoiceChangerActivity::class.java) },
            Feature("🧰", "도구 모음", "사진·카메라·보안·네트워크 ${ToolsActivity.countLabel(this)}", 0xFFFEF3C7.toInt()) { go(ToolsActivity::class.java) },
            Feature("🔌", "포트 검사", "IP로 열린 포트 점검", 0xFFCFFAFE.toInt(), true) { startActivity(Intent(this, NetworkActivity::class.java).putExtra("tool", "port_scan")) },
            Feature("🌐", "IP 찾기", "내 IP·Wi-Fi 기기·도메인", 0xFFFEF9C3.toInt(), true) { startActivity(Intent(this, NetworkActivity::class.java).putExtra("tool", "my_ip")) },
            Feature("🚗", "번호판 인식", "카메라로 읽어 목록 저장", 0xFFDCFCE7.toInt()) { go(PlateActivity::class.java) },
            Feature("🔎", "번호판 조회", "종류·용도 풀이", 0xFFCCFBF1.toInt()) { go(PlateLookupActivity::class.java) },
            Feature("🚶", "사람 인식", "인원 수·관절·자세", 0xFFFFE4E6.toInt()) { go(PersonActivity::class.java) },
            Feature("🎲", "실시간 3D 얼굴", "카메라로 3D 모델", 0xFFE0E7FF.toInt()) { go(LiveActivity::class.java) },
            Feature("✂️", "편집", "표정 따라하기·배경 제거", 0xFFFCE7F3.toInt()) { go(EditActivity::class.java) },
            Feature("🖼️", "의심 사진 비교", "사칭 의심 사진 확인", 0xFFFFEDD5.toInt()) {
                pickSuspects.launch(PickVisualMediaRequest(ActivityResultContracts.PickVisualMedia.ImageOnly))
            },
        )
        features.chunked(2).forEach { pair ->
            val row = LinearLayout(this).apply { orientation = LinearLayout.HORIZONTAL }
            pair.forEachIndexed { i, f -> row.addView(featureCard(f), LinearLayout.LayoutParams(0, MATCH_PARENT, 1f).apply { if (i == 1) leftMargin = dp(12) }) }
            page.addView(row, UiKit.params(bottom = 12, ctx = this))
        }

        // ---- 내 아이디 점검
        page.addView(UiKit.sectionTitle(this, "내 계정 점검", "255개 사이트에서 내 아이디가 쓰이는지 확인해요"))
        page.addView(buildAccountCard())

        results = LinearLayout(this).apply { orientation = LinearLayout.VERTICAL }
        page.addView(results)
        showResults()

        WorkManager.getInstance(this).getWorkInfosByTagLiveData(ScanWorker.TAG).observe(this) { infos -> onWork(infos) }

        // 지난번에 앱이 비정상 종료됐다면 원인을 보여 줌 (보내 주시면 고치는 데 도움이 됨)
        SelfCheckApp.takeCrashReport(this)?.let { report ->
            android.app.AlertDialog.Builder(this)
                .setTitle("지난번에 앱이 비정상 종료됐습니다")
                .setMessage(report)
                .setPositiveButton("내용 복사") { _, _ ->
                    getSystemService(android.content.ClipboardManager::class.java)
                        .setPrimaryClip(android.content.ClipData.newPlainText("오류 내용", report))
                    toast("복사했습니다")
                }
                .setNegativeButton("닫기", null)
                .show()
        }
    }

    private fun go(c: Class<*>) = startActivity(Intent(this, c))

    private fun buildHero(): View {
        val hero = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL; setPadding(dp(22), dp(24), dp(22), dp(22))
            background = UiKit.gradient(this@MainActivity, 26f); elevation = dipf(3f)
        }
        hero.addView(TextView(this).apply { text = "셀프 점검"; textSize = 30f; setTextColor(Color.WHITE); setTypeface(null, Typeface.BOLD) })
        hero.addView(TextView(this).apply {
            text = "얼굴·목소리·계정을 내 폰 안에서 점검해요"
            textSize = 14.5f; setTextColor(0xE6FFFFFF.toInt()); setLineSpacing(0f, 1.15f); setPadding(0, dp(6), 0, 0)
        })
        val chips = LinearLayout(this).apply { orientation = LinearLayout.HORIZONTAL; setPadding(0, dp(16), 0, 0) }
        fun pill(t: String) = TextView(this).apply {
            text = t; textSize = 12.5f; setTextColor(Color.WHITE); setPadding(dp(12), dp(6), dp(12), dp(6)); setSingleLine()
            background = UiKit.rounded(this@MainActivity, 0x33FFFFFF, 20f)
        }
        chips.addView(pill("🔒 분석은 폰 안에서만"))
        chips.addView(pill("🧰 도구 ${ToolsActivity.countLabel(this)}"), LinearLayout.LayoutParams(WRAP_CONTENT, WRAP_CONTENT).apply { leftMargin = dp(8) })
        hero.addView(chips)
        return hero
    }

    private fun featureCard(f: Feature): View {
        val c = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL; setPadding(dp(14), dp(14), dp(14), dp(14)); minimumHeight = dp(132); isClickable = true
            background = UiKit.ripple(this@MainActivity, UiKit.rounded(this@MainActivity, Pal.surface, 18f, Pal.outline, 1), 18f)
            elevation = dipf(1.5f)
        }
        val top = LinearLayout(this).apply { orientation = LinearLayout.HORIZONTAL; gravity = Gravity.CENTER_VERTICAL }
        top.addView(UiKit.badge(this, f.emoji, 46, f.tint, 22f))
        if (f.isNew) top.addView(TextView(this).apply {
            text = "NEW"; textSize = 10.5f; setTextColor(Color.WHITE); setTypeface(null, Typeface.BOLD); setPadding(dp(8), dp(3), dp(8), dp(3))
            background = UiKit.rounded(this@MainActivity, Pal.primary, 12f)
        }, LinearLayout.LayoutParams(WRAP_CONTENT, WRAP_CONTENT).apply { leftMargin = dp(8) })
        c.addView(top)
        c.addView(TextView(this).apply { text = UiKit.keepWords(f.title); textSize = 16f; setTextColor(Pal.text); setTypeface(null, Typeface.BOLD); setPadding(0, dp(12), 0, 0) })
        c.addView(TextView(this).apply { text = UiKit.keepWords(f.sub); textSize = 12.5f; setTextColor(Pal.text2); setLineSpacing(0f, 1.1f); setPadding(0, dp(3), 0, 0); breakStrategy = android.text.Layout.BREAK_STRATEGY_BALANCED })
        c.setOnClickListener { f.open() }
        return c
    }

    private fun buildAccountCard(): View {
        val card = UiKit.card(this)

        card.addView(UiKit.text(this, "내 아이디", 14f, Pal.text, true))
        usernameInput = EditText(this).apply {
            setText(Store.usernamesRaw(this@MainActivity)); hint = "예: myid, my.id2 (여러 개는 쉼표로)"
            inputType = InputType.TYPE_CLASS_TEXT or InputType.TYPE_TEXT_FLAG_NO_SUGGESTIONS
            background = UiKit.rounded(this@MainActivity, Pal.surface2, 14f)
            setPadding(dp(14), dp(12), dp(14), dp(12)); textSize = 15f; setTextColor(Pal.text); setHintTextColor(Pal.text3); setSingleLine()
        }
        card.addView(usernameInput, UiKit.params(top = 8, ctx = this))

        card.addView(UiKit.text(this, "내 얼굴 사진 (선택, 3~5장 권장)", 14f, Pal.text, true), UiKit.params(top = 18, ctx = this))
        photoInfo = UiKit.text(this, "", 12.5f, Pal.text2)
        card.addView(photoInfo, UiKit.params(top = 4, ctx = this))
        thumbs = LinearLayout(this).apply { orientation = LinearLayout.HORIZONTAL }
        card.addView(HorizontalScrollView(this).apply { addView(thumbs); isHorizontalScrollBarEnabled = false }, UiKit.params(top = 10, ctx = this))
        val photoBtns = LinearLayout(this).apply { orientation = LinearLayout.HORIZONTAL }
        photoBtns.addView(UiKit.button(this, "사진 고르기", BtnStyle.SOFT, 14f) { pickRefs.launch(PickVisualMediaRequest(ActivityResultContracts.PickVisualMedia.ImageOnly)) }, LinearLayout.LayoutParams(0, WRAP_CONTENT, 1f))
        photoBtns.addView(UiKit.button(this, "사진 지우기", BtnStyle.GHOST, 14f) { FaceMatcher.refsDir(this).listFiles()?.forEach { it.delete() }; refreshPhotoInfo() }, LinearLayout.LayoutParams(0, WRAP_CONTENT, 1f).apply { leftMargin = dp(8) })
        card.addView(photoBtns, UiKit.params(top = 10, ctx = this))
        refreshPhotoInfo()

        val rep = UiKit.switchRow(this, "⏰", "24시간마다 자동으로 다시 점검", "화면을 꺼도 하루에 한 번 혼자 돌아가요", Store.repeat(this)) { c ->
            Store.setRepeat(this, c); saveNames(); ScanWorker.schedule(this, c)
        }
        repeatSwitch = rep.sw
        card.addView(rep.view, UiKit.params(top = 14, ctx = this))

        startBtn = UiKit.button(this, "점검 시작", BtnStyle.PRIMARY, 16f) {
            if (running) { ScanWorker.cancel(this); return@button }
            saveNames()
            if (Store.usernames(this).isEmpty()) { toast("아이디를 입력하세요"); return@button }
            ScanWorker.runNow(this)
            ScanWorker.schedule(this, repeatSwitch.isChecked)
        }
        card.addView(startBtn, LinearLayout.LayoutParams(MATCH_PARENT, dp(52)).apply { topMargin = dp(14) })

        progressBar = ProgressBar(this, null, android.R.attr.progressBarStyleHorizontal).apply {
            visibility = View.GONE; progressTintList = android.content.res.ColorStateList.valueOf(Pal.primary)
        }
        card.addView(progressBar, UiKit.params(top = 12, ctx = this))
        statusText = UiKit.text(this, "", 12.5f, Pal.text2)
        card.addView(statusText, UiKit.params(top = 4, ctx = this))
        return card
    }

    private fun onWork(infos: List<WorkInfo>) {
        val active = infos.firstOrNull { it.state == WorkInfo.State.RUNNING }
        val wasRunning = running
        running = active != null
        startBtn.text = if (running) "점검 중지" else "점검 시작"
        UiKit.styleButton(startBtn, if (running) BtnStyle.DANGER else BtnStyle.PRIMARY); startBtn.textSize = 16f
        if (active != null) {
            val p = active.progress
            val total = p.getInt("total", 0); val done = p.getInt("done", 0)
            progressBar.visibility = View.VISIBLE
            progressBar.max = maxOf(total, 1); progressBar.progress = done
            statusText.text = (p.getString("stage") ?: "진행 중") + if (total > 0) "  $done/$total" else ""
            statusText.append("\n화면을 꺼도 계속 진행됩니다. 끝나면 알림이 옵니다.")
        } else {
            progressBar.visibility = View.GONE
            if (wasRunning) { statusText.text = ""; showResults() }
        }
    }

    private fun saveNames() = Store.setUsernames(this, usernameInput.text.toString())

    override fun onResume() {
        super.onResume()
        if (::thumbs.isInitialized) refreshPhotoInfo()
    }

    private fun refreshPhotoInfo() {
        val files = FaceMatcher.refsDir(this).listFiles()?.sortedBy { it.name } ?: emptyList()
        photoInfo.text = if (files.isEmpty()) "등록된 사진 없음 (사진 없이도 아이디 점검은 됩니다)"
        else "등록된 사진 ${files.size}장 · 사진을 누르면 사진 정보와 3D 얼굴 모델을 볼 수 있어요"
        thumbs.removeAllViews()
        val size = dp(84)
        for (f in files) {
            val iv = ImageView(this).apply {
                scaleType = ImageView.ScaleType.CENTER_CROP
                background = UiKit.rounded(this@MainActivity, Pal.surface2, 16f)
                outlineProvider = ViewOutlineProvider.BACKGROUND; clipToOutline = true
                setOnClickListener {
                    startActivity(Intent(this@MainActivity, PhotoActivity::class.java).putExtra("path", f.absolutePath))
                }
            }
            thumbs.addView(iv, LinearLayout.LayoutParams(size, size).apply { rightMargin = dp(8) })
            thread {
                val bmp = runCatching {
                    android.graphics.ImageDecoder.decodeBitmap(android.graphics.ImageDecoder.createSource(f)) { d, info, _ ->
                        val sc = 256.0 / maxOf(info.size.width, info.size.height)
                        if (sc < 1) d.setTargetSize((info.size.width * sc).toInt().coerceAtLeast(1), (info.size.height * sc).toInt().coerceAtLeast(1))
                    }
                }.getOrNull()
                if (bmp != null) runOnUiThread { iv.setImageBitmap(bmp) }
            }
        }
    }

    private fun saveRefs(uris: List<Uri>) {
        val dir = FaceMatcher.refsDir(this)
        uris.forEachIndexed { i, u ->
            runCatching {
                contentResolver.openInputStream(u)?.use { input ->
                    File(dir, "ref_${System.currentTimeMillis()}_$i.jpg").outputStream().use { input.copyTo(it) }
                }
            }
        }
        refreshPhotoInfo()
    }

    private fun compareSuspects(uris: List<Uri>) {
        if (FaceMatcher.refsDir(this).listFiles().isNullOrEmpty()) { toast("먼저 내 얼굴 사진을 등록하세요"); return }
        statusText.text = "얼굴 비교 준비 중..."
        thread {
            val lines = try {
                val m = FaceMatcher(this) { s -> runOnUiThread { statusText.text = s } }
                if (m.loadRefs(this) == 0) listOf("등록한 사진에서 얼굴을 찾지 못했습니다")
                else uris.mapIndexed { i, u ->
                    val s = runCatching { m.bestScore(FaceMatcher.decodeUri(contentResolver, u)) }.getOrNull()
                    "사진 ${i + 1}: " + when {
                        s == null -> "얼굴 없음"
                        s >= FaceMatcher.SAME_PERSON -> "%.2f  내 얼굴과 비슷함".format(s)
                        else -> "%.2f  다른 사람으로 보임".format(s)
                    }
                }
            } catch (e: Exception) {
                listOf("오류: ${e.message}")
            }
            runOnUiThread { statusText.text = "의심 사진 비교 결과\n" + lines.joinToString("\n") }
        }
    }

    private fun showResults() {
        results.removeAllViews()
        val (time, rows) = Store.loadResults(this) ?: return
        val visible = rows.filter { it.status != "not_found" }
        val fmt = SimpleDateFormat("yyyy-MM-dd HH:mm", Locale.KOREA)
        results.addView(UiKit.sectionTitle(this, "점검 결과", "마지막 점검 ${fmt.format(Date(time))} · 항목을 누르면 사이트가 열려요"))
        // 요약 칩
        val sum = LinearLayout(this).apply { orientation = LinearLayout.HORIZONTAL }
        fun stat(n: Int, label: String, fg: Int, bg: Int) = TextView(this).apply {
            text = "$label $n"; textSize = 12.5f; setTextColor(fg); setTypeface(null, Typeface.BOLD); setPadding(dp(12), dp(6), dp(12), dp(6)); setSingleLine()
            background = UiKit.rounded(this@MainActivity, bg, 20f)
        }
        val stats = listOf(
            stat(rows.count { it.status == "found" }, "있음", Pal.good, Pal.goodSoft),
            stat(rows.count { it.status == "possible" }, "있을 수도", Pal.warn, Pal.warnSoft),
            stat(rows.count { it.status == "blocked" }, "차단", Pal.text2, Pal.surface2),
            stat(rows.count { it.status == "error" }, "오류", Pal.bad, Pal.badSoft),
        )
        stats.forEachIndexed { i, v -> sum.addView(v, LinearLayout.LayoutParams(WRAP_CONTENT, WRAP_CONTENT).apply { if (i > 0) leftMargin = dp(8) }) }
        results.addView(HorizontalScrollView(this).apply { addView(sum); isHorizontalScrollBarEnabled = false })
        results.addView(UiKit.text(this, "없음 ${rows.count { it.status == "not_found" }}개는 숨겼어요", 12f, Pal.text3), UiKit.params(top = 6, ctx = this))

        for (r in visible) {
            val suspicious = (r.faceScore ?: 0.0) >= FaceMatcher.SAME_PERSON
            val (fg, bg) = when (r.status) { "found" -> Pal.good to Pal.goodSoft; "possible" -> Pal.warn to Pal.warnSoft; else -> Pal.text2 to Pal.surface2 }
            val card = LinearLayout(this).apply {
                orientation = LinearLayout.VERTICAL; setPadding(dp(14), dp(12), dp(14), dp(12)); isClickable = true
                val base = UiKit.rounded(this@MainActivity, if (suspicious) Pal.badSoft else Pal.surface, 16f, if (suspicious) 0xFFF5B5B5.toInt() else Pal.outline, 1)
                background = UiKit.ripple(this@MainActivity, base, 16f)
                setOnClickListener { runCatching { startActivity(Intent(Intent.ACTION_VIEW, Uri.parse(r.url))) } }
            }
            val head = LinearLayout(this).apply { orientation = LinearLayout.HORIZONTAL; gravity = Gravity.CENTER_VERTICAL }
            head.addView(TextView(this).apply {
                text = UsernameChecker.LABEL[r.status] ?: r.status; textSize = 11.5f; setTextColor(fg); setTypeface(null, Typeface.BOLD)
                setPadding(dp(10), dp(3), dp(10), dp(3)); background = UiKit.rounded(this@MainActivity, bg, 12f)
            })
            head.addView(TextView(this).apply { text = r.site; textSize = 15.5f; setTextColor(Pal.text); setTypeface(null, Typeface.BOLD); setPadding(dp(10), 0, 0, 0) },
                LinearLayout.LayoutParams(0, WRAP_CONTENT, 1f))
            head.addView(TextView(this).apply { text = r.username; textSize = 12.5f; setTextColor(Pal.text3) })
            card.addView(head)
            card.addView(TextView(this).apply { text = r.url; textSize = 12f; setTextColor(Pal.primaryDark); setPadding(0, dp(6), 0, 0); setSingleLine(); ellipsize = android.text.TextUtils.TruncateAt.MIDDLE })
            r.faceScore?.let {
                card.addView(TextView(this).apply {
                    text = if (it >= FaceMatcher.SAME_PERSON) "⚠ 프로필 사진이 내 얼굴과 비슷해요 (%.2f)".format(it) else "프로필 얼굴 유사도 %.2f".format(it)
                    textSize = 12.5f; setTextColor(if (it >= FaceMatcher.SAME_PERSON) Pal.bad else Pal.text2); setPadding(0, dp(4), 0, 0)
                    if (it >= FaceMatcher.SAME_PERSON) setTypeface(null, Typeface.BOLD)
                })
            }
            if (r.note.isNotEmpty()) card.addView(TextView(this).apply { text = r.note; textSize = 12f; setTextColor(Pal.text2); setPadding(0, dp(4), 0, 0) })
            results.addView(card, UiKit.params(top = 8, ctx = this))
        }
    }

    private fun toast(t: String) = Toast.makeText(this, t, Toast.LENGTH_SHORT).show()
}
