package com.selfcheck.app

import android.Manifest
import android.content.Intent
import android.graphics.Color
import android.graphics.Typeface
import android.net.Uri
import android.os.Build
import android.os.Bundle
import android.text.InputType
import android.view.Gravity
import android.view.View
import android.view.ViewGroup.LayoutParams.MATCH_PARENT
import android.view.ViewGroup.LayoutParams.WRAP_CONTENT
import android.widget.Button
import android.widget.HorizontalScrollView
import android.widget.ImageView
import android.widget.CheckBox
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
    private lateinit var repeatBox: CheckBox
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

    private fun dp(v: Int) = (v * resources.displayMetrics.density).toInt()

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        ScanWorker.ensureChannel(this)
        if (Build.VERSION.SDK_INT >= 33) askNoti.launch(Manifest.permission.POST_NOTIFICATIONS)

        val root = LinearLayout(this).apply { orientation = LinearLayout.VERTICAL; setPadding(dp(16), dp(16), dp(16), dp(32)) }
        val scroll = ScrollView(this).apply { addView(root); setBackgroundColor(Color.WHITE) }
        scroll.setOnApplyWindowInsetsListener { v, insets ->
            @Suppress("DEPRECATION")
            v.setPadding(0, insets.systemWindowInsetTop, 0, insets.systemWindowInsetBottom); insets
        }
        setContentView(scroll)

        root.addView(TextView(this).apply { text = "셀프 점검"; textSize = 24f; setTypeface(null, Typeface.BOLD) })
        root.addView(hint("내 아이디가 255개 사이트에서 쓰이는지 확인하고, 찾은 계정의 프로필 사진을 내 얼굴과 비교해 사칭 의심 계정을 표시합니다. 얼굴 비교는 휴대폰 안에서만 처리됩니다."))

        root.addView(label("1. 내 아이디 (여러 개는 쉼표로 구분)"))
        usernameInput = EditText(this).apply {
            setText(Store.usernamesRaw(this@MainActivity)); hint = "예: myid, my.id2"
            inputType = InputType.TYPE_CLASS_TEXT or InputType.TYPE_TEXT_FLAG_NO_SUGGESTIONS
        }
        root.addView(usernameInput)

        root.addView(label("2. 내 얼굴 사진 (선택, 3~5장 권장)"))
        photoInfo = hint("")
        root.addView(photoInfo)
        thumbs = LinearLayout(this).apply { orientation = LinearLayout.HORIZONTAL }
        root.addView(HorizontalScrollView(this).apply { addView(thumbs) },
            LinearLayout.LayoutParams(MATCH_PARENT, WRAP_CONTENT).apply { topMargin = dp(6) })
        root.addView(row(
            button("사진 고르기") { pickRefs.launch(PickVisualMediaRequest(ActivityResultContracts.PickVisualMedia.ImageOnly)) },
            button("사진 지우기") { FaceMatcher.refsDir(this).listFiles()?.forEach { it.delete() }; refreshPhotoInfo() },
        ))
        refreshPhotoInfo()

        repeatBox = CheckBox(this).apply {
            text = "24시간마다 자동으로 다시 점검"; isChecked = Store.repeat(this@MainActivity)
            setOnCheckedChangeListener { _, c ->
                Store.setRepeat(this@MainActivity, c); saveNames(); ScanWorker.schedule(this@MainActivity, c)
            }
        }
        root.addView(repeatBox)

        startBtn = button("점검 시작") {
            if (running) { ScanWorker.cancel(this); return@button }
            saveNames()
            if (Store.usernames(this).isEmpty()) { toast("아이디를 입력하세요"); return@button }
            ScanWorker.runNow(this)
            ScanWorker.schedule(this, repeatBox.isChecked)
        }
        root.addView(startBtn, LinearLayout.LayoutParams(MATCH_PARENT, WRAP_CONTENT).apply { topMargin = dp(8) })

        root.addView(button("실시간 카메라 3D") {
            startActivity(Intent(this, LiveActivity::class.java))
        }, LinearLayout.LayoutParams(MATCH_PARENT, WRAP_CONTENT))

        root.addView(button("의심 사진을 내 얼굴과 비교") {
            pickSuspects.launch(PickVisualMediaRequest(ActivityResultContracts.PickVisualMedia.ImageOnly))
        }, LinearLayout.LayoutParams(MATCH_PARENT, WRAP_CONTENT))

        progressBar = ProgressBar(this, null, android.R.attr.progressBarStyleHorizontal).apply { visibility = View.GONE }
        root.addView(progressBar, LinearLayout.LayoutParams(MATCH_PARENT, WRAP_CONTENT).apply { topMargin = dp(12) })
        statusText = hint("")
        root.addView(statusText)

        results = LinearLayout(this).apply { orientation = LinearLayout.VERTICAL }
        root.addView(results)
        showResults()

        WorkManager.getInstance(this).getWorkInfosByTagLiveData(ScanWorker.TAG).observe(this) { infos -> onWork(infos) }
    }

    private fun onWork(infos: List<WorkInfo>) {
        val active = infos.firstOrNull { it.state == WorkInfo.State.RUNNING }
        val wasRunning = running
        running = active != null
        startBtn.text = if (running) "점검 중지" else "점검 시작"
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
        else "등록된 사진 ${files.size}장 · 사진을 누르면 사진 정보와 3D 얼굴 모델을 볼 수 있습니다"
        thumbs.removeAllViews()
        val size = dp(84)
        for (f in files) {
            val iv = ImageView(this).apply {
                scaleType = ImageView.ScaleType.CENTER_CROP
                setBackgroundColor(Color.LTGRAY)
                setOnClickListener {
                    startActivity(Intent(this@MainActivity, PhotoActivity::class.java).putExtra("path", f.absolutePath))
                }
            }
            thumbs.addView(iv, LinearLayout.LayoutParams(size, size).apply { rightMargin = dp(6) })
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
        results.addView(label("마지막 점검: ${fmt.format(Date(time))}"))
        results.addView(hint(
            "있음 ${rows.count { it.status == "found" }} · 있을 수도 ${rows.count { it.status == "possible" }} · " +
                "차단 ${rows.count { it.status == "blocked" }} · 오류 ${rows.count { it.status == "error" }} · " +
                "없음 ${rows.count { it.status == "not_found" }} (없음은 숨김)\n항목을 누르면 사이트가 열립니다."))
        for (r in visible) {
            val color = when (r.status) {
                "found" -> Color.rgb(10, 125, 44); "possible" -> Color.rgb(178, 107, 0); else -> Color.GRAY
            }
            val face = r.faceScore?.let {
                if (it >= FaceMatcher.SAME_PERSON) "\n⚠ 프로필 사진이 내 얼굴과 비슷함 (%.2f)".format(it) else "\n프로필 얼굴 유사도 %.2f".format(it)
            } ?: ""
            val tv = TextView(this).apply {
                text = "[${UsernameChecker.LABEL[r.status]}] ${r.site}  (${r.username})\n${r.url}$face" +
                    if (r.note.isNotEmpty()) "\n${r.note}" else ""
                setTextColor(color); textSize = 14f
                setPadding(0, dp(8), 0, dp(8))
                if ((r.faceScore ?: 0.0) >= FaceMatcher.SAME_PERSON) setBackgroundColor(Color.rgb(255, 225, 225))
                setOnClickListener { runCatching { startActivity(Intent(Intent.ACTION_VIEW, Uri.parse(r.url))) } }
            }
            results.addView(tv)
        }
    }

    private fun label(t: String) = TextView(this).apply {
        text = t; textSize = 16f; setTypeface(null, Typeface.BOLD); setTextColor(Color.BLACK); setPadding(0, dp(16), 0, dp(4))
    }
    private fun hint(t: String) = TextView(this).apply { text = t; textSize = 13f; setTextColor(Color.DKGRAY) }
    private fun button(t: String, onClick: () -> Unit) = Button(this).apply { text = t; setOnClickListener { onClick() } }
    private fun row(vararg views: View) = LinearLayout(this).apply {
        orientation = LinearLayout.HORIZONTAL; gravity = Gravity.CENTER_VERTICAL
        views.forEach { addView(it, LinearLayout.LayoutParams(0, WRAP_CONTENT, 1f)) }
    }
    private fun toast(t: String) = Toast.makeText(this, t, Toast.LENGTH_SHORT).show()
}
