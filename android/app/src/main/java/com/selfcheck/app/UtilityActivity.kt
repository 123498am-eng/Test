package com.selfcheck.app

import android.app.KeyguardManager
import android.app.admin.DevicePolicyManager
import android.content.Intent
import android.content.pm.ApplicationInfo
import android.content.pm.PackageInfo
import android.content.pm.PackageManager
import android.graphics.Bitmap
import android.graphics.Color
import android.net.Uri
import android.os.Build
import android.os.Bundle
import android.provider.Settings
import android.text.Editable
import android.text.InputType
import android.text.TextWatcher
import android.view.ViewGroup.LayoutParams.MATCH_PARENT
import android.view.ViewGroup.LayoutParams.WRAP_CONTENT
import android.widget.CheckBox
import android.widget.EditText
import android.widget.ImageView
import android.widget.LinearLayout
import android.widget.SeekBar
import android.widget.TextView
import com.google.zxing.BarcodeFormat
import com.google.zxing.EncodeHintType
import com.google.zxing.qrcode.QRCodeWriter
import com.google.zxing.qrcode.decoder.ErrorCorrectionLevel
import java.io.File
import java.net.HttpURLConnection
import java.net.URL
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale
import kotlin.concurrent.thread

/** 보안·개인정보 도구 (비밀번호·스미싱·링크·개인정보·QR 만들기·앱 권한·기기 보안) */
class UtilityActivity : ColumnActivity() {
    companion object {
        val TOOLS = listOf(
            Triple("pw_breach", "비밀번호 유출 확인", "내 비밀번호가 유출된 목록에 있는지 확인 (비밀번호 자체는 보내지 않음)"),
            Triple("pw_strength", "비밀번호 강도 검사", "뚫리는 데 걸리는 시간과 약점"),
            Triple("pw_make", "비밀번호 만들기", "안전한 무작위 비밀번호·암호 문구"),
            Triple("smishing", "스미싱 문자 검사", "받은 문자를 붙여 넣으면 사기 문자 신호를 찾음"),
            Triple("link", "링크 안전 검사", "주소만 보고 피싱·사칭 신호 찾기, 단축 주소 펼치기"),
            Triple("privacy", "개인정보 가리기 (글)", "주민번호·전화·카드·계좌·주소를 찾아 가린 글 만들기"),
            Triple("qr_make", "QR 코드 만들기", "링크·글·와이파이·연락처 QR 만들기"),
            Triple("app_audit", "앱 권한 점검", "카메라·마이크·위치·문자 권한을 가진 앱, 스토커웨어 의심 조합"),
            Triple("device_check", "기기 보안 점검", "화면 잠금·보안 패치·개발자 옵션·루팅 흔적"),
        )
    }

    private lateinit var out: LinearLayout

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        val id = intent.getStringExtra("tool") ?: ""
        val t = TOOLS.firstOrNull { it.first == id } ?: run { finish(); return }
        setupColumn(t.second, t.third)
        out = LinearLayout(this).apply { orientation = LinearLayout.VERTICAL }
        when (id) {
            "pw_breach" -> pwBreach(); "pw_strength" -> pwStrength(); "pw_make" -> pwMake(); "smishing" -> smishing(); "link" -> link()
            "privacy" -> privacy(); "qr_make" -> qrMake(); "app_audit" -> appAudit(); "device_check" -> deviceCheck()
        }
        col.addView(out)
    }

    private fun input(hint: String, multi: Boolean = false, password: Boolean = false) = EditText(this).apply {
        this.hint = hint
        if (multi) { minLines = 4; gravity = android.view.Gravity.TOP } else setSingleLine()
        if (password) inputType = InputType.TYPE_CLASS_TEXT or InputType.TYPE_TEXT_VARIATION_VISIBLE_PASSWORD or InputType.TYPE_TEXT_FLAG_NO_SUGGESTIONS
    }.also { styleInput(it); full(it) }

    private fun result(t: String, color: Int = Color.BLACK) = out.addView(TextView(this).apply { text = t; textSize = 15f; setTextColor(color); setTextIsSelectable(true); setPadding(0, dp(6), 0, dp(6)) })
    private fun levelColor(l: Int) = when (l) { 0 -> Pal.good; 1 -> Pal.warn; else -> Pal.bad }

    // ---------------- 비밀번호
    private fun pwBreach() {
        val et = input("확인할 비밀번호", password = true)
        col.addView(hint("비밀번호를 SHA-1 로 바꾼 값의 앞 5글자만 haveibeenpwned.com 에 보내고, 나머지 비교는 휴대폰 안에서 합니다 (k-익명성). 비밀번호 자체는 어디에도 보내지 않습니다."))
        full(button("확인") {
            val pw = et.text.toString(); if (pw.isEmpty()) return@button
            out.removeAllViews(); result("확인 중...")
            thread {
                val r = runCatching {
                    val h = PasswordCheck.sha1Hex(pw)
                    val c = URL("https://api.pwnedpasswords.com/range/${h.take(5)}").openConnection() as HttpURLConnection
                    c.setRequestProperty("Add-Padding", "true"); c.setRequestProperty("User-Agent", "SelfCheck-Android")
                    c.connectTimeout = 10000; c.readTimeout = 15000
                    val body = c.inputStream.bufferedReader().use { it.readText() }
                    PasswordCheck.countInRange(body, h.drop(5))
                }
                runOnUiThread {
                    out.removeAllViews()
                    r.onSuccess { n ->
                        if (n > 0) result("⚠ 유출된 비밀번호입니다 (유출 자료에서 ${"%,d".format(n)}번 발견).\n이 비밀번호를 쓰는 모든 사이트에서 바로 바꾸세요.", levelColor(2))
                        else result("유출 목록에서 발견되지 않았습니다.\n그래도 사이트마다 다른 비밀번호를 쓰세요.", levelColor(0))
                    }.onFailure { result("확인 실패: ${it.message}\n(인터넷 연결을 확인하세요)", levelColor(1)) }
                }
            }
        })
    }

    private fun showStrength(pw: String) {
        out.removeAllViews()
        if (pw.isEmpty()) return
        val r = PasswordCheck.check(pw)
        out.addView(bar("강도: ${r.label}", (r.score + 1) * 20f, "%.0f비트".format(r.bits), lowIsGood = false))
        result("뚫리는 데 걸리는 시간(빠른 오프라인 공격 기준): ${r.crack}", levelColor(if (r.score >= 3) 0 else if (r.score == 2) 1 else 2))
        r.tips.forEach { result("• $it", Color.DKGRAY) }
    }

    private fun pwStrength() {
        val et = input("비밀번호 입력 (휴대폰 밖으로 나가지 않음)", password = true)
        et.addTextChangedListener(object : TextWatcher {
            override fun afterTextChanged(s: Editable?) { showStrength(s?.toString() ?: "") }
            override fun beforeTextChanged(s: CharSequence?, a: Int, b: Int, c: Int) {}
            override fun onTextChanged(s: CharSequence?, a: Int, b: Int, c: Int) {}
        })
    }

    private fun pwMake() {
        var len = 16
        val label = hint("길이: $len")
        col.addView(label)
        col.addView(SeekBar(this).apply {
            max = 40; progress = len - 8
            setOnSeekBarChangeListener(object : SeekBar.OnSeekBarChangeListener {
                override fun onProgressChanged(sb: SeekBar, p: Int, u: Boolean) { len = p + 8; label.text = "길이: $len" }
                override fun onStartTrackingTouch(sb: SeekBar) {}
                override fun onStopTrackingTouch(sb: SeekBar) {}
            })
        })
        val up = CheckBox(this).apply { text = "대문자"; isChecked = true }; val dg = CheckBox(this).apply { text = "숫자"; isChecked = true }; val sy = CheckBox(this).apply { text = "특수문자"; isChecked = true }
        col.addView(LinearLayout(this).apply { addView(up); addView(dg); addView(sy) })
        fun show(p: String) {
            out.removeAllViews()
            out.addView(TextView(this).apply { text = p; textSize = 22f; typeface = android.graphics.Typeface.MONOSPACE; setTextColor(Color.BLACK); setTextIsSelectable(true); setPadding(0, dp(10), 0, dp(4)) })
            val r = PasswordCheck.check(p)
            result("강도 ${r.label} · 뚫리는 데 ${r.crack}", Color.DKGRAY)
            out.addView(button("복사") { copy(p, "비밀번호") })
        }
        col.addView(buttons("비밀번호 만들기" to { _ -> show(PasswordCheck.generate(len, up.isChecked, dg.isChecked, sy.isChecked)) },
            "암호 문구 만들기" to { _ -> show(PasswordCheck.passphrase(4)) }))
        col.addView(hint("만든 비밀번호는 저장되지 않습니다. 비밀번호 관리 앱에 보관하세요."))
    }

    // ---------------- 스미싱·링크
    private fun smishing() {
        val et = input("받은 문자 내용을 붙여 넣으세요", multi = true)
        col.addView(buttons("검사" to { _ ->
            out.removeAllViews()
            val r = SmsCheck.check(et.text.toString())
            result(r.verdict, levelColor(r.level))
            out.addView(bar("위험 점수", (r.score * 12f).coerceAtMost(100f), "${r.score}점"))
            r.reasons.forEach { result("• $it", Color.DKGRAY) }
            r.links.forEach { (u, l) -> result("링크 $u\n→ ${l.verdict}" + if (l.reasons.isNotEmpty()) "\n  - " + l.reasons.joinToString("\n  - ") else "", levelColor(l.level)) }
            result("의심되면: 링크·전화 금지 → 118(한국인터넷진흥원) 또는 112 상담", Color.GRAY)
        }, "붙여넣기" to { _ ->
            getSystemService(android.content.ClipboardManager::class.java).primaryClip?.getItemAt(0)?.coerceToText(this)?.let { et.setText(it) }
        }))
    }

    private fun link() {
        val et = input("링크 주소 (예: https://...)")
        col.addView(buttons("검사" to { _ ->
            out.removeAllViews()
            val r = LinkCheck.check(et.text.toString())
            result("${r.host}\n${r.verdict}", levelColor(r.level))
            r.reasons.forEach { result("• $it", Color.DKGRAY) }
        }, "단축 주소 펼치기" to { _ -> expand(et.text.toString()) }))
        col.addView(hint("검사는 주소 글자만 봅니다. '단축 주소 펼치기'는 주소에 접속해 이동할 곳만 확인합니다 (페이지 내용은 받지 않음). 접속하면 상대가 접속 기록을 볼 수 있으니 의심스러운 주소는 펼치지 않는 것이 더 안전합니다."))
    }

    private fun expand(u0: String) {
        out.removeAllViews(); result("확인 중...")
        thread {
            val chain = ArrayList<String>()
            val r = runCatching {
                var u = if (u0.startsWith("http")) u0.trim() else "https://${u0.trim()}"
                chain += u
                repeat(6) {
                    val c = URL(u).openConnection() as HttpURLConnection
                    c.instanceFollowRedirects = false; c.requestMethod = "HEAD"; c.connectTimeout = 8000; c.readTimeout = 8000
                    c.setRequestProperty("User-Agent", "Mozilla/5.0")
                    val code = c.responseCode; val loc = c.getHeaderField("Location"); c.disconnect()
                    if (code !in 300..399 || loc == null) return@runCatching
                    u = URL(URL(u), loc).toString(); chain += u
                }
            }
            runOnUiThread {
                out.removeAllViews()
                if (r.isFailure && chain.size <= 1) { result("확인 실패: ${r.exceptionOrNull()?.message}", levelColor(1)); return@runOnUiThread }
                chain.forEachIndexed { i, u -> val l = LinkCheck.check(u); result("${if (i == 0) "처음" else "→ $i"}: $u\n   ${l.verdict}", levelColor(l.level)) }
            }
        }
    }

    // ---------------- 개인정보
    private fun privacy() {
        val et = input("검사할 글 (예: 보내기 전 문서·게시글)", multi = true)
        fun run() {
            out.removeAllViews()
            val text = et.text.toString()
            val hits = PrivacyMask.find(text)
            if (hits.isEmpty()) { result("찾은 개인정보가 없습니다", levelColor(0)); return }
            result("찾은 개인정보 ${hits.size}개", levelColor(2))
            hits.groupBy { it.kind }.forEach { (k, v) -> result("• $k ${v.size}개", Color.DKGRAY) }
            val masked = PrivacyMask.mask(text)
            out.addView(section("가린 글"))
            result(masked)
            out.addView(button("가린 글 복사") { copy(masked, "가린 글") })
        }
        col.addView(buttons("찾아서 가리기" to { _ -> run() }))
        col.addView(hint("검사는 휴대폰 안에서만 합니다."))
    }

    // ---------------- QR 만들기
    private fun qrBitmap(text: String, size: Int = 900): Bitmap {
        val m = QRCodeWriter().encode(text, BarcodeFormat.QR_CODE, size, size, mapOf(EncodeHintType.CHARACTER_SET to "UTF-8", EncodeHintType.MARGIN to 2, EncodeHintType.ERROR_CORRECTION to ErrorCorrectionLevel.M))
        val px = IntArray(m.width * m.height) { i -> if (m.get(i % m.width, i / m.width)) Color.BLACK else Color.WHITE }
        return Bitmap.createBitmap(px, m.width, m.height, Bitmap.Config.ARGB_8888)
    }

    private fun qrMake() {
        var mode = 0
        val modes = listOf("링크·글", "와이파이", "연락처")
        val a = input("링크 또는 글"); val b = input("비밀번호").apply { visibility = android.view.View.GONE }; val c = input("이메일").apply { visibility = android.view.View.GONE }
        val modeBtn = button("종류: ${modes[0]}") { btn ->
            mode = (mode + 1) % 3; btn.text = "종류: ${modes[mode]}"
            a.hint = listOf("링크 또는 글", "와이파이 이름(SSID)", "이름")[mode]
            b.visibility = if (mode == 0) android.view.View.GONE else android.view.View.VISIBLE; b.hint = if (mode == 1) "와이파이 비밀번호 (없으면 비움)" else "전화번호"
            c.visibility = if (mode == 2) android.view.View.VISIBLE else android.view.View.GONE
        }
        col.addView(modeBtn, 2)
        val iv = ImageView(this).apply { adjustViewBounds = true }
        var current: Bitmap? = null
        fun make() {
            val text = when (mode) { 1 -> QrText.wifi(a.text.toString(), b.text.toString()); 2 -> QrText.contact(a.text.toString(), b.text.toString(), c.text.toString()); else -> a.text.toString() }
            if (text.isBlank()) return
            runCatching { qrBitmap(text) }.onSuccess { bm -> current = bm; iv.setImageBitmap(bm) }.onFailure { toast("만들 수 없습니다: ${it.message}") }
        }
        fun save() {
            val bm = current ?: return
            thread { val m = runCatching { MediaSave.savePng(this, bm, "qr_${System.currentTimeMillis()}.png") }.getOrElse { "실패: ${it.message}" }; runOnUiThread { toast(m) } }
        }
        col.addView(buttons("만들기" to { _ -> make() }, "저장" to { _ -> save() }, "보내기" to { _ -> current?.let { MediaSave.share(this, it) } }))
        out.addView(iv, LinearLayout.LayoutParams(MATCH_PARENT, WRAP_CONTENT))
    }

    // ---------------- 앱 권한
    private fun appAudit() {
        result("앱 목록 확인 중...")
        thread {
            val pm = packageManager
            val pkgs: List<PackageInfo> = if (Build.VERSION.SDK_INT >= 33) pm.getInstalledPackages(PackageManager.PackageInfoFlags.of(PackageManager.GET_PERMISSIONS.toLong()))
                else @Suppress("DEPRECATION") pm.getInstalledPackages(PackageManager.GET_PERMISSIONS)
            val launchable = pm.queryIntentActivities(Intent(Intent.ACTION_MAIN).addCategory(Intent.CATEGORY_LAUNCHER), 0).map { it.activityInfo.packageName }.toSet()
            val access = (Settings.Secure.getString(contentResolver, Settings.Secure.ENABLED_ACCESSIBILITY_SERVICES) ?: "").split(':').map { it.substringBefore('/') }.toSet()
            val notif = (Settings.Secure.getString(contentResolver, "enabled_notification_listeners") ?: "").split(':').map { it.substringBefore('/') }.toSet()
            val admins = (getSystemService(DevicePolicyManager::class.java).activeAdmins ?: emptyList()).map { it.packageName }.toSet()
            val groups = linkedMapOf(
                "카메라" to listOf("android.permission.CAMERA"), "마이크" to listOf("android.permission.RECORD_AUDIO"),
                "위치" to listOf("android.permission.ACCESS_FINE_LOCATION", "android.permission.ACCESS_COARSE_LOCATION"),
                "백그라운드 위치" to listOf("android.permission.ACCESS_BACKGROUND_LOCATION"),
                "문자" to listOf("android.permission.READ_SMS", "android.permission.RECEIVE_SMS", "android.permission.SEND_SMS"),
                "연락처" to listOf("android.permission.READ_CONTACTS"), "통화 기록" to listOf("android.permission.READ_CALL_LOG"),
                "사진·동영상" to listOf("android.permission.READ_MEDIA_IMAGES", "android.permission.READ_MEDIA_VIDEO", "android.permission.READ_EXTERNAL_STORAGE"),
            )
            class Row(val name: String, val pkg: String, val perms: List<String>, val flags: List<String>, val risk: Int)
            val rows = ArrayList<Row>()
            for (p in pkgs) {
                val ai = p.applicationInfo ?: continue
                if (ai.flags and ApplicationInfo.FLAG_SYSTEM != 0 || p.packageName == packageName) continue
                val req = p.requestedPermissions ?: emptyArray(); val fl = p.requestedPermissionsFlags ?: IntArray(0)
                val granted = req.indices.filter { it < fl.size && fl[it] and PackageInfo.REQUESTED_PERMISSION_GRANTED != 0 }.map { req[it] }.toSet()
                val perms = groups.filter { (_, ps) -> ps.any { it in granted } }.keys.toList()
                val flags = ArrayList<String>()
                if (p.packageName in access) flags += "접근성(화면 읽기·조작)"
                if (p.packageName in notif) flags += "알림 읽기"
                if (p.packageName in admins) flags += "기기 관리자"
                if (p.packageName !in launchable) flags += "아이콘 숨김"
                val installer = runCatching { if (Build.VERSION.SDK_INT >= 30) pm.getInstallSourceInfo(p.packageName).installingPackageName else @Suppress("DEPRECATION") pm.getInstallerPackageName(p.packageName) }.getOrNull()
                val stores = setOf("com.android.vending", "com.sec.android.app.samsungapps", "com.skt.skaf.A000Z00040", "com.kt.olleh.storefront", "com.lguplus.appstore", "com.onestore.android.app")
                if (installer == null || installer !in stores) flags += "스토어 밖에서 설치"
                val spy = (flags.any { it.startsWith("접근성") || it == "알림 읽기" || it == "기기 관리자" }) && perms.any { it in setOf("문자", "위치", "백그라운드 위치", "마이크", "통화 기록") }
                val risk = (if (spy) 10 else 0) + (if ("아이콘 숨김" in flags) 3 else 0) + (if ("스토어 밖에서 설치" in flags) 2 else 0) + perms.size
                if (perms.isNotEmpty() || flags.any { it != "스토어 밖에서 설치" }) rows += Row(pm.getApplicationLabel(ai).toString(), p.packageName, perms, flags, risk)
            }
            rows.sortByDescending { it.risk }
            runOnUiThread {
                out.removeAllViews()
                val spyCount = rows.count { it.risk >= 10 }
                result(if (spyCount > 0) "⚠ 스토커웨어 의심 조합 앱 ${spyCount}개 — 내가 설치한 앱인지 확인하세요" else "스토커웨어로 의심되는 조합의 앱은 없습니다", levelColor(if (spyCount > 0) 2 else 0))
                result("권한을 가진 앱 ${rows.size}개 (위에서부터 주의 순) · 누르면 앱 설정이 열립니다", Color.DKGRAY)
                for (r in rows) out.addView(TextView(this).apply {
                    text = "${r.name}\n  권한: ${r.perms.joinToString(", ").ifEmpty { "-" }}" + if (r.flags.isNotEmpty()) "\n  특이: ${r.flags.joinToString(", ")}" else ""
                    textSize = 14f; setTextColor(if (r.risk >= 10) levelColor(2) else if (r.risk >= 5) levelColor(1) else Color.BLACK); setPadding(0, dp(6), 0, dp(6))
                    setOnClickListener { runCatching { startActivity(Intent(Settings.ACTION_APPLICATION_DETAILS_SETTINGS, Uri.parse("package:${r.pkg}"))) } }
                })
                result("스토커웨어 의심 조합: 접근성·알림 읽기·기기 관리자 중 하나 + 문자·위치·마이크·통화 기록 권한. 모르는 앱이면 설정에서 권한을 끄거나 삭제하고, 112 또는 여성긴급전화 1366 에 상담하세요.", Color.GRAY)
            }
        }
    }

    // ---------------- 기기 보안
    private fun deviceCheck() {
        fun item(ok: Boolean?, title: String, detail: String) = out.addView(TextView(this).apply {
            text = "${when (ok) { true -> "✅"; false -> "⚠"; null -> "ℹ" }} $title\n   $detail"; textSize = 14f
            setTextColor(when (ok) { true -> levelColor(0); false -> levelColor(2); null -> Color.DKGRAY }); setPadding(0, dp(6), 0, dp(6))
        })
        val secure = getSystemService(KeyguardManager::class.java).isDeviceSecure
        item(secure, "화면 잠금", if (secure) "설정되어 있습니다" else "잠금이 없습니다. 설정 → 보안에서 PIN·지문을 설정하세요")
        val patch = Build.VERSION.SECURITY_PATCH
        val months = runCatching { ((System.currentTimeMillis() - SimpleDateFormat("yyyy-MM-dd", Locale.US).parse(patch)!!.time) / (30L * 86400000)).toInt() }.getOrDefault(-1)
        item(if (months < 0) null else months <= 6, "보안 패치", "$patch (${if (months >= 0) "${months}개월 전" else "알 수 없음"}) — 6개월 넘으면 업데이트를 확인하세요")
        item(Build.VERSION.SDK_INT >= 31, "안드로이드 버전", "Android ${Build.VERSION.RELEASE} (API ${Build.VERSION.SDK_INT})")
        val dev = Settings.Global.getInt(contentResolver, Settings.Global.DEVELOPMENT_SETTINGS_ENABLED, 0) == 1
        val adb = Settings.Global.getInt(contentResolver, Settings.Global.ADB_ENABLED, 0) == 1
        item(!adb, "USB 디버깅", if (adb) "켜져 있습니다. 쓰지 않으면 끄세요 (개발자 옵션)" else "꺼져 있습니다")
        item(if (dev) null else true, "개발자 옵션", if (dev) "켜져 있습니다" else "꺼져 있습니다")
        val suPaths = listOf("/system/bin/su", "/system/xbin/su", "/sbin/su", "/system/app/Superuser.apk", "/data/adb/magisk", "/system/sbin/su", "/vendor/bin/su")
        val rooted = suPaths.any { File(it).exists() } || (Build.TAGS ?: "").contains("test-keys")
        item(!rooted, "루팅 흔적", if (rooted) "루팅 흔적이 있습니다. 금융 앱·보안에 위험할 수 있습니다" else "발견되지 않았습니다")
        val enc = getSystemService(DevicePolicyManager::class.java).storageEncryptionStatus
        item(enc == DevicePolicyManager.ENCRYPTION_STATUS_ACTIVE || enc == DevicePolicyManager.ENCRYPTION_STATUS_ACTIVE_PER_USER, "저장소 암호화", if (enc >= 3) "암호화되어 있습니다" else "확인되지 않았습니다")
        val access = Settings.Secure.getString(contentResolver, Settings.Secure.ENABLED_ACCESSIBILITY_SERVICES) ?: ""
        val accNames = access.split(':').filter { it.isNotBlank() }.map { it.substringBefore('/') }
        item(if (accNames.isEmpty()) true else null, "접근성 서비스", if (accNames.isEmpty()) "켜진 서비스 없음" else "켜짐: ${accNames.joinToString()} — 모르는 앱이면 끄세요 (화면 내용을 읽을 수 있음)")
        item(null, "Play 프로텍트", "Play 스토어 → 프로필 → Play 프로텍트에서 '앱 검사'가 켜져 있는지 확인하세요")
    }
}
