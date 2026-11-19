package com.selfcheck.app

import android.app.Activity
import android.graphics.Bitmap
import android.graphics.Canvas
import android.view.View
import android.view.View.MeasureSpec
import androidx.activity.ComponentActivity
import android.content.Context
import android.content.Intent
import androidx.test.core.app.ApplicationProvider
import androidx.work.Configuration
import androidx.work.WorkManager
import org.junit.Assume.assumeTrue
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.Robolectric
import org.robolectric.RobolectricTestRunner
import org.robolectric.annotation.Config
import org.robolectric.annotation.GraphicsMode
import java.io.File

/** -PuiShots 를 주지 않으면 시험을 통째로 무시 (Robolectric 이 안드로이드 SDK 를 내려받으려 하지 않게) */
class ShotRunner(cls: Class<*>) : RobolectricTestRunner(cls) {
    override fun isIgnored(child: org.junit.runners.model.FrameworkMethod): Boolean = System.getProperty("ui.shots.dir") == null || super.isIgnored(child)
}

/**
 * 화면을 컴퓨터에서 실제로 그려 PNG 로 저장해 눈으로 확인하는 시험 (-PuiShots=폴더 를 줄 때만 실행).
 * Robolectric 네이티브 그래픽으로 진짜 Activity 를 띄워서, 코드가 만든 화면 그대로를 그립니다.
 */
@RunWith(ShotRunner::class)
@GraphicsMode(GraphicsMode.Mode.NATIVE)
@Config(sdk = [35], qualifiers = "w411dp-h891dp-xxhdpi")
class UiShotTest {
    private val dir: File? = System.getProperty("ui.shots.dir")?.let { File(it) }

    private fun shoot(a: Activity, name: String, heightDp: Int = 891) {
        val d = a.resources.displayMetrics
        val w = d.widthPixels; val h = (heightDp * d.density).toInt()
        val v: View = a.window.decorView
        v.measure(MeasureSpec.makeMeasureSpec(w, MeasureSpec.EXACTLY), MeasureSpec.makeMeasureSpec(h, MeasureSpec.EXACTLY))
        v.layout(0, 0, w, h)
        val bmp = Bitmap.createBitmap(w, h, Bitmap.Config.ARGB_8888)
        v.draw(Canvas(bmp))
        dir!!.mkdirs()
        File(dir, "$name.png").outputStream().use { bmp.compress(Bitmap.CompressFormat.PNG, 100, it) }
    }

    @Before fun initWork() {
        val ctx = ApplicationProvider.getApplicationContext<Context>()
        runCatching { WorkManager.initialize(ctx, Configuration.Builder().setExecutor(java.util.concurrent.Executors.newSingleThreadExecutor()).build()) }
    }

    private inline fun <reified T : ComponentActivity> screen(name: String, heightDp: Int = 891, extras: Map<String, String> = emptyMap(), tweak: (T) -> Unit = {}) {
        assumeTrue(dir != null)
        val intent = Intent(ApplicationProvider.getApplicationContext(), T::class.java).also { i -> extras.forEach { (k, v) -> i.putExtra(k, v) } }
        val c = Robolectric.buildActivity(T::class.java, intent).setup()
        tweak(c.get())
        shoot(c.get(), name, heightDp)
        c.pause().stop().destroy()
    }

    private inline fun <reified T : ComponentActivity> tryScreen(name: String, heightDp: Int, extras: Map<String, String> = emptyMap()) {
        try { screen<T>(name, heightDp, extras) } catch (e: Throwable) { if (e is org.junit.AssumptionViolatedException) throw e; System.err.println("스크린샷 건너뜀 $name: $e") }
    }

    private val tag get() = System.getProperty("ui.shots.tag") ?: "before"

    private fun voicePrefs(vararg kv: Pair<String, Any>) {
        val e = ApplicationProvider.getApplicationContext<Context>().getSharedPreferences("voice_ui", Context.MODE_PRIVATE).edit().clear()
        for ((k, v) in kv) when (v) { is Boolean -> e.putBoolean(k, v); is Float -> e.putFloat(k, v); is String -> e.putString(k, v) }
        e.commit()
    }

    @Test fun voice() = screen<VoiceChangerActivity>("${tag}_voice", 1500)
    /** 원본 목소리 섞기를 켜고, 변조 목소리 듣기를 끈 상태 (뉴스 앵커 선택) */
    @Test fun voiceToggles() { voicePrefs("preset" to "news_f_anchor", "category" to "뉴스 여성", "origOn" to true, "origLevel" to 0.7f, "monitor" to false); screen<VoiceChangerActivity>("${tag}_voice_toggles", 1100) }
    /** 효과 전용 프리셋: 원본 스위치가 비활성 */
    @Test fun voiceEffect() { voicePrefs("preset" to "cave", "category" to "효과"); screen<VoiceChangerActivity>("${tag}_voice_effect", 1100) }
    @Test fun edit() = screen<EditActivity>("${tag}_edit", 700)
    // 카메라 화면: 카메라 권한이 없는 상태에서 위쪽·아래쪽 버튼 줄이 어떻게 보이는지 (지원 안 되는 환경이면 건너뜀)
    @Test fun cameraPerson() = tryScreen<PersonActivity>("${tag}_cam_person", 891)
    @Test fun cameraLiveTool() = tryScreen<LiveToolActivity>("${tag}_cam_livetool", 891, mapOf("tool" to "squat"))
    @Test fun cameraPlate() = tryScreen<PlateActivity>("${tag}_cam_plate", 891)
    @Test fun photoToolLip() = screen<PhotoToolActivity>("${tag}_phototool_lip", 700, mapOf("tool" to "lip"))
    @Test fun utilityLink() = screen<UtilityActivity>("${tag}_utility_link", 700, mapOf("tool" to "link"))
    @Test fun photoInfo() {
        val f = java.io.File.createTempFile("shot", ".png")
        Bitmap.createBitmap(300, 400, Bitmap.Config.ARGB_8888).also { it.eraseColor(0xFFCCB6A0.toInt()) }.compress(Bitmap.CompressFormat.PNG, 100, f.outputStream())
        screen<PhotoActivity>("${tag}_photoinfo", 1000, mapOf("path" to f.absolutePath))
    }
    @Test fun home() = screen<MainActivity>("${tag}_home", 2200)
    @Test fun tools() = screen<ToolsActivity>("${tag}_tools", 1500)
    @Test fun faceScan() = screen<FaceScanActivity>("${tag}_facescan", 700)
    @Test fun faceCompare() = screen<FaceCompareActivity>("${tag}_facecompare", 1100)
    @Test fun plateLookup() = screen<PlateLookupActivity>("${tag}_platelookup", 900)
    @Test fun photoTool() = screen<PhotoToolActivity>("${tag}_phototool", 900, mapOf("tool" to "skin_smooth"))
    @Test fun utility() = screen<UtilityActivity>("${tag}_utility", 900, mapOf("tool" to "pw_strength"))
    @Test fun sensor() = screen<SensorActivity>("${tag}_sensor", 800, mapOf("tool" to "level"))
}
